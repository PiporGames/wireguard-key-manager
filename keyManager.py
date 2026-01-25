#!/usr/bin/env python3
"""
WireGuard Key Manager
"""
import os
import sys
import json
import subprocess
import re
from pathlib import Path
from typing import Optional, List, Dict

# Configuración de la aplicación
KEYS_DB_FILE = "keys_database.json"
SERVER_PUBLIC_KEY_FILE = "publickey"
# Configuración de WireGuard
ENDPOINT = "example.com:51820"
PRIVATE_NETWORK = "10.1.1.0/24, 10.1.2.0/24"
DNS_SERVER = "10.1.1.1"

# Constantes de validación
MAX_NAME_LENGTH = 64
VALID_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
VALID_IP_PATTERN = re.compile(r'^10\.1\.[12]\.([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$')



### VALIDACIÓN Y SANITIZACIÓN ###

def sanitize_name(name: str) -> str:
    """Sanitiza y valida el nombre de una llave."""
    if not name or not isinstance(name, str):
        raise ValueError("El nombre no puede estar vacío")
    
    # Eliminar espacios en blanco al inicio y final
    name = name.strip()
    
    # Verificar longitud
    if len(name) == 0:
        raise ValueError("El nombre no puede estar vacío")
    
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"El nombre no puede exceder {MAX_NAME_LENGTH} caracteres")
    
    # Verificar caracteres permitidos (solo alfanuméricos, guiones y guiones bajos)
    if not VALID_NAME_PATTERN.match(name):
        raise ValueError("El nombre solo puede contener letras, números, guiones (-) y guiones bajos (_)")
    
    # Prevenir nombres especiales de sistema
    forbidden_names = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 
                      'lpt1', 'lpt2', 'lpt3', '.', '..', 'wg0', 'server', 'localhost']
    if name.lower() in forbidden_names:
        raise ValueError(f"El nombre '{name}' está reservado y no puede usarse")
    
    return name

def validate_ip(ip: str) -> str:
    """Valida y sanitiza una dirección IP."""
    if not ip or not isinstance(ip, str):
        raise ValueError("La IP no puede estar vacía")
    
    # Eliminar espacios
    ip = ip.strip()
    
    # Validar formato usando regex estricto
    if not VALID_IP_PATTERN.match(ip):
        raise ValueError("La IP debe estar en el rango 10.1.1.1-254 (red privada) o 10.1.2.1-254 (usuarios)")
    
    # Verificar que no sea IP reservada
    parts = ip.split('.')
    last_octet = int(parts[3])
    
    if last_octet == 0:
        raise ValueError("La IP no puede terminar en .0 (dirección de red)")
    
    if last_octet == 255:
        raise ValueError("La IP no puede terminar en .255 (dirección de broadcast)")
    
    return ip

def validate_network_type(network_type: int) -> int:
    """Valida el tipo de red."""
    if not isinstance(network_type, int):
        raise ValueError("El tipo de red debe ser un número entero")
    
    if network_type not in [0, 1]:
        raise ValueError("El tipo de red debe ser 0 (red privada) o 1 (usuarios)")
    
    return network_type

def safe_filename(name: str) -> str:
    """Genera un nombre de archivo seguro previene path traversal."""
    # El nombre ya fue sanitizado, solo necesitamos el basename para prevenir path traversal
    return os.path.basename(name) + ".conf"



### APLICACIÓN PRINCIPAL ###

class WireGuardKeyManager:
    
    # Métodos privados
    def __init__(self, db_path: str = None):
        """Inicializa el gestor de llaves"""
        if db_path is None:
            # Usar el directorio donde está el script
            script_dir = Path(__file__).parent
            self.db_path = script_dir / KEYS_DB_FILE
            self.server_pubkey_path = script_dir / SERVER_PUBLIC_KEY_FILE
        else:
            self.db_path = Path(db_path)
            self.server_pubkey_path = Path(db_path).parent / SERVER_PUBLIC_KEY_FILE
        
        self.keys_db = self._load_database()
    
    def _load_database(self) -> Dict:
        """Carga la base de datos de llaves"""
        if self.db_path.exists():
            with open(self.db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"keys": []}
    
    def _save_database(self):
        """Guarda la base de datos de llaves"""
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.keys_db, f, indent=2, ensure_ascii=False)
    
    def _get_server_public_key(self) -> str:
        """Obtiene la llave pública del servidor"""
        if self.server_pubkey_path.exists():
            with open(self.server_pubkey_path, 'r') as f:
                return f.read().strip()
        return ""
    
    def _generate_keypair(self) -> tuple[str, str]:
        """Genera un par de llaves WireGuard (privada, pública)"""
        try:
            # Generar llave privada
            private_key = subprocess.check_output(
                ["wg", "genkey"],
                universal_newlines=True
            ).strip()
            
            # Generar llave pública desde la privada
            public_key = subprocess.check_output(
                ["wg", "pubkey"],
                input=private_key,
                universal_newlines=True
            ).strip()
            
            return private_key, public_key
        except subprocess.CalledProcessError as e:
            raise Exception(f"Error generando llaves: {e}")
        except FileNotFoundError:
            raise Exception("WireGuard no está instalado o 'wg' no está en el PATH")
    
    def _get_next_available_ip(self, network_type: int) -> str:
        """Obtiene la siguiente IP disponible según el tipo de red
        network_type: 0 = red privada (10.1.1.X), 1 = usuarios (10.1.2.X)
        """
        # Validar tipo de red
        network_type = validate_network_type(network_type)
        
        used_ips = set()
        for key_entry in self.keys_db["keys"]:
            ip = key_entry["ip"].split("/")[0]  # Remover /24
            used_ips.add(ip)
        
        # Definir el rango según el tipo de red
        if network_type == 0:
            # Red privada: 10.1.1.2 - 10.1.1.254
            network_prefix = "10.1.1"
            network_name = "red privada 10.1.1.0/24"
            start_ip = 2
        else:
            # Usuarios: 10.1.2.1 - 10.1.2.254
            network_prefix = "10.1.2"
            network_name = "usuarios 10.1.2.0/24"
            start_ip = 1
        
        # Buscar IP disponible en el rango
        for i in range(start_ip, 255):
            ip = f"{network_prefix}.{i}"
            if ip not in used_ips:
                return ip
        
        raise Exception(f"No hay IPs disponibles en la red {network_name}")
    
    def _add_peer_to_wireguard(self, public_key: str, ip: str):
        """Añade el peer a la configuración de WireGuard."""
        try:
            # Añadir peer usando wg set
            subprocess.run(
                ["wg", "set", "wg0", "peer", public_key, "allowed-ips", f"{ip}/32"],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Guardar configuración
            subprocess.run(
                ["wg-quick", "save", "wg0"],
                check=False,  # No fallar si no existe el comando
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            raise Exception(f"No se pudo registrar en WireGuard: {error_msg}")
        except FileNotFoundError:
            raise Exception("WireGuard no está instalado o 'wg' no está en el PATH")
    
    def _remove_peer_from_wireguard(self, public_key: str):
        """Elimina el peer de la configuración de WireGuard."""
        try:
            # Eliminar peer
            subprocess.run(
                ["wg", "set", "wg0", "peer", public_key, "remove"],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Guardar configuración
            subprocess.run(
                ["wg-quick", "save", "wg0"],
                check=False,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            raise Exception(f"No se pudo eliminar de WireGuard: {error_msg}")
        except FileNotFoundError:
            raise Exception("WireGuard no está instalado o 'wg' no está en el PATH")
    
    def _generate_config_file(self, key_entry: Dict) -> str:
        """Genera el contenido del archivo de configuración."""
        server_pubkey = self._get_server_public_key()
        
        return f"""[Interface]
PrivateKey = {key_entry['private_key']}
Address = {key_entry['ip']}
DNS = {DNS_SERVER}

[Peer]
PublicKey = {server_pubkey}
AllowedIPs = {PRIVATE_NETWORK}
Endpoint = {ENDPOINT}
"""    
    

    # Métodos públicos
    def create_key(self, name: str, network_type: int = 1) -> Dict:
        """Crea una nueva llave de WireGuard."""
        # Sanitizar y validar inputs
        name = sanitize_name(name)
        network_type = validate_network_type(network_type)
        # Verificar que el nombre no exista
        for key_entry in self.keys_db["keys"]:
            if key_entry["name"] == name:
                raise Exception(f"Ya existe una llave con el nombre '{name}'")
        
        # Generar par de llaves
        private_key, public_key = self._generate_keypair()
        
        # Obtener siguiente IP disponible según el tipo de red
        ip = self._get_next_available_ip(network_type)
        
        # Crear entrada
        key_entry = {
            "name": name,
            "private_key": private_key,
            "public_key": public_key,
            "ip": ip,
            "network_type": network_type
        }
        
        # Registrar con WireGuard (si falla, no guardamos nada)
        self._add_peer_to_wireguard(public_key, ip)
        
        # Añadir a la base de datos
        self.keys_db["keys"].append(key_entry)
        self._save_database()
        
        return {
            "name": name,
            "ip": ip,
            "public_key": public_key,
            "network_type": network_type
        }
    
    def delete_key(self, name: str) -> bool:
        """Elimina una llave de WireGuard."""
        # Sanitizar nombre
        name = sanitize_name(name)
        
        for i, key_entry in enumerate(self.keys_db["keys"]):
            if key_entry["name"] == name:
                # Eliminar de WireGuard
                self._remove_peer_from_wireguard(key_entry["public_key"])
                
                # Eliminar de la base de datos
                del self.keys_db["keys"][i]
                self._save_database()
                
                return True
        
        raise Exception(f"No se encontró la llave '{name}'")
    
    def export_key_text(self, name: str) -> str:
        """Devuelve la configuración de una llave como texto."""
        # Sanitizar nombre
        name = sanitize_name(name)
        
        for key_entry in self.keys_db["keys"]:
            if key_entry["name"] == name:
                return self._generate_config_file(key_entry)
        
        raise Exception(f"No se encontró la llave '{name}'")
    
    def export_key_file(self, name: str) -> str:
        """Escribe la configuración de una llave a un archivo."""
        # Sanitizar nombre
        name = sanitize_name(name)
        
        for key_entry in self.keys_db["keys"]:
            if key_entry["name"] == name:
                config_content = self._generate_config_file(key_entry)
                # Usar función segura para nombre de archivo (previene path traversal)
                config_filename = safe_filename(name)
                
                with open(config_filename, 'w', encoding='utf-8') as f:
                    f.write(config_content)
                
                return config_filename
        
        raise Exception(f"No se encontró la llave '{name}'")
   
    def export_key_mod_base64(self, name: str) -> str:
        """Devuelve la configuración de una llave en formato modificado (especial) base64."""
        import base64
        
        # Sanitizar nombre
        name = sanitize_name(name)
        
        # Obtener configuración como texto
        config_text = self.export_key_text(name)
        
        # Justo antes de la linea de DNS, insertar el parámetro especial de NetworkPrivacy especial para Windows.
        config_lines = config_text.splitlines()
        for i, line in enumerate(config_lines):
            if line.startswith("DNS"):
                config_lines.insert(i, "NetworkPrivacy = Private")
                break
            
        config_text = "\n".join(config_lines)
        
        # Codificar en base64
        config_bytes = config_text.encode('utf-8')
        base64_bytes = base64.b64encode(config_bytes)
        base64_string = base64_bytes.decode('utf-8')
        
        # Le concatenamos el prefijo especial
        base64_string = name + "@" + base64_string
        
        return base64_string
    
    def move_key(self, name: str, new_ip: str) -> bool:
        """Mueve una llave a una nueva IP"""
        # Sanitizar y validar inputs
        name = sanitize_name(name)
        new_ip = validate_ip(new_ip)
        
        # Verificar que la IP no esté en uso
        for key_entry in self.keys_db["keys"]:
            if key_entry["name"] != name:
                existing_ip = key_entry["ip"].split("/")[0]
                if existing_ip == new_ip:
                    raise Exception(f"La IP {new_ip} ya está en uso por '{key_entry['name']}'")
        
        # Buscar y actualizar la llave
        for key_entry in self.keys_db["keys"]:
            if key_entry["name"] == name:
                old_ip = key_entry["ip"].split("/")[0]
                
                # Eliminar peer antiguo de WireGuard
                self._remove_peer_from_wireguard(key_entry["public_key"])
                
                # Actualizar IP
                key_entry["ip"] = f"{new_ip}/24"
                self._save_database()
                
                # Añadir peer con nueva IP
                self._add_peer_to_wireguard(key_entry["public_key"], new_ip)
                
                return True
        
        raise Exception(f"No se encontró la llave '{name}'")

    def list_keys(self) -> List[Dict]:
        """Lista todas las llaves registradas"""
        return self.keys_db["keys"]
    

# Menú interactivo
def interactive_menu():
    """Menú interactivo."""
    manager = WireGuardKeyManager()
    
    while True:
        print("\n=== Gestor de Llaves WireGuard ===")
        print("1. Listar llaves")
        print("2. Crear llave")
        print("3. Exportar llave (texto)")
        print("4. Exportar llave (archivo)")
        print("5. Exportar llave (base64 modificado)")
        print("6. Eliminar llave")
        print("7. Mover llave a otra IP")
        print("8. Salir")
        
        choice = input("\nSeleccione una opción: ").strip()
        
        try:
            if choice == "1":
                keys = manager.list_keys()
                if not keys:
                    print("\nNo hay llaves registradas.")
                else:
                    print("\n--- Llaves Registradas ---")
                    for idx, key in enumerate(keys, start=1):
                        net_type = key.get('network_type', 1)
                        net_label = "Red Privada" if net_type == 0 else "Usuario"
                        print(f"  {idx}. {key['name']} @ {key['ip']} ({net_label}) [{key['public_key']}]")
                        print()
            
            elif choice == "2":
                name = input("Ingrese el nombre de la llave: ").strip()
                
                # Validar nombre antes de continuar
                try:
                    name = sanitize_name(name)
                except ValueError as e:
                    print(f"Error: {e}")
                    continue
                
                print("Tipo de dispositivo:")
                print("  0 - Red privada (10.1.1.X)")
                print("  1 - Usuario (10.1.2.X)")
                net_type_input = input("Seleccione tipo [1]: ").strip()
                
                try:
                    if net_type_input == "":
                        network_type = 1
                    else:
                        # Validar que sea numérico
                        network_type = int(net_type_input)
                        network_type = validate_network_type(network_type)
                except (ValueError, TypeError) as e:
                    print(f"Error: Tipo inválido. {e}")
                    continue
                
                result = manager.create_key(name, network_type)
                net_label = "Red Privada" if network_type == 0 else "Usuario"
                print(f"\n✓ Llave creada exitosamente:")
                print(f"  Nombre: {result['name']}")
                print(f"  Tipo: {net_label}")
                print(f"  IP: {result['ip']}")
                print(f"  Llave Pública: {result['public_key'][:40]}...")
            
            elif choice == "3":
                name = input("Ingrese el nombre de la llave: ").strip()
                
                try:
                    config = manager.export_key_text(name)
                    print(f"\n--- Configuración de '{name}' ---")
                    print(config)
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
            
            elif choice == "4":
                name = input("Ingrese el nombre de la llave: ").strip()
                
                try:
                    filename = manager.export_key_file(name)
                    print(f"\n✓ Archivo de configuración creado: {filename}")
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
                    
            elif choice == "5":
                name = input("Ingrese el nombre de la llave: ").strip()
                
                try:
                    base64_mod = manager.export_key_mod_base64(name)
                    print(f"\n--- Configuración en Base64 Modificado de '{name}' ---")
                    print(base64_mod)
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
            
            elif choice == "6":
                name = input("Ingrese el nombre de la llave a eliminar: ").strip()
                
                try:
                    manager.delete_key(name)
                    print(f"\n✓ Llave '{name}' eliminada exitosamente")
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
                    continue
            
            elif choice == "7":
                name = input("Ingrese el nombre de la llave: ").strip()
                new_ip = input("Ingrese la nueva IP (10.1.2.X): ").strip()
                
                try:
                    manager.move_key(name, new_ip)
                    print(f"\n✓ Llave '{name}' movida a {new_ip} exitosamente")
                except (ValueError, Exception) as e:
                    print(f"Error: {e}")
                    continue
            
            elif choice == "8":
                print("\nSaliendo...")
                break
            
            else:
                print("\nOpción inválida")
        
        except Exception as e:
            print(f"\nError: {e}")


# Modo servidor HTTP simple
def run_server():
    """Inicia el servidor HTTP."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    port = sys.argv[2] if len(sys.argv) > 2 else 9999
    
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                if self.path == '/list':
                    self._reply(200, json.dumps(WireGuardKeyManager().list_keys()))
                elif self.path.startswith('/export/text?name='):
                    name = self.path.split('=')[1]
                    self._reply(200, WireGuardKeyManager().export_key_text(name), 'text/plain')
                
                elif self.path.startswith('/export/file?name='):          
                    name = self.path.split('=')[1]
                    self._reply(200, WireGuardKeyManager().export_key_file(name), 'text/plain')
                    
                elif self.path.startswith('/export/modbase64?name='):
                    name = self.path.split('=')[1]
                    self._reply(200, WireGuardKeyManager().export_key_mod_base64(name), 'text/plain')
                
                else: self.send_error(404)
            except Exception as e: self._reply(500, json.dumps({'error': str(e)}))

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length))
                mgr = WireGuardKeyManager()
                
                if self.path == '/create':
                    self._reply(200, json.dumps(mgr.create_key(data['name'], data.get('type', 1))))
                    
                elif self.path == '/delete':
                    mgr.delete_key(data['name'])
                    self._reply(200, json.dumps({'status': 'ok'}))
                    
                elif self.path == '/move':
                    mgr.move_key(data['name'], data['ip'])
                    self._reply(200, json.dumps({'status': 'ok'}))
                    
                else: self.send_error(404)
            except Exception as e: self._reply(500, json.dumps({'error': str(e)}))

        def _reply(self, code, body, content_type='application/json'):
            self.send_response(code)
            self.send_header('Content-type', content_type)
            self.end_headers()
            self.wfile.write(body.encode())
            
        def log_message(self, format, *args): pass

    print(f"Iniciando servidor en puerto {port}...")
    try: HTTPServer(('localhost', int(port)), Handler).serve_forever()
    except KeyboardInterrupt: pass



# Programa principal
def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--server':
        run_server()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()