# WireGuard Key Manager

Este proyecto es una herramienta para la gestión automatizada de llaves y configuraciones de clientes WireGuard.  
Ofrece una interfaz de línea de comandos (CLI) interactiva y un servidor API HTTP desde el que controlar la creación, eliminación y reasignación de nuevas llaves asociadas a IPs.

## Características

*   **Gestión de Llaves:** Permite crear, listar, eliminar y reasignar IPs de clientes.
*   **Segregación de Redes:** El programa segmenta las llaves en dos tipos (o subredes) diferentes, dependiendo de su privilegio:
    *   **Red Privada (Tipo 0):** Rango `10.1.1.x`. Pensado para dispositivos que formen parte de la red de trabajadores.
    *   **Usuarios (Tipo 1):** Rango `10.1.2.x`. Pensado para dispositivos que consuman de los servicios de la red de trabajadores.  

    Nota: La jerarquía de red es simplemente cosmética, y no representa ninguna funcionalidad diferente.
*   **Formatos de Exportación:** Se permite exportar la configuración en tres maneras diferentes:
    - Un archivo `.conf`
    - Texto plano
    - Base64 modificado, compatible con el comando `wireguard://install/` de la [versión modificada de Wireguard para URIs y NetPriv](https://github.com/PiporGames/wireguard-windows)
*   **Validación:** Verificación estricta de nombres y rangos IP para evitar conflictos.
*   **Modo Servicio:** A parte de tener un menú interactivo, también permite solicitudes API HTTP ligera para gestión remota.

## Requisitos

*   Python 3.x
*   Permisos de root (para acceder a comandos wg).
*   Llave pública del servidor (`publickey`) en el directorio de ejecución.

## Configuración

Las configuraciones principales se encuentran al inicio de `keyManager.py`:
*   **Base de datos:** `keys_database.json`  
Especifica donde se encuentra la base de datos de llaves
*   **Endpoint WireGuard:** `example.com:51820`  
Especifica el punto de entrada por donde acceder al servicio de Wireguard desde fuera
*   **DNS:** `10.1.1.1`  
Especifica el servidor DNS a usar por los clientes de la red

## Instalación y Uso

### 0. Preparación

Antes de comenzar, es necesario asegurarse de que el servidor de wireguard no contenga ninguna llave de cliente ya creada.  
  
Este programa utiliza una base de datos propia para gestionar las llaves, por lo que no sería capaz de reconocer llaves ya existentes.  
Para eliminar todas las llaves existentes, ejecute:

```bash
sudo wg show wg0 peers | xargs -I {} sudo wg set wg0 peer {} remove
```
Luego, asegúrese de tener la llave pública del servidor en el archivo `publickey` en el mismo directorio que el script.

### 1. Interfaz de Línea de Comandos (CLI)

Ejecute el script sin argumentos para abrir el menú interactivo:

```bash
sudo python keyManager.py
```

El menú permite crear llaves, listar clientes, exportar configuraciones y gestionar IPs fácilmente.

### 2. Instalación como Servicio (API HTTP)

Para ejecutar la herramienta como un servicio systemd en fondo:

```bash
sudo ./install-service.sh
```

Esto instalará y activará el servicio `wireguard-keymanager`. El servidor escuchará por defecto en el puerto **9999** (o el especificado en el script).

### 3. Uso de la API

Una vez activo el servicio, puede interactuar mediante HTTP:

*   **GET** `/list`: Listar todas las llaves.
*   **GET** `/export/text?name=<nombre>`: Obtener configuración en texto.
*   **GET** `/export/file?name=<nombre>`: Descargar archivo `.conf`.
*   **GET** `/export/base64?name=<nombre>`: Obtener configuración en base64.
*   **POST** `/create`: Crear llave (JSON body: `{"name": "usuario", "type": 1}`).
*   **POST** `/delete`: Eliminar llave (JSON body: `{"name": "usuario"}`).
*   **POST** `/move`: Cambiar IP (JSON body: `{"name": "usuario", "ip": "10.1.2.50"}`).
