#!/bin/bash

# Nombre del servicio
SERVICE_NAME="wireguard-keymanager"

# Obtener la ruta absoluta del directorio donde está este script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SCRIPT_PATH="$SCRIPT_DIR/keyManager.py"

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
  echo "Error: Este script debe ejecutarse como root (sudo)."
  exit 1
fi

# Verificar que keyManager.py existe
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: No se encuentra $SCRIPT_PATH"
    exit 1
fi

# Hacer ejecutable el script python
chmod +x "$SCRIPT_PATH"

echo "Configurando servicio $SERVICE_NAME..."
echo "Directorio de trabajo: $SCRIPT_DIR"
echo "Ejecutable: $SCRIPT_PATH"

# Crear archivo de unidad systemd
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=WireGuard Key Manager HTTP Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_PATH --server
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Recargar demonio de systemd
echo "Recargando systemd..."
systemctl daemon-reload

# Habilitar y arrancar el servicio
echo "Habilitando y arrancando el servicio..."
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

# Mostrar estado
echo "----------------------------------------"
systemctl status $SERVICE_NAME --no-pager
echo "----------------------------------------"
echo "Instalación completada. El servicio está escuchando en el puerto 9999."
