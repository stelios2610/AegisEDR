#!/bin/bash
# AegisEDR Console — Install Script for Ubuntu 22.04/24.04
set -e

echo "============================================"
echo "  AegisEDR Security Console — Installer"
echo "============================================"

# Directories
INSTALL_DIR="/opt/aegisedr"
DATA_DIR="/opt/aegisedr/data"
YARA_DIR="/opt/aegisedr/yara_rules"
QUARANTINE_DIR="/opt/aegisedr/quarantine"
IOC_DIR="/opt/aegisedr/ioc_cache"
SERVICE_USER="aegisedr"

echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv nginx openssl clamav clamav-daemon

echo "[2/7] Creating service user and directories..."
id -u $SERVICE_USER &>/dev/null || useradd --system --no-create-home --shell /bin/false $SERVICE_USER
mkdir -p $INSTALL_DIR $DATA_DIR $YARA_DIR $QUARANTINE_DIR $IOC_DIR

echo "[3/7] Copying application files..."
cp -r . $INSTALL_DIR/
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR

echo "[4/7] Installing Python dependencies..."
python3 -m venv $INSTALL_DIR/venv
$INSTALL_DIR/venv/bin/pip install -q --upgrade pip
$INSTALL_DIR/venv/bin/pip install -q -r $INSTALL_DIR/requirements.txt

echo "[5/7] Generating SSL certificate..."
mkdir -p /etc/aegisedr/ssl
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/aegisedr/ssl/key.pem \
  -out /etc/aegisedr/ssl/cert.pem \
  -subj "/CN=AegisEDR/O=AegisEDR/C=GR" 2>/dev/null

echo "[6/7] Configuring nginx..."
cat > /etc/nginx/sites-available/aegisedr << 'NGINX'
server {
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/aegisedr/ssl/cert.pem;
    ssl_certificate_key /etc/aegisedr/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
server {
    listen 80;
    return 301 https://$host$request_uri;
}
NGINX
ln -sf /etc/nginx/sites-available/aegisedr /etc/nginx/sites-enabled/aegisedr
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "[7/7] Installing systemd service..."
cat > /etc/systemd/system/aegisedr.service << SERVICE
[Unit]
Description=AegisEDR Security Console
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=AEGISEDR_DB=$DATA_DIR/aegisedr.db
Environment=AEGISEDR_YARA=$YARA_DIR
Environment=AEGISEDR_QUARANTINE=$QUARANTINE_DIR
ExecStart=$INSTALL_DIR/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aegisedr
systemctl start aegisedr

# Update ClamAV signatures
freshclam --quiet &

echo ""
echo "============================================"
echo "  AegisEDR installed successfully!"
echo ""
echo "  Console: https://$(hostname -I | awk '{print $1}')"
echo "  Default login: admin / AegisEDR2024!"
echo ""
echo "  IMPORTANT: Change the default password!"
echo "============================================"
