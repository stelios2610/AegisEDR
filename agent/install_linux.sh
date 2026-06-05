#!/bin/bash
# AegisEDR Linux Agent Installer
# Usage: curl -fsSL http://CONSOLE_IP/agent/install.sh | sudo bash -s -- http://CONSOLE_IP:9000
set -e

CONSOLE_URL="${1:-}"
AGENT_DIR="/opt/aegisedr-agent"
SERVICE_NAME="aegisedr-agent"

if [ -z "$CONSOLE_URL" ]; then
    echo "ERROR: Console URL required"
    echo "Usage: $0 http://CONSOLE_IP:9000"
    exit 1
fi

echo "=================================="
echo "  AegisEDR Agent Installer"
echo "  Console: $CONSOLE_URL"
echo "=================================="

echo "[1/5] Installing dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv clamav 2>/dev/null || true

echo "[2/5] Creating agent directory..."
mkdir -p $AGENT_DIR
mkdir -p /etc/aegisedr-agent
mkdir -p /var/lib/aegisedr-agent/quarantine

echo "[3/5] Downloading agent..."
curl -fsSL "$CONSOLE_URL/agent/agent_linux.py" -o "$AGENT_DIR/agent.py"

echo "[4/5] Installing Python packages..."
python3 -m venv "$AGENT_DIR/venv"
"$AGENT_DIR/venv/bin/pip" install -q requests watchdog psutil yara-python 2>/dev/null || \
"$AGENT_DIR/venv/bin/pip" install -q requests watchdog psutil

echo "[5/5] Creating systemd service..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << SERVICE
[Unit]
Description=AegisEDR Security Agent
After=network.target

[Service]
Type=simple
ExecStart=$AGENT_DIR/venv/bin/python $AGENT_DIR/agent.py $CONSOLE_URL
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo ""
echo "=================================="
echo "  Agent installed and running!"
echo "  Check console to adopt endpoint."
echo "  Logs: journalctl -u $SERVICE_NAME -f"
echo "=================================="
