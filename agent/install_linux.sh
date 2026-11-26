#!/bin/bash
# AegisEDR Linux Agent Installer
# Usage:
#   sudo bash install_linux.sh https://CONSOLE ENROLLMENT_CODE CERT_SHA256
# The CERT_SHA256 is the SHA-256 of the console PEM, shown on the Deploy page.
# The installer fetches that PEM once, checks the hash, then uses it for every download.
set -euo pipefail

CONSOLE_URL="${1:-}"
ENROLL_CODE="${2:-}"
CERT_SHA256="${3:-}"
AGENT_DIR="/opt/aegisedr-agent"
SERVICE_NAME="aegisedr-agent"
CA_PATH="/etc/aegisedr-agent/console.pem"

if [ -z "$CONSOLE_URL" ] || [ -z "$ENROLL_CODE" ]; then
    echo "Usage: $0 https://CONSOLE ENROLLMENT_CODE [CERT_SHA256]"
    exit 1
fi

echo "=================================="
echo "  AegisEDR Agent Installer"
echo "  Console: $CONSOLE_URL"
echo "=================================="

echo "[1/6] Installing dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv clamav-daemon 2>/dev/null || true

echo "[2/6] Creating agent directory..."
mkdir -p "$AGENT_DIR" /etc/aegisedr-agent /var/lib/aegisedr-agent/quarantine
chmod 750 /etc/aegisedr-agent

echo "[3/6] Pinning the console certificate..."
CURL_CA=()
if [[ "$CONSOLE_URL" == https://* ]]; then
    if [ -z "$CERT_SHA256" ]; then
        echo "ERROR: HTTPS console requires the certificate SHA-256 from the Deploy page."
        exit 1
    fi
    curl -kfsSL -o "$CA_PATH" "$CONSOLE_URL/api/ca"
    echo "${CERT_SHA256}  ${CA_PATH}" | sha256sum -c -
    chmod 644 "$CA_PATH"
    CURL_CA=(--cacert "$CA_PATH")
fi

echo "[4/6] Downloading agent..."
curl -fsSL "${CURL_CA[@]}" "$CONSOLE_URL/agent/agent_linux.py" -o "$AGENT_DIR/agent.py"
curl -fsSL "${CURL_CA[@]}" "$CONSOLE_URL/agent/edr_common.py" -o "$AGENT_DIR/edr_common.py"

python3 - << PY
import json, os
cfg = {
    "console_url": "${CONSOLE_URL}",
    "enrollment_code": "${ENROLL_CODE}",
}
ca = "${CA_PATH}"
if os.path.isfile(ca):
    cfg["ca_cert"] = ca
fd = os.open("/etc/aegisedr-agent/config.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, json.dumps(cfg, indent=2).encode())
os.close(fd)
PY

echo "[5/6] Installing Python packages..."
python3 -m venv "$AGENT_DIR/venv"
"$AGENT_DIR/venv/bin/pip" install -q requests watchdog psutil yara-python 2>/dev/null || \
"$AGENT_DIR/venv/bin/pip" install -q requests watchdog psutil

echo "[6/6] Creating systemd service..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << SERVICE
[Unit]
Description=AegisEDR Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$AGENT_DIR
ExecStart=$AGENT_DIR/venv/bin/python $AGENT_DIR/agent.py $CONSOLE_URL
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
echo "=================================="
echo "  Agent installed."
echo "  Adopt the endpoint in the console before protection starts."
echo "  Logs: journalctl -u $SERVICE_NAME -f"
echo "=================================="
