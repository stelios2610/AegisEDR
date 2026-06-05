#!/bin/bash
# Build AegisEDR Linux Agent .deb package
# Usage: bash build_linux_deb.sh http://CONSOLE_IP:9000
set -e

AGENT_VERSION="1.0.0"
CONSOLE_URL="${1:-http://CONSOLE_IP:9000}"
PKG_NAME="aegisedr-agent"
PKG_DIR="/tmp/${PKG_NAME}_${AGENT_VERSION}"

echo "╔═══════════════════════════════════════════╗"
echo "║   AegisEDR Linux Agent .deb Builder      ║"
echo "╚═══════════════════════════════════════════╝"
echo "Console URL: $CONSOLE_URL"

# Install build deps
apt-get install -y dpkg-dev python3 python3-pip python3-venv 2>/dev/null || true

# Clean
rm -rf "$PKG_DIR"

# .deb structure
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/opt/aegisedr-agent"
mkdir -p "$PKG_DIR/etc/aegisedr-agent"
mkdir -p "$PKG_DIR/etc/systemd/system"
mkdir -p "$PKG_DIR/var/lib/aegisedr-agent/quarantine"
mkdir -p "$PKG_DIR/var/log"

# Copy agent
cp "$(dirname "$0")/agent_linux.py" "$PKG_DIR/opt/aegisedr-agent/agent.py"

# Create venv + install deps inside package
python3 -m venv "$PKG_DIR/opt/aegisedr-agent/venv"
"$PKG_DIR/opt/aegisedr-agent/venv/bin/pip" install -q \
    requests watchdog psutil yara-python 2>/dev/null || \
"$PKG_DIR/opt/aegisedr-agent/venv/bin/pip" install -q requests watchdog psutil

# DEBIAN/control
cat > "$PKG_DIR/DEBIAN/control" << CONTROL
Package: ${PKG_NAME}
Version: ${AGENT_VERSION}
Section: net
Priority: optional
Architecture: amd64
Depends: python3, clamav
Maintainer: AegisEDR Security <support@aegisedr.local>
Description: AegisEDR Security Agent
 Endpoint protection agent for AegisEDR Security Console.
 Provides real-time malware detection, ransomware prevention,
 anti-spyware, and IoC-based threat detection.
CONTROL

# DEBIAN/conffiles
echo "/etc/aegisedr-agent/config.json" > "$PKG_DIR/DEBIAN/conffiles"

# DEBIAN/postinst — runs after installation
cat > "$PKG_DIR/DEBIAN/postinst" << POSTINST
#!/bin/bash
set -e
CONSOLE_URL="${CONSOLE_URL}"

# Write initial config with console URL
if [ ! -f /etc/aegisedr-agent/config.json ]; then
    cat > /etc/aegisedr-agent/config.json << CONFIG
{
  "console_url": "\${CONSOLE_URL}"
}
CONFIG
fi

# systemd service
cat > /etc/systemd/system/aegisedr-agent.service << SERVICE
[Unit]
Description=AegisEDR Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/aegisedr-agent/venv/bin/python /opt/aegisedr-agent/agent.py \${CONSOLE_URL}
Restart=always
RestartSec=30
StandardOutput=append:/var/log/aegisedr-agent.log
StandardError=append:/var/log/aegisedr-agent.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aegisedr-agent
systemctl start aegisedr-agent

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   AegisEDR Agent installed!               ║"
echo "║                                           ║"
echo "║   Connecting to: \${CONSOLE_URL}"
echo "║   Check console to ADOPT this endpoint.  ║"
echo "║                                           ║"
echo "║   Logs: journalctl -u aegisedr-agent -f  ║"
echo "╚═══════════════════════════════════════════╝"
POSTINST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# DEBIAN/prerm — runs before uninstall
cat > "$PKG_DIR/DEBIAN/prerm" << PRERM
#!/bin/bash
systemctl stop aegisedr-agent 2>/dev/null || true
systemctl disable aegisedr-agent 2>/dev/null || true
PRERM
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# DEBIAN/postrm — runs after uninstall
cat > "$PKG_DIR/DEBIAN/postrm" << POSTRM
#!/bin/bash
if [ "\$1" = "purge" ]; then
    rm -rf /opt/aegisedr-agent
    rm -rf /etc/aegisedr-agent
    rm -rf /var/lib/aegisedr-agent
    rm -f /var/log/aegisedr-agent.log
    rm -f /etc/systemd/system/aegisedr-agent.service
    systemctl daemon-reload
fi
POSTRM
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# Set permissions
chmod -R 755 "$PKG_DIR/opt"
chmod -R 755 "$PKG_DIR/etc"

# Build .deb
OUTPUT_DIR="$(dirname "$0")/../dist"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DEB="$OUTPUT_DIR/${PKG_NAME}_${AGENT_VERSION}_amd64.deb"

dpkg-deb --build --root-owner-group "$PKG_DIR" "$OUTPUT_DEB"

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║  .deb package built successfully!        ║"
echo "║                                          ║"
echo "║  File: $OUTPUT_DEB"
echo "║                                          ║"
echo "║  Install on endpoint:                    ║"
echo "║  sudo dpkg -i aegisedr-agent_*.deb       ║"
echo "║  sudo apt-get install -f                 ║"
echo "╚═══════════════════════════════════════════╝"
