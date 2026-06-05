#!/bin/bash
# AegisEDR Appliance ISO Builder
# Builds a bootable Ubuntu-based ISO with AegisEDR pre-installed
# Run on Ubuntu 22.04 or 24.04
# Usage: sudo bash build_iso.sh
set -e

UBUNTU_VERSION="24.04.2"
UBUNTU_ISO="ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
UBUNTU_URL="https://releases.ubuntu.com/24.04/${UBUNTU_ISO}"
WORK_DIR="/tmp/aegisedr-iso-build"
OUTPUT_ISO="AegisEDR-1.0.0-amd64.iso"

echo "╔══════════════════════════════════════════════╗"
echo "║     AegisEDR Appliance ISO Builder           ║"
echo "╚══════════════════════════════════════════════╝"

# Dependencies
echo "[1/8] Installing build dependencies..."
apt-get update -qq
apt-get install -y xorriso squashfs-tools genisoimage curl wget p7zip-full \
                   python3 python3-pip cloud-image-utils isolinux

# Workspace
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{iso_orig,iso_custom,scripts}
cd "$WORK_DIR"

# Download Ubuntu ISO
echo "[2/8] Downloading Ubuntu Server ${UBUNTU_VERSION}..."
if [ ! -f "$UBUNTU_ISO" ]; then
    wget -q --show-progress "$UBUNTU_URL" -O "$UBUNTU_ISO"
fi

# Extract ISO
echo "[3/8] Extracting ISO..."
7z x "$UBUNTU_ISO" -o"iso_orig/" -y > /dev/null

# Copy to custom dir
cp -a iso_orig/. iso_custom/

# Inject autoinstall config into GRUB
echo "[4/8] Configuring autoinstall bootloader..."
cat > iso_custom/grub/grub.cfg << 'GRUB'
set default=0
set timeout=5

menuentry "AegisEDR Security Console (Install)" {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}

menuentry "AegisEDR Security Console (Install - Interactive)" {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}
GRUB

# Create nocloud autoinstall directory
mkdir -p iso_custom/nocloud

# Meta-data (required but can be empty)
cat > iso_custom/nocloud/meta-data << 'META'
instance-id: aegisedr-appliance
local-hostname: aegisedr
META

# Main autoinstall user-data
cat > iso_custom/nocloud/user-data << 'USERDATA'
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us

  identity:
    hostname: aegisedr
    username: aegisedr
    password: "$6$rounds=4096$aegisedr$qZ5VzCGPDhNzJFyXWr2BqVQmyHCmQb4N/7B6xzUjlWr3kFpDnRH7MtKhP0LuI8vEm5JkrQXtGcN2dHsL3Y0"
    # Password: AegisEDR2024! (hashed) — force change on first login

  storage:
    layout:
      name: lvm
      sizing-policy: all

  network:
    network:
      version: 2
      ethernets:
        eth0:
          dhcp4: true
          dhcp-identifier: mac

  packages:
    - python3
    - python3-pip
    - python3-venv
    - nginx
    - openssl
    - clamav
    - clamav-daemon
    - git
    - curl
    - wget
    - htop
    - net-tools
    - ufw

  user-data:
    chpasswd:
      expire: true

  late-commands:
    - curtin in-target --target=/target -- bash /cdrom/scripts/post_install.sh
USERDATA

# Post-install script (runs inside the new system)
cat > iso_custom/scripts/post_install.sh << 'POSTINSTALL'
#!/bin/bash
set -e
LOG="/var/log/aegisedr-install.log"
exec > >(tee -a $LOG) 2>&1

echo "[AegisEDR] Starting post-installation setup..."

# Copy AegisEDR application
mkdir -p /opt/aegisedr
cp -r /cdrom/aegisedr/* /opt/aegisedr/
chmod +x /opt/aegisedr/build/install.sh

# Install Python deps
python3 -m venv /opt/aegisedr/venv
/opt/aegisedr/venv/bin/pip install --quiet -r /opt/aegisedr/requirements.txt

# Create service user
useradd --system --no-create-home --shell /bin/false aegisedr 2>/dev/null || true

# Create directories
mkdir -p /opt/aegisedr/data
mkdir -p /opt/aegisedr/quarantine
mkdir -p /opt/aegisedr/ioc_cache
mkdir -p /etc/aegisedr/ssl
chown -R aegisedr:aegisedr /opt/aegisedr

# Generate self-signed SSL cert
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/aegisedr/ssl/key.pem \
    -out /etc/aegisedr/ssl/cert.pem \
    -subj "/CN=AegisEDR/O=AegisEDR/C=GR" 2>/dev/null

# nginx config
cat > /etc/nginx/sites-available/aegisedr << 'NGINX'
server {
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/aegisedr/ssl/cert.pem;
    ssl_certificate_key /etc/aegisedr/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
    }
}
server { listen 80; return 301 https://$host$request_uri; }
NGINX
ln -sf /etc/nginx/sites-available/aegisedr /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# AegisEDR systemd service
cat > /etc/systemd/system/aegisedr.service << 'SERVICE'
[Unit]
Description=AegisEDR Security Console
After=network.target
[Service]
Type=simple
User=aegisedr
WorkingDirectory=/opt/aegisedr
Environment=AEGISEDR_DB=/opt/aegisedr/data/aegisedr.db
Environment=AEGISEDR_YARA=/opt/aegisedr/yara_rules
Environment=AEGISEDR_QUARANTINE=/opt/aegisedr/quarantine
ExecStart=/opt/aegisedr/venv/bin/python main.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
SERVICE

# First-boot wizard service
cat > /etc/systemd/system/aegisedr-setup.service << 'SETUP'
[Unit]
Description=AegisEDR First Boot Setup Wizard
After=network.target
Before=aegisedr.service
ConditionPathExists=!/opt/aegisedr/.setup_done
[Service]
Type=oneshot
ExecStart=/opt/aegisedr/build/first_boot.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SETUP

# Firewall rules
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "HTTP redirect"
ufw allow 443/tcp comment "AegisEDR Console HTTPS"
ufw allow 9000/tcp comment "AegisEDR Agent API"
ufw --force enable

# Enable services
systemctl daemon-reload
systemctl enable aegisedr.service
systemctl enable aegisedr-setup.service
systemctl enable nginx
systemctl enable clamav-freshclam

# Update ClamAV signatures in background
freshclam --quiet &

echo "[AegisEDR] Post-installation complete!"
POSTINSTALL

chmod +x iso_custom/scripts/post_install.sh

# Copy AegisEDR application files into ISO
echo "[5/8] Embedding AegisEDR application..."
mkdir -p iso_custom/aegisedr
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='venv' --exclude='data' \
    "$SCRIPT_DIR/" iso_custom/aegisedr/

# Copy first-boot wizard
cp "$SCRIPT_DIR/build/first_boot.sh" iso_custom/scripts/

echo "[6/8] Writing first-boot wizard..."
# (first_boot.sh already copied above)

# Create checksums
echo "[7/8] Creating checksums..."
cd iso_custom
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
cd ..

# Repack ISO
echo "[8/8] Building ISO..."
xorriso -as mkisofs \
    -r \
    -V "AegisEDR-1.0.0" \
    -o "$OUTPUT_ISO" \
    --grub2-mbr iso_orig/boot/grub/i386-pc/boot_hybrid.img \
    -partition_offset 16 \
    --mbr-force-bootable \
    -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b iso_orig/boot/grub/efi.img \
    -appended_part_as_gpt \
    -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
    -c '/boot/boot.cat' \
    -b '/boot/grub/i386-pc/eltorito.img' \
    -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
    -eltorito-alt-boot \
    -e '--interval:appended_partition_2:::' \
    -no-emul-boot \
    iso_custom/ 2>/dev/null

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  ISO built successfully!                     ║"
echo "║  Output: $WORK_DIR/$OUTPUT_ISO"
echo "║                                              ║"
echo "║  Default login: aegisedr / AegisEDR2024!    ║"
echo "║  Console: https://<server-ip>               ║"
echo "╚══════════════════════════════════════════════╝"
