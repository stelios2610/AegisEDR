#!/bin/bash
# Runs INSIDE the Docker container to build the ISO
set -e

UBUNTU_VERSION="24.04.2"
UBUNTU_ISO="ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
WORK_DIR="/build/iso_work"
OUTPUT="/output/AegisEDR-1.0.0-amd64.iso"

echo "╔══════════════════════════════════════════════╗"
echo "║     AegisEDR ISO Builder (Docker)            ║"
echo "╚══════════════════════════════════════════════╝"

mkdir -p "$WORK_DIR/iso_src" "$WORK_DIR/iso_out" /output

# Download Ubuntu ISO if not present
if [ ! -f "/build/$UBUNTU_ISO" ]; then
    echo "[1/8] Downloading Ubuntu Server ${UBUNTU_VERSION}..."
    wget -q --show-progress \
        "https://releases.ubuntu.com/${UBUNTU_VERSION}/${UBUNTU_ISO}" \
        -O "/build/$UBUNTU_ISO"
else
    echo "[1/8] Ubuntu ISO already present."
fi

# Extract ISO
echo "[2/8] Extracting ISO..."
7z x "/build/$UBUNTU_ISO" -o"$WORK_DIR/iso_src/" -y > /dev/null

cp -a "$WORK_DIR/iso_src/." "$WORK_DIR/iso_out/"

# GRUB bootloader config
echo "[3/8] Configuring autoinstall bootloader..."
mkdir -p "$WORK_DIR/iso_out/nocloud"

cat > "$WORK_DIR/iso_out/grub/grub.cfg" << 'GRUB'
set default=0
set timeout=8
set timeout_style=menu

if loadfont /boot/grub/font.pf2 ; then
  set gfxmode=auto
  insmod all_video
  insmod gfxterm
  terminal_output gfxterm
fi

menuentry "Install AegisEDR Security Console" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}

menuentry "Install AegisEDR (Interactive)" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}

menuentry "Boot from next device" {
    exit 1
}
GRUB

# Cloud-init meta-data
cat > "$WORK_DIR/iso_out/nocloud/meta-data" << 'META'
instance-id: aegisedr-console
local-hostname: aegisedr
META

# Autoinstall user-data
cat > "$WORK_DIR/iso_out/nocloud/user-data" << 'USERDATA'
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
    variant: ''

  identity:
    hostname: aegisedr
    username: aegisedr
    password: "$6$rounds=4096$tzMO5B0I$FJC5QFXN4Y8bV3K7mWz9pXeA2hRsL6nDqG0JtKuI1vHdP8rMwZcE3aNbO5fYl4gXjS7iUqVR0kZeT2mL9C."
    # Default password: AegisEDR2024! — wizard forces change

  storage:
    layout:
      name: lvm
      sizing-policy: all

  network:
    network:
      version: 2
      ethernets:
        enp0s3:
          dhcp4: true
          dhcp-identifier: mac
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
    - figlet

  user-data:
    chpasswd:
      expire: true

  late-commands:
    - curtin in-target --target=/target -- bash /cdrom/scripts/aegisedr_install.sh
    - echo 'aegisedr ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/aegisedr
USERDATA

# Post-install script
echo "[4/8] Writing post-install script..."
mkdir -p "$WORK_DIR/iso_out/scripts"

cat > "$WORK_DIR/iso_out/scripts/aegisedr_install.sh" << 'INSTALL'
#!/bin/bash
set -e
exec > /var/log/aegisedr-install.log 2>&1
echo "=== AegisEDR Post-Install $(date) ==="

# Copy AegisEDR app
mkdir -p /opt/aegisedr
cp -r /cdrom/app/* /opt/aegisedr/

# Python venv
python3 -m venv /opt/aegisedr/venv
/opt/aegisedr/venv/bin/pip install --quiet --upgrade pip
/opt/aegisedr/venv/bin/pip install --quiet -r /opt/aegisedr/requirements.txt

# Service user
useradd --system --no-create-home --shell /bin/false aegisedr 2>/dev/null || true

# Directories
mkdir -p /opt/aegisedr/data /opt/aegisedr/quarantine /opt/aegisedr/ioc_cache
mkdir -p /etc/aegisedr/ssl
chown -R aegisedr:aegisedr /opt/aegisedr

# Self-signed SSL
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/aegisedr/ssl/key.pem \
    -out /etc/aegisedr/ssl/cert.pem \
    -subj "/CN=AegisEDR/O=AegisEDR/C=GR" 2>/dev/null
chmod 640 /etc/aegisedr/ssl/key.pem
chown root:aegisedr /etc/aegisedr/ssl/key.pem

# nginx
cat > /etc/nginx/sites-available/aegisedr << 'NGINX'
server {
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/aegisedr/ssl/cert.pem;
    ssl_certificate_key /etc/aegisedr/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300;
        client_max_body_size 100m;
    }
}
server { listen 80; server_name _; return 301 https://$host$request_uri; }
NGINX
ln -sf /etc/nginx/sites-available/aegisedr /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# AegisEDR service
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
Description=AegisEDR First Boot Setup
After=multi-user.target network.target
ConditionPathExists=!/opt/aegisedr/.setup_done
[Service]
Type=oneshot
ExecStart=/opt/aegisedr/build/first_boot.sh
StandardInput=tty
TTYPath=/dev/tty1
StandardOutput=tty
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SETUP

# Firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 9000/tcp
ufw --force enable

# MOTD
cat > /etc/motd << 'MOTD'

  ╔═══════════════════════════════════════════════════╗
  ║          AegisEDR Security Console v1.0           ║
  ║                                                   ║
  ║  Console: https://<this-server-ip>                ║
  ║  Logs:    journalctl -u aegisedr -f               ║
  ║  Config:  /opt/aegisedr/                          ║
  ╚═══════════════════════════════════════════════════╝

MOTD

systemctl daemon-reload
systemctl enable aegisedr.service
systemctl enable aegisedr-setup.service
systemctl enable nginx
systemctl enable clamav-freshclam

echo "=== AegisEDR install complete ==="
INSTALL
chmod +x "$WORK_DIR/iso_out/scripts/aegisedr_install.sh"

# Copy AegisEDR application into ISO
echo "[5/8] Embedding AegisEDR application..."
mkdir -p "$WORK_DIR/iso_out/app"
rsync -a \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='venv' \
    --exclude='data' \
    --exclude='build/iso_work' \
    /aegisedr/ "$WORK_DIR/iso_out/app/"

# Copy first-boot wizard
cp /aegisedr/build/first_boot.sh "$WORK_DIR/iso_out/app/build/"

# Checksums
echo "[6/8] Creating checksums..."
cd "$WORK_DIR/iso_out"
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt

# Repack ISO
echo "[7/8] Building final ISO..."
xorriso -as mkisofs \
    -r \
    -V "AegisEDR-1.0.0" \
    --grub2-mbr "$WORK_DIR/iso_src/boot/grub/i386-pc/boot_hybrid.img" \
    -partition_offset 16 \
    --mbr-force-bootable \
    -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b \
        "$WORK_DIR/iso_src/boot/grub/efi.img" \
    -appended_part_as_gpt \
    -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
    -c '/boot/boot.cat' \
    -b '/boot/grub/i386-pc/eltorito.img' \
    -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
    -eltorito-alt-boot \
    -e '--interval:appended_partition_2:::' \
    -no-emul-boot \
    -o "$OUTPUT" \
    "$WORK_DIR/iso_out/" 2>/dev/null

SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ISO built successfully!                    ║"
echo "║                                              ║"
echo "║   File: AegisEDR-1.0.0-amd64.iso            ║"
echo "║   Size: $SIZE                                "
echo "║                                              ║"
echo "║   Boot in Hyper-V / VMware / VirtualBox      ║"
echo "║   → Auto-installs Ubuntu + AegisEDR         ║"
echo "║   → First-boot wizard sets IP + password    ║"
echo "║   → Console: https://<server-ip>            ║"
echo "╚═══════════════════════════════════════════════╝"
