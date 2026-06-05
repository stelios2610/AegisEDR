#!/bin/bash
# AegisEDR ISO Builder — runs inside Docker container
# Input:  /ubuntu.iso  (Ubuntu Server ISO, mounted)
#         /aegisedr/   (project source, mounted)
# Output: /output/AegisEDR-1.0.0-amd64.iso
set -e

WORK="/tmp/aegisedr-build"
SRC="$WORK/src"
CUSTOM="$WORK/custom"
OUTPUT="/output/AegisEDR-1.0.0-amd64.iso"

echo "=============================================="
echo "  AegisEDR ISO Builder"
echo "=============================================="
echo ""

mkdir -p "$SRC" "$CUSTOM" /output

# ── 1. Extract Ubuntu ISO ─────────────────────────────────────────────────────
echo "[1/7] Extracting Ubuntu ISO..."
7z x /ubuntu.iso -o"$SRC" -y > /dev/null
cp -a "$SRC/." "$CUSTOM/"
echo "      Done."

# ── 2. GRUB bootloader config ─────────────────────────────────────────────────
echo "[2/7] Configuring bootloader..."

# Find grub.cfg location (varies between Ubuntu versions)
GRUB_CFG=""
for f in "$CUSTOM/boot/grub/grub.cfg" "$CUSTOM/grub/grub.cfg" "$CUSTOM/EFI/boot/grub.cfg"; do
    [ -f "$f" ] && GRUB_CFG="$f" && break
done

if [ -n "$GRUB_CFG" ]; then
    cat > "$GRUB_CFG" << 'GRUBCFG'
set default=0
set timeout=10
set timeout_style=menu

if loadfont /boot/grub/font.pf2; then
  set gfxmode=1024x768
  insmod all_video
  insmod gfxterm
  terminal_output gfxterm
fi

menuentry "Install AegisEDR Security Console" --class ubuntu --class os {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}

menuentry "Install AegisEDR (Safe Mode)" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}

menuentry "Boot from disk" {
    exit 1
}
GRUBCFG
fi

# ── 3. Cloud-init autoinstall ─────────────────────────────────────────────────
echo "[3/7] Writing autoinstall configuration..."
mkdir -p "$CUSTOM/nocloud"

cat > "$CUSTOM/nocloud/meta-data" << 'META'
instance-id: aegisedr-1
local-hostname: aegisedr
META

cat > "$CUSTOM/nocloud/user-data" << 'USERDATA'
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
    password: "$6$rounds=65536$aegisedr$EbKQf4DlN8TvJqPz5sYmX2wR6uHcA1gB7iF3eL9oM0nD4kV"

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
        eth0:
          dhcp4: true
        ens3:
          dhcp4: true
        ens33:
          dhcp4: true

  ssh:
    install-server: true
    allow-pw: true

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
    - net-tools
    - ufw
    - whiptail
    - figlet
    - htop

  user-data:
    chpasswd:
      expire: false

  late-commands:
    - curtin in-target --target=/target -- bash /cdrom/aegisedr_setup/install.sh
    - "echo 'aegisedr ALL=(ALL) NOPASSWD: ALL' > /target/etc/sudoers.d/aegisedr"
    - chmod 440 /target/etc/sudoers.d/aegisedr
USERDATA

# ── 4. Post-install script ────────────────────────────────────────────────────
echo "[4/7] Writing post-install script..."
mkdir -p "$CUSTOM/aegisedr_setup"

cat > "$CUSTOM/aegisedr_setup/install.sh" << 'INSTALL'
#!/bin/bash
set -e
exec >> /var/log/aegisedr-install.log 2>&1
echo "=== AegisEDR Install: $(date) ==="

# Copy AegisEDR application
mkdir -p /opt/aegisedr
cp -r /cdrom/aegisedr_app/* /opt/aegisedr/

# Python virtual environment
python3 -m venv /opt/aegisedr/venv
/opt/aegisedr/venv/bin/pip install --quiet --upgrade pip
/opt/aegisedr/venv/bin/pip install --quiet \
    fastapi uvicorn[standard] jinja2 python-multipart \
    bcrypt pyjwt aiosqlite httpx aiofiles \
    requests schedule psutil

# Service user
useradd --system --no-create-home --shell /bin/false aegisedr 2>/dev/null || true

# Directories
mkdir -p /opt/aegisedr/{data,quarantine,ioc_cache,yara_rules}
mkdir -p /etc/aegisedr/ssl
chown -R aegisedr:aegisedr /opt/aegisedr

# SSL self-signed certificate
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/aegisedr/ssl/key.pem \
    -out    /etc/aegisedr/ssl/cert.pem \
    -subj   "/CN=AegisEDR/O=AegisEDR Security/C=GR" 2>/dev/null
chmod 640 /etc/aegisedr/ssl/key.pem
chown root:aegisedr /etc/aegisedr/ssl/key.pem

# Copy YARA rules
cp /cdrom/aegisedr_app/yara_rules/*.yar /opt/aegisedr/yara_rules/ 2>/dev/null || true

# nginx reverse proxy config
cat > /etc/nginx/sites-available/aegisedr << 'NGINX'
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/aegisedr/ssl/cert.pem;
    ssl_certificate_key /etc/aegisedr/ssl/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass         http://127.0.0.1:9000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 300;
        client_max_body_size 100m;
    }
}
server {
    listen 80;
    return 301 https://$host$request_uri;
}
NGINX

ln -sf /etc/nginx/sites-available/aegisedr /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# AegisEDR systemd service
cat > /etc/systemd/system/aegisedr.service << 'SVC'
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
StandardOutput=append:/var/log/aegisedr.log
StandardError=append:/var/log/aegisedr.log

[Install]
WantedBy=multi-user.target
SVC

# First-boot setup wizard service
cat > /etc/systemd/system/aegisedr-firstboot.service << 'FB'
[Unit]
Description=AegisEDR First Boot Configuration Wizard
After=multi-user.target network.target
Before=aegisedr.service
ConditionPathExists=!/opt/aegisedr/.configured

[Service]
Type=oneshot
ExecStart=/opt/aegisedr/build/first_boot.sh
StandardInput=tty
TTYPath=/dev/tty1
StandardOutput=tty
StandardError=tty
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FB

# Firewall rules
ufw --force reset > /dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "HTTP redirect"
ufw allow 443/tcp comment "AegisEDR Console"
ufw allow 9000/tcp comment "Agent API"
ufw --force enable

# Login banner
cat > /etc/issue << 'BANNER'

  ╔══════════════════════════════════════════════════╗
  ║          AegisEDR Security Console               ║
  ║                  Version 1.0.0                   ║
  ║                                                  ║
  ║  First boot: setup wizard will start             ║
  ║  Default login: aegisedr / AegisEDR2024!        ║
  ╚══════════════════════════════════════════════════╝

BANNER
cp /etc/issue /etc/issue.net

# MOTD
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════╗
  ║          AegisEDR Security Console               ║
  ╠══════════════════════════════════════════════════╣
  ║  Console : https://<this-ip>                     ║
  ║  Logs    : journalctl -u aegisedr -f             ║
  ║  Config  : /opt/aegisedr/                        ║
  ╚══════════════════════════════════════════════════╝

MOTD

# Enable all services
systemctl daemon-reload
systemctl enable aegisedr.service
systemctl enable aegisedr-firstboot.service
systemctl enable nginx
systemctl enable clamav-freshclam

echo "=== AegisEDR install complete: $(date) ==="
INSTALL

chmod +x "$CUSTOM/aegisedr_setup/install.sh"

# ── 5. Copy AegisEDR application ──────────────────────────────────────────────
echo "[5/7] Embedding AegisEDR application..."
mkdir -p "$CUSTOM/aegisedr_app"
rsync -a \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='venv' \
    --exclude='data' \
    --exclude='dist' \
    --exclude='assets/*.png' \
    --exclude='assets/*.bmp' \
    --exclude='assets/*.ico' \
    /aegisedr/ "$CUSTOM/aegisedr_app/"

echo "      $(du -sh "$CUSTOM/aegisedr_app" | cut -f1) embedded."

# ── 6. Checksums ─────────────────────────────────────────────────────────────
echo "[6/7] Updating checksums..."
cd "$CUSTOM"
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
cd -

# ── 7. Repack ISO ─────────────────────────────────────────────────────────────
echo "[7/7] Repacking ISO..."

# Detect hybrid MBR and EFI images
MBR=""
EFI=""

for f in \
    "$SRC/boot/grub/i386-pc/boot_hybrid.img" \
    "$SRC/isolinux/isohdpfx.bin"; do
    [ -f "$f" ] && MBR="$f" && break
done

for f in \
    "$SRC/boot/grub/efi.img" \
    "$SRC/EFI/efi.img"; do
    [ -f "$f" ] && EFI="$f" && break
done

if [ -n "$MBR" ] && [ -n "$EFI" ]; then
    xorriso -as mkisofs \
        -r -V "AegisEDR-1.0.0" \
        --grub2-mbr "$MBR" \
        -partition_offset 16 \
        --mbr-force-bootable \
        -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "$EFI" \
        -appended_part_as_gpt \
        -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
        -c '/boot/boot.cat' \
        -b '/boot/grub/i386-pc/eltorito.img' \
        -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
        -eltorito-alt-boot \
        -e '--interval:appended_partition_2:::' \
        -no-emul-boot \
        -o "$OUTPUT" \
        "$CUSTOM/" 2>/dev/null
else
    # Simple fallback (still bootable via GRUB)
    xorriso -as mkisofs \
        -r -J -joliet-long \
        -V "AegisEDR-1.0.0" \
        -b boot/grub/i386-pc/eltorito.img \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -o "$OUTPUT" \
        "$CUSTOM/" 2>/dev/null || \
    xorriso -as mkisofs \
        -r -J -V "AegisEDR-1.0.0" \
        -o "$OUTPUT" \
        "$CUSTOM/" 2>/dev/null
fi

SIZE=$(du -sh "$OUTPUT" | cut -f1)

echo ""
echo "=============================================="
echo "  ISO built successfully!"
echo ""
echo "  File : AegisEDR-1.0.0-amd64.iso"
echo "  Size : $SIZE"
echo ""
echo "  Boot in Hyper-V / VMware / VirtualBox"
echo "  -> Auto-installs Ubuntu + AegisEDR"
echo "  -> First boot: network + user setup"
echo "  -> Console: https://<server-ip>"
echo "=============================================="
