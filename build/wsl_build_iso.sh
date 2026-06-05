#!/bin/bash
set -e

ISO='/mnt/c/Users/stelakis-pc/Downloads/ubuntu-26.04-live-server-amd64.iso'
PROJECT='/mnt/c/users/stelakis-pc/projects/aegis-edr'
OUTPUT='/mnt/c/users/stelakis-pc/projects/aegis-edr/dist/AegisEDR-1.0.0-amd64.iso'
WORK='/tmp/aegisedr-build'
SRC="$WORK/src"
CUSTOM="$WORK/custom"

echo "=============================================="
echo "  AegisEDR ISO Builder"
echo "=============================================="

# Check ISO exists
if [ ! -f "$ISO" ]; then
    echo "ERROR: ISO not found at $ISO"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$SRC" "$CUSTOM" "$(dirname "$OUTPUT")"

echo "[1/7] Extracting Ubuntu ISO (2-3 minutes)..."
7z x "$ISO" -o"$SRC" -y > /dev/null
cp -a "$SRC/." "$CUSTOM/"
echo "      Done."

echo "[2/7] Configuring bootloader..."
for f in "$CUSTOM/boot/grub/grub.cfg" "$CUSTOM/grub/grub.cfg"; do
    if [ -f "$f" ]; then
        cat > "$f" << 'GRUBCFG'
set default=0
set timeout=10

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
GRUBCFG
        echo "      Updated: $f"
        break
    fi
done

echo "[3/7] Writing autoinstall configuration..."
mkdir -p "$CUSTOM/nocloud"

cat > "$CUSTOM/nocloud/meta-data" << 'META'
instance-id: aegisedr-1
local-hostname: aegisedr
META

# Generate password hash for "AegisEDR2024!"
PASS_HASH=$(python3 -c "import crypt; print(crypt.crypt('AegisEDR2024!', crypt.mksalt(crypt.METHOD_SHA512)))" 2>/dev/null || echo "\$6\$aegisedr\$placeholder")

cat > "$CUSTOM/nocloud/user-data" << USERDATA
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
    password: "${PASS_HASH}"
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
  user-data:
    chpasswd:
      expire: false
  late-commands:
    - curtin in-target --target=/target -- bash /cdrom/aegisedr_setup/install.sh
    - "echo 'aegisedr ALL=(ALL) NOPASSWD: ALL' > /target/etc/sudoers.d/aegisedr"
    - chmod 440 /target/etc/sudoers.d/aegisedr
USERDATA

echo "[4/7] Writing post-install script..."
mkdir -p "$CUSTOM/aegisedr_setup"

# Write the install script that runs inside the new system after Ubuntu installs
cat > "$CUSTOM/aegisedr_setup/install.sh" << 'INSTALLSCRIPT'
#!/bin/bash
set -e
exec >> /var/log/aegisedr-install.log 2>&1
echo "=== AegisEDR Install: $(date) ==="

# ── Copy app files from ISO ───────────────────────────────────────────────────
mkdir -p /opt/aegisedr
cp -r /cdrom/aegisedr_app/* /opt/aegisedr/

# ── Python venv — EXACT packages from running server ─────────────────────────
python3 -m venv /opt/aegisedr/venv
/opt/aegisedr/venv/bin/pip install --quiet --upgrade pip
/opt/aegisedr/venv/bin/pip install --quiet -r /cdrom/server-configs/requirements-server.txt

# ── Service user + directories ────────────────────────────────────────────────
useradd --system --no-create-home --shell /bin/false aegisedr 2>/dev/null || true
mkdir -p /opt/aegisedr/{data,quarantine,ioc_cache,yara_rules,downloads}
mkdir -p /etc/aegisedr/ssl

# ── SSL cert ──────────────────────────────────────────────────────────────────
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/aegisedr/ssl/key.pem \
    -out    /etc/aegisedr/ssl/cert.pem \
    -subj   "/CN=AegisEDR/O=AegisEDR/C=GR" 2>/dev/null
chmod 640 /etc/aegisedr/ssl/key.pem
chown root:aegisedr /etc/aegisedr/ssl/key.pem

# ── YARA rules + MSI ─────────────────────────────────────────────────────────
cp /cdrom/aegisedr_app/yara_rules/*.yar /opt/aegisedr/yara_rules/ 2>/dev/null || true
cp /cdrom/aegisedr_app/downloads/*.msi  /opt/aegisedr/downloads/  2>/dev/null || true

# ── nginx — EXACT copy from server ───────────────────────────────────────────
cp /cdrom/server-configs/nginx-aegisedr.conf /etc/nginx/sites-available/aegisedr
ln -sf /etc/nginx/sites-available/aegisedr /etc/nginx/sites-enabled/aegisedr
rm -f /etc/nginx/sites-enabled/default

# ── systemd service — EXACT copy from server ─────────────────────────────────
cp /cdrom/server-configs/aegisedr.service /etc/systemd/system/aegisedr.service

# ── Fix ownership ─────────────────────────────────────────────────────────────
chown -R aegisedr:aegisedr /opt/aegisedr

cat > /etc/systemd/system/aegisedr-firstboot.service << 'FB'
[Unit]
Description=AegisEDR First Boot Configuration Wizard
After=network-online.target multi-user.target
Wants=network-online.target
Before=aegisedr.service
ConditionPathExists=!/opt/aegisedr/.configured
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/aegisedr/build/first_boot.sh
StandardInput=tty
TTYPath=/dev/tty1
StandardOutput=tty
StandardError=tty
RemainAfterExit=yes
TimeoutStartSec=600
[Install]
WantedBy=multi-user.target
FB

ufw --force reset > /dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 9000/tcp
ufw --force enable

cat > /etc/motd << 'MOTD'

  +--------------------------------------------------+
  |         AegisEDR Security Console                |
  |               Version 1.0.0                      |
  +--------------------------------------------------+
  | Console : https://<server-ip>                    |
  | Logs    : journalctl -u aegisedr -f              |
  +--------------------------------------------------+

MOTD

systemctl daemon-reload
systemctl enable aegisedr.service
systemctl enable aegisedr-firstboot.service
systemctl enable nginx
systemctl enable clamav-freshclam

echo "=== Install complete: $(date) ==="
INSTALLSCRIPT

chmod +x "$CUSTOM/aegisedr_setup/install.sh"

echo "[5/7] Embedding AegisEDR application..."
mkdir -p "$CUSTOM/aegisedr_app"
rsync -a \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='venv' \
    --exclude='data' \
    --exclude='dist' \
    --exclude='build/wsl_build_iso.sh' \
    --exclude='build/*.log' \
    "$PROJECT/" "$CUSTOM/aegisedr_app/"
echo "      $(du -sh "$CUSTOM/aegisedr_app" | cut -f1) embedded."

# Embed server configs (exact copies from running server)
echo "[5b/7] Embedding server configs..."
SCONF="$(dirname "$(readlink -f "$0")")/server-configs"
mkdir -p "$CUSTOM/server-configs"
cp "$SCONF/"* "$CUSTOM/server-configs/" 2>/dev/null || true
echo "      $(ls "$CUSTOM/server-configs/" | wc -l) server config files embedded."

echo "[6/7] Updating checksums..."
cd "$CUSTOM"
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
cd -

echo "[7/7] Repacking ISO (bootable for Hyper-V / VMware)..."

# Ubuntu 26.04 stores boot images in [BOOT] directory (7z extraction convention)
MBR=""
EFI=""

# Try Ubuntu 26.04 format first ([BOOT] dir from 7z extraction)
[ -f "$SRC/[BOOT]/1-Boot-NoEmul.img" ] && MBR="$SRC/[BOOT]/1-Boot-NoEmul.img"
[ -f "$SRC/[BOOT]/2-Boot-NoEmul.img" ] && EFI="$SRC/[BOOT]/2-Boot-NoEmul.img"

# Fallback: Ubuntu 22.04/24.04 format
if [ -z "$MBR" ]; then
    for f in "$SRC/boot/grub/i386-pc/boot_hybrid.img" "$SRC/isolinux/isohdpfx.bin"; do
        [ -f "$f" ] && MBR="$f" && break
    done
fi
if [ -z "$EFI" ]; then
    for f in "$SRC/boot/grub/efi.img" "$SRC/EFI/efi.img"; do
        [ -f "$f" ] && EFI="$f" && break
    done
fi

echo "      MBR image: ${MBR:-not found}"
echo "      EFI image: ${EFI:-not found}"

if [ -n "$MBR" ] && [ -n "$EFI" ]; then
    echo "      Building hybrid BIOS+UEFI bootable ISO..."
    xorriso -as mkisofs \
        -r -V "AegisEDR-1.0.0" \
        --grub2-mbr "$MBR" \
        -partition_offset 16 \
        --mbr-force-bootable \
        -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "$EFI" \
        -appended_part_as_gpt \
        -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
        -c '/boot/boot.catalog' \
        -b '/boot/grub/i386-pc/eltorito.img' \
        -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
        -eltorito-alt-boot \
        -e '--interval:appended_partition_2:::' \
        -no-emul-boot \
        -o "$OUTPUT" "$CUSTOM/" 2>&1 | tail -5
else
    echo "      ERROR: Boot images not found in ISO!"
    echo "      Listing [BOOT] and boot/ contents:"
    ls "$SRC/[BOOT]/" 2>/dev/null || echo "No [BOOT] dir"
    find "$SRC/boot" -name "*.img" 2>/dev/null
    exit 1
fi

SIZE=$(du -sh "$OUTPUT" | cut -f1)
echo ""
echo "=============================================="
echo "  DONE!"
echo "  AegisEDR-1.0.0-amd64.iso ($SIZE)"
echo "  Location: dist/AegisEDR-1.0.0-amd64.iso"
echo "=============================================="
