#!/bin/bash
# Check Ubuntu ISO structure to find correct boot files
ISO='/mnt/c/Users/stelakis-pc/Downloads/ubuntu-26.04-live-server-amd64.iso'
WORK='/tmp/iso-check'

mkdir -p "$WORK"
echo "=== Extracting ISO to check structure ==="
7z x "$ISO" -o"$WORK" -y > /dev/null

echo ""
echo "=== Boot-related files ==="
find "$WORK" -name "*.img" -o -name "*.efi" -o -name "grub.cfg" -o -name "isolinux.cfg" 2>/dev/null | head -30

echo ""
echo "=== boot/ directory ==="
ls -la "$WORK/boot/" 2>/dev/null || echo "No boot/ dir"

echo ""
echo "=== EFI directory ==="
ls -la "$WORK/EFI/" 2>/dev/null || echo "No EFI/ dir"

echo ""
echo "=== boot/grub/ ==="
ls -la "$WORK/boot/grub/" 2>/dev/null || echo "No boot/grub"

echo ""
echo "=== [BOOT] or boot images ==="
find "$WORK" -maxdepth 3 -name "*.img" 2>/dev/null

rm -rf "$WORK"
