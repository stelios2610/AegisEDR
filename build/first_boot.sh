#!/bin/bash
# AegisEDR First Boot Setup Wizard
# Runs automatically on first boot via systemd
# Uses whiptail for dialog-based TUI
set -e

DONE_FILE="/opt/aegisedr/.configured"
LOG="/var/log/aegisedr-setup.log"
exec > >(tee -a "$LOG") 2>&1

# ── ASCII banner on TTY ───────────────────────────────────────────────────────
clear
cat << 'BANNER'

    ___              _       ___ ____  ____
   / _ \  ___  __ _(_)___  | __||  _ \|  _ \
  | |_| |/ _ \/ _` | / __| | _| | | | | |_) |
  |  _  |  __/ (_| | \__ \ | |__| |_| |  _ <
  |_| |_|\___|\__, |_|___/ |___||____/|_| \_\
               |___/
           Security Console  v1.0.0
  ─────────────────────────────────────────────
         First Boot Configuration Wizard
  ─────────────────────────────────────────────

BANNER
sleep 2

# ── Detect network interface ──────────────────────────────────────────────────
IFACE=$(ip -o link show | grep -v lo | grep -v docker | awk -F': ' '{print $2}' | head -1)
CURRENT_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
MAC=$(ip link show "$IFACE" 2>/dev/null | grep -oP '(?<=link/ether\s)[0-9a-f:]+' | head -1 || echo "")

# ── STEP 1: Network Configuration ────────────────────────────────────────────
NET_CHOICE=$(whiptail --title "AegisEDR — Network Setup" \
    --menu "Detected interface: $IFACE\nCurrent IP: ${CURRENT_IP:-not assigned}\n\nSelect network configuration:" \
    18 60 2 \
    "1" "DHCP  (automatic IP from router)" \
    "2" "Static IP  (manual configuration)" \
    3>&1 1>&2 2>&3) || { echo "Cancelled."; exit 1; }

CONSOLE_IP=""

if [ "$NET_CHOICE" = "2" ]; then
    # Static IP wizard
    STATIC_IP=$(whiptail --title "Static IP" --inputbox \
        "Enter IP address for this server:\n(Example: 192.168.1.50)" \
        10 55 "192.168.1.50" 3>&1 1>&2 2>&3) || exit 1

    NETMASK=$(whiptail --title "Subnet Mask" --inputbox \
        "Enter subnet mask:\n(Example: 255.255.255.0)" \
        10 55 "255.255.255.0" 3>&1 1>&2 2>&3) || exit 1

    GATEWAY=$(whiptail --title "Gateway" --inputbox \
        "Enter default gateway (router IP):\n(Example: 192.168.1.1)" \
        10 55 "192.168.1.1" 3>&1 1>&2 2>&3) || exit 1

    DNS=$(whiptail --title "DNS Server" --inputbox \
        "Enter DNS server IP:" \
        10 55 "8.8.8.8" 3>&1 1>&2 2>&3) || exit 1

    # Convert mask to CIDR prefix length
    cidr() {
        local mask=$1 bits=0
        IFS=. read -r a b c d <<< "$mask"
        for byte in $a $b $c $d; do
            for ((bit=7; bit>=0; bit--)); do
                (( (byte >> bit) & 1 )) && ((bits++)) || true
            done
        done
        echo $bits
    }
    PREFIX=$(cidr "$NETMASK")

    # Write netplan
    cat > /etc/netplan/00-aegisedr.yaml << NETPLAN
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses:
        - ${STATIC_IP}/${PREFIX}
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses: [${DNS}, 8.8.8.8]
NETPLAN
    chmod 600 /etc/netplan/00-aegisedr.yaml
    netplan apply 2>/dev/null || true
    sleep 2
    CONSOLE_IP="$STATIC_IP"

else
    # DHCP — wait for IP
    whiptail --title "AegisEDR" --infobox "Configuring DHCP on $IFACE...\nPlease wait." 7 45
    dhclient "$IFACE" 2>/dev/null || true
    sleep 3
    CONSOLE_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "unknown")
fi

# ── STEP 2: Hostname ──────────────────────────────────────────────────────────
HOSTNAME=$(whiptail --title "AegisEDR — Hostname" --inputbox \
    "Set the hostname for this server:" \
    10 55 "aegisedr" 3>&1 1>&2 2>&3) || HOSTNAME="aegisedr"

HOSTNAME=$(echo "$HOSTNAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
[ -z "$HOSTNAME" ] && HOSTNAME="aegisedr"
hostnamectl set-hostname "$HOSTNAME"
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

# ── STEP 3: Create Admin Account ──────────────────────────────────────────────
whiptail --title "AegisEDR — Admin Account" --msgbox \
    "Now create the administrator account\nfor the AegisEDR web console.\n\n(This is NOT a system account — only for the web UI)" \
    11 58

while true; do
    ADMIN_USER=$(whiptail --title "Admin Username" --inputbox \
        "Enter admin username for the web console:" \
        10 55 "admin" 3>&1 1>&2 2>&3) || exit 1

    # Validate username
    if [[ ! "$ADMIN_USER" =~ ^[a-zA-Z][a-zA-Z0-9_]{2,31}$ ]]; then
        whiptail --title "Invalid Username" --msgbox \
            "Username must:\n- Start with a letter\n- Be 3-32 characters\n- Only letters, numbers, underscore" \
            10 50
        continue
    fi
    break
done

while true; do
    ADMIN_PASS=$(whiptail --title "Admin Password" --passwordbox \
        "Enter password for '$ADMIN_USER':\n(minimum 8 characters)" \
        10 55 3>&1 1>&2 2>&3) || exit 1

    ADMIN_PASS2=$(whiptail --title "Confirm Password" --passwordbox \
        "Confirm password for '$ADMIN_USER':" \
        10 55 3>&1 1>&2 2>&3) || exit 1

    if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
        whiptail --title "Error" --msgbox "Passwords do not match. Try again." 8 45
        continue
    fi

    if [ ${#ADMIN_PASS} -lt 8 ]; then
        whiptail --title "Error" --msgbox "Password too short (minimum 8 characters)." 8 45
        continue
    fi
    break
done

# ── STEP 4: Apply configuration ───────────────────────────────────────────────
whiptail --title "AegisEDR" --infobox \
    "Applying configuration...\n\nPlease wait." 8 45

# Initialize DB and create admin user
python3 - << PYSETUP
import asyncio, sys
sys.path.insert(0, '/opt/aegisedr')
import bcrypt

async def setup():
    from core.database import init_db, get_db
    await init_db()
    db = await get_db()
    async with db:
        db.row_factory = __import__('aiosqlite').Row
        hashed = bcrypt.hashpw('${ADMIN_PASS}'.encode(), bcrypt.gensalt(12)).decode()
        # Remove default admin, create new one
        await db.execute("DELETE FROM users")
        await db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ('${ADMIN_USER}', hashed, 'admin')
        )
        await db.commit()
        print("DB: admin user created")

asyncio.run(setup())
PYSETUP

# Load YARA rules from files into DB
python3 - << 'YARALOAD'
import sys, os, re, sqlite3
sys.path.insert(0, '/opt/aegisedr')
db_path = os.environ.get('AEGISEDR_DB', '/opt/aegisedr/data/aegisedr.db')
yara_dir = os.environ.get('AEGISEDR_YARA', '/opt/aegisedr/yara_rules')
db = sqlite3.connect(db_path)
count = 0
for fname in os.listdir(yara_dir):
    if not fname.endswith('.yar'):
        continue
    category = fname.replace('.yar', '')
    content = open(os.path.join(yara_dir, fname)).read()
    for m in re.finditer(r'rule\s+(\w+)\s*\{', content):
        rule_name = m.group(1)
        start = m.start()
        depth = 0
        end = start
        for i, c in enumerate(content[start:]):
            if c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0: end = start + i + 1; break
        rule_text = content[start:end]
        desc = (re.search(r'description\s*=\s*"([^"]+)"', rule_text) or type('', (), {'group': lambda s,x: rule_name})()).group(1)
        try:
            db.execute("INSERT OR IGNORE INTO yara_rules (name, category, description, rule_content, enabled) VALUES (?,?,?,?,1)",
                       (rule_name, category, desc, rule_text))
            count += 1
        except Exception: pass
db.commit()
print(f"YARA: {count} rules loaded")
YARALOAD

# Update nginx server_name
sed -i "s/server_name _;/server_name $HOSTNAME $CONSOLE_IP _;/" \
    /etc/nginx/sites-available/aegisedr 2>/dev/null || true

# Start services
systemctl start aegisedr 2>/dev/null || true
sleep 2
systemctl reload nginx 2>/dev/null || true

# Update ClamAV signatures in background
freshclam --quiet &

# Mark as configured
touch "$DONE_FILE"

# ── STEP 5: Done! ─────────────────────────────────────────────────────────────
whiptail --title "AegisEDR — Setup Complete!" \
    --msgbox "
  AegisEDR is ready!

  Console URL : https://${CONSOLE_IP}
  Username    : ${ADMIN_USER}
  Password    : (as configured)

  Hostname    : ${HOSTNAME}
  Interface   : ${IFACE}

  To install agent on endpoints:
  https://${CONSOLE_IP}/endpoints

  Press OK to continue to login prompt." \
    20 60

clear
cat << READY

  ╔══════════════════════════════════════════════════╗
  ║         AegisEDR Security Console               ║
  ║              Setup Complete!                     ║
  ╠══════════════════════════════════════════════════╣
  ║                                                  ║
  ║  Console : https://${CONSOLE_IP}
  ║  Login   : ${ADMIN_USER}                         ║
  ║                                                  ║
  ║  Open a browser on your PC and go to:           ║
  ║  https://${CONSOLE_IP}                          ║
  ║                                                  ║
  ╚══════════════════════════════════════════════════╝

READY

# Disable this service so wizard doesn't run again
systemctl disable aegisedr-firstboot.service 2>/dev/null || true
