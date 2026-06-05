# AegisEDR — Build Guide

## 1. ISO (Console Appliance)

Τρέξε σε Ubuntu 22.04 ή 24.04:

```bash
cd build/
sudo bash build_iso.sh
# Output: /tmp/aegisedr-iso-build/AegisEDR-1.0.0-amd64.iso
```

Boot το ISO σε Hyper-V / VMware → first-boot wizard → ρώτα IP + password.
Console: `https://<server-ip>`  |  Login: `admin / [your password]`

---

## 2. Linux Agent (.deb)

```bash
cd agent/
bash build_linux_deb.sh http://CONSOLE_IP:9000
# Output: dist/aegisedr-agent_1.0.0_amd64.deb
```

Install σε endpoint:
```bash
sudo dpkg -i aegisedr-agent_1.0.0_amd64.deb
```

---

## 3. Windows Agent (.exe installer)

```bash
# Πρώτα install: pip install pyinstaller
# Και: Inno Setup 6 από https://jrsoftware.org/isdl.php

python agent/build_windows_installer.py http://CONSOLE_IP:9000
# Output: dist/AegisEDR-Agent-Setup-v1.0.0.exe
```

Τρέξε το .exe σε Windows → wizard ρωτά Console URL → εγκαθίσταται ως Task.

---

## Adoption Flow

1. Agent εγκαθίσταται → συνδέεται στο console
2. Console → Endpoints → εμφανίζεται **⏳ Pending**
3. Admin πατάει **Adopt** → agent ενεργοποιείται
4. Αρχίζει real-time protection
