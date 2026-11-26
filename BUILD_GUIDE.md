# AegisEDR — Build Guide

## 1. ISO (Console Appliance)

Τρέξε σε Ubuntu 22.04 ή 24.04:

```bash
cd build/
sudo bash build_iso.sh
# Output: /tmp/aegisedr-iso-build/AegisEDR-1.0.0-amd64.iso
```

Boot το ISO σε Hyper-V / VMware → first-boot wizard → ρώτα IP + password.
Console: `https://<server-ip>/setup`  |  The one-time setup token is in `/opt/aegisedr/data/setup_token`. There is no default password.

---

## 2. Linux Agent (.deb)

```bash
cd agent/
# CONSOLE is https://<server>. ENROLL and the certificate SHA-256 come from the Deploy page.
sudo bash install_linux.sh https://CONSOLE ENROLLMENT_CODE CERT_SHA256
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

# Download install.ps1 from the console Deploy page. It asks for the console URL,
# an enrollment code, and the certificate SHA-256. It does not disable Defender.
# Output: dist/AegisEDR-Agent-Setup-v1.0.0.exe
```

Τρέξε το .exe σε Windows → wizard ρωτά Console URL → εγκαθίσταται ως Task.

---

## Adoption Flow

1. Agent εγκαθίσταται → συνδέεται στο console
2. Console → Endpoints → εμφανίζεται **⏳ Pending**
3. Admin πατάει **Adopt** → agent ενεργοποιείται
4. Αρχίζει real-time protection
