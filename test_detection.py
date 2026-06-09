"""
AegisEDR Detection Test Suite
Creates SAFE test files that trigger detection rules (NOT real malware).
Run this to verify AegisEDR detects threats correctly.
"""
import os
import sys
import time
import hashlib
import sqlite3
import random
import struct
import shutil

TEST_DIR   = r"C:\Users\Public\AegisEDR_Test"
DB_PATH    = r"C:\ProgramData\AegisEDR\aegisedr.db"

os.makedirs(TEST_DIR, exist_ok=True)

print("=" * 55)
print("  AegisEDR Detection Test Suite")
print("  All files are SAFE — trigger signatures only")
print("=" * 55)
print()

results = []

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

# ── Test 1: EICAR standard test file ─────────────────────────────────────────
print("[1/5] EICAR standard test file...")
eicar = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
eicar_path = os.path.join(TEST_DIR, "eicar_test.com")
with open(eicar_path, "wb") as f:
    f.write(eicar)
print(f"  Created: {eicar_path}")
print(f"  SHA256:  {sha256(eicar_path)}")
results.append(("EICAR test", eicar_path, "com"))

# ── Test 2: YARA ransomware trigger ───────────────────────────────────────────
print("\n[2/5] Ransomware YARA trigger (WannaCry + LockBit strings)...")
ransom_path = os.path.join(TEST_DIR, "test_ransomware_trigger.exe")
content = (
    b"MZ"                                       # PE header magic
    + b"\x00" * 58
    + b"WannaCrypt\x00"                          # WannaCry rule: $s1
    + b"@WanaDecryptor@\x00"                     # WannaCry rule: $s3
    + b"tasksche.exe\x00"                        # WannaCry rule: $s4
    + b"LockBit\x00"                             # LockBit rule: $s1
    + b"All of your files are stolen and encrypted\x00"  # LockBit ransom note
    + b"YOUR FILES ARE ENCRYPTED\x00"             # Generic ransom rule
    + b"HOW TO DECRYPT\x00"                      # Generic ransom rule
    + b"bitcoin\x00"                             # Generic ransom rule
    + b"\x00" * 512
)
with open(ransom_path, "wb") as f:
    f.write(content)
print(f"  Created: {ransom_path}")
print(f"  SHA256:  {sha256(ransom_path)}")
results.append(("Ransomware YARA trigger", ransom_path, "exe"))

# ── Test 3: YARA coinminer trigger ─────────────────────────────────────────────
print("\n[3/5] Coinminer YARA trigger (XMRig strings)...")
miner_path = os.path.join(TEST_DIR, "test_miner_trigger.exe")
content = (
    b"MZ"
    + b"\x00" * 58
    + b"stratum+tcp://pool.minexmr.com:4444\x00"  # Miner rule: $pool1 + $s1
    + b"xmrig\x00"                                 # Miner rule: $s3
    + b"--donate-level 1\x00"                      # Miner rule: $s7
    + b"cryptonight\x00"                           # Miner rule: $s6
    + b"\x00" * 512
)
with open(miner_path, "wb") as f:
    f.write(content)
print(f"  Created: {miner_path}")
print(f"  SHA256:  {sha256(miner_path)}")
results.append(("Coinminer YARA trigger", miner_path, "exe"))

# ── Test 4: High-entropy packed binary ────────────────────────────────────────
print("\n[4/5] High-entropy binary (packed/obfuscated detection)...")
entropy_path = os.path.join(TEST_DIR, "test_high_entropy.exe")
rng = random.Random(42)  # fixed seed = reproducible
random_bytes = bytes([rng.randint(0, 255) for _ in range(64 * 1024)])
with open(entropy_path, "wb") as f:
    f.write(b"MZ" + b"\x00" * 58 + random_bytes)
print(f"  Created: {entropy_path}")
print(f"  SHA256:  {sha256(entropy_path)}")

# Calculate entropy for display
freq = [0] * 256
for b in random_bytes:
    freq[b] += 1
import math
entropy = -sum((f/len(random_bytes)) * math.log2(f/len(random_bytes)) for f in freq if f)
print(f"  Entropy: {entropy:.2f} bits/byte  (threshold: 7.5)")
results.append(("High entropy binary", entropy_path, "exe"))

# ── Test 5: IoC hash match ─────────────────────────────────────────────────────
print("\n[5/5] IoC hash match test...")
ioc_path = os.path.join(TEST_DIR, "test_ioc_match.exe")
with open(ioc_path, "wb") as f:
    f.write(b"MZ\x00" * 64 + b"AegisEDR_IoC_Test_Payload_SAFE\x00")
ioc_hash = sha256(ioc_path)
print(f"  Created: {ioc_path}")
print(f"  SHA256:  {ioc_hash}")
print(f"  Adding hash to local IoC database...")

added = False
if os.path.isfile(DB_PATH):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("""
            INSERT OR REPLACE INTO ioc_hashes (hash, threat_name, severity)
            VALUES (?, ?, ?)
        """, (ioc_hash, "Test:IoC_Match_Simulation", "high"))
        conn.commit()
        conn.close()
        added = True
        print(f"  IoC hash added to DB.")
    except Exception as e:
        print(f"  DB error: {e}")
else:
    print(f"  DB not found at {DB_PATH} — start AegisEDR agent first.")

results.append(("IoC hash match", ioc_path, "exe"))

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("=" * 55)
print(f"  Test files created in: {TEST_DIR}")
print()
print("  What should happen in AegisEDR:")
print("  - 'Threats' tab should show 4-5 detections")
print("  - Critical/High severity threats")
print("  - Some may be auto-quarantined")
print()
print("  Test files:")
for name, path, _ in results:
    print(f"  [{name}]")
    print(f"    {os.path.basename(path)}")
print()
print("  NOTE: These are detection test strings only.")
print("  They contain NO executable code and are SAFE.")
print()
print("  To clean up after testing:")
print(f"  Run: Remove-Item '{TEST_DIR}' -Recurse -Force")
print("=" * 55)
print()

# ── Trigger realtime scan by touching the files ────────────────────────────────
print("Waiting 3 seconds for real-time agent to pick up files...")
time.sleep(3)

print("Queuing a scan via AegisEDR database...")
if os.path.isfile(DB_PATH):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute(
            "INSERT INTO scan_queue (scan_type, scan_path, status) VALUES ('custom', ?, 'pending')",
            (TEST_DIR,)
        )
        conn.commit()
        conn.close()
        print(f"Scan queued for: {TEST_DIR}")
        print("Open AegisEDR dashboard -> Scan tab to watch progress.")
    except Exception as e:
        print(f"Could not queue scan: {e}")
else:
    print(f"Agent DB not found. Start AegisEDR-Agent first, then run this script again.")
    print(f"OR open AegisEDR dashboard -> Scan -> Custom Scan -> {TEST_DIR}")
