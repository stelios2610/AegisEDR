/* AegisEDR — Anti-Ransomware YARA Rules */
/* Detects: LockBit, BlackCat/ALPHV, REvil, Conti, WannaCry, and generic patterns */

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware family"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "LockBit" wide ascii nocase
        $s2 = "lockbit" nocase
        $s3 = "Restore-My-Files.txt" nocase
        $s4 = "lockbit3.0" nocase
        $s5 = { 4C 6F 63 6B 42 69 74 } // "LockBit"
        $ext1 = ".lockbit" nocase
        $ext2 = ".lb3" nocase
        $ransom = "All of your files are stolen and encrypted" nocase
    condition:
        any of them
}

rule BlackCat_ALPHV {
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "ALPHV" wide ascii
        $s2 = "BlackCat" wide ascii nocase
        $s3 = "blackcat_" nocase
        $s4 = "RECOVER" wide ascii
        $s5 = ".alphv" nocase
        $rust = "panicked at" ascii  // Rust panic = BlackCat signature
        $note = "RECOVER-" wide ascii
    condition:
        (any of ($s*)) or ($rust and $note)
}

rule REvil_Sodinokibi {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "sodinokibi" nocase wide ascii
        $s2 = "REvil" wide ascii
        $s3 = "-readme.txt" nocase
        $s4 = "nssm.exe" nocase
        $key = "expand: 32-byte k" nocase
        $note = "Your files are encrypted" nocase
        $sk = { 72 61 6E 64 6F 6D 5F 73 65 65 64 } // "random_seed"
    condition:
        any of them
}

rule Conti_Ransomware {
    meta:
        description = "Detects Conti ransomware"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "CONTI_LOG.txt" nocase
        $s2 = "conti_v3" nocase
        $s3 = "ContiLocker" wide ascii
        $note1 = "readme.txt" nocase
        $note2 = "All your files" nocase
        $note3 = "Conti News" nocase
        $wipe = "vssadmin delete shadows" nocase
    condition:
        2 of them
}

rule WannaCry_EternalBlue {
    meta:
        description = "Detects WannaCry ransomware and EternalBlue exploit"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "WannaCrypt" wide ascii
        $s2 = "wncry" nocase wide ascii
        $s3 = "@WanaDecryptor@" wide ascii
        $s4 = "tasksche.exe" nocase
        $s5 = "mssecsvc.exe" nocase
        $smb = { 57 00 61 00 6E 00 61 00 43 00 72 00 79 00 } // "WanaCry"
        $kill = "MsWinZonesCacheCounterMutexA" wide ascii
    condition:
        any of them
}

rule Generic_Ransomware_Behavior {
    meta:
        description = "Generic ransomware behavioral patterns"
        author = "AegisEDR"
        severity = "critical"
        category = "ransomware"
    strings:
        $enc1 = "CryptEncrypt" wide ascii
        $enc2 = "BCryptEncrypt" wide ascii
        $enc3 = "AES_cbc_encrypt" wide ascii
        $vss1 = "vssadmin" nocase wide ascii
        $vss2 = "delete shadows" nocase wide ascii
        $vss3 = "wbadmin delete" nocase wide ascii
        $note1 = "YOUR FILES ARE ENCRYPTED" nocase wide ascii
        $note2 = "HOW TO DECRYPT" nocase wide ascii
        $note3 = "PAY THE RANSOM" nocase wide ascii
        $note4 = "bitcoin" nocase wide ascii
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypt" nocase
    condition:
        (any of ($enc*) and any of ($note*)) or
        (any of ($vss*) and any of ($note*)) or
        (2 of ($note*) and any of ($ext*))
}

rule Ransomware_Note_Patterns {
    meta:
        description = "Detects ransom note text patterns"
        author = "AegisEDR"
        severity = "high"
        category = "ransomware"
    strings:
        $n1 = "All your files have been encrypted" nocase
        $n2 = "Your personal files are encrypted" nocase
        $n3 = "To decrypt your files" nocase
        $n4 = "unique decryption key" nocase
        $n5 = "Bitcoin address" nocase wide ascii
        $n6 = "DO_NOT_MODIFY" nocase wide ascii
        $n7 = "DECRYPT_INSTRUCTIONS" nocase wide ascii
    condition:
        2 of them
}

rule Shadow_Copy_Deletion {
    meta:
        description = "Detects shadow copy deletion — a hallmark of ransomware"
        author = "AegisEDR"
        severity = "high"
        category = "ransomware"
    strings:
        $vss1 = "vssadmin.exe delete" nocase wide ascii
        $vss2 = "wmic shadowcopy delete" nocase wide ascii
        $vss3 = "Get-WmiObject Win32_ShadowCopy" nocase wide ascii
        $vss4 = "DisableVolumeSnapshots" nocase wide ascii
    condition:
        any of them
}
