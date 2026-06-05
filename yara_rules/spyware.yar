/* AegisEDR — Anti-Spyware YARA Rules */
/* Detects: Predator, Pegasus, FinFisher, commercial spyware families */

rule Predator_Spyware_Indicators {
    meta:
        description = "Detects Predator spyware (Intellexa/Cytrox) indicators"
        author = "AegisEDR"
        severity = "critical"
        category = "spyware"
    strings:
        $s1 = "intellexa" nocase wide ascii
        $s2 = "cytrox" nocase wide ascii
        $s3 = "predator.exe" nocase wide ascii
        $s4 = "/predator/" nocase wide ascii
        $s5 = "alien_install" nocase wide ascii
        $s6 = { 50 72 65 64 61 74 6F 72 }  // "Predator"
        $net1 = "predator-c2" nocase
        $net2 = "/alien/agent" nocase
    condition:
        any of ($s*) or any of ($net*)
}

rule Pegasus_NSO_Indicators {
    meta:
        description = "Detects NSO Group Pegasus spyware indicators"
        author = "AegisEDR"
        severity = "critical"
        category = "spyware"
    strings:
        $s1 = "pegasus" nocase wide ascii
        $s2 = "NSO Group" wide ascii
        $s3 = "bh_agent" nocase
        $s4 = "stagefright" nocase
        $s5 = "/sms/pegasus" nocase
        $b1 = { 67 75 61 72 64 69 61 6E } // "guardian"
        $url1 = "peg1.drivehq.com" nocase
        $url2 = "peg2.drivehq.com" nocase
    condition:
        any of them
}

rule FinFisher_FinSpy {
    meta:
        description = "Detects FinFisher / FinSpy commercial surveillance software"
        author = "AegisEDR"
        severity = "critical"
        category = "spyware"
    strings:
        $s1 = "FinFisher" wide ascii
        $s2 = "FinSpy" wide ascii
        $s3 = "Gamma Group" wide ascii
        $s4 = "finfisher" nocase
        $s5 = { 46 69 6E 46 69 73 68 65 72 } // "FinFisher"
        $s6 = "WINVNC_LICENSE" wide ascii
        $pdb = "\\FinSpy\\" nocase
    condition:
        any of them
}

rule Generic_Keylogger {
    meta:
        description = "Detects generic keylogger behavior patterns"
        author = "AegisEDR"
        severity = "high"
        category = "spyware"
    strings:
        $api1 = "SetWindowsHookEx" wide ascii
        $api2 = "GetAsyncKeyState" wide ascii
        $api3 = "GetKeyboardState" wide ascii
        $api4 = "GetForegroundWindow" wide ascii
        $file1 = "keylog" nocase wide ascii
        $file2 = "keystroke" nocase wide ascii
        $file3 = "keystrokes.txt" nocase
    condition:
        (2 of ($api*)) and (any of ($file*))
}

rule Screen_Capture_Spyware {
    meta:
        description = "Detects unauthorized screen capture / surveillance tools"
        author = "AegisEDR"
        severity = "high"
        category = "spyware"
    strings:
        $api1 = "BitBlt" wide ascii
        $api2 = "GetDC" wide ascii
        $api3 = "CreateCompatibleBitmap" wide ascii
        $s1 = "screenshot" nocase wide ascii
        $s2 = "screencapture" nocase wide ascii
        $s3 = "capturescreen" nocase wide ascii
        $s4 = "printscreen" nocase wide ascii
    condition:
        (2 of ($api*)) and (any of ($s*))
}

rule Microphone_Camera_Access {
    meta:
        description = "Detects unauthorized microphone/camera access"
        author = "AegisEDR"
        severity = "high"
        category = "spyware"
    strings:
        $cam1 = "VideoCaptureDevice" wide ascii
        $cam2 = "IMediaControl" wide ascii
        $cam3 = "capCreateCaptureWindow" wide ascii
        $mic1 = "waveInOpen" wide ascii
        $mic2 = "AudioCapture" wide ascii
        $mic3 = "IMMDeviceEnumerator" wide ascii
        $sus = "recording" nocase wide ascii
    condition:
        (any of ($cam*) or any of ($mic*)) and $sus
}

rule Data_Exfiltration_Spyware {
    meta:
        description = "Detects data exfiltration patterns common in spyware"
        author = "AegisEDR"
        severity = "high"
        category = "spyware"
    strings:
        $e1 = "exfil" nocase wide ascii
        $e2 = "uploadData" nocase wide ascii
        $e3 = "sendFile" nocase wide ascii
        $enc1 = "base64_encode" nocase wide ascii
        $enc2 = "AES_encrypt" nocase wide ascii
        $c2 = "C2_SERVER" nocase wide ascii
        $c2b = "command_and_control" nocase wide ascii
    condition:
        (any of ($e*)) and (any of ($enc*) or any of ($c2*))
}
