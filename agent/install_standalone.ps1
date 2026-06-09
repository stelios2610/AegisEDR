# AegisEDR Standalone Installer
# No central console required - all data stored locally
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_standalone.ps1

$AgentDir    = "C:\Program Files\AegisEDR"
$DataDir     = "C:\ProgramData\AegisEDR"
$RulesDir    = "$DataDir\rules"
$QuarDir     = "$DataDir\Quarantine"
$AgentTask   = "AegisEDRAgent"
$TrayTask    = "AegisEDRTray"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  AegisEDR Standalone Installer v2.0" -ForegroundColor Cyan
Write-Host "  Local protection - no server needed" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "[1/7] Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $AgentDir  | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir   | Out-Null
New-Item -ItemType Directory -Force -Path $RulesDir  | Out-Null
New-Item -ItemType Directory -Force -Path $QuarDir   | Out-Null
Write-Host "  OK" -ForegroundColor Green

Write-Host "[2/7] Checking Python..." -ForegroundColor Yellow
$pythonExe = $null

# Check for existing Python (avoid Windows Store stub)
$candidates = @(
    (Get-Command python -ErrorAction SilentlyContinue).Source,
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe"
)
foreach ($c in $candidates) {
    if ($c -and (Test-Path $c) -and $c -notlike "*WindowsApps*") {
        $pythonExe = $c
        break
    }
}
if (-not $pythonExe) {
    # Search common install locations
    $found = Get-ChildItem "C:\Users\$env:USERNAME\AppData\Local\Programs\Python" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $pythonExe = $found.FullName }
}
if (-not $pythonExe) {
    Write-Host "  Python not found - downloading Python 3.12..." -ForegroundColor Yellow
    $pyUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    $pyInst = "$env:TEMP\python_installer.exe"
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyInst -UseBasicParsing
    Start-Process -Wait -FilePath $pyInst -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1"
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}
Write-Host "  Python: $pythonExe" -ForegroundColor Green

Write-Host "[3/7] Installing Python packages..." -ForegroundColor Yellow
& $pythonExe -m pip install -q --upgrade pip
& $pythonExe -m pip install -q watchdog psutil yara-python customtkinter pillow pystray
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Warning: some packages may have failed, retrying without yara-python..." -ForegroundColor Yellow
    & $pythonExe -m pip install -q watchdog psutil customtkinter pillow pystray
}
Write-Host "  OK" -ForegroundColor Green

Write-Host "[4/7] Copying agent files..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$filesToCopy = @(
    "agent_standalone.py",
    "app_standalone.py",
    "tray_standalone.py"
)
foreach ($f in $filesToCopy) {
    $src = Join-Path $scriptDir $f
    if (Test-Path $src) {
        Copy-Item $src "$AgentDir\$f" -Force
        Write-Host "  Copied: $f" -ForegroundColor Gray
    } else {
        Write-Host "  WARNING: $f not found at $src" -ForegroundColor Yellow
    }
}

# Copy YARA rules
$rulesSource = Join-Path (Split-Path $scriptDir -Parent) "yara_rules"
if (Test-Path $rulesSource) {
    Copy-Item "$rulesSource\*.yar" $RulesDir -Force -ErrorAction SilentlyContinue
    Write-Host "  YARA rules copied to $RulesDir" -ForegroundColor Gray
} else {
    Write-Host "  Warning: YARA rules not found at $rulesSource" -ForegroundColor Yellow
}
Write-Host "  OK" -ForegroundColor Green

Write-Host "[5/7] Disabling Windows Defender..." -ForegroundColor Yellow
try {
    $policyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $rtpKey    = "$policyKey\Real-Time Protection"
    $spyKey    = "$policyKey\Spynet"
    New-Item -Path $policyKey -Force | Out-Null
    New-Item -Path $rtpKey    -Force | Out-Null
    New-Item -Path $spyKey    -Force | Out-Null
    Set-ItemProperty -Path $policyKey -Name "DisableAntiSpyware"         -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $policyKey -Name "DisableAntiVirus"            -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtpKey    -Name "DisableRealtimeMonitoring"   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtpKey    -Name "DisableIOAVProtection"       -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtpKey    -Name "DisableBehaviorMonitoring"   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtpKey    -Name "DisableOnAccessProtection"   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $spyKey    -Name "SpynetReporting"             -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $spyKey    -Name "SubmitSamplesConsent"        -Value 2 -Type DWord -Force
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $AgentDir  -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $DataDir   -ErrorAction SilentlyContinue
    Write-Host "  Defender disabled via Group Policy. Reboot for full effect." -ForegroundColor Green
} catch {
    Write-Host "  Warning: $_" -ForegroundColor Yellow
}

Write-Host "[6/7] Registering scheduled tasks..." -ForegroundColor Yellow

# Agent task (SYSTEM, runs at startup, restarts on failure)
$agentAction    = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$AgentDir\agent_standalone.py`"" -WorkingDirectory $AgentDir
$agentTrigger   = New-ScheduledTaskTrigger -AtStartup
$agentSettings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$agentPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $AgentTask -Action $agentAction -Trigger $agentTrigger -Settings $agentSettings -Principal $agentPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
Write-Host "  Agent task registered (SYSTEM, auto-restart)" -ForegroundColor Green

# Tray task (all users, at logon)
$trayAction    = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$AgentDir\tray_standalone.py`"" -WorkingDirectory $AgentDir
$trayTrigger   = New-ScheduledTaskTrigger -AtLogOn
$traySettings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
$trayPrincipal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
Register-ScheduledTask -TaskName $TrayTask -Action $trayAction -Trigger $trayTrigger -Settings $traySettings -Principal $trayPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $TrayTask -ErrorAction SilentlyContinue
Write-Host "  Tray task registered (all users, at logon)" -ForegroundColor Green

Write-Host "[7/7] Creating shortcuts..." -ForegroundColor Yellow
$wshell = New-Object -comObject WScript.Shell
# Desktop shortcut
$desktop = [System.Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcut = $wshell.CreateShortcut("$desktop\AegisEDR.lnk")
$shortcut.TargetPath      = $pythonExe
$shortcut.Arguments       = "`"$AgentDir\app_standalone.py`""
$shortcut.WorkingDirectory = $AgentDir
$shortcut.Description     = "AegisEDR Security Dashboard"
$shortcut.Save()
Write-Host "  Desktop shortcut created" -ForegroundColor Green

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  AegisEDR installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Agent:  Running as SYSTEM service" -ForegroundColor White
Write-Host "  Tray:   Auto-starts at logon" -ForegroundColor White
Write-Host "  Data:   $DataDir" -ForegroundColor White
Write-Host "  Logs:   $DataDir\agent.log" -ForegroundColor White
Write-Host ""
Write-Host "  NOTE: Reboot recommended for Defender" -ForegroundColor Yellow
Write-Host "        to fully disable." -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Green
