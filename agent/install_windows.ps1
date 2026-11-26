# AegisEDR Windows Agent Installer
# Run as Administrator in PowerShell
# Usage: iex (iwr "http://CONSOLE_IP/agent/install.ps1" -UseBasicParsing).Content

param(
    [string]$ConsoleUrl = "",
    [string]$EnrollmentCode = "",
    [string]$CertSha256 = ""
)

if (-not $ConsoleUrl) {
    $ConsoleUrl = Read-Host "Enter AegisEDR Console URL (https://console)"
}
if (-not $EnrollmentCode) {
    $EnrollmentCode = Read-Host "Enter the enrollment code from the console Deploy page"
}

$AgentDir = "C:\Program Files\AegisEDR"
$DataDir  = "C:\ProgramData\AegisEDR"
$ServiceName = "AegisEDRAgent"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AegisEDR Windows Agent Installer" -ForegroundColor Cyan
Write-Host "  Console: $ConsoleUrl" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "[1/6] Creating directories..."
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir\Quarantine" | Out-Null

Write-Host "[2/6] Pinning the console certificate and downloading the agent..."
$curlCa = @()
$caPath = Join-Path $DataDir "console.pem"
if ($ConsoleUrl -like "https://*") {
    if (-not $CertSha256) {
        Write-Host "ERROR: HTTPS requires the certificate SHA-256 from the Deploy page." -ForegroundColor Red
        exit 1
    }
    & curl.exe -k -fsSL -o $caPath "$ConsoleUrl/api/ca"
    $actual = (Get-FileHash -Algorithm SHA256 $caPath).Hash.ToLower()
    if ($actual -ne $CertSha256.ToLower()) {
        Write-Host "ERROR: Console certificate does not match the expected SHA-256." -ForegroundColor Red
        exit 1
    }
    $curlCa = @("--cacert", $caPath)
}
& curl.exe @curlCa -fsSL -o "$AgentDir\agent.py" "$ConsoleUrl/agent/agent_windows.py"
& curl.exe @curlCa -fsSL -o "$AgentDir\edr_common.py" "$ConsoleUrl/agent/edr_common.py"
& curl.exe @curlCa -fsSL -o "$AgentDir\app_windows.py" "$ConsoleUrl/agent/app_windows.py"
& curl.exe @curlCa -fsSL -o "$AgentDir\tray_windows.py" "$ConsoleUrl/agent/tray_windows.py"
if (-not (Test-Path "$AgentDir\agent.py") -or (Get-Item "$AgentDir\agent.py").Length -lt 100) {
    Write-Host "ERROR: Failed to download agent. Check console URL and connectivity." -ForegroundColor Red
    exit 1
}
$cfg = @{ console_url = $ConsoleUrl; enrollment_code = $EnrollmentCode }
if (Test-Path $caPath) { $cfg.ca_cert = $caPath }
$json = $cfg | ConvertTo-Json
[System.IO.File]::WriteAllText((Join-Path $DataDir "config.json"), $json, (New-Object System.Text.UTF8Encoding $false))

Write-Host "[3/6] Checking Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  Python not found - downloading installer..." -ForegroundColor Yellow
    $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python_installer.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
    Start-Process -Wait -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1"
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

Write-Host "[4/6] Installing Python packages..."
python -m pip install -q requests watchdog psutil customtkinter pillow yara-python 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -q requests watchdog psutil customtkinter pillow
}

Write-Host "[5/6] Installing the agent service and tray. Windows Defender is left enabled."
$wrapperPath = "$AgentDir\run_agent.py"
"import subprocess, sys, os" | Out-File -FilePath $wrapperPath -Encoding utf8
"os.chdir(r'$AgentDir')" | Add-Content -Path $wrapperPath -Encoding utf8
"subprocess.run([sys.executable, r'$AgentDir\agent.py', '$ConsoleUrl'])" | Add-Content -Path $wrapperPath -Encoding utf8

# Detect Python executable path (avoid Windows Store stub)
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if ($pythonExe -like "*WindowsApps*") {
    # Find real python
    $pythonExe = Get-ChildItem "C:\Users\$env:USERNAME\AppData\Local\Programs\Python" -Recurse -Filter "python.exe" -ErrorAction SilentlyContinue |
                 Select-Object -First 1 -ExpandProperty FullName
    if (-not $pythonExe) {
        $pythonExe = Get-ChildItem "C:\Python*" -Filter "python.exe" -ErrorAction SilentlyContinue |
                     Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $pythonExe) { $pythonExe = "python" }
Write-Host "  Using Python: $pythonExe" -ForegroundColor Gray

# Background agent task (runs as SYSTEM)
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
    nssm install $ServiceName $pythonExe "$AgentDir\agent.py $ConsoleUrl"
    nssm set $ServiceName AppDirectory $AgentDir
    nssm set $ServiceName Description "AegisEDR Security Agent"
    nssm start $ServiceName
} else {
    $action    = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$AgentDir\agent.py`" $ConsoleUrl" -WorkingDirectory $AgentDir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $ServiceName
    Write-Host "  Agent registered as Scheduled Task (SYSTEM)" -ForegroundColor Yellow
}

# Tray icon task - runs when user logs in (not SYSTEM, so tray is visible)
$trayTask = "AegisEDRTray"
$trayAction = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$AgentDir\tray_windows.py`"" -WorkingDirectory $AgentDir
$trayTrigger = New-ScheduledTaskTrigger -AtLogOn
$traySettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
$trayPrincipal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
Register-ScheduledTask -TaskName $trayTask -Action $trayAction -Trigger $trayTrigger -Settings $traySettings -Principal $trayPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $trayTask
Write-Host "  Tray registered for current and future logons." -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Agent installed successfully!" -ForegroundColor Green
Write-Host "  Check console to adopt this endpoint." -ForegroundColor Green
Write-Host "  Logs: $DataDir\agent.log" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
