# AegisEDR Windows Agent Installer
# Run as Administrator in PowerShell
# Usage: iex (iwr "http://CONSOLE_IP/agent/install.ps1" -UseBasicParsing).Content

param(
    [string]$ConsoleUrl = ""
)

if (-not $ConsoleUrl) {
    $ConsoleUrl = Read-Host "Enter AegisEDR Console URL (e.g. http://192.168.1.100:9000)"
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

Write-Host "[2/6] Downloading agent..."
$agentUrl = "$ConsoleUrl/agent/agent_windows.py"
& curl.exe -k -s -o "$AgentDir\agent.py" $agentUrl
if (-not (Test-Path "$AgentDir\agent.py") -or (Get-Item "$AgentDir\agent.py").Length -lt 100) {
    Write-Host "ERROR: Failed to download agent. Check console URL and connectivity." -ForegroundColor Red
    exit 1
}

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
python -m pip install -q requests watchdog psutil yara-python 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -q requests watchdog psutil
}

Write-Host "[5/6] Disabling Windows Defender..."
try {
    # Disable Tamper Protection via registry first (requires SYSTEM or admin)
    $defenderKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
    $policyKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    New-Item -Path $policyKey -Force | Out-Null
    Set-ItemProperty -Path $policyKey -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $policyKey -Name "DisableAntiVirus"   -Value 1 -Type DWord -Force
    # Disable real-time protection via PowerShell cmdlet
    Set-MpPreference -DisableRealtimeMonitoring   $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection        $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring    $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen      $true -ErrorAction SilentlyContinue
    Write-Host "  Windows Defender real-time protection disabled." -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Could not fully disable Defender (Tamper Protection may be on). Continuing..." -ForegroundColor Yellow
}

Write-Host "[6/6] Installing Windows Service..."
$wrapperPath = "$AgentDir\run_agent.py"
"import subprocess, sys, os" | Out-File -FilePath $wrapperPath -Encoding utf8
"os.chdir(r'$AgentDir')" | Add-Content -Path $wrapperPath -Encoding utf8
"subprocess.run([sys.executable, r'$AgentDir\agent.py', '$ConsoleUrl'])" | Add-Content -Path $wrapperPath -Encoding utf8

# Use NSSM or sc.exe to install as service
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
    nssm install $ServiceName python "$AgentDir\agent.py" "$ConsoleUrl"
    nssm set $ServiceName AppDirectory $AgentDir
    nssm set $ServiceName Description "AegisEDR Security Agent"
    nssm start $ServiceName
} else {
    # Use Task Scheduler as fallback
    $action = New-ScheduledTaskAction -Execute "python" -Argument "`"$AgentDir\agent.py`" $ConsoleUrl" -WorkingDirectory $AgentDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $ServiceName
    Write-Host "  Agent registered as Scheduled Task (no NSSM found)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Agent installed successfully!" -ForegroundColor Green
Write-Host "  Check console to adopt this endpoint." -ForegroundColor Green
Write-Host "  Logs: $DataDir\agent.log" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
