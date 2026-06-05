# AegisEDR Windows — Full Build Script
# Builds: AegisEDR-Agent.exe + AegisEDR-Tray.exe + Setup installer
# Requirements: pip install pyinstaller pystray Pillow cairosvg
#               Inno Setup 6 installed

param(
    [string]$ConsoleUrl = "http://CONSOLE_IP:9000"
)

$ErrorActionPreference = "Stop"
$Root     = Split-Path -Parent $PSScriptRoot
$AgentDir = $PSScriptRoot
$DistDir  = Join-Path $Root "dist"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   AegisEDR Windows Full Build                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# Step 1: Generate assets (logo PNG, icon.ico)
Write-Host "[1/4] Generating logo and icons..." -ForegroundColor Yellow
python "$Root\assets\generate_assets.py"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠ Asset generation failed (cairosvg missing?)" -ForegroundColor Yellow
    Write-Host "  Run: pip install cairosvg Pillow" -ForegroundColor Gray
}

# Step 2: Build Agent EXE
Write-Host ""
Write-Host "[2/4] Building AegisEDR-Agent.exe..." -ForegroundColor Yellow
$icon = if (Test-Path "$Root\assets\icon.ico") { "--icon=$Root\assets\icon.ico" } else { "" }

$pyiArgs = @(
    "--onefile",
    "--noconsole",
    "--name=AegisEDR-Agent",
    "--distpath=$DistDir",
    "--workpath=$DistDir\_build_tmp",
    "--specpath=$DistDir",
    "--noconfirm",
    "--hidden-import=watchdog.observers.winapi",
    "--hidden-import=psutil",
    "--add-data=$Root\yara_rules;yara_rules"
)
if ($icon) { $pyiArgs += $icon }
$pyiArgs += "$AgentDir\agent_windows.py"

pyinstaller @pyiArgs
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Agent build failed." -ForegroundColor Red; exit 1 }
Write-Host "✓ AegisEDR-Agent.exe" -ForegroundColor Green

# Step 3: Build Tray EXE
Write-Host ""
Write-Host "[3/4] Building AegisEDR-Tray.exe..." -ForegroundColor Yellow

$trayArgs = @(
    "--onefile",
    "--noconsole",
    "--name=AegisEDR-Tray",
    "--distpath=$DistDir",
    "--workpath=$DistDir\_build_tmp",
    "--specpath=$DistDir",
    "--noconfirm",
    "--hidden-import=pystray._win32"
)
if ($icon) { $trayArgs += $icon }
$trayArgs += "$AgentDir\tray_windows.py"

pyinstaller @trayArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠ Tray build failed (pystray missing?)" -ForegroundColor Yellow
    Write-Host "  Run: pip install pystray Pillow" -ForegroundColor Gray
} else {
    Write-Host "✓ AegisEDR-Tray.exe" -ForegroundColor Green
}

# Step 4: Build Installer
Write-Host ""
Write-Host "[4/4] Building Windows Installer with Inno Setup..." -ForegroundColor Yellow

$inno = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $inno)) {
    Write-Host "  ✗ Inno Setup not found." -ForegroundColor Red
    Write-Host "  Download: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "  Then run: & '$inno' '$AgentDir\AegisEDR_Agent.iss'" -ForegroundColor Gray
    exit 0
}

& $inno "$AgentDir\AegisEDR_Agent.iss"
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Installer build failed." -ForegroundColor Red; exit 1 }

$installer = Get-ChildItem "$DistDir\AegisEDR-Agent-Setup-*.exe" | Select-Object -Last 1
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ✓ Build complete!                          ║" -ForegroundColor Green
Write-Host "║                                              ║" -ForegroundColor Green
Write-Host "║   Installer: $($installer.Name)" -ForegroundColor Green
Write-Host "║   Location:  $DistDir" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Start-Process explorer.exe $DistDir
