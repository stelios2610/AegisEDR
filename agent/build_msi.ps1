# AegisEDR Agent MSI Builder
# Installs WiX v4 if needed, then builds the .msi
# Usage: .\build_msi.ps1 -ConsoleUrl http://192.168.1.100:9000

param(
    [string]$ConsoleUrl = "http://CONSOLE_IP:9000"
)

$ErrorActionPreference = "Stop"
$Root    = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $Root "dist"
$AgentDir = $PSScriptRoot

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     AegisEDR Agent MSI Builder               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# ── Step 1: Generate icons/assets ────────────────────────────────────────────
Write-Host "[1/5] Generating assets..." -ForegroundColor Yellow
try {
    python "$Root\assets\generate_assets.py"
    Write-Host "  ✓ Assets generated" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Asset generation skipped (pip install cairosvg Pillow)" -ForegroundColor Yellow
}

# ── Step 2: Build Agent EXE with PyInstaller ─────────────────────────────────
Write-Host ""
Write-Host "[2/5] Building AegisEDR-Agent.exe..." -ForegroundColor Yellow

$icon = if (Test-Path "$Root\assets\icon.ico") { "--icon=$Root\assets\icon.ico" } else { $null }
$pyiArgs = @(
    "--onefile", "--noconsole",
    "--name=AegisEDR-Agent",
    "--distpath=$DistDir",
    "--workpath=$DistDir\_tmp",
    "--specpath=$DistDir",
    "--noconfirm",
    "--hidden-import=watchdog.observers.winapi",
    "--hidden-import=psutil"
)
if ($icon) { $pyiArgs += $icon }
$pyiArgs += "$AgentDir\agent_windows.py"

pyinstaller @pyiArgs
if ($LASTEXITCODE -ne 0) { Write-Host "✗ PyInstaller failed." -ForegroundColor Red; exit 1 }
Write-Host "  ✓ AegisEDR-Agent.exe" -ForegroundColor Green

# ── Step 3: Build Tray EXE ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/5] Building AegisEDR-Tray.exe..." -ForegroundColor Yellow
$trayArgs = @(
    "--onefile", "--noconsole",
    "--name=AegisEDR-Tray",
    "--distpath=$DistDir",
    "--workpath=$DistDir\_tmp",
    "--specpath=$DistDir",
    "--noconfirm",
    "--hidden-import=pystray._win32"
)
if ($icon) { $trayArgs += $icon }
$trayArgs += "$AgentDir\tray_windows.py"

pyinstaller @trayArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠ Tray build failed (pip install pystray Pillow)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ AegisEDR-Tray.exe" -ForegroundColor Green
}

# ── Step 3b: Build App (GUI Console) EXE ────────────────────────────────────
Write-Host ""
Write-Host "[3b] Building AegisEDR.exe (dashboard UI)..." -ForegroundColor Yellow
$appArgs = @(
    "--onefile", "--noconsole",
    "--name=AegisEDR",
    "--distpath=$DistDir",
    "--workpath=$DistDir\_tmp",
    "--specpath=$DistDir",
    "--noconfirm",
    "--hidden-import=customtkinter",
    "--hidden-import=PIL._tkinter_finder",
    "--collect-all=customtkinter"
)
if ($icon) { $appArgs += $icon }
$appArgs += "$AgentDir\app_windows.py"

pyinstaller @appArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ⚠ App build failed (pip install customtkinter pillow)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ AegisEDR.exe" -ForegroundColor Green
}

# ── Step 4: Install WiX v4 if needed ─────────────────────────────────────────
Write-Host ""
Write-Host "[4/5] Checking WiX Toolset..." -ForegroundColor Yellow

$wix = Get-Command "wix" -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "  WiX not found — installing via dotnet tool..." -ForegroundColor Yellow

    $dotnet = Get-Command "dotnet" -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Host "  Installing .NET SDK..." -ForegroundColor Yellow
        winget install Microsoft.DotNet.SDK.8 --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }

    dotnet tool install --global wix
    $env:Path = "$env:USERPROFILE\.dotnet\tools;" + $env:Path
    Write-Host "  ✓ WiX v4 installed" -ForegroundColor Green
} else {
    Write-Host "  ✓ WiX found: $(wix --version)" -ForegroundColor Green
}

# ── Step 5: Build MSI ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/5] Building MSI installer..." -ForegroundColor Yellow

$msiOutput = Join-Path $DistDir "AegisEDR-Agent-1.0.0-x64.msi"

Set-Location $AgentDir

wix build AegisEDR_Agent.wxs `
    -o $msiOutput `
    -d "ConsoleUrl=$ConsoleUrl" `
    -arch x64 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ WiX build failed." -ForegroundColor Red
    exit 1
}

$size = [math]::Round((Get-Item $msiOutput).Length / 1MB, 1)

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ✓ MSI built successfully!                  ║" -ForegroundColor Green
Write-Host "║                                              ║" -ForegroundColor Green
Write-Host "║   File: AegisEDR-Agent-1.0.0-x64.msi        ║" -ForegroundColor Green
Write-Host "║   Size: $size MB" -ForegroundColor Green
Write-Host "║                                              ║" -ForegroundColor Green
Write-Host "║   Distribute and run on any Windows 10/11   ║" -ForegroundColor Green
Write-Host "║   system to install the AegisEDR Agent.     ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Green

Start-Process explorer.exe $DistDir
