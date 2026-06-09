# AegisEDR Standalone Build Script
# Builds 3 executables + MSI installer
# Run from: agent\ folder

$ErrorActionPreference = "Stop"
$Root     = Split-Path $PSScriptRoot -Parent
$AgentDir = $PSScriptRoot
$DistDir  = Join-Path $Root "dist_standalone"
$YaraRules = Join-Path $Root "yara_rules"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  AegisEDR Standalone Builder" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check PyInstaller
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python -or $python -like "*WindowsApps*") {
    Write-Host "ERROR: Python not found in PATH" -ForegroundColor Red
    exit 1
}

& $python -m PyInstaller --version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing PyInstaller..." -ForegroundColor Yellow
    & $python -m pip install -q pyinstaller
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# ── Step 1: Build AegisEDR-Agent.exe ──────────────────────────────────────────
Write-Host "[1/4] Building AegisEDR-Agent.exe..." -ForegroundColor Yellow
Push-Location $AgentDir
& $python -m PyInstaller `
    --onefile --noconsole `
    --name "AegisEDR-Agent" `
    --add-data "$YaraRules;yara_rules" `
    agent_standalone.py
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR building agent" -ForegroundColor Red; exit 1 }
Pop-Location

Copy-Item "$AgentDir\dist\AegisEDR-Agent.exe" "$DistDir\" -Force
Write-Host "  OK: AegisEDR-Agent.exe" -ForegroundColor Green

# ── Step 2: Build AegisEDR.exe (UI) ──────────────────────────────────────────
Write-Host "[2/4] Building AegisEDR.exe (dashboard UI)..." -ForegroundColor Yellow
Push-Location $AgentDir
& $python -m PyInstaller `
    --onefile --noconsole `
    --name "AegisEDR" `
    --collect-all customtkinter `
    app_standalone.py
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR building app" -ForegroundColor Red; exit 1 }
Pop-Location

Copy-Item "$AgentDir\dist\AegisEDR.exe" "$DistDir\" -Force
Write-Host "  OK: AegisEDR.exe" -ForegroundColor Green

# ── Step 3: Build AegisEDR-Tray.exe ──────────────────────────────────────────
Write-Host "[3/4] Building AegisEDR-Tray.exe..." -ForegroundColor Yellow
Push-Location $AgentDir
& $python -m PyInstaller `
    --onefile --noconsole `
    --name "AegisEDR-Tray" `
    tray_standalone.py
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR building tray" -ForegroundColor Red; exit 1 }
Pop-Location

Copy-Item "$AgentDir\dist\AegisEDR-Tray.exe" "$DistDir\" -Force
Write-Host "  OK: AegisEDR-Tray.exe" -ForegroundColor Green

# ── Step 4: Build MSI ─────────────────────────────────────────────────────────
Write-Host "[4/4] Building MSI installer..." -ForegroundColor Yellow

# Check WiX
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "  Installing WiX Toolset..." -ForegroundColor Yellow
    & dotnet tool install --global wix
    $env:Path += ";$env:USERPROFILE\.dotnet\tools"
}

$wxsPath = Join-Path $AgentDir "AegisEDR_Standalone.wxs"
$msiOut  = Join-Path $DistDir "AegisEDR-Standalone-2.0.0-x64.msi"

Push-Location $AgentDir
wix build $wxsPath `
    -d "DistDir=$DistDir" `
    -d "YaraRulesDir=$YaraRules" `
    -o $msiOut
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: MSI build failed. Executables are ready in $DistDir" -ForegroundColor Yellow
} else {
    Write-Host "  OK: $msiOut" -ForegroundColor Green
}
Pop-Location

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Output folder: $DistDir" -ForegroundColor White
$exes = Get-ChildItem $DistDir -Filter "*.exe" | ForEach-Object { "  $($_.Name)  ($([math]::Round($_.Length/1MB,1)) MB)" }
$exes | ForEach-Object { Write-Host $_ -ForegroundColor White }
$msi = Get-ChildItem $DistDir -Filter "*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($msi) {
    Write-Host "  $($msi.Name)  ($([math]::Round($msi.Length/1MB,1)) MB)" -ForegroundColor Cyan
}
Write-Host "======================================" -ForegroundColor Green
