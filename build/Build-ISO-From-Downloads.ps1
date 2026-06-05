# AegisEDR ISO Builder
# Χτίζει το AegisEDR-1.0.0-amd64.iso χρησιμοποιώντας Docker Desktop ή WSL2
# Χρησιμοποιεί το ubuntu ISO από τα Downloads
#
# Χρήση: .\Build-ISO-From-Downloads.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistDir     = Join-Path $ProjectRoot "dist"
$OutputISO   = Join-Path $DistDir "AegisEDR-1.0.0-amd64.iso"

# Find Ubuntu ISO in Downloads
$UbuntuISO = Get-ChildItem "$env:USERPROFILE\Downloads" -Filter "ubuntu-*.iso" |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 1

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  AegisEDR ISO Builder" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

if (-not $UbuntuISO) {
    Write-Host ""
    Write-Host "ERROR: Ubuntu ISO not found in Downloads." -ForegroundColor Red
    Write-Host "Download from: https://ubuntu.com/download/server" -ForegroundColor Yellow
    exit 1
}

$isoSizeGB = [math]::Round($UbuntuISO.Length / 1GB, 1)
Write-Host ""
Write-Host "Ubuntu ISO : $($UbuntuISO.Name) ($isoSizeGB GB)" -ForegroundColor Green
Write-Host "Output     : AegisEDR-1.0.0-amd64.iso" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# ── Check Docker ──────────────────────────────────────────────────────────────
$useDocker = $false
$useWSL    = $false

try {
    $v = docker version --format "{{.Server.Version}}" 2>$null
    if ($v) { $useDocker = $true; Write-Host "Builder    : Docker v$v" -ForegroundColor Green }
} catch {}

if (-not $useDocker) {
    # Try WSL2
    $wslDistros = wsl --list --quiet 2>$null | Where-Object { $_ -match "Ubuntu" }
    if ($wslDistros) {
        $useWSL = $true
        Write-Host "Builder    : WSL2 ($($wslDistros | Select-Object -First 1))" -ForegroundColor Green
    }
}

if (-not $useDocker -and -not $useWSL) {
    Write-Host ""
    Write-Host "ERROR: Neither Docker Desktop nor WSL2 Ubuntu found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Option A — Install Docker Desktop:" -ForegroundColor Yellow
    Write-Host "  https://www.docker.com/products/docker-desktop" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Option B — Install WSL2 Ubuntu (run as Admin):" -ForegroundColor Yellow
    Write-Host "  wsl --install -d Ubuntu" -ForegroundColor Gray
    exit 1
}

Write-Host ""
Write-Host "Building ISO..." -ForegroundColor Yellow
Write-Host "(This takes 5-15 minutes)" -ForegroundColor Gray
Write-Host ""

# ── Build via Docker ──────────────────────────────────────────────────────────
if ($useDocker) {
    Write-Host "[1/3] Building Docker image..." -ForegroundColor Yellow
    Set-Location $ProjectRoot
    docker build -f "build\Dockerfile.iso" -t aegisedr-iso-builder . --quiet
    if ($LASTEXITCODE -ne 0) { Write-Host "Docker build failed." -ForegroundColor Red; exit 1 }

    Write-Host "[2/3] Running ISO builder..." -ForegroundColor Yellow
    docker run --rm `
        -v "$($UbuntuISO.FullName):/ubuntu.iso:ro" `
        -v "${ProjectRoot}:/aegisedr:ro" `
        -v "${DistDir}:/output" `
        aegisedr-iso-builder

    if ($LASTEXITCODE -ne 0) { Write-Host "ISO build failed." -ForegroundColor Red; exit 1 }
}

# ── Build via WSL2 ────────────────────────────────────────────────────────────
if ($useWSL -and -not $useDocker) {
    Write-Host "[1/3] Installing build tools in WSL2..." -ForegroundColor Yellow

    # Convert Windows paths to WSL paths
    $wslISO     = wsl wslpath -u $($UbuntuISO.FullName.Replace('\','/'))
    $wslProject = wsl wslpath -u $($ProjectRoot.Replace('\','/'))
    $wslOutput  = wsl wslpath -u $($DistDir.Replace('\','/'))

    $wslScript = @"
set -e
apt-get update -qq
apt-get install -y xorriso p7zip-full rsync 2>/dev/null
mkdir -p $wslOutput
export UBUNTU_ISO=$wslISO
ln -sf $wslISO /ubuntu.iso 2>/dev/null || true
cp -f $wslISO /ubuntu.iso 2>/dev/null || ln -sf $wslISO /ubuntu.iso
ln -sf $wslProject /aegisedr 2>/dev/null || true
OUTPUT_DIR=$wslOutput bash $wslProject/build/build_iso_from_existing.sh
"@

    Write-Host "[2/3] Running ISO builder in WSL2..." -ForegroundColor Yellow
    wsl -u root bash -c $wslScript

    if ($LASTEXITCODE -ne 0) { Write-Host "ISO build failed." -ForegroundColor Red; exit 1 }
}

# ── Verify output ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/3] Verifying output..." -ForegroundColor Yellow

if (Test-Path $OutputISO) {
    $sizeGB = [math]::Round((Get-Item $OutputISO).Length / 1GB, 2)
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  ISO ready!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  AegisEDR-1.0.0-amd64.iso" -ForegroundColor White
    Write-Host "  Size: $sizeGB GB" -ForegroundColor White
    Write-Host "  Path: $DistDir" -ForegroundColor White
    Write-Host ""
    Write-Host "  Οδηγίες χρήσης:" -ForegroundColor Cyan
    Write-Host "  1. Δημιούργησε νέο VM σε Hyper-V ή VMware" -ForegroundColor Gray
    Write-Host "  2. Βάλε το ISO ως CD/DVD boot drive" -ForegroundColor Gray
    Write-Host "  3. Boot -> αυτόματη εγκατάσταση Ubuntu" -ForegroundColor Gray
    Write-Host "  4. Μετά την εγκατάσταση: wizard για IP + user" -ForegroundColor Gray
    Write-Host "  5. Console: https://<server-ip>" -ForegroundColor Gray
    Write-Host "=============================================" -ForegroundColor Green

    # Open output folder
    Start-Process explorer.exe $DistDir
} else {
    Write-Host "ERROR: ISO file not found in output." -ForegroundColor Red
    exit 1
}
