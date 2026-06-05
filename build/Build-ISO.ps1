# AegisEDR ISO Builder — Windows PowerShell script
# Requirements: Docker Desktop installed and running
# Usage: .\Build-ISO.ps1

param(
    [switch]$NoBuildCache
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$OutputDir   = Join-Path $ProjectRoot "dist"
$ISOName     = "AegisEDR-1.0.0-amd64.iso"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     AegisEDR ISO Builder for Windows         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Docker
try {
    $dockerVersion = docker version --format "{{.Server.Version}}" 2>$null
    Write-Host "✓ Docker found: v$dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker Desktop not found or not running." -ForegroundColor Red
    Write-Host "  Install from: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# Create output dir
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host ""
Write-Host "[1/3] Building Docker image (includes Ubuntu ISO download)..." -ForegroundColor Yellow
Write-Host "      This may take 10-20 minutes on first run." -ForegroundColor Gray

$buildArgs = @("build", "-f", "build\Dockerfile", "-t", "aegisedr-iso-builder", ".")
if ($NoBuildCache) { $buildArgs += "--no-cache" }

Set-Location $ProjectRoot
docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Docker build failed." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Building ISO inside Docker container..." -ForegroundColor Yellow

docker run --rm `
    -v "${OutputDir}:/output" `
    --name aegisedr-iso-build `
    aegisedr-iso-builder

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ ISO build failed. Check Docker logs." -ForegroundColor Red
    exit 1
}

# Verify output
$ISOPath = Join-Path $OutputDir $ISOName
if (Test-Path $ISOPath) {
    $size = (Get-Item $ISOPath).Length / 1GB
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║   ✓ ISO built successfully!                  ║" -ForegroundColor Green
    Write-Host "║                                              ║" -ForegroundColor Green
    Write-Host "║   File: $ISOName" -ForegroundColor Green
    Write-Host ("║   Size: {0:F1} GB" -f $size) -ForegroundColor Green
    Write-Host "║                                              ║" -ForegroundColor Green
    Write-Host "║   Location: $OutputDir" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "[3/3] Opening output folder..." -ForegroundColor Yellow
    Start-Process explorer.exe $OutputDir
} else {
    Write-Host "✗ ISO file not found in output directory." -ForegroundColor Red
    exit 1
}
