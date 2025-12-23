$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

# Ensure we are at project root
if (!(Test-Path "vault-core")) {
    Write-Error "Please run this script from the project root directory."
    exit 1
}

# 1. Build
Write-Step "Building Binaries"
.\scripts\build.ps1

# 2. Check for WiX
if (!(Get-Command "candle" -ErrorAction SilentlyContinue) -or !(Get-Command "light" -ErrorAction SilentlyContinue)) {
    Write-Warning "WiX Toolset (candle.exe / light.exe) not found in PATH."
    Write-Warning "Please install WiX Toolset v3.11+ to generate MSI."
    Write-Warning "Download from: https://wixtoolset.org/releases/"
    exit 1
}

# 3. Generate MSI
Write-Step "Generating MSI Installer"

if (!(Test-Path "dist")) {
    New-Item -ItemType Directory -Path "dist" | Out-Null
}

try {
    # Compile
    candle.exe .\scripts\installer.wxs -out dist\installer.wixobj
    
    # Link
    light.exe -ext WixUIExtension -out dist\dirLocker.msi dist\installer.wixobj
    
    Write-Host "Success! Installer created at dist\dirLocker.msi" -ForegroundColor Green
}
catch {
    Write-Error "Failed to generate MSI: $_"
    exit 1
}
