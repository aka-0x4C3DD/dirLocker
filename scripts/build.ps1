$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Check-Command {
    param([string]$Name)
    if (!(Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Error "$Name is required but not found in PATH."
        exit 1
    }
}

# Check prerequisites
Check-Command "go"
Check-Command "cargo"

# Ensure bin directory exists
if (!(Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# 1. Build Rust Core
Write-Step "Building Rust Core (vault-core)"
Push-Location "vault-core"
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
} finally {
    Pop-Location
}

# 2. Build Go CLI
Write-Step "Building CLI Application"
$env:CGO_ENABLED = "1"
# Note: On Windows, we might need specific CGO flags depending on where the rust lib is compiled to
# For now, assuming standard linkage
go build -o bin/dirlocker-cli.exe ./cmd/cli
if ($LASTEXITCODE -ne 0) { Write-Error "CLI build failed"; exit 1 }

# 3. Build Go GUI
Write-Step "Building GUI Application"
go build -o bin/dirlocker-gui.exe ./cmd/gui
if ($LASTEXITCODE -ne 0) { Write-Error "GUI build failed"; exit 1 }

Write-Step "Build Complete"
Write-Host "Binaries are located in the bin/ directory." -ForegroundColor Green
Get-ChildItem -Path "bin" | Select-Object Name, Length, LastWriteTime
