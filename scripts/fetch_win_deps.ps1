$ErrorActionPreference = "Stop"

$DepsDir = "build/windows"
If (-not (Test-Path $DepsDir)) {
    New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
}

$WinFspUrl = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
$WinFspPath = Join-Path $DepsDir "winfsp.msi"

if (-not (Test-Path $WinFspPath)) {
    Write-Host "Downloading WinFSP installer..."
    Invoke-WebRequest -Uri $WinFspUrl -OutFile $WinFspPath
    Write-Host "Downloaded WinFSP."
} else {
    Write-Host "WinFSP installer already present."
}

# WebView2
$WebView2Url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
$WebView2Path = Join-Path $DepsDir "MicrosoftEdgeWebview2Setup.exe"

if (-not (Test-Path $WebView2Path)) {
    Write-Host "Downloading WebView2 Bootstrapper..."
    # Note: The link redirects. Invoke-WebRequest handles redirects.
    Invoke-WebRequest -Uri $WebView2Url -OutFile $WebView2Path
    Write-Host "Downloaded WebView2 Bootstrapper."
} else {
    Write-Host "WebView2 Bootstrapper already present."
}
