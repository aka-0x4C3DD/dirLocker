@echo off
REM Build script for Windows filesystem daemons

echo Building dirLocker Windows filesystem daemons...

REM Set build flags
set CGO_ENABLED=1

echo Building Windows Dokany daemon...
go build -tags "windows" -o dirlocker-dokany.exe ./cmd/dokany
if %ERRORLEVEL% neq 0 (
    echo Failed to build Dokany daemon
    exit /b 1
)
echo ✓ Built dirlocker-dokany.exe

echo Building Windows WinFSP daemon...
go build -tags "windows" -o dirlocker-winfsp.exe ./cmd/winfsp
if %ERRORLEVEL% neq 0 (
    echo Failed to build WinFSP daemon
    exit /b 1
)
echo ✓ Built dirlocker-winfsp.exe

echo Build complete!
echo.
echo Usage:
echo   dirlocker-dokany.exe --vault ^<vault-file^> --drive ^<drive-letter^>
echo   dirlocker-winfsp.exe --vault ^<vault-file^> --drive ^<drive-letter^>