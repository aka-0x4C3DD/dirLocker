#!/bin/bash

# Build script for FUSE filesystem daemons

set -e

echo "Building dirLocker FUSE filesystem daemons..."

# Set build flags
export CGO_ENABLED=1

# Build Linux FUSE daemon
if [[ "$GOOS" == "linux" || (-z "$GOOS" && "$(uname -s)" == "Linux") ]]; then
    echo "Building Linux FUSE daemon..."
    go build -tags "linux" -o dirlocker-fuse ./cmd/fuse
    echo "✓ Built dirlocker-fuse for Linux"
fi

# Build macOS FUSE daemon
if [[ "$GOOS" == "darwin" || (-z "$GOOS" && "$(uname -s)" == "Darwin") ]]; then
    echo "Building macOS FUSE daemon..."
    go build -tags "darwin" -o dirlocker-fuse ./cmd/fuse
    echo "✓ Built dirlocker-fuse for macOS"
fi

# Build Windows filesystem daemons
if [[ "$GOOS" == "windows" || (-z "$GOOS" && "$(uname -s)" == "MINGW"*) ]]; then
    echo "Building Windows Dokany daemon..."
    go build -tags "windows" -o dirlocker-dokany.exe ./cmd/dokany
    echo "✓ Built dirlocker-dokany.exe for Windows"
    
    echo "Building Windows WinFSP daemon..."
    go build -tags "windows" -o dirlocker-winfsp.exe ./cmd/winfsp
    echo "✓ Built dirlocker-winfsp.exe for Windows"
fi

echo "Build complete!"
echo ""
echo "Usage:"
echo "  Linux/macOS: ./dirlocker-fuse --vault <vault-file> --mountpoint <mount-point>"
echo "  Windows:     dirlocker-dokany.exe --vault <vault-file> --drive <drive-letter>"
echo "               dirlocker-winfsp.exe --vault <vault-file> --drive <drive-letter>"