#!/bin/bash
set -e

# package_linux.sh - Create DEB package for dirLocker

VERSION="1.0.0"
ARCH="amd64"
PACKAGE_NAME="dirlocker"
DIST_DIR="dist"
DEB_DIR="$DIST_DIR/$PACKAGE_NAME-$VERSION-$ARCH"

echo "=== Packaging for Linux ($ARCH) ==="

# 1. Build
echo "Building binaries..."
go build -o bin/dirlocker ./cmd/cli
go build -o bin/dirlocker-gui ./cmd/gui

# 2. Prepare Directory Structure
echo "Creating package structure..."
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/usr/bin"
mkdir -p "$DEB_DIR/usr/share/applications"
mkdir -p "$DEB_DIR/usr/share/icons/hicolor/512x512/apps"
mkdir -p "$DEB_DIR/DEBIAN"

# 3. Copy Binaries
cp bin/dirlocker "$DEB_DIR/usr/bin/"
cp bin/dirlocker-gui "$DEB_DIR/usr/bin/"

# 4. Create Control File
cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: dirLocker Team <team@dirlocker.io>
Description: Cross-platform encrypted file vault application
 dirLocker allows you to create secure, encrypted vaults for your files.
EOF

# 5. Create Desktop Entry
cat > "$DEB_DIR/usr/share/applications/dirlocker.desktop" << EOF
[Desktop Entry]
Name=dirLocker
Comment=Encrypted File Vault
Exec=/usr/bin/dirlocker-gui
Icon=dirlocker
Terminal=false
Type=Application
Categories=Utility;Security;
EOF

# 6. Build Package
echo "Building .deb package..."
if command -v dpkg-deb >/dev/null; then
    dpkg-deb --build "$DEB_DIR"
    echo "Success! Package created at $DIST_DIR/$PACKAGE_NAME-$VERSION-$ARCH.deb"
else
    echo "Warning: dpkg-deb not found. Skipping .deb generation."
    echo "Files are prepared in $DEB_DIR"
fi
