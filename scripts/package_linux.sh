#!/bin/bash
set -e

# Configuration
APP_NAME="dirlocker"
VERSION="1.0.0"
ARCH="amd64"
BIN_DIR="bin"
LINUX_DIR="$BIN_DIR/linux"
DEB_DIR="$BIN_DIR/deb"
RPM_DIR="$BIN_DIR/rpm"

echo "=== Packaging for Linux (Seamless Dependency Management) ==="

# Ensure directories exist
mkdir -p "$DEB_DIR/$APP_NAME/DEBIAN"
mkdir -p "$DEB_DIR/$APP_NAME/usr/local/bin"
mkdir -p "$DEB_DIR/$APP_NAME/usr/share/applications"
mkdir -p "$DEB_DIR/$APP_NAME/usr/share/icons/hicolor/512x512/apps"

# Copy binary
cp "$LINUX_DIR/dirlocker-gui" "$DEB_DIR/$APP_NAME/usr/local/bin/$APP_NAME"
chmod 755 "$DEB_DIR/$APP_NAME/usr/local/bin/$APP_NAME"

# Copy Icon
cp "pkg/iconmanager/icon.png" "$DEB_DIR/$APP_NAME/usr/share/icons/hicolor/512x512/apps/$APP_NAME.png"

# Create Desktop Entry
cat <<EOF > "$DEB_DIR/$APP_NAME/usr/share/applications/$APP_NAME.desktop"
[Desktop Entry]
Type=Application
Name=dirLocker
Comment=Secure Cross-Platform Vault
Exec=/usr/local/bin/$APP_NAME
Icon=$APP_NAME
Terminal=false
Categories=Utility;Security;
EOF

# --- DEBIAN CONTROL FILE (The "Seamless" Magic) ---
# Depends: fuse3 (for mounting), libwebkit2gtk-4.0-37 (for Wails GUI)
cat <<EOF > "$DEB_DIR/$APP_NAME/DEBIAN/control"
Package: $APP_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: fuse3, libwebkit2gtk-4.0-37, libgtk-3-0
Maintainer: dirLocker Team <team@dirlocker.io>
Description: Secure Cross-Platform Vault
 dirLocker provides plausible deniability and strong encryption for your sensitive files.
EOF

# Build .deb
dpkg-deb --build "$DEB_DIR/$APP_NAME" "$BIN_DIR/${APP_NAME}_${VERSION}_${ARCH}.deb"
echo "✅ DEB package created at $BIN_DIR/${APP_NAME}_${VERSION}_${ARCH}.deb"

# Note: RPM generation usually requires 'rpmbuild' or 'fpm'. 
# We'll skip complex RPM logic here but note that 'alien' can convert .deb to .rpm if needed.
