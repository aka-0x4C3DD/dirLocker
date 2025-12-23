#!/bin/bash
set -e

# package_macos.sh - Create PKG package for macOS

VERSION="1.0.0"
APP_NAME="dirLocker"
DIST_DIR="dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"

echo "=== Packaging for macOS ==="

# 1. Build
echo "Building binaries..."
go build -o bin/dirlocker-gui ./cmd/gui

# 2. Create App Bundle Structure
echo "Creating App Bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# 3. Copy Binary
cp bin/dirlocker-gui "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

# 4. Create Info.plist (Basic)
cat > "$APP_BUNDLE/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>io.dirlocker.app</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
</dict>
</plist>
EOF

# 5. Build PKG
echo "Building .pkg installer..."
if command -v pkgbuild >/dev/null; then
    pkgbuild --root "$APP_BUNDLE" \
             --identifier "io.dirlocker.app" \
             --version "$VERSION" \
             --install-location "/Applications/$APP_NAME.app" \
             "$DIST_DIR/$APP_NAME.pkg"
    echo "Success! Package created at $DIST_DIR/$APP_NAME.pkg"
else
    echo "Warning: pkgbuild not found. Skipping .pkg generation."
    echo "App bundle is prepared at $APP_BUNDLE"
fi
