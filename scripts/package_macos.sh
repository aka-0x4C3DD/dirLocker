#!/bin/bash
set -e

APP_NAME="dirLocker"
VERSION="1.0.0"
BIN_DIR="bin"
APP_BUNDLE="$BIN_DIR/$APP_NAME.app"
PKG_DIR="$BIN_DIR/pkg_root"
SCRIPTS_DIR="$BIN_DIR/scripts"

echo "=== Packaging for macOS (Seamless Dependency Check) ==="

# 1. Structure Preparation (Already done by Makefile, but ensuring clean slate for pkg)
mkdir -p "$PKG_DIR/usr/local/bin"
mkdir -p "$SCRIPTS_DIR"

# 2. Create Pre-install Script (The "Seamless" Check)
# This script runs before installation. It checks for macFUSE.
cat <<EOF > "$SCRIPTS_DIR/preinstall"
#!/bin/bash
# Check for macFUSE
if [ ! -d "/Library/Frameworks/macFUSE.framework" ] && [ ! -f "/usr/local/lib/libfuse.dylib" ]; then
    osascript -e 'display dialog "dirLocker requires macFUSE to mount vaults.\n\nPlease install macFUSE from osxfuse.github.io" buttons {"OK"} default button "OK" with icon stop'
    exit 1
fi
exit 0
EOF
chmod +x "$SCRIPTS_DIR/preinstall"

# 3. Build the Component Package
# Note: In a real environment, we'd use 'pkgbuild'
echo "Generating component package structure..."
# We assume 'pkgbuild' is available on macOS build runners.
# constructing command string for reference/execution
PKG_CMD="pkgbuild --root \"$APP_BUNDLE\" --install-location \"/Applications/$APP_NAME.app\" --scripts \"$SCRIPTS_DIR\" \"$BIN_DIR/$APP_NAME.pkg\""

echo "To build the final PKG on macOS, run:"
echo "$PKG_CMD"

# Since we are on Windows/Cross-platform environment, we'll write this command to a helper script
echo "$PKG_CMD" > "$BIN_DIR/build_pkg.sh"
chmod +x "$BIN_DIR/build_pkg.sh"

echo "✅ macOS Packaging logic prepared. Run 'bin/build_pkg.sh' on a macOS machine."
