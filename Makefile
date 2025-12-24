.PHONY: all build build-core build-cli build-gui test clean check check-tools

BINARY_DIR := bin
EXTENSION := 
SHELL_CMD := bash
IS_WINDOWS := 0

ifeq ($(OS),Windows_NT)
	EXTENSION := .exe
	IS_WINDOWS := 1
	# On Windows, try to use functionality available in Git Bash or similar
	SHELL_CMD := bash
else
	SHELL_CMD := sh
endif

# Colors for pretty output
cyan := \033[0;36m
green := \033[0;32m
reset := \033[0m

define print_step
	@echo -e "$(cyan)=== $(1) ===$(reset)"
endef

all: build

build: check-tools build-core build-cli build-gui
	@echo -e "$(green)Build Complete. Binaries are located in $(BINARY_DIR)/$(reset)"
	@ls -lh $(BINARY_DIR)

check-tools:
	$(call print_step,Checking Prerequisites)
	@command -v go >/dev/null 2>&1 || { echo >&2 "Go is required but not installed. Aborting."; exit 1; }
	@command -v cargo >/dev/null 2>&1 || { echo >&2 "Cargo is required but not installed. Aborting."; exit 1; }
	@mkdir -p $(BINARY_DIR)

build-core:
	$(call print_step,Building Rust Core)
	cd vault-core && cargo build --release

build-cli:
	$(call print_step,Building CLI Application)
	@mkdir -p $(BINARY_DIR)
	# CGO_ENABLED=1 is required for linking against the Rust core
	export CGO_ENABLED=1 && go build -o $(BINARY_DIR)/dirlocker-cli$(EXTENSION) ./cmd/cli

resources:
	$(call print_step,Generating Windows Resources)
ifeq ($(IS_WINDOWS),1)
	@command -v go-winres >/dev/null 2>&1 || { echo "Installing go-winres..."; go install github.com/tc-hib/go-winres@latest; }
	cd cmd/gui && go-winres make --in winres.json
endif

build-gui:
	$(call print_step,Building GUI Application with Wails)
	@mkdir -p $(BINARY_DIR)
	# Build using Wails
	cd cmd/gui && wails build -clean
	# Copy artifacts to bin directory
	@if [ -f cmd/gui/build/bin/gui.exe ]; then \
		cp cmd/gui/build/bin/gui.exe $(BINARY_DIR)/dirlocker-gui.exe; \
		echo "Copied Windows binary"; \
	fi
	@if [ -f cmd/gui/build/bin/gui ]; then \
		cp cmd/gui/build/bin/gui $(BINARY_DIR)/dirlocker-gui; \
		echo "Copied Unix binary"; \
	fi
	# Ensure icon exists for packaging
	@if [ -f cmd/gui/build/windows/icon.ico ]; then \
		cp cmd/gui/build/windows/icon.ico pkg/iconmanager/default_icon.ico; \
	fi

package-windows: build-gui
	$(call print_step,Packaging for Windows (MSI))
ifeq ($(IS_WINDOWS),1)
	@mkdir -p dist
	@mkdir -p build/windows
	@if command -v candle >/dev/null 2>&1; then \
		echo "Compiling WiX installer..."; \
		candle -out dist/installer.wixobj build/windows/installer.wxs; \
		echo "Linking MSI..."; \
		light -ext WixUIExtension -out dist/dirLocker.msi dist/installer.wixobj; \
		echo -e "$(green)MSI Installer created at dist/dirLocker.msi$(reset)"; \
	else \
		echo "Warning: WiX Toolset (candle/light) not found. Skipping MSI generation."; \
	fi
endif


package-linux: build-gui
	$(call print_step,Packaging for Linux)
	@mkdir -p $(BINARY_DIR)/linux/share/applications
	@mkdir -p $(BINARY_DIR)/linux/share/icons
	@cp $(BINARY_DIR)/dirlocker-gui $(BINARY_DIR)/linux/dirlocker-gui
	@cp pkg/iconmanager/icon.png $(BINARY_DIR)/linux/share/icons/dirlocker.png
	@echo "[Desktop Entry]" > $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Type=Application" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Name=dirLocker" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Comment=Secure Cross-Platform Vault" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Exec=/usr/local/bin/dirlocker-gui" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Icon=dirlocker" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Terminal=false" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo "Categories=Utility;Security;" >> $(BINARY_DIR)/linux/share/applications/dirlocker.desktop
	@echo -e "$(green)Linux package created in $(BINARY_DIR)/linux$(reset)"

package-mac: build-gui
	$(call print_step,Packaging for macOS)
	@mkdir -p $(BINARY_DIR)/dirLocker.app/Contents/MacOS
	@mkdir -p $(BINARY_DIR)/dirLocker.app/Contents/Resources
	@cp $(BINARY_DIR)/dirlocker-gui $(BINARY_DIR)/dirLocker.app/Contents/MacOS/dirLocker
	@if [ -f pkg/iconmanager/icon.icns ]; then \
		cp pkg/iconmanager/icon.icns $(BINARY_DIR)/dirLocker.app/Contents/Resources/icon.icns; \
	else \
		echo "Warning: icon.icns not found, using generic icon"; \
	fi
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '<plist version="1.0">' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '<dict>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>CFBundleExecutable</key>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>string>dirLocker</string>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>CFBundleIconFile</key>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>string>icon.icns</string>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>CFBundleIdentifier</key>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>string>com.aka-0x4c3dd.dirlocker</string>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>CFBundleName</key>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>string>dirLocker</string>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>CFBundlePackageType</key>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '    <key>string>APPL</string>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '</dict>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo '</plist>' >> $(BINARY_DIR)/dirLocker.app/Contents/Info.plist
	@echo -e "$(green)macOS App Bundle created in $(BINARY_DIR)/dirLocker.app$(reset)"

test: test-go test-rust

test-go:
	$(call print_step,Running Go Tests)
	export CGO_ENABLED=1 && go test -tags cgo -v ./pkg/... ./internal/... ./tests/...

test-rust:
	$(call print_step,Running Rust Tests)
	cd vault-core && cargo test

clean:
	$(call print_step,Cleaning Artifacts)
	rm -rf $(BINARY_DIR)
	cd vault-core && cargo clean

check:
	$(call print_step,Static Analysis)
	go vet ./...
	cd vault-core && cargo check
