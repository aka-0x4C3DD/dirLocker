.PHONY: all build build-core build-cli build-gui test clean check check-tools

SHELL := pwsh.exe
.SHELLFLAGS := -NoProfile -Command

BINARY_DIR := bin
EXTENSION := 
IS_WINDOWS := 0

ifeq ($(OS),Windows_NT)
	EXTENSION := .exe
	IS_WINDOWS := 1
endif

# Colors for pretty output
cyan := \033[0;36m
green := \033[0;32m
reset := \033[0m

define print_step
	@Write-Host "=== $(1) ===" -ForegroundColor Cyan
endef

all: build

build: check-tools build-core build-cli build-gui
	@Write-Host "Build Complete. Binaries are located in $(BINARY_DIR)/" -ForegroundColor Green
	@Get-ChildItem -Path $(BINARY_DIR) | Select-Object Name, Length, LastWriteTime


check-tools:
	$(call print_step,Checking Prerequisites)
	@if (-not (Get-Command go -ErrorAction SilentlyContinue)) { echo "Go is required but not installed. Aborting."; exit 1 }
	@if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { echo "Cargo is required but not installed. Aborting."; exit 1 }
	@if (-not (Test-Path $(BINARY_DIR))) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR) | Out-Null }

build-core:
	$(call print_step,Building Rust Core)
	cd vault-core; cargo build --release

build-cli:
	$(call print_step,Building CLI Application)
	@if (-not (Test-Path $(BINARY_DIR))) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR) | Out-Null }
	# CGO_ENABLED=1 is required for linking against the Rust core
	$env:CGO_ENABLED=1; go build -o $(BINARY_DIR)/dirlocker-cli$(EXTENSION) ./cmd/cli

resources:
	$(call print_step,Generating Windows Resources)
ifeq ($(IS_WINDOWS),1)
	@if (-not (Get-Command go-winres -ErrorAction SilentlyContinue)) { echo "Installing go-winres..."; go install github.com/tc-hib/go-winres@latest }
	cd cmd/gui; go-winres make --in winres.json
endif

build-gui:
	$(call print_step,Building GUI Application with Wails)
	@if (-not (Test-Path $(BINARY_DIR))) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR) | Out-Null }
	
	# Generate Icons
	@Write-Host "Generating Icons..." -ForegroundColor Cyan
	go run scripts/resize_icon.go

	# Build using Wails
	cd cmd/gui; wails build -clean
	# Copy artifacts to bin directory
	@if (Test-Path cmd/gui/build/bin/gui.exe) { Copy-Item cmd/gui/build/bin/gui.exe -Destination $(BINARY_DIR)/dirlocker-gui.exe; echo "Copied Windows binary" }
	@if (Test-Path cmd/gui/build/bin/gui) { Copy-Item cmd/gui/build/bin/gui -Destination $(BINARY_DIR)/dirlocker-gui; echo "Copied Unix binary" }
	# Ensure icon exists for packaging
	@if (Test-Path cmd/gui/build/windows/icon.ico) { Copy-Item cmd/gui/build/windows/icon.ico -Destination pkg/iconmanager/default_icon.ico }

package-windows: build-gui
	$(call print_step,Packaging for Windows (MSI))
ifeq ($(IS_WINDOWS),1)
	@if (-not (Test-Path dist)) { New-Item -ItemType Directory -Force -Path dist | Out-Null }
	@if (-not (Test-Path build/windows)) { New-Item -ItemType Directory -Force -Path build/windows | Out-Null }
	@if (Get-Command candle -ErrorAction SilentlyContinue) { \
		Write-Host "Compiling WiX installer..."; \
		candle -out dist/installer.wixobj build/windows/installer.wxs; \
		Write-Host "Linking MSI..."; \
		light -ext WixUIExtension -out dist/dirLocker.msi dist/installer.wixobj; \
		Write-Host "MSI Installer created at dist/dirLocker.msi" -ForegroundColor Green; \
	} else { \
		Write-Host "Warning: WiX Toolset (candle/light) not found. Skipping MSI generation."; \
	}
endif


package-linux: build-gui
	$(call print_step,Packaging for Linux)
	@if (-not (Test-Path $(BINARY_DIR)/linux/share/applications)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/linux/share/applications | Out-Null }
	@if (-not (Test-Path $(BINARY_DIR)/linux/share/icons)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/linux/share/icons | Out-Null }
	@Copy-Item $(BINARY_DIR)/dirlocker-gui $(BINARY_DIR)/linux/dirlocker-gui
	@Copy-Item pkg/iconmanager/icon.png $(BINARY_DIR)/linux/share/icons/dirlocker.png
	@Set-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "[Desktop Entry]"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Type=Application"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Name=dirLocker"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Comment=Secure Cross-Platform Vault"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Exec=/usr/local/bin/dirlocker-gui"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Icon=dirlocker"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Terminal=false"
	@Add-Content -Path $(BINARY_DIR)/linux/share/applications/dirlocker.desktop -Value "Categories=Utility;Security;"
	@Write-Host "Linux package created in $(BINARY_DIR)/linux" -ForegroundColor Green

package-mac: build-gui
	$(call print_step,Packaging for macOS)
	@if (-not (Test-Path $(BINARY_DIR)/dirLocker.app/Contents/MacOS)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/dirLocker.app/Contents/MacOS | Out-Null }
	@if (-not (Test-Path $(BINARY_DIR)/dirLocker.app/Contents/Resources)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/dirLocker.app/Contents/Resources | Out-Null }
	@Copy-Item $(BINARY_DIR)/dirlocker-gui $(BINARY_DIR)/dirLocker.app/Contents/MacOS/dirLocker
	@if (Test-Path pkg/iconmanager/icon.icns) {
		Copy-Item pkg/iconmanager/icon.icns $(BINARY_DIR)/dirLocker.app/Contents/Resources/icon.icns
	} else {
		Write-Host "Warning: icon.icns not found, using generic icon"
	}
	@Set-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '<?xml version="1.0" encoding="UTF-8"?>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '<plist version="1.0">'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '<dict>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>CFBundleExecutable</key>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>string>dirLocker</string>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>CFBundleIconFile</key>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>string>icon.icns</string>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>CFBundleIdentifier</key>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>string>com.aka-0x4c3dd.dirlocker</string>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>CFBundleName</key>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>string>dirLocker</string>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>CFBundlePackageType</key>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '    <key>string>APPL</string>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '</dict>'
	@Add-Content -Path $(BINARY_DIR)/dirLocker.app/Contents/Info.plist -Value '</plist>'
	@Write-Host "macOS App Bundle created in $(BINARY_DIR)/dirLocker.app" -ForegroundColor Green

test: test-go test-rust

test-go:
	$(call print_step,Running Go Tests)
	$env:CGO_ENABLED=1; go test -tags cgo -v ./pkg/... ./internal/... ./tests/...

test-rust:
	$(call print_step,Running Rust Tests)
	cd vault-core; cargo test

clean:
	$(call print_step,Cleaning Artifacts)
	@if (Test-Path $(BINARY_DIR)) { Remove-Item -Recurse -Force $(BINARY_DIR) }
	cd vault-core; cargo clean

check:
	$(call print_step,Static Analysis)
	go vet ./...
	cd vault-core; cargo check
