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
ifeq ($(IS_WINDOWS),1)
	cd vault-core; cargo build --release --target x86_64-pc-windows-gnu
else
	cd vault-core; cargo build --release
endif

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
	$(call print_step,Packaging for Windows (MSI + Bootstrapper))
ifeq ($(IS_WINDOWS),1)
	@if (-not (Test-Path dist)) { New-Item -ItemType Directory -Force -Path dist | Out-Null }
	@if (-not (Test-Path build/windows)) { New-Item -ItemType Directory -Force -Path build/windows | Out-Null }
	
	@Write-Host "Fetching dependencies..."
	@pwsh -File scripts/fetch_win_deps.ps1
	
	@if (Get-Command candle -ErrorAction SilentlyContinue) { \
		Write-Host "Compiling WiX installer..."; \
		candle -out dist/installer.wixobj build/windows/installer.wxs; \
		Write-Host "Linking MSI..."; \
		light -ext WixUIExtension -out dist/dirLocker.msi dist/installer.wixobj; \
		Write-Host "MSI Installer created at dist/dirLocker.msi" -ForegroundColor Green; \
		\
		Write-Host "Compiling Bootstrapper Bundle..."; \
		candle -ext WixBalExtension -out dist/bundle.wixobj build/windows/bundle.wxs; \
		Write-Host "Linking Bootstrapper..."; \
		light -ext WixBalExtension -out dist/dirLocker-setup.exe dist/bundle.wixobj; \
		Write-Host "Bootstrapper created at dist/dirLocker-setup.exe" -ForegroundColor Green; \
	} else { \
		Write-Host "Warning: WiX Toolset (candle/light) not found. Skipping MSI/Bundle generation."; \
	}
endif


package-linux: build-gui
	$(call print_step,Packaging for Linux (DEB + Dependencies))
	@if (Test-Path scripts/package_linux.sh) { \
		bash scripts/package_linux.sh; \
	} else { \
		Write-Host "Error: scripts/package_linux.sh not found" -ForegroundColor Red; \
	}

package-mac: build-gui
	$(call print_step,Packaging for macOS (PKG Preparation))
	@# First ensure standard .app structure is ready (from previous steps)
	@if (-not (Test-Path $(BINARY_DIR)/dirLocker.app/Contents/MacOS)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/dirLocker.app/Contents/MacOS | Out-Null }
	@if (-not (Test-Path $(BINARY_DIR)/dirLocker.app/Contents/Resources)) { New-Item -ItemType Directory -Force -Path $(BINARY_DIR)/dirLocker.app/Contents/Resources | Out-Null }
	@Copy-Item $(BINARY_DIR)/dirlocker-gui $(BINARY_DIR)/dirLocker.app/Contents/MacOS/dirLocker
	@if (Test-Path pkg/iconmanager/icon.icns) { Copy-Item pkg/iconmanager/icon.icns $(BINARY_DIR)/dirLocker.app/Contents/Resources/icon.icns }
	@# Run the helper script to prepare PKG logic
	@if (Test-Path scripts/package_macos.sh) { \
		bash scripts/package_macos.sh; \
	}

test: test-go test-rust

test-go: build-core
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
