# Technology Stack

## Core Architecture
- **Rust Core Library** (`vault-core/`): Cryptographic operations and vault management with C FFI
- **Go Application Layer** (`cmd/`, `pkg/`, `internal/`): CLI/GUI applications with full CGO integration
- **Python Tooling** (`tools/`): Development tools and MCP integration

## Languages & Frameworks
- **Rust**: Core cryptographic library with C FFI exports (MinGW compatible on Windows)
- **Go 1.24**: Application layer with Cobra CLI and Qt GUI (CGO enabled)
- **Python 3.13+**: Tooling with FastMCP and MCP CLI support

## Key Dependencies

### Rust (vault-core)
- **Cryptography**: aes-gcm, chacha20poly1305, argon2, x25519-dalek, hkdf
- **Serialization**: serde, serde_json
- **Utilities**: uuid, chrono, thiserror, base64, hex, getrandom
- **FFI**: libc for C compatibility

### Go
- **CLI Framework**: github.com/spf13/cobra, github.com/spf13/viper
- **Logging**: github.com/sirupsen/logrus
- **Testing**: github.com/stretchr/testify
- **File Hiding**: github.com/google/uuid, golang.org/x/crypto
- **Terminal**: golang.org/x/term

### Python
- **MCP Integration**: fastmcp, mcp[cli]

## Build System

### Production Build (CGO Enabled - Default)
```bash
# Build Rust core first (Windows MinGW target)
cd vault-core
cargo build --release --target x86_64-pc-windows-gnu

# Build Go applications with CGO (Windows)
cd ..
set CGO_ENABLED=1
go build -o dirlocker-cli.exe ./cmd/cli

# Linux/macOS
cd vault-core
cargo build --release

cd ..
export CGO_ENABLED=1
go build -o dirlocker ./cmd/cli
```

### Development Build (CGO Disabled - Stub Mode)
```bash
export CGO_ENABLED=0
go build -o dirlocker ./cmd/cli
```

### Testing
```bash
# Run Go tests with CGO enabled (full functionality)
set CGO_ENABLED=1
go test ./pkg/vault
go test ./pkg/filehider
go test ./tests -run TestCLI

# Run Rust tests
cd vault-core
cargo test

# Run integration tests
go test ./tests/ffi_integration_test.go

# Python development
cd tools
uv sync
uv run python main.py
```

### Common Commands
```bash
# Clean builds
go clean
cargo clean

# Format code
go fmt ./...
cargo fmt

# Lint code
go vet ./...
cargo clippy

# Generate documentation
go doc ./...
cargo doc --open

# Verify CGO integration
set CGO_ENABLED=1 && go build ./cmd/cli
```

## CGO Integration Status ✅

### Windows Toolchain Compatibility
- **Rust Target**: `x86_64-pc-windows-gnu` (MinGW compatible)
- **Go CGO**: Uses MinGW GCC toolchain
- **Library Path**: `vault-core/target/x86_64-pc-windows-gnu/release/libvault_core.a`
- **Linking**: Static linking with Windows system libraries

### Crypto Implementation
- **AES-256-GCM**: Pure Rust `aes-gcm` crate
- **XChaCha20-Poly1305**: Pure Rust `chacha20poly1305` crate (replaced libsodium)
- **Key Derivation**: `argon2` and `hkdf` crates
- **No C Dependencies**: Eliminates cross-compilation issues

### Verified Functionality
- ✅ Vault creation and opening
- ✅ File encryption/decryption
- ✅ Password management
- ✅ Recovery key generation
- ✅ Secure sharing with X25519
- ✅ File hiding system
- ✅ CLI integration tests