# Technology Stack

## Core Architecture
- **Rust Core Library** (`vault-core/`): Cryptographic operations and vault management
- **Go Application Layer** (`cmd/`, `pkg/`, `internal/`): CLI/GUI applications with CGO bindings
- **Python Tooling** (`main.py`, `pyproject.toml`): Development tools and MCP integration

## Languages & Frameworks
- **Rust**: Core cryptographic library with C FFI exports
- **Go 1.24**: Application layer with Cobra CLI and Qt GUI
- **Python 3.13+**: Tooling with FastMCP and MCP CLI support

## Key Dependencies

### Rust (vault-core)
- **Cryptography**: libsodium-sys, aes-gcm, argon2, x25519-dalek
- **Serialization**: serde, serde_json
- **Utilities**: uuid, chrono, thiserror, base64, hex

### Go
- **CLI Framework**: github.com/spf13/cobra, github.com/spf13/viper
- **GUI Framework**: github.com/therecipe/qt
- **Logging**: github.com/sirupsen/logrus
- **Testing**: github.com/stretchr/testify

### Python
- **MCP Integration**: fastmcp, mcp[cli]

## Build System

### Development Build (CGO Disabled)
```bash
export CGO_ENABLED=0
go build -o dirlocker ./cmd/cli
go build -o dirlocker-gui ./cmd/gui
```

### Production Build (CGO Enabled)
```bash
# Build Rust core first
cd vault-core
cargo build --release

# Build Go applications with CGO
cd ..
export CGO_ENABLED=1
go build -o dirlocker ./cmd/cli
go build -o dirlocker-gui ./cmd/gui
```

### Testing
```bash
# Run Go tests
go test ./...
go test ./tests/integration_test.go

# Run Rust tests
cd vault-core
cargo test

# Python development
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
```