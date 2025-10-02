# dirLocker

A cross-platform encrypted file vault application with advanced cryptographic features, file hiding capabilities, and filesystem mounting support.

## Features

- **Encrypted Vaults**: Create secure encrypted containers using AES-256-GCM or XChaCha20-Poly1305
- **File Hiding**: Make files completely invisible to the operating system
- **Filesystem Mounting**: Mount vaults as virtual drives (FUSE, Dokany, WinFSP)
- **Secure Sharing**: Share vault access using X25519 key exchange
- **Recovery Keys**: Generate recovery keys for vault access restoration
- **Cross-Platform**: Windows, Linux, and macOS support
- **CLI & GUI**: Both command-line and graphical interfaces

## Project Structure

```
dirLocker/
├── bin/                    # Compiled executables (gitignored)
├── cmd/                    # Application entry points
│   ├── cli/               # Command-line interface
│   ├── gui/               # Graphical interface (Fyne)
│   ├── fuse/              # FUSE filesystem daemon
│   ├── dokany/            # Dokany filesystem (Windows)
│   └── winfsp/            # WinFSP filesystem (Windows)
├── pkg/                    # Public Go packages
│   ├── vault/             # Vault management API
│   ├── config/            # Configuration management
│   ├── logging/           # Secure logging
│   ├── filehider/         # File hiding system
│   ├── mount/             # Filesystem mounting
│   └── iconmanager/       # Icon management
├── internal/               # Private Go packages
│   ├── cli/               # CLI implementations
│   ├── gui/               # GUI implementations
│   ├── core/              # Core business logic
│   ├── vault/             # Low-level vault operations
│   ├── fuse/              # FUSE implementation
│   ├── dokany/            # Dokany implementation
│   └── winfsp/            # WinFSP implementation
├── vault-core/             # Rust cryptographic core library
│   ├── src/               # Rust source code
│   └── target/            # Rust build artifacts (gitignored)
├── tests/                  # Integration tests
├── docs/                   # Documentation
│   ├── implementation/    # Implementation summaries
│   └── *.md              # Architecture and design docs
├── scripts/                # Build scripts
├── tools/                  # Python development tools
├── examples/               # Example code
├── .kiro/                  # Kiro IDE configuration
│   ├── settings/          # IDE settings
│   ├── specs/             # Feature specifications
│   └── steering/          # Steering rules
└── log/                    # Application logs (gitignored)
```

## Quick Start

### Prerequisites

- **Rust**: 1.70+ (for building vault-core)
- **Go**: 1.24+ (for building applications)
- **Python**: 3.13+ (for development tools)
- **CGO**: Enabled for Rust-Go integration

### Building

#### Windows (MinGW)

```cmd
REM Build Rust core
cd vault-core
cargo build --release --target x86_64-pc-windows-gnu

REM Build Go applications
cd ..
set CGO_ENABLED=1
go build -o bin/dirlocker-cli.exe ./cmd/cli
go build -o bin/dirlocker-gui.exe ./cmd/gui
```

#### Linux/macOS

```bash
# Build Rust core
cd vault-core
cargo build --release

# Build Go applications
cd ..
export CGO_ENABLED=1
go build -o bin/dirlocker ./cmd/cli
go build -o bin/dirlocker-gui ./cmd/gui
```

### Usage

#### CLI

```bash
# Create a vault
./bin/dirlocker-cli create myvault.vault

# Open and list contents
./bin/dirlocker-cli list myvault.vault

# Hide a file
./bin/dirlocker-cli hide /path/to/file

# Mount a vault
./bin/dirlocker-cli mount myvault.vault /mnt/vault
```

#### GUI

```bash
# Launch the GUI application
./bin/dirlocker-gui
```

## Architecture

dirLocker uses a layered architecture:

1. **Rust Core Library** (`vault-core/`): Cryptographic operations and vault format
2. **Go Application Layer** (`pkg/`, `internal/`): Business logic and platform integration
3. **User Interfaces** (`cmd/`): CLI and GUI applications
4. **Platform Integration**: Filesystem mounting (FUSE, Dokany, WinFSP)

## Security Features

- **AES-256-GCM**: Hardware-accelerated encryption
- **XChaCha20-Poly1305**: Pure Rust implementation
- **Argon2id**: Strong key derivation
- **X25519**: Elliptic curve key exchange
- **HKDF**: Key expansion and subkey derivation
- **AEAD**: Authenticated encryption for all data
- **Plausible Deniability**: Hidden file tables

## Documentation

- [Architecture Documentation](docs/)
- [Implementation Summaries](docs/implementation/)
- [Filesystem Mounting](docs/FILESYSTEM_MOUNTING.md)
- [Vault Corruption Fixes](docs/VAULT_CORRUPTION_FIXES.md)
- [Feature Specifications](.kiro/specs/)

## Development

### Running Tests

```bash
# Go tests
go test ./pkg/...
go test ./internal/...
go test ./tests/...

# Rust tests
cd vault-core
cargo test
```

### Development Tools

```bash
# Python tools (MCP integration)
cd tools
uv sync
uv run python main.py
```

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see the [specifications](.kiro/specs/) for planned features and implementation details.
