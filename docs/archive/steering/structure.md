# Project Structure

## Root Level Organization
```
dirLocker/
├── cmd/                    # Application entry points
├── pkg/                    # Public Go packages
├── internal/               # Private Go packages
├── vault-core/             # Rust core library
├── tests/                  # Integration tests
├── .kiro/                  # Kiro IDE configuration
└── etc/                    # Additional resources
```

## Go Application Structure

### Commands (`cmd/`)
- `cmd/cli/`: Command-line interface application
- `cmd/gui/`: Qt-based graphical interface

### Public Packages (`pkg/`)
- `pkg/vault/`: High-level vault management API with CGO bindings
- `pkg/config/`: Configuration management
- `pkg/logging/`: Secure logging system
- `pkg/filehider/`: Cross-platform file hiding system

### Internal Packages (`internal/`)
- `internal/cli/`: CLI-specific implementations
- `internal/gui/`: GUI-specific implementations  
- `internal/core/`: Core business logic
- `internal/vault/`: Low-level vault operations
- `internal/config/`: Internal configuration handling
- `internal/logging/`: Internal logging utilities

## Rust Core Library (`vault-core/`)
```
vault-core/
├── src/                    # Rust source code
├── target/                 # Build artifacts
├── Cargo.toml             # Rust package manifest
├── Cargo.lock             # Dependency lock file
├── vault_core.h           # C header for FFI
└── README.md              # Core library documentation
```

## Architecture Patterns

### Layered Architecture
1. **Rust Core**: Cryptographic operations, vault format, FFI exports
2. **Go Bindings**: CGO wrappers around Rust core (`pkg/vault/cgo.go`)
3. **Go Manager**: High-level vault management (`pkg/vault/manager.go`)
4. **Applications**: CLI and GUI interfaces (`cmd/`)

### Package Dependencies
- Applications depend on `pkg/` packages
- `pkg/` packages may use `internal/` packages
- `internal/` packages are implementation details
- All Go code interfaces with Rust via `pkg/vault/cgo.go`

### Build Constraints
- CGO-enabled builds: Full functionality with Rust integration (`pkg/vault/cgo.go`)
- CGO-disabled builds: Stub implementations for development (`pkg/vault/stub.go`)
- Platform-specific builds: Windows/Unix implementations for file hiding

## File Naming Conventions
- Go files: `snake_case.go`
- Rust files: `snake_case.rs`
- Test files: `*_test.go` (Go), `tests.rs` or `#[cfg(test)]` (Rust)
- CGO files: `cgo.go` with `//go:build cgo` constraint
- Stub files: `stub.go` with `//go:build !cgo` constraint
- Platform files: `*_windows.go`, `*_unix.go` with build constraints

## Configuration Files
- `.kiro/`: IDE-specific configuration and steering rules
- `go.mod`/`go.sum`: Go module dependencies
- `Cargo.toml`/`Cargo.lock`: Rust dependencies
- `pyproject.toml`/`uv.lock`: Python tooling dependencies

## Implementation Status

### ✅ Completed Components
- **Rust Core Library**: Full cryptographic implementation with FFI
- **CGO Integration**: Working Windows MinGW + Linux/macOS support
- **File Hiding System**: Cross-platform implementation with encryption
- **CLI Application**: Basic vault operations and file hiding
- **Testing Suite**: Comprehensive tests for all components

### 🚧 In Progress
- **GUI Application**: Qt-based interface (basic structure exists)
- **Advanced Features**: Mount operations, repair functionality
- **Icon Management**: Custom application icons and detection

### 📁 Key Directories
```
dirLocker/
├── vault-core/
│   ├── src/
│   │   ├── crypto.rs          # Encryption engines
│   │   ├── ffi.rs             # C FFI exports
│   │   ├── vault.rs           # Core vault logic
│   │   └── lib.rs             # Library entry point
│   └── target/
│       └── x86_64-pc-windows-gnu/release/  # MinGW build
├── pkg/
│   ├── vault/
│   │   ├── cgo.go             # CGO bindings (working)
│   │   └── stub.go            # Development stubs
│   └── filehider/
│       ├── interface.go       # File hiding interface
│       ├── registry.go        # Encrypted metadata
│       ├── windows.go         # Windows implementation
│       └── unix.go            # Unix implementation
└── cmd/
    ├── cli/                   # Working CLI application
    └── gui/                   # Qt GUI (needs fixes)
```