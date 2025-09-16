# Go Application Structure and Core Library Integration

This document describes the Go application structure and integration with the Rust core library that was implemented in task 9.

## Project Structure

```
dirLocker/
├── cmd/
│   ├── cli/                    # Command-line interface application
│   │   ├── main.go            # CLI entry point
│   │   └── commands/          # CLI command implementations
│   │       ├── create.go      # Create vault command
│   │       ├── open.go        # Open vault command
│   │       ├── close.go       # Close vault command
│   │       ├── list.go        # List vaults command
│   │       ├── info.go        # Vault info command
│   │       ├── password.go    # Password management
│   │       ├── recovery.go    # Recovery key operations
│   │       ├── share.go       # Vault sharing operations
│   │       ├── mount.go       # Filesystem mounting
│   │       ├── repair.go      # Vault repair operations
│   │       └── config.go      # Configuration management
│   └── gui/                   # Graphical user interface application
│       └── main.go            # GUI entry point (Qt-based)
├── pkg/
│   ├── vault/                 # Vault management layer
│   │   ├── cgo.go            # CGO bindings to Rust core (with build constraint)
│   │   ├── stub.go           # Stub implementations for non-CGO builds
│   │   └── manager.go        # High-level vault management
│   ├── config/               # Configuration management
│   │   └── config.go         # Configuration structures and validation
│   └── logging/              # Secure logging system
│       └── logger.go         # Logger that never logs sensitive data
├── tests/
│   └── integration_test.go   # Integration tests between Go and Rust layers
├── vault-core/               # Rust core library (existing)
└── go.mod                    # Go module definition
```

## Key Components Implemented

### 1. CGO Bindings (`pkg/vault/cgo.go`)

- **Purpose**: Provides Go bindings to the Rust core library via C FFI
- **Features**:
  - Type-safe wrappers around C functions
  - Automatic memory management with finalizers
  - Error handling that converts C error codes to Go errors
  - Support for all vault operations (create, open, close, password management, sharing)

- **Key Types**:
  - `VaultHandle`: Opaque handle to vault instances
  - `CipherType`: Encryption algorithm enumeration
  - `VaultError`: Structured error handling
  - `UnlockMaterial`: Credentials for vault access
  - `RecoveryKey`: Recovery key management
  - `X25519KeyPair`: Key pairs for secure sharing

### 2. Vault Manager (`pkg/vault/manager.go`)

- **Purpose**: High-level vault management with additional features
- **Features**:
  - Manages multiple open vaults simultaneously
  - Automatic idle vault closing with configurable timeout
  - Thread-safe operations with proper locking
  - Vault metadata tracking (open time, last used, sharing status)
  - Integration with configuration and logging systems

- **Key Methods**:
  - `CreateVault()`: Create new encrypted vaults
  - `OpenVault()`: Open existing vaults with password
  - `OpenVaultWithRecipientKey()`: Open shared vaults
  - `CloseVault()` / `CloseAllVaults()`: Resource cleanup
  - `ChangeVaultPassword()`: Password management
  - `GenerateRecoveryKey()`: Recovery key generation

### 3. Configuration System (`pkg/config/config.go`)

- **Purpose**: Centralized configuration management with validation
- **Features**:
  - JSON-based configuration files
  - Default value handling
  - Configuration validation and sanitization
  - Support for vault settings, KDF parameters, logging, security options
  - Path management for config, data, temp, and hidden directories

- **Key Settings**:
  - Vault: Default cipher, chunk size, auto-lock timeout
  - KDF: Memory, operations, parallelism parameters
  - Logging: Level, file rotation, compression
  - Security: Secure memory, clipboard management
  - Directories: Configurable paths for different data types

### 4. Secure Logging (`pkg/logging/logger.go`)

- **Purpose**: Logging system that never logs sensitive data
- **Features**:
  - Automatic detection and redaction of sensitive patterns
  - Support for passwords, keys, tokens, cryptographic data
  - Structured logging with key-value pairs
  - Multiple output targets (console, file)
  - Audit and security event logging
  - Performance metrics logging

- **Security Patterns Detected**:
  - Password fields and values
  - Cryptographic keys and tokens
  - Base64 and hexadecimal encoded data
  - File paths with sensitive extensions

### 5. Command-Line Interface (`cmd/cli/`)

- **Purpose**: Full-featured CLI for vault operations
- **Features**:
  - Comprehensive command set for all vault operations
  - Interactive password prompts with hidden input
  - Structured help system and command completion
  - Global flags for configuration and logging
  - Error handling with user-friendly messages

- **Available Commands**:
  - `create`: Create new vaults with cipher selection
  - `open`/`close`: Vault lifecycle management
  - `list`/`info`: Vault inspection and status
  - `password`: Password change operations
  - `recovery`: Recovery key generation and usage
  - `share`: Secure vault sharing with key management
  - `mount`/`repair`: Advanced operations (placeholders)
  - `config`: Configuration management

### 6. Graphical User Interface (`cmd/gui/`)

- **Purpose**: Qt-based GUI application (structure implemented)
- **Features**:
  - Main window with vault list and management
  - System tray integration
  - Menu bar and toolbar with actions
  - Dialog system for vault operations
  - Cross-platform GUI framework

### 7. Integration Tests (`tests/integration_test.go`)

- **Purpose**: Comprehensive testing of Go-Rust integration
- **Test Coverage**:
  - Vault lifecycle operations (create, open, close)
  - Password management and validation
  - Recovery key generation and usage
  - Secure sharing operations
  - Configuration management
  - Secure logging verification
  - Error handling scenarios

## Build System

### CGO-Enabled Build (Production)
```bash
# Requires C compiler and Rust core library
export CGO_ENABLED=1
go build -o dirlocker ./cmd/cli
```

### CGO-Disabled Build (Development/Testing)
```bash
# Uses stub implementations
export CGO_ENABLED=0
go build -o dirlocker ./cmd/cli
```

## Error Handling Strategy

1. **Rust Core Errors**: Converted to structured Go errors with error codes
2. **Go Layer Errors**: Wrapped with context and user-friendly messages
3. **Logging**: All errors logged with sanitized context
4. **CLI**: User-friendly error messages without technical details
5. **Recovery**: Graceful degradation when possible

## Security Considerations

1. **Memory Safety**: 
   - Automatic cleanup with finalizers
   - Secure memory clearing where possible
   - No sensitive data in logs

2. **Input Validation**:
   - Password strength requirements
   - Path validation and sanitization
   - Configuration parameter bounds checking

3. **Error Information**:
   - No sensitive data in error messages
   - Consistent error responses to prevent information leakage

## Integration Points with Rust Core

The Go layer integrates with the Rust core library through:

1. **FFI Functions**: Direct calls to C-compatible Rust functions
2. **Memory Management**: Proper handling of allocated memory across language boundaries
3. **Error Propagation**: Translation of Rust error codes to Go error types
4. **Type Safety**: Go type wrappers around C structures
5. **Resource Cleanup**: Automatic resource management with Go finalizers

## Testing Strategy

1. **Unit Tests**: Individual component testing
2. **Integration Tests**: Go-Rust boundary testing
3. **End-to-End Tests**: Full application workflow testing
4. **Security Tests**: Sensitive data handling verification
5. **Performance Tests**: Memory and resource usage validation

## Requirements Satisfied

This implementation satisfies the following requirements from the specification:

- **11.1**: Go application structure with CLI and GUI applications ✓
- **11.4**: CGO bindings to Rust core library with proper error handling ✓
- **15.3**: VaultManager wrapper around core library FFI calls ✓
- **15.5**: Configuration management system with JSON serialization ✓
- **Logging**: System that never logs sensitive data ✓
- **Integration Tests**: Between Go layer and Rust core ✓

## Next Steps

The following components are ready for implementation in subsequent tasks:

1. **File Operations**: Reading, writing, and streaming files within vaults
2. **Filesystem Mounting**: FUSE/WinFsp integration for direct file access
3. **GUI Dialogs**: Complete Qt-based user interface
4. **Advanced Features**: Vault repair, integrity checking, algorithm rotation
5. **Platform Integration**: System tray, file associations, auto-start

This foundation provides a robust, secure, and extensible platform for the encrypted vault application.