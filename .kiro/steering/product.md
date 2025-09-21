# Product Overview

dirLocker is an encrypted file vault application that provides secure file storage with advanced cryptographic features.

## Core Features
- **Encrypted Vaults**: Create and manage encrypted containers for secure file storage ✅
- **Multi-Language Architecture**: Rust core library with Go application layer and Python tooling ✅
- **File Hiding System**: Make files completely invisible to the operating system ✅
- **CLI Interface**: Command-line application for vault operations ✅
- **GUI Interface**: Qt-based graphical interface (in development) 🚧
- **Secure Sharing**: Vault sharing capabilities with X25519 key exchange ✅
- **Recovery System**: Recovery key generation for vault access restoration ✅
- **Cross-Platform**: Windows, Linux, and macOS support ✅

## Key Security Features
- **Multiple Encryption Algorithms**: AES-256-GCM, XChaCha20-Poly1305 ✅
- **Strong Key Derivation**: Argon2 with configurable parameters ✅
- **Secure File Hiding**: Encrypted metadata registry with PBKDF2 ✅
- **X25519 Key Exchange**: Elliptic curve cryptography for secure sharing ✅
- **Recovery System**: Cryptographic recovery keys for vault access ✅
- **Memory Security**: Automatic cleanup and secure random generation ✅
- **File Integrity**: SHA256 checksums and tamper detection ✅
- **No Sensitive Logging**: Secure logging practices implemented ✅

## Target Users
- **Privacy-Conscious Individuals**: Secure personal file storage and hiding
- **Organizations**: Encrypted data containers for sensitive information
- **Collaborative Teams**: Secure file sharing with cryptographic keys
- **Cross-Platform Users**: Consistent security across Windows, Linux, macOS
- **Security Professionals**: Advanced cryptographic features and recovery options

## Current Capabilities

### ✅ Working Features
- **Vault Operations**: Create, open, encrypt/decrypt files
- **File Hiding**: Make files invisible to OS with encrypted tracking
- **Password Management**: Change passwords without re-encryption
- **Recovery Keys**: Generate and use recovery keys for vault access
- **Secure Sharing**: X25519 key exchange and envelope encryption
- **CLI Interface**: Full command-line functionality
- **Cross-Platform**: Windows (MinGW), Linux, macOS support

### 🚧 In Development
- **GUI Application**: Qt-based graphical interface (basic structure exists)
- **Icon Management**: Custom application icons and detection system
- **Mount Operations**: Virtual filesystem mounting
- **Advanced Repair**: Vault corruption recovery tools

### 🔧 Technical Achievements
- **CGO Integration**: Rust ↔ Go FFI working on all platforms
- **Pure Rust Crypto**: No C dependencies, cross-compilation friendly
- **Comprehensive Testing**: Full test coverage with integration tests
- **Platform Abstraction**: Clean separation of platform-specific code