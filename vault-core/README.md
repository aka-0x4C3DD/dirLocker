# Vault Core

Core cryptographic library for encrypted vault containers, providing cross-platform encryption and file management capabilities.

## Features

- **Cross-platform compatibility**: Works on Windows, macOS, Linux, iOS, and Android
- **Strong encryption**: Supports AES-256-GCM and XChaCha20-Poly1305 ciphers
- **Secure key derivation**: Uses Argon2id with configurable parameters
- **FFI interface**: C-compatible API for integration with other languages
- **Memory safety**: Built in Rust with secure memory handling

## Architecture

The library is structured in several modules:

- `crypto`: Cryptographic operations and cipher implementations
- `vault`: Core vault management and file operations
- `error`: Error types and handling
- `ffi`: Foreign Function Interface for C compatibility

## Dependencies

- `aes-gcm`: AES-256-GCM encryption
- `argon2`: Argon2id key derivation
- `hkdf`: HMAC-based Key Derivation Function
- `x25519-dalek`: X25519 key exchange (for future sharing features)
- `libsodium-sys`: XChaCha20-Poly1305 encryption
- `serde`: Serialization for vault metadata

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## FFI Usage

The library exports a C-compatible interface that can be used from other languages:

```c
#include "vault_core.h"

// Create a new vault
CVaultHandle vault = vault_create("test.vault", "password", CIPHER_AES256_GCM);
if (vault == NULL) {
    CErrorCode error = vault_get_last_error();
    printf("Error: %s\n", vault_error_message(error));
}

// Close the vault
vault_close(vault);
```

## Security Considerations

- All sensitive data is zeroed from memory when no longer needed
- Cryptographic operations use secure random number generation
- Key derivation uses memory-hard functions to resist brute force attacks
- AEAD ciphers provide both confidentiality and authenticity

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.