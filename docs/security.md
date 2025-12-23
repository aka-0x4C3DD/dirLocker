# Security Architecture

**dirLocker** is built with a "security-first" philosophy. This document details the cryptographic primitives and security mechanisms used.

## Cryptographic Primitives

All core cryptographic operations are handled by the `vault-core` Rust library to ensure memory safety and constant-time execution where possible.

| Component | Algorithm / Primitive | Purpose |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256-GCM / XChaCha20-Poly1305 | File content and metadata encryption. |
| **Key Derivation** | Argon2id | Deriving master encryption keys from user passwords. |
| **Key Exchange** | X25519 (Curve25519) | Secure sharing mechanism. |
| **Authentication** | Poly1305 (MAC) | Ensuring data integrity and authenticity. |
| **Key Management** | HKDF (HMAC-based KDF) | Subkey generation from master secrets. |

## Vault Structure

Each vault is a single file (`.vault` or `.vc`) with the following encrypted structure:

1.  **Header**: Unencrypted versioning and salt.
2.  **Key Slot Area**: Encrypted master keys protected by user password (Argon2id).
3.  **Metadata Block**: Encrypted file table (paths, attributes).
4.  **Content Store**: Encrypted file chunks.

## Key Management

### Master Key
*   Never stored on disk in plaintext.
*   Encrypted by the user's password derived key.
*   Held in protected memory (zeroed on drop in Rust).

### Recovery Keys
*   Generated cryptographically secure random bytes.
*   Can decrypt the Master Key independently of the password.
*   Must be stored offline by the user.

## File Hiding (Plausible Deniability)

On supported platforms, dirLocker attempts to make the vault file "invisible" to casual inspection:
*   **Windows**: Sets `FileAttributes::Hidden` and `System` attributes.
*   **macOS/Linux**: Prefixes filename with `.` (dotfile).

## Threat Model

**dirLocker protects against:**
*   Passive analysis of the vault file.
*   Offline brute-force attacks (mitigated by Argon2id).
*   Data tampering (mitigated by GCM/Poly1305 integrity checks).

**dirLocker does NOT protect against:**
*   Compromised host OS (keyloggers, memory dumpers) while the vault is OPEN.
*   Physical coercion (user forced to reveal password).
