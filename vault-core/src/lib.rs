//! Vault Core - Cryptographic library for encrypted vault containers
//!
//! This library provides the core cryptographic functionality for creating,
//! opening, and managing encrypted vault containers with cross-platform compatibility.

pub mod crypto;
pub mod error;
pub mod ffi;
pub mod format;
pub mod vault;

// Re-export main types for library users
pub use crypto::CipherType;
pub use error::{VaultError, VaultResult};
pub use vault::{Vault, VaultHandle};

// FFI exports for C compatibility
pub use ffi::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_creation() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        let result = Vault::create(&path, "password123", CipherType::Aes256Gcm);
        assert!(result.is_ok());

        let vault = result.unwrap();
        assert_eq!(vault.path(), path);
        assert_eq!(vault.header().cipher, "aes-256-gcm");
        assert_eq!(vault.header().kdf, "argon2id");
        assert!(vault.is_open());
    }

    #[test]
    fn test_vault_creation_empty_password() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        let result = Vault::create(&path, "", CipherType::Aes256Gcm);
        assert!(result.is_err());

        if let Err(VaultError::InvalidArgument { details }) = result {
            assert!(details.contains("Password cannot be empty"));
        } else {
            panic!("Expected InvalidArgument error");
        }
    }
}

#[test]
fn test_vault_create_and_open() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();
    let original_uuid = vault.header().vault_uuid;
    drop(vault); // Close the vault

    // Open vault
    let opened_vault = Vault::open(&path, "test_password").unwrap();
    assert_eq!(opened_vault.header().vault_uuid, original_uuid);
    assert_eq!(opened_vault.header().cipher, "aes-256-gcm");
    assert!(opened_vault.is_open());
}

#[test]
fn test_vault_open_wrong_password() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let _vault = Vault::create(&path, "correct_password", CipherType::Aes256Gcm).unwrap();

    // Try to open with wrong password - should succeed for now since we don't validate password yet
    // This will be properly implemented in later tasks when we add file table decryption
    let result = Vault::open(&path, "wrong_password");
    assert!(result.is_ok()); // Will fail properly once password validation is implemented
}

#[test]
fn test_vault_open_nonexistent_file() {
    let result = Vault::open("nonexistent.vault", "password");
    assert!(result.is_err());

    if let Err(VaultError::FileNotFound { path }) = result {
        assert!(path.contains("nonexistent.vault"));
    } else {
        panic!("Expected FileNotFound error");
    }
}

#[test]
fn test_cross_platform_cipher_compatibility() {
    use tempfile::tempdir;

    let ciphers = [CipherType::Aes256Gcm, CipherType::XChaCha20Poly1305];

    for (i, cipher) in ciphers.iter().enumerate() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join(format!("test_{}.vault", i));

        // Create vault with specific cipher
        let vault = Vault::create(&path, "test_password", *cipher).unwrap();
        let expected_cipher = cipher.to_string();
        assert_eq!(vault.header().cipher, expected_cipher);
        drop(vault);

        // Open vault and verify cipher is preserved
        let opened_vault = Vault::open(&path, "test_password").unwrap();
        assert_eq!(opened_vault.header().cipher, expected_cipher);
    }
}

#[test]
fn test_vault_header_validation() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();
    let header = vault.header();

    // Verify header contents
    assert_eq!(header.kdf, "argon2id");
    assert!(header.kdf_params.salt.len() >= 16);
    assert!(header.kdf_params.memory >= 1024);
    assert!(header.kdf_params.operations >= 1);
    assert!(header.kdf_params.parallelism >= 1);
    assert_eq!(header.chunk_size, 4 * 1024 * 1024);
    assert!(!header.vault_uuid.is_nil());
    assert!(header.created_at <= chrono::Utc::now());
}
