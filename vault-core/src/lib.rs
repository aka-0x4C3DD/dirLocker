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

    // Try to open with wrong password - should fail now that we have proper password validation
    let result = Vault::open(&path, "wrong_password");
    assert!(result.is_err());
    
    // Should be InvalidPassword error
    if let Err(VaultError::InvalidPassword) = result {
        // Expected
    } else {
        panic!("Expected InvalidPassword error");
    }
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

#[test]
fn test_vault_file_operations() {
    use tempfile::tempdir;
    use chrono::Utc;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Verify vault has subkeys
    assert!(vault.subkeys().is_some());

    // Create test file entry
    let entry = {
        let subkeys = vault.subkeys().unwrap();
        format::FileEntry::new(
            "test_document.pdf",
            1024 * 1024,
            Utc::now(),
            0o644,
            false,
            vault.crypto(),
            &subkeys.filename_key,
        ).unwrap()
    };

    // Add file entry
    vault.add_file_entry(entry).unwrap();

    // List files
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "test_document.pdf");
    assert_eq!(files[0].1.size, 1024 * 1024);
    assert!(!files[0].1.is_dir);

    // Find specific file
    let found = vault.find_file("test_document.pdf").unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().size, 1024 * 1024);

    // Try to find non-existent file
    let not_found = vault.find_file("nonexistent.txt").unwrap();
    assert!(not_found.is_none());
}

#[test]
fn test_vault_encrypted_file_table_persistence() {
    use tempfile::tempdir;
    use chrono::Utc;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");
    let password = "test_password";

    // Create vault and add files
    {
        let mut vault = Vault::create(&path, password, CipherType::Aes256Gcm).unwrap();

        // Add multiple files
        let files = [
            ("document.pdf", 1024 * 1024, false),
            ("image.jpg", 2 * 1024 * 1024, false),
            ("folder", 0, true),
        ];

        for (name, size, is_dir) in &files {
            let entry = {
                let subkeys = vault.subkeys().unwrap();
                format::FileEntry::new(
                    name,
                    *size,
                    Utc::now(),
                    if *is_dir { 0o755 } else { 0o644 },
                    *is_dir,
                    vault.crypto(),
                    &subkeys.filename_key,
                ).unwrap()
            };
            vault.add_file_entry(entry).unwrap();
        }

        // Save file table
        vault.save_file_table().unwrap();
    }

    // Reopen vault and verify files are preserved
    {
        let vault = Vault::open(&path, password).expect("Failed to reopen vault with correct password");
        let files = vault.list_files().unwrap();

        assert_eq!(files.len(), 3);

        // Verify file details
        let file_names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert!(file_names.contains(&"document.pdf"));
        assert!(file_names.contains(&"image.jpg"));
        assert!(file_names.contains(&"folder"));

        // Check specific file properties
        for (name, entry) in &files {
            match name.as_str() {
                "document.pdf" => {
                    assert_eq!(entry.size, 1024 * 1024);
                    assert!(!entry.is_dir);
                }
                "image.jpg" => {
                    assert_eq!(entry.size, 2 * 1024 * 1024);
                    assert!(!entry.is_dir);
                }
                "folder" => {
                    assert_eq!(entry.size, 0);
                    assert!(entry.is_dir);
                }
                _ => panic!("Unexpected file: {}", name),
            }
        }
    }
}

#[test]
fn test_vault_wrong_password_file_table() {
    use tempfile::tempdir;
    use chrono::Utc;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    // Create vault with files
    {
        let mut vault = Vault::create(&path, correct_password, CipherType::Aes256Gcm).unwrap();

        let entry = {
            let subkeys = vault.subkeys().unwrap();
            format::FileEntry::new(
                "secret.txt",
                1024,
                Utc::now(),
                0o600,
                false,
                vault.crypto(),
                &subkeys.filename_key,
            ).unwrap()
        };
        vault.add_file_entry(entry).unwrap();
        vault.save_file_table().unwrap();
    }

    // Try to open with wrong password
    let result = Vault::open(&path, wrong_password);
    assert!(result.is_err());

    // Verify it's specifically an InvalidPassword error
    if let Err(VaultError::InvalidPassword) = result {
        // Expected
    } else {
        panic!("Expected InvalidPassword error");
    }

    // Verify correct password still works
    let vault = Vault::open(&path, correct_password).expect("Failed to open vault with correct password");
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "secret.txt");
}

#[test]
fn test_vault_metadata_protection() {
    use tempfile::tempdir;
    use chrono::Utc;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Create file with specific metadata
    let filename = "sensitive_document.pdf";
    let size = 1337; // Specific size
    let mtime = Utc::now();
    let mode = 0o600; // Specific permissions

    let entry = {
        let subkeys = vault.subkeys().unwrap();
        format::FileEntry::new(
            filename,
            size,
            mtime,
            mode,
            false,
            vault.crypto(),
            &subkeys.filename_key,
        ).unwrap()
    };

    vault.add_file_entry(entry).unwrap();
    vault.save_file_table().unwrap();

    // Read raw vault file and verify metadata is not visible
    let raw_data = std::fs::read(&path).unwrap();
    let raw_string = String::from_utf8_lossy(&raw_data);

    // Filename should not appear in plaintext
    assert!(!raw_string.contains(filename));
    
    // Size should not appear in plaintext (convert to string representations)
    assert!(!raw_string.contains(&size.to_string()));
    
    // Mode should not appear in plaintext
    assert!(!raw_string.contains(&mode.to_string()));

    // But we should be able to decrypt and access the metadata
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, filename);
    assert_eq!(files[0].1.size, size);
    assert_eq!(files[0].1.mode, mode);
    assert_eq!(files[0].1.mtime, mtime);
}
