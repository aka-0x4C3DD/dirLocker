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

#[test]
fn test_file_chunking_and_streaming() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Create test data larger than default chunk size (4MB)
    let chunk_size = 4 * 1024 * 1024; // 4MB
    let test_data_size = chunk_size + (chunk_size / 2); // 6MB total
    let mut test_data = Vec::with_capacity(test_data_size);
    
    // Fill with predictable pattern for verification
    for i in 0..test_data_size {
        test_data.push((i % 256) as u8);
    }

    // Write file using chunking
    vault.write_file("large_file.bin", &test_data).unwrap();

    // Verify file was stored correctly
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "large_file.bin");
    assert_eq!(files[0].1.size, test_data_size as u64);
    
    // Should have 2 chunks (4MB + 2MB)
    assert_eq!(files[0].1.chunks.len(), 2);

    // Read entire file back
    let read_data = vault.read_file("large_file.bin").unwrap();
    assert_eq!(read_data.len(), test_data_size);
    assert_eq!(read_data, test_data);

    // Test range reading
    let range_data = vault.read_file_range("large_file.bin", 1000, 2000).unwrap();
    assert_eq!(range_data.len(), 2000);
    assert_eq!(range_data, test_data[1000..3000]);

    // Test cross-chunk range reading
    let cross_chunk_start = chunk_size - 1000;
    let cross_chunk_data = vault.read_file_range("large_file.bin", cross_chunk_start as u64, 2000).unwrap();
    assert_eq!(cross_chunk_data.len(), 2000);
    assert_eq!(cross_chunk_data, test_data[cross_chunk_start..cross_chunk_start + 2000]);
}

#[test]
fn test_file_streaming_api() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::XChaCha20Poly1305).unwrap();

    // Create test data
    let test_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    vault.write_file("stream_test.dat", &test_data).unwrap();

    // Create file stream
    let mut stream = vault.create_file_stream("stream_test.dat").unwrap();

    // Test stream properties
    assert_eq!(stream.size(), test_data.len() as u64);
    assert_eq!(stream.position(), 0);
    assert!(!stream.is_eof());

    // Read first 1000 bytes
    let chunk1 = stream.read(1000).unwrap();
    assert_eq!(chunk1.len(), 1000);
    assert_eq!(chunk1, test_data[0..1000]);
    assert_eq!(stream.position(), 1000);

    // Seek to middle
    stream.seek(5000).unwrap();
    assert_eq!(stream.position(), 5000);

    // Read from middle
    let chunk2 = stream.read(1000).unwrap();
    assert_eq!(chunk2.len(), 1000);
    assert_eq!(chunk2, test_data[5000..6000]);
    assert_eq!(stream.position(), 6000);

    // Seek near end
    stream.seek(9500).unwrap();
    let chunk3 = stream.read(1000).unwrap();
    assert_eq!(chunk3.len(), 500); // Only 500 bytes left
    assert_eq!(chunk3, test_data[9500..10000]);
    assert!(stream.is_eof());

    // Test read_exact
    stream.seek(0).unwrap();
    let exact_data = stream.read_exact(100).unwrap();
    assert_eq!(exact_data.len(), 100);
    assert_eq!(exact_data, test_data[0..100]);

    // Test read_exact with insufficient data
    stream.seek(9950).unwrap();
    assert!(stream.read_exact(100).is_err()); // Only 50 bytes left
}

#[test]
fn test_large_file_performance() {
    use tempfile::tempdir;
    use std::time::Instant;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Create 16MB test file
    let file_size = 16 * 1024 * 1024;
    let test_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

    // Measure write performance
    let write_start = Instant::now();
    vault.write_file("large_file.bin", &test_data).unwrap();
    let write_duration = write_start.elapsed();
    println!("Write 16MB in {:?}", write_duration);

    // Verify chunking
    let files = vault.list_files().unwrap();
    assert_eq!(files[0].1.chunks.len(), 4); // 16MB / 4MB = 4 chunks

    // Measure full read performance
    let read_start = Instant::now();
    let read_data = vault.read_file("large_file.bin").unwrap();
    let read_duration = read_start.elapsed();
    println!("Read 16MB in {:?}", read_duration);
    assert_eq!(read_data, test_data);

    // Measure random access performance
    let random_start = Instant::now();
    let _range1 = vault.read_file_range("large_file.bin", 1000000, 1000).unwrap();
    let _range2 = vault.read_file_range("large_file.bin", 8000000, 1000).unwrap();
    let _range3 = vault.read_file_range("large_file.bin", 15000000, 1000).unwrap();
    let random_duration = random_start.elapsed();
    println!("Random access (3x1KB) in {:?}", random_duration);

    // Performance should be reasonable (these are loose bounds for CI)
    assert!(write_duration.as_secs() < 10, "Write took too long: {:?}", write_duration);
    assert!(read_duration.as_secs() < 10, "Read took too long: {:?}", read_duration);
    assert!(random_duration.as_secs() < 5, "Random access took too long: {:?}", random_duration);
}

#[test]
fn test_chunk_encryption_uniqueness() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Create file with repeated data to test nonce uniqueness
    // Use data larger than the default chunk size (4MB) to ensure multiple chunks
    let chunk_size = vault.header().chunk_size as usize; // Use vault's chunk size
    let repeated_data = vec![0x42u8; chunk_size + (chunk_size / 2)]; // 1.5x chunk size to ensure 2 chunks

    vault.write_file("repeated_data.bin", &repeated_data).unwrap();

    // Read raw vault file to verify chunks are encrypted differently
    let _raw_vault_data = std::fs::read(&path).unwrap();
    
    // Find the file entry to get chunk information
    let files = vault.list_files().unwrap();
    let file_entry = &files[0].1;
    
    // Verify we have multiple chunks
    assert!(file_entry.chunks.len() >= 2);

    // Read each chunk's encrypted data
    let mut encrypted_chunks = Vec::new();
    for chunk in &file_entry.chunks {
        let (nonce, encrypted_data) = format::VaultFormat::read_chunk_from_vault_with_nonce_size(
            &path,
            chunk.offset,
            chunk.size,
            12, // AES-GCM nonce size for this test
        ).unwrap();
        
        // Verify nonce is unique (store for comparison)
        for (existing_nonce, _) in &encrypted_chunks {
            assert_ne!(nonce, *existing_nonce, "Nonces should be unique for each chunk");
        }
        
        encrypted_chunks.push((nonce, encrypted_data));
    }

    // Verify encrypted data is different even though plaintext is the same
    if encrypted_chunks.len() >= 2 {
        assert_ne!(
            encrypted_chunks[0].1, 
            encrypted_chunks[1].1,
            "Encrypted chunks should be different even with same plaintext"
        );
    }

    // Verify we can still decrypt correctly
    let decrypted_data = vault.read_file("repeated_data.bin").unwrap();
    assert_eq!(decrypted_data, repeated_data);
}

#[test]
fn test_simple_file_write_read() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Test small file (less than chunk size)
    let small_data = b"Hello, World! This is a small file.";
    
    // Write file
    vault.write_file("small.txt", small_data).unwrap();
    
    // Check file was added to file table
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "small.txt");
    assert_eq!(files[0].1.size, small_data.len() as u64);
    
    // Read file back
    let read_small = vault.read_file("small.txt").unwrap();
    assert_eq!(read_small, small_data);
}

#[test]
fn test_empty_and_small_files() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Test single byte file first
    vault.write_file("single.txt", &[42]).unwrap();
    let single_data = vault.read_file("single.txt").unwrap();
    assert_eq!(single_data, vec![42]);

    // Test small file (less than chunk size)
    let small_data = b"Hello, World! This is a small file.";
    vault.write_file("small.txt", small_data).unwrap();
    let read_small = vault.read_file("small.txt").unwrap();
    assert_eq!(read_small, small_data);

    // Test empty file last (most problematic)
    vault.write_file("empty.txt", &[]).unwrap();
    let empty_data = vault.read_file("empty.txt").unwrap();
    assert_eq!(empty_data.len(), 0);

    // Verify all files exist
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 3);
    
    let filenames: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert!(filenames.contains(&"empty.txt"));
    assert!(filenames.contains(&"single.txt"));
    assert!(filenames.contains(&"small.txt"));
}

#[test]
fn test_file_overwrite_and_replacement() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test.vault");

    // Create vault
    let mut vault = Vault::create(&path, "test_password", CipherType::Aes256Gcm).unwrap();

    // Write initial file
    let initial_data = b"Initial file content";
    vault.write_file("test.txt", initial_data).unwrap();

    // Verify initial file
    let read_data = vault.read_file("test.txt").unwrap();
    assert_eq!(read_data, initial_data);
    
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);

    // Overwrite with larger file
    let new_data = b"This is a much longer file content that should replace the previous content completely";
    vault.write_file("test.txt", new_data).unwrap();

    // Verify overwrite
    let read_new_data = vault.read_file("test.txt").unwrap();
    assert_eq!(read_new_data, new_data);
    
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1); // Still only one file
    assert_eq!(files[0].1.size, new_data.len() as u64);

    // Overwrite with smaller file
    let small_data = b"Small";
    vault.write_file("test.txt", small_data).unwrap();

    // Verify final overwrite
    let read_small_data = vault.read_file("test.txt").unwrap();
    assert_eq!(read_small_data, small_data);
    
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1.size, small_data.len() as u64);
}
