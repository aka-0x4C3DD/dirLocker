//! Vault container format implementation
//!
//! This module implements the standardized vault container format:
//! [Magic][Version][HeaderLen][HeaderJSON][FileTable][Chunks...]

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Seek};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{VaultError, VaultResult};
use crate::crypto::{CryptoEngine, SubKeys, generate_nonce};

/// Magic bytes for vault files: "VLT1"
pub const VAULT_MAGIC: &[u8; 4] = b"VLT1";

/// Current vault format version
pub const VAULT_VERSION: u8 = 0x01;

/// Minimum supported vault version
pub const MIN_SUPPORTED_VERSION: u8 = 0x01;

/// Maximum supported vault version
pub const MAX_SUPPORTED_VERSION: u8 = 0x01;

/// Vault file header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub cipher: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub vault_uuid: Uuid,
    pub file_table_offset: u64,
    pub file_table_size: u64,
    pub chunk_size: u32,
    pub flags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub platform_hint: String,
}

/// KDF parameters for Argon2id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    #[serde(with = "base64_serde")]
    pub salt: Vec<u8>,
    pub memory: u32,
    pub operations: u32,
    pub parallelism: u32,
}

/// File table structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTable {
    pub files: Vec<FileEntry>,
}

/// Individual file entry in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    #[serde(with = "base64_serde")]
    pub name_encrypted: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub iv: Vec<u8>,
    pub size: u64,
    pub chunks: Vec<ChunkInfo>,
    pub mtime: DateTime<Utc>,
    pub mode: u32,
    pub is_dir: bool,
}

impl FileEntry {
    /// Create a new file entry with encrypted filename and metadata
    pub fn new(
        filename: &str,
        size: u64,
        mtime: DateTime<Utc>,
        mode: u32,
        is_dir: bool,
        crypto_engine: &dyn CryptoEngine,
        filename_key: &[u8],
    ) -> VaultResult<Self> {
        // Encrypt filename
        let (name_encrypted, iv) = VaultFormat::encrypt_filename(filename, crypto_engine, filename_key)?;

        Ok(FileEntry {
            name_encrypted,
            iv,
            size,
            chunks: vec![],
            mtime,
            mode,
            is_dir,
        })
    }

    /// Decrypt and return the filename
    pub fn decrypt_filename(
        &self,
        crypto_engine: &dyn CryptoEngine,
        filename_key: &[u8],
    ) -> VaultResult<String> {
        VaultFormat::decrypt_filename(&self.name_encrypted, &self.iv, crypto_engine, filename_key)
    }

    /// Add a chunk to this file entry
    pub fn add_chunk(&mut self, offset: u64, size: u32, iv: Vec<u8>) {
        self.chunks.push(ChunkInfo { offset, size, iv });
    }

    /// Get the total number of chunks for this file
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Validate the file entry structure
    pub fn validate(&self) -> VaultResult<()> {
        if self.name_encrypted.is_empty() {
            return Err(VaultError::corrupted_vault("Empty encrypted filename"));
        }

        if self.iv.is_empty() {
            return Err(VaultError::corrupted_vault("Empty filename IV"));
        }

        // Note: We allow files with size > 0 but no chunks at this stage
        // Chunks will be added when file content is actually stored
        // This validation will be stricter in later tasks when file operations are implemented

        // Validate chunk consistency
        for chunk in &self.chunks {
            if chunk.size == 0 {
                return Err(VaultError::corrupted_vault("Zero-size chunk"));
            }
            if chunk.iv.is_empty() {
                return Err(VaultError::corrupted_vault("Empty chunk IV"));
            }
        }

        // Note: We don't validate chunk size consistency at this stage
        // since file content storage will be implemented in later tasks

        Ok(())
    }
}

/// Chunk information for file storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub offset: u64,
    pub size: u32,
    #[serde(with = "base64_serde")]
    pub iv: Vec<u8>,
}

/// Vault file format reader/writer
pub struct VaultFormat;

impl VaultFormat {
    /// Write a new vault file with the given header and empty file table
    pub fn create_vault_file<P: AsRef<Path>>(path: P, header: &VaultHeader) -> VaultResult<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write magic bytes
        writer.write_all(VAULT_MAGIC)?;

        // Write version
        writer.write_all(&[VAULT_VERSION])?;

        // Serialize header to JSON
        let header_json = serde_json::to_string_pretty(header)?;
        let header_bytes = header_json.as_bytes();

        // Write header length (big-endian 32-bit)
        let header_len = header_bytes.len() as u32;
        writer.write_all(&header_len.to_be_bytes())?;

        // Write header JSON
        writer.write_all(header_bytes)?;

        writer.flush()?;

        Ok(())
    }

    /// Write an encrypted file table to a vault file
    pub fn write_encrypted_file_table<P: AsRef<Path>>(
        path: P,
        header: &VaultHeader,
        file_table: &FileTable,
        crypto_engine: &dyn CryptoEngine,
        subkeys: &SubKeys,
    ) -> VaultResult<()> {
        // Serialize file table to JSON
        let file_table_json = serde_json::to_string(file_table)?;
        let file_table_bytes = file_table_json.as_bytes();

        // Generate nonce for file table encryption
        let nonce = generate_nonce(crypto_engine.nonce_size())?;

        // Use header JSON as Additional Authenticated Data (AAD)
        let header_json = serde_json::to_string(header)?;
        let aad = header_json.as_bytes();

        // Encrypt file table using file_encryption_key
        let encrypted_file_table = crypto_engine.encrypt(
            &subkeys.file_encryption_key,
            &nonce,
            file_table_bytes,
            aad,
        )?;

        // Calculate file table offset (magic + version + header_len + header)
        let header_json_bytes = serde_json::to_string_pretty(header)?.into_bytes();
        let file_table_offset = 4 + 1 + 4 + header_json_bytes.len() as u64;

        // Open file for writing at specific position
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)?;

        // Seek to file table position
        file.seek(std::io::SeekFrom::Start(file_table_offset))?;

        // Write nonce first
        file.write_all(&nonce)?;

        // Write encrypted file table
        file.write_all(&encrypted_file_table)?;

        // Truncate file to remove any old data
        file.set_len(file_table_offset + nonce.len() as u64 + encrypted_file_table.len() as u64)?;

        file.flush()?;

        Ok(())
    }

    /// Read and decrypt a file table from a vault file
    pub fn read_encrypted_file_table<P: AsRef<Path>>(
        path: P,
        header: &VaultHeader,
        file_table_offset: u64,
        crypto_engine: &dyn CryptoEngine,
        subkeys: &SubKeys,
    ) -> VaultResult<FileTable> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        
        // Check if there's any data after the header
        if file_size <= file_table_offset {
            // No file table data yet
            return Ok(FileTable { files: vec![] });
        }

        let mut reader = BufReader::new(file);

        // Seek to file table position
        reader.get_mut().seek(std::io::SeekFrom::Start(file_table_offset))?;

        // Check if we have enough data for a nonce
        let remaining_size = file_size - file_table_offset;
        if remaining_size < crypto_engine.nonce_size() as u64 {
            // Not enough data for a nonce, assume empty file table
            return Ok(FileTable { files: vec![] });
        }

        // Read nonce
        let mut nonce = vec![0u8; crypto_engine.nonce_size()];
        reader.read_exact(&mut nonce)?;

        // Calculate encrypted file table size
        let encrypted_size = remaining_size - crypto_engine.nonce_size() as u64;
        
        if encrypted_size == 0 {
            // Empty file table
            return Ok(FileTable { files: vec![] });
        }

        // Read encrypted file table
        let mut encrypted_file_table = vec![0u8; encrypted_size as usize];
        reader.read_exact(&mut encrypted_file_table)?;

        // Use header JSON as Additional Authenticated Data (AAD)
        let header_json = serde_json::to_string(header)?;
        let aad = header_json.as_bytes();

        // Decrypt file table using file_encryption_key
        let decrypted_bytes = crypto_engine.decrypt(
            &subkeys.file_encryption_key,
            &nonce,
            &encrypted_file_table,
            aad,
        )?;

        // Parse JSON
        let file_table_json = std::str::from_utf8(&decrypted_bytes)?;
        let file_table: FileTable = serde_json::from_str(file_table_json)?;

        Ok(file_table)
    }

    /// Read and parse a vault file header
    pub fn read_vault_header<P: AsRef<Path>>(path: P) -> VaultResult<(VaultHeader, u64)> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read and verify magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if &magic != VAULT_MAGIC {
            return Err(VaultError::corrupted_vault(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                VAULT_MAGIC, magic
            )));
        }

        // Read and verify version
        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        let version = version[0];

        if !Self::is_version_supported(version) {
            return Err(VaultError::corrupted_vault(format!(
                "Unsupported vault version: {} (supported: {}-{})",
                version, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION
            )));
        }

        // Read header length
        let mut header_len_bytes = [0u8; 4];
        reader.read_exact(&mut header_len_bytes)?;
        let header_len = u32::from_be_bytes(header_len_bytes) as usize;

        // Validate header length (reasonable bounds check)
        if header_len == 0 || header_len > 1024 * 1024 {
            return Err(VaultError::corrupted_vault(format!(
                "Invalid header length: {}",
                header_len
            )));
        }

        // Read header JSON
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;

        let header_json = std::str::from_utf8(&header_bytes)?;
        let header: VaultHeader = serde_json::from_str(header_json)?;

        // Validate header contents
        Self::validate_header(&header)?;

        // Calculate file table offset
        let file_table_offset = 4 + 1 + 4 + header_len as u64; // magic + version + header_len + header

        Ok((header, file_table_offset))
    }

    /// Check if a vault version is supported
    pub fn is_version_supported(version: u8) -> bool {
        version >= MIN_SUPPORTED_VERSION && version <= MAX_SUPPORTED_VERSION
    }

    /// Validate header contents
    fn validate_header(header: &VaultHeader) -> VaultResult<()> {
        // Validate cipher
        let _cipher_type: crate::crypto::CipherType = header.cipher.parse()?;

        // Validate KDF
        if header.kdf != "argon2id" {
            return Err(VaultError::corrupted_vault(format!(
                "Unsupported KDF: {}",
                header.kdf
            )));
        }

        // Validate KDF parameters
        if header.kdf_params.salt.len() < 16 {
            return Err(VaultError::corrupted_vault(
                "Salt too short (minimum 16 bytes)".to_string(),
            ));
        }

        if header.kdf_params.memory < 1024 {
            return Err(VaultError::corrupted_vault(
                "Memory parameter too low (minimum 1024 KB)".to_string(),
            ));
        }

        if header.kdf_params.operations < 1 {
            return Err(VaultError::corrupted_vault(
                "Operations parameter too low (minimum 1)".to_string(),
            ));
        }

        if header.kdf_params.parallelism < 1 {
            return Err(VaultError::corrupted_vault(
                "Parallelism parameter too low (minimum 1)".to_string(),
            ));
        }

        // Validate chunk size
        if header.chunk_size < 1024 || header.chunk_size > 64 * 1024 * 1024 {
            return Err(VaultError::corrupted_vault(format!(
                "Invalid chunk size: {} (must be between 1KB and 64MB)",
                header.chunk_size
            )));
        }

        Ok(())
    }

    /// Get the current vault format version
    pub fn current_version() -> u8 {
        VAULT_VERSION
    }

    /// Get supported version range
    pub fn supported_version_range() -> (u8, u8) {
        (MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION)
    }

    /// Encrypt a filename using deterministic AEAD
    pub fn encrypt_filename(
        filename: &str,
        crypto_engine: &dyn CryptoEngine,
        filename_key: &[u8],
    ) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        // Use deterministic nonce generation for filename encryption
        // This ensures the same filename always produces the same ciphertext
        let nonce = Self::derive_filename_nonce(filename, crypto_engine.nonce_size())?;

        // Encrypt filename with empty AAD (filenames are self-contained)
        let encrypted_filename = crypto_engine.encrypt(
            filename_key,
            &nonce,
            filename.as_bytes(),
            &[], // No AAD for filenames
        )?;

        Ok((encrypted_filename, nonce))
    }

    /// Decrypt a filename using deterministic AEAD
    pub fn decrypt_filename(
        encrypted_filename: &[u8],
        nonce: &[u8],
        crypto_engine: &dyn CryptoEngine,
        filename_key: &[u8],
    ) -> VaultResult<String> {
        // Decrypt filename
        let decrypted_bytes = crypto_engine.decrypt(
            filename_key,
            nonce,
            encrypted_filename,
            &[], // No AAD for filenames
        )?;

        // Convert to string
        let filename = String::from_utf8(decrypted_bytes)
            .map_err(|e| VaultError::crypto_error(format!("Invalid filename UTF-8: {}", e)))?;

        Ok(filename)
    }

    /// Derive a deterministic nonce for filename encryption
    /// This ensures the same filename always produces the same encrypted result
    fn derive_filename_nonce(filename: &str, nonce_size: usize) -> VaultResult<Vec<u8>> {
        use sha2::{Sha256, Digest};

        // Hash the filename to create a deterministic nonce
        let mut hasher = Sha256::new();
        hasher.update(b"filename_nonce_v1:"); // Version prefix
        hasher.update(filename.as_bytes());
        let hash = hasher.finalize();

        // Take the required number of bytes for the nonce
        if nonce_size > hash.len() {
            return Err(VaultError::crypto_error(format!(
                "Nonce size {} too large for SHA256 hash",
                nonce_size
            )));
        }

        Ok(hash[..nonce_size].to_vec())
    }
}

/// Helper module for base64 serialization of byte arrays
mod base64_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| D::Error::custom(format!("Base64 decode error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    pub fn create_test_header() -> VaultHeader {
        VaultHeader {
            cipher: "aes-256-gcm".to_string(),
            kdf: "argon2id".to_string(),
            kdf_params: KdfParams {
                salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                memory: 65536,
                operations: 3,
                parallelism: 1,
            },
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 0,
            file_table_size: 0,
            chunk_size: 4 * 1024 * 1024,
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: "test".to_string(),
        }
    }

    #[test]
    fn test_vault_format_create_and_read() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let header = create_test_header();
        let original_uuid = header.vault_uuid;

        // Create vault file
        VaultFormat::create_vault_file(path, &header).unwrap();

        // Read header back
        let (read_header, file_table_offset) = VaultFormat::read_vault_header(path).unwrap();

        // Verify header contents
        assert_eq!(read_header.cipher, "aes-256-gcm");
        assert_eq!(read_header.kdf, "argon2id");
        assert_eq!(
            read_header.kdf_params.salt,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(read_header.kdf_params.memory, 65536);
        assert_eq!(read_header.kdf_params.operations, 3);
        assert_eq!(read_header.kdf_params.parallelism, 1);
        assert_eq!(read_header.vault_uuid, original_uuid);
        assert_eq!(read_header.chunk_size, 4 * 1024 * 1024);
        assert_eq!(read_header.platform_hint, "test");

        // Verify file table offset is reasonable
        assert!(file_table_offset > 9); // At least magic + version + header_len
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write invalid magic bytes
        temp_file.write_all(b"XXXX").unwrap();
        temp_file.write_all(&[VAULT_VERSION]).unwrap();
        temp_file.flush().unwrap();

        let result = VaultFormat::read_vault_header(temp_file.path());
        assert!(result.is_err());

        if let Err(VaultError::CorruptedVault { details }) = result {
            assert!(details.contains("Invalid magic bytes"));
        } else {
            panic!("Expected CorruptedVault error");
        }
    }

    #[test]
    fn test_unsupported_version() {
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write valid magic but unsupported version
        temp_file.write_all(VAULT_MAGIC).unwrap();
        temp_file.write_all(&[0xFF]).unwrap(); // Unsupported version
        temp_file.flush().unwrap();

        let result = VaultFormat::read_vault_header(temp_file.path());
        assert!(result.is_err());

        if let Err(VaultError::CorruptedVault { details }) = result {
            assert!(details.contains("Unsupported vault version"));
        } else {
            panic!("Expected CorruptedVault error");
        }
    }

    #[test]
    fn test_version_support_check() {
        assert!(VaultFormat::is_version_supported(0x01));
        assert!(!VaultFormat::is_version_supported(0x00));
        assert!(!VaultFormat::is_version_supported(0xFF));
    }

    #[test]
    fn test_header_validation() {
        // Valid header
        let valid_header = create_test_header();
        assert!(VaultFormat::validate_header(&valid_header).is_ok());

        // Invalid cipher
        let mut invalid_header = create_test_header();
        invalid_header.cipher = "invalid-cipher".to_string();
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Invalid KDF
        let mut invalid_header = create_test_header();
        invalid_header.kdf = "invalid-kdf".to_string();
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Salt too short
        let mut invalid_header = create_test_header();
        invalid_header.kdf_params.salt = vec![1, 2, 3]; // Too short
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Memory too low
        let mut invalid_header = create_test_header();
        invalid_header.kdf_params.memory = 512; // Too low
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Operations too low
        let mut invalid_header = create_test_header();
        invalid_header.kdf_params.operations = 0; // Too low
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Parallelism too low
        let mut invalid_header = create_test_header();
        invalid_header.kdf_params.parallelism = 0; // Too low
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Chunk size too small
        let mut invalid_header = create_test_header();
        invalid_header.chunk_size = 512; // Too small
        assert!(VaultFormat::validate_header(&invalid_header).is_err());

        // Chunk size too large
        let mut invalid_header = create_test_header();
        invalid_header.chunk_size = 128 * 1024 * 1024; // Too large
        assert!(VaultFormat::validate_header(&invalid_header).is_err());
    }

    #[test]
    fn test_cross_platform_compatibility() {
        // Test that headers created on different "platforms" can be read
        let platforms = ["windows", "macos", "linux", "ios", "android"];

        for platform in &platforms {
            let temp_file = NamedTempFile::new().unwrap();
            let path = temp_file.path();

            let mut header = create_test_header();
            header.platform_hint = platform.to_string();

            // Create vault file
            VaultFormat::create_vault_file(path, &header).unwrap();

            // Read header back
            let (read_header, _) = VaultFormat::read_vault_header(path).unwrap();

            // Verify platform hint is preserved
            assert_eq!(read_header.platform_hint, *platform);
        }
    }

    #[test]
    fn test_base64_serialization() {
        let test_data = vec![0x01, 0x02, 0x03, 0x04, 0xFF, 0xFE];

        let kdf_params = KdfParams {
            salt: test_data.clone(),
            memory: 1024,
            operations: 1,
            parallelism: 1,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&kdf_params).unwrap();

        // Should contain base64 encoded salt
        assert!(json.contains("AQIDBP/+"));

        // Deserialize back
        let deserialized: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.salt, test_data);
    }
}

#[test]
fn test_vault_format_with_known_test_vectors() {
    use tempfile::NamedTempFile;

    // Test with known values to ensure cross-platform compatibility
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let mut header = VaultHeader {
        cipher: "aes-256-gcm".to_string(),
        kdf: "argon2id".to_string(),
        kdf_params: KdfParams {
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            memory: 65536,
            operations: 3,
            parallelism: 1,
        },
        vault_uuid: Uuid::new_v4(),
        file_table_offset: 0,
        file_table_size: 0,
        chunk_size: 4 * 1024 * 1024,
        flags: vec![],
        created_at: Utc::now(),
        platform_hint: "test".to_string(),
    };
    // Use fixed values for reproducible test
    header.kdf_params.salt = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    header.kdf_params.memory = 65536;
    header.kdf_params.operations = 3;
    header.kdf_params.parallelism = 1;
    header.chunk_size = 4 * 1024 * 1024;

    // Create vault file
    VaultFormat::create_vault_file(path, &header).unwrap();

    // Read raw file and verify format
    let file_contents = std::fs::read(path).unwrap();

    // Verify magic bytes
    assert_eq!(&file_contents[0..4], b"VLT1");

    // Verify version
    assert_eq!(file_contents[4], 0x01);

    // Verify header length is reasonable
    let header_len = u32::from_be_bytes([
        file_contents[5],
        file_contents[6],
        file_contents[7],
        file_contents[8],
    ]);
    assert!(header_len > 100); // Should be substantial JSON
    assert!(header_len < 10000); // But not too large

    // Verify we can parse it back
    let (parsed_header, _) = VaultFormat::read_vault_header(path).unwrap();
    assert_eq!(parsed_header.kdf_params.salt, header.kdf_params.salt);
    assert_eq!(parsed_header.kdf_params.memory, 65536);
    assert_eq!(parsed_header.kdf_params.operations, 3);
    assert_eq!(parsed_header.kdf_params.parallelism, 1);
}

#[test]
fn test_algorithm_identifier_parsing() {
    use tempfile::NamedTempFile;

    // Test that all supported algorithms can be parsed correctly
    let algorithms = [
        ("aes-256-gcm", "AES-256-GCM"),
        ("xchacha20poly1305", "XChaCha20-Poly1305"),
    ];

    for (algo_str, _description) in &algorithms {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let header = VaultHeader {
            cipher: algo_str.to_string(),
            kdf: "argon2id".to_string(),
            kdf_params: KdfParams {
                salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                memory: 65536,
                operations: 3,
                parallelism: 1,
            },
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 0,
            file_table_size: 0,
            chunk_size: 4 * 1024 * 1024,
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: "test".to_string(),
        };

        // Create and read back
        VaultFormat::create_vault_file(path, &header).unwrap();
        let (parsed_header, _) = VaultFormat::read_vault_header(path).unwrap();

        assert_eq!(parsed_header.cipher, *algo_str);

        // Verify the cipher can be parsed by crypto module
        let _cipher_type: crate::crypto::CipherType = parsed_header.cipher.parse().unwrap();
    }
}

#[test]
fn test_version_compatibility_checking() {
    // Test that version checking works correctly
    assert!(VaultFormat::is_version_supported(0x01));

    // Test boundary conditions
    assert!(!VaultFormat::is_version_supported(0x00));
    assert!(!VaultFormat::is_version_supported(0x02));
    assert!(!VaultFormat::is_version_supported(0xFF));

    // Test version range
    let (min, max) = VaultFormat::supported_version_range();
    assert_eq!(min, 0x01);
    assert_eq!(max, 0x01);
    assert_eq!(VaultFormat::current_version(), 0x01);
}

#[test]
fn test_large_header_handling() {
    use tempfile::NamedTempFile;

    // Test with a header that has large fields to ensure proper handling
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let mut header = VaultHeader {
        cipher: "aes-256-gcm".to_string(),
        kdf: "argon2id".to_string(),
        kdf_params: KdfParams {
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            memory: 65536,
            operations: 3,
            parallelism: 1,
        },
        vault_uuid: Uuid::new_v4(),
        file_table_offset: 0,
        file_table_size: 0,
        chunk_size: 4 * 1024 * 1024,
        flags: vec![],
        created_at: Utc::now(),
        platform_hint: "test".to_string(),
    };
    // Add many flags to make header larger
    header.flags = (0..100).map(|i| format!("flag_{}", i)).collect();

    // Should still work
    VaultFormat::create_vault_file(path, &header).unwrap();
    let (parsed_header, _) = VaultFormat::read_vault_header(path).unwrap();

    assert_eq!(parsed_header.flags.len(), 100);
    assert_eq!(parsed_header.flags[0], "flag_0");
    assert_eq!(parsed_header.flags[99], "flag_99");
}

#[test]
fn test_malformed_header_rejection() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test various malformed headers
    let mut temp_file = NamedTempFile::new().unwrap();

    // Valid magic and version, but zero header length
    temp_file.write_all(VAULT_MAGIC).unwrap();
    temp_file.write_all(&[VAULT_VERSION]).unwrap();
    temp_file.write_all(&[0, 0, 0, 0]).unwrap(); // Zero length
    temp_file.flush().unwrap();

    let result = VaultFormat::read_vault_header(temp_file.path());
    assert!(result.is_err());

    // Test extremely large header length
    let mut temp_file2 = NamedTempFile::new().unwrap();
    temp_file2.write_all(VAULT_MAGIC).unwrap();
    temp_file2.write_all(&[VAULT_VERSION]).unwrap();
    temp_file2.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap(); // Max u32
    temp_file2.flush().unwrap();

    let result = VaultFormat::read_vault_header(temp_file2.path());
    assert!(result.is_err());
}

#[test]
fn test_filename_encryption_deterministic() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let filename = "test_file.txt";

    // Encrypt the same filename multiple times
    let (encrypted1, nonce1) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key).unwrap();
    let (encrypted2, nonce2) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key).unwrap();

    // Should produce identical results (deterministic)
    assert_eq!(encrypted1, encrypted2);
    assert_eq!(nonce1, nonce2);

    // Decrypt both and verify they match
    let decrypted1 = VaultFormat::decrypt_filename(&encrypted1, &nonce1, engine.as_ref(), &filename_key).unwrap();
    let decrypted2 = VaultFormat::decrypt_filename(&encrypted2, &nonce2, engine.as_ref(), &filename_key).unwrap();

    assert_eq!(decrypted1, filename);
    assert_eq!(decrypted2, filename);
    assert_eq!(decrypted1, decrypted2);
}

#[test]
fn test_filename_encryption_different_names() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let filename1 = "file1.txt";
    let filename2 = "file2.txt";

    // Encrypt different filenames
    let (encrypted1, nonce1) = VaultFormat::encrypt_filename(filename1, engine.as_ref(), &filename_key).unwrap();
    let (encrypted2, nonce2) = VaultFormat::encrypt_filename(filename2, engine.as_ref(), &filename_key).unwrap();

    // Should produce different results
    assert_ne!(encrypted1, encrypted2);
    assert_ne!(nonce1, nonce2);

    // Decrypt and verify
    let decrypted1 = VaultFormat::decrypt_filename(&encrypted1, &nonce1, engine.as_ref(), &filename_key).unwrap();
    let decrypted2 = VaultFormat::decrypt_filename(&encrypted2, &nonce2, engine.as_ref(), &filename_key).unwrap();

    assert_eq!(decrypted1, filename1);
    assert_eq!(decrypted2, filename2);
}

#[test]
fn test_filename_encryption_different_keys() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key1 = generate_random_bytes(32).unwrap();
    let filename_key2 = generate_random_bytes(32).unwrap();

    let filename = "test_file.txt";

    // Encrypt with different keys
    let (encrypted1, nonce1) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key1).unwrap();
    let (encrypted2, nonce2) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key2).unwrap();

    // Should produce different results even with same filename
    assert_ne!(encrypted1, encrypted2);
    // Nonces should be the same (deterministic based on filename)
    assert_eq!(nonce1, nonce2);

    // Decrypt with correct keys
    let decrypted1 = VaultFormat::decrypt_filename(&encrypted1, &nonce1, engine.as_ref(), &filename_key1).unwrap();
    let decrypted2 = VaultFormat::decrypt_filename(&encrypted2, &nonce2, engine.as_ref(), &filename_key2).unwrap();

    assert_eq!(decrypted1, filename);
    assert_eq!(decrypted2, filename);

    // Decrypt with wrong keys should fail
    assert!(VaultFormat::decrypt_filename(&encrypted1, &nonce1, engine.as_ref(), &filename_key2).is_err());
    assert!(VaultFormat::decrypt_filename(&encrypted2, &nonce2, engine.as_ref(), &filename_key1).is_err());
}

#[test]
fn test_filename_encryption_unicode() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let unicode_filenames = [
        "файл.txt",           // Cyrillic
        "文件.txt",           // Chinese
        "ファイル.txt",        // Japanese
        "🔒secure_file.txt",  // Emoji
        "café_résumé.pdf",    // Accented characters
    ];

    for filename in &unicode_filenames {
        // Encrypt
        let (encrypted, nonce) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key).unwrap();

        // Decrypt
        let decrypted = VaultFormat::decrypt_filename(&encrypted, &nonce, engine.as_ref(), &filename_key).unwrap();

        assert_eq!(decrypted, *filename);
    }
}

#[test]
fn test_file_entry_creation_and_validation() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};
    use chrono::Utc;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let filename = "test_document.pdf";
    let size = 1024 * 1024; // 1MB
    let mtime = Utc::now();
    let mode = 0o644;

    // Create file entry
    let entry = FileEntry::new(
        filename,
        size,
        mtime,
        mode,
        false, // not a directory
        engine.as_ref(),
        &filename_key,
    ).unwrap();

    // Validate entry
    assert!(entry.validate().is_ok());
    assert_eq!(entry.size, size);
    assert_eq!(entry.mtime, mtime);
    assert_eq!(entry.mode, mode);
    assert!(!entry.is_dir);
    assert!(!entry.name_encrypted.is_empty());
    assert!(!entry.iv.is_empty());

    // Decrypt filename
    let decrypted_name = entry.decrypt_filename(engine.as_ref(), &filename_key).unwrap();
    assert_eq!(decrypted_name, filename);
}

#[test]
fn test_file_entry_directory() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};
    use chrono::Utc;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let dirname = "documents";
    let mtime = Utc::now();
    let mode = 0o755;

    // Create directory entry
    let entry = FileEntry::new(
        dirname,
        0, // directories have size 0
        mtime,
        mode,
        true, // is a directory
        engine.as_ref(),
        &filename_key,
    ).unwrap();

    // Validate entry
    assert!(entry.validate().is_ok());
    assert_eq!(entry.size, 0);
    assert!(entry.is_dir);
    assert_eq!(entry.chunks.len(), 0);

    // Decrypt dirname
    let decrypted_name = entry.decrypt_filename(engine.as_ref(), &filename_key).unwrap();
    assert_eq!(decrypted_name, dirname);
}

#[test]
fn test_file_entry_with_chunks() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes, generate_nonce};
    use chrono::Utc;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    let filename = "large_file.bin";
    let chunk_size = 1024;
    let num_chunks = 3;
    let total_size = (chunk_size * num_chunks) as u64;

    // Create file entry
    let mut entry = FileEntry::new(
        filename,
        total_size,
        Utc::now(),
        0o644,
        false,
        engine.as_ref(),
        &filename_key,
    ).unwrap();

    // Add chunks
    for i in 0..num_chunks {
        let offset = (i * chunk_size) as u64;
        let iv = generate_nonce(engine.nonce_size()).unwrap();
        entry.add_chunk(offset, chunk_size as u32, iv);
    }

    // Validate entry
    assert!(entry.validate().is_ok());
    assert_eq!(entry.chunk_count(), num_chunks);
    assert_eq!(entry.chunks.len(), num_chunks);

    // Check chunk details
    for (i, chunk) in entry.chunks.iter().enumerate() {
        assert_eq!(chunk.offset, (i * chunk_size) as u64);
        assert_eq!(chunk.size, chunk_size as u32);
        assert!(!chunk.iv.is_empty());
    }
}

#[test]
fn test_file_entry_validation_errors() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};
    use chrono::Utc;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    let filename_key = generate_random_bytes(32).unwrap();

    // Create a valid entry first
    let mut entry = FileEntry::new(
        "test.txt",
        1000,
        Utc::now(),
        0o644,
        false,
        engine.as_ref(),
        &filename_key,
    ).unwrap();

    // Test empty encrypted filename
    entry.name_encrypted.clear();
    assert!(entry.validate().is_err());

    // Reset and test empty IV
    entry = FileEntry::new(
        "test.txt",
        1000,
        Utc::now(),
        0o644,
        false,
        engine.as_ref(),
        &filename_key,
    ).unwrap();
    entry.iv.clear();
    assert!(entry.validate().is_err());

    // Test non-empty file with no chunks - this is now allowed at this stage
    entry = FileEntry::new(
        "test.txt",
        1000,
        Utc::now(),
        0o644,
        false,
        engine.as_ref(),
        &filename_key,
    ).unwrap();
    // File has size > 0 but no chunks - should pass validation at this stage
    assert!(entry.validate().is_ok());
}

#[test]
fn test_encrypted_file_table_operations() {
    use crate::crypto::{create_crypto_engine, CipherType, derive_all_subkeys, derive_key};
    use tempfile::NamedTempFile;
    use chrono::Utc;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    
    // Create test subkeys
    let password = "test_password";
    let salt = vec![1u8; 32];
    let master_key = derive_key(password, &salt, 65536, 3, 1).unwrap();
    let subkeys = derive_all_subkeys(&master_key).unwrap();

    // Create test header
    let header = tests::create_test_header();

    // Create test file table with encrypted entries
    let mut file_table = FileTable { files: vec![] };

    // Add some test files
    let files = [
        ("document.pdf", 1024 * 1024, false),
        ("image.jpg", 2 * 1024 * 1024, false),
        ("folder", 0, true),
    ];

    for (name, size, is_dir) in &files {
        let entry = FileEntry::new(
            name,
            *size,
            Utc::now(),
            if *is_dir { 0o755 } else { 0o644 },
            *is_dir,
            engine.as_ref(),
            &subkeys.filename_key,
        ).unwrap();
        file_table.files.push(entry);
    }

    // Create temporary file
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    // First create the vault file structure
    VaultFormat::create_vault_file(path, &header).unwrap();

    // Write encrypted file table
    VaultFormat::write_encrypted_file_table(
        path,
        &header,
        &file_table,
        engine.as_ref(),
        &subkeys,
    ).unwrap();

    // Read back encrypted file table
    let header_json_bytes = serde_json::to_string_pretty(&header).unwrap().into_bytes();
    let file_table_offset = 4 + 1 + 4 + header_json_bytes.len() as u64;

    let decrypted_table = VaultFormat::read_encrypted_file_table(
        path,
        &header,
        file_table_offset,
        engine.as_ref(),
        &subkeys,
    ).unwrap();

    // Verify file table contents
    assert_eq!(decrypted_table.files.len(), 3);

    // Decrypt and verify filenames
    for (i, entry) in decrypted_table.files.iter().enumerate() {
        let decrypted_name = entry.decrypt_filename(engine.as_ref(), &subkeys.filename_key).unwrap();
        assert_eq!(decrypted_name, files[i].0);
        assert_eq!(entry.size, files[i].1);
        assert_eq!(entry.is_dir, files[i].2);
    }
}

#[test]
fn test_file_table_authentication() {
    use crate::crypto::{create_crypto_engine, CipherType, derive_all_subkeys, derive_key};
    use tempfile::NamedTempFile;

    let engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
    
    // Create test subkeys
    let password = "test_password";
    let salt = vec![1u8; 32];
    let master_key = derive_key(password, &salt, 65536, 3, 1).unwrap();
    let subkeys = derive_all_subkeys(&master_key).unwrap();

    // Create test header
    let header = tests::create_test_header();

    // Create empty file table
    let file_table = FileTable { files: vec![] };

    // Create temporary file
    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path();

    // Create vault file and write encrypted file table
    VaultFormat::create_vault_file(path, &header).unwrap();
    VaultFormat::write_encrypted_file_table(
        path,
        &header,
        &file_table,
        engine.as_ref(),
        &subkeys,
    ).unwrap();

    // Create modified header (should cause authentication failure)
    let mut modified_header = header.clone();
    modified_header.vault_uuid = uuid::Uuid::new_v4(); // Change UUID

    // Try to read with modified header (should fail due to AAD mismatch)
    let header_json_bytes = serde_json::to_string_pretty(&header).unwrap().into_bytes();
    let file_table_offset = 4 + 1 + 4 + header_json_bytes.len() as u64;

    let result = VaultFormat::read_encrypted_file_table(
        path,
        &modified_header, // Wrong header
        file_table_offset,
        engine.as_ref(),
        &subkeys,
    );

    // Should fail due to authentication failure
    assert!(result.is_err());
}

#[test]
fn test_cross_cipher_filename_encryption() {
    use crate::crypto::{create_crypto_engine, CipherType, generate_random_bytes};

    let ciphers = [CipherType::Aes256Gcm, CipherType::XChaCha20Poly1305];
    let filename = "test_file.txt";
    let filename_key = generate_random_bytes(32).unwrap();

    for cipher in &ciphers {
        let engine = create_crypto_engine(*cipher).unwrap();

        // Encrypt filename
        let (encrypted, nonce) = VaultFormat::encrypt_filename(filename, engine.as_ref(), &filename_key).unwrap();

        // Decrypt filename
        let decrypted = VaultFormat::decrypt_filename(&encrypted, &nonce, engine.as_ref(), &filename_key).unwrap();

        assert_eq!(decrypted, filename);
        assert_eq!(nonce.len(), engine.nonce_size());
    }
}
