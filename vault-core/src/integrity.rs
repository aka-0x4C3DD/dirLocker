//! Vault integrity checking and repair mechanisms
//!
//! This module provides functionality for:
//! - Atomic write operations using temp-file-then-rename pattern
//! - Chunk integrity validation using AEAD tags
//! - Vault repair functionality that reconstructs file table from valid chunks
//! - Partial recovery system for corrupted vaults
//! - Integrity checking and validation functions

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::crypto::{CryptoEngine, SubKeys, create_crypto_engine, CipherType};
use crate::error::{VaultError, VaultResult};
use crate::format::{VaultFormat, VaultHeader, FileTable, FileEntry, ChunkInfo};

/// Atomic file writer that uses temp-file-then-rename pattern
pub struct AtomicFileWriter {
    temp_path: PathBuf,
    final_path: PathBuf,
    file: Option<File>,
}

impl AtomicFileWriter {
    /// Create a new atomic file writer
    pub fn new<P: AsRef<Path>>(final_path: P) -> VaultResult<Self> {
        let final_path = final_path.as_ref().to_path_buf();
        let temp_path = Self::generate_temp_path(&final_path)?;
        
        let file = File::create(&temp_path)?;
        
        Ok(AtomicFileWriter {
            temp_path,
            final_path,
            file: Some(file),
        })
    }

    /// Generate a temporary file path
    fn generate_temp_path(original_path: &Path) -> VaultResult<PathBuf> {
        let mut temp_path = original_path.to_path_buf();
        
        // Add random suffix to avoid conflicts
        let random_suffix: u64 = rand::random();
        let temp_name = format!("{}.tmp.{}", 
            original_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault"),
            random_suffix
        );
        
        temp_path.set_file_name(temp_name);
        Ok(temp_path)
    }

    /// Write data to the temporary file
    pub fn write(&mut self, data: &[u8]) -> VaultResult<()> {
        if let Some(ref mut file) = self.file {
            file.write_all(data)?;
            Ok(())
        } else {
            Err(VaultError::internal_error("AtomicFileWriter already committed or aborted"))
        }
    }

    /// Flush the temporary file
    pub fn flush(&mut self) -> VaultResult<()> {
        if let Some(ref mut file) = self.file {
            file.flush()?;
            Ok(())
        } else {
            Err(VaultError::internal_error("AtomicFileWriter already committed or aborted"))
        }
    }

    /// Commit the write by atomically renaming temp file to final location
    pub fn commit(mut self) -> VaultResult<()> {
        if let Some(file) = self.file.take() {
            // Ensure all data is written to disk
            file.sync_all()?;
            drop(file);
            
            // Atomic rename
            std::fs::rename(&self.temp_path, &self.final_path)?;
            Ok(())
        } else {
            Err(VaultError::internal_error("AtomicFileWriter already committed or aborted"))
        }
    }

    /// Abort the write by removing the temporary file
    pub fn abort(mut self) -> VaultResult<()> {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.temp_path); // Ignore errors on cleanup
        }
        Ok(())
    }
}

impl Drop for AtomicFileWriter {
    fn drop(&mut self) {
        if self.file.is_some() {
            // Auto-cleanup temp file if not committed
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

/// Chunk integrity validation result
#[derive(Debug, Clone)]
pub struct ChunkValidationResult {
    pub is_valid: bool,
    pub error_message: Option<String>,
    pub chunk_index: usize,
    pub chunk_offset: u64,
    pub chunk_size: u32,
}

/// File integrity validation result
#[derive(Debug, Clone)]
pub struct FileValidationResult {
    pub filename: String,
    pub is_valid: bool,
    pub total_chunks: usize,
    pub valid_chunks: usize,
    pub invalid_chunks: Vec<ChunkValidationResult>,
    pub can_be_recovered: bool,
}

/// Vault integrity validation result
#[derive(Debug, Clone)]
pub struct VaultValidationResult {
    pub is_valid: bool,
    pub header_valid: bool,
    pub file_table_valid: bool,
    pub total_files: usize,
    pub valid_files: usize,
    pub corrupted_files: Vec<FileValidationResult>,
    pub recoverable_files: usize,
}

/// Vault repair result
#[derive(Debug, Clone)]
pub struct VaultRepairResult {
    pub success: bool,
    pub files_recovered: usize,
    pub files_lost: usize,
    pub chunks_recovered: usize,
    pub chunks_lost: usize,
    pub repair_log: Vec<String>,
}

/// Vault integrity checker and repair system
pub struct VaultIntegrityChecker;

impl VaultIntegrityChecker {
    /// Validate the integrity of an entire vault
    pub fn validate_vault<P: AsRef<Path>>(
        path: P,
        password: &str,
    ) -> VaultResult<VaultValidationResult> {
        let path = path.as_ref();
        
        // Try to read and validate header
        let header_valid = match VaultFormat::read_vault_header(path) {
            Ok((header, _)) => {
                // Additional header validation
                Self::validate_header_integrity(&header).is_ok()
            }
            Err(_) => false,
        };

        if !header_valid {
            return Ok(VaultValidationResult {
                is_valid: false,
                header_valid: false,
                file_table_valid: false,
                total_files: 0,
                valid_files: 0,
                corrupted_files: vec![],
                recoverable_files: 0,
            });
        }

        // Read header and derive keys
        let (header, file_table_offset) = VaultFormat::read_vault_header(path)?;
        let cipher_type: CipherType = header.cipher.parse()?;
        let crypto = create_crypto_engine(cipher_type)?;
        
        let master_key = crate::crypto::derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;
        
        let subkeys = crate::crypto::derive_all_subkeys(&master_key)?;

        // Try to read and validate file table
        let (file_table_valid, file_table) = match VaultFormat::read_encrypted_file_table(
            path,
            &header,
            file_table_offset,
            crypto.as_ref(),
            &subkeys,
        ) {
            Ok(table) => (true, Some(table)),
            Err(VaultError::CryptoError { .. }) => {
                // Crypto error likely means wrong password - propagate it
                return Err(VaultError::InvalidPassword);
            }
            Err(_) => (false, None),
        };

        let mut result = VaultValidationResult {
            is_valid: header_valid && file_table_valid,
            header_valid,
            file_table_valid,
            total_files: 0,
            valid_files: 0,
            corrupted_files: vec![],
            recoverable_files: 0,
        };

        // If we have a valid file table, validate individual files
        if let Some(file_table) = file_table {
            result.total_files = file_table.files.len();
            
            for file_entry in &file_table.files {
                let file_result = Self::validate_file_integrity(
                    path,
                    file_entry,
                    &header,
                    crypto.as_ref(),
                    &subkeys,
                )?;
                
                if file_result.is_valid {
                    result.valid_files += 1;
                } else {
                    if file_result.can_be_recovered {
                        result.recoverable_files += 1;
                    }
                    result.corrupted_files.push(file_result);
                }
            }
            
            result.is_valid = result.is_valid && result.corrupted_files.is_empty();
        }

        Ok(result)
    }

    /// Validate the integrity of a single file's chunks
    pub fn validate_file_integrity<P: AsRef<Path>>(
        vault_path: P,
        file_entry: &FileEntry,
        _header: &VaultHeader,
        crypto: &dyn CryptoEngine,
        subkeys: &SubKeys,
    ) -> VaultResult<FileValidationResult> {
        let vault_path = vault_path.as_ref();
        
        // Decrypt filename for reporting
        let filename = file_entry.decrypt_filename(crypto, &subkeys.filename_key)
            .unwrap_or_else(|_| "<corrupted_filename>".to_string());

        let mut invalid_chunks = Vec::new();
        let mut valid_chunks = 0;

        // Validate each chunk
        for (chunk_index, chunk) in file_entry.chunks.iter().enumerate() {
            let chunk_result = Self::validate_chunk_integrity(
                vault_path,
                chunk,
                chunk_index,
                crypto,
                &subkeys.file_encryption_key,
            );

            match chunk_result {
                Ok(()) => valid_chunks += 1,
                Err(error) => {
                    invalid_chunks.push(ChunkValidationResult {
                        is_valid: false,
                        error_message: Some(error.to_string()),
                        chunk_index,
                        chunk_offset: chunk.offset,
                        chunk_size: chunk.size,
                    });
                }
            }
        }

        let total_chunks = file_entry.chunks.len();
        let is_valid = invalid_chunks.is_empty();
        
        // A file can be recovered if at least 50% of chunks are valid
        let can_be_recovered = valid_chunks > 0 && (valid_chunks as f64 / total_chunks as f64) >= 0.5;

        Ok(FileValidationResult {
            filename,
            is_valid,
            total_chunks,
            valid_chunks,
            invalid_chunks,
            can_be_recovered,
        })
    }

    /// Validate the integrity of a single chunk using AEAD tags
    pub fn validate_chunk_integrity<P: AsRef<Path>>(
        vault_path: P,
        chunk: &ChunkInfo,
        chunk_index: usize,
        crypto: &dyn CryptoEngine,
        file_encryption_key: &[u8],
    ) -> VaultResult<()> {
        let vault_path = vault_path.as_ref();

        // Read the chunk data
        let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
            vault_path,
            chunk.offset,
            chunk.size,
            crypto.nonce_size(),
        ).map_err(|e| VaultError::corrupted_vault(format!(
            "Failed to read chunk {} at offset {}: {}",
            chunk_index, chunk.offset, e
        )))?;

        // Verify the nonce matches what's stored in the chunk info
        if nonce != chunk.iv {
            return Err(VaultError::corrupted_vault(format!(
                "Chunk {} nonce mismatch: expected {:?}, got {:?}",
                chunk_index, chunk.iv, nonce
            )));
        }

        // Try to decrypt the chunk - this validates the AEAD tag
        crypto.decrypt(
            file_encryption_key,
            &nonce,
            &encrypted_chunk,
            &[], // No AAD for chunks
        ).map_err(|e| VaultError::corrupted_vault(format!(
            "Chunk {} AEAD validation failed: {}",
            chunk_index, e
        )))?;

        Ok(())
    }

    /// Validate header integrity and consistency
    fn validate_header_integrity(header: &VaultHeader) -> VaultResult<()> {
        // Check cipher is supported
        let _cipher_type: CipherType = header.cipher.parse()
            .map_err(|_| VaultError::corrupted_vault(format!("Invalid cipher: {}", header.cipher)))?;

        // Validate KDF parameters
        if header.kdf != "argon2id" {
            return Err(VaultError::corrupted_vault(format!("Invalid KDF: {}", header.kdf)));
        }

        if header.kdf_params.salt.len() < 16 {
            return Err(VaultError::corrupted_vault("Salt too short".to_string()));
        }

        if header.kdf_params.memory < 1024 {
            return Err(VaultError::corrupted_vault("Memory parameter too low".to_string()));
        }

        // Validate offsets and sizes
        if header.file_table_offset == 0 {
            return Err(VaultError::corrupted_vault("Invalid file table offset".to_string()));
        }

        if header.file_table_reserved_size < 64 * 1024 {
            return Err(VaultError::corrupted_vault("File table reserved size too small".to_string()));
        }

        if header.chunk_size < 1024 || header.chunk_size > 64 * 1024 * 1024 {
            return Err(VaultError::corrupted_vault("Invalid chunk size".to_string()));
        }

        // Validate UUID
        if header.vault_uuid.is_nil() {
            return Err(VaultError::corrupted_vault("Invalid vault UUID".to_string()));
        }

        Ok(())
    }

    /// Repair a corrupted vault by reconstructing the file table from valid chunks
    pub fn repair_vault<P: AsRef<Path>>(
        path: P,
        password: &str,
        create_backup: bool,
    ) -> VaultResult<VaultRepairResult> {
        let path = path.as_ref();
        let mut repair_log = Vec::new();

        // Create backup if requested
        if create_backup {
            let backup_path = Self::create_backup_path(path)?;
            std::fs::copy(path, &backup_path)?;
            repair_log.push(format!("Created backup at: {}", backup_path.display()));
        }

        // Try to read header
        let (header, file_table_offset) = VaultFormat::read_vault_header(path)
            .map_err(|e| VaultError::corrupted_vault(format!("Cannot read vault header: {}", e)))?;

        let cipher_type: CipherType = header.cipher.parse()?;
        let crypto = create_crypto_engine(cipher_type)?;
        
        let master_key = crate::crypto::derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;
        
        let subkeys = crate::crypto::derive_all_subkeys(&master_key)?;

        // Try to read existing file table
        let existing_file_table = VaultFormat::read_encrypted_file_table(
            path,
            &header,
            file_table_offset,
            crypto.as_ref(),
            &subkeys,
        ).ok();

        if let Some(file_table) = existing_file_table {
            repair_log.push("Existing file table found, validating files...".to_string());
            
            // Validate and repair existing file table
            Self::repair_existing_file_table(
                path,
                &header,
                file_table,
                crypto.as_ref(),
                &subkeys,
                &mut repair_log,
            )
        } else {
            repair_log.push("File table corrupted, attempting reconstruction from chunks...".to_string());
            
            // Reconstruct file table from scratch by scanning chunks
            Self::reconstruct_file_table_from_chunks(
                path,
                &header,
                crypto.as_ref(),
                &subkeys,
                &mut repair_log,
            )
        }
    }

    /// Repair an existing file table by removing corrupted entries and fixing valid ones
    fn repair_existing_file_table<P: AsRef<Path>>(
        vault_path: P,
        header: &VaultHeader,
        mut file_table: FileTable,
        crypto: &dyn CryptoEngine,
        subkeys: &SubKeys,
        repair_log: &mut Vec<String>,
    ) -> VaultResult<VaultRepairResult> {
        let vault_path = vault_path.as_ref();
        let mut files_recovered = 0;
        let mut files_lost = 0;
        let mut chunks_recovered = 0;
        let mut chunks_lost = 0;

        let mut valid_files = Vec::new();

        // Validate each file and its chunks
        for file_entry in file_table.files {
            let file_result = Self::validate_file_integrity(
                vault_path,
                &file_entry,
                header,
                crypto,
                subkeys,
            )?;

            if file_result.is_valid {
                // File is completely valid
                valid_files.push(file_entry);
                files_recovered += 1;
                chunks_recovered += file_result.total_chunks;
                repair_log.push(format!("File '{}' is valid", file_result.filename));
            } else if file_result.can_be_recovered {
                // File has some valid chunks, try to recover
                let recovered_file = Self::recover_partial_file(
                    vault_path,
                    &file_entry,
                    header,
                    crypto,
                    subkeys,
                    repair_log,
                )?;
                
                if let Some(recovered) = recovered_file {
                    valid_files.push(recovered);
                    files_recovered += 1;
                    chunks_recovered += file_result.valid_chunks;
                    chunks_lost += file_result.invalid_chunks.len();
                    repair_log.push(format!(
                        "File '{}' partially recovered ({}/{} chunks)",
                        file_result.filename, file_result.valid_chunks, file_result.total_chunks
                    ));
                } else {
                    files_lost += 1;
                    chunks_lost += file_result.total_chunks;
                    repair_log.push(format!("File '{}' could not be recovered", file_result.filename));
                }
            } else {
                // File is too corrupted to recover
                files_lost += 1;
                chunks_lost += file_result.total_chunks;
                repair_log.push(format!("File '{}' is too corrupted to recover", file_result.filename));
            }
        }

        // Update file table with valid files
        file_table.files = valid_files;

        // Write repaired file table
        VaultFormat::write_encrypted_file_table(
            vault_path,
            header,
            &file_table,
            crypto,
            subkeys,
        )?;

        repair_log.push("Repaired file table written successfully".to_string());

        Ok(VaultRepairResult {
            success: true,
            files_recovered,
            files_lost,
            chunks_recovered,
            chunks_lost,
            repair_log: repair_log.clone(),
        })
    }

    /// Reconstruct file table from scratch by scanning all chunks in the vault
    fn reconstruct_file_table_from_chunks<P: AsRef<Path>>(
        _vault_path: P,
        _header: &VaultHeader,
        _crypto: &dyn CryptoEngine,
        _subkeys: &SubKeys,
        repair_log: &mut Vec<String>,
    ) -> VaultResult<VaultRepairResult> {
        
        repair_log.push("Scanning vault for recoverable chunks...".to_string());
        
        // This is a complex operation that would scan the entire vault file
        // looking for valid encrypted chunks. For now, we'll return a basic result
        // indicating that reconstruction is not yet implemented.
        
        repair_log.push("Full reconstruction from chunks is not yet implemented".to_string());
        repair_log.push("Please restore from backup if available".to_string());

        Ok(VaultRepairResult {
            success: false,
            files_recovered: 0,
            files_lost: 0,
            chunks_recovered: 0,
            chunks_lost: 0,
            repair_log: repair_log.clone(),
        })
    }

    /// Attempt to recover a partially corrupted file by keeping only valid chunks
    fn recover_partial_file<P: AsRef<Path>>(
        vault_path: P,
        file_entry: &FileEntry,
        _header: &VaultHeader,
        crypto: &dyn CryptoEngine,
        subkeys: &SubKeys,
        repair_log: &mut Vec<String>,
    ) -> VaultResult<Option<FileEntry>> {
        let vault_path = vault_path.as_ref();
        let mut valid_chunks = Vec::new();
        let mut recovered_size = 0u64;

        // Test each chunk and keep only valid ones
        for (chunk_index, chunk) in file_entry.chunks.iter().enumerate() {
            match Self::validate_chunk_integrity(
                vault_path,
                chunk,
                chunk_index,
                crypto,
                &subkeys.file_encryption_key,
            ) {
                Ok(()) => {
                    // Chunk is valid, try to decrypt to get actual size
                    if let Ok((nonce, encrypted_chunk)) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                        vault_path,
                        chunk.offset,
                        chunk.size,
                        crypto.nonce_size(),
                    ) {
                        if let Ok(decrypted) = crypto.decrypt(
                            &subkeys.file_encryption_key,
                            &nonce,
                            &encrypted_chunk,
                            &[],
                        ) {
                            valid_chunks.push(chunk.clone());
                            recovered_size += decrypted.len() as u64;
                        }
                    }
                }
                Err(_) => {
                    // Chunk is corrupted, skip it
                    repair_log.push(format!("Skipping corrupted chunk {} in file", chunk_index));
                }
            }
        }

        if valid_chunks.is_empty() {
            return Ok(None);
        }

        // Create a new file entry with only valid chunks
        let mut recovered_file = file_entry.clone();
        recovered_file.chunks = valid_chunks;
        recovered_file.size = recovered_size;

        Ok(Some(recovered_file))
    }

    /// Create a backup file path
    fn create_backup_path(original_path: &Path) -> VaultResult<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let mut backup_path = original_path.to_path_buf();
        
        let backup_name = format!("{}.backup.{}",
            original_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault"),
            timestamp
        );
        
        backup_path.set_file_name(backup_name);
        Ok(backup_path)
    }

    /// Perform a quick integrity check without full validation
    pub fn quick_integrity_check<P: AsRef<Path>>(path: P) -> VaultResult<bool> {
        let path = path.as_ref();
        
        // Check if file exists and is readable
        if !path.exists() {
            return Ok(false);
        }

        // Try to read header
        match VaultFormat::read_vault_header(path) {
            Ok((header, _)) => {
                // Basic header validation
                Ok(Self::validate_header_integrity(&header).is_ok())
            }
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::vault::Vault;
    use crate::crypto::CipherType;

    #[test]
    fn test_atomic_file_writer_success() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        let test_data = b"Hello, atomic world!";
        
        {
            let mut writer = AtomicFileWriter::new(&file_path).unwrap();
            writer.write(test_data).unwrap();
            writer.flush().unwrap();
            
            // File should not exist yet
            assert!(!file_path.exists());
            
            writer.commit().unwrap();
        }
        
        // File should exist now
        assert!(file_path.exists());
        let content = std::fs::read(&file_path).unwrap();
        assert_eq!(content, test_data);
    }

    #[test]
    fn test_atomic_file_writer_abort() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        let test_data = b"This should not be written";
        
        {
            let mut writer = AtomicFileWriter::new(&file_path).unwrap();
            writer.write(test_data).unwrap();
            writer.flush().unwrap();
            
            // File should not exist yet
            assert!(!file_path.exists());
            
            writer.abort().unwrap();
        }
        
        // File should still not exist
        assert!(!file_path.exists());
    }

    #[test]
    fn test_atomic_file_writer_drop_cleanup() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        
        let test_data = b"This should be cleaned up";
        
        {
            let mut writer = AtomicFileWriter::new(&file_path).unwrap();
            writer.write(test_data).unwrap();
            writer.flush().unwrap();
            
            // File should not exist yet
            assert!(!file_path.exists());
            
            // Drop without commit - should clean up temp file
        }
        
        // File should still not exist
        assert!(!file_path.exists());
    }

    #[test]
    fn test_vault_integrity_validation_valid_vault() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a valid vault
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        
        // Add some test files
        vault.write_file("test1.txt", b"Hello, World!").unwrap();
        vault.write_file("test2.txt", b"Another test file with more content").unwrap();
        drop(vault);

        // Validate the vault
        let result = VaultIntegrityChecker::validate_vault(&vault_path, password).unwrap();
        
        assert!(result.is_valid);
        assert!(result.header_valid);
        assert!(result.file_table_valid);
        assert_eq!(result.total_files, 2);
        assert_eq!(result.valid_files, 2);
        assert!(result.corrupted_files.is_empty());
    }

    #[test]
    fn test_vault_integrity_validation_wrong_password() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "correct_password";
        let wrong_password = "wrong_password";

        // Create a valid vault
        let vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        drop(vault);

        // Try to validate with wrong password
        let result = VaultIntegrityChecker::validate_vault(&vault_path, wrong_password);
        
        // Should fail due to wrong password
        assert!(result.is_err());
    }

    #[test]
    fn test_quick_integrity_check() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let nonexistent_path = temp_dir.path().join("nonexistent.vault");

        // Test nonexistent file
        assert!(!VaultIntegrityChecker::quick_integrity_check(&nonexistent_path).unwrap());

        // Create a valid vault
        let vault = Vault::create(&vault_path, "password", CipherType::Aes256Gcm).unwrap();
        drop(vault);

        // Test valid vault
        assert!(VaultIntegrityChecker::quick_integrity_check(&vault_path).unwrap());

        // Test corrupted vault (truncate the file)
        let _original_size = std::fs::metadata(&vault_path).unwrap().len();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&vault_path)
            .unwrap();
        file.set_len(10).unwrap(); // Truncate to 10 bytes
        drop(file);

        assert!(!VaultIntegrityChecker::quick_integrity_check(&vault_path).unwrap());
    }

    #[test]
    fn test_chunk_integrity_validation() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a vault with a file
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("test.txt", b"Hello, World! This is a test file.").unwrap();
        
        let files = vault.list_files().unwrap();
        let file_entry = &files[0].1;
        let _header = vault.header().clone();
        let crypto = vault.crypto();
        let subkeys = vault.subkeys().unwrap();
        
        // Validate the chunk
        let chunk = &file_entry.chunks[0];
        let result = VaultIntegrityChecker::validate_chunk_integrity(
            &vault_path,
            chunk,
            0,
            crypto,
            &subkeys.file_encryption_key,
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_integrity_validation() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a vault with a file
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("test.txt", b"Hello, World! This is a test file.").unwrap();
        
        let files = vault.list_files().unwrap();
        let file_entry = &files[0].1;
        let header = vault.header().clone();
        let crypto = vault.crypto();
        let subkeys = vault.subkeys().unwrap();
        
        // Validate the file
        let result = VaultIntegrityChecker::validate_file_integrity(
            &vault_path,
            file_entry,
            &header,
            crypto,
            subkeys,
        ).unwrap();
        
        assert!(result.is_valid);
        assert_eq!(result.filename, "test.txt");
        assert_eq!(result.total_chunks, 1);
        assert_eq!(result.valid_chunks, 1);
        assert!(result.invalid_chunks.is_empty());
        assert!(result.can_be_recovered);
    }

    #[test]
    fn test_vault_repair_valid_vault() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a valid vault
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("test1.txt", b"Hello, World!").unwrap();
        vault.write_file("test2.txt", b"Another test file").unwrap();
        drop(vault);

        // Repair the vault (should succeed with no changes needed)
        let result = VaultIntegrityChecker::repair_vault(&vault_path, password, false).unwrap();
        
        assert!(result.success);
        assert_eq!(result.files_recovered, 2);
        assert_eq!(result.files_lost, 0);
        assert!(result.chunks_recovered >= 2); // At least one chunk per file
        assert_eq!(result.chunks_lost, 0);
    }

    #[test]
    fn test_atomic_file_writer_multiple_writes() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("multi_write.txt");
        
        let data1 = b"First chunk of data\n";
        let data2 = b"Second chunk of data\n";
        let data3 = b"Third chunk of data\n";
        
        {
            let mut writer = AtomicFileWriter::new(&file_path).unwrap();
            writer.write(data1).unwrap();
            writer.write(data2).unwrap();
            writer.write(data3).unwrap();
            writer.flush().unwrap();
            
            // File should not exist yet
            assert!(!file_path.exists());
            
            writer.commit().unwrap();
        }
        
        // File should exist now with all data
        assert!(file_path.exists());
        let content = std::fs::read(&file_path).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        expected.extend_from_slice(data3);
        assert_eq!(content, expected);
    }

    #[test]
    fn test_corrupted_vault_detection() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a valid vault with multiple files
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("file1.txt", b"Content of file 1").unwrap();
        vault.write_file("file2.txt", b"Content of file 2 with more data").unwrap();
        vault.write_file("file3.txt", b"Content of file 3").unwrap();
        drop(vault);

        // Validate the vault is initially valid
        let result = VaultIntegrityChecker::validate_vault(&vault_path, password).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.total_files, 3);
        assert_eq!(result.valid_files, 3);

        // Corrupt the vault by truncating it
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&vault_path)
            .unwrap();
        file.set_len(100).unwrap(); // Truncate to 100 bytes
        drop(file);

        // Validate that corruption is detected
        assert!(!VaultIntegrityChecker::quick_integrity_check(&vault_path).unwrap());
    }

    #[test]
    fn test_vault_repair_with_backup() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a valid vault
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("important.txt", b"Important data that should be preserved").unwrap();
        drop(vault);

        // Repair the vault with backup creation
        let result = VaultIntegrityChecker::repair_vault(&vault_path, password, true).unwrap();
        
        assert!(result.success);
        assert_eq!(result.files_recovered, 1);
        assert_eq!(result.files_lost, 0);
        assert!(!result.repair_log.is_empty());
        
        // Check that backup was created
        let backup_files: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains("backup") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        
        assert!(!backup_files.is_empty(), "Backup file should have been created");
    }

    #[test]
    fn test_integrity_validation_with_large_file() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a vault with a large file (multiple chunks)
        let mut vault = Vault::create(&vault_path, password, CipherType::XChaCha20Poly1305).unwrap();
        
        // Create 8MB of test data (2 chunks of 4MB each)
        let chunk_size = 4 * 1024 * 1024;
        let large_data: Vec<u8> = (0..(2 * chunk_size)).map(|i| (i % 256) as u8).collect();
        
        vault.write_file("large_file.bin", &large_data).unwrap();
        drop(vault);

        // Validate the vault
        let result = VaultIntegrityChecker::validate_vault(&vault_path, password).unwrap();
        
        assert!(result.is_valid);
        assert_eq!(result.total_files, 1);
        assert_eq!(result.valid_files, 1);
        assert!(result.corrupted_files.is_empty());
        
        // Verify the file has multiple chunks
        let vault = Vault::open(&vault_path, password).unwrap();
        let files = vault.list_files().unwrap();
        let file_entry = &files[0].1;
        assert!(file_entry.chunks.len() >= 2, "Large file should have multiple chunks");
    }

    #[test]
    fn test_file_validation_result_structure() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.vault");
        let password = "test_password";

        // Create a vault with files
        let mut vault = Vault::create(&vault_path, password, CipherType::Aes256Gcm).unwrap();
        vault.write_file("small.txt", b"Small file").unwrap();
        vault.write_file("empty.txt", b"").unwrap();
        
        let files = vault.list_files().unwrap();
        let small_file_entry = &files[0].1;
        let empty_file_entry = &files[1].1;
        let header = vault.header().clone();
        let crypto = vault.crypto();
        let subkeys = vault.subkeys().unwrap();

        // Validate individual files
        let small_result = VaultIntegrityChecker::validate_file_integrity(
            &vault_path,
            small_file_entry,
            &header,
            crypto,
            subkeys,
        ).unwrap();

        let empty_result = VaultIntegrityChecker::validate_file_integrity(
            &vault_path,
            empty_file_entry,
            &header,
            crypto,
            subkeys,
        ).unwrap();

        // Check small file validation
        assert!(small_result.is_valid);
        assert_eq!(small_result.filename, "small.txt");
        assert_eq!(small_result.total_chunks, 1);
        assert_eq!(small_result.valid_chunks, 1);
        assert!(small_result.invalid_chunks.is_empty());
        assert!(small_result.can_be_recovered);

        // Check empty file validation
        assert!(empty_result.is_valid);
        assert_eq!(empty_result.filename, "empty.txt");
        assert_eq!(empty_result.total_chunks, 1); // Even empty files have one chunk
        assert_eq!(empty_result.valid_chunks, 1);
        assert!(empty_result.invalid_chunks.is_empty());
        assert!(empty_result.can_be_recovered);
    }}
