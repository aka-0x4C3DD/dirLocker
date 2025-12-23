//! Core vault implementation and handle management

use std::collections::HashMap;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{
    derive_all_subkeys, derive_key, generate_nonce, CipherType, CryptoEngine, SubKeys,
};
use crate::error::{VaultError, VaultResult};
use crate::format::{FileTable, KdfParams, VaultFormat, VaultHeader};
use crate::password::{AlgorithmRotationManager, PasswordManager, RecoveryKey, WrappedMasterKey};
use crate::sharing::{SharingManager, X25519KeyPair};

// Re-export format types for convenience
pub use crate::format::{ChunkInfo, FileEntry};

/// File information for FFI compatibility
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub mtime: chrono::DateTime<chrono::Utc>,
    pub mode: u32,
}

/// Vault space usage statistics
#[derive(Debug, Clone)]
pub struct VaultSpaceUsage {
    pub total_file_size: u64,
    pub used_space: u64,
    pub free_space: u64,
    pub fragmentation_count: usize,
    pub chunk_count: usize,
    pub file_count: usize,
}

/// File streaming interface for reading large files efficiently
pub struct FileStream {
    path: PathBuf,
    file_entry: FileEntry,
    chunk_size: u32,
    position: u64,
    crypto: Box<dyn CryptoEngine>,
    subkeys: SubKeys,
}

impl FileStream {
    pub fn new(
        path: PathBuf,
        file_entry: FileEntry,
        chunk_size: u32,
        crypto: &dyn CryptoEngine,
        subkeys: &SubKeys,
    ) -> Self {
        Self {
            path,
            file_entry,
            chunk_size,
            position: 0,
            crypto: crate::crypto::create_crypto_engine(crypto.cipher_type()).unwrap(),
            subkeys: subkeys.clone(),
        }
    }

    pub fn size(&self) -> u64 {
        self.file_entry.size
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn is_eof(&self) -> bool {
        self.position >= self.file_entry.size
    }

    pub fn seek(&mut self, position: u64) -> VaultResult<()> {
        self.position = std::cmp::min(position, self.file_entry.size);
        Ok(())
    }

    pub fn read(&mut self, length: usize) -> VaultResult<Vec<u8>> {
        if self.is_eof() {
            return Ok(Vec::new());
        }

        let end_position = std::cmp::min(self.position + length as u64, self.file_entry.size);
        let actual_length = end_position - self.position;

        let chunk_size = self.chunk_size as u64;
        let start_chunk = (self.position / chunk_size) as usize;
        let end_chunk = ((end_position - 1) / chunk_size) as usize;

        let mut result = Vec::with_capacity(actual_length as usize);

        // Read relevant chunks
        for chunk_index in start_chunk..=end_chunk {
            if chunk_index >= self.file_entry.chunks.len() {
                break;
            }

            let chunk = &self.file_entry.chunks[chunk_index];
            let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                &self.path,
                chunk.offset,
                chunk.size,
                self.crypto.nonce_size(),
            )?;

            // Decrypt chunk
            let decrypted_chunk = self.crypto.decrypt(
                &self.subkeys.file_encryption_key,
                &nonce,
                &encrypted_chunk,
                &[], // No AAD for chunks
            )?;

            // Calculate the portion of this chunk we need
            let chunk_start_offset = chunk_index as u64 * chunk_size;
            let chunk_end_offset = chunk_start_offset + decrypted_chunk.len() as u64;

            let copy_start = if self.position > chunk_start_offset {
                (self.position - chunk_start_offset) as usize
            } else {
                0
            };

            let copy_end = if end_position < chunk_end_offset {
                (end_position - chunk_start_offset) as usize
            } else {
                decrypted_chunk.len()
            };

            if copy_start < copy_end {
                result.extend_from_slice(&decrypted_chunk[copy_start..copy_end]);
            }
        }

        self.position = end_position;
        Ok(result)
    }

    pub fn read_exact(&mut self, length: usize) -> VaultResult<Vec<u8>> {
        let data = self.read(length)?;
        if data.len() != length {
            return Err(VaultError::internal_error(format!(
                "Could not read exact amount: requested {}, got {}",
                length,
                data.len()
            )));
        }
        Ok(data)
    }
}

/// Opaque handle for vault instances
pub type VaultHandle = usize;

/// Main vault structure
pub struct Vault {
    handle: VaultHandle,
    path: PathBuf,
    header: VaultHeader,
    crypto: Box<dyn CryptoEngine>,
    file_table: Option<FileTable>,
    subkeys: Option<SubKeys>,
    sharing_manager: Option<SharingManager>,
    deniability_manager: Option<crate::deniability::DeniabilityManager>,
    metadata_sections: Option<crate::format::MetadataSections>,
    is_open: bool,
}

/// Global vault registry for handle management
static VAULT_REGISTRY: Mutex<Option<VaultRegistry>> = Mutex::new(None);

struct VaultRegistry {
    vaults: HashMap<VaultHandle, Arc<Mutex<Vault>>>,
    next_handle: VaultHandle,
}

impl VaultRegistry {
    fn new() -> Self {
        Self {
            vaults: HashMap::new(),
            next_handle: 1,
        }
    }

    fn register_vault(&mut self, vault: Vault) -> VaultHandle {
        let handle = self.next_handle;
        self.next_handle += 1;

        let mut vault = vault;
        vault.handle = handle;

        self.vaults.insert(handle, Arc::new(Mutex::new(vault)));
        handle
    }

    fn get_vault(&self, handle: VaultHandle) -> Option<Arc<Mutex<Vault>>> {
        self.vaults.get(&handle).cloned()
    }

    fn remove_vault(&mut self, handle: VaultHandle) -> Option<Arc<Mutex<Vault>>> {
        self.vaults.remove(&handle)
    }
}

impl Vault {
    /// Create a new vault container
    pub fn create<P: AsRef<Path>>(
        path: P,
        password: &str,
        cipher_type: CipherType,
    ) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Validate inputs
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        if path.exists() {
            return Err(VaultError::invalid_argument("Vault file already exists"));
        }

        // Create crypto engine
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

        // Generate KDF parameters
        let mut salt = vec![0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|e| VaultError::crypto_error(format!("Failed to generate salt: {}", e)))?;

        let kdf_params = KdfParams {
            salt,
            memory: 65536, // 64MB
            operations: 3,
            parallelism: 1,
        };

        // Derive master key from password
        let master_key = derive_key(
            password,
            &kdf_params.salt,
            kdf_params.memory,
            kdf_params.operations,
            kdf_params.parallelism,
        )?;

        // Derive subkeys from master key
        let subkeys = derive_all_subkeys(&master_key)?;

        // Calculate proper offsets for the new layout
        let temp_header = VaultHeader {
            cipher: cipher_type.to_string(),
            kdf: "argon2id".to_string(),
            kdf_params: kdf_params.clone(),
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 0,
            file_table_size: 0,
            file_table_reserved_size: 1024 * 1024, // 1MB reserved for file table
            chunk_data_start_offset: 0,
            chunk_size: 4 * 1024 * 1024, // 4MB default
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: std::env::consts::OS.to_string(),
            file_table_version: 2, // Updated for metadata sections support
            metadata_sections_offset: 0,
            metadata_sections_size: 0,
            hidden_tables_offset: 0, // Legacy field for backward compatibility
            hidden_tables_size: 0,   // Legacy field for backward compatibility
        };

        // Calculate actual offsets using the same format as the file format
        // First pass to get approximate size
        let temp_header_json = serde_json::to_string(&temp_header)?;
        let approx_header_size = 4 + 1 + 4 + temp_header_json.len() as u64;

        // Simple layout: Header -> FileTable -> Chunks -> MetadataSections (at end)
        let file_table_offset = approx_header_size;
        let chunk_data_start_offset = file_table_offset + temp_header.file_table_reserved_size;

        // Create header with calculated offsets
        let mut header = VaultHeader {
            metadata_sections_offset: 0, // Will be set when metadata sections are added
            metadata_sections_size: 0,   // No metadata sections yet
            file_table_offset,
            chunk_data_start_offset,
            ..temp_header
        };

        // Second pass with updated header to get exact size
        let final_header_json = serde_json::to_string(&header)?;
        let final_header_size = 4 + 1 + 4 + final_header_json.len() as u64;

        // Recalculate with exact header size
        header.file_table_offset = final_header_size;
        header.chunk_data_start_offset = final_header_size + header.file_table_reserved_size;

        // Write vault file to disk
        VaultFormat::create_vault_file(&path, &header)?;

        // Write empty encrypted file table
        let empty_file_table = FileTable::new();
        VaultFormat::write_encrypted_file_table(
            &path,
            &header,
            &empty_file_table,
            crypto.as_ref(),
            &subkeys,
        )?;

        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header: header.clone(),
            crypto,
            file_table: Some(empty_file_table),
            subkeys: Some(subkeys),
            sharing_manager: Some(SharingManager::new(header.vault_uuid)),
            deniability_manager: Some(crate::deniability::DeniabilityManager::new(header.clone())),
            metadata_sections: Some(crate::format::MetadataSections::new()),
            is_open: true,
        };

        Ok(vault)
    }

    /// Open an existing vault container
    pub fn open<P: AsRef<Path>>(path: P, password: &str) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Validate inputs
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        if !path.exists() {
            return Err(VaultError::file_not_found(path.display().to_string()));
        }

        // Read and parse vault header
        let (header, file_table_offset) = VaultFormat::read_vault_header(&path)?;

        // Parse cipher type from header
        let cipher_type: CipherType = header.cipher.parse()?;

        // Create crypto engine
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

        // Derive master key from password to verify it's correct
        let master_key = derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;

        // Derive subkeys from master key
        let subkeys = derive_all_subkeys(&master_key)?;

        // Try to decrypt and parse file table
        let file_table = match VaultFormat::read_encrypted_file_table(
            &path,
            &header,
            file_table_offset,
            crypto.as_ref(),
            &subkeys,
        ) {
            Ok(table) => Some(table),
            Err(VaultError::CryptoError { .. }) => {
                // Decryption failed - likely wrong password
                return Err(VaultError::InvalidPassword);
            }
            Err(e) => return Err(e),
        };

        let mut deniability_mgr = crate::deniability::DeniabilityManager::new(header.clone());

        // Load hidden tables metadata if present
        if header.hidden_tables_offset > 0 {
            let _ = deniability_mgr.load_from_vault(&path, &subkeys.file_encryption_key);
            // Ignore errors - hidden tables are optional
        }

        // Load metadata sections by scanning the end of the file
        let metadata_sections = Some(
            Self::scan_for_metadata_sections(&path, crypto.as_ref(), &subkeys.metadata_key)
                .unwrap_or_else(|_| crate::format::MetadataSections::new()),
        );

        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header: header.clone(),
            crypto,
            file_table,
            subkeys: Some(subkeys),
            sharing_manager: Some(SharingManager::new(header.vault_uuid)),
            deniability_manager: Some(deniability_mgr),
            metadata_sections,
            is_open: true,
        };

        Ok(vault)
    }

    /// Get the vault handle
    pub fn handle(&self) -> VaultHandle {
        self.handle
    }

    /// Get the vault path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the vault header
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Get the crypto engine
    pub fn crypto(&self) -> &dyn CryptoEngine {
        self.crypto.as_ref()
    }

    /// Check if the vault is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Get the subkeys (if vault is open)
    pub fn subkeys(&self) -> Option<&SubKeys> {
        self.subkeys.as_ref()
    }

    /// Get the file table (if vault is open)
    pub fn file_table(&self) -> Option<&FileTable> {
        self.file_table.as_ref()
    }

    /// Get mutable access to the file table (if vault is open)
    pub fn file_table_mut(&mut self) -> Option<&mut FileTable> {
        self.file_table.as_mut()
    }

    /// Add a file entry to the vault
    pub fn add_file_entry(&mut self, entry: crate::format::FileEntry) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Validate the entry
        entry.validate()?;

        if let Some(ref mut file_table) = self.file_table {
            file_table.files.push(entry);
        } else {
            return Err(VaultError::internal_error("File table not available"));
        }

        Ok(())
    }

    /// List all files in the vault (decrypted filenames)
    pub fn list_files(&self) -> VaultResult<Vec<FileInfo>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self
            .file_table
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let mut files = Vec::new();
        for entry in &file_table.files {
            let filename = entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            files.push(FileInfo {
                name: filename,
                size: entry.size,
                is_dir: entry.is_dir,
                mtime: entry.mtime,
                mode: entry.mode,
            });
        }

        Ok(files)
    }

    /// Find a file entry by decrypted filename
    pub fn find_file(&self, filename: &str) -> VaultResult<Option<&crate::format::FileEntry>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self
            .file_table
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        for entry in &file_table.files {
            let entry_filename =
                entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            if entry_filename == filename {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Save the current file table to disk (encrypted) using atomic operations
    pub fn save_file_table(&self) -> VaultResult<()> {
        self.save_file_table_with_atomic(true)
    }

    /// Save the current file table to disk with optional atomic operations
    pub fn save_file_table_with_atomic(&self, use_atomic: bool) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self
            .file_table
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        VaultFormat::write_encrypted_file_table_atomic(
            &self.path,
            &self.header,
            file_table,
            self.crypto.as_ref(),
            subkeys,
            use_atomic,
        )?;

        Ok(())
    }

    /// Save the vault header to disk (updates hidden table metadata)
    ///
    /// NOTE: This method is currently disabled to prevent vault corruption.
    /// The issue is that updating the header changes its size, which shifts
    /// the file table offset and corrupts the vault structure.
    ///
    /// For now, hidden tables metadata is not persisted across vault sessions.
    /// This is documented as a known limitation.
    #[allow(dead_code)]
    fn save_header(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // DISABLED: This causes vault corruption by changing header size
        // which shifts file table offset. For now, don't persist hidden tables.

        // Save hidden tables metadata to separate location
        if let Some(ref mut deniability_mgr) = self.deniability_manager {
            let master_key = self
                .subkeys
                .as_ref()
                .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?
                .file_encryption_key
                .clone();

            // Only save metadata to separate location, don't update header
            deniability_mgr.save_to_vault(&self.path, &master_key)?;

            // DON'T update header - this causes corruption
            // self.header = deniability_mgr.get_updated_header();
        }

        // DON'T rewrite the vault header - this causes corruption
        // VaultFormat::update_vault_header(&self.path, &self.header)?;

        Ok(())
    }

    /// Write file data to vault using chunking
    pub fn write_file(&mut self, filename: &str, data: &[u8]) -> VaultResult<()> {
        self.write_file_with_options(filename, data, true)
    }

    /// Write file data to vault with option to defer file table save
    pub fn write_file_with_options(
        &mut self,
        filename: &str,
        data: &[u8],
        save_file_table: bool,
    ) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Validate filename
        if filename.is_empty() {
            return Err(VaultError::invalid_argument("Filename cannot be empty"));
        }

        // Check if file already exists and remove it
        if let Some(existing_index) = self.find_file_index(filename)? {
            self.remove_file_by_index(existing_index)?;
        }

        // Get subkeys after potential mutation
        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?
            .clone();

        // Create file entry with chunks
        let mut file_entry = FileEntry::new(
            filename,
            data.len() as u64,
            chrono::Utc::now(),
            0o644,
            false,
            self.crypto.as_ref(),
            &subkeys.filename_key,
        )?;

        // Chunk the file data and encrypt each chunk
        let chunk_size = self.header.chunk_size as usize;

        // Handle empty files - still need at least one chunk (even if empty)
        if data.is_empty() {
            // Generate unique nonce for empty chunk
            let nonce = generate_nonce(self.crypto.nonce_size())?;

            // Encrypt empty data
            let encrypted_chunk = self.crypto.encrypt(
                &subkeys.file_encryption_key,
                &nonce,
                &[], // Empty data
                &[], // No AAD for chunks
            )?;

            // Calculate total chunk size
            let total_chunk_size = nonce.len() + encrypted_chunk.len();

            // Find space for this chunk
            let current_offset = self.calculate_next_chunk_offset(total_chunk_size as u64)?;

            // Write encrypted chunk to vault file
            VaultFormat::write_chunk_to_vault(
                &self.path,
                current_offset,
                &nonce,
                &encrypted_chunk,
            )?;

            // Add chunk info to file entry
            file_entry.add_chunk(current_offset, total_chunk_size as u32, nonce);
        } else {
            // Handle non-empty files
            for (_chunk_index, chunk_data) in data.chunks(chunk_size).enumerate() {
                // Generate unique nonce for this chunk
                let nonce = generate_nonce(self.crypto.nonce_size())?;

                // Encrypt chunk with file encryption key
                let encrypted_chunk = self.crypto.encrypt(
                    &subkeys.file_encryption_key,
                    &nonce,
                    chunk_data,
                    &[], // No AAD for chunks
                )?;

                // Calculate total chunk size
                let total_chunk_size = nonce.len() + encrypted_chunk.len();

                // Find space for this chunk
                let current_offset = self.calculate_next_chunk_offset(total_chunk_size as u64)?;

                // Write encrypted chunk to vault file
                VaultFormat::write_chunk_to_vault(
                    &self.path,
                    current_offset,
                    &nonce,
                    &encrypted_chunk,
                )?;

                // Add chunk info to file entry
                file_entry.add_chunk(current_offset, total_chunk_size as u32, nonce);
            }
        }

        // Add file entry to vault and optionally save file table
        self.add_file_entry(file_entry)?;
        if save_file_table {
            self.save_file_table()?;
        }

        Ok(())
    }

    /// Write multiple files to vault efficiently (batch operation)
    pub fn write_files_batch(&mut self, files: &[(&str, &[u8])]) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Write all files without saving file table each time
        for (filename, data) in files {
            self.write_file_with_options(filename, data, false)?;
        }

        // Save file table once at the end
        self.save_file_table()?;

        Ok(())
    }

    /// Read file data from vault with streaming support
    pub fn read_file(&self, filename: &str) -> VaultResult<Vec<u8>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_entry = self
            .find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let mut file_data = Vec::with_capacity(file_entry.size as usize);

        // Read and decrypt each chunk
        for chunk in &file_entry.chunks {
            let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                &self.path,
                chunk.offset,
                chunk.size,
                self.crypto.nonce_size(),
            )?;

            // Decrypt chunk
            let decrypted_chunk = self.crypto.decrypt(
                &subkeys.file_encryption_key,
                &nonce,
                &encrypted_chunk,
                &[], // No AAD for chunks
            )?;

            file_data.extend_from_slice(&decrypted_chunk);
        }

        Ok(file_data)
    }

    /// Read a range of bytes from a file without loading the entire file
    pub fn read_file_range(
        &self,
        filename: &str,
        offset: u64,
        length: u64,
    ) -> VaultResult<Vec<u8>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_entry = self
            .find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        if offset >= file_entry.size {
            return Ok(Vec::new());
        }

        let end_offset = std::cmp::min(offset + length, file_entry.size);
        let actual_length = end_offset - offset;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let chunk_size = self.header.chunk_size as u64;
        let start_chunk = (offset / chunk_size) as usize;
        let end_chunk = ((end_offset - 1) / chunk_size) as usize;

        let mut result = Vec::with_capacity(actual_length as usize);

        // Read only the relevant chunks
        for chunk_index in start_chunk..=end_chunk {
            if chunk_index >= file_entry.chunks.len() {
                break;
            }

            let chunk = &file_entry.chunks[chunk_index];
            let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                &self.path,
                chunk.offset,
                chunk.size,
                self.crypto.nonce_size(),
            )?;

            // Decrypt chunk
            let decrypted_chunk = self.crypto.decrypt(
                &subkeys.file_encryption_key,
                &nonce,
                &encrypted_chunk,
                &[], // No AAD for chunks
            )?;

            // Calculate the portion of this chunk we need
            let chunk_start_offset = chunk_index as u64 * chunk_size;
            let chunk_end_offset = chunk_start_offset + decrypted_chunk.len() as u64;

            let copy_start = if offset > chunk_start_offset {
                (offset - chunk_start_offset) as usize
            } else {
                0
            };

            let copy_end = if end_offset < chunk_end_offset {
                (end_offset - chunk_start_offset) as usize
            } else {
                decrypted_chunk.len()
            };

            if copy_start < copy_end {
                result.extend_from_slice(&decrypted_chunk[copy_start..copy_end]);
            }
        }

        Ok(result)
    }

    /// Create a streaming reader for a file
    pub fn create_file_stream(&self, filename: &str) -> VaultResult<FileStream> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_entry = self
            .find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        Ok(FileStream::new(
            self.path.clone(),
            file_entry.clone(),
            self.header.chunk_size,
            self.crypto.as_ref(),
            self.subkeys.as_ref().unwrap(),
        ))
    }

    /// Calculate the next available offset for chunk storage using space management
    fn calculate_next_chunk_offset(&mut self, required_size: u64) -> VaultResult<u64> {
        let file_table = self
            .file_table
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        // Use the new space management system
        VaultFormat::find_next_chunk_offset(&self.path, &self.header, file_table, required_size)
    }

    /// Find file index by name
    fn find_file_index(&self, filename: &str) -> VaultResult<Option<usize>> {
        let file_table = self
            .file_table
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        for (index, entry) in file_table.files.iter().enumerate() {
            let entry_filename =
                entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            if entry_filename == filename {
                return Ok(Some(index));
            }
        }

        Ok(None)
    }

    /// Remove file by index and reclaim its space
    fn remove_file_by_index(&mut self, index: usize) -> VaultResult<()> {
        if let Some(ref mut file_table) = self.file_table {
            if index < file_table.files.len() {
                let removed_file = file_table.files.remove(index);

                // Reclaim space from deleted chunks
                VaultFormat::reclaim_deleted_space(
                    &self.path,
                    &self.header,
                    file_table,
                    &removed_file.chunks,
                )?;
            }
        }
        Ok(())
    }

    /// Defragment the vault to consolidate free space
    pub fn defragment(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self
            .file_table
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        VaultFormat::defragment_vault(
            &self.path,
            &self.header,
            file_table,
            self.crypto.as_ref(),
            subkeys,
        )?;

        // Save the updated file table
        self.save_file_table()?;

        Ok(())
    }

    /// Get vault space usage statistics
    pub fn get_space_usage(&self) -> VaultResult<VaultSpaceUsage> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self
            .file_table
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let file_metadata = std::fs::metadata(&self.path)?;
        let total_file_size = file_metadata.len();

        let mut used_space = 0u64;
        let mut chunk_count = 0usize;

        for file_entry in &file_table.files {
            for chunk in &file_entry.chunks {
                used_space += chunk.size as u64;
                chunk_count += 1;
            }
        }

        let free_space = file_table.total_free_space();
        let fragmentation_count = file_table.free_space_regions.len();

        Ok(VaultSpaceUsage {
            total_file_size,
            used_space,
            free_space,
            fragmentation_count,
            chunk_count,
            file_count: file_table.files.len(),
        })
    }

    /// Check if the vault would benefit from defragmentation
    pub fn needs_defragmentation(&self) -> VaultResult<bool> {
        let usage = self.get_space_usage()?;

        // Suggest defragmentation if:
        // 1. More than 10% free space AND more than 5 fragmented regions
        // 2. More than 20 fragmented regions regardless of free space
        let free_space_ratio = usage.free_space as f64 / usage.total_file_size as f64;

        Ok((free_space_ratio > 0.1 && usage.fragmentation_count > 5)
            || usage.fragmentation_count > 20)
    }

    /// Validate the integrity of this vault
    pub fn validate_integrity(
        &self,
        password: &str,
    ) -> VaultResult<crate::integrity::VaultValidationResult> {
        crate::integrity::VaultIntegrityChecker::validate_vault(&self.path, password)
    }

    /// Perform a quick integrity check on this vault
    pub fn quick_integrity_check(&self) -> VaultResult<bool> {
        crate::integrity::VaultIntegrityChecker::quick_integrity_check(&self.path)
    }

    /// Repair this vault if it's corrupted
    pub fn repair_vault(
        path: &Path,
        password: &str,
        create_backup: bool,
    ) -> VaultResult<crate::integrity::VaultRepairResult> {
        crate::integrity::VaultIntegrityChecker::repair_vault(path, password, create_backup)
    }

    /// Add a recipient for secure sharing
    pub fn add_sharing_recipient(&mut self, recipient_public_key: [u8; 32]) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let sharing_manager = self
            .sharing_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        sharing_manager.add_recipient(recipient_public_key, subkeys, self.crypto.as_ref())
    }

    /// Remove a recipient from secure sharing
    pub fn remove_sharing_recipient(
        &mut self,
        recipient_public_key: &[u8; 32],
    ) -> VaultResult<bool> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        Ok(sharing_manager.remove_recipient(recipient_public_key))
    }

    /// List all sharing recipients
    pub fn list_sharing_recipients(&self) -> VaultResult<Vec<[u8; 32]>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        Ok(sharing_manager.list_recipients())
    }

    /// Check if a recipient has sharing access
    pub fn has_sharing_recipient(&self, recipient_public_key: &[u8; 32]) -> VaultResult<bool> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        Ok(sharing_manager.has_recipient(recipient_public_key))
    }

    /// Get the number of sharing recipients
    pub fn sharing_recipient_count(&self) -> VaultResult<usize> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        Ok(sharing_manager.recipient_count())
    }

    /// Export sharing envelopes for distribution
    pub fn export_sharing_envelopes(&self) -> VaultResult<String> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        sharing_manager.export_envelopes()
    }

    /// Import sharing envelopes from external source
    pub fn import_sharing_envelopes(&mut self, json: &str) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let sharing_manager = self
            .sharing_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Sharing manager not available"))?;

        sharing_manager.import_envelopes(json)
    }

    /// Open vault using recipient's private key (for shared access)
    pub fn open_with_recipient_key<P: AsRef<Path>>(
        path: P,
        recipient_private_key: &[u8; 32],
        envelopes_json: &str,
    ) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            return Err(VaultError::file_not_found(path.display().to_string()));
        }

        // Read and parse vault header
        let (header, file_table_offset) = VaultFormat::read_vault_header(&path)?;

        // Parse cipher type from header
        let cipher_type: CipherType = header.cipher.parse()?;

        // Create crypto engine
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

        // Import sharing envelopes
        let envelope_collection =
            crate::sharing::ShareEnvelopeCollection::import_json(envelopes_json)?;

        // Verify vault UUID matches
        if envelope_collection.vault_uuid != header.vault_uuid {
            return Err(VaultError::crypto_error(
                "Envelope collection doesn't match vault UUID",
            ));
        }

        // Create sharing manager from collection
        let sharing_manager = SharingManager::from_collection(envelope_collection)?;

        // Decrypt vault subkeys using recipient's private key
        let subkeys =
            sharing_manager.decrypt_for_recipient(recipient_private_key, crypto.as_ref())?;

        // Try to decrypt and parse file table
        let file_table = match VaultFormat::read_encrypted_file_table(
            &path,
            &header,
            file_table_offset,
            crypto.as_ref(),
            &subkeys,
        ) {
            Ok(table) => Some(table),
            Err(VaultError::CryptoError { .. }) => {
                // Decryption failed - likely wrong key or corrupted envelopes
                return Err(VaultError::InvalidPassword);
            }
            Err(e) => return Err(e),
        };

        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header: header.clone(),
            crypto,
            file_table,
            subkeys: Some(subkeys),
            sharing_manager: Some(sharing_manager),
            deniability_manager: Some(crate::deniability::DeniabilityManager::new(header)),
            metadata_sections: Some(crate::format::MetadataSections::new()),
            is_open: true,
        };

        Ok(vault)
    }

    /// Generate a new X25519 key pair for sharing
    pub fn generate_sharing_keypair() -> VaultResult<X25519KeyPair> {
        X25519KeyPair::generate()
    }

    /// Change the vault password without re-encrypting file chunks
    pub fn change_password(&self, old_password: &str, new_password: &str) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let password_manager = PasswordManager::new(crate::crypto::create_crypto_engine(
            self.crypto.cipher_type(),
        )?);

        password_manager.change_password(&self.path, old_password, new_password, None)
    }

    /// Change the vault password with custom KDF parameters
    pub fn change_password_with_params(
        &self,
        old_password: &str,
        new_password: &str,
        new_kdf_params: KdfParams,
    ) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let password_manager = PasswordManager::new(crate::crypto::create_crypto_engine(
            self.crypto.cipher_type(),
        )?);

        password_manager.change_password(
            &self.path,
            old_password,
            new_password,
            Some(new_kdf_params),
        )
    }

    /// Generate a recovery key for this vault
    pub fn generate_recovery_key(
        &self,
        password: &str,
    ) -> VaultResult<(RecoveryKey, WrappedMasterKey)> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let password_manager = PasswordManager::new(crate::crypto::create_crypto_engine(
            self.crypto.cipher_type(),
        )?);

        password_manager.setup_recovery_key(&self.path, password)
    }

    /// Recover vault access using a recovery key and set new password
    pub fn recover_with_key<P: AsRef<Path>>(
        path: P,
        recovery_key: &RecoveryKey,
        wrapped_master_key: &WrappedMasterKey,
        new_password: &str,
    ) -> VaultResult<()> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(VaultError::file_not_found(path.display().to_string()));
        }

        // Read header to determine cipher type
        let (header, _) = VaultFormat::read_vault_header(path)?;
        let cipher_type: CipherType = header.cipher.parse()?;

        let password_manager =
            PasswordManager::new(crate::crypto::create_crypto_engine(cipher_type)?);

        password_manager.recover_with_recovery_key(
            path,
            recovery_key,
            wrapped_master_key,
            new_password,
            None,
        )
    }

    /// Recover vault access with custom KDF parameters
    pub fn recover_with_key_and_params<P: AsRef<Path>>(
        path: P,
        recovery_key: &RecoveryKey,
        wrapped_master_key: &WrappedMasterKey,
        new_password: &str,
        new_kdf_params: KdfParams,
    ) -> VaultResult<()> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(VaultError::file_not_found(path.display().to_string()));
        }

        // Read header to determine cipher type
        let (header, _) = VaultFormat::read_vault_header(path)?;
        let cipher_type: CipherType = header.cipher.parse()?;

        let password_manager =
            PasswordManager::new(crate::crypto::create_crypto_engine(cipher_type)?);

        password_manager.recover_with_recovery_key(
            path,
            recovery_key,
            wrapped_master_key,
            new_password,
            Some(new_kdf_params),
        )
    }

    /// Rotate the vault to a new encryption algorithm
    /// This is a background operation that re-encrypts all chunks
    pub fn rotate_algorithm(
        &self,
        password: &str,
        new_cipher_type: CipherType,
        progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>,
    ) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let old_crypto_engine = crate::crypto::create_crypto_engine(self.crypto.cipher_type())?;
        let new_crypto_engine = crate::crypto::create_crypto_engine(new_cipher_type)?;

        let rotation_manager = AlgorithmRotationManager::new(old_crypto_engine, new_crypto_engine);

        rotation_manager.rotate_algorithm(&self.path, password, progress_callback)
    }

    /// Get the current master key (for advanced operations)
    /// WARNING: This exposes the master key - use with extreme caution
    pub fn get_master_key(&self, password: &str) -> VaultResult<[u8; 32]> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        derive_key(
            password,
            &self.header.kdf_params.salt,
            self.header.kdf_params.memory,
            self.header.kdf_params.operations,
            self.header.kdf_params.parallelism,
        )
    }

    /// Wrap the current master key with a password (for backup purposes)
    pub fn wrap_master_key_with_password(
        &self,
        current_password: &str,
        wrapping_password: &str,
    ) -> VaultResult<WrappedMasterKey> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let master_key = self.get_master_key(current_password)?;

        let password_manager = PasswordManager::new(crate::crypto::create_crypto_engine(
            self.crypto.cipher_type(),
        )?);

        password_manager.wrap_master_key(&master_key, wrapping_password, &self.header.kdf_params)
    }

    /// Close the vault
    pub fn close(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Ok(());
        }

        self.is_open = false;
        self.file_table = None;
        self.sharing_manager = None;

        // Securely clear subkeys
        if let Some(mut subkeys) = self.subkeys.take() {
            subkeys.clear();
        }

        Ok(())
    }

    /// Delete a file from the vault
    pub fn delete_file(&mut self, filename: &str) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Find the file entry
        let file_table = self
            .file_table
            .as_mut()
            .ok_or_else(|| VaultError::invalid_argument("File table not available"))?;

        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::invalid_argument("Subkeys not available"))?;

        // Find and remove the file entry
        let mut found_index = None;
        for (index, entry) in file_table.files.iter().enumerate() {
            let decrypted_name =
                entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            if decrypted_name == filename {
                found_index = Some(index);
                break;
            }
        }

        let index = found_index
            .ok_or_else(|| VaultError::file_not_found(&format!("File not found: {}", filename)))?;

        // Remove the file entry
        file_table.files.remove(index);

        // Save the updated file table
        self.save_file_table()?;

        Ok(())
    }

    /// Create a directory in the vault
    pub fn create_directory(&mut self, dirname: &str) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Validate directory name
        if dirname.is_empty() {
            return Err(VaultError::invalid_argument(
                "Directory name cannot be empty",
            ));
        }

        // Check if directory already exists
        match self.find_file(dirname) {
            Ok(Some(_)) => {
                return Err(VaultError::invalid_argument(&format!(
                    "Directory already exists: {}",
                    dirname
                )));
            }
            Ok(None) => {
                // Directory doesn't exist, proceed with creation
            }
            Err(e) => {
                // Error occurred during search
                return Err(e);
            }
        }

        // Create directory entry
        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let dir_entry = crate::format::FileEntry::new(
            dirname,
            0,
            chrono::Utc::now(),
            0o755, // Directory permissions
            true,  // is_dir
            self.crypto.as_ref(),
            &subkeys.filename_key,
        )?;

        // Add to file table
        let file_table = self
            .file_table
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        file_table.files.push(dir_entry);

        // Save the updated file table
        self.save_file_table()?;

        Ok(())
    }

    // Plausible Deniability Methods

    /// Add a hidden file table with its own password
    pub fn add_hidden_file_table(
        &mut self,
        password: &str,
        cipher_type: CipherType,
        is_decoy: bool,
    ) -> VaultResult<Uuid> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        let table_id = deniability_mgr.add_hidden_table(password, cipher_type, is_decoy)?;

        // TODO: Save the updated header once persistence is fully implemented
        // self.save_header()?;

        Ok(table_id)
    }

    /// Remove a hidden file table
    pub fn remove_hidden_file_table(&mut self, table_id: &Uuid) -> VaultResult<bool> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        let removed = deniability_mgr.remove_hidden_table(table_id)?;

        // TODO: Save the updated header once persistence is fully implemented
        // if removed {
        //     self.save_header()?;
        // }

        Ok(removed)
    }

    /// Get the number of hidden file tables
    pub fn hidden_file_table_count(&self) -> VaultResult<usize> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        Ok(deniability_mgr.table_count())
    }

    /// List all hidden file table IDs
    pub fn list_hidden_file_table_ids(&self) -> VaultResult<Vec<Uuid>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        Ok(deniability_mgr.list_table_ids())
    }

    /// Set the active hidden file table for operations
    pub fn set_active_hidden_file_table(&mut self, table_id: Uuid) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        deniability_mgr.set_active_table(table_id)
    }

    /// Open a vault with a hidden file table password
    /// Returns the vault and the table ID that was unlocked
    pub fn open_with_hidden_table<P: AsRef<Path>>(
        path: P,
        password: &str,
    ) -> VaultResult<(Self, Uuid)> {
        let path = path.as_ref().to_path_buf();

        // First, try to open as a normal vault
        match Self::open(&path, password) {
            Ok(vault) => {
                // Successfully opened with main password
                // Return with a dummy UUID to indicate main table
                return Ok((vault, Uuid::nil()));
            }
            Err(VaultError::InvalidPassword) => {
                // Wrong password for main table, try hidden tables
            }
            Err(e) => return Err(e),
        }

        // Read vault header to initialize deniability manager
        let (header, _) = VaultFormat::read_vault_header(&path)?;

        // Create a temporary deniability manager to try unlocking
        let deniability_mgr = crate::deniability::DeniabilityManager::new(header.clone());

        // Try to unlock a hidden table
        match deniability_mgr.try_unlock_table(&path, password)? {
            Some(table_id) => {
                // Successfully unlocked a hidden table
                // Read the hidden file table
                let file_table = deniability_mgr.read_hidden_table(&path, &table_id, password)?;

                // Get the table metadata to determine cipher
                let metadata = deniability_mgr
                    .get_table_metadata(&table_id)
                    .ok_or_else(|| VaultError::internal_error("Table metadata not found"))?;

                let cipher_type: CipherType = metadata.cipher.parse()?;
                let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

                // Derive keys from password
                let master_key = derive_key(
                    password,
                    &metadata.kdf_params.salt,
                    metadata.kdf_params.memory,
                    metadata.kdf_params.operations,
                    metadata.kdf_params.parallelism,
                )?;

                let subkeys = derive_all_subkeys(&master_key)?;

                // Create vault with the hidden file table
                let mut vault = Vault {
                    handle: 0,
                    path,
                    header: header.clone(),
                    crypto,
                    file_table: Some(file_table),
                    subkeys: Some(subkeys),
                    sharing_manager: Some(SharingManager::new(header.vault_uuid)),
                    deniability_manager: Some(deniability_mgr),
                    metadata_sections: Some(crate::format::MetadataSections::new()),
                    is_open: true,
                };

                // Set the active table
                vault.set_active_hidden_file_table(table_id)?;

                Ok((vault, table_id))
            }
            None => {
                // No hidden table matched this password
                Err(VaultError::InvalidPassword)
            }
        }
    }

    /// Create a decoy file table with fake content
    pub fn create_decoy_file_table(
        &mut self,
        password: &str,
        cipher_type: CipherType,
    ) -> VaultResult<Uuid> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        let table_id = deniability_mgr.create_decoy_table(password, cipher_type)?;

        // TODO: Save the updated header once persistence is fully implemented
        // self.save_header()?;

        Ok(table_id)
    }

    /// Wipe metadata that could reveal the existence of hidden tables
    pub fn wipe_revealing_metadata(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let deniability_mgr = self
            .deniability_manager
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Deniability manager not available"))?;

        deniability_mgr.wipe_revealing_metadata();

        // TODO: Save the updated header once persistence is fully implemented
        // self.save_header()?;

        Ok(())
    }

    /// Get documentation about plausible deniability limitations
    pub fn get_deniability_limitations() -> &'static str {
        crate::deniability::DeniabilityManager::get_limitations_doc()
    }

    /// Set a metadata section in the vault
    pub fn set_metadata_section(
        &mut self,
        section_type: crate::format::MetadataSectionType,
        data: Vec<u8>,
    ) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let metadata_sections = self
            .metadata_sections
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Metadata sections not available"))?;

        // Find existing section or add new one
        let section = crate::format::MetadataSection {
            section_type: section_type.clone(),
            data,
        };

        // Remove existing section of the same type
        metadata_sections
            .sections
            .retain(|s| s.section_type != section_type);

        // Add new section
        metadata_sections.sections.push(section);

        // Persist metadata sections to disk
        self.save_metadata_sections()?;

        Ok(())
    }

    /// Get a metadata section from the vault
    pub fn get_metadata_section(
        &self,
        section_type: &crate::format::MetadataSectionType,
    ) -> VaultResult<Option<Vec<u8>>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let metadata_sections = self
            .metadata_sections
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Metadata sections not available"))?;

        // Find section by type
        for section in &metadata_sections.sections {
            if section.section_type == *section_type {
                return Ok(Some(section.data.clone()));
            }
        }

        Ok(None)
    }

    /// Remove a metadata section from the vault
    pub fn remove_metadata_section(
        &mut self,
        section_type: &crate::format::MetadataSectionType,
    ) -> VaultResult<bool> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let metadata_sections = self
            .metadata_sections
            .as_mut()
            .ok_or_else(|| VaultError::internal_error("Metadata sections not available"))?;

        let initial_len = metadata_sections.sections.len();
        metadata_sections
            .sections
            .retain(|s| s.section_type != *section_type);
        let removed = metadata_sections.sections.len() < initial_len;

        if removed {
            // Persist changes to disk
            self.save_metadata_sections()?;
        }

        Ok(removed)
    }

    /// Migrate this vault to use metadata sections format
    pub fn migrate_to_metadata_sections(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // With the new approach, all vaults support metadata sections by default
        // No migration is needed since we scan for metadata sections at the end of the file
        Ok(())
    }

    /// Check if this vault supports metadata sections
    pub fn supports_metadata_sections(&self) -> bool {
        self.header.metadata_sections_offset > 0 || self.header.file_table_version >= 2
    }

    /// Scan for metadata sections at the end of the file
    fn scan_for_metadata_sections<P: AsRef<Path>>(
        path: P,
        crypto_engine: &dyn CryptoEngine,
        metadata_key: &[u8],
    ) -> VaultResult<crate::format::MetadataSections> {
        let file_data = std::fs::read(path)?;

        let nonce_size = crypto_engine.nonce_size();
        let min_encrypted_size = nonce_size + crypto_engine.tag_size();

        // Since we append metadata sections at the end, we should look backwards from the end
        // Try to find the start of the encrypted metadata sections
        if file_data.len() < min_encrypted_size {
            return Ok(crate::format::MetadataSections::new());
        }

        // Try to find metadata sections by looking for the encrypted data pattern
        // Since we know the structure: nonce + encrypted_data, we can search for valid decryptions

        // Try different starting positions from the end, working backwards
        let search_limit = std::cmp::min(4096, file_data.len()); // Search last 4KB

        for start_pos in (file_data.len().saturating_sub(search_limit)..file_data.len()).rev() {
            if start_pos + min_encrypted_size > file_data.len() {
                continue;
            }

            let data_slice = &file_data[start_pos..];

            // Try to decrypt this slice as metadata sections
            match VaultFormat::decrypt_metadata_sections(data_slice, crypto_engine, metadata_key) {
                Ok(sections) => {
                    if !sections.sections.is_empty() {
                        return Ok(sections);
                    }
                }
                Err(_) => continue, // Try next position
            }
        }

        // No metadata sections found
        Ok(crate::format::MetadataSections::new())
    }

    /// Save metadata sections to disk (append at end of file)
    fn save_metadata_sections(&mut self) -> VaultResult<()> {
        let subkeys = self
            .subkeys
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let metadata_sections = self
            .metadata_sections
            .as_ref()
            .ok_or_else(|| VaultError::internal_error("Metadata sections not available"))?;

        // If no metadata sections, just update the size to 0 in memory
        if metadata_sections.sections.is_empty() {
            if self.header.metadata_sections_size > 0 {
                self.header.metadata_sections_offset = 0;
                self.header.metadata_sections_size = 0;
                // Don't update the header on disk to avoid size issues
            }
            return Ok(());
        }

        // Encrypt metadata sections
        let encrypted_data = VaultFormat::encrypt_metadata_sections(
            metadata_sections,
            self.crypto.as_ref(),
            &subkeys.metadata_key,
        )?;

        let new_size = encrypted_data.len() as u64;

        // Get current file size to determine where to append metadata sections
        let file_size = std::fs::metadata(&self.path)?.len();

        // If we already have metadata sections, we'll overwrite them
        let metadata_offset = if self.header.metadata_sections_offset > 0 {
            self.header.metadata_sections_offset
        } else {
            file_size // Append at end
        };

        // Update header in memory (but don't write to disk to avoid header size issues)
        self.header.metadata_sections_offset = metadata_offset;
        self.header.metadata_sections_size = new_size;

        // Write metadata sections at the calculated offset
        let mut file = std::fs::OpenOptions::new().write(true).open(&self.path)?;

        file.seek(std::io::SeekFrom::Start(metadata_offset))?;
        file.write_all(&encrypted_data)?;
        file.flush()?;

        // Truncate file if the new metadata sections are smaller than the old ones
        let new_file_size = metadata_offset + new_size;
        file.set_len(new_file_size)?;

        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Initialize the vault registry
pub fn init_vault_registry() {
    let mut registry = VAULT_REGISTRY.lock().unwrap();
    if registry.is_none() {
        *registry = Some(VaultRegistry::new());
    }
}

/// Register a vault and return its handle
pub fn register_vault(vault: Vault) -> VaultHandle {
    init_vault_registry();
    let mut registry = VAULT_REGISTRY.lock().unwrap();
    registry.as_mut().unwrap().register_vault(vault)
}

/// Get a vault by handle
pub fn get_vault(handle: VaultHandle) -> Option<Arc<Mutex<Vault>>> {
    let registry = VAULT_REGISTRY.lock().unwrap();
    registry.as_ref()?.get_vault(handle)
}

/// Remove a vault from the registry
pub fn remove_vault(handle: VaultHandle) -> Option<Arc<Mutex<Vault>>> {
    let mut registry = VAULT_REGISTRY.lock().unwrap();
    registry.as_mut()?.remove_vault(handle)
}
