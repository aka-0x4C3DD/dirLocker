//! Core vault implementation and handle management

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{CipherType, CryptoEngine, derive_key, derive_all_subkeys, SubKeys, generate_nonce};
use crate::error::{VaultError, VaultResult};
use crate::format::{FileTable, KdfParams, VaultFormat, VaultHeader};

// Re-export format types for convenience
pub use crate::format::{ChunkInfo, FileEntry};

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

        // Create vault header
        let header = VaultHeader {
            cipher: cipher_type.to_string(),
            kdf: "argon2id".to_string(),
            kdf_params,
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 0,        // Will be calculated by format module
            file_table_size: 0,          // Will be calculated by format module
            chunk_size: 4 * 1024 * 1024, // 4MB default
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: std::env::consts::OS.to_string(),
        };

        // Write vault file to disk
        VaultFormat::create_vault_file(&path, &header)?;

        // Write empty encrypted file table
        let empty_file_table = FileTable { files: vec![] };
        VaultFormat::write_encrypted_file_table(&path, &header, &empty_file_table, crypto.as_ref(), &subkeys)?;

        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header,
            crypto,
            file_table: Some(empty_file_table),
            subkeys: Some(subkeys),
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

        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header,
            crypto,
            file_table,
            subkeys: Some(subkeys),
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
    pub fn list_files(&self) -> VaultResult<Vec<(String, &crate::format::FileEntry)>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self.file_table.as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self.subkeys.as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        let mut files = Vec::new();
        for entry in &file_table.files {
            let filename = entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            files.push((filename, entry));
        }

        Ok(files)
    }

    /// Find a file entry by decrypted filename
    pub fn find_file(&self, filename: &str) -> VaultResult<Option<&crate::format::FileEntry>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self.file_table.as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self.subkeys.as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        for entry in &file_table.files {
            let entry_filename = entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            if entry_filename == filename {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Save the current file table to disk (encrypted)
    pub fn save_file_table(&self) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_table = self.file_table.as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self.subkeys.as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        VaultFormat::write_encrypted_file_table(
            &self.path,
            &self.header,
            file_table,
            self.crypto.as_ref(),
            subkeys,
        )?;

        Ok(())
    }

    /// Write file data to vault using chunking
    pub fn write_file(&mut self, filename: &str, data: &[u8]) -> VaultResult<()> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        // Check if file already exists and remove it
        if let Some(existing_index) = self.find_file_index(filename)? {
            self.remove_file_by_index(existing_index)?;
        }

        // Get subkeys after potential mutation
        let subkeys = self.subkeys.as_ref()
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
        let mut current_offset = self.calculate_next_chunk_offset()?;

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

            // Write encrypted chunk to vault file
            VaultFormat::write_chunk_to_vault(
                &self.path,
                current_offset,
                &nonce,
                &encrypted_chunk,
            )?;

            // Calculate total chunk size before moving nonce
            let total_chunk_size = nonce.len() + encrypted_chunk.len();

            // Add chunk info to file entry
            file_entry.add_chunk(
                current_offset,
                total_chunk_size as u32,
                nonce,
            );
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

                // Write encrypted chunk to vault file
                VaultFormat::write_chunk_to_vault(
                    &self.path,
                    current_offset,
                    &nonce,
                    &encrypted_chunk,
                )?;

                // Calculate total chunk size before moving nonce
                let total_chunk_size = nonce.len() + encrypted_chunk.len();

                // Add chunk info to file entry
                file_entry.add_chunk(
                    current_offset,
                    total_chunk_size as u32,
                    nonce,
                );

                // Update offset for next chunk
                current_offset += total_chunk_size as u64;
            }
        }

        // Add file entry to vault and save file table first
        self.add_file_entry(file_entry)?;
        self.save_file_table()?;

        Ok(())
    }

    /// Read file data from vault with streaming support
    pub fn read_file(&self, filename: &str) -> VaultResult<Vec<u8>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_entry = self.find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        let subkeys = self.subkeys.as_ref()
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
    pub fn read_file_range(&self, filename: &str, offset: u64, length: u64) -> VaultResult<Vec<u8>> {
        if !self.is_open {
            return Err(VaultError::invalid_argument("Vault is not open"));
        }

        let file_entry = self.find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        if offset >= file_entry.size {
            return Ok(Vec::new());
        }

        let end_offset = std::cmp::min(offset + length, file_entry.size);
        let actual_length = end_offset - offset;

        let subkeys = self.subkeys.as_ref()
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

        let file_entry = self.find_file(filename)?
            .ok_or_else(|| VaultError::file_not_found(filename.to_string()))?;

        Ok(FileStream::new(
            self.path.clone(),
            file_entry.clone(),
            self.header.chunk_size,
            self.crypto.as_ref(),
            self.subkeys.as_ref().unwrap(),
        ))
    }

    /// Calculate the next available offset for chunk storage
    fn calculate_next_chunk_offset(&self) -> VaultResult<u64> {
        let file_table = self.file_table.as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let mut max_offset = 0u64;

        // Find the highest chunk offset + size
        for file_entry in &file_table.files {
            for chunk in &file_entry.chunks {
                let chunk_end = chunk.offset + chunk.size as u64;
                if chunk_end > max_offset {
                    max_offset = chunk_end;
                }
            }
        }

        // If no chunks exist, calculate where chunks should start
        if max_offset == 0 {
            // Calculate header size
            let header_json = serde_json::to_string_pretty(&self.header)?;
            let header_size = 4 + 1 + 4 + header_json.len() as u64; // magic + version + header_len + header
            
            // Estimate file table size (we need to be conservative here)
            let file_table_json = serde_json::to_string(&file_table)?;
            let estimated_file_table_size = self.crypto.nonce_size() as u64 + 
                file_table_json.len() as u64 + 
                self.crypto.tag_size() as u64 + 
                1024; // Add padding for growth
            
            max_offset = header_size + estimated_file_table_size;
        }


        Ok(max_offset)
    }

    /// Find file index by name
    fn find_file_index(&self, filename: &str) -> VaultResult<Option<usize>> {
        let file_table = self.file_table.as_ref()
            .ok_or_else(|| VaultError::internal_error("File table not available"))?;

        let subkeys = self.subkeys.as_ref()
            .ok_or_else(|| VaultError::internal_error("Subkeys not available"))?;

        for (index, entry) in file_table.files.iter().enumerate() {
            let entry_filename = entry.decrypt_filename(self.crypto.as_ref(), &subkeys.filename_key)?;
            if entry_filename == filename {
                return Ok(Some(index));
            }
        }

        Ok(None)
    }

    /// Remove file by index
    fn remove_file_by_index(&mut self, index: usize) -> VaultResult<()> {
        if let Some(ref mut file_table) = self.file_table {
            if index < file_table.files.len() {
                file_table.files.remove(index);
            }
        }
        Ok(())
    }

    /// Close the vault
    pub fn close(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Ok(());
        }

        self.is_open = false;
        self.file_table = None;

        // Securely clear subkeys
        if let Some(mut subkeys) = self.subkeys.take() {
            subkeys.clear();
        }

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

/// Streaming reader for vault files
pub struct FileStream {
    vault_path: PathBuf,
    file_entry: FileEntry,
    chunk_size: u32,
    crypto: Box<dyn CryptoEngine>,
    subkeys: SubKeys,
    current_position: u64,
}

impl FileStream {
    /// Create a new file stream
    pub fn new(
        vault_path: PathBuf,
        file_entry: FileEntry,
        chunk_size: u32,
        crypto: &dyn CryptoEngine,
        subkeys: &SubKeys,
    ) -> Self {
        Self {
            vault_path,
            file_entry,
            chunk_size,
            crypto: crate::crypto::create_crypto_engine(crypto.cipher_type()).unwrap(),
            subkeys: subkeys.clone(),
            current_position: 0,
        }
    }

    /// Get the total file size
    pub fn size(&self) -> u64 {
        self.file_entry.size
    }

    /// Get the current position in the stream
    pub fn position(&self) -> u64 {
        self.current_position
    }

    /// Seek to a specific position in the file
    pub fn seek(&mut self, position: u64) -> VaultResult<()> {
        if position > self.file_entry.size {
            return Err(VaultError::invalid_argument("Seek position beyond file size"));
        }
        self.current_position = position;
        Ok(())
    }

    /// Read up to `length` bytes from the current position
    pub fn read(&mut self, length: usize) -> VaultResult<Vec<u8>> {
        if self.current_position >= self.file_entry.size {
            return Ok(Vec::new()); // EOF
        }

        let end_position = std::cmp::min(
            self.current_position + length as u64,
            self.file_entry.size,
        );
        let actual_length = end_position - self.current_position;

        let chunk_size = self.chunk_size as u64;
        let start_chunk = (self.current_position / chunk_size) as usize;
        let end_chunk = ((end_position - 1) / chunk_size) as usize;

        let mut result = Vec::with_capacity(actual_length as usize);

        // Read only the relevant chunks
        for chunk_index in start_chunk..=end_chunk {
            if chunk_index >= self.file_entry.chunks.len() {
                break;
            }

            let chunk = &self.file_entry.chunks[chunk_index];
            let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                &self.vault_path,
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

            let copy_start = if self.current_position > chunk_start_offset {
                (self.current_position - chunk_start_offset) as usize
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

        self.current_position = end_position;
        Ok(result)
    }

    /// Read exactly `length` bytes or return an error if not enough data
    pub fn read_exact(&mut self, length: usize) -> VaultResult<Vec<u8>> {
        let data = self.read(length)?;
        if data.len() != length {
            return Err(VaultError::invalid_argument(
                "Not enough data available to read exact amount",
            ));
        }
        Ok(data)
    }

    /// Check if we're at the end of the file
    pub fn is_eof(&self) -> bool {
        self.current_position >= self.file_entry.size
    }
}
