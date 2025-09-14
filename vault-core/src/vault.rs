//! Core vault implementation and handle management

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::crypto::{CipherType, CryptoEngine, derive_key, derive_all_subkeys, SubKeys};
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
