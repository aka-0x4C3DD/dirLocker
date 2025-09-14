//! Core vault implementation and handle management

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use uuid::Uuid;
use chrono::Utc;

use crate::crypto::{CipherType, CryptoEngine};
use crate::error::{VaultError, VaultResult};
use crate::format::{VaultHeader, VaultFormat, KdfParams, FileTable};

// Re-export format types for convenience
pub use crate::format::{FileEntry, ChunkInfo};

/// Opaque handle for vault instances
pub type VaultHandle = usize;

/// Main vault structure
pub struct Vault {
    handle: VaultHandle,
    path: PathBuf,
    header: VaultHeader,
    crypto: Box<dyn CryptoEngine>,
    file_table: Option<FileTable>,
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
        
        // Create vault header
        let header = VaultHeader {
            cipher: cipher_type.to_string(),
            kdf: "argon2id".to_string(),
            kdf_params,
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 0, // Will be calculated by format module
            file_table_size: 0,   // Will be calculated by format module
            chunk_size: 4 * 1024 * 1024, // 4MB default
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: std::env::consts::OS.to_string(),
        };
        
        // Write vault file to disk
        VaultFormat::create_vault_file(&path, &header)?;
        
        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header,
            crypto,
            file_table: Some(FileTable { files: vec![] }),
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
        let (header, _file_table_offset) = VaultFormat::read_vault_header(&path)?;
        
        // Parse cipher type from header
        let cipher_type: CipherType = header.cipher.parse()?;
        
        // Create crypto engine
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;
        
        // Derive key from password to verify it's correct
        let _derived_key = crate::crypto::derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;
        
        // TODO: Decrypt and parse file table (will be implemented in later tasks)
        // For now, create empty file table
        let file_table = Some(FileTable { files: vec![] });
        
        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header,
            crypto,
            file_table,
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
    
    /// Check if the vault is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }
    
    /// Close the vault
    pub fn close(&mut self) -> VaultResult<()> {
        if !self.is_open {
            return Ok(());
        }
        
        self.is_open = false;
        self.file_table = None;
        
        // TODO: Implement secure memory clearing
        
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