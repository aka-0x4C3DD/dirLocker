//! Core vault implementation and handle management

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::crypto::{CipherType, CryptoEngine};
use crate::error::{VaultError, VaultResult};

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

/// Vault header structure matching the specification
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
    pub name_encrypted: Vec<u8>,
    pub iv: Vec<u8>,
    pub size: u64,
    pub chunks: Vec<ChunkInfo>,
    pub mtime: DateTime<Utc>,
    pub mode: u32,
    pub is_dir: bool,
}

/// Chunk information for file storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub offset: u64,
    pub size: u32,
    pub iv: Vec<u8>,
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
            file_table_offset: 0, // Will be set when writing
            file_table_size: 0,   // Will be set when writing
            chunk_size: 4 * 1024 * 1024, // 4MB default
            flags: vec![],
            created_at: Utc::now(),
            platform_hint: std::env::consts::OS.to_string(),
        };
        
        let vault = Vault {
            handle: 0, // Will be set by registry
            path,
            header,
            crypto,
            file_table: Some(FileTable { files: vec![] }),
            is_open: false,
        };
        
        // TODO: Write vault file to disk (will be implemented in later tasks)
        
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
        
        // TODO: Read and parse vault file (will be implemented in later tasks)
        // For now, return a placeholder
        Err(VaultError::internal_error("Vault opening not yet implemented"))
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