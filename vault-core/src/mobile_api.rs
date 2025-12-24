// Mobile API Wrapper for Flutter Rust Bridge

use crate::vault::Vault;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Simple logger initialization
pub fn init_mobile_logger() {
    // env_logger::init(); // Simplified for now, can use android_logger later
}

pub struct MobileVault {
    inner: Arc<Mutex<Vault>>,
}

/// Simplified file info for mobile UI
pub struct MobileFileInfo {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

impl MobileVault {
    // Constructor (Open existing vault)
    pub fn new_instance(path: String, password: String) -> Result<MobileVault, String> {
        let path_buf = PathBuf::from(&path);

        // Use the existing Vault::open method
        match Vault::open(&path_buf, &password) {
            Ok(vault) => Ok(MobileVault {
                inner: Arc::new(Mutex::new(vault)),
            }),
            Err(e) => Err(format!("Failed to open vault: {}", e)),
        }
    }

    // List files in the vault
    pub fn list_files(&self) -> Result<Vec<MobileFileInfo>, String> {
        let vault = self
            .inner
            .lock()
            .map_err(|_| "Failed to lock vault mutex".to_string())?;

        match vault.list_files() {
            Ok(files) => Ok(files
                .into_iter()
                .map(|f| MobileFileInfo {
                    name: f.name,
                    size: f.size,
                    is_dir: f.is_dir,
                })
                .collect()),
            Err(e) => Err(format!("Failed to list files: {}", e)),
        }
    }
}
