//! Vault Core - Cryptographic library for encrypted vault containers
//! 
//! This library provides the core cryptographic functionality for creating,
//! opening, and managing encrypted vault containers with cross-platform compatibility.

pub mod crypto;
pub mod error;
pub mod ffi;
pub mod vault;

// Re-export main types for library users
pub use error::{VaultError, VaultResult};
pub use vault::{Vault, VaultHandle};
pub use crypto::CipherType;

// FFI exports for C compatibility
pub use ffi::*;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vault_creation() {
        let result = Vault::create("test.vault", "password123", CipherType::Aes256Gcm);
        assert!(result.is_ok());
        
        let vault = result.unwrap();
        assert_eq!(vault.path().to_str().unwrap(), "test.vault");
        assert_eq!(vault.header().cipher, "aes-256-gcm");
        assert_eq!(vault.header().kdf, "argon2id");
    }
    
    #[test]
    fn test_vault_creation_empty_password() {
        let result = Vault::create("test.vault", "", CipherType::Aes256Gcm);
        assert!(result.is_err());
        
        if let Err(VaultError::InvalidArgument { details }) = result {
            assert!(details.contains("Password cannot be empty"));
        } else {
            panic!("Expected InvalidArgument error");
        }
    }
}