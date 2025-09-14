//! Cryptographic operations and cipher implementations

use std::fmt;

use crate::error::{VaultError, VaultResult};

/// Supported cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl fmt::Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherType::Aes256Gcm => write!(f, "aes-256-gcm"),
            CipherType::XChaCha20Poly1305 => write!(f, "xchacha20poly1305"),
        }
    }
}

impl std::str::FromStr for CipherType {
    type Err = VaultError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-256-gcm" => Ok(CipherType::Aes256Gcm),
            "xchacha20poly1305" => Ok(CipherType::XChaCha20Poly1305),
            _ => Err(VaultError::unsupported_cipher(s)),
        }
    }
}

/// Trait for cryptographic engines
pub trait CryptoEngine: Send + Sync {
    /// Encrypt data with associated data
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>>;
    
    /// Decrypt data with associated data
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>>;
    
    /// Get the key size in bytes
    fn key_size(&self) -> usize;
    
    /// Get the nonce size in bytes
    fn nonce_size(&self) -> usize;
    
    /// Get the authentication tag size in bytes
    fn tag_size(&self) -> usize;
    
    /// Get the cipher type
    fn cipher_type(&self) -> CipherType;
}

/// AES-256-GCM implementation
pub struct Aes256GcmEngine;

impl CryptoEngine for Aes256GcmEngine {
    fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        
        if key.len() != 32 {
            return Err(VaultError::crypto_error("Invalid key size for AES-256-GCM"));
        }
        
        if nonce.len() != 12 {
            return Err(VaultError::crypto_error("Invalid nonce size for AES-256-GCM"));
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::crypto_error(format!("Failed to create AES-256-GCM cipher: {}", e)))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        
        cipher.encrypt(nonce, payload)
            .map_err(|e| VaultError::crypto_error(format!("AES-256-GCM encryption failed: {}", e)))
    }
    
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        
        if key.len() != 32 {
            return Err(VaultError::crypto_error("Invalid key size for AES-256-GCM"));
        }
        
        if nonce.len() != 12 {
            return Err(VaultError::crypto_error("Invalid nonce size for AES-256-GCM"));
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::crypto_error(format!("Failed to create AES-256-GCM cipher: {}", e)))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        
        cipher.decrypt(nonce, payload)
            .map_err(|e| VaultError::crypto_error(format!("AES-256-GCM decryption failed: {}", e)))
    }
    
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 12 }
    fn tag_size(&self) -> usize { 16 }
    fn cipher_type(&self) -> CipherType { CipherType::Aes256Gcm }
}

/// XChaCha20-Poly1305 implementation (placeholder for now)
pub struct XChaCha20Poly1305Engine;

impl CryptoEngine for XChaCha20Poly1305Engine {
    fn encrypt(&self, _key: &[u8], _nonce: &[u8], _plaintext: &[u8], _aad: &[u8]) -> VaultResult<Vec<u8>> {
        // TODO: Implement using libsodium bindings
        Err(VaultError::internal_error("XChaCha20-Poly1305 not yet implemented"))
    }
    
    fn decrypt(&self, _key: &[u8], _nonce: &[u8], _ciphertext: &[u8], _aad: &[u8]) -> VaultResult<Vec<u8>> {
        // TODO: Implement using libsodium bindings
        Err(VaultError::internal_error("XChaCha20-Poly1305 not yet implemented"))
    }
    
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 24 }
    fn tag_size(&self) -> usize { 16 }
    fn cipher_type(&self) -> CipherType { CipherType::XChaCha20Poly1305 }
}

/// Create a crypto engine for the specified cipher type
pub fn create_crypto_engine(cipher_type: CipherType) -> VaultResult<Box<dyn CryptoEngine>> {
    match cipher_type {
        CipherType::Aes256Gcm => Ok(Box::new(Aes256GcmEngine)),
        CipherType::XChaCha20Poly1305 => Ok(Box::new(XChaCha20Poly1305Engine)),
    }
}

/// Key derivation using Argon2id
pub fn derive_key(password: &str, salt: &[u8], memory: u32, operations: u32, parallelism: u32) -> VaultResult<[u8; 32]> {
    use argon2::{Argon2, Algorithm, Version, Params};
    
    let params = Params::new(memory, operations, parallelism, Some(32))
        .map_err(|e| VaultError::crypto_error(format!("Invalid Argon2 parameters: {}", e)))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::crypto_error(format!("Argon2 key derivation failed: {}", e)))?;
    
    Ok(key)
}

/// Derive subkeys using HKDF
pub fn derive_subkeys(master_key: &[u8], info: &[u8]) -> VaultResult<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = [0u8; 32];
    
    hk.expand(info, &mut subkey)
        .map_err(|e| VaultError::crypto_error(format!("HKDF expansion failed: {}", e)))?;
    
    Ok(subkey)
}

/// Generate a secure random nonce
pub fn generate_nonce(size: usize) -> VaultResult<Vec<u8>> {
    let mut nonce = vec![0u8; size];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| VaultError::crypto_error(format!("Failed to generate nonce: {}", e)))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cipher_type_display() {
        assert_eq!(CipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(CipherType::XChaCha20Poly1305.to_string(), "xchacha20poly1305");
    }
    
    #[test]
    fn test_cipher_type_from_str() {
        assert_eq!("aes-256-gcm".parse::<CipherType>().unwrap(), CipherType::Aes256Gcm);
        assert_eq!("xchacha20poly1305".parse::<CipherType>().unwrap(), CipherType::XChaCha20Poly1305);
        assert!("invalid".parse::<CipherType>().is_err());
    }
    
    #[test]
    fn test_aes256gcm_engine_properties() {
        let engine = Aes256GcmEngine;
        assert_eq!(engine.key_size(), 32);
        assert_eq!(engine.nonce_size(), 12);
        assert_eq!(engine.tag_size(), 16);
        assert_eq!(engine.cipher_type(), CipherType::Aes256Gcm);
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt = b"test_salt_32_bytes_long_exactly!";
        
        let key = derive_key(password, salt, 1024, 1, 1).unwrap();
        assert_eq!(key.len(), 32);
        
        // Same inputs should produce same key
        let key2 = derive_key(password, salt, 1024, 1, 1).unwrap();
        assert_eq!(key, key2);
        
        // Different inputs should produce different keys
        let key3 = derive_key("different_password", salt, 1024, 1, 1).unwrap();
        assert_ne!(key, key3);
    }
    
    #[test]
    fn test_subkey_derivation() {
        let master_key = b"master_key_32_bytes_long_exactly";
        let info1 = b"file_encryption_key";
        let info2 = b"filename_key";
        
        let subkey1 = derive_subkeys(master_key, info1).unwrap();
        let subkey2 = derive_subkeys(master_key, info2).unwrap();
        
        assert_eq!(subkey1.len(), 32);
        assert_eq!(subkey2.len(), 32);
        assert_ne!(subkey1, subkey2);
    }
    
    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce(12).unwrap();
        let nonce2 = generate_nonce(12).unwrap();
        
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2); // Should be different (very high probability)
    }
}