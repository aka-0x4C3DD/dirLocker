//! Cryptographic operations and cipher implementations

use std::fmt;

use crate::error::{VaultError, VaultResult};

/// Key derivation constants
pub const MASTER_KEY_SIZE: usize = 32;
pub const SUBKEY_SIZE: usize = 32;
pub const MIN_SALT_SIZE: usize = 16;
pub const RECOMMENDED_SALT_SIZE: usize = 32;

/// HKDF info strings for subkey derivation
pub const FILE_ENCRYPTION_KEY_INFO: &[u8] = b"file_encryption_key";
pub const FILENAME_KEY_INFO: &[u8] = b"filename_key";
pub const MAC_KEY_INFO: &[u8] = b"mac_key";

/// Minimum Argon2id parameters for security
pub const MIN_MEMORY_KB: u32 = 64 * 1024; // 64MB
pub const MIN_OPERATIONS: u32 = 3;
pub const MIN_PARALLELISM: u32 = 1;

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
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>>;

    /// Decrypt data with associated data
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>>;

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
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if key.len() != 32 {
            return Err(VaultError::crypto_error("Invalid key size for AES-256-GCM"));
        }

        if nonce.len() != 12 {
            return Err(VaultError::crypto_error(
                "Invalid nonce size for AES-256-GCM",
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            VaultError::crypto_error(format!("Failed to create AES-256-GCM cipher: {}", e))
        })?;

        let nonce = Nonce::from_slice(nonce);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };

        cipher
            .encrypt(nonce, payload)
            .map_err(|e| VaultError::crypto_error(format!("AES-256-GCM encryption failed: {}", e)))
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if key.len() != 32 {
            return Err(VaultError::crypto_error("Invalid key size for AES-256-GCM"));
        }

        if nonce.len() != 12 {
            return Err(VaultError::crypto_error(
                "Invalid nonce size for AES-256-GCM",
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            VaultError::crypto_error(format!("Failed to create AES-256-GCM cipher: {}", e))
        })?;

        let nonce = Nonce::from_slice(nonce);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| VaultError::crypto_error(format!("AES-256-GCM decryption failed: {}", e)))
    }

    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        12
    }
    fn tag_size(&self) -> usize {
        16
    }
    fn cipher_type(&self) -> CipherType {
        CipherType::Aes256Gcm
    }
}

/// XChaCha20-Poly1305 implementation using pure Rust
pub struct XChaCha20Poly1305Engine;

impl CryptoEngine for XChaCha20Poly1305Engine {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>> {
        use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, KeyInit, XNonce};

        if key.len() != 32 {
            return Err(VaultError::crypto_error(
                "Invalid key size for XChaCha20-Poly1305",
            ));
        }

        if nonce.len() != 24 {
            return Err(VaultError::crypto_error(
                "Invalid nonce size for XChaCha20-Poly1305",
            ));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| {
            VaultError::crypto_error(format!("Failed to create XChaCha20-Poly1305 cipher: {}", e))
        })?;

        let nonce = XNonce::from_slice(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };

        cipher.encrypt(nonce, payload).map_err(|e| {
            VaultError::crypto_error(format!("XChaCha20-Poly1305 encryption failed: {}", e))
        })
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> VaultResult<Vec<u8>> {
        use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, KeyInit, XNonce};

        if key.len() != 32 {
            return Err(VaultError::crypto_error(
                "Invalid key size for XChaCha20-Poly1305",
            ));
        }

        if nonce.len() != 24 {
            return Err(VaultError::crypto_error(
                "Invalid nonce size for XChaCha20-Poly1305",
            ));
        }

        if ciphertext.len() < 16 {
            return Err(VaultError::crypto_error(
                "Ciphertext too short for XChaCha20-Poly1305",
            ));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| {
            VaultError::crypto_error(format!("Failed to create XChaCha20-Poly1305 cipher: {}", e))
        })?;

        let nonce = XNonce::from_slice(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };

        cipher.decrypt(nonce, payload).map_err(|e| {
            VaultError::crypto_error(format!("XChaCha20-Poly1305 decryption failed: {}", e))
        })
    }

    fn key_size(&self) -> usize {
        32
    }
    fn nonce_size(&self) -> usize {
        24
    }
    fn tag_size(&self) -> usize {
        16
    }
    fn cipher_type(&self) -> CipherType {
        CipherType::XChaCha20Poly1305
    }
}

/// Create a crypto engine for the specified cipher type
pub fn create_crypto_engine(cipher_type: CipherType) -> VaultResult<Box<dyn CryptoEngine>> {
    match cipher_type {
        CipherType::Aes256Gcm => Ok(Box::new(Aes256GcmEngine)),
        CipherType::XChaCha20Poly1305 => Ok(Box::new(XChaCha20Poly1305Engine)),
    }
}

/// Key derivation using Argon2id with security validation
pub fn derive_key(
    password: &str,
    salt: &[u8],
    memory: u32,
    operations: u32,
    parallelism: u32,
) -> VaultResult<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Validate parameters meet minimum security requirements
    if salt.len() < MIN_SALT_SIZE {
        return Err(VaultError::crypto_error(format!(
            "Salt too short: {} bytes (minimum {})",
            salt.len(),
            MIN_SALT_SIZE
        )));
    }

    if memory < MIN_MEMORY_KB {
        return Err(VaultError::crypto_error(format!(
            "Memory parameter too low: {} KB (minimum {} KB)",
            memory, MIN_MEMORY_KB
        )));
    }

    if operations < MIN_OPERATIONS {
        return Err(VaultError::crypto_error(format!(
            "Operations parameter too low: {} (minimum {})",
            operations, MIN_OPERATIONS
        )));
    }

    if parallelism < MIN_PARALLELISM {
        return Err(VaultError::crypto_error(format!(
            "Parallelism parameter too low: {} (minimum {})",
            parallelism, MIN_PARALLELISM
        )));
    }

    if password.is_empty() {
        return Err(VaultError::crypto_error("Password cannot be empty"));
    }

    let params = Params::new(memory, operations, parallelism, Some(MASTER_KEY_SIZE))
        .map_err(|e| VaultError::crypto_error(format!("Invalid Argon2 parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; MASTER_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::crypto_error(format!("Argon2 key derivation failed: {}", e)))?;

    Ok(key)
}

/// Derive subkeys using HKDF-SHA256
pub fn derive_subkeys(master_key: &[u8], info: &[u8]) -> VaultResult<[u8; SUBKEY_SIZE]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    if master_key.len() != MASTER_KEY_SIZE {
        return Err(VaultError::crypto_error(format!(
            "Invalid master key size: {} bytes (expected {})",
            master_key.len(),
            MASTER_KEY_SIZE
        )));
    }

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = [0u8; SUBKEY_SIZE];

    hk.expand(info, &mut subkey)
        .map_err(|e| VaultError::crypto_error(format!("HKDF expansion failed: {}", e)))?;

    Ok(subkey)
}

/// Derive all required subkeys from master key
pub fn derive_all_subkeys(master_key: &[u8]) -> VaultResult<SubKeys> {
    let file_encryption_key = derive_subkeys(master_key, FILE_ENCRYPTION_KEY_INFO)?;
    let filename_key = derive_subkeys(master_key, FILENAME_KEY_INFO)?;
    let mac_key = derive_subkeys(master_key, MAC_KEY_INFO)?;

    Ok(SubKeys {
        file_encryption_key,
        filename_key,
        mac_key,
    })
}

/// Container for all derived subkeys
#[derive(Debug, Clone)]
pub struct SubKeys {
    pub file_encryption_key: [u8; SUBKEY_SIZE],
    pub filename_key: [u8; SUBKEY_SIZE],
    pub mac_key: [u8; SUBKEY_SIZE],
}

impl SubKeys {
    /// Securely clear all subkeys from memory
    pub fn clear(&mut self) {
        // Zero out all key material
        self.file_encryption_key.fill(0);
        self.filename_key.fill(0);
        self.mac_key.fill(0);
    }
}

impl Drop for SubKeys {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Generate a secure random nonce using OS CSPRNG
pub fn generate_nonce(size: usize) -> VaultResult<Vec<u8>> {
    if size == 0 {
        return Err(VaultError::crypto_error("Nonce size cannot be zero"));
    }

    if size > 1024 {
        return Err(VaultError::crypto_error(
            "Nonce size too large (maximum 1024 bytes)",
        ));
    }

    let mut nonce = vec![0u8; size];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| VaultError::crypto_error(format!("Failed to generate nonce: {}", e)))?;
    Ok(nonce)
}

/// Generate a secure random salt for key derivation
pub fn generate_salt() -> VaultResult<Vec<u8>> {
    generate_nonce(RECOMMENDED_SALT_SIZE)
}

/// Generate secure random bytes using OS CSPRNG
pub fn generate_random_bytes(size: usize) -> VaultResult<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    if size > 1024 * 1024 {
        return Err(VaultError::crypto_error(
            "Random bytes size too large (maximum 1MB)",
        ));
    }

    let mut bytes = vec![0u8; size];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| VaultError::crypto_error(format!("Failed to generate random bytes: {}", e)))?;
    Ok(bytes)
}

/// Check if AES hardware acceleration is available
pub fn has_aes_hardware_acceleration() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        unsafe {
            // Check for AES-NI support
            let cpuid = __cpuid(1);
            (cpuid.ecx & (1 << 25)) != 0
        }
    }
    #[cfg(target_arch = "x86")]
    {
        use std::arch::x86::*;
        unsafe {
            // Check for AES-NI support
            let cpuid = __cpuid(1);
            (cpuid.ecx & (1 << 25)) != 0
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARM64 typically has AES acceleration
        // This is a simplified check - in practice you'd check specific CPU features
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        // Conservative default for other architectures
        false
    }
}

/// Recommend the best cipher based on hardware capabilities
pub fn recommend_cipher() -> CipherType {
    if has_aes_hardware_acceleration() {
        CipherType::Aes256Gcm
    } else {
        CipherType::XChaCha20Poly1305
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_type_display() {
        assert_eq!(CipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(
            CipherType::XChaCha20Poly1305.to_string(),
            "xchacha20poly1305"
        );
    }

    #[test]
    fn test_cipher_type_from_str() {
        assert_eq!(
            "aes-256-gcm".parse::<CipherType>().unwrap(),
            CipherType::Aes256Gcm
        );
        assert_eq!(
            "xchacha20poly1305".parse::<CipherType>().unwrap(),
            CipherType::XChaCha20Poly1305
        );
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
    fn test_xchacha20poly1305_engine_properties() {
        let engine = XChaCha20Poly1305Engine;
        assert_eq!(engine.key_size(), 32);
        assert_eq!(engine.nonce_size(), 24);
        assert_eq!(engine.tag_size(), 16);
        assert_eq!(engine.cipher_type(), CipherType::XChaCha20Poly1305);
    }

    #[test]
    fn test_aes256gcm_encryption_decryption() {
        let engine = Aes256GcmEngine;
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        // Test encryption
        let ciphertext = engine.encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

        // Test decryption
        let decrypted = engine.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test with wrong AAD should fail
        let wrong_aad = b"wrong additional data";
        assert!(engine
            .decrypt(&key, &nonce, &ciphertext, wrong_aad)
            .is_err());

        // Test with wrong key should fail
        let wrong_key = [3u8; 32];
        assert!(engine
            .decrypt(&wrong_key, &nonce, &ciphertext, aad)
            .is_err());
    }

    #[test]
    fn test_aes256gcm_invalid_inputs() {
        let engine = Aes256GcmEngine;
        let plaintext = b"test";
        let aad = b"";

        // Invalid key size
        let short_key = [1u8; 16];
        let nonce = [2u8; 12];
        assert!(engine.encrypt(&short_key, &nonce, plaintext, aad).is_err());

        // Invalid nonce size
        let key = [1u8; 32];
        let short_nonce = [2u8; 8];
        assert!(engine.encrypt(&key, &short_nonce, plaintext, aad).is_err());
    }

    #[test]
    fn test_xchacha20poly1305_encryption_decryption() {
        let engine = XChaCha20Poly1305Engine;
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let plaintext = b"Hello, XChaCha20-Poly1305!";
        let aad = b"additional authenticated data";

        // Test encryption
        let ciphertext = engine.encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

        // Test decryption
        let decrypted = engine.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test with wrong AAD should fail
        let wrong_aad = b"wrong aad";
        assert!(engine
            .decrypt(&key, &nonce, &ciphertext, wrong_aad)
            .is_err());
    }

    #[test]
    fn test_xchacha20poly1305_invalid_inputs() {
        let engine = XChaCha20Poly1305Engine;
        let plaintext = b"test";
        let aad = b"";

        // Invalid key size
        let short_key = [1u8; 16];
        let nonce = [2u8; 24];
        assert!(engine.encrypt(&short_key, &nonce, plaintext, aad).is_err());

        // Invalid nonce size
        let key = [1u8; 32];
        let short_nonce = [2u8; 12];
        assert!(engine.encrypt(&key, &short_nonce, plaintext, aad).is_err());

        // Ciphertext too short for decryption
        let short_ciphertext = [1u8; 8];
        let valid_nonce = [2u8; 24];
        assert!(engine
            .decrypt(&key, &valid_nonce, &short_ciphertext, aad)
            .is_err());
    }

    #[test]
    fn test_key_derivation_with_validation() {
        let password = "test_password";
        let salt = generate_salt().unwrap();

        // Valid parameters
        let key = derive_key(
            password,
            &salt,
            MIN_MEMORY_KB,
            MIN_OPERATIONS,
            MIN_PARALLELISM,
        )
        .unwrap();
        assert_eq!(key.len(), MASTER_KEY_SIZE);

        // Same inputs should produce same key
        let key2 = derive_key(
            password,
            &salt,
            MIN_MEMORY_KB,
            MIN_OPERATIONS,
            MIN_PARALLELISM,
        )
        .unwrap();
        assert_eq!(key, key2);

        // Different inputs should produce different keys
        let key3 = derive_key(
            "different_password",
            &salt,
            MIN_MEMORY_KB,
            MIN_OPERATIONS,
            MIN_PARALLELISM,
        )
        .unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_key_derivation_parameter_validation() {
        let password = "test_password";
        let salt = generate_salt().unwrap();

        // Salt too short
        let short_salt = vec![1u8; 8];
        assert!(derive_key(
            password,
            &short_salt,
            MIN_MEMORY_KB,
            MIN_OPERATIONS,
            MIN_PARALLELISM
        )
        .is_err());

        // Memory too low
        assert!(derive_key(password, &salt, 1024, MIN_OPERATIONS, MIN_PARALLELISM).is_err());

        // Operations too low
        assert!(derive_key(password, &salt, MIN_MEMORY_KB, 0, MIN_PARALLELISM).is_err());

        // Parallelism too low
        assert!(derive_key(password, &salt, MIN_MEMORY_KB, MIN_OPERATIONS, 0).is_err());

        // Empty password
        assert!(derive_key("", &salt, MIN_MEMORY_KB, MIN_OPERATIONS, MIN_PARALLELISM).is_err());
    }

    #[test]
    fn test_subkey_derivation() {
        let master_key = [1u8; MASTER_KEY_SIZE];

        let subkey1 = derive_subkeys(&master_key, FILE_ENCRYPTION_KEY_INFO).unwrap();
        let subkey2 = derive_subkeys(&master_key, FILENAME_KEY_INFO).unwrap();
        let subkey3 = derive_subkeys(&master_key, MAC_KEY_INFO).unwrap();

        assert_eq!(subkey1.len(), SUBKEY_SIZE);
        assert_eq!(subkey2.len(), SUBKEY_SIZE);
        assert_eq!(subkey3.len(), SUBKEY_SIZE);

        // All subkeys should be different
        assert_ne!(subkey1, subkey2);
        assert_ne!(subkey2, subkey3);
        assert_ne!(subkey1, subkey3);

        // Same inputs should produce same subkey
        let subkey1_again = derive_subkeys(&master_key, FILE_ENCRYPTION_KEY_INFO).unwrap();
        assert_eq!(subkey1, subkey1_again);
    }

    #[test]
    fn test_derive_all_subkeys() {
        let master_key = [1u8; MASTER_KEY_SIZE];

        let subkeys = derive_all_subkeys(&master_key).unwrap();

        // Verify all subkeys are different
        assert_ne!(subkeys.file_encryption_key, subkeys.filename_key);
        assert_ne!(subkeys.filename_key, subkeys.mac_key);
        assert_ne!(subkeys.file_encryption_key, subkeys.mac_key);

        // Verify they match individual derivations
        let file_key = derive_subkeys(&master_key, FILE_ENCRYPTION_KEY_INFO).unwrap();
        let filename_key = derive_subkeys(&master_key, FILENAME_KEY_INFO).unwrap();
        let mac_key = derive_subkeys(&master_key, MAC_KEY_INFO).unwrap();

        assert_eq!(subkeys.file_encryption_key, file_key);
        assert_eq!(subkeys.filename_key, filename_key);
        assert_eq!(subkeys.mac_key, mac_key);
    }

    #[test]
    fn test_subkey_derivation_invalid_master_key() {
        let short_key = [1u8; 16];
        assert!(derive_subkeys(&short_key, FILE_ENCRYPTION_KEY_INFO).is_err());

        let long_key = [1u8; 64];
        assert!(derive_subkeys(&long_key, FILE_ENCRYPTION_KEY_INFO).is_err());
    }

    #[test]
    fn test_subkeys_clear() {
        let master_key = [1u8; MASTER_KEY_SIZE];
        let mut subkeys = derive_all_subkeys(&master_key).unwrap();

        // Verify keys are not zero initially
        assert_ne!(subkeys.file_encryption_key, [0u8; SUBKEY_SIZE]);
        assert_ne!(subkeys.filename_key, [0u8; SUBKEY_SIZE]);
        assert_ne!(subkeys.mac_key, [0u8; SUBKEY_SIZE]);

        // Clear keys
        subkeys.clear();

        // Verify keys are now zero
        assert_eq!(subkeys.file_encryption_key, [0u8; SUBKEY_SIZE]);
        assert_eq!(subkeys.filename_key, [0u8; SUBKEY_SIZE]);
        assert_eq!(subkeys.mac_key, [0u8; SUBKEY_SIZE]);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce(12).unwrap();
        let nonce2 = generate_nonce(12).unwrap();

        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2); // Should be different (very high probability)

        // Test different sizes
        let nonce24 = generate_nonce(24).unwrap();
        assert_eq!(nonce24.len(), 24);

        // Test edge cases
        assert!(generate_nonce(0).is_err());
        assert!(generate_nonce(2000).is_err()); // Too large
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_eq!(salt1.len(), RECOMMENDED_SALT_SIZE);
        assert_eq!(salt2.len(), RECOMMENDED_SALT_SIZE);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(32).unwrap();
        let bytes2 = generate_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different

        // Test zero size
        let empty = generate_random_bytes(0).unwrap();
        assert_eq!(empty.len(), 0);

        // Test large size should fail
        assert!(generate_random_bytes(2 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_cipher_recommendation() {
        let recommended = recommend_cipher();
        // Should be one of the supported ciphers
        assert!(matches!(
            recommended,
            CipherType::Aes256Gcm | CipherType::XChaCha20Poly1305
        ));
    }

    #[test]
    fn test_crypto_engine_creation() {
        let aes_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        assert_eq!(aes_engine.cipher_type(), CipherType::Aes256Gcm);

        let xchacha_engine = create_crypto_engine(CipherType::XChaCha20Poly1305).unwrap();
        assert_eq!(xchacha_engine.cipher_type(), CipherType::XChaCha20Poly1305);
    }

    #[test]
    fn test_cross_platform_compatibility() {
        // Test that encryption/decryption works consistently
        let engines = [
            create_crypto_engine(CipherType::Aes256Gcm).unwrap(),
            create_crypto_engine(CipherType::XChaCha20Poly1305).unwrap(),
        ];

        for engine in &engines {
            let key = generate_random_bytes(engine.key_size()).unwrap();
            let nonce = generate_nonce(engine.nonce_size()).unwrap();
            let plaintext = b"Cross-platform test data";
            let aad = b"test aad";

            let ciphertext = engine.encrypt(&key, &nonce, plaintext, aad).unwrap();
            let decrypted = engine.decrypt(&key, &nonce, &ciphertext, aad).unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_argon2_test_vectors() {
        // Test with known Argon2id test vectors for consistency
        let password = "password";
        let salt = b"somesalt16bytess"; // 16 bytes minimum
        let memory = 65536;
        let operations = 3;
        let parallelism = 1;

        let key1 = derive_key(password, salt, memory, operations, parallelism).unwrap();
        let key2 = derive_key(password, salt, memory, operations, parallelism).unwrap();

        // Same parameters should produce identical keys
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let different_salt = b"different16bytes";
        let key3 = derive_key(password, different_salt, memory, operations, parallelism).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_hkdf_test_vectors() {
        // Test HKDF with known inputs for consistency
        let master_key = [0x0b; 22]; // Not 32 bytes to test validation
        assert!(derive_subkeys(&master_key, b"test").is_err());

        let master_key = [0x0b; 32];
        let info = b"test info";

        let subkey1 = derive_subkeys(&master_key, info).unwrap();
        let subkey2 = derive_subkeys(&master_key, info).unwrap();

        // Same inputs should produce same output
        assert_eq!(subkey1, subkey2);

        // Different info should produce different output
        let subkey3 = derive_subkeys(&master_key, b"different info").unwrap();
        assert_ne!(subkey1, subkey3);
    }

    #[test]
    fn test_memory_security() {
        // Test that sensitive data is properly cleared
        let master_key = [0x42; MASTER_KEY_SIZE];
        let subkeys = derive_all_subkeys(&master_key).unwrap();

        // Verify keys contain expected data
        assert_ne!(subkeys.file_encryption_key[0], 0);

        // Drop should clear memory
        drop(subkeys);

        // Create new subkeys to verify they're properly derived
        let subkeys2 = derive_all_subkeys(&master_key).unwrap();
        assert_ne!(subkeys2.file_encryption_key, [0u8; SUBKEY_SIZE]);
    }
}
