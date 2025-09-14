//! Password management and recovery systems
//!
//! This module implements secure password management including:
//! - Master key wrapping/unwrapping for password changes
//! - Recovery key generation and management
//! - Algorithm rotation support
//! - Secure key storage and memory management

use std::path::Path;

use crate::crypto::{
    derive_key, derive_all_subkeys, generate_random_bytes, generate_nonce, 
    CryptoEngine, MASTER_KEY_SIZE
};
use crate::error::{VaultError, VaultResult};
use crate::format::{KdfParams, VaultFormat};

/// Size of recovery keys in bytes (32 bytes = 256 bits)
pub const RECOVERY_KEY_SIZE: usize = 32;

/// Recovery key structure for secure vault access
#[derive(Debug, Clone)]
pub struct RecoveryKey {
    /// The raw recovery key bytes
    key_data: [u8; RECOVERY_KEY_SIZE],
}

impl RecoveryKey {
    /// Generate a new cryptographically secure recovery key
    pub fn generate() -> VaultResult<Self> {
        let key_bytes = generate_random_bytes(RECOVERY_KEY_SIZE)?;
        let mut key_data = [0u8; RECOVERY_KEY_SIZE];
        key_data.copy_from_slice(&key_bytes);
        
        Ok(RecoveryKey { key_data })
    }

    /// Create a recovery key from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() != RECOVERY_KEY_SIZE {
            return Err(VaultError::invalid_argument(format!(
                "Recovery key must be exactly {} bytes, got {}",
                RECOVERY_KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key_data = [0u8; RECOVERY_KEY_SIZE];
        key_data.copy_from_slice(bytes);
        
        Ok(RecoveryKey { key_data })
    }

    /// Get the recovery key as bytes
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_SIZE] {
        &self.key_data
    }

    /// Convert recovery key to hex string for display/storage
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key_data)
    }

    /// Create recovery key from hex string
    pub fn from_hex(hex_str: &str) -> VaultResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| VaultError::invalid_argument(format!("Invalid hex string: {}", e)))?;
        
        Self::from_bytes(&bytes)
    }

    /// Securely clear the recovery key from memory
    pub fn clear(&mut self) {
        self.key_data.fill(0);
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Wrapped master key structure for secure storage
#[derive(Debug, Clone)]
pub struct WrappedMasterKey {
    /// The encrypted master key
    pub encrypted_key: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// KDF parameters used for key derivation
    pub kdf_params: KdfParams,
    /// Cipher used for wrapping
    pub cipher: String,
}

/// Password manager for vault operations
pub struct PasswordManager {
    crypto_engine: Box<dyn CryptoEngine>,
}

impl PasswordManager {
    /// Create a new password manager with the specified crypto engine
    pub fn new(crypto_engine: Box<dyn CryptoEngine>) -> Self {
        Self { crypto_engine }
    }

    /// Wrap a master key with a password-derived key
    pub fn wrap_master_key(
        &self,
        master_key: &[u8; MASTER_KEY_SIZE],
        password: &str,
        kdf_params: &KdfParams,
    ) -> VaultResult<WrappedMasterKey> {
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        // Derive wrapping key from password
        let wrapping_key = derive_key(
            password,
            &kdf_params.salt,
            kdf_params.memory,
            kdf_params.operations,
            kdf_params.parallelism,
        )?;

        // Generate nonce for encryption
        let nonce = generate_nonce(self.crypto_engine.nonce_size())?;

        // Encrypt master key with wrapping key
        let encrypted_key = self.crypto_engine.encrypt(
            &wrapping_key,
            &nonce,
            master_key,
            &[], // No AAD for master key wrapping
        )?;

        Ok(WrappedMasterKey {
            encrypted_key,
            nonce,
            kdf_params: kdf_params.clone(),
            cipher: self.crypto_engine.cipher_type().to_string(),
        })
    }

    /// Unwrap a master key using a password
    pub fn unwrap_master_key(
        &self,
        wrapped_key: &WrappedMasterKey,
        password: &str,
    ) -> VaultResult<[u8; MASTER_KEY_SIZE]> {
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        // Verify cipher compatibility
        if wrapped_key.cipher != self.crypto_engine.cipher_type().to_string() {
            return Err(VaultError::crypto_error(format!(
                "Cipher mismatch: expected {}, got {}",
                self.crypto_engine.cipher_type(),
                wrapped_key.cipher
            )));
        }

        // Derive wrapping key from password
        let wrapping_key = derive_key(
            password,
            &wrapped_key.kdf_params.salt,
            wrapped_key.kdf_params.memory,
            wrapped_key.kdf_params.operations,
            wrapped_key.kdf_params.parallelism,
        )?;

        // Decrypt master key
        let decrypted_bytes = self.crypto_engine.decrypt(
            &wrapping_key,
            &wrapped_key.nonce,
            &wrapped_key.encrypted_key,
            &[], // No AAD for master key wrapping
        )?;

        // Validate decrypted key size
        if decrypted_bytes.len() != MASTER_KEY_SIZE {
            return Err(VaultError::crypto_error(format!(
                "Invalid master key size: expected {}, got {}",
                MASTER_KEY_SIZE,
                decrypted_bytes.len()
            )));
        }

        let mut master_key = [0u8; MASTER_KEY_SIZE];
        master_key.copy_from_slice(&decrypted_bytes);
        
        Ok(master_key)
    }

    /// Wrap a master key with a recovery key
    pub fn wrap_master_key_with_recovery(
        &self,
        master_key: &[u8; MASTER_KEY_SIZE],
        recovery_key: &RecoveryKey,
    ) -> VaultResult<WrappedMasterKey> {
        // Generate nonce for encryption
        let nonce = generate_nonce(self.crypto_engine.nonce_size())?;

        // Encrypt master key with recovery key directly (no KDF needed)
        let encrypted_key = self.crypto_engine.encrypt(
            recovery_key.as_bytes(),
            &nonce,
            master_key,
            &[], // No AAD for master key wrapping
        )?;

        // Create dummy KDF params for recovery key (not used but needed for structure)
        let kdf_params = KdfParams {
            salt: vec![0u8; 32], // Dummy salt
            memory: 0,           // Indicates recovery key mode
            operations: 0,
            parallelism: 0,
        };

        Ok(WrappedMasterKey {
            encrypted_key,
            nonce,
            kdf_params,
            cipher: self.crypto_engine.cipher_type().to_string(),
        })
    }

    /// Unwrap a master key using a recovery key
    pub fn unwrap_master_key_with_recovery(
        &self,
        wrapped_key: &WrappedMasterKey,
        recovery_key: &RecoveryKey,
    ) -> VaultResult<[u8; MASTER_KEY_SIZE]> {
        // Verify this is a recovery key wrapped master key
        if wrapped_key.kdf_params.memory != 0 {
            return Err(VaultError::invalid_argument(
                "This wrapped key was not created with a recovery key"
            ));
        }

        // Verify cipher compatibility
        if wrapped_key.cipher != self.crypto_engine.cipher_type().to_string() {
            return Err(VaultError::crypto_error(format!(
                "Cipher mismatch: expected {}, got {}",
                self.crypto_engine.cipher_type(),
                wrapped_key.cipher
            )));
        }

        // Decrypt master key using recovery key directly
        let decrypted_bytes = self.crypto_engine.decrypt(
            recovery_key.as_bytes(),
            &wrapped_key.nonce,
            &wrapped_key.encrypted_key,
            &[], // No AAD for master key wrapping
        )?;

        // Validate decrypted key size
        if decrypted_bytes.len() != MASTER_KEY_SIZE {
            return Err(VaultError::crypto_error(format!(
                "Invalid master key size: expected {}, got {}",
                MASTER_KEY_SIZE,
                decrypted_bytes.len()
            )));
        }

        let mut master_key = [0u8; MASTER_KEY_SIZE];
        master_key.copy_from_slice(&decrypted_bytes);
        
        Ok(master_key)
    }

    /// Change password by re-wrapping the master key without re-encrypting chunks
    pub fn change_password<P: AsRef<Path>>(
        &self,
        vault_path: P,
        old_password: &str,
        new_password: &str,
        new_kdf_params: Option<KdfParams>,
    ) -> VaultResult<()> {
        if old_password.is_empty() || new_password.is_empty() {
            return Err(VaultError::invalid_argument("Passwords cannot be empty"));
        }

        if old_password == new_password {
            return Err(VaultError::invalid_argument("New password must be different from old password"));
        }

        // Read current vault header
        let (mut header, file_table_offset) = VaultFormat::read_vault_header(&vault_path)?;

        // Derive master key using old password
        let old_master_key = derive_key(
            old_password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;

        // Verify old password is correct by attempting to decrypt file table
        let old_subkeys = derive_all_subkeys(&old_master_key)?;
        let crypto_engine = crate::crypto::create_crypto_engine(header.cipher.parse()?)?;
        
        // Try to read file table to verify password
        let file_table = VaultFormat::read_encrypted_file_table(
            &vault_path,
            &header,
            file_table_offset,
            crypto_engine.as_ref(),
            &old_subkeys,
        ).map_err(|_| VaultError::InvalidPassword)?;

        // Read all chunk data before modifying the file
        let mut chunk_data = Vec::new();
        for file_entry in &file_table.files {
            let mut file_chunks = Vec::new();
            for chunk in &file_entry.chunks {
                let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                    &vault_path,
                    chunk.offset,
                    chunk.size,
                    crypto_engine.nonce_size(),
                )?;

                // Decrypt with old subkeys
                let plaintext = crypto_engine.decrypt(
                    &old_subkeys.file_encryption_key,
                    &nonce,
                    &encrypted_chunk,
                    &[], // No AAD for chunks
                )?;

                file_chunks.push(plaintext);
            }
            chunk_data.push(file_chunks);
        }

        // Use provided KDF params or generate new ones
        let new_kdf_params = match new_kdf_params {
            Some(params) => params,
            None => {
                // Generate new salt for security
                let new_salt = generate_random_bytes(32)?;
                KdfParams {
                    salt: new_salt,
                    memory: header.kdf_params.memory,
                    operations: header.kdf_params.operations,
                    parallelism: header.kdf_params.parallelism,
                }
            }
        };

        // Update header with new KDF parameters
        header.kdf_params = new_kdf_params;

        // Derive new master key and subkeys
        let new_master_key = derive_key(
            new_password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;

        let new_subkeys = derive_all_subkeys(&new_master_key)?;

        // Create new vault file with updated header
        VaultFormat::create_vault_file(&vault_path, &header)?;

        // Calculate new file table offset
        let new_file_table_offset = 4 + 1 + 4 + serde_json::to_string_pretty(&header)?.len() as u64;

        // Re-encrypt and write all chunks with new subkeys
        let mut updated_file_table = file_table.clone();
        let mut current_chunk_offset = new_file_table_offset + 1024; // Leave space for file table

        for (file_idx, file_chunks) in chunk_data.iter().enumerate() {
            updated_file_table.files[file_idx].chunks.clear();
            
            for chunk_data in file_chunks {
                // Generate new nonce
                let new_nonce = generate_nonce(crypto_engine.nonce_size())?;

                // Encrypt with new subkeys
                let new_encrypted_chunk = crypto_engine.encrypt(
                    &new_subkeys.file_encryption_key,
                    &new_nonce,
                    chunk_data,
                    &[], // No AAD for chunks
                )?;

                // Write chunk to vault
                VaultFormat::write_chunk_to_vault(
                    &vault_path,
                    current_chunk_offset,
                    &new_nonce,
                    &new_encrypted_chunk,
                )?;

                // Update chunk info
                let total_chunk_size = new_nonce.len() + new_encrypted_chunk.len();
                updated_file_table.files[file_idx].chunks.push(crate::format::ChunkInfo {
                    offset: current_chunk_offset,
                    size: total_chunk_size as u32,
                    iv: new_nonce,
                });

                current_chunk_offset += total_chunk_size as u64;
            }
        }

        // Write updated file table with new subkeys
        VaultFormat::write_encrypted_file_table(
            &vault_path,
            &header,
            &updated_file_table,
            crypto_engine.as_ref(),
            &new_subkeys,
        )?;

        Ok(())
    }

    /// Generate a recovery key and wrap the master key with it
    pub fn setup_recovery_key<P: AsRef<Path>>(
        &self,
        vault_path: P,
        password: &str,
    ) -> VaultResult<(RecoveryKey, WrappedMasterKey)> {
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        // Read current vault header
        let (header, file_table_offset) = VaultFormat::read_vault_header(&vault_path)?;

        // Derive master key using current password
        let master_key = derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;

        // Verify password is correct by attempting to decrypt file table
        let subkeys = derive_all_subkeys(&master_key)?;
        let crypto_engine = crate::crypto::create_crypto_engine(header.cipher.parse()?)?;
        
        let _file_table = VaultFormat::read_encrypted_file_table(
            &vault_path,
            &header,
            file_table_offset,
            crypto_engine.as_ref(),
            &subkeys,
        ).map_err(|_| VaultError::InvalidPassword)?;

        // Generate recovery key
        let recovery_key = RecoveryKey::generate()?;

        // Wrap master key with recovery key
        let wrapped_master_key = self.wrap_master_key_with_recovery(&master_key, &recovery_key)?;

        Ok((recovery_key, wrapped_master_key))
    }

    /// Recover vault access using recovery key
    pub fn recover_with_recovery_key<P: AsRef<Path>>(
        &self,
        vault_path: P,
        recovery_key: &RecoveryKey,
        wrapped_master_key: &WrappedMasterKey,
        new_password: &str,
        new_kdf_params: Option<KdfParams>,
    ) -> VaultResult<()> {
        if new_password.is_empty() {
            return Err(VaultError::invalid_argument("New password cannot be empty"));
        }

        // Unwrap master key using recovery key
        let old_master_key = self.unwrap_master_key_with_recovery(wrapped_master_key, recovery_key)?;

        // Read current vault header
        let (mut header, file_table_offset) = VaultFormat::read_vault_header(&vault_path)?;

        // Derive old subkeys to decrypt existing data
        let old_subkeys = derive_all_subkeys(&old_master_key)?;
        let crypto_engine = crate::crypto::create_crypto_engine(header.cipher.parse()?)?;
        
        // Read existing file table
        let file_table = VaultFormat::read_encrypted_file_table(
            &vault_path,
            &header,
            file_table_offset,
            crypto_engine.as_ref(),
            &old_subkeys,
        )?;

        // Read all chunk data before modifying the file
        let mut chunk_data = Vec::new();
        for file_entry in &file_table.files {
            let mut file_chunks = Vec::new();
            for chunk in &file_entry.chunks {
                let (nonce, encrypted_chunk) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                    &vault_path,
                    chunk.offset,
                    chunk.size,
                    crypto_engine.nonce_size(),
                )?;

                // Decrypt with old subkeys
                let plaintext = crypto_engine.decrypt(
                    &old_subkeys.file_encryption_key,
                    &nonce,
                    &encrypted_chunk,
                    &[], // No AAD for chunks
                )?;

                file_chunks.push(plaintext);
            }
            chunk_data.push(file_chunks);
        }

        // Use provided KDF params or generate new ones
        let new_kdf_params = match new_kdf_params {
            Some(params) => params,
            None => {
                // Generate new salt for security
                let new_salt = generate_random_bytes(32)?;
                KdfParams {
                    salt: new_salt,
                    memory: 65536, // 64MB default
                    operations: 3,
                    parallelism: 1,
                }
            }
        };

        // Update header with new KDF parameters
        header.kdf_params = new_kdf_params;

        // Derive new master key and subkeys
        let new_master_key = derive_key(
            new_password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;
        let new_subkeys = derive_all_subkeys(&new_master_key)?;

        // Create new vault file with updated header
        VaultFormat::create_vault_file(&vault_path, &header)?;

        // Calculate new file table offset
        let new_file_table_offset = 4 + 1 + 4 + serde_json::to_string_pretty(&header)?.len() as u64;

        // Re-encrypt and write all chunks with new subkeys
        let mut updated_file_table = file_table.clone();
        let mut current_chunk_offset = new_file_table_offset + 1024; // Leave space for file table

        for (file_idx, file_chunks) in chunk_data.iter().enumerate() {
            updated_file_table.files[file_idx].chunks.clear();
            
            for chunk_data in file_chunks {
                // Generate new nonce
                let new_nonce = generate_nonce(crypto_engine.nonce_size())?;

                // Encrypt with new subkeys
                let new_encrypted_chunk = crypto_engine.encrypt(
                    &new_subkeys.file_encryption_key,
                    &new_nonce,
                    chunk_data,
                    &[], // No AAD for chunks
                )?;

                // Write chunk to vault
                VaultFormat::write_chunk_to_vault(
                    &vault_path,
                    current_chunk_offset,
                    &new_nonce,
                    &new_encrypted_chunk,
                )?;

                // Update chunk info
                let total_chunk_size = new_nonce.len() + new_encrypted_chunk.len();
                updated_file_table.files[file_idx].chunks.push(crate::format::ChunkInfo {
                    offset: current_chunk_offset,
                    size: total_chunk_size as u32,
                    iv: new_nonce,
                });

                current_chunk_offset += total_chunk_size as u64;
            }
        }

        // Write updated file table with new subkeys
        VaultFormat::write_encrypted_file_table(
            &vault_path,
            &header,
            &updated_file_table,
            crypto_engine.as_ref(),
            &new_subkeys,
        )?;

        Ok(())
    }
}

/// Algorithm rotation manager for upgrading vault encryption
pub struct AlgorithmRotationManager {
    old_crypto_engine: Box<dyn CryptoEngine>,
    new_crypto_engine: Box<dyn CryptoEngine>,
}

impl AlgorithmRotationManager {
    /// Create a new algorithm rotation manager
    pub fn new(
        old_crypto_engine: Box<dyn CryptoEngine>,
        new_crypto_engine: Box<dyn CryptoEngine>,
    ) -> Self {
        Self {
            old_crypto_engine,
            new_crypto_engine,
        }
    }

    /// Rotate vault to new encryption algorithm
    /// This is a background operation that re-encrypts all chunks
    pub fn rotate_algorithm<P: AsRef<Path>>(
        &self,
        vault_path: P,
        password: &str,
        progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>,
    ) -> VaultResult<()> {
        if password.is_empty() {
            return Err(VaultError::invalid_argument("Password cannot be empty"));
        }

        // Read current vault header
        let (mut header, file_table_offset) = VaultFormat::read_vault_header(&vault_path)?;

        // Verify current cipher matches old engine
        if header.cipher != self.old_crypto_engine.cipher_type().to_string() {
            return Err(VaultError::crypto_error(format!(
                "Vault cipher {} doesn't match old engine {}",
                header.cipher,
                self.old_crypto_engine.cipher_type()
            )));
        }

        // Derive master key and subkeys with old algorithm
        let master_key = derive_key(
            password,
            &header.kdf_params.salt,
            header.kdf_params.memory,
            header.kdf_params.operations,
            header.kdf_params.parallelism,
        )?;

        let old_subkeys = derive_all_subkeys(&master_key)?;

        // Read file table with old algorithm
        let file_table = VaultFormat::read_encrypted_file_table(
            &vault_path,
            &header,
            file_table_offset,
            self.old_crypto_engine.as_ref(),
            &old_subkeys,
        )?;

        // Update header to new cipher
        header.cipher = self.new_crypto_engine.cipher_type().to_string();

        // Derive new subkeys (same master key, but may have different derived keys due to algorithm change)
        let new_subkeys = derive_all_subkeys(&master_key)?;

        // Re-encrypt all file chunks with new algorithm
        let total_chunks = file_table.files.iter().map(|f| f.chunks.len()).sum();
        let mut processed_chunks = 0;

        for file_entry in &file_table.files {
            for chunk in &file_entry.chunks {
                // Read and decrypt chunk with old algorithm
                let (old_nonce, old_encrypted_data) = VaultFormat::read_chunk_from_vault_with_nonce_size(
                    &vault_path,
                    chunk.offset,
                    chunk.size,
                    self.old_crypto_engine.nonce_size(),
                )?;

                let plaintext_data = self.old_crypto_engine.decrypt(
                    &old_subkeys.file_encryption_key,
                    &old_nonce,
                    &old_encrypted_data,
                    &[], // No AAD for chunks
                )?;

                // Generate new nonce for new algorithm
                let new_nonce = generate_nonce(self.new_crypto_engine.nonce_size())?;

                // Encrypt with new algorithm
                let new_encrypted_data = self.new_crypto_engine.encrypt(
                    &new_subkeys.file_encryption_key,
                    &new_nonce,
                    &plaintext_data,
                    &[], // No AAD for chunks
                )?;

                // Write new encrypted chunk back to same offset
                VaultFormat::write_chunk_to_vault(
                    &vault_path,
                    chunk.offset,
                    &new_nonce,
                    &new_encrypted_data,
                )?;

                processed_chunks += 1;
                if let Some(ref callback) = progress_callback {
                    callback(processed_chunks, total_chunks);
                }
            }
        }

        // Write updated header
        VaultFormat::create_vault_file(&vault_path, &header)?;

        // Re-encrypt file table with new algorithm
        VaultFormat::write_encrypted_file_table(
            &vault_path,
            &header,
            &file_table,
            self.new_crypto_engine.as_ref(),
            &new_subkeys,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherType, create_crypto_engine};


    fn create_test_kdf_params() -> KdfParams {
        KdfParams {
            salt: generate_random_bytes(32).unwrap(),
            memory: 65536,
            operations: 3,
            parallelism: 1,
        }
    }

    #[test]
    fn test_recovery_key_generation() {
        let recovery_key = RecoveryKey::generate().unwrap();
        assert_eq!(recovery_key.as_bytes().len(), RECOVERY_KEY_SIZE);

        // Generate another key - should be different
        let recovery_key2 = RecoveryKey::generate().unwrap();
        assert_ne!(recovery_key.as_bytes(), recovery_key2.as_bytes());
    }

    #[test]
    fn test_recovery_key_hex_conversion() {
        let recovery_key = RecoveryKey::generate().unwrap();
        let hex_str = recovery_key.to_hex();
        
        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(hex_str.len(), 64);
        
        // Should be able to recreate from hex
        let recovered_key = RecoveryKey::from_hex(&hex_str).unwrap();
        assert_eq!(recovery_key.as_bytes(), recovered_key.as_bytes());
    }

    #[test]
    fn test_recovery_key_from_bytes() {
        let test_bytes = [0x42u8; RECOVERY_KEY_SIZE];
        let recovery_key = RecoveryKey::from_bytes(&test_bytes).unwrap();
        assert_eq!(recovery_key.as_bytes(), &test_bytes);

        // Wrong size should fail
        let wrong_size = [0x42u8; 16];
        assert!(RecoveryKey::from_bytes(&wrong_size).is_err());
    }

    #[test]
    fn test_master_key_wrapping_unwrapping() {
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let password = "test_password";
        let kdf_params = create_test_kdf_params();

        // Wrap master key
        let wrapped_key = password_manager
            .wrap_master_key(&master_key, password, &kdf_params)
            .unwrap();

        // Unwrap master key
        let unwrapped_key = password_manager
            .unwrap_master_key(&wrapped_key, password)
            .unwrap();

        assert_eq!(master_key, unwrapped_key);
    }

    #[test]
    fn test_master_key_wrapping_wrong_password() {
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let kdf_params = create_test_kdf_params();

        // Wrap master key
        let wrapped_key = password_manager
            .wrap_master_key(&master_key, password, &kdf_params)
            .unwrap();

        // Try to unwrap with wrong password - should fail
        assert!(password_manager
            .unwrap_master_key(&wrapped_key, wrong_password)
            .is_err());
    }

    #[test]
    fn test_recovery_key_wrapping_unwrapping() {
        let crypto_engine = create_crypto_engine(CipherType::XChaCha20Poly1305).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let recovery_key = RecoveryKey::generate().unwrap();

        // Wrap master key with recovery key
        let wrapped_key = password_manager
            .wrap_master_key_with_recovery(&master_key, &recovery_key)
            .unwrap();

        // Verify it's marked as recovery key wrapped
        assert_eq!(wrapped_key.kdf_params.memory, 0);

        // Unwrap master key with recovery key
        let unwrapped_key = password_manager
            .unwrap_master_key_with_recovery(&wrapped_key, &recovery_key)
            .unwrap();

        assert_eq!(master_key, unwrapped_key);
    }

    #[test]
    fn test_recovery_key_wrong_key() {
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let recovery_key = RecoveryKey::generate().unwrap();
        let wrong_recovery_key = RecoveryKey::generate().unwrap();

        // Wrap master key with recovery key
        let wrapped_key = password_manager
            .wrap_master_key_with_recovery(&master_key, &recovery_key)
            .unwrap();

        // Try to unwrap with wrong recovery key - should fail
        assert!(password_manager
            .unwrap_master_key_with_recovery(&wrapped_key, &wrong_recovery_key)
            .is_err());
    }

    #[test]
    fn test_password_wrapping_with_recovery_key_fails() {
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let password = "test_password";
        let kdf_params = create_test_kdf_params();
        let recovery_key = RecoveryKey::generate().unwrap();

        // Wrap master key with password
        let password_wrapped = password_manager
            .wrap_master_key(&master_key, password, &kdf_params)
            .unwrap();

        // Try to unwrap password-wrapped key with recovery key - should fail
        assert!(password_manager
            .unwrap_master_key_with_recovery(&password_wrapped, &recovery_key)
            .is_err());

        // Wrap master key with recovery key
        let recovery_wrapped = password_manager
            .wrap_master_key_with_recovery(&master_key, &recovery_key)
            .unwrap();

        // Try to unwrap recovery-wrapped key with password - should fail
        assert!(password_manager
            .unwrap_master_key(&recovery_wrapped, password)
            .is_err());
    }

    #[test]
    fn test_empty_password_validation() {
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let password_manager = PasswordManager::new(crypto_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let kdf_params = create_test_kdf_params();

        // Empty password should fail
        assert!(password_manager
            .wrap_master_key(&master_key, "", &kdf_params)
            .is_err());

        let wrapped_key = password_manager
            .wrap_master_key(&master_key, "valid_password", &kdf_params)
            .unwrap();

        // Empty password for unwrapping should fail
        assert!(password_manager
            .unwrap_master_key(&wrapped_key, "")
            .is_err());
    }

    #[test]
    fn test_cipher_mismatch_detection() {
        let aes_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let xchacha_engine = create_crypto_engine(CipherType::XChaCha20Poly1305).unwrap();

        let aes_manager = PasswordManager::new(aes_engine);
        let xchacha_manager = PasswordManager::new(xchacha_engine);

        let master_key = [0x42u8; MASTER_KEY_SIZE];
        let password = "test_password";
        let kdf_params = create_test_kdf_params();

        // Wrap with AES
        let aes_wrapped = aes_manager
            .wrap_master_key(&master_key, password, &kdf_params)
            .unwrap();

        // Try to unwrap with XChaCha20 - should fail
        assert!(xchacha_manager
            .unwrap_master_key(&aes_wrapped, password)
            .is_err());
    }

    #[test]
    fn test_recovery_key_clearing() {
        let mut recovery_key = RecoveryKey::generate().unwrap();
        
        // Verify key is not all zeros initially
        assert_ne!(recovery_key.as_bytes(), &[0u8; RECOVERY_KEY_SIZE]);
        
        // Clear the key
        recovery_key.clear();
        
        // Verify key is now all zeros
        assert_eq!(recovery_key.as_bytes(), &[0u8; RECOVERY_KEY_SIZE]);
    }
}