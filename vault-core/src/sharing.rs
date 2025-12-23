//! Secure sharing and envelope encryption implementation
//!
//! This module implements X25519 key exchange with AEAD envelope encryption
//! to enable secure sharing of vault access with multiple recipients.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
// X25519 operations are handled via curve25519-dalek directly

use crate::crypto::{generate_nonce, generate_random_bytes, CryptoEngine, SubKeys};
use crate::error::{VaultError, VaultResult};

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// Shared secret size for X25519
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// X25519 key pair for sharing operations
#[derive(Debug, Clone)]
pub struct X25519KeyPair {
    pub public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    pub private_key: [u8; X25519_PRIVATE_KEY_SIZE],
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair using secure random generation
    pub fn generate() -> VaultResult<Self> {
        // Generate random private key bytes
        let private_key = generate_random_bytes(X25519_PRIVATE_KEY_SIZE)?;
        let private_key: [u8; X25519_PRIVATE_KEY_SIZE] = private_key
            .try_into()
            .map_err(|_| VaultError::crypto_error("Failed to convert private key bytes"))?;

        // Compute the public key from the private key using curve25519-dalek
        let public_key = Self::compute_public_key_from_private(&private_key)?;

        Ok(X25519KeyPair {
            public_key,
            private_key,
        })
    }

    /// Create a key pair from existing private key bytes
    pub fn from_private_key(private_key: [u8; X25519_PRIVATE_KEY_SIZE]) -> VaultResult<Self> {
        let public_key = Self::compute_public_key_from_private(&private_key)?;

        Ok(X25519KeyPair {
            public_key,
            private_key,
        })
    }

    /// Compute public key from private key bytes using curve25519-dalek
    fn compute_public_key_from_private(
        private_key: &[u8; X25519_PRIVATE_KEY_SIZE],
    ) -> VaultResult<[u8; X25519_PUBLIC_KEY_SIZE]> {
        // Use curve25519-dalek's scalar multiplication
        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

        // Convert private key to scalar
        let scalar = Scalar::from_bytes_mod_order(*private_key);

        // Multiply by base point to get public key
        let point = &scalar * ED25519_BASEPOINT_TABLE;

        // Convert to Montgomery form for X25519
        let public_key_bytes = point.to_montgomery().to_bytes();

        Ok(public_key_bytes)
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.public_key
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> &[u8; X25519_PRIVATE_KEY_SIZE] {
        &self.private_key
    }

    /// Perform X25519 key exchange to derive shared secret
    pub fn exchange(
        &self,
        peer_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) -> VaultResult<[u8; X25519_SHARED_SECRET_SIZE]> {
        // Use curve25519-dalek for the key exchange
        use curve25519_dalek::{montgomery::MontgomeryPoint, scalar::Scalar};

        // Convert our private key to scalar
        let scalar = Scalar::from_bytes_mod_order(self.private_key);

        // Convert peer public key to Montgomery point
        let peer_point = MontgomeryPoint(*peer_public_key);

        // Perform scalar multiplication
        let shared_point = scalar * peer_point;

        Ok(shared_point.to_bytes())
    }

    /// Securely clear the private key from memory
    pub fn clear(&mut self) {
        self.private_key.fill(0);
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Encrypted envelope containing vault access for a single recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEnvelope {
    /// Recipient's public key
    #[serde(with = "base64_key_serde")]
    pub recipient_public_key: [u8; X25519_PUBLIC_KEY_SIZE],

    /// Ephemeral public key used for this envelope
    #[serde(with = "base64_key_serde")]
    pub ephemeral_public_key: [u8; X25519_PUBLIC_KEY_SIZE],

    /// Encrypted vault subkeys
    #[serde(with = "base64_vec_serde")]
    pub encrypted_subkeys: Vec<u8>,

    /// Nonce used for encryption
    #[serde(with = "base64_vec_serde")]
    pub nonce: Vec<u8>,

    /// Cipher used for envelope encryption
    pub cipher: String,

    /// Envelope creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ShareEnvelope {
    /// Create a new share envelope for a recipient
    pub fn create(
        recipient_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
        vault_subkeys: &SubKeys,
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<Self> {
        // Generate ephemeral key pair for this envelope
        let ephemeral_keypair = X25519KeyPair::generate()?;

        // Perform key exchange to get shared secret
        let shared_secret = ephemeral_keypair.exchange(&recipient_public_key)?;

        // Serialize vault subkeys for encryption
        let subkeys_data = Self::serialize_subkeys(vault_subkeys)?;

        // Generate nonce for encryption
        let nonce = generate_nonce(crypto_engine.nonce_size())?;

        // Encrypt subkeys using shared secret as key
        let encrypted_subkeys = crypto_engine.encrypt(
            &shared_secret,
            &nonce,
            &subkeys_data,
            &recipient_public_key, // Use recipient public key as AAD
        )?;

        Ok(ShareEnvelope {
            recipient_public_key,
            ephemeral_public_key: ephemeral_keypair.public_key,
            encrypted_subkeys,
            nonce,
            cipher: crypto_engine.cipher_type().to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    /// Decrypt the envelope using recipient's private key
    pub fn decrypt(
        &self,
        recipient_private_key: &[u8; X25519_PRIVATE_KEY_SIZE],
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<SubKeys> {
        // Verify cipher compatibility
        if self.cipher != crypto_engine.cipher_type().to_string() {
            return Err(VaultError::crypto_error(format!(
                "Envelope cipher {} doesn't match engine cipher {}",
                self.cipher,
                crypto_engine.cipher_type()
            )));
        }

        // Create key pair from recipient's private key
        let recipient_keypair = X25519KeyPair::from_private_key(*recipient_private_key)?;

        // Perform key exchange with ephemeral public key
        let shared_secret = recipient_keypair.exchange(&self.ephemeral_public_key)?;

        // Decrypt subkeys
        let decrypted_data = crypto_engine.decrypt(
            &shared_secret,
            &self.nonce,
            &self.encrypted_subkeys,
            &self.recipient_public_key, // Use recipient public key as AAD
        )?;

        // Deserialize subkeys
        Self::deserialize_subkeys(&decrypted_data)
    }

    /// Serialize subkeys for encryption
    fn serialize_subkeys(subkeys: &SubKeys) -> VaultResult<Vec<u8>> {
        let mut data = Vec::with_capacity(128); // 4 * 32 bytes
        data.extend_from_slice(&subkeys.file_encryption_key);
        data.extend_from_slice(&subkeys.filename_key);
        data.extend_from_slice(&subkeys.mac_key);
        data.extend_from_slice(&subkeys.metadata_key);
        Ok(data)
    }

    /// Deserialize subkeys from decrypted data
    fn deserialize_subkeys(data: &[u8]) -> VaultResult<SubKeys> {
        if data.len() != 128 {
            return Err(VaultError::crypto_error(format!(
                "Invalid subkeys data length: {} (expected 128)",
                data.len()
            )));
        }

        let file_encryption_key: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| VaultError::crypto_error("Failed to parse file encryption key"))?;

        let filename_key: [u8; 32] = data[32..64]
            .try_into()
            .map_err(|_| VaultError::crypto_error("Failed to parse filename key"))?;

        let mac_key: [u8; 32] = data[64..96]
            .try_into()
            .map_err(|_| VaultError::crypto_error("Failed to parse MAC key"))?;

        // For sharing, we need to derive the metadata key as well
        let metadata_key: [u8; 32] = data[96..128]
            .try_into()
            .map_err(|_| VaultError::crypto_error("Failed to parse metadata key"))?;

        Ok(SubKeys {
            file_encryption_key,
            filename_key,
            mac_key,
            metadata_key,
        })
    }

    /// Validate the envelope structure
    pub fn validate(&self) -> VaultResult<()> {
        if self.encrypted_subkeys.is_empty() {
            return Err(VaultError::crypto_error("Empty encrypted subkeys"));
        }

        if self.nonce.is_empty() {
            return Err(VaultError::crypto_error("Empty nonce"));
        }

        // Validate cipher
        let _: crate::crypto::CipherType = self.cipher.parse()?;

        Ok(())
    }
}

/// Collection of share envelopes for multiple recipients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEnvelopeCollection {
    /// Map of recipient public key to their envelope
    pub envelopes: HashMap<String, ShareEnvelope>,

    /// Vault UUID this collection belongs to
    pub vault_uuid: uuid::Uuid,

    /// Collection creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last modified timestamp
    pub modified_at: chrono::DateTime<chrono::Utc>,
}

impl ShareEnvelopeCollection {
    /// Create a new empty envelope collection
    pub fn new(vault_uuid: uuid::Uuid) -> Self {
        let now = chrono::Utc::now();
        ShareEnvelopeCollection {
            envelopes: HashMap::new(),
            vault_uuid,
            created_at: now,
            modified_at: now,
        }
    }

    /// Add a recipient to the collection
    pub fn add_recipient(
        &mut self,
        recipient_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
        vault_subkeys: &SubKeys,
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<()> {
        let envelope = ShareEnvelope::create(recipient_public_key, vault_subkeys, crypto_engine)?;

        let key_string = hex::encode(recipient_public_key);
        self.envelopes.insert(key_string, envelope);
        self.modified_at = chrono::Utc::now();

        Ok(())
    }

    /// Remove a recipient from the collection
    pub fn remove_recipient(
        &mut self,
        recipient_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) -> bool {
        let key_string = hex::encode(recipient_public_key);
        let removed = self.envelopes.remove(&key_string).is_some();

        if removed {
            self.modified_at = chrono::Utc::now();
        }

        removed
    }

    /// Get an envelope for a specific recipient
    pub fn get_envelope(
        &self,
        recipient_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) -> Option<&ShareEnvelope> {
        let key_string = hex::encode(recipient_public_key);
        self.envelopes.get(&key_string)
    }

    /// List all recipient public keys
    pub fn list_recipients(&self) -> Vec<[u8; X25519_PUBLIC_KEY_SIZE]> {
        self.envelopes
            .keys()
            .filter_map(|key_str| {
                hex::decode(key_str)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
            })
            .collect()
    }

    /// Get the number of recipients
    pub fn recipient_count(&self) -> usize {
        self.envelopes.len()
    }

    /// Check if a recipient exists
    pub fn has_recipient(&self, recipient_public_key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> bool {
        let key_string = hex::encode(recipient_public_key);
        self.envelopes.contains_key(&key_string)
    }

    /// Export the collection as JSON
    pub fn export_json(&self) -> VaultResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VaultError::crypto_error(format!("Failed to export envelopes: {}", e)))
    }

    /// Import a collection from JSON
    pub fn import_json(json: &str) -> VaultResult<Self> {
        let collection: ShareEnvelopeCollection = serde_json::from_str(json)
            .map_err(|e| VaultError::crypto_error(format!("Failed to import envelopes: {}", e)))?;

        // Validate all envelopes
        for envelope in collection.envelopes.values() {
            envelope.validate()?;
        }

        Ok(collection)
    }

    /// Validate the entire collection
    pub fn validate(&self) -> VaultResult<()> {
        for (key_str, envelope) in &self.envelopes {
            // Validate key string format
            let _key_bytes: [u8; X25519_PUBLIC_KEY_SIZE] = hex::decode(key_str)
                .map_err(|_| VaultError::crypto_error("Invalid recipient key format"))?
                .try_into()
                .map_err(|_| VaultError::crypto_error("Invalid recipient key length"))?;

            // Validate envelope
            envelope.validate()?;
        }

        Ok(())
    }
}

/// Sharing manager for vault operations
pub struct SharingManager {
    vault_uuid: uuid::Uuid,
    envelopes: ShareEnvelopeCollection,
}

impl SharingManager {
    /// Create a new sharing manager for a vault
    pub fn new(vault_uuid: uuid::Uuid) -> Self {
        SharingManager {
            vault_uuid,
            envelopes: ShareEnvelopeCollection::new(vault_uuid),
        }
    }

    /// Load sharing manager from existing envelope collection
    pub fn from_collection(collection: ShareEnvelopeCollection) -> VaultResult<Self> {
        collection.validate()?;

        Ok(SharingManager {
            vault_uuid: collection.vault_uuid,
            envelopes: collection,
        })
    }

    /// Add a new recipient to the vault sharing
    pub fn add_recipient(
        &mut self,
        recipient_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
        vault_subkeys: &SubKeys,
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<()> {
        self.envelopes
            .add_recipient(recipient_public_key, vault_subkeys, crypto_engine)
    }

    /// Remove a recipient from vault sharing
    pub fn remove_recipient(
        &mut self,
        recipient_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) -> bool {
        self.envelopes.remove_recipient(recipient_public_key)
    }

    /// Decrypt vault access for a recipient
    pub fn decrypt_for_recipient(
        &self,
        recipient_private_key: &[u8; X25519_PRIVATE_KEY_SIZE],
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<SubKeys> {
        // Derive public key from private key to find the right envelope
        let keypair = X25519KeyPair::from_private_key(*recipient_private_key)
            .map_err(|e| VaultError::crypto_error(format!("Failed to create keypair: {}", e)))?;
        let public_key = keypair.public_key_bytes();

        let envelope = self
            .envelopes
            .get_envelope(public_key)
            .ok_or_else(|| VaultError::crypto_error("No envelope found for recipient"))?;

        envelope.decrypt(recipient_private_key, crypto_engine)
    }

    /// List all recipients
    pub fn list_recipients(&self) -> Vec<[u8; X25519_PUBLIC_KEY_SIZE]> {
        self.envelopes.list_recipients()
    }

    /// Get recipient count
    pub fn recipient_count(&self) -> usize {
        self.envelopes.recipient_count()
    }

    /// Check if a recipient has access
    pub fn has_recipient(&self, recipient_public_key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> bool {
        self.envelopes.has_recipient(recipient_public_key)
    }

    /// Export envelopes for sharing
    pub fn export_envelopes(&self) -> VaultResult<String> {
        self.envelopes.export_json()
    }

    /// Import envelopes from external source
    pub fn import_envelopes(&mut self, json: &str) -> VaultResult<()> {
        let imported_collection = ShareEnvelopeCollection::import_json(json)?;

        // Verify vault UUID matches
        if imported_collection.vault_uuid != self.vault_uuid {
            return Err(VaultError::crypto_error(
                "Imported envelopes belong to different vault",
            ));
        }

        // Merge envelopes (imported ones take precedence)
        for (key, envelope) in imported_collection.envelopes {
            self.envelopes.envelopes.insert(key, envelope);
        }

        self.envelopes.modified_at = chrono::Utc::now();

        Ok(())
    }

    /// Get the envelope collection
    pub fn get_collection(&self) -> &ShareEnvelopeCollection {
        &self.envelopes
    }

    /// Update all envelopes with new vault subkeys (for key rotation)
    pub fn update_all_envelopes(
        &mut self,
        new_vault_subkeys: &SubKeys,
        crypto_engine: &dyn CryptoEngine,
    ) -> VaultResult<()> {
        let recipients: Vec<_> = self.list_recipients();

        // Clear existing envelopes
        self.envelopes.envelopes.clear();

        // Recreate envelopes with new subkeys
        for recipient_key in recipients {
            self.envelopes
                .add_recipient(recipient_key, new_vault_subkeys, crypto_engine)?;
        }

        Ok(())
    }
}

/// Helper module for base64 serialization of 32-byte keys
mod base64_key_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let encoded = String::deserialize(deserializer)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| D::Error::custom(format!("Base64 decode error: {}", e)))?;

        decoded
            .try_into()
            .map_err(|_| D::Error::custom("Invalid key length"))
    }
}

/// Helper module for base64 serialization of Vec<u8>
mod base64_vec_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| D::Error::custom(format!("Base64 decode error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_crypto_engine, derive_all_subkeys, CipherType};

    fn create_test_subkeys() -> SubKeys {
        let master_key = [0x42u8; 32];
        derive_all_subkeys(&master_key).unwrap()
    }

    #[test]
    fn test_x25519_keypair_generation() {
        let keypair1 = X25519KeyPair::generate().unwrap();
        let keypair2 = X25519KeyPair::generate().unwrap();

        // Keys should be different
        assert_ne!(keypair1.public_key, keypair2.public_key);
        assert_ne!(keypair1.private_key, keypair2.private_key);

        // Keys should be correct length
        assert_eq!(keypair1.public_key.len(), X25519_PUBLIC_KEY_SIZE);
        assert_eq!(keypair1.private_key.len(), X25519_PRIVATE_KEY_SIZE);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice_keypair = X25519KeyPair::generate().unwrap();
        let bob_keypair = X25519KeyPair::generate().unwrap();

        // Perform key exchange from both sides
        let alice_shared = alice_keypair
            .exchange(bob_keypair.public_key_bytes())
            .unwrap();
        let bob_shared = bob_keypair
            .exchange(alice_keypair.public_key_bytes())
            .unwrap();

        // Shared secrets should be identical
        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), X25519_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_keypair_from_private_key() {
        let original_keypair = X25519KeyPair::generate().unwrap();
        let private_key = original_keypair.private_key;

        let reconstructed_keypair = X25519KeyPair::from_private_key(private_key).unwrap();

        // Public keys should match
        assert_eq!(
            original_keypair.public_key,
            reconstructed_keypair.public_key
        );
        assert_eq!(
            original_keypair.private_key,
            reconstructed_keypair.private_key
        );
    }

    #[test]
    fn test_share_envelope_creation_and_decryption() {
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Create envelope
        let envelope = ShareEnvelope::create(
            recipient_keypair.public_key,
            &vault_subkeys,
            crypto_engine.as_ref(),
        )
        .unwrap();

        // Validate envelope
        envelope.validate().unwrap();

        // Decrypt envelope
        let decrypted_subkeys = envelope
            .decrypt(
                recipient_keypair.private_key_bytes(),
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Verify subkeys match
        assert_eq!(
            vault_subkeys.file_encryption_key,
            decrypted_subkeys.file_encryption_key
        );
        assert_eq!(vault_subkeys.filename_key, decrypted_subkeys.filename_key);
        assert_eq!(vault_subkeys.mac_key, decrypted_subkeys.mac_key);
    }

    #[test]
    fn test_share_envelope_wrong_private_key() {
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        let wrong_keypair = X25519KeyPair::generate().unwrap();
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Create envelope for recipient
        let envelope = ShareEnvelope::create(
            recipient_keypair.public_key,
            &vault_subkeys,
            crypto_engine.as_ref(),
        )
        .unwrap();

        // Try to decrypt with wrong private key
        let result = envelope.decrypt(wrong_keypair.private_key_bytes(), crypto_engine.as_ref());

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_share_envelope_cipher_mismatch() {
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        let vault_subkeys = create_test_subkeys();
        let aes_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();
        let xchacha_engine = create_crypto_engine(CipherType::XChaCha20Poly1305).unwrap();

        // Create envelope with AES
        let envelope = ShareEnvelope::create(
            recipient_keypair.public_key,
            &vault_subkeys,
            aes_engine.as_ref(),
        )
        .unwrap();

        // Try to decrypt with XChaCha20
        let result = envelope.decrypt(
            recipient_keypair.private_key_bytes(),
            xchacha_engine.as_ref(),
        );

        // Should fail due to cipher mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_collection_operations() {
        let vault_uuid = uuid::Uuid::new_v4();
        let mut collection = ShareEnvelopeCollection::new(vault_uuid);
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipients
        let alice_keypair = X25519KeyPair::generate().unwrap();
        let bob_keypair = X25519KeyPair::generate().unwrap();

        collection
            .add_recipient(
                alice_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        collection
            .add_recipient(
                bob_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Verify recipients
        assert_eq!(collection.recipient_count(), 2);
        assert!(collection.has_recipient(alice_keypair.public_key_bytes()));
        assert!(collection.has_recipient(bob_keypair.public_key_bytes()));

        // List recipients
        let recipients = collection.list_recipients();
        assert_eq!(recipients.len(), 2);
        assert!(recipients.contains(&alice_keypair.public_key));
        assert!(recipients.contains(&bob_keypair.public_key));

        // Remove recipient
        assert!(collection.remove_recipient(alice_keypair.public_key_bytes()));
        assert_eq!(collection.recipient_count(), 1);
        assert!(!collection.has_recipient(alice_keypair.public_key_bytes()));
        assert!(collection.has_recipient(bob_keypair.public_key_bytes()));

        // Try to remove non-existent recipient
        assert!(!collection.remove_recipient(alice_keypair.public_key_bytes()));
    }

    #[test]
    fn test_envelope_collection_export_import() {
        let vault_uuid = uuid::Uuid::new_v4();
        let mut collection = ShareEnvelopeCollection::new(vault_uuid);
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipient
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        collection
            .add_recipient(
                recipient_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Export to JSON
        let json = collection.export_json().unwrap();
        assert!(!json.is_empty());

        // Import from JSON
        let imported_collection = ShareEnvelopeCollection::import_json(&json).unwrap();

        // Verify imported collection
        assert_eq!(imported_collection.vault_uuid, vault_uuid);
        assert_eq!(imported_collection.recipient_count(), 1);
        assert!(imported_collection.has_recipient(recipient_keypair.public_key_bytes()));

        // Verify envelope can still be decrypted
        let envelope = imported_collection
            .get_envelope(recipient_keypair.public_key_bytes())
            .unwrap();
        let decrypted_subkeys = envelope
            .decrypt(
                recipient_keypair.private_key_bytes(),
                crypto_engine.as_ref(),
            )
            .unwrap();

        assert_eq!(
            vault_subkeys.file_encryption_key,
            decrypted_subkeys.file_encryption_key
        );
    }

    #[test]
    fn test_sharing_manager_operations() {
        let vault_uuid = uuid::Uuid::new_v4();
        let mut manager = SharingManager::new(vault_uuid);
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipients
        let alice_keypair = X25519KeyPair::generate().unwrap();
        let bob_keypair = X25519KeyPair::generate().unwrap();

        manager
            .add_recipient(
                alice_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        manager
            .add_recipient(
                bob_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Verify recipients
        assert_eq!(manager.recipient_count(), 2);
        assert!(manager.has_recipient(alice_keypair.public_key_bytes()));
        assert!(manager.has_recipient(bob_keypair.public_key_bytes()));

        // Decrypt for Alice
        let alice_subkeys = manager
            .decrypt_for_recipient(alice_keypair.private_key_bytes(), crypto_engine.as_ref())
            .unwrap();

        assert_eq!(
            vault_subkeys.file_encryption_key,
            alice_subkeys.file_encryption_key
        );

        // Decrypt for Bob
        let bob_subkeys = manager
            .decrypt_for_recipient(bob_keypair.private_key_bytes(), crypto_engine.as_ref())
            .unwrap();

        assert_eq!(
            vault_subkeys.file_encryption_key,
            bob_subkeys.file_encryption_key
        );

        // Remove Alice
        assert!(manager.remove_recipient(alice_keypair.public_key_bytes()));
        assert_eq!(manager.recipient_count(), 1);

        // Alice should no longer be able to decrypt
        let result = manager
            .decrypt_for_recipient(alice_keypair.private_key_bytes(), crypto_engine.as_ref());
        assert!(result.is_err());

        // Bob should still work
        let bob_subkeys = manager
            .decrypt_for_recipient(bob_keypair.private_key_bytes(), crypto_engine.as_ref())
            .unwrap();
        assert_eq!(
            vault_subkeys.file_encryption_key,
            bob_subkeys.file_encryption_key
        );
    }

    #[test]
    fn test_sharing_manager_export_import() {
        let vault_uuid = uuid::Uuid::new_v4();
        let mut manager = SharingManager::new(vault_uuid);
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipient
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        manager
            .add_recipient(
                recipient_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Export envelopes
        let exported_json = manager.export_envelopes().unwrap();

        // Create new manager and import
        let mut new_manager = SharingManager::new(vault_uuid);
        new_manager.import_envelopes(&exported_json).unwrap();

        // Verify import worked
        assert_eq!(new_manager.recipient_count(), 1);
        assert!(new_manager.has_recipient(recipient_keypair.public_key_bytes()));

        // Verify decryption still works
        let decrypted_subkeys = new_manager
            .decrypt_for_recipient(
                recipient_keypair.private_key_bytes(),
                crypto_engine.as_ref(),
            )
            .unwrap();

        assert_eq!(
            vault_subkeys.file_encryption_key,
            decrypted_subkeys.file_encryption_key
        );
    }

    #[test]
    fn test_sharing_manager_wrong_vault_uuid() {
        let vault_uuid1 = uuid::Uuid::new_v4();
        let vault_uuid2 = uuid::Uuid::new_v4();

        let mut manager1 = SharingManager::new(vault_uuid1);
        let vault_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipient to manager1
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        manager1
            .add_recipient(
                recipient_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        // Export from manager1
        let exported_json = manager1.export_envelopes().unwrap();

        // Try to import into manager2 with different vault UUID
        let mut manager2 = SharingManager::new(vault_uuid2);
        let result = manager2.import_envelopes(&exported_json);

        // Should fail due to UUID mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_update_all() {
        let vault_uuid = uuid::Uuid::new_v4();
        let mut manager = SharingManager::new(vault_uuid);
        let old_subkeys = create_test_subkeys();
        let crypto_engine = create_crypto_engine(CipherType::Aes256Gcm).unwrap();

        // Add recipients with old subkeys
        let alice_keypair = X25519KeyPair::generate().unwrap();
        let bob_keypair = X25519KeyPair::generate().unwrap();

        manager
            .add_recipient(
                alice_keypair.public_key,
                &old_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

        manager
            .add_recipient(bob_keypair.public_key, &old_subkeys, crypto_engine.as_ref())
            .unwrap();

        // Create new subkeys
        let new_master_key = [0x24u8; 32];
        let new_subkeys = derive_all_subkeys(&new_master_key).unwrap();

        // Update all envelopes
        manager
            .update_all_envelopes(&new_subkeys, crypto_engine.as_ref())
            .unwrap();

        // Verify recipients can decrypt new subkeys
        let alice_decrypted = manager
            .decrypt_for_recipient(alice_keypair.private_key_bytes(), crypto_engine.as_ref())
            .unwrap();

        let bob_decrypted = manager
            .decrypt_for_recipient(bob_keypair.private_key_bytes(), crypto_engine.as_ref())
            .unwrap();

        // Should match new subkeys, not old ones
        assert_eq!(
            new_subkeys.file_encryption_key,
            alice_decrypted.file_encryption_key
        );
        assert_eq!(
            new_subkeys.file_encryption_key,
            bob_decrypted.file_encryption_key
        );
        assert_ne!(
            old_subkeys.file_encryption_key,
            alice_decrypted.file_encryption_key
        );
    }

    #[test]
    fn test_cross_cipher_compatibility() {
        let recipient_keypair = X25519KeyPair::generate().unwrap();
        let vault_subkeys = create_test_subkeys();

        // Test with both cipher types
        let ciphers = [CipherType::Aes256Gcm, CipherType::XChaCha20Poly1305];

        for cipher_type in &ciphers {
            let crypto_engine = create_crypto_engine(*cipher_type).unwrap();

            // Create and decrypt envelope
            let envelope = ShareEnvelope::create(
                recipient_keypair.public_key,
                &vault_subkeys,
                crypto_engine.as_ref(),
            )
            .unwrap();

            let decrypted_subkeys = envelope
                .decrypt(
                    recipient_keypair.private_key_bytes(),
                    crypto_engine.as_ref(),
                )
                .unwrap();

            // Verify subkeys match
            assert_eq!(
                vault_subkeys.file_encryption_key,
                decrypted_subkeys.file_encryption_key
            );
            assert_eq!(vault_subkeys.filename_key, decrypted_subkeys.filename_key);
            assert_eq!(vault_subkeys.mac_key, decrypted_subkeys.mac_key);
        }
    }

    #[test]
    fn test_keypair_memory_clearing() {
        let mut keypair = X25519KeyPair::generate().unwrap();

        // Verify key is not zero initially
        assert_ne!(keypair.private_key, [0u8; 32]);

        // Clear the key
        keypair.clear();

        // Verify key is now zero
        assert_eq!(keypair.private_key, [0u8; 32]);
    }

    #[test]
    fn test_subkeys_serialization_deserialization() {
        let subkeys = create_test_subkeys();

        // Serialize
        let serialized = ShareEnvelope::serialize_subkeys(&subkeys).unwrap();
        assert_eq!(serialized.len(), 128);

        // Deserialize
        let deserialized = ShareEnvelope::deserialize_subkeys(&serialized).unwrap();

        // Verify match
        assert_eq!(
            subkeys.file_encryption_key,
            deserialized.file_encryption_key
        );
        assert_eq!(subkeys.filename_key, deserialized.filename_key);
        assert_eq!(subkeys.mac_key, deserialized.mac_key);
    }

    #[test]
    fn test_invalid_subkeys_deserialization() {
        // Test with wrong length
        let wrong_length_data = vec![0u8; 50];
        let result = ShareEnvelope::deserialize_subkeys(&wrong_length_data);
        assert!(result.is_err());

        // Test with empty data
        let empty_data = vec![];
        let result = ShareEnvelope::deserialize_subkeys(&empty_data);
        assert!(result.is_err());
    }
}
