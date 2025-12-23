//! Plausible Deniability Implementation
//!
//! This module provides support for multiple independent file tables encrypted
//! under separate passwords, enabling plausible deniability. Different passwords
//! unlock different file tables stored in the same container, making them
//! indistinguishable from each other.
//!
//! # Security Considerations
//!
//! - File tables are stored at different offsets but appear identical in format
//! - Each file table has its own encryption key derived from a separate password
//! - Block allocation patterns may leak information about multiple file tables
//! - Timestamp metadata may reveal file table creation order
//! - Users should understand these limitations before relying on this feature
//!
//! # Current Limitations
//!
//! - Hidden tables metadata is not persisted across vault sessions
//! - This prevents vault corruption but limits functionality
//! - Hidden tables only exist during the current vault session

use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{derive_all_subkeys, derive_key, CipherType};
use crate::error::{VaultError, VaultResult};
use crate::format::{FileTable, VaultHeader};

/// Maximum number of file tables supported in a single vault
pub const MAX_FILE_TABLES: usize = 10;

/// Metadata for a hidden file table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenFileTableMetadata {
    /// Unique identifier for this file table
    pub table_id: Uuid,
    /// Offset in the vault file where this table is stored
    pub offset: u64,
    /// Size of the encrypted file table data
    pub size: u64,
    /// Reserved space for this file table
    pub reserved_size: u64,
    /// Cipher used for this file table
    pub cipher: String,
    /// KDF parameters for deriving the key
    pub kdf_params: crate::format::KdfParams,
    /// Creation timestamp (may leak information)
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether this is a decoy table
    pub is_decoy: bool,
}

/// Manager for multiple file tables with plausible deniability
#[derive(Debug)]
pub struct DeniabilityManager {
    /// Main vault header
    vault_header: VaultHeader,
    /// Metadata for all hidden file tables
    hidden_tables: Vec<HiddenFileTableMetadata>,
    /// Currently active file table (if any)
    active_table_id: Option<Uuid>,
}

impl DeniabilityManager {
    /// Create a new deniability manager for a vault
    pub fn new(vault_header: VaultHeader) -> Self {
        Self {
            vault_header,
            hidden_tables: Vec::new(),
            active_table_id: None,
        }
    }

    /// Load hidden tables metadata from vault file
    ///
    /// NOTE: Currently disabled because hidden tables are not persisted.
    /// This is a known limitation of the current implementation.
    pub fn load_from_vault<P: AsRef<Path>>(
        &mut self,
        _vault_path: P,
        _master_key: &[u8],
    ) -> VaultResult<()> {
        // DISABLED: Hidden tables metadata is not persisted to prevent vault corruption

        if self.vault_header.hidden_tables_offset == 0 {
            // No hidden tables (expected since we don't persist them)
            return Ok(());
        }

        // Even if the header indicates hidden tables exist, we don't load them
        // because the persistence mechanism is disabled to prevent corruption.

        log::warn!(
            "Hidden tables metadata loading is disabled - tables only exist in current session"
        );

        // Clear any existing hidden tables since we can't load persisted ones
        self.hidden_tables.clear();
        self.active_table_id = None;

        Ok(())
    }

    /// Save hidden tables metadata to vault file
    ///
    /// NOTE: Currently disabled to prevent vault corruption.
    /// Hidden tables metadata is not persisted across vault sessions.
    /// This is a known limitation documented in the deniability features.
    pub fn save_to_vault<P: AsRef<Path>>(
        &mut self,
        _vault_path: P,
        _master_key: &[u8],
    ) -> VaultResult<()> {
        // DISABLED: Saving hidden tables metadata causes vault corruption
        // because it requires updating the vault header, which changes the
        // header size and shifts file table offsets.

        // For now, hidden tables only exist in memory during the vault session.
        // This is documented as a limitation of the current implementation.

        if self.hidden_tables.is_empty() {
            return Ok(());
        }

        // TODO: Implement proper persistence without corrupting vault structure
        // Possible solutions:
        // 1. Reserve space in header for hidden tables metadata
        // 2. Store metadata in a separate file
        // 3. Use a different vault format that supports dynamic header sizes

        log::warn!("Hidden tables metadata persistence is disabled to prevent vault corruption");

        Ok(())
    }

    /// Get the vault header (no longer stores hidden tables directly)
    pub fn get_updated_header(&self) -> VaultHeader {
        self.vault_header.clone()
    }

    /// Add a new hidden file table with its own password
    pub fn add_hidden_table(
        &mut self,
        _password: &str,
        cipher_type: CipherType,
        is_decoy: bool,
    ) -> VaultResult<Uuid> {
        if self.hidden_tables.len() >= MAX_FILE_TABLES {
            return Err(VaultError::invalid_argument(format!(
                "Maximum number of file tables ({}) reached",
                MAX_FILE_TABLES
            )));
        }

        // Generate unique KDF parameters for this table
        let mut salt = vec![0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|e| VaultError::crypto_error(format!("Failed to generate salt: {}", e)))?;

        let kdf_params = crate::format::KdfParams {
            salt,
            memory: 65536, // 64MB
            operations: 3,
            parallelism: 1,
        };

        // Calculate offset for this file table
        // Place it after the main file table's reserved space
        let offset = self.calculate_next_table_offset();

        let table_id = Uuid::new_v4();
        let metadata = HiddenFileTableMetadata {
            table_id,
            offset,
            size: 0,                    // Will be updated when table is written
            reserved_size: 1024 * 1024, // 1MB reserved
            cipher: cipher_type.to_string(),
            kdf_params,
            created_at: chrono::Utc::now(),
            is_decoy,
        };

        self.hidden_tables.push(metadata);
        Ok(table_id)
    }

    /// Remove a hidden file table
    pub fn remove_hidden_table(&mut self, table_id: &Uuid) -> VaultResult<bool> {
        if let Some(index) = self
            .hidden_tables
            .iter()
            .position(|t| &t.table_id == table_id)
        {
            self.hidden_tables.remove(index);

            // Clear active table if it was removed
            if self.active_table_id.as_ref() == Some(table_id) {
                self.active_table_id = None;
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get metadata for a specific hidden table
    pub fn get_table_metadata(&self, table_id: &Uuid) -> Option<&HiddenFileTableMetadata> {
        self.hidden_tables.iter().find(|t| &t.table_id == table_id)
    }

    /// List all hidden file table IDs
    pub fn list_table_ids(&self) -> Vec<Uuid> {
        self.hidden_tables.iter().map(|t| t.table_id).collect()
    }

    /// Get the number of hidden file tables
    pub fn table_count(&self) -> usize {
        self.hidden_tables.len()
    }

    /// Set the active file table
    pub fn set_active_table(&mut self, table_id: Uuid) -> VaultResult<()> {
        if self.hidden_tables.iter().any(|t| t.table_id == table_id) {
            self.active_table_id = Some(table_id);
            Ok(())
        } else {
            Err(VaultError::invalid_argument("File table not found"))
        }
    }

    /// Get the active file table ID
    pub fn active_table_id(&self) -> Option<Uuid> {
        self.active_table_id
    }

    /// Calculate the next available offset for a file table
    fn calculate_next_table_offset(&self) -> u64 {
        if self.hidden_tables.is_empty() {
            // First hidden table goes after main table's reserved space
            self.vault_header.chunk_data_start_offset
        } else {
            // Find the highest offset + reserved size
            self.hidden_tables
                .iter()
                .map(|t| t.offset + t.reserved_size)
                .max()
                .unwrap_or(self.vault_header.chunk_data_start_offset)
        }
    }

    /// Write a hidden file table to the vault
    pub fn write_hidden_table<P: AsRef<Path>>(
        &mut self,
        vault_path: P,
        table_id: &Uuid,
        file_table: &FileTable,
        password: &str,
    ) -> VaultResult<()> {
        let metadata = self
            .get_table_metadata(table_id)
            .ok_or_else(|| VaultError::invalid_argument("File table not found"))?
            .clone();

        // Derive key from password
        let master_key = derive_key(
            password,
            &metadata.kdf_params.salt,
            metadata.kdf_params.memory,
            metadata.kdf_params.operations,
            metadata.kdf_params.parallelism,
        )?;

        let subkeys = derive_all_subkeys(&master_key)?;

        // Create crypto engine
        let cipher_type: CipherType = metadata.cipher.parse()?;
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

        // Serialize file table
        let file_table_json = serde_json::to_vec(file_table)?;

        // Generate nonce
        let nonce = crate::crypto::generate_nonce(crypto.nonce_size())?;

        // Encrypt file table with header as AAD
        let header_json = serde_json::to_string(&self.vault_header)?;
        let encrypted_table = crypto.encrypt(
            &subkeys.file_encryption_key,
            &nonce,
            &file_table_json,
            header_json.as_bytes(),
        )?;

        // Write to vault file at the specified offset
        let mut file = std::fs::OpenOptions::new().write(true).open(vault_path)?;

        use std::io::{Seek, Write};
        file.seek(std::io::SeekFrom::Start(metadata.offset))?;

        // Write nonce
        file.write_all(&nonce)?;

        // Write encrypted data
        file.write_all(&encrypted_table)?;

        // Update metadata with actual size
        if let Some(table_meta) = self
            .hidden_tables
            .iter_mut()
            .find(|t| &t.table_id == table_id)
        {
            table_meta.size = (nonce.len() + encrypted_table.len()) as u64;
        }

        Ok(())
    }

    /// Read a hidden file table from the vault
    pub fn read_hidden_table<P: AsRef<Path>>(
        &self,
        vault_path: P,
        table_id: &Uuid,
        password: &str,
    ) -> VaultResult<FileTable> {
        let metadata = self
            .get_table_metadata(table_id)
            .ok_or_else(|| VaultError::invalid_argument("File table not found"))?;

        // Derive key from password
        let master_key = derive_key(
            password,
            &metadata.kdf_params.salt,
            metadata.kdf_params.memory,
            metadata.kdf_params.operations,
            metadata.kdf_params.parallelism,
        )?;

        let subkeys = derive_all_subkeys(&master_key)?;

        // Create crypto engine
        let cipher_type: CipherType = metadata.cipher.parse()?;
        let crypto = crate::crypto::create_crypto_engine(cipher_type)?;

        // Read encrypted data from vault
        let mut file = std::fs::File::open(vault_path)?;

        use std::io::{Read, Seek};
        file.seek(std::io::SeekFrom::Start(metadata.offset))?;

        // Read nonce
        let mut nonce = vec![0u8; crypto.nonce_size()];
        file.read_exact(&mut nonce)?;

        // Read encrypted data
        if metadata.size == 0 {
            // Hidden table hasn't been written yet
            return Err(VaultError::invalid_argument("Hidden table not initialized"));
        }

        let nonce_size = crypto.nonce_size() as u64;
        if metadata.size < nonce_size {
            return Err(VaultError::corrupted_vault("Invalid hidden table size"));
        }

        let encrypted_size = metadata.size - nonce_size;
        let mut encrypted_data = vec![0u8; encrypted_size as usize];
        file.read_exact(&mut encrypted_data)?;

        // Decrypt with header as AAD
        let header_json = serde_json::to_string(&self.vault_header)?;
        let decrypted_data = crypto.decrypt(
            &subkeys.file_encryption_key,
            &nonce,
            &encrypted_data,
            header_json.as_bytes(),
        )?;

        // Deserialize file table
        let file_table: FileTable = serde_json::from_slice(&decrypted_data)?;

        Ok(file_table)
    }

    /// Try to open a hidden file table with a password
    /// Returns the table ID if successful
    pub fn try_unlock_table<P: AsRef<Path>>(
        &self,
        vault_path: P,
        password: &str,
    ) -> VaultResult<Option<Uuid>> {
        // Try each hidden table
        for metadata in &self.hidden_tables {
            match self.read_hidden_table(vault_path.as_ref(), &metadata.table_id, password) {
                Ok(_) => return Ok(Some(metadata.table_id)),
                Err(VaultError::CryptoError { .. }) => continue, // Wrong password, try next
                Err(e) => return Err(e),                         // Other error
            }
        }

        Ok(None)
    }

    /// Create a decoy file table with random data
    pub fn create_decoy_table(
        &mut self,
        _password: &str,
        cipher_type: CipherType,
    ) -> VaultResult<Uuid> {
        let table_id = self.add_hidden_table(_password, cipher_type, true)?;

        // Create a file table with some decoy files
        let _decoy_table = FileTable::new();

        // Add some fake file entries
        let _decoy_files = vec![
            ("documents/report.pdf", 1024 * 512, false),
            ("photos/vacation.jpg", 1024 * 1024 * 2, false),
            ("notes.txt", 1024 * 10, false),
        ];

        // Note: We would need to create actual encrypted file entries here
        // For now, just return the table ID

        Ok(table_id)
    }

    /// Wipe metadata that could reveal the existence of hidden tables
    pub fn wipe_revealing_metadata(&mut self) {
        // Remove timestamps that could reveal creation order
        for table in &mut self.hidden_tables {
            // Set all timestamps to the same value as the vault creation
            table.created_at = self.vault_header.created_at;
        }

        // Shuffle the order of hidden tables to prevent inference
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.hidden_tables.shuffle(&mut rng);
    }

    /// Get documentation about deniability limitations
    pub fn get_limitations_doc() -> &'static str {
        r#"
Plausible Deniability Limitations:

1. CURRENT IMPLEMENTATION LIMITATION:
   - Hidden tables metadata is NOT persisted across vault sessions
   - Hidden tables only exist during the current vault session
   - This prevents vault corruption but limits functionality
   - Persistence is disabled until a safe implementation is developed

2. Block Allocation Patterns:
   - The vault file size may reveal the total amount of data stored
   - Chunk allocation patterns could be analyzed to infer multiple file tables
   - Fragmentation patterns may differ between file tables

3. Timestamp Leakage:
   - File system timestamps on the vault file itself
   - Creation timestamps in file table metadata (can be wiped)
   - Access patterns may reveal usage of different passwords

4. Traffic Analysis:
   - Frequency of vault access may reveal multiple users
   - Different access patterns for different file tables

5. Cryptographic Considerations:
   - Each file table uses independent encryption keys
   - KDF parameters are stored separately for each table
   - Nonce reuse is prevented across all tables

6. Best Practices:
   - Use similar file sizes across all file tables
   - Access all file tables regularly to mask usage patterns
   - Consider using decoy file tables with realistic content
   - Wipe metadata regularly using the provided function
   - Understand that true deniability is difficult to achieve

7. Legal Considerations:
   - Plausible deniability may not be legally recognized in all jurisdictions
   - Coercion or legal compulsion may override technical protections
   - Users should understand local laws before relying on this feature

8. Technical Roadmap:
   - Future versions may implement safe persistence mechanisms
   - Possible solutions include reserved header space or separate metadata files
   - Current implementation prioritizes vault integrity over persistence
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deniability_manager_creation() {
        let header = create_test_header();
        let manager = DeniabilityManager::new(header);

        assert_eq!(manager.table_count(), 0);
        assert!(manager.active_table_id().is_none());
    }

    #[test]
    fn test_add_hidden_table() {
        let header = create_test_header();
        let mut manager = DeniabilityManager::new(header);

        let table_id = manager
            .add_hidden_table("hidden_password", CipherType::Aes256Gcm, false)
            .unwrap();

        assert_eq!(manager.table_count(), 1);
        assert!(manager.get_table_metadata(&table_id).is_some());
    }

    #[test]
    fn test_max_file_tables_limit() {
        let header = create_test_header();
        let mut manager = DeniabilityManager::new(header);

        // Add maximum number of tables
        for i in 0..MAX_FILE_TABLES {
            let result =
                manager.add_hidden_table(&format!("password_{}", i), CipherType::Aes256Gcm, false);
            assert!(result.is_ok());
        }

        // Try to add one more - should fail
        let result = manager.add_hidden_table("extra_password", CipherType::Aes256Gcm, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_hidden_table() {
        let header = create_test_header();
        let mut manager = DeniabilityManager::new(header);

        let table_id = manager
            .add_hidden_table("password", CipherType::Aes256Gcm, false)
            .unwrap();

        assert_eq!(manager.table_count(), 1);

        let removed = manager.remove_hidden_table(&table_id).unwrap();
        assert!(removed);
        assert_eq!(manager.table_count(), 0);
    }

    #[test]
    fn test_set_active_table() {
        let header = create_test_header();
        let mut manager = DeniabilityManager::new(header);

        let table_id = manager
            .add_hidden_table("password", CipherType::Aes256Gcm, false)
            .unwrap();

        manager.set_active_table(table_id).unwrap();
        assert_eq!(manager.active_table_id(), Some(table_id));
    }

    fn create_test_header() -> VaultHeader {
        VaultHeader {
            cipher: "aes-256-gcm".to_string(),
            kdf: "argon2id".to_string(),
            kdf_params: crate::format::KdfParams {
                salt: vec![0u8; 32],
                memory: 65536,
                operations: 3,
                parallelism: 1,
            },
            vault_uuid: Uuid::new_v4(),
            file_table_offset: 1000,
            file_table_size: 0,
            file_table_reserved_size: 1024 * 1024,
            chunk_data_start_offset: 1000 + 1024 * 1024,
            chunk_size: 4 * 1024 * 1024,
            flags: vec![],
            created_at: chrono::Utc::now(),
            platform_hint: "test".to_string(),
            file_table_version: 1,
            metadata_sections_offset: 0,
            metadata_sections_size: 0,
            hidden_tables_offset: 0,
            hidden_tables_size: 0,
        }
    }
}
