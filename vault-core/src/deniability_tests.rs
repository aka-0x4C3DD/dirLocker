//! Comprehensive tests for plausible deniability features

#[cfg(test)]
mod tests {
    use crate::crypto::CipherType;
    use crate::vault::Vault;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn test_create_vault_with_hidden_table() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add a hidden file table
        let table_id = vault
            .add_hidden_file_table("hidden_password", CipherType::XChaCha20Poly1305, false)
            .unwrap();

        assert!(table_id != Uuid::nil());
        assert_eq!(vault.hidden_file_table_count().unwrap(), 1);
    }

    #[test]
    fn test_multiple_hidden_tables() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add multiple hidden file tables
        let table1 = vault
            .add_hidden_file_table("password1", CipherType::Aes256Gcm, false)
            .unwrap();

        let table2 = vault
            .add_hidden_file_table("password2", CipherType::XChaCha20Poly1305, false)
            .unwrap();

        let table3 = vault
            .add_hidden_file_table(
                "password3",
                CipherType::Aes256Gcm,
                true, // decoy
            )
            .unwrap();

        assert_eq!(vault.hidden_file_table_count().unwrap(), 3);

        // List all table IDs
        let table_ids = vault.list_hidden_file_table_ids().unwrap();
        assert_eq!(table_ids.len(), 3);
        assert!(table_ids.contains(&table1));
        assert!(table_ids.contains(&table2));
        assert!(table_ids.contains(&table3));
    }

    #[test]
    fn test_remove_hidden_table() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add hidden table
        let table_id = vault
            .add_hidden_file_table("hidden_password", CipherType::Aes256Gcm, false)
            .unwrap();

        assert_eq!(vault.hidden_file_table_count().unwrap(), 1);

        // Remove the table
        let removed = vault.remove_hidden_file_table(&table_id).unwrap();
        assert!(removed);
        assert_eq!(vault.hidden_file_table_count().unwrap(), 0);

        // Try to remove again - should return false
        let removed_again = vault.remove_hidden_file_table(&table_id).unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_max_hidden_tables_limit() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add maximum number of hidden tables
        for i in 0..crate::deniability::MAX_FILE_TABLES {
            let result = vault.add_hidden_file_table(
                &format!("password_{}", i),
                CipherType::Aes256Gcm,
                false,
            );
            assert!(result.is_ok(), "Failed to add table {}", i);
        }

        assert_eq!(
            vault.hidden_file_table_count().unwrap(),
            crate::deniability::MAX_FILE_TABLES
        );

        // Try to add one more - should fail
        let result = vault.add_hidden_file_table("extra_password", CipherType::Aes256Gcm, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_active_hidden_table() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add hidden table
        let table_id = vault
            .add_hidden_file_table("hidden_password", CipherType::Aes256Gcm, false)
            .unwrap();

        // Set as active
        vault.set_active_hidden_file_table(table_id).unwrap();

        // Try to set non-existent table as active - should fail
        let fake_id = Uuid::new_v4();
        let result = vault.set_active_hidden_file_table(fake_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_decoy_table() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Create decoy table
        let decoy_id = vault
            .create_decoy_file_table("decoy_password", CipherType::XChaCha20Poly1305)
            .unwrap();

        assert!(decoy_id != Uuid::nil());
        assert_eq!(vault.hidden_file_table_count().unwrap(), 1);

        // Verify it's in the list
        let table_ids = vault.list_hidden_file_table_ids().unwrap();
        assert!(table_ids.contains(&decoy_id));
    }

    #[test]
    fn test_wipe_revealing_metadata() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create main vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add multiple hidden tables
        vault
            .add_hidden_file_table("password1", CipherType::Aes256Gcm, false)
            .unwrap();
        vault
            .add_hidden_file_table("password2", CipherType::XChaCha20Poly1305, false)
            .unwrap();

        // Wipe metadata
        vault.wipe_revealing_metadata().unwrap();

        // Vault should still function normally
        assert_eq!(vault.hidden_file_table_count().unwrap(), 2);
    }

    #[test]
    fn test_open_with_main_password() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault with hidden tables
        {
            let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();
            vault
                .add_hidden_file_table("hidden1", CipherType::Aes256Gcm, false)
                .unwrap();
            vault
                .add_hidden_file_table("hidden2", CipherType::XChaCha20Poly1305, false)
                .unwrap();

            // Verify tables were added
            assert_eq!(vault.hidden_file_table_count().unwrap(), 2);
        }

        // Open with main password - should work
        let vault = Vault::open(&path, "main_password").unwrap();

        // Should be able to access the vault
        assert!(vault.is_open());

        // Note: Hidden tables metadata persistence is not yet fully implemented
        // This is documented in the limitations
    }

    #[test]
    fn test_open_with_wrong_password() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault
        {
            let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();
            vault
                .add_hidden_file_table("hidden_password", CipherType::Aes256Gcm, false)
                .unwrap();
        }

        // Try to open with wrong password - should fail
        let result = Vault::open(&path, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_deniability_limitations_doc() {
        let doc = Vault::get_deniability_limitations();

        // Verify documentation contains key information
        assert!(doc.contains("Block Allocation Patterns"));
        assert!(doc.contains("Timestamp Leakage"));
        assert!(doc.contains("Traffic Analysis"));
        assert!(doc.contains("Cryptographic Considerations"));
        assert!(doc.contains("Best Practices"));
        assert!(doc.contains("Legal Considerations"));
    }

    #[test]
    fn test_hidden_table_independence() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault with multiple hidden tables
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        let table1 = vault
            .add_hidden_file_table("password1", CipherType::Aes256Gcm, false)
            .unwrap();

        let table2 = vault
            .add_hidden_file_table("password2", CipherType::XChaCha20Poly1305, false)
            .unwrap();

        // Verify both tables exist
        assert_eq!(vault.hidden_file_table_count().unwrap(), 2);

        let table_ids = vault.list_hidden_file_table_ids().unwrap();
        assert!(table_ids.contains(&table1));
        assert!(table_ids.contains(&table2));

        // Note: Full persistence across vault close/open is not yet implemented
        // This is documented in the limitations
    }

    #[test]
    fn test_different_ciphers_for_tables() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault with main cipher
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add hidden table with different cipher
        let table_id = vault
            .add_hidden_file_table("hidden_password", CipherType::XChaCha20Poly1305, false)
            .unwrap();

        assert!(table_id != Uuid::nil());

        // Verify table was created
        let table_ids = vault.list_hidden_file_table_ids().unwrap();
        assert!(table_ids.contains(&table_id));
    }

    #[test]
    fn test_decoy_vs_real_tables() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add real hidden table
        let real_table = vault
            .add_hidden_file_table(
                "real_password",
                CipherType::Aes256Gcm,
                false, // not a decoy
            )
            .unwrap();

        // Add decoy table
        let decoy_table = vault
            .create_decoy_file_table("decoy_password", CipherType::XChaCha20Poly1305)
            .unwrap();

        // Both should be in the list
        assert_eq!(vault.hidden_file_table_count().unwrap(), 2);

        let table_ids = vault.list_hidden_file_table_ids().unwrap();
        assert!(table_ids.contains(&real_table));
        assert!(table_ids.contains(&decoy_table));
    }

    #[test]
    fn test_vault_operations_with_active_hidden_table() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("test.vault");

        // Create vault
        let mut vault = Vault::create(&path, "main_password", CipherType::Aes256Gcm).unwrap();

        // Add hidden table
        let table_id = vault
            .add_hidden_file_table("hidden_password", CipherType::Aes256Gcm, false)
            .unwrap();

        // Set as active
        vault.set_active_hidden_file_table(table_id).unwrap();

        // Vault should still be functional
        assert!(vault.is_open());

        // Can still perform basic operations
        let files = vault.list_files().unwrap();
        assert_eq!(files.len(), 0); // Empty vault
    }
}
