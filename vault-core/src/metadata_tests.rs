//! Tests for metadata sections functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::CipherType;
    use crate::format::MetadataSectionType;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_sections_basic_operations() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_metadata.vault");

        // Create a new vault
        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Test setting metadata section
        let test_data = b"test metadata content".to_vec();
        vault
            .set_metadata_section(MetadataSectionType::UserSettings, test_data.clone())
            .unwrap();

        // Test getting metadata section
        let retrieved_data = vault
            .get_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert_eq!(retrieved_data, Some(test_data.clone()));

        // Test getting non-existent section
        let non_existent = vault
            .get_metadata_section(&MetadataSectionType::AuditLog)
            .unwrap();
        assert_eq!(non_existent, None);

        // Test removing metadata section
        let removed = vault
            .remove_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert!(removed);

        // Verify it's gone
        let after_removal = vault
            .get_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert_eq!(after_removal, None);

        // Test removing non-existent section
        let not_removed = vault
            .remove_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert!(!not_removed);
    }

    #[test]
    fn test_metadata_sections_persistence() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_persistence.vault");

        // Create vault and add metadata
        {
            let mut vault =
                Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

            let user_settings = b"user preferences data".to_vec();
            let audit_log = b"audit log entries".to_vec();

            vault
                .set_metadata_section(MetadataSectionType::UserSettings, user_settings.clone())
                .unwrap();
            vault
                .set_metadata_section(MetadataSectionType::AuditLog, audit_log.clone())
                .unwrap();

            // Verify data is there
            assert_eq!(
                vault
                    .get_metadata_section(&MetadataSectionType::UserSettings)
                    .unwrap(),
                Some(user_settings)
            );
            assert_eq!(
                vault
                    .get_metadata_section(&MetadataSectionType::AuditLog)
                    .unwrap(),
                Some(audit_log)
            );
        }

        // Reopen vault and verify persistence
        {
            let vault = Vault::open(&vault_path, "test_password").unwrap();

            let user_settings = vault
                .get_metadata_section(&MetadataSectionType::UserSettings)
                .unwrap();
            let audit_log = vault
                .get_metadata_section(&MetadataSectionType::AuditLog)
                .unwrap();

            assert_eq!(user_settings, Some(b"user preferences data".to_vec()));
            assert_eq!(audit_log, Some(b"audit log entries".to_vec()));
        }
    }

    #[test]
    fn test_metadata_sections_update_existing() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_update.vault");

        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Set initial data
        let initial_data = b"initial data".to_vec();
        vault
            .set_metadata_section(MetadataSectionType::UserSettings, initial_data)
            .unwrap();

        // Update with new data
        let updated_data = b"updated data".to_vec();
        vault
            .set_metadata_section(MetadataSectionType::UserSettings, updated_data.clone())
            .unwrap();

        // Verify updated data
        let retrieved = vault
            .get_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert_eq!(retrieved, Some(updated_data));
    }

    #[test]
    fn test_metadata_sections_multiple_types() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_multiple.vault");

        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Add different types of metadata
        let user_settings = b"user settings".to_vec();
        let sharing_keys = b"sharing keys data".to_vec();
        let recovery_info = b"recovery information".to_vec();

        vault
            .set_metadata_section(MetadataSectionType::UserSettings, user_settings.clone())
            .unwrap();
        vault
            .set_metadata_section(MetadataSectionType::SharingKeys, sharing_keys.clone())
            .unwrap();
        vault
            .set_metadata_section(MetadataSectionType::RecoveryInfo, recovery_info.clone())
            .unwrap();

        // Verify all are stored correctly
        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::UserSettings)
                .unwrap(),
            Some(user_settings)
        );
        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::SharingKeys)
                .unwrap(),
            Some(sharing_keys)
        );
        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::RecoveryInfo)
                .unwrap(),
            Some(recovery_info)
        );

        // Remove one and verify others remain
        vault
            .remove_metadata_section(&MetadataSectionType::SharingKeys)
            .unwrap();

        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::UserSettings)
                .unwrap(),
            Some(b"user settings".to_vec())
        );
        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::SharingKeys)
                .unwrap(),
            None
        );
        assert_eq!(
            vault
                .get_metadata_section(&MetadataSectionType::RecoveryInfo)
                .unwrap(),
            Some(b"recovery information".to_vec())
        );
    }

    #[test]
    fn test_metadata_sections_migration() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_migration.vault");

        // Create a vault and migrate it to metadata sections format
        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Verify it supports metadata sections
        assert!(vault.supports_metadata_sections());

        // Migration should be a no-op for new vaults
        vault.migrate_to_metadata_sections().unwrap();

        // Should still support metadata sections
        assert!(vault.supports_metadata_sections());

        // Should be able to use metadata sections
        let test_data = b"post-migration data".to_vec();
        vault
            .set_metadata_section(MetadataSectionType::UserSettings, test_data.clone())
            .unwrap();

        let retrieved = vault
            .get_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert_eq!(retrieved, Some(test_data));
    }

    #[test]
    fn test_metadata_sections_empty_data() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_empty.vault");

        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Test setting empty data
        let empty_data = Vec::new();
        vault
            .set_metadata_section(MetadataSectionType::UserSettings, empty_data.clone())
            .unwrap();

        // Verify empty data is stored and retrieved correctly
        let retrieved = vault
            .get_metadata_section(&MetadataSectionType::UserSettings)
            .unwrap();
        assert_eq!(retrieved, Some(empty_data));
    }

    #[test]
    fn test_metadata_sections_large_data() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_large.vault");

        let mut vault = Vault::create(&vault_path, "test_password", CipherType::Aes256Gcm).unwrap();

        // Test with large data (1MB)
        let large_data = vec![0xAB; 1024 * 1024];
        vault
            .set_metadata_section(MetadataSectionType::AuditLog, large_data.clone())
            .unwrap();

        // Verify large data is stored and retrieved correctly
        let retrieved = vault
            .get_metadata_section(&MetadataSectionType::AuditLog)
            .unwrap();
        assert_eq!(retrieved, Some(large_data));
    }
}
