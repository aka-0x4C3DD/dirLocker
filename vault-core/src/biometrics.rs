use crate::error::{VaultError, VaultResult};
use keyring::Entry;

pub fn save_credential(service: &str, user: &str, password: &str) -> VaultResult<()> {
    let entry = Entry::new(service, user).map_err(|e| VaultError::InternalError {
        details: format!("Keyring error: {}", e),
    })?;
    entry
        .set_password(password)
        .map_err(|e| VaultError::InternalError {
            details: format!("Keyring set error: {}", e),
        })?;
    Ok(())
}

pub fn get_credential(service: &str, user: &str) -> VaultResult<String> {
    let entry = Entry::new(service, user).map_err(|e| VaultError::InternalError {
        details: format!("Keyring error: {}", e),
    })?;
    entry.get_password().map_err(|e| {
        // If not found, distinct error? For now InternalError is fine as generic failure
        VaultError::InternalError {
            details: format!("Keyring get error: {}", e),
        }
    })
}

pub fn delete_credential(service: &str, user: &str) -> VaultResult<()> {
    let entry = Entry::new(service, user).map_err(|e| VaultError::InternalError {
        details: format!("Keyring error: {}", e),
    })?;
    entry
        .delete_password()
        .map_err(|e| VaultError::InternalError {
            details: format!("Keyring delete error: {}", e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper to generate a unique user for testing to avoid conflicts
    fn unique_user() -> String {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        format!("test_user_{}", since_the_epoch.as_millis())
    }

    #[test]
    fn test_biometrics_lifecycle() {
        if std::env::var("CI").is_ok() {
            return;
        }
        let service = "test_dirLocker_service";
        let user = unique_user();
        let password = "super_secret_password";

        // 1. Save
        assert!(save_credential(service, &user, password).is_ok());

        // 2. Get
        let retrieved = get_credential(service, &user).expect("Should retrieve password");
        assert_eq!(retrieved, password);

        // 3. Delete
        assert!(delete_credential(service, &user).is_ok());

        // 4. Get again (should fail)
        let result = get_credential(service, &user);
        assert!(result.is_err(), "Should fail to get deleted credential");
    }

    #[test]
    fn test_biometrics_overwrite() {
        if std::env::var("CI").is_ok() {
            return;
        }
        let service = "test_dirLocker_service";
        let user = unique_user();
        let pass1 = "password_v1";
        let pass2 = "password_v2";

        // 1. Save v1
        assert!(save_credential(service, &user, pass1).is_ok());

        // 2. Overwrite with v2
        assert!(save_credential(service, &user, pass2).is_ok());

        // 3. Get -> Should be v2
        let retrieved = get_credential(service, &user).expect("Should retrieve password");
        assert_eq!(retrieved, pass2);

        // Cleanup
        let _ = delete_credential(service, &user);
    }
}
