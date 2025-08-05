use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Diagnostic, Debug)]
pub enum LilVaultError {
    #[error("Database error")]
    #[diagnostic(
        code(lilvault::db_error),
        help("Check database file permissions and path")
    )]
    Database(#[from] sqlx::Error),

    #[error("Migration error")]
    #[diagnostic(
        code(lilvault::migration_error),
        help("Try resetting the database or check migration files")
    )]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Encryption error: {message}")]
    #[diagnostic(
        code(lilvault::encryption_error),
        help("Check key format and encryption parameters")
    )]
    Encryption { message: String },

    #[error("Decryption error: {message}")]
    #[diagnostic(
        code(lilvault::decryption_error),
        help("Verify the correct key is being used and data is not corrupted")
    )]
    Decryption { message: String },

    #[error("SSH key parsing error: {message}")]
    #[diagnostic(
        code(lilvault::ssh_key_error),
        help("Ensure SSH key is in valid OpenSSH format")
    )]
    SshKey { message: String },

    #[error("IO error: {0}")]
    #[diagnostic(code(lilvault::io_error))]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error")]
    #[diagnostic(code(lilvault::json_error), help("Check data format and encoding"))]
    Json(#[from] serde_json::Error),

    #[error("Master key not found: {name}")]
    #[diagnostic(
        code(lilvault::master_key_not_found),
        help("List available master keys with 'lilvault key list --key-type vault'")
    )]
    MasterKeyNotFound { name: String },

    #[error("Host key not found: {hostname}")]
    #[diagnostic(
        code(lilvault::host_key_not_found),
        help("Add host key with 'lilvault key add-host'")
    )]
    HostKeyNotFound { hostname: String },

    #[error("Secret not found: {name}")]
    #[diagnostic(
        code(lilvault::secret_not_found),
        help("List available secrets with 'lilvault secret list'")
    )]
    SecretNotFound { name: String },

    #[error("Secret version not found: {name} version {version}")]
    #[diagnostic(
        code(lilvault::secret_version_not_found),
        help("Show secret information with 'lilvault secret info {name}'")
    )]
    SecretVersionNotFound { name: String, version: i64 },

    #[error("Invalid key fingerprint: {fingerprint}")]
    #[diagnostic(code(lilvault::invalid_fingerprint))]
    InvalidFingerprint { fingerprint: String },

    #[error("Vault not initialized")]
    #[diagnostic(
        code(lilvault::vault_not_initialized),
        help("Initialize vault with 'lilvault init'")
    )]
    VaultNotInitialized,

    #[error("Vault already initialized")]
    #[diagnostic(
        code(lilvault::vault_already_initialized),
        help("Use existing vault or delete it to reinitialize")
    )]
    VaultAlreadyInitialized,

    #[error("Password required")]
    #[diagnostic(
        code(lilvault::password_required),
        help("Provide password when prompted")
    )]
    PasswordRequired,

    #[error("Invalid password")]
    #[diagnostic(code(lilvault::invalid_password), help("Check password and try again"))]
    InvalidPassword,

    #[error("No access to secret: {secret_name}")]
    #[diagnostic(
        code(lilvault::no_access),
        help("This key cannot decrypt the specified secret")
    )]
    NoAccess { secret_name: String },

    #[error("Internal error: {message}")]
    #[diagnostic(code(lilvault::internal_error))]
    Internal { message: String },
}

pub type Result<T> = std::result::Result<T, LilVaultError>;

impl From<anyhow::Error> for LilVaultError {
    fn from(err: anyhow::Error) -> Self {
        LilVaultError::Internal {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = LilVaultError::SecretNotFound {
            name: "test-secret".to_string(),
        };
        assert_eq!(error.to_string(), "Secret not found: test-secret");
    }

    #[test]
    fn test_internal_error() {
        let error = LilVaultError::Internal {
            message: "Something went wrong".to_string(),
        };
        assert_eq!(error.to_string(), "Internal error: Something went wrong");
    }

    #[test]
    fn test_ssh_key_error() {
        let error = LilVaultError::SshKey {
            message: "Invalid SSH key format".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "SSH key parsing error: Invalid SSH key format"
        );
    }

    #[test]
    fn test_vault_not_initialized() {
        let error = LilVaultError::VaultNotInitialized;
        assert_eq!(error.to_string(), "Vault not initialized");
    }

    #[test]
    fn test_vault_already_initialized() {
        let error = LilVaultError::VaultAlreadyInitialized;
        assert_eq!(error.to_string(), "Vault already initialized");
    }

    #[test]
    fn test_password_required() {
        let error = LilVaultError::PasswordRequired;
        assert_eq!(error.to_string(), "Password required");
    }

    #[test]
    fn test_invalid_password() {
        let error = LilVaultError::InvalidPassword;
        assert_eq!(error.to_string(), "Invalid password");
    }

    #[test]
    fn test_no_access_error() {
        let error = LilVaultError::NoAccess {
            secret_name: "private-secret".to_string(),
        };
        assert_eq!(error.to_string(), "No access to secret: private-secret");
    }

    #[test]
    fn test_secret_version_not_found() {
        let error = LilVaultError::SecretVersionNotFound {
            name: "my-secret".to_string(),
            version: 42,
        };
        assert_eq!(
            error.to_string(),
            "Secret version not found: my-secret version 42"
        );
    }

    #[test]
    fn test_invalid_fingerprint() {
        let error = LilVaultError::InvalidFingerprint {
            fingerprint: "invalid-fp".to_string(),
        };
        assert_eq!(error.to_string(), "Invalid key fingerprint: invalid-fp");
    }

    #[test]
    fn test_host_key_not_found() {
        let error = LilVaultError::HostKeyNotFound {
            hostname: "server1".to_string(),
        };
        assert_eq!(error.to_string(), "Host key not found: server1");
    }

    #[test]
    fn test_master_key_not_found() {
        let error = LilVaultError::MasterKeyNotFound {
            name: "backup-key".to_string(),
        };
        assert_eq!(error.to_string(), "Master key not found: backup-key");
    }

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_error = anyhow::anyhow!("Test anyhow error");
        let lilvault_error: LilVaultError = anyhow_error.into();

        match lilvault_error {
            LilVaultError::Internal { message } => {
                assert_eq!(message, "Test anyhow error");
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_result_type_alias() {
        fn test_function() -> Result<String> {
            Ok("success".to_string())
        }

        let result = test_function();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[test]
    fn test_result_with_error() {
        fn test_function() -> Result<String> {
            Err(LilVaultError::PasswordRequired)
        }

        let result = test_function();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Password required");
    }
}
