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

    #[error("Age encryption error")]
    #[diagnostic(
        code(lilvault::encryption_error),
        help("Check key format and encryption parameters")
    )]
    Encryption(#[from] age::EncryptError),

    #[error("Age decryption error")]
    #[diagnostic(
        code(lilvault::decryption_error),
        help("Verify the correct key is being used and data is not corrupted")
    )]
    Decryption(#[from] age::DecryptError),

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
        help("List available master keys with 'lilvault list-master-keys'")
    )]
    MasterKeyNotFound { name: String },

    #[error("Host key not found: {hostname}")]
    #[diagnostic(
        code(lilvault::host_key_not_found),
        help("Add host key with 'lilvault add-host'")
    )]
    HostKeyNotFound { hostname: String },

    #[error("Secret not found: {name}")]
    #[diagnostic(
        code(lilvault::secret_not_found),
        help("List available secrets with 'lilvault list'")
    )]
    SecretNotFound { name: String },

    #[error("Secret version not found: {name} version {version}")]
    #[diagnostic(
        code(lilvault::secret_version_not_found),
        help("List available versions with 'lilvault versions {name}'")
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
