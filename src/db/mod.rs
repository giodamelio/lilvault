use crate::Result;
use sqlx::{Sqlite, SqlitePool, Transaction, sqlite::SqlitePoolOptions};
use std::path::Path;

pub mod audit_log;
pub mod keys;
pub mod models;
pub mod secret_host_access;
pub mod secret_storage;
pub mod secrets;
pub mod secrets_keys;

use models::*;

/// Database manager for LilVault operations
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection and run migrations
    pub async fn new(database_path: &Path) -> Result<Self> {
        // Ensure database file and parent directories exist
        Self::ensure_database_file(database_path).await?;

        // Create connection URL
        let database_url = format!("sqlite:{}", database_path.display());

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    /// Check if the vault is initialized (has at least one vault key)
    pub async fn is_initialized(&self) -> Result<bool> {
        keys::is_initialized(&self.pool).await
    }

    /// Get database pool for direct access
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Begin a new database transaction
    pub async fn begin_transaction(&self) -> Result<Transaction<'_, Sqlite>> {
        Ok(self.pool.begin().await?)
    }

    /// Execute a function within a database transaction
    /// If the function returns an error, the transaction is automatically rolled back
    pub async fn transaction<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: FnOnce(Transaction<'_, Sqlite>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let tx = self.begin_transaction().await?;
        let result = f(tx).await;
        match result {
            Ok(value) => Ok(value),
            Err(e) => {
                // Transaction is automatically rolled back when dropped
                Err(e)
            }
        }
    }

    /// Create database file and parent directories if they don't exist
    async fn ensure_database_file(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create empty file if it doesn't exist
        if !path.exists() {
            std::fs::File::create(path)?;
        }

        Ok(())
    }

    /// Close the database connection
    pub async fn close(self) {
        self.pool.close().await;
    }

    // Key Operations (unified vault and host keys)

    /// Insert a new key (vault or host)
    pub async fn insert_key(&self, key: &Key) -> Result<()> {
        keys::insert_key(&self.pool, key).await
    }

    /// Get all keys of a specific type
    pub async fn get_keys_by_type(&self, key_type: &str) -> Result<Vec<Key>> {
        keys::get_keys_by_type(&self.pool, key_type).await
    }

    /// Get all vault keys
    pub async fn get_all_vault_keys(&self) -> Result<Vec<Key>> {
        keys::get_all_vault_keys(&self.pool).await
    }

    /// Get all host keys
    pub async fn get_all_host_keys(&self) -> Result<Vec<Key>> {
        keys::get_all_host_keys(&self.pool).await
    }

    /// Get key by fingerprint
    pub async fn get_key(&self, fingerprint: &str) -> Result<Option<Key>> {
        keys::get_key(&self.pool, fingerprint).await
    }

    /// Get vault key by fingerprint
    pub async fn get_vault_key(&self, fingerprint: &str) -> Result<Option<Key>> {
        keys::get_vault_key(&self.pool, fingerprint).await
    }

    /// Get vault key by name
    pub async fn get_vault_key_by_name(&self, name: &str) -> Result<Option<Key>> {
        keys::get_vault_key_by_name(&self.pool, name).await
    }

    /// Get host key by hostname
    pub async fn get_host_key_by_hostname(&self, hostname: &str) -> Result<Option<Key>> {
        keys::get_host_key_by_hostname(&self.pool, hostname).await
    }

    /// Get host key by fingerprint
    pub async fn get_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Key>> {
        keys::get_host_key_by_fingerprint(&self.pool, fingerprint).await
    }

    /// Remove key by fingerprint
    pub async fn remove_key(&self, fingerprint: &str) -> Result<bool> {
        keys::remove_key(&self.pool, fingerprint).await
    }

    /// Remove vault key by fingerprint
    pub async fn remove_vault_key(&self, fingerprint: &str) -> Result<bool> {
        keys::remove_vault_key(&self.pool, fingerprint).await
    }

    /// Remove host key by hostname
    pub async fn remove_host_key_by_hostname(&self, hostname: &str) -> Result<bool> {
        keys::remove_host_key_by_hostname(&self.pool, hostname).await
    }

    /// Remove host key by fingerprint
    pub async fn remove_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<bool> {
        keys::remove_host_key_by_fingerprint(&self.pool, fingerprint).await
    }

    /// Rename a key
    pub async fn rename_key(&self, fingerprint: &str, new_name: &str) -> Result<bool> {
        keys::rename_key(&self.pool, fingerprint, new_name).await
    }

    // Secret Operations

    /// Insert a new secret metadata
    pub async fn insert_secret(&self, secret: &Secret) -> Result<()> {
        secrets::insert_secret(&self.pool, secret).await
    }

    /// Get secret metadata by name
    pub async fn get_secret(&self, name: &str) -> Result<Option<Secret>> {
        secrets::get_secret(&self.pool, name).await
    }

    /// Get all secrets
    pub async fn get_all_secrets(&self) -> Result<Vec<Secret>> {
        secrets::get_all_secrets(&self.pool).await
    }

    /// Insert secret storage entry (encrypted data for a specific key)
    pub async fn insert_secret_storage(&self, storage: &SecretStorage) -> Result<()> {
        secret_storage::insert_secret_storage(&self.pool, storage).await
    }

    /// Get next version number for a secret
    pub async fn get_next_secret_version(&self, secret_name: &str) -> Result<i64> {
        secret_storage::get_next_secret_version(&self.pool, secret_name).await
    }

    /// Get secret storage entries for a specific secret and version
    pub async fn get_secret_storage(
        &self,
        secret_name: &str,
        version: i64,
    ) -> Result<Vec<SecretStorage>> {
        secret_storage::get_secret_storage(&self.pool, secret_name, version).await
    }

    /// Get secret storage entry for a specific secret, version, and key
    pub async fn get_secret_storage_for_key(
        &self,
        secret_name: &str,
        version: i64,
        key_fingerprint: &str,
    ) -> Result<Option<SecretStorage>> {
        secret_storage::get_secret_storage_for_key(
            &self.pool,
            secret_name,
            version,
            key_fingerprint,
        )
        .await
    }

    /// Get latest version of a secret
    pub async fn get_latest_secret_version(&self, secret_name: &str) -> Result<Option<i64>> {
        secret_storage::get_latest_secret_version(&self.pool, secret_name).await
    }

    /// Get all versions of a secret accessible by a specific key
    pub async fn get_secret_versions_for_key(
        &self,
        secret_name: &str,
        key_fingerprint: &str,
    ) -> Result<Vec<i64>> {
        secret_storage::get_secret_versions_for_key(&self.pool, secret_name, key_fingerprint).await
    }

    /// Get all secrets accessible by a specific key
    pub async fn get_secrets_for_key(&self, key_fingerprint: &str) -> Result<Vec<String>> {
        secret_storage::get_secrets_for_key(&self.pool, key_fingerprint).await
    }

    // Audit Log Operations

    /// Insert a new audit log entry
    pub async fn insert_audit_entry(&self, audit_entry: &AuditLog) -> Result<()> {
        audit_log::insert_audit_entry(&self.pool, audit_entry).await
    }

    /// Get recent audit log entries with limit
    pub async fn get_audit_entries(&self, limit: i64) -> Result<Vec<AuditLog>> {
        audit_log::get_audit_entries(&self.pool, limit).await
    }

    /// Get audit entries for a specific resource and/or operation
    pub async fn get_audit_entries_filtered(
        &self,
        resource: Option<&str>,
        operation: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditLog>> {
        audit_log::get_audit_entries_filtered(&self.pool, resource, operation, limit).await
    }

    /// Get audit entries since a number of days ago
    pub async fn get_audit_entries_since(&self, days: i64, limit: i64) -> Result<Vec<AuditLog>> {
        audit_log::get_audit_entries_since(&self.pool, days, limit).await
    }

    /// Log an audit entry with current timestamp
    pub async fn log_audit(
        &self,
        operation: &str,
        resource: &str,
        details: Option<&str>,
        version: Option<i64>,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        audit_log::log_audit(
            &self.pool,
            operation,
            resource,
            details,
            version,
            success,
            error_message,
        )
        .await
    }

    /// Get all secrets that need re-encryption for a new key
    pub async fn get_secrets_for_reencryption(&self) -> Result<Vec<String>> {
        secrets::get_secrets_for_reencryption(&self.pool).await
    }

    /// Get all existing encrypted versions of a secret (for re-encryption)
    pub async fn get_all_secret_versions(&self, secret_name: &str) -> Result<Vec<i64>> {
        secret_storage::get_all_secret_versions(&self.pool, secret_name).await
    }

    /// Get an encrypted secret copy that can be decrypted (for re-encryption source)
    pub async fn get_decryptable_secret_copy(
        &self,
        secret_name: &str,
        version: i64,
        available_key_fingerprints: &[String],
    ) -> Result<Option<SecretStorage>> {
        secret_storage::get_decryptable_secret_copy(
            &self.pool,
            secret_name,
            version,
            available_key_fingerprints,
        )
        .await
    }

    /// Check if a secret version is already encrypted for a specific key
    pub async fn is_secret_encrypted_for_key(
        &self,
        secret_name: &str,
        version: i64,
        key_fingerprint: &str,
    ) -> Result<bool> {
        secret_storage::is_secret_encrypted_for_key(
            &self.pool,
            secret_name,
            version,
            key_fingerprint,
        )
        .await
    }

    /// Insert secret host access entry
    pub async fn insert_secret_host_access(&self, access: &SecretHostAccess) -> Result<()> {
        secret_host_access::insert_secret_host_access(&self.pool, access).await
    }

    /// Get all host keys that can access a secret
    pub async fn get_secret_host_access(&self, secret_name: &str) -> Result<Vec<String>> {
        secret_host_access::get_secret_host_access(&self.pool, secret_name).await
    }

    /// Get all keys that a secret is encrypted for (from secrets_keys table)
    pub async fn get_secret_keys(&self, secret_name: &str) -> Result<Vec<SecretKeyInfo>> {
        secrets_keys::get_secret_keys(&self.pool, secret_name).await
    }

    /// Insert a secret-key relationship (secret is encrypted for this key)
    pub async fn insert_secret_key(&self, secret_key: &SecretKey) -> Result<()> {
        secrets_keys::insert_secret_key(&self.pool, secret_key).await
    }

    /// Remove all key relationships for a secret
    pub async fn remove_all_secret_keys(&self, secret_name: &str) -> Result<()> {
        secrets_keys::remove_all_secret_keys(&self.pool, secret_name).await
    }

    /// Remove a specific key relationship for a secret
    pub async fn remove_secret_key(
        &self,
        secret_name: &str,
        key_fingerprint: &str,
    ) -> Result<bool> {
        secrets_keys::remove_secret_key(&self.pool, secret_name, key_fingerprint).await
    }

    /// Check if a secret is encrypted for a specific key
    pub async fn is_secret_encrypted_for_key_new(
        &self,
        secret_name: &str,
        key_fingerprint: &str,
    ) -> Result<bool> {
        secrets_keys::is_secret_encrypted_for_key_new(&self.pool, secret_name, key_fingerprint)
            .await
    }

    /// Remove all host access entries for a secret
    pub async fn remove_secret_host_access(&self, secret_name: &str) -> Result<()> {
        secret_host_access::remove_secret_host_access(&self.pool, secret_name).await
    }

    /// Check if a host key can access a secret
    pub async fn can_host_access_secret(
        &self,
        secret_name: &str,
        host_key_fingerprint: &str,
    ) -> Result<bool> {
        secret_host_access::can_host_access_secret(&self.pool, secret_name, host_key_fingerprint)
            .await
    }

    /// Get comprehensive information about a secret without exposing the data
    pub async fn get_secret_info(&self, secret_name: &str) -> Result<Option<SecretInfo>> {
        secrets::get_secret_info(&self.pool, secret_name).await
    }
}
