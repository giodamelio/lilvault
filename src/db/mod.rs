use crate::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;

pub mod models;

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
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_keys")
            .fetch_one(&self.pool)
            .await?;

        Ok(count.0 > 0)
    }

    /// Get database pool for direct access
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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

    // Vault Key Operations

    /// Insert a new vault key
    pub async fn insert_vault_key(&self, vault_key: &VaultKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO vault_keys (fingerprint, name, public_key, encrypted_private_key, created_at) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&vault_key.fingerprint)
        .bind(&vault_key.name)
        .bind(&vault_key.public_key)
        .bind(&vault_key.encrypted_private_key)
        .bind(vault_key.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all vault keys
    pub async fn get_all_vault_keys(&self) -> Result<Vec<VaultKey>> {
        let keys = sqlx::query_as::<_, VaultKey>(
            "SELECT fingerprint, name, public_key, encrypted_private_key, created_at FROM vault_keys ORDER BY created_at"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    /// Get vault key by fingerprint
    pub async fn get_vault_key(&self, fingerprint: &str) -> Result<Option<VaultKey>> {
        let key = sqlx::query_as::<_, VaultKey>(
            "SELECT fingerprint, name, public_key, encrypted_private_key, created_at FROM vault_keys WHERE fingerprint = ?"
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Remove vault key by fingerprint
    pub async fn remove_vault_key(&self, fingerprint: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM vault_keys WHERE fingerprint = ?")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // Host Key Operations

    /// Insert a new host key
    pub async fn insert_host_key(&self, host_key: &HostKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO host_keys (fingerprint, hostname, public_key, added_at) VALUES (?, ?, ?, ?)"
        )
        .bind(&host_key.fingerprint)
        .bind(&host_key.hostname)
        .bind(&host_key.public_key)
        .bind(host_key.added_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all host keys
    pub async fn get_all_host_keys(&self) -> Result<Vec<HostKey>> {
        let keys = sqlx::query_as::<_, HostKey>(
            "SELECT fingerprint, hostname, public_key, added_at FROM host_keys ORDER BY hostname",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    /// Get host key by hostname
    pub async fn get_host_key_by_hostname(&self, hostname: &str) -> Result<Option<HostKey>> {
        let key = sqlx::query_as::<_, HostKey>(
            "SELECT fingerprint, hostname, public_key, added_at FROM host_keys WHERE hostname = ?",
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Get host key by fingerprint
    pub async fn get_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<Option<HostKey>> {
        let key = sqlx::query_as::<_, HostKey>(
            "SELECT fingerprint, hostname, public_key, added_at FROM host_keys WHERE fingerprint = ?"
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Remove host key by hostname
    pub async fn remove_host_key_by_hostname(&self, hostname: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM host_keys WHERE hostname = ?")
            .bind(hostname)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Remove host key by fingerprint
    pub async fn remove_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM host_keys WHERE fingerprint = ?")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // Secret Operations

    /// Insert a new secret metadata
    pub async fn insert_secret(&self, secret: &Secret) -> Result<()> {
        sqlx::query(
            "INSERT INTO secrets (name, description, template, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&secret.name)
        .bind(&secret.description)
        .bind(&secret.template)
        .bind(secret.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get secret metadata by name
    pub async fn get_secret(&self, name: &str) -> Result<Option<Secret>> {
        let secret = sqlx::query_as::<_, Secret>(
            "SELECT name, description, template, created_at FROM secrets WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(secret)
    }

    /// Get all secrets
    pub async fn get_all_secrets(&self) -> Result<Vec<Secret>> {
        let secrets = sqlx::query_as::<_, Secret>(
            "SELECT name, description, template, created_at FROM secrets ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(secrets)
    }

    /// Insert secret storage entry (encrypted data for a specific key)
    pub async fn insert_secret_storage(&self, storage: &SecretStorage) -> Result<()> {
        sqlx::query(
            "INSERT INTO secret_storage (secret_name, version, key_fingerprint, key_type, encrypted_data, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&storage.secret_name)
        .bind(storage.version)
        .bind(&storage.key_fingerprint)
        .bind(&storage.key_type)
        .bind(&storage.encrypted_data)
        .bind(storage.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get next version number for a secret
    pub async fn get_next_secret_version(&self, secret_name: &str) -> Result<i64> {
        let row: (Option<i64>,) =
            sqlx::query_as("SELECT MAX(version) FROM secret_storage WHERE secret_name = ?")
                .bind(secret_name)
                .fetch_one(&self.pool)
                .await?;

        Ok(row.0.unwrap_or(0) + 1)
    }

    /// Get secret storage entries for a specific secret and version
    pub async fn get_secret_storage(
        &self,
        secret_name: &str,
        version: i64,
    ) -> Result<Vec<SecretStorage>> {
        let entries = sqlx::query_as::<_, SecretStorage>(
            "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at FROM secret_storage WHERE secret_name = ? AND version = ? ORDER BY key_type, key_fingerprint"
        )
        .bind(secret_name)
        .bind(version)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Get secret storage entry for a specific secret, version, and key
    pub async fn get_secret_storage_for_key(
        &self,
        secret_name: &str,
        version: i64,
        key_fingerprint: &str,
    ) -> Result<Option<SecretStorage>> {
        let entry = sqlx::query_as::<_, SecretStorage>(
            "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at FROM secret_storage WHERE secret_name = ? AND version = ? AND key_fingerprint = ?"
        )
        .bind(secret_name)
        .bind(version)
        .bind(key_fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(entry)
    }

    /// Get latest version of a secret
    pub async fn get_latest_secret_version(&self, secret_name: &str) -> Result<Option<i64>> {
        let row: (Option<i64>,) =
            sqlx::query_as("SELECT MAX(version) FROM secret_storage WHERE secret_name = ?")
                .bind(secret_name)
                .fetch_one(&self.pool)
                .await?;

        Ok(row.0)
    }

    /// Get all versions of a secret accessible by a specific key
    pub async fn get_secret_versions_for_key(
        &self,
        secret_name: &str,
        key_fingerprint: &str,
    ) -> Result<Vec<i64>> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? AND key_fingerprint = ? ORDER BY version DESC"
        )
        .bind(secret_name)
        .bind(key_fingerprint)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Get all secrets accessible by a specific key
    pub async fn get_secrets_for_key(&self, key_fingerprint: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT secret_name FROM secret_storage WHERE key_fingerprint = ? ORDER BY secret_name"
        )
        .bind(key_fingerprint)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}
