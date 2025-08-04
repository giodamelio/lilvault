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
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM keys WHERE key_type = 'vault'")
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

    // Key Operations (unified vault and host keys)

    /// Insert a new key (vault or host)
    pub async fn insert_key(&self, key: &Key) -> Result<()> {
        sqlx::query(
            "INSERT INTO keys (fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&key.fingerprint)
        .bind(&key.key_type)
        .bind(&key.name)
        .bind(&key.public_key)
        .bind(&key.encrypted_private_key)
        .bind(key.created_at)
        .bind(key.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all keys of a specific type
    pub async fn get_keys_by_type(&self, key_type: &str) -> Result<Vec<Key>> {
        let keys = sqlx::query_as::<_, Key>(
            "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE key_type = ? ORDER BY name"
        )
        .bind(key_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    /// Get all vault keys
    pub async fn get_all_vault_keys(&self) -> Result<Vec<Key>> {
        self.get_keys_by_type("vault").await
    }

    /// Get all host keys
    pub async fn get_all_host_keys(&self) -> Result<Vec<Key>> {
        self.get_keys_by_type("host").await
    }

    /// Get key by fingerprint
    pub async fn get_key(&self, fingerprint: &str) -> Result<Option<Key>> {
        let key = sqlx::query_as::<_, Key>(
            "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ?"
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Get vault key by fingerprint
    pub async fn get_vault_key(&self, fingerprint: &str) -> Result<Option<Key>> {
        let key = sqlx::query_as::<_, Key>(
            "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ? AND key_type = 'vault'"
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Get host key by hostname
    pub async fn get_host_key_by_hostname(&self, hostname: &str) -> Result<Option<Key>> {
        let key = sqlx::query_as::<_, Key>(
            "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE name = ? AND key_type = 'host'"
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Get host key by fingerprint
    pub async fn get_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Key>> {
        let key = sqlx::query_as::<_, Key>(
            "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ? AND key_type = 'host'"
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    /// Remove key by fingerprint
    pub async fn remove_key(&self, fingerprint: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ?")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Remove vault key by fingerprint
    pub async fn remove_vault_key(&self, fingerprint: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ? AND key_type = 'vault'")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Remove host key by hostname
    pub async fn remove_host_key_by_hostname(&self, hostname: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM keys WHERE name = ? AND key_type = 'host'")
            .bind(hostname)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Remove host key by fingerprint
    pub async fn remove_host_key_by_fingerprint(&self, fingerprint: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ? AND key_type = 'host'")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // Secret Operations

    /// Insert a new secret metadata
    pub async fn insert_secret(&self, secret: &Secret) -> Result<()> {
        sqlx::query(
            "INSERT INTO secrets (name, description, template, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&secret.name)
        .bind(&secret.description)
        .bind(&secret.template)
        .bind(secret.created_at)
        .bind(secret.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get secret metadata by name
    pub async fn get_secret(&self, name: &str) -> Result<Option<Secret>> {
        let secret = sqlx::query_as::<_, Secret>(
            "SELECT name, description, template, created_at, updated_at FROM secrets WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(secret)
    }

    /// Get all secrets
    pub async fn get_all_secrets(&self) -> Result<Vec<Secret>> {
        let secrets = sqlx::query_as::<_, Secret>(
            "SELECT name, description, template, created_at, updated_at FROM secrets ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(secrets)
    }

    /// Insert secret storage entry (encrypted data for a specific key)
    pub async fn insert_secret_storage(&self, storage: &SecretStorage) -> Result<()> {
        sqlx::query(
            "INSERT INTO secret_storage (secret_name, version, key_fingerprint, key_type, encrypted_data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&storage.secret_name)
        .bind(storage.version)
        .bind(&storage.key_fingerprint)
        .bind(&storage.key_type)
        .bind(&storage.encrypted_data)
        .bind(storage.created_at)
        .bind(storage.updated_at)
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
            "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at, updated_at FROM secret_storage WHERE secret_name = ? AND version = ? ORDER BY key_type, key_fingerprint"
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
            "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at, updated_at FROM secret_storage WHERE secret_name = ? AND version = ? AND key_fingerprint = ?"
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

    // Audit Log Operations

    /// Insert a new audit log entry
    pub async fn insert_audit_entry(&self, audit_entry: &AuditLog) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (created_at, operation, resource, details, version, success, error_message, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(audit_entry.created_at)
        .bind(&audit_entry.operation)
        .bind(&audit_entry.resource)
        .bind(&audit_entry.details)
        .bind(audit_entry.version)
        .bind(audit_entry.success)
        .bind(&audit_entry.error_message)
        .bind(audit_entry.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get recent audit log entries with limit
    pub async fn get_audit_entries(&self, limit: i64) -> Result<Vec<AuditLog>> {
        let entries = sqlx::query_as::<_, AuditLog>(
            "SELECT id, created_at, operation, resource, details, version, success, error_message, updated_at FROM audit_log ORDER BY created_at DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Get audit entries for a specific resource and/or operation
    pub async fn get_audit_entries_filtered(
        &self,
        resource: Option<&str>,
        operation: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditLog>> {
        let mut query = "SELECT id, created_at, operation, resource, details, version, success, error_message, updated_at FROM audit_log WHERE 1=1".to_string();
        let mut bind_values = Vec::new();

        if let Some(res) = resource {
            query.push_str(" AND resource = ?");
            bind_values.push(res);
        }

        if let Some(op) = operation {
            query.push_str(" AND operation = ?");
            bind_values.push(op);
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ?");

        let mut sqlx_query = sqlx::query_as::<_, AuditLog>(&query);
        for value in bind_values {
            sqlx_query = sqlx_query.bind(value);
        }
        sqlx_query = sqlx_query.bind(limit);

        let entries = sqlx_query.fetch_all(&self.pool).await?;
        Ok(entries)
    }

    /// Get audit entries since a number of days ago
    pub async fn get_audit_entries_since(&self, days: i64, limit: i64) -> Result<Vec<AuditLog>> {
        let entries = sqlx::query_as::<_, AuditLog>(
            "SELECT id, created_at, operation, resource, details, version, success, error_message, updated_at FROM audit_log WHERE created_at >= datetime('now', '-' || ? || ' days') ORDER BY created_at DESC LIMIT ?"
        )
        .bind(days)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
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
        let now = chrono::Utc::now();
        let audit_entry = AuditLog {
            id: 0, // Will be auto-generated
            created_at: now,
            operation: operation.to_string(),
            resource: resource.to_string(),
            details: details.map(|s| s.to_string()),
            version,
            success,
            error_message: error_message.map(|s| s.to_string()),
            updated_at: now,
        };

        self.insert_audit_entry(&audit_entry).await
    }

    /// Get all secrets that need re-encryption for a new key
    pub async fn get_secrets_for_reencryption(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT name FROM secrets ORDER BY name")
                .fetch_all(&self.pool)
                .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Get all existing encrypted versions of a secret (for re-encryption)
    pub async fn get_all_secret_versions(&self, secret_name: &str) -> Result<Vec<i64>> {
        let rows: Vec<(i64,)> = sqlx::query_as(
            "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? ORDER BY version DESC"
        )
        .bind(secret_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Get an encrypted secret copy that can be decrypted (for re-encryption source)
    pub async fn get_decryptable_secret_copy(
        &self,
        secret_name: &str,
        version: i64,
        available_key_fingerprints: &[String],
    ) -> Result<Option<SecretStorage>> {
        if available_key_fingerprints.is_empty() {
            return Ok(None);
        }

        // Build placeholders for the IN clause
        let placeholders = available_key_fingerprints
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at, updated_at
             FROM secret_storage
             WHERE secret_name = ? AND version = ? AND key_fingerprint IN ({placeholders})
             LIMIT 1"
        );

        let mut query_builder = sqlx::query_as::<_, SecretStorage>(&query)
            .bind(secret_name)
            .bind(version);

        for fingerprint in available_key_fingerprints {
            query_builder = query_builder.bind(fingerprint);
        }

        let result = query_builder.fetch_optional(&self.pool).await?;
        Ok(result)
    }

    /// Check if a secret version is already encrypted for a specific key
    pub async fn is_secret_encrypted_for_key(
        &self,
        secret_name: &str,
        version: i64,
        key_fingerprint: &str,
    ) -> Result<bool> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM secret_storage WHERE secret_name = ? AND version = ? AND key_fingerprint = ?"
        )
        .bind(secret_name)
        .bind(version)
        .bind(key_fingerprint)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// Get comprehensive information about a secret without exposing the data
    pub async fn get_secret_info(&self, secret_name: &str) -> Result<Option<SecretInfo>> {
        // Get secret metadata
        let secret = match self.get_secret(secret_name).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        // Get all versions
        let versions: Vec<(i64,)> = sqlx::query_as(
            "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? ORDER BY version DESC"
        )
        .bind(secret_name)
        .fetch_all(&self.pool)
        .await?;

        let all_versions: Vec<i64> = versions.into_iter().map(|v| v.0).collect();

        // Get keys for each version
        let mut version_info = Vec::new();
        for version in &all_versions {
            let keys_info: Vec<(String, String, Option<String>)> = sqlx::query_as(
                r#"
                SELECT ss.key_fingerprint, ss.key_type,
                       CASE
                           WHEN ss.key_type = 'vault' THEN k.name
                           ELSE k.name
                       END as key_name
                FROM secret_storage ss
                LEFT JOIN keys k ON ss.key_fingerprint = k.fingerprint
                WHERE ss.secret_name = ? AND ss.version = ?
                ORDER BY ss.key_type, k.name
                "#,
            )
            .bind(secret_name)
            .bind(version)
            .fetch_all(&self.pool)
            .await?;

            let keys: Vec<SecretKeyInfo> = keys_info
                .into_iter()
                .map(|(fingerprint, key_type, name)| {
                    let display_name =
                        name.unwrap_or_else(|| format!("Unknown ({})", &fingerprint[..8]));
                    SecretKeyInfo {
                        fingerprint,
                        key_type,
                        name: display_name,
                    }
                })
                .collect();

            version_info.push(SecretVersionInfo {
                version: *version,
                encrypted_for_keys: keys,
            });
        }

        Ok(Some(SecretInfo {
            name: secret.name,
            description: secret.description,
            template: secret.template,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
            total_versions: all_versions.len() as i64,
            latest_version: all_versions.first().copied(),
            versions: version_info,
        }))
    }
}
