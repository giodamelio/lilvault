use crate::Result;
use crate::db::models::SecretStorage;
use sqlx::SqlitePool;

pub async fn insert_secret_storage(pool: &SqlitePool, storage: &SecretStorage) -> Result<()> {
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
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_next_secret_version(pool: &SqlitePool, secret_name: &str) -> Result<i64> {
    let row: (Option<i64>,) =
        sqlx::query_as("SELECT MAX(version) FROM secret_storage WHERE secret_name = ?")
            .bind(secret_name)
            .fetch_one(pool)
            .await?;

    Ok(row.0.unwrap_or(0) + 1)
}

pub async fn get_secret_storage(
    pool: &SqlitePool,
    secret_name: &str,
    version: i64,
) -> Result<Vec<SecretStorage>> {
    let entries = sqlx::query_as::<_, SecretStorage>(
        "SELECT id, secret_name, version, key_fingerprint, key_type, encrypted_data, created_at, updated_at FROM secret_storage WHERE secret_name = ? AND version = ? ORDER BY key_type, key_fingerprint"
    )
    .bind(secret_name)
    .bind(version)
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn get_secret_storage_for_key(
    pool: &SqlitePool,
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
    .fetch_optional(pool)
    .await?;

    Ok(entry)
}

pub async fn get_latest_secret_version(
    pool: &SqlitePool,
    secret_name: &str,
) -> Result<Option<i64>> {
    let row: (Option<i64>,) =
        sqlx::query_as("SELECT MAX(version) FROM secret_storage WHERE secret_name = ?")
            .bind(secret_name)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

pub async fn get_secret_versions_for_key(
    pool: &SqlitePool,
    secret_name: &str,
    key_fingerprint: &str,
) -> Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? AND key_fingerprint = ? ORDER BY version DESC"
    )
    .bind(secret_name)
    .bind(key_fingerprint)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_secrets_for_key(pool: &SqlitePool, key_fingerprint: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT secret_name FROM secret_storage WHERE key_fingerprint = ? ORDER BY secret_name"
    )
    .bind(key_fingerprint)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_all_secret_versions(pool: &SqlitePool, secret_name: &str) -> Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? ORDER BY version DESC",
    )
    .bind(secret_name)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_decryptable_secret_copy(
    pool: &SqlitePool,
    secret_name: &str,
    version: i64,
    available_key_fingerprints: &[String],
) -> Result<Option<SecretStorage>> {
    if available_key_fingerprints.is_empty() {
        return Ok(None);
    }

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

    let result = query_builder.fetch_optional(pool).await?;
    Ok(result)
}

pub async fn is_secret_encrypted_for_key(
    pool: &SqlitePool,
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
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}
