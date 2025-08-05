use crate::Result;
use crate::db::models::Key;
use sqlx::SqlitePool;

pub async fn insert_key(pool: &SqlitePool, key: &Key) -> Result<()> {
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
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_keys_by_type(pool: &SqlitePool, key_type: &str) -> Result<Vec<Key>> {
    let keys = sqlx::query_as::<_, Key>(
        "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE key_type = ? ORDER BY name"
    )
    .bind(key_type)
    .fetch_all(pool)
    .await?;

    Ok(keys)
}

pub async fn get_all_vault_keys(pool: &SqlitePool) -> Result<Vec<Key>> {
    get_keys_by_type(pool, "vault").await
}

pub async fn get_all_host_keys(pool: &SqlitePool) -> Result<Vec<Key>> {
    get_keys_by_type(pool, "host").await
}

pub async fn get_key(pool: &SqlitePool, fingerprint: &str) -> Result<Option<Key>> {
    let key = sqlx::query_as::<_, Key>(
        "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ?"
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

pub async fn get_vault_key(pool: &SqlitePool, fingerprint: &str) -> Result<Option<Key>> {
    let key = sqlx::query_as::<_, Key>(
        "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ? AND key_type = 'vault'"
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

pub async fn get_host_key_by_hostname(pool: &SqlitePool, hostname: &str) -> Result<Option<Key>> {
    let key = sqlx::query_as::<_, Key>(
        "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE name = ? AND key_type = 'host'"
    )
    .bind(hostname)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

pub async fn get_host_key_by_fingerprint(
    pool: &SqlitePool,
    fingerprint: &str,
) -> Result<Option<Key>> {
    let key = sqlx::query_as::<_, Key>(
        "SELECT fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at FROM keys WHERE fingerprint = ? AND key_type = 'host'"
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

pub async fn remove_key(pool: &SqlitePool, fingerprint: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ?")
        .bind(fingerprint)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn remove_vault_key(pool: &SqlitePool, fingerprint: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ? AND key_type = 'vault'")
        .bind(fingerprint)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn remove_host_key_by_hostname(pool: &SqlitePool, hostname: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM keys WHERE name = ? AND key_type = 'host'")
        .bind(hostname)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn remove_host_key_by_fingerprint(pool: &SqlitePool, fingerprint: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM keys WHERE fingerprint = ? AND key_type = 'host'")
        .bind(fingerprint)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn is_initialized(pool: &SqlitePool) -> Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM keys WHERE key_type = 'vault'")
        .fetch_one(pool)
        .await?;

    Ok(count.0 > 0)
}
