use crate::Result;
use crate::db::models::{SecretKey, SecretKeyInfo};
use sqlx::SqlitePool;

pub async fn get_secret_keys(pool: &SqlitePool, secret_name: &str) -> Result<Vec<SecretKeyInfo>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT sk.key_fingerprint, sk.key_type, k.name
        FROM secrets_keys sk
        LEFT JOIN keys k ON sk.key_fingerprint = k.fingerprint
        WHERE sk.secret_name = ?
        ORDER BY sk.key_type, k.name
        "#,
    )
    .bind(secret_name)
    .fetch_all(pool)
    .await?;

    let keys: Vec<SecretKeyInfo> = rows
        .into_iter()
        .map(|(fingerprint, key_type, name)| {
            let display_name = name.unwrap_or_else(|| format!("Unknown ({})", &fingerprint[..8]));
            SecretKeyInfo {
                fingerprint,
                key_type,
                name: display_name,
            }
        })
        .collect();

    Ok(keys)
}

pub async fn insert_secret_key(pool: &SqlitePool, secret_key: &SecretKey) -> Result<()> {
    sqlx::query(
        "INSERT INTO secrets_keys (secret_name, key_fingerprint, key_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&secret_key.secret_name)
    .bind(&secret_key.key_fingerprint)
    .bind(&secret_key.key_type)
    .bind(secret_key.created_at)
    .bind(secret_key.updated_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn remove_all_secret_keys(pool: &SqlitePool, secret_name: &str) -> Result<()> {
    sqlx::query("DELETE FROM secrets_keys WHERE secret_name = ?")
        .bind(secret_name)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn remove_secret_key(
    pool: &SqlitePool,
    secret_name: &str,
    key_fingerprint: &str,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM secrets_keys WHERE secret_name = ? AND key_fingerprint = ?")
            .bind(secret_name)
            .bind(key_fingerprint)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn is_secret_encrypted_for_key_new(
    pool: &SqlitePool,
    secret_name: &str,
    key_fingerprint: &str,
) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM secrets_keys WHERE secret_name = ? AND key_fingerprint = ?",
    )
    .bind(secret_name)
    .bind(key_fingerprint)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}
