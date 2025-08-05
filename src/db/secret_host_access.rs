use crate::Result;
use crate::db::models::SecretHostAccess;
use sqlx::SqlitePool;

pub async fn insert_secret_host_access(pool: &SqlitePool, access: &SecretHostAccess) -> Result<()> {
    sqlx::query(
        "INSERT INTO secret_host_access (secret_name, host_key_fingerprint, created_at, updated_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&access.secret_name)
    .bind(&access.host_key_fingerprint)
    .bind(access.created_at)
    .bind(access.updated_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_secret_host_access(pool: &SqlitePool, secret_name: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT host_key_fingerprint FROM secret_host_access WHERE secret_name = ? ORDER BY host_key_fingerprint"
    )
    .bind(secret_name)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn remove_secret_host_access(pool: &SqlitePool, secret_name: &str) -> Result<()> {
    sqlx::query("DELETE FROM secret_host_access WHERE secret_name = ?")
        .bind(secret_name)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn can_host_access_secret(
    pool: &SqlitePool,
    secret_name: &str,
    host_key_fingerprint: &str,
) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM secret_host_access WHERE secret_name = ? AND host_key_fingerprint = ?"
    )
    .bind(secret_name)
    .bind(host_key_fingerprint)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}
