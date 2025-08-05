use crate::Result;
use crate::db::models::{Secret, SecretInfo, SecretKeyInfo, SecretVersionInfo};
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

pub async fn insert_secret(pool: &SqlitePool, secret: &Secret) -> Result<()> {
    sqlx::query(
        "INSERT INTO secrets (name, description, template, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&secret.name)
    .bind(&secret.description)
    .bind(&secret.template)
    .bind(secret.created_at)
    .bind(secret.updated_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_secret(pool: &SqlitePool, name: &str) -> Result<Option<Secret>> {
    let secret = sqlx::query_as::<_, Secret>(
        "SELECT name, description, template, created_at, updated_at FROM secrets WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(secret)
}

pub async fn get_all_secrets(pool: &SqlitePool) -> Result<Vec<Secret>> {
    let secrets = sqlx::query_as::<_, Secret>(
        "SELECT name, description, template, created_at, updated_at FROM secrets ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(secrets)
}

pub async fn get_secrets_for_reencryption(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT name FROM secrets ORDER BY name")
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_secret_info(pool: &SqlitePool, secret_name: &str) -> Result<Option<SecretInfo>> {
    let secret = match get_secret(pool, secret_name).await? {
        Some(s) => s,
        None => return Ok(None),
    };

    let versions: Vec<(i64,)> = sqlx::query_as(
        "SELECT DISTINCT version FROM secret_storage WHERE secret_name = ? ORDER BY version DESC",
    )
    .bind(secret_name)
    .fetch_all(pool)
    .await?;

    let all_versions: Vec<i64> = versions.into_iter().map(|v| v.0).collect();

    let mut version_info = Vec::new();
    for version in &all_versions {
        type KeysInfoRow = (String, String, Option<String>, DateTime<Utc>, DateTime<Utc>);
        let keys_info: Vec<KeysInfoRow> = sqlx::query_as(
            r#"
            SELECT ss.key_fingerprint, ss.key_type,
                   CASE
                       WHEN ss.key_type = 'vault' THEN k.name
                       ELSE k.name
                   END as key_name,
                   ss.created_at, ss.updated_at
            FROM secret_storage ss
            LEFT JOIN keys k ON ss.key_fingerprint = k.fingerprint
            WHERE ss.secret_name = ? AND ss.version = ?
            ORDER BY ss.key_type, k.name
            "#,
        )
        .bind(secret_name)
        .bind(version)
        .fetch_all(pool)
        .await?;

        let keys: Vec<SecretKeyInfo> = keys_info
            .iter()
            .map(|(fingerprint, key_type, name, _, _)| {
                let display_name = name
                    .clone()
                    .unwrap_or_else(|| format!("Unknown ({})", &fingerprint[..8]));
                SecretKeyInfo {
                    fingerprint: fingerprint.clone(),
                    key_type: key_type.clone(),
                    name: display_name,
                }
            })
            .collect();

        let version_created_at = keys_info
            .iter()
            .map(|(_, _, _, created, _)| *created)
            .min()
            .unwrap_or_else(Utc::now);
        let version_updated_at = keys_info
            .iter()
            .map(|(_, _, _, _, updated)| *updated)
            .max()
            .unwrap_or_else(Utc::now);

        version_info.push(SecretVersionInfo {
            version: *version,
            encrypted_for_keys: keys,
            created_at: version_created_at,
            updated_at: version_updated_at,
        });
    }

    let recipients = super::secrets_keys::get_secret_keys(pool, secret_name).await?;

    Ok(Some(SecretInfo {
        name: secret.name,
        description: secret.description,
        template: secret.template,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
        total_versions: all_versions.len() as i64,
        latest_version: all_versions.first().copied(),
        versions: version_info,
        recipients,
    }))
}
