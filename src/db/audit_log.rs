use crate::Result;
use crate::db::models::AuditLog;
use sqlx::SqlitePool;

pub async fn insert_audit_entry(pool: &SqlitePool, audit_entry: &AuditLog) -> Result<()> {
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
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_audit_entries(pool: &SqlitePool, limit: i64) -> Result<Vec<AuditLog>> {
    let entries = sqlx::query_as::<_, AuditLog>(
        "SELECT id, created_at, operation, resource, details, version, success, error_message, updated_at FROM audit_log ORDER BY created_at DESC LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn get_audit_entries_filtered(
    pool: &SqlitePool,
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

    let entries = sqlx_query.fetch_all(pool).await?;
    Ok(entries)
}

pub async fn get_audit_entries_since(
    pool: &SqlitePool,
    days: i64,
    limit: i64,
) -> Result<Vec<AuditLog>> {
    let entries = sqlx::query_as::<_, AuditLog>(
        "SELECT id, created_at, operation, resource, details, version, success, error_message, updated_at FROM audit_log WHERE created_at >= datetime('now', '-' || ? || ' days') ORDER BY created_at DESC LIMIT ?"
    )
    .bind(days)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn log_audit(
    pool: &SqlitePool,
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

    insert_audit_entry(pool, &audit_entry).await
}
