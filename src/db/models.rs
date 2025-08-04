use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct VaultKey {
    pub fingerprint: String,
    pub name: String,
    pub public_key: String,
    pub encrypted_private_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct HostKey {
    pub fingerprint: String,
    pub hostname: String,
    pub public_key: String,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub description: Option<String>,
    pub template: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SecretStorage {
    pub id: i64,
    pub secret_name: String,
    pub version: i64,
    pub key_fingerprint: String,
    pub key_type: String,
    pub encrypted_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub resource: String,
    pub details: Option<String>,
    pub version: Option<i64>,
    pub success: bool,
    pub error_message: Option<String>,
}
