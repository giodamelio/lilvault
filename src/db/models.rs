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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_vault_key_serialization() {
        let vault_key = VaultKey {
            fingerprint: "abc123".to_string(),
            name: "test-key".to_string(),
            public_key: "age1ql3n4n93j3j4l2a3rk6t3q3q5z3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0a1"
                .to_string(),
            encrypted_private_key: b"encrypted_data".to_vec(),
            created_at: Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&vault_key).expect("Should serialize to JSON");
        assert!(json.contains("abc123"));
        assert!(json.contains("test-key"));

        // Test JSON deserialization
        let deserialized: VaultKey =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.fingerprint, vault_key.fingerprint);
        assert_eq!(deserialized.name, vault_key.name);
        assert_eq!(deserialized.public_key, vault_key.public_key);
        assert_eq!(
            deserialized.encrypted_private_key,
            vault_key.encrypted_private_key
        );
        assert_eq!(deserialized.created_at, vault_key.created_at);
    }

    #[test]
    fn test_host_key_serialization() {
        let host_key = HostKey {
            fingerprint: "def456".to_string(),
            hostname: "server1".to_string(),
            public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB test@example.com".to_string(),
            added_at: Utc.with_ymd_and_hms(2024, 2, 1, 10, 30, 0).unwrap(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&host_key).expect("Should serialize to JSON");
        assert!(json.contains("def456"));
        assert!(json.contains("server1"));

        // Test JSON deserialization
        let deserialized: HostKey =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.fingerprint, host_key.fingerprint);
        assert_eq!(deserialized.hostname, host_key.hostname);
        assert_eq!(deserialized.public_key, host_key.public_key);
        assert_eq!(deserialized.added_at, host_key.added_at);
    }

    #[test]
    fn test_secret_serialization() {
        let secret = Secret {
            name: "my-secret".to_string(),
            description: Some("Test secret description".to_string()),
            template: None,
            created_at: Utc.with_ymd_and_hms(2024, 3, 1, 14, 15, 0).unwrap(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&secret).expect("Should serialize to JSON");
        assert!(json.contains("my-secret"));
        assert!(json.contains("Test secret description"));

        // Test JSON deserialization
        let deserialized: Secret =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.name, secret.name);
        assert_eq!(deserialized.description, secret.description);
        assert_eq!(deserialized.template, secret.template);
        assert_eq!(deserialized.created_at, secret.created_at);
    }

    #[test]
    fn test_secret_storage_serialization() {
        let storage = SecretStorage {
            id: 1,
            secret_name: "test-secret".to_string(),
            version: 2,
            key_fingerprint: "ghi789".to_string(),
            key_type: "vault".to_string(),
            encrypted_data: b"secret_encrypted_data".to_vec(),
            created_at: Utc.with_ymd_and_hms(2024, 4, 1, 16, 45, 0).unwrap(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&storage).expect("Should serialize to JSON");
        assert!(json.contains("test-secret"));
        assert!(json.contains("ghi789"));
        assert!(json.contains("vault"));

        // Test JSON deserialization
        let deserialized: SecretStorage =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.id, storage.id);
        assert_eq!(deserialized.secret_name, storage.secret_name);
        assert_eq!(deserialized.version, storage.version);
        assert_eq!(deserialized.key_fingerprint, storage.key_fingerprint);
        assert_eq!(deserialized.key_type, storage.key_type);
        assert_eq!(deserialized.encrypted_data, storage.encrypted_data);
        assert_eq!(deserialized.created_at, storage.created_at);
    }

    #[test]
    fn test_audit_log_serialization() {
        let audit_entry = AuditLog {
            id: 10,
            timestamp: Utc.with_ymd_and_hms(2024, 5, 1, 9, 20, 0).unwrap(),
            operation: "store_secret".to_string(),
            resource: "my-secret".to_string(),
            details: Some("Secret stored successfully".to_string()),
            version: Some(1),
            success: true,
            error_message: None,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&audit_entry).expect("Should serialize to JSON");
        assert!(json.contains("store_secret"));
        assert!(json.contains("my-secret"));
        assert!(json.contains("Secret stored successfully"));

        // Test JSON deserialization
        let deserialized: AuditLog =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.id, audit_entry.id);
        assert_eq!(deserialized.timestamp, audit_entry.timestamp);
        assert_eq!(deserialized.operation, audit_entry.operation);
        assert_eq!(deserialized.resource, audit_entry.resource);
        assert_eq!(deserialized.details, audit_entry.details);
        assert_eq!(deserialized.version, audit_entry.version);
        assert_eq!(deserialized.success, audit_entry.success);
        assert_eq!(deserialized.error_message, audit_entry.error_message);
    }

    #[test]
    fn test_secret_with_template() {
        let secret = Secret {
            name: "templated-secret".to_string(),
            description: None,
            template: Some("Hello {{username}}!".to_string()),
            created_at: Utc.with_ymd_and_hms(2024, 6, 1, 11, 0, 0).unwrap(),
        };

        let json = serde_json::to_string(&secret).expect("Should serialize to JSON");
        let deserialized: Secret =
            serde_json::from_str(&json).expect("Should deserialize from JSON");

        assert_eq!(
            deserialized.template,
            Some("Hello {{username}}!".to_string())
        );
        assert_eq!(deserialized.description, None);
    }

    #[test]
    fn test_audit_log_with_error() {
        let audit_entry = AuditLog {
            id: 11,
            timestamp: Utc.with_ymd_and_hms(2024, 5, 2, 10, 30, 0).unwrap(),
            operation: "decrypt_secret".to_string(),
            resource: "failed-secret".to_string(),
            details: None,
            version: Some(2),
            success: false,
            error_message: Some("Invalid password".to_string()),
        };

        let json = serde_json::to_string(&audit_entry).expect("Should serialize to JSON");
        let deserialized: AuditLog =
            serde_json::from_str(&json).expect("Should deserialize from JSON");

        assert_eq!(deserialized.success, false);
        assert_eq!(
            deserialized.error_message,
            Some("Invalid password".to_string())
        );
        assert_eq!(deserialized.details, None);
    }
}
