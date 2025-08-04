-- Initial schema for LilVault
-- Creates tables for vault keys, host keys, secrets, secret storage, and audit log

-- Vault keys (password-protected age keys for administrative access)
CREATE TABLE vault_keys (
    fingerprint TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Host keys (SSH public keys converted to age recipients)
CREATE TABLE host_keys (
    fingerprint TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Secret metadata
CREATE TABLE secrets (
    name TEXT PRIMARY KEY,
    description TEXT,
    template TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Low-level secret storage - one row per secret+version+key combination
CREATE TABLE secret_storage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    key_fingerprint TEXT NOT NULL,
    key_type TEXT NOT NULL CHECK(key_type IN ('vault', 'host')),
    encrypted_data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(secret_name, version, key_fingerprint),
    FOREIGN KEY(secret_name) REFERENCES secrets(name)
);

-- Simplified audit log for debugging and change tracking
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operation TEXT NOT NULL,        -- CREATE_SECRET, UPDATE_SECRET, ADD_HOST, etc.
    resource TEXT NOT NULL,         -- secret name, host name, key name
    details TEXT,                   -- Simple text description of what changed
    version INTEGER,                -- For secrets, null for other resources
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,             -- If success = false
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_secret_storage_key ON secret_storage(key_fingerprint, secret_name, version);
CREATE INDEX idx_audit_timestamp ON audit_log(created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource);
CREATE INDEX idx_audit_operation ON audit_log(operation);

-- Triggers to automatically update updated_at timestamps
CREATE TRIGGER vault_keys_updated_at
    AFTER UPDATE ON vault_keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE vault_keys SET updated_at = CURRENT_TIMESTAMP WHERE fingerprint = NEW.fingerprint;
END;

CREATE TRIGGER host_keys_updated_at
    AFTER UPDATE ON host_keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE host_keys SET updated_at = CURRENT_TIMESTAMP WHERE fingerprint = NEW.fingerprint;
END;

CREATE TRIGGER secrets_updated_at
    AFTER UPDATE ON secrets
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secrets SET updated_at = CURRENT_TIMESTAMP WHERE name = NEW.name;
END;

CREATE TRIGGER secret_storage_updated_at
    AFTER UPDATE ON secret_storage
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secret_storage SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER audit_log_updated_at
    AFTER UPDATE ON audit_log
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE audit_log SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
