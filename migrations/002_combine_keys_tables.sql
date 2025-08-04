-- Combine vault_keys and host_keys into a single keys table
-- This simplifies queries and makes key management more consistent

-- Create the new unified keys table
CREATE TABLE keys (
    fingerprint TEXT PRIMARY KEY,
    key_type TEXT NOT NULL CHECK(key_type IN ('vault', 'host')),
    name TEXT NOT NULL,                      -- For vault keys: user-defined name, for host keys: hostname
    public_key TEXT NOT NULL,
    encrypted_private_key BLOB,              -- Only populated for vault keys, NULL for host keys
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migrate data from vault_keys table
INSERT INTO keys (fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at)
SELECT fingerprint, 'vault', name, public_key, encrypted_private_key, created_at, updated_at
FROM vault_keys;

-- Migrate data from host_keys table
INSERT INTO keys (fingerprint, key_type, name, public_key, encrypted_private_key, created_at, updated_at)
SELECT fingerprint, 'host', hostname, public_key, NULL, created_at, updated_at
FROM host_keys;

-- Drop the old tables
DROP TABLE vault_keys;
DROP TABLE host_keys;

-- Create trigger for automatic updated_at timestamp
CREATE TRIGGER keys_updated_at
    AFTER UPDATE ON keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE keys SET updated_at = CURRENT_TIMESTAMP WHERE fingerprint = NEW.fingerprint;
END;

-- Create indexes for performance
CREATE INDEX idx_keys_type ON keys(key_type);
CREATE INDEX idx_keys_name ON keys(name);
