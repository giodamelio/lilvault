-- Add updated_at columns to all tables for better change tracking
-- This migration adds updated_at columns and creates triggers to automatically update them

-- Add updated_at column to vault_keys table
ALTER TABLE vault_keys ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add updated_at column to host_keys table
-- Note: rename added_at to created_at for consistency
ALTER TABLE host_keys ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add updated_at column to secrets table
ALTER TABLE secrets ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add updated_at column to secret_storage table
ALTER TABLE secret_storage ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add updated_at column to audit_log table
-- Note: rename timestamp to created_at for consistency
ALTER TABLE audit_log ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create triggers to automatically update the updated_at column when rows are modified
-- SQLite doesn't support multiple triggers per table, so we use UPDATE OF for all columns

-- Trigger for vault_keys
CREATE TRIGGER vault_keys_updated_at
    AFTER UPDATE ON vault_keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE vault_keys SET updated_at = CURRENT_TIMESTAMP WHERE fingerprint = NEW.fingerprint;
END;

-- Trigger for host_keys
CREATE TRIGGER host_keys_updated_at
    AFTER UPDATE ON host_keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE host_keys SET updated_at = CURRENT_TIMESTAMP WHERE fingerprint = NEW.fingerprint;
END;

-- Trigger for secrets
CREATE TRIGGER secrets_updated_at
    AFTER UPDATE ON secrets
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secrets SET updated_at = CURRENT_TIMESTAMP WHERE name = NEW.name;
END;

-- Trigger for secret_storage
CREATE TRIGGER secret_storage_updated_at
    AFTER UPDATE ON secret_storage
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secret_storage SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Trigger for audit_log
CREATE TRIGGER audit_log_updated_at
    AFTER UPDATE ON audit_log
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE audit_log SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Update existing records to set updated_at = created_at initially
UPDATE vault_keys SET updated_at = created_at;
UPDATE host_keys SET updated_at = added_at;
UPDATE secrets SET updated_at = created_at;
UPDATE secret_storage SET updated_at = created_at;
UPDATE audit_log SET updated_at = timestamp;
