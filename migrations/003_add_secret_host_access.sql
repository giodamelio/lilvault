-- Add secret-specific host access control
-- This table defines which host keys can access each secret
-- Vault keys always have access (not stored here, handled in application logic)

CREATE TABLE secret_host_access (
    secret_name TEXT NOT NULL,
    host_key_fingerprint TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (secret_name, host_key_fingerprint),
    FOREIGN KEY (secret_name) REFERENCES secrets(name) ON DELETE CASCADE,
    FOREIGN KEY (host_key_fingerprint) REFERENCES keys(fingerprint) ON DELETE CASCADE
);

-- Trigger to auto-update updated_at timestamp
CREATE TRIGGER secret_host_access_updated_at
    AFTER UPDATE ON secret_host_access
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secret_host_access SET updated_at = CURRENT_TIMESTAMP
    WHERE secret_name = NEW.secret_name AND host_key_fingerprint = NEW.host_key_fingerprint;
END;

-- Index for efficient querying of host access
CREATE INDEX idx_secret_host_access_secret ON secret_host_access(secret_name);
CREATE INDEX idx_secret_host_access_host ON secret_host_access(host_key_fingerprint);
