-- Join table between secrets and keys
-- This table defines which keys (vault or host) a secret is encrypted for
-- By default, secrets are only encrypted for vault keys
-- Host keys must be explicitly added via share commands

CREATE TABLE secrets_keys (
    secret_name TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    key_type TEXT NOT NULL CHECK(key_type IN ('vault', 'host')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (secret_name, key_fingerprint),
    FOREIGN KEY (secret_name) REFERENCES secrets(name) ON DELETE CASCADE,
    FOREIGN KEY (key_fingerprint) REFERENCES keys(fingerprint) ON DELETE CASCADE
);

-- Trigger to auto-update updated_at timestamp
CREATE TRIGGER secrets_keys_updated_at
    AFTER UPDATE ON secrets_keys
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE secrets_keys SET updated_at = CURRENT_TIMESTAMP
    WHERE secret_name = NEW.secret_name AND key_fingerprint = NEW.key_fingerprint;
END;

-- Index for efficient querying
CREATE INDEX idx_secrets_keys_secret ON secrets_keys(secret_name);
CREATE INDEX idx_secrets_keys_key ON secrets_keys(key_fingerprint);
CREATE INDEX idx_secrets_keys_type ON secrets_keys(key_type);
