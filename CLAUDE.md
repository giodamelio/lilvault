# LilVault - Homelab Secrets Management

A secure, encrypted secrets management system designed for homelabs with per-host encryption, infinite versioning, and audit logging.

## Project Overview

LilVault is a single-file SQLite-based secrets manager that allows you to safely distribute encrypted secrets across your homelab infrastructure. Each host can only decrypt secrets intended for them, while master keys provide administrative access to all secrets.

## Core Features

- **Single SQLite file**: Portable vault that can be safely distributed to all hosts
- **Per-host encryption**: Each secret encrypted separately for each target host using their SSH public keys
- **Vault key support**: Multiple password-protected vault keys for administrative access
- **Infinite versioning**: Never delete secrets, only create new versions
- **Audit logging**: Simple debugging-focused audit trail for all operations
- **Safe distribution**: Vault file can be copied to any host - they only see their secrets

## Development Principles

- Never modify existing migrations
- Don't edit migrations that have already been used. Add new ones to make changes to the db schema.

## Architecture

### Encryption Strategy
- **Host encryption**: SSH public keys converted to age recipients
- **Vault keys**: Password-protected age keys for full vault access
- **Storage**: Multiple encrypted copies per secret (one per target host + vault keys)

### Database Schema
```sql
-- Vault keys (password-protected age keys)
CREATE TABLE vault_keys (
    fingerprint TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Host keys (SSH public keys)
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

-- Low-level secret storage (one row per secret+version+key)
CREATE TABLE secret_storage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    key_fingerprint TEXT NOT NULL,
    key_type TEXT NOT NULL CHECK(key_type IN ('vault', 'host')),
    encrypted_data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(secret_name, version, key_fingerprint)
);

-- Simple audit log for debugging
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operation TEXT NOT NULL,
    resource TEXT NOT NULL,
    details TEXT,
    version INTEGER,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Database Standards

### Database Query Organization
All database queries MUST be organized by table in the `src/db/` module:

- **`src/db/keys.rs`** - All queries for the `keys` table (vault and host keys)
- **`src/db/secrets.rs`** - All queries for the `secrets` table (metadata and complex queries)
- **`src/db/secret_storage.rs`** - All queries for the `secret_storage` table (encrypted data)
- **`src/db/secrets_keys.rs`** - All queries for the `secrets_keys` relationship table
- **`src/db/secret_host_access.rs`** - All queries for the `secret_host_access` table
- **`src/db/audit_log.rs`** - All queries for the `audit_log` table
- **`src/db/models.rs`** - Database model structs and tests
- **`src/db/mod.rs`** - Database connection management and method delegation

#### Query Organization Rules:
1. **Table-specific modules**: Each table gets its own module containing all related queries
2. **Pure functions**: All query functions take `&SqlitePool` as the first parameter
3. **No business logic**: Query modules contain only database access code, no business logic
4. **Consistent naming**: Function names should be descriptive (e.g., `get_host_key_by_hostname`)
5. **Error handling**: All functions return `Result<T>` from the crate's error system
6. **Database-only**: Only database access code in these modules - no I/O, crypto, or other concerns

#### Adding New Queries:
When adding new database functionality:
1. Add the query function to the appropriate table module (e.g., `src/db/keys.rs`)
2. Add a delegation method to `Database` impl in `src/db/mod.rs` that calls the query function
3. Write tests for the new functionality
4. Update schema documentation if adding new tables/columns

This organization provides:
- **Better testability**: Each query function can be unit tested independently
- **Clear separation**: Database logic is isolated from business logic
- **Easy maintenance**: All queries for a table are in one place
- **Consistent patterns**: All query modules follow the same structure

### Required Columns for All Tables
Every table MUST include these timestamp columns:
- `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` - When the record was first created
- `updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` - When the record was last modified

### Automatic updated_at Triggers
All tables have automatic triggers that update `updated_at` when records are modified:
```sql
CREATE TRIGGER table_name_updated_at
    AFTER UPDATE ON table_name
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE table_name SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
```

### Table Creation Checklist
When creating new tables, ensure you:
1. ✅ Include `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
2. ✅ Include `updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
3. ✅ Create corresponding `updated_at` trigger (see migration 001 for examples)
4. ✅ Update the Rust model struct to include both timestamp fields
5. ✅ Update all database queries to handle the new columns
6. ✅ Add unit tests for the new model serialization/deserialization
7. ✅ Run `dump-schema` to update `db/schema.sql`

### Schema Documentation
The project maintains a `db/schema.sql` file (similar to Rails' `db/schema.rb`) that contains the complete, up-to-date database schema. This file is:

- **Auto-generated** from the current migration state
- **Read-only** - never edit directly, create migrations instead
- **Version controlled** for easy schema diffing and understanding
- **Updated** automatically on devenv entry and manually via `dump-schema`

This provides a single source of truth for the current database structure without needing to piece together multiple migration files.

## Technology Stack

### Core Dependencies
- **sqlx**: Async SQLite database access with compile-time query verification
- **age**: Modern encryption with SSH key support
- **clap**: CLI argument parsing with derive macros
- **dialoguer**: Rich CLI interactions and password prompts
- **miette**: Beautiful error reporting and diagnostics
- **thiserror**: Custom error type definitions

### Supporting Libraries
- **tokio**: Async runtime
- **chrono**: Date/time handling
- **uuid**: Unique identifiers
- **serde/serde_json**: Serialization
- **tera**: Template engine (future feature)

## CLI Interface

### Basic Operations
```bash
# Initialize vault
lilvault init --name "primary"

# Vault key management
lilvault vault add --name "backup"
lilvault vault list
lilvault vault remove <fingerprint>

# Host key management
lilvault keys add-host <hostname> <ssh-public-key-path>
lilvault keys scan-host <hostname> [--port 22] [--key-types rsa,ecdsa,ed25519] [--timeout 5]
lilvault keys list [--key-type host]
lilvault keys remove <hostname-or-fingerprint>

# Secret operations
lilvault secret store <secret-name> [--hosts host1,host2] [--file <path> | --stdin] [--description "desc"]
lilvault secret get <secret-name> [--version <n>] [--key <fingerprint>]
lilvault secret list [--key <fingerprint>]
lilvault secret versions <secret-name> [--key <fingerprint>]
lilvault secret delete <secret-name>

# Audit log
lilvault audit list [--limit 50]
lilvault audit show [--resource <name>] [--operation <op>]
lilvault audit since --days 7
```

## Implementation Phases

### Phase 1: Foundation ✅ (Current)
- [x] Set up Cargo.toml with dependencies
- [x] Database schema with SQLx migrations
- [x] Basic project structure with error handling
- [x] CLI structure with clap
- [x] Database connection and migration system

### Phase 2: Core Encryption
- [ ] Master key generation with age and password protection
- [ ] SSH host key management with age ssh recipients
- [ ] Core encrypt/decrypt operations
- [ ] Key fingerprint generation and storage

### Phase 3: Secret Management
- [ ] Secret storage with per-key encryption
- [ ] Version management at storage level
- [ ] Secret retrieval with access control
- [ ] Multi-host encryption support

### Phase 4: Audit & CLI Polish
- [ ] Simplified audit logging for debugging
- [ ] Audit log viewing and querying commands
- [ ] Rich password prompts with dialoguer
- [ ] Comprehensive error handling with miette

### Phase 5: Advanced Features (Future)
- [ ] Template system with Tera
- [ ] SystemD credentials integration
- [ ] External sync capabilities
- [ ] Performance optimizations

## Security Properties

- **Key isolation**: Each key can only decrypt secrets intended for it
- **Vault key access**: Vault keys can decrypt all secrets for administration
- **Safe distribution**: Vault file safe to copy anywhere - hosts only see their data
- **Audit trail**: All mutations logged for debugging and change tracking
- **Version control**: Different secret versions can have different host access

## Development Commands

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run

# Database operations
cargo run -- migrate         # Apply pending migrations (if any)
dump-schema                  # Generate db/schema.sql from current state

# Lint and format
cargo clippy
cargo fmt

# Generate documentation
cargo doc --no-deps --open
```

## Documentation

The project uses Rust's built-in documentation system. Documentation is automatically generated and updated via Claude Code hooks.

### Viewing Documentation

Local documentation is generated in `target/doc/` and includes:
- **API Documentation**: Generated from doc comments in the source code
- **Dependency Documentation**: Documentation for all project dependencies (when built with `cargo doc`)

```bash
# Generate and open documentation in browser
cargo doc --no-deps --open

# Generate documentation for dependencies too
cargo doc --open
```

### Auto-Generated Documentation

Claude Code hooks automatically regenerate documentation when:
- `src/lib.rs` or `src/main.rs` are modified
- `Cargo.toml` is updated (dependencies change)

The generated documentation can be found at:
- Main crate docs: `target/doc/lilvault/index.html`
- Dependency docs: `target/doc/index.html`

### Development Hooks

The project uses Claude Code hooks for automated development workflow:
- **treefmt**: Automatic code formatting after any file modification
- **cargo check**: Compilation check after Rust file changes
- **cargo test**: Run tests when test files are modified
- **cargo clippy**: Linting after Rust file changes
- **cargo doc**: Documentation regeneration for main files and dependency changes
- **cargo tree**: Check for duplicate dependencies when Cargo.toml changes

## Future Features

- **Templating**: Generate config files from templates with secret injection
- **SystemD Integration**: Seamless integration with SystemD credential system
- **External Sync**: Bi-directional sync with popular password managers
- **Advanced Audit**: Rich querying and reporting capabilities

## Contributing

This project uses:
- Standard Rust toolchain with rustfmt and clippy
- SQLx for compile-time verified SQL queries
- Conventional commit messages
- Integration tests for all major functionality

## License

[License TBD]
