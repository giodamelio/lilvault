# CLI Testing Implementation Instructions

## Context
LilVault is a secrets management CLI tool with the following core functionality:
- Vault key management (init, add, list, remove)
- Host key management (add, list, remove)
- Secret operations (store, get, list, versions, delete)
- Audit commands (list, show, since) - not yet implemented

## Current State
- Core functionality is implemented and working
- CLI uses clap with organized subcommands: `lilvault {vault|host|secret|audit} <subcommand>`
- Uses SQLite database with migrations
- Password prompts for vault key operations
- Supports file and stdin input for secrets

## Testing Requirements

### Add Dependencies to Cargo.toml
```toml
[dev-dependencies]
assert_cmd = "2.0"
assert_fs = "1.1"
# tempfile = "3.0" # Already present
# tokio-test = "0.4" # Already present
```

### Test Structure to Create

1. **Integration Tests** (`tests/cli_tests.rs`):
   - Full end-to-end CLI workflows
   - Real database operations with temp files
   - Password input simulation
   - Output verification

2. **Key Test Scenarios**:
   - **Vault Initialization**: Test `lilvault init --name "test"`
   - **Vault Key Management**: Add/list/remove vault keys
   - **Host Key Management**: Add SSH keys, list hosts, remove by name/fingerprint
   - **Secret Storage**: Store secrets with different input methods (file, stdin)
   - **Secret Retrieval**: Get secrets with vault key authentication
   - **Error Handling**: Invalid commands, missing database, wrong passwords
   - **CLI Help/Usage**: Verify help text and subcommand structure

3. **Testing Patterns**:
   - Use `assert_fs::TempDir` for isolated database files
   - Use `Command::cargo_bin("lilvault")` to test the actual binary
   - Mock password input with `write_stdin("password\npassword\n")`
   - Test both success and failure cases
   - Verify database state changes where appropriate

### Example Test Structure
```rust
use assert_cmd::Command;
use assert_fs::prelude::*;
use std::fs;

#[test]
fn test_complete_workflow() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let ssh_key = temp.child("test_key.pub");

    // Create test SSH key file
    ssh_key.write_str("ssh-rsa AAAAB3NzaN... test@example.com").unwrap();

    // Test init
    Command::cargo_bin("lilvault").unwrap()
        .args(&["--database", vault_db.to_str().unwrap()])
        .args(&["init", "--name", "test-key"])
        .write_stdin("password123\npassword123\n")
        .assert()
        .success()
        .stdout(predicates::str::contains("Vault initialized successfully"));

    // Test host add
    Command::cargo_bin("lilvault").unwrap()
        .args(&["--database", vault_db.to_str().unwrap()])
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Continue testing other operations...
}
```

### Important Testing Considerations
- **Database Isolation**: Each test should use its own temporary database
- **Password Handling**: Non-interactive environment requires stdin simulation
- **File Operations**: Test both file input and stdin for secrets
- **Error Cases**: Test missing files, invalid SSH keys, wrong passwords
- **Output Verification**: Check success messages and table formatting
- **Cleanup**: Use tempfile/assert_fs for automatic cleanup

### Current CLI Structure Reference
```bash
lilvault [--database <path>] [--verbose] <COMMAND>

Commands:
  init              Initialize a new vault
  vault <COMMAND>   Vault key management (add|list|remove)
  host <COMMAND>    Host key management (add|list|remove)
  secret <COMMAND>  Secret management (store|get|list|versions|delete)
  audit <COMMAND>   Audit log commands (list|show|since)
```

## Implementation Priority
1. Basic init and vault key tests
2. Host key management tests
3. Secret storage and retrieval tests
4. Error handling and edge cases
5. Full workflow integration tests

## Notes
- The application requires password input for vault operations
- SSH public keys must be valid format for host key tests
- Database is created automatically on first use
- All encryption/decryption happens automatically in the CLI
