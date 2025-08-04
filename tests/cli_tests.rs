use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;

/// Helper function to create a test SSH public key by generating it with ssh-keygen
fn create_test_ssh_key(temp_dir: &assert_fs::TempDir) -> assert_fs::fixture::ChildPath {
    use std::process::Command;

    let key_path = temp_dir.child("test_key");
    let pub_key_path = temp_dir.child("test_key.pub");

    // Generate SSH key pair using ssh-keygen
    let output = Command::new("ssh-keygen")
        .args(&[
            "-t",
            "rsa",
            "-b",
            "2048",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "", // No passphrase
            "-C",
            "test@example.com",
            "-q", // Quiet mode
        ])
        .output()
        .expect("Failed to execute ssh-keygen - make sure it's installed");

    if !output.status.success() {
        panic!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub_key_path
}

/// Helper function to get a lilvault command with a specific database
fn lilvault_cmd(db_path: &str) -> Command {
    let mut cmd = Command::cargo_bin("lilvault").unwrap();
    cmd.args(&["--database", db_path]);
    cmd
}

/// Helper function to create a password file
fn create_password_file(
    temp_dir: &assert_fs::TempDir,
    password: &str,
) -> assert_fs::fixture::ChildPath {
    let password_file = temp_dir.child("password.txt");
    password_file.write_str(password).unwrap();
    password_file
}

#[test]
fn test_init_vault() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");

    // Test vault initialization
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "test-key",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault initialized successfully"))
        .stdout(predicate::str::contains("Vault key name: test-key"))
        .stdout(predicate::str::contains("Fingerprint:"));

    // Verify database file was created
    vault_db.assert(predicate::path::exists());
}

#[test]
fn test_init_vault_already_initialized() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");

    // Initialize vault first
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "test-key",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Try to initialize again
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "another-key",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Vault is already initialized"));
}

#[test]
fn test_vault_key_management() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file1 = create_password_file(&temp, "password123");
    let password_file2 = temp.child("password2.txt");
    password_file2.write_str("backup456").unwrap();

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file1.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add another vault key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "vault",
            "add",
            "--name",
            "backup",
            "--password-file",
            password_file2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault key added successfully"))
        .stdout(predicate::str::contains("Name: backup"));

    // List vault keys
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault Keys:"))
        .stdout(predicate::str::contains("primary"))
        .stdout(predicate::str::contains("backup"));
}

#[test]
fn test_vault_key_remove() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file1 = create_password_file(&temp, "password123");
    let password_file2 = temp.child("password2.txt");
    password_file2.write_str("backup456").unwrap();

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file1.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add another vault key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "vault",
            "add",
            "--name",
            "backup",
            "--password-file",
            password_file2.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Get the fingerprint of backup key
    let output = lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = output_str.lines().collect();
    let backup_line = lines
        .iter()
        .find(|line| line.contains("backup"))
        .expect("Should find backup key line");
    let fingerprint = backup_line.split_whitespace().next().unwrap();

    // Remove the backup key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "remove", fingerprint])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault key removed"));

    // Verify key was removed
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("primary"))
        .stdout(predicate::str::contains("backup").not());
}

#[test]
fn test_vault_key_remove_last_key() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Get the fingerprint of the only key
    let output = lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = output_str.lines().collect();
    let key_line = lines
        .iter()
        .find(|line| line.contains("primary"))
        .expect("Should find primary key line");
    let fingerprint = key_line.split_whitespace().next().unwrap();

    // Try to remove the last key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "remove", fingerprint])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot remove the last vault key"));
}

#[test]
fn test_host_key_management() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Host key added successfully"))
        .stdout(predicate::str::contains("Hostname: testhost"));

    // List host keys
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Host Keys:"))
        .stdout(predicate::str::contains("testhost"));
}

#[test]
fn test_host_key_add_duplicate() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Try to add same hostname again
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Host 'testhost' already exists"));
}

#[test]
fn test_host_key_remove() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Remove host key by hostname
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "remove", "testhost"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Host key removed: testhost"));

    // Verify key was removed
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No host keys found"));
}

#[test]
fn test_secret_storage_from_stdin() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Store secret from stdin
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "secret",
            "store",
            "test-secret",
            "--stdin",
            "--description",
            "Test secret",
        ])
        .write_stdin("my-secret-value")
        .assert()
        .success()
        .stdout(predicate::str::contains("Secret stored successfully"))
        .stdout(predicate::str::contains("Name: test-secret"))
        .stdout(predicate::str::contains("Version: 1"));
}

#[test]
fn test_secret_storage_from_file() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);
    let secret_file = temp.child("secret.txt");
    secret_file.write_str("file-secret-content").unwrap();

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Store secret from file
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "secret",
            "store",
            "file-secret",
            "--file",
            secret_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Secret stored successfully"))
        .stdout(predicate::str::contains("Name: file-secret"));
}

#[test]
fn test_secret_get_with_vault_key() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    let init_output = lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let init_str = String::from_utf8(init_output).unwrap();
    let fingerprint = init_str
        .lines()
        .find(|line| line.contains("Fingerprint:"))
        .unwrap()
        .split("Fingerprint: ")
        .nth(1)
        .unwrap()
        .trim();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Store secret
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "store", "test-secret", "--stdin"])
        .write_stdin("my-secret-value")
        .assert()
        .success();

    // Get secret with vault key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "secret",
            "get",
            "test-secret",
            "--key",
            fingerprint,
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Secret: test-secret"))
        .stdout(predicate::str::contains("Version: 1"))
        .stdout(predicate::str::contains("Data: my-secret-value"));
}

#[test]
fn test_secret_list() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Store multiple secrets
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "secret",
            "store",
            "secret1",
            "--stdin",
            "--description",
            "First secret",
        ])
        .write_stdin("value1")
        .assert()
        .success();

    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "secret",
            "store",
            "secret2",
            "--stdin",
            "--description",
            "Second secret",
        ])
        .write_stdin("value2")
        .assert()
        .success();

    // List secrets
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Secrets:"))
        .stdout(predicate::str::contains("secret1"))
        .stdout(predicate::str::contains("secret2"))
        .stdout(predicate::str::contains("First secret"))
        .stdout(predicate::str::contains("Second secret"));
}

#[test]
fn test_secret_versions() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add host key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "testhost", ssh_key.to_str().unwrap()])
        .assert()
        .success();

    // Store same secret multiple times to create versions
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "store", "versioned-secret", "--stdin"])
        .write_stdin("version1")
        .assert()
        .success();

    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "store", "versioned-secret", "--stdin"])
        .write_stdin("version2")
        .assert()
        .success();

    // Check versions
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "versions", "versioned-secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Versions of secret 'versioned-secret'",
        ))
        .stdout(predicate::str::contains("Version"))
        .stdout(predicate::str::contains("1"))
        .stdout(predicate::str::contains("2"));
}

#[test]
fn test_error_handling_missing_database() {
    // Test command on non-existent directory should fail
    Command::cargo_bin("lilvault")
        .unwrap()
        .args(&["--database", "/nonexistent/path/vault.db"])
        .args(&["vault", "list"])
        .assert()
        .failure();
}

#[test]
fn test_error_handling_uninitialized_vault() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("empty.db");

    // Try to use vault commands without initialization
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["vault", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Vault not initialized"));

    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Vault not initialized"));

    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["secret", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Vault not initialized"));
}

#[test]
fn test_error_handling_invalid_ssh_key() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password123");
    let invalid_key = temp.child("invalid_key.pub");
    invalid_key.write_str("not-a-valid-ssh-key").unwrap();

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&[
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Try to add invalid SSH key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(&["host", "add", "badhost", invalid_key.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_help_commands() {
    // Test main help
    Command::cargo_bin("lilvault")
        .unwrap()
        .args(&["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "A secure, encrypted secrets management system",
        ));

    // Test subcommand help
    Command::cargo_bin("lilvault")
        .unwrap()
        .args(&["vault", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault key management"));

    Command::cargo_bin("lilvault")
        .unwrap()
        .args(&["host", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Host key management"));

    Command::cargo_bin("lilvault")
        .unwrap()
        .args(&["secret", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Secret management"));
}
