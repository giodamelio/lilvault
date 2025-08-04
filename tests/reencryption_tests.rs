use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command as StdCommand;

/// Helper function to create a test SSH public key by generating it with ssh-keygen
fn create_test_ssh_key(temp_dir: &assert_fs::TempDir) -> assert_fs::fixture::ChildPath {
    let key_path = temp_dir.child("test_key");
    let pub_key_path = temp_dir.child("test_key.pub");

    // Generate SSH key pair using ssh-keygen
    let output = StdCommand::new("ssh-keygen")
        .args([
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
    cmd.args(["--database", db_path]);
    cmd
}

/// Helper function to create a password file
fn create_password_file(
    temp_dir: &assert_fs::TempDir,
    filename: &str,
    password: &str,
) -> assert_fs::fixture::ChildPath {
    let password_file = temp_dir.child(filename);
    password_file.write_str(password).unwrap();
    password_file
}

#[test]
fn test_reencryption_single_vault_key() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password1.txt", "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Store a secret
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "store", "test-secret", "--stdin"])
        .write_stdin("my-secret-data")
        .assert()
        .success();

    // Add host key - should trigger re-encryption
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "keys",
            "add-host",
            "testhost",
            ssh_key.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Creating new versions of existing secrets",
        ));

    // Verify secret has new version by checking info
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "info", "test-secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version History (2 versions):"));
}

#[test]
fn test_reencryption_multiple_vault_keys_with_password_file() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file1 = create_password_file(&temp, "password1.txt", "password123");
    let password_file2 = create_password_file(&temp, "password2.txt", "backup456");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file1.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Add second vault key
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "keys",
            "add-vault",
            "--name",
            "backup",
            "--password-file",
            password_file2.to_str().unwrap(),
            "--no-reencrypt", // Skip re-encryption for now
        ])
        .assert()
        .success();

    // Store a secret
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "store", "test-secret", "--stdin"])
        .write_stdin("my-secret-data")
        .assert()
        .success();

    // Add host key - should trigger re-encryption with vault key selection
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "keys",
            "add-host",
            "testhost",
            ssh_key.to_str().unwrap(),
            "--password-file",
            password_file2.to_str().unwrap(), // Use backup vault key password
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Creating new versions of existing secrets",
        ))
        .stdout(predicate::str::contains(
            "Non-interactive environment detected, using first vault key",
        ));

    // Verify secret has new version
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "info", "test-secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version History (2 versions):"));
}

#[test]
fn test_no_reencrypt_flag() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password1.txt", "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Store a secret
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "store", "test-secret", "--stdin"])
        .write_stdin("my-secret-data")
        .assert()
        .success();

    // Add host key with no-reencrypt flag
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "keys",
            "add-host",
            "testhost",
            ssh_key.to_str().unwrap(),
            "--no-reencrypt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Skipping re-encryption due to --no-reencrypt flag",
        ));

    // Verify secret still has only 1 version
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "info", "test-secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version History (1 versions):"));
}

#[test]
fn test_reencryption_audit_logging() {
    let temp = assert_fs::TempDir::new().unwrap();
    let vault_db = temp.child("test.db");
    let password_file = create_password_file(&temp, "password1.txt", "password123");
    let ssh_key = create_test_ssh_key(&temp);

    // Initialize vault
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "init",
            "--name",
            "primary",
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Store a secret
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["secret", "store", "test-secret", "--stdin"])
        .write_stdin("my-secret-data")
        .assert()
        .success();

    // Add host key to trigger re-encryption
    lilvault_cmd(vault_db.to_str().unwrap())
        .args([
            "keys",
            "add-host",
            "testhost",
            ssh_key.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Check audit log for re-encryption entries
    lilvault_cmd(vault_db.to_str().unwrap())
        .args(["audit", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CREATE_SECRET_VERSION"))
        .stdout(predicate::str::contains("REENCRYPT_FOR_NEW_KEY"));
}
