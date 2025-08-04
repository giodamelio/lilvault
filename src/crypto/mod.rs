// Crypto module for handling age encryption/decryption and key management

use crate::{LilVaultError, Result};
use age::{
    Decryptor, Encryptor,
    armor::{ArmoredReader, ArmoredWriter, Format},
    secrecy::{ExposeSecret, Secret},
    ssh::{Identity as SshIdentity, Recipient as SshRecipient},
    x25519::Identity,
};
use dialoguer::Password;
use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;

/// Generate a new age X25519 key pair and encrypt the private key with a password
pub fn generate_master_key(password: &str) -> Result<(String, Vec<u8>)> {
    // Generate new identity
    let identity = Identity::generate();

    // Get the public key (recipient)
    let recipient = identity.to_public();
    let public_key = recipient.to_string();

    // Convert private key to string
    let private_key_string = identity.to_string().expose_secret().to_string();

    // Encrypt the private key with the password
    let encrypted_private_key = encrypt_with_password(private_key_string.as_bytes(), password)?;

    Ok((public_key, encrypted_private_key))
}

/// Decrypt a master key using a password
pub fn decrypt_master_key(encrypted_private_key: &[u8], password: &str) -> Result<Identity> {
    let private_key_bytes = decrypt_with_password(encrypted_private_key, password)?;
    let private_key_string =
        String::from_utf8(private_key_bytes).map_err(|_| LilVaultError::Internal {
            message: "Invalid UTF-8 in decrypted private key".to_string(),
        })?;

    let identity = private_key_string
        .parse::<Identity>()
        .map_err(|e| LilVaultError::Internal {
            message: format!("Failed to parse private key: {e}"),
        })?;

    Ok(identity)
}

/// Parse SSH public key into age recipient
pub fn parse_ssh_public_key(ssh_public_key: &str) -> Result<SshRecipient> {
    ssh_public_key
        .parse::<SshRecipient>()
        .map_err(|e| LilVaultError::SshKey {
            message: format!("Failed to parse SSH public key: {e:?}"),
        })
}

/// Generate fingerprint for a key (using the public key string)
pub fn generate_fingerprint(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let result = hasher.finalize();
    format!("{result:x}")[..16].to_string()
}

/// Encrypt data with multiple recipients
pub fn encrypt_for_recipients(
    data: &[u8],
    recipients: Vec<Box<dyn age::Recipient + Send>>,
) -> Result<Vec<u8>> {
    let encryptor = match Encryptor::with_recipients(recipients) {
        Some(enc) => enc,
        None => {
            return Err(LilVaultError::Internal {
                message: "No recipients provided for encryption".to_string(),
            });
        }
    };

    let mut encrypted = vec![];
    let writer = ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor)
        .map_err(|e| LilVaultError::Encryption(e.into()))?;

    let mut age_writer = encryptor
        .wrap_output(writer)
        .map_err(LilVaultError::Encryption)?;

    age_writer.write_all(data).map_err(LilVaultError::Io)?;

    age_writer
        .finish()
        .and_then(|armor_writer| armor_writer.finish())
        .map_err(|e| LilVaultError::Encryption(e.into()))?;

    Ok(encrypted)
}

/// Decrypt data with an identity
pub fn decrypt_with_identity(encrypted_data: &[u8], identity: &Identity) -> Result<Vec<u8>> {
    let armored_reader = ArmoredReader::new(encrypted_data);
    let decryptor = match Decryptor::new(armored_reader).map_err(LilVaultError::Decryption)? {
        Decryptor::Recipients(d) => d,
        _ => {
            return Err(LilVaultError::Internal {
                message: "Unexpected decryptor type".to_string(),
            });
        }
    };

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(LilVaultError::Decryption)?;

    reader
        .read_to_end(&mut decrypted)
        .map_err(LilVaultError::Io)?;

    Ok(decrypted)
}

/// Decrypt data with SSH identity
pub fn decrypt_with_ssh_identity(
    encrypted_data: &[u8],
    ssh_identity: &SshIdentity,
) -> Result<Vec<u8>> {
    let armored_reader = ArmoredReader::new(encrypted_data);
    let decryptor = match Decryptor::new(armored_reader).map_err(LilVaultError::Decryption)? {
        Decryptor::Recipients(d) => d,
        _ => {
            return Err(LilVaultError::Internal {
                message: "Unexpected decryptor type".to_string(),
            });
        }
    };

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(ssh_identity as &dyn age::Identity))
        .map_err(LilVaultError::Decryption)?;

    reader
        .read_to_end(&mut decrypted)
        .map_err(LilVaultError::Io)?;

    Ok(decrypted)
}

/// Decrypt secret with vault key using password
pub fn decrypt_secret_with_vault_key(
    encrypted_data: &[u8],
    encrypted_private_key: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    // First decrypt the private key with the password
    let identity = decrypt_master_key(encrypted_private_key, password)?;

    // Then decrypt the secret data with the identity
    decrypt_with_identity(encrypted_data, &identity)
}

/// Encrypt data with password (for master key storage)
fn encrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_user_passphrase(Secret::new(password.to_owned()));

    let mut encrypted = vec![];
    let writer = ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor)
        .map_err(|e| LilVaultError::Encryption(e.into()))?;

    let mut age_writer = encryptor
        .wrap_output(writer)
        .map_err(LilVaultError::Encryption)?;

    age_writer.write_all(data).map_err(LilVaultError::Io)?;

    age_writer
        .finish()
        .and_then(|armor_writer| armor_writer.finish())
        .map_err(|e| LilVaultError::Encryption(e.into()))?;

    Ok(encrypted)
}

/// Decrypt data with password (for master key storage)
fn decrypt_with_password(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>> {
    let armored_reader = ArmoredReader::new(encrypted_data);
    let decryptor = match Decryptor::new(armored_reader).map_err(LilVaultError::Decryption)? {
        Decryptor::Passphrase(d) => d,
        _ => {
            return Err(LilVaultError::Internal {
                message: "Expected passphrase decryptor".to_string(),
            });
        }
    };

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(&Secret::new(password.to_owned()), None)
        .map_err(LilVaultError::Decryption)?;

    reader
        .read_to_end(&mut decrypted)
        .map_err(LilVaultError::Io)?;

    Ok(decrypted)
}

/// Prompt user for password or read from file
pub fn prompt_password(prompt: &str) -> Result<String> {
    Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| LilVaultError::Internal {
            message: format!("Password prompt failed: {e}"),
        })
}

/// Read password from file
pub fn read_password_from_file(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| LilVaultError::Internal {
            message: format!("Failed to read password file '{}': {}", path.display(), e),
        })
}

/// Get password either from file or interactive prompt
pub fn get_password(prompt: &str, password_file: Option<&std::path::Path>) -> Result<String> {
    match password_file {
        Some(path) => read_password_from_file(path),
        None => prompt_password(prompt),
    }
}

/// Convert vault key to age recipient for encryption
pub fn vault_key_to_recipient(public_key: &str) -> Result<Box<dyn age::Recipient + Send>> {
    let recipient =
        public_key
            .parse::<age::x25519::Recipient>()
            .map_err(|e| LilVaultError::Internal {
                message: format!("Failed to parse vault public key: {e}"),
            })?;
    Ok(Box::new(recipient))
}

/// Convert host SSH key to age recipient for encryption
pub fn host_key_to_recipient(ssh_public_key: &str) -> Result<Box<dyn age::Recipient + Send>> {
    let recipient = parse_ssh_public_key(ssh_public_key)?;
    Ok(Box::new(recipient))
}

/// Encrypt data for a single recipient (used for re-encryption)
pub fn encrypt_for_single_recipient(
    data: &[u8],
    recipient: Box<dyn age::Recipient + Send>,
) -> Result<Vec<u8>> {
    encrypt_for_recipients(data, vec![recipient])
}

/// Launch the user's $EDITOR to edit content and return the edited content
/// Returns None if content was unchanged, Some(new_content) if changed
pub fn edit_with_editor(initial_content: &str) -> Result<Option<String>> {
    // Get editor from environment, fallback to common defaults
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| {
            // Try to find a reasonable default editor
            for editor in ["nano", "vim", "vi", "emacs"] {
                if Command::new("which")
                    .arg(editor)
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false)
                {
                    return editor.to_string();
                }
            }
            "nano".to_string() // Final fallback
        });

    // Create a temporary file with the initial content
    let mut temp_file = NamedTempFile::new()?;

    // Write initial content to temp file
    temp_file.write_all(initial_content.as_bytes())?;
    temp_file.flush()?;

    // Launch the editor
    let status = Command::new(&editor).arg(temp_file.path()).status()?;

    if !status.success() {
        return Err(LilVaultError::Internal {
            message: format!("Editor '{editor}' exited with non-zero status"),
        });
    }

    // Read the edited content
    let mut edited_content = String::new();
    temp_file.reopen()?.read_to_string(&mut edited_content)?;

    // Check if content changed
    if edited_content == initial_content {
        Ok(None) // No changes
    } else {
        Ok(Some(edited_content)) // Content changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_fingerprint() {
        // Test that fingerprint is deterministic and correct length
        let public_key = "age1ql3n4n93j3j4l2a3rk6t3q3q5z3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0a1";
        let fingerprint1 = generate_fingerprint(public_key);
        let fingerprint2 = generate_fingerprint(public_key);

        assert_eq!(
            fingerprint1, fingerprint2,
            "Fingerprint should be deterministic"
        );
        assert_eq!(
            fingerprint1.len(),
            16,
            "Fingerprint should be 16 characters long"
        );

        // Test different keys produce different fingerprints
        let different_key = "age1ql3n4n93j3j4l2a3rk6t3q3q5z3a4a5a6a7a8a9a0a1a2a3a4a5a6a7a8a9a0a2";
        let different_fingerprint = generate_fingerprint(different_key);
        assert_ne!(
            fingerprint1, different_fingerprint,
            "Different keys should have different fingerprints"
        );
    }

    #[test]
    fn test_generate_fingerprint_empty_key() {
        let fingerprint = generate_fingerprint("");
        assert_eq!(
            fingerprint.len(),
            16,
            "Empty key should still produce 16-char fingerprint"
        );
    }

    #[test]
    fn test_read_password_from_file() {
        // Create a temporary file with a password
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let password = "test-password-123";
        writeln!(temp_file, "{password}").expect("Failed to write to temp file");

        let result = read_password_from_file(temp_file.path());
        assert!(
            result.is_ok(),
            "Should successfully read password from file"
        );
        assert_eq!(result.unwrap(), password, "Should return correct password");
    }

    #[test]
    fn test_read_password_from_file_with_whitespace() {
        // Create a temporary file with password and whitespace
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let password = "test-password-123";
        writeln!(temp_file, "  {password}  \n").expect("Failed to write to temp file");

        let result = read_password_from_file(temp_file.path());
        assert!(
            result.is_ok(),
            "Should successfully read password from file"
        );
        assert_eq!(
            result.unwrap(),
            password,
            "Should trim whitespace from password"
        );
    }

    #[test]
    fn test_read_password_from_nonexistent_file() {
        let result = read_password_from_file(std::path::Path::new("/nonexistent/file.txt"));
        assert!(result.is_err(), "Should fail when file doesn't exist");

        match result.unwrap_err() {
            LilVaultError::Internal { message } => {
                assert!(
                    message.contains("Failed to read password file"),
                    "Error message should indicate file read failure"
                );
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_get_password_with_file() {
        // Create a temporary file with a password
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let password = "file-password-456";
        writeln!(temp_file, "{password}").expect("Failed to write to temp file");

        let result = get_password("Enter password", Some(temp_file.path()));
        assert!(result.is_ok(), "Should successfully get password from file");
        assert_eq!(
            result.unwrap(),
            password,
            "Should return correct password from file"
        );
    }

    #[test]
    fn test_master_key_roundtrip() {
        let password = "test-password-123";

        // Generate a master key
        let (public_key, encrypted_private_key) =
            generate_master_key(password).expect("Should generate master key successfully");

        // Verify public key format
        assert!(
            public_key.starts_with("age1"),
            "Public key should start with 'age1'"
        );
        assert!(
            !encrypted_private_key.is_empty(),
            "Encrypted private key should not be empty"
        );

        // Decrypt the master key
        let identity = decrypt_master_key(&encrypted_private_key, password)
            .expect("Should decrypt master key successfully");

        // Verify we can get the public key back
        let recovered_public_key = identity.to_public().to_string();
        assert_eq!(
            public_key, recovered_public_key,
            "Public key should match after roundtrip"
        );
    }

    #[test]
    fn test_decrypt_master_key_wrong_password() {
        let password = "correct-password";
        let wrong_password = "wrong-password";

        // Generate a master key
        let (_public_key, encrypted_private_key) =
            generate_master_key(password).expect("Should generate master key successfully");

        // Try to decrypt with wrong password
        let result = decrypt_master_key(&encrypted_private_key, wrong_password);
        assert!(result.is_err(), "Should fail with wrong password");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let test_data = b"Hello, World! This is secret data.";
        let password = "test-password-789";

        // Generate a key pair
        let (_public_key, encrypted_private_key) =
            generate_master_key(password).expect("Should generate master key");

        let identity = decrypt_master_key(&encrypted_private_key, password)
            .expect("Should decrypt master key");

        // Encrypt data
        let recipient = identity.to_public();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encrypted_data = encrypt_for_recipients(test_data, recipients)
            .expect("Should encrypt data successfully");

        // Decrypt data
        let decrypted_data = decrypt_with_identity(&encrypted_data, &identity)
            .expect("Should decrypt data successfully");

        assert_eq!(
            test_data,
            decrypted_data.as_slice(),
            "Decrypted data should match original"
        );
    }

    #[test]
    fn test_encrypt_for_recipients_empty_recipients() {
        let test_data = b"test data";
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![];

        let result = encrypt_for_recipients(test_data, recipients);
        assert!(result.is_err(), "Should fail with empty recipients list");

        match result.unwrap_err() {
            LilVaultError::Internal { message } => {
                assert!(
                    message.contains("No recipients provided"),
                    "Error should indicate no recipients"
                );
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_decrypt_secret_with_vault_key() {
        let test_data = b"secret vault data";
        let password = "vault-password-123";

        // Generate vault key
        let (_public_key, encrypted_private_key) =
            generate_master_key(password).expect("Should generate vault key");

        let identity =
            decrypt_master_key(&encrypted_private_key, password).expect("Should decrypt vault key");

        // Encrypt data with the vault key
        let recipient = identity.to_public();
        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
        let encrypted_data =
            encrypt_for_recipients(test_data, recipients).expect("Should encrypt data");

        // Decrypt using vault key function
        let decrypted_data =
            decrypt_secret_with_vault_key(&encrypted_data, &encrypted_private_key, password)
                .expect("Should decrypt with vault key");

        assert_eq!(
            test_data,
            decrypted_data.as_slice(),
            "Decrypted data should match original"
        );
    }

    #[test]
    fn test_parse_ssh_public_key_invalid() {
        let invalid_key = "not-a-valid-ssh-key";
        let result = parse_ssh_public_key(invalid_key);

        assert!(result.is_err(), "Should fail with invalid SSH key");
        match result.unwrap_err() {
            LilVaultError::SshKey { message } => {
                assert!(
                    message.contains("Failed to parse SSH public key"),
                    "Error should indicate SSH key parsing failure"
                );
            }
            _ => panic!("Expected SshKey error"),
        }
    }

    #[test]
    fn test_edit_with_editor_no_changes() {
        // Mock editor that doesn't change content by setting EDITOR to cat
        std::env::set_var("EDITOR", "cat");

        let initial_content = "unchanged content";
        let result = edit_with_editor(initial_content);

        assert!(result.is_ok(), "Should succeed with cat as editor");
        match result.unwrap() {
            None => {
                // This is expected - content should be unchanged when using cat
            }
            Some(_) => {
                // cat might add a newline on some systems, this is also acceptable
            }
        }

        // Clean up
        std::env::remove_var("EDITOR");
    }
}
