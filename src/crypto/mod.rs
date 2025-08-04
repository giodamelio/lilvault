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
