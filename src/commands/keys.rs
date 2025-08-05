use dialoguer::Select;
use lilvault::cli::KeyCommands;
use lilvault::crypto::{
    decrypt_master_key, decrypt_with_identity, encrypt_for_recipients, generate_fingerprint,
    generate_master_key, get_password, get_password_with_confirmation, host_key_to_recipient,
    parse_ssh_public_key, vault_key_to_recipient,
};
use lilvault::db::{
    Database,
    models::{Key, SecretStorage},
};
use miette::{IntoDiagnostic, Result};
use std::fs;
use std::path::Path;
use tabled::{Table, Tabled};
use tracing::{error, info, warn};

#[derive(Tabled)]
struct KeyTableRow {
    #[tabled(rename = "Fingerprint")]
    fingerprint: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    key_type: String,
    #[tabled(rename = "Created")]
    created: String,
}

/// Handle keys commands
pub async fn handle_keys(db: &Database, command: KeyCommands) -> Result<()> {
    match command {
        KeyCommands::AddVault {
            name,
            password_file,
            no_reencrypt,
        } => handle_add_vault(db, name, password_file.as_deref(), no_reencrypt).await,

        KeyCommands::AddHost {
            hostname,
            key_path,
            no_reencrypt,
            password_file,
        } => {
            handle_add_host(
                db,
                hostname,
                key_path,
                no_reencrypt,
                password_file.as_deref(),
            )
            .await
        }

        KeyCommands::ScanHost {
            hostname,
            port,
            key_types,
            timeout: _,
        } => handle_scan_host(db, hostname, port, key_types).await,

        KeyCommands::List { key_type } => handle_list(db, key_type).await,

        KeyCommands::Remove { identifier } => handle_remove(db, identifier).await,
    }
}

async fn handle_add_vault(
    db: &Database,
    name: String,
    password_file: Option<&Path>,
    no_reencrypt: bool,
) -> Result<()> {
    // Get password
    let password =
        get_password_with_confirmation("Enter password for new vault key", password_file, true)
            .into_diagnostic()?;

    // Generate vault key
    let (public_key, encrypted_private_key) = generate_master_key(&password).into_diagnostic()?;
    let fingerprint = generate_fingerprint(&public_key);

    // Create vault key record
    let vault_key = Key::new_vault_key(
        fingerprint.clone(),
        name.clone(),
        public_key.clone(),
        encrypted_private_key,
    );

    // Store in database
    db.insert_key(&vault_key).await.into_diagnostic()?;

    // Re-encrypt existing secrets for the new vault key (unless disabled)
    if !no_reencrypt {
        let all_vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
        let mut all_keys = all_vault_keys.clone();
        all_keys.extend(all_host_keys);
        reencrypt_secrets_for_new_key(db, &vault_key, &all_vault_keys, &all_keys, password_file)
            .await?;
    } else {
        info!("Skipping re-encryption due to --no-reencrypt flag");
    }

    // Log audit entry
    db.log_audit(
        "ADD_VAULT_KEY",
        &name,
        Some(&format!("Added vault key with fingerprint {fingerprint}")),
        None,
        true,
        None,
    )
    .await
    .into_diagnostic()?;

    info!("✓ Vault key added successfully!");
    info!("  Name: {name}");
    info!("  Fingerprint: {fingerprint}");

    Ok(())
}

async fn handle_add_host(
    db: &Database,
    hostname: String,
    key_path: std::path::PathBuf,
    no_reencrypt: bool,
    password_file: Option<&Path>,
) -> Result<()> {
    // Check if hostname already exists
    if db
        .get_host_key_by_hostname(&hostname)
        .await
        .into_diagnostic()?
        .is_some()
    {
        error!("Host '{hostname}' already exists");
        std::process::exit(1);
    }

    // Read SSH public key file
    let ssh_public_key = fs::read_to_string(&key_path)
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                "Failed to read SSH key file '{}': {}",
                key_path.display(),
                e
            )
        })?;

    let ssh_public_key = ssh_public_key.trim();

    // Parse and validate SSH public key
    let _ssh_recipient = parse_ssh_public_key(ssh_public_key).into_diagnostic()?;
    let fingerprint = generate_fingerprint(ssh_public_key);

    // Create host key record
    let host_key = Key::new_host_key(
        fingerprint.clone(),
        hostname.clone(),
        ssh_public_key.to_string(),
    );

    // Store in database
    db.insert_key(&host_key).await.into_diagnostic()?;

    // Re-encrypt existing secrets for the new host key (unless disabled)
    if !no_reencrypt {
        let all_vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
        let mut all_keys = all_vault_keys.clone();
        all_keys.extend(all_host_keys);
        reencrypt_secrets_for_new_key(db, &host_key, &all_vault_keys, &all_keys, password_file)
            .await?;
    } else {
        info!("Skipping re-encryption due to --no-reencrypt flag");
    }

    // Log audit entry
    db.log_audit(
        "ADD_HOST_KEY",
        &hostname,
        Some(&format!("Added host key with fingerprint {fingerprint}")),
        None,
        true,
        None,
    )
    .await
    .into_diagnostic()?;

    info!("✓ Host key added successfully!");
    info!("  Hostname: {hostname}");
    info!("  Fingerprint: {fingerprint}");
    info!("  Key file: {}", key_path.display());

    Ok(())
}

async fn handle_scan_host(
    db: &Database,
    hostname: String,
    port: u16,
    key_types: String,
) -> Result<()> {
    use std::process::Command;

    info!(
        "Scanning host {} on port {} for SSH keys...",
        hostname, port
    );

    // Parse key types
    let types: Vec<&str> = key_types.split(',').map(|s| s.trim()).collect();
    let mut collected_keys = Vec::new();

    for key_type in types {
        let key_type = match key_type.to_lowercase().as_str() {
            "rsa" => "rsa",
            "ecdsa" => "ecdsa",
            "ed25519" => "ed25519",
            _ => {
                warn!("Unsupported key type '{}', skipping", key_type);
                continue;
            }
        };

        info!("  Scanning for {} keys...", key_type);

        // Use ssh-keyscan to get the key
        let output = Command::new("ssh-keyscan")
            .arg("-p")
            .arg(port.to_string())
            .arg("-t")
            .arg(key_type)
            .arg(&hostname)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    for line in stdout.lines() {
                        if !line.is_empty() && !line.starts_with('#') {
                            // Parse the ssh-keyscan output format: "hostname keytype key"
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 3 {
                                let public_key = format!("{} {}", parts[1], parts[2]);
                                collected_keys.push((key_type.to_string(), public_key));
                                info!("    Found {} key", key_type);
                            }
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    warn!(
                        "    Failed to scan for {} keys: {}",
                        key_type,
                        stderr.trim()
                    );
                }
            }
            Err(e) => {
                error!(
                    "Failed to run ssh-keyscan: {}. Make sure ssh-keyscan is installed.",
                    e
                );
                std::process::exit(1);
            }
        }
    }

    if collected_keys.is_empty() {
        error!("No SSH keys found for host {}", hostname);
        std::process::exit(1);
    }

    info!(
        "Found {} SSH keys for host {}",
        collected_keys.len(),
        hostname
    );

    // Check if hostname already exists
    if db
        .get_host_key_by_hostname(&hostname)
        .await
        .into_diagnostic()?
        .is_some()
    {
        error!("Host '{}' already exists", hostname);
        std::process::exit(1);
    }

    // If multiple keys found, let user choose (or take the first one)
    let (selected_key_type, selected_public_key) = if collected_keys.len() == 1 {
        collected_keys.into_iter().next().unwrap()
    } else {
        info!("Multiple keys found. Selecting keys in preference order: ed25519, ecdsa, rsa");

        // Prefer ed25519, then ecdsa, then rsa
        let preference_order = ["ed25519", "ecdsa", "rsa"];
        let mut selected = None;

        for preferred in &preference_order {
            if let Some(key) = collected_keys.iter().find(|(t, _)| t == preferred) {
                selected = Some(key.clone());
                break;
            }
        }

        selected.unwrap_or_else(|| collected_keys.into_iter().next().unwrap())
    };

    info!("Selected {} key for import", selected_key_type);

    // Parse and validate SSH public key
    let _ssh_recipient = parse_ssh_public_key(&selected_public_key).into_diagnostic()?;
    let fingerprint = generate_fingerprint(&selected_public_key);

    // Create host key record
    let host_key = Key::new_host_key(fingerprint.clone(), hostname.clone(), selected_public_key);

    // Store in database
    db.insert_key(&host_key).await.into_diagnostic()?;

    // Log audit entry
    db.log_audit(
        "SCAN_HOST_KEY",
        &hostname,
        Some(&format!(
            "Scanned and added {selected_key_type} key with fingerprint {fingerprint}"
        )),
        None,
        true,
        None,
    )
    .await
    .into_diagnostic()?;

    info!("✓ Host key imported successfully!");
    info!("  Hostname: {}", hostname);
    info!("  Key type: {}", selected_key_type);
    info!("  Fingerprint: {}", fingerprint);

    Ok(())
}

async fn handle_list(db: &Database, key_type: Option<String>) -> Result<()> {
    let keys = if let Some(filter_type) = key_type {
        if filter_type == "vault" {
            db.get_all_vault_keys().await.into_diagnostic()?
        } else if filter_type == "host" {
            db.get_all_host_keys().await.into_diagnostic()?
        } else {
            error!("Invalid key type '{}'. Use 'vault' or 'host'", filter_type);
            std::process::exit(1);
        }
    } else {
        // Show all keys
        let mut all_keys = db.get_all_vault_keys().await.into_diagnostic()?;
        let mut host_keys = db.get_all_host_keys().await.into_diagnostic()?;
        all_keys.append(&mut host_keys);
        all_keys.sort_by(|a, b| a.name.cmp(&b.name));
        all_keys
    };

    if keys.is_empty() {
        info!("No keys found.");
        return Ok(());
    }

    let table_data: Vec<KeyTableRow> = keys
        .into_iter()
        .map(|key| KeyTableRow {
            fingerprint: key.fingerprint,
            name: key.name,
            key_type: key.key_type,
            created: key.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        })
        .collect();

    let table = Table::new(table_data);
    println!("{table}");

    Ok(())
}

async fn handle_remove(db: &Database, identifier: String) -> Result<()> {
    // Check if this is a vault key and if it's the last one
    if let Some(key) = db.get_key(&identifier).await.into_diagnostic()? {
        if key.key_type == "vault" {
            let vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
            if vault_keys.len() <= 1 {
                error!("Cannot remove the last vault key. At least one vault key must remain.");
                std::process::exit(1);
            }
        }
    }

    // Try to remove as vault key first, then host key
    let removed_vault = db.remove_vault_key(&identifier).await.into_diagnostic()?;
    let removed_host = if !removed_vault {
        db.remove_host_key_by_hostname(&identifier)
            .await
            .into_diagnostic()?
            || db
                .remove_host_key_by_fingerprint(&identifier)
                .await
                .into_diagnostic()?
    } else {
        false
    };

    if removed_vault || removed_host {
        let key_type = if removed_vault { "vault" } else { "host" };
        let operation = if removed_vault {
            "REMOVE_VAULT_KEY"
        } else {
            "REMOVE_HOST_KEY"
        };

        // Log audit entry
        db.log_audit(
            operation,
            &identifier,
            Some(&format!("{key_type} key removed")),
            None,
            true,
            None,
        )
        .await
        .into_diagnostic()?;

        info!("✓ {} key removed: {}", key_type, identifier);
    } else {
        error!("Key not found: {}", identifier);
        std::process::exit(1);
    }

    Ok(())
}

/// Re-encrypt all existing secrets for a new key
async fn reencrypt_secrets_for_new_key(
    db: &Database,
    new_key: &Key,
    vault_keys: &[Key],
    all_keys: &[Key],
    password_file: Option<&Path>,
) -> Result<()> {
    info!(
        "🔄 Creating new versions of existing secrets for new key: {}",
        new_key.name
    );

    // Get all secrets that need re-encryption
    let secret_names = db.get_secrets_for_reencryption().await.into_diagnostic()?;

    if secret_names.is_empty() {
        info!("No existing secrets to re-encrypt");
        return Ok(());
    }

    info!(
        "Found {} secret(s) to create new versions for",
        secret_names.len()
    );

    // Select which vault key to use for decryption
    let selected_vault_key = if vault_keys.len() == 1 {
        &vault_keys[0]
    } else {
        // Multiple vault keys - let user choose (or use first if non-interactive)
        let key_options: Vec<String> = vault_keys
            .iter()
            .map(|k| format!("{} ({})", k.name, &k.fingerprint[..8]))
            .collect();

        match Select::new()
            .with_prompt("Select vault key to use for re-encryption")
            .items(&key_options)
            .default(0)
            .interact()
        {
            Ok(selection) => &vault_keys[selection],
            Err(_) => {
                // Non-interactive environment - use first vault key
                info!("Non-interactive environment detected, using first vault key");
                &vault_keys[0]
            }
        }
    };

    info!(
        "Using vault key '{}' for re-encryption",
        selected_vault_key.name
    );

    // Get password for the selected vault key (only once)
    let password = get_password(
        &format!(
            "Enter password for vault key '{}' to decrypt secrets for new version creation",
            selected_vault_key.name
        ),
        password_file,
    )
    .into_diagnostic()?;

    // Decrypt the selected vault key identity (only once)
    let identity = decrypt_master_key(
        selected_vault_key
            .encrypted_private_key
            .as_ref()
            .expect("Vault key should have private key"),
        &password,
    )
    .into_diagnostic()?;

    let mut new_versions_created = 0;

    for secret_name in &secret_names {
        info!("Processing secret: {secret_name}");

        // Get the latest version of this secret to use as source
        let latest_version = match db
            .get_latest_secret_version(secret_name)
            .await
            .into_diagnostic()?
        {
            Some(v) => v,
            None => {
                warn!("  No versions found for secret {secret_name}, skipping");
                continue;
            }
        };

        // Get a copy we can decrypt from the latest version using our selected vault key
        let source_copy = db
            .get_decryptable_secret_copy(
                secret_name,
                latest_version,
                &[selected_vault_key.fingerprint.clone()],
            )
            .await
            .into_diagnostic()?;

        let source_copy = match source_copy {
            Some(copy) => copy,
            None => {
                warn!(
                    "  No decryptable copy found for latest version with selected vault key, skipping"
                );
                continue;
            }
        };

        // Decrypt the secret data using our pre-decrypted identity
        let decrypted_data =
            decrypt_with_identity(&source_copy.encrypted_data, &identity).into_diagnostic()?;

        // Get the next version number for this secret
        let new_version = db
            .get_next_secret_version(secret_name)
            .await
            .into_diagnostic()?;

        // Create recipients for ALL keys (existing + new key)
        let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

        for key in all_keys {
            let recipient = match key.key_type.as_str() {
                "vault" => vault_key_to_recipient(&key.public_key).into_diagnostic()?,
                "host" => host_key_to_recipient(&key.public_key).into_diagnostic()?,
                _ => {
                    error!("Unknown key type: {}", key.key_type);
                    continue;
                }
            };
            recipients.push(recipient);
        }

        // Encrypt the secret for all recipients
        let encrypted_data =
            encrypt_for_recipients(&decrypted_data, recipients).into_diagnostic()?;

        // Store encrypted copies for each key
        let mut stored_count = 0;
        for key in all_keys {
            let new_storage = SecretStorage::new(
                secret_name.clone(),
                new_version,
                key.fingerprint.clone(),
                key.key_type.clone(),
                encrypted_data.clone(),
            );

            db.insert_secret_storage(&new_storage)
                .await
                .into_diagnostic()?;
            stored_count += 1;
        }

        // Log audit entry for this specific secret's new version
        db.log_audit(
            "CREATE_SECRET_VERSION",
            secret_name,
            Some(&format!(
                "Created version {new_version} with encryption for new key '{}' (total {} keys)",
                new_key.name,
                all_keys.len()
            )),
            Some(new_version),
            true,
            None,
        )
        .await
        .into_diagnostic()?;

        info!("  ✓ Created version {new_version} encrypted for {stored_count} keys");
        new_versions_created += 1;
    }

    info!(
        "✅ Re-encryption complete: {} new secret versions created",
        new_versions_created
    );

    // Log the overall re-encryption operation
    db.log_audit(
        "REENCRYPT_FOR_NEW_KEY",
        &format!("new_key:{}", new_key.fingerprint),
        Some(&format!(
            "Created new versions of {new_versions_created} secrets for new key '{}'",
            new_key.name
        )),
        None,
        true,
        None,
    )
    .await
    .into_diagnostic()?;

    Ok(())
}
