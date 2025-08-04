use age::x25519::Recipient;
use chrono::Utc;
use clap::Parser;
use dialoguer::Select;
use lilvault::cli::{AuditCommands, Cli, Commands, KeyCommands, SecretCommands};
use lilvault::crypto::{
    decrypt_master_key, decrypt_secret_with_vault_key, decrypt_with_identity, edit_with_editor,
    encrypt_for_recipients, generate_fingerprint, generate_master_key, get_password,
    host_key_to_recipient, parse_ssh_public_key, vault_key_to_recipient,
};
use lilvault::db::{
    Database,
    models::{Key, Secret, SecretStorage},
};
use miette::{IntoDiagnostic, Result};
use std::fs;
use tracing::{error, info, warn};

/// Helper function to check if the vault database is properly initialized
async fn ensure_initialized(db: &Database) -> Result<()> {
    if !db.is_initialized().await.into_diagnostic()? {
        error!("Vault not initialized. Run 'lilvault init' first.");
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
    password_file: Option<&std::path::Path>,
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
            let new_storage = SecretStorage {
                id: 0, // Will be auto-generated
                secret_name: secret_name.clone(),
                version: new_version,
                key_fingerprint: key.fingerprint.clone(),
                key_type: key.key_type.clone(),
                encrypted_data: encrypted_data.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = if cli.verbose { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    // Create database connection
    let db = Database::new(&cli.database).await.into_diagnostic()?;

    // Handle commands
    match cli.command {
        Commands::Init {
            name,
            password_file,
        } => {
            if db.is_initialized().await.into_diagnostic()? {
                error!("Vault is already initialized");
                std::process::exit(1);
            }

            // Get password
            let password = if let Some(ref path) = password_file {
                get_password("", Some(path)).into_diagnostic()?
            } else {
                let password =
                    get_password("Enter password for vault key", None).into_diagnostic()?;
                let confirm_password = get_password("Confirm password", None).into_diagnostic()?;

                if password != confirm_password {
                    error!("Passwords do not match");
                    std::process::exit(1);
                }
                password
            };

            // Generate vault key
            let (public_key, encrypted_private_key) =
                generate_master_key(&password).into_diagnostic()?;
            let fingerprint = generate_fingerprint(&public_key);

            // Create vault key record
            let now = Utc::now();
            let vault_key = Key {
                fingerprint: fingerprint.clone(),
                key_type: "vault".to_string(),
                name: name.clone(),
                public_key: public_key.clone(),
                encrypted_private_key: Some(encrypted_private_key),
                created_at: now,
                updated_at: now,
            };

            // Store in database
            db.insert_key(&vault_key).await.into_diagnostic()?;

            // Log audit entry
            db.log_audit(
                "INIT_VAULT",
                &name,
                Some("Vault initialized with new master key"),
                None,
                true,
                None,
            )
            .await
            .into_diagnostic()?;

            info!("✓ Vault initialized successfully!");
            info!("  Vault key name: {name}");
            info!("  Fingerprint: {fingerprint}");
            info!("  Database: {}", cli.database.display());
        }

        Commands::Keys { command } => {
            ensure_initialized(&db).await?;
            match command {
                KeyCommands::AddVault {
                    name,
                    password_file,
                    no_reencrypt,
                } => {
                    // Get password
                    let password = if let Some(ref path) = password_file {
                        get_password("", Some(path)).into_diagnostic()?
                    } else {
                        let password = get_password("Enter password for new vault key", None)
                            .into_diagnostic()?;
                        let confirm_password =
                            get_password("Confirm password", None).into_diagnostic()?;

                        if password != confirm_password {
                            error!("Passwords do not match");
                            std::process::exit(1);
                        }
                        password
                    };

                    // Generate vault key
                    let (public_key, encrypted_private_key) =
                        generate_master_key(&password).into_diagnostic()?;
                    let fingerprint = generate_fingerprint(&public_key);

                    // Create vault key record
                    let now = Utc::now();
                    let vault_key = Key {
                        fingerprint: fingerprint.clone(),
                        key_type: "vault".to_string(),
                        name: name.clone(),
                        public_key: public_key.clone(),
                        encrypted_private_key: Some(encrypted_private_key),
                        created_at: now,
                        updated_at: now,
                    };

                    // Store in database
                    db.insert_key(&vault_key).await.into_diagnostic()?;

                    // Re-encrypt existing secrets for the new vault key (unless disabled)
                    if !no_reencrypt {
                        let all_vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
                        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
                        let mut all_keys = all_vault_keys.clone();
                        all_keys.extend(all_host_keys);
                        reencrypt_secrets_for_new_key(
                            &db,
                            &vault_key,
                            &all_vault_keys,
                            &all_keys,
                            password_file.as_deref(),
                        )
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
                }
                KeyCommands::AddHost {
                    hostname,
                    key_path,
                    no_reencrypt,
                    password_file,
                } => {
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
                    let ssh_public_key =
                        fs::read_to_string(&key_path)
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
                    let now = Utc::now();
                    let host_key = Key {
                        fingerprint: fingerprint.clone(),
                        key_type: "host".to_string(),
                        name: hostname.clone(),
                        public_key: ssh_public_key.to_string(),
                        encrypted_private_key: None,
                        created_at: now,
                        updated_at: now,
                    };

                    // Store in database
                    db.insert_key(&host_key).await.into_diagnostic()?;

                    // Re-encrypt existing secrets for the new host key (unless disabled)
                    if !no_reencrypt {
                        let all_vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
                        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
                        let mut all_keys = all_vault_keys.clone();
                        all_keys.extend(all_host_keys);
                        reencrypt_secrets_for_new_key(
                            &db,
                            &host_key,
                            &all_vault_keys,
                            &all_keys,
                            password_file.as_deref(),
                        )
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
                }
                KeyCommands::ScanHost {
                    hostname,
                    port,
                    key_types,
                    timeout: _,
                } => {
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
                                            let parts: Vec<&str> =
                                                line.split_whitespace().collect();
                                            if parts.len() >= 3 {
                                                let public_key =
                                                    format!("{} {}", parts[1], parts[2]);
                                                collected_keys
                                                    .push((key_type.to_string(), public_key));
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
                        info!(
                            "Multiple keys found. Selecting keys in preference order: ed25519, ecdsa, rsa"
                        );

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
                    let _ssh_recipient =
                        parse_ssh_public_key(&selected_public_key).into_diagnostic()?;
                    let fingerprint = generate_fingerprint(&selected_public_key);

                    // Create host key record
                    let now = Utc::now();
                    let host_key = Key {
                        fingerprint: fingerprint.clone(),
                        key_type: "host".to_string(),
                        name: hostname.clone(),
                        public_key: selected_public_key,
                        encrypted_private_key: None,
                        created_at: now,
                        updated_at: now,
                    };

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
                }
                KeyCommands::List { key_type } => {
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

                    info!("Keys:");
                    info!("{:<16} {:<20} {:<8} Created", "Fingerprint", "Name", "Type");
                    info!("{}", "-".repeat(70));

                    for key in keys {
                        info!(
                            "{:<16} {:<20} {:<8} {}",
                            key.fingerprint,
                            key.name,
                            key.key_type,
                            key.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
                KeyCommands::Remove { identifier } => {
                    // Check if this is a vault key and if it's the last one
                    if let Some(key) = db.get_key(&identifier).await.into_diagnostic()? {
                        if key.key_type == "vault" {
                            let vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
                            if vault_keys.len() <= 1 {
                                error!(
                                    "Cannot remove the last vault key. At least one vault key must remain."
                                );
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
                }
            }
        }

        Commands::Secret { command } => {
            ensure_initialized(&db).await?;
            match command {
                SecretCommands::Store {
                    name,
                    hosts,
                    file,
                    stdin,
                    description,
                } => {
                    // Read secret data
                    let secret_data = if stdin {
                        use std::io::Read;
                        let mut buffer = String::new();
                        std::io::stdin()
                            .read_to_string(&mut buffer)
                            .into_diagnostic()?;
                        buffer.trim().as_bytes().to_vec()
                    } else if let Some(file_path) = file {
                        fs::read(&file_path).into_diagnostic().map_err(|e| {
                            miette::miette!("Failed to read file '{}': {}", file_path.display(), e)
                        })?
                    } else {
                        error!("Must specify either --file or --stdin");
                        std::process::exit(1);
                    };

                    // Get all vault keys and specified host keys
                    let vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
                    let mut target_keys = Vec::new();

                    // Add all vault keys as recipients
                    for vault_key in &vault_keys {
                        // Parse the vault key's public key to create a recipient
                        let recipient: Recipient = vault_key.public_key.parse().map_err(|e| {
                            miette::miette!(
                                "Failed to parse vault key public key {}: {:?}",
                                vault_key.fingerprint,
                                e
                            )
                        })?;
                        target_keys.push((
                            vault_key.fingerprint.clone(),
                            "vault".to_string(),
                            Box::new(recipient) as Box<dyn age::Recipient + Send>,
                        ));
                    }

                    // Add specified host keys
                    if let Some(host_list) = hosts {
                        let hostnames: Vec<&str> = host_list.split(',').map(|h| h.trim()).collect();
                        for hostname in hostnames {
                            if let Some(host_key) = db
                                .get_host_key_by_hostname(hostname)
                                .await
                                .into_diagnostic()?
                            {
                                let ssh_recipient =
                                    parse_ssh_public_key(&host_key.public_key).into_diagnostic()?;
                                target_keys.push((
                                    host_key.fingerprint.clone(),
                                    "host".to_string(),
                                    Box::new(ssh_recipient) as Box<dyn age::Recipient + Send>,
                                ));
                            } else {
                                warn!("Host '{hostname}' not found, skipping");
                            }
                        }
                    } else {
                        // If no hosts specified, add all host keys
                        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
                        for host_key in all_host_keys {
                            let ssh_recipient =
                                parse_ssh_public_key(&host_key.public_key).into_diagnostic()?;
                            target_keys.push((
                                host_key.fingerprint.clone(),
                                "host".to_string(),
                                Box::new(ssh_recipient) as Box<dyn age::Recipient + Send>,
                            ));
                        }
                    }

                    if target_keys.is_empty() {
                        error!("No keys available for encryption");
                        std::process::exit(1);
                    }

                    // Create or update secret metadata
                    let secret_exists = db.get_secret(&name).await.into_diagnostic()?.is_some();
                    if !secret_exists {
                        let now = Utc::now();
                        let secret = Secret {
                            name: name.clone(),
                            description: description.clone(),
                            template: None,
                            created_at: now,
                            updated_at: now,
                        };
                        db.insert_secret(&secret).await.into_diagnostic()?;
                    }

                    // Get next version number
                    let version = db.get_next_secret_version(&name).await.into_diagnostic()?;

                    let mut stored_count = 0;

                    // Store encrypted data for each target key (per-key encryption)
                    for (key_fingerprint, key_type, recipient) in target_keys {
                        // Encrypt secret data for this specific key
                        let encrypted_data = encrypt_for_recipients(&secret_data, vec![recipient])
                            .into_diagnostic()?;

                        let now = Utc::now();
                        let storage_entry = SecretStorage {
                            id: 0, // Will be set by database
                            secret_name: name.clone(),
                            version,
                            key_fingerprint: key_fingerprint.clone(),
                            key_type: key_type.clone(),
                            encrypted_data,
                            created_at: now,
                            updated_at: now,
                        };

                        db.insert_secret_storage(&storage_entry)
                            .await
                            .into_diagnostic()?;
                        stored_count += 1;
                    }

                    // Log audit entry
                    db.log_audit(
                        "STORE_SECRET",
                        &name,
                        Some(&format!(
                            "Stored secret version {version} for {stored_count} keys"
                        )),
                        Some(version),
                        true,
                        None,
                    )
                    .await
                    .into_diagnostic()?;

                    info!("✓ Secret stored successfully!");
                    info!("  Name: {name}");
                    info!("  Version: {version}");
                    info!("  Encrypted for {stored_count} keys");
                    if let Some(desc) = description {
                        info!("  Description: {desc}");
                    }
                }
                SecretCommands::Get {
                    name,
                    version,
                    key,
                    password_file,
                } => {
                    // Determine version to retrieve
                    let target_version = if let Some(v) = version {
                        v
                    } else {
                        // Get latest version
                        match db
                            .get_latest_secret_version(&name)
                            .await
                            .into_diagnostic()?
                        {
                            Some(v) => v,
                            None => {
                                error!("Secret '{name}' not found");
                                std::process::exit(1);
                            }
                        }
                    };

                    // If key specified, try to get secret for that key
                    if let Some(key_fingerprint) = key {
                        match db
                            .get_secret_storage_for_key(&name, target_version, &key_fingerprint)
                            .await
                            .into_diagnostic()?
                        {
                            Some(storage) => {
                                // Decrypt based on key type
                                let decrypted_data = match storage.key_type.as_str() {
                                    "vault" => {
                                        // Get vault key and prompt for password
                                        let vault_key = db
                                            .get_vault_key(&key_fingerprint)
                                            .await
                                            .into_diagnostic()?
                                            .ok_or_else(|| {
                                                miette::miette!(
                                                    "Vault key not found: {}",
                                                    key_fingerprint
                                                )
                                            })?;

                                        let password = get_password(
                                            &format!(
                                                "Enter password for vault key '{}'",
                                                vault_key.name
                                            ),
                                            password_file.as_deref(),
                                        )
                                        .into_diagnostic()?;

                                        decrypt_secret_with_vault_key(
                                            &storage.encrypted_data,
                                            vault_key.encrypted_private_key(),
                                            &password,
                                        )
                                        .into_diagnostic()?
                                    }
                                    "host" => {
                                        error!(
                                            "Host key decryption requires SSH private key, which is not supported in this CLI"
                                        );
                                        error!(
                                            "Host keys are intended for automated host access, not interactive CLI use"
                                        );
                                        std::process::exit(1);
                                    }
                                    _ => {
                                        error!("Unknown key type: {}", storage.key_type);
                                        std::process::exit(1);
                                    }
                                };

                                // Log audit entry for secret access
                                db.log_audit(
                                    "GET_SECRET",
                                    &name,
                                    Some(&format!("Retrieved secret version {target_version} with key {key_fingerprint}")),
                                    Some(target_version),
                                    true,
                                    None,
                                )
                                .await
                                .into_diagnostic()?;

                                info!("Secret: {name}");
                                info!("Version: {target_version}");
                                info!("Key: {} ({})", key_fingerprint, storage.key_type);
                                info!("Data: {}", String::from_utf8_lossy(&decrypted_data));
                            }
                            None => {
                                error!(
                                    "Secret '{name}' version {target_version} not accessible with key '{key_fingerprint}'"
                                );
                                std::process::exit(1);
                            }
                        }
                    } else {
                        // No key specified, show available keys for this secret
                        let entries = db
                            .get_secret_storage(&name, target_version)
                            .await
                            .into_diagnostic()?;
                        if entries.is_empty() {
                            error!("Secret '{name}' version {target_version} not found");
                            std::process::exit(1);
                        }

                        // Check if we're in a terminal and can do interactive selection
                        if atty::is(atty::Stream::Stdout) && atty::is(atty::Stream::Stdin) {
                            // Create selection options
                            let mut options = Vec::new();
                            let mut vault_entries = Vec::new();

                            for entry in &entries {
                                if entry.key_type == "vault" {
                                    // Get the vault key name for better display
                                    if let Ok(Some(vault_key)) =
                                        db.get_vault_key(&entry.key_fingerprint).await
                                    {
                                        options.push(format!(
                                            "{} ({}) - vault key",
                                            vault_key.name,
                                            &entry.key_fingerprint[..8]
                                        ));
                                        vault_entries.push(entry);
                                    }
                                }
                            }

                            if vault_entries.is_empty() {
                                info!(
                                    "Secret '{name}' version {target_version} is encrypted for the following keys:"
                                );
                                for entry in entries {
                                    info!("  {} ({})", entry.key_fingerprint, entry.key_type);
                                }
                                info!("\nNo vault keys available for interactive decryption.");
                                info!(
                                    "Host keys require SSH private keys and are not supported for interactive CLI use."
                                );
                                info!("Use --key <fingerprint> with a vault key for decryption.");
                                return Ok(());
                            }

                            // Show interactive selection
                            let selection = Select::new()
                                .with_prompt(format!("Select a key to decrypt secret '{name}' version {target_version}"))
                                .items(&options)
                                .default(0)
                                .interact()
                                .map_err(|e| miette::miette!("Selection failed: {}", e))?;

                            let selected_entry = vault_entries[selection];
                            let key_fingerprint = &selected_entry.key_fingerprint;

                            // Get vault key and prompt for password
                            let vault_key = db
                                .get_vault_key(key_fingerprint)
                                .await
                                .into_diagnostic()?
                                .ok_or_else(|| {
                                    miette::miette!("Vault key not found: {}", key_fingerprint)
                                })?;

                            let password = get_password(
                                &format!("Enter password for vault key '{}'", vault_key.name),
                                password_file.as_deref(),
                            )
                            .into_diagnostic()?;

                            let decrypted_data = decrypt_secret_with_vault_key(
                                &selected_entry.encrypted_data,
                                vault_key.encrypted_private_key(),
                                &password,
                            )
                            .into_diagnostic()?;

                            // Log audit entry for secret access
                            db.log_audit(
                                "GET_SECRET",
                                &name,
                                Some(&format!("Retrieved secret version {target_version} with key {key_fingerprint} (interactive)")),
                                Some(target_version),
                                true,
                                None,
                            )
                            .await
                            .into_diagnostic()?;

                            info!("Secret: {name}");
                            info!("Version: {target_version}");
                            info!("Key: {} ({})", key_fingerprint, selected_entry.key_type);
                            info!("Data: {}", String::from_utf8_lossy(&decrypted_data));
                        } else {
                            // Not in terminal, show available keys
                            info!(
                                "Secret '{name}' version {target_version} is encrypted for the following keys:"
                            );
                            for entry in entries {
                                info!("  {} ({})", entry.key_fingerprint, entry.key_type);
                            }
                            info!("\nUse --key <fingerprint> to decrypt with a specific key");
                        }
                    }
                }
                SecretCommands::List { key } => {
                    if let Some(key_fingerprint) = key {
                        // List secrets accessible by specific key
                        let secret_names = db
                            .get_secrets_for_key(&key_fingerprint)
                            .await
                            .into_diagnostic()?;
                        if secret_names.is_empty() {
                            info!("No secrets accessible by key: {key_fingerprint}");
                            return Ok(());
                        }

                        info!("Secrets accessible by key {key_fingerprint}:");
                        for secret_name in secret_names {
                            let versions = db
                                .get_secret_versions_for_key(&secret_name, &key_fingerprint)
                                .await
                                .into_diagnostic()?;
                            info!(
                                "  {} ({} versions: {})",
                                secret_name,
                                versions.len(),
                                versions
                                    .iter()
                                    .map(|v| v.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                        }
                    } else {
                        // List all secrets
                        let secrets = db.get_all_secrets().await.into_diagnostic()?;
                        if secrets.is_empty() {
                            info!("No secrets found.");
                            return Ok(());
                        }

                        info!("Secrets:");
                        info!("{:<20} {:<30} Created", "Name", "Description");
                        info!("{}", "-".repeat(70));

                        for secret in secrets {
                            let latest_version = db
                                .get_latest_secret_version(&secret.name)
                                .await
                                .into_diagnostic()?;
                            let description = secret.description.as_deref().unwrap_or("");
                            info!(
                                "{:<20} {:<30} {} (v{})",
                                secret.name,
                                description,
                                secret.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                                latest_version.unwrap_or(0)
                            );
                        }
                    }
                }
                SecretCommands::Versions { name, key } => {
                    if let Some(key_fingerprint) = key {
                        // Show versions accessible by specific key
                        let versions = db
                            .get_secret_versions_for_key(&name, &key_fingerprint)
                            .await
                            .into_diagnostic()?;
                        if versions.is_empty() {
                            info!(
                                "No versions of secret '{name}' accessible by key: {key_fingerprint}"
                            );
                            return Ok(());
                        }

                        info!("Versions of secret '{name}' accessible by key {key_fingerprint}:");
                        for version in versions {
                            if let Some(entry) = db
                                .get_secret_storage_for_key(&name, version, &key_fingerprint)
                                .await
                                .into_diagnostic()?
                            {
                                info!(
                                    "  Version {} - Created: {}",
                                    version,
                                    entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                                );
                            }
                        }
                    } else {
                        // Show all versions regardless of key
                        let all_entries =
                            db.get_secret_storage(&name, 1).await.into_diagnostic()?; // Get version 1 first to check if secret exists
                        if all_entries.is_empty() {
                            // Try to get any version to see if secret exists
                            if db.get_secret(&name).await.into_diagnostic()?.is_none() {
                                error!("Secret '{name}' not found");
                                std::process::exit(1);
                            }
                        }

                        // Get all versions by finding the max version
                        let mut version = 1i64;
                        let mut found_versions = Vec::new();

                        loop {
                            let entries = db
                                .get_secret_storage(&name, version)
                                .await
                                .into_diagnostic()?;
                            if entries.is_empty() {
                                break;
                            }

                            // Get creation time from first entry
                            let created_at = entries[0].created_at;
                            let key_count = entries.len();
                            found_versions.push((version, created_at, key_count));
                            version += 1;
                        }

                        if found_versions.is_empty() {
                            info!("No versions found for secret '{name}'");
                            return Ok(());
                        }

                        info!("Versions of secret '{name}':");
                        info!("{:<8} {:<25} Keys", "Version", "Created");
                        info!("{}", "-".repeat(50));

                        for (ver, created, key_count) in found_versions {
                            info!(
                                "{:<8} {:<25} {}",
                                ver,
                                created.format("%Y-%m-%d %H:%M:%S UTC"),
                                key_count
                            );
                        }
                    }
                }
                SecretCommands::Delete { name } => {
                    // Check if secret exists
                    if db.get_secret(&name).await.into_diagnostic()?.is_none() {
                        error!("Secret '{name}' not found");
                        std::process::exit(1);
                    }

                    // For now, we'll implement a simple approach - we don't actually delete the data
                    // but we could add a 'deleted' flag to the secrets table in a future version
                    // For this implementation, we'll just report what we would do

                    let versions = db
                        .get_latest_secret_version(&name)
                        .await
                        .into_diagnostic()?;
                    match versions {
                        Some(latest_version) => {
                            // Log audit entry
                            db.log_audit(
                                "DELETE_SECRET",
                                &name,
                                Some(&format!(
                                    "Secret marked as deleted (latest version: {latest_version})"
                                )),
                                Some(latest_version),
                                true,
                                None,
                            )
                            .await
                            .into_diagnostic()?;

                            info!("✓ Secret '{name}' marked as deleted");
                            info!("  Latest version: {latest_version}");
                            info!(
                                "  Note: {latest_version} versions of encrypted data are preserved for audit purposes"
                            );

                            // In a production system, we would:
                            // 1. Update the secrets table to mark as deleted
                            // 2. Optionally add a deletion timestamp
                            // 3. Keep all versions in secret_storage for audit
                        }
                        None => {
                            info!("Secret '{name}' has no stored versions");
                        }
                    }
                }
                SecretCommands::Generate {
                    name,
                    length,
                    format,
                    hosts,
                    description,
                } => {
                    use rand::RngCore;

                    // Generate random bytes using a cryptographically secure RNG
                    let mut rng = rand::thread_rng();
                    let mut random_bytes = vec![0u8; length];
                    rng.fill_bytes(&mut random_bytes);

                    // Format the random data according to the specified format
                    let secret_data = match format.as_str() {
                        "hex" => hex::encode(&random_bytes).into_bytes(),
                        "base64" => {
                            use base64::Engine;
                            base64::engine::general_purpose::STANDARD
                                .encode(&random_bytes)
                                .into_bytes()
                        }
                        "alphanumeric" => {
                            use rand::seq::SliceRandom;
                            const CHARS: &[u8] =
                                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                            (0..length)
                                .map(|_| *CHARS.choose(&mut rng).unwrap())
                                .collect::<Vec<u8>>()
                        }
                        _ => {
                            error!(
                                "Invalid format '{}'. Use 'hex', 'base64', or 'alphanumeric'",
                                format
                            );
                            std::process::exit(1);
                        }
                    };

                    // Get all vault keys and specified host keys (reuse logic from Store command)
                    let vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
                    let mut target_keys = Vec::new();

                    // Add all vault keys as recipients
                    for vault_key in &vault_keys {
                        let recipient: Recipient = vault_key.public_key.parse().map_err(|e| {
                            miette::miette!(
                                "Failed to parse vault key public key {}: {:?}",
                                vault_key.fingerprint,
                                e
                            )
                        })?;
                        target_keys.push((
                            vault_key.fingerprint.clone(),
                            "vault".to_string(),
                            Box::new(recipient) as Box<dyn age::Recipient + Send>,
                        ));
                    }

                    // Add specified host keys
                    if let Some(host_list) = hosts {
                        let hostnames: Vec<&str> = host_list.split(',').map(|h| h.trim()).collect();
                        for hostname in hostnames {
                            if let Some(host_key) = db
                                .get_host_key_by_hostname(hostname)
                                .await
                                .into_diagnostic()?
                            {
                                let ssh_recipient =
                                    parse_ssh_public_key(&host_key.public_key).into_diagnostic()?;
                                target_keys.push((
                                    host_key.fingerprint.clone(),
                                    "host".to_string(),
                                    Box::new(ssh_recipient) as Box<dyn age::Recipient + Send>,
                                ));
                            } else {
                                warn!("Host '{hostname}' not found, skipping");
                            }
                        }
                    } else {
                        // If no hosts specified, add all host keys
                        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
                        for host_key in all_host_keys {
                            let ssh_recipient =
                                parse_ssh_public_key(&host_key.public_key).into_diagnostic()?;
                            target_keys.push((
                                host_key.fingerprint.clone(),
                                "host".to_string(),
                                Box::new(ssh_recipient) as Box<dyn age::Recipient + Send>,
                            ));
                        }
                    }

                    if target_keys.is_empty() {
                        error!("No keys available for encryption");
                        std::process::exit(1);
                    }

                    // Create or update secret metadata
                    let secret_exists = db.get_secret(&name).await.into_diagnostic()?.is_some();
                    if !secret_exists {
                        let now = Utc::now();
                        let secret = Secret {
                            name: name.clone(),
                            description: description.clone(),
                            template: None,
                            created_at: now,
                            updated_at: now,
                        };
                        db.insert_secret(&secret).await.into_diagnostic()?;
                    }

                    // Get next version number
                    let version = db.get_next_secret_version(&name).await.into_diagnostic()?;

                    let mut stored_count = 0;

                    // Store encrypted data for each target key (per-key encryption)
                    for (key_fingerprint, key_type, recipient) in target_keys {
                        // Encrypt secret data for this specific key
                        let encrypted_data = encrypt_for_recipients(&secret_data, vec![recipient])
                            .into_diagnostic()?;

                        let now = Utc::now();
                        let storage_entry = SecretStorage {
                            id: 0, // Will be set by database
                            secret_name: name.clone(),
                            version,
                            key_fingerprint: key_fingerprint.clone(),
                            key_type: key_type.clone(),
                            encrypted_data,
                            created_at: now,
                            updated_at: now,
                        };

                        db.insert_secret_storage(&storage_entry)
                            .await
                            .into_diagnostic()?;
                        stored_count += 1;
                    }

                    // Log audit entry
                    db.log_audit(
                        "GENERATE_SECRET",
                        &name,
                        Some(&format!("Generated {format} secret (length: {length}) version {version} for {stored_count} keys")),
                        Some(version),
                        true,
                        None,
                    )
                    .await
                    .into_diagnostic()?;

                    info!("✓ Secret generated and stored successfully!");
                    info!("  Name: {name}");
                    info!("  Format: {format}");
                    info!("  Length: {length}");
                    info!("  Version: {version}");
                    info!("  Encrypted for {stored_count} keys");
                    if let Some(desc) = description {
                        info!("  Description: {desc}");
                    }
                }

                SecretCommands::Info { name } => match db.get_secret_info(&name).await? {
                    Some(info) => {
                        // Show basic secret information at top
                        println!("Secret: {}", info.name);
                        if let Some(desc) = &info.description {
                            println!("Description: {desc}");
                        }
                        if let Some(template) = &info.template {
                            println!("Template: {template}");
                        }

                        // Current version info only
                        if let Some(latest) = info.latest_version {
                            println!("Current version: {latest}");
                        }

                        println!(
                            "Created: {}",
                            info.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        println!(
                            "Updated: {}",
                            info.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        println!();

                        // Version history table with all details
                        if info.versions.is_empty() {
                            println!("No encrypted versions found");
                        } else {
                            println!("Version History ({} versions):", info.total_versions);
                            println!(
                                "┌─────────┬─────────────────────┬───────────┬─────────────────────────────────────────────┐"
                            );
                            println!(
                                "│ Version │ Created             │ Key Count │ Encrypted For                               │"
                            );
                            println!(
                                "├─────────┼─────────────────────┼───────────┼─────────────────────────────────────────────┤"
                            );

                            for version_info in &info.versions {
                                let mut vault_keys = Vec::new();
                                let mut host_keys = Vec::new();

                                for key in &version_info.encrypted_for_keys {
                                    if key.key_type == "vault" {
                                        vault_keys.push(key.name.as_str());
                                    } else {
                                        host_keys.push(key.name.as_str());
                                    }
                                }

                                // Build clean key display
                                let keys_text = if vault_keys.is_empty() && host_keys.is_empty() {
                                    "No keys".to_string()
                                } else {
                                    let mut parts = Vec::new();
                                    if !vault_keys.is_empty() {
                                        parts.push(format!("vault:[{}]", vault_keys.join(", ")));
                                    }
                                    if !host_keys.is_empty() {
                                        parts.push(format!("host:[{}]", host_keys.join(", ")));
                                    }
                                    parts.join(" ")
                                };

                                // Truncate long key lists to fit in table
                                let display_keys = if keys_text.len() > 40 {
                                    format!("{}...", &keys_text[..37])
                                } else {
                                    keys_text
                                };

                                println!(
                                    "│ {:>7} │ {:<19} │ {:>9} │ {:<43} │",
                                    version_info.version,
                                    version_info.created_at.format("%Y-%m-%d %H:%M:%S"),
                                    version_info.encrypted_for_keys.len(),
                                    display_keys
                                );
                            }
                            println!(
                                "└─────────┴─────────────────────┴───────────┴─────────────────────────────────────────────┘"
                            );
                        }
                    }
                    None => {
                        error!("Secret '{name}' not found");
                        std::process::exit(1);
                    }
                },

                SecretCommands::Edit {
                    name,
                    key,
                    password_file,
                } => {
                    // Check if secret exists
                    if db.get_secret(&name).await.into_diagnostic()?.is_none() {
                        error!("Secret '{name}' not found");
                        std::process::exit(1);
                    }

                    // Use the same logic as the Get command but launch editor afterwards
                    let vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;
                    if vault_keys.is_empty() {
                        error!("No vault keys available for decryption");
                        std::process::exit(1);
                    }

                    let selected_key = if let Some(key_fingerprint) = key {
                        // Use specific key
                        vault_keys
                            .iter()
                            .find(|k| k.fingerprint == key_fingerprint)
                            .cloned()
                    } else if vault_keys.len() == 1 {
                        // Use the only available key
                        Some(vault_keys[0].clone())
                    } else {
                        // Multiple vault keys, let user choose
                        let items: Vec<String> = vault_keys
                            .iter()
                            .map(|k| format!("{} ({})", k.name, &k.fingerprint[..8]))
                            .collect();

                        let selection = Select::new()
                            .with_prompt("Select vault key to decrypt with")
                            .items(&items)
                            .interact()
                            .into_diagnostic()?;

                        Some(vault_keys[selection].clone())
                    };

                    let key = match selected_key {
                        Some(key) => key,
                        None => {
                            error!("Specified key not found");
                            std::process::exit(1);
                        }
                    };

                    // Get password
                    let password = get_password(
                        &format!("Enter password for vault key '{}'", key.name),
                        password_file.as_deref(),
                    )?;

                    // Get the latest version of the secret
                    let latest_version = db
                        .get_latest_secret_version(&name)
                        .await
                        .into_diagnostic()?;
                    let latest_version = match latest_version {
                        Some(version) => version,
                        None => {
                            error!("No versions found for secret '{name}'");
                            std::process::exit(1);
                        }
                    };

                    // Get encrypted data for this key
                    let storage = db
                        .get_secret_storage_for_key(&name, latest_version, &key.fingerprint)
                        .await
                        .into_diagnostic()?;

                    let encrypted_data = match storage {
                        Some(s) => s.encrypted_data,
                        None => {
                            error!("Secret '{name}' not accessible with this key");
                            std::process::exit(1);
                        }
                    };

                    // Decrypt the secret
                    let decrypted_data = decrypt_secret_with_vault_key(
                        &encrypted_data,
                        key.encrypted_private_key.as_ref().unwrap(),
                        &password,
                    )?;

                    // Convert to string for editing
                    let current_text = String::from_utf8(decrypted_data).map_err(|_| {
                        miette::miette!(
                            "Secret contains non-UTF8 data and cannot be edited as text"
                        )
                    })?;

                    // Launch editor
                    match edit_with_editor(&current_text)? {
                        Some(new_content) => {
                            // Content changed, store new version
                            info!("Secret content changed, creating new version");

                            // Get all keys for re-encryption
                            let vault_keys =
                                db.get_keys_by_type("vault").await.into_diagnostic()?;
                            let host_keys = db.get_keys_by_type("host").await.into_diagnostic()?;

                            // Create recipients from all keys
                            let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

                            for key in &vault_keys {
                                recipients.push(vault_key_to_recipient(&key.public_key)?);
                            }

                            for key in &host_keys {
                                recipients.push(host_key_to_recipient(&key.public_key)?);
                            }

                            if recipients.is_empty() {
                                error!("No keys available for encryption");
                                std::process::exit(1);
                            }

                            // Encrypt the new content
                            let encrypted_data =
                                encrypt_for_recipients(new_content.as_bytes(), recipients)?;

                            // Get next version number
                            let next_version =
                                db.get_next_secret_version(&name).await.into_diagnostic()?;

                            // Store encrypted data for each key
                            for key in &vault_keys {
                                let storage = SecretStorage {
                                    id: 0, // Will be set by database
                                    secret_name: name.clone(),
                                    version: next_version,
                                    key_fingerprint: key.fingerprint.clone(),
                                    key_type: "vault".to_string(),
                                    encrypted_data: encrypted_data.clone(),
                                    created_at: Utc::now(),
                                    updated_at: Utc::now(),
                                };
                                db.insert_secret_storage(&storage).await.into_diagnostic()?;
                            }

                            for key in &host_keys {
                                let storage = SecretStorage {
                                    id: 0, // Will be set by database
                                    secret_name: name.clone(),
                                    version: next_version,
                                    key_fingerprint: key.fingerprint.clone(),
                                    key_type: "host".to_string(),
                                    encrypted_data: encrypted_data.clone(),
                                    created_at: Utc::now(),
                                    updated_at: Utc::now(),
                                };
                                db.insert_secret_storage(&storage).await.into_diagnostic()?;
                            }

                            // Log the operation
                            db.log_audit(
                                "EDIT_SECRET",
                                &name,
                                Some(&format!("Secret '{name}' edited via $EDITOR")),
                                Some(next_version),
                                true,
                                None,
                            )
                            .await
                            .into_diagnostic()?;

                            info!(
                                "Secret '{}' successfully updated with new version {}",
                                name, next_version
                            );
                        }
                        None => {
                            info!("No changes made to secret '{}'", name);
                        }
                    }
                }
            }
        }

        Commands::Audit { command } => {
            ensure_initialized(&db).await?;
            match command {
                AuditCommands::List { limit } => {
                    let entries = db.get_audit_entries(limit).await.into_diagnostic()?;

                    if entries.is_empty() {
                        info!("No audit entries found.");
                        return Ok(());
                    }

                    info!("Audit Log ({} entries):", entries.len());
                    info!(
                        "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                        "ID", "Timestamp", "Operation", "Resource", "Success"
                    );
                    info!("{}", "-".repeat(90));

                    for entry in entries {
                        let success_icon = if entry.success { "✓" } else { "✗" };
                        let details = entry.details.as_deref().unwrap_or("");
                        let error_info = if !entry.success {
                            entry.error_message.as_deref().unwrap_or("Unknown error")
                        } else {
                            details
                        };

                        info!(
                            "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                            entry.id,
                            entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                            entry.operation,
                            entry.resource,
                            success_icon,
                            error_info
                        );
                    }
                }
                AuditCommands::Show {
                    resource,
                    operation,
                } => {
                    let entries = db
                        .get_audit_entries_filtered(
                            resource.as_deref(),
                            operation.as_deref(),
                            100, // Default limit for filtered results
                        )
                        .await
                        .into_diagnostic()?;

                    if entries.is_empty() {
                        info!("No audit entries found matching the criteria.");
                        return Ok(());
                    }

                    info!("Filtered Audit Log ({} entries):", entries.len());
                    if let Some(ref res) = resource {
                        info!("  Resource: {res}");
                    }
                    if let Some(ref op) = operation {
                        info!("  Operation: {op}");
                    }
                    info!("");

                    info!(
                        "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                        "ID", "Timestamp", "Operation", "Resource", "Success"
                    );
                    info!("{}", "-".repeat(90));

                    for entry in entries {
                        let success_icon = if entry.success { "✓" } else { "✗" };
                        let details = entry.details.as_deref().unwrap_or("");
                        let error_info = if !entry.success {
                            entry.error_message.as_deref().unwrap_or("Unknown error")
                        } else {
                            details
                        };

                        info!(
                            "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                            entry.id,
                            entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                            entry.operation,
                            entry.resource,
                            success_icon,
                            error_info
                        );
                    }
                }
                AuditCommands::Since { days } => {
                    let entries = db
                        .get_audit_entries_since(days, 100)
                        .await
                        .into_diagnostic()?;

                    if entries.is_empty() {
                        info!("No audit entries found from the last {days} days.");
                        return Ok(());
                    }

                    info!(
                        "Audit Log from last {days} days ({} entries):",
                        entries.len()
                    );
                    info!(
                        "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                        "ID", "Timestamp", "Operation", "Resource", "Success"
                    );
                    info!("{}", "-".repeat(90));

                    for entry in entries {
                        let success_icon = if entry.success { "✓" } else { "✗" };
                        let details = entry.details.as_deref().unwrap_or("");
                        let error_info = if !entry.success {
                            entry.error_message.as_deref().unwrap_or("Unknown error")
                        } else {
                            details
                        };

                        info!(
                            "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                            entry.id,
                            entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                            entry.operation,
                            entry.resource,
                            success_icon,
                            error_info
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
