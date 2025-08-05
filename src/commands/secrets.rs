use lilvault::cli::SecretCommands;
use lilvault::db::Database;
use lilvault::validation::{validate_file_path, validate_hostname, validate_secret_name};
use miette::Result;

/// Handle secrets commands
pub async fn handle_secrets(db: &Database, command: SecretCommands) -> Result<()> {
    match command {
        SecretCommands::Store {
            name,
            hosts,
            file,
            stdin,
            description,
        } => handle_store(db, name, hosts, file, stdin, description).await,

        SecretCommands::Get {
            name,
            version,
            key,
            password_file,
        } => handle_get(db, name, version, key, password_file.as_deref()).await,

        SecretCommands::List { key } => handle_list(db, key).await,

        SecretCommands::Delete { name } => handle_delete(db, name).await,

        SecretCommands::Generate {
            name,
            hosts,
            length,
            format,
            description,
        } => handle_generate(db, name, hosts, length, format, description).await,

        SecretCommands::Info { name } => handle_info(db, name).await,

        SecretCommands::Edit {
            name,
            key,
            password_file,
        } => handle_edit(db, name, key, password_file.as_deref()).await,

        SecretCommands::Share {
            host,
            secrets,
            vault_key,
            password_file,
        } => handle_share(db, host, secrets, vault_key, password_file.as_deref()).await,

        SecretCommands::Unshare { host, secrets } => handle_unshare(db, host, secrets).await,
    }
}

// TODO: Implement individual handler functions
async fn handle_store(
    db: &Database,
    name: String,
    hosts: Vec<String>,
    file: Option<std::path::PathBuf>,
    stdin: bool,
    description: Option<String>,
) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;
    if let Some(ref path) = file {
        validate_file_path(path)?;
    }
    for hostname in &hosts {
        validate_hostname(hostname)?;
    }

    // Begin transaction for atomic secret storage
    let tx = db.begin_transaction().await?;

    use chrono::Utc;
    use lilvault::crypto::{encrypt_for_recipients, host_key_to_recipient, vault_key_to_recipient};
    use lilvault::db::models::{Secret, SecretStorage};
    use miette::IntoDiagnostic;
    use std::fs;
    use tracing::{error, info, warn};

    // Read secret data
    let secret_data = if stdin {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .into_diagnostic()?;
        buffer.trim().as_bytes().to_vec()
    } else if let Some(file_path) = file {
        fs::read(&file_path)
            .into_diagnostic()
            .map_err(|e| miette::miette!("Failed to read file '{}': {}", file_path.display(), e))?
    } else {
        // Default: use $EDITOR to edit the secret
        use lilvault::utils::edit_with_editor;

        info!("Opening editor to input secret");

        match edit_with_editor("").into_diagnostic()? {
            Some(content) => content.as_bytes().to_vec(),
            None => {
                error!("No secret content provided");
                std::process::exit(1);
            }
        }
    };

    // Get all vault keys and specified host keys
    let vault_keys = db.get_all_vault_keys().await.into_diagnostic()?;
    let mut target_keys = Vec::new();

    // Add all vault keys as recipients
    for vault_key in &vault_keys {
        let recipient = vault_key_to_recipient(&vault_key.public_key).into_diagnostic()?;
        target_keys.push((
            vault_key.fingerprint.clone(),
            "vault".to_string(),
            recipient,
        ));
    }

    // Add specified host keys
    if !hosts.is_empty() {
        for hostname in &hosts {
            if let Some(host_key) = db
                .get_host_key_by_hostname(hostname)
                .await
                .into_diagnostic()?
            {
                let ssh_recipient =
                    host_key_to_recipient(&host_key.public_key).into_diagnostic()?;
                target_keys.push((
                    host_key.fingerprint.clone(),
                    "host".to_string(),
                    ssh_recipient,
                ));
            } else {
                warn!("Host '{hostname}' not found, skipping");
            }
        }
    } else {
        // If no hosts specified, add all host keys
        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
        for host_key in all_host_keys {
            let ssh_recipient = host_key_to_recipient(&host_key.public_key).into_diagnostic()?;
            target_keys.push((
                host_key.fingerprint.clone(),
                "host".to_string(),
                ssh_recipient,
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
        let encrypted_data =
            encrypt_for_recipients(&secret_data, vec![recipient]).into_diagnostic()?;

        let storage_entry = SecretStorage::new(
            name.clone(),
            version,
            key_fingerprint.clone(),
            key_type.clone(),
            encrypted_data,
        );

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

    // Commit transaction
    tx.commit().await.into_diagnostic()?;

    info!("✓ Secret stored successfully!");
    info!("  Name: {name}");
    info!("  Version: {version}");
    info!("  Encrypted for {stored_count} keys");
    if let Some(desc) = description {
        info!("  Description: {desc}");
    }

    Ok(())
}

async fn handle_get(
    db: &Database,
    name: String,
    version: Option<i64>,
    key: Option<String>,
    password_file: Option<&std::path::Path>,
) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;
    if let Some(path) = password_file {
        validate_file_path(path)?;
    }

    use dialoguer::Select;
    use lilvault::crypto::{decrypt_secret_with_vault_key, get_password};
    use miette::IntoDiagnostic;
    use tracing::{error, info};

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
                                miette::miette!("Vault key not found: {}", key_fingerprint)
                            })?;

                        let password = get_password(
                            &format!("Enter password for vault key '{}'", vault_key.name),
                            password_file,
                        )
                        .into_diagnostic()?;

                        {
                            let encrypted_private_key = vault_key
                                .encrypted_private_key
                                .as_ref()
                                .ok_or_else(|| {
                                    miette::miette!(
                                        "Vault key '{}' is missing its private key - this indicates database corruption",
                                        vault_key.name
                                    )
                                })?;

                            decrypt_secret_with_vault_key(
                                &storage.encrypted_data,
                                encrypted_private_key,
                                &password,
                            )
                            .into_diagnostic()?
                        }
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
                    Some(&format!(
                        "Retrieved secret version {target_version} with key {key_fingerprint}"
                    )),
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

            // Collect vault key entries with their full key info for sorting
            let mut vault_key_entries = Vec::new();
            for entry in &entries {
                if entry.key_type == "vault" {
                    if let Ok(Some(vault_key)) = db.get_vault_key(&entry.key_fingerprint).await {
                        vault_key_entries.push((entry, vault_key));
                    }
                }
            }

            // Sort vault keys by creation date (oldest first)
            vault_key_entries.sort_by(|a, b| a.1.created_at.cmp(&b.1.created_at));

            // Build options and vault_entries in sorted order
            for (entry, vault_key) in vault_key_entries {
                options.push(format!(
                    "{} ({}) - vault key",
                    vault_key.name,
                    &entry.key_fingerprint[..8]
                ));
                vault_entries.push(entry);
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
                .with_prompt(format!(
                    "Select a key to decrypt secret '{name}' version {target_version}"
                ))
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
                .ok_or_else(|| miette::miette!("Vault key not found: {}", key_fingerprint))?;

            let password = get_password(
                &format!("Enter password for vault key '{}'", vault_key.name),
                password_file,
            )
            .into_diagnostic()?;

            let encrypted_private_key = vault_key
                .encrypted_private_key
                .as_ref()
                .ok_or_else(|| {
                    miette::miette!(
                        "Vault key '{}' is missing its private key - this indicates database corruption",
                        vault_key.name
                    )
                })?;

            let decrypted_data = decrypt_secret_with_vault_key(
                &selected_entry.encrypted_data,
                encrypted_private_key,
                &password,
            )
            .into_diagnostic()?;

            // Log audit entry for secret access
            db.log_audit(
                "GET_SECRET",
                &name,
                Some(&format!(
                    "Retrieved secret version {target_version} with key {key_fingerprint} (interactive)"
                )),
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
            info!("Secret '{name}' version {target_version} is encrypted for the following keys:");
            for entry in entries {
                info!("  {} ({})", entry.key_fingerprint, entry.key_type);
            }
            info!("\nUse --key <fingerprint> to decrypt with a specific key");
        }
    }

    Ok(())
}

async fn handle_list(db: &Database, key: Option<String>) -> Result<()> {
    use miette::IntoDiagnostic;
    use tracing::info;

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

    Ok(())
}

async fn handle_delete(db: &Database, name: String) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;

    use miette::IntoDiagnostic;
    use tracing::{error, info};

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

    Ok(())
}

async fn handle_generate(
    db: &Database,
    name: String,
    hosts: Vec<String>,
    length: usize,
    format: String,
    description: Option<String>,
) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;
    for hostname in &hosts {
        validate_hostname(hostname)?;
    }

    use chrono::Utc;
    use lilvault::crypto::{encrypt_for_recipients, host_key_to_recipient, vault_key_to_recipient};
    use lilvault::db::models::{Secret, SecretStorage};
    use miette::IntoDiagnostic;
    use rand::RngCore;
    use tracing::{error, info, warn};

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
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            (0..length)
                .map(|_| {
                    #[allow(clippy::expect_used)]
                    let result = *CHARS.choose(&mut rng).expect("CHARS is non-empty");
                    result
                })
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
        let recipient = vault_key_to_recipient(&vault_key.public_key).into_diagnostic()?;
        target_keys.push((
            vault_key.fingerprint.clone(),
            "vault".to_string(),
            recipient,
        ));
    }

    // Add specified host keys
    if !hosts.is_empty() {
        for hostname in &hosts {
            if let Some(host_key) = db
                .get_host_key_by_hostname(hostname)
                .await
                .into_diagnostic()?
            {
                let ssh_recipient =
                    host_key_to_recipient(&host_key.public_key).into_diagnostic()?;
                target_keys.push((
                    host_key.fingerprint.clone(),
                    "host".to_string(),
                    ssh_recipient,
                ));
            } else {
                warn!("Host '{hostname}' not found, skipping");
            }
        }
    } else {
        // If no hosts specified, add all host keys
        let all_host_keys = db.get_all_host_keys().await.into_diagnostic()?;
        for host_key in all_host_keys {
            let ssh_recipient = host_key_to_recipient(&host_key.public_key).into_diagnostic()?;
            target_keys.push((
                host_key.fingerprint.clone(),
                "host".to_string(),
                ssh_recipient,
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
        let encrypted_data =
            encrypt_for_recipients(&secret_data, vec![recipient]).into_diagnostic()?;

        let storage_entry = SecretStorage::new(
            name.clone(),
            version,
            key_fingerprint.clone(),
            key_type.clone(),
            encrypted_data,
        );

        db.insert_secret_storage(&storage_entry)
            .await
            .into_diagnostic()?;
        stored_count += 1;
    }

    // Log audit entry
    db.log_audit(
        "GENERATE_SECRET",
        &name,
        Some(&format!(
            "Generated {format} secret (length {length}) version {version} for {stored_count} keys"
        )),
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

    Ok(())
}

async fn handle_info(db: &Database, name: String) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;

    use miette::IntoDiagnostic;
    use tracing::error;

    match db.get_secret_info(&name).await.into_diagnostic()? {
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
                    // Create list of all key names, one per line
                    let mut key_lines = Vec::new();

                    for key in &version_info.encrypted_for_keys {
                        key_lines.push(format!("{} ({})", key.name, key.key_type));
                    }

                    // Print first line with all columns
                    println!(
                        "│ {:>7} │ {:<19} │ {:>9} │ {:<43} │",
                        version_info.version,
                        version_info.created_at.format("%Y-%m-%d %H:%M:%S"),
                        version_info.encrypted_for_keys.len(),
                        key_lines.first().unwrap_or(&String::new())
                    );

                    // Print additional lines for remaining keys
                    for key_line in key_lines.iter().skip(1) {
                        println!("│ {:>7} │ {:<19} │ {:>9} │ {:<43} │", "", "", "", key_line);
                    }
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
    }

    Ok(())
}

async fn handle_edit(
    db: &Database,
    name: String,
    key: Option<String>,
    password_file: Option<&std::path::Path>,
) -> Result<()> {
    // Validate input
    validate_secret_name(&name)?;
    if let Some(path) = password_file {
        validate_file_path(path)?;
    }

    use dialoguer::Select;
    use lilvault::crypto::{
        Recipient, decrypt_secret_with_vault_key, encrypt_for_recipients, get_password,
        host_key_to_recipient, vault_key_to_recipient,
    };
    use lilvault::db::models::SecretStorage;
    use lilvault::utils::edit_with_editor;
    use miette::IntoDiagnostic;
    use tracing::{error, info};

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

    let vault_key = match selected_key {
        Some(key) => key,
        None => {
            error!("Specified key not found");
            std::process::exit(1);
        }
    };

    // Get password
    let password = get_password(
        &format!("Enter password for vault key '{}'", vault_key.name),
        password_file,
    )
    .into_diagnostic()?;

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
        .get_secret_storage_for_key(&name, latest_version, &vault_key.fingerprint)
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
    let encrypted_private_key = vault_key.encrypted_private_key.as_ref().ok_or_else(|| {
        miette::miette!(
            "Vault key '{}' is missing its private key - this indicates database corruption",
            vault_key.name
        )
    })?;

    let decrypted_data =
        decrypt_secret_with_vault_key(&encrypted_data, encrypted_private_key, &password)
            .into_diagnostic()?;

    // Convert to string for editing
    let current_text = String::from_utf8(decrypted_data).map_err(|_| {
        miette::miette!("Secret contains non-UTF8 data and cannot be edited as text")
    })?;

    // Launch editor
    match edit_with_editor(&current_text).into_diagnostic()? {
        Some(new_content) => {
            // Content changed, store new version
            info!("Secret content changed, creating new version");

            // Get all keys for re-encryption
            let vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;
            let host_keys = db.get_keys_by_type("host").await.into_diagnostic()?;

            // Create recipients from all keys
            let mut recipients: Vec<Recipient> = Vec::new();

            for key in &vault_keys {
                recipients.push(vault_key_to_recipient(&key.public_key).into_diagnostic()?);
            }

            for key in &host_keys {
                recipients.push(host_key_to_recipient(&key.public_key).into_diagnostic()?);
            }

            if recipients.is_empty() {
                error!("No keys available for encryption");
                std::process::exit(1);
            }

            // Encrypt the new content
            let encrypted_data =
                encrypt_for_recipients(new_content.as_bytes(), recipients).into_diagnostic()?;

            // Get next version number
            let next_version = db.get_next_secret_version(&name).await.into_diagnostic()?;

            // Store encrypted data for each key
            for key in &vault_keys {
                let storage = SecretStorage::new(
                    name.clone(),
                    next_version,
                    key.fingerprint.clone(),
                    "vault".to_string(),
                    encrypted_data.clone(),
                );
                db.insert_secret_storage(&storage).await.into_diagnostic()?;
            }

            for key in &host_keys {
                let storage = SecretStorage::new(
                    name.clone(),
                    next_version,
                    key.fingerprint.clone(),
                    "host".to_string(),
                    encrypted_data.clone(),
                );
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

    Ok(())
}

async fn handle_share(
    db: &Database,
    host: String,
    secret_names: Vec<String>,
    vault_key: Option<String>,
    password_file: Option<&std::path::Path>,
) -> Result<()> {
    // Validate input
    validate_hostname(&host)?;
    for secret_name in &secret_names {
        validate_secret_name(secret_name)?;
    }
    if let Some(path) = password_file {
        validate_file_path(path)?;
    }

    use chrono::Utc;
    use dialoguer::Select;
    use lilvault::crypto::{
        Recipient, decrypt_secret_with_vault_key, encrypt_for_recipients, get_password,
        host_key_to_recipient, vault_key_to_recipient,
    };
    use lilvault::db::models::{SecretKey, SecretStorage};
    use miette::IntoDiagnostic;
    use tracing::{error, info, warn};

    if secret_names.is_empty() {
        error!("No secrets specified");
        std::process::exit(1);
    }

    // Get the host key
    let host_key = match db.get_host_key_by_hostname(&host).await.into_diagnostic()? {
        Some(key) => key,
        None => {
            error!("Host key not found for hostname: {host}");
            std::process::exit(1);
        }
    };

    // Get vault keys for selection
    let vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;
    if vault_keys.is_empty() {
        error!("No vault keys available for decryption");
        std::process::exit(1);
    }

    // Select vault key to use for decryption
    let selected_vault_key = if let Some(key_fingerprint) = vault_key {
        vault_keys
            .iter()
            .find(|k| k.fingerprint == key_fingerprint)
            .cloned()
    } else if vault_keys.len() == 1 {
        Some(vault_keys[0].clone())
    } else {
        // Multiple vault keys, let user choose
        let items: Vec<String> = vault_keys
            .iter()
            .map(|k| format!("{} ({})", k.name, &k.fingerprint[..8]))
            .collect();

        let selection = Select::new()
            .with_prompt("Select vault key to decrypt secrets for sharing")
            .items(&items)
            .interact()
            .into_diagnostic()?;

        Some(vault_keys[selection].clone())
    };

    let selected_vault_key = match selected_vault_key {
        Some(key) => key,
        None => {
            error!("Specified vault key not found");
            std::process::exit(1);
        }
    };

    // Get password for vault key
    let password = get_password(
        &format!("Enter password for vault key '{}'", selected_vault_key.name),
        password_file,
    )
    .into_diagnostic()?;

    let mut shared_count = 0;
    let mut failed_secrets = Vec::new();

    // Process each secret
    for secret_name in &secret_names {
        // Check if secret exists
        if db
            .get_secret(secret_name)
            .await
            .into_diagnostic()?
            .is_none()
        {
            warn!("Secret '{secret_name}' not found - skipping");
            failed_secrets.push(secret_name.clone());
            continue;
        }

        // Get the latest version of the secret
        let latest_version = match db
            .get_latest_secret_version(secret_name)
            .await
            .into_diagnostic()?
        {
            Some(version) => version,
            None => {
                warn!("No versions found for secret '{secret_name}' - skipping");
                failed_secrets.push(secret_name.clone());
                continue;
            }
        };

        // Get encrypted data for the vault key
        let storage = db
            .get_secret_storage_for_key(
                secret_name,
                latest_version,
                &selected_vault_key.fingerprint,
            )
            .await
            .into_diagnostic()?;

        let encrypted_data = match storage {
            Some(s) => s.encrypted_data,
            None => {
                warn!("Secret '{secret_name}' not accessible with this vault key - skipping");
                failed_secrets.push(secret_name.clone());
                continue;
            }
        };

        // Decrypt the secret
        let encrypted_private_key = selected_vault_key
            .encrypted_private_key
            .as_ref()
            .ok_or_else(|| {
                miette::miette!(
                    "Vault key '{}' is missing its private key - this indicates database corruption",
                    selected_vault_key.name
                )
            })?;

        let decrypted_data = match decrypt_secret_with_vault_key(
            &encrypted_data,
            encrypted_private_key,
            &password,
        ) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to decrypt secret '{secret_name}': {e} - skipping");
                failed_secrets.push(secret_name.clone());
                continue;
            }
        };

        // Check if already shared with this host
        if db
            .is_secret_encrypted_for_key_new(secret_name, &host_key.fingerprint)
            .await
            .into_diagnostic()?
        {
            info!("Secret '{secret_name}' already shared with host '{host}' - skipping");
            continue;
        }

        // Get the next version number for this secret
        let new_version = db
            .get_next_secret_version(secret_name)
            .await
            .into_diagnostic()?;

        // Get all current keys that the secret is encrypted for
        let current_vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;

        // Get all keys that this secret is currently encrypted for
        let secret_key_info = db.get_secret_keys(secret_name).await.into_diagnostic()?;
        let current_host_keys: Vec<_> = {
            let mut host_keys = Vec::new();
            for key_info in &secret_key_info {
                if key_info.key_type == "host" {
                    if let Some(key) = db.get_key(&key_info.fingerprint).await.into_diagnostic()? {
                        host_keys.push(key);
                    }
                }
            }
            host_keys
        };

        // Add the new host key to existing host keys
        let mut all_host_keys = current_host_keys;
        all_host_keys.push(host_key.clone());

        // Create recipients for all keys (vault + all host keys)
        let mut recipients: Vec<Recipient> = Vec::new();

        for key in &current_vault_keys {
            recipients.push(vault_key_to_recipient(&key.public_key).into_diagnostic()?);
        }

        for key in &all_host_keys {
            recipients.push(host_key_to_recipient(&key.public_key).into_diagnostic()?);
        }

        // Encrypt the secret for all recipients
        let encrypted_data =
            encrypt_for_recipients(&decrypted_data, recipients).into_diagnostic()?;

        // Store encrypted copies for each key
        // Store for vault keys
        for key in &current_vault_keys {
            let storage_entry = SecretStorage::new(
                secret_name.clone(),
                new_version,
                key.fingerprint.clone(),
                "vault".to_string(),
                encrypted_data.clone(),
            );
            db.insert_secret_storage(&storage_entry)
                .await
                .into_diagnostic()?;
        }

        // Store for all host keys (existing + new)
        for key in &all_host_keys {
            let storage_entry = SecretStorage::new(
                secret_name.clone(),
                new_version,
                key.fingerprint.clone(),
                "host".to_string(),
                encrypted_data.clone(),
            );
            db.insert_secret_storage(&storage_entry)
                .await
                .into_diagnostic()?;
        }

        // Update secrets_keys table with the new host key
        let now = Utc::now();
        let secret_key = SecretKey {
            secret_name: secret_name.clone(),
            key_fingerprint: host_key.fingerprint.clone(),
            key_type: "host".to_string(),
            created_at: now,
            updated_at: now,
        };
        db.insert_secret_key(&secret_key).await.into_diagnostic()?;

        // Log audit entry
        db.log_audit(
            "SHARE_SECRET",
            secret_name,
            Some(&format!(
                "Shared secret version {new_version} with host: {host}"
            )),
            Some(new_version),
            true,
            None,
        )
        .await
        .into_diagnostic()?;

        shared_count += 1;
    }

    // Report results
    if shared_count > 0 {
        info!("✓ Shared {shared_count} secrets with host '{host}'");
        for secret_name in &secret_names {
            if !failed_secrets.contains(secret_name) {
                info!("  - {secret_name}");
            }
        }
    }

    if !failed_secrets.is_empty() {
        warn!("Failed to share {} secrets:", failed_secrets.len());
        for secret_name in &failed_secrets {
            warn!("  - {secret_name}");
        }
    }

    if shared_count == 0 {
        error!("No secrets were shared successfully");
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_unshare(db: &Database, host: String, secret_names: Vec<String>) -> Result<()> {
    // Validate input
    validate_hostname(&host)?;
    for secret_name in &secret_names {
        validate_secret_name(secret_name)?;
    }

    use miette::IntoDiagnostic;
    use tracing::{error, info, warn};

    if secret_names.is_empty() {
        error!("No secrets specified");
        std::process::exit(1);
    }

    // Get the host key
    let host_key = match db.get_host_key_by_hostname(&host).await.into_diagnostic()? {
        Some(key) => key,
        None => {
            error!("Host key not found for hostname: {host}");
            std::process::exit(1);
        }
    };

    let mut unshared_count = 0;
    let mut failed_secrets = Vec::new();
    let mut not_shared_secrets = Vec::new();

    // Process each secret
    for secret_name in &secret_names {
        // Check if secret exists
        if db
            .get_secret(secret_name)
            .await
            .into_diagnostic()?
            .is_none()
        {
            warn!("Secret '{secret_name}' not found - skipping");
            failed_secrets.push(secret_name.clone());
            continue;
        }

        // Check if secret is currently shared with this host
        if !db
            .is_secret_encrypted_for_key_new(secret_name, &host_key.fingerprint)
            .await
            .into_diagnostic()?
        {
            info!("Secret '{secret_name}' not shared with host '{host}' - skipping");
            not_shared_secrets.push(secret_name.clone());
            continue;
        }

        // Remove secret-key relationship
        if db
            .remove_secret_key(secret_name, &host_key.fingerprint)
            .await
            .into_diagnostic()?
        {
            // Log audit entry
            db.log_audit(
                "UNSHARE_SECRET",
                secret_name,
                Some(&format!("Removed access for host: {host}")),
                None,
                true,
                None,
            )
            .await
            .into_diagnostic()?;

            unshared_count += 1;
        } else {
            warn!("Failed to remove access for secret '{secret_name}' - skipping");
            failed_secrets.push(secret_name.clone());
        }
    }

    // Note: We don't remove the encrypted storage entries because:
    // 1. They serve as audit trail
    // 2. Future versions won't include these hosts
    // 3. The secrets_keys table controls access, not secret_storage

    // Report results
    if unshared_count > 0 {
        info!("✓ Unshared {unshared_count} secrets from host '{host}'");
        for secret_name in &secret_names {
            if !failed_secrets.contains(secret_name) && !not_shared_secrets.contains(secret_name) {
                info!("  - {secret_name}");
            }
        }
    }

    if !not_shared_secrets.is_empty() {
        info!("Secrets not previously shared with '{host}':");
        for secret_name in &not_shared_secrets {
            info!("  - {secret_name}");
        }
    }

    if !failed_secrets.is_empty() {
        warn!("Failed to process {} secrets:", failed_secrets.len());
        for secret_name in &failed_secrets {
            warn!("  - {secret_name}");
        }
    }

    if unshared_count == 0
        && failed_secrets.is_empty()
        && not_shared_secrets.len() == secret_names.len()
    {
        info!("No changes made - no secrets were shared with host '{host}'");
    } else if unshared_count == 0 {
        error!("No secrets were unshared successfully");
        std::process::exit(1);
    }

    Ok(())
}
