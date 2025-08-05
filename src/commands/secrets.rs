use lilvault::cli::SecretCommands;
use lilvault::db::Database;
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

        SecretCommands::Versions { name, key } => handle_versions(db, name, key).await,

        SecretCommands::Delete { name } => handle_delete(db, name).await,

        SecretCommands::Generate {
            name,
            length,
            format,
            hosts,
            description,
        } => handle_generate(db, name, length, format, hosts, description).await,

        SecretCommands::Info { name } => handle_info(db, name).await,

        SecretCommands::Edit {
            name,
            key,
            password_file,
        } => handle_edit(db, name, key, password_file.as_deref()).await,

        SecretCommands::Share {
            name,
            hosts,
            vault_key,
            password_file,
        } => handle_share(db, name, hosts, vault_key, password_file.as_deref()).await,

        SecretCommands::Unshare { name, hosts } => handle_unshare(db, name, hosts).await,
    }
}

// TODO: Implement individual handler functions
async fn handle_store(
    _db: &Database,
    _name: String,
    _hosts: Option<String>,
    _file: Option<std::path::PathBuf>,
    _stdin: bool,
    _description: Option<String>,
) -> Result<()> {
    todo!("Implement store command")
}

async fn handle_get(
    db: &Database,
    name: String,
    version: Option<i64>,
    key: Option<String>,
    password_file: Option<&std::path::Path>,
) -> Result<()> {
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

                        decrypt_secret_with_vault_key(
                            &storage.encrypted_data,
                            vault_key.encrypted_private_key.as_ref().unwrap(),
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

            for entry in &entries {
                if entry.key_type == "vault" {
                    // Get the vault key name for better display
                    if let Ok(Some(vault_key)) = db.get_vault_key(&entry.key_fingerprint).await {
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

            let decrypted_data = decrypt_secret_with_vault_key(
                &selected_entry.encrypted_data,
                vault_key.encrypted_private_key.as_ref().unwrap(),
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

async fn handle_versions(db: &Database, name: String, key: Option<String>) -> Result<()> {
    use miette::IntoDiagnostic;
    use tracing::{error, info};

    if let Some(key_fingerprint) = key {
        // Show versions accessible by specific key
        let versions = db
            .get_secret_versions_for_key(&name, &key_fingerprint)
            .await
            .into_diagnostic()?;
        if versions.is_empty() {
            info!("No versions of secret '{name}' accessible by key: {key_fingerprint}");
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
        let all_entries = db.get_secret_storage(&name, 1).await.into_diagnostic()?; // Get version 1 first to check if secret exists
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

    Ok(())
}

async fn handle_delete(db: &Database, name: String) -> Result<()> {
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
    _db: &Database,
    _name: String,
    _length: usize,
    _format: String,
    _hosts: Option<String>,
    _description: Option<String>,
) -> Result<()> {
    todo!("Implement generate command")
}

async fn handle_info(db: &Database, name: String) -> Result<()> {
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
    use dialoguer::Select;
    use lilvault::crypto::{
        decrypt_secret_with_vault_key, edit_with_editor, encrypt_for_recipients, get_password,
        host_key_to_recipient, vault_key_to_recipient,
    };
    use lilvault::db::models::SecretStorage;
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
    let decrypted_data = decrypt_secret_with_vault_key(
        &encrypted_data,
        vault_key.encrypted_private_key.as_ref().unwrap(),
        &password,
    )
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
            let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

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
    _db: &Database,
    _name: String,
    _hosts: String,
    _vault_key: Option<String>,
    _password_file: Option<&std::path::Path>,
) -> Result<()> {
    todo!("Implement share command")
}

async fn handle_unshare(db: &Database, name: String, hosts: String) -> Result<()> {
    use miette::IntoDiagnostic;
    use tracing::{error, warn};

    // Check if secret exists
    if db.get_secret(&name).await.into_diagnostic()?.is_none() {
        error!("Secret '{name}' not found");
        std::process::exit(1);
    }

    // Parse hostnames
    let hostnames: Vec<&str> = hosts.split(',').map(|h| h.trim()).collect();
    if hostnames.is_empty() {
        error!("No hosts specified");
        std::process::exit(1);
    }

    // Get host keys to remove
    let mut host_keys_to_remove = Vec::new();
    for hostname in &hostnames {
        match db
            .get_host_key_by_hostname(hostname)
            .await
            .into_diagnostic()?
        {
            Some(key) => host_keys_to_remove.push(key),
            None => {
                warn!("Host key not found for hostname: {hostname}");
            }
        }
    }

    if host_keys_to_remove.is_empty() {
        error!("No valid host keys found to remove");
        std::process::exit(1);
    }

    // Remove secret-key relationships
    let mut removed_count = 0;
    for host_key in &host_keys_to_remove {
        if db
            .remove_secret_key(&name, &host_key.fingerprint)
            .await
            .into_diagnostic()?
        {
            removed_count += 1;
        }
    }

    // Note: We don't remove the encrypted storage entries because:
    // 1. They serve as audit trail
    // 2. Future versions won't include these hosts
    // 3. The secrets_keys table controls access, not secret_storage

    if removed_count > 0 {
        use tracing::info;

        // Log audit entry
        let host_names: Vec<String> = host_keys_to_remove.iter().map(|k| k.name.clone()).collect();
        db.log_audit(
            "UNSHARE_SECRET",
            &name,
            Some(&format!(
                "Removed access for {} hosts: {}",
                removed_count,
                host_names.join(", ")
            )),
            None,
            true,
            None,
        )
        .await
        .into_diagnostic()?;

        info!("✓ Secret '{name}' unshared from {removed_count} hosts");
        for host_key in &host_keys_to_remove {
            info!("  - {}", host_key.name);
        }
    } else {
        use tracing::info;
        info!("No changes made - secret was not shared with specified hosts");
    }

    Ok(())
}
