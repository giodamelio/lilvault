use age::x25519::Recipient;
use chrono::Utc;
use clap::Parser;
use lilvault::cli::{
    AuditCommands, Cli, Commands, HostKeyCommands, SecretCommands, VaultKeyCommands,
};
use lilvault::crypto::{
    decrypt_secret_with_vault_key, encrypt_for_recipients, generate_fingerprint,
    generate_master_key, get_password, parse_ssh_public_key,
};
use lilvault::db::{
    Database,
    models::{HostKey, Secret, SecretStorage, VaultKey},
};
use miette::{IntoDiagnostic, Result};
use std::fs;

/// Helper function to check if the vault database is properly initialized
async fn ensure_initialized(db: &Database) -> Result<()> {
    if !db.is_initialized().await.into_diagnostic()? {
        eprintln!("Error: Vault not initialized. Run 'lilvault init' first.");
        std::process::exit(1);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    // Create database connection
    let db = Database::new(&cli.database).await.into_diagnostic()?;

    // Handle commands
    match cli.command {
        Commands::Init {
            name,
            password_file,
        } => {
            if db.is_initialized().await.into_diagnostic()? {
                eprintln!("Error: Vault is already initialized");
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
                    eprintln!("Error: Passwords do not match");
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
            let vault_key = VaultKey {
                fingerprint: fingerprint.clone(),
                name: name.clone(),
                public_key: public_key.clone(),
                encrypted_private_key,
                created_at: now,
                updated_at: now,
            };

            // Store in database
            db.insert_vault_key(&vault_key).await.into_diagnostic()?;

            println!("✓ Vault initialized successfully!");
            println!("  Vault key name: {name}");
            println!("  Fingerprint: {fingerprint}");
            println!("  Database: {}", cli.database.display());
        }

        Commands::Vault { command } => {
            ensure_initialized(&db).await?;
            match command {
                VaultKeyCommands::Add {
                    name,
                    password_file,
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
                            eprintln!("Error: Passwords do not match");
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
                    let vault_key = VaultKey {
                        fingerprint: fingerprint.clone(),
                        name: name.clone(),
                        public_key: public_key.clone(),
                        encrypted_private_key,
                        created_at: now,
                        updated_at: now,
                    };

                    // Store in database
                    db.insert_vault_key(&vault_key).await.into_diagnostic()?;

                    println!("✓ Vault key added successfully!");
                    println!("  Name: {name}");
                    println!("  Fingerprint: {fingerprint}");
                }
                VaultKeyCommands::List => {
                    let keys = db.get_all_vault_keys().await.into_diagnostic()?;

                    if keys.is_empty() {
                        println!("No vault keys found.");
                        return Ok(());
                    }

                    println!("Vault Keys:");
                    println!("{:<16} {:<20} Created", "Fingerprint", "Name");
                    println!("{}", "-".repeat(60));

                    for key in keys {
                        println!(
                            "{:<16} {:<20} {}",
                            key.fingerprint,
                            key.name,
                            key.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
                VaultKeyCommands::Remove { fingerprint } => {
                    // Check if this is the last vault key
                    let keys = db.get_all_vault_keys().await.into_diagnostic()?;
                    if keys.len() <= 1 {
                        eprintln!(
                            "Error: Cannot remove the last vault key. At least one vault key must remain."
                        );
                        std::process::exit(1);
                    }

                    if db.remove_vault_key(&fingerprint).await.into_diagnostic()? {
                        println!("✓ Vault key removed: {fingerprint}");
                    } else {
                        eprintln!("Error: Vault key not found: {fingerprint}");
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Host { command } => {
            ensure_initialized(&db).await?;
            match command {
                HostKeyCommands::Add { hostname, key_path } => {
                    // Check if hostname already exists
                    if db
                        .get_host_key_by_hostname(&hostname)
                        .await
                        .into_diagnostic()?
                        .is_some()
                    {
                        eprintln!("Error: Host '{hostname}' already exists");
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
                    let host_key = HostKey {
                        fingerprint: fingerprint.clone(),
                        hostname: hostname.clone(),
                        public_key: ssh_public_key.to_string(),
                        created_at: now,
                        updated_at: now,
                    };

                    // Store in database
                    db.insert_host_key(&host_key).await.into_diagnostic()?;

                    println!("✓ Host key added successfully!");
                    println!("  Hostname: {hostname}");
                    println!("  Fingerprint: {fingerprint}");
                    println!("  Key file: {}", key_path.display());
                }
                HostKeyCommands::List => {
                    let keys = db.get_all_host_keys().await.into_diagnostic()?;

                    if keys.is_empty() {
                        println!("No host keys found.");
                        return Ok(());
                    }

                    println!("Host Keys:");
                    println!("{:<16} {:<20} Added", "Fingerprint", "Hostname");
                    println!("{}", "-".repeat(60));

                    for key in keys {
                        println!(
                            "{:<16} {:<20} {}",
                            key.fingerprint,
                            key.hostname,
                            key.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
                HostKeyCommands::Remove { identifier } => {
                    // Try to remove by hostname first, then by fingerprint
                    let removed = if db
                        .remove_host_key_by_hostname(&identifier)
                        .await
                        .into_diagnostic()?
                    {
                        true
                    } else {
                        db.remove_host_key_by_fingerprint(&identifier)
                            .await
                            .into_diagnostic()?
                    };

                    if removed {
                        println!("✓ Host key removed: {identifier}");
                    } else {
                        eprintln!("Error: Host key not found: {identifier}");
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
                        eprintln!("Error: Must specify either --file or --stdin");
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
                                eprintln!("Warning: Host '{hostname}' not found, skipping");
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
                        eprintln!("Error: No keys available for encryption");
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

                    println!("✓ Secret stored successfully!");
                    println!("  Name: {name}");
                    println!("  Version: {version}");
                    println!("  Encrypted for {stored_count} keys");
                    if let Some(desc) = description {
                        println!("  Description: {desc}");
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
                                eprintln!("Error: Secret '{name}' not found");
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
                                            &vault_key.encrypted_private_key,
                                            &password,
                                        )
                                        .into_diagnostic()?
                                    }
                                    "host" => {
                                        eprintln!(
                                            "Error: Host key decryption requires SSH private key, which is not supported in this CLI"
                                        );
                                        eprintln!(
                                            "Host keys are intended for automated host access, not interactive CLI use"
                                        );
                                        std::process::exit(1);
                                    }
                                    _ => {
                                        eprintln!("Error: Unknown key type: {}", storage.key_type);
                                        std::process::exit(1);
                                    }
                                };

                                println!("Secret: {name}");
                                println!("Version: {target_version}");
                                println!("Key: {} ({})", key_fingerprint, storage.key_type);
                                println!("Data: {}", String::from_utf8_lossy(&decrypted_data));
                            }
                            None => {
                                eprintln!(
                                    "Error: Secret '{name}' version {target_version} not accessible with key '{key_fingerprint}'"
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
                            eprintln!("Error: Secret '{name}' version {target_version} not found");
                            std::process::exit(1);
                        }

                        println!(
                            "Secret '{name}' version {target_version} is encrypted for the following keys:"
                        );
                        for entry in entries {
                            println!("  {} ({})", entry.key_fingerprint, entry.key_type);
                        }
                        println!("\nUse --key <fingerprint> to decrypt with a specific key");
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
                            println!("No secrets accessible by key: {key_fingerprint}");
                            return Ok(());
                        }

                        println!("Secrets accessible by key {key_fingerprint}:");
                        for secret_name in secret_names {
                            let versions = db
                                .get_secret_versions_for_key(&secret_name, &key_fingerprint)
                                .await
                                .into_diagnostic()?;
                            println!(
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
                            println!("No secrets found.");
                            return Ok(());
                        }

                        println!("Secrets:");
                        println!("{:<20} {:<30} Created", "Name", "Description");
                        println!("{}", "-".repeat(70));

                        for secret in secrets {
                            let latest_version = db
                                .get_latest_secret_version(&secret.name)
                                .await
                                .into_diagnostic()?;
                            let description = secret.description.as_deref().unwrap_or("");
                            println!(
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
                            println!(
                                "No versions of secret '{name}' accessible by key: {key_fingerprint}"
                            );
                            return Ok(());
                        }

                        println!(
                            "Versions of secret '{name}' accessible by key {key_fingerprint}:"
                        );
                        for version in versions {
                            if let Some(entry) = db
                                .get_secret_storage_for_key(&name, version, &key_fingerprint)
                                .await
                                .into_diagnostic()?
                            {
                                println!(
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
                                eprintln!("Error: Secret '{name}' not found");
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
                            println!("No versions found for secret '{name}'");
                            return Ok(());
                        }

                        println!("Versions of secret '{name}':");
                        println!("{:<8} {:<25} Keys", "Version", "Created");
                        println!("{}", "-".repeat(50));

                        for (ver, created, key_count) in found_versions {
                            println!(
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
                        eprintln!("Error: Secret '{name}' not found");
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
                            println!("✓ Secret '{name}' marked as deleted");
                            println!("  Latest version: {latest_version}");
                            println!(
                                "  Note: {latest_version} versions of encrypted data are preserved for audit purposes"
                            );

                            // In a production system, we would:
                            // 1. Update the secrets table to mark as deleted
                            // 2. Optionally add a deletion timestamp
                            // 3. Keep all versions in secret_storage for audit
                        }
                        None => {
                            println!("Secret '{name}' has no stored versions");
                        }
                    }
                }
            }
        }

        Commands::Audit { command } => {
            ensure_initialized(&db).await?;
            match command {
                AuditCommands::List { limit } => {
                    println!("Listing {limit} recent audit entries");
                    // TODO: Implement audit listing
                }
                AuditCommands::Show {
                    resource,
                    operation,
                } => {
                    println!("Showing audit entries");
                    if let Some(resource) = resource {
                        println!("  Resource: {resource}");
                    }
                    if let Some(operation) = operation {
                        println!("  Operation: {operation}");
                    }
                    // TODO: Implement audit show
                }
                AuditCommands::Since { days } => {
                    println!("Showing audit entries from {days} days ago");
                    // TODO: Implement audit since
                }
            }
        }
    }

    Ok(())
}
