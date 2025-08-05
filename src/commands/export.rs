use lilvault::cli::ExportCommands;
use lilvault::db::Database;
use miette::{IntoDiagnostic, Result};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use tracing::{info, warn};

/// Handle export commands
pub async fn handle_export(db: &Database, command: ExportCommands) -> Result<()> {
    match command {
        ExportCommands::Dot { output } => handle_dot_export(db, output).await,

        ExportCommands::Csv { output } => handle_csv_export(db, output).await,

        ExportCommands::SystemdCreds {
            directory,
            system,
            user,
            force,
            key,
        } => handle_systemd_creds_export(db, directory, system, user, force, key).await,
    }
}

async fn handle_dot_export(db: &Database, output: Option<std::path::PathBuf>) -> Result<()> {
    // Get all keys (always include both vault and host keys)
    let mut all_keys = db.get_all_vault_keys().await.into_diagnostic()?;
    let mut host_keys = db.get_all_host_keys().await.into_diagnostic()?;
    all_keys.append(&mut host_keys);

    // Always get secrets metadata for DOT graph
    let secrets = db.get_all_secrets().await.into_diagnostic()?;

    // Generate DOT graph
    let mut dot_content = String::new();
    dot_content.push_str("digraph lilvault_keys {\n");
    dot_content.push_str("  rankdir=LR;\n");
    dot_content.push_str("  node [shape=box];\n\n");

    // Add nodes for keys
    for key in &all_keys {
        let node_id = format!("key_{}", &key.fingerprint[..8]);
        let label = format!(
            "{}\\n{}\\n{}",
            key.name,
            key.key_type,
            &key.fingerprint[..8]
        );
        let color = if key.key_type == "vault" {
            "lightblue"
        } else {
            "lightgreen"
        };

        dot_content.push_str(&format!(
            "  {node_id} [label=\"{label}\" fillcolor=\"{color}\" style=\"filled\"];\n"
        ));
    }

    // Add nodes for secrets
    for secret in &secrets {
        let node_id = format!("secret_{}", secret.name.replace(['-', '.'], "_"));
        let label = format!("{}\\nsecret", secret.name);

        dot_content.push_str(&format!(
            "  {node_id} [label=\"{label}\" fillcolor=\"lightyellow\" style=\"filled\" shape=\"ellipse\"];\n"
        ));
    }

    // Add relationships (vault keys can decrypt secrets that host keys can access)
    dot_content.push_str("\n  // Key relationships\n");
    let vault_keys: Vec<_> = all_keys.iter().filter(|k| k.key_type == "vault").collect();
    let host_keys: Vec<_> = all_keys.iter().filter(|k| k.key_type == "host").collect();

    // Connect vault keys to host keys (representing that vault keys can manage host access)
    for vault_key in &vault_keys {
        for host_key in &host_keys {
            let vault_node = format!("key_{}", &vault_key.fingerprint[..8]);
            let host_node = format!("key_{}", &host_key.fingerprint[..8]);
            dot_content.push_str(&format!(
                "  {vault_node} -> {host_node} [style=\"dashed\" color=\"gray\" label=\"manages\"];\n"
            ));
        }
    }

    // Add relationships between keys and secrets (always included)
    if !secrets.is_empty() {
        dot_content.push_str("\n  // Key-Secret relationships\n");

        for secret in &secrets {
            let secret_node = format!("secret_{}", secret.name.replace(['-', '.'], "_"));

            // All vault keys can access all secrets
            for vault_key in &vault_keys {
                let vault_node = format!("key_{}", &vault_key.fingerprint[..8]);
                dot_content.push_str(&format!(
                    "  {vault_node} -> {secret_node} [color=\"blue\" label=\"can decrypt\"];\n"
                ));
            }

            // In the future, we could query which specific host keys have access to each secret
            // For now, we'll show that host keys can potentially access secrets (via vault key management)
            for host_key in &host_keys {
                let host_node = format!("key_{}", &host_key.fingerprint[..8]);
                dot_content.push_str(&format!(
                    "  {secret_node} -> {host_node} [color=\"green\" style=\"dashed\" label=\"accessible by\"];\n"
                ));
            }
        }
    }

    dot_content.push_str("}\n");

    // Write output
    match output {
        Some(path) => {
            let mut file = File::create(&path).into_diagnostic()?;
            file.write_all(dot_content.as_bytes()).into_diagnostic()?;
            info!("DOT graph exported to: {}", path.display());
        }
        None => {
            print!("{dot_content}");
        }
    }

    Ok(())
}

async fn handle_csv_export(db: &Database, output: Option<std::path::PathBuf>) -> Result<()> {
    // Get all keys (always include both vault and host keys)
    let mut all_keys = db.get_all_vault_keys().await.into_diagnostic()?;
    let mut host_keys = db.get_all_host_keys().await.into_diagnostic()?;
    all_keys.append(&mut host_keys);
    all_keys.sort_by(|a, b| a.name.cmp(&b.name));

    // Always get secrets metadata
    let secrets = db.get_all_secrets().await.into_diagnostic()?;

    // Generate CSV content (always export all data)
    let mut csv_content = String::new();
    csv_content.push_str("type,identifier,name,key_type,created_at,updated_at,description\n");

    // Add all keys
    for key in all_keys {
        csv_content.push_str(&format!(
            "key,{},{},{},{},{},\n",
            key.fingerprint,
            key.name,
            key.key_type,
            key.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            key.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    // Add all secrets metadata
    for secret in secrets {
        csv_content.push_str(&format!(
            "secret,{},{},secret,{},{},{}\n",
            secret.name,
            secret.name,
            secret.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            secret.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            secret.description.as_deref().unwrap_or("")
        ));
    }

    // Write output
    match output {
        Some(path) => {
            let mut file = File::create(&path).into_diagnostic()?;
            file.write_all(csv_content.as_bytes()).into_diagnostic()?;
            info!("CSV exported to: {}", path.display());
        }
        None => {
            print!("{csv_content}");
        }
    }

    Ok(())
}

async fn handle_systemd_creds_export(
    db: &Database,
    directory: PathBuf,
    system: bool,
    _user: bool,
    force: bool,
    key: Option<String>,
) -> Result<()> {
    use lilvault::crypto::decrypt_with_ssh_identity;

    // First, determine which host we're exporting for
    let target_host_key = match key.clone() {
        Some(identifier) => {
            // Try to find the host key by identifier
            if let Some(key) = db.get_key(&identifier).await.into_diagnostic()? {
                if key.key_type == "host" {
                    key
                } else {
                    return Err(miette::miette!("Key '{}' is not a host key", identifier));
                }
            } else if let Some(key) = db
                .get_host_key_by_hostname(&identifier)
                .await
                .into_diagnostic()?
            {
                key
            } else {
                return Err(miette::miette!("Host key not found: {}", identifier));
            }
        }
        None => {
            // Get current hostname and find corresponding host key
            let hostname = std::process::Command::new("hostname")
                .output()
                .into_diagnostic()?
                .stdout;
            let hostname = String::from_utf8(hostname)
                .into_diagnostic()?
                .trim()
                .to_string();

            db.get_host_key_by_hostname(&hostname)
                .await
                .into_diagnostic()?
                .ok_or_else(|| {
                    miette::miette!("No host key found for hostname '{}'. Add a host key first with: lilvault keys add-host {} <ssh-public-key-path>", hostname, hostname)
                })?
        }
    };

    info!("Exporting secrets for host '{}'", target_host_key.name);

    // Get secrets accessible by this host key
    let secret_names = db
        .get_secrets_for_key(&target_host_key.fingerprint)
        .await
        .into_diagnostic()?;

    if secret_names.is_empty() {
        info!("No secrets accessible by host '{}'", target_host_key.name);
        return Ok(());
    }

    // Load the SSH private key for the host
    let ssh_identity = load_host_ssh_identity(&target_host_key.name)?;

    info!("Using SSH private key for host '{}'", target_host_key.name);

    // Ensure directory exists
    create_dir_all(&directory).into_diagnostic()?;

    let mut exported_count = 0;
    let mut skipped_count = 0;

    for secret_name in secret_names {
        let cred_file = directory.join(format!("{secret_name}.cred"));

        // Check if file exists and handle force flag
        if cred_file.exists() && !force {
            warn!(
                "Skipping {}: credential file already exists (use --force to overwrite)",
                secret_name
            );
            skipped_count += 1;
            continue;
        }

        // Get the latest version of the secret
        let latest_version = db
            .get_latest_secret_version(&secret_name)
            .await
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("No versions found for secret '{}'", secret_name))?;

        // Get the encrypted secret data for the host key
        let secret_storage = db
            .get_secret_storage_for_key(&secret_name, latest_version, &target_host_key.fingerprint)
            .await
            .into_diagnostic()?
            .ok_or_else(|| {
                miette::miette!(
                    "Secret '{}' not accessible by host key {}",
                    secret_name,
                    target_host_key.fingerprint
                )
            })?;

        // Decrypt the secret data using the SSH identity
        let decrypted_data =
            decrypt_with_ssh_identity(&secret_storage.encrypted_data, &ssh_identity)
                .into_diagnostic()?;

        // Create a temporary file with the decrypted (plaintext) data
        let temp_file = std::env::temp_dir().join(format!("lilvault_temp_{secret_name}"));
        std::fs::write(&temp_file, &decrypted_data).into_diagnostic()?;

        // Build systemd-creds command
        let mut cmd = std::process::Command::new("systemd-creds");
        cmd.arg("encrypt")
            .arg("--with-key=host")
            .arg(&temp_file)
            .arg(&cred_file);

        // Determine if we should use system or user credentials
        let use_system = if system {
            // Explicitly requested system credentials
            true
        } else if is_running_as_root() {
            // If running as root and no explicit --user flag, default to system
            !_user // Only use system if --user wasn't explicitly set
        } else {
            // Non-root users default to user credentials
            false
        };

        if !use_system {
            // User credentials
            cmd.arg("--user");
        }
        // System credentials are the default behavior (no extra flag needed)

        // Execute the command
        let output = cmd.output().into_diagnostic()?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_file);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette::miette!(
                "Failed to encrypt credential '{}': {}",
                secret_name,
                stderr
            ));
        }

        info!("Exported {} to {}", secret_name, cred_file.display());
        exported_count += 1;
    }

    info!(
        "SystemD credentials export complete: {} exported, {} skipped",
        exported_count, skipped_count
    );

    Ok(())
}

/// Load SSH private key for the host
fn load_host_ssh_identity(hostname: &str) -> Result<lilvault::crypto::SshIdentityType> {
    lilvault::crypto::load_host_ssh_identity(hostname).into_diagnostic()
}

/// Check if the current process is running as root
fn is_running_as_root() -> bool {
    // Check if the USER environment variable is root, or if we're running with UID 0
    std::env::var("USER").unwrap_or_default() == "root"
        || std::env::var("USERNAME").unwrap_or_default() == "root"
        || std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
            .unwrap_or(false)
}
