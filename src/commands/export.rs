use lilvault::cli::ExportCommands;
use lilvault::db::Database;
use miette::{IntoDiagnostic, Result};
use std::fs::File;
use std::io::Write;
use tracing::info;

/// Handle export commands
pub async fn handle_export(db: &Database, command: ExportCommands) -> Result<()> {
    match command {
        ExportCommands::Dot { output } => handle_dot_export(db, output).await,

        ExportCommands::Csv { output } => handle_csv_export(db, output).await,
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
