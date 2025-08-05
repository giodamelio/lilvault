use lilvault::crypto::{generate_fingerprint, generate_master_key, get_password_with_confirmation};
use lilvault::db::{Database, models::Key};
use miette::{IntoDiagnostic, Result};
use std::path::Path;
use tracing::{error, info};

/// Handle the init command
pub async fn handle_init(db: &Database, name: String, password_file: Option<&Path>) -> Result<()> {
    if db.is_initialized().await.into_diagnostic()? {
        error!("Vault is already initialized");
        std::process::exit(1);
    }

    // Get password
    let password =
        get_password_with_confirmation("Enter password for vault key", password_file, true)
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

    Ok(())
}
