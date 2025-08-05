use chrono::Utc;
use lilvault::crypto::{generate_fingerprint, generate_master_key, get_password};
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
    let password = if let Some(path) = password_file {
        get_password("", Some(path)).into_diagnostic()?
    } else {
        let password = get_password("Enter password for vault key", None).into_diagnostic()?;
        let confirm_password = get_password("Confirm password", None).into_diagnostic()?;

        if password != confirm_password {
            error!("Passwords do not match");
            std::process::exit(1);
        }
        password
    };

    // Generate vault key
    let (public_key, encrypted_private_key) = generate_master_key(&password).into_diagnostic()?;
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

    Ok(())
}
