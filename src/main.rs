// Clippy lints to prevent unsafe operations
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]

use clap::Parser;
use lilvault::cli::{Cli, Commands};
use lilvault::db::Database;
use miette::{IntoDiagnostic, Result};
use tracing::{error, info};

mod commands;

/// Helper function to check if the vault database is properly initialized
async fn ensure_initialized(db: &Database) -> Result<()> {
    if !db.is_initialized().await.into_diagnostic()? {
        error!("Vault not initialized. Run 'lilvault init' first.");
        std::process::exit(1);
    }
    Ok(())
}

/// Re-encrypt all existing secrets for a new key
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
            commands::init::handle_init(&db, name, password_file.as_deref()).await?;
            info!("  Database: {}", cli.database.display());
        }

        Commands::Key { command } => {
            ensure_initialized(&db).await?;
            commands::keys::handle_keys(&db, command).await?;
        }
        Commands::Secret { command } => {
            ensure_initialized(&db).await?;
            commands::secrets::handle_secrets(&db, command).await?;
        }
        Commands::Audit { command } => {
            ensure_initialized(&db).await?;
            commands::audit::handle_audit(&db, command).await?;
        }
        Commands::Export { command } => {
            ensure_initialized(&db).await?;
            commands::export::handle_export(&db, command).await?;
        }
    }

    Ok(())
}
