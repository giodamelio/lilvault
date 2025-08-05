// Clippy lints to prevent unsafe operations
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]

use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use lilvault::cli::{Cli, Commands, CompletionShell, CompletionValueType};
use lilvault::db::Database;
use miette::{IntoDiagnostic, Result};
use std::io;
use tracing::{error, info};

mod commands;

/// Generate shell completion script
fn generate_completion(shell: CompletionShell) -> Result<()> {
    match shell {
        CompletionShell::Bash => generate_bash_completion(),
        CompletionShell::Zsh => generate_zsh_completion(),
        CompletionShell::Fish => generate_fish_completion(),
        CompletionShell::PowerShell => generate_powershell_completion(),
        CompletionShell::Elvish => generate_elvish_completion(),
    }
}

/// Generate enhanced Bash completion with dynamic support
fn generate_bash_completion() -> Result<()> {
    let mut cmd = Cli::command();
    generate(Shell::Bash, &mut cmd, "lilvault", &mut io::stdout());

    // Add custom dynamic completion logic
    println!(
        r#"
# Enhanced lilvault completion with dynamic values
_lilvault_complete_secrets() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=( $(compgen -W "$(lilvault complete-values secrets 2>/dev/null || true)" -- "$cur") )
}}

_lilvault_complete_keys() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=( $(compgen -W "$(lilvault complete-values keys 2>/dev/null || true)" -- "$cur") )
}}

_lilvault_complete_vault_keys() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=( $(compgen -W "$(lilvault complete-values vault-keys 2>/dev/null || true)" -- "$cur") )
}}

_lilvault_complete_host_keys() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=( $(compgen -W "$(lilvault complete-values host-keys 2>/dev/null || true)" -- "$cur") )
}}

# Override completion for specific commands
complete -F _lilvault_complete_secrets -o default lilvault secret get
complete -F _lilvault_complete_secrets -o default lilvault secret info
complete -F _lilvault_complete_secrets -o default lilvault secret delete
complete -F _lilvault_complete_secrets -o default lilvault secret edit
complete -F _lilvault_complete_keys -o default lilvault key remove
complete -F _lilvault_complete_keys -o default lilvault key rename
complete -F _lilvault_complete_host_keys -o default lilvault key list-secrets
"#
    );
    Ok(())
}

/// Generate enhanced Zsh completion with dynamic support
fn generate_zsh_completion() -> Result<()> {
    // Generate the base completion first
    let mut cmd = Cli::command();
    let mut output = Vec::new();
    generate(
        Shell::Zsh,
        &mut cmd,
        "lilvault",
        &mut std::io::Cursor::new(&mut output),
    );
    let base_completion = String::from_utf8(output).into_diagnostic()?;

    // Print the base completion but modify specific argument patterns
    let enhanced_completion = base_completion
        .replace(
            "':name -- Name of the secret:'",
            "':name -- Name of the secret:_lilvault_complete_secrets'"
        )
        .replace(
            "':identifier -- Key fingerprint or hostname to remove:'",
            "':identifier -- Key fingerprint or hostname to remove:_lilvault_complete_keys'"
        )
        .replace(
            "':identifier -- Key fingerprint, vault key name, or hostname to rename:'",
            "':identifier -- Key fingerprint, vault key name, or hostname to rename:_lilvault_complete_keys'"
        )
        .replace(
            "':identifier -- Hostname or key fingerprint to check access for:'",
            "':identifier -- Hostname or key fingerprint to check access for:_lilvault_complete_host_keys'"
        );

    print!("{enhanced_completion}");

    // Add custom dynamic completion functions
    println!(
        r#"
# Dynamic completion functions for lilvault
_lilvault_complete_secrets() {{
    local secrets=($(lilvault complete-values secrets 2>/dev/null || echo))
    _describe 'secrets' secrets
}}

_lilvault_complete_keys() {{
    local keys=($(lilvault complete-values keys 2>/dev/null || echo))
    _describe 'keys' keys
}}

_lilvault_complete_host_keys() {{
    local host_keys=($(lilvault complete-values host-keys 2>/dev/null || echo))
    _describe 'host-keys' host_keys
}}"#
    );
    Ok(())
}

/// Generate Fish completion (basic implementation)
fn generate_fish_completion() -> Result<()> {
    let mut cmd = Cli::command();
    generate(Shell::Fish, &mut cmd, "lilvault", &mut io::stdout());
    println!("# Fish dynamic completion support would go here");
    Ok(())
}

/// Generate PowerShell completion (basic implementation)
fn generate_powershell_completion() -> Result<()> {
    let mut cmd = Cli::command();
    generate(Shell::PowerShell, &mut cmd, "lilvault", &mut io::stdout());
    println!("# PowerShell dynamic completion support would go here");
    Ok(())
}

/// Generate Elvish completion (basic implementation)
fn generate_elvish_completion() -> Result<()> {
    let mut cmd = Cli::command();
    generate(Shell::Elvish, &mut cmd, "lilvault", &mut io::stdout());
    println!("# Elvish dynamic completion support would go here");
    Ok(())
}

/// Handle dynamic completion values
async fn handle_complete_values(
    db: &Database,
    value_type: CompletionValueType,
    prefix: Option<&str>,
) -> Result<()> {
    match value_type {
        CompletionValueType::Secrets => {
            let secrets = db.get_all_secrets().await.into_diagnostic()?;
            for secret in secrets {
                if let Some(prefix) = prefix {
                    if secret.name.starts_with(prefix) {
                        println!("{}", secret.name);
                    }
                } else {
                    println!("{}", secret.name);
                }
            }
        }
        CompletionValueType::Keys => {
            // Get both vault and host keys
            let vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;
            let host_keys = db.get_keys_by_type("host").await.into_diagnostic()?;

            for key in vault_keys.iter().chain(host_keys.iter()) {
                let identifier = &key.name;
                if let Some(prefix) = prefix {
                    if identifier.starts_with(prefix) {
                        println!("{identifier}");
                    }
                } else {
                    println!("{identifier}");
                }
            }
        }
        CompletionValueType::VaultKeys => {
            let vault_keys = db.get_keys_by_type("vault").await.into_diagnostic()?;
            for key in vault_keys {
                if let Some(prefix) = prefix {
                    if key.name.starts_with(prefix) {
                        println!("{}", key.name);
                    }
                } else {
                    println!("{}", key.name);
                }
            }
        }
        CompletionValueType::HostKeys => {
            let host_keys = db.get_keys_by_type("host").await.into_diagnostic()?;
            for key in host_keys {
                if let Some(prefix) = prefix {
                    if key.name.starts_with(prefix) {
                        println!("{}", key.name);
                    }
                } else {
                    println!("{}", key.name);
                }
            }
        }
    }
    Ok(())
}

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
        Commands::Completion { shell } => {
            generate_completion(shell)?;
        }
        Commands::CompleteValues { value_type, prefix } => {
            handle_complete_values(&db, value_type, prefix.as_deref()).await?;
        }
    }

    Ok(())
}
