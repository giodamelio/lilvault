use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "lilvault")]
pub struct Cli {
    /// Path to the vault database file
    #[arg(short, long, default_value = "vault.db", env = "LILVAULT_DB")]
    pub database: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new vault
    Init {
        /// Name for the initial vault key
        #[arg(long, default_value = "primary")]
        name: String,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// Vault key management
    Vault {
        #[command(subcommand)]
        command: VaultKeyCommands,
    },

    /// Host key management
    Host {
        #[command(subcommand)]
        command: HostKeyCommands,
    },

    /// Secret management
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },

    /// Audit log commands
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum VaultKeyCommands {
    /// Add a new vault key
    Add {
        /// Name for the vault key
        #[arg(long)]
        name: String,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// List all vault keys
    List,

    /// Remove a vault key
    Remove {
        /// Fingerprint of the vault key to remove
        fingerprint: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum HostKeyCommands {
    /// Add a host key
    Add {
        /// Hostname for the key
        hostname: String,
        /// Path to SSH public key file
        key_path: PathBuf,
    },

    /// List all host keys
    List,

    /// Remove a host key
    Remove {
        /// Hostname or fingerprint to remove
        identifier: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecretCommands {
    /// Store a secret
    Store {
        /// Name of the secret
        name: String,
        /// Hosts that should have access (comma-separated)
        #[arg(long)]
        hosts: Option<String>,
        /// Read secret from file
        #[arg(long, conflicts_with = "stdin")]
        file: Option<PathBuf>,
        /// Read secret from stdin
        #[arg(long)]
        stdin: bool,
        /// Optional description for the secret
        #[arg(long)]
        description: Option<String>,
    },

    /// Retrieve a secret
    Get {
        /// Name of the secret
        name: String,
        /// Specific version to retrieve
        #[arg(long)]
        version: Option<i64>,
        /// Key fingerprint to use for decryption
        #[arg(long)]
        key: Option<String>,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// List secrets
    List {
        /// Only show secrets accessible by this key
        #[arg(long)]
        key: Option<String>,
    },

    /// Show versions of a secret
    Versions {
        /// Name of the secret
        name: String,
        /// Only show versions accessible by this key
        #[arg(long)]
        key: Option<String>,
    },

    /// Delete a secret (marks as deleted, doesn't remove versions)
    Delete {
        /// Name of the secret to delete
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List recent audit log entries
    List {
        /// Maximum number of entries to show
        #[arg(long, default_value = "50")]
        limit: i64,
    },

    /// Show audit entries for a specific resource
    Show {
        /// Resource name to show entries for
        #[arg(long)]
        resource: Option<String>,
        /// Operation type to filter by
        #[arg(long)]
        operation: Option<String>,
    },

    /// Show audit entries since a number of days ago
    Since {
        /// Number of days to look back
        #[arg(long)]
        days: i64,
    },
}
