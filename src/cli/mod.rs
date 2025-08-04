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

    /// Key management (vault and host keys)
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
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
pub enum KeyCommands {
    /// Add a new vault key
    AddVault {
        /// Name for the vault key
        #[arg(long)]
        name: String,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Skip re-encrypting existing secrets for this new key
        #[arg(long)]
        no_reencrypt: bool,
    },

    /// Add a host key
    AddHost {
        /// Hostname for the key
        hostname: String,
        /// Path to SSH public key file
        key_path: PathBuf,
        /// Skip re-encrypting existing secrets for this new key
        #[arg(long)]
        no_reencrypt: bool,
        /// Path to file containing the password for re-encryption (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// Scan and import host keys like ssh-keyscan
    ScanHost {
        /// Hostname or IP address to scan
        hostname: String,
        /// Port to scan (default: 22)
        #[arg(short, long, default_value = "22")]
        port: u16,
        /// Key types to scan for (comma-separated: rsa, ecdsa, ed25519)
        #[arg(short, long, default_value = "rsa,ecdsa,ed25519")]
        key_types: String,
        /// Timeout in seconds for connection
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// List all keys (or filter by type)
    List {
        /// Filter by key type (vault or host)
        #[arg(long)]
        key_type: Option<String>,
    },

    /// Remove a key
    Remove {
        /// Key fingerprint or hostname to remove
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

    /// Show information about a secret without exposing its content
    Info {
        /// Name of the secret
        name: String,
    },

    /// Delete a secret (marks as deleted, doesn't remove versions)
    Delete {
        /// Name of the secret to delete
        name: String,
    },

    /// Generate a random secret and store it
    Generate {
        /// Name of the secret
        name: String,
        /// Length of the generated secret
        #[arg(long, default_value = "32")]
        length: usize,
        /// Format of the generated secret
        #[arg(long, default_value = "hex", value_parser = ["hex", "base64", "alphanumeric"])]
        format: String,
        /// Hosts that should have access (comma-separated)
        #[arg(long)]
        hosts: Option<String>,
        /// Optional description for the secret
        #[arg(long)]
        description: Option<String>,
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
