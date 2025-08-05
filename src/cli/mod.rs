use clap::{Parser, Subcommand, ValueEnum, ValueHint};
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
    Key {
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

    /// Export data in various formats
    Export {
        #[command(subcommand)]
        command: ExportCommands,
    },

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completion for
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    /// Internal completion helper (hidden from help)
    #[command(hide = true)]
    CompleteValues {
        /// Type of values to complete
        #[arg(value_enum)]
        value_type: CompletionValueType,
        /// Optional filter prefix
        prefix: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CompletionShell {
    /// Bash shell completion
    Bash,
    /// Zsh shell completion
    Zsh,
    /// Fish shell completion
    Fish,
    /// PowerShell completion
    PowerShell,
    /// Elvish shell completion
    Elvish,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CompletionValueType {
    /// Complete secret names
    Secrets,
    /// Complete key identifiers (hostnames and fingerprints)
    Keys,
    /// Complete vault key names
    VaultKeys,
    /// Complete host key names/hostnames
    HostKeys,
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
        #[arg(value_hint = ValueHint::Other)]
        identifier: String,
    },

    /// Rename a key
    Rename {
        /// Key fingerprint, vault key name, or hostname to rename
        #[arg(value_hint = ValueHint::Other)]
        identifier: String,
        /// New name for the key
        new_name: String,
    },

    /// List secrets accessible by a host key
    ListSecrets {
        /// Hostname or key fingerprint to check access for
        #[arg(value_hint = ValueHint::Other)]
        identifier: String,
    },

    /// List all SSH keys found on the local host (hidden debug command)
    #[command(hide = true)]
    ListHostKeys,
}

#[derive(Subcommand, Debug)]
pub enum SecretCommands {
    /// Store a secret
    Store {
        /// Name of the secret
        #[arg(value_hint = ValueHint::Other)]
        name: String,
        /// Hosts that should have access to this secret (defaults to all hosts if none specified)
        hosts: Vec<String>,
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
        #[arg(value_hint = ValueHint::Other)]
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

    /// Show information about a secret without exposing its content
    Info {
        /// Name of the secret
        #[arg(value_hint = ValueHint::Other)]
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
        #[arg(value_hint = ValueHint::Other)]
        name: String,
        /// Hosts that should have access to this secret (defaults to all hosts if none specified)
        hosts: Vec<String>,
        /// Length of the generated secret
        #[arg(long, default_value = "32")]
        length: usize,
        /// Format of the generated secret
        #[arg(long, default_value = "hex", value_parser = ["hex", "base64", "alphanumeric"])]
        format: String,
        /// Optional description for the secret
        #[arg(long)]
        description: Option<String>,
    },

    /// Edit a secret using $EDITOR
    Edit {
        /// Name of the secret to edit
        name: String,
        /// Key fingerprint to use for decryption
        #[arg(long)]
        key: Option<String>,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// Share secrets with a host
    Share {
        /// Hostname to share secrets with
        host: String,
        /// Names of the secrets to share
        secrets: Vec<String>,
        /// Vault key fingerprint to use for decryption
        #[arg(long)]
        vault_key: Option<String>,
        /// Path to file containing the password (for non-interactive use)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },

    /// Unshare secrets from a host
    Unshare {
        /// Hostname to unshare secrets from
        host: String,
        /// Names of the secrets to unshare
        secrets: Vec<String>,
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

#[derive(Subcommand, Debug)]
pub enum ExportCommands {
    /// Export key relationships as DOT graph
    Dot {
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Export keys as CSV
    Csv {
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Export secrets as encrypted systemd credentials
    SystemdCreds {
        /// Target directory for credential files
        directory: std::path::PathBuf,
        /// Encrypt for system-wide credentials
        #[arg(long)]
        system: bool,
        /// Encrypt for user-scoped credentials (default)
        #[arg(long)]
        user: bool,
        /// Overwrite existing credential files
        #[arg(long)]
        force: bool,
        /// Host key fingerprint or hostname to export secrets for (defaults to current hostname)
        #[arg(long)]
        key: Option<String>,
    },
}
