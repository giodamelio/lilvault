# LilVault

> **⚠️ EXTREMELY EXPERIMENTAL - DO NOT USE IN PRODUCTION ⚠️**
>
> This project is **highly experimental** and was developed using **Claude Code** AI assistance. It is **NOT** ready for production use and should **NOT** be used to store real secrets or sensitive data. Consider this a proof-of-concept or learning project only.
>
> **You have been warned!** Use at your own risk. 🚨

## What is LilVault?

LilVault is an experimental secrets management system designed for homelabs. It provides encrypted secret storage with per-host access control using SSH public keys and password-protected vault keys.

## Key Features (Experimental)

- **Single SQLite file**: Portable vault that can be distributed to multiple hosts
- **Per-host encryption**: Each secret encrypted separately for each target host using SSH public keys
- **Vault keys**: Password-protected administrative keys for full vault access
- **Version control**: Secrets are versioned, never deleted
- **Audit logging**: Simple audit trail for debugging
- **Shell completion**: Auto-completion for commands and dynamic data

## Basic Usage

```bash
# Initialize a new vault
lilvault init --name "primary"

# Add a host key (SSH public key)
lilvault key add-host myserver /path/to/host_key.pub

# Store a secret
lilvault secret store api-key --file secret.txt

# Retrieve a secret
lilvault secret get api-key

# List all secrets
lilvault secret list

# Generate shell completion
lilvault completion bash > lilvault-completion.bash
```

## Architecture

- **Database**: SQLite with automatic migrations
- **Encryption**: [age](https://age-encryption.org/) with SSH key support
- **CLI**: Built with Rust and [clap](https://docs.rs/clap/)
- **Completion**: Dynamic shell completion for secrets and keys

## Development Status

This project is in **very early development** and was created as an experiment with AI-assisted coding using Claude Code. Many features are incomplete, untested, or may not work as expected.

### What Works (Maybe)
- Basic vault initialization
- Key management (vault and host keys)
- Secret storage and retrieval
- Shell completion generation
- Audit logging

### What Doesn't Work (Probably)
- Production-ready security
- Edge cases and error handling
- Performance at scale
- Data migration between versions
- Pretty much everything else

## Installation

**Don't install this.** But if you insist on experimenting:

```bash
git clone <this-repo>
cd lilvault
cargo build --release
```

### Nix Package

If you're using Nix, the package includes shell completions for all supported shells:

```bash
nix build .#lilvault
```

**Completion Files Included:**
- **Bash, Zsh, Fish**: Installed to standard system locations (auto-discovered by shells)
- **PowerShell**: Available at `$out/share/lilvault/completions/lilvault.ps1`
- **Elvish**: Available at `$out/share/lilvault/completions/lilvault.elv`

To manually install PowerShell/Elvish completions, copy them to your shell's completion directory or source them in your shell configuration.

## Contributing

This is an experimental project. While contributions are welcome, please understand that this is not production software and the codebase may change dramatically or be abandoned at any time.

## License

[License TBD] - but definitely includes "No warranty, use at your own risk"

## Disclaimer

Again, to be absolutely clear: **THIS IS EXPERIMENTAL SOFTWARE**. Do not use it for anything important. It was built as a learning exercise with AI assistance and has not been audited, tested thoroughly, or validated for security. You probably shouldn't even run it on your computer.

*Made with [Claude Code](https://claude.ai/code) 🤖*
