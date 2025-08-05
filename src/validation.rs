use miette::{Result, miette};
use std::net::IpAddr;
use std::path::Path;

/// Helper function to check if a string contains only alphanumeric characters, hyphens, underscores, and/or dots
fn is_alphanumeric_with_separators(s: &str, allow_spaces: bool, allow_dots: bool) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || (allow_spaces && c == ' ')
            || (allow_dots && c == '.')
    })
}

/// Validates a hostname or IP address
pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() {
        return Err(miette!("Hostname cannot be empty"));
    }

    // Try to parse as IP address first (using standard library)
    if hostname.parse::<IpAddr>().is_ok() {
        return Ok(()); // Valid IP address
    }

    // Validate as hostname using the hostname-validator crate
    if hostname_validator::is_valid(hostname) {
        Ok(())
    } else {
        Err(miette!(
            "Invalid hostname '{}'. Must be a valid hostname or IP address",
            hostname
        ))
    }
}

/// Validates a secret name - must be non-empty and contain only safe characters
pub fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(miette!("Secret name cannot be empty"));
    }

    if name.len() > 255 {
        return Err(miette!("Secret name cannot exceed 255 characters"));
    }

    // Allow alphanumeric, hyphens, underscores, and dots (no spaces)
    if !is_alphanumeric_with_separators(name, false, true) {
        return Err(miette!(
            "Secret name '{}' contains invalid characters. Only alphanumeric, hyphens, underscores, and dots are allowed",
            name
        ));
    }

    // Don't allow names that start with dots (hidden files)
    if name.starts_with('.') {
        return Err(miette!("Secret name cannot start with a dot"));
    }

    // Don't allow certain reserved names
    let reserved_names = [".", "..", "CON", "PRN", "AUX", "NUL"];
    let upper_name = name.to_uppercase();
    if reserved_names.contains(&upper_name.as_str()) {
        return Err(miette!(
            "Secret name '{}' is reserved and cannot be used",
            name
        ));
    }

    Ok(())
}

/// Validates a vault key name - must be non-empty and reasonable
pub fn validate_vault_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(miette!("Vault key name cannot be empty"));
    }

    if name.len() > 256 {
        return Err(miette!("Vault key name cannot exceed 256 characters"));
    }

    // Allow alphanumeric, hyphens, and underscores (no spaces or dots)
    if !is_alphanumeric_with_separators(name, false, false) {
        return Err(miette!(
            "Vault key name '{}' contains invalid characters. Only alphanumeric characters, hyphens, and underscores are allowed",
            name
        ));
    }

    Ok(())
}

/// Validates that a file path exists and is readable
pub fn validate_file_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(miette!("File '{}' does not exist", path.display()));
    }

    if !path.is_file() {
        return Err(miette!("Path '{}' is not a file", path.display()));
    }

    // Try to check if file is readable
    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(miette!("Cannot read file '{}': {}", path.display(), e)),
    }
}

/// Validates that a directory path exists and is writable
pub fn validate_directory_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(miette!("Directory '{}' does not exist", path.display()));
    }

    if !path.is_dir() {
        return Err(miette!("Path '{}' is not a directory", path.display()));
    }

    // Try to check if directory is writable by creating a temporary file
    let temp_file = path.join(".lilvault_write_test");
    match std::fs::File::create(&temp_file) {
        Ok(_) => {
            // Clean up the test file
            let _ = std::fs::remove_file(&temp_file);
            Ok(())
        }
        Err(e) => Err(miette!(
            "Cannot write to directory '{}': {}",
            path.display(),
            e
        )),
    }
}

/// Validates a port number is in valid range
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(miette!("Port cannot be 0"));
    }
    Ok(())
}

/// Validates a timeout value is reasonable
pub fn validate_timeout(timeout: u64) -> Result<()> {
    if timeout == 0 {
        return Err(miette!("Timeout cannot be 0"));
    }
    if timeout > 300 {
        return Err(miette!("Timeout cannot exceed 300 seconds"));
    }
    Ok(())
}

/// Validates key types string contains only valid SSH key types
pub fn validate_key_types(key_types: &str) -> Result<()> {
    if key_types.is_empty() {
        return Err(miette!("Key types cannot be empty"));
    }

    let valid_types = ["rsa", "ecdsa", "ed25519", "dsa"];
    let types: Vec<&str> = key_types
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if types.is_empty() {
        return Err(miette!("No valid key types specified"));
    }

    for key_type in types {
        if !valid_types.contains(&key_type) {
            return Err(miette!(
                "Invalid key type '{}'. Valid types are: {}",
                key_type,
                valid_types.join(", ")
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_hostname() {
        // Valid hostnames
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("server1").is_ok());
        assert!(validate_hostname("my-server").is_ok());

        // Valid IP addresses
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("::1").is_ok());
        assert!(validate_hostname("2001:db8::1").is_ok());

        // Invalid hostnames
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid").is_err());
        assert!(validate_hostname("invalid-").is_err());
        assert!(validate_hostname("invalid..com").is_err());
        assert!(validate_hostname("invalid$.com").is_err());
    }

    #[test]
    fn test_validate_secret_name() {
        // Valid names
        assert!(validate_secret_name("my-secret").is_ok());
        assert!(validate_secret_name("database_password").is_ok());
        assert!(validate_secret_name("api.key").is_ok());
        assert!(validate_secret_name("secret123").is_ok());

        // Invalid names
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name(".hidden").is_err());
        assert!(validate_secret_name("invalid/name").is_err());
        assert!(validate_secret_name("invalid name").is_err()); // spaces not allowed
        assert!(validate_secret_name("CON").is_err());
    }

    #[test]
    fn test_validate_vault_key_name() {
        // Valid names
        assert!(validate_vault_key_name("primary").is_ok());
        assert!(validate_vault_key_name("backup-key").is_ok());
        assert!(validate_vault_key_name("server_key").is_ok());
        assert!(validate_vault_key_name("key_1").is_ok());

        // Invalid names
        assert!(validate_vault_key_name("").is_err());
        assert!(validate_vault_key_name("invalid@name").is_err());
        assert!(validate_vault_key_name("invalid/name").is_err());
        assert!(validate_vault_key_name("invalid name").is_err()); // spaces not allowed
        assert!(validate_vault_key_name("api.key").is_err()); // dots not allowed
    }

    #[test]
    fn test_vault_key_name_size_limit() {
        let long_name = "a".repeat(256);
        assert!(validate_vault_key_name(&long_name).is_ok());

        let too_long_name = "a".repeat(257);
        assert!(validate_vault_key_name(&too_long_name).is_err());
    }

    #[test]
    fn test_validate_file_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        // Valid file
        assert!(validate_file_path(&file_path).is_ok());

        // Non-existent file
        let missing_path = temp_dir.path().join("missing.txt");
        assert!(validate_file_path(&missing_path).is_err());

        // Directory instead of file
        assert!(validate_file_path(temp_dir.path()).is_err());
    }

    #[test]
    fn test_validate_directory_path() {
        let temp_dir = TempDir::new().unwrap();

        // Valid directory
        assert!(validate_directory_path(temp_dir.path()).is_ok());

        // Non-existent directory
        let missing_dir = temp_dir.path().join("missing");
        assert!(validate_directory_path(&missing_dir).is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(22).is_ok());
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_timeout() {
        assert!(validate_timeout(5).is_ok());
        assert!(validate_timeout(30).is_ok());
        assert!(validate_timeout(300).is_ok());
        assert!(validate_timeout(0).is_err());
        assert!(validate_timeout(301).is_err());
    }

    #[test]
    fn test_validate_key_types() {
        assert!(validate_key_types("rsa").is_ok());
        assert!(validate_key_types("rsa,ecdsa").is_ok());
        assert!(validate_key_types("rsa,ecdsa,ed25519").is_ok());
        assert!(validate_key_types("ed25519").is_ok());

        assert!(validate_key_types("").is_err());
        assert!(validate_key_types("invalid").is_err());
        assert!(validate_key_types("rsa,invalid").is_err());
    }

    #[test]
    fn test_is_alphanumeric_with_separators() {
        // Test with no spaces or dots
        assert!(is_alphanumeric_with_separators("test_key-1", false, false));
        assert!(!is_alphanumeric_with_separators("test key", false, false));
        assert!(!is_alphanumeric_with_separators("test.key", false, false));

        // Test with spaces allowed
        assert!(is_alphanumeric_with_separators("test key", true, false));
        assert!(!is_alphanumeric_with_separators("test.key", true, false));

        // Test with dots allowed
        assert!(is_alphanumeric_with_separators("test.key", false, true));
        assert!(!is_alphanumeric_with_separators("test key", false, true));

        // Test with both allowed
        assert!(is_alphanumeric_with_separators("test key.name", true, true));
    }
}
