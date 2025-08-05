/// Utility functions for LilVault
///
/// This module contains small, pure functions that can be easily tested
/// and reused throughout the application.
use crate::{LilVaultError, Result};
use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;
/// Parse a comma-separated list of hostnames into a vector
///
/// Trims whitespace from each hostname and filters out empty strings.
///
/// # Examples
///
/// ```
/// use lilvault::utils::parse_hostname_list;
///
/// let hostnames = parse_hostname_list("server1, server2, server3");
/// assert_eq!(hostnames, vec!["server1", "server2", "server3"]);
///
/// let hostnames = parse_hostname_list("server1,server2,  server3  ");
/// assert_eq!(hostnames, vec!["server1", "server2", "server3"]);
///
/// let hostnames = parse_hostname_list("");
/// assert_eq!(hostnames, Vec::<String>::new());
/// ```
pub fn parse_hostname_list(host_list: &str) -> Vec<String> {
    host_list
        .split(',')
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .map(|h| h.to_string())
        .collect()
}

/// Format a timestamp for consistent display across the application
///
/// Uses the format: "YYYY-MM-DD HH:MM:SS UTC"
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone, Utc};
/// use lilvault::utils::format_timestamp;
///
/// let timestamp = Utc.with_ymd_and_hms(2024, 3, 15, 14, 30, 0).unwrap();
/// assert_eq!(format_timestamp(&timestamp), "2024-03-15 14:30:00 UTC");
/// ```
pub fn format_timestamp(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Join a list of items into a comma-separated string
///
/// This is a convenience function for creating readable lists in output.
///
/// # Examples
///
/// ```
/// use lilvault::utils::join_list;
///
/// let versions = vec![1, 2, 3, 4];
/// assert_eq!(join_list(&versions), "1, 2, 3, 4");
///
/// let empty: Vec<i32> = vec![];
/// assert_eq!(join_list(&empty), "");
/// ```
pub fn join_list<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Launch the user's $EDITOR to edit content and return the edited content
/// Returns None if content was unchanged, Some(new_content) if changed
pub fn edit_with_editor(initial_content: &str) -> Result<Option<String>> {
    edit_with_editor_and_instructions(initial_content, None)
}

/// Launch the user's $EDITOR to edit content with custom instructions
/// Returns None if content was unchanged, Some(new_content) if changed
pub fn edit_with_editor_and_instructions(
    initial_content: &str,
    instructions: Option<&str>,
) -> Result<Option<String>> {
    // Get editor from environment, no fallback
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .map_err(|_| LilVaultError::Internal {
            message: "No EDITOR or VISUAL environment variable set. Please set one of these environment variables to your preferred editor.".to_string(),
        })?;

    // Create a temporary file with the initial content
    let mut temp_file = NamedTempFile::new()?;

    // Write content in git-like format: content first, then instructions as comments
    let file_content = if let Some(instr) = instructions {
        format!("{initial_content}\n# {instr}")
    } else if initial_content.is_empty() {
        // For new secrets, start with blank line and instructions below
        "\n# Please enter your secret above.\n# Lines starting with '#' will be ignored, and an empty message aborts the operation.".to_string()
    } else {
        // For existing content, just add it as-is
        initial_content.to_string()
    };

    temp_file.write_all(file_content.as_bytes())?;
    temp_file.flush()?;

    // Launch the editor
    let status = Command::new(&editor).arg(temp_file.path()).status()?;

    if !status.success() {
        return Err(LilVaultError::Internal {
            message: format!("Editor '{editor}' exited with non-zero status"),
        });
    }

    // Read the edited content
    let mut edited_content = String::new();
    temp_file.reopen()?.read_to_string(&mut edited_content)?;

    // Filter out comment lines and trim whitespace (git-like processing)
    let filtered_content: String = edited_content
        .lines()
        .filter(|line| !line.trim().starts_with('#'))
        .collect::<Vec<&str>>()
        .join("\n")
        .trim() // Trim all leading/trailing whitespace including newlines
        .to_string();

    // Check if content is empty (abort operation)
    if filtered_content.is_empty() {
        Ok(None) // Empty content (abort operation)
    } else {
        // Compare filtered content with original content (not trimmed original)
        // This way we detect when whitespace trimming should be applied
        if filtered_content == initial_content {
            Ok(None) // No changes
        } else {
            Ok(Some(filtered_content)) // Content changed or whitespace trimmed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_parse_hostname_list_normal() {
        let result = parse_hostname_list("server1,server2,server3");
        assert_eq!(result, vec!["server1", "server2", "server3"]);
    }

    #[test]
    fn test_parse_hostname_list_with_spaces() {
        let result = parse_hostname_list("server1, server2 , server3  ");
        assert_eq!(result, vec!["server1", "server2", "server3"]);
    }

    #[test]
    fn test_parse_hostname_list_single_hostname() {
        let result = parse_hostname_list("single-server");
        assert_eq!(result, vec!["single-server"]);
    }

    #[test]
    fn test_parse_hostname_list_empty() {
        let result = parse_hostname_list("");
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn test_parse_hostname_list_empty_segments() {
        let result = parse_hostname_list("server1,,server2,  ,server3");
        assert_eq!(result, vec!["server1", "server2", "server3"]);
    }

    #[test]
    fn test_parse_hostname_list_with_special_characters() {
        let result = parse_hostname_list("web-01.prod, db_server, api.example.com");
        assert_eq!(result, vec!["web-01.prod", "db_server", "api.example.com"]);
    }

    #[test]
    fn test_format_timestamp() {
        let timestamp = Utc.with_ymd_and_hms(2024, 3, 15, 14, 30, 45).unwrap();
        let result = format_timestamp(&timestamp);
        assert_eq!(result, "2024-03-15 14:30:45 UTC");
    }

    #[test]
    fn test_format_timestamp_different_dates() {
        let timestamp1 = Utc.with_ymd_and_hms(2023, 12, 31, 23, 59, 59).unwrap();
        let timestamp2 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();

        assert_eq!(format_timestamp(&timestamp1), "2023-12-31 23:59:59 UTC");
        assert_eq!(format_timestamp(&timestamp2), "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_join_list_integers() {
        let versions = vec![1, 2, 3, 4, 5];
        let result = join_list(&versions);
        assert_eq!(result, "1, 2, 3, 4, 5");
    }

    #[test]
    fn test_join_list_strings() {
        let items = vec!["apple", "banana", "cherry"];
        let result = join_list(&items);
        assert_eq!(result, "apple, banana, cherry");
    }

    #[test]
    fn test_join_list_single_item() {
        let items = vec![42];
        let result = join_list(&items);
        assert_eq!(result, "42");
    }

    #[test]
    fn test_join_list_empty() {
        let items: Vec<i32> = vec![];
        let result = join_list(&items);
        assert_eq!(result, "");
    }

    #[test]
    fn test_join_list_mixed_types() {
        // Test with different types that implement Display
        let floats = vec![1.5, 2.7, 3.15];
        let result = join_list(&floats);
        assert_eq!(result, "1.5, 2.7, 3.15");

        let chars = vec!['a', 'b', 'c'];
        let result = join_list(&chars);
        assert_eq!(result, "a, b, c");
    }
}
