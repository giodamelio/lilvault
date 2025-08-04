/// Utility functions for LilVault
///
/// This module contains small, pure functions that can be easily tested
/// and reused throughout the application.
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
        let floats = vec![1.5, 2.7, 3.14];
        let result = join_list(&floats);
        assert_eq!(result, "1.5, 2.7, 3.14");

        let chars = vec!['a', 'b', 'c'];
        let result = join_list(&chars);
        assert_eq!(result, "a, b, c");
    }
}
