use lilvault::cli::AuditCommands;
use lilvault::db::Database;
use miette::{IntoDiagnostic, Result};
use tracing::info;

/// Handle audit commands
pub async fn handle_audit(db: &Database, command: AuditCommands) -> Result<()> {
    match command {
        AuditCommands::List { limit } => {
            let entries = db.get_audit_entries(limit).await.into_diagnostic()?;

            if entries.is_empty() {
                info!("No audit entries found.");
                return Ok(());
            }

            info!("Audit Log ({} entries):", entries.len());
            info!(
                "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                "ID", "Timestamp", "Operation", "Resource", "Success"
            );
            info!("{}", "-".repeat(90));

            for entry in entries {
                let success_icon = if entry.success { "✓" } else { "✗" };
                let details = entry.details.as_deref().unwrap_or("");
                let error_info = if !entry.success {
                    entry.error_message.as_deref().unwrap_or("Unknown error")
                } else {
                    details
                };

                info!(
                    "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                    entry.id,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    entry.operation,
                    entry.resource,
                    success_icon,
                    error_info
                );
            }
            Ok(())
        }

        AuditCommands::Show {
            resource,
            operation,
        } => {
            let entries = db
                .get_audit_entries_filtered(resource.as_deref(), operation.as_deref(), 100)
                .await
                .into_diagnostic()?;

            if entries.is_empty() {
                info!("No matching audit entries found.");
                return Ok(());
            }

            info!("Audit Log - Filtered Results ({} entries):", entries.len());
            info!(
                "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                "ID", "Timestamp", "Operation", "Resource", "Success"
            );
            info!("{}", "-".repeat(90));

            for entry in entries {
                let success_icon = if entry.success { "✓" } else { "✗" };
                let details = entry.details.as_deref().unwrap_or("");
                let error_info = if !entry.success {
                    entry.error_message.as_deref().unwrap_or("Unknown error")
                } else {
                    details
                };

                info!(
                    "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                    entry.id,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    entry.operation,
                    entry.resource,
                    success_icon,
                    error_info
                );
            }
            Ok(())
        }

        AuditCommands::Since { days } => {
            let entries = db
                .get_audit_entries_since(days, 1000)
                .await
                .into_diagnostic()?;

            if entries.is_empty() {
                info!("No audit entries found in the last {} days.", days);
                return Ok(());
            }

            info!(
                "Audit Log - Last {} days ({} entries):",
                days,
                entries.len()
            );
            info!(
                "{:<8} {:<25} {:<15} {:<20} {:<7} Details",
                "ID", "Timestamp", "Operation", "Resource", "Success"
            );
            info!("{}", "-".repeat(90));

            for entry in entries {
                let success_icon = if entry.success { "✓" } else { "✗" };
                let details = entry.details.as_deref().unwrap_or("");
                let error_info = if !entry.success {
                    entry.error_message.as_deref().unwrap_or("Unknown error")
                } else {
                    details
                };

                info!(
                    "{:<8} {:<25} {:<15} {:<20} {:<7} {}",
                    entry.id,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    entry.operation,
                    entry.resource,
                    success_icon,
                    error_info
                );
            }
            Ok(())
        }
    }
}
