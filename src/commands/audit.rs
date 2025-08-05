use lilvault::cli::AuditCommands;
use lilvault::db::{Database, models::AuditLog};
use miette::{IntoDiagnostic, Result};
use tabled::{Table, Tabled};
use tracing::info;

#[derive(Tabled)]
struct AuditTableRow {
    #[tabled(rename = "ID")]
    id: i64,
    #[tabled(rename = "Timestamp")]
    timestamp: String,
    #[tabled(rename = "Operation")]
    operation: String,
    #[tabled(rename = "Resource")]
    resource: String,
    #[tabled(rename = "Success")]
    success: String,
    #[tabled(rename = "Details")]
    details: String,
}

fn display_audit_entries(entries: &[AuditLog], title: &str) {
    if entries.is_empty() {
        if title.contains("Last") && title.contains("days") {
            info!("No audit entries found in the specified time period.");
        } else if title.contains("Filtered") {
            info!("No matching audit entries found.");
        } else {
            info!("No audit entries found.");
        }
        return;
    }

    info!("{title} ({} entries):", entries.len());

    let table_data: Vec<AuditTableRow> = entries
        .iter()
        .map(|entry| {
            let success_icon = if entry.success { "✓" } else { "✗" };
            let details = if !entry.success {
                entry.error_message.as_deref().unwrap_or("Unknown error")
            } else {
                entry.details.as_deref().unwrap_or("")
            };

            AuditTableRow {
                id: entry.id,
                timestamp: entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                operation: entry.operation.clone(),
                resource: entry.resource.clone(),
                success: success_icon.to_string(),
                details: details.to_string(),
            }
        })
        .collect();

    let table = Table::new(table_data);
    println!("{table}");
}

/// Handle audit commands
pub async fn handle_audit(db: &Database, command: AuditCommands) -> Result<()> {
    match command {
        AuditCommands::List { limit } => {
            let entries = db.get_audit_entries(limit).await.into_diagnostic()?;
            display_audit_entries(&entries, "Audit Log");
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
            display_audit_entries(&entries, "Audit Log - Filtered Results");
            Ok(())
        }

        AuditCommands::Since { days } => {
            let entries = db
                .get_audit_entries_since(days, 1000)
                .await
                .into_diagnostic()?;
            display_audit_entries(&entries, &format!("Audit Log - Last {days} days"));
            Ok(())
        }
    }
}
