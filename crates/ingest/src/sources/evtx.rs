//! EVTX channel CSV parser.
//!
//! Fetches the EVTX-ETW-Resources CSV and generates one EventLog
//! IngestRecord per Windows Event Log channel.
//!
//! CSV columns (from EVTX-Providers-Win11-22H2.csv):
//! ProviderName, ChannelName, ChannelPath, ChannelType, ...

use std::collections::HashSet;

use crate::normalize::to_snake_case;
use crate::record::{IngestRecord, IngestType};

const EVTX_CSV_URL: &str = "https://raw.githubusercontent.com/nasbench/EVTX-ETW-Resources/main/ETWProvidersCSVs/EVTX-Providers-Win11-22H2.csv";

/// Parse a CSV string of EVTX channel data into IngestRecords.
///
/// Expected columns (may be in any order, detected by header):
/// ProviderName, ChannelName, ChannelPath
pub fn parse_evtx_csv(content: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    let mut lines = content.lines();
    let header_line = match lines.next() {
        Some(h) => h,
        None => return records,
    };

    // Detect column indices
    let headers: Vec<&str> = split_csv_line(header_line);
    let provider_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("ProviderName"));
    let channel_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("ChannelName"));
    let path_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("ChannelPath"));

    let channel_idx = match channel_idx {
        Some(i) => i,
        None => {
            eprintln!("WARN: evtx: no ChannelName column in CSV header");
            return records;
        }
    };

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols = split_csv_line(line);

        let channel_name = cols.get(channel_idx).copied().unwrap_or("").trim();
        if channel_name.is_empty() {
            continue;
        }

        let provider_name = provider_idx
            .and_then(|i| cols.get(i))
            .copied()
            .unwrap_or("")
            .trim()
            .to_string();

        let channel_path = path_idx
            .and_then(|i| cols.get(i))
            .copied()
            .unwrap_or("")
            .trim()
            .to_string();

        // Build file path for the .evtx file
        let file_path = if !channel_path.is_empty() {
            // ChannelPath is often something like:
            //   %SystemRoot%\System32\winevt\Logs\Application.evtx
            channel_path.clone()
        } else {
            // Derive from channel name: replace / and spaces with \
            let sanitized = channel_name.replace('/', "\\");
            format!(r"Windows\System32\winevt\Logs\{sanitized}.evtx")
        };

        // Build ID from channel name
        let channel_snake = to_snake_case(channel_name);
        let raw_id = format!("evtx_{channel_snake}");
        let id = ensure_unique(raw_id, &mut seen_ids);
        seen_ids.insert(id.clone());

        // Truncate to 60 chars
        let id = if id.len() > 60 {
            id[..60].trim_end_matches('_').to_string()
        } else {
            id
        };

        let meaning = if !provider_name.is_empty() {
            format!(
                "Windows Event Log channel '{channel_name}' from provider '{provider_name}'."
            )
        } else {
            format!("Windows Event Log channel '{channel_name}'.")
        };

        // Infer triage priority from channel name
        let triage = infer_evtx_triage(channel_name);

        let rec = IngestRecord {
            id,
            name: channel_name.to_string(),
            source_name: "evtx",
            artifact_type: IngestType::EventLog,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(file_path),
            meaning,
            mitre_techniques: Vec::new(),
            triage_priority: triage.to_string(),
            sources: vec![EVTX_CSV_URL.to_string()],
        };

        records.push(rec);
    }

    records
}

fn infer_evtx_triage(channel: &str) -> &'static str {
    let lower = channel.to_ascii_lowercase();
    if lower.contains("security") {
        "Critical"
    } else if lower.contains("system")
        || lower.contains("powershell")
        || lower.contains("sysmon")
        || lower.contains("wmi")
        || lower.contains("taskscheduler")
        || lower.contains("task-scheduler")
        || lower.contains("bits-client")
    {
        "High"
    } else if lower.contains("application")
        || lower.contains("dns")
        || lower.contains("firewall")
        || lower.contains("applocker")
    {
        "Medium"
    } else {
        "Low"
    }
}

/// Split a CSV line respecting double-quoted fields.
fn split_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = line.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                let field = line[start..i].trim_matches('"');
                fields.push(field);
                start = i + 1;
            }
            _ => {}
        }
    }
    // last field
    fields.push(line[start..].trim_matches('"'));
    fields
}

fn ensure_unique(base: String, seen: &mut HashSet<String>) -> String {
    if !seen.contains(&base) {
        return base;
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}_{n}");
        if !seen.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Fetch EVTX channel records from the nasbench CSV.
pub fn fetch_evtx_records() -> Vec<IngestRecord> {
    let client = match reqwest::blocking::Client::builder()
        .user_agent("forensicnomicon-ingest/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("WARN: evtx: failed to build HTTP client: {e}");
            return Vec::new();
        }
    };

    match client.get(EVTX_CSV_URL).send().and_then(|r| r.text()) {
        Ok(content) => parse_evtx_csv(&content),
        Err(e) => {
            eprintln!("WARN: evtx: failed to fetch CSV: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = "\
ProviderName,ChannelName,ChannelPath,ChannelType
Microsoft-Windows-Security-Auditing,Security,%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx,Admin
Microsoft-Windows-PowerShell,Windows PowerShell,%SystemRoot%\\System32\\winevt\\Logs\\Windows PowerShell.evtx,Admin
Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-Sysmon/Operational,%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx,Operational
,Application,%SystemRoot%\\System32\\winevt\\Logs\\Application.evtx,Admin
";

    #[test]
    fn parse_returns_records() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        assert!(!records.is_empty(), "should return records");
    }

    #[test]
    fn parse_artifact_type_is_event_log() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        for rec in &records {
            assert_eq!(rec.artifact_type, IngestType::EventLog, "wrong type for {}", rec.id);
        }
    }

    #[test]
    fn parse_ids_are_snake_case_with_evtx_prefix() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        for rec in &records {
            assert!(
                rec.id.starts_with("evtx_"),
                "ID missing evtx_ prefix: {}",
                rec.id
            );
            assert!(
                rec.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ID not snake_case: {}",
                rec.id
            );
        }
    }

    #[test]
    fn parse_file_path_is_present() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        for rec in &records {
            assert!(
                rec.file_path.is_some(),
                "missing file_path for {}",
                rec.id
            );
        }
    }

    #[test]
    fn parse_ids_are_unique() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        let mut ids = std::collections::HashSet::new();
        for rec in &records {
            assert!(ids.insert(rec.id.clone()), "duplicate ID: {}", rec.id);
        }
    }

    #[test]
    fn parse_security_channel_is_critical() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        let sec = records
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case("Security"))
            .expect("no Security channel");
        assert_eq!(sec.triage_priority, "Critical");
    }

    #[test]
    fn parse_source_name_is_evtx() {
        let records = parse_evtx_csv(SAMPLE_CSV);
        for rec in &records {
            assert_eq!(rec.source_name, "evtx", "wrong source_name for {}", rec.id);
        }
    }

    #[test]
    fn fetch_evtx_records_from_network() {
        let records = fetch_evtx_records();
        if records.is_empty() {
            eprintln!("WARN: evtx: network fetch returned 0 records (acceptable in offline CI)");
        } else {
            assert!(
                records.len() > 100,
                "expected many evtx channels, got {}",
                records.len()
            );
        }
    }
}
