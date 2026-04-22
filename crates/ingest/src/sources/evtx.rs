//! EVTX channel artifact generator.
//!
//! Fetches per-provider CSV files from the nasbench/EVTX-ETW-Resources
//! repository, extracts unique Channel names, and generates one EventLog
//! IngestRecord per unique channel.
//!
//! CSV columns (per-provider CSVs):
//! Event ID, Event Version, Level, Channel, Task, Opcode, Keyword, ...

use std::collections::HashSet;

use crate::normalize::to_snake_case;
use crate::record::{IngestRecord, IngestType};

const EVTX_CONTENTS_URL: &str =
    "https://api.github.com/repos/nasbench/EVTX-ETW-Resources/contents/ETWProvidersCSVs/Internal";
const EVTX_RAW_BASE: &str = "https://raw.githubusercontent.com/nasbench/EVTX-ETW-Resources/main/";

/// Parse a per-provider CSV string and return unique (ProviderName, Channel) pairs.
///
/// Expected header includes at minimum a "Channel" column (case-insensitive).
pub fn parse_evtx_csv(content: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    let channels = extract_channels_from_csv(content);

    for (provider, channel) in channels {
        let channel_snake = to_snake_case(&channel);
        let raw_id = format!("evtx_{channel_snake}");
        // Truncate to 60 chars
        let id_base = if raw_id.len() > 60 {
            raw_id[..60].trim_end_matches('_').to_string()
        } else {
            raw_id
        };
        let id = ensure_unique(id_base, &mut seen_ids);
        seen_ids.insert(id.clone());

        // Build file path
        let sanitized = channel.replace('/', "\\");
        let file_path = format!(r"%SystemRoot%\System32\winevt\Logs\{sanitized}.evtx");

        let meaning = if !provider.is_empty() {
            format!("Windows Event Log channel '{channel}' from provider '{provider}'.")
        } else {
            format!("Windows Event Log channel '{channel}'.")
        };

        let triage = infer_evtx_triage(&channel);

        records.push(IngestRecord {
            id,
            name: channel.clone(),
            source_name: "evtx",
            artifact_type: IngestType::EventLog,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(file_path),
            meaning,
            mitre_techniques: Vec::new(),
            triage_priority: triage.to_string(),
            sources: vec!["https://github.com/nasbench/EVTX-ETW-Resources".to_string()],
        });
    }

    records
}

/// Extract unique (provider, channel) pairs from a CSV.
/// The CSV must have headers; we look for a "Channel" column.
fn extract_channels_from_csv(content: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut seen_channels: HashSet<String> = HashSet::new();
    let mut lines = content.lines();

    let header_line = match lines.next() {
        Some(h) => h,
        None => return result,
    };
    let headers: Vec<&str> = split_csv_line(header_line);

    let channel_idx = headers
        .iter()
        .position(|h| h.trim_matches('"').eq_ignore_ascii_case("channel"));
    let provider_idx = headers
        .iter()
        .position(|h| h.trim_matches('"').eq_ignore_ascii_case("provider"));

    let channel_idx = match channel_idx {
        Some(i) => i,
        None => return result,
    };

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols = split_csv_line(line);
        let channel = cols
            .get(channel_idx)
            .copied()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();

        if channel.is_empty() || seen_channels.contains(&channel) {
            continue;
        }
        seen_channels.insert(channel.clone());

        let provider = provider_idx
            .and_then(|i| cols.get(i))
            .copied()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();

        result.push((provider, channel));
    }

    result
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
                fields.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    fields.push(&line[start..]);
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

/// Fetch EVTX channel records from the nasbench repository.
///
/// Walks all per-provider CSV files under ETWProvidersCSVs/Internal/,
/// extracts unique Channel values, and creates one IngestRecord per channel.
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

    // Use the Contents API (not the tree API, which gets truncated) to list
    // the ETWProvidersCSVs/Internal/ directory.
    let contents: Vec<serde_json::Value> =
        match client.get(EVTX_CONTENTS_URL).send().and_then(|r| r.json()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARN: evtx: failed to fetch contents listing: {e}");
                return Vec::new();
            }
        };

    let mut all_channels: HashSet<String> = HashSet::new();
    let mut all_records = Vec::new();

    {
        let csv_paths: Vec<String> = contents
            .iter()
            .filter_map(|item| item.get("path").and_then(|p| p.as_str()))
            .filter(|p| p.ends_with(".csv"))
            .map(|s| s.to_string())
            .collect();

        for path in csv_paths {
            let url = format!("{EVTX_RAW_BASE}{path}");
            std::thread::sleep(std::time::Duration::from_millis(50));
            match client.get(&url).send().and_then(|r| r.text()) {
                Ok(content) => {
                    let pairs = extract_channels_from_csv(&content);
                    for (provider, channel) in pairs {
                        if all_channels.insert(channel.clone()) {
                            let channel_snake = to_snake_case(&channel);
                            let raw_id = format!("evtx_{channel_snake}");
                            let id = if raw_id.len() > 60 {
                                raw_id[..60].trim_end_matches('_').to_string()
                            } else {
                                raw_id
                            };

                            let sanitized = channel.replace('/', "\\");
                            let file_path =
                                format!(r"%SystemRoot%\System32\winevt\Logs\{sanitized}.evtx");

                            let meaning = if !provider.is_empty() {
                                format!("Windows Event Log channel '{channel}' from provider '{provider}'.")
                            } else {
                                format!("Windows Event Log channel '{channel}'.")
                            };

                            let triage = infer_evtx_triage(&channel);

                            all_records.push(IngestRecord {
                                id,
                                name: channel.clone(),
                                source_name: "evtx",
                                artifact_type: IngestType::EventLog,
                                hive: None,
                                key_path: String::new(),
                                value_name: None,
                                file_path: Some(file_path),
                                meaning,
                                mitre_techniques: Vec::new(),
                                triage_priority: triage.to_string(),
                                sources: vec![
                                    "https://github.com/nasbench/EVTX-ETW-Resources".to_string()
                                ],
                            });
                        }
                    }
                }
                Err(e) => {
                    eprintln!("WARN: evtx: failed to fetch {url}: {e}");
                }
            }
        }
    }

    all_records
}

#[cfg(test)]
mod tests {
    use super::*;

    // CSV format from nasbench: Event ID, Event Version, Level, Channel, Task, ...
    const SAMPLE_CSV: &str = "\
Event ID,Event Version,Level,Channel,Task,Opcode,Keyword
4624,0,0,Security,12544,0,0x8020000000000000
4625,0,0,Security,12546,0,0x8010000000000000
7036,0,4,System,7040,0,0x8080000000000000
400,0,4,Windows PowerShell,1,0,0x80000000000000
4002,0,4,Application,0,0,0x80000000000000
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
            assert_eq!(
                rec.artifact_type,
                IngestType::EventLog,
                "wrong type for {}",
                rec.id
            );
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
            assert!(rec.file_path.is_some(), "missing file_path for {}", rec.id);
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
    fn parse_deduplicates_channels() {
        // Security appears twice — should produce only one record
        let records = parse_evtx_csv(SAMPLE_CSV);
        let sec_count = records.iter().filter(|r| r.name == "Security").count();
        assert_eq!(sec_count, 1, "should deduplicate Security channel");
    }

    #[test]
    fn fetch_evtx_records_from_network() {
        let records = fetch_evtx_records();
        if records.is_empty() {
            eprintln!("WARN: evtx: network fetch returned 0 records (acceptable in offline CI)");
        } else {
            assert!(
                records.len() > 50,
                "expected many evtx channels, got {}",
                records.len()
            );
        }
    }
}
