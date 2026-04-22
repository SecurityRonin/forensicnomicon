//! Parser for RECmd batch (.reb) YAML files.
//!
//! Format: YAML with a top-level `Keys:` list. Each entry has:
//! - `Description` (human name)
//! - `HiveType` (NTUSER, HKLM, HKCU, SYSTEM, etc.)
//! - `Category`
//! - `KeyPath`
//! - `Recursive`
//! - `Comment` (used as meaning)

use std::collections::HashSet;

use crate::normalize::{normalize_registry_id, to_snake_case};
use crate::record::{IngestRecord, IngestType};

const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/RECmd_Batch_MC.reb";

/// Parse a `.reb` YAML string into a list of `IngestRecord`s.
pub fn parse_reb(content: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    // State machine: we look for `    -` blocks and extract fields
    let mut description = String::new();
    let mut hive_type = String::new();
    let mut key_path = String::new();
    let mut comment = String::new();
    let mut in_entry = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "-" {
            // Flush previous entry
            if in_entry && !description.is_empty() && !key_path.is_empty() {
                if let Some(rec) =
                    build_record(&description, &hive_type, &key_path, &comment, &mut seen_ids)
                {
                    records.push(rec);
                }
            }
            description.clear();
            hive_type.clear();
            key_path.clear();
            comment.clear();
            in_entry = true;
            continue;
        }

        if !in_entry {
            continue;
        }

        if let Some(val) = strip_yaml_field(trimmed, "Description") {
            description = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "HiveType") {
            hive_type = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "KeyPath") {
            key_path = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "Comment") {
            comment = val.to_string();
        }
    }

    // Flush last entry
    if in_entry && !description.is_empty() && !key_path.is_empty() {
        if let Some(rec) =
            build_record(&description, &hive_type, &key_path, &comment, &mut seen_ids)
        {
            records.push(rec);
        }
    }

    records
}

/// Fetch and parse a `.reb` file from a URL.
pub fn parse_reb_url(url: &str) -> Result<Vec<IngestRecord>, Box<dyn std::error::Error>> {
    let content = reqwest::blocking::get(url)?.text()?;
    Ok(parse_reb(&content))
}

/// Convenience function: fetch the canonical RECmd batch file.
pub fn fetch_regedit_records() -> Vec<IngestRecord> {
    match parse_reb_url(SOURCE_URL) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("WARN: failed to fetch RECmd batch file: {e}");
            Vec::new()
        }
    }
}

fn strip_yaml_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    if line.starts_with(&prefix) {
        Some(line[prefix.len()..].trim())
    } else {
        None
    }
}

fn build_record(
    description: &str,
    hive_type: &str,
    key_path: &str,
    comment: &str,
    seen_ids: &mut HashSet<String>,
) -> Option<IngestRecord> {
    if description.is_empty() || key_path.is_empty() {
        return None;
    }

    // Map HiveType to a canonical hive string
    let hive = map_hive_type(hive_type);

    // Build a synthetic full path for ID normalization
    let full_path = if let Some(ref h) = hive {
        format!("{h}\\{key_path}")
    } else {
        key_path.to_string()
    };

    let base_id = normalize_registry_id(&full_path, "regedit");

    // Ensure uniqueness
    let id = if seen_ids.contains(&base_id) {
        // Append suffix from description to differentiate
        let desc_part = to_snake_case(description);
        let candidate = format!("{}_{}", base_id, &desc_part[..desc_part.len().min(15)]);
        let candidate = &candidate[..candidate.len().min(60)];
        let candidate = candidate.trim_end_matches('_').to_string();
        if seen_ids.contains(&candidate) {
            // Last resort: append counter
            let mut n = 2u32;
            loop {
                let c = format!("{base_id}_{n}");
                if !seen_ids.contains(&c) {
                    break c;
                }
                n += 1;
            }
        } else {
            candidate
        }
    } else {
        base_id
    };
    seen_ids.insert(id.clone());

    let meaning = if comment.is_empty() {
        description.to_string()
    } else {
        comment.to_string()
    };

    let triage = infer_triage(description, comment);
    let mitre = extract_mitre(comment);

    Some(IngestRecord {
        id,
        name: description.to_string(),
        source_name: "regedit",
        artifact_type: IngestType::RegistryKey,
        hive: hive.map(|h| h.to_string()),
        key_path: key_path.to_string(),
        value_name: None,
        file_path: None,
        meaning,
        mitre_techniques: mitre,
        triage_priority: triage.to_string(),
        sources: vec![SOURCE_URL.to_string()],
    })
}

fn map_hive_type(hive_type: &str) -> Option<&'static str> {
    match hive_type.trim().to_ascii_uppercase().as_str() {
        "NTUSER" | "HKCU" | "HKEY_CURRENT_USER" => Some("HKCU"),
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some("HKLM"),
        "SYSTEM" => Some("HKLM\\SYSTEM"),
        "SOFTWARE" => Some("HKLM\\SOFTWARE"),
        "SAM" => Some("HKLM\\SAM"),
        "SECURITY" => Some("HKLM\\SECURITY"),
        "USRCLASS" | "HKCR" | "HKEY_CLASSES_ROOT" => Some("HKCU\\Software\\Classes"),
        "BCD" => Some("BCD"),
        "AMCACHE" => Some("Amcache"),
        _ => None,
    }
}

fn infer_triage(description: &str, comment: &str) -> &'static str {
    let combined = format!("{description} {comment}").to_ascii_lowercase();
    if combined.contains("credential")
        || combined.contains("password")
        || combined.contains("sam ")
        || combined.contains("lateral")
    {
        "Critical"
    } else if combined.contains("autorun")
        || combined.contains("run key")
        || combined.contains("persistence")
        || combined.contains("execution")
        || combined.contains("proxy")
        || combined.contains("shell")
        || combined.contains("service")
    {
        "High"
    } else if combined.contains("config")
        || combined.contains("log")
        || combined.contains("mru")
        || combined.contains("browser")
        || combined.contains("history")
    {
        "Medium"
    } else {
        "Low"
    }
}

fn extract_mitre(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"T\d{4}(?:\.\d{3})?").unwrap();
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_REB: &str = r#"Description: RECmd batch file
Author: Mike Cary
Version: 1
Id: 4eec0ce6-d1c3-4b65-9f0e-3ccd429d506c
Keys:
    -
        Description: Network
        HiveType: NTUSER
        Category: Devices
        KeyPath: Network
        Recursive: true
        Comment: Network Drives
    -
        Description: User Run Key
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: User Run Key
    -
        Description: System Run Key
        HiveType: HKLM
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: System Run Key
    -
        Description: PortProxy v4ToV4
        HiveType: HKLM
        Category: Network
        KeyPath: SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4
        Recursive: true
        Comment: Port proxying - lateral movement indicator
"#;

    #[test]
    fn parse_returns_records() {
        let records = parse_reb(SAMPLE_REB);
        assert!(!records.is_empty(), "should return at least one record");
    }

    #[test]
    fn parse_correct_record_count() {
        let records = parse_reb(SAMPLE_REB);
        assert_eq!(
            records.len(),
            4,
            "expected 4 entries, got {}",
            records.len()
        );
    }

    #[test]
    fn parse_ntuser_hive_detected() {
        let records = parse_reb(SAMPLE_REB);
        let network = records
            .iter()
            .find(|r| r.key_path == "Network")
            .expect("no Network record");
        assert_eq!(network.hive.as_deref(), Some("HKCU"));
        assert_eq!(network.name, "Network");
    }

    #[test]
    fn parse_hklm_hive_detected() {
        let records = parse_reb(SAMPLE_REB);
        let run = records
            .iter()
            .find(|r| r.name == "System Run Key")
            .expect("no System Run Key");
        assert_eq!(run.hive.as_deref(), Some("HKLM"));
        assert_eq!(
            run.key_path,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn parse_meaning_from_comment() {
        let records = parse_reb(SAMPLE_REB);
        let portproxy = records
            .iter()
            .find(|r| r.name == "PortProxy v4ToV4")
            .expect("no PortProxy record");
        assert!(
            portproxy.meaning.contains("Port proxy") || portproxy.meaning.contains("lateral"),
            "meaning should include comment text, got: {}",
            portproxy.meaning
        );
    }

    #[test]
    fn parse_source_name_is_regedit() {
        let records = parse_reb(SAMPLE_REB);
        for rec in &records {
            assert_eq!(
                rec.source_name, "regedit",
                "wrong source_name for {}",
                rec.id
            );
        }
    }

    #[test]
    fn parse_ids_are_unique() {
        let records = parse_reb(SAMPLE_REB);
        let mut ids = std::collections::HashSet::new();
        for rec in &records {
            assert!(ids.insert(rec.id.clone()), "duplicate ID: {}", rec.id);
        }
    }

    #[test]
    fn parse_ids_are_snake_case() {
        let records = parse_reb(SAMPLE_REB);
        for rec in &records {
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
    fn parse_from_url_returns_records() {
        // This test hits the network — skip in offline CI if needed
        let result = parse_reb_url("https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/RECmd_Batch_MC.reb");
        match result {
            Ok(records) => {
                assert!(!records.is_empty(), "expected records from URL");
                assert!(records.len() > 10, "expected many records from real file");
            }
            Err(e) => {
                // Network failure is acceptable in CI
                eprintln!("WARN: network fetch failed (acceptable in offline CI): {e}");
            }
        }
    }
}
