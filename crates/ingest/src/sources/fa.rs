//! Parser for ForensicArtifacts YAML files.
//!
//! Format: multi-document YAML with fields:
//! - `name`
//! - `doc`
//! - `sources` (list with `type` and `attributes`)
//! - `supported_os`
//! - `urls`

use std::collections::HashSet;

use crate::normalize::{normalize_file_id, normalize_registry_id};
use crate::record::{IngestRecord, IngestType};

/// Parse a ForensicArtifacts YAML string (possibly multi-document) into IngestRecords.
pub fn parse_fa_yaml(content: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    // Split into YAML documents by ---
    // The content may start with --- or not; split on \n--- to handle both
    let raw_docs: Vec<&str> = content.split("\n---").collect();

    for doc in raw_docs {
        let doc = doc.trim_start_matches("---").trim();
        if doc.is_empty() {
            continue;
        }
        match serde_yaml::from_str::<serde_yaml::Value>(doc) {
            Ok(value) => parse_document(&value, &mut records, &mut seen_ids),
            Err(_) => {
                // Try the whole chunk if splitting produced something off
                continue;
            }
        }
    }

    records
}

fn parse_document(
    value: &serde_yaml::Value,
    records: &mut Vec<IngestRecord>,
    seen_ids: &mut HashSet<String>,
) {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return;
    }

    let doc = value
        .get("doc")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let urls: Vec<String> = value
        .get("urls")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|u| u.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let sources_list = value
        .get("sources")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();

    for source_entry in &sources_list {
        let source_type = source_entry
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ingest_type = match source_type {
            "REGISTRY_KEY" => IngestType::RegistryKey,
            "REGISTRY_VALUE" => IngestType::RegistryValue,
            "FILE" => IngestType::File,
            "DIRECTORY" => IngestType::Directory,
            _ => continue, // skip WMI and other types
        };

        let attributes = source_entry.get("attributes");

        let paths: Vec<String> = match &ingest_type {
            IngestType::RegistryKey | IngestType::RegistryValue => attributes
                .and_then(|a| a.get("keys"))
                .and_then(|k| k.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
            IngestType::File | IngestType::Directory => attributes
                .and_then(|a| a.get("paths"))
                .and_then(|k| k.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };

        for path in paths {
            let (id, hive, key_path, file_path) = match &ingest_type {
                IngestType::RegistryKey | IngestType::RegistryValue => {
                    let raw_id = normalize_registry_id(&path, "fa");
                    let id = ensure_unique(raw_id, seen_ids);
                    let hive = detect_hive_string(&path);
                    let key_path = strip_hive_from_path(&path);
                    (id, hive, key_path, None)
                }
                IngestType::File | IngestType::Directory => {
                    let is_dir = matches!(ingest_type, IngestType::Directory);
                    let raw_id = normalize_file_id(&path, "fa", is_dir);
                    let id = ensure_unique(raw_id, seen_ids);
                    (id, None, String::new(), Some(path.clone()))
                }
                _ => continue,
            };

            seen_ids.insert(id.clone());

            let triage = infer_triage(&name, &doc);

            let rec = IngestRecord {
                id,
                name: name.clone(),
                source_name: "fa",
                artifact_type: ingest_type.clone(),
                hive,
                key_path,
                value_name: None,
                file_path,
                meaning: doc.clone(),
                mitre_techniques: Vec::new(),
                triage_priority: triage.to_string(),
                sources: urls.clone(),
            };

            records.push(rec);
        }
    }
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

fn detect_hive_string(path: &str) -> Option<String> {
    let upper = path.to_ascii_uppercase();
    if upper.starts_with("HKEY_LOCAL_MACHINE\\SYSTEM") || upper.starts_with("HKLM\\SYSTEM") {
        Some("HKLM\\SYSTEM".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE\\SOFTWARE")
        || upper.starts_with("HKLM\\SOFTWARE")
    {
        Some("HKLM\\SOFTWARE".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE\\SAM") || upper.starts_with("HKLM\\SAM") {
        Some("HKLM\\SAM".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE\\SECURITY")
        || upper.starts_with("HKLM\\SECURITY")
    {
        Some("HKLM\\SECURITY".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE") || upper.starts_with("HKLM") {
        Some("HKLM\\SOFTWARE".to_string())
    } else if upper.starts_with("HKEY_CURRENT_USER\\SOFTWARE\\CLASSES")
        || upper.starts_with("HKCU\\SOFTWARE\\CLASSES")
    {
        Some("HKCU\\Software\\Classes".to_string())
    } else if upper.starts_with("HKEY_CURRENT_USER") || upper.starts_with("HKCU") {
        Some("HKCU".to_string())
    } else {
        None
    }
}

fn strip_hive_from_path(path: &str) -> String {
    let upper = path.to_ascii_uppercase();
    let prefixes = [
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_CURRENT_USER\\",
        "HKLM\\",
        "HKCU\\",
    ];
    for prefix in prefixes {
        if upper.starts_with(prefix) {
            return path[prefix.len()..].to_string();
        }
    }
    path.to_string()
}

fn infer_triage(name: &str, doc: &str) -> &'static str {
    let combined = format!("{} {}", name, doc).to_ascii_lowercase();
    if combined.contains("credential")
        || combined.contains("password")
        || combined.contains("lsass")
        || combined.contains("sam ")
        || combined.contains("ntds")
        || combined.contains("token")
        || combined.contains("privilege")
    {
        "Critical"
    } else if combined.contains("execution")
        || combined.contains("persistence")
        || combined.contains("run key")
        || combined.contains("startup")
        || combined.contains("service")
        || combined.contains("scheduled task")
        || combined.contains("autorun")
    {
        "High"
    } else if combined.contains("browser")
        || combined.contains("log")
        || combined.contains("event")
        || combined.contains("history")
        || combined.contains("config")
        || combined.contains("settings")
    {
        "Medium"
    } else {
        "Low"
    }
}

/// Fetch and parse ForensicArtifacts YAML from a single URL.
pub fn fetch_fa_artifacts(url: &str) -> Result<Vec<IngestRecord>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("forensicnomicon-ingest/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let content = client.get(url).send()?.text()?;
    Ok(parse_fa_yaml(&content))
}

/// Fetch all ForensicArtifacts YAML files from the GitHub repository.
pub fn fetch_all_fa_artifacts() -> Vec<IngestRecord> {
    let tree_url =
        "https://api.github.com/repos/forensicartifacts/artifacts/git/trees/main?recursive=1";
    let client = match reqwest::blocking::Client::builder()
        .user_agent("forensicnomicon-ingest/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("WARN: fa: failed to build HTTP client: {e}");
            return Vec::new();
        }
    };

    let tree: serde_json::Value = match client.get(tree_url).send().and_then(|r| r.json()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("WARN: fa: failed to fetch tree: {e}");
            return Vec::new();
        }
    };

    let base_url = "https://raw.githubusercontent.com/forensicartifacts/artifacts/main/";
    let mut all_records = Vec::new();

    if let Some(tree_items) = tree.get("tree").and_then(|t| t.as_array()) {
        let yaml_paths: Vec<String> = tree_items
            .iter()
            .filter_map(|item| item.get("path").and_then(|p| p.as_str()))
            .filter(|p| p.ends_with(".yaml") && p.starts_with("artifacts/"))
            .map(|s| s.to_string())
            .collect();

        for path in yaml_paths {
            let url = format!("{base_url}{path}");
            std::thread::sleep(std::time::Duration::from_millis(200));
            match client.get(&url).send().and_then(|r| r.text()) {
                Ok(content) => {
                    let records = parse_fa_yaml(&content);
                    all_records.extend(records);
                }
                Err(e) => {
                    eprintln!("WARN: fa: failed to fetch {url}: {e}");
                }
            }
        }
    }

    all_records
}

// RED: ForensicArtifacts YAML parser tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::IngestType;

    const SAMPLE_FA_YAML: &str = r#"---
name: WindowsRunKeys
doc: Windows Run and RunOnce persistence keys.
sources:
- type: REGISTRY_KEY
  attributes:
    keys:
    - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
    - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    - 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
supported_os: [Windows]
urls:
- 'https://attack.mitre.org/techniques/T1547/001/'
---
name: WindowsEventLogs
doc: Windows Event logs.
sources:
- type: FILE
  attributes:
    paths:
    - '%%environ_systemroot%%\System32\winevt\Logs\*.evtx'
supported_os: [Windows]
urls:
- 'https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logs'
---
name: WindowsNtdsDatabase
doc: Active Directory database file.
sources:
- type: FILE
  attributes:
    paths:
    - '%%environ_systemroot%%\ntds\ntds.dit'
supported_os: [Windows]
urls: []
"#;

    #[test]
    fn parse_returns_records() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        assert!(!records.is_empty(), "should return records");
    }

    #[test]
    fn parse_registry_key_type() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        let run = records.iter().find(|r| r.name == "WindowsRunKeys");
        assert!(run.is_some(), "no WindowsRunKeys record");
        let run = run.unwrap();
        assert_eq!(run.artifact_type, IngestType::RegistryKey);
    }

    #[test]
    fn parse_file_type() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        let evtx = records.iter().find(|r| r.name == "WindowsEventLogs");
        assert!(evtx.is_some(), "no WindowsEventLogs record");
        let evtx = evtx.unwrap();
        assert_eq!(evtx.artifact_type, IngestType::File);
    }

    #[test]
    fn parse_source_name_is_fa() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        for rec in &records {
            assert_eq!(
                rec.source_name, "fa",
                "wrong source_name: {}",
                rec.source_name
            );
        }
    }

    #[test]
    fn parse_meaning_from_doc() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        let ntds = records
            .iter()
            .find(|r| r.name == "WindowsNtdsDatabase")
            .expect("no ntds");
        assert!(
            ntds.meaning.contains("Active Directory"),
            "meaning: {}",
            ntds.meaning
        );
    }

    #[test]
    fn parse_ids_are_unique_and_snake_case() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        let mut ids = std::collections::HashSet::new();
        for rec in &records {
            assert!(ids.insert(rec.id.clone()), "duplicate ID: {}", rec.id);
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
    fn parse_multiple_keys_produces_multiple_records() {
        let records = parse_fa_yaml(SAMPLE_FA_YAML);
        // WindowsRunKeys has 3 keys → expect >= 3 registry records
        let registry_count = records
            .iter()
            .filter(|r| r.artifact_type == IngestType::RegistryKey)
            .count();
        assert!(
            registry_count >= 3,
            "expected >= 3 registry records, got {registry_count}"
        );
    }

    #[test]
    fn fetch_fa_windows_returns_records() {
        let result = fetch_fa_artifacts("https://raw.githubusercontent.com/forensicartifacts/artifacts/main/artifacts/data/windows.yaml");
        match result {
            Ok(records) => {
                assert!(!records.is_empty(), "expected FA windows records");
                assert!(records.len() > 20, "expected many FA records");
            }
            Err(e) => {
                eprintln!("WARN: network fetch failed (acceptable in offline CI): {e}");
            }
        }
    }
}
