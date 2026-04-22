//! Velociraptor artifact YAML parser.
//!
//! Fetches artifact definition YAML files from the Velocidex/velociraptor
//! GitHub repository and extracts registry/file artifact paths from
//! parameter defaults.

use std::collections::HashSet;

use crate::normalize::{normalize_file_id, normalize_registry_id};
use crate::record::{IngestRecord, IngestType};

const VELO_TREE_URL: &str =
    "https://api.github.com/repos/Velocidex/velociraptor/git/trees/master?recursive=1";
const VELO_RAW_BASE: &str =
    "https://raw.githubusercontent.com/Velocidex/velociraptor/master/";

/// Parse a Velociraptor artifact YAML string into IngestRecords.
///
/// Extracts:
/// - `name` → artifact name
/// - `description` → meaning
/// - `parameters[].default` values that look like registry paths or file paths
pub fn parse_velociraptor_yaml(content: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    // Velociraptor YAML files are single-document
    let value: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(_) => return records,
    };

    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return records;
    }

    let description = value
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let parameters = value
        .get("parameters")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();

    for param in &parameters {
        let default_val = match param.get("default").and_then(|v| v.as_str()) {
            Some(s) => s.trim(),
            None => continue,
        };

        if default_val.is_empty() {
            continue;
        }

        if let Some(rec) = try_parse_as_registry(default_val, &name, &description, &mut seen_ids)
        {
            records.push(rec);
        } else if let Some(rec) =
            try_parse_as_file(default_val, &name, &description, &mut seen_ids)
        {
            records.push(rec);
        }
    }

    records
}

fn try_parse_as_registry(
    value: &str,
    artifact_name: &str,
    description: &str,
    seen: &mut HashSet<String>,
) -> Option<IngestRecord> {
    let upper = value.to_ascii_uppercase();
    let is_registry = upper.starts_with("HKEY_")
        || upper.starts_with("HKLM\\")
        || upper.starts_with("HKCU\\")
        || upper.starts_with("HKCR\\")
        || upper.starts_with("HKU\\")
        || upper.starts_with("HKLM/")
        || upper.starts_with("HKCU/");

    if !is_registry {
        return None;
    }

    // Normalize path separators
    let normalized = value.replace('/', "\\");

    let raw_id = normalize_registry_id(&normalized, "velociraptor");
    let id = ensure_unique(raw_id, seen);
    seen.insert(id.clone());

    let hive = detect_hive_string(&normalized);
    let key_path = strip_hive_from_path(&normalized);
    let triage = infer_triage(artifact_name, description);

    Some(IngestRecord {
        id,
        name: artifact_name.to_string(),
        source_name: "velociraptor",
        artifact_type: IngestType::RegistryKey,
        hive,
        key_path,
        value_name: None,
        file_path: None,
        meaning: description.to_string(),
        mitre_techniques: Vec::new(),
        triage_priority: triage.to_string(),
        sources: vec!["https://github.com/Velocidex/velociraptor".to_string()],
    })
}

fn try_parse_as_file(
    value: &str,
    artifact_name: &str,
    description: &str,
    seen: &mut HashSet<String>,
) -> Option<IngestRecord> {
    // Must look like an absolute path: starts with drive letter, /, ~, or
    // common Windows path prefixes
    let looks_like_path = value.starts_with('/')
        || value.starts_with('~')
        || (value.len() > 2 && value.as_bytes()[1] == b':')
        || value.starts_with('%')
        || value.to_ascii_lowercase().starts_with("c:\\")
        || value.to_ascii_lowercase().starts_with(r"%%environ_")
        || value.to_ascii_lowercase().starts_with(r"%%users.");

    if !looks_like_path {
        return None;
    }

    // Skip very short values or things that look like SQL / glob patterns
    if value.len() < 5 || value.contains('\n') || value.contains("SELECT") {
        return None;
    }

    let raw_id = normalize_file_id(value, "velociraptor", false);
    let id = ensure_unique(raw_id, seen);
    seen.insert(id.clone());

    let triage = infer_triage(artifact_name, description);

    Some(IngestRecord {
        id,
        name: artifact_name.to_string(),
        source_name: "velociraptor",
        artifact_type: IngestType::File,
        hive: None,
        key_path: String::new(),
        value_name: None,
        file_path: Some(value.to_string()),
        meaning: description.to_string(),
        mitre_techniques: Vec::new(),
        triage_priority: triage.to_string(),
        sources: vec!["https://github.com/Velocidex/velociraptor".to_string()],
    })
}

fn detect_hive_string(path: &str) -> Option<String> {
    let upper = path.to_ascii_uppercase();
    if upper.starts_with("HKEY_LOCAL_MACHINE\\SYSTEM")
        || upper.starts_with("HKLM\\SYSTEM")
    {
        Some("HKLM\\SYSTEM".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE\\SOFTWARE")
        || upper.starts_with("HKLM\\SOFTWARE")
    {
        Some("HKLM\\SOFTWARE".to_string())
    } else if upper.starts_with("HKEY_LOCAL_MACHINE\\SAM")
        || upper.starts_with("HKLM\\SAM")
    {
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

fn infer_triage(name: &str, description: &str) -> &'static str {
    let combined = format!("{} {}", name, description).to_ascii_lowercase();
    if combined.contains("credential")
        || combined.contains("password")
        || combined.contains("lsass")
        || combined.contains("sam ")
        || combined.contains("ntds")
        || combined.contains("token")
        || combined.contains("privilege")
    {
        "Critical"
    } else if combined.contains("shimcache")
        || combined.contains("appcompat")
        || combined.contains("amcache")
        || combined.contains("prefetch")
        || combined.contains("registry")
        || combined.contains("execution")
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

/// Fetch and parse all Velociraptor artifact YAMLs from GitHub.
pub fn fetch_velociraptor_artifacts() -> Vec<IngestRecord> {
    let client = match reqwest::blocking::Client::builder()
        .user_agent("forensicnomicon-ingest/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("WARN: velociraptor: failed to build HTTP client: {e}");
            return Vec::new();
        }
    };

    let tree: serde_json::Value = match client.get(VELO_TREE_URL).send().and_then(|r| r.json()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("WARN: velociraptor: failed to fetch tree: {e}");
            return Vec::new();
        }
    };

    let mut all_records = Vec::new();

    if let Some(tree_items) = tree.get("tree").and_then(|t| t.as_array()) {
        let yaml_paths: Vec<String> = tree_items
            .iter()
            .filter_map(|item| item.get("path").and_then(|p| p.as_str()))
            .filter(|p| {
                p.starts_with("artifacts/definitions/") && p.ends_with(".yaml")
            })
            .map(|s| s.to_string())
            .collect();

        for path in yaml_paths {
            let url = format!("{VELO_RAW_BASE}{path}");
            std::thread::sleep(std::time::Duration::from_millis(200));
            match client.get(&url).send().and_then(|r| r.text()) {
                Ok(content) => {
                    let records = parse_velociraptor_yaml(&content);
                    all_records.extend(records);
                }
                Err(e) => {
                    eprintln!("WARN: velociraptor: failed to fetch {url}: {e}");
                }
            }
        }
    }

    all_records
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r#"
name: Windows.Registry.AppCompatCache
description: |
  Reads the Shimcache from the AppCompatCache registry key.
  AppCompatCache is a mechanism to quickly detect if a file
  has ever been executed on the Windows system.
sources:
  - precondition: SELECT OS From info() where OS = 'windows'
    query: |
      SELECT * FROM read_reg_key(globs=shimcacheKey + "/*")
parameters:
  - name: shimcacheKey
    default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
  - name: Profile
    default: "{}"
"#;

    const SAMPLE_FILE_YAML: &str = r#"
name: Windows.EventLogs.Evtx
description: Parses Windows EVTX event log files.
parameters:
  - name: EvtxGlob
    default: '%SystemRoot%\System32\winevt\Logs\*.evtx'
  - name: MaxCount
    default: "1000"
"#;

    #[test]
    fn parse_registry_artifact() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        assert!(!records.is_empty(), "should return at least one record");
        let rec = records.iter().find(|r| r.artifact_type == IngestType::RegistryKey);
        assert!(rec.is_some(), "expected a RegistryKey record");
    }

    #[test]
    fn parse_artifact_name_used_as_record_name() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        for rec in &records {
            assert_eq!(
                rec.name, "Windows.Registry.AppCompatCache",
                "wrong name: {}",
                rec.name
            );
        }
    }

    #[test]
    fn parse_description_used_as_meaning() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        assert!(!records.is_empty());
        let rec = &records[0];
        assert!(
            rec.meaning.contains("Shimcache") || rec.meaning.contains("AppCompatCache"),
            "meaning doesn't contain expected text: {}",
            rec.meaning
        );
    }

    #[test]
    fn parse_ids_are_snake_case_with_velociraptor_prefix() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        for rec in &records {
            assert!(
                rec.id.starts_with("velociraptor_"),
                "ID missing velociraptor_ prefix: {}",
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
    fn parse_source_name_is_velociraptor() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        for rec in &records {
            assert_eq!(
                rec.source_name, "velociraptor",
                "wrong source_name for {}",
                rec.id
            );
        }
    }

    #[test]
    fn parse_file_artifact_from_path_param() {
        let records = parse_velociraptor_yaml(SAMPLE_FILE_YAML);
        let file_rec = records.iter().find(|r| r.artifact_type == IngestType::File);
        assert!(file_rec.is_some(), "expected a File record from path param");
    }

    #[test]
    fn shimcache_is_high_priority() {
        let records = parse_velociraptor_yaml(SAMPLE_YAML);
        assert!(!records.is_empty());
        let rec = &records[0];
        assert!(
            rec.triage_priority == "High" || rec.triage_priority == "Critical",
            "shimcache should be High/Critical, got: {}",
            rec.triage_priority
        );
    }

    #[test]
    fn non_string_defaults_are_skipped() {
        // MaxCount = "1000" — not a path, should be skipped
        let records = parse_velociraptor_yaml(SAMPLE_FILE_YAML);
        // Should only have the file path record, not a "1000" record
        for rec in &records {
            assert!(
                rec.file_path.as_deref() != Some("1000"),
                "should not create record for numeric default"
            );
        }
    }
}
