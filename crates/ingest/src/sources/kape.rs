//! Parser for KAPE .tkape (YAML) target files.
//!
//! Format: YAML with a `Targets:` list. Each entry has:
//! - `Name`
//! - `Category`
//! - `Path` (filesystem path, may have %user% placeholders)
//! - `FileMask` (optional)
//! - `IsDirectory` (bool)
//! - `Recursive` (bool)
//! - `Comment` (optional)

use std::collections::HashSet;

use crate::normalize::{normalize_file_id, to_snake_case};
use crate::record::{IngestRecord, IngestType};

const KAPE_TREE_URL: &str =
    "https://api.github.com/repos/EricZimmerman/KapeFiles/git/trees/master?recursive=1";
const KAPE_RAW_BASE: &str = "https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/";

/// Parse a `.tkape` YAML string into `IngestRecord`s.
/// `file_name` is the base name (e.g., "Chrome") used in meaning fallback.
pub fn parse_tkape(content: &str, file_name: &str) -> Vec<IngestRecord> {
    let mut records = Vec::new();
    let mut seen_ids = HashSet::new();

    let mut name = String::new();
    let mut path = String::new();
    let mut file_mask = String::new();
    let mut is_directory = false;
    let mut comment = String::new();
    let mut in_entry = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "-" {
            // Flush previous entry
            if in_entry && !name.is_empty() && !path.is_empty() {
                if let Some(rec) = build_record(
                    &name,
                    &path,
                    &file_mask,
                    is_directory,
                    &comment,
                    file_name,
                    &mut seen_ids,
                ) {
                    records.push(rec);
                }
            }
            name.clear();
            path.clear();
            file_mask.clear();
            is_directory = false;
            comment.clear();
            in_entry = true;
            continue;
        }

        if !in_entry {
            continue;
        }

        if let Some(val) = strip_yaml_field(trimmed, "Name") {
            name = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "Path") {
            path = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "FileMask") {
            file_mask = val.to_string();
        } else if let Some(val) = strip_yaml_field(trimmed, "IsDirectory") {
            is_directory = val.trim().eq_ignore_ascii_case("true");
        } else if let Some(val) = strip_yaml_field(trimmed, "Comment") {
            comment = val.to_string();
        }
    }

    // Flush last entry
    if in_entry && !name.is_empty() && !path.is_empty() {
        if let Some(rec) = build_record(
            &name,
            &path,
            &file_mask,
            is_directory,
            &comment,
            file_name,
            &mut seen_ids,
        ) {
            records.push(rec);
        }
    }

    records
}

/// Fetch all KAPE .tkape target files from GitHub and return parsed records.
pub fn fetch_kape_targets() -> Result<Vec<IngestRecord>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("forensicnomicon-ingest/0.1")
        .build()?;

    // Get the file tree
    let tree: serde_json::Value = client.get(KAPE_TREE_URL).send()?.json()?;

    let files = tree["tree"]
        .as_array()
        .ok_or("no tree array")?
        .iter()
        .filter_map(|f| f["path"].as_str())
        .filter(|p| p.ends_with(".tkape") && p.starts_with("Targets/"))
        .map(|p| p.to_string())
        .collect::<Vec<_>>();

    let mut all_records = Vec::new();
    let mut global_seen = HashSet::new();

    for file_path in &files {
        let url = format!("{KAPE_RAW_BASE}{file_path}");
        let content = match client.get(&url).send() {
            Ok(resp) => match resp.text() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("WARN: failed to read {file_path}: {e}");
                    continue;
                }
            },
            Err(e) => {
                eprintln!("WARN: failed to fetch {file_path}: {e}");
                continue;
            }
        };

        // Extract base name from path (e.g. "Targets/Browsers/Chrome.tkape" -> "Chrome")
        let base_name = std::path::Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let records = parse_tkape(&content, base_name);
        for mut rec in records {
            // Ensure global uniqueness
            if global_seen.contains(&rec.id) {
                let mut n = 2u32;
                loop {
                    let candidate = format!("{}_{n}", rec.id);
                    if !global_seen.contains(&candidate) {
                        rec.id = candidate;
                        break;
                    }
                    n += 1;
                }
            }
            global_seen.insert(rec.id.clone());
            all_records.push(rec);
        }
    }

    Ok(all_records)
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
    name: &str,
    path: &str,
    file_mask: &str,
    is_directory: bool,
    comment: &str,
    source_file: &str,
    seen_ids: &mut HashSet<String>,
) -> Option<IngestRecord> {
    if name.is_empty() || path.is_empty() {
        return None;
    }

    // Build full path (path + file_mask if not empty)
    let full_path = if !file_mask.is_empty() && !is_directory {
        format!("{path}{file_mask}")
    } else {
        path.to_string()
    };

    let artifact_type = if is_directory {
        IngestType::Directory
    } else {
        IngestType::File
    };

    let base_id = normalize_file_id(&full_path, "kape", is_directory);

    // Ensure uniqueness within this file
    let id = if seen_ids.contains(&base_id) {
        let name_part = to_snake_case(name);
        let name_short = &name_part[..name_part.len().min(20)];
        let candidate = format!(
            "kape_{}_{}",
            if is_directory { "dir" } else { "file" },
            name_short
        );
        let candidate = candidate.trim_end_matches('_').to_string();
        if seen_ids.contains(&candidate) {
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

    let meaning = if !comment.is_empty() {
        comment.to_string()
    } else {
        format!("{name} — collected by KAPE {source_file} target")
    };

    let triage = infer_triage(name, comment);

    Some(IngestRecord {
        id,
        name: name.to_string(),
        source_name: "kape",
        artifact_type,
        hive: None,
        key_path: String::new(),
        value_name: None,
        file_path: Some(full_path),
        meaning,
        mitre_techniques: extract_mitre(comment),
        triage_priority: triage.to_string(),
        sources: vec![format!(
            "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/{source_file}.tkape"
        )],
    })
}

fn infer_triage(name: &str, comment: &str) -> &'static str {
    let combined = format!("{name} {comment}").to_ascii_lowercase();
    if combined.contains("credential")
        || combined.contains("password")
        || combined.contains("sam ")
        || combined.contains("ntds")
    {
        "Critical"
    } else if combined.contains("prefetch")
        || combined.contains("event log")
        || combined.contains("registry")
        || combined.contains("mft")
        || combined.contains("lnk")
        || combined.contains("shellbag")
    {
        "High"
    } else if combined.contains("browser")
        || combined.contains("history")
        || combined.contains("cookie")
        || combined.contains("download")
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

    const SAMPLE_TKAPE: &str = r#"Description: Chrome
Author: Eric Zimmerman
Version: 1.4
Id: a56d0a8f-3229-489e-aea7-353d1f6f9639
RecreateDirectories: true
Targets:
    -
        Name: Chrome Bookmarks XP
        Category: Communications
        Path: C:\Documents and Settings\%user%\Local Settings\Application Data\Google\Chrome\User Data\*\
        FileMask: Bookmarks*
        IsDirectory: false
        Recursive: true
    -
        Name: Chrome History
        Category: Communications
        Path: C:\Users\%user%\AppData\Local\Google\Chrome\User Data\Default\
        FileMask: History*
        IsDirectory: false
        Recursive: false
    -
        Name: Chrome User Data Folder
        Category: Communications
        Path: C:\Users\%user%\AppData\Local\Google\Chrome\User Data\
        FileMask:
        IsDirectory: true
        Recursive: true
"#;

    #[test]
    fn parse_returns_records() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        assert!(!records.is_empty(), "should return at least one record");
    }

    #[test]
    fn parse_correct_count() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        assert_eq!(
            records.len(),
            3,
            "expected 3 targets, got {}",
            records.len()
        );
    }

    #[test]
    fn parse_file_artifact_type() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        let history = records
            .iter()
            .find(|r| r.name == "Chrome History")
            .expect("no Chrome History");
        use crate::record::IngestType;
        assert_eq!(history.artifact_type, IngestType::File);
        assert!(history.file_path.is_some(), "file_path should be set");
    }

    #[test]
    fn parse_directory_artifact_type() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        use crate::record::IngestType;
        let dir_rec = records
            .iter()
            .find(|r| r.artifact_type == IngestType::Directory);
        assert!(dir_rec.is_some(), "expected at least one Directory record");
    }

    #[test]
    fn parse_source_name_is_kape() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        for rec in &records {
            assert_eq!(rec.source_name, "kape", "wrong source_name for {}", rec.id);
        }
    }

    #[test]
    fn parse_ids_are_unique() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        let mut ids = std::collections::HashSet::new();
        for rec in &records {
            assert!(ids.insert(rec.id.clone()), "duplicate ID: {}", rec.id);
        }
    }

    #[test]
    fn parse_ids_are_snake_case() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
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
    fn fetch_kape_index_returns_files() {
        // Network test
        let result = fetch_kape_targets();
        match result {
            Ok(records) => {
                assert!(!records.is_empty(), "expected KAPE records from GitHub");
                assert!(records.len() > 20, "expected many KAPE records");
            }
            Err(e) => {
                eprintln!("WARN: network fetch failed (acceptable in offline CI): {e}");
            }
        }
    }
}
