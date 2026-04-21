// RED: Tests only — KAPE .tkape parser
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
        assert_eq!(records.len(), 3, "expected 3 targets, got {}", records.len());
    }

    #[test]
    fn parse_file_artifact_type() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        let history = records.iter().find(|r| r.name == "Chrome History").expect("no Chrome History");
        use crate::record::IngestType;
        assert_eq!(history.artifact_type, IngestType::File);
        assert!(history.file_path.is_some(), "file_path should be set");
    }

    #[test]
    fn parse_directory_artifact_type() {
        let records = parse_tkape(SAMPLE_TKAPE, "Chrome");
        use crate::record::IngestType;
        let dir_rec = records.iter().find(|r| r.artifact_type == IngestType::Directory);
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
                rec.id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
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
