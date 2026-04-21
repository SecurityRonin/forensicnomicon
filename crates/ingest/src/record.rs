/// The type of artifact being ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestType {
    RegistryKey,
    RegistryValue,
    File,
    Directory,
    EventLog,
}

/// Intermediate record produced by each source parser before code generation.
#[derive(Debug, Clone)]
pub struct IngestRecord {
    pub id: String,
    pub name: String,
    pub source_name: &'static str,
    pub artifact_type: IngestType,
    pub hive: Option<String>,
    pub key_path: String,
    pub value_name: Option<String>,
    pub file_path: Option<String>,
    pub meaning: String,
    pub mitre_techniques: Vec<String>,
    pub triage_priority: String,
    pub sources: Vec<String>,
}

impl IngestRecord {
    /// Construct a minimal registry-key record.
    pub fn registry_key(
        id: impl Into<String>,
        name: impl Into<String>,
        source_name: &'static str,
        hive: Option<String>,
        key_path: impl Into<String>,
        meaning: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source_name,
            artifact_type: IngestType::RegistryKey,
            hive,
            key_path: key_path.into(),
            value_name: None,
            file_path: None,
            meaning: meaning.into(),
            mitre_techniques: Vec::new(),
            triage_priority: "Medium".to_string(),
            sources: Vec::new(),
        }
    }

    /// Construct a minimal file record.
    pub fn file(
        id: impl Into<String>,
        name: impl Into<String>,
        source_name: &'static str,
        file_path: impl Into<String>,
        meaning: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source_name,
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(file_path.into()),
            meaning: meaning.into(),
            mitre_techniques: Vec::new(),
            triage_priority: "Medium".to_string(),
            sources: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_key_record_has_correct_type() {
        let rec = IngestRecord::registry_key(
            "regedit_run",
            "Run Key",
            "regedit",
            Some("HKLM\\SOFTWARE".to_string()),
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Persistence via Run key",
        );
        assert_eq!(rec.id, "regedit_run");
        assert_eq!(rec.name, "Run Key");
        assert_eq!(rec.source_name, "regedit");
        assert_eq!(rec.artifact_type, IngestType::RegistryKey);
        assert_eq!(rec.hive, Some("HKLM\\SOFTWARE".to_string()));
        assert_eq!(rec.key_path, "Microsoft\\Windows\\CurrentVersion\\Run");
        assert!(rec.file_path.is_none());
        assert!(rec.value_name.is_none());
        assert_eq!(rec.triage_priority, "Medium");
        assert!(rec.mitre_techniques.is_empty());
    }

    #[test]
    fn file_record_has_correct_type() {
        let rec = IngestRecord::file(
            "kape_file_chrome_history",
            "Chrome History",
            "kape",
            r"C:\Users\%user%\AppData\Local\Google\Chrome\User Data\Default\History",
            "Chrome browsing history SQLite database",
        );
        assert_eq!(rec.artifact_type, IngestType::File);
        assert!(rec.hive.is_none());
        assert_eq!(rec.key_path, "");
        assert_eq!(
            rec.file_path.as_deref(),
            Some(r"C:\Users\%user%\AppData\Local\Google\Chrome\User Data\Default\History")
        );
    }

    #[test]
    fn record_fields_are_mutable() {
        let mut rec = IngestRecord::registry_key(
            "test_id",
            "Test Name",
            "test",
            None,
            "Some\\Key",
            "description",
        );
        rec.mitre_techniques.push("T1547.001".to_string());
        rec.triage_priority = "High".to_string();
        rec.sources.push("https://example.com".to_string());
        assert_eq!(rec.mitre_techniques, vec!["T1547.001"]);
        assert_eq!(rec.triage_priority, "High");
        assert_eq!(rec.sources, vec!["https://example.com"]);
    }

    #[test]
    fn ingest_type_equality() {
        assert_eq!(IngestType::RegistryKey, IngestType::RegistryKey);
        assert_ne!(IngestType::File, IngestType::Directory);
        assert_ne!(IngestType::RegistryKey, IngestType::RegistryValue);
    }
}
