//! Code generation: emit valid `ArtifactDescriptor` Rust statics from `IngestRecord`s.

use crate::record::{IngestRecord, IngestType};

/// Map a hive string to the `HiveTarget` variant name.
fn hive_variant(hive: &str) -> &'static str {
    let upper = hive.to_ascii_uppercase();
    if upper.contains("HKLM\\SYSTEM") || upper.contains("HKEY_LOCAL_MACHINE\\SYSTEM") {
        "HklmSystem"
    } else if upper.contains("HKLM\\SOFTWARE") || upper.contains("HKEY_LOCAL_MACHINE\\SOFTWARE") {
        "HklmSoftware"
    } else if upper.contains("HKLM\\SAM") || upper.contains("HKEY_LOCAL_MACHINE\\SAM") {
        "HklmSam"
    } else if upper.contains("HKLM\\SECURITY") || upper.contains("HKEY_LOCAL_MACHINE\\SECURITY") {
        "HklmSecurity"
    } else if upper.contains("HKCU\\SOFTWARE\\CLASSES")
        || upper.contains("HKEY_CURRENT_USER\\SOFTWARE\\CLASSES")
    {
        "UsrClass"
    } else if upper.contains("HKCU")
        || upper.contains("HKEY_CURRENT_USER")
        || upper.contains("NTUSER")
    {
        "NtUser"
    } else if upper.contains("AMCACHE") {
        "Amcache"
    } else if upper.contains("BCD") {
        "Bcd"
    } else {
        "None"
    }
}

/// Map an `IngestType` to the `ArtifactType` variant name.
fn artifact_type_variant(t: &IngestType) -> &'static str {
    match t {
        IngestType::RegistryKey => "RegistryKey",
        IngestType::RegistryValue => "RegistryValue",
        IngestType::File => "File",
        IngestType::Directory => "Directory",
        IngestType::EventLog => "EventLog",
    }
}

/// Map triage priority string to `TriagePriority` variant.
fn triage_variant(p: &str) -> &'static str {
    match p.to_ascii_lowercase().as_str() {
        "critical" => "Critical",
        "high" => "High",
        "low" => "Low",
        _ => "Medium",
    }
}

/// Escape a string for use inside a Rust string literal (double-quote delimited).
fn escape_rust_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Convert a snake_case ID to SCREAMING_SNAKE_CASE for the static name.
fn to_static_name(id: &str) -> String {
    id.to_ascii_uppercase()
}

/// Generate a `pub(crate) static NAME: ArtifactDescriptor = ...;` from an `IngestRecord`.
pub fn generate_static(rec: &IngestRecord) -> String {
    let static_name = to_static_name(&rec.id);
    let artifact_type = artifact_type_variant(&rec.artifact_type);

    // Hive field
    let hive_field = if let Some(ref h) = rec.hive {
        format!("Some(HiveTarget::{})", hive_variant(h))
    } else {
        "None".to_string()
    };

    // key_path — use raw strings to avoid double-escaping backslashes
    let key_path = rec.key_path.replace('\\', "\\\\");

    // value_name
    let value_name_field = match &rec.value_name {
        Some(v) => format!("Some(\"{}\")", escape_rust_str(v)),
        None => "None".to_string(),
    };

    // file_path
    let file_path_field = match &rec.file_path {
        Some(p) => format!("Some(\"{}\")", escape_rust_str(p)),
        None => "None".to_string(),
    };

    // scope: registry artifacts are system, file artifacts are mixed
    let scope = match &rec.artifact_type {
        IngestType::RegistryKey | IngestType::RegistryValue => {
            if rec
                .hive
                .as_deref()
                .map(|h| h.to_ascii_uppercase().contains("HKCU"))
                .unwrap_or(false)
            {
                "DataScope::User"
            } else {
                "DataScope::System"
            }
        }
        _ => "DataScope::Mixed",
    };

    // MITRE techniques slice
    let mitre = if rec.mitre_techniques.is_empty() {
        "&[]".to_string()
    } else {
        let items: Vec<String> = rec
            .mitre_techniques
            .iter()
            .map(|t| format!("\"{}\"", escape_rust_str(t)))
            .collect();
        format!("&[{}]", items.join(", "))
    };

    // Sources slice
    let sources = if rec.sources.is_empty() {
        "&[]".to_string()
    } else {
        let items: Vec<String> = rec
            .sources
            .iter()
            .map(|s| format!("\"{}\"", escape_rust_str(s)))
            .collect();
        format!("&[{}]", items.join(", "))
    };

    let triage = triage_variant(&rec.triage_priority);
    let meaning = escape_rust_str(&rec.meaning);
    let name = escape_rust_str(&rec.name);

    format!(
        r#"pub(crate) static {static_name}: ArtifactDescriptor = ArtifactDescriptor {{
    id: "{id}",
    name: "{name}",
    artifact_type: ArtifactType::{artifact_type},
    hive: {hive_field},
    key_path: "{key_path}",
    value_name: {value_name_field},
    file_path: {file_path_field},
    scope: {scope},
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "{meaning}",
    mitre_techniques: {mitre},
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::{triage},
    related_artifacts: &[],
    sources: {sources},
}};
"#,
        id = rec.id,
    )
}

/// Generate the file header comment and `#![allow]` attribute for a generated module.
pub fn generate_module_header(source_name: &str, count: usize) -> String {
    format!(
        r#"// AUTO-GENERATED by forensicnomicon ingest pipeline.
// Source: {source_name}
// Entries: {count}
// Do not edit manually — re-run `cargo run -p ingest` to regenerate.
#![allow(clippy::too_many_lines)]

use forensicnomicon::catalog::{{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, HiveTarget, OsScope,
    TriagePriority,
}};
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{IngestRecord, IngestType};

    fn sample_registry_record() -> IngestRecord {
        IngestRecord {
            id: "regedit_portproxy_v4tov4_tcp".to_string(),
            name: "PortProxy v4ToV4 TCP Mapping".to_string(),
            source_name: "regedit",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKLM\\SYSTEM".to_string()),
            key_path: r"CurrentControlSet\Services\PortProxy\v4tov4\tcp".to_string(),
            value_name: None,
            file_path: None,
            meaning:
                "Records IPv4-to-IPv4 port forwarding rules; commonly abused for lateral movement."
                    .to_string(),
            mitre_techniques: vec!["T1090".to_string()],
            triage_priority: "High".to_string(),
            sources: vec!["https://example.com/portproxy".to_string()],
        }
    }

    fn sample_file_record() -> IngestRecord {
        IngestRecord {
            id: "kape_file_chrome_history".to_string(),
            name: "Chrome History".to_string(),
            source_name: "kape",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"C:\Users\%user%\AppData\Local\Google\Chrome\User Data\Default\History"
                    .to_string(),
            ),
            meaning: "Chrome browsing history SQLite database.".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        }
    }

    #[test]
    fn generate_static_contains_pub_crate_static() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("pub(crate) static"),
            "missing pub(crate) static in:\n{output}"
        );
    }

    #[test]
    fn generate_static_contains_artifact_descriptor() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("ArtifactDescriptor"),
            "missing ArtifactDescriptor in:\n{output}"
        );
    }

    #[test]
    fn generate_static_uses_correct_id() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains(r#"id: "regedit_portproxy_v4tov4_tcp""#),
            "missing id field in:\n{output}"
        );
    }

    #[test]
    fn generate_static_has_uppercase_static_name() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("REGEDIT_PORTPROXY_V4TOV4_TCP"),
            "missing uppercase static name in:\n{output}"
        );
    }

    #[test]
    fn generate_static_registry_key_type() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("ArtifactType::RegistryKey"),
            "wrong artifact type in:\n{output}"
        );
    }

    #[test]
    fn generate_static_hive_some() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("Some(HiveTarget::HklmSystem)"),
            "wrong hive in:\n{output}"
        );
    }

    #[test]
    fn generate_static_file_type_and_path() {
        let rec = sample_file_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("ArtifactType::File"),
            "wrong type in:\n{output}"
        );
        assert!(
            output.contains("file_path: Some("),
            "missing file_path in:\n{output}"
        );
        assert!(
            output.contains("Chrome"),
            "missing path content in:\n{output}"
        );
    }

    #[test]
    fn generate_static_mitre_techniques() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains(r#""T1090""#),
            "missing MITRE technique in:\n{output}"
        );
    }

    #[test]
    fn generate_static_triage_high() {
        let rec = sample_registry_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("TriagePriority::High"),
            "wrong triage priority in:\n{output}"
        );
    }

    #[test]
    fn generate_static_empty_mitre_and_sources() {
        let rec = sample_file_record();
        let output = generate_static(&rec);
        assert!(
            output.contains("mitre_techniques: &[]"),
            "missing empty mitre in:\n{output}"
        );
        assert!(
            output.contains("sources: &[]"),
            "missing empty sources in:\n{output}"
        );
    }

    #[test]
    fn generate_module_header_contains_source_and_count() {
        let header = generate_module_header("regedit", 42);
        assert!(header.contains("regedit"), "missing source name in header");
        assert!(header.contains("42"), "missing count in header");
        assert!(
            header.contains("#![allow(clippy::too_many_lines)]"),
            "missing clippy allow"
        );
    }
}
