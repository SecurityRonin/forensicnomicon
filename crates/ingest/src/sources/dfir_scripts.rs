//! dfir-scripts.github.io Windows registry artifact source.
//!
//! Ingests the registry key PATHS (non-copyrightable facts) and ATT&CK technique
//! IDs from the dfir-scripts reference dataset
//! (github.com/dfir-scripts/dfir-scripts.github.io, `registry/…_schema.json`).
//!
//! License note: the dfir-scripts repo carries **no license**, so this source
//! deliberately does NOT copy dfir's `description` / `forensic_value` prose. Only
//! the key paths and ATT&CK technique IDs (facts) are ingested; `meaning` is our
//! own summary pointing at the authoritative parsers dfir itself references
//! (RegRipper, Autoruns, SBECmd, AmcacheParser). dfir-scripts is cited as the
//! discovery source. All 16 categories are ingested.

use std::collections::HashSet;

use serde::Deserialize;

use crate::github::github_client;
use crate::normalize::normalize_registry_id_unique;
use crate::record::{IngestRecord, IngestType};

const DFIR_REGISTRY_JSON_URL: &str = "https://raw.githubusercontent.com/dfir-scripts/dfir-scripts.github.io/main/registry/windows_registry_artifacts_schema_v0.3.json";
const DISCOVERY_SOURCE: &str = "https://dfir-scripts.github.io/";
const SOURCE_NAME: &str = "dfir_scripts";

#[derive(Deserialize)]
struct Schema {
    categories: std::collections::BTreeMap<String, Category>,
}

#[derive(Deserialize)]
struct Category {
    #[serde(default)]
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    name: String,
    #[serde(default)]
    hive: Vec<String>,
    #[serde(default)]
    keys: Vec<String>,
    /// ATT&CK technique IDs (e.g. "T1547.001"). dfir's `mitre` field is the
    /// tactic (TAxxxx) and is not ingested.
    #[serde(default)]
    techniques: Vec<String>,
}

/// Fetch and parse the dfir-scripts registry artifact dataset from GitHub.
pub fn fetch_dfir_scripts_artifacts() -> Vec<IngestRecord> {
    let client = match github_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("WARN: dfir_scripts: could not build HTTP client: {e}");
            return Vec::new();
        }
    };
    let text = match client
        .get(DFIR_REGISTRY_JSON_URL)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::text)
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("WARN: dfir_scripts: fetch failed: {e}");
            return Vec::new();
        }
    };
    let mut records = parse_dfir_scripts(&text);
    // The pipeline dedups by id, and dfir's `dfir_scripts_*` ids never collide
    // with existing source-prefixed ids for the SAME registry path. Drop keys a
    // sibling source already covers so we don't add a duplicate descriptor.
    let catalog_paths = catalog_registry_paths();
    let before = records.len();
    records.retain(|r| !path_already_catalogued(&r.key_path, &catalog_paths));
    eprintln!(
        "  dfir_scripts: dropped {} keys already in catalog; {} net-new of {}",
        before - records.len(),
        records.len(),
        before
    );
    records
}

/// Registry key paths already present anywhere in the catalog descriptors
/// (best-effort textual scan of the descriptor `.rs` files, uppercased).
fn catalog_registry_paths() -> HashSet<String> {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../data/src/catalog/descriptors");
    let mut paths = HashSet::new();
    collect_key_paths(&dir, &mut paths);
    paths
}

fn collect_key_paths(dir: &std::path::Path, out: &mut HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_key_paths(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            if let Ok(text) = std::fs::read_to_string(&p) {
                for line in text.lines() {
                    if let Some(v) = extract_key_path(line) {
                        // Descriptors write key_path with escaped backslashes
                        // ("A\\B"); dfir keys (from JSON) are single-backslash.
                        // Collapse so both sides compare on single backslashes.
                        out.insert(v.replace("\\\\", "\\").to_uppercase());
                    }
                }
            }
        }
    }
}

/// Extract the string literal after `key_path:` on a line (handles `"..."`,
/// `r"..."`, `r#"..."#`). Returns None for empty / non-matching lines.
fn extract_key_path(line: &str) -> Option<String> {
    let after = line.split_once("key_path:")?.1.trim_start();
    let after = after.trim_start_matches('r').trim_start_matches('#');
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    let v = &after[..end];
    (!v.is_empty()).then(|| v.to_string())
}

/// True when the catalog already covers this exact registry key path, allowing
/// for a hive prefix on the catalog side (dfir keys are hive-relative).
fn path_already_catalogued(key: &str, catalog: &HashSet<String>) -> bool {
    let key = key.to_uppercase();
    let suffix = format!("\\{key}");
    catalog.iter().any(|c| *c == key || c.ends_with(&suffix))
}

/// Parse the dfir-scripts registry schema JSON into ingest records — one per
/// (artifact, registry key). License-safe: no dfir prose is copied.
fn parse_dfir_scripts(json: &str) -> Vec<IngestRecord> {
    let schema: Schema = match serde_json::from_str(json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("WARN: dfir_scripts: JSON parse failed: {e}");
            return Vec::new();
        }
    };
    let mut ids: HashSet<String> = HashSet::new();
    let mut records = Vec::new();
    for (category, cat) in &schema.categories {
        let priority = triage_for_category(category);
        for art in &cat.artifacts {
            let mitre: Vec<String> = art
                .techniques
                .iter()
                .map(|t| t.trim().to_string())
                .filter(|t| is_attack_technique(t))
                .collect();
            let hive = art.hive.first().cloned();
            for key in &art.keys {
                let key = key.trim();
                if key.is_empty() {
                    continue;
                }
                let id = normalize_registry_id_unique(key, SOURCE_NAME, &ids);
                ids.insert(id.clone());
                // License-safe meaning: our own summary + the factual artifact
                // name; dfir's description/forensic_value prose is never copied.
                let meaning = format!(
                    "{} — Windows registry artifact ({}). Parse/interpret with \
                     RegRipper, Autoruns, SBECmd, or AmcacheParser.",
                    art.name,
                    human_category(category)
                );
                records.push(IngestRecord {
                    id,
                    name: art.name.clone(),
                    source_name: SOURCE_NAME,
                    artifact_type: IngestType::RegistryKey,
                    hive: hive.clone(),
                    key_path: key.to_string(),
                    value_name: None,
                    os_scope: "Win7Plus".to_string(),
                    file_path: None,
                    meaning,
                    mitre_techniques: mitre.clone(),
                    triage_priority: priority.to_string(),
                    sources: vec![DISCOVERY_SOURCE.to_string()],
                });
            }
        }
    }
    records
}

/// True for ATT&CK technique IDs shaped like `Txxxx` or `Txxxx.yyy`.
fn is_attack_technique(t: &str) -> bool {
    let t = t.trim();
    t.starts_with('T') && t[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Triage priority derived from the dfir category (structure-driven, not per-key).
fn triage_for_category(category: &str) -> &'static str {
    match category {
        "autostart_and_persistence"
        | "execution_artifacts"
        | "software_installation_and_execution"
        | "security_accounts_and_policy"
        | "malware_indicators"
        | "notable_attacker_tools"
        | "lolrmm_abused_rmm_tools" => "High",
        "user_activity_and_mru"
        | "network_and_remote_access"
        | "usb_devices_and_hardware"
        | "cloud_and_modern_windows" => "Medium",
        _ => "Low",
    }
}

fn human_category(category: &str) -> String {
    category.replace('_', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
        "metadata": {"version": "v0.1"},
        "categories": {
            "autostart_and_persistence": {
                "artifacts": [
                    {
                        "name": "Run / RunOnce Autostart Keys",
                        "hive": ["SOFTWARE", "NTUSER.DAT"],
                        "keys": [
                            "Microsoft\\Windows\\CurrentVersion\\Run",
                            "Microsoft\\Windows\\CurrentVersion\\RunOnce"
                        ],
                        "description": "COPYRIGHTED_DFIR_PROSE_DO_NOT_COPY",
                        "forensic_value": "MORE_DFIR_PROSE_DO_NOT_COPY",
                        "mitre": "TA0003",
                        "techniques": ["T1547.001", "not-an-id"],
                        "parsers": ["RegRipper"]
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn parses_one_record_per_key_license_safe() {
        let recs = parse_dfir_scripts(FIXTURE);
        assert_eq!(recs.len(), 2, "one record per registry key");

        let run = &recs[0];
        assert_eq!(run.source_name, "dfir_scripts");
        assert_eq!(run.artifact_type, IngestType::RegistryKey);
        assert_eq!(run.key_path, r"Microsoft\Windows\CurrentVersion\Run");
        assert_eq!(run.hive.as_deref(), Some("SOFTWARE"));
        assert_eq!(run.mitre_techniques, vec!["T1547.001".to_string()]);
        assert_eq!(run.triage_priority, "High");
        assert!(run
            .sources
            .iter()
            .any(|s| s.contains("dfir-scripts.github.io")));

        // License-safe: the artifact name (a factual label) may appear, but dfir's
        // description / forensic_value prose must NOT be copied into meaning.
        assert!(run.meaning.contains("Run / RunOnce Autostart Keys"));
        assert!(!run.meaning.contains("COPYRIGHTED_DFIR_PROSE_DO_NOT_COPY"));
        assert!(!run.meaning.contains("MORE_DFIR_PROSE_DO_NOT_COPY"));

        // ids unique + normalized
        assert_ne!(recs[0].id, recs[1].id);
        assert!(recs[0].id.starts_with("dfir_scripts_"));
    }

    #[test]
    fn non_attack_tokens_are_dropped() {
        let recs = parse_dfir_scripts(FIXTURE);
        assert!(recs
            .iter()
            .all(|r| r.mitre_techniques.iter().all(|t| is_attack_technique(t))));
    }

    #[test]
    fn extract_key_path_handles_quote_forms() {
        // escaped form (how descriptors are written)
        assert_eq!(
            extract_key_path(r#"    key_path: "Software\\Microsoft\\Run","#).as_deref(),
            Some(r"Software\\Microsoft\\Run")
        );
        // raw-string form
        assert_eq!(
            extract_key_path(r##"    key_path: r"Software\Foo","##).as_deref(),
            Some(r"Software\Foo")
        );
        // empty and non-matching lines
        assert_eq!(extract_key_path(r#"    key_path: "","#), None);
        assert_eq!(extract_key_path(r#"    name: "x","#), None);
    }

    #[test]
    fn path_dedup_matches_across_hive_prefix_and_escaping() {
        // Catalog paths as extracted+normalized: escaped backslashes collapsed,
        // uppercased, hive prefix present.
        let mut cat = HashSet::new();
        cat.insert(r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN".to_string());
        // hive-relative dfir key IS covered (suffix match past the SOFTWARE hive)
        assert!(path_already_catalogued(
            r"Microsoft\Windows\CurrentVersion\Run",
            &cat
        ));
        // a sibling key that is NOT catalogued is kept
        assert!(!path_already_catalogued(
            r"Microsoft\Windows\CurrentVersion\RunOnceEx",
            &cat
        ));
    }
}
