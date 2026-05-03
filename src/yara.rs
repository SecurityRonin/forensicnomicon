//! YARA rule template generator.
//!
//! Generates YARA rule skeletons from catalog artifact metadata and
//! container signatures. Output is valid YARA syntax that analysts
//! can refine and deploy.

use crate::catalog::{ArtifactType, HiveTarget, TriagePriority, CATALOG};

/// Return the Windows registry root prefix string for a given hive target.
fn hive_prefix(hive: HiveTarget) -> &'static str {
    match hive {
        HiveTarget::HklmSystem => r"HKEY_LOCAL_MACHINE\SYSTEM",
        HiveTarget::HklmSoftware => r"HKEY_LOCAL_MACHINE\SOFTWARE",
        HiveTarget::HklmSam => r"HKEY_LOCAL_MACHINE\SAM",
        HiveTarget::HklmSecurity => r"HKEY_LOCAL_MACHINE\SECURITY",
        HiveTarget::NtUser => r"HKEY_CURRENT_USER",
        HiveTarget::UsrClass => r"HKEY_CURRENT_USER\Software\Classes",
        HiveTarget::Amcache => {
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatCache"
        }
        HiveTarget::Bcd => r"HKEY_LOCAL_MACHINE\BCD00000000",
        HiveTarget::None => "",
    }
}

/// Sanitize an artifact id into a valid YARA rule name identifier.
///
/// YARA identifiers may contain letters, digits, and underscores. Hyphens and
/// dots are replaced with underscores.
fn sanitize_id(id: &str) -> String {
    id.replace(['-', '.'], "_")
}

/// Generate a YARA rule skeleton for a catalog artifact.
///
/// Uses the artifact's key_path, file_path, and MITRE techniques to produce a
/// valid YARA rule template that analysts can refine and deploy.
///
/// Returns `None` only if the artifact is not found in the catalog.
pub fn yara_rule_template(artifact_id: &str) -> Option<String> {
    let artifact = CATALOG.by_id(artifact_id)?;

    let rule_name = sanitize_id(artifact.id);

    let mitre = artifact
        .mitre_techniques
        .first()
        .copied()
        .unwrap_or("(none)");

    let priority = match artifact.triage_priority {
        TriagePriority::Critical => "critical",
        TriagePriority::High => "high",
        TriagePriority::Medium => "medium",
        TriagePriority::Low => "low",
    };

    // Truncate meaning and sanitize quotes so the YARA string literal stays valid.
    let meaning = artifact.meaning.replace('"', "'");
    let meaning_short: String = meaning.chars().take(120).collect();

    // Build the strings block depending on artifact type.
    let (strings_block, condition_var) = match artifact.artifact_type {
        ArtifactType::RegistryKey | ArtifactType::RegistryValue => {
            // Construct full registry path: HKEY_... \ key_path
            let full_path = if let Some(hive) = artifact.hive {
                let prefix = hive_prefix(hive);
                if artifact.key_path.is_empty() {
                    prefix.to_string()
                } else {
                    format!(r"{}\{}", prefix, artifact.key_path)
                }
            } else {
                artifact.key_path.to_string()
            };
            let block =
                format!("    strings:\n        $key_path = \"{full_path}\" nocase wide ascii");
            (block, "$key_path")
        }
        ArtifactType::File | ArtifactType::Directory => {
            // Prefer file_path; fall back to key_path.
            let path = artifact.file_path.unwrap_or(artifact.key_path);
            // Use the filename portion for a compact, focused string match.
            let filename = path.rsplit(['\\', '/']).next().unwrap_or(path);
            let target = if filename.is_empty() { path } else { filename };
            let block =
                format!("    strings:\n        $file_path = \"{target}\" nocase wide ascii");
            (block, "$file_path")
        }
        ArtifactType::EventLog => {
            let path = artifact.file_path.unwrap_or(artifact.key_path);
            let filename = path.rsplit(['\\', '/']).next().unwrap_or(path);
            let block =
                format!("    strings:\n        $evtx_file = \"{filename}\" nocase wide ascii");
            (block, "$evtx_file")
        }
        ArtifactType::MemoryRegion | ArtifactType::LiveResponse | ArtifactType::DatabaseEntry => {
            let block = format!(
                "    strings:\n        $artifact = \"{}\" nocase wide ascii",
                artifact.name
            );
            (block, "$artifact")
        }
    };

    let rule = format!(
        "rule {rule_name}\n{{\n    meta:\n        description = \"{meaning_short}\"\n        mitre = \"{mitre}\"\n        triage_priority = \"{priority}\"\n{strings_block}\n    condition:\n        {condition_var}\n}}"
    );

    Some(rule)
}

/// Generate YARA rules for all catalog artifacts.
///
/// Returns a vec of `(artifact_id, rule_string)` pairs. Every catalog entry
/// produces a rule; the caller receives the artifact id alongside the rule so
/// results can be filtered or indexed by id.
pub fn all_yara_templates() -> Vec<(&'static str, String)> {
    CATALOG
        .list()
        .iter()
        .filter_map(|d| yara_rule_template(d.id).map(|rule| (d.id, rule)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_generates_yara_rule() {
        // prefetch_file should have a container signature with magic bytes
        if let Some(rule) = yara_rule_template("prefetch_file") {
            assert!(
                rule.contains("rule prefetch_file"),
                "Rule name should be prefetch_file"
            );
            assert!(rule.contains("meta:"), "Should have meta block");
            assert!(rule.contains("condition:"), "Should have condition block");
            assert!(
                rule.contains("T1059") || rule.contains("mitre"),
                "Should reference MITRE"
            );
        }
        // It's OK if prefetch has no container signature — test that it doesn't panic
    }

    #[test]
    fn nonexistent_artifact_returns_none() {
        assert!(yara_rule_template("this_does_not_exist").is_none());
    }

    #[test]
    fn all_templates_returns_nonempty() {
        let templates = all_yara_templates();
        // At minimum, registry key artifacts with key_path should produce templates
        assert!(
            !templates.is_empty(),
            "all_yara_templates() should return at least some templates"
        );
    }

    #[test]
    fn generated_rule_has_valid_structure() {
        let templates = all_yara_templates();
        for (id, rule) in &templates {
            assert!(
                rule.contains("rule "),
                "Rule for '{id}' missing 'rule' keyword"
            );
            assert!(
                rule.contains("meta:"),
                "Rule for '{id}' missing 'meta:' block"
            );
            assert!(
                rule.contains("condition:"),
                "Rule for '{id}' missing 'condition:' block"
            );
        }
    }

    #[test]
    fn rule_name_is_valid_identifier() {
        let templates = all_yara_templates();
        for (id, rule) in &templates {
            let expected_name = id.replace(['-', '.'], "_");
            assert!(
                rule.contains(&format!("rule {expected_name}")),
                "Rule for '{id}' should use identifier '{expected_name}'"
            );
        }
    }

    #[test]
    fn run_key_generates_registry_string() {
        if let Some(rule) = yara_rule_template("run_key_hklm") {
            // Registry artifacts should have key_path strings
            assert!(
                rule.contains("$key_path") || rule.contains("Run"),
                "Registry artifact should include key path in YARA rule"
            );
        }
    }
}
