//! ATT&CK Navigator layer generator.
//!
//! Generates MITRE ATT&CK Navigator JSON layers showing which techniques
//! have catalog artifact coverage and how many artifacts cover each technique.

use crate::catalog::CATALOG;
use crate::mitre::AttackTechnique;
use std::collections::HashMap;

/// Generate an ATT&CK Navigator layer JSON for the catalog.
///
/// Returns a JSON string directly importable into the ATT&CK Navigator
/// at <https://mitre-attack.github.io/attack-navigator/>
pub fn generate_navigator_layer(layer_name: &str) -> String {
    let coverage = technique_coverage();

    let mut techniques_json = Vec::new();
    let mut sorted: Vec<(&str, &Vec<&str>)> = coverage.iter().map(|(k, v)| (*k, v)).collect();
    sorted.sort_by_key(|(k, _)| *k);

    for (technique_id, artifact_ids) in &sorted {
        let count = artifact_ids.len();
        let color = match count {
            1 => "#cce5ff",
            2 => "#66b3ff",
            _ => "#0066cc",
        };
        let comment = format!("{count} artifact{}", if count == 1 { "" } else { "s" });
        techniques_json.push(format!(
            r#"    {{"techniqueID": "{technique_id}", "score": {count}, "color": "{color}", "comment": "{comment}"}}"#,
        ));
    }

    let techniques_str = techniques_json.join(",\n");

    format!(
        r#"{{
  "name": "{layer_name}",
  "versions": {{"attack": "14", "navigator": "4.9", "layer": "4.5"}},
  "domain": "enterprise-attack",
  "description": "forensicnomicon coverage",
  "techniques": [
{techniques_str}
  ]
}}"#,
    )
}

/// Render an investigation's [`Report`](crate::report::Report) as an ATT&CK
/// Navigator layer — one technique heatmap of everything observed in the case,
/// scored by the highest severity seen for each technique. Directly importable
/// into the ATT&CK Navigator.
#[must_use]
pub fn report_to_navigator_layer(report: &crate::report::Report, layer_name: &str) -> String {
    findings_to_navigator_layer(&report.findings, layer_name)
}

/// Render a set of [`Finding`](crate::report::Finding)s as an ATT&CK Navigator
/// layer. Each `mitre-attack` external ref on a finding contributes its
/// technique; entries are deduplicated by technique ID, scored by the **maximum
/// severity** of the contributing findings, colored on a severity gradient, and
/// commented with the finding codes and total occurrence count. Findings with no
/// MITRE reference are omitted (they have no place on the matrix).
#[must_use]
pub fn findings_to_navigator_layer(
    findings: &[crate::report::Finding],
    layer_name: &str,
) -> String {
    use crate::report::Severity;

    struct Agg {
        severity: Option<Severity>,
        occurrences: u64,
        codes: Vec<String>,
    }

    // BTreeMap keeps the output deterministic (sorted by technique ID).
    let mut by_technique: std::collections::BTreeMap<String, Agg> =
        std::collections::BTreeMap::new();
    for finding in findings {
        let occ = finding
            .context
            .occurrences
            .map_or(1, std::num::NonZeroU64::get);
        for reference in &finding.context.external_refs {
            if reference.scheme != "mitre-attack" {
                continue;
            }
            let agg = by_technique.entry(reference.id.clone()).or_insert(Agg {
                severity: None,
                occurrences: 0,
                codes: Vec::new(),
            });
            if finding.severity > agg.severity {
                agg.severity = finding.severity;
            }
            agg.occurrences = agg.occurrences.saturating_add(occ);
            let code = finding.code.to_string();
            if !agg.codes.contains(&code) {
                agg.codes.push(code);
            }
        }
    }

    let mut techniques_json = Vec::new();
    for (technique_id, agg) in &by_technique {
        let comment = json_escape(&format!(
            "{} ({} occurrence{})",
            agg.codes.join(", "),
            agg.occurrences,
            if agg.occurrences == 1 { "" } else { "s" }
        ));
        techniques_json.push(format!(
            r#"    {{"techniqueID": "{technique_id}", "score": {}, "color": "{}", "comment": "{comment}", "enabled": true}}"#,
            severity_score(agg.severity),
            severity_color(agg.severity),
        ));
    }
    let techniques_str = techniques_json.join(",\n");
    let name = json_escape(layer_name);

    format!(
        r#"{{
  "name": "{name}",
  "versions": {{"attack": "14", "navigator": "4.9", "layer": "4.5"}},
  "domain": "enterprise-attack",
  "description": "Investigation findings — ATT&CK techniques observed, scored by severity",
  "techniques": [
{techniques_str}
  ]
}}"#,
    )
}

/// Navigator `score` (0-100) for a finding severity. `None` ("not scored")
/// still places the technique on the matrix at a low score.
fn severity_score(severity: Option<crate::report::Severity>) -> u32 {
    use crate::report::Severity;
    match severity {
        Some(Severity::Critical) => 100,
        Some(Severity::High) => 78,
        Some(Severity::Medium) => 55,
        Some(Severity::Low) => 35,
        Some(Severity::Info) => 15,
        _ => 5, // None, or any future variant
    }
}

/// Severity gradient color (green → red) for the Navigator heatmap.
fn severity_color(severity: Option<crate::report::Severity>) -> &'static str {
    use crate::report::Severity;
    match severity {
        Some(Severity::Critical) => "#c0392b",
        Some(Severity::High) => "#e67e22",
        Some(Severity::Medium) => "#f1c40f",
        Some(Severity::Low) => "#b7d04a",
        Some(Severity::Info) => "#7fb069",
        _ => "#9e9e9e", // None, or any future variant
    }
}

/// Minimal JSON string escaping for embedded layer-name / comment text.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Returns a map of technique ID → artifact IDs for coverage reporting.
pub fn technique_coverage() -> HashMap<&'static str, Vec<&'static str>> {
    let mut map: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for descriptor in CATALOG.list() {
        for &technique in descriptor.mitre_techniques {
            map.entry(technique).or_default().push(descriptor.id);
        }
    }
    map
}

/// Returns the count of unique ATT&CK techniques covered by the catalog.
pub fn covered_technique_count() -> usize {
    technique_coverage().len()
}

/// Returns all ATT&CK techniques covered by the catalog as typed structs.
///
/// Each returned [`AttackTechnique`] has `tactic` set to `"unknown"` because
/// the catalog stores technique IDs only, not tactic context. Use
/// [`crate::mitre::lookup_attack_for_rule_name`] or the ATT&CK STIX bundle
/// to resolve tactic context for specific techniques.
pub fn covered_techniques() -> Vec<AttackTechnique> {
    let mut techniques: Vec<&'static str> = technique_coverage().into_keys().collect();
    techniques.sort_unstable();
    techniques
        .into_iter()
        .map(|id| AttackTechnique {
            technique_id: id,
            tactic: "unknown",
            name: id,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigator_layer_is_valid_json_structure() {
        let layer = generate_navigator_layer("test-layer");
        assert!(layer.contains("\"name\": \"test-layer\""));
        assert!(layer.contains("\"domain\": \"enterprise-attack\""));
        assert!(layer.contains("\"techniques\":"));
        assert!(layer.contains("\"techniqueID\":"));
    }

    #[test]
    fn navigator_layer_contains_common_techniques() {
        let layer = generate_navigator_layer("test");
        // T1547 (boot persistence) should definitely be in the catalog
        assert!(
            layer.contains("T1547") || layer.contains("T1059"),
            "Navigator layer should contain common MITRE techniques"
        );
    }

    #[test]
    fn coverage_map_nonempty() {
        let coverage = technique_coverage();
        assert!(
            !coverage.is_empty(),
            "Should have at least some technique coverage"
        );
    }

    #[test]
    fn covered_technique_count_reasonable() {
        let count = covered_technique_count();
        assert!(
            count >= 10,
            "Should cover at least 10 ATT&CK techniques, got {count}"
        );
        assert!(count <= 500, "Technique count seems too high: {count}");
    }

    #[test]
    fn layer_name_is_embedded() {
        let layer = generate_navigator_layer("my-custom-layer");
        assert!(layer.contains("my-custom-layer"));
    }

    #[test]
    fn layer_has_color_coding() {
        let layer = generate_navigator_layer("test");
        assert!(
            layer.contains("\"color\":"),
            "Layer should have color coding"
        );
    }

    #[test]
    fn coverage_artifacts_are_valid_ids() {
        let coverage = technique_coverage();
        for artifact_ids in coverage.values() {
            for id in artifact_ids {
                assert!(
                    CATALOG.by_id(id).is_some(),
                    "coverage map references unknown artifact: {id}",
                );
            }
        }
    }

    // ── Findings → Navigator layer ────────────────────────────────────────

    #[test]
    fn findings_layer_dedups_by_technique_and_takes_max_severity() {
        use crate::report::{Category, Finding, Severity};
        let findings = vec![
            Finding::observation(Severity::Medium, Category::Threat, "MEM-LSASS-ACCESS")
                .mitre("T1003.001")
                .occurrences(2)
                .build(),
            // same technique, higher severity, different code
            Finding::observation(Severity::Critical, Category::Threat, "MEM-CREDENTIAL-DUMP")
                .mitre("T1003.001")
                .build(),
            Finding::observation(Severity::Low, Category::Concealment, "NTFS-TIMESTOMP")
                .mitre("T1070.006")
                .build(),
        ];
        let layer = findings_to_navigator_layer(&findings, "case-001");
        assert!(layer.contains(r#""name": "case-001""#));
        assert!(layer.contains(r#""domain": "enterprise-attack""#));
        // T1003.001 deduped to a single technique entry
        assert_eq!(layer.matches(r#""techniqueID": "T1003.001""#).count(), 1);
        // max severity (Critical) drives the score
        let line = layer
            .lines()
            .find(|l| l.contains("T1003.001"))
            .expect("T1003.001 entry");
        assert!(line.contains(r#""score": 100"#), "got: {line}");
        // both contributing finding codes appear in the comment
        assert!(line.contains("MEM-LSASS-ACCESS") && line.contains("MEM-CREDENTIAL-DUMP"));
        // the second technique is present too
        assert!(layer.contains(r#""techniqueID": "T1070.006""#));
    }

    #[test]
    fn findings_without_mitre_refs_are_excluded() {
        use crate::report::{Category, Finding, Severity};
        let findings =
            vec![
                Finding::observation(Severity::High, Category::Integrity, "MBR-PART-OVERLAP")
                    .build(),
            ];
        let layer = findings_to_navigator_layer(&findings, "x");
        assert!(
            !layer.contains("techniqueID"),
            "no technique entries when findings carry no MITRE refs"
        );
    }

    #[test]
    fn report_to_layer_delegates_to_findings() {
        use crate::report::{Category, Finding, Report, Severity};
        let mut report = Report::default();
        report.findings = vec![Finding::observation(Severity::High, Category::Threat, "X")
            .mitre("T1059")
            .build()];
        let layer = report_to_navigator_layer(&report, "r");
        assert!(layer.contains(r#""techniqueID": "T1059""#));
    }
}
