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
}
