//! Chainsaw / Hayabusa EVTX detection rule mapping.
//!
//! Maps catalog artifacts to detection rules used by the
//! [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and
//! [Hayabusa](https://github.com/Yamato-Security/hayabusa) hunt tools.

/// Which hunt tool a rule bundle belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum HuntTool {
    /// WithSecure Chainsaw (<https://github.com/WithSecureLabs/chainsaw>).
    Chainsaw,
    /// Yamato Security Hayabusa (<https://github.com/Yamato-Security/hayabusa>).
    Hayabusa,
    /// Compatible with both tools (standard Sigma rule).
    Both,
}

/// Reference to a Chainsaw or Hayabusa detection rule for a catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HuntRuleRef {
    /// Catalog artifact ID this rule targets.
    pub artifact_id: &'static str,
    /// Tool the rule targets.
    pub tool: HuntTool,
    /// Rule name / title.
    pub rule_title: &'static str,
    /// Rule category (maps to the event log channel, e.g. `"Security"`, `"System"`).
    pub log_channel: &'static str,
    /// MITRE ATT&CK techniques detected.
    pub mitre_techniques: &'static [&'static str],
}

/// All Chainsaw / Hayabusa hunt rule references known to the catalog.
///
/// Sources:
/// - Chainsaw rule pack: <https://github.com/WithSecureLabs/chainsaw/tree/master/rules>
/// - Hayabusa rules: <https://github.com/Yamato-Security/hayabusa-rules>
/// - SigmaHQ (rules compatible with both tools): <https://github.com/SigmaHQ/sigma>
pub static HUNT_RULE_TABLE: &[HuntRuleRef] = &[];

/// Return all hunt rule references for a catalog artifact.
pub fn hunt_rules_for(_artifact_id: &str) -> Vec<&'static HuntRuleRef> {
    todo!()
}

/// Return all artifact IDs that have hunt rule coverage.
///
/// The returned list is sorted and deduplicated.
pub fn covered_artifact_ids() -> Vec<&'static str> {
    todo!()
}

/// Return all rules for a specific tool.
///
/// Rules with [`HuntTool::Both`] are included for every tool variant.
pub fn rules_for_tool(_tool: HuntTool) -> Vec<&'static HuntRuleRef> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_nonempty() {
        assert!(!HUNT_RULE_TABLE.is_empty());
    }

    #[test]
    fn evtx_security_has_hunt_rules() {
        let rules = hunt_rules_for("evtx_security");
        assert!(!rules.is_empty());
    }

    #[test]
    fn unknown_artifact_returns_empty() {
        assert!(hunt_rules_for("this_does_not_exist").is_empty());
    }

    #[test]
    fn covered_artifacts_nonempty() {
        let ids = covered_artifact_ids();
        assert!(ids.len() >= 5);
    }

    #[test]
    fn chainsaw_rules_exist() {
        let rules = rules_for_tool(HuntTool::Chainsaw);
        assert!(!rules.is_empty());
    }

    #[test]
    fn hayabusa_rules_exist() {
        let rules = rules_for_tool(HuntTool::Hayabusa);
        assert!(!rules.is_empty());
    }

    #[test]
    fn all_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for r in HUNT_RULE_TABLE {
            assert!(
                ids.contains(r.artifact_id),
                "Unknown artifact_id: {}",
                r.artifact_id
            );
        }
    }
}
