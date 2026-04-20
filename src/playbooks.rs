//! Investigation playbook engine.
//!
//! Provides directed investigation paths: given a trigger artifact or MITRE
//! technique, what artifacts to examine next, in what order, and why.

/// One step in an investigation playbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InvestigationStep {
    /// Catalog artifact ID to examine.
    pub artifact_id: &'static str,
    /// Why this step matters in context.
    pub rationale: &'static str,
    /// What specific indicators or values to look for.
    pub look_for: &'static str,
    /// Artifact IDs that become relevant if this step yields results.
    pub unlocks: &'static [&'static str],
}

/// A directed investigation path for a specific scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InvestigationPath {
    /// Unique playbook identifier.
    pub id: &'static str,
    /// What triggers this path (artifact ID or MITRE technique).
    pub trigger: &'static str,
    /// Human-readable scenario name.
    pub name: &'static str,
    /// Ordered investigation steps.
    pub steps: &'static [InvestigationStep],
    /// ATT&CK tactics this path covers.
    pub tactics_covered: &'static [&'static str],
    /// Brief description of the scenario.
    pub description: &'static str,
}

pub static PLAYBOOKS: &[InvestigationPath] = &[];

/// Returns the playbook with the given ID.
pub fn playbook_by_id(_id: &str) -> Option<&'static InvestigationPath> {
    todo!()
}

/// Returns all playbooks whose trigger matches the given artifact ID or MITRE technique.
pub fn playbooks_for_trigger(_trigger: &str) -> Vec<&'static InvestigationPath> {
    todo!()
}

/// Returns all playbooks that reference the given artifact ID in any step.
pub fn playbooks_for_artifact(_artifact_id: &str) -> Vec<&'static InvestigationPath> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn six_playbooks_defined() {
        assert_eq!(PLAYBOOKS.len(), 6, "Expected 6 playbooks");
    }

    #[test]
    fn playbook_by_id_works() {
        let pb = playbook_by_id("lateral_movement_rdp")
            .expect("lateral_movement_rdp playbook must exist");
        assert!(!pb.steps.is_empty());
        assert!(!pb.tactics_covered.is_empty());
    }

    #[test]
    fn playbooks_for_trigger_rdp() {
        let pbs = playbooks_for_trigger("rdp_client_servers");
        assert!(!pbs.is_empty(), "Should find playbooks triggered by rdp_client_servers");
    }

    #[test]
    fn playbooks_for_artifact_evtx_security() {
        let pbs = playbooks_for_artifact("evtx_security");
        assert!(pbs.len() >= 2, "evtx_security should appear in multiple playbooks");
    }

    #[test]
    fn all_step_artifact_ids_exist_in_catalog() {
        for pb in PLAYBOOKS {
            for step in pb.steps {
                assert!(
                    CATALOG.by_id(step.artifact_id).is_some(),
                    "playbook '{}' step references unknown artifact: {}",
                    pb.id,
                    step.artifact_id
                );
            }
        }
    }

    #[test]
    fn all_unlocks_reference_valid_artifacts() {
        for pb in PLAYBOOKS {
            for step in pb.steps {
                for unlocked_id in step.unlocks {
                    assert!(
                        CATALOG.by_id(unlocked_id).is_some(),
                        "playbook '{}' step '{}' unlocks unknown artifact: {}",
                        pb.id,
                        step.artifact_id,
                        unlocked_id
                    );
                }
            }
        }
    }

    #[test]
    fn all_playbooks_have_nonempty_steps_and_tactics() {
        for pb in PLAYBOOKS {
            assert!(!pb.steps.is_empty(), "Playbook '{}' has no steps", pb.id);
            assert!(!pb.tactics_covered.is_empty(), "Playbook '{}' has no tactics", pb.id);
            assert!(!pb.description.is_empty(), "Playbook '{}' has no description", pb.id);
        }
    }

    #[test]
    fn unknown_playbook_returns_none() {
        assert!(playbook_by_id("does_not_exist").is_none());
    }
}
