//! OS version artifact change tracking.
//!
//! Documents how forensic artifacts have changed across OS versions —
//! format changes, location moves, introductions, and deprecations.
//! Helps analysts apply the right parsing logic for the target OS version.

use crate::catalog::OsScope;

/// How an artifact changed between OS versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChangeType {
    /// Artifact first appeared in this OS version.
    Introduced,
    /// Binary format changed (requires different parser).
    FormatChanged,
    /// File or registry path moved.
    LocationMoved,
    /// Artifact no longer produced by default.
    Deprecated,
    /// Artifact completely removed.
    Removed,
    /// Behavior or semantics changed without format change.
    BehaviorChanged,
}

/// One version-specific change to a forensic artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VersionChange {
    /// The OS version where this change took effect.
    pub os_version: OsScope,
    pub change_type: ChangeType,
    /// Human-readable description of what changed and its forensic impact.
    pub description: &'static str,
    /// Authoritative reference URL documenting the change.
    pub reference: &'static str,
}

/// Complete version history for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ArtifactVersionHistory {
    pub artifact_id: &'static str,
    pub changes: &'static [VersionChange],
}

pub static VERSION_HISTORY_TABLE: &[ArtifactVersionHistory] = &[];

/// Returns the version history for a given artifact ID, or None.
pub fn version_history_for(_artifact_id: &str) -> Option<&'static ArtifactVersionHistory> {
    todo!("implement version_history_for")
}

/// Returns all artifacts that changed in a specific OS version.
pub fn changes_in_os_version(_os_version: OsScope) -> Vec<&'static ArtifactVersionHistory> {
    todo!("implement changes_in_os_version")
}

/// Returns all artifacts that introduced, changed, or moved in Win10+.
pub fn win10_changes() -> Vec<&'static ArtifactVersionHistory> {
    todo!("implement win10_changes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::OsScope;

    #[test]
    fn prefetch_has_win10_format_change() {
        let history = version_history_for("prefetch_file")
            .expect("prefetch_file must have version history");
        assert!(
            history.changes.iter().any(|c| c.os_version == OsScope::Win10Plus
                && c.change_type == ChangeType::FormatChanged),
            "prefetch_file should record Win10+ format change"
        );
    }

    #[test]
    fn bam_introduced_in_win10() {
        let history = version_history_for("bam_user").expect("bam_user must have version history");
        assert!(
            history.changes.iter().any(|c| c.change_type == ChangeType::Introduced
                && c.os_version == OsScope::Win10Plus),
            "bam_user should be introduced in Win10+"
        );
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(version_history_for("nonexistent_xyz").is_none());
    }

    #[test]
    fn win10_changes_returns_nonempty() {
        let changes = win10_changes();
        assert!(!changes.is_empty(), "Should have Win10+ changes");
        assert!(changes
            .iter()
            .all(|h| h.changes.iter().any(|c| c.os_version == OsScope::Win10Plus)));
    }

    #[test]
    fn all_changes_have_references() {
        for history in VERSION_HISTORY_TABLE {
            for change in history.changes {
                assert!(
                    change.reference.starts_with("https://")
                        || change.reference.starts_with("http://"),
                    "artifact '{}' has change without a valid URL reference",
                    history.artifact_id
                );
                assert!(
                    !change.description.is_empty(),
                    "artifact '{}' has change with empty description",
                    history.artifact_id
                );
            }
        }
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        use crate::catalog::CATALOG;
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.for_triage().into_iter().map(|d| d.id).collect();
        for entry in VERSION_HISTORY_TABLE {
            assert!(
                catalog_ids.contains(entry.artifact_id),
                "version history references unknown catalog id: {}",
                entry.artifact_id
            );
        }
    }

    #[test]
    fn changes_have_correct_os_version_types() {
        for history in VERSION_HISTORY_TABLE {
            for change in history.changes {
                if change.change_type == ChangeType::Introduced {
                    assert!(
                        change.description.len() > 20,
                        "Introduced change for '{}' has too-short description",
                        history.artifact_id
                    );
                }
            }
        }
    }
}
