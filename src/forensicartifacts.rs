//! ForensicArtifacts.com YAML interop.
//!
//! Provides a static mapping table from catalog artifact IDs to their
//! [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) definition
//! names, and a serialization helper that produces minimal FA-compatible YAML
//! strings without any external YAML library dependency.

/// Mapping from a catalog artifact to its ForensicArtifacts.com definition name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ForensicArtifactsRef {
    /// Catalog artifact ID.
    pub artifact_id: &'static str,
    /// ForensicArtifacts definition name (e.g. "WindowsPrefetch").
    pub fa_name: &'static str,
    /// ForensicArtifacts source type (e.g. "FILE", "REGISTRY_KEY").
    pub source_type: &'static str,
}

/// Static mapping table from catalog artifact IDs to ForensicArtifacts definitions.
///
/// Definition names sourced from
/// <https://github.com/ForensicArtifacts/artifacts/tree/main/data>.
pub static FA_TABLE: &[ForensicArtifactsRef] = &[
    ForensicArtifactsRef {
        artifact_id: "prefetch_dir",
        fa_name: "WindowsPrefetch",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "evtx_security",
        fa_name: "WindowsEventLogs",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "evtx_system",
        fa_name: "WindowsEventLogs",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "amcache_app_file",
        fa_name: "WindowsAmcache",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "shimcache",
        fa_name: "WindowsAppCompatCache",
        source_type: "REGISTRY_KEY",
    },
    ForensicArtifactsRef {
        artifact_id: "userassist_exe",
        fa_name: "WindowsUserAssist",
        source_type: "REGISTRY_KEY",
    },
    ForensicArtifactsRef {
        artifact_id: "lnk_files",
        fa_name: "WindowsRecentFiles",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "mft_file",
        fa_name: "WindowsNTFSMFT",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "ntds_dit",
        fa_name: "WindowsNTDSDatabase",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "sam_users",
        fa_name: "WindowsSAMDatabase",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "run_key_hklm",
        fa_name: "WindowsRunKeys",
        source_type: "REGISTRY_KEY",
    },
    ForensicArtifactsRef {
        artifact_id: "scheduled_tasks_dir",
        fa_name: "WindowsScheduledTasks",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "linux_bash_history",
        fa_name: "LinuxShellHistoryFile",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "linux_passwd",
        fa_name: "UnixPasswd",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "linux_auth_log",
        fa_name: "LinuxAuthLog",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "macos_launch_agents_user",
        fa_name: "MacOSLaunchAgentsPlistFiles",
        source_type: "FILE",
    },
    ForensicArtifactsRef {
        artifact_id: "macos_launch_daemons",
        fa_name: "MacOSLaunchDaemonsPlistFiles",
        source_type: "FILE",
    },
];

/// Find the ForensicArtifacts mapping for a catalog artifact.
pub fn fa_ref_for(artifact_id: &str) -> Option<&'static ForensicArtifactsRef> {
    FA_TABLE.iter().find(|r| r.artifact_id == artifact_id)
}

/// Generate a minimal ForensicArtifacts-compatible YAML string for an artifact.
///
/// Returns `None` if the artifact is not in the catalog or has no FA mapping.
///
/// The YAML output follows the ForensicArtifacts definition format:
/// ```yaml
/// name: WindowsPrefetch
/// doc: Windows Prefetch files.
/// sources:
/// - type: FILE
///   attributes:
///     paths:
///     - '%%environ_systemroot%%\Prefetch\*.pf'
/// labels:
/// - forensic_artifact
/// urls:
/// - https://forensicartifacts.com/
/// ```
///
/// The path field is populated from the catalog artifact's `file_path` (preferred)
/// or `key_path` for registry artifacts.
pub fn to_fa_yaml(artifact_id: &str) -> Option<String> {
    use crate::catalog::CATALOG;

    let fa_ref = fa_ref_for(artifact_id)?;
    let desc = CATALOG.by_id(artifact_id)?;

    // Prefer file_path; fall back to key_path for registry artifacts.
    let path = desc
        .file_path
        .map_or_else(|| desc.key_path.to_string(), str::to_string);

    Some(format!(
        "name: {fa_name}\ndoc: {doc}.\nsources:\n- type: {source_type}\n  attributes:\n    paths:\n    - '{path}'\nlabels:\n- forensic_artifact\nurls:\n- https://forensicartifacts.com/\n",
        fa_name = fa_ref.fa_name,
        doc = desc.name,
        source_type = fa_ref.source_type,
        path = path,
    ))
}

/// List all catalog artifact IDs that have ForensicArtifacts mappings.
pub fn mapped_artifact_ids() -> Vec<&'static str> {
    FA_TABLE.iter().map(|r| r.artifact_id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_nonempty() {
        assert!(!FA_TABLE.is_empty());
    }

    #[test]
    fn prefetch_has_fa_ref() {
        let r = fa_ref_for("prefetch_dir").expect("prefetch_dir should have FA ref");
        assert_eq!(r.fa_name, "WindowsPrefetch");
    }

    #[test]
    fn unknown_returns_none() {
        assert!(fa_ref_for("nonexistent").is_none());
    }

    #[test]
    fn to_fa_yaml_produces_valid_structure() {
        let yaml = to_fa_yaml("prefetch_dir").expect("should produce YAML");
        assert!(yaml.contains("name:"), "YAML should contain name field");
        assert!(
            yaml.contains("doc:") || yaml.contains("sources:"),
            "YAML should have doc or sources"
        );
    }

    #[test]
    fn mapped_ids_nonempty() {
        let ids = mapped_artifact_ids();
        assert!(ids.len() >= 10);
    }

    #[test]
    fn all_fa_artifact_ids_valid() {
        use crate::catalog::CATALOG;
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for r in FA_TABLE {
            assert!(
                catalog_ids.contains(r.artifact_id),
                "Unknown artifact_id: {}",
                r.artifact_id
            );
        }
    }
}
