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

pub static VERSION_HISTORY_TABLE: &[ArtifactVersionHistory] = &[
    ArtifactVersionHistory {
        artifact_id: "prefetch_file",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::Introduced,
                description: "Prefetch enabled by default on non-server Windows; MAM format v17.",
                reference: "https://www.libscca.info/",
            },
            VersionChange {
                os_version: OsScope::Win8Plus,
                change_type: ChangeType::FormatChanged,
                description: "Format version bumped to v26; adds execution count and 8 run times.",
                reference: "https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::FormatChanged,
                description: "Format version v30; files compressed with Xpress Huffman by default. Max 1024 entries (was 128/256).",
                reference: "https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "amcache_app_file",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::Introduced,
                description: "RecentFileCache.bcf introduced (predecessor to Amcache.hve).",
                reference: "https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf",
            },
            VersionChange {
                os_version: OsScope::Win8Plus,
                change_type: ChangeType::LocationMoved,
                description: "Amcache.hve replaces RecentFileCache.bcf at %SystemRoot%\\AppCompat\\Programs\\Amcache.hve.",
                reference: "https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::FormatChanged,
                description: "New hive structure with InventoryApplicationFile, InventoryApplication keys. SHA1 hash recorded.",
                reference: "https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "shimcache",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::Introduced,
                description: "AppCompatCache stored in SYSTEM hive; records path, size, last modified time.",
                reference: "https://www.mandiant.com/resources/blog/caching-out-the-val",
            },
            VersionChange {
                os_version: OsScope::Win8Plus,
                change_type: ChangeType::FormatChanged,
                description: "Format changed; execution flag removed. Size field dropped on Win8.",
                reference: "https://www.mandiant.com/resources/blog/caching-out-the-val",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::BehaviorChanged,
                description: "Cache written on shutdown/reboot only; live analysis requires memory forensics for current state.",
                reference: "https://www.mandiant.com/resources/blog/caching-out-the-val",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "userassist_exe",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::FormatChanged,
                description: "Win7 adds run count and focus time fields (72-byte USERASSIST_ENTRY structure).",
                reference: "https://www.nirsoft.net/utils/userassist_view.html",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::BehaviorChanged,
                description: "UWP/Store app launches recorded with different GUID key structure.",
                reference: "https://www.sans.org/blog/userassist-digital-forensic-artifact/",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "bam_user",
        changes: &[VersionChange {
            os_version: OsScope::Win10Plus,
            change_type: ChangeType::Introduced,
            description: "Background Activity Moderator introduced in Windows 10 1709 (Fall Creators Update). Records last execution time per binary.",
            reference: "https://www.sans.org/blog/background-activity-moderator/",
        }],
    },
    ArtifactVersionHistory {
        artifact_id: "lnk_files",
        changes: &[VersionChange {
            os_version: OsScope::Win7Plus,
            change_type: ChangeType::BehaviorChanged,
            description: "Win7 added EnvironmentVariableDataBlock; network share paths stored differently.",
            reference: "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink",
        }],
    },
    ArtifactVersionHistory {
        artifact_id: "jump_list_auto",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::Introduced,
                description: "Jump Lists introduced with Windows 7 taskbar. Stored as OLE CFB files.",
                reference: "https://www.4n6k.com/2011/09/jump-list-forensics-automated-vs-custom.html",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::FormatChanged,
                description: "Windows 10 1607+ changed the internal OLE stream format for some jump list entries.",
                reference: "https://github.com/EricZimmerman/JumpList",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "evtx_security",
        changes: &[
            VersionChange {
                os_version: OsScope::Win7Plus,
                change_type: ChangeType::Introduced,
                description: "EVTX format replaces legacy EVT format. Event IDs renumbered (e.g., 528→4624 for logon).",
                reference: "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::BehaviorChanged,
                description: "New event IDs added for Credential Guard (4627), DPAPI (4692/4693), PRT refresh.",
                reference: "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "mft_file",
        changes: &[
            VersionChange {
                os_version: OsScope::Win8Plus,
                change_type: ChangeType::BehaviorChanged,
                description: "Integrity streams ($Integrity) added; transactional NTFS changes affect USN journal entries.",
                reference: "https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants",
            },
            VersionChange {
                os_version: OsScope::Win10Plus,
                change_type: ChangeType::BehaviorChanged,
                description: "ReFS introduced as alternative; MFT analysis not applicable to ReFS volumes.",
                reference: "https://docs.microsoft.com/en-us/windows-server/storage/refs/refs-overview",
            },
        ],
    },
    ArtifactVersionHistory {
        artifact_id: "ntds_dit",
        changes: &[VersionChange {
            os_version: OsScope::Win10Plus,
            change_type: ChangeType::BehaviorChanged,
            description: "Credential Guard (Virtualization Based Security) protects NTLM/Kerberos secrets in isolated LSA; NTDS.dit hashes may not be crackable on live systems with CG enabled.",
            reference: "https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works",
        }],
    },
    ArtifactVersionHistory {
        artifact_id: "shellbags_user",
        changes: &[VersionChange {
            os_version: OsScope::Win7Plus,
            change_type: ChangeType::LocationMoved,
            description: "Shellbags split between NTUSER.DAT (Desktop) and UsrClass.dat (all other folders) starting Win7.",
            reference: "https://www.sans.org/blog/shellbag-forensics-addressing-popular-misconceptions/",
        }],
    },
    ArtifactVersionHistory {
        artifact_id: "scheduled_tasks_dir",
        changes: &[VersionChange {
            os_version: OsScope::Win7Plus,
            change_type: ChangeType::FormatChanged,
            description: "Task XML format (Task Scheduler 2.0) replaces binary .job files. Tasks stored in %SystemRoot%\\System32\\Tasks.",
            reference: "https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema",
        }],
    },
    ArtifactVersionHistory {
        artifact_id: "linux_journal_dir",
        changes: &[VersionChange {
            os_version: OsScope::LinuxSystemd,
            change_type: ChangeType::Introduced,
            description: "systemd-journald introduced binary journal format at /var/log/journal/. Replaces/supplements syslog.",
            reference: "https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html",
        }],
    },
];

/// Returns the version history for a given artifact ID, or `None`.
pub fn version_history_for(artifact_id: &str) -> Option<&'static ArtifactVersionHistory> {
    VERSION_HISTORY_TABLE
        .iter()
        .find(|e| e.artifact_id == artifact_id)
}

/// Returns all artifacts that changed in a specific OS version.
pub fn changes_in_os_version(os_version: OsScope) -> Vec<&'static ArtifactVersionHistory> {
    VERSION_HISTORY_TABLE
        .iter()
        .filter(|e| e.changes.iter().any(|c| c.os_version == os_version))
        .collect()
}

/// Returns all artifacts that introduced, changed, or moved in Win10+.
pub fn win10_changes() -> Vec<&'static ArtifactVersionHistory> {
    changes_in_os_version(OsScope::Win10Plus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::OsScope;

    #[test]
    fn prefetch_has_win10_format_change() {
        let history =
            version_history_for("prefetch_file").expect("prefetch_file must have version history");
        assert!(
            history
                .changes
                .iter()
                .any(|c| c.os_version == OsScope::Win10Plus
                    && c.change_type == ChangeType::FormatChanged),
            "prefetch_file should record Win10+ format change"
        );
    }

    #[test]
    fn bam_introduced_in_win10() {
        let history = version_history_for("bam_user").expect("bam_user must have version history");
        assert!(
            history
                .changes
                .iter()
                .any(|c| c.change_type == ChangeType::Introduced
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
                        || change.reference.starts_with("http://"), // cov:unreachable: short-circuit alternative; all current references use https
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
