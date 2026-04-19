//! Artifact volatility model — RFC 3227 Order of Volatility encoded as data.
//!
//! Maps each catalog artifact to a [`VolatilityClass`], enabling tools to
//! sort collection order from most-volatile to least-volatile.

/// How quickly an artifact is overwritten or lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VolatilityClass {
    /// Survives deletion (journal, shadow copies, slack space).
    Residual = 0,
    /// Persistent until explicit deletion (registry keys, most files).
    Persistent = 1,
    /// Overwritten by user activity (MRU, recent docs, browser history).
    ActivityDriven = 2,
    /// Overwritten on rotation (event logs, prefetch circular buffer).
    RotatingBuffer = 3,
    /// Lost on reboot (RAM contents, process handles, network state).
    Volatile = 4,
}

/// Volatility entry for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VolatilityEntry {
    /// Catalog artifact ID.
    pub artifact_id: &'static str,
    pub volatility: VolatilityClass,
    /// One-line rationale for this classification.
    pub rationale: &'static str,
}

/// Volatility table for all catalog artifacts.
/// Sorted by artifact_id for determinism.
pub static VOLATILITY_TABLE: &[VolatilityEntry] = &[
    // ── Execution artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "amcache_app_file",
        volatility: VolatilityClass::Persistent,
        rationale: "Persists until Windows Update or manual clear",
    },
    VolatilityEntry {
        artifact_id: "bam_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated by OS on background activity manager flush",
    },
    VolatilityEntry {
        artifact_id: "dam_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated by OS on desktop activity monitor flush",
    },
    VolatilityEntry {
        artifact_id: "prefetch_file",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Max 1024 entries, FIFO eviction on Win10+",
    },
    VolatilityEntry {
        artifact_id: "shimcache",
        volatility: VolatilityClass::Volatile,
        rationale: "Written to registry only on shutdown; live state is in memory",
    },
    VolatilityEntry {
        artifact_id: "userassist_exe",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated per user GUI interaction; persists in NTUSER.DAT",
    },
    // ── Persistence artifacts ────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "active_setup_hklm",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "appinit_dlls",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "boot_execute",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "com_hijack_clsid_hkcu",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key per-user; persists in NTUSER.DAT",
    },
    VolatilityEntry {
        artifact_id: "ifeo_debugger",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "run_key_hkcu",
        volatility: VolatilityClass::Persistent,
        rationale: "Per-user registry key; persists in NTUSER.DAT",
    },
    VolatilityEntry {
        artifact_id: "run_key_hklm",
        volatility: VolatilityClass::Persistent,
        rationale: "System registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "run_key_hklm_once",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Deleted by OS after single execution",
    },
    VolatilityEntry {
        artifact_id: "scheduled_tasks_dir",
        volatility: VolatilityClass::Persistent,
        rationale: "XML files in tasks directory; persist until task deleted",
    },
    VolatilityEntry {
        artifact_id: "services_imagepath",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key under SYSTEM; persists until service removed",
    },
    VolatilityEntry {
        artifact_id: "winlogon_shell",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    // ── Credential artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "chrome_login_data",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "dcc2_cache",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated; last 10 cached credentials by default",
    },
    VolatilityEntry {
        artifact_id: "dpapi_cred_user",
        volatility: VolatilityClass::Persistent,
        rationale: "Encrypted credential blobs; persist until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "dpapi_masterkey_user",
        volatility: VolatilityClass::Persistent,
        rationale: "Master keys persist; old keys backed up in AD",
    },
    VolatilityEntry {
        artifact_id: "dpapi_system_masterkey",
        volatility: VolatilityClass::Persistent,
        rationale: "System DPAPI master key; persists in SYSTEM hive",
    },
    VolatilityEntry {
        artifact_id: "firefox_logins",
        volatility: VolatilityClass::Persistent,
        rationale: "JSON file; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "lsa_secrets",
        volatility: VolatilityClass::Persistent,
        rationale: "System hive registry; persists until credential removed",
    },
    VolatilityEntry {
        artifact_id: "ntds_dit",
        volatility: VolatilityClass::Persistent,
        rationale: "AD database; persists until account deleted",
    },
    VolatilityEntry {
        artifact_id: "sam_users",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM registry hive; persists until account deleted",
    },
    // ── Filesystem artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "jump_list_auto",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated on file access; max entries per app",
    },
    VolatilityEntry {
        artifact_id: "jump_list_custom",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Pinned by user; persists until app unpins",
    },
    VolatilityEntry {
        artifact_id: "lnk_files",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Created on file open; max ~150 recent items",
    },
    VolatilityEntry {
        artifact_id: "mft_file",
        volatility: VolatilityClass::Residual,
        rationale: "Metadata persists in unallocated MFT entries after deletion",
    },
    VolatilityEntry {
        artifact_id: "mru_recent_docs",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated per file open; fixed max MRU depth",
    },
    VolatilityEntry {
        artifact_id: "recycle_bin",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Deleted on permanent delete; survives recycle until purge",
    },
    VolatilityEntry {
        artifact_id: "shellbags_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated on folder access; persists in UsrClass.dat",
    },
    VolatilityEntry {
        artifact_id: "usn_journal",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular journal; oldest entries overwritten first",
    },
    // ── SRUM / telemetry artifacts ───────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "srum_app_resource",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM ESE database; rotated by Windows on schedule",
    },
    VolatilityEntry {
        artifact_id: "srum_db",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM ESE database; records rolled up and purged periodically",
    },
    VolatilityEntry {
        artifact_id: "srum_network_usage",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM network table; rotated by Windows on schedule",
    },
    // ── Network artifacts ────────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "network_drives",
        volatility: VolatilityClass::Persistent,
        rationale: "Mapped drive registry entry; persists until unmapped",
    },
    VolatilityEntry {
        artifact_id: "networklist_profiles",
        volatility: VolatilityClass::Persistent,
        rationale: "Network profiles persist in registry",
    },
    VolatilityEntry {
        artifact_id: "rdp_client_servers",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "MRU; rotated when max entries exceeded",
    },
    VolatilityEntry {
        artifact_id: "wifi_profiles",
        volatility: VolatilityClass::Persistent,
        rationale: "WiFi profiles persist in registry until deleted",
    },
    // ── Event log artifacts ──────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "evtx_powershell",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; oldest events overwritten at max size",
    },
    VolatilityEntry {
        artifact_id: "evtx_security",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; default 128 MB max",
    },
    VolatilityEntry {
        artifact_id: "evtx_sysmon",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; size depends on Sysmon config",
    },
    VolatilityEntry {
        artifact_id: "evtx_system",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; default 20 MB max",
    },
    // ── Linux artifacts ──────────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "linux_auth_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "logrotate weekly by default",
    },
    VolatilityEntry {
        artifact_id: "linux_bash_history",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Written at shell exit; max HISTSIZE entries",
    },
    VolatilityEntry {
        artifact_id: "linux_chrome_login_linux",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "linux_firefox_logins_linux",
        volatility: VolatilityClass::Persistent,
        rationale: "JSON file; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "linux_gnome_keyring",
        volatility: VolatilityClass::Persistent,
        rationale: "Keyring database file; persists until secrets removed",
    },
    VolatilityEntry {
        artifact_id: "linux_kde_kwallet",
        volatility: VolatilityClass::Persistent,
        rationale: "KWallet database file; persists until secrets removed",
    },
    VolatilityEntry {
        artifact_id: "linux_passwd",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until account deleted",
    },
    VolatilityEntry {
        artifact_id: "linux_shadow",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until account deleted or password changed",
    },
    VolatilityEntry {
        artifact_id: "linux_ssh_private_key",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "linux_sudoers_d",
        volatility: VolatilityClass::Persistent,
        rationale: "Files in /etc/sudoers.d/; persist until explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "linux_journal_dir",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "systemd journal; rotated by journald size/time limits",
    },
    VolatilityEntry {
        artifact_id: "linux_user_crontab",
        volatility: VolatilityClass::Persistent,
        rationale: "Crontab entry; persists until crontab -r",
    },
    VolatilityEntry {
        artifact_id: "linux_wtmp",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Rotated by logrotate",
    },
];

/// Returns the volatility entry for a given artifact ID, or `None` if unknown.
pub fn volatility_for(artifact_id: &str) -> Option<&'static VolatilityEntry> {
    VOLATILITY_TABLE
        .iter()
        .find(|e| e.artifact_id == artifact_id)
}

/// Returns all artifacts sorted most-volatile-first (Volatile → Residual).
/// Ties broken by artifact ID for determinism.
pub fn acquisition_order() -> Vec<&'static VolatilityEntry> {
    let mut entries: Vec<&VolatilityEntry> = VOLATILITY_TABLE.iter().collect();
    entries.sort_by(|a, b| {
        b.volatility
            .cmp(&a.volatility)
            .then(a.artifact_id.cmp(b.artifact_id))
    });
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn shimcache_is_volatile() {
        let entry = volatility_for("shimcache").expect("shimcache should be in table");
        assert_eq!(entry.volatility, VolatilityClass::Volatile);
    }

    #[test]
    fn mft_is_residual() {
        let entry = volatility_for("mft_file").expect("mft_file should be in table");
        assert_eq!(entry.volatility, VolatilityClass::Residual);
    }

    #[test]
    fn evtx_security_is_rotating_buffer() {
        let entry = volatility_for("evtx_security").expect("evtx_security should be in table");
        assert_eq!(entry.volatility, VolatilityClass::RotatingBuffer);
    }

    #[test]
    fn acquisition_order_volatile_first() {
        let order = acquisition_order();
        assert!(!order.is_empty());
        // First entry must be the most volatile
        assert_eq!(
            order[0].volatility,
            VolatilityClass::Volatile,
            "acquisition_order should start with Volatile class"
        );
        // Last entry must be Residual
        assert_eq!(
            order.last().unwrap().volatility,
            VolatilityClass::Residual,
            "acquisition_order should end with Residual class"
        );
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(volatility_for("this_does_not_exist").is_none());
    }

    #[test]
    fn table_covers_critical_triage_artifacts() {
        // All Critical triage artifacts should be in the volatility table
        let missing: Vec<&str> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == crate::catalog::TriagePriority::Critical)
            .filter(|d| volatility_for(d.id).is_none())
            .map(|d| d.id)
            .collect();
        assert!(
            missing.is_empty(),
            "Critical-priority artifacts missing from volatility table: {missing:?}"
        );
    }

    #[test]
    fn all_table_artifact_ids_exist_in_catalog() {
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for entry in VOLATILITY_TABLE {
            assert!(
                catalog_ids.contains(entry.artifact_id),
                "volatility table references unknown catalog id: {}",
                entry.artifact_id
            );
        }
    }

    #[test]
    fn volatility_ordering_is_consistent() {
        // Volatile > RotatingBuffer > ActivityDriven > Persistent > Residual
        assert!(VolatilityClass::Volatile > VolatilityClass::RotatingBuffer);
        assert!(VolatilityClass::RotatingBuffer > VolatilityClass::ActivityDriven);
        assert!(VolatilityClass::ActivityDriven > VolatilityClass::Persistent);
        assert!(VolatilityClass::Persistent > VolatilityClass::Residual);
    }
}
