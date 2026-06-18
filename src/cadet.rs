//! **CADET** — *Categories of Activity in Digital Evidence Taxonomy*.
//!
//! The forensic-semantic axis: *what evidence means*, independent of which
//! artifact/source recorded it. Many artifacts answer one category (login ←
//! `auth.log` + `wtmp` + EVTX 4624; device-install ← `setupapi.dev.log` +
//! registry `USBSTOR` + EVTX). This is forensic knowledge, so it lives in
//! `forensicnomicon`; correlation and reporting group timeline events by
//! [`ActivityCategory`] across sources, while the *routing* type (which parser
//! reads a file) is a consumer concern.
//!
//! The brand is **CADET** (the citable framework handle); the Rust type is
//! [`ActivityCategory`] (reads in code) — mirroring how **ATT&CK** (brand)
//! pairs with [`crate::mitre::AttackTechnique`] (type).
//!
//! **Grounding (not invented):** this vocabulary is a synthesis of established
//! DFIR taxonomies, with a stable [`ActivityCategory::code`] per variant and an
//! ATT&CK-tactic mapping where the activity is inherently adversarial:
//! - **SANS "Evidence of…"** (FOR500) — the practitioner analysis-question set
//!   (Program Execution, File/Folder Opening, USB Usage, Account/Logon Usage,
//!   Browser Usage, Geolocation, Cloud Storage).
//! - **Plaso/log2timeline tags** (`tag_linux.txt`/`tag_windows.txt`) — the
//!   cross-platform super-timeline precedent (`application_execution`, `login`…).
//! - **MITRE ATT&CK** tactics — for the adversarial overlap (see
//!   [`ActivityCategory::attack_tactic`]).
//! - **CASE/UCO** is the eventual *export/interchange* target (a different,
//!   serialization layer); [`ActivityCategory::code`] is the stable key a future
//!   CASE/UCO exporter maps to UCO `Action`/`Observable` concepts.
//!
//! Note: categories describe *observed* activity, not *inferred* intent —
//! e.g. [`ActivityCategory::FileSystemActivity`] is kept unified rather than
//! split into SANS's interpretive "opening vs download vs deletion" buckets,
//! which are an analyst inference layered on top of the same filesystem evidence.
//!
//! Complements [`crate::report::Category`] (the analysis-lens axis —
//! Integrity/Structure/Threat/…); this is the activity/behavior axis.

/// A CADET category — the forensic-semantic category of a timeline event,
/// *what happened*, independent of the source artifact that recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ActivityCategory {
    /// Program / process execution. *(SANS: Program Execution; Plaso:
    /// `application_execution`; ATT&CK: TA0002.)* Prefetch, Amcache, BAM,
    /// UserAssist, Shimcache, SRUM app usage, process lists.
    Execution,
    /// Autostart / persistence mechanisms. *(ATT&CK: TA0003.)* Run keys, COM
    /// hijacks, services, startup folders.
    Persistence,
    /// Scheduled / recurring task definitions. *(Plaso; ATT&CK technique
    /// T1053.)* cron, at, Task Scheduler.
    ScheduledTask,
    /// Logon / logoff / authentication. *(SANS: Account/Logon Usage; Plaso:
    /// `login`.)* auth.log, wtmp/btmp, EVTX 4624/4625, sudo.
    LoginActivity,
    /// File / folder access, transfer, and filesystem metadata — kept **unified**
    /// (observed activity, not inferred intent). *(SANS: File/Folder Opening +
    /// File Download + Deleted File/File Knowledge.)* LNK, jump lists, shellbags,
    /// RecentDocs/OpenSaveMRU, `$MFT`, `$UsnJrnl`, bodyfile.
    FileSystemActivity,
    /// Device / driver / removable-media install & usage. *(SANS: External
    /// Device / USB Usage.)* setupapi.dev.log, registry USBSTOR/MountedDevices,
    /// EVTX plug-and-play.
    DeviceInstall,
    /// Network connections / configuration. *(SANS: Network Activity.)* network
    /// state, SRUM network usage.
    NetworkActivity,
    /// Web browsing. *(SANS: Browser Usage.)* history, typed URLs, downloads,
    /// session recovery.
    BrowserActivity,
    /// Host state / configuration / general system logs & inventory. syslog,
    /// macOS unified log, system info, generic registry config.
    SystemState,
    /// User / group account & credential artifacts. *(ATT&CK: TA0006 Credential
    /// Access.)* SAM, LSA secrets, `/etc/passwd`.
    AccountActivity,
    /// Installed-package inventory. dpkg, rpm, pip.
    PackageInventory,
    /// Anti-forensics / concealment. *(ATT&CK: TA0005 Defense Evasion, Indicator
    /// Removal T1070.)* log clearing, rootkit scan results, timestomping.
    AntiForensics,
    /// Direct user-interaction artifacts. Biome App.MenuItem, recent items, MRUs.
    UserActivity,
    /// Integrity / verification artifacts. hash manifests, assessments.
    Integrity,
    /// Geolocation evidence. *(SANS: Geolocation.)* Wi-Fi/network geo, EXIF GPS,
    /// timezone, map app caches.
    Geolocation,
    /// Cloud-storage sync artifacts. *(SANS: Cloud Storage.)* OneDrive, Google
    /// Drive, Box, Dropbox metadata.
    CloudStorage,
}

impl ActivityCategory {
    /// Stable kebab-case identifier — the published contract for persistence and
    /// the eventual CASE/UCO export mapping. **Never change a shipped code.**
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Persistence => "persistence",
            Self::ScheduledTask => "scheduled-task",
            Self::LoginActivity => "login-activity",
            Self::FileSystemActivity => "filesystem-activity",
            Self::DeviceInstall => "device-install",
            Self::NetworkActivity => "network-activity",
            Self::BrowserActivity => "browser-activity",
            Self::SystemState => "system-state",
            Self::AccountActivity => "account-activity",
            Self::PackageInventory => "package-inventory",
            Self::AntiForensics => "anti-forensics",
            Self::UserActivity => "user-activity",
            Self::Integrity => "integrity",
            Self::Geolocation => "geolocation",
            Self::CloudStorage => "cloud-storage",
        }
    }

    /// Inverse of [`Self::code`] — reconstruct from the stable identifier
    /// (deserialization / round-trip). `None` for an unrecognized code.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "execution" => Self::Execution,
            "persistence" => Self::Persistence,
            "scheduled-task" => Self::ScheduledTask,
            "login-activity" => Self::LoginActivity,
            "filesystem-activity" => Self::FileSystemActivity,
            "device-install" => Self::DeviceInstall,
            "network-activity" => Self::NetworkActivity,
            "browser-activity" => Self::BrowserActivity,
            "system-state" => Self::SystemState,
            "account-activity" => Self::AccountActivity,
            "package-inventory" => Self::PackageInventory,
            "anti-forensics" => Self::AntiForensics,
            "user-activity" => Self::UserActivity,
            "integrity" => Self::Integrity,
            "geolocation" => Self::Geolocation,
            "cloud-storage" => Self::CloudStorage,
            _ => return None,
        })
    }

    /// The MITRE ATT&CK **tactic** ID this category maps to, when the activity is
    /// inherently adversarial — `None` for the benign/forensic-only categories
    /// (most timeline activity is not, by itself, an ATT&CK tactic). This is the
    /// alignment with forensicnomicon's existing ATT&CK knowledge, not a
    /// reinvention of it.
    #[must_use]
    pub fn attack_tactic(self) -> Option<&'static str> {
        match self {
            Self::Execution => Some("TA0002"),       // Execution
            Self::Persistence => Some("TA0003"),     // Persistence
            Self::AccountActivity => Some("TA0006"), // Credential Access
            Self::AntiForensics => Some("TA0005"),   // Defense Evasion
            _ => None,
        }
    }
}

impl core::fmt::Display for ActivityCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::ScheduledTask => "Scheduled Task",
            Self::LoginActivity => "Login Activity",
            Self::FileSystemActivity => "File System Activity",
            Self::DeviceInstall => "Device Install",
            Self::NetworkActivity => "Network Activity",
            Self::BrowserActivity => "Browser Activity",
            Self::SystemState => "System State",
            Self::AccountActivity => "Account Activity",
            Self::PackageInventory => "Package Inventory",
            Self::AntiForensics => "Anti-Forensics",
            Self::UserActivity => "User Activity",
            Self::Integrity => "Integrity",
            Self::Geolocation => "Geolocation",
            Self::CloudStorage => "Cloud Storage",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl crate::catalog::ArtifactDescriptor {
    /// Best-effort CADET [`ActivityCategory`] for this catalog artifact, derived
    /// from its **structural identity** (registry key path + `id`) — never from
    /// `mitre_techniques`, which is the *adversarial* axis and miscategorizes
    /// benign artifacts (IE TypedURLs carries `T1217`/Discovery yet is
    /// [`BrowserActivity`](ActivityCategory::BrowserActivity)). The
    /// catalog-driven registry scanner tags each hit with this.
    ///
    /// Categories describe *observed* activity, not inferred intent: a
    /// benign-by-default system list (e.g. `FilesNotToSnapshot`, present on every
    /// host) is [`SystemState`](ActivityCategory::SystemState), **not**
    /// [`AntiForensics`](ActivityCategory::AntiForensics), even where its MITRE
    /// mapping is adversarial. Tuned for the Windows-registry artifact families
    /// the scanner surfaces; generic host-config and non-registry artifacts
    /// default to [`SystemState`](ActivityCategory::SystemState).
    #[must_use]
    pub fn activity_category(&self) -> ActivityCategory {
        use ActivityCategory as C;
        let hay = format!("{} {}", self.id, self.key_path).to_ascii_lowercase();
        let has = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));

        // Specific identity families are matched before the broad autostart
        // bucket so e.g. credential *providers* (autostart) don't fall into the
        // account rule, and LSA *secrets* (account) don't fall into LSA packages.
        if has(&[
            "profilelist",
            "profile_list",
            "sam_users",
            "sam_hive",
            "account_users",
            "user_account",
            "_sid",
            "dcc2",
            "lsa_secret",
            "logonui_last",
            "loggedon_user",
            "last_loggedon",
        ]) {
            return C::AccountActivity;
        }
        if has(&[
            "typed_urls",
            "typedurls",
            "default_browser",
            "internet explorer",
            "browsers_",
        ]) {
            return C::BrowserActivity;
        }
        if has(&[
            "proxy",
            "rdp_",
            "terminal server client",
            "firewall",
            "network_share",
            "network_provider",
            "networklist",
            "lanmanserver",
            "\\shares",
            "\\interfaces",
        ]) {
            return C::NetworkActivity;
        }
        if has(&[
            "mounteddevices",
            "mounted_devices",
            "usbstor",
            "setupapi",
            "portabledevices",
        ]) {
            return C::DeviceInstall;
        }
        if has(&[
            "recentdocs",
            "recent_docs",
            "comdlg32",
            "lastvisitedpidl",
            "opensave",
            "cidsizemru",
            "shellbag",
            "bagmru",
        ]) {
            return C::FileSystemActivity;
        }
        if has(&[
            "userassist",
            "shimcache",
            "appcompatcache",
            "muicache",
            "app_paths",
        ]) {
            return C::Execution;
        }
        if has(&[
            "run_key",
            "currentversion\\run",
            "runonce",
            "winlogon",
            "userinit",
            "boot_execute",
            "appinit",
            "image_file_execution",
            "ifeo",
            "known_dlls",
            "\\services\\",
            "_services",
            "credential_provider",
            "lsa_auth",
            "lsa_notification",
            "lsa_security",
            "auth_packages",
            "auth_pkg",
            "notification_packages",
            "security_packages",
            "security_pkg",
            "netsh",
            "ssodl",
            "shellserviceobjectdelayload",
            "shellex",
            "contextmenuhandler",
            "copyhookhandler",
            "dragdrophandler",
            "propertysheethandler",
            "com_server",
            "\\clsid",
            "password_filter",
            "winsock",
            "\\lsp",
            "protocol_catalog",
            "autorun",
            "command processor",
            "exefile\\shell",
            "taskband",
            "initial_program",
            "runtime_exception",
            "autoplayhandler",
            "active_setup",
            "startup",
            "valley_rat",
        ]) {
            return C::Persistence;
        }
        C::SystemState
    }
}

#[cfg(test)]
mod tests {
    use super::ActivityCategory;

    /// The full set, for exhaustive round-trip / coverage checks.
    const ALL: &[ActivityCategory] = &[
        ActivityCategory::Execution,
        ActivityCategory::Persistence,
        ActivityCategory::ScheduledTask,
        ActivityCategory::LoginActivity,
        ActivityCategory::FileSystemActivity,
        ActivityCategory::DeviceInstall,
        ActivityCategory::NetworkActivity,
        ActivityCategory::BrowserActivity,
        ActivityCategory::SystemState,
        ActivityCategory::AccountActivity,
        ActivityCategory::PackageInventory,
        ActivityCategory::AntiForensics,
        ActivityCategory::UserActivity,
        ActivityCategory::Integrity,
        ActivityCategory::Geolocation,
        ActivityCategory::CloudStorage,
    ];

    #[test]
    fn display_is_human_readable() {
        assert_eq!(ActivityCategory::Execution.to_string(), "Execution");
        assert_eq!(
            ActivityCategory::FileSystemActivity.to_string(),
            "File System Activity"
        );
        assert_eq!(ActivityCategory::CloudStorage.to_string(), "Cloud Storage");
    }

    #[test]
    fn code_round_trips_for_every_variant() {
        for &c in ALL {
            assert_eq!(
                ActivityCategory::from_code(c.code()),
                Some(c),
                "code() / from_code() must round-trip {c:?}"
            );
        }
    }

    #[test]
    fn codes_are_unique_kebab() {
        let mut seen = std::collections::HashSet::new();
        for &c in ALL {
            let code = c.code();
            assert!(seen.insert(code), "duplicate code {code}");
            assert!(
                code.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'),
                "code must be kebab-case: {code}"
            );
        }
    }

    #[test]
    fn attack_tactic_maps_only_adversarial_categories() {
        // The clean adversarial overlaps map to ATT&CK tactics; benign/forensic
        // categories return None (CADET is a superset of ATT&CK).
        assert_eq!(ActivityCategory::Execution.attack_tactic(), Some("TA0002"));
        assert_eq!(
            ActivityCategory::Persistence.attack_tactic(),
            Some("TA0003")
        );
        assert_eq!(
            ActivityCategory::AntiForensics.attack_tactic(),
            Some("TA0005")
        );
        assert_eq!(
            ActivityCategory::AccountActivity.attack_tactic(),
            Some("TA0006")
        );
        assert_eq!(ActivityCategory::FileSystemActivity.attack_tactic(), None);
        assert_eq!(ActivityCategory::BrowserActivity.attack_tactic(), None);
    }

    #[test]
    fn descriptor_activity_category_classifies_known_registry_families() {
        use crate::catalog::CATALOG;
        // Real catalog ids → their structural category (verified against the live
        // catalog, not synthetic descriptors — Doer-Checker). mitre is NOT used:
        // browsers_ie_typed_urls carries T1217/Discovery yet must be BrowserActivity.
        let cases = [
            ("run_key_hklm", ActivityCategory::Persistence),
            ("winlogon_shell", ActivityCategory::Persistence),
            ("com_server_hklm", ActivityCategory::Persistence),
            (
                "fa_currentcontrolset_services",
                ActivityCategory::Persistence,
            ),
            ("userassist_exe", ActivityCategory::Execution),
            ("shimcache", ActivityCategory::Execution),
            ("browsers_ie_typed_urls", ActivityCategory::BrowserActivity),
            ("typed_urls", ActivityCategory::BrowserActivity),
            ("fa_system_mounteddevices", ActivityCategory::DeviceInstall),
            ("profile_list_users", ActivityCategory::AccountActivity),
            ("sam_users", ActivityCategory::AccountActivity),
            ("lsa_secrets", ActivityCategory::AccountActivity),
            ("dcc2_cache", ActivityCategory::AccountActivity),
            ("mru_recent_docs", ActivityCategory::FileSystemActivity),
            ("rdp_client_default", ActivityCategory::NetworkActivity),
            ("firewall_rules", ActivityCategory::NetworkActivity),
            // Benign-by-default system config: SystemState, NOT AntiForensics
            // (its MITRE mapping is adversarial, but the artifact is observed config).
            ("vss_files_not_to_snapshot", ActivityCategory::SystemState),
            ("computer_name", ActivityCategory::SystemState),
            ("system_timezone", ActivityCategory::SystemState),
        ];
        for (id, expected) in cases {
            let d = CATALOG
                .by_id(id)
                .unwrap_or_else(|| panic!("catalog id {id} should exist"));
            assert_eq!(
                d.activity_category(),
                expected,
                "{id} ({}) → expected {expected:?}",
                d.key_path
            );
        }
    }
}
