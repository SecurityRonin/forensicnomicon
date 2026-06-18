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
}
