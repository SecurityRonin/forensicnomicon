//! Forensic activity categories — *what evidence means*, independent of which
//! artifact/source it came from.
//!
//! This is the semantic axis: many artifacts answer the same category (login
//! evidence comes from `auth.log` + `wtmp` + EVTX 4624; device-install from
//! `setupapi.dev.log` + registry `USBSTOR` + EVTX). It is forensic knowledge, so
//! it lives here in `forensicnomicon` (not in a consumer like issen): correlation
//! and reporting group timeline events by this category across sources, while the
//! *routing* type (which parser reads a file) stays a consumer concern.
//!
//! Complements [`crate::report::Category`] (the analysis-lens axis —
//! Integrity/Structure/Threat/…); this one is the activity/behavior axis.

/// The forensic-semantic category of a timeline event — *what happened*,
/// independent of the source artifact that recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ForensicCategory {
    /// Program / process execution (prefetch, amcache, userassist, bam,
    /// shimcache, SRUM app usage, process lists).
    Execution,
    /// Autostart / persistence mechanisms (run keys, COM hijacks, services).
    Persistence,
    /// Scheduled / recurring task definitions (cron, at, Task Scheduler).
    ScheduledTask,
    /// Logon / logoff / authentication (auth.log, wtmp, EVTX 4624/4625, sudo).
    LoginActivity,
    /// File / folder access and filesystem metadata (LNK, jump lists,
    /// shellbags, `$MFT`, `$UsnJrnl`, bodyfile).
    FileSystemActivity,
    /// Device / driver / removable-media install (setupapi.dev.log, registry
    /// USBSTOR/MountedDevices, EVTX plug-and-play).
    DeviceInstall,
    /// Network connections / configuration (network state, SRUM network).
    NetworkActivity,
    /// Web browsing (history, typed URLs, downloads).
    BrowserActivity,
    /// Host state / configuration / general system logs (syslog, macOS unified
    /// log, system info, registry config).
    SystemState,
    /// User / group account artifacts (SAM, `/etc/passwd`).
    AccountActivity,
    /// Installed-package inventory (dpkg, rpm, pip).
    PackageInventory,
    /// Anti-forensics / concealment (log clearing, rootkit scan results).
    AntiForensics,
    /// Direct user-interaction artifacts (Biome App.MenuItem, recent items).
    UserActivity,
    /// Integrity / verification artifacts (hash manifests, assessments).
    Integrity,
}

impl core::fmt::Display for ForensicCategory {
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
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::ForensicCategory;

    #[test]
    fn display_is_human_readable() {
        assert_eq!(
            ForensicCategory::LoginActivity.to_string(),
            "Login Activity"
        );
        assert_eq!(
            ForensicCategory::DeviceInstall.to_string(),
            "Device Install"
        );
        assert_eq!(ForensicCategory::Execution.to_string(), "Execution");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(ForensicCategory::Persistence, ForensicCategory::Execution);
    }
}
