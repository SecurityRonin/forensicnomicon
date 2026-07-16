/// PuTTY registry paths — saved sessions, SSH host key cache.
///
/// Sources:
/// - Mandiant/FireEye — "Using the Registry to Discover Unix Systems and Jump Boxes"
///   (Mar 2017), primary forensic reference for PuTTY registry artifacts in
///   lateral movement investigations:
///   <https://www.fireeye.com/blog/threat-research/2017/03/using_the_registryt.html>
/// - SANS ISC — Didier Stevens, diary #27376, "PuTTY: ssh Host Keys in the Registry"
///   (documents SshHostKeys as an artifact of prior SSH connections):
///   <https://isc.sans.edu/diary/27376>
/// - PuTTY documentation — Appendix C: registry storage layout:
///   <https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html>
/// - Eric Zimmerman RECmd / RegistryPlugins — practical parser coverage for
///   PuTTY-family registry artifacts:
///   <https://github.com/EricZimmerman/RECmd>
///   <https://github.com/EricZimmerman/RegistryPlugins>
pub const PUTTY_PATHS: &[&str] = &[
    r"Software\SimonTatham\PuTTY\Sessions",
    r"Software\SimonTatham\PuTTY\SshHostKeys",
    r"Software\SimonTatham\PuTTY\Jumplist\Recent sessions",
];

/// WinSCP registry paths — saved sessions including obfuscated passwords.
///
/// Sources:
/// - WinSCP documentation — registry storage location reference:
///   <https://winscp.net/eng/docs/ui_pref_storage>
/// - az4n6 (Paul Rascagneres) — "WinSCP Saved Password Forensics" (Mar 2013),
///   demonstrates recovering obfuscated credentials from the Sessions key:
///   <https://az4n6.blogspot.com/2013/03/winscp-saved-password.html>
/// - Synacktiv — "WinSCP Passwords — How They Are Stored" (2022),
///   reverse-engineers the XOR-based obfuscation used to encode saved passwords:
///   <https://www.synacktiv.com/en/publications/winscp-passwords-how-they-are-stored>
/// - Eric Zimmerman RECmd / RegistryPlugins — registry parser coverage for
///   WinSCP session artifacts:
///   <https://github.com/EricZimmerman/RECmd>
///   <https://github.com/EricZimmerman/RegistryPlugins>
pub const WINSCP_PATHS: &[&str] = &[
    r"Software\Martin Prikryl\WinSCP 2\Sessions",
    r"Software\Martin Prikryl\WinSCP 2\Configuration",
];

/// Microsoft OneDrive registry paths.
///
/// Sources:
/// - Microsoft — OneDrive sync client registry administration settings:
///   <https://learn.microsoft.com/en-us/sharepoint/sync-client-administration-settings>
/// - SANS DFIR blog — Brian Maloney, "Recreating OneDrive's Folder Structure from
///   UserCid.dat" (Feb 2019), demonstrates recovering cloud folder hierarchy from
///   registry and file artifacts:
///   <https://www.sans.org/blog/recreating-onedrive-s-folder-structure-from-usercid-dat>
/// - SANS DFIR blog — Chad Tilbury, "Cloud Storage Acquisition from Endpoint Devices"
///   (Sep 2019), covers OneDrive registry paths as acquisition starting points:
///   <https://www.sans.org/blog/cloud-storage-acquisition-from-endpoint-devices>
pub const ONEDRIVE_PATHS: &[&str] = &[
    r"Software\Microsoft\OneDrive",
    r"Software\Microsoft\OneDrive\Accounts\Personal",
    r"Software\Microsoft\OneDrive\Accounts\Business1",
    r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    r"SOFTWARE\Microsoft\OneDrive",
];

/// Dropbox registry paths.
///
/// Sources:
/// - SANS DFIR blog — Chad Tilbury, "Cloud Storage Acquisition from Endpoint Devices"
///   (Sep 2019), covers Dropbox registry paths as triage starting points alongside
///   OneDrive and Google Drive:
///   <https://www.sans.org/blog/cloud-storage-acquisition-from-endpoint-devices>
/// - Dropbox — Windows installation registry reference (official developer docs):
///   <https://help.dropbox.com/installs/system-requirements>
pub const DROPBOX_PATHS: &[&str] = &[
    r"Software\Dropbox",
    r"Software\Dropbox\ks\client",
    r"SOFTWARE\Dropbox",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox",
];

/// Google Chrome registry paths (installation, policies, extensions).
///
/// Sources:
/// - Google — Chrome enterprise policy registry keys reference
///   (SOFTWARE\Policies\Google\Chrome, extension force-install list):
///   <https://chromeenterprise.google/policies/>
/// - SANS DFIR blog — "Big Brother Forensics: Device Tracking Using Browser-Based
///   Artifacts Part 1" (Jan 2020), covers Chrome registry paths as forensic artifacts:
///   <https://www.sans.org/blog/big-brother-forensics-device-tracking-using-browser-based-artifacts-part-1>
/// - SANS DFIR blog — Chad Tilbury, "Google Chrome Platform Notification Analysis"
///   (Mar 2022), covers SOFTWARE\Google\Chrome in the context of push notification
///   forensics:
///   <https://www.sans.org/blog/google-chrome-platform-notification-analysis>
pub const CHROME_PATHS: &[&str] = &[
    r"Software\Google\Chrome",
    r"SOFTWARE\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    r"SOFTWARE\Google\Update\Clients",
    r"SOFTWARE\Clients\StartMenuInternet\Google Chrome",
];

/// KiTTY registry paths (PuTTY fork).
///
/// Sources:
/// - KiTTY documentation — registry storage (inherits PuTTY HKCU layout):
///   <https://www.9bis.net/kitty/?page=Documentation>
/// - Mandiant/FireEye — "Using the Registry to Discover Unix Systems and Jump Boxes"
///   (Mar 2017), documents the PuTTY-family registry pattern that KiTTY inherits:
///   <https://www.fireeye.com/blog/threat-research/2017/03/using_the_registryt.html>
/// - SANS ISC — Didier Stevens, diary #27376, "PuTTY: ssh Host Keys in the Registry":
///   <https://isc.sans.edu/diary/27376>
pub const KITTY_PATHS: &[&str] = &[
    r"Software\9bis.com\KiTTY\Sessions",
    r"Software\9bis.com\KiTTY\SshHostKeys",
];

/// WinRAR registry paths — archive open/create/extract history.
///
/// Sources:
/// - win.rar GmbH - official registry-backed history behavior documented via
///   WinRAR help and configuration references:
///   <https://www.win-rar.com/switches/settings.htm>
/// - regipy WinRAR plugin - explicit NTUSER registry paths used for DFIR
///   extraction:
///   <https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/winrar.py>
/// - Eric Zimmerman RECmd / RegistryPlugins — registry parser coverage for
///   WinRAR history keys:
///   <https://github.com/EricZimmerman/RECmd>
///   <https://github.com/EricZimmerman/RegistryPlugins>
pub const WINRAR_PATHS: &[&str] = &[
    r"SOFTWARE\WinRAR\ArcHistory",
    r"SOFTWARE\WinRAR\DialogEditHistory\ArcName",
    r"SOFTWARE\WinRAR\DialogEditHistory\ExtrPath",
];

/// Returns an iterator over all third-party application forensic artifact paths.
///
/// Prefer this over the legacy `ALL_THIRD_PARTY_PATHS` slice for bulk scanning —
/// zero allocation, no data duplication.
pub fn all_third_party_paths() -> impl Iterator<Item = &'static str> {
    PUTTY_PATHS
        .iter()
        .chain(WINSCP_PATHS.iter())
        .chain(ONEDRIVE_PATHS.iter())
        .chain(DROPBOX_PATHS.iter())
        .chain(CHROME_PATHS.iter())
        .chain(KITTY_PATHS.iter())
        .chain(WINRAR_PATHS.iter())
        .copied()
}

/// Returns true if the given registry path matches a known third-party application
/// forensic artifact path (case-insensitive contains match).
pub fn is_third_party_artifact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    all_third_party_paths().any(|entry| lower.contains(&entry.to_ascii_lowercase()))
}

/// Returns the application name if the path matches a known third-party app artifact,
/// or None if not recognized.
pub fn identify_application(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let matches = |entries: &[&str]| {
        entries
            .iter()
            .any(|e| lower.contains(&e.to_ascii_lowercase()))
    };
    if matches(PUTTY_PATHS) {
        Some("PuTTY")
    } else if matches(KITTY_PATHS) {
        Some("KiTTY")
    } else if matches(WINSCP_PATHS) {
        Some("WinSCP")
    } else if matches(ONEDRIVE_PATHS) {
        Some("OneDrive")
    } else if matches(DROPBOX_PATHS) {
        Some("Dropbox")
    } else if matches(CHROME_PATHS) {
        Some("Chrome")
    } else if matches(WINRAR_PATHS) {
        Some("WinRAR")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn identify_application_covers_all_branches() {
        assert_eq!(identify_application(PUTTY_PATHS[0]), Some("PuTTY"));
        assert_eq!(identify_application(KITTY_PATHS[0]), Some("KiTTY"));
        assert_eq!(identify_application(WINSCP_PATHS[0]), Some("WinSCP"));
        assert_eq!(identify_application(ONEDRIVE_PATHS[0]), Some("OneDrive"));
        assert_eq!(identify_application(DROPBOX_PATHS[0]), Some("Dropbox"));
        assert_eq!(identify_application(CHROME_PATHS[0]), Some("Chrome"));
        assert_eq!(identify_application(WINRAR_PATHS[0]), Some("WinRAR"));
        assert_eq!(identify_application(r"SOFTWARE\Unknown\App"), None);
    }
    use super::*;

    #[test]
    fn putty_paths_contains_sessions_key() {
        assert!(PUTTY_PATHS.contains(&r"Software\SimonTatham\PuTTY\Sessions"));
    }

    #[test]
    fn onedrive_paths_contains_hkcu_key() {
        assert!(ONEDRIVE_PATHS.contains(&r"Software\Microsoft\OneDrive"));
    }

    #[test]
    fn all_third_party_paths_not_empty() {
        assert!(
            all_third_party_paths().next().is_some(),
            "all_third_party_paths() must yield at least one entry"
        );
    }

    #[test]
    fn all_third_party_paths_covers_all_tools() {
        let all: Vec<_> = all_third_party_paths().collect();
        for path in [
            PUTTY_PATHS[0],
            WINSCP_PATHS[0],
            ONEDRIVE_PATHS[0],
            DROPBOX_PATHS[0],
            CHROME_PATHS[0],
            KITTY_PATHS[0],
            WINRAR_PATHS[0],
        ] {
            assert!(
                all.contains(&path),
                "Missing path in all_third_party_paths: {path}"
            );
        }
    }

    #[test]
    fn is_third_party_artifact_path_putty_matches() {
        assert!(
            is_third_party_artifact_path(r"Software\SimonTatham\PuTTY\Sessions\my-server"),
            "PuTTY sessions path must match"
        );
    }

    #[test]
    fn is_third_party_artifact_path_case_insensitive() {
        assert!(
            is_third_party_artifact_path(r"software\simontatham\putty\sessions"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_third_party_artifact_path_unrelated_returns_false() {
        assert!(
            !is_third_party_artifact_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }

    #[test]
    fn identify_application_putty() {
        assert_eq!(
            identify_application(r"Software\SimonTatham\PuTTY\SshHostKeys"),
            Some("PuTTY"),
            "Should identify PuTTY"
        );
    }

    #[test]
    fn identify_application_unknown_returns_none() {
        assert_eq!(
            identify_application(r"SOFTWARE\SomethingElse\Unknown"),
            None,
            "Unknown path should return None"
        );
    }

    #[test]
    fn identify_application_winrar() {
        assert_eq!(
            identify_application(r"SOFTWARE\WinRAR\ArcHistory"),
            Some("WinRAR"),
            "Should identify WinRAR"
        );
    }
}
