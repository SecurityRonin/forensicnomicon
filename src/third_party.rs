/// PuTTY registry paths — saved sessions, SSH host key cache.
///
/// Sources:
/// - Harlan Carvey, "Windows Registry Forensics" — SSH client artifacts chapter
/// - SANS FOR500 — Windows forensics: PuTTY registry artifacts
/// - PuTTY documentation — registry storage layout:
///   <https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html>
pub const PUTTY_PATHS: &[&str] = &[
    r"Software\SimonTatham\PuTTY\Sessions",
    r"Software\SimonTatham\PuTTY\SshHostKeys",
    r"Software\SimonTatham\PuTTY\Jumplist\Recent sessions",
];

/// WinSCP registry paths — saved sessions including obfuscated passwords.
///
/// Sources:
/// - WinSCP documentation — registry storage:
///   <https://winscp.net/eng/docs/ui_pref_storage>
/// - SANS FOR500 — WinSCP session credential recovery
/// - Magnet Forensics — WinSCP artifact analysis:
///   <https://www.magnetforensics.com/blog/artifacts-for-incident-responders/>
pub const WINSCP_PATHS: &[&str] = &[
    r"Software\Martin Prikryl\WinSCP 2\Sessions",
    r"Software\Martin Prikryl\WinSCP 2\Configuration",
];

/// Microsoft OneDrive registry paths.
///
/// Sources:
/// - Microsoft — OneDrive registry keys reference:
///   <https://learn.microsoft.com/en-us/sharepoint/sync-client-administration-settings>
/// - SANS FOR500 — OneDrive forensic artifacts
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
/// - Magnet Forensics — Dropbox forensic artifacts:
///   <https://www.magnetforensics.com/blog/artifacts-for-incident-responders/>
/// - SANS FOR500 — cloud storage registry artifacts
pub const DROPBOX_PATHS: &[&str] = &[
    r"Software\Dropbox",
    r"Software\Dropbox\ks\client",
    r"SOFTWARE\Dropbox",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox",
];

/// Google Chrome registry paths (installation, policies, extensions).
///
/// Sources:
/// - Google — Chrome enterprise policy registry keys:
///   <https://chromeenterprise.google/policies/>
/// - Magnet Forensics — Chrome forensic artifacts:
///   <https://www.magnetforensics.com/blog/forensic-analysis-of-google-chrome/>
/// - SANS FOR500 — browser registry artifacts
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
/// - KiTTY documentation — registry storage (inherits PuTTY layout):
///   <https://www.9bis.net/kitty/?page=Documentation>
/// - SANS FOR500 — SSH client artifacts (covers PuTTY forks)
pub const KITTY_PATHS: &[&str] = &[
    r"Software\9bis.com\KiTTY\Sessions",
    r"Software\9bis.com\KiTTY\SshHostKeys",
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
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn putty_paths_not_empty() {
        assert!(!PUTTY_PATHS.is_empty(), "PUTTY_PATHS must not be empty");
    }

    #[test]
    fn onedrive_paths_not_empty() {
        assert!(
            !ONEDRIVE_PATHS.is_empty(),
            "ONEDRIVE_PATHS must not be empty"
        );
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
}
