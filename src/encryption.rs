/// Registry paths that indicate presence of VeraCrypt encryption tool.
///
/// Sources:
/// - Elcomsoft — VeraCrypt forensic analysis:
///   <https://blog.elcomsoft.com/2020/03/breaking-veracrypt-obtaining-and-extracting-on-the-fly-encryption-keys/>
/// - Belkasoft — VeraCrypt artefacts in Windows registry:
///   <https://belkasoft.com/veracrypt-forensics>
/// - VeraCrypt documentation — Windows registry keys:
///   <https://veracrypt.fr/en/Documentation.html>
pub const VERACRYPT_PATHS: &[&str] = &[
    r"SOFTWARE\VeraCrypt",
    r"SOFTWARE\Wow6432Node\VeraCrypt",
    r"SYSTEM\CurrentControlSet\Services\veracrypt",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt",
];

/// BitLocker-related registry evidence.
///
/// Sources:
/// - Microsoft — BitLocker registry settings reference:
///   <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings>
/// - SANS DFIR — BitLocker forensics and key recovery:
///   <https://www.sans.org/blog/windows-full-disk-encryption-fde-forensics/>
pub const BITLOCKER_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\FVE",
    r"SYSTEM\CurrentControlSet\Control\BitLockerStatus",
    r"SYSTEM\CurrentControlSet\Services\BDESVC",
    r"SYSTEM\CurrentControlSet\Services\fvevol",
];

/// EFS (Encrypting File System) policy paths.
///
/// Sources:
/// - Microsoft — EFS registry configuration:
///   <https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption>
/// - SANS — EFS forensic artifacts:
///   <https://www.sans.org/blog/protecting-sensitive-files-with-efs/>
pub const EFS_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS",
    r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS",
];

/// 7-Zip MRU and settings paths.
///
/// Sources:
/// - Harlan Carvey, "Windows Registry Forensics" — archiver MRU chapter
/// - SANS FOR500 — Windows forensics: archiver registry artifacts
pub const SEVENZIP_PATHS: &[&str] = &[
    r"SOFTWARE\7-Zip",
    r"SOFTWARE\Wow6432Node\7-Zip",
    r"Software\7-Zip",
];

/// WinRAR MRU paths (archive access evidence).
///
/// Sources:
/// - Harlan Carvey, "Windows Registry Forensics" — archiver MRU chapter
/// - SANS FOR500 — Windows forensics: WinRAR registry artifacts
pub const WINRAR_PATHS: &[&str] = &[
    r"SOFTWARE\WinRAR",
    r"SOFTWARE\WinRAR SFX",
    r"Software\WinRAR",
];

/// Tor Browser / Tor Project registry paths.
///
/// Sources:
/// - Tor Project — Windows installation documentation:
///   <https://tb-manual.torproject.org/installation/>
/// - SANS — Tor Browser forensic artefacts:
///   <https://www.sans.org/blog/tor-browser-forensics/>
pub const TOR_PATHS: &[&str] = &[r"SOFTWARE\Tor Project", r"SOFTWARE\Wow6432Node\Tor Project"];

/// Returns an iterator over all encryption tool indicator paths.
///
/// Prefer this over the legacy `ALL_ENCRYPTION_PATHS` slice for bulk scanning —
/// zero allocation, no data duplication.
pub fn all_encryption_paths() -> impl Iterator<Item = &'static str> {
    VERACRYPT_PATHS
        .iter()
        .chain(BITLOCKER_PATHS.iter())
        .chain(EFS_PATHS.iter())
        .chain(SEVENZIP_PATHS.iter())
        .chain(WINRAR_PATHS.iter())
        .chain(TOR_PATHS.iter())
        .copied()
}

/// Returns true if the given registry path matches a known encryption tool indicator
/// (case-insensitive contains match).
pub fn is_encryption_tool_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    all_encryption_paths().any(|entry| lower.contains(&entry.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veracrypt_paths_not_empty() {
        assert!(
            !VERACRYPT_PATHS.is_empty(),
            "VERACRYPT_PATHS must not be empty"
        );
    }

    #[test]
    fn bitlocker_paths_not_empty() {
        assert!(
            !BITLOCKER_PATHS.is_empty(),
            "BITLOCKER_PATHS must not be empty"
        );
    }

    #[test]
    fn sevenzip_paths_not_empty() {
        assert!(
            !SEVENZIP_PATHS.is_empty(),
            "SEVENZIP_PATHS must not be empty"
        );
    }

    #[test]
    fn all_encryption_paths_includes_tor() {
        assert!(
            all_encryption_paths().any(|p| p == r"SOFTWARE\Tor Project"),
            "all_encryption_paths() must include Tor Project"
        );
    }

    #[test]
    fn all_encryption_paths_covers_all_tools() {
        let all: Vec<_> = all_encryption_paths().collect();
        for path in [
            VERACRYPT_PATHS[0],
            BITLOCKER_PATHS[0],
            EFS_PATHS[0],
            SEVENZIP_PATHS[0],
            WINRAR_PATHS[0],
            TOR_PATHS[0],
        ] {
            assert!(
                all.contains(&path),
                "Missing path in all_encryption_paths: {path}"
            );
        }
    }

    #[test]
    fn is_encryption_tool_path_veracrypt_matches() {
        assert!(
            is_encryption_tool_path(r"SOFTWARE\VeraCrypt\MRUList"),
            "VeraCrypt path must match"
        );
    }

    #[test]
    fn is_encryption_tool_path_case_insensitive() {
        assert!(
            is_encryption_tool_path(r"software\veracrypt"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_encryption_tool_path_unrelated_returns_false() {
        assert!(
            !is_encryption_tool_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }
}
