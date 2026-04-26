/// Registry paths that indicate presence of VeraCrypt encryption tool.
///
/// Sources:
/// - Elcomsoft — "Breaking VeraCrypt: Obtaining and Extracting On-The-Fly
///   Encryption Keys" (Jun 2021), covers OTFE key extraction from RAM and
///   hibernation files:
///   <https://blog.elcomsoft.com/2021/06/breaking-veracrypt-obtaining-and-extracting-on-the-fly-encryption-keys/>
/// - Elcomsoft — "Live System Analysis: Discovering Encrypted Disk Volumes"
///   (Jul 2020), covers VeraCrypt OTFE keys in hibernation/page files:
///   <https://blog.elcomsoft.com/2020/07/live-system-analysis-discovering-encrypted-disk-volumes/>
/// - Belkasoft — VeraCrypt forensic artifacts in the Windows registry:
///   <https://belkasoft.com/veracrypt-forensics>
/// - SANS white paper — "Mission Implausible: Defeating Plausible Deniability
///   with Digital Forensics" (VeraCrypt nested volumes and deniable OS):
///   <https://www.sans.org/white-papers/39500>
pub const VERACRYPT_PATHS: &[&str] = &[
    r"SOFTWARE\VeraCrypt",
    r"SOFTWARE\Wow6432Node\VeraCrypt",
    r"SYSTEM\CurrentControlSet\Services\veracrypt",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt",
];

/// BitLocker-related registry evidence.
///
/// Sources:
/// - Microsoft — BitLocker Group Policy settings registry reference
///   (HKLM\SOFTWARE\Policies\Microsoft\FVE):
///   <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings>
/// - Harlan Carvey — "Drive Encryption" (Apr 2007), WMI-based BitLocker detection
///   and live acquisition as the recommended response to active encryption:
///   <http://windowsir.blogspot.com/2007/04/drive-encryption.html>
/// - Geoff Chappell — deep technical reference for every FVE registry value:
///   <https://www.geoffchappell.com/studies/windows/win32/fveapi/policy/index.htm>
pub const BITLOCKER_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\FVE",
    r"SYSTEM\CurrentControlSet\Control\BitLockerStatus",
    r"SYSTEM\CurrentControlSet\Services\BDESVC",
    r"SYSTEM\CurrentControlSet\Services\fvevol",
];

/// EFS (Encrypting File System) policy paths.
///
/// Sources:
/// - SANS white paper — "A Forensic Analysis of the Encrypting File System" (Feb 2021),
///   covers EFS registry keys, DDF/DRF fields, ransomware abuse of EFS:
///   <https://www.sans.org/white-papers/40160>
/// - Microsoft — Windows EFS developer reference:
///   <https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption>
pub const EFS_PATHS: &[&str] = &[
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS",
    r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS",
];

/// 7-Zip MRU and settings paths.
///
/// Sources:
/// - Harlan Carvey, *Windows Registry Forensics* (2nd ed., Syngress/Elsevier, 2016)
///   ISBN 978-0-12-803291-6 — archiver MRU chapter:
///   <https://shop.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6>
pub const SEVENZIP_PATHS: &[&str] = &[
    r"SOFTWARE\7-Zip",
    r"SOFTWARE\Wow6432Node\7-Zip",
    r"Software\7-Zip",
];

/// WinRAR MRU paths (archive access evidence).
///
/// Sources:
/// - Harlan Carvey, *Windows Registry Forensics* (2nd ed., Syngress/Elsevier, 2016)
///   ISBN 978-0-12-803291-6 — archiver MRU chapter:
///   <https://shop.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6>
pub const WINRAR_PATHS: &[&str] = &[
    r"SOFTWARE\WinRAR",
    r"SOFTWARE\WinRAR SFX",
    r"Software\WinRAR",
];

/// Tor Browser / Tor Project registry paths.
///
/// Sources:
/// - SANS white paper #37642 — "Tor Browser Artifacts in Windows 10" (Feb 2017),
///   primary DFIR reference for Tor Browser Windows registry artifacts:
///   <https://www.sans.org/white-papers/37642>
/// - MDPI 2024 (open access) — "Analyzing Tor Browser Artifacts for Enhanced Web
///   Forensics" (documents PowerShell checking for SOFTWARE\Tor Project):
///   <https://www.mdpi.com/2078-2489/15/8/495>
/// - Tor Project — Windows installation documentation:
///   <https://tb-manual.torproject.org/installation/>
pub const TOR_PATHS: &[&str] = &[r"SOFTWARE\Tor Project", r"SOFTWARE\Wow6432Node\Tor Project"];

/// Returns an iterator over all encryption tool indicator paths.
///
/// Prefer this over any duplicated flat slice for bulk scanning —
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

/// File extensions associated with known ransomware families.
///
/// Sources:
/// - MITRE ATT&CK T1486 — Data Encrypted for Impact:
///   <https://attack.mitre.org/techniques/T1486/>
/// - ID Ransomware — crowdsourced ransomware extension database:
///   <https://id-ransomware.malwarehunterteam.com/>
/// - Coveware — Quarterly Ransomware Reports documenting prevalent families:
///   <https://www.coveware.com/ransomware-quarterly-reports>
pub const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".wcry",   // WannaCry
    ".wnry",   // WannaCry
    ".wncry",  // WannaCry
    ".locky",  // Locky
    ".zepto",  // Locky variant
    ".odin",   // Locky variant
    ".cerber", // Cerber
    ".cerber2",
    ".cerber3",
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypz",
    ".cryp1",
    ".crinf",
    ".r5a",
    ".XData",
    ".cobra", // Dharma
    ".dharma",
    ".phobos", // Phobos
    ".ryuk",   // Ryuk
    ".conti",  // Conti
    ".hive",   // Hive
    ".BlackCat",
    ".alphv", // BlackCat/ALPHV
    ".revil", // REvil/Sodinokibi
    ".sodinokibi",
    ".darkside",
    ".chaos",
    ".zeppelin",
    ".paymen45",
    ".eking", // Phobos variant
    ".acute", // Phobos variant
    ".scarab",
    ".globe",
    ".stampado",
    ".kr3",
    ".crypted",
    ".enc",
    ".fucked",
];

/// Returns `true` if `ext` matches a known ransomware file extension (case-insensitive).
///
/// Pass the extension with or without a leading dot (`.wcry` or `wcry`).
pub fn is_ransomware_extension(ext: &str) -> bool {
    let normalized = if ext.starts_with('.') {
        ext.to_ascii_lowercase()
    } else {
        format!(".{}", ext.to_ascii_lowercase())
    };
    RANSOMWARE_EXTENSIONS
        .iter()
        .any(|e| e.to_ascii_lowercase() == normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veracrypt_paths_contains_hklm_key() {
        assert!(VERACRYPT_PATHS.contains(&r"SOFTWARE\VeraCrypt"));
    }

    #[test]
    fn bitlocker_paths_contains_fve_policy() {
        assert!(BITLOCKER_PATHS.contains(&r"SOFTWARE\Policies\Microsoft\FVE"));
    }

    #[test]
    fn sevenzip_paths_contains_hklm_key() {
        assert!(SEVENZIP_PATHS.contains(&r"SOFTWARE\7-Zip"));
    }

    #[test]
    fn all_encryption_paths_includes_tor() {
        assert!(all_encryption_paths().any(|p| p == r"SOFTWARE\Tor Project"));
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
        assert!(is_encryption_tool_path(r"SOFTWARE\VeraCrypt\MRUList"));
    }

    #[test]
    fn is_encryption_tool_path_case_insensitive() {
        assert!(is_encryption_tool_path(r"software\veracrypt"));
    }

    #[test]
    fn is_encryption_tool_path_unrelated_returns_false() {
        assert!(!is_encryption_tool_path(r"SOFTWARE\Microsoft\Office"));
    }

    // --- RANSOMWARE_EXTENSIONS / is_ransomware_extension ---
    #[test]
    fn ransomware_extensions_contains_wcry() {
        assert!(RANSOMWARE_EXTENSIONS.contains(&".wcry"));
    }
    #[test]
    fn ransomware_extensions_contains_locky() {
        assert!(RANSOMWARE_EXTENSIONS.contains(&".locky"));
    }
    #[test]
    fn ransomware_extensions_contains_conti() {
        assert!(RANSOMWARE_EXTENSIONS.contains(&".conti"));
    }
    #[test]
    fn detects_wcry_with_dot() {
        assert!(is_ransomware_extension(".wcry"));
    }
    #[test]
    fn detects_wcry_without_dot() {
        assert!(is_ransomware_extension("wcry"));
    }
    #[test]
    fn detects_locky_uppercase() {
        assert!(is_ransomware_extension(".LOCKY"));
    }
    #[test]
    fn detects_ryuk() {
        assert!(is_ransomware_extension(".ryuk"));
    }
    #[test]
    fn detects_conti() {
        assert!(is_ransomware_extension(".conti"));
    }
    #[test]
    fn detects_blackcat() {
        assert!(is_ransomware_extension(".BlackCat"));
    }
    #[test]
    fn does_not_flag_docx() {
        assert!(!is_ransomware_extension(".docx"));
    }
    #[test]
    fn does_not_flag_exe() {
        assert!(!is_ransomware_extension(".exe"));
    }
    #[test]
    fn empty_string_not_ransomware_ext() {
        assert!(!is_ransomware_extension(""));
    }
}
