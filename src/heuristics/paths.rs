//! File path and name anomaly heuristics + Zone.Identifier constants.

// ── Zone.Identifier (Mark-of-the-Web) ─────────────────────────────────────

pub const ZONE_LOCAL: u32 = 0;
pub const ZONE_INTRANET: u32 = 1;
pub const ZONE_TRUSTED: u32 = 2;
pub const ZONE_INTERNET: u32 = 3;
pub const ZONE_RESTRICTED: u32 = 4;

/// Returns `true` if the ZoneId indicates the file was downloaded from the internet
/// or a restricted zone (ZoneId >= 3). Executables with this mark running without
/// warning indicate MOTW bypass (T1553.005).
#[must_use]
pub fn is_internet_download(zone_id: u32) -> bool {
    zone_id >= ZONE_INTERNET
}

// ── File name anomalies ────────────────────────────────────────────────────

/// Returns `true` if the filename has a double extension (e.g. `invoice.pdf.exe`).
/// Social engineering technique to disguise executable as document.
///
/// Logic: the filename (without directory) contains at least two `.` characters
/// and neither the first nor second extension from the right is empty.
#[must_use]
pub fn is_double_extension(filename: &str) -> bool {
    // Work on the base name only (after last path separator)
    let name = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let parts: Vec<&str> = name.splitn(3, '.').collect();
    // Need at least: stem, first-ext, second-ext — all non-empty
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

/// Returns `true` if the path contains an Alternate Data Stream separator.
/// ADS paths look like `C:\file.txt:hidden_stream`.
/// Skips the drive-letter colon (first two characters).
#[must_use]
pub fn is_alternate_data_stream(path: &str) -> bool {
    path.chars().skip(2).any(|c| c == ':')
}

/// Returns `true` if the filename begins with a dot (Linux/macOS hidden file convention).
#[must_use]
pub fn is_linux_hidden_name(name: &str) -> bool {
    name.starts_with('.') && name.len() > 1
}

/// Returns `true` if the path begins with a UNC prefix (`\\` or `//`).
/// UNC paths in LNK files or prefetch indicate network execution (T1021).
#[must_use]
pub fn is_unc_path(path: &str) -> bool {
    path.starts_with("\\\\") || path.starts_with("//")
}

/// Path prefixes associated with suspicious execution locations.
pub const SUSPICIOUS_EXEC_PREFIXES: &[&str] = &[
    "\\Temp\\",
    "\\tmp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/var/tmp/",
];

/// Returns `true` if the path contains a suspicious execution prefix.
#[must_use]
pub fn is_suspicious_exec_path(path: &str) -> bool {
    SUSPICIOUS_EXEC_PREFIXES.iter().any(|p| path.contains(p))
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_internet_is_internet_download() {
        assert!(is_internet_download(ZONE_INTERNET));
    }

    #[test]
    fn zone_restricted_is_internet_download() {
        assert!(is_internet_download(ZONE_RESTRICTED));
    }

    #[test]
    fn zone_local_is_not_internet_download() {
        assert!(!is_internet_download(ZONE_LOCAL));
    }

    #[test]
    fn zone_trusted_is_not_internet_download() {
        assert!(!is_internet_download(ZONE_TRUSTED));
    }

    #[test]
    fn double_extension_pdf_exe() {
        assert!(is_double_extension("invoice.pdf.exe"));
    }

    #[test]
    fn double_extension_doc_exe() {
        assert!(is_double_extension("report.doc.exe"));
    }

    #[test]
    fn single_extension_not_double() {
        assert!(!is_double_extension("program.exe"));
    }

    #[test]
    fn no_extension_not_double() {
        assert!(!is_double_extension("makefile"));
    }

    #[test]
    fn double_extension_empty_part_not_flagged() {
        // ".hidden.exe" — the stem before the first dot is empty
        assert!(!is_double_extension(".hidden.exe"));
    }

    #[test]
    fn ads_path_detected() {
        assert!(is_alternate_data_stream(r"C:\file.txt:stream"));
    }

    #[test]
    fn normal_path_not_ads() {
        assert!(!is_alternate_data_stream(r"C:\file.txt"));
    }

    #[test]
    fn drive_colon_not_ads() {
        // Only the drive-letter colon at position 1 — no ADS colon after skip(2)
        assert!(!is_alternate_data_stream(r"C:\dir\file.txt"));
    }

    #[test]
    fn linux_hidden_dot_file() {
        assert!(is_linux_hidden_name(".bashrc"));
    }

    #[test]
    fn linux_hidden_double_dot() {
        assert!(is_linux_hidden_name("..file"));
    }

    #[test]
    fn linux_non_hidden() {
        assert!(!is_linux_hidden_name("bashrc"));
    }

    #[test]
    fn linux_single_dot_not_hidden() {
        // len must be > 1
        assert!(!is_linux_hidden_name("."));
    }

    #[test]
    fn unc_path_backslash() {
        assert!(is_unc_path(r"\\server\share"));
    }

    #[test]
    fn unc_path_forward_slash() {
        assert!(is_unc_path("//server/share"));
    }

    #[test]
    fn normal_path_not_unc() {
        assert!(!is_unc_path(r"C:\Windows"));
    }

    #[test]
    fn suspicious_exec_tmp_path() {
        assert!(is_suspicious_exec_path(
            r"C:\Users\bob\AppData\Local\Temp\evil.exe"
        ));
    }

    #[test]
    fn suspicious_exec_dev_shm() {
        assert!(is_suspicious_exec_path("/dev/shm/payload"));
    }

    #[test]
    fn normal_exec_path_not_suspicious() {
        assert!(!is_suspicious_exec_path(r"C:\Windows\System32\calc.exe"));
    }

    // ── HKCU\Console allowlist (Valley RAT detection) ──────────────────────
    // Source: https://windowsir.blogspot.com/2026/01/grab-bag.html
    // Source: https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures

    #[test]
    fn console_facename_is_known() {
        assert!(!is_suspicious_console_value_name("FaceName"));
    }

    #[test]
    fn console_fontsize_is_known() {
        assert!(!is_suspicious_console_value_name("FontSize"));
    }

    #[test]
    fn console_colortable00_is_known() {
        assert!(!is_suspicious_console_value_name("ColorTable00"));
    }

    #[test]
    fn console_known_value_case_insensitive() {
        // Windows registry value names are case-insensitive
        assert!(!is_suspicious_console_value_name("facename"));
        assert!(!is_suspicious_console_value_name("FACENAME"));
    }

    #[test]
    fn console_arbitrary_blob_name_is_suspicious() {
        // Valley RAT writes config under non-standard value names
        assert!(is_suspicious_console_value_name("config"));
        assert!(is_suspicious_console_value_name("d33f351a4aeea5e608853d1a56661059"));
    }

    #[test]
    fn console_empty_value_name_is_suspicious() {
        // The default unnamed value is not used by the legitimate Console key
        assert!(is_suspicious_console_value_name(""));
    }

    #[test]
    fn console_numeric_subkey_is_suspicious() {
        // HKCU\Console\0\<md5> is the Valley RAT plugin store path
        assert!(is_suspicious_console_subkey(r"HKCU\Console\0"));
        assert!(is_suspicious_console_subkey(
            r"HKCU\Console\0\d33f351a4aeea5e608853d1a56661059"
        ));
    }

    #[test]
    fn console_app_subkey_not_suspicious() {
        // Per-app Console subkeys (cmd.exe, etc.) are legitimate
        assert!(!is_suspicious_console_subkey(r"HKCU\Console\cmd.exe"));
        assert!(!is_suspicious_console_subkey(
            r"HKCU\Console\%SystemRoot%_System32_cmd.exe"
        ));
    }

    #[test]
    fn console_root_key_not_flagged_as_subkey() {
        // The root HKCU\Console key itself is not a subkey
        assert!(!is_suspicious_console_subkey(r"HKCU\Console"));
        assert!(!is_suspicious_console_subkey(r"HKCU\Console\"));
    }

    #[test]
    fn console_subkey_check_case_insensitive() {
        // Registry key paths are case-insensitive on Windows
        assert!(is_suspicious_console_subkey(r"hkcu\console\0"));
    }

    #[test]
    fn non_console_key_not_flagged() {
        assert!(!is_suspicious_console_subkey(
            r"HKCU\Software\Microsoft\Windows"
        ));
    }

    // ── NTUSER.MAN mandatory-profile persistence ──────────────────────────
    // Source: https://deceptiq.com/blog/ntuser-man-registry-persistence
    // Source: https://windowsir.blogspot.com/2026/01/grab-bag.html

    #[test]
    fn ntuser_man_in_userprofile_detected() {
        assert!(is_ntuser_man_path(r"C:\Users\bob\NTUSER.MAN"));
    }

    #[test]
    fn ntuser_man_case_insensitive() {
        // Windows file names are case-insensitive
        assert!(is_ntuser_man_path(r"C:\Users\bob\ntuser.man"));
        assert!(is_ntuser_man_path(r"C:\Users\bob\NtUser.Man"));
    }

    #[test]
    fn ntuser_dat_not_flagged() {
        // The legitimate per-user hive must not match
        assert!(!is_ntuser_man_path(r"C:\Users\bob\NTUSER.DAT"));
    }

    #[test]
    fn ntuser_man_on_unc_share_detected() {
        // Roaming-profile-share placement is also a vector
        assert!(is_ntuser_man_path(r"\\server\share\profile.v6\NTUSER.MAN"));
    }

    #[test]
    fn ntuser_man_substring_in_other_filename_not_flagged() {
        // Only the basename is matched — substrings elsewhere are not
        assert!(!is_ntuser_man_path(
            r"C:\Users\bob\notes\ntuser.man.backup.txt"
        ));
    }
}
