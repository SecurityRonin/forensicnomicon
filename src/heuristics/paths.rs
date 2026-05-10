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

// ── HKCU\Console value-name allowlist (Valley RAT) ─────────────────────────
//
// The legitimate `HKCU\Console` key normally contains only a small,
// well-documented set of Console subsystem display values (FaceName,
// FontSize, ColorTable*, CursorSize, WindowSize, ScreenColors, etc.). Per
// Carvey's commentary on Valley RAT (Silver Fox campaign), the malware
// abuses this exact key to store its configuration as binary blobs under
// non-standard value names, and stores downloaded plugins under
// `HKCU\Console\0\<md5_hash>` — a numeric subkey path that does not match
// any documented Windows Console behavior.
//
// Source: https://windowsir.blogspot.com/2026/01/grab-bag.html
// Source: https://www.cloudsek.com/blog/silver-fox-targeting-india-using-tax-themed-phishing-lures

/// Documented value names that legitimately appear under `HKCU\Console`
/// (and per-application Console subkeys reuse the same set).
pub const CONSOLE_KNOWN_VALUE_NAMES: &[&str] = &[
    "ColorTable00",
    "ColorTable01",
    "ColorTable02",
    "ColorTable03",
    "ColorTable04",
    "ColorTable05",
    "ColorTable06",
    "ColorTable07",
    "ColorTable08",
    "ColorTable09",
    "ColorTable10",
    "ColorTable11",
    "ColorTable12",
    "ColorTable13",
    "ColorTable14",
    "ColorTable15",
    "CtrlKeyShortcutsDisabled",
    "CursorColor",
    "CursorSize",
    "CursorType",
    "DefaultBackground",
    "DefaultForeground",
    "EnableColorSelection",
    "ExtendedEditKey",
    "ExtendedEditKeyCustom",
    "FaceName",
    "FilterOnPaste",
    "FontFamily",
    "FontSize",
    "FontWeight",
    "ForceV2",
    "HistoryBufferSize",
    "HistoryNoDup",
    "InsertMode",
    "LineSelection",
    "LineWrap",
    "LoadConIme",
    "NumberOfHistoryBuffers",
    "PopupColors",
    "QuickEdit",
    "ScreenBufferSize",
    "ScreenColors",
    "TerminalScrolling",
    "TrimLeadingZeros",
    "WindowAlpha",
    "WindowPosition",
    "WindowSize",
    "WordDelimiters",
];

/// Returns `true` if the value name is NOT in the documented `HKCU\Console`
/// allowlist — i.e. an unexpected value name that warrants investigation.
///
/// Comparison is case-insensitive (registry value names are case-insensitive
/// on Windows). An empty value name (the default unnamed value) is also
/// flagged: the legitimate Console key does not use it.
#[must_use]
pub fn is_suspicious_console_value_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    !CONSOLE_KNOWN_VALUE_NAMES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// Returns `true` if the registry path is a non-standard subkey directly
/// under `HKCU\Console` whose first segment is purely numeric (e.g.
/// `HKCU\Console\0\<md5_hash>` — the Valley RAT plugin store).
///
/// The legitimate Console key holds per-application subkeys whose names
/// are derived from the executable name (e.g. `cmd.exe` or
/// `%SystemRoot%_System32_cmd.exe`); a bare integer subkey is unique to
/// the Valley RAT layout. Comparison is case-insensitive (registry key
/// paths are case-insensitive on Windows).
#[must_use]
pub fn is_suspicious_console_subkey(key_path: &str) -> bool {
    const PREFIX: &str = "HKCU\\Console\\";
    if key_path.len() <= PREFIX.len() {
        return false;
    }
    if !key_path
        .get(..PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PREFIX))
    {
        return false;
    }
    let tail = &key_path[PREFIX.len()..];
    let first_segment = tail.split('\\').next().unwrap_or(tail);
    !first_segment.is_empty() && first_segment.chars().all(|c| c.is_ascii_digit())
}

// ── NTUSER.MAN mandatory-profile persistence ───────────────────────────────
//
// Per DeceptIQ (27 Dec 2025) and Carvey's grab-bag commentary, the mere
// existence of an `NTUSER.MAN` mandatory-profile hive is a high-confidence
// indicator of compromise outside kiosk/shared-workstation deployments.
// Windows loads `NTUSER.MAN` *instead of* `NTUSER.DAT`, so a planted
// `.MAN` bypasses EDR registry callbacks entirely.
//
// Source: https://deceptiq.com/blog/ntuser-man-registry-persistence
// Source: https://windowsir.blogspot.com/2026/01/grab-bag.html

/// Returns `true` if the file path's basename is exactly `NTUSER.MAN`
/// (case-insensitive — Windows file names are case-insensitive).
///
/// Caller is responsible for the kiosk/shared-workstation context check;
/// in environments not using mandatory profiles, any hit warrants
/// investigation.
#[must_use]
pub fn is_ntuser_man_path(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    base.eq_ignore_ascii_case("NTUSER.MAN")
}

/// Returns `true` if the COM handler DLL path for a Scheduled Task action is
/// outside the expected Windows system directories, indicating potential abuse.
///
/// # Detection
/// Legitimate built-in task COM handlers (e.g. RegIdleBackup → regidle.dll)
/// reside in `%SystemRoot%\System32`. An attacker abusing Scheduled Task COM
/// handler hijacking (T1053.005 + T1218) places a malicious DLL in a
/// user-writable path. The RegIdleBackup technique was observed in TA505/
/// GraceWire campaigns (Fox-IT/NCC Group report, 2021).
///
/// Match is case-insensitive; backslash and forward-slash normalized.
///
/// Source: <https://windowsir.blogspot.com/2022/12/why-i-love-regripper.html>
#[must_use]
pub fn is_task_com_handler_dll_suspicious(_dll_path: &str) -> bool {
    false // stub — implementation in GREEN commit
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
        assert!(is_suspicious_console_value_name(
            "d33f351a4aeea5e608853d1a56661059"
        ));
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

    // ── is_task_com_handler_dll_suspicious ────────────────────────────────────

    #[test]
    fn system32_dll_is_not_suspicious() {
        assert!(!is_task_com_handler_dll_suspicious(
            r"%SystemRoot%\System32\regidle.dll"
        ));
    }

    #[test]
    fn system32_dll_case_insensitive() {
        assert!(!is_task_com_handler_dll_suspicious(
            r"C:\WINDOWS\system32\DeviceDirectoryClient.dll"
        ));
    }

    #[test]
    fn syswow64_dll_is_not_suspicious() {
        assert!(!is_task_com_handler_dll_suspicious(
            r"%SystemRoot%\SysWOW64\example.dll"
        ));
    }

    #[test]
    fn temp_dir_dll_is_suspicious() {
        assert!(is_task_com_handler_dll_suspicious(
            r"C:\Users\bob\AppData\Local\Temp\evil.dll"
        ));
    }

    #[test]
    fn programdata_dll_is_suspicious() {
        assert!(is_task_com_handler_dll_suspicious(r"C:\ProgramData\payload.dll"));
    }

    #[test]
    fn empty_dll_path_is_not_flagged() {
        assert!(!is_task_com_handler_dll_suspicious(""));
    }
}
