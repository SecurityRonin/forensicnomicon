/// Returns `true` if `path` is a trusted Windows system library directory (case-insensitive).
///
/// Sources:
/// - Microsoft — Windows file system layout:
///   <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>
/// - SANS DFIR — DLL hijacking and masquerading detection:
///   <https://www.sans.org/blog/defense-spotlight-finding-dll-hijack-attempts/>
/// - MITRE ATT&CK T1574.001 — DLL Search Order Hijacking:
///   <https://attack.mitre.org/techniques/T1574/001/>
pub fn is_trusted_windows_lib_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("system32")
        || lower.contains("syswow64")
        || lower.contains("winsxs")
        || lower.contains("windows\\system")
        || lower.contains("program files\\windows defender")
}

/// Returns `true` if `path` is a trusted Linux system library directory.
///
/// Sources:
/// - Filesystem Hierarchy Standard (FHS) 3.0 — canonical Linux directory layout:
///   <https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html>
/// - MITRE ATT&CK T1574.006 — Dynamic Linker Hijacking:
///   <https://attack.mitre.org/techniques/T1574/006/>
pub fn is_trusted_linux_lib_path(path: &str) -> bool {
    path.starts_with("/lib")
        || path.starts_with("/lib64")
        || path.starts_with("/usr/lib")
        || path.starts_with("/usr/lib64")
        || path.starts_with("/usr/local/lib")
}

/// Returns `true` if `path` refers to a temp/scratch directory commonly abused by malware.
///
/// Sources:
/// - MITRE ATT&CK T1036.005 — Match Legitimate Name or Location:
///   <https://attack.mitre.org/techniques/T1036/005/>
/// - Red Canary — dropper staging from temp directories:
///   <https://redcanary.com/blog/threat-intelligence/staging-directories/>
/// - SANS FOR508 course material — malware staging paths (temp directory abuse)
pub fn is_suspicious_temp_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("/tmp/")
        || lower.contains("\\appdata\\local\\temp")
        || lower.contains("%temp%")
        || lower.contains("%tmp%")
}

/// Returns `true` if `path` is a known attacker staging location beyond `/tmp` and `%TEMP%`.
///
/// Sources:
/// - Red Canary — "Staging directories" dropper research (C:\Users\Public\, C:\ProgramData\):
///   <https://redcanary.com/blog/threat-intelligence/staging-directories/>
/// - MITRE ATT&CK T1036.005 — Match Legitimate Name or Location:
///   <https://attack.mitre.org/techniques/T1036/005/>
/// - SANS FOR508 — common attacker staging paths
pub fn is_suspicious_staging_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("/tmp/")
        || lower.contains("/dev/shm/")
        || lower.contains("\\appdata\\local\\temp")
        || lower.contains("%temp%")
        || lower.contains("%tmp%")
        || lower.contains("\\users\\public\\")
        || lower.contains("\\programdata\\")
        || lower.contains("c:\\perflogs\\")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("\\recycler\\")
        || lower.contains("\\$recycle.bin\\")
        || lower.contains("c:\\intel\\")
        || lower.contains("c:\\dell\\")
        || lower.contains("\\windows\\debug\\")
}

/// Returns `true` if `path` falls in a directory commonly abused for DLL hijacking.
///
/// Sources:
/// - MITRE ATT&CK T1574.001 — DLL Search Order Hijacking:
///   <https://attack.mitre.org/techniques/T1574/001/>
/// - SANS — "Defense Spotlight: Finding DLL Hijack Attempts":
///   <https://www.sans.org/blog/defense-spotlight-finding-dll-hijack-attempts/>
/// - Mandiant — "DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry":
///   <https://www.mandiant.com/resources/blog/dll-side-loading-thorn-in-side-of-anti-virus-industry>
pub fn is_hijackable_dll_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\current directory\\")
        || (lower.contains("\\users\\") && lower.ends_with(".dll"))
        || (lower.contains("\\appdata\\") && lower.ends_with(".dll"))
        || (lower.contains("\\downloads\\") && lower.ends_with(".dll"))
        || (lower.contains("\\desktop\\") && lower.ends_with(".dll"))
        || (lower.contains("\\temp\\") && lower.ends_with(".dll"))
        || (lower.contains("c:\\programdata\\") && lower.ends_with(".dll"))
        || (lower.contains("c:\\users\\public\\") && lower.ends_with(".dll"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_trusted_windows_lib_path ---
    #[test]
    fn trusts_system32_lowercase() {
        assert!(is_trusted_windows_lib_path(
            r"C:\Windows\System32\ntdll.dll"
        ));
    }

    #[test]
    fn trusts_syswow64_mixed_case() {
        assert!(is_trusted_windows_lib_path(
            r"C:\Windows\SysWOW64\kernel32.dll"
        ));
    }

    #[test]
    fn trusts_winsxs() {
        assert!(is_trusted_windows_lib_path(r"C:\Windows\WinSxS\foo.dll"));
    }

    #[test]
    fn trusts_program_files_defender() {
        assert!(is_trusted_windows_lib_path(
            r"C:\Program Files\Windows Defender\MpSvc.dll"
        ));
    }

    #[test]
    fn untrusts_temp_path() {
        assert!(!is_trusted_windows_lib_path(
            r"C:\Users\user\AppData\Local\Temp\evil.dll"
        ));
    }

    #[test]
    fn untrusts_random_path() {
        assert!(!is_trusted_windows_lib_path(
            r"C:\Users\user\Downloads\payload.dll"
        ));
    }

    // --- is_trusted_linux_lib_path ---
    #[test]
    fn trusts_lib64() {
        assert!(is_trusted_linux_lib_path("/lib64/libc.so.6"));
    }

    #[test]
    fn trusts_usr_lib() {
        assert!(is_trusted_linux_lib_path(
            "/usr/lib/x86_64-linux-gnu/libssl.so"
        ));
    }

    #[test]
    fn trusts_usr_local_lib() {
        assert!(is_trusted_linux_lib_path("/usr/local/lib/libfoo.so"));
    }

    #[test]
    fn untrusts_tmp() {
        assert!(!is_trusted_linux_lib_path("/tmp/evil.so"));
    }

    #[test]
    fn untrusts_home_dir() {
        assert!(!is_trusted_linux_lib_path("/home/user/evil.so"));
    }

    // --- is_suspicious_temp_path ---
    #[test]
    fn flags_windows_temp() {
        assert!(is_suspicious_temp_path(r"C:\Windows\Temp\dropper.exe"));
    }

    #[test]
    fn flags_appdata_local_temp() {
        assert!(is_suspicious_temp_path(
            r"C:\Users\user\AppData\Local\Temp\x.exe"
        ));
    }

    #[test]
    fn flags_linux_tmp() {
        assert!(is_suspicious_temp_path("/tmp/payload.sh"));
    }

    #[test]
    fn flags_percent_temp_env() {
        assert!(is_suspicious_temp_path("%TEMP%\\stager.exe"));
    }

    #[test]
    fn does_not_flag_system32() {
        assert!(!is_suspicious_temp_path(r"C:\Windows\System32\calc.exe"));
    }

    // Edge: empty string
    #[test]
    fn empty_string_not_suspicious() {
        assert!(!is_suspicious_temp_path(""));
    }

    // --- is_suspicious_staging_path ---
    #[test]
    fn flags_dev_shm() {
        assert!(is_suspicious_staging_path("/dev/shm/payload.sh"));
    }
    #[test]
    fn flags_users_public() {
        assert!(is_suspicious_staging_path(r"C:\Users\Public\stager.exe"));
    }
    #[test]
    fn flags_programdata() {
        assert!(is_suspicious_staging_path(r"C:\ProgramData\update.exe"));
    }
    #[test]
    fn flags_windows_tasks() {
        assert!(is_suspicious_staging_path(r"C:\Windows\Tasks\evil.exe"));
    }
    #[test]
    fn flags_recycle_bin() {
        assert!(is_suspicious_staging_path(r"C:\$Recycle.Bin\evil.exe"));
    }
    #[test]
    fn flags_windows_temp_staging() {
        assert!(is_suspicious_staging_path(r"C:\Windows\Temp\dropper.exe"));
    }
    #[test]
    fn does_not_flag_program_files() {
        assert!(!is_suspicious_staging_path(
            r"C:\Program Files\MyApp\app.exe"
        ));
    }
    #[test]
    fn does_not_flag_system32_staging() {
        assert!(!is_suspicious_staging_path(
            r"C:\Windows\System32\svchost.exe"
        ));
    }
    #[test]
    fn empty_string_not_staging_path() {
        assert!(!is_suspicious_staging_path(""));
    }

    // --- is_hijackable_dll_path ---
    #[test]
    fn flags_dll_in_users_dir() {
        assert!(is_hijackable_dll_path(
            r"C:\Users\victim\Documents\version.dll"
        ));
    }
    #[test]
    fn flags_dll_in_appdata() {
        assert!(is_hijackable_dll_path(
            r"C:\Users\victim\AppData\Roaming\evil.dll"
        ));
    }
    #[test]
    fn flags_dll_in_downloads() {
        assert!(is_hijackable_dll_path(
            r"C:\Users\victim\Downloads\dbghelp.dll"
        ));
    }
    #[test]
    fn flags_dll_in_programdata() {
        assert!(is_hijackable_dll_path(r"C:\ProgramData\Temp\hijack.dll"));
    }
    #[test]
    fn flags_dll_in_temp() {
        assert!(is_hijackable_dll_path(r"C:\Windows\Temp\evil.dll"));
    }
    #[test]
    fn does_not_flag_system32_dll() {
        assert!(!is_hijackable_dll_path(r"C:\Windows\System32\ntdll.dll"));
    }
    #[test]
    fn does_not_flag_exe_in_appdata() {
        assert!(!is_hijackable_dll_path(
            r"C:\Users\victim\AppData\Local\app.exe"
        ));
    }
    #[test]
    fn empty_string_not_hijackable() {
        assert!(!is_hijackable_dll_path(""));
    }
}
