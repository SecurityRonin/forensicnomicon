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
}
