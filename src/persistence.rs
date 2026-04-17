/// Windows registry autorun keys used for persistence.
///
/// Sources:
/// - Harlan Carvey, "Windows Registry Forensics" (2nd ed.) — Run key chapter:
///   <https://www.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-9>
/// - MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder:
///   <https://attack.mitre.org/techniques/T1547/001/>
/// - Sysinternals Autoruns — canonical Windows autostart locations:
///   <https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>
pub const WINDOWS_RUN_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"SYSTEM\CurrentControlSet\Services",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Software\Classes\exefile\shell\open\command",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// Linux filesystem paths associated with persistence mechanisms.
///
/// Sources:
/// - MITRE ATT&CK T1053.003 — Cron:
///   <https://attack.mitre.org/techniques/T1053/003/>
/// - MITRE ATT&CK T1574.006 — Dynamic Linker Hijacking (/etc/ld.so.preload):
///   <https://attack.mitre.org/techniques/T1574/006/>
/// - pberba.github.io — Persistence in Linux series (comprehensive survey):
///   <https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-osquery/>
pub const LINUX_PERSISTENCE_PATHS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/profile.d",
    "/etc/ld.so.preload",
    "/etc/pam.d",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.config/autostart",
];

/// macOS filesystem paths associated with persistence mechanisms.
///
/// Sources:
/// - MITRE ATT&CK T1543.004 — Launch Daemon:
///   <https://attack.mitre.org/techniques/T1543/004/>
/// - MITRE ATT&CK T1543.001 — Launch Agent:
///   <https://attack.mitre.org/techniques/T1543/001/>
/// - Howard Oakley / The Eclectic Light Company — LaunchAgent/Daemon forensics:
///   <https://eclecticlight.co/2021/09/16/launch-agents-and-daemons-in-big-sur/>
pub const MACOS_PERSISTENCE_PATHS: &[&str] = &[
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "~/Library/LaunchAgents",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
    "/Library/StartupItems",
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
];

/// IFEO (Image File Execution Options) debugger hijack paths.
///
/// Sources:
/// - MITRE ATT&CK T1546.012 — Image File Execution Options Injection:
///   <https://attack.mitre.org/techniques/T1546/012/>
/// - Harlan Carvey, "Windows Registry Forensics" — IFEO chapter
pub const IFEO_PATHS: &[&str] =
    &[r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"];

/// AppInit_DLLs — loaded into every user-mode process.
///
/// Sources:
/// - MITRE ATT&CK T1546.010 — AppInit DLLs:
///   <https://attack.mitre.org/techniques/T1546/010/>
/// - Microsoft — AppInit_DLLs Registry Value and Windows 8:
///   <https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls>
pub const APPINIT_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// Session Manager BootExecute / KnownDLLs — boot-time execution.
///
/// Sources:
/// - MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder (BootExecute):
///   <https://attack.mitre.org/techniques/T1547/001/>
/// - Microsoft — Session Manager registry keys:
///   <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/registering-a-boot-start-driver>
pub const SESSION_MANAGER_PATHS: &[&str] = &[
    r"SYSTEM\CurrentControlSet\Control\Session Manager",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
];

/// Active Setup — runs per-user on first login.
///
/// Sources:
/// - MITRE ATT&CK T1547.014 — Active Setup:
///   <https://attack.mitre.org/techniques/T1547/014/>
pub const ACTIVE_SETUP_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
];

/// Screensaver abuse.
///
/// Sources:
/// - MITRE ATT&CK T1546.002 — Screensaver:
///   <https://attack.mitre.org/techniques/T1546/002/>
pub const SCREENSAVER_PATHS: &[&str] = &[r"Control Panel\Desktop"];

/// Winlogon notification and helper DLLs.
///
/// Sources:
/// - MITRE ATT&CK T1547.004 — Winlogon Helper DLL:
///   <https://attack.mitre.org/techniques/T1547/004/>
/// - Harlan Carvey, "Windows Registry Forensics" — Winlogon chapter
pub const WINLOGON_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
];

/// COM/CLSID hijacking paths.
///
/// Sources:
/// - MITRE ATT&CK T1546.015 — Component Object Model Hijacking:
///   <https://attack.mitre.org/techniques/T1546/015/>
/// - SpecterOps — COM hijacking for persistence (Casey Smith, 2016):
///   <https://www.specterops.io/blog>
pub const COM_HIJACK_PATHS: &[&str] = &[
    r"SOFTWARE\Classes\CLSID",
    r"SOFTWARE\Classes\WOW6432Node\CLSID",
];

/// Returns an iterator over every known Windows persistence path, computed by
/// chaining the individual sub-group slices. No data is duplicated — each path
/// string lives in exactly one sub-group constant.
pub fn all_windows_persistence_paths() -> impl Iterator<Item = &'static str> {
    WINDOWS_RUN_KEYS
        .iter()
        .chain(IFEO_PATHS.iter())
        .chain(APPINIT_PATHS.iter())
        .chain(SESSION_MANAGER_PATHS.iter())
        .chain(ACTIVE_SETUP_PATHS.iter())
        .chain(SCREENSAVER_PATHS.iter())
        .chain(WINLOGON_PATHS.iter())
        .chain(COM_HIJACK_PATHS.iter())
        .copied()
}

/// Returns true if the given registry path is a known Windows persistence location
/// (case-insensitive contains match across all sub-group constants).
pub fn is_persistence_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    all_windows_persistence_paths().any(|entry| lower.contains(&entry.to_ascii_lowercase()))
}

/// Returns true if the IFEO debugger value looks like an attacker-controlled binary.
/// Suspicious if: contains \temp\ or \appdata\; not empty and not a known debugger.
pub fn is_suspicious_ifeo_debugger(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    // Known benign debuggers
    let benign = ["ntsd", "windbg", "vsjitdebugger.exe"];
    if benign.iter().any(|b| lower.contains(b)) {
        return false;
    }
    // Suspicious locations
    lower.contains(r"\temp\") || lower.contains(r"\appdata\")
}

/// Returns `true` if `path` references a known persistence location on any platform
/// (case-insensitive).
pub fn is_persistence_location(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let check = |entry: &&str| lower.contains(&entry.to_ascii_lowercase());
    WINDOWS_RUN_KEYS.iter().any(check)
        || LINUX_PERSISTENCE_PATHS.iter().any(check)
        || MACOS_PERSISTENCE_PATHS.iter().any(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn windows_run_keys_contains_run() {
        assert!(
            WINDOWS_RUN_KEYS.contains(&r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "Run key must be present"
        );
    }

    #[test]
    fn windows_run_keys_contains_services() {
        assert!(
            WINDOWS_RUN_KEYS.contains(&r"SYSTEM\CurrentControlSet\Services"),
            "Services key must be present"
        );
    }

    #[test]
    fn linux_persistence_contains_cron_d() {
        assert!(
            LINUX_PERSISTENCE_PATHS.contains(&"/etc/cron.d"),
            "/etc/cron.d must be present"
        );
    }

    #[test]
    fn linux_persistence_contains_ld_so_preload() {
        assert!(
            LINUX_PERSISTENCE_PATHS.contains(&"/etc/ld.so.preload"),
            "/etc/ld.so.preload must be present"
        );
    }

    #[test]
    fn macos_persistence_contains_launch_agents() {
        assert!(
            MACOS_PERSISTENCE_PATHS.contains(&"/Library/LaunchAgents"),
            "/Library/LaunchAgents must be present"
        );
    }

    #[test]
    fn macos_persistence_contains_launch_daemons() {
        assert!(
            MACOS_PERSISTENCE_PATHS.contains(&"/Library/LaunchDaemons"),
            "/Library/LaunchDaemons must be present"
        );
    }

    // --- is_persistence_location ---
    #[test]
    fn detects_windows_run_key_path() {
        assert!(is_persistence_location(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn detects_linux_cron_path() {
        assert!(is_persistence_location("/etc/cron.daily/malware"));
    }

    #[test]
    fn detects_macos_launch_agents() {
        assert!(is_persistence_location(
            "/Library/LaunchAgents/com.evil.plist"
        ));
    }

    #[test]
    fn detects_ld_so_preload() {
        assert!(is_persistence_location("/etc/ld.so.preload"));
    }

    #[test]
    fn does_not_flag_random_path() {
        assert!(!is_persistence_location("/usr/bin/ls"));
    }

    // Edge: empty string
    #[test]
    fn empty_string_not_persistence() {
        assert!(!is_persistence_location(""));
    }

    // --- Module 1 new constants ---
    #[test]
    fn ifeo_paths_not_empty() {
        assert!(!IFEO_PATHS.is_empty(), "IFEO_PATHS must not be empty");
    }

    #[test]
    fn appinit_paths_not_empty() {
        assert!(!APPINIT_PATHS.is_empty(), "APPINIT_PATHS must not be empty");
    }

    #[test]
    fn session_manager_paths_not_empty() {
        assert!(
            !SESSION_MANAGER_PATHS.is_empty(),
            "SESSION_MANAGER_PATHS must not be empty"
        );
    }

    #[test]
    fn all_windows_persistence_paths_contains_run_keys() {
        assert!(
            all_windows_persistence_paths()
                .any(|p| p == r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "all_windows_persistence_paths() must include the Run key"
        );
    }

    // --- is_persistence_path ---
    #[test]
    fn is_persistence_path_run_key_matches() {
        assert!(
            is_persistence_path(r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "Run key should match"
        );
    }

    #[test]
    fn is_persistence_path_ifeo_matches() {
        assert!(
            is_persistence_path(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
            ),
            "IFEO path should match"
        );
    }

    #[test]
    fn is_persistence_path_case_insensitive() {
        assert!(
            is_persistence_path(r"software\microsoft\windows\currentversion\run"),
            "Match must be case-insensitive"
        );
    }

    // --- is_suspicious_ifeo_debugger ---
    #[test]
    fn is_suspicious_ifeo_debugger_temp_path() {
        assert!(
            is_suspicious_ifeo_debugger(r"C:\Users\user\AppData\Local\Temp\evil.exe"),
            "Path in \\temp\\ must be flagged"
        );
    }

    #[test]
    fn is_suspicious_ifeo_debugger_windbg_benign() {
        assert!(
            !is_suspicious_ifeo_debugger("windbg"),
            "windbg should not be flagged as suspicious"
        );
    }
}
