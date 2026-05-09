//! Process, session, and Linux capability heuristics.

// ── Windows process heuristics ─────────────────────────────────────────────

/// Returns `true` if the PID is a valid Windows process ID.
/// Windows PIDs are always multiples of 4 and non-zero.
#[must_use]
pub fn is_valid_windows_pid(pid: u32) -> bool {
    pid != 0 && pid % 4 == 0
}

/// Returns `true` if the child process appears to have been created before its parent.
/// This is impossible under normal conditions and indicates PPID spoofing (T1134.004).
#[must_use]
pub fn is_child_born_before_parent(child_create_ns: i64, parent_create_ns: i64) -> bool {
    child_create_ns < parent_create_ns
}

// ── Windows logon type constants (Event ID 4624) ──────────────────────────

pub const LOGON_INTERACTIVE: u32 = 2;
pub const LOGON_NETWORK: u32 = 3;
pub const LOGON_BATCH: u32 = 4;
pub const LOGON_SERVICE: u32 = 5;
pub const LOGON_NETWORK_CLEARTEXT: u32 = 8;
pub const LOGON_NEW_CREDENTIALS: u32 = 9; // pass-the-hash / pass-the-ticket
pub const LOGON_REMOTE_INTERACTIVE: u32 = 10; // RDP

/// Returns `true` for network-originating logon types (lateral movement candidates).
#[must_use]
pub fn is_remote_logon(logon_type: u32) -> bool {
    matches!(
        logon_type,
        LOGON_NETWORK | LOGON_REMOTE_INTERACTIVE | LOGON_NETWORK_CLEARTEXT
    )
}

/// Returns `true` for logon types commonly used in lateral movement / credential abuse.
#[must_use]
pub fn is_lateral_movement_logon(logon_type: u32) -> bool {
    matches!(
        logon_type,
        LOGON_NEW_CREDENTIALS | LOGON_NETWORK | LOGON_NETWORK_CLEARTEXT
    )
}

/// Returns `true` if the Windows session ID indicates Session 0 (system/service, non-interactive).
#[must_use]
pub fn is_system_session(session_id: u32) -> bool {
    session_id == 0
}

/// Token elevation type 3 = full admin token (UAC bypassed or already elevated).
pub const TOKEN_ELEVATION_FULL: u32 = 3;

/// Returns `true` if the token elevation type indicates a fully elevated (admin) token.
#[must_use]
pub fn is_elevated_token(elevation_type: u32) -> bool {
    elevation_type == TOKEN_ELEVATION_FULL
}

// ── Windows OpenSSH / WinSCP lateral movement heuristics ─────────────────────

/// Domain string emitted by the Windows OpenSSH server (`sshd.exe`) in
/// Event ID 4624 records.
///
/// Per [Mari DeGrazia, *Detecting Lateral Movement with WinSCP*](https://az4n6.blogspot.com/2020/02/detecting-laterial-movment-with-winscp.html):
/// "The login is a type 5 with the account name sshd_1860 and the domain of
/// VIRTUAL USERS, and the process of sshd.exe."  This domain is created
/// automatically when OpenSSH Server is installed as a Windows optional
/// feature (Win 10 1809+, Server 2019+).  Seeing it in a 4624 record
/// identifies the logon as originating from an SSH client such as WinSCP.
pub const OPENSSH_VIRTUAL_USERS_DOMAIN: &str = "VIRTUAL USERS";

/// Returns `true` if `domain` matches the Windows OpenSSH server's synthetic
/// `VIRTUAL USERS` logon domain (case-insensitive).
///
/// Presence of this domain in a 4624 record indicates the logon was
/// authenticated by the Windows OpenSSH service rather than a normal
/// Windows authentication provider — a high-confidence indicator of
/// SSH-based lateral movement.
#[must_use]
pub fn is_openssh_virtual_users_domain(domain: &str) -> bool {
    domain.eq_ignore_ascii_case(OPENSSH_VIRTUAL_USERS_DOMAIN)
}

/// Returns `true` if the combination of `logon_type`, `domain`, and
/// `process_name` matches the Windows OpenSSH server pattern documented
/// for WinSCP-based lateral movement:
///
/// - `logon_type` == 5 (`LOGON_SERVICE`) — the service-level logon emitted
///   by `sshd.exe`
/// - `domain` == `"VIRTUAL USERS"` (case-insensitive)
/// - `process_name` == `"sshd.exe"` (case-insensitive)
///
/// All three must be true simultaneously; any partial match produces `false`.
///
/// # Source
/// [Mari DeGrazia, *Detecting Lateral Movement with WinSCP*](https://az4n6.blogspot.com/2020/02/detecting-laterial-movment-with-winscp.html)
#[must_use]
pub fn is_winscp_ssh_service_logon(logon_type: u32, domain: &str, process_name: &str) -> bool {
    logon_type == LOGON_SERVICE
        && is_openssh_virtual_users_domain(domain)
        && process_name.eq_ignore_ascii_case("sshd.exe")
}

// ── Linux process heuristics ────────────────────────────────────────────────

/// Suspicious PID gap: gaps larger than this in a sorted /proc PID list
/// suggest a rootkit is hiding processes.
pub const SUSPICIOUS_PID_GAP: u32 = 50;

/// Returns `true` if the sorted PID list contains a gap larger than `max_gap`.
/// A gap in consecutive /proc entries means processes were hidden.
#[must_use]
pub fn has_pid_gap(sorted_pids: &[u32], max_gap: u32) -> bool {
    sorted_pids
        .windows(2)
        .any(|w| w[1].saturating_sub(w[0]) > max_gap)
}

// Linux POSIX capability numbers (from linux/capability.h)
pub const CAP_DAC_OVERRIDE: u32 = 1; // bypass file permission checks
pub const CAP_NET_RAW: u32 = 13; // raw sockets / packet capture
pub const CAP_SYS_PTRACE: u32 = 19; // ptrace any process
pub const CAP_SYS_ADMIN: u32 = 21; // broad system administration

/// Capabilities that grant near-root privileges or forensic evasion ability.
pub const DANGEROUS_CAPS: &[u32] = &[CAP_DAC_OVERRIDE, CAP_NET_RAW, CAP_SYS_PTRACE, CAP_SYS_ADMIN];

/// Returns `true` if `cap` is in the dangerous capabilities list.
#[must_use]
pub fn is_dangerous_capability(cap: u32) -> bool {
    DANGEROUS_CAPS.contains(&cap)
}

// ── Registry-value command-line heuristics ────────────────────────────────────

/// Returns `true` if a Windows Run key value invokes PowerShell as a two-stage
/// stager — either by passing `-enc`/`-EncodedCommand` with a base64 payload, or
/// by calling `Get-ItemProperty`/`gp` to read the payload from a secondary
/// registry key.
///
/// This is the persistence pattern documented in az4n6 "Malicious PowerShell in
/// the Registry: Persistence" (2018-06-13): the Run key value holds a small
/// PowerShell stub that reads a base64-encoded payload stored in a separate,
/// non-standard registry key, then executes it via `-enc`.
///
/// The predicate is intentionally broad: both the two-key indirection pattern
/// **and** direct `-enc` invocations are flagged, since both represent obfuscated
/// PowerShell execution from autostart locations (T1547.001 + T1059.001 + T1027).
///
/// Comparison is case-insensitive.
#[must_use]
pub fn is_run_key_powershell_stager(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    // Must involve PowerShell at all.
    if !lower.contains("powershell") {
        return false;
    }
    // Two-stage: reads payload from another registry key.
    if lower.contains("get-itemproperty") || lower.contains("(gp ") || lower.contains("(gp\t") {
        return true;
    }
    // Direct encoded payload: -enc or -encodedcommand flag present.
    if lower.contains(" -enc ") || lower.contains(" -enc\t") || lower.contains("-encodedcommand") {
        return true;
    }
    false
}

/// Returns `true` if a registry value's data string contains `%COMSPEC%`.
///
/// `%COMSPEC%` expands to the full path of `cmd.exe` at runtime. Attackers
/// use this environment-variable form in registry persistence values (Run keys,
/// `cmd.exe` AutoRun, etc.) to evade static string matching that looks for the
/// literal path `C:\Windows\System32\cmd.exe`.
///
/// Documented as a triage search technique in az4n6 "Malicious PowerShell in
/// the Registry: Persistence" (2018-06-13): searching all loaded hives for
/// `%COMSPEC%` surfaces suspicious persistence entries.
///
/// Comparison is case-insensitive (registry value data is not case-normalised).
#[must_use]
pub fn is_comspec_in_registry_value(value: &str) -> bool {
    value.to_lowercase().contains("%comspec%")
}

/// Returns `true` if a service `ImagePath` / binPath string contains indicators
/// of compression-stacked PowerShell obfuscation.
///
/// Attackers embed gzip-compressed, base64-encoded payloads directly in the
/// `ImagePath` of a Windows service (visible in Event ID 7045 `Service File Name`
/// field and in `HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath`).
/// The giveaway strings are references to the .NET GZip or Deflate stream classes
/// used to decompress the payload at runtime:
///
/// - `GzipStream` — the .NET `System.IO.Compression.GzipStream` class
/// - `[IO.Compression.CompressionMode]` — the Deflate-mode enum reference
///   (also appears as `[IO.Compression.GzipStream]` or similar)
///
/// Both patterns are documented as triage search terms by Mari DeGrazia in
/// [*Finding and Decoding Malicious PowerShell Scripts*](https://az4n6.blogspot.com/2017/10/finding-and-decoding-malicious.html):
/// "Look for 'Gzipstream' or '\[IO.Compression.CompressionMode\]::Decompress'
/// for hints on what type of compression was used."
///
/// Comparison is case-insensitive.
#[must_use]
pub fn is_service_binpath_compression_obfuscated(_binpath: &str) -> bool {
    false // RED: stub — implementation pending
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_windows_pid_4() {
        assert!(is_valid_windows_pid(4));
    }

    #[test]
    fn valid_windows_pid_1000() {
        assert!(is_valid_windows_pid(1000));
    }

    #[test]
    fn invalid_windows_pid_zero() {
        assert!(!is_valid_windows_pid(0));
    }

    #[test]
    fn invalid_windows_pid_odd() {
        assert!(!is_valid_windows_pid(1001));
    }

    #[test]
    fn child_born_before_parent_returns_true() {
        assert!(is_child_born_before_parent(100, 200));
    }

    #[test]
    fn child_born_after_parent_returns_false() {
        assert!(!is_child_born_before_parent(200, 100));
    }

    #[test]
    fn child_same_time_as_parent_returns_false() {
        assert!(!is_child_born_before_parent(100, 100));
    }

    #[test]
    fn remote_logon_network() {
        assert!(is_remote_logon(LOGON_NETWORK));
    }

    #[test]
    fn remote_logon_rdp() {
        assert!(is_remote_logon(LOGON_REMOTE_INTERACTIVE));
    }

    #[test]
    fn remote_logon_cleartext() {
        assert!(is_remote_logon(LOGON_NETWORK_CLEARTEXT));
    }

    #[test]
    fn interactive_logon_is_not_remote() {
        assert!(!is_remote_logon(LOGON_INTERACTIVE));
    }

    #[test]
    fn lateral_movement_new_credentials() {
        assert!(is_lateral_movement_logon(LOGON_NEW_CREDENTIALS));
    }

    #[test]
    fn lateral_movement_network() {
        assert!(is_lateral_movement_logon(LOGON_NETWORK));
    }

    #[test]
    fn service_logon_is_not_lateral() {
        assert!(!is_lateral_movement_logon(LOGON_SERVICE));
    }

    #[test]
    fn system_session_zero() {
        assert!(is_system_session(0));
    }

    #[test]
    fn user_session_one() {
        assert!(!is_system_session(1));
    }

    #[test]
    fn elevated_token_type_3() {
        assert!(is_elevated_token(TOKEN_ELEVATION_FULL));
    }

    #[test]
    fn non_elevated_token_type_1() {
        assert!(!is_elevated_token(1));
    }

    #[test]
    fn pid_gap_detected() {
        // gap between 2 and 100 is 98, > 50
        assert!(has_pid_gap(&[1, 2, 100, 101], 50));
    }

    #[test]
    fn pid_gap_not_detected_small_gaps() {
        assert!(!has_pid_gap(&[1, 2, 3, 4], 50));
    }

    #[test]
    fn pid_gap_empty_slice() {
        assert!(!has_pid_gap(&[], 50));
    }

    #[test]
    fn dangerous_cap_sys_admin() {
        assert!(is_dangerous_capability(CAP_SYS_ADMIN));
    }

    #[test]
    fn dangerous_cap_net_raw() {
        assert!(is_dangerous_capability(CAP_NET_RAW));
    }

    #[test]
    fn non_dangerous_cap_chown() {
        // CAP_CHOWN = 0
        assert!(!is_dangerous_capability(0));
    }

    // ── is_openssh_virtual_users_domain ──────────────────────────────────────

    #[test]
    fn virtual_users_domain_matches() {
        // Per az4n6.blogspot.com/2020/02/detecting-laterial-movment-with-winscp.html:
        // Windows OpenSSH server emits 4624 events with domain "VIRTUAL USERS".
        assert!(is_openssh_virtual_users_domain("VIRTUAL USERS"));
    }

    #[test]
    fn virtual_users_domain_case_insensitive() {
        assert!(is_openssh_virtual_users_domain("virtual users"));
        assert!(is_openssh_virtual_users_domain("Virtual Users"));
    }

    #[test]
    fn normal_domain_not_virtual_users() {
        assert!(!is_openssh_virtual_users_domain("WORKGROUP"));
        assert!(!is_openssh_virtual_users_domain("CORP"));
        assert!(!is_openssh_virtual_users_domain("NT AUTHORITY"));
    }

    #[test]
    fn empty_domain_not_virtual_users() {
        assert!(!is_openssh_virtual_users_domain(""));
    }

    // ── is_winscp_ssh_service_logon ───────────────────────────────────────────

    #[test]
    fn winscp_ssh_logon_type5_virtual_users_sshd() {
        // The exact combination the blog describes: 4624 type 5, VIRTUAL USERS, sshd.exe.
        assert!(is_winscp_ssh_service_logon(5, "VIRTUAL USERS", "sshd.exe"));
    }

    #[test]
    fn winscp_ssh_logon_process_case_insensitive() {
        assert!(is_winscp_ssh_service_logon(5, "VIRTUAL USERS", "SSHD.EXE"));
        assert!(is_winscp_ssh_service_logon(5, "VIRTUAL USERS", "Sshd.Exe"));
    }

    #[test]
    fn winscp_ssh_logon_wrong_type_not_flagged() {
        // Type 3 (network) with same domain/process is NOT the OpenSSH service pattern.
        assert!(!is_winscp_ssh_service_logon(3, "VIRTUAL USERS", "sshd.exe"));
    }

    #[test]
    fn winscp_ssh_logon_wrong_domain_not_flagged() {
        assert!(!is_winscp_ssh_service_logon(5, "CORP", "sshd.exe"));
    }

    #[test]
    fn winscp_ssh_logon_wrong_process_not_flagged() {
        assert!(!is_winscp_ssh_service_logon(5, "VIRTUAL USERS", "lsass.exe"));
    }

    // ── is_run_key_powershell_stager ──────────────────────────────────────────

    #[test]
    fn run_key_get_item_property_stager_detected() {
        // Typical two-stage: powershell reads payload from another registry key.
        let cmd = r"powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -enc (Get-ItemProperty HKLM:\Software\hztGpoWa).hztGpoWa";
        assert!(is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_gp_shorthand_stager_detected() {
        // (gp ...) is common shorthand for Get-ItemProperty.
        let cmd = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -enc (gp HKLM:\software\payload).data";
        assert!(is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_powershell_encoded_command_detected() {
        // Direct -EncodedCommand stager (no Get-ItemProperty — still a PS stager).
        let cmd = "powershell -EncodedCommand JABjAG0AZAAgAD0AIAB7AHsAaQBuAHYAbwBrAGUALQBtAGkAbQBpAGsAYQB0AHoAfQB9";
        assert!(is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_powershell_enc_short_flag_detected() {
        let cmd = "powershell.exe -nop -w hidden -enc SQBFAFgA";
        assert!(is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_normal_powershell_not_stager() {
        // Legitimate-looking PS invocation without obfuscation or payload read.
        let cmd = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File C:\scripts\backup.ps1";
        assert!(!is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_non_powershell_not_stager() {
        let cmd = r"C:\Program Files\SomeApp\app.exe --start";
        assert!(!is_run_key_powershell_stager(cmd));
    }

    #[test]
    fn run_key_empty_value_not_stager() {
        assert!(!is_run_key_powershell_stager(""));
    }

    // ── is_comspec_in_registry_value ─────────────────────────────────────────

    #[test]
    fn comspec_uppercase_detected() {
        let value = r"%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -enc SQBFAFgA";
        assert!(is_comspec_in_registry_value(value));
    }

    #[test]
    fn comspec_lowercase_detected() {
        // Registry string comparison should be case-insensitive.
        let value = r"%comspec% /c powershell -enc SQBFAFgA";
        assert!(is_comspec_in_registry_value(value));
    }

    #[test]
    fn comspec_mixed_case_detected() {
        let value = r"%ComSpec% /c cmd /c start";
        assert!(is_comspec_in_registry_value(value));
    }

    #[test]
    fn value_without_comspec_not_flagged() {
        let value = r"C:\Windows\system32\cmd.exe /c start";
        assert!(!is_comspec_in_registry_value(value));
    }

    #[test]
    fn empty_value_not_flagged_comspec() {
        assert!(!is_comspec_in_registry_value(""));
    }

    // ── is_service_binpath_compression_obfuscated ─────────────────────────────

    #[test]
    fn binpath_gzipstream_detected() {
        // Typical pattern: PS decoder uses System.IO.Compression.GzipStream inline.
        // Per az4n6.blogspot.com/2017/10/finding-and-decoding-malicious.html:
        // look for "Gzipstream" as a triage indicator.
        let binpath = r"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAHoAaQBwAFMAdAByAGUAYQBtACAAJABtACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkA";
        assert!(is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_gzipstream_case_insensitive() {
        // Mixed-case variant — registry data is not normalised.
        let binpath = "%COMSPEC% /c powershell -enc ... GZIPStream ...";
        assert!(is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_io_compression_compressionmode_detected() {
        // Deflate-mode pattern: [IO.Compression.CompressionMode]::Decompress
        // Per az4n6 post: look for "[IO.Compression.CompressionMode]::Decompress".
        let binpath = r"%COMSPEC% /c powershell -nop [IO.Compression.CompressionMode]::Decompress";
        assert!(is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_io_compression_gzipstream_class_detected() {
        // Inline class reference: [IO.Compression.GzipStream]
        let binpath = r"%COMSPEC% /c powershell -nop [IO.Compression.GzipStream]";
        assert!(is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_plain_base64_only_not_compression_flagged() {
        // Plain -EncodedCommand without any compression indicator is NOT flagged
        // by this predicate (is_run_key_powershell_stager handles that case).
        let binpath = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -enc SQBFAFgA";
        assert!(!is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_legitimate_service_not_flagged() {
        let binpath = r"C:\Windows\System32\svchost.exe -k netsvcs";
        assert!(!is_service_binpath_compression_obfuscated(binpath));
    }

    #[test]
    fn binpath_empty_not_flagged_compression() {
        assert!(!is_service_binpath_compression_obfuscated(""));
    }
}
