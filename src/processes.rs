/// Legitimate Windows process names commonly masqueraded by attackers.
pub const WINDOWS_MASQUERADE_TARGETS: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "conhost.exe",
    "wermgr.exe",
    "services.exe",
    "winlogon.exe",
    "smss.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "system",
    "registry",
];

/// Well-known malware / offensive-tool process names.
pub const KNOWN_MALWARE_PROCESS_NAMES: &[&str] = &[
    "xmrig",
    "mimikatz",
    "meterpreter",
    "beacon",
    "empire",
    "cobaltstrike",
    "ngrok",
    "frp",
    "chisel",
    "ligolo",
    "sliver",
    "havoc",
    "brute",
    "pwncat",
    "reptile",
    "diamorphine",
];

/// Returns `true` if `name` is a high-value masquerade target (case-insensitive).
pub fn is_masquerade_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_MASQUERADE_TARGETS
        .iter()
        .any(|t| t.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known malware process name (case-insensitive).
pub fn is_known_malware_process(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    KNOWN_MALWARE_PROCESS_NAMES
        .iter()
        .any(|t| t.to_ascii_lowercase() == lower)
}

/// Well-known credential access / password harvesting tool names.
///
/// Sources:
/// - MITRE ATT&CK T1003 — OS Credential Dumping:
///   <https://attack.mitre.org/techniques/T1003/>
/// - Mandiant — "Mimikatz Overview, Defenses and Detection" (Mar 2021):
///   <https://www.mandiant.com/resources/blog/mimikatz-detections>
pub const CREDENTIAL_ACCESS_TOOLS: &[&str] = &[
    "mimikatz",
    "mimikatz.exe",
    "pypykatz",
    "pypykatz.exe",
    "wce",
    "wce.exe",
    "gsecdump",
    "gsecdump.exe",
    "fgdump",
    "fgdump.exe",
    "pwdump",
    "pwdump7",
    "pwdump7.exe",
    "secretsdump",
    "impacket-secretsdump",
    "invoke-mimikatz",
    "crackmapexec",
    "cme",
    "lsassy",
    "procdump",
    "procdump64",
    "procdump.exe",
    "procdump64.exe",
];

/// Process names and DLLs known to access the LSASS process memory.
///
/// Sources:
/// - MITRE ATT&CK T1003.001 — LSASS Memory:
///   <https://attack.mitre.org/techniques/T1003/001/>
/// - Elastic Security — "Credential Access via LSASS" detection rule:
///   <https://www.elastic.co/guide/en/security/current/credential-access-via-lsass-memory-dump.html>
/// - Microsoft — Windows Defender credential guard and LSASS protection
pub const LSASS_ACCESS_TOOLS: &[&str] = &[
    "procdump",
    "procdump64",
    "procdump.exe",
    "procdump64.exe",
    "comsvcs.dll",
    "werfault.exe",
    "sqldumper.exe",
    "lsassy",
    "nanodump",
    "handlekatz",
    "rdrleakdiag.exe",
    "out-minidump",
];

/// Returns `true` if `name` matches a known credential-access tool (case-insensitive).
pub fn is_credential_access_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_ACCESS_TOOLS
        .iter()
        .any(|t| t.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a tool known to access LSASS memory (case-insensitive).
pub fn is_lsass_access_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LSASS_ACCESS_TOOLS
        .iter()
        .any(|t| t.to_ascii_lowercase() == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constant membership ---
    #[test]
    fn masquerade_targets_contains_svchost() {
        assert!(WINDOWS_MASQUERADE_TARGETS.contains(&"svchost.exe"));
    }

    #[test]
    fn masquerade_targets_contains_lsass() {
        assert!(WINDOWS_MASQUERADE_TARGETS.contains(&"lsass.exe"));
    }

    #[test]
    fn malware_names_contains_mimikatz() {
        assert!(KNOWN_MALWARE_PROCESS_NAMES.contains(&"mimikatz"));
    }

    #[test]
    fn malware_names_contains_xmrig() {
        assert!(KNOWN_MALWARE_PROCESS_NAMES.contains(&"xmrig"));
    }

    // --- is_masquerade_target ---
    #[test]
    fn detects_svchost_lowercase() {
        assert!(is_masquerade_target("svchost.exe"));
    }

    #[test]
    fn detects_lsass_uppercase() {
        assert!(is_masquerade_target("LSASS.EXE"));
    }

    #[test]
    fn detects_explorer_mixed_case() {
        assert!(is_masquerade_target("Explorer.exe"));
    }

    #[test]
    fn does_not_flag_random_process() {
        assert!(!is_masquerade_target("mygame.exe"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_masquerade_target() {
        assert!(!is_masquerade_target(""));
    }

    // --- is_known_malware_process ---
    #[test]
    fn detects_mimikatz() {
        assert!(is_known_malware_process("mimikatz"));
    }

    #[test]
    fn detects_meterpreter_uppercase() {
        assert!(is_known_malware_process("METERPRETER"));
    }

    #[test]
    fn detects_beacon() {
        assert!(is_known_malware_process("beacon"));
    }

    #[test]
    fn does_not_flag_chrome() {
        assert!(!is_known_malware_process("chrome"));
    }

    // Edge: empty
    #[test]
    fn empty_string_not_malware_process() {
        assert!(!is_known_malware_process(""));
    }

    // --- CREDENTIAL_ACCESS_TOOLS / is_credential_access_tool ---
    #[test]
    fn credential_tools_contains_mimikatz() {
        assert!(CREDENTIAL_ACCESS_TOOLS.contains(&"mimikatz"));
    }
    #[test]
    fn credential_tools_contains_pypykatz() {
        assert!(CREDENTIAL_ACCESS_TOOLS.contains(&"pypykatz"));
    }
    #[test]
    fn credential_tools_contains_procdump() {
        assert!(CREDENTIAL_ACCESS_TOOLS.contains(&"procdump"));
    }
    #[test]
    fn detects_mimikatz_exact() {
        assert!(is_credential_access_tool("mimikatz"));
    }
    #[test]
    fn detects_mimikatz_exe() {
        assert!(is_credential_access_tool("mimikatz.exe"));
    }
    #[test]
    fn detects_pypykatz_uppercase() {
        assert!(is_credential_access_tool("PYPYKATZ"));
    }
    #[test]
    fn detects_crackmapexec() {
        assert!(is_credential_access_tool("crackmapexec"));
    }
    #[test]
    fn does_not_flag_calc_as_cred_tool() {
        assert!(!is_credential_access_tool("calc.exe"));
    }
    #[test]
    fn empty_string_not_cred_tool() {
        assert!(!is_credential_access_tool(""));
    }

    // --- LSASS_ACCESS_TOOLS / is_lsass_access_tool ---
    #[test]
    fn lsass_tools_contains_procdump() {
        assert!(LSASS_ACCESS_TOOLS.contains(&"procdump"));
    }
    #[test]
    fn lsass_tools_contains_comsvcs() {
        assert!(LSASS_ACCESS_TOOLS.contains(&"comsvcs.dll"));
    }
    #[test]
    fn detects_procdump_exe() {
        assert!(is_lsass_access_tool("procdump.exe"));
    }
    #[test]
    fn detects_comsvcs_dll() {
        assert!(is_lsass_access_tool("comsvcs.dll"));
    }
    #[test]
    fn detects_nanodump() {
        assert!(is_lsass_access_tool("nanodump"));
    }
    #[test]
    fn lsass_tool_case_insensitive() {
        assert!(is_lsass_access_tool("PROCDUMP64.EXE"));
    }
    #[test]
    fn does_not_flag_notepad_as_lsass_tool() {
        assert!(!is_lsass_access_tool("notepad.exe"));
    }
    #[test]
    fn empty_string_not_lsass_tool() {
        assert!(!is_lsass_access_tool(""));
    }
}
