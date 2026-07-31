/// Legitimate Windows process names commonly masqueraded by attackers.
///
/// Attackers name malware after these processes to blend in with normal system
/// activity. Detection relies on checking parent/child relationships, image path,
/// and process ancestry — not just the process name.
///
/// Sources:
/// - MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location:
///   <https://attack.mitre.org/techniques/T1036/005/>
/// - Elastic Security — "Detecting Process Masquerading" detection rule series:
///   <https://www.elastic.co/guide/en/security/current/masquerading-as-a-windows-system-process.html>
/// - Microsoft — "Processes that should not be duplicated" (Windows Internals, 7th ed.):
///   <https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals>
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
    "wininit.exe",
    "smss.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "system",
    "registry",
];

/// Well-known malware / offensive-tool process names.
///
/// This list covers C2 frameworks, cryptominers, post-exploitation agents,
/// tunneling tools, and rootkits commonly detected by name in process telemetry.
///
/// Sources:
/// - MITRE ATT&CK T1059 — Command and Scripting Interpreter (C2 agent names):
///   <https://attack.mitre.org/techniques/T1059/>
/// - Elastic Security Labs — threat research naming conventions for Sliver, Havoc,
///   and Brute Ratel C4: <https://www.elastic.co/security-labs/>
/// - SentinelOne Labs — XMRig and cryptominer process taxonomy:
///   <https://www.sentinelone.com/labs/>
/// - BishopFox Sliver C2 framework (process name `sliver`):
///   <https://github.com/BishopFox/sliver>
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

/// Windows binaries whose canonical home is `System32` (or `SysWOW64`): finding
/// one of these executed from any other directory is a strong masquerade /
/// relocation indicator (MITRE T1036.005).
///
/// This is the location-bound subset of [`WINDOWS_MASQUERADE_TARGETS`] — it
/// deliberately omits `explorer.exe` (canonically in `\Windows\`, not
/// `System32`) and the `system` / `registry` kernel pseudo-processes (no image
/// path), so a relocation check over it does not false-positive on them.
///
/// Sources:
/// - MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location:
///   <https://attack.mitre.org/techniques/T1036/005/>
/// - SANS FOR508 — known-good system-binary image paths baseline.
pub const WINDOWS_SYSTEM32_BINARIES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "conhost.exe",
    "wermgr.exe",
    "services.exe",
    "winlogon.exe",
    "wininit.exe",
    "smss.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "lsaiso.exe",
    "rundll32.exe",
];

/// Returns `true` if `name` is a binary whose canonical home is `System32`
/// (case-insensitive). See [`WINDOWS_SYSTEM32_BINARIES`].
#[must_use]
pub fn is_system32_binary(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_SYSTEM32_BINARIES
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
/// - Microsoft — Windows Defender Credential Guard and LSASS protection:
///   <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works>
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

/// Windows processes that must have exactly one instance at a time.
///
/// Multiple instances of any of these indicate masquerading, injection, or a
/// compromised system. Parent relationship must also be validated separately.
///
/// Sources:
/// - Microsoft Windows Internals (7th ed.), Part 1 — system process descriptions.
/// - SANS FOR508 — "Advanced Incident Response, Threat Hunting, and Digital
///   Forensics", process baseline methodology.
/// - MITRE ATT&CK T1055, T1036 — Process Injection / Masquerading:
///   <https://attack.mitre.org/techniques/T1055/>
pub const WINDOWS_SINGLETON_PROCESSES: &[&str] = &[
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "lsm.exe",
];

/// Valid parent-child process relationships on Windows (single-parent form).
///
/// Each tuple is `(child_name, required_parent_name)`. A child seen with any
/// other parent is suspicious and warrants investigation.
///
/// For processes that may have multiple valid parents (e.g. `dllhost.exe`),
/// use [`WINDOWS_PPID_RULES`] instead.
///
/// Sources:
/// - Microsoft Windows Internals (7th ed.) — process ancestry diagrams.
/// - SANS FOR508 process baseline: svchost must have services.exe as parent,
///   lsass must have wininit.exe, etc.
/// - MITRE ATT&CK T1055, T1036.003 — parent spoofing and process injection:
///   <https://attack.mitre.org/techniques/T1036/003/>
pub const WINDOWS_PARENT_RULES: &[(&str, &str)] = &[
    ("svchost.exe", "services.exe"),
    ("lsass.exe", "wininit.exe"),
    ("services.exe", "wininit.exe"),
    ("wininit.exe", "smss.exe"),
];

/// Confidence level of a PPID spoofing alert.
///
/// `High` — the parent constraint is tight; a violation is a strong indicator of
/// PPID spoofing (MITRE ATT&CK T1134.004).
///
/// `Low` — the allowed-parent list is deliberately broad because the process has
/// many legitimate spawners (e.g. COM Surrogate `dllhost.exe`). A violation is
/// a weak signal; correlate with additional context before escalating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SpoofConfidence {
    High,
    Low,
}

/// Expected parent process names for Windows system processes (PPID spoofing detection).
///
/// Each tuple is `(child_name_lower, &[allowed_parent_names_lower], SpoofConfidence)`.
/// A child seen with a parent not in the allowed list signals PPID spoofing
/// (MITRE ATT&CK T1134.004). Use [`expected_parents`] for case-insensitive lookup.
///
/// Sources:
/// - Windows Internals 7th ed. — process ancestry diagrams.
/// - MITRE ATT&CK T1134.004: <https://attack.mitre.org/techniques/T1134/004/>
/// - SANS FOR508 — process baseline methodology.
/// - Elastic Security "Suspicious Parent Process" detection rules.
pub const WINDOWS_PPID_RULES: &[(&str, &[&str], SpoofConfidence)] = &[
    // --- Core session-init hierarchy ---
    ("smss.exe", &["system"], SpoofConfidence::High),
    ("csrss.exe", &["smss.exe"], SpoofConfidence::High),
    ("winlogon.exe", &["smss.exe"], SpoofConfidence::High),
    ("wininit.exe", &["smss.exe"], SpoofConfidence::High),
    // --- wininit.exe children ---
    ("lsass.exe", &["wininit.exe"], SpoofConfidence::High),
    ("services.exe", &["wininit.exe"], SpoofConfidence::High),
    ("lsm.exe", &["wininit.exe"], SpoofConfidence::High), // Local Session Manager (WI7 ch.2)
    // --- Services tree ---
    ("svchost.exe", &["services.exe"], SpoofConfidence::High),
    ("taskhost.exe", &["services.exe"], SpoofConfidence::High),
    ("taskhostw.exe", &["services.exe"], SpoofConfidence::High),
    ("spoolsv.exe", &["services.exe"], SpoofConfidence::High),
    (
        "searchindexer.exe",
        &["services.exe"],
        SpoofConfidence::High,
    ),
    ("msdtc.exe", &["services.exe"], SpoofConfidence::High), // Distributed Transaction Coordinator
    (
        "trustedinstaller.exe",
        &["services.exe"],
        SpoofConfidence::High,
    ), // Windows servicing (WI7 ch.2)
    ("vssvc.exe", &["services.exe"], SpoofConfidence::High), // Volume Shadow Copy
    ("msmpeng.exe", &["services.exe"], SpoofConfidence::High), // Windows Defender AV engine
    ("nissrv.exe", &["services.exe"], SpoofConfidence::High), // Defender Network Inspection Service
    // --- svchost-hosted subsystems ---
    ("audiodg.exe", &["svchost.exe"], SpoofConfidence::High), // Audio Device Graph Isolation (WI7 ch.6)
    ("wmiprvse.exe", &["svchost.exe"], SpoofConfidence::High), // WMI Provider Host isolation (WI7 ch.4)
    ("runtimebroker.exe", &["svchost.exe"], SpoofConfidence::High), // UWP capability broker (WI7 ch.8)
    // --- Search sub-processes ---
    (
        "searchprotocolhost.exe",
        &["searchindexer.exe"],
        SpoofConfidence::High,
    ),
    (
        "searchfilterhost.exe",
        &["searchindexer.exe"],
        SpoofConfidence::High,
    ),
    // --- winlogon.exe children ---
    ("userinit.exe", &["winlogon.exe"], SpoofConfidence::High),
    ("logonui.exe", &["winlogon.exe"], SpoofConfidence::High), // credential UI at logon/lock
    ("dwm.exe", &["winlogon.exe"], SpoofConfidence::High),     // Desktop Window Manager (WI7 ch.3)
    // fontdrvhost: two legitimate instances — session-0 (wininit) and per-user (winlogon).
    (
        "fontdrvhost.exe",
        &["wininit.exe", "winlogon.exe"],
        SpoofConfidence::High,
    ),
    // userinit children
    (
        "explorer.exe",
        &["userinit.exe", "winlogon.exe"],
        SpoofConfidence::High,
    ), // winlogon for auto-logon / shell replacement
    // --- Low-confidence: broad legitimate spawner sets ---
    // dllhost (COM Surrogate) can be spawned by any process activating an out-of-proc COM
    // object. The four entries here cover the most common legitimate spawners; an unlisted
    // parent is suspicious but not definitive — correlate with COM class activation events.
    (
        "dllhost.exe",
        &["svchost.exe", "services.exe", "explorer.exe", "mmc.exe"],
        SpoofConfidence::Low,
    ),
];

/// Look up the allowed parent names and alert confidence for `child_name`.
///
/// Returns `None` if the process is not tracked (no rule defined).
/// Returns `Some((parents, High))` when a parent mismatch is a strong spoofing signal.
/// Returns `Some((parents, Low))` when the process has many legitimate spawners and a
/// mismatch is only a weak signal requiring additional corroboration.
pub fn expected_parents(child_name: &str) -> Option<(&'static [&'static str], SpoofConfidence)> {
    let lower = child_name.to_ascii_lowercase();
    WINDOWS_PPID_RULES
        .iter()
        .find(|(child, _, _)| *child == lower.as_str())
        .map(|(_, parents, conf)| (*parents, *conf))
}

/// Windows processes that should never establish network connections.
///
/// Network activity from these processes is a strong anomaly indicator —
/// often associated with process hollowing, DLL injection, or C2 in disguise.
///
/// Sources:
/// - SANS FOR508 — anomalous network connection detection heuristics.
/// - MITRE ATT&CK T1055 — Process Injection into non-network-capable binaries:
///   <https://attack.mitre.org/techniques/T1055/>
pub const WINDOWS_NON_NETWORKING_PROCESSES: &[&str] = &[
    "notepad.exe",
    "calc.exe",
    "mspaint.exe",
    "write.exe",
    "wordpad.exe",
    "snippingtool.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
];

/// Windows kernel image PDB name prefixes used to identify the kernel binary.
///
/// The kernel PE exports one of these as the PDB name in its debug directory.
/// Used for ISF symbol auto-resolution and kernel base locating.
///
/// Sources:
/// - Microsoft Symbol Server naming conventions for ntoskrnl/ntkrnlmp/ntkrnlpa.
/// - Volatility3 ISF profile naming: ntkrnlmp.pdb, ntoskrnl.exe.pdb, etc.
pub const WINDOWS_KERNEL_PDB_PREFIXES: &[&str] = &["ntkrnl", "ntoskrnl"];

/// PE/MZ magic bytes — first two bytes of any valid Windows Portable Executable.
///
/// Sources:
/// - Microsoft PE/COFF specification (revision 11):
///   <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
pub const PE_MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];

/// Returns `true` if `name` is a Windows singleton process (case-insensitive).
pub fn is_singleton_process(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_SINGLETON_PROCESSES.iter().any(|t| *t == lower)
}

/// Returns the required parent name for `child_name`, or `None` if no rule applies.
///
/// Lookup is case-insensitive on the child name.
pub fn expected_parent(child_name: &str) -> Option<&'static str> {
    let lower = child_name.to_ascii_lowercase();
    WINDOWS_PARENT_RULES
        .iter()
        .find(|(child, _)| *child == lower.as_str())
        .map(|(_, parent)| *parent)
}

/// Returns `true` if `name` should never have network connections (case-insensitive).
pub fn is_non_networking_process(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_NON_NETWORKING_PROCESSES.iter().any(|t| *t == lower)
}

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

    /// `WINDOWS_SYSTEM32_BINARIES` is curated for a location question, so it
    /// neither mirrors nor is contained by `WINDOWS_MASQUERADE_TARGETS`; its doc
    /// comment states exactly how the two differ. Pin both directions so a data
    /// edit cannot silently make that statement false — and so the additions are
    /// visible to `heuristics::srum`, which builds its name baseline on this list.
    #[test]
    fn system32_binaries_differ_from_masquerade_targets_as_documented() {
        let added: Vec<&str> = WINDOWS_SYSTEM32_BINARIES
            .iter()
            .copied()
            .filter(|name| !WINDOWS_MASQUERADE_TARGETS.contains(name))
            .collect();
        assert_eq!(
            added,
            ["lsaiso.exe", "rundll32.exe"],
            "System32 names absent from WINDOWS_MASQUERADE_TARGETS changed — \
             update the WINDOWS_SYSTEM32_BINARIES doc comment to match"
        );

        let omitted: Vec<&str> = WINDOWS_MASQUERADE_TARGETS
            .iter()
            .copied()
            .filter(|name| !WINDOWS_SYSTEM32_BINARIES.contains(name))
            .collect();
        assert_eq!(
            omitted,
            ["explorer.exe", "system", "registry"],
            "masquerade targets deliberately omitted from the System32 list changed — \
             update the WINDOWS_SYSTEM32_BINARIES doc comment to match"
        );

        assert_eq!(
            WINDOWS_SYSTEM32_BINARIES.len() - added.len(),
            13,
            "shared-entry count changed — update the WINDOWS_SYSTEM32_BINARIES doc comment"
        );
    }

    #[test]
    fn system32_binary_recognizes_svchost_case_insensitively() {
        assert!(is_system32_binary("svchost.exe"));
        assert!(is_system32_binary("SVCHOST.EXE"));
        assert!(is_system32_binary("Spoolsv.exe"));
    }

    #[test]
    fn system32_binary_excludes_explorer_and_pseudo_processes() {
        // explorer lives in \Windows\, not System32; system/registry have no path.
        assert!(!is_system32_binary("explorer.exe"));
        assert!(!is_system32_binary("system"));
        assert!(!is_system32_binary("registry"));
        assert!(!is_system32_binary("coreupdater.exe"));
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

    // --- WINDOWS_SINGLETON_PROCESSES ---
    #[test]
    fn singleton_list_contains_lsass() {
        assert!(WINDOWS_SINGLETON_PROCESSES.contains(&"lsass.exe"));
    }
    #[test]
    fn singleton_list_contains_services() {
        assert!(WINDOWS_SINGLETON_PROCESSES.contains(&"services.exe"));
    }
    #[test]
    fn singleton_list_contains_wininit() {
        assert!(WINDOWS_SINGLETON_PROCESSES.contains(&"wininit.exe"));
    }
    #[test]
    fn is_singleton_process_case_insensitive() {
        assert!(is_singleton_process("LSASS.EXE"));
    }
    #[test]
    fn is_singleton_process_returns_false_for_svchost() {
        // svchost can have many instances — not a singleton
        assert!(!is_singleton_process("svchost.exe"));
    }

    // --- WINDOWS_PARENT_RULES ---
    #[test]
    fn parent_rules_contain_svchost_services() {
        assert!(WINDOWS_PARENT_RULES.contains(&("svchost.exe", "services.exe")));
    }
    #[test]
    fn parent_rules_contain_lsass_wininit() {
        assert!(WINDOWS_PARENT_RULES.contains(&("lsass.exe", "wininit.exe")));
    }
    #[test]
    fn expected_parent_for_svchost_is_services() {
        assert_eq!(expected_parent("svchost.exe"), Some("services.exe"));
    }
    #[test]
    fn expected_parent_for_explorer_is_none() {
        assert_eq!(expected_parent("explorer.exe"), None);
    }

    // --- WINDOWS_NON_NETWORKING_PROCESSES ---
    #[test]
    fn non_networking_contains_notepad() {
        assert!(WINDOWS_NON_NETWORKING_PROCESSES.contains(&"notepad.exe"));
    }
    #[test]
    fn non_networking_contains_calc() {
        assert!(WINDOWS_NON_NETWORKING_PROCESSES.contains(&"calc.exe"));
    }
    #[test]
    fn is_non_networking_process_case_insensitive() {
        assert!(is_non_networking_process("NOTEPAD.EXE"));
    }
    #[test]
    fn is_non_networking_process_false_for_chrome() {
        assert!(!is_non_networking_process("chrome.exe"));
    }

    // --- WINDOWS_KERNEL_PDB_PREFIXES ---
    #[test]
    fn kernel_pdb_prefixes_contains_ntkrnl() {
        assert!(WINDOWS_KERNEL_PDB_PREFIXES.contains(&"ntkrnl"));
    }
    #[test]
    fn kernel_pdb_prefixes_contains_ntoskrnl() {
        assert!(WINDOWS_KERNEL_PDB_PREFIXES.contains(&"ntoskrnl"));
    }

    // --- PE_MZ_MAGIC ---
    #[test]
    fn pe_mz_magic_is_4d5a() {
        assert_eq!(PE_MZ_MAGIC, [0x4D, 0x5A]);
    }

    // --- WINDOWS_PPID_RULES / expected_parents ---

    // count
    #[test]
    fn ppid_rules_has_twenty_eight_entries() {
        assert_eq!(WINDOWS_PPID_RULES.len(), 28);
    }

    // SpoofConfidence enum
    #[test]
    fn spoof_confidence_high_ne_low() {
        assert_ne!(SpoofConfidence::High, SpoofConfidence::Low);
    }

    // existing entries still present (tuple now has 3 fields)
    #[test]
    fn ppid_rules_contains_svchost_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "svchost.exe" && ps.contains(&"services.exe")));
    }
    #[test]
    fn ppid_rules_contains_lsass_wininit() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "lsass.exe" && ps.contains(&"wininit.exe")));
    }
    #[test]
    fn ppid_rules_smss_parent_is_system() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "smss.exe" && ps.contains(&"system")));
    }

    // dllhost: expanded parents + Low confidence
    #[test]
    fn ppid_rules_dllhost_allows_svchost_and_services() {
        let (_, ps, _) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "dllhost.exe")
            .unwrap();
        assert!(ps.contains(&"svchost.exe"));
        assert!(ps.contains(&"services.exe"));
    }
    #[test]
    fn ppid_rules_dllhost_allows_explorer() {
        let (_, ps, _) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "dllhost.exe")
            .unwrap();
        assert!(
            ps.contains(&"explorer.exe"),
            "COM thumbnail/preview handlers: explorer → dllhost"
        );
    }
    #[test]
    fn ppid_rules_dllhost_allows_mmc() {
        let (_, ps, _) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "dllhost.exe")
            .unwrap();
        assert!(
            ps.contains(&"mmc.exe"),
            "MMC snap-ins activate COM surrogates"
        );
    }
    #[test]
    fn ppid_rules_dllhost_confidence_is_low() {
        let (_, _, conf) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "dllhost.exe")
            .unwrap();
        assert_eq!(*conf, SpoofConfidence::Low);
    }
    #[test]
    fn ppid_rules_lsass_confidence_is_high() {
        let (_, _, conf) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "lsass.exe")
            .unwrap();
        assert_eq!(*conf, SpoofConfidence::High);
    }

    // new high-confidence entries
    #[test]
    fn ppid_rules_wininit_parent_is_smss() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "wininit.exe" && ps.contains(&"smss.exe")));
    }
    #[test]
    fn ppid_rules_lsm_parent_is_wininit() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "lsm.exe" && ps.contains(&"wininit.exe")));
    }
    #[test]
    fn ppid_rules_explorer_allows_userinit_and_winlogon() {
        let (_, ps, _) = WINDOWS_PPID_RULES
            .iter()
            .find(|(c, _, _)| *c == "explorer.exe")
            .unwrap();
        assert!(
            ps.contains(&"userinit.exe"),
            "normal logon: userinit → explorer"
        );
        assert!(
            ps.contains(&"winlogon.exe"),
            "auto-logon / shell replacement"
        );
    }
    #[test]
    fn ppid_rules_logonui_parent_is_winlogon() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "logonui.exe" && ps.contains(&"winlogon.exe")));
    }
    #[test]
    fn ppid_rules_dwm_parent_is_winlogon() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "dwm.exe" && ps.contains(&"winlogon.exe")));
    }
    #[test]
    fn ppid_rules_msdtc_parent_is_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "msdtc.exe" && ps.contains(&"services.exe")));
    }
    #[test]
    fn ppid_rules_trustedinstaller_parent_is_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "trustedinstaller.exe" && ps.contains(&"services.exe")));
    }
    #[test]
    fn ppid_rules_vssvc_parent_is_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "vssvc.exe" && ps.contains(&"services.exe")));
    }
    #[test]
    fn ppid_rules_msmpeng_parent_is_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "msmpeng.exe" && ps.contains(&"services.exe")));
    }
    #[test]
    fn ppid_rules_nissrv_parent_is_services() {
        assert!(WINDOWS_PPID_RULES
            .iter()
            .any(|(c, ps, _)| *c == "nissrv.exe" && ps.contains(&"services.exe")));
    }

    // expected_parents: new Option<(parents, confidence)> return type
    #[test]
    fn expected_parents_svchost_returns_services_high() {
        let (parents, conf) = expected_parents("svchost.exe").unwrap();
        assert_eq!(parents, &["services.exe"]);
        assert_eq!(conf, SpoofConfidence::High);
    }
    #[test]
    fn expected_parents_dllhost_is_low_confidence() {
        let (parents, conf) = expected_parents("dllhost.exe").unwrap();
        assert!(parents.contains(&"svchost.exe"));
        assert!(parents.contains(&"explorer.exe"));
        assert_eq!(conf, SpoofConfidence::Low);
    }
    #[test]
    fn expected_parents_unknown_process_returns_none() {
        assert!(expected_parents("calc.exe").is_none());
    }
    #[test]
    fn expected_parents_case_insensitive() {
        let (parents, _) = expected_parents("SVCHOST.EXE").unwrap();
        assert!(parents.contains(&"services.exe"));
    }
    #[test]
    fn expected_parents_fontdrvhost_returns_two_parents() {
        let (p, _) = expected_parents("fontdrvhost.exe").unwrap();
        assert!(p.contains(&"wininit.exe"));
        assert!(p.contains(&"winlogon.exe"));
        assert_eq!(p.len(), 2);
    }
    #[test]
    fn expected_parents_runtimebroker_returns_svchost() {
        let (p, _) = expected_parents("runtimebroker.exe").unwrap();
        assert_eq!(p, &["svchost.exe"]);
    }
    #[test]
    fn expected_parents_wmiprvse_returns_svchost() {
        let (p, _) = expected_parents("wmiprvse.exe").unwrap();
        assert_eq!(p, &["svchost.exe"]);
    }
}
