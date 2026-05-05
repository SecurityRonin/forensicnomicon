//! MITRE ATT&CK integration.
//!
//! Canonical home for ATT&CK-typed data shared across forensicnomicon modules:
//!
//! - [`AttackTechnique`] — the shared ATT&CK technique struct (re-used by
//!   [`crate::navigator`] and [`crate::attack_flow`])
//! - [`lookup_attack_for_rule_name`] — map a YARA rule name prefix to its
//!   ATT&CK technique, for enriching YARA scan results without embedding
//!   forensic knowledge in the calling tool (used by blazehash)
//!
//! Re-exported as `forensicnomicon::attack` for backwards compatibility.

/// A resolved MITRE ATT&CK technique entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTechnique {
    /// ATT&CK technique ID, e.g. `"T1486"` or `"T1059.001"`.
    pub technique_id: &'static str,
    /// ATT&CK tactic (lowercase kebab-case), e.g. `"impact"`.
    pub tactic: &'static str,
    /// Human-readable technique name, e.g. `"Data Encrypted for Impact"`.
    pub name: &'static str,
}

/// YARA rule name prefix → ATT&CK technique mapping.
///
/// Entries are matched case-insensitively against the start of the rule name.
/// The first matching entry wins.
static ATTACK_PREFIXES: &[(&str, &str, &str, &str)] = &[
    (
        "rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "ransomware_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("wiper_", "T1485", "impact", "Data Destruction"),
    (
        "creddump_",
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ),
    (
        "keylogger_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    ("rootkit_", "T1014", "defense-evasion", "Rootkit"),
    (
        "backdoor_",
        "T1505",
        "persistence",
        "Server Software Component",
    ),
    (
        "dropper_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    ("miner_", "T1496", "impact", "Resource Hijacking"),
    (
        "stealer_",
        "T1041",
        "exfiltration",
        "Exfiltration Over C2 Channel",
    ),
    (
        "exploit_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    ("loader_", "T1129", "execution", "Shared Modules"),
    (
        "persistence_",
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ),
    (
        "injection_",
        "T1055",
        "defense-evasion",
        "Process Injection",
    ),
    (
        "shellcode_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "webshell_",
        "T1505.003",
        "persistence",
        "Server Software Component: Web Shell",
    ),
    ("powershell_", "T1059.001", "execution", "PowerShell"),
    (
        "maldoc_",
        "T1566.001",
        "initial-access",
        "Phishing: Spearphishing Attachment",
    ),
    (
        "botnet_",
        "T1571",
        "command-and-control",
        "Non-Standard Port",
    ),
    ("antiav_", "T1562", "defense-evasion", "Impair Defenses"),
];

/// Look up a MITRE ATT&CK technique by matching the start of `rule_name`
/// case-insensitively against the known prefix table.
///
/// Returns `None` if no prefix matches.
pub fn lookup_attack_for_rule_name(rule_name: &str) -> Option<AttackTechnique> {
    let lower = rule_name.to_lowercase();
    for &(prefix, technique_id, tactic, name) in ATTACK_PREFIXES {
        if lower.starts_with(prefix) {
            return Some(AttackTechnique {
                technique_id,
                tactic,
                name,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ransomware_prefix_maps_to_t1486() {
        let r = lookup_attack_for_rule_name("ransomware_locky").unwrap();
        assert_eq!(r.technique_id, "T1486");
        assert_eq!(r.tactic, "impact");
        assert_eq!(r.name, "Data Encrypted for Impact");
    }

    #[test]
    fn rootkit_prefix_maps_to_t1014() {
        let r = lookup_attack_for_rule_name("rootkit_necurs").unwrap();
        assert_eq!(r.technique_id, "T1014");
        assert_eq!(r.tactic, "defense-evasion");
    }

    #[test]
    fn case_insensitive_match() {
        let r = lookup_attack_for_rule_name("Ransomware_petya").unwrap();
        assert_eq!(r.technique_id, "T1486");
    }

    #[test]
    fn powershell_prefix_maps_to_t1059_001() {
        let r = lookup_attack_for_rule_name("powershell_empire").unwrap();
        assert_eq!(r.technique_id, "T1059.001");
    }

    #[test]
    fn webshell_maps_to_t1505_003() {
        let r = lookup_attack_for_rule_name("webshell_china_chopper").unwrap();
        assert_eq!(r.technique_id, "T1505.003");
    }

    #[test]
    fn unknown_prefix_returns_none() {
        assert!(lookup_attack_for_rule_name("generic_malware").is_none());
        assert!(lookup_attack_for_rule_name("").is_none());
    }

    #[test]
    fn all_20_prefixes_are_reachable() {
        let probes = [
            "rat_",
            "ransomware_",
            "wiper_",
            "creddump_",
            "keylogger_",
            "rootkit_",
            "backdoor_",
            "dropper_",
            "miner_",
            "stealer_",
            "exploit_",
            "loader_",
            "persistence_",
            "injection_",
            "shellcode_",
            "webshell_",
            "powershell_",
            "maldoc_",
            "botnet_",
            "antiav_",
        ];
        for prefix in probes {
            let name = format!("{prefix}test");
            assert!(
                lookup_attack_for_rule_name(&name).is_some(),
                "prefix '{prefix}' returned None"
            );
        }
    }

    // ── Long-tail prefix tests (RED: all fail until entries are added) ──────

    #[test]
    fn malware_archetypes_are_mapped() {
        let cases = [
            ("trojan_zeus",        "T1204"),
            ("spyware_pegasus",    "T1113"),
            ("spy_agent",          "T1113"),
            ("adware_fireball",    "T1176"),
            ("banker_emotet",      "T1185"),
            ("packer_upx",         "T1027.002"),
            ("clickfraud_adrozek", "T1496"),
            ("worm_wannacry",      "T1570"),
            ("virus_bifrost",      "T1203"),
            ("dialer_premium",     "T1571"),
            ("downloader_upatre",  "T1105"),
            ("infostealer_vidar",  "T1552"),
            ("formgrab_zeus",      "T1056.003"),
            ("stalkerware_spyic",  "T1125"),
            ("clipper_cryptobot",  "T1115"),
            ("cryptominer_xmrig",  "T1496"),
            ("cryptojack_coinhive","T1496"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn credential_attacks_are_mapped() {
        let cases = [
            ("lsass_dump",          "T1003.001"),
            ("samdump_hive",        "T1003.002"),
            ("ntds_extract",        "T1003.003"),
            ("dcsync_attack",       "T1003.006"),
            ("kerberoast_spn",      "T1558.003"),
            ("goldenticket_forge",  "T1558.001"),
            ("silverticket_forge",  "T1558.002"),
            ("passhash_relay",      "T1550.002"),
            ("brute_force_rdp",     "T1110"),
            ("spray_password",      "T1110.003"),
            ("credstuff_combo",     "T1110.004"),
            ("pwsteal_pony",        "T1555"),
            ("cookiesteal_chrome",  "T1539"),
            ("mimikatz_sekurlsa",   "T1003"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn lateral_movement_prefixes_are_mapped() {
        let cases = [
            ("rdp_scanner",   "T1021.001"),
            ("vnc_hijack",    "T1021.005"),
            ("smb_relay",     "T1021.002"),
            ("lateral_psexec","T1570"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn defense_evasion_prefixes_are_mapped() {
        let cases = [
            ("obfusc_xor",          "T1027"),
            ("packed_pe",           "T1027.002"),
            ("antidebug_isdebugged","T1622"),
            ("antivm_cpuid",        "T1497"),
            ("antisandbox_sleep",   "T1497"),
            ("timestomp_mace",      "T1070.006"),
            ("logclear_evtx",       "T1070.001"),
            ("uacbypass_fodhelper", "T1548.002"),
            ("dllhijack_phantom",   "T1574.001"),
            ("dllsideload_teams",   "T1574.002"),
            ("antiforensic_wipe",   "T1070"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn process_injection_variants_are_mapped() {
        let cases = [
            ("prochollow_svchost",  "T1055.012"),
            ("reflective_dll",      "T1055.001"),
            ("threadhijack_remote", "T1055.003"),
            ("atom_bombing",        "T1055"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn persistence_mechanisms_are_mapped() {
        let cases = [
            ("bootkit_necurs",   "T1542.003"),
            ("mbr_infector",     "T1542.003"),
            ("uefi_lojax",       "T1542.001"),
            ("schtask_persist",  "T1053.005"),
            ("cron_persist",     "T1053.003"),
            ("regpersist_run",   "T1547.001"),
            ("service_hollow",   "T1543.003"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn c2_network_prefixes_are_mapped() {
        let cases = [
            ("c2_http",              "T1071"),
            ("beacon_cobalt",        "T1071"),
            ("dnstunnel_iodine",     "T1071.004"),
            ("dga_conficker",        "T1568.002"),
            ("fastflux_storm",       "T1568.001"),
            ("proxy_socks5",         "T1090"),
            ("tunnel_ssh",           "T1572"),
            ("icmptunnel_ping",      "T1095"),
            ("domainfronting_cdn",   "T1090.004"),
            ("p2p_botnet",           "T1090"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn collection_prefixes_are_mapped() {
        let cases = [
            ("screenshot_grab",  "T1113"),
            ("audiocap_record",  "T1123"),
            ("webcam_capture",   "T1125"),
            ("exfil_ftp",        "T1041"),
            ("keylog_hook",      "T1056.001"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn scripting_execution_prefixes_are_mapped() {
        let cases = [
            ("macro_office",    "T1137"),
            ("vba_shellcode",   "T1059.005"),
            ("jscript_rat",     "T1059.007"),
            ("wmi_exec",        "T1047"),
            ("lnk_shortcut",    "T1204.002"),
            ("iso_smuggle",     "T1553.005"),
            ("dde_office",      "T1559.002"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn initial_access_exploitation_prefixes_are_mapped() {
        let cases = [
            ("exploitkit_angler",       "T1189"),
            ("drivebydownload_zeroday", "T1189"),
            ("heapspray_ie",            "T1203"),
            ("rce_log4j",               "T1203"),
            ("lpe_kernel",              "T1068"),
            ("phish_spear",             "T1566"),
            ("watering_hole",           "T1189"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn impact_prefixes_are_mapped() {
        let cases = [
            ("dos_synflood",    "T1499"),
            ("ddos_amplify",    "T1498"),
            ("vss_delete",      "T1490"),
            ("shadow_wipe",     "T1490"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn named_tool_prefixes_are_mapped() {
        let cases = [
            ("cobaltstrike_beacon", "T1219"),
            ("meterpreter_shell",   "T1219"),
            ("sliver_implant",      "T1219"),
            ("empire_stager",       "T1059.001"),
            ("impacket_secretsdump","T1021"),
            ("metasploit_msfvenom", "T1203"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }
}
