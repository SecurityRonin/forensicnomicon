//! MITRE ATT&CK integration.
//!
//! Canonical home for ATT&CK-typed data shared across forensicnomicon modules:
//!
//! - [`AttackTechnique`] — the shared ATT&CK technique struct
//! - [`lookup_attack_for_rule_name`] — map a YARA rule name prefix to its
//!   ATT&CK technique, for enriching YARA scan results without embedding
//!   forensic knowledge in the calling tool

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

/// YARA rule name prefix → ATT&CK technique mapping (~500 entries).
///
/// Entries are matched case-insensitively against the start of the rule name.
/// The first matching entry wins. Organised by category; named families are
/// grouped after generic archetypes so that a generic prefix like `rat_`
/// fires before a family prefix like `ratty_`.
static ATTACK_PREFIXES: &[(&[u8], &str, &str, &str)] = &[
    (
        &[0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // rat_
    (
        &[
            0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // ransomware_
    (
        &[0xd0, 0xce, 0xd7, 0xc2, 0xd5, 0xf8],
        "T1485",
        "impact",
        "Data Destruction",
    ), // wiper_
    (
        &[0xc4, 0xd5, 0xc2, 0xc3, 0xc3, 0xd2, 0xca, 0xd7, 0xf8],
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ), // creddump_
    (
        &[0xcc, 0xc2, 0xde, 0xcb, 0xc8, 0xc0, 0xc0, 0xc2, 0xd5, 0xf8],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // keylogger_
    (
        &[0xd5, 0xc8, 0xc8, 0xd3, 0xcc, 0xce, 0xd3, 0xf8],
        "T1014",
        "defense-evasion",
        "Rootkit",
    ), // rootkit_
    (
        &[0xc5, 0xc6, 0xc4, 0xcc, 0xc3, 0xc8, 0xc8, 0xd5, 0xf8],
        "T1505",
        "persistence",
        "Server Software Component",
    ), // backdoor_
    (
        &[0xc3, 0xd5, 0xc8, 0xd7, 0xd7, 0xc2, 0xd5, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // dropper_
    (
        &[0xca, 0xce, 0xc9, 0xc2, 0xd5, 0xf8],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // miner_
    (
        &[0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8],
        "T1041",
        "exfiltration",
        "Exfiltration Over C2 Channel",
    ), // stealer_
    (
        &[0xc2, 0xdf, 0xd7, 0xcb, 0xc8, 0xce, 0xd3, 0xf8],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // exploit_
    (
        &[0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8],
        "T1129",
        "execution",
        "Shared Modules",
    ), // loader_
    (
        &[
            0xd7, 0xc2, 0xd5, 0xd4, 0xce, 0xd4, 0xd3, 0xc2, 0xc9, 0xc4, 0xc2, 0xf8,
        ],
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ), // persistence_
    (
        &[0xce, 0xc9, 0xcd, 0xc2, 0xc4, 0xd3, 0xce, 0xc8, 0xc9, 0xf8],
        "T1055",
        "defense-evasion",
        "Process Injection",
    ), // injection_
    (
        &[0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xc4, 0xc8, 0xc3, 0xc2, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // shellcode_
    (
        &[0xd0, 0xc2, 0xc5, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1505.003",
        "persistence",
        "Server Software Component: Web Shell",
    ), // webshell_
    (
        &[
            0xd7, 0xc8, 0xd0, 0xc2, 0xd5, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8,
        ],
        "T1059.001",
        "execution",
        "PowerShell",
    ), // powershell_
    (
        &[0xca, 0xc6, 0xcb, 0xc3, 0xc8, 0xc4, 0xf8],
        "T1566.001",
        "initial-access",
        "Phishing: Spearphishing Attachment",
    ), // maldoc_
    (
        &[0xc5, 0xc8, 0xd3, 0xc9, 0xc2, 0xd3, 0xf8],
        "T1571",
        "command-and-control",
        "Non-Standard Port",
    ), // botnet_
    (
        &[0xc6, 0xc9, 0xd3, 0xce, 0xc6, 0xd1, 0xf8],
        "T1562",
        "defense-evasion",
        "Impair Defenses",
    ), // antiav_
    (
        &[0xd3, 0xd5, 0xc8, 0xcd, 0xc6, 0xc9, 0xf8],
        "T1204",
        "execution",
        "User Execution",
    ), // trojan_
    (
        &[0xd4, 0xd7, 0xde, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8],
        "T1113",
        "collection",
        "Screen Capture",
    ), // spyware_
    (
        &[0xd4, 0xd7, 0xde, 0xf8],
        "T1113",
        "collection",
        "Screen Capture",
    ), // spy_
    (
        &[0xc6, 0xc3, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8],
        "T1176",
        "persistence",
        "Browser Extensions",
    ), // adware_
    (
        &[0xc5, 0xc6, 0xc9, 0xcc, 0xc2, 0xd5, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // banker_
    (
        &[0xd7, 0xc6, 0xc4, 0xcc, 0xc2, 0xd5, 0xf8],
        "T1027.002",
        "defense-evasion",
        "Obfuscated Files or Information: Software Packing",
    ), // packer_
    (
        &[
            0xc4, 0xcb, 0xce, 0xc4, 0xcc, 0xc1, 0xd5, 0xc6, 0xd2, 0xc3, 0xf8,
        ],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // clickfraud_
    (
        &[0xd0, 0xc8, 0xd5, 0xca, 0xf8],
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ), // worm_
    (
        &[0xd1, 0xce, 0xd5, 0xd2, 0xd4, 0xf8],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // virus_
    (
        &[0xc3, 0xce, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8],
        "T1571",
        "command-and-control",
        "Non-Standard Port",
    ), // dialer_
    (
        &[
            0xc3, 0xc8, 0xd0, 0xc9, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // downloader_
    (
        &[
            0xce, 0xc9, 0xc1, 0xc8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // infostealer_
    (
        &[0xc1, 0xc8, 0xd5, 0xca, 0xc0, 0xd5, 0xc6, 0xc5, 0xf8],
        "T1056.003",
        "collection",
        "Input Capture: Web Portal Capture",
    ), // formgrab_
    (
        &[
            0xd4, 0xd3, 0xc6, 0xcb, 0xcc, 0xc2, 0xd5, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8,
        ],
        "T1125",
        "collection",
        "Video Capture",
    ), // stalkerware_
    (
        &[0xc4, 0xcb, 0xce, 0xd7, 0xd7, 0xc2, 0xd5, 0xf8],
        "T1115",
        "collection",
        "Clipboard Data",
    ), // clipper_
    (
        &[
            0xc4, 0xd5, 0xde, 0xd7, 0xd3, 0xc8, 0xca, 0xce, 0xc9, 0xc2, 0xd5, 0xf8,
        ],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // cryptominer_
    (
        &[
            0xc4, 0xd5, 0xde, 0xd7, 0xd3, 0xc8, 0xcd, 0xc6, 0xc4, 0xcc, 0xf8,
        ],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // cryptojack_
    (
        &[0xce, 0xca, 0xd7, 0xcb, 0xc6, 0xc9, 0xd3, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // implant_
    (
        &[0xd4, 0xd3, 0xc6, 0xc0, 0xc2, 0xd5, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // stager_
    (
        &[0xd7, 0xc6, 0xde, 0xcb, 0xc8, 0xc6, 0xc3, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // payload_
    (
        &[0xcb, 0xc8, 0xc4, 0xcc, 0xc5, 0xce, 0xd3, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // lockbit_
    (
        &[0xc4, 0xc8, 0xc9, 0xd3, 0xce, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // conti_
    (
        &[0xd5, 0xc2, 0xd1, 0xce, 0xcb, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // revil_
    (
        &[
            0xd4, 0xc8, 0xc3, 0xce, 0xc9, 0xc8, 0xcc, 0xce, 0xc5, 0xce, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // sodinokibi_
    (
        &[0xc3, 0xc6, 0xd5, 0xcc, 0xd4, 0xce, 0xc3, 0xc2, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // darkside_
    (
        &[0xca, 0xc6, 0xdd, 0xc2, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // maze_
    (
        &[0xd5, 0xde, 0xd2, 0xcc, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // ryuk_
    (
        &[0xc5, 0xcb, 0xc6, 0xc4, 0xcc, 0xc4, 0xc6, 0xd3, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // blackcat_
    (
        &[0xc6, 0xcb, 0xd7, 0xcf, 0xd1, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // alphv_
    (
        &[0xc4, 0xcb, 0x97, 0xd7, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // cl0p_
    (
        &[0xc4, 0xcb, 0xc8, 0xd7, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // clop_
    (
        &[0xc6, 0xcc, 0xce, 0xd5, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // akira_
    (
        &[
            0xc5, 0xcb, 0xc6, 0xc4, 0xcc, 0xc5, 0xc6, 0xd4, 0xd3, 0xc6, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // blackbasta_
    (
        &[
            0xcf, 0xce, 0xd1, 0xc2, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // hive_ransom_
    (
        &[0xcb, 0xc8, 0xd5, 0xc2, 0xc9, 0xdd, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // lorenz_
    (
        &[0xc2, 0xc0, 0xd5, 0xc2, 0xc0, 0xc8, 0xd5, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // egregor_
    (
        &[0xc9, 0xc2, 0xd3, 0xd0, 0xc6, 0xcb, 0xcc, 0xc2, 0xd5, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // netwalker_
    (
        &[0xc3, 0xcf, 0xc6, 0xd5, 0xca, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // dharma_
    (
        &[0xd7, 0xcf, 0xc8, 0xc5, 0xc8, 0xd4, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // phobos_
    (
        &[0xca, 0xc6, 0xcc, 0xc8, 0xd7, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // makop_
    (
        &[0xc6, 0xd1, 0xc6, 0xc3, 0xc3, 0xc8, 0xc9, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // avaddon_
    (
        &[0xc0, 0xd5, 0xce, 0xc2, 0xc1, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // grief_
    (
        &[0xd5, 0xc6, 0xc0, 0xc9, 0xc6, 0xd5, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // ragnar_
    (
        &[0xc3, 0xc8, 0xd7, 0xd7, 0xcb, 0xc2, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // dopple_
    (
        &[0xc9, 0xc2, 0xc1, 0xce, 0xcb, 0xce, 0xca, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // nefilim_
    (
        &[0xd7, 0xc6, 0xde, 0x95, 0xcc, 0xc2, 0xde, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // pay2key_
    (
        &[
            0xde, 0xc6, 0xc9, 0xcb, 0xd2, 0xc8, 0xd0, 0xc6, 0xc9, 0xc0, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // yanluowang_
    (
        &[0xc9, 0xc8, 0xcc, 0xc8, 0xde, 0xc6, 0xd0, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // nokoyawa_
    (
        &[0xc5, 0xc6, 0xc5, 0xd2, 0xcc, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // babuk_
    (
        &[0xca, 0xc8, 0xc9, 0xd3, 0xce, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // monti_
    (
        &[0xc5, 0xce, 0xc6, 0xc9, 0xcb, 0xce, 0xc6, 0xc9, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // bianlian_
    (
        &[0xd5, 0xcf, 0xde, 0xd4, 0xce, 0xc3, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // rhysida_
    (
        &[0xd3, 0xd5, 0xce, 0xc0, 0xc8, 0xc9, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // trigona_
    (
        &[
            0xc4, 0xc6, 0xc4, 0xd3, 0xd2, 0xd4, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // cactus_ransom_
    (
        &[0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xc2, 0xdf, 0xdf, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // ransomexx_
    (
        &[
            0xcb, 0xc8, 0xc4, 0xcc, 0xc2, 0xd5, 0xc0, 0xc8, 0xc0, 0xc6, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // lockergoga_
    (
        &[
            0xca, 0xc2, 0xc0, 0xc6, 0xc4, 0xc8, 0xd5, 0xd3, 0xc2, 0xdf, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // megacortex_
    (
        &[
            0xcf, 0xc2, 0xcb, 0xcb, 0xc8, 0xcc, 0xce, 0xd3, 0xd3, 0xde, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // hellokitty_
    (
        &[0xc3, 0xc6, 0xd5, 0xcc, 0xd7, 0xc8, 0xd0, 0xc2, 0xd5, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // darkpower_
    (
        &[0xcf, 0xc6, 0xd5, 0xc3, 0xc5, 0xce, 0xd3, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // hardbit_
    (
        &[
            0xc4, 0xde, 0xc4, 0xcb, 0xc8, 0xd7, 0xd4, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca,
            0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // cyclops_ransom_
    (
        &[0xcb, 0xc8, 0xc4, 0xcc, 0xc1, 0xce, 0xcb, 0xc2, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // lockfile_
    (
        &[0xd4, 0xd2, 0xc9, 0xc4, 0xd5, 0xde, 0xd7, 0xd3, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // suncrypt_
    (
        &[
            0xd4, 0xc9, 0xc6, 0xd3, 0xc4, 0xcf, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // snatch_ransom_
    (
        &[0xca, 0xc2, 0xd4, 0xd7, 0xce, 0xc9, 0xc8, 0xdd, 0xc6, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // mespinoza_
    (
        &[0x9f, 0xc5, 0xc6, 0xd4, 0xc2, 0xf8],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // 8base_
    (
        &[
            0xcf, 0xd2, 0xc9, 0xd3, 0xc2, 0xd5, 0xd4, 0xf8, 0xce, 0xc9, 0xd3, 0xcb, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // hunters_intl_
    (
        &[
            0xd1, 0xce, 0xc4, 0xc2, 0xf8, 0xd4, 0xc8, 0xc4, 0xce, 0xc2, 0xd3, 0xde, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // vice_society_
    (
        &[
            0xca, 0xc8, 0xc9, 0xc2, 0xde, 0xf8, 0xca, 0xc2, 0xd4, 0xd4, 0xc6, 0xc0, 0xc2, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // money_message_
    (
        &[
            0xca, 0xc2, 0xc8, 0xd0, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // meow_ransom_
    (
        &[
            0xd6, 0xd2, 0xc6, 0xc9, 0xd3, 0xd2, 0xca, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca,
            0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // quantum_ransom_
    (
        &[0xc6, 0xd4, 0xde, 0xc9, 0xc4, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // asyncrat_
    (
        &[0xc9, 0xcd, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // njrat_
    (
        &[0xd5, 0xc2, 0xca, 0xc4, 0xc8, 0xd4, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // remcos_
    (
        &[0xd6, 0xd2, 0xc6, 0xd4, 0xc6, 0xd5, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // quasar_
    (
        &[0xc3, 0xc6, 0xd5, 0xcc, 0xc4, 0xc8, 0xca, 0xc2, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // darkcomet_
    (
        &[0xc9, 0xc6, 0xc9, 0xc8, 0xc4, 0xc8, 0xd5, 0xc2, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // nanocore_
    (
        &[0xc9, 0xc2, 0xd3, 0xd0, 0xce, 0xd5, 0xc2, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // netwire_
    (
        &[0xd0, 0xc6, 0xd5, 0xdd, 0xc8, 0xc9, 0xc2, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // warzone_
    (
        &[0xdf, 0xd3, 0xd5, 0xc2, 0xca, 0xc2, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // xtremerat_
    (
        &[
            0xc4, 0xd5, 0xce, 0xca, 0xd4, 0xc8, 0xc9, 0xf8, 0xd5, 0xc6, 0xd3, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // crimson_rat_
    (
        &[0xc5, 0xc6, 0xc9, 0xc3, 0xc8, 0xc8, 0xcc, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // bandook_
    (
        &[0xd7, 0xc6, 0xd5, 0xc6, 0xcb, 0xcb, 0xc6, 0xdf, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // parallax_
    (
        &[0xce, 0xca, 0xca, 0xce, 0xc9, 0xc2, 0xc9, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // imminent_
    (
        &[0xc3, 0xc4, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // dcrat_
    (
        &[0xd7, 0xd5, 0xc8, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // prorat_
    (
        &[0xc0, 0xcf, 0x97, 0xd4, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // gh0st_
    (
        &[0xd7, 0xc8, 0xce, 0xd4, 0xc8, 0xc9, 0xce, 0xd1, 0xde, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // poisonivy_
    (
        &[0xd7, 0xcb, 0xd2, 0xc0, 0xdf, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // plugx_
    (
        &[0xd4, 0xcf, 0xc6, 0xc3, 0xc8, 0xd0, 0xd7, 0xc6, 0xc3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // shadowpad_
    (
        &[
            0xcb, 0xd2, 0xca, 0xce, 0xc9, 0xc8, 0xd4, 0xce, 0xd3, 0xde, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // luminosity_
    (
        &[0xcb, 0xce, 0xca, 0xc2, 0xc9, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // limenat_
    (
        &[0xc5, 0xc6, 0xc3, 0xc9, 0xc2, 0xd0, 0xd4, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // badnews_
    (
        &[0xc4, 0xc8, 0xd5, 0xc2, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // coreshell_
    (
        &[0xc8, 0xd5, 0xc4, 0xd2, 0xd4, 0xf8, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // orcus_rat_
    (
        &[0xc6, 0xc3, 0xd0, 0xce, 0xc9, 0xc3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // adwind_
    (
        &[0xcd, 0xd5, 0xc6, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // jrat_
    (
        &[0xdf, 0xd0, 0xc8, 0xd5, 0xca, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // xworm_
    (
        &[
            0xc9, 0xc2, 0xd3, 0xd4, 0xd2, 0xd7, 0xd7, 0xc8, 0xd5, 0xd3, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // netsupport_
    (
        &[
            0xd5, 0xc2, 0xd1, 0xc2, 0xc9, 0xc0, 0xc2, 0xf8, 0xd5, 0xc6, 0xd3, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // revenge_rat_
    (
        &[0xc1, 0xde, 0xc9, 0xcb, 0xc8, 0xd4, 0xcc, 0xce, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // fynloski_
    (
        &[0xc5, 0xce, 0xc1, 0xd5, 0xc8, 0xd4, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // bifrost_
    (
        &[
            0xd7, 0xc6, 0xc9, 0xc3, 0xc8, 0xd5, 0xc6, 0xf8, 0xd5, 0xc6, 0xd3, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // pandora_rat_
    (
        &[0xd5, 0xc6, 0xd3, 0xd3, 0xde, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // ratty_
    (
        &[0xd7, 0xd2, 0xca, 0xc6, 0xcc, 0xce, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // pumakit_
    (
        &[0xde, 0xc6, 0xde, 0xce, 0xcf, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // yayih_
    (
        &[0xc2, 0xca, 0xc8, 0xd3, 0xc2, 0xd3, 0xf8],
        "T1566",
        "initial-access",
        "Phishing",
    ), // emotet_
    (
        &[0xd3, 0xd5, 0xce, 0xc4, 0xcc, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // trickbot_
    (
        &[0xd6, 0xc6, 0xcc, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // qakbot_
    (
        &[0xd6, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // qbot_
    (
        &[0xc3, 0xd5, 0xce, 0xc3, 0xc2, 0xdf, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // dridex_
    (
        &[0xd2, 0xd5, 0xd4, 0xc9, 0xce, 0xc1, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // ursnif_
    (
        &[0xdd, 0xc2, 0xd2, 0xd4, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // zeus_
    (
        &[0xc0, 0xc8, 0xdd, 0xce, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // gozi_
    (
        &[0xc1, 0xcb, 0xd2, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // flubot_
    (
        &[0xc4, 0xc2, 0xd5, 0xc5, 0xc2, 0xd5, 0xd2, 0xd4, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // cerberus_
    (
        &[
            0xc6, 0xc9, 0xd2, 0xc5, 0xce, 0xd4, 0xf8, 0xc5, 0xc6, 0xc9, 0xcc, 0xc2, 0xd5, 0xf8,
        ],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // anubis_banker_
    (
        &[0xd3, 0xc2, 0xc6, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // teabot_
    (
        &[0xc5, 0xd5, 0xc6, 0xd3, 0xc6, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // brata_
    (
        &[0xd4, 0xcf, 0xc6, 0xd5, 0xcc, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // sharkbot_
    (
        &[0xdf, 0xc2, 0xc9, 0xc8, 0xca, 0xc8, 0xd5, 0xd7, 0xcf, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // xenomorph_
    (
        &[0xc0, 0xc8, 0xc3, 0xc1, 0xc6, 0xd3, 0xcf, 0xc2, 0xd5, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // godfather_
    (
        &[0xc3, 0xc6, 0xc9, 0xc6, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // danabot_
    (
        &[0xce, 0xd4, 0xc1, 0xc5, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // isfb_
    (
        &[0xd4, 0xd7, 0xde, 0xc2, 0xde, 0xc2, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // spyeye_
    (
        &[0xc4, 0xc6, 0xd5, 0xc5, 0xc2, 0xd5, 0xd7, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // carberp_
    (
        &[0xd3, 0xce, 0xc9, 0xc5, 0xc6, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // tinba_
    (
        &[0xcc, 0xd5, 0xc8, 0xc9, 0xc8, 0xd4, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // kronos_
    (
        &[0xc0, 0xc6, 0xca, 0xc2, 0xc8, 0xd1, 0xc2, 0xd5, 0xf8],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // gameover_
    (
        &[
            0xcf, 0xc8, 0xc8, 0xcc, 0xf8, 0xc5, 0xc6, 0xc9, 0xcc, 0xc2, 0xd5, 0xf8,
        ],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // hook_banker_
    (
        &[
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xd0, 0xd5, 0xc8, 0xc5, 0xc6, 0xf8,
        ],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // android_wroba_
    (
        &[
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xd4, 0xc8, 0xd1, 0xc6, 0xf8,
        ],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // android_sova_
    (
        &[0xd5, 0xc2, 0xc3, 0xcb, 0xce, 0xc9, 0xc2, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // redline_
    (
        &[0xd5, 0xc6, 0xc4, 0xc4, 0xc8, 0xc8, 0xc9, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // raccoon_
    (
        &[0xc6, 0xdd, 0xc8, 0xd5, 0xd2, 0xcb, 0xd3, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // azorult_
    (
        &[0xd1, 0xce, 0xc3, 0xc6, 0xd5, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // vidar_
    (
        &[0xcb, 0xd2, 0xca, 0xca, 0xc6, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // lumma_
    (
        &[0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc4, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // stealc_
    (
        &[
            0xd5, 0xcf, 0xc6, 0xc3, 0xc6, 0xca, 0xc6, 0xc9, 0xd3, 0xcf, 0xde, 0xd4, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // rhadamanthys_
    (
        &[0xc2, 0xd5, 0xc5, 0xce, 0xd2, 0xca, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // erbium_
    (
        &[
            0xca, 0xde, 0xd4, 0xd3, 0xce, 0xc4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5,
            0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // mystic_stealer_
    (
        &[
            0xd3, 0xce, 0xd3, 0xc6, 0xc9, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // titan_stealer_
    (
        &[
            0xc6, 0xd3, 0xc8, 0xca, 0xce, 0xc4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5,
            0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // atomic_stealer_
    (
        &[
            0xc6, 0xd2, 0xd5, 0xc8, 0xd5, 0xc6, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5,
            0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // aurora_stealer_
    (
        &[
            0xca, 0xc6, 0xd5, 0xd4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // mars_stealer_
    (
        &[0xc6, 0xd5, 0xcc, 0xc2, 0xce, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // arkei_
    (
        &[0xcc, 0xd7, 0xc8, 0xd3, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // kpot_
    (
        &[
            0xd3, 0xc6, 0xd2, 0xd5, 0xd2, 0xd4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5,
            0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // taurus_stealer_
    (
        &[
            0xd7, 0xd5, 0xc2, 0xc3, 0xc6, 0xd3, 0xc8, 0xd5, 0xf8, 0xd3, 0xcf, 0xce, 0xc2, 0xc1,
            0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // predator_thief_
    (
        &[0xc4, 0xd5, 0xde, 0xd7, 0xd3, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // cryptbot_
    (
        &[
            0xc9, 0xc2, 0xdf, 0xd2, 0xd4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // nexus_stealer_
    (
        &[
            0xd0, 0xcf, 0xce, 0xd3, 0xc2, 0xd4, 0xc9, 0xc6, 0xcc, 0xc2, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // whitesnake_
    (
        &[0xd5, 0xce, 0xd4, 0xc2, 0xd7, 0xd5, 0xc8, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // risepro_
    (
        &[
            0xc5, 0xcb, 0xc6, 0xc4, 0xcc, 0xc0, 0xd2, 0xc6, 0xd5, 0xc3, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // blackguard_
    (
        &[
            0xd7, 0xd5, 0xde, 0xc9, 0xd3, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // prynt_stealer_
    (
        &[0xd3, 0xde, 0xd7, 0xcf, 0xc8, 0xc9, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // typhon_
    (
        &[0xc5, 0xd5, 0xc6, 0xc8, 0xc3, 0xc8, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // braodo_
    (
        &[0xd4, 0xc8, 0xc4, 0xc2, 0xcb, 0xc6, 0xd5, 0xd4, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // socelars_
    (
        &[0xcb, 0xc8, 0xcc, 0xce, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // lokibot_
    (
        &[0xc1, 0xc8, 0xd5, 0xca, 0xc5, 0xc8, 0xc8, 0xcc, 0xf8],
        "T1056.003",
        "collection",
        "Input Capture: Web Portal Capture",
    ), // formbook_
    (
        &[
            0xc6, 0xc0, 0xc2, 0xc9, 0xd3, 0xf8, 0xd3, 0xc2, 0xd4, 0xcb, 0xc6, 0xf8,
        ],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // agent_tesla_
    (
        &[
            0xca, 0xc6, 0xd4, 0xd4, 0xcb, 0xc8, 0xc0, 0xc0, 0xc2, 0xd5, 0xf8,
        ],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // masslogger_
    (
        &[0xcf, 0xd0, 0xc8, 0xd5, 0xca, 0xf8],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // hworm_
    (
        &[
            0xc6, 0xca, 0xc8, 0xd4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // amos_stealer_
    (
        &[0xd2, 0xca, 0xc5, 0xd5, 0xc6, 0xcb, 0xf8],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // umbral_
    (
        &[0xc5, 0xd2, 0xca, 0xc5, 0xcb, 0xc2, 0xc5, 0xc2, 0xc2, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // bumblebee_
    (
        &[
            0xd4, 0xd6, 0xd2, 0xce, 0xd5, 0xd5, 0xc2, 0xcb, 0xd0, 0xc6, 0xc1, 0xc1, 0xcb, 0xc2,
            0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // squirrelwaffle_
    (
        &[
            0xc0, 0xc8, 0xc8, 0xd3, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // gootloader_
    (
        &[
            0xc5, 0xc6, 0xdd, 0xc6, 0xd5, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // bazarloader_
    (
        &[0xce, 0xc4, 0xc2, 0xc3, 0xce, 0xc3, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // icedid_
    (
        &[0xc0, 0xd2, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // guloader_
    (
        &[
            0xc3, 0xc8, 0xc9, 0xd2, 0xd3, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // donutloader_
    (
        &[
            0xcb, 0xc6, 0xd3, 0xd5, 0xc8, 0xc3, 0xc2, 0xc4, 0xd3, 0xd2, 0xd4, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // latrodectus_
    (
        &[0xd7, 0xce, 0xcc, 0xc6, 0xc5, 0xc8, 0xd3, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // pikabot_
    (
        &[
            0xca, 0xc6, 0xd3, 0xc6, 0xc9, 0xc5, 0xd2, 0xc4, 0xcf, 0xd2, 0xd4, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // matanbuchus_
    (
        &[0xc3, 0xc6, 0xd5, 0xcc, 0xc0, 0xc6, 0xd3, 0xc2, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // darkgate_
    (
        &[
            0xd7, 0xd5, 0xce, 0xd1, 0xc6, 0xd3, 0xc2, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // privateloader_
    (
        &[
            0xd4, 0xca, 0xc8, 0xcc, 0xc2, 0xcb, 0xc8, 0xc6, 0xc3, 0xc2, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // smokeloader_
    (
        &[0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0xc5, 0xc4, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // systembc_
    (
        &[0xc6, 0xca, 0xc6, 0xc3, 0xc2, 0xde, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // amadey_
    (
        &[0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xca, 0xc2, 0xc3, 0xc6, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // andromeda_
    (
        &[0xc4, 0xcf, 0xc6, 0xce, 0xc9, 0xd4, 0xcf, 0xc8, 0xd3, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // chainshot_
    (
        &[0xd3, 0xce, 0xc9, 0xde, 0xd3, 0xd2, 0xd5, 0xcb, 0xc6, 0xf8],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // tinyturla_
    (
        &[
            0xc5, 0xc6, 0xdd, 0xc6, 0xd5, 0xc5, 0xc6, 0xc4, 0xcc, 0xc3, 0xc8, 0xc8, 0xd5, 0xf8,
        ],
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ), // bazarbackdoor_
    (
        &[
            0xc4, 0xc8, 0xc5, 0xc6, 0xcb, 0xd3, 0xd4, 0xd3, 0xd5, 0xce, 0xcc, 0xc2, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // cobaltstrike_
    (
        &[
            0xca, 0xc2, 0xd3, 0xc2, 0xd5, 0xd7, 0xd5, 0xc2, 0xd3, 0xc2, 0xd5, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // meterpreter_
    (
        &[0xd4, 0xcb, 0xce, 0xd1, 0xc2, 0xd5, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // sliver_
    (
        &[0xc2, 0xca, 0xd7, 0xce, 0xd5, 0xc2, 0xf8],
        "T1059.001",
        "execution",
        "PowerShell",
    ), // empire_
    (
        &[0xce, 0xca, 0xd7, 0xc6, 0xc4, 0xcc, 0xc2, 0xd3, 0xf8],
        "T1021",
        "lateral-movement",
        "Remote Services",
    ), // impacket_
    (
        &[
            0xca, 0xc2, 0xd3, 0xc6, 0xd4, 0xd7, 0xcb, 0xc8, 0xce, 0xd3, 0xf8,
        ],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // metasploit_
    (
        &[0xcf, 0xc6, 0xd1, 0xc8, 0xc4, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // havoc_
    (
        &[
            0xc5, 0xd5, 0xd2, 0xd3, 0xc2, 0xf8, 0xd5, 0xc6, 0xd3, 0xc2, 0xcb, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // brute_ratel_
    (
        &[0xc9, 0xce, 0xc0, 0xcf, 0xd3, 0xcf, 0xc6, 0xd0, 0xcc, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // nighthawk_
    (
        &[0xc4, 0xc8, 0xd1, 0xc2, 0xc9, 0xc6, 0xc9, 0xd3, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // covenant_
    (
        &[0xca, 0xc2, 0xd5, 0xcb, 0xce, 0xc9, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // merlin_
    (
        &[0xd7, 0xc8, 0xd4, 0xcf, 0xc4, 0x95, 0xf8],
        "T1059.001",
        "execution",
        "PowerShell",
    ), // poshc2_
    (
        &[
            0xd4, 0xce, 0xcb, 0xc2, 0xc9, 0xd3, 0xd3, 0xd5, 0xce, 0xc9, 0xce, 0xd3, 0xde, 0xf8,
        ],
        "T1059.006",
        "execution",
        "Python",
    ), // silenttrinity_
    (
        &[0xc3, 0xc2, 0xce, 0xca, 0xc8, 0xd4, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // deimos_
    (
        &[0xc4, 0xc6, 0xcb, 0xc3, 0xc2, 0xd5, 0xc6, 0xf8],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // caldera_
    (
        &[0xca, 0xce, 0xca, 0xce, 0xcc, 0xc6, 0xd3, 0xdd, 0xf8],
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ), // mimikatz_
    (
        &[0xcb, 0xd4, 0xc6, 0xd4, 0xd4, 0xf8],
        "T1003.001",
        "credential-access",
        "OS Credential Dumping: LSASS Memory",
    ), // lsass_
    (
        &[0xd4, 0xc6, 0xca, 0xc3, 0xd2, 0xca, 0xd7, 0xf8],
        "T1003.002",
        "credential-access",
        "OS Credential Dumping: Security Account Manager",
    ), // samdump_
    (
        &[0xc9, 0xd3, 0xc3, 0xd4, 0xf8],
        "T1003.003",
        "credential-access",
        "OS Credential Dumping: NTDS",
    ), // ntds_
    (
        &[0xc3, 0xc4, 0xd4, 0xde, 0xc9, 0xc4, 0xf8],
        "T1003.006",
        "credential-access",
        "OS Credential Dumping: DCSync",
    ), // dcsync_
    (
        &[
            0xcc, 0xc2, 0xd5, 0xc5, 0xc2, 0xd5, 0xc8, 0xc6, 0xd4, 0xd3, 0xf8,
        ],
        "T1558.003",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Kerberoasting",
    ), // kerberoast_
    (
        &[
            0xc0, 0xc8, 0xcb, 0xc3, 0xc2, 0xc9, 0xd3, 0xce, 0xc4, 0xcc, 0xc2, 0xd3, 0xf8,
        ],
        "T1558.001",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Golden Ticket",
    ), // goldenticket_
    (
        &[
            0xd4, 0xce, 0xcb, 0xd1, 0xc2, 0xd5, 0xd3, 0xce, 0xc4, 0xcc, 0xc2, 0xd3, 0xf8,
        ],
        "T1558.002",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Silver Ticket",
    ), // silverticket_
    (
        &[0xd7, 0xc6, 0xd4, 0xd4, 0xcf, 0xc6, 0xd4, 0xcf, 0xf8],
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ), // passhash_
    (
        &[
            0xd7, 0xc6, 0xd4, 0xd4, 0xd3, 0xcf, 0xc2, 0xcf, 0xc6, 0xd4, 0xcf, 0xf8,
        ],
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ), // passthehash_
    (
        &[
            0xc8, 0xd1, 0xc2, 0xd5, 0xd7, 0xc6, 0xd4, 0xd4, 0xd3, 0xcf, 0xc2, 0xcf, 0xc6, 0xd4,
            0xcf, 0xf8,
        ],
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ), // overpassthehash_
    (
        &[0xc5, 0xd5, 0xd2, 0xd3, 0xc2, 0xf8],
        "T1110",
        "credential-access",
        "Brute Force",
    ), // brute_
    (
        &[0xd4, 0xd7, 0xd5, 0xc6, 0xde, 0xf8],
        "T1110.003",
        "credential-access",
        "Brute Force: Password Spraying",
    ), // spray_
    (
        &[0xc4, 0xd5, 0xc2, 0xc3, 0xd4, 0xd3, 0xd2, 0xc1, 0xc1, 0xf8],
        "T1110.004",
        "credential-access",
        "Brute Force: Credential Stuffing",
    ), // credstuff_
    (
        &[0xd7, 0xd0, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xf8],
        "T1555",
        "credential-access",
        "Credentials from Password Stores",
    ), // pwsteal_
    (
        &[
            0xc4, 0xc8, 0xc8, 0xcc, 0xce, 0xc2, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xf8,
        ],
        "T1539",
        "credential-access",
        "Steal Web Session Cookie",
    ), // cookiesteal_
    (
        &[
            0xc4, 0xd5, 0xc2, 0xc3, 0xc2, 0xc9, 0xd3, 0xce, 0xc6, 0xcb, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // credential_
    (
        &[0xd7, 0xd0, 0xc3, 0xd2, 0xca, 0xd7, 0xf8],
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ), // pwdump_
    (
        &[0xc4, 0xc6, 0xc4, 0xcf, 0xc2, 0xc3, 0xd2, 0xca, 0xd7, 0xf8],
        "T1003.005",
        "credential-access",
        "OS Credential Dumping: Cached Domain Credentials",
    ), // cachedump_
    (
        &[0xcf, 0xc6, 0xd4, 0xcf, 0xc3, 0xd2, 0xca, 0xd7, 0xf8],
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ), // hashdump_
    (
        &[0xcc, 0xc2, 0xd5, 0xc5, 0xd5, 0xd2, 0xd3, 0xc2, 0xf8],
        "T1110.003",
        "credential-access",
        "Brute Force: Password Spraying",
    ), // kerbrute_
    (
        &[0xd5, 0xd2, 0xc5, 0xc2, 0xd2, 0xd4, 0xf8],
        "T1558",
        "credential-access",
        "Steal or Forge Kerberos Tickets",
    ), // rubeus_
    (
        &[0xcb, 0xc6, 0xdd, 0xc6, 0xc0, 0xc9, 0xc2, 0xf8],
        "T1555",
        "credential-access",
        "Credentials from Password Stores",
    ), // lazagne_
    (
        &[
            0xc5, 0xcb, 0xc8, 0xc8, 0xc3, 0xcf, 0xc8, 0xd2, 0xc9, 0xc3, 0xf8,
        ],
        "T1087",
        "discovery",
        "Account Discovery",
    ), // bloodhound_
    (
        &[
            0xd4, 0xcf, 0xc6, 0xd5, 0xd7, 0xcf, 0xc8, 0xd2, 0xc9, 0xc3, 0xf8,
        ],
        "T1087",
        "discovery",
        "Account Discovery",
    ), // sharphound_
    (
        &[0xc4, 0xc2, 0xd5, 0xd3, 0xce, 0xd7, 0xde, 0xf8],
        "T1649",
        "credential-access",
        "Steal or Forge Authentication Certificates",
    ), // certipy_
    (
        &[0xc0, 0xc8, 0xc3, 0xc3, 0xce, 0xf8],
        "T1087.002",
        "discovery",
        "Account Discovery: Domain Account",
    ), // goddi_
    (
        &[
            0xc6, 0xc3, 0xce, 0xc3, 0xc9, 0xd4, 0xc3, 0xd2, 0xca, 0xd7, 0xf8,
        ],
        "T1087.002",
        "discovery",
        "Account Discovery: Domain Account",
    ), // adidnsdump_
    (
        &[0xd5, 0xc3, 0xd7, 0xf8],
        "T1021.001",
        "lateral-movement",
        "Remote Services: Remote Desktop Protocol",
    ), // rdp_
    (
        &[0xd1, 0xc9, 0xc4, 0xf8],
        "T1021.005",
        "lateral-movement",
        "Remote Services: VNC",
    ), // vnc_
    (
        &[0xd4, 0xca, 0xc5, 0xf8],
        "T1021.002",
        "lateral-movement",
        "Remote Services: SMB/Windows Admin Shares",
    ), // smb_
    (
        &[0xcb, 0xc6, 0xd3, 0xc2, 0xd5, 0xc6, 0xcb, 0xf8],
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ), // lateral_
    (
        &[0xd7, 0xd4, 0xc2, 0xdf, 0xc2, 0xc4, 0xf8],
        "T1569.002",
        "execution",
        "System Services: Service Execution",
    ), // psexec_
    (
        &[0xd0, 0xca, 0xce, 0xc2, 0xdf, 0xc2, 0xc4, 0xf8],
        "T1047",
        "execution",
        "Windows Management Instrumentation",
    ), // wmiexec_
    (
        &[0xc3, 0xc4, 0xc8, 0xca, 0xf8, 0xc2, 0xdf, 0xc2, 0xc4, 0xf8],
        "T1021.003",
        "lateral-movement",
        "Remote Services: Distributed Component Object Model",
    ), // dcom_exec_
    (
        &[0xd0, 0xce, 0xc9, 0xd5, 0xca, 0xf8],
        "T1021.006",
        "lateral-movement",
        "Remote Services: Windows Remote Management",
    ), // winrm_
    (
        &[0xc6, 0xd3, 0xc2, 0xdf, 0xc2, 0xc4, 0xf8],
        "T1053.005",
        "persistence",
        "Scheduled Task/Job: Scheduled Task",
    ), // atexec_
    (
        &[
            0xd7, 0xc2, 0xd3, 0xce, 0xd3, 0xd7, 0xc8, 0xd3, 0xc6, 0xca, 0xf8,
        ],
        "T1187",
        "credential-access",
        "Forced Authentication",
    ), // petitpotam_
    (
        &[
            0xd7, 0xd5, 0xce, 0xc9, 0xd3, 0xc2, 0xd5, 0xc5, 0xd2, 0xc0, 0xf8,
        ],
        "T1187",
        "credential-access",
        "Forced Authentication",
    ), // printerbug_
    (
        &[0xc4, 0xc8, 0xc2, 0xd5, 0xc4, 0xc2, 0xd5, 0xf8],
        "T1187",
        "credential-access",
        "Forced Authentication",
    ), // coercer_
    (
        &[0xc8, 0xc5, 0xc1, 0xd2, 0xd4, 0xc4, 0xf8],
        "T1027",
        "defense-evasion",
        "Obfuscated Files or Information",
    ), // obfusc_
    (
        &[0xd7, 0xc6, 0xc4, 0xcc, 0xc2, 0xc3, 0xf8],
        "T1027.002",
        "defense-evasion",
        "Obfuscated Files or Information: Software Packing",
    ), // packed_
    (
        &[0xc6, 0xc9, 0xd3, 0xce, 0xc3, 0xc2, 0xc5, 0xd2, 0xc0, 0xf8],
        "T1622",
        "defense-evasion",
        "Debugger Evasion",
    ), // antidebug_
    (
        &[0xc6, 0xc9, 0xd3, 0xce, 0xd1, 0xca, 0xf8],
        "T1497",
        "defense-evasion",
        "Virtualization/Sandbox Evasion",
    ), // antivm_
    (
        &[
            0xc6, 0xc9, 0xd3, 0xce, 0xd4, 0xc6, 0xc9, 0xc3, 0xc5, 0xc8, 0xdf, 0xf8,
        ],
        "T1497",
        "defense-evasion",
        "Virtualization/Sandbox Evasion",
    ), // antisandbox_
    (
        &[0xd3, 0xce, 0xca, 0xc2, 0xd4, 0xd3, 0xc8, 0xca, 0xd7, 0xf8],
        "T1070.006",
        "defense-evasion",
        "Indicator Removal: Timestomp",
    ), // timestomp_
    (
        &[0xcb, 0xc8, 0xc0, 0xc4, 0xcb, 0xc2, 0xc6, 0xd5, 0xf8],
        "T1070.001",
        "defense-evasion",
        "Indicator Removal: Clear Windows Event Logs",
    ), // logclear_
    (
        &[0xd2, 0xc6, 0xc4, 0xc5, 0xde, 0xd7, 0xc6, 0xd4, 0xd4, 0xf8],
        "T1548.002",
        "privilege-escalation",
        "Abuse Elevation Control Mechanism: Bypass UAC",
    ), // uacbypass_
    (
        &[0xc3, 0xcb, 0xcb, 0xcf, 0xce, 0xcd, 0xc6, 0xc4, 0xcc, 0xf8],
        "T1574.001",
        "defense-evasion",
        "Hijack Execution Flow: DLL Search Order Hijacking",
    ), // dllhijack_
    (
        &[
            0xc3, 0xcb, 0xcb, 0xd4, 0xce, 0xc3, 0xc2, 0xcb, 0xc8, 0xc6, 0xc3, 0xf8,
        ],
        "T1574.002",
        "defense-evasion",
        "Hijack Execution Flow: DLL Side-Loading",
    ), // dllsideload_
    (
        &[
            0xc6, 0xc9, 0xd3, 0xce, 0xc1, 0xc8, 0xd5, 0xc2, 0xc9, 0xd4, 0xce, 0xc4, 0xf8,
        ],
        "T1070",
        "defense-evasion",
        "Indicator Removal",
    ), // antiforensic_
    (
        &[
            0xca, 0xc6, 0xd4, 0xd6, 0xd2, 0xc2, 0xd5, 0xc6, 0xc3, 0xc2, 0xf8,
        ],
        "T1036",
        "defense-evasion",
        "Masquerading",
    ), // masquerade_
    (
        &[0xd4, 0xd3, 0xc2, 0xc0, 0xf8],
        "T1027.003",
        "defense-evasion",
        "Obfuscated Files or Information: Steganography",
    ), // steg_
    (
        &[0xc2, 0xc9, 0xc4, 0xc8, 0xc3, 0xc2, 0xf8],
        "T1027",
        "defense-evasion",
        "Obfuscated Files or Information",
    ), // encode_
    (
        &[
            0xd4, 0xce, 0xc0, 0xc9, 0xf8, 0xc1, 0xc8, 0xd5, 0xc0, 0xc2, 0xf8,
        ],
        "T1553.002",
        "defense-evasion",
        "Subvert Trust Controls: Code Signing",
    ), // sign_forge_
    (
        &[0xd2, 0xc9, 0xcf, 0xc8, 0xc8, 0xcc, 0xf8],
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ), // unhook_
    (
        &[
            0xc2, 0xc3, 0xd5, 0xf8, 0xc5, 0xde, 0xd7, 0xc6, 0xd4, 0xd4, 0xf8,
        ],
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ), // edr_bypass_
    (
        &[
            0xc6, 0xca, 0xd4, 0xce, 0xf8, 0xc5, 0xde, 0xd7, 0xc6, 0xd4, 0xd4, 0xf8,
        ],
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ), // amsi_bypass_
    (
        &[
            0xc4, 0xcb, 0xca, 0xf8, 0xc5, 0xde, 0xd7, 0xc6, 0xd4, 0xd4, 0xf8,
        ],
        "T1562",
        "defense-evasion",
        "Impair Defenses",
    ), // clm_bypass_
    (
        &[
            0xc2, 0xd3, 0xd0, 0xf8, 0xc5, 0xde, 0xd7, 0xc6, 0xd4, 0xd4, 0xf8,
        ],
        "T1562.006",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Cloud Logs",
    ), // etw_bypass_
    (
        &[
            0xc3, 0xc2, 0xc1, 0xc2, 0xc9, 0xc3, 0xc2, 0xd5, 0xf8, 0xcc, 0xce, 0xcb, 0xcb, 0xf8,
        ],
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ), // defender_kill_
    (
        &[0xcb, 0xc8, 0xcb, 0xc5, 0xce, 0xc9, 0xf8],
        "T1218",
        "defense-evasion",
        "System Binary Proxy Execution",
    ), // lolbin_
    (
        &[0xd3, 0xc8, 0xcc, 0xc2, 0xc9, 0xf8],
        "T1134",
        "defense-evasion",
        "Access Token Manipulation",
    ), // token_
    (
        &[
            0xce, 0xca, 0xd7, 0xc2, 0xd5, 0xd4, 0xc8, 0xc9, 0xc6, 0xd3, 0xc2, 0xf8,
        ],
        "T1134.001",
        "defense-evasion",
        "Access Token Manipulation: Token Impersonation/Theft",
    ), // impersonate_
    (
        &[
            0xc4, 0xc8, 0xca, 0xd7, 0xce, 0xcb, 0xc2, 0xf8, 0xc6, 0xc1, 0xd3, 0xc2, 0xd5, 0xf8,
        ],
        "T1027.004",
        "defense-evasion",
        "Obfuscated Files or Information: Compile After Delivery",
    ), // compile_after_
    (
        &[
            0xd7, 0xd5, 0xc8, 0xc4, 0xcf, 0xc8, 0xcb, 0xcb, 0xc8, 0xd0, 0xf8,
        ],
        "T1055.012",
        "defense-evasion",
        "Process Injection: Process Hollowing",
    ), // prochollow_
    (
        &[
            0xd5, 0xc2, 0xc1, 0xcb, 0xc2, 0xc4, 0xd3, 0xce, 0xd1, 0xc2, 0xf8,
        ],
        "T1055.001",
        "defense-evasion",
        "Process Injection: Dynamic-link Library Injection",
    ), // reflective_
    (
        &[
            0xd3, 0xcf, 0xd5, 0xc2, 0xc6, 0xc3, 0xcf, 0xce, 0xcd, 0xc6, 0xc4, 0xcc, 0xf8,
        ],
        "T1055.003",
        "defense-evasion",
        "Process Injection: Thread Execution Hijacking",
    ), // threadhijack_
    (
        &[0xc6, 0xd3, 0xc8, 0xca, 0xf8],
        "T1055",
        "defense-evasion",
        "Process Injection",
    ), // atom_
    (
        &[
            0xd7, 0xd5, 0xc8, 0xc4, 0xc3, 0xc8, 0xd7, 0xd7, 0xc2, 0xcb, 0xf8,
        ],
        "T1055.013",
        "defense-evasion",
        "Process Injection: Process Doppelgänging",
    ), // procdoppel_
    (
        &[
            0xc0, 0xcf, 0xc8, 0xd4, 0xd3, 0xd0, 0xd5, 0xce, 0xd3, 0xc2, 0xf8,
        ],
        "T1055.016",
        "defense-evasion",
        "Process Injection: Process Ghostwriting",
    ), // ghostwrite_
    (
        &[
            0xc6, 0xd7, 0xc4, 0xf8, 0xce, 0xc9, 0xcd, 0xc2, 0xc4, 0xd3, 0xf8,
        ],
        "T1055.004",
        "defense-evasion",
        "Process Injection: Asynchronous Procedure Call",
    ), // apc_inject_
    (
        &[0xd7, 0xc2, 0xf8, 0xce, 0xc9, 0xcd, 0xc2, 0xc4, 0xd3, 0xf8],
        "T1055.002",
        "defense-evasion",
        "Process Injection: Portable Executable Injection",
    ), // pe_inject_
    (
        &[0xc5, 0xc8, 0xc8, 0xd3, 0xcc, 0xce, 0xd3, 0xf8],
        "T1542.003",
        "persistence",
        "Pre-OS Boot: Bootkit",
    ), // bootkit_
    (
        &[0xca, 0xc5, 0xd5, 0xf8],
        "T1542.003",
        "persistence",
        "Pre-OS Boot: Bootkit",
    ), // mbr_
    (
        &[0xd2, 0xc2, 0xc1, 0xce, 0xf8],
        "T1542.001",
        "persistence",
        "Pre-OS Boot: System Firmware",
    ), // uefi_
    (
        &[0xd4, 0xc4, 0xcf, 0xd3, 0xc6, 0xd4, 0xcc, 0xf8],
        "T1053.005",
        "persistence",
        "Scheduled Task/Job: Scheduled Task",
    ), // schtask_
    (
        &[0xc4, 0xd5, 0xc8, 0xc9, 0xf8],
        "T1053.003",
        "persistence",
        "Scheduled Task/Job: Cron",
    ), // cron_
    (
        &[
            0xd5, 0xc2, 0xc0, 0xd7, 0xc2, 0xd5, 0xd4, 0xce, 0xd4, 0xd3, 0xf8,
        ],
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ), // regpersist_
    (
        &[0xd4, 0xc2, 0xd5, 0xd1, 0xce, 0xc4, 0xc2, 0xf8],
        "T1543.003",
        "persistence",
        "Create or Modify System Process: Windows Service",
    ), // service_
    (
        &[0xc6, 0xd2, 0xd3, 0xc8, 0xd5, 0xd2, 0xc9, 0xf8],
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ), // autorun_
    (
        &[0xcb, 0xc8, 0xc0, 0xc8, 0xc9, 0xf8],
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ), // logon_
    (
        &[
            0xc4, 0xc8, 0xca, 0xf8, 0xcf, 0xce, 0xcd, 0xc6, 0xc4, 0xcc, 0xf8,
        ],
        "T1546.015",
        "privilege-escalation",
        "Event Triggered Execution: Component Object Model Hijacking",
    ), // com_hijack_
    (
        &[0xc6, 0xd7, 0xd7, 0xce, 0xc9, 0xce, 0xd3, 0xf8],
        "T1546.010",
        "privilege-escalation",
        "Event Triggered Execution: AppInit DLLs",
    ), // appinit_
    (
        &[0xce, 0xc1, 0xc2, 0xc8, 0xf8],
        "T1546.012",
        "privilege-escalation",
        "Event Triggered Execution: Image File Execution Options Injection",
    ), // ifeo_
    (
        &[
            0xd0, 0xca, 0xce, 0xf8, 0xd7, 0xc2, 0xd5, 0xd4, 0xce, 0xd4, 0xd3, 0xf8,
        ],
        "T1546.003",
        "privilege-escalation",
        "Event Triggered Execution: WMI Event Subscription",
    ), // wmi_persist_
    (
        &[
            0xca, 0xc6, 0xc4, 0xd5, 0xc8, 0xf8, 0xd7, 0xc2, 0xd5, 0xd4, 0xce, 0xd4, 0xd3, 0xf8,
        ],
        "T1137",
        "persistence",
        "Office Application Startup",
    ), // macro_persist_
    (
        &[0xc4, 0x95, 0xf8],
        "T1071",
        "command-and-control",
        "Application Layer Protocol",
    ), // c2_
    (
        &[0xc5, 0xc2, 0xc6, 0xc4, 0xc8, 0xc9, 0xf8],
        "T1071",
        "command-and-control",
        "Application Layer Protocol",
    ), // beacon_
    (
        &[0xc3, 0xc9, 0xd4, 0xd3, 0xd2, 0xc9, 0xc9, 0xc2, 0xcb, 0xf8],
        "T1071.004",
        "command-and-control",
        "Application Layer Protocol: DNS",
    ), // dnstunnel_
    (
        &[0xc3, 0xc0, 0xc6, 0xf8],
        "T1568.002",
        "command-and-control",
        "Dynamic Resolution: Domain Generation Algorithms",
    ), // dga_
    (
        &[0xc1, 0xc6, 0xd4, 0xd3, 0xc1, 0xcb, 0xd2, 0xdf, 0xf8],
        "T1568.001",
        "command-and-control",
        "Dynamic Resolution: Fast Flux DNS",
    ), // fastflux_
    (
        &[0xd7, 0xd5, 0xc8, 0xdf, 0xde, 0xf8],
        "T1090",
        "command-and-control",
        "Proxy",
    ), // proxy_
    (
        &[0xd3, 0xd2, 0xc9, 0xc9, 0xc2, 0xcb, 0xf8],
        "T1572",
        "command-and-control",
        "Protocol Tunneling",
    ), // tunnel_
    (
        &[
            0xce, 0xc4, 0xca, 0xd7, 0xd3, 0xd2, 0xc9, 0xc9, 0xc2, 0xcb, 0xf8,
        ],
        "T1095",
        "command-and-control",
        "Non-Application Layer Protocol",
    ), // icmptunnel_
    (
        &[
            0xc3, 0xc8, 0xca, 0xc6, 0xce, 0xc9, 0xc1, 0xd5, 0xc8, 0xc9, 0xd3, 0xce, 0xc9, 0xc0,
            0xf8,
        ],
        "T1090.004",
        "command-and-control",
        "Proxy: Domain Fronting",
    ), // domainfronting_
    (
        &[0xd7, 0x95, 0xd7, 0xf8],
        "T1090",
        "command-and-control",
        "Proxy",
    ), // p2p_
    (
        &[0xc4, 0x95, 0xf8, 0xcf, 0xd3, 0xd3, 0xd7, 0xf8],
        "T1071.001",
        "command-and-control",
        "Application Layer Protocol: Web Protocols",
    ), // c2_http_
    (
        &[0xc4, 0x95, 0xf8, 0xc3, 0xc9, 0xd4, 0xf8],
        "T1071.004",
        "command-and-control",
        "Application Layer Protocol: DNS",
    ), // c2_dns_
    (
        &[0xc4, 0x95, 0xf8, 0xd4, 0xca, 0xd3, 0xd7, 0xf8],
        "T1071.003",
        "command-and-control",
        "Application Layer Protocol: Mail Protocols",
    ), // c2_smtp_
    (
        &[0xc4, 0x95, 0xf8, 0xc4, 0xd2, 0xd4, 0xd3, 0xc8, 0xca, 0xf8],
        "T1095",
        "command-and-control",
        "Non-Application Layer Protocol",
    ), // c2_custom_
    (
        &[
            0xd5, 0xc2, 0xd1, 0xc2, 0xd5, 0xd4, 0xc2, 0xf8, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8,
        ],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // reverse_shell_
    (
        &[0xc5, 0xce, 0xc9, 0xc3, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // bindshell_
    (
        &[
            0xd4, 0xc4, 0xd5, 0xc2, 0xc2, 0xc9, 0xd4, 0xcf, 0xc8, 0xd3, 0xf8,
        ],
        "T1113",
        "collection",
        "Screen Capture",
    ), // screenshot_
    (
        &[0xc6, 0xd2, 0xc3, 0xce, 0xc8, 0xc4, 0xc6, 0xd7, 0xf8],
        "T1123",
        "collection",
        "Audio Capture",
    ), // audiocap_
    (
        &[0xd0, 0xc2, 0xc5, 0xc4, 0xc6, 0xca, 0xf8],
        "T1125",
        "collection",
        "Video Capture",
    ), // webcam_
    (
        &[0xc2, 0xdf, 0xc1, 0xce, 0xcb, 0xf8],
        "T1041",
        "exfiltration",
        "Exfiltration Over C2 Channel",
    ), // exfil_
    (
        &[0xcc, 0xc2, 0xde, 0xcb, 0xc8, 0xc0, 0xf8],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // keylog_
    (
        &[0xc4, 0xcb, 0xce, 0xd7, 0xcb, 0xc8, 0xc0, 0xf8],
        "T1115",
        "collection",
        "Clipboard Data",
    ), // cliplog_
    (
        &[0xd4, 0xc4, 0xd5, 0xc2, 0xc2, 0xc9, 0xd5, 0xc2, 0xc4, 0xf8],
        "T1113",
        "collection",
        "Screen Capture",
    ), // screenrec_
    (
        &[
            0xc6, 0xd5, 0xc4, 0xcf, 0xce, 0xd1, 0xc2, 0xf8, 0xc2, 0xdf, 0xc1, 0xce, 0xcb, 0xf8,
        ],
        "T1560",
        "collection",
        "Archive Collected Data",
    ), // archive_exfil_
    (
        &[
            0xc4, 0xcb, 0xc8, 0xd2, 0xc3, 0xf8, 0xc2, 0xdf, 0xc1, 0xce, 0xcb, 0xf8,
        ],
        "T1567",
        "exfiltration",
        "Exfiltration Over Web Service",
    ), // cloud_exfil_
    (
        &[
            0xc2, 0xca, 0xc6, 0xce, 0xcb, 0xf8, 0xc2, 0xdf, 0xc1, 0xce, 0xcb, 0xf8,
        ],
        "T1048.003",
        "exfiltration",
        "Exfiltration Over Alternative Protocol",
    ), // email_exfil_
    (
        &[
            0xc5, 0xd5, 0xc8, 0xd0, 0xd4, 0xc2, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xf8,
        ],
        "T1539",
        "credential-access",
        "Steal Web Session Cookie",
    ), // browse_steal_
    (
        &[
            0xc1, 0xce, 0xcb, 0xc2, 0xd4, 0xc2, 0xc6, 0xd5, 0xc4, 0xcf, 0xf8,
        ],
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ), // filesearch_
    (
        &[0xca, 0xc6, 0xc4, 0xd5, 0xc8, 0xf8],
        "T1137",
        "persistence",
        "Office Application Startup",
    ), // macro_
    (
        &[0xd1, 0xc5, 0xc6, 0xf8],
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ), // vba_
    (
        &[0xcd, 0xd4, 0xc4, 0xd5, 0xce, 0xd7, 0xd3, 0xf8],
        "T1059.007",
        "execution",
        "Command and Scripting Interpreter: JavaScript",
    ), // jscript_
    (
        &[0xd0, 0xca, 0xce, 0xf8],
        "T1047",
        "execution",
        "Windows Management Instrumentation",
    ), // wmi_
    (
        &[0xcb, 0xc9, 0xcc, 0xf8],
        "T1204.002",
        "execution",
        "User Execution: Malicious File",
    ), // lnk_
    (
        &[0xce, 0xd4, 0xc8, 0xf8],
        "T1553.005",
        "defense-evasion",
        "Subvert Trust Controls: Mark-of-the-Web Bypass",
    ), // iso_
    (
        &[0xc3, 0xc3, 0xc2, 0xf8],
        "T1559.002",
        "execution",
        "Inter-Process Communication: Dynamic Data Exchange",
    ), // dde_
    (
        &[0xcf, 0xd3, 0xc6, 0xf8],
        "T1218.005",
        "defense-evasion",
        "System Binary Proxy Execution: Mshta",
    ), // hta_
    (
        &[0xca, 0xd4, 0xcf, 0xd3, 0xc6, 0xf8],
        "T1218.005",
        "defense-evasion",
        "System Binary Proxy Execution: Mshta",
    ), // mshta_
    (
        &[0xd5, 0xc2, 0xc0, 0xd4, 0xd1, 0xd5, 0x94, 0x95, 0xf8],
        "T1218.010",
        "defense-evasion",
        "System Binary Proxy Execution: Regsvr32",
    ), // regsvr32_
    (
        &[0xd5, 0xd2, 0xc9, 0xc3, 0xcb, 0xcb, 0x94, 0x95, 0xf8],
        "T1218.011",
        "defense-evasion",
        "System Binary Proxy Execution: Rundll32",
    ), // rundll32_
    (
        &[0xca, 0xd4, 0xce, 0xc2, 0xdf, 0xc2, 0xc4, 0xf8],
        "T1218.007",
        "defense-evasion",
        "System Binary Proxy Execution: Msiexec",
    ), // msiexec_
    (
        &[0xc4, 0xc2, 0xd5, 0xd3, 0xd2, 0xd3, 0xce, 0xcb, 0xf8],
        "T1140",
        "defense-evasion",
        "Deobfuscate/Decode Files or Information",
    ), // certutil_
    (
        &[0xc5, 0xce, 0xd3, 0xd4, 0xc6, 0xc3, 0xca, 0xce, 0xc9, 0xf8],
        "T1197",
        "defense-evasion",
        "BITS Jobs",
    ), // bitsadmin_
    (
        &[0xc4, 0xca, 0xd4, 0xd3, 0xd7, 0xf8],
        "T1218.003",
        "defense-evasion",
        "System Binary Proxy Execution: CMSTP",
    ), // cmstp_
    (
        &[0xd0, 0xd4, 0xc4, 0xd5, 0xce, 0xd7, 0xd3, 0xf8],
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ), // wscript_
    (
        &[0xc4, 0xd4, 0xc4, 0xd5, 0xce, 0xd7, 0xd3, 0xf8],
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ), // cscript_
    (
        &[
            0xc2, 0xdf, 0xd7, 0xcb, 0xc8, 0xce, 0xd3, 0xcc, 0xce, 0xd3, 0xf8,
        ],
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ), // exploitkit_
    (
        &[
            0xc3, 0xd5, 0xce, 0xd1, 0xc2, 0xc5, 0xde, 0xc3, 0xc8, 0xd0, 0xc9, 0xcb, 0xc8, 0xc6,
            0xc3, 0xf8,
        ],
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ), // drivebydownload_
    (
        &[0xcf, 0xc2, 0xc6, 0xd7, 0xd4, 0xd7, 0xd5, 0xc6, 0xde, 0xf8],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // heapspray_
    (
        &[0xd5, 0xc4, 0xc2, 0xf8],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // rce_
    (
        &[0xcb, 0xd7, 0xc2, 0xf8],
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ), // lpe_
    (
        &[0xd7, 0xcf, 0xce, 0xd4, 0xcf, 0xf8],
        "T1566",
        "initial-access",
        "Phishing",
    ), // phish_
    (
        &[0xd0, 0xc6, 0xd3, 0xc2, 0xd5, 0xce, 0xc9, 0xc0, 0xf8],
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ), // watering_
    (
        &[0xd4, 0xca, 0xce, 0xd4, 0xcf, 0xce, 0xc9, 0xc0, 0xf8],
        "T1566",
        "initial-access",
        "Phishing",
    ), // smishing_
    (
        &[0xd1, 0xce, 0xd4, 0xcf, 0xce, 0xc9, 0xc0, 0xf8],
        "T1566",
        "initial-access",
        "Phishing",
    ), // vishing_
    (
        &[0xd4, 0xd7, 0xc2, 0xc6, 0xd5, 0xf8],
        "T1566.001",
        "initial-access",
        "Phishing: Spearphishing Attachment",
    ), // spear_
    (
        &[
            0xd4, 0xd2, 0xd7, 0xd7, 0xcb, 0xde, 0xf8, 0xc4, 0xcf, 0xc6, 0xce, 0xc9, 0xf8,
        ],
        "T1195",
        "initial-access",
        "Supply Chain Compromise",
    ), // supply_chain_
    (
        &[0xd3, 0xde, 0xd7, 0xc8, 0xd4, 0xd6, 0xd2, 0xc6, 0xd3, 0xf8],
        "T1195.002",
        "initial-access",
        "Supply Chain Compromise: Compromise Software Supply Chain",
    ), // typosquat_
    (
        &[
            0xd3, 0xd5, 0xd2, 0xd4, 0xd3, 0xc2, 0xc3, 0xd5, 0xc2, 0xcb, 0xf8,
        ],
        "T1199",
        "initial-access",
        "Trusted Relationship",
    ), // trustedrel_
    (
        &[0xd5, 0xc2, 0xd7, 0xc8, 0xc4, 0xc8, 0xc9, 0xc1, 0xf8],
        "T1195.001",
        "initial-access",
        "Supply Chain Compromise: Compromise Software Dependencies",
    ), // repoconf_
    (
        &[
            0xc2, 0xd3, 0xc2, 0xd5, 0xc9, 0xc6, 0xcb, 0xc5, 0xcb, 0xd2, 0xc2, 0xf8,
        ],
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ), // eternalblue_
    (
        &[0xca, 0xd4, 0x96, 0x90, 0xf8, 0x97, 0x96, 0x97, 0xf8],
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ), // ms17_010_
    (
        &[0xcb, 0xc8, 0xc0, 0x93, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // log4shell_
    (
        &[0xcb, 0x93, 0xcd, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // l4jshell_
    (
        &[
            0xd7, 0xd5, 0xc8, 0xdf, 0xde, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // proxyshell_
    (
        &[
            0xd7, 0xd5, 0xc8, 0xdf, 0xde, 0xcb, 0xc8, 0xc0, 0xc8, 0xc9, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // proxylogon_
    (
        &[
            0xd7, 0xd5, 0xce, 0xc9, 0xd3, 0xc9, 0xce, 0xc0, 0xcf, 0xd3, 0xca, 0xc6, 0xd5, 0xc2,
            0xf8,
        ],
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ), // printnightmare_
    (
        &[0xdd, 0xc2, 0xd5, 0xc8, 0xcb, 0xc8, 0xc0, 0xc8, 0xc9, 0xf8],
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ), // zerologon_
    (
        &[0xc5, 0xcb, 0xd2, 0xc2, 0xcc, 0xc2, 0xc2, 0xd7, 0xf8],
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ), // bluekeep_
    (
        &[0xc1, 0xc8, 0xcb, 0xcb, 0xce, 0xc9, 0xc6, 0xf8],
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ), // follina_
    (
        &[
            0xd4, 0xd7, 0xd5, 0xce, 0xc9, 0xc0, 0x93, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // spring4shell_
    (
        &[
            0xc4, 0xce, 0xd3, 0xd5, 0xce, 0xdf, 0xc5, 0xcb, 0xc2, 0xc2, 0xc3, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // citrixbleed_
    (
        &[
            0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xd4, 0xcf, 0xc8, 0xc4, 0xcc, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // shellshock_
    (
        &[
            0xcf, 0xc2, 0xc6, 0xd5, 0xd3, 0xc5, 0xcb, 0xc2, 0xc2, 0xc3, 0xf8,
        ],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // heartbleed_
    (
        &[0xc4, 0xd1, 0xc2, 0xf8],
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ), // cve_
    (
        &[0xc3, 0xc8, 0xd4, 0xf8],
        "T1499",
        "impact",
        "Endpoint Denial of Service",
    ), // dos_
    (
        &[0xc3, 0xc3, 0xc8, 0xd4, 0xf8],
        "T1498",
        "impact",
        "Network Denial of Service",
    ), // ddos_
    (
        &[0xd1, 0xd4, 0xd4, 0xf8],
        "T1490",
        "impact",
        "Inhibit System Recovery",
    ), // vss_
    (
        &[0xd4, 0xcf, 0xc6, 0xc3, 0xc8, 0xd0, 0xf8],
        "T1490",
        "impact",
        "Inhibit System Recovery",
    ), // shadow_
    (
        &[0xc3, 0xce, 0xd4, 0xcc, 0xf8, 0xd0, 0xce, 0xd7, 0xc2, 0xf8],
        "T1561",
        "impact",
        "Disk Wipe",
    ), // disk_wipe_
    (
        &[0xca, 0xc5, 0xd5, 0xf8, 0xd0, 0xce, 0xd7, 0xc2, 0xf8],
        "T1561.002",
        "impact",
        "Disk Wipe: Disk Structure Wipe",
    ), // mbr_wipe_
    (
        &[
            0xc3, 0xc2, 0xc1, 0xc6, 0xc4, 0xc2, 0xca, 0xc2, 0xc9, 0xd3, 0xf8,
        ],
        "T1491",
        "impact",
        "Defacement",
    ), // defacement_
    (
        &[
            0xc3, 0xc6, 0xd3, 0xc6, 0xf8, 0xc3, 0xc2, 0xd4, 0xd3, 0xd5, 0xc8, 0xde, 0xf8,
        ],
        "T1485",
        "impact",
        "Data Destruction",
    ), // data_destroy_
    (
        &[0xc1, 0xce, 0xd5, 0xca, 0xf8, 0xd0, 0xce, 0xd7, 0xc2, 0xf8],
        "T1495",
        "impact",
        "Firmware Corruption",
    ), // firm_wipe_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xd5, 0xc8, 0xc8, 0xd3, 0xcc, 0xce, 0xd3, 0xf8,
        ],
        "T1014",
        "defense-evasion",
        "Rootkit",
    ), // linux_rootkit_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xc5, 0xc6, 0xc4, 0xcc, 0xc3, 0xc8, 0xc8, 0xd5,
            0xf8,
        ],
        "T1505",
        "persistence",
        "Server Software Component",
    ), // linux_backdoor_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xca, 0xce, 0xc9, 0xc2, 0xd5, 0xf8,
        ],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // linux_miner_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xd0, 0xc8, 0xd5, 0xca, 0xf8,
        ],
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ), // linux_worm_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // linux_ransom_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // linux_stealer_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xc2, 0xc5, 0xd2, 0xd5, 0xde, 0xf8,
        ],
        "T1505",
        "persistence",
        "Server Software Component",
    ), // linux_ebury_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xca, 0xce, 0xd5, 0xc6, 0xce, 0xf8,
        ],
        "T1498",
        "impact",
        "Network Denial of Service",
    ), // linux_mirai_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xdf, 0xc8, 0xd5, 0xc3, 0xc3, 0xc8, 0xd4, 0xf8,
        ],
        "T1498",
        "impact",
        "Network Denial of Service",
    ), // linux_xorddos_
    (
        &[
            0xcb, 0xce, 0xc9, 0xd2, 0xdf, 0xf8, 0xd4, 0xcc, 0xce, 0xc3, 0xca, 0xc6, 0xd7, 0xf8,
        ],
        "T1496",
        "impact",
        "Resource Hijacking",
    ), // linux_skidmap_
    (
        &[
            0xca, 0xc6, 0xc4, 0xc8, 0xd4, 0xf8, 0xc5, 0xc6, 0xc4, 0xcc, 0xc3, 0xc8, 0xc8, 0xd5,
            0xf8,
        ],
        "T1505",
        "persistence",
        "Server Software Component",
    ), // macos_backdoor_
    (
        &[
            0xca, 0xc6, 0xc4, 0xc8, 0xd4, 0xf8, 0xd7, 0xc2, 0xd5, 0xd4, 0xce, 0xd4, 0xd3, 0xf8,
        ],
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ), // macos_persist_
    (
        &[
            0xca, 0xc6, 0xc4, 0xc8, 0xd4, 0xf8, 0xd4, 0xd3, 0xc2, 0xc6, 0xcb, 0xc2, 0xd5, 0xf8,
        ],
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ), // macos_stealer_
    (
        &[
            0xca, 0xc6, 0xc4, 0xc8, 0xd4, 0xf8, 0xcc, 0xc2, 0xde, 0xcb, 0xc8, 0xc0, 0xf8,
        ],
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ), // macos_keylog_
    (
        &[
            0xca, 0xc6, 0xc4, 0xc8, 0xd4, 0xf8, 0xc6, 0xc3, 0xcb, 0xc8, 0xc6, 0xc3, 0xf8,
        ],
        "T1176",
        "persistence",
        "Browser Extensions",
    ), // macos_adload_
    (
        &[
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xc5, 0xc6, 0xc9, 0xcc, 0xc2, 0xd5,
            0xf8,
        ],
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ), // android_banker_
    (
        &[
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xd4, 0xd7, 0xde, 0xd0, 0xc6, 0xd5,
            0xc2, 0xf8,
        ],
        "T1430",
        "collection",
        "Location Tracking",
    ), // android_spyware_
    (
        &[
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xd5, 0xc6, 0xd3, 0xf8,
        ],
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ), // android_rat_
    (
        &[
            0xce, 0xc8, 0xd4, 0xf8, 0xd4, 0xd7, 0xde, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8,
        ],
        "T1430",
        "collection",
        "Location Tracking",
    ), // ios_spyware_
    (
        &[
            0xce, 0xc8, 0xd3, 0xf8, 0xc5, 0xc8, 0xd3, 0xc9, 0xc2, 0xd3, 0xf8,
        ],
        "T1498",
        "impact",
        "Network Denial of Service",
    ), // iot_botnet_
    (
        &[
            0xce, 0xc8, 0xd3, 0xf8, 0xd5, 0xc6, 0xc9, 0xd4, 0xc8, 0xca, 0xf8,
        ],
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ), // iot_ransom_
    (
        &[0xd7, 0xde, 0xd3, 0xcf, 0xc8, 0xc9, 0xf8],
        "T1059.006",
        "execution",
        "Command and Scripting Interpreter: Python",
    ), // python_
    (
        &[0xc0, 0xc8, 0xcb, 0xc6, 0xc9, 0xc0, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // golang_
    (
        &[0xc9, 0xce, 0xca, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // nim_
    (
        &[
            0xd5, 0xd2, 0xd4, 0xd3, 0xf8, 0xca, 0xc6, 0xcb, 0xd0, 0xc6, 0xd5, 0xc2, 0xf8,
        ],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // rust_malware_
    (
        &[0xc3, 0xc8, 0xd3, 0xc9, 0xc2, 0xd3, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // dotnet_
    (
        &[0xc5, 0xc6, 0xd4, 0xcf, 0xf8],
        "T1059.004",
        "execution",
        "Command and Scripting Interpreter: Unix Shell",
    ), // bash_
    (
        &[0xd7, 0xcf, 0xd7, 0xf8],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // php_
    (
        &[
            0xc6, 0xd2, 0xd3, 0xc8, 0xcf, 0xc8, 0xd3, 0xcc, 0xc2, 0xde, 0xf8,
        ],
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ), // autohotkey_
    (
        &[0xd7, 0xc8, 0xd5, 0xd3, 0xd4, 0xc4, 0xc6, 0xc9, 0xf8],
        "T1046",
        "discovery",
        "Network Service Discovery",
    ), // portscan_
    (
        &[0xd4, 0xc9, 0xce, 0xc1, 0xc1, 0xc2, 0xd5, 0xf8],
        "T1040",
        "credential-access",
        "Network Sniffing",
    ), // sniffer_
    (
        &[
            0xc6, 0xd5, 0xd7, 0xf8, 0xd7, 0xc8, 0xce, 0xd4, 0xc8, 0xc9, 0xf8,
        ],
        "T1557.002",
        "credential-access",
        "Adversary-in-the-Middle: ARP Cache Poisoning",
    ), // arp_poison_
    (
        &[0xca, 0xce, 0xd3, 0xca, 0xf8],
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ), // mitm_
    (
        &[0xc3, 0xc9, 0xd4, 0xd4, 0xd7, 0xc8, 0xc8, 0xc1, 0xf8],
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ), // dnsspoof_
    (
        &[0xd4, 0xd4, 0xcb, 0xd4, 0xd3, 0xd5, 0xce, 0xd7, 0xf8],
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ), // sslstrip_
    (
        &[0xc9, 0xca, 0xc6, 0xd7, 0xf8],
        "T1046",
        "discovery",
        "Network Service Discovery",
    ), // nmap_
    (
        &[0xca, 0xc6, 0xd4, 0xd4, 0xc4, 0xc6, 0xc9, 0xf8],
        "T1046",
        "discovery",
        "Network Service Discovery",
    ), // masscan_
    (
        &[0xcb, 0xce, 0xc9, 0xd7, 0xc2, 0xc6, 0xd4, 0xf8],
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ), // linpeas_
    (
        &[0xd0, 0xce, 0xc9, 0xd7, 0xc2, 0xc6, 0xd4, 0xf8],
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ), // winpeas_
    (
        &[0xd4, 0xc2, 0xc6, 0xd3, 0xc5, 0xc2, 0xcb, 0xd3, 0xf8],
        "T1082",
        "discovery",
        "System Information Discovery",
    ), // seatbelt_
    (
        &[0xd7, 0xc8, 0xd0, 0xc2, 0xd5, 0xd1, 0xce, 0xc2, 0xd0, 0xf8],
        "T1069",
        "discovery",
        "Permission Groups Discovery",
    ), // powerview_
    (
        &[0xd5, 0xc2, 0xd4, 0xd7, 0xc8, 0xc9, 0xc3, 0xc2, 0xd5, 0xf8],
        "T1557.001",
        "credential-access",
        "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
    ), // responder_
    (
        &[0xcc, 0xc2, 0xd5, 0xc5, 0xc2, 0xd5, 0xc8, 0xd4, 0xf8],
        "T1558",
        "credential-access",
        "Steal or Forge Kerberos Tickets",
    ), // kerberos_
    (
        &[0xc9, 0xc6, 0xca, 0xc2, 0xc3, 0xd7, 0xce, 0xd7, 0xc2, 0xf8],
        "T1559.001",
        "execution",
        "Inter-Process Communication: Component Object Model",
    ), // namedpipe_
    (
        &[
            0xd4, 0xc6, 0xca, 0xf8, 0xc6, 0xc4, 0xc4, 0xc2, 0xd4, 0xd4, 0xf8,
        ],
        "T1003.002",
        "credential-access",
        "OS Credential Dumping: Security Account Manager",
    ), // sam_access_
    (
        &[
            0xd4, 0xc2, 0xc4, 0xd5, 0xc2, 0xd3, 0xd4, 0xc3, 0xd2, 0xca, 0xd7, 0xf8,
        ],
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ), // secretsdump_
    (
        &[0xd5, 0xc2, 0xc0, 0xf8, 0xd4, 0xcf, 0xc2, 0xcb, 0xcb, 0xf8],
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ), // reg_shell_
];

/// Look up a MITRE ATT&CK technique by matching the start of `rule_name`
/// case-insensitively against the known prefix table.
///
/// Returns `None` if no prefix matches.
pub fn lookup_attack_for_rule_name(rule_name: &str) -> Option<AttackTechnique> {
    let lower = rule_name.to_lowercase();
    for &(prefix, technique_id, tactic, name) in ATTACK_PREFIXES {
        if crate::obf::starts_with_obf(&lower, prefix, crate::obf::OBF_KEY) {
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
    fn all_original_20_prefixes_are_reachable() {
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

    // ── Long-tail prefix tests ──────────────────────────────────────────────

    #[test]
    fn malware_archetypes_are_mapped() {
        let cases = [
            ("trojan_zeus", "T1204"),
            ("spyware_pegasus", "T1113"),
            ("spy_agent", "T1113"),
            ("adware_fireball", "T1176"),
            ("banker_emotet", "T1185"),
            ("packer_upx", "T1027.002"),
            ("clickfraud_adrozek", "T1496"),
            ("worm_wannacry", "T1570"),
            ("virus_bifrost", "T1203"),
            ("dialer_premium", "T1571"),
            ("downloader_upatre", "T1105"),
            ("infostealer_vidar", "T1552"),
            ("formgrab_zeus", "T1056.003"),
            ("stalkerware_spyic", "T1125"),
            ("clipper_cryptobot", "T1115"),
            ("cryptominer_xmrig", "T1496"),
            ("cryptojack_coinhive", "T1496"),
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
            ("lsass_dump", "T1003.001"),
            ("samdump_hive", "T1003.002"),
            ("ntds_extract", "T1003.003"),
            ("dcsync_attack", "T1003.006"),
            ("kerberoast_spn", "T1558.003"),
            ("goldenticket_forge", "T1558.001"),
            ("silverticket_forge", "T1558.002"),
            ("passhash_relay", "T1550.002"),
            ("brute_force_rdp", "T1110"),
            ("spray_password", "T1110.003"),
            ("credstuff_combo", "T1110.004"),
            ("pwsteal_pony", "T1555"),
            ("cookiesteal_chrome", "T1539"),
            ("mimikatz_sekurlsa", "T1003"),
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
            ("rdp_scanner", "T1021.001"),
            ("vnc_hijack", "T1021.005"),
            ("smb_relay", "T1021.002"),
            ("lateral_psexec", "T1570"),
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
            ("obfusc_xor", "T1027"),
            ("packed_pe", "T1027.002"),
            ("antidebug_isdebugged", "T1622"),
            ("antivm_cpuid", "T1497"),
            ("antisandbox_sleep", "T1497"),
            ("timestomp_mace", "T1070.006"),
            ("logclear_evtx", "T1070.001"),
            ("uacbypass_fodhelper", "T1548.002"),
            ("dllhijack_phantom", "T1574.001"),
            ("dllsideload_teams", "T1574.002"),
            ("antiforensic_wipe", "T1070"),
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
            ("prochollow_svchost", "T1055.012"),
            ("reflective_dll", "T1055.001"),
            ("threadhijack_remote", "T1055.003"),
            ("atom_bombing", "T1055"),
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
            ("bootkit_necurs", "T1542.003"),
            ("mbr_infector", "T1542.003"),
            ("uefi_lojax", "T1542.001"),
            ("schtask_persist", "T1053.005"),
            ("cron_persist", "T1053.003"),
            ("regpersist_run", "T1547.001"),
            ("service_hollow", "T1543.003"),
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
            ("c2_http", "T1071"),
            ("beacon_cobalt", "T1071"),
            ("dnstunnel_iodine", "T1071.004"),
            ("dga_conficker", "T1568.002"),
            ("fastflux_storm", "T1568.001"),
            ("proxy_socks5", "T1090"),
            ("tunnel_ssh", "T1572"),
            ("icmptunnel_ping", "T1095"),
            ("domainfronting_cdn", "T1090.004"),
            ("p2p_botnet", "T1090"),
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
            ("screenshot_grab", "T1113"),
            ("audiocap_record", "T1123"),
            ("webcam_capture", "T1125"),
            ("exfil_ftp", "T1041"),
            ("keylog_hook", "T1056.001"),
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
            ("macro_office", "T1137"),
            ("vba_shellcode", "T1059.005"),
            ("jscript_rat", "T1059.007"),
            ("wmi_exec", "T1047"),
            ("lnk_shortcut", "T1204.002"),
            ("iso_smuggle", "T1553.005"),
            ("dde_office", "T1559.002"),
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
            ("exploitkit_angler", "T1189"),
            ("drivebydownload_zeroday", "T1189"),
            ("heapspray_ie", "T1203"),
            ("rce_log4j", "T1203"),
            ("lpe_kernel", "T1068"),
            ("phish_spear", "T1566"),
            ("watering_hole", "T1189"),
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
            ("dos_synflood", "T1499"),
            ("ddos_amplify", "T1498"),
            ("vss_delete", "T1490"),
            ("shadow_wipe", "T1490"),
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
            ("meterpreter_shell", "T1219"),
            ("sliver_implant", "T1219"),
            ("empire_stager", "T1059.001"),
            ("impacket_secretsdump", "T1021"),
            ("metasploit_msfvenom", "T1203"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("prefix for '{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn named_ransomware_families_are_mapped() {
        let families = [
            "lockbit_",
            "conti_",
            "revil_",
            "blackcat_",
            "alphv_",
            "cl0p_",
            "akira_",
            "blackbasta_",
            "rhysida_",
            "trigona_",
            "babuk_",
            "dharma_",
        ];
        for prefix in families {
            let r = lookup_attack_for_rule_name(&format!("{prefix}sample"))
                .unwrap_or_else(|| panic!("'{prefix}' returned None"));
            assert_eq!(r.technique_id, "T1486", "'{prefix}' should map to T1486");
        }
    }

    #[test]
    fn named_rat_families_are_mapped() {
        let families = [
            "asyncrat_",
            "njrat_",
            "remcos_",
            "quasar_",
            "plugx_",
            "gh0st_",
            "shadowpad_",
            "xworm_",
            "dcrat_",
            "warzone_",
            "bifrost_",
        ];
        for prefix in families {
            let r = lookup_attack_for_rule_name(&format!("{prefix}sample"))
                .unwrap_or_else(|| panic!("'{prefix}' returned None"));
            assert_eq!(r.technique_id, "T1219", "'{prefix}' should map to T1219");
        }
    }

    #[test]
    fn named_infostealer_families_are_mapped() {
        let families = [
            "redline_",
            "raccoon_",
            "vidar_",
            "lumma_",
            "stealc_",
            "rhadamanthys_",
            "azorult_",
            "arkei_",
            "kpot_",
            "whitesnake_",
        ];
        for prefix in families {
            let r = lookup_attack_for_rule_name(&format!("{prefix}sample"))
                .unwrap_or_else(|| panic!("'{prefix}' returned None"));
            assert_eq!(r.technique_id, "T1552", "'{prefix}' should map to T1552");
        }
    }

    #[test]
    fn named_loader_families_are_mapped() {
        let families = [
            "bumblebee_",
            "icedid_",
            "guloader_",
            "pikabot_",
            "darkgate_",
            "smokeloader_",
            "amadey_",
            "latrodectus_",
            "systembc_",
        ];
        for prefix in families {
            let r = lookup_attack_for_rule_name(&format!("{prefix}sample"))
                .unwrap_or_else(|| panic!("'{prefix}' returned None"));
            assert_eq!(r.technique_id, "T1105", "'{prefix}' should map to T1105");
        }
    }

    #[test]
    fn cve_specific_prefixes_are_mapped() {
        let cases = [
            ("eternalblue_exploit", "T1210"),
            ("log4shell_payload", "T1190"),
            ("proxyshell_rce", "T1190"),
            ("zerologon_poc", "T1068"),
            ("bluekeep_exploit", "T1210"),
            ("follina_doc", "T1203"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("'{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    #[test]
    fn platform_specific_prefixes_are_mapped() {
        let cases = [
            ("linux_rootkit_sample", "T1014"),
            ("linux_miner_xmrig", "T1496"),
            ("macos_backdoor_sample", "T1505"),
            ("android_banker_cerb", "T1185"),
            ("android_spyware_pegasus", "T1430"),
            ("iot_botnet_mirai", "T1498"),
        ];
        for (rule, expected_id) in cases {
            let r = lookup_attack_for_rule_name(rule)
                .unwrap_or_else(|| panic!("'{rule}' returned None"));
            assert_eq!(r.technique_id, expected_id, "wrong id for '{rule}'");
        }
    }

    // ── Pruning RED tests ───────────────────────────────────────────────────
    // Assert entries that should be removed/renamed after table pruning.
    // All fail until the table is updated.

    #[test]
    fn golang_prefix_replaces_go() {
        // go_ renamed → golang_: golang_ must match, bare go_ must not
        assert!(
            lookup_attack_for_rule_name("golang_implant").is_some(),
            "golang_implant should match golang_ prefix"
        );
        assert!(
            lookup_attack_for_rule_name("go_rat").is_none(),
            "go_rat should not match after go_ is removed"
        );
    }

    #[test]
    fn pruned_language_prefixes_return_none() {
        // perl_, ruby_, java_, nodejs_ removed — too generic or no real YARA usage
        for rule in &["perl_backdoor", "ruby_rat", "java_trojan", "nodejs_stealer"] {
            assert!(
                lookup_attack_for_rule_name(rule).is_none(),
                "'{rule}' should return None after language pruning"
            );
        }
    }

    #[test]
    fn pruned_generic_recon_prefixes_return_none() {
        // scan_, recon_, enum_, discovery_, harvest_, osint_ removed — false-positive magnets
        for rule in &[
            "scan_tool",
            "recon_kit",
            "enum_users",
            "discovery_module",
            "harvest_creds",
            "osint_framework",
        ] {
            assert!(
                lookup_attack_for_rule_name(rule).is_none(),
                "'{rule}' should return None after recon pruning"
            );
        }
    }

    #[test]
    fn pruned_windows_registry_prefixes_return_none() {
        // reg_, event_, prefetch_ removed — too broad
        for rule in &["reg_editor", "event_log_cleaner", "prefetch_wipe"] {
            assert!(
                lookup_attack_for_rule_name(rule).is_none(),
                "'{rule}' should return None after registry pruning"
            );
        }
    }
}
