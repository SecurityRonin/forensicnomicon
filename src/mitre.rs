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
static ATTACK_PREFIXES: &[(&str, &str, &str, &str)] = &[
    // ── Generic archetypes (original 20) ───────────────────────────────
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
    // ── Malware archetypes ──────────────────────────────────────────────
    ("trojan_", "T1204", "execution", "User Execution"),
    ("spyware_", "T1113", "collection", "Screen Capture"),
    ("spy_", "T1113", "collection", "Screen Capture"),
    ("adware_", "T1176", "persistence", "Browser Extensions"),
    (
        "banker_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "packer_",
        "T1027.002",
        "defense-evasion",
        "Obfuscated Files or Information: Software Packing",
    ),
    ("clickfraud_", "T1496", "impact", "Resource Hijacking"),
    (
        "worm_",
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ),
    (
        "virus_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    (
        "dialer_",
        "T1571",
        "command-and-control",
        "Non-Standard Port",
    ),
    (
        "downloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "infostealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "formgrab_",
        "T1056.003",
        "collection",
        "Input Capture: Web Portal Capture",
    ),
    ("stalkerware_", "T1125", "collection", "Video Capture"),
    ("clipper_", "T1115", "collection", "Clipboard Data"),
    ("cryptominer_", "T1496", "impact", "Resource Hijacking"),
    ("cryptojack_", "T1496", "impact", "Resource Hijacking"),
    (
        "implant_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "stager_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "payload_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    // ── Named ransomware families ───────────────────────────────────────
    ("lockbit_", "T1486", "impact", "Data Encrypted for Impact"),
    ("conti_", "T1486", "impact", "Data Encrypted for Impact"),
    ("revil_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "sodinokibi_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("darkside_", "T1486", "impact", "Data Encrypted for Impact"),
    ("maze_", "T1486", "impact", "Data Encrypted for Impact"),
    ("ryuk_", "T1486", "impact", "Data Encrypted for Impact"),
    ("blackcat_", "T1486", "impact", "Data Encrypted for Impact"),
    ("alphv_", "T1486", "impact", "Data Encrypted for Impact"),
    ("cl0p_", "T1486", "impact", "Data Encrypted for Impact"),
    ("clop_", "T1486", "impact", "Data Encrypted for Impact"),
    ("akira_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "blackbasta_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "hive_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("lorenz_", "T1486", "impact", "Data Encrypted for Impact"),
    ("egregor_", "T1486", "impact", "Data Encrypted for Impact"),
    ("netwalker_", "T1486", "impact", "Data Encrypted for Impact"),
    ("dharma_", "T1486", "impact", "Data Encrypted for Impact"),
    ("phobos_", "T1486", "impact", "Data Encrypted for Impact"),
    ("makop_", "T1486", "impact", "Data Encrypted for Impact"),
    ("avaddon_", "T1486", "impact", "Data Encrypted for Impact"),
    ("grief_", "T1486", "impact", "Data Encrypted for Impact"),
    ("ragnar_", "T1486", "impact", "Data Encrypted for Impact"),
    ("dopple_", "T1486", "impact", "Data Encrypted for Impact"),
    ("nefilim_", "T1486", "impact", "Data Encrypted for Impact"),
    ("pay2key_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "yanluowang_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("nokoyawa_", "T1486", "impact", "Data Encrypted for Impact"),
    ("babuk_", "T1486", "impact", "Data Encrypted for Impact"),
    ("monti_", "T1486", "impact", "Data Encrypted for Impact"),
    ("bianlian_", "T1486", "impact", "Data Encrypted for Impact"),
    ("rhysida_", "T1486", "impact", "Data Encrypted for Impact"),
    ("trigona_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "cactus_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("ransomexx_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "lockergoga_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "megacortex_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "hellokitty_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("darkpower_", "T1486", "impact", "Data Encrypted for Impact"),
    ("hardbit_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "cyclops_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("lockfile_", "T1486", "impact", "Data Encrypted for Impact"),
    ("suncrypt_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "snatch_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    ("mespinoza_", "T1486", "impact", "Data Encrypted for Impact"),
    ("8base_", "T1486", "impact", "Data Encrypted for Impact"),
    (
        "hunters_intl_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "vice_society_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "money_message_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "meow_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "quantum_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    // ── Named RATs ─────────────────────────────────────────────────────
    (
        "asyncrat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "njrat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "remcos_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "quasar_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "darkcomet_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "nanocore_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "netwire_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "warzone_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "xtremerat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "crimson_rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "bandook_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "parallax_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "imminent_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "dcrat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "prorat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "gh0st_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "poisonivy_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "plugx_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "shadowpad_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "luminosity_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "limenat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "badnews_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "coreshell_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "orcus_rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "adwind_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "jrat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "xworm_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "netsupport_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "revenge_rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "fynloski_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "bifrost_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "pandora_rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "ratty_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "pumakit_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "yayih_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    // ── Banking trojans / financial malware ────────────────────────────
    ("emotet_", "T1566", "initial-access", "Phishing"),
    (
        "trickbot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "qakbot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    ("qbot_", "T1185", "collection", "Browser Session Hijacking"),
    (
        "dridex_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "ursnif_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    ("zeus_", "T1185", "collection", "Browser Session Hijacking"),
    ("gozi_", "T1185", "collection", "Browser Session Hijacking"),
    (
        "flubot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "cerberus_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "anubis_banker_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "teabot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    ("brata_", "T1185", "collection", "Browser Session Hijacking"),
    (
        "sharkbot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "xenomorph_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "godfather_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "danabot_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    ("isfb_", "T1185", "collection", "Browser Session Hijacking"),
    (
        "spyeye_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "carberp_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    ("tinba_", "T1185", "collection", "Browser Session Hijacking"),
    (
        "kronos_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "gameover_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "hook_banker_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "android_wroba_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "android_sova_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    // ── Infostealers ───────────────────────────────────────────────────
    (
        "redline_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "raccoon_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "azorult_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "vidar_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "lumma_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "stealc_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "rhadamanthys_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "erbium_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "mystic_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "titan_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "atomic_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "aurora_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "mars_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "arkei_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "kpot_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "taurus_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "predator_thief_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "cryptbot_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "nexus_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "whitesnake_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "risepro_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "blackguard_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "prynt_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "typhon_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "braodo_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "socelars_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "lokibot_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "formbook_",
        "T1056.003",
        "collection",
        "Input Capture: Web Portal Capture",
    ),
    (
        "agent_tesla_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    (
        "masslogger_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    (
        "hworm_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    (
        "amos_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "umbral_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    // ── Loaders / droppers ─────────────────────────────────────────────
    (
        "bumblebee_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "squirrelwaffle_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "gootloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "bazarloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "icedid_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "guloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "donutloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "latrodectus_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "pikabot_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "matanbuchus_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "darkgate_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "privateloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "smokeloader_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "systembc_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "amadey_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "andromeda_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "chainshot_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "tinyturla_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    (
        "bazarbackdoor_",
        "T1105",
        "command-and-control",
        "Ingress Tool Transfer",
    ),
    // ── C2 frameworks / offensive tools ───────────────────────────────
    (
        "cobaltstrike_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "meterpreter_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "sliver_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    ("empire_", "T1059.001", "execution", "PowerShell"),
    ("impacket_", "T1021", "lateral-movement", "Remote Services"),
    (
        "metasploit_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    (
        "havoc_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "brute_ratel_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "nighthawk_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "covenant_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "merlin_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    ("poshc2_", "T1059.001", "execution", "PowerShell"),
    ("silenttrinity_", "T1059.006", "execution", "Python"),
    (
        "deimos_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "caldera_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    (
        "mimikatz_",
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ),
    // ── Credential attacks ─────────────────────────────────────────────
    (
        "lsass_",
        "T1003.001",
        "credential-access",
        "OS Credential Dumping: LSASS Memory",
    ),
    (
        "samdump_",
        "T1003.002",
        "credential-access",
        "OS Credential Dumping: Security Account Manager",
    ),
    (
        "ntds_",
        "T1003.003",
        "credential-access",
        "OS Credential Dumping: NTDS",
    ),
    (
        "dcsync_",
        "T1003.006",
        "credential-access",
        "OS Credential Dumping: DCSync",
    ),
    (
        "kerberoast_",
        "T1558.003",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Kerberoasting",
    ),
    (
        "goldenticket_",
        "T1558.001",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Golden Ticket",
    ),
    (
        "silverticket_",
        "T1558.002",
        "credential-access",
        "Steal or Forge Kerberos Tickets: Silver Ticket",
    ),
    (
        "passhash_",
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ),
    (
        "passthehash_",
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ),
    (
        "overpassthehash_",
        "T1550.002",
        "defense-evasion",
        "Use Alternate Authentication Material: Pass the Hash",
    ),
    ("brute_", "T1110", "credential-access", "Brute Force"),
    (
        "spray_",
        "T1110.003",
        "credential-access",
        "Brute Force: Password Spraying",
    ),
    (
        "credstuff_",
        "T1110.004",
        "credential-access",
        "Brute Force: Credential Stuffing",
    ),
    (
        "pwsteal_",
        "T1555",
        "credential-access",
        "Credentials from Password Stores",
    ),
    (
        "cookiesteal_",
        "T1539",
        "credential-access",
        "Steal Web Session Cookie",
    ),
    (
        "credential_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "pwdump_",
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ),
    (
        "cachedump_",
        "T1003.005",
        "credential-access",
        "OS Credential Dumping: Cached Domain Credentials",
    ),
    (
        "hashdump_",
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ),
    (
        "kerbrute_",
        "T1110.003",
        "credential-access",
        "Brute Force: Password Spraying",
    ),
    (
        "rubeus_",
        "T1558",
        "credential-access",
        "Steal or Forge Kerberos Tickets",
    ),
    (
        "lazagne_",
        "T1555",
        "credential-access",
        "Credentials from Password Stores",
    ),
    ("bloodhound_", "T1087", "discovery", "Account Discovery"),
    ("sharphound_", "T1087", "discovery", "Account Discovery"),
    (
        "certipy_",
        "T1649",
        "credential-access",
        "Steal or Forge Authentication Certificates",
    ),
    (
        "goddi_",
        "T1087.002",
        "discovery",
        "Account Discovery: Domain Account",
    ),
    (
        "adidnsdump_",
        "T1087.002",
        "discovery",
        "Account Discovery: Domain Account",
    ),
    // ── Lateral movement ───────────────────────────────────────────────
    (
        "rdp_",
        "T1021.001",
        "lateral-movement",
        "Remote Services: Remote Desktop Protocol",
    ),
    (
        "vnc_",
        "T1021.005",
        "lateral-movement",
        "Remote Services: VNC",
    ),
    (
        "smb_",
        "T1021.002",
        "lateral-movement",
        "Remote Services: SMB/Windows Admin Shares",
    ),
    (
        "lateral_",
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ),
    (
        "psexec_",
        "T1569.002",
        "execution",
        "System Services: Service Execution",
    ),
    (
        "wmiexec_",
        "T1047",
        "execution",
        "Windows Management Instrumentation",
    ),
    (
        "dcom_exec_",
        "T1021.003",
        "lateral-movement",
        "Remote Services: Distributed Component Object Model",
    ),
    (
        "winrm_",
        "T1021.006",
        "lateral-movement",
        "Remote Services: Windows Remote Management",
    ),
    (
        "atexec_",
        "T1053.005",
        "persistence",
        "Scheduled Task/Job: Scheduled Task",
    ),
    (
        "petitpotam_",
        "T1187",
        "credential-access",
        "Forced Authentication",
    ),
    (
        "printerbug_",
        "T1187",
        "credential-access",
        "Forced Authentication",
    ),
    (
        "coercer_",
        "T1187",
        "credential-access",
        "Forced Authentication",
    ),
    // ── Defense evasion / obfuscation ──────────────────────────────────
    (
        "obfusc_",
        "T1027",
        "defense-evasion",
        "Obfuscated Files or Information",
    ),
    (
        "packed_",
        "T1027.002",
        "defense-evasion",
        "Obfuscated Files or Information: Software Packing",
    ),
    ("antidebug_", "T1622", "defense-evasion", "Debugger Evasion"),
    (
        "antivm_",
        "T1497",
        "defense-evasion",
        "Virtualization/Sandbox Evasion",
    ),
    (
        "antisandbox_",
        "T1497",
        "defense-evasion",
        "Virtualization/Sandbox Evasion",
    ),
    (
        "timestomp_",
        "T1070.006",
        "defense-evasion",
        "Indicator Removal: Timestomp",
    ),
    (
        "logclear_",
        "T1070.001",
        "defense-evasion",
        "Indicator Removal: Clear Windows Event Logs",
    ),
    (
        "uacbypass_",
        "T1548.002",
        "privilege-escalation",
        "Abuse Elevation Control Mechanism: Bypass UAC",
    ),
    (
        "dllhijack_",
        "T1574.001",
        "defense-evasion",
        "Hijack Execution Flow: DLL Search Order Hijacking",
    ),
    (
        "dllsideload_",
        "T1574.002",
        "defense-evasion",
        "Hijack Execution Flow: DLL Side-Loading",
    ),
    (
        "antiforensic_",
        "T1070",
        "defense-evasion",
        "Indicator Removal",
    ),
    ("masquerade_", "T1036", "defense-evasion", "Masquerading"),
    (
        "steg_",
        "T1027.003",
        "defense-evasion",
        "Obfuscated Files or Information: Steganography",
    ),
    (
        "encode_",
        "T1027",
        "defense-evasion",
        "Obfuscated Files or Information",
    ),
    (
        "sign_forge_",
        "T1553.002",
        "defense-evasion",
        "Subvert Trust Controls: Code Signing",
    ),
    (
        "unhook_",
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ),
    (
        "edr_bypass_",
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ),
    (
        "amsi_bypass_",
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ),
    ("clm_bypass_", "T1562", "defense-evasion", "Impair Defenses"),
    (
        "etw_bypass_",
        "T1562.006",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Cloud Logs",
    ),
    (
        "defender_kill_",
        "T1562.001",
        "defense-evasion",
        "Impair Defenses: Disable or Modify Tools",
    ),
    (
        "lolbin_",
        "T1218",
        "defense-evasion",
        "System Binary Proxy Execution",
    ),
    (
        "token_",
        "T1134",
        "defense-evasion",
        "Access Token Manipulation",
    ),
    (
        "impersonate_",
        "T1134.001",
        "defense-evasion",
        "Access Token Manipulation: Token Impersonation/Theft",
    ),
    (
        "compile_after_",
        "T1027.004",
        "defense-evasion",
        "Obfuscated Files or Information: Compile After Delivery",
    ),
    // ── Process injection variants ─────────────────────────────────────
    (
        "prochollow_",
        "T1055.012",
        "defense-evasion",
        "Process Injection: Process Hollowing",
    ),
    (
        "reflective_",
        "T1055.001",
        "defense-evasion",
        "Process Injection: Dynamic-link Library Injection",
    ),
    (
        "threadhijack_",
        "T1055.003",
        "defense-evasion",
        "Process Injection: Thread Execution Hijacking",
    ),
    ("atom_", "T1055", "defense-evasion", "Process Injection"),
    (
        "procdoppel_",
        "T1055.013",
        "defense-evasion",
        "Process Injection: Process Doppelgänging",
    ),
    (
        "ghostwrite_",
        "T1055.016",
        "defense-evasion",
        "Process Injection: Process Ghostwriting",
    ),
    (
        "apc_inject_",
        "T1055.004",
        "defense-evasion",
        "Process Injection: Asynchronous Procedure Call",
    ),
    (
        "pe_inject_",
        "T1055.002",
        "defense-evasion",
        "Process Injection: Portable Executable Injection",
    ),
    // ── Persistence mechanisms ─────────────────────────────────────────
    (
        "bootkit_",
        "T1542.003",
        "persistence",
        "Pre-OS Boot: Bootkit",
    ),
    ("mbr_", "T1542.003", "persistence", "Pre-OS Boot: Bootkit"),
    (
        "uefi_",
        "T1542.001",
        "persistence",
        "Pre-OS Boot: System Firmware",
    ),
    (
        "schtask_",
        "T1053.005",
        "persistence",
        "Scheduled Task/Job: Scheduled Task",
    ),
    (
        "cron_",
        "T1053.003",
        "persistence",
        "Scheduled Task/Job: Cron",
    ),
    (
        "regpersist_",
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ),
    (
        "service_",
        "T1543.003",
        "persistence",
        "Create or Modify System Process: Windows Service",
    ),
    (
        "autorun_",
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ),
    (
        "logon_",
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ),
    (
        "com_hijack_",
        "T1546.015",
        "privilege-escalation",
        "Event Triggered Execution: Component Object Model Hijacking",
    ),
    (
        "appinit_",
        "T1546.010",
        "privilege-escalation",
        "Event Triggered Execution: AppInit DLLs",
    ),
    (
        "ifeo_",
        "T1546.012",
        "privilege-escalation",
        "Event Triggered Execution: Image File Execution Options Injection",
    ),
    (
        "wmi_persist_",
        "T1546.003",
        "privilege-escalation",
        "Event Triggered Execution: WMI Event Subscription",
    ),
    (
        "macro_persist_",
        "T1137",
        "persistence",
        "Office Application Startup",
    ),
    // ── C2 / Network ───────────────────────────────────────────────────
    (
        "c2_",
        "T1071",
        "command-and-control",
        "Application Layer Protocol",
    ),
    (
        "beacon_",
        "T1071",
        "command-and-control",
        "Application Layer Protocol",
    ),
    (
        "dnstunnel_",
        "T1071.004",
        "command-and-control",
        "Application Layer Protocol: DNS",
    ),
    (
        "dga_",
        "T1568.002",
        "command-and-control",
        "Dynamic Resolution: Domain Generation Algorithms",
    ),
    (
        "fastflux_",
        "T1568.001",
        "command-and-control",
        "Dynamic Resolution: Fast Flux DNS",
    ),
    ("proxy_", "T1090", "command-and-control", "Proxy"),
    (
        "tunnel_",
        "T1572",
        "command-and-control",
        "Protocol Tunneling",
    ),
    (
        "icmptunnel_",
        "T1095",
        "command-and-control",
        "Non-Application Layer Protocol",
    ),
    (
        "domainfronting_",
        "T1090.004",
        "command-and-control",
        "Proxy: Domain Fronting",
    ),
    ("p2p_", "T1090", "command-and-control", "Proxy"),
    (
        "c2_http_",
        "T1071.001",
        "command-and-control",
        "Application Layer Protocol: Web Protocols",
    ),
    (
        "c2_dns_",
        "T1071.004",
        "command-and-control",
        "Application Layer Protocol: DNS",
    ),
    (
        "c2_smtp_",
        "T1071.003",
        "command-and-control",
        "Application Layer Protocol: Mail Protocols",
    ),
    (
        "c2_custom_",
        "T1095",
        "command-and-control",
        "Non-Application Layer Protocol",
    ),
    (
        "reverse_shell_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "bindshell_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    // ── Collection / Exfiltration ──────────────────────────────────────
    ("screenshot_", "T1113", "collection", "Screen Capture"),
    ("audiocap_", "T1123", "collection", "Audio Capture"),
    ("webcam_", "T1125", "collection", "Video Capture"),
    (
        "exfil_",
        "T1041",
        "exfiltration",
        "Exfiltration Over C2 Channel",
    ),
    (
        "keylog_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    ("cliplog_", "T1115", "collection", "Clipboard Data"),
    ("screenrec_", "T1113", "collection", "Screen Capture"),
    (
        "archive_exfil_",
        "T1560",
        "collection",
        "Archive Collected Data",
    ),
    (
        "cloud_exfil_",
        "T1567",
        "exfiltration",
        "Exfiltration Over Web Service",
    ),
    (
        "email_exfil_",
        "T1048.003",
        "exfiltration",
        "Exfiltration Over Alternative Protocol",
    ),
    (
        "browse_steal_",
        "T1539",
        "credential-access",
        "Steal Web Session Cookie",
    ),
    (
        "filesearch_",
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ),
    // ── Scripting / Execution ──────────────────────────────────────────
    (
        "macro_",
        "T1137",
        "persistence",
        "Office Application Startup",
    ),
    (
        "vba_",
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ),
    (
        "jscript_",
        "T1059.007",
        "execution",
        "Command and Scripting Interpreter: JavaScript",
    ),
    (
        "wmi_",
        "T1047",
        "execution",
        "Windows Management Instrumentation",
    ),
    (
        "lnk_",
        "T1204.002",
        "execution",
        "User Execution: Malicious File",
    ),
    (
        "iso_",
        "T1553.005",
        "defense-evasion",
        "Subvert Trust Controls: Mark-of-the-Web Bypass",
    ),
    (
        "dde_",
        "T1559.002",
        "execution",
        "Inter-Process Communication: Dynamic Data Exchange",
    ),
    (
        "hta_",
        "T1218.005",
        "defense-evasion",
        "System Binary Proxy Execution: Mshta",
    ),
    (
        "mshta_",
        "T1218.005",
        "defense-evasion",
        "System Binary Proxy Execution: Mshta",
    ),
    (
        "regsvr32_",
        "T1218.010",
        "defense-evasion",
        "System Binary Proxy Execution: Regsvr32",
    ),
    (
        "rundll32_",
        "T1218.011",
        "defense-evasion",
        "System Binary Proxy Execution: Rundll32",
    ),
    (
        "msiexec_",
        "T1218.007",
        "defense-evasion",
        "System Binary Proxy Execution: Msiexec",
    ),
    (
        "certutil_",
        "T1140",
        "defense-evasion",
        "Deobfuscate/Decode Files or Information",
    ),
    ("bitsadmin_", "T1197", "defense-evasion", "BITS Jobs"),
    (
        "cmstp_",
        "T1218.003",
        "defense-evasion",
        "System Binary Proxy Execution: CMSTP",
    ),
    (
        "wscript_",
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ),
    (
        "cscript_",
        "T1059.005",
        "execution",
        "Command and Scripting Interpreter: Visual Basic",
    ),
    // ── Initial access / Exploitation ──────────────────────────────────
    (
        "exploitkit_",
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ),
    (
        "drivebydownload_",
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ),
    (
        "heapspray_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    (
        "rce_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    (
        "lpe_",
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ),
    ("phish_", "T1566", "initial-access", "Phishing"),
    (
        "watering_",
        "T1189",
        "initial-access",
        "Drive-by Compromise",
    ),
    ("smishing_", "T1566", "initial-access", "Phishing"),
    ("vishing_", "T1566", "initial-access", "Phishing"),
    (
        "spear_",
        "T1566.001",
        "initial-access",
        "Phishing: Spearphishing Attachment",
    ),
    (
        "supply_chain_",
        "T1195",
        "initial-access",
        "Supply Chain Compromise",
    ),
    (
        "typosquat_",
        "T1195.002",
        "initial-access",
        "Supply Chain Compromise: Compromise Software Supply Chain",
    ),
    (
        "trustedrel_",
        "T1199",
        "initial-access",
        "Trusted Relationship",
    ),
    (
        "repoconf_",
        "T1195.001",
        "initial-access",
        "Supply Chain Compromise: Compromise Software Dependencies",
    ),
    // ── Named CVEs / exploit techniques ────────────────────────────────
    (
        "eternalblue_",
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ),
    (
        "ms17_010_",
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ),
    (
        "log4shell_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "l4jshell_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "proxyshell_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "proxylogon_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "printnightmare_",
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ),
    (
        "zerologon_",
        "T1068",
        "privilege-escalation",
        "Exploitation for Privilege Escalation",
    ),
    (
        "bluekeep_",
        "T1210",
        "lateral-movement",
        "Exploitation of Remote Services",
    ),
    (
        "follina_",
        "T1203",
        "execution",
        "Exploitation for Client Execution",
    ),
    (
        "spring4shell_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "citrixbleed_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "shellshock_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "heartbleed_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    (
        "cve_",
        "T1190",
        "initial-access",
        "Exploit Public-Facing Application",
    ),
    // ── Impact ─────────────────────────────────────────────────────────
    ("dos_", "T1499", "impact", "Endpoint Denial of Service"),
    ("ddos_", "T1498", "impact", "Network Denial of Service"),
    ("vss_", "T1490", "impact", "Inhibit System Recovery"),
    ("shadow_", "T1490", "impact", "Inhibit System Recovery"),
    ("disk_wipe_", "T1561", "impact", "Disk Wipe"),
    (
        "mbr_wipe_",
        "T1561.002",
        "impact",
        "Disk Wipe: Disk Structure Wipe",
    ),
    ("defacement_", "T1491", "impact", "Defacement"),
    ("data_destroy_", "T1485", "impact", "Data Destruction"),
    ("firm_wipe_", "T1495", "impact", "Firmware Corruption"),
    // ── Platform-specific ──────────────────────────────────────────────
    ("linux_rootkit_", "T1014", "defense-evasion", "Rootkit"),
    (
        "linux_backdoor_",
        "T1505",
        "persistence",
        "Server Software Component",
    ),
    ("linux_miner_", "T1496", "impact", "Resource Hijacking"),
    (
        "linux_worm_",
        "T1570",
        "lateral-movement",
        "Lateral Tool Transfer",
    ),
    (
        "linux_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    (
        "linux_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "linux_ebury_",
        "T1505",
        "persistence",
        "Server Software Component",
    ),
    (
        "linux_mirai_",
        "T1498",
        "impact",
        "Network Denial of Service",
    ),
    (
        "linux_xorddos_",
        "T1498",
        "impact",
        "Network Denial of Service",
    ),
    ("linux_skidmap_", "T1496", "impact", "Resource Hijacking"),
    (
        "macos_backdoor_",
        "T1505",
        "persistence",
        "Server Software Component",
    ),
    (
        "macos_persist_",
        "T1547",
        "persistence",
        "Boot or Logon Autostart Execution",
    ),
    (
        "macos_stealer_",
        "T1552",
        "credential-access",
        "Unsecured Credentials",
    ),
    (
        "macos_keylog_",
        "T1056.001",
        "collection",
        "Input Capture: Keylogging",
    ),
    (
        "macos_adload_",
        "T1176",
        "persistence",
        "Browser Extensions",
    ),
    (
        "android_banker_",
        "T1185",
        "collection",
        "Browser Session Hijacking",
    ),
    (
        "android_spyware_",
        "T1430",
        "collection",
        "Location Tracking",
    ),
    (
        "android_rat_",
        "T1219",
        "command-and-control",
        "Remote Access Software",
    ),
    ("ios_spyware_", "T1430", "collection", "Location Tracking"),
    (
        "iot_botnet_",
        "T1498",
        "impact",
        "Network Denial of Service",
    ),
    (
        "iot_ransom_",
        "T1486",
        "impact",
        "Data Encrypted for Impact",
    ),
    // ── Scripting language-specific ────────────────────────────────────
    (
        "python_",
        "T1059.006",
        "execution",
        "Command and Scripting Interpreter: Python",
    ),
    (
        "golang_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "nim_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "rust_malware_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "dotnet_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "bash_",
        "T1059.004",
        "execution",
        "Command and Scripting Interpreter: Unix Shell",
    ),
    (
        "php_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    (
        "autohotkey_",
        "T1059",
        "execution",
        "Command and Scripting Interpreter",
    ),
    // ── Network / Reconnaissance ───────────────────────────────────────
    (
        "portscan_",
        "T1046",
        "discovery",
        "Network Service Discovery",
    ),
    ("sniffer_", "T1040", "credential-access", "Network Sniffing"),
    (
        "arp_poison_",
        "T1557.002",
        "credential-access",
        "Adversary-in-the-Middle: ARP Cache Poisoning",
    ),
    (
        "mitm_",
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ),
    (
        "dnsspoof_",
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ),
    (
        "sslstrip_",
        "T1557",
        "credential-access",
        "Adversary-in-the-Middle",
    ),
    ("nmap_", "T1046", "discovery", "Network Service Discovery"),
    (
        "masscan_",
        "T1046",
        "discovery",
        "Network Service Discovery",
    ),
    (
        "linpeas_",
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ),
    (
        "winpeas_",
        "T1083",
        "discovery",
        "File and Directory Discovery",
    ),
    (
        "seatbelt_",
        "T1082",
        "discovery",
        "System Information Discovery",
    ),
    (
        "powerview_",
        "T1069",
        "discovery",
        "Permission Groups Discovery",
    ),
    (
        "responder_",
        "T1557.001",
        "credential-access",
        "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
    ),
    // ── Windows registry / system ──────────────────────────────────────
    (
        "kerberos_",
        "T1558",
        "credential-access",
        "Steal or Forge Kerberos Tickets",
    ),
    (
        "namedpipe_",
        "T1559.001",
        "execution",
        "Inter-Process Communication: Component Object Model",
    ),
    (
        "sam_access_",
        "T1003.002",
        "credential-access",
        "OS Credential Dumping: Security Account Manager",
    ),
    (
        "secretsdump_",
        "T1003",
        "credential-access",
        "OS Credential Dumping",
    ),
    (
        "reg_shell_",
        "T1547.001",
        "persistence",
        "Boot or Logon Autostart Execution: Registry Run Keys",
    ),
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
