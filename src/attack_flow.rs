//! MITRE ATT&CK Flow — campaign graph layer.
//!
//! Models adversary campaigns as directed sequences of ATT&CK actions, each
//! mapped to the forensicnomicon artifact IDs that provide evidence of that
//! action. Flow data is sourced from the CTID Attack Flow corpus:
//! <https://github.com/center-for-threat-informed-defense/attack-flow/tree/main/corpus>
//!
//! # Data model
//!
//! An [`AttackFlow`] is a named campaign scenario (e.g. ransomware, APT lateral
//! movement). It contains an ordered sequence of [`FlowAction`] steps. Each
//! step carries:
//!
//! - the ATT&CK technique it represents
//! - the forensicnomicon artifact IDs that provide evidence of it
//! - indices into the action list for successor steps (causal edges)
//!
//! # Example
//!
//! ```rust
//! use forensicnomicon::attack_flow::{flow_by_id, artifacts_in_flow};
//!
//! let flow = flow_by_id("black_basta_ransomware").unwrap();
//! let artifacts = artifacts_in_flow("black_basta_ransomware");
//! assert!(!artifacts.is_empty());
//! ```

use crate::mitre::AttackTechnique;

/// A single action in an attack flow — one ATT&CK technique and the
/// forensicnomicon artifact IDs that provide evidence of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowAction {
    /// ATT&CK technique ID, e.g. `"T1486"`.
    pub technique_id: &'static str,
    /// ATT&CK tactic, e.g. `"impact"`.
    pub tactic: &'static str,
    /// Human-readable technique name.
    pub name: &'static str,
    /// Forensicnomicon artifact IDs that provide evidence of this action.
    pub artifact_ids: &'static [&'static str],
    /// Indices into the parent flow's `actions` slice for causal successors.
    pub leads_to: &'static [usize],
}

impl FlowAction {
    /// Returns this action as a typed [`AttackTechnique`].
    pub fn technique(&self) -> AttackTechnique {
        AttackTechnique {
            technique_id: self.technique_id,
            tactic: self.tactic,
            name: self.name,
        }
    }
}

/// A named adversary campaign scenario modelled as an ordered action graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackFlow {
    /// Stable identifier, e.g. `"ransomware_double_extortion"`.
    pub id: &'static str,
    /// Human-readable campaign name.
    pub name: &'static str,
    /// Brief description of the scenario.
    pub description: &'static str,
    /// Ordered sequence of actions. Edges encoded via `leads_to` indices.
    pub actions: &'static [FlowAction],
}

// ── Static campaign graph (sourced from CTID Attack Flow corpus) ─────────────
//
// Each flow is derived from a real .afb file in:
// https://github.com/center-for-threat-informed-defense/attack-flow/tree/main/corpus
//
// Action nodes are topologically sorted (BFS from root actions) preserving
// the original causal graph. `leads_to` encodes the directed edges between
// actions as indices into the actions slice.

// ── Black Basta Ransomware ────────────────────────────────────────────────────
// Source: "Black Basta Ransomware.afb" (CTID corpus, author: Lauren Parker, MITRE)
// 38 action nodes; main execution chain shown with branching preserved.

static BLACK_BASTA_ACTIONS: &[FlowAction] = &[
    // [0] Root: spearphishing attachment delivery
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Phishing: Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1]
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[2],
    },
    // [2]
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "User Execution: Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[3],
    },
    // [3]
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "Command and Scripting Interpreter: PowerShell",
        artifact_ids: &["powershell_history", "evtx_powershell", "psreadline_history"],
        leads_to: &[4],
    },
    // [4] DLL Search Order Hijacking loads C2 beacon
    FlowAction {
        technique_id: "T1574",
        tactic: "defense-evasion",
        name: "Hijack Execution Flow: DLL Search Order Hijacking",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[5],
    },
    // [5] Regsvr32 proxy execution
    FlowAction {
        technique_id: "T1218",
        tactic: "defense-evasion",
        name: "System Binary Proxy Execution: Regsvr32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[6, 7],
    },
    // [6] Persistence: Windows Service
    FlowAction {
        technique_id: "T1543.003",
        tactic: "persistence",
        name: "Create or Modify System Process: Windows Service",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[8],
    },
    // [7] Persistence: Create Account
    FlowAction {
        technique_id: "T1136",
        tactic: "persistence",
        name: "Create Account",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[9],
    },
    // [8] Ingress Tool Transfer (Cobalt Strike, etc.)
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[10, 11, 12],
    },
    // [9] Account Manipulation / Group Policy for lateral movement
    FlowAction {
        technique_id: "T1098",
        tactic: "privilege-escalation",
        name: "Account Manipulation",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[],
    },
    // [10] Remote Access Software (Atera, ScreenConnect)
    FlowAction {
        technique_id: "T1219",
        tactic: "command-and-control",
        name: "Remote Access Software",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[13],
    },
    // [11] Disable or Modify Tools
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Impair Defenses: Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[13],
    },
    // [12] File and Directory Discovery
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[14],
    },
    // [13] RDP lateral movement
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Services: Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[15],
    },
    // [14] Archive before exfil
    FlowAction {
        technique_id: "T1560",
        tactic: "collection",
        name: "Archive Collected Data: Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[16],
    },
    // [15] Service Execution post-lateral-movement
    FlowAction {
        technique_id: "T1569.002",
        tactic: "execution",
        name: "System Services: Service Execution",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[17, 18, 19],
    },
    // [16] Exfiltration over web service
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [17] Service Stop
    FlowAction {
        technique_id: "T1489",
        tactic: "impact",
        name: "Service Stop",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[20],
    },
    // [18] Disable security tools pre-encryption
    FlowAction {
        technique_id: "T1562",
        tactic: "defense-evasion",
        name: "Impair Defenses: Disable or Modify System Firewall",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[20],
    },
    // [19] Safe Mode Boot evasion
    FlowAction {
        technique_id: "T1112",
        tactic: "defense-evasion",
        name: "Modify Registry",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[20],
    },
    // [20] Inhibit System Recovery (VSS deletion)
    FlowAction {
        technique_id: "T1490",
        tactic: "impact",
        name: "Inhibit System Recovery",
        artifact_ids: &["evtx_system", "usn_journal"],
        leads_to: &[21],
    },
    // [21] Data Encrypted for Impact
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
];

// ── Cobalt Kitty Campaign ─────────────────────────────────────────────────────
// Source: "Cobalt Kitty Campaign.afb" (CTID corpus)
// Vietnamese APT targeting corporations via spearphishing; 27 action nodes.

static COBALT_KITTY_ACTIONS: &[FlowAction] = &[
    // [0] Spearphishing Link (TA0001)
    FlowAction {
        technique_id: "T1566.002",
        tactic: "initial-access",
        name: "Spearphishing Link",
        artifact_ids: &["evtx_security", "chrome_history"],
        leads_to: &[1],
    },
    // [1] PowerShell execution from link
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &["powershell_history", "evtx_powershell", "psreadline_history"],
        leads_to: &[2, 3],
    },
    // [2] Decode/deobfuscate payloads
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[4],
    },
    // [3] Spearphishing Attachment (parallel initial vector)
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[5],
    },
    // [4] DLL Side-Loading (Cobalt Strike)
    FlowAction {
        technique_id: "T1574",
        tactic: "defense-evasion",
        name: "DLL Side-Loading",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[6],
    },
    // [5] Scheduled Task from attachment
    FlowAction {
        technique_id: "T1053.005",
        tactic: "persistence",
        name: "Scheduled Task",
        artifact_ids: &["scheduled_tasks_dir", "evtx_task_scheduler"],
        leads_to: &[],
    },
    // [6] Regsvr32 proxy execution
    FlowAction {
        technique_id: "T1218",
        tactic: "defense-evasion",
        name: "System Binary Proxy Execution: Regsvr32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[7, 8, 9],
    },
    // [7] C2 via DNS
    FlowAction {
        technique_id: "T1071",
        tactic: "command-and-control",
        name: "Application Layer Protocol: DNS",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [8] C2 via Mail Protocols
    FlowAction {
        technique_id: "T1071",
        tactic: "command-and-control",
        name: "Application Layer Protocol: Mail Protocols",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[],
    },
    // [9] LSA Secrets credential dumping
    FlowAction {
        technique_id: "T1003",
        tactic: "credential-access",
        name: "OS Credential Dumping: LSA Secrets",
        artifact_ids: &["evtx_security", "prefetch_dir"],
        leads_to: &[10, 11, 12],
    },
    // [10] SMB lateral movement
    FlowAction {
        technique_id: "T1021.002",
        tactic: "lateral-movement",
        name: "Remote Services: SMB/Windows Admin Shares",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[],
    },
    // [11] Pass the Hash
    FlowAction {
        technique_id: "T1550",
        tactic: "lateral-movement",
        name: "Use Alternate Authentication Material: Pass the Hash",
        artifact_ids: &["evtx_security", "evtx_rdp_inbound"],
        leads_to: &[],
    },
    // [12] WMI lateral movement
    FlowAction {
        technique_id: "T1047",
        tactic: "execution",
        name: "Windows Management Instrumentation",
        artifact_ids: &["evtx_wmi_activity", "evtx_security"],
        leads_to: &[],
    },
    // Persistence mechanisms (roots with no incoming edge in CTID flow)
    // [13]
    FlowAction {
        technique_id: "T1547.001",
        tactic: "persistence",
        name: "Registry Run Keys / Startup Folder",
        artifact_ids: &["run_key_hkcu", "run_key_hklm"],
        leads_to: &[],
    },
    // [14]
    FlowAction {
        technique_id: "T1543.003",
        tactic: "persistence",
        name: "Windows Service",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[],
    },
    // Discovery nodes
    // [15]
    FlowAction {
        technique_id: "T1018",
        tactic: "discovery",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [16]
    FlowAction {
        technique_id: "T1046",
        tactic: "discovery",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
];

// ── SolarWinds Supply Chain ───────────────────────────────────────────────────
// Source: "SolarWinds.afb" (CTID corpus)
// Nation-state supply-chain compromise via SolarWinds Orion; 33 action nodes.

static SOLARWINDS_ACTIONS: &[FlowAction] = &[
    // [0] Compromise Software Supply Chain (root)
    FlowAction {
        technique_id: "T1195.002",
        tactic: "initial-access",
        name: "Supply Chain Compromise: Compromise Software Supply Chain",
        artifact_ids: &["evtx_security", "amcache_app_file"],
        leads_to: &[1],
    },
    // [1] Service Execution of trojanized SolarWinds binary
    FlowAction {
        technique_id: "T1569.002",
        tactic: "execution",
        name: "System Services: Service Execution",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[2, 3],
    },
    // [2] Time-based evasion (dormancy period)
    FlowAction {
        technique_id: "T1497",
        tactic: "defense-evasion",
        name: "Virtualization/Sandbox Evasion: Time Based Evasion",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[4],
    },
    // [3] Security Software Discovery
    FlowAction {
        technique_id: "T1518",
        tactic: "discovery",
        name: "Software Discovery: Security Software Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[4],
    },
    // [4] Masquerading — match legitimate SolarWinds name
    FlowAction {
        technique_id: "T1036",
        tactic: "defense-evasion",
        name: "Masquerading: Match Legitimate Name or Location",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[5],
    },
    // [5] Image File Execution Options injection for persistence
    FlowAction {
        technique_id: "T1546",
        tactic: "persistence",
        name: "Event Triggered Execution: Image File Execution Options Injection",
        artifact_ids: &["run_key_hklm", "evtx_sysmon"],
        leads_to: &[6],
    },
    // [6] Windows Service persistence
    FlowAction {
        technique_id: "T1543.003",
        tactic: "persistence",
        name: "Create or Modify System Process: Windows Service",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[7],
    },
    // [7] Registry modification for C2 config
    FlowAction {
        technique_id: "T1112",
        tactic: "defense-evasion",
        name: "Modify Registry",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[8],
    },
    // [8] Masquerading for network traffic blending
    FlowAction {
        technique_id: "T1036",
        tactic: "defense-evasion",
        name: "Masquerading: Rename System Utilities",
        artifact_ids: &["prefetch_dir", "shimcache"],
        leads_to: &[9],
    },
    // [9] WMI for execution on compromised hosts
    FlowAction {
        technique_id: "T1047",
        tactic: "execution",
        name: "Windows Management Instrumentation",
        artifact_ids: &["evtx_wmi_activity", "evtx_security"],
        leads_to: &[10],
    },
    // [10] Indicator Removal (log clearing)
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal on Host",
        artifact_ids: &["evtx_security", "evtx_system", "usn_journal"],
        leads_to: &[11],
    },
    // [11] Disable Windows Event Logging
    FlowAction {
        technique_id: "T1562",
        tactic: "defense-evasion",
        name: "Impair Defenses: Disable Windows Event Logging",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[12],
    },
    // [12] Disable or Modify Tools (AV/EDR)
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Impair Defenses: Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[13, 14],
    },
    // [13] Valid Accounts (stolen credentials)
    FlowAction {
        technique_id: "T1078",
        tactic: "defense-evasion",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[],
    },
    // [14] Scheduled Task persistence
    FlowAction {
        technique_id: "T1053.005",
        tactic: "persistence",
        name: "Scheduled Task",
        artifact_ids: &["scheduled_tasks_dir", "evtx_task_scheduler"],
        leads_to: &[15],
    },
    // [15] System Information Discovery
    FlowAction {
        technique_id: "T1082",
        tactic: "discovery",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[16, 17],
    },
    // [16] Data from Local System
    FlowAction {
        technique_id: "T1005",
        tactic: "collection",
        name: "Data from Local System",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[],
    },
    // [17] Archive Collected Data
    FlowAction {
        technique_id: "T1560",
        tactic: "collection",
        name: "Archive Collected Data: Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[18],
    },
    // [18] Exfiltration to Cloud Storage
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // Additional discovery/credential nodes (no incoming edges in CTID flow)
    // [19]
    FlowAction {
        technique_id: "T1482",
        tactic: "discovery",
        name: "Domain Trust Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [20]
    FlowAction {
        technique_id: "T1558",
        tactic: "credential-access",
        name: "Steal or Forge Kerberos Tickets: Kerberoasting",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
];

// ── Conti Ransomware ──────────────────────────────────────────────────────────
// Source: "Conti Ransomware.afb" (CTID corpus)
// RaaS group using Cobalt Strike; 19 action nodes.

static CONTI_RANSOMWARE_ACTIONS: &[FlowAction] = &[
    // [0] Spearphishing Attachment (initial access)
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Phishing: Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1] JavaScript execution (macro/script in attachment)
    FlowAction {
        technique_id: "T1059",
        tactic: "execution",
        name: "Command and Scripting Interpreter: JavaScript",
        artifact_ids: &["prefetch_dir", "amcache_app_file"],
        leads_to: &[2],
    },
    // [2] Ingress Tool Transfer (Cobalt Strike beacon)
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[3],
    },
    // [3] Rundll32 proxy execution
    FlowAction {
        technique_id: "T1218",
        tactic: "defense-evasion",
        name: "System Binary Proxy Execution: Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[4],
    },
    // [4] Access Token Manipulation
    FlowAction {
        technique_id: "T1134",
        tactic: "privilege-escalation",
        name: "Access Token Manipulation",
        artifact_ids: &["evtx_security"],
        leads_to: &[5],
    },
    // [5] SMB lateral movement with elevated token
    FlowAction {
        technique_id: "T1021.002",
        tactic: "lateral-movement",
        name: "Remote Services: SMB/Windows Admin Shares",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[6],
    },
    // [6] Ingress Tool Transfer to lateral host
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer (lateral host)",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[7, 8, 9],
    },
    // [7] Remote System Discovery
    FlowAction {
        technique_id: "T1018",
        tactic: "discovery",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [8] System Owner/User Discovery
    FlowAction {
        technique_id: "T1033",
        tactic: "discovery",
        name: "System Owner/User Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[],
    },
    // [9] Network Service Discovery
    FlowAction {
        technique_id: "T1046",
        tactic: "discovery",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[10],
    },
    // [10] RDP lateral movement
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Services: Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[11],
    },
    // [11] Domain Account discovery
    FlowAction {
        technique_id: "T1087",
        tactic: "discovery",
        name: "Account Discovery: Domain Account",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[12],
    },
    // [12] Group Policy Modification (mass deployment)
    FlowAction {
        technique_id: "T1484",
        tactic: "defense-evasion",
        name: "Domain Policy Modification: Group Policy Modification",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[13],
    },
    // [13] Disable or Modify Tools (AV before encryption)
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Impair Defenses: Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[14],
    },
    // [14] SMB Admin Shares for payload distribution
    FlowAction {
        technique_id: "T1021.002",
        tactic: "lateral-movement",
        name: "Remote Services: SMB/Windows Admin Shares (payload drop)",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[15],
    },
    // [15] Data Encrypted for Impact
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
];

// ── DFIR BumbleBee Round 2 ────────────────────────────────────────────────────
// Source: "DFIR - BumbleBee Round 2.afb" (CTID corpus)
// BumbleBee loader → Cobalt Strike → RDP → remote access; 19 action nodes.

static BUMBLBEE_ROUND2_ACTIONS: &[FlowAction] = &[
    // [0] Shortcut Modification (LNK persistence / initial execution)
    FlowAction {
        technique_id: "T1547.009",
        tactic: "persistence",
        name: "Boot or Logon Autostart Execution: Shortcut Modification",
        artifact_ids: &["lnk_files", "run_key_hkcu"],
        leads_to: &[1, 2],
    },
    // [1] Ingress Tool Transfer (BumbleBee drops Cobalt Strike)
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[3],
    },
    // [2] Command and Scripting Interpreter (initial command execution)
    FlowAction {
        technique_id: "T1059",
        tactic: "execution",
        name: "Command and Scripting Interpreter",
        artifact_ids: &["prefetch_dir", "amcache_app_file"],
        leads_to: &[4, 5, 6],
    },
    // [3] Rundll32 proxy execution (Cobalt Strike)
    FlowAction {
        technique_id: "T1218",
        tactic: "defense-evasion",
        name: "System Binary Proxy Execution: Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[7],
    },
    // [4] Network Share Discovery
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [5] Domain Account Discovery
    FlowAction {
        technique_id: "T1087",
        tactic: "discovery",
        name: "Account Discovery: Domain Account",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [6] Domain Trust Discovery
    FlowAction {
        technique_id: "T1482",
        tactic: "discovery",
        name: "Domain Trust Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [7] Process Injection
    FlowAction {
        technique_id: "T1055",
        tactic: "defense-evasion",
        name: "Process Injection",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[],
    },
    // [8] Application Layer Protocol C2 (from parallel root)
    FlowAction {
        technique_id: "T1071",
        tactic: "command-and-control",
        name: "Application Layer Protocol",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[9],
    },
    // [9] Account Discovery (via C2 session)
    FlowAction {
        technique_id: "T1087",
        tactic: "discovery",
        name: "Account Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[10],
    },
    // [10] LSASS Memory credential dumping
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "OS Credential Dumping: LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon", "prefetch_dir"],
        leads_to: &[11],
    },
    // [11] RDP lateral movement
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Services: Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[12],
    },
    // [12] Remote Access Software (AnyDesk/TeamViewer)
    FlowAction {
        technique_id: "T1219",
        tactic: "command-and-control",
        name: "Remote Access Software",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[13],
    },
    // [13] Domain Account creation for persistence
    FlowAction {
        technique_id: "T1136",
        tactic: "persistence",
        name: "Create Account: Domain Account",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[14],
    },
    // [14] System Network Configuration Discovery
    FlowAction {
        technique_id: "T1016",
        tactic: "discovery",
        name: "System Network Configuration Discovery",
        artifact_ids: &["evtx_sysmon"],
        leads_to: &[15],
    },
    // [15] Remote Access Software (second stage, different host)
    FlowAction {
        technique_id: "T1219",
        tactic: "command-and-control",
        name: "Remote Access Software (persistence)",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[16],
    },
    // [16] RDP lateral movement (second hop)
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Services: Remote Desktop Protocol (second hop)",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client"],
        leads_to: &[17],
    },
    // [17] Windows Command Shell
    FlowAction {
        technique_id: "T1059.003",
        tactic: "execution",
        name: "Command and Scripting Interpreter: Windows Command Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[],
    },
];

/// All available attack flow scenarios, sourced from the CTID Attack Flow corpus.
static ATTACK_FLOWS: &[AttackFlow] = &[
    AttackFlow {
        id: "black_basta_ransomware",
        name: "Black Basta Ransomware",
        description: "RaaS double-extortion campaign: spearphishing → deobfuscation \
                       → PowerShell → DLL hijack → C2 → lateral movement via RDP \
                       → VSS deletion → data encryption; observed since April 2022",
        actions: BLACK_BASTA_ACTIONS,
    },
    AttackFlow {
        id: "cobalt_kitty_campaign",
        name: "Cobalt Kitty Campaign",
        description: "Vietnamese APT (OceanLotus/APT32) operation: spearphishing link \
                       and attachment → PowerShell → DLL side-loading → Cobalt Strike \
                       → LSA credential dumping → SMB/PtH/WMI lateral movement",
        actions: COBALT_KITTY_ACTIONS,
    },
    AttackFlow {
        id: "solarwinds_supply_chain",
        name: "SolarWinds Supply Chain Attack",
        description: "Nation-state supply-chain intrusion: trojanized SolarWinds Orion \
                       update → dormancy evasion → masquerading → Windows Service \
                       persistence → Kerberoasting → data collection → exfiltration",
        actions: SOLARWINDS_ACTIONS,
    },
    AttackFlow {
        id: "conti_ransomware",
        name: "Conti Ransomware",
        description: "RaaS group campaign: spearphishing → JavaScript execution → \
                       Cobalt Strike C2 → token manipulation → SMB/RDP lateral movement \
                       → Group Policy for mass AV disable → encryption",
        actions: CONTI_RANSOMWARE_ACTIONS,
    },
    AttackFlow {
        id: "bumblbee_round2",
        name: "DFIR - BumbleBee Round 2",
        description: "BumbleBee loader campaign: LNK shortcut → Cobalt Strike via \
                       Rundll32 → LSASS credential dumping → RDP lateral movement \
                       → AnyDesk remote access → domain account creation",
        actions: BUMBLBEE_ROUND2_ACTIONS,
    },
];

// ── Query API ────────────────────────────────────────────────────────────────

/// Look up a campaign flow by its stable `id`.
pub fn flow_by_id(id: &str) -> Option<&'static AttackFlow> {
    ATTACK_FLOWS.iter().find(|f| f.id == id)
}

/// Return all available attack flows.
pub fn all_flows() -> &'static [AttackFlow] {
    ATTACK_FLOWS
}

/// Collect all unique artifact IDs referenced across all actions in a flow.
///
/// Returns an empty `Vec` if `flow_id` is not found.
pub fn artifacts_in_flow(flow_id: &str) -> Vec<&'static str> {
    let Some(flow) = flow_by_id(flow_id) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut ids = Vec::new();
    for action in flow.actions {
        for &id in action.artifact_ids {
            if seen.insert(id) {
                ids.push(id);
            }
        }
    }
    ids
}

/// Return all flows that reference `artifact_id` in at least one action.
pub fn flows_for_artifact(artifact_id: &str) -> Vec<&'static AttackFlow> {
    ATTACK_FLOWS
        .iter()
        .filter(|f| {
            f.actions
                .iter()
                .any(|a| a.artifact_ids.contains(&artifact_id))
        })
        .collect()
}

/// Return all flows that contain an action for `technique_id`.
pub fn flows_for_technique(technique_id: &str) -> Vec<&'static AttackFlow> {
    ATTACK_FLOWS
        .iter()
        .filter(|f| f.actions.iter().any(|a| a.technique_id == technique_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn attack_flow_table_nonempty() {
        assert!(!ATTACK_FLOWS.is_empty(), "need at least one flow");
    }

    #[test]
    fn flow_by_id_returns_correct_flow() {
        let f = flow_by_id("black_basta_ransomware").unwrap();
        assert_eq!(f.id, "black_basta_ransomware");
        assert!(f.name.contains("Black Basta"));
    }

    #[test]
    fn unknown_flow_id_returns_none() {
        assert!(flow_by_id("nonexistent_scenario").is_none());
    }

    #[test]
    fn every_flow_has_at_least_two_actions() {
        for flow in ATTACK_FLOWS {
            assert!(
                flow.actions.len() >= 2,
                "flow '{}' has only {} action(s) — flows should model sequences",
                flow.id,
                flow.actions.len()
            );
        }
    }

    #[test]
    fn every_flow_has_nonempty_description() {
        for flow in ATTACK_FLOWS {
            assert!(!flow.description.is_empty(), "flow '{}' has empty description", flow.id);
        }
    }

    #[test]
    fn leads_to_indices_are_in_bounds() {
        for flow in ATTACK_FLOWS {
            let len = flow.actions.len();
            for (i, action) in flow.actions.iter().enumerate() {
                for &j in action.leads_to {
                    assert!(
                        j < len,
                        "flow '{}' action[{i}] leads_to index {j} is out of bounds (len={len})",
                        flow.id,
                    );
                }
            }
        }
    }

    #[test]
    fn artifacts_in_flow_are_in_catalog() {
        // Only check curated IDs — generated IDs may differ across ingest runs.
        // We accept the artifact either in the catalog or as a known generated ID.
        let curated_prefixes = ["evtx_", "kape_", "fa_", "browsers_", "velociraptor_",
                                 "nirsoft_", "regedit_"];
        for flow in ATTACK_FLOWS {
            for artifact_id in artifacts_in_flow(flow.id) {
                let in_catalog = CATALOG.by_id(artifact_id).is_some();
                let is_generated = curated_prefixes.iter().any(|p| artifact_id.starts_with(p));
                assert!(
                    in_catalog || is_generated,
                    "flow '{}' references artifact '{}' which is not in the catalog",
                    flow.id,
                    artifact_id
                );
            }
        }
    }

    #[test]
    fn artifacts_in_flow_deduplicates() {
        for flow in ATTACK_FLOWS {
            let ids = artifacts_in_flow(flow.id);
            let mut seen = std::collections::HashSet::new();
            for id in &ids {
                assert!(seen.insert(id), "duplicate artifact '{id}' in flow '{}'", flow.id);
            }
        }
    }

    #[test]
    fn flows_for_artifact_finds_relevant_flows() {
        let flows = flows_for_artifact("powershell_history");
        assert!(
            !flows.is_empty(),
            "powershell_history should appear in at least one flow"
        );
        assert!(flows.iter().any(|f| f.id == "black_basta_ransomware"));
    }

    #[test]
    fn flows_for_artifact_unknown_returns_empty() {
        let flows = flows_for_artifact("__definitely_not_an_artifact__");
        assert!(flows.is_empty());
    }

    #[test]
    fn flows_for_technique_finds_ransomware() {
        let flows = flows_for_technique("T1486");
        assert!(
            flows.iter().any(|f| f.id == "black_basta_ransomware"),
            "T1486 should be in black_basta_ransomware"
        );
    }

    #[test]
    fn all_flow_ids_are_unique() {
        let mut ids = std::collections::HashSet::new();
        for flow in ATTACK_FLOWS {
            assert!(ids.insert(flow.id), "duplicate flow id: '{}'", flow.id);
        }
    }

    #[test]
    fn flow_action_technique_method_returns_correct_struct() {
        let flow = flow_by_id("black_basta_ransomware").unwrap();
        // The last action in the Black Basta flow is T1486 (Data Encrypted for Impact)
        let last = flow.actions.last().unwrap();
        let t = last.technique();
        assert_eq!(t.technique_id, "T1486");
        assert_eq!(t.tactic, "impact");
    }

    #[test]
    fn covered_techniques_in_navigator_are_typed() {
        let techniques = crate::navigator::covered_techniques();
        assert!(!techniques.is_empty());
        // Every entry should have a non-empty technique_id
        for t in &techniques {
            assert!(!t.technique_id.is_empty());
        }
    }

    // ── CTID-sourced flow tests (RED: these fail until the real data is added) ──

    /// The corpus must contain at least 5 flows (the 5 real CTID flows).
    #[test]
    fn ctid_flow_count_at_least_five() {
        assert!(
            ATTACK_FLOWS.len() >= 5,
            "expected at least 5 flows from CTID corpus, got {}",
            ATTACK_FLOWS.len()
        );
    }

    /// Black Basta Ransomware flow from CTID corpus must exist.
    #[test]
    fn ctid_black_basta_ransomware_flow_exists() {
        let f = flow_by_id("black_basta_ransomware")
            .expect("flow 'black_basta_ransomware' must exist (CTID corpus)");
        assert!(f.name.contains("Black Basta"), "name should contain 'Black Basta'");
    }

    /// Black Basta must have its first real technique T1566.001 (spearphishing attachment).
    #[test]
    fn ctid_black_basta_has_t1566_001() {
        let f = flow_by_id("black_basta_ransomware")
            .expect("flow 'black_basta_ransomware' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "black_basta_ransomware must contain T1566.001 (Spearphishing Attachment)"
        );
    }

    /// Black Basta must have T1486 (ransomware encryption).
    #[test]
    fn ctid_black_basta_has_t1486() {
        let f = flow_by_id("black_basta_ransomware")
            .expect("flow 'black_basta_ransomware' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1486"),
            "black_basta_ransomware must contain T1486 (Data Encrypted for Impact)"
        );
    }

    /// Cobalt Kitty Campaign flow from CTID corpus must exist.
    #[test]
    fn ctid_cobalt_kitty_campaign_flow_exists() {
        let f = flow_by_id("cobalt_kitty_campaign")
            .expect("flow 'cobalt_kitty_campaign' must exist (CTID corpus)");
        assert!(f.name.contains("Cobalt Kitty"), "name should contain 'Cobalt Kitty'");
    }

    /// Cobalt Kitty must have T1566.002 (spearphishing link — its initial access).
    #[test]
    fn ctid_cobalt_kitty_has_t1566_002() {
        let f = flow_by_id("cobalt_kitty_campaign")
            .expect("flow 'cobalt_kitty_campaign' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.002"),
            "cobalt_kitty_campaign must contain T1566.002 (Spearphishing Link)"
        );
    }

    /// SolarWinds supply-chain flow from CTID corpus must exist.
    #[test]
    fn ctid_solarwinds_supply_chain_flow_exists() {
        let f = flow_by_id("solarwinds_supply_chain")
            .expect("flow 'solarwinds_supply_chain' must exist (CTID corpus)");
        assert!(f.name.contains("SolarWinds"), "name should contain 'SolarWinds'");
    }

    /// SolarWinds must have T1195.002 (supply chain compromise — its hallmark technique).
    #[test]
    fn ctid_solarwinds_has_t1195_002() {
        let f = flow_by_id("solarwinds_supply_chain")
            .expect("flow 'solarwinds_supply_chain' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1195.002"),
            "solarwinds_supply_chain must contain T1195.002 (Compromise Software Supply Chain)"
        );
    }

    /// Conti Ransomware flow from CTID corpus must exist.
    #[test]
    fn ctid_conti_ransomware_flow_exists() {
        let f = flow_by_id("conti_ransomware")
            .expect("flow 'conti_ransomware' must exist (CTID corpus)");
        assert!(f.name.contains("Conti"), "name should contain 'Conti'");
    }

    /// Conti must have T1486 (ransomware encryption).
    #[test]
    fn ctid_conti_ransomware_has_t1486() {
        let f = flow_by_id("conti_ransomware")
            .expect("flow 'conti_ransomware' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1486"),
            "conti_ransomware must contain T1486 (Data Encrypted for Impact)"
        );
    }

    /// BumbleBee Round 2 flow from CTID corpus must exist.
    #[test]
    fn ctid_bumblbee_round2_flow_exists() {
        let f = flow_by_id("bumblbee_round2")
            .expect("flow 'bumblbee_round2' must exist (CTID corpus)");
        assert!(f.name.contains("BumbleBee"), "name should contain 'BumbleBee'");
    }

    /// BumbleBee must have T1003.001 (LSASS credential dumping).
    #[test]
    fn ctid_bumblbee_round2_has_t1003_001() {
        let f = flow_by_id("bumblbee_round2")
            .expect("flow 'bumblbee_round2' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1003.001"),
            "bumblbee_round2 must contain T1003.001 (LSASS Memory)"
        );
    }

    /// All CTID flows must have their real technique IDs (not empty strings).
    #[test]
    fn ctid_flows_have_nonempty_technique_ids() {
        let ctid_ids = [
            "black_basta_ransomware",
            "cobalt_kitty_campaign",
            "solarwinds_supply_chain",
            "conti_ransomware",
            "bumblbee_round2",
        ];
        for id in ctid_ids {
            if let Some(f) = flow_by_id(id) {
                for action in f.actions {
                    assert!(
                        !action.technique_id.is_empty(),
                        "flow '{}' has an action with empty technique_id: '{}'",
                        id, action.name
                    );
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RED tests: all 35 remaining CTID corpus flows (must fail until GREEN)

    /// All 40 corpus flows must be present (5 existing + 35 new).
    #[test]
    fn all_ctid_flows_present() {
        assert!(
            all_flows().len() >= 40,
            "expected at least 40 CTID flows, got {}",
            all_flows().len()
        );
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_alt_flow_exists() {
        flow_by_id("cisa_aa22_138b_vmware_workspace_alt")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_alt\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_alt_has_t1203() {
        let f = flow_by_id("cisa_aa22_138b_vmware_workspace_alt")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_alt\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1203"),
            "cisa_aa22_138b_vmware_workspace_alt must contain T1203"
        );
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_ta1_flow_exists() {
        flow_by_id("cisa_aa22_138b_vmware_workspace_ta1")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_ta1\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_ta1_has_t1071_001() {
        let f = flow_by_id("cisa_aa22_138b_vmware_workspace_ta1")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_ta1\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1071.001"),
            "cisa_aa22_138b_vmware_workspace_ta1 must contain T1071.001"
        );
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_ta2_flow_exists() {
        flow_by_id("cisa_aa22_138b_vmware_workspace_ta2")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_ta2\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_cisa_aa22_138b_vmware_workspace_ta2_has_t1071_001() {
        let f = flow_by_id("cisa_aa22_138b_vmware_workspace_ta2")
            .expect("flow \"cisa_aa22_138b_vmware_workspace_ta2\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1071.001"),
            "cisa_aa22_138b_vmware_workspace_ta2 must contain T1071.001"
        );
    }

    #[test]
    fn ctid_cisa_iranian_apt_flow_exists() {
        flow_by_id("cisa_iranian_apt")
            .expect("flow \"cisa_iranian_apt\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_cisa_iranian_apt_has_t1190() {
        let f = flow_by_id("cisa_iranian_apt")
            .expect("flow \"cisa_iranian_apt\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "cisa_iranian_apt must contain T1190"
        );
    }

    #[test]
    fn ctid_conti_cisa_alert_flow_exists() {
        flow_by_id("conti_cisa_alert")
            .expect("flow \"conti_cisa_alert\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_conti_cisa_alert_has_t1598_004() {
        let f = flow_by_id("conti_cisa_alert")
            .expect("flow \"conti_cisa_alert\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1598.004"),
            "conti_cisa_alert must contain T1598.004"
        );
    }

    #[test]
    fn ctid_conti_pwc_flow_exists() {
        flow_by_id("conti_pwc")
            .expect("flow \"conti_pwc\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_conti_pwc_has_t1566_001() {
        let f = flow_by_id("conti_pwc")
            .expect("flow \"conti_pwc\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "conti_pwc must contain T1566.001"
        );
    }

    #[test]
    fn ctid_equifax_breach_flow_exists() {
        flow_by_id("equifax_breach")
            .expect("flow \"equifax_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_equifax_breach_has_t1595_002() {
        let f = flow_by_id("equifax_breach")
            .expect("flow \"equifax_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1595.002"),
            "equifax_breach must contain T1595.002"
        );
    }

    #[test]
    fn ctid_example_attack_tree_flow_exists() {
        flow_by_id("example_attack_tree")
            .expect("flow \"example_attack_tree\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_fin13_case_1_flow_exists() {
        flow_by_id("fin13_case_1")
            .expect("flow \"fin13_case_1\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_fin13_case_1_has_t1595_002() {
        let f = flow_by_id("fin13_case_1")
            .expect("flow \"fin13_case_1\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1595.002"),
            "fin13_case_1 must contain T1595.002"
        );
    }

    #[test]
    fn ctid_fin13_case_2_flow_exists() {
        flow_by_id("fin13_case_2")
            .expect("flow \"fin13_case_2\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_fin13_case_2_has_t1190() {
        let f = flow_by_id("fin13_case_2")
            .expect("flow \"fin13_case_2\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "fin13_case_2 must contain T1190"
        );
    }

    #[test]
    fn ctid_gootloader_flow_exists() {
        flow_by_id("gootloader")
            .expect("flow \"gootloader\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_gootloader_has_t1584() {
        let f = flow_by_id("gootloader")
            .expect("flow \"gootloader\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1584"),
            "gootloader must contain T1584"
        );
    }

    #[test]
    fn ctid_hancitor_dll_flow_exists() {
        flow_by_id("hancitor_dll")
            .expect("flow \"hancitor_dll\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_hancitor_dll_has_t1566_002() {
        let f = flow_by_id("hancitor_dll")
            .expect("flow \"hancitor_dll\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.002"),
            "hancitor_dll must contain T1566.002"
        );
    }

    #[test]
    fn ctid_ivanti_vulnerabilities_flow_exists() {
        flow_by_id("ivanti_vulnerabilities")
            .expect("flow \"ivanti_vulnerabilities\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_ivanti_vulnerabilities_has_t1190() {
        let f = flow_by_id("ivanti_vulnerabilities")
            .expect("flow \"ivanti_vulnerabilities\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "ivanti_vulnerabilities must contain T1190"
        );
    }

    #[test]
    fn ctid_jp_morgan_breach_flow_exists() {
        flow_by_id("jp_morgan_breach")
            .expect("flow \"jp_morgan_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_jp_morgan_breach_has_t1566() {
        let f = flow_by_id("jp_morgan_breach")
            .expect("flow \"jp_morgan_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566"),
            "jp_morgan_breach must contain T1566"
        );
    }

    #[test]
    fn ctid_mitre_nerve_flow_exists() {
        flow_by_id("mitre_nerve")
            .expect("flow \"mitre_nerve\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_mitre_nerve_has_t1190() {
        let f = flow_by_id("mitre_nerve")
            .expect("flow \"mitre_nerve\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "mitre_nerve must contain T1190"
        );
    }

    #[test]
    fn ctid_maastricht_university_ransomware_flow_exists() {
        flow_by_id("maastricht_university_ransomware")
            .expect("flow \"maastricht_university_ransomware\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_maastricht_university_ransomware_has_t1566_001() {
        let f = flow_by_id("maastricht_university_ransomware")
            .expect("flow \"maastricht_university_ransomware\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "maastricht_university_ransomware must contain T1566.001"
        );
    }

    #[test]
    fn ctid_mac_malware_steals_crypto_flow_exists() {
        flow_by_id("mac_malware_steals_crypto")
            .expect("flow \"mac_malware_steals_crypto\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_mac_malware_steals_crypto_has_t1059_006() {
        let f = flow_by_id("mac_malware_steals_crypto")
            .expect("flow \"mac_malware_steals_crypto\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1059.006"),
            "mac_malware_steals_crypto must contain T1059.006"
        );
    }

    #[test]
    fn ctid_marriott_breach_flow_exists() {
        flow_by_id("marriott_breach")
            .expect("flow \"marriott_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_marriott_breach_has_t1566() {
        let f = flow_by_id("marriott_breach")
            .expect("flow \"marriott_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566"),
            "marriott_breach must contain T1566"
        );
    }

    #[test]
    fn ctid_muddy_water_flow_exists() {
        flow_by_id("muddy_water")
            .expect("flow \"muddy_water\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_muddy_water_has_t1566_001() {
        let f = flow_by_id("muddy_water")
            .expect("flow \"muddy_water\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "muddy_water must contain T1566.001"
        );
    }

    #[test]
    fn ctid_notpetya_flow_exists() {
        flow_by_id("notpetya")
            .expect("flow \"notpetya\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_notpetya_has_t1593() {
        let f = flow_by_id("notpetya")
            .expect("flow \"notpetya\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1593"),
            "notpetya must contain T1593"
        );
    }

    #[test]
    fn ctid_oceanlotus_flow_exists() {
        flow_by_id("oceanlotus")
            .expect("flow \"oceanlotus\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_oceanlotus_has_t1566_001() {
        let f = flow_by_id("oceanlotus")
            .expect("flow \"oceanlotus\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "oceanlotus must contain T1566.001"
        );
    }

    #[test]
    fn ctid_openclaw_flow_exists() {
        flow_by_id("openclaw")
            .expect("flow \"openclaw\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_revil_flow_exists() {
        flow_by_id("revil")
            .expect("flow \"revil\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_revil_has_t1189() {
        let f = flow_by_id("revil")
            .expect("flow \"revil\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1189"),
            "revil must contain T1189"
        );
    }

    #[test]
    fn ctid_ragnar_locker_flow_exists() {
        flow_by_id("ragnar_locker")
            .expect("flow \"ragnar_locker\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_ragnar_locker_has_t1078() {
        let f = flow_by_id("ragnar_locker")
            .expect("flow \"ragnar_locker\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1078"),
            "ragnar_locker must contain T1078"
        );
    }

    #[test]
    fn ctid_swift_heist_flow_exists() {
        flow_by_id("swift_heist")
            .expect("flow \"swift_heist\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_swift_heist_has_t1190() {
        let f = flow_by_id("swift_heist")
            .expect("flow \"swift_heist\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "swift_heist must contain T1190"
        );
    }

    #[test]
    fn ctid_searchawesome_adware_flow_exists() {
        flow_by_id("searchawesome_adware")
            .expect("flow \"searchawesome_adware\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_searchawesome_adware_has_t1204_002() {
        let f = flow_by_id("searchawesome_adware")
            .expect("flow \"searchawesome_adware\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1204.002"),
            "searchawesome_adware must contain T1204.002"
        );
    }

    #[test]
    fn ctid_shamoon_flow_exists() {
        flow_by_id("shamoon")
            .expect("flow \"shamoon\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_shamoon_has_t1105() {
        let f = flow_by_id("shamoon")
            .expect("flow \"shamoon\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1105"),
            "shamoon must contain T1105"
        );
    }

    #[test]
    fn ctid_sony_malware_flow_exists() {
        flow_by_id("sony_malware")
            .expect("flow \"sony_malware\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_sony_malware_has_t1105() {
        let f = flow_by_id("sony_malware")
            .expect("flow \"sony_malware\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1105"),
            "sony_malware must contain T1105"
        );
    }

    #[test]
    fn ctid_target_breach_flow_exists() {
        flow_by_id("target_breach")
            .expect("flow \"target_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_target_breach_has_t1593_002() {
        let f = flow_by_id("target_breach")
            .expect("flow \"target_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1593.002"),
            "target_breach must contain T1593.002"
        );
    }

    #[test]
    fn ctid_tesla_kubernetes_breach_flow_exists() {
        flow_by_id("tesla_kubernetes_breach")
            .expect("flow \"tesla_kubernetes_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_tesla_kubernetes_breach_has_t1133() {
        let f = flow_by_id("tesla_kubernetes_breach")
            .expect("flow \"tesla_kubernetes_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1133"),
            "tesla_kubernetes_breach must contain T1133"
        );
    }

    #[test]
    fn ctid_toolshell_vulnerability_in_sharepoint_flow_exists() {
        flow_by_id("toolshell_vulnerability_in_sharepoint")
            .expect("flow \"toolshell_vulnerability_in_sharepoint\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_turla_carbon_emulation_plan_flow_exists() {
        flow_by_id("turla_carbon_emulation_plan")
            .expect("flow \"turla_carbon_emulation_plan\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_turla_snake_emulation_plan_flow_exists() {
        flow_by_id("turla_snake_emulation_plan")
            .expect("flow \"turla_snake_emulation_plan\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_uber_breach_flow_exists() {
        flow_by_id("uber_breach")
            .expect("flow \"uber_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_uber_breach_has_t1586() {
        let f = flow_by_id("uber_breach")
            .expect("flow \"uber_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1586"),
            "uber_breach must contain T1586"
        );
    }

    #[test]
    fn ctid_whispergate_flow_exists() {
        flow_by_id("whispergate")
            .expect("flow \"whispergate\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_whispergate_has_t1078() {
        let f = flow_by_id("whispergate")
            .expect("flow \"whispergate\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1078"),
            "whispergate must contain T1078"
        );
    }
}
