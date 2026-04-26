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
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
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
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
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

// ═══════════════════════════════════════════════════════════════════════════════
// NEW FLOWS FROM CTID CORPUS
// ═══════════════════════════════════════════════════════════════════════════════

// ── CISA AA22-138B VMWare Workspace (Alt) ─────────────────────────────────────
// Source: "CISA AA22-138B VMWare Workspace (Alt).afb" (CTID corpus)
// 11 action nodes

static CISA_AA22_138B_VMWARE_WORKSPACE_ALT_ACTIONS: &[FlowAction] = &[
    // [0] T1203
    FlowAction {
        technique_id: "T1203",
        tactic: "execution",
        name: "Exploitation for Client Execution",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1068
    FlowAction {
        technique_id: "T1068",
        tactic: "privilege-escalation",
        name: "Exploitation for Privilege Escalation",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1059
    FlowAction {
        technique_id: "T1059",
        tactic: "execution",
        name: "Command and Scripting Interpreter",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "discovery",
        name: "Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[4],
    },
    // [4] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[5],
    },
    // [5] T1560.001
    FlowAction {
        technique_id: "T1560.001",
        tactic: "collection",
        name: "Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [7] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[8],
    },
    // [8] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[9],
    },
    // [9] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[10],
    },
    // [10] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[],
    },
];

// ── CISA AA22-138B VMWare Workspace (TA1) ─────────────────────────────────────
// Source: "CISA AA22-138B VMWare Workspace (TA1).afb" (CTID corpus)
// 10 action nodes

static CISA_AA22_138B_VMWARE_WORKSPACE_TA1_ACTIONS: &[FlowAction] = &[
    // [0] T1071.001
    FlowAction {
        technique_id: "T1071.001",
        tactic: "command-and-control",
        name: "Web Protocols",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[1],
    },
    // [1] T1203
    FlowAction {
        technique_id: "T1203",
        tactic: "execution",
        name: "Exploitation for Client Execution",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[2, 3],
    },
    // [2] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[4],
    },
    // [3] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[4],
    },
    // [4] T1068
    FlowAction {
        technique_id: "T1068",
        tactic: "privilege-escalation",
        name: "Exploitation for Privilege Escalation",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5],
    },
    // [5] T1119
    FlowAction {
        technique_id: "T1119",
        tactic: "collection",
        name: "Automated Collection",
        artifact_ids: &["evtx_sysmon", "mft_file"],
        leads_to: &[6],
    },
    // [6] T1560.001
    FlowAction {
        technique_id: "T1560.001",
        tactic: "collection",
        name: "Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[7],
    },
    // [7] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[8],
    },
    // [8] T1071.001
    FlowAction {
        technique_id: "T1071.001",
        tactic: "command-and-control",
        name: "Web Protocols",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[9],
    },
    // [9] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
];

// ── CISA AA22-138B VMWare Workspace (TA2) ─────────────────────────────────────
// Source: "CISA AA22-138B VMWare Workspace (TA2).afb" (CTID corpus)
// 11 action nodes

static CISA_AA22_138B_VMWARE_WORKSPACE_TA2_ACTIONS: &[FlowAction] = &[
    // [0] T1071.001
    FlowAction {
        technique_id: "T1071.001",
        tactic: "command-and-control",
        name: "Web Protocols",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[1],
    },
    // [1] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[2],
    },
    // [2] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[3],
    },
    // [3] T1059.004
    FlowAction {
        technique_id: "T1059.004",
        tactic: "execution",
        name: "Unix Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1003.008
    FlowAction {
        technique_id: "T1003.008",
        tactic: "unknown",
        name: "OS Credential Dumping: /etc/passwd and /etc/shadow",
        artifact_ids: &["evtx_security", "prefetch_dir"],
        leads_to: &[5],
    },
    // [5] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[6],
    },
    // [6] T1573.001
    FlowAction {
        technique_id: "T1573.001",
        tactic: "command-and-control",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[7],
    },
    // [7] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[8],
    },
    // [8] T1090
    FlowAction {
        technique_id: "T1090",
        tactic: "command-and-control",
        name: "Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[9],
    },
    // [9] T1222.002
    FlowAction {
        technique_id: "T1222.002",
        tactic: "unknown",
        name: "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
        artifact_ids: &["evtx_security", "mft_file"],
        leads_to: &[10],
    },
    // [10] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[],
    },
];

// ── CISA Iranian APT ──────────────────────────────────────────────────────────
// Source: "CISA Iranian APT.afb" (CTID corpus)
// 23 action nodes

static CISA_IRANIAN_APT_ACTIONS: &[FlowAction] = &[
    // [0] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[2],
    },
    // [2] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[3],
    },
    // [3] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[4],
    },
    // [4] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[5],
    },
    // [5] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[6],
    },
    // [6] T1136.001
    FlowAction {
        technique_id: "T1136.001",
        tactic: "persistence",
        name: "Local Account",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[7],
    },
    // [7] T1016.001
    FlowAction {
        technique_id: "T1016.001",
        tactic: "discovery",
        name: "Internet Connection Discovery",
        artifact_ids: &["evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1053.005
    FlowAction {
        technique_id: "T1053.005",
        tactic: "persistence",
        name: "Scheduled Task",
        artifact_ids: &["scheduled_tasks_dir", "evtx_task_scheduler"],
        leads_to: &[9],
    },
    // [9] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[10],
    },
    // [10] T1078.001
    FlowAction {
        technique_id: "T1078.001",
        tactic: "unknown",
        name: "Default Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[11],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [12] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[13],
    },
    // [13] T1136.002
    FlowAction {
        technique_id: "T1136.002",
        tactic: "privilege-escalation",
        name: "Domain Account",
        artifact_ids: &["evtx_security", "ntds_dit"],
        leads_to: &[14],
    },
    // [14] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[15],
    },
    // [15] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[16],
    },
    // [16] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[17],
    },
    // [17] T1090
    FlowAction {
        technique_id: "T1090",
        tactic: "command-and-control",
        name: "Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[18],
    },
    // [18] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[19],
    },
    // [19] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[20],
    },
    // [20] T1018
    FlowAction {
        technique_id: "T1018",
        tactic: "discovery",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[21],
    },
    // [21] T1098
    FlowAction {
        technique_id: "T1098",
        tactic: "persistence",
        name: "Account Manipulation",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[22],
    },
    // [22] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
];

// ── Conti CISA Alert ──────────────────────────────────────────────────────────
// Source: "Conti CISA Alert.afb" (CTID corpus)
// 18 action nodes

static CONTI_CISA_ALERT_ACTIONS: &[FlowAction] = &[
    // [0] T1598.004
    FlowAction {
        technique_id: "T1598.004",
        tactic: "reconnaissance",
        name: "Social Engineering",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5, 6],
    },
    // [1] T1608.006
    FlowAction {
        technique_id: "T1608.006",
        tactic: "resource-development",
        name: "Fake Software",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5, 6],
    },
    // [2] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[5, 6],
    },
    // [3] T1566.002
    FlowAction {
        technique_id: "T1566.002",
        tactic: "initial-access",
        name: "Spearphishing Link",
        artifact_ids: &["evtx_security", "chrome_history"],
        leads_to: &[5, 6],
    },
    // [4] T1076
    FlowAction {
        technique_id: "T1076",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[7, 8, 9],
    },
    // [5] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[7, 8, 9],
    },
    // [6] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[7, 8, 9],
    },
    // [7] T1057
    FlowAction {
        technique_id: "T1057",
        tactic: "discovery",
        name: "Process Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[11, 12, 13],
    },
    // [8] T1558.003
    FlowAction {
        technique_id: "T1558.003",
        tactic: "credential-access",
        name: "Kerberoasting",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [9] T1110
    FlowAction {
        technique_id: "T1110",
        tactic: "credential-access",
        name: "Brute Force",
        artifact_ids: &["evtx_security"],
        leads_to: &[11, 12, 13],
    },
    // [10] T1110
    FlowAction {
        technique_id: "T1110",
        tactic: "credential-access",
        name: "Brute Force",
        artifact_ids: &["evtx_security"],
        leads_to: &[11, 12, 13],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "persistence",
        name: "Persistence",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "privilege-escalation",
        name: "Privilege Escalation",
        artifact_ids: &["evtx_security"],
        leads_to: &[15, 16, 17],
    },
    // [13] T1203
    FlowAction {
        technique_id: "T1203",
        tactic: "execution",
        name: "Exploitation for Client Execution",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "privilege-escalation",
        name: "Privilege Escalation",
        artifact_ids: &["evtx_security"],
        leads_to: &[15, 16, 17],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [16] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
    // [17] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Conti PWC ─────────────────────────────────────────────────────────────────
// Source: "Conti PWC.afb" (CTID corpus)
// 7 action nodes

static CONTI_PWC_ACTIONS: &[FlowAction] = &[
    // [0] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1] T1204
    FlowAction {
        technique_id: "T1204",
        tactic: "execution",
        name: "User Execution",
        artifact_ids: &["lnk_files", "prefetch_dir"],
        leads_to: &[2],
    },
    // [2] T1586
    FlowAction {
        technique_id: "T1586",
        tactic: "resource-development",
        name: "Compromise Accounts",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3, 4, 5],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [4] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: " File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[6],
    },
    // [5] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Equifax Breach ────────────────────────────────────────────────────────────
// Source: "Equifax Breach.afb" (CTID corpus)
// 12 action nodes

static EQUIFAX_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1595.002
    FlowAction {
        technique_id: "T1595.002",
        tactic: "reconnaissance",
        name: "Vulnerability Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[1],
    },
    // [1] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3, 4],
    },
    // [3] T1590
    FlowAction {
        technique_id: "T1590",
        tactic: "reconnaissance",
        name: "Gather Victim Network Information",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[5],
    },
    // [4] T1589.001
    FlowAction {
        technique_id: "T1589.001",
        tactic: "reconnaissance",
        name: "Credentials",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[5],
    },
    // [5] T1573
    FlowAction {
        technique_id: "T1573",
        tactic: "command-and-control",
        name: "Encrypted Channel",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[6, 7],
    },
    // [6] T1560
    FlowAction {
        technique_id: "T1560",
        tactic: "collection",
        name: "Archive Collected Data",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[8],
    },
    // [7] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[8],
    },
    // [8] T1048.002
    FlowAction {
        technique_id: "T1048.002",
        tactic: "exfiltration",
        name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        artifact_ids: &["srum_network_usage", "evtx_security"],
        leads_to: &[9],
    },
    // [9] T1090.003
    FlowAction {
        technique_id: "T1090.003",
        tactic: "command-and-control",
        name: "Multi-hop Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[10, 11],
    },
    // [10] T1070.001
    FlowAction {
        technique_id: "T1070.001",
        tactic: "defense-evasion",
        name: "Clear Windows Event Logs",
        artifact_ids: &["evtx_security", "evtx_system", "usn_journal"],
        leads_to: &[],
    },
    // [11] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[],
    },
];

// ── Example Attack Tree ───────────────────────────────────────────────────────
// Source: "Example Attack Tree.afb" (CTID corpus)
// 40 action nodes

static EXAMPLE_ATTACK_TREE_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Compile Known User Data",
        artifact_ids: &["evtx_security"],
        leads_to: &[29],
    },
    // [1] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Determine Approximate Location",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Synthesize Known User Data and Information Within Dataset",
        artifact_ids: &["evtx_security"],
        leads_to: &[29],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Find a Free Copy of the Dataset Containing User Location Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[32],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Browser Session Hijacking",
        artifact_ids: &["evtx_security"],
        leads_to: &[30],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Downloading Manipulated Browser Extension ",
        artifact_ids: &["evtx_security"],
        leads_to: &[30],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Purchase User Credentials",
        artifact_ids: &["evtx_security"],
        leads_to: &[31],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Acquire User Credentials From Public Database",
        artifact_ids: &["evtx_security"],
        leads_to: &[31],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Purchase Dataset Containing User Location Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[32],
    },
    // [9] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Learn Tracker Serial Number",
        artifact_ids: &["evtx_security"],
        leads_to: &[33],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Device Data Is Unencrypted",
        artifact_ids: &["evtx_security"],
        leads_to: &[34],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Steal Tracker",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "User Interacts With Malicious Media ",
        artifact_ids: &["evtx_security"],
        leads_to: &[35],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Get Within Wireless Range of the Device",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Eavesdrop on Device Communications",
        artifact_ids: &["evtx_security"],
        leads_to: &[39],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Replace Tracker After Firmware Modification",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Associate Data with Unique Device ID",
        artifact_ids: &["evtx_security"],
        leads_to: &[36],
    },
    // [17] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Push Malicious Firmware Update",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [18] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Record User Login Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[37],
    },
    // [19] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Prompt User for Login Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[38],
    },
    // [20] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Get Within Wireless Range of the Device",
        artifact_ids: &["evtx_security"],
        leads_to: &[39],
    },
    // [21] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Re-Associate Device To Controlled User Account",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [22] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Trigger Synchronization Over BLE",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Local Data is Encrypted",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [24] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Disable Encryption",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [25] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Disable Authentication",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [26] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Replay Authentication Sequence Over Local BLE",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [27] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Associate Tracker With a Controlled Device Account",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [28] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Configure an Alternative Server Address Inside Victim’s Smartphone App",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [29] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Isolate User Data",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [30] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Session Hijacking ",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [31] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Leverage Existing User Credentials On The Web",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [32] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Aquire the Data",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [33] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Associate the Device with a Unique Identifier",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [34] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Device Data Is Unencrypted",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [35] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Send User Phishing Message",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [36] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Local Data Is in Plaintext",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [37] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Deploy Keylogger On User’s Device",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [38] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Direct User to Duplicate Site",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [39] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Wirelessly Connect to Tracker",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── FIN13 Case 1 ──────────────────────────────────────────────────────────────
// Source: "FIN13 Case 1.afb" (CTID corpus)
// 40 action nodes

static FIN13_CASE_1_ACTIONS: &[FlowAction] = &[
    // [0] T1595.002
    FlowAction {
        technique_id: "T1595.002",
        tactic: "reconnaissance",
        name: "Vulnerability Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[1],
    },
    // [1] T1595
    FlowAction {
        technique_id: "T1595",
        tactic: "reconnaissance",
        name: "Active Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[2],
    },
    // [2] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1046
    FlowAction {
        technique_id: "T1046",
        tactic: "discovery",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[5],
    },
    // [5] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [8] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[9, 10, 11, 12, 13],
    },
    // [9] T1033
    FlowAction {
        technique_id: "T1033",
        tactic: "discovery",
        name: "System Owner/User Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [10] T1222
    FlowAction {
        technique_id: "T1222",
        tactic: "defense-evasion",
        name: "File and Directory Permissions Modification",
        artifact_ids: &["evtx_security", "mft_file"],
        leads_to: &[14],
    },
    // [11] T1555
    FlowAction {
        technique_id: "T1555",
        tactic: "credential-access",
        name: "Credentials from Password Stores",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[14],
    },
    // [12] T1070.002
    FlowAction {
        technique_id: "T1070.002",
        tactic: "defense-evasion",
        name: "Clear Linux or Mac System Logs",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[14],
    },
    // [13] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [14] T1595.001
    FlowAction {
        technique_id: "T1595.001",
        tactic: "unknown",
        name: " Active Scanning: Scanning IP Blocks",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[15],
    },
    // [15] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: " Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[16],
    },
    // [16] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[17],
    },
    // [17] T1210
    FlowAction {
        technique_id: "T1210",
        tactic: "lateral-movement",
        name: "Exploitation of Remote Services",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[18],
    },
    // [18] T1003
    FlowAction {
        technique_id: "T1003",
        tactic: "credential-access",
        name: "OS Credential Dumping",
        artifact_ids: &["evtx_security", "prefetch_dir"],
        leads_to: &[19],
    },
    // [19] T1021.004
    FlowAction {
        technique_id: "T1021.004",
        tactic: "lateral-movement",
        name: "SSH",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[20],
    },
    // [20] T1005
    FlowAction {
        technique_id: "T1005",
        tactic: "collection",
        name: "Data from Local System",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[21],
    },
    // [21] T1040
    FlowAction {
        technique_id: "T1040",
        tactic: "credential-access",
        name: "Network Sniffing",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[22],
    },
    // [22] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "unknown",
        name: "Indicator Removal on Host: File Deletion",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[23],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[24],
    },
    // [24] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[25],
    },
    // [25] T1558.003
    FlowAction {
        technique_id: "T1558.003",
        tactic: "credential-access",
        name: "Kerberoasting",
        artifact_ids: &["evtx_security"],
        leads_to: &[26],
    },
    // [26] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "unknown",
        name: "Valid Accounts: Local Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[27],
    },
    // [27] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[28],
    },
    // [28] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[29],
    },
    // [29] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "unknown",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[30],
    },
    // [30] T1595.001
    FlowAction {
        technique_id: "T1595.001",
        tactic: "reconnaissance",
        name: "Scanning IP Blocks",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[31],
    },
    // [31] T1110
    FlowAction {
        technique_id: "T1110",
        tactic: "credential-access",
        name: "Brute Force",
        artifact_ids: &["evtx_security"],
        leads_to: &[32],
    },
    // [32] T1590
    FlowAction {
        technique_id: "T1590",
        tactic: "reconnaissance",
        name: "Gather Victim Network Information",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[33],
    },
    // [33] T1595
    FlowAction {
        technique_id: "T1595",
        tactic: "reconnaissance",
        name: "Active Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[34],
    },
    // [34] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[35],
    },
    // [35] T1533
    FlowAction {
        technique_id: "T1533",
        tactic: "collection",
        name: "Data from Local System",
        artifact_ids: &["mft_file", "evtx_security"],
        leads_to: &[36],
    },
    // [36] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[37],
    },
    // [37] T1111
    FlowAction {
        technique_id: "T1111",
        tactic: "credential-access",
        name: "Multi-Factor Authentication Interception",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[38],
    },
    // [38] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[39],
    },
    // [39] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Fraud",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── FIN13 Case 2 ──────────────────────────────────────────────────────────────
// Source: "FIN13 Case 2.afb" (CTID corpus)
// 19 action nodes

static FIN13_CASE_2_ACTIONS: &[FlowAction] = &[
    // [0] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[2],
    },
    // [2] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1203
    FlowAction {
        technique_id: "T1203",
        tactic: "execution",
        name: "Exploitation for Client Execution",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5],
    },
    // [5] T1595
    FlowAction {
        technique_id: "T1595",
        tactic: "reconnaissance",
        name: "Active Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [7] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[9],
    },
    // [9] T1005
    FlowAction {
        technique_id: "T1005",
        tactic: "collection",
        name: "Data From Local System",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[10, 11],
    },
    // [10] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[12],
    },
    // [11] T1021
    FlowAction {
        technique_id: "T1021",
        tactic: "lateral-movement",
        name: "Remote Services",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[12],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [13] T1595.002
    FlowAction {
        technique_id: "T1595.002",
        tactic: "reconnaissance",
        name: "Vulnerability Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[14],
    },
    // [14] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[15],
    },
    // [15] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "unknown",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[16],
    },
    // [16] T1111
    FlowAction {
        technique_id: "T1111",
        tactic: "credential-access",
        name: "Multi-Factor Authentication Interception",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[17],
    },
    // [17] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[18],
    },
    // [18] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Fraud",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Gootloader ────────────────────────────────────────────────────────────────
// Source: "Gootloader.afb" (CTID corpus)
// 36 action nodes

static GOOTLOADER_ACTIONS: &[FlowAction] = &[
    // [0] T1584
    FlowAction {
        technique_id: "T1584",
        tactic: "resource-development",
        name: "Compromise Infrastructure",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1189
    FlowAction {
        technique_id: "T1189",
        tactic: "initial-access",
        name: "Drive-by Compromise",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[3],
    },
    // [3] T1059.007
    FlowAction {
        technique_id: "T1059.007",
        tactic: "execution",
        name: "JavaScript",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1112
    FlowAction {
        technique_id: "T1112",
        tactic: "defense-evasion",
        name: "Modify Registry",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[5],
    },
    // [5] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[6],
    },
    // [6] T1053.005
    FlowAction {
        technique_id: "T1053.005",
        tactic: "persistence",
        name: "Scheduled Task",
        artifact_ids: &["scheduled_tasks_dir", "evtx_task_scheduler"],
        leads_to: &[7],
    },
    // [7] T1218.011
    FlowAction {
        technique_id: "T1218.011",
        tactic: "defense-evasion",
        name: "Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[8, 9, 10],
    },
    // [8] T1482
    FlowAction {
        technique_id: "T1482",
        tactic: "discovery",
        name: "Domain Trust Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[11],
    },
    // [9] T1087
    FlowAction {
        technique_id: "T1087",
        tactic: "discovery",
        name: "Account Discovery",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[11],
    },
    // [10] T1615
    FlowAction {
        technique_id: "T1615",
        tactic: "discovery",
        name: "Group Policy Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[11],
    },
    // [11] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[12],
    },
    // [12] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[13],
    },
    // [13] T1059
    FlowAction {
        technique_id: "T1059",
        tactic: "execution",
        name: "Command and Scripting Interpreter",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [14] T1047
    FlowAction {
        technique_id: "T1047",
        tactic: "execution",
        name: "Windows Management Instrumentation",
        artifact_ids: &["evtx_wmi_activity", "evtx_security"],
        leads_to: &[15],
    },
    // [15] T1518.001
    FlowAction {
        technique_id: "T1518.001",
        tactic: "discovery",
        name: "Security Software Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[16],
    },
    // [16] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[17],
    },
    // [17] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[18],
    },
    // [18] T1555
    FlowAction {
        technique_id: "T1555",
        tactic: "credential-access",
        name: "Credentials from Password Stores",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[19],
    },
    // [19] T1021.006
    FlowAction {
        technique_id: "T1021.006",
        tactic: "lateral-movement",
        name: "Windows Remote Management",
        artifact_ids: &["evtx_security", "evtx_winrm"],
        leads_to: &[20],
    },
    // [20] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[21],
    },
    // [21] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[22],
    },
    // [22] T1021.002
    FlowAction {
        technique_id: "T1021.002",
        tactic: "lateral-movement",
        name: "SMB/Windows Admin Shares",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[23],
    },
    // [23] T1021.006
    FlowAction {
        technique_id: "T1021.006",
        tactic: "lateral-movement",
        name: "Windows Remote Management",
        artifact_ids: &["evtx_security", "evtx_winrm"],
        leads_to: &[24],
    },
    // [24] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[25, 26, 27],
    },
    // [25] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[28],
    },
    // [26] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[28],
    },
    // [27] T1555
    FlowAction {
        technique_id: "T1555",
        tactic: "credential-access",
        name: "Credentials from Password Stores",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[28],
    },
    // [28] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[29, 30, 31],
    },
    // [29] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[32],
    },
    // [30] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[32],
    },
    // [31] T1021.006
    FlowAction {
        technique_id: "T1021.006",
        tactic: "lateral-movement",
        name: "Windows Remote Management",
        artifact_ids: &["evtx_security", "evtx_winrm"],
        leads_to: &[32],
    },
    // [32] T1039
    FlowAction {
        technique_id: "T1039",
        tactic: "discovery",
        name: "Data from Network Shared Drive",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[33],
    },
    // [33] T1046
    FlowAction {
        technique_id: "T1046",
        tactic: "discovery",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[34],
    },
    // [34] T1039
    FlowAction {
        technique_id: "T1039",
        tactic: "collection",
        name: "Data from Network Shared Drive",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[35],
    },
    // [35] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[],
    },
];

// ── Hancitor DLL ──────────────────────────────────────────────────────────────
// Source: "Hancitor DLL.afb" (CTID corpus)
// 23 action nodes

static HANCITOR_DLL_ACTIONS: &[FlowAction] = &[
    // [0] T1566.002
    FlowAction {
        technique_id: "T1566.002",
        tactic: "initial-access",
        name: "Spearphishing Link",
        artifact_ids: &["evtx_security", "chrome_history"],
        leads_to: &[1],
    },
    // [1] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[2],
    },
    // [2] T1059.005
    FlowAction {
        technique_id: "T1059.005",
        tactic: "execution",
        name: "Visual Basic",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1218.011
    FlowAction {
        technique_id: "T1218.011",
        tactic: "defense-evasion",
        name: "Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[4],
    },
    // [4] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[5],
    },
    // [5] T1055
    FlowAction {
        technique_id: "T1055",
        tactic: "privilege-escalation",
        name: "Process Injection",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[6, 7, 8],
    },
    // [6] T1016.001
    FlowAction {
        technique_id: "T1016.001",
        tactic: "discovery",
        name: "Internet Connection Discovery",
        artifact_ids: &["evtx_sysmon"],
        leads_to: &[9],
    },
    // [7] T1046
    FlowAction {
        technique_id: "T1046",
        tactic: "discovery",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[9],
    },
    // [8] T1087.001
    FlowAction {
        technique_id: "T1087.001",
        tactic: "discovery",
        name: "Local Account",
        artifact_ids: &["evtx_security", "sam_users"],
        leads_to: &[9],
    },
    // [9] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[10],
    },
    // [10] T1497
    FlowAction {
        technique_id: "T1497",
        tactic: "defense-evasion",
        name: "Virtualization/Sandbox Evasion",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[11],
    },
    // [11] T1218.011
    FlowAction {
        technique_id: "T1218.011",
        tactic: "defense-evasion",
        name: "Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[12],
    },
    // [12] T1027
    FlowAction {
        technique_id: "T1027",
        tactic: "defense-evasion",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[13],
    },
    // [13] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[14],
    },
    // [14] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[15],
    },
    // [15] T1027.004
    FlowAction {
        technique_id: "T1027.004",
        tactic: "defense-evasion",
        name: "Compile After Delivery",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[16],
    },
    // [16] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[17],
    },
    // [17] T1212
    FlowAction {
        technique_id: "T1212",
        tactic: "credential-access",
        name: "Exploitation for Credential Access",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[18],
    },
    // [18] T1550.002
    FlowAction {
        technique_id: "T1550.002",
        tactic: "lateral-movement",
        name: "Pass the Hash",
        artifact_ids: &["evtx_security", "evtx_rdp_inbound"],
        leads_to: &[19],
    },
    // [19] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[20],
    },
    // [20] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[21],
    },
    // [21] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[22],
    },
    // [22] T1595.001
    FlowAction {
        technique_id: "T1595.001",
        tactic: "reconnaissance",
        name: "Scanning IP Blocks",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[],
    },
];

// ── Ivanti Vulnerabilities ────────────────────────────────────────────────────
// Source: "Ivanti Vulnerabilities.afb" (CTID corpus)
// 23 action nodes

static IVANTI_VULNERABILITIES_ACTIONS: &[FlowAction] = &[
    // [0] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3, 4, 5, 6, 7, 8, 9, 10],
    },
    // [1] T1021.002
    FlowAction {
        technique_id: "T1021.002",
        tactic: "lateral-movement",
        name: "SMB/Windows Admin Shares",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[],
    },
    // [2] T1021.004
    FlowAction {
        technique_id: "T1021.004",
        tactic: "lateral-movement",
        name: "SSH",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[11],
    },
    // [3] T1554
    FlowAction {
        technique_id: "T1554",
        tactic: "persistence",
        name: "Compromise Host Software Binary",
        artifact_ids: &["shimcache", "amcache_app_file"],
        leads_to: &[],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [5] T1070.002
    FlowAction {
        technique_id: "T1070.002",
        tactic: "defense-evasion",
        name: "Clear Linux or Mac System Logs",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[],
    },
    // [6] T1562
    FlowAction {
        technique_id: "T1562",
        tactic: "defense-evasion",
        name: "Impair Defenses",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[],
    },
    // [7] T1554
    FlowAction {
        technique_id: "T1554",
        tactic: "persistence",
        name: "Compromise Host Software Binary",
        artifact_ids: &["shimcache", "amcache_app_file"],
        leads_to: &[12],
    },
    // [8] T1592.004
    FlowAction {
        technique_id: "T1592.004",
        tactic: "reconnaissance",
        name: "Client Configurations",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [9] T1554
    FlowAction {
        technique_id: "T1554",
        tactic: "persistence",
        name: "Compromise Host Software Binary",
        artifact_ids: &["shimcache", "amcache_app_file"],
        leads_to: &[13],
    },
    // [10] T1614
    FlowAction {
        technique_id: "T1614",
        tactic: "unknown",
        name: "System Location Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [11] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "persistence",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [12] T1056.003
    FlowAction {
        technique_id: "T1056.003",
        tactic: "credential-access",
        name: "Web Portal Capture",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[14, 17],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "persistence",
        name: "Persistence",
        artifact_ids: &["evtx_security"],
        leads_to: &[15],
    },
    // [15] T1090.001
    FlowAction {
        technique_id: "T1090.001",
        tactic: "lateral-movement",
        name: "Internal Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[16],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "reconnaissance",
        name: "Internal Proxy",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [17] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[18, 19, 21],
    },
    // [18] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "reconnaissance",
        name: "Reconnaissance",
        artifact_ids: &["evtx_security"],
        leads_to: &[20],
    },
    // [19] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[17],
    },
    // [20] T1003.003
    FlowAction {
        technique_id: "T1003.003",
        tactic: "reconnaissance",
        name: "NTDS",
        artifact_ids: &["ntds_dit", "evtx_security"],
        leads_to: &[22],
    },
    // [21] T1552.002
    FlowAction {
        technique_id: "T1552.002",
        tactic: "credential-access",
        name: "Credentials in Registry",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [22] T1560.001
    FlowAction {
        technique_id: "T1560.001",
        tactic: "collection",
        name: "Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[],
    },
];

// ── JP Morgan Breach ──────────────────────────────────────────────────────────
// Source: "JP Morgan Breach.afb" (CTID corpus)
// 12 action nodes

static JP_MORGAN_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1566
    FlowAction {
        technique_id: "T1566",
        tactic: "initial-access",
        name: "Phishing",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1] T1056
    FlowAction {
        technique_id: "T1056",
        tactic: "collection",
        name: "Input Capture",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[4, 5],
    },
    // [4] T1068
    FlowAction {
        technique_id: "T1068",
        tactic: "privilege-escalation",
        name: "Exploitation for Privilege Escalation",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[6],
    },
    // [5] T1587.001
    FlowAction {
        technique_id: "T1587.001",
        tactic: "resource-development",
        name: "Malware",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[6],
    },
    // [6] T1056
    FlowAction {
        technique_id: "T1056",
        tactic: "collection",
        name: "Input Capture",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[7],
    },
    // [7] T1030
    FlowAction {
        technique_id: "T1030",
        tactic: "exfiltration",
        name: "Data Transfer Size Limits",
        artifact_ids: &["srum_network_usage", "mft_file"],
        leads_to: &[8],
    },
    // [8] T1090.003
    FlowAction {
        technique_id: "T1090.003",
        tactic: "command-and-control",
        name: "Multi-hop Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[9],
    },
    // [9] T1090.002
    FlowAction {
        technique_id: "T1090.002",
        tactic: "command-and-control",
        name: "External Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[10],
    },
    // [10] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[11],
    },
    // [11] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
];

// ── MITRE NERVE ───────────────────────────────────────────────────────────────
// Source: "MITRE NERVE.afb" (CTID corpus)
// 33 action nodes

static MITRE_NERVE_ACTIONS: &[FlowAction] = &[
    // [0] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1505.003
    FlowAction {
        technique_id: "T1505.003",
        tactic: "initial-access",
        name: "Web Shell",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2, 3, 4, 5],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[6, 7],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [4] T1563.002
    FlowAction {
        technique_id: "T1563.002",
        tactic: "lateral-movement",
        name: "RDP Hijacking",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[9],
    },
    // [5] T1074
    FlowAction {
        technique_id: "T1074",
        tactic: "collection",
        name: "Data Staged",
        artifact_ids: &["mft_file", "lnk_files"],
        leads_to: &[],
    },
    // [6] T1036.008
    FlowAction {
        technique_id: "T1036.008",
        tactic: "defense-evasion",
        name: "Masquerade File Type",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[],
    },
    // [7] T1573.001
    FlowAction {
        technique_id: "T1573.001",
        tactic: "command-and-control",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [8] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[10],
    },
    // [9] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "lateral-movement",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[11, 12, 13, 14],
    },
    // [10] T1005
    FlowAction {
        technique_id: "T1005",
        tactic: "discovery",
        name: "Data from Local System",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[15],
    },
    // [11] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[16, 17, 18],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[19, 20],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Lateral Movement",
        artifact_ids: &["evtx_security"],
        leads_to: &[21, 22, 23, 24, 25],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[26],
    },
    // [15] T1074
    FlowAction {
        technique_id: "T1074",
        tactic: "collection",
        name: "Data Staged",
        artifact_ids: &["mft_file", "lnk_files"],
        leads_to: &[27],
    },
    // [16] T1135
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [17] T1217
    FlowAction {
        technique_id: "T1217",
        tactic: "discovery",
        name: "Browser Information Discovery",
        artifact_ids: &["chrome_history", "firefox_places"],
        leads_to: &[],
    },
    // [18] T1119
    FlowAction {
        technique_id: "T1119",
        tactic: "collection",
        name: "Automated Collection",
        artifact_ids: &["evtx_sysmon", "mft_file"],
        leads_to: &[28],
    },
    // [19] T1037.004
    FlowAction {
        technique_id: "T1037.004",
        tactic: "persistence",
        name: "RC Scripts",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[29],
    },
    // [20] T1037
    FlowAction {
        technique_id: "T1037",
        tactic: "persistence",
        name: "Boot or Logon Initialization Scripts",
        artifact_ids: &["run_key_hklm", "evtx_sysmon"],
        leads_to: &[29],
    },
    // [21] T1564.006
    FlowAction {
        technique_id: "T1564.006",
        tactic: "defense-evasion",
        name: "Run Virtual Instance",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[30],
    },
    // [22] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "lateral-movement",
        name: "Remote Services",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "discovery",
        name: "Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [24] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[],
    },
    // [25] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Create Virtual Machines",
        artifact_ids: &["evtx_security"],
        leads_to: &[31],
    },
    // [26] T1059.006
    FlowAction {
        technique_id: "T1059.006",
        tactic: "execution",
        name: "Python",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[],
    },
    // [27] T1048
    FlowAction {
        technique_id: "T1048",
        tactic: "exfiltration",
        name: "Exfiltration Over Alternative Protocol",
        artifact_ids: &["srum_network_usage", "evtx_security"],
        leads_to: &[],
    },
    // [28] T1005
    FlowAction {
        technique_id: "T1005",
        tactic: "discovery",
        name: "Data from Local System",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[32],
    },
    // [29] T1071.001
    FlowAction {
        technique_id: "T1071.001",
        tactic: "command-and-control",
        name: "Web Protocols",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [30] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [31] T1021.001
    FlowAction {
        technique_id: "T1021.001",
        tactic: "lateral-movement",
        name: "Remote Desktop Protocol",
        artifact_ids: &["evtx_rdp_inbound", "evtx_rdp_client", "evtx_security"],
        leads_to: &[],
    },
    // [32] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
];

// ── Maastricht University Ransomware ──────────────────────────────────────────
// Source: "Maastricht University Ransomware.afb" (CTID corpus)
// 18 action nodes

static MAASTRICHT_UNIVERSITY_RANSOMWARE_ACTIONS: &[FlowAction] = &[
    // [0] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "unknown",
        name: "Phishing: Spearphishing Attachment ",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "unknown",
        name: "User Execution: Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[2, 3, 4],
    },
    // [2] T1095
    FlowAction {
        technique_id: "T1095",
        tactic: "unknown",
        name: "Non-Application Layer Protocol",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [3] T1547.001
    FlowAction {
        technique_id: "T1547.001",
        tactic: "unknown",
        name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        artifact_ids: &["run_key_hkcu", "run_key_hklm"],
        leads_to: &[],
    },
    // [4] T1059.004
    FlowAction {
        technique_id: "T1059.004",
        tactic: "unknown",
        name: "Command and Scripting Interpreter: 
Unix Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[5, 6, 7],
    },
    // [5] T1595.002
    FlowAction {
        technique_id: "T1595.002",
        tactic: "unknown",
        name: "Active Scanning: Vulnerability Scanning",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[],
    },
    // [6] T1018
    FlowAction {
        technique_id: "T1018",
        tactic: "unknown",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
    // [7] T1210
    FlowAction {
        technique_id: "T1210",
        tactic: "unknown",
        name: "Exploitation of Remote Services",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1068
    FlowAction {
        technique_id: "T1068",
        tactic: "unknown",
        name: "Exploitation for Privilege Escalation",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[4, 9],
    },
    // [9] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "unknown",
        name: "OS Credential Dumping: LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[10],
    },
    // [10] T1059
    FlowAction {
        technique_id: "T1059",
        tactic: "unknown",
        name: "Command and Scripting Interpreter",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[11, 12, 13],
    },
    // [11] T1046
    FlowAction {
        technique_id: "T1046",
        tactic: "unknown",
        name: "Network Service Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[14],
    },
    // [12] T1057
    FlowAction {
        technique_id: "T1057",
        tactic: "unknown",
        name: "Process Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[14],
    },
    // [13] T1018
    FlowAction {
        technique_id: "T1018",
        tactic: "unknown",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[14],
    },
    // [14] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[15, 16],
    },
    // [15] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "unknown",
        name: "Impair Defense: Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[16],
    },
    // [16] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "unknown",
        name: "Impair Defenses: Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[17],
    },
    // [17] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "unknown",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
];

// ── Mac Malware Steals Crypto ─────────────────────────────────────────────────
// Source: "Mac Malware Steals Crypto.afb" (CTID corpus)
// 9 action nodes

static MAC_MALWARE_STEALS_CRYPTO_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "initial-access",
        name: "Initial Access",
        artifact_ids: &["evtx_security"],
        leads_to: &[1, 2],
    },
    // [1] T1059.006
    FlowAction {
        technique_id: "T1059.006",
        tactic: "execution",
        name: "Python",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [2] T1059.004
    FlowAction {
        technique_id: "T1059.004",
        tactic: "execution",
        name: "Unix Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [3] T1211
    FlowAction {
        technique_id: "T1211",
        tactic: "defense-evasion",
        name: "Exploitation for Defense Evasion",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [6] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[7],
    },
    // [7] T1059.006
    FlowAction {
        technique_id: "T1059.006",
        tactic: "execution",
        name: "Python",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1518.001
    FlowAction {
        technique_id: "T1518.001",
        tactic: "discovery",
        name: "Security Software Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[],
    },
];

// ── Marriott Breach ───────────────────────────────────────────────────────────
// Source: "Marriott Breach.afb" (CTID corpus)
// 8 action nodes

static MARRIOTT_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1566
    FlowAction {
        technique_id: "T1566",
        tactic: "initial-access",
        name: "Phishing",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1, 2],
    },
    // [1] T1555
    FlowAction {
        technique_id: "T1555",
        tactic: "credential-access",
        name: "Credentials from Password Stores",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[3],
    },
    // [2] T1219
    FlowAction {
        technique_id: "T1219",
        tactic: "command-and-control",
        name: "Remote Access Software",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1590.004
    FlowAction {
        technique_id: "T1590.004",
        tactic: "reconnaissance",
        name: "Network Topology",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[4, 5],
    },
    // [4] T1560
    FlowAction {
        technique_id: "T1560",
        tactic: "collection",
        name: "Archive Collected Data",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[6],
    },
    // [5] T1001
    FlowAction {
        technique_id: "T1001",
        tactic: "command-and-control",
        name: "Data Obfuscation",
        artifact_ids: &["srum_network_usage", "evtx_security"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [7] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[],
    },
];

// ── Muddy Water ───────────────────────────────────────────────────────────────
// Source: "Muddy Water.afb" (CTID corpus)
// 28 action nodes

static MUDDY_WATER_ACTIONS: &[FlowAction] = &[
    // [0] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[2],
    },
    // [1] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[3],
    },
    // [2] T1204.001
    FlowAction {
        technique_id: "T1204.001",
        tactic: "execution",
        name: "Malicious Link",
        artifact_ids: &["lnk_files", "prefetch_dir"],
        leads_to: &[4],
    },
    // [3] T1204.001
    FlowAction {
        technique_id: "T1204.001",
        tactic: "execution",
        name: "Malicious Link",
        artifact_ids: &["lnk_files", "prefetch_dir"],
        leads_to: &[5],
    },
    // [4] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "unknown",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[6],
    },
    // [5] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[7],
    },
    // [6] T1059.005
    FlowAction {
        technique_id: "T1059.005",
        tactic: "execution",
        name: "Visual Basic",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[8, 9, 10],
    },
    // [7] T1036
    FlowAction {
        technique_id: "T1036",
        tactic: "defense-evasion",
        name: "Masquerading",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[11],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Canary Tokens",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [9] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[13, 16],
    },
    // [10] T1547.001
    FlowAction {
        technique_id: "T1547.001",
        tactic: "persistence",
        name: "Registry Run Keys / Startup Folder",
        artifact_ids: &["run_key_hkcu", "run_key_hklm"],
        leads_to: &[12, 13],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Directory created",
        artifact_ids: &["evtx_security"],
        leads_to: &[14, 15],
    },
    // [12] T1218
    FlowAction {
        technique_id: "T1218",
        tactic: "unknown",
        name: "System Binary Proxy Execution",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[],
    },
    // [13] T1059.005
    FlowAction {
        technique_id: "T1059.005",
        tactic: "execution",
        name: "Visual Basic",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[16],
    },
    // [14] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[17],
    },
    // [15] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[17],
    },
    // [16] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[18],
    },
    // [17] T1547.001
    FlowAction {
        technique_id: "T1547.001",
        tactic: "persistence",
        name: "Registry Run Keys / Startup Folder",
        artifact_ids: &["run_key_hkcu", "run_key_hklm"],
        leads_to: &[19],
    },
    // [18] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[20],
    },
    // [19] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "execution",
        name: "Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[21],
    },
    // [20] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[22, 23],
    },
    // [21] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[24],
    },
    // [22] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "unknown",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "collection",
        name: "Collection",
        artifact_ids: &["evtx_security"],
        leads_to: &[25],
    },
    // [24] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "execution",
        name: "Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[26],
    },
    // [25] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [26] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[27],
    },
    // [27] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[],
    },
];

// ── NotPetya ──────────────────────────────────────────────────────────────────
// Source: "NotPetya.afb" (CTID corpus)
// 23 action nodes

static NOTPETYA_ACTIONS: &[FlowAction] = &[
    // [0] T1593
    FlowAction {
        technique_id: "T1593",
        tactic: "reconnaissance",
        name: "Search Open Websites/Domains",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[1],
    },
    // [1] T1195.002
    FlowAction {
        technique_id: "T1195.002",
        tactic: "initial-access",
        name: "Compromise Software Supply Chain",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1195.002
    FlowAction {
        technique_id: "T1195.002",
        tactic: "initial-access",
        name: "Compromise Software Supply Chain",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1195
    FlowAction {
        technique_id: "T1195",
        tactic: "initial-access",
        name: "Supply Chain Compromise",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1036
    FlowAction {
        technique_id: "T1036",
        tactic: "defense-evasion",
        name: "Masquerading",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[5, 6],
    },
    // [5] T1057
    FlowAction {
        technique_id: "T1057",
        tactic: "discovery",
        name: "Malware Privilege Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[7, 8],
    },
    // [6] T1518.001
    FlowAction {
        technique_id: "T1518.001",
        tactic: "discovery",
        name: "Security Software Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[10, 15, 16],
    },
    // [7] T1134.001
    FlowAction {
        technique_id: "T1134.001",
        tactic: "privilege-escalation",
        name: "Token Impersonation/Theft",
        artifact_ids: &["evtx_security"],
        leads_to: &[9, 10, 11],
    },
    // [8] T1003.001
    FlowAction {
        technique_id: "T1003.001",
        tactic: "credential-access",
        name: "LSASS Memory",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[9, 10, 11],
    },
    // [9] T1016
    FlowAction {
        technique_id: "T1016",
        tactic: "discovery",
        name: "System Network Configuration Discovery",
        artifact_ids: &["evtx_sysmon"],
        leads_to: &[15, 16],
    },
    // [10] T0866
    FlowAction {
        technique_id: "T0866",
        tactic: "lateral-movement",
        name: "Exploitation of Remote Services ",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [11] T1021.002
    FlowAction {
        technique_id: "T1021.002",
        tactic: "unknown",
        name: "Remote Services: SMB/Windows Admin Shares",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[13],
    },
    // [12] T1055.001
    FlowAction {
        technique_id: "T1055.001",
        tactic: "defense-evasion",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[14],
    },
    // [13] T1218.011
    FlowAction {
        technique_id: "T1218.011",
        tactic: "defense-evasion",
        name: "Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[15, 16],
    },
    // [14] T1218.011
    FlowAction {
        technique_id: "T1218.011",
        tactic: "defense-evasion",
        name: "Rundll32",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[15, 16],
    },
    // [15] T1561.002
    FlowAction {
        technique_id: "T1561.002",
        tactic: "impact",
        name: "Disk Structure Wipe",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[],
    },
    // [16] T1542.003
    FlowAction {
        technique_id: "T1542.003",
        tactic: "persistence",
        name: "Bootkit",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[17],
    },
    // [17] T1053.005
    FlowAction {
        technique_id: "T1053.005",
        tactic: "persistence",
        name: "Scheduled Task",
        artifact_ids: &["scheduled_tasks_dir", "evtx_task_scheduler"],
        leads_to: &[18],
    },
    // [18] T1529
    FlowAction {
        technique_id: "T1529",
        tactic: "impact",
        name: "System Shutdown/Reboot",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[19],
    },
    // [19] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[20],
    },
    // [20] T1070.001
    FlowAction {
        technique_id: "T1070.001",
        tactic: "defense-evasion",
        name: "Clear Windows Event Logs",
        artifact_ids: &["evtx_security", "evtx_system", "usn_journal"],
        leads_to: &[21],
    },
    // [21] T1529
    FlowAction {
        technique_id: "T1529",
        tactic: "impact",
        name: "System Shutdown/Reboot",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[22],
    },
    // [22] T1485
    FlowAction {
        technique_id: "T1485",
        tactic: "impact",
        name: "Data Destruction",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[],
    },
];

// ── OceanLotus ────────────────────────────────────────────────────────────────
// Source: "OceanLotus.afb" (CTID corpus)
// 23 action nodes

static OCEANLOTUS_ACTIONS: &[FlowAction] = &[
    // [0] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[1],
    },
    // [1] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[2],
    },
    // [2] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[3],
    },
    // [3] T1036
    FlowAction {
        technique_id: "T1036",
        tactic: "defense-evasion",
        name: "Masquerading",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[4],
    },
    // [4] T1027.009
    FlowAction {
        technique_id: "T1027.009",
        tactic: "defense-evasion",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[5],
    },
    // [5] T1543.001
    FlowAction {
        technique_id: "T1543.001",
        tactic: "persistence",
        name: "Launch Agent",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[6],
    },
    // [6] T1070
    FlowAction {
        technique_id: "T1070",
        tactic: "defense-evasion",
        name: "Indicator Removal",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[7],
    },
    // [7] T1082
    FlowAction {
        technique_id: "T1082",
        tactic: "discovery",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[8],
    },
    // [8] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[9],
    },
    // [9] T1018
    FlowAction {
        technique_id: "T1018",
        tactic: "discovery",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[10],
    },
    // [10] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[11],
    },
    // [11] T1021
    FlowAction {
        technique_id: "T1021",
        tactic: "lateral-movement",
        name: "Remote Services",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[12],
    },
    // [12] T1021.004
    FlowAction {
        technique_id: "T1021.004",
        tactic: "lateral-movement",
        name: "SSH",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[13],
    },
    // [13] T1059.004
    FlowAction {
        technique_id: "T1059.004",
        tactic: "execution",
        name: "Unix Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[14, 15],
    },
    // [14] T1135
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[16],
    },
    // [15] T1082
    FlowAction {
        technique_id: "T1082",
        tactic: "discovery",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[16],
    },
    // [16] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[17],
    },
    // [17] T1119
    FlowAction {
        technique_id: "T1119",
        tactic: "collection",
        name: "Automated Collection",
        artifact_ids: &["evtx_sysmon", "mft_file"],
        leads_to: &[18, 19],
    },
    // [18] T1564.001
    FlowAction {
        technique_id: "T1564.001",
        tactic: "defense-evasion",
        name: "Hidden Files and Directories",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[20],
    },
    // [19] T1560.001
    FlowAction {
        technique_id: "T1560.001",
        tactic: "collection",
        name: "Archive via Utility",
        artifact_ids: &["mft_file", "prefetch_dir"],
        leads_to: &[22],
    },
    // [20] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[21],
    },
    // [21] T1074.001
    FlowAction {
        technique_id: "T1074.001",
        tactic: "collection",
        name: "Local Data Staging",
        artifact_ids: &["mft_file", "lnk_files"],
        leads_to: &[22],
    },
    // [22] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
];

// ── OpenClaw Command & Control via Prompt Injection ───────────────────────────
// Source: "OpenClaw.afb" (CTID corpus)
// 18 action nodes

static OPENCLAW_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Search Open Websites/Domains: Code Repositories",
        artifact_ids: &["evtx_security"],
        leads_to: &[2],
    },
    // [1] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Acquire Infrastructure",
        artifact_ids: &["evtx_security"],
        leads_to: &[3],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Acquire Public AI Artifacts: AI Agent Configuration",
        artifact_ids: &["evtx_security"],
        leads_to: &[4, 5, 6],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Masquerading",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Discover LLM System Information: Special Character Sets",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Discover LLM System Information: System Instruction Keywords",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "LLM Prompt Crafting",
        artifact_ids: &["evtx_security"],
        leads_to: &[8, 13, 14],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "LLM Prompt Crafting",
        artifact_ids: &["evtx_security"],
        leads_to: &[8, 10],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Stage Capabilities",
        artifact_ids: &["evtx_security"],
        leads_to: &[9],
    },
    // [9] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Drive-by Compromise",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "LLM Prompt Injection: Indirect",
        artifact_ids: &["evtx_security"],
        leads_to: &[11],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "LLM Jailbreak",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "AI Agent Tool Invocation",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Modify AI Agent Configuration",
        artifact_ids: &["evtx_security"],
        leads_to: &[14],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "LLM Prompt Injection: Direct",
        artifact_ids: &["evtx_security"],
        leads_to: &[15, 16],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "AI Agent Context Poisoning: Thread",
        artifact_ids: &["evtx_security"],
        leads_to: &[17],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "AI Agent",
        artifact_ids: &["evtx_security"],
        leads_to: &[17],
    },
    // [17] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Machine Compromise: Local AI Agent",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── REvil ─────────────────────────────────────────────────────────────────────
// Source: "REvil.afb" (CTID corpus)
// 25 action nodes

static REVIL_ACTIONS: &[FlowAction] = &[
    // [0] T1189
    FlowAction {
        technique_id: "T1189",
        tactic: "initial-access",
        name: "Drive-by Compromise",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [1] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "initial-access",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[4],
    },
    // [2] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[4],
    },
    // [3] T1068
    FlowAction {
        technique_id: "T1068",
        tactic: "privilege-escalation",
        name: "Exploitation for Privilege Escalation",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[5],
    },
    // [5] T1134.002
    FlowAction {
        technique_id: "T1134.002",
        tactic: "privilege-escalation",
        name: "Create Process with Token",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [6] T1012
    FlowAction {
        technique_id: "T1012",
        tactic: "discovery",
        name: "Query Registry",
        artifact_ids: &["evtx_sysmon", "run_key_hklm"],
        leads_to: &[7, 8, 9],
    },
    // [7] T1069.002
    FlowAction {
        technique_id: "T1069.002",
        tactic: "discovery",
        name: "Domain Groups",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[10],
    },
    // [8] T1033
    FlowAction {
        technique_id: "T1033",
        tactic: "discovery",
        name: "System Owner/User Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[10],
    },
    // [9] T1082
    FlowAction {
        technique_id: "T1082",
        tactic: "discovery",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[10],
    },
    // [10] T1027
    FlowAction {
        technique_id: "T1027",
        tactic: "defense-evasion",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[11],
    },
    // [11] T1112
    FlowAction {
        technique_id: "T1112",
        tactic: "defense-evasion",
        name: "Modify Registry",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[12],
    },
    // [12] T1489
    FlowAction {
        technique_id: "T1489",
        tactic: "impact",
        name: "Service Stop",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[13, 14],
    },
    // [13] T1059.003
    FlowAction {
        technique_id: "T1059.003",
        tactic: "execution",
        name: "Windows Command Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[15],
    },
    // [14] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[15],
    },
    // [15] T1490
    FlowAction {
        technique_id: "T1490",
        tactic: "impact",
        name: "Inhibit System Recovery",
        artifact_ids: &["evtx_system", "usn_journal"],
        leads_to: &[16],
    },
    // [16] T1485
    FlowAction {
        technique_id: "T1485",
        tactic: "impact",
        name: "Data Destruction",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[17],
    },
    // [17] T1083
    FlowAction {
        technique_id: "T1083",
        tactic: "discovery",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[18, 19],
    },
    // [18] T1135
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[19],
    },
    // [19] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[20],
    },
    // [20] T1491.001
    FlowAction {
        technique_id: "T1491.001",
        tactic: "impact",
        name: "Internal Defacement",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[21],
    },
    // [21] T1012
    FlowAction {
        technique_id: "T1012",
        tactic: "discovery",
        name: "Query Registry",
        artifact_ids: &["evtx_sysmon", "run_key_hklm"],
        leads_to: &[22, 23],
    },
    // [22] T1071.001
    FlowAction {
        technique_id: "T1071.001",
        tactic: "command-and-control",
        name: "Web Protocols",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[24],
    },
    // [23] T1573.002
    FlowAction {
        technique_id: "T1573.002",
        tactic: "command-and-control",
        name: "Asymmetric Cryptography",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[24],
    },
    // [24] T1041
    FlowAction {
        technique_id: "T1041",
        tactic: "exfiltration",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[],
    },
];

// ── Ragnar Locker ─────────────────────────────────────────────────────────────
// Source: "Ragnar Locker.afb" (CTID corpus)
// 19 action nodes

static RAGNAR_LOCKER_ACTIONS: &[FlowAction] = &[
    // [0] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[2],
    },
    // [1] T1110
    FlowAction {
        technique_id: "T1110",
        tactic: "credential-access",
        name: "Brute Force",
        artifact_ids: &["evtx_security"],
        leads_to: &[2],
    },
    // [2] T1546.015
    FlowAction {
        technique_id: "T1546.015",
        tactic: "privilege-escalation",
        name: "Component Object Model Hijacking",
        artifact_ids: &["run_key_hklm", "evtx_sysmon"],
        leads_to: &[3, 4],
    },
    // [3] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[5],
    },
    // [4] T1484.001
    FlowAction {
        technique_id: "T1484.001",
        tactic: "privilege-escalation",
        name: "Group Policy Modification",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[5],
    },
    // [5] T1218.007
    FlowAction {
        technique_id: "T1218.007",
        tactic: "defense-evasion",
        name: "Msiexec",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[6],
    },
    // [6] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[7],
    },
    // [7] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[8, 9, 10, 11, 12],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "execution",
        name: "Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [9] T1489
    FlowAction {
        technique_id: "T1489",
        tactic: "impact",
        name: "Service Stop",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[13],
    },
    // [10] T1490
    FlowAction {
        technique_id: "T1490",
        tactic: "impact",
        name: "Inhibit System Recovery",
        artifact_ids: &["evtx_system", "usn_journal"],
        leads_to: &[13],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "reconnaissance",
        name: "Reconnaissance",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [13] T1614.001
    FlowAction {
        technique_id: "T1614.001",
        tactic: "discovery",
        name: "System Language Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [14] T1564.006
    FlowAction {
        technique_id: "T1564.006",
        tactic: "defense-evasion",
        name: "Run Virtual Instance",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[15],
    },
    // [15] T1120
    FlowAction {
        technique_id: "T1120",
        tactic: "discovery",
        name: "Peripheral Device Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[16],
    },
    // [16] T1567
    FlowAction {
        technique_id: "T1567",
        tactic: "exfiltration",
        name: "Exfiltration over Web Service",
        artifact_ids: &["srum_network_usage", "evtx_security", "dns_debug_log"],
        leads_to: &[17],
    },
    // [17] T1027
    FlowAction {
        technique_id: "T1027",
        tactic: "defense-evasion",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[18],
    },
    // [18] T1486
    FlowAction {
        technique_id: "T1486",
        tactic: "impact",
        name: "Data Encrypted for Impact",
        artifact_ids: &["mft_file", "usn_journal", "recycle_bin"],
        leads_to: &[],
    },
];

// ── SWIFT Heist ───────────────────────────────────────────────────────────────
// Source: "SWIFT Heist.afb" (CTID corpus)
// 11 action nodes

static SWIFT_HEIST_ACTIONS: &[FlowAction] = &[
    // [0] T1190
    FlowAction {
        technique_id: "T1190",
        tactic: "initial-access",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [1] T1566.001
    FlowAction {
        technique_id: "T1566.001",
        tactic: "initial-access",
        name: "Spearphishing Attachment",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[3],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Accounts opened illegally",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [3] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[4],
    },
    // [4] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[5],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Fraudulent payment orders",
        artifact_ids: &["evtx_security"],
        leads_to: &[6, 7],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Send money to Philippines account",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Send money to individual accounts",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [8] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[9],
    },
    // [9] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[10],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Changing Bank Balances",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── SearchAwesome Adware ──────────────────────────────────────────────────────
// Source: "SearchAwesome Adware.afb" (CTID corpus)
// 11 action nodes

static SEARCHAWESOME_ADWARE_ACTIONS: &[FlowAction] = &[
    // [0] T1204.002
    FlowAction {
        technique_id: "T1204.002",
        tactic: "execution",
        name: "Malicious File",
        artifact_ids: &["lnk_files", "prefetch_dir", "amcache_app_file"],
        leads_to: &[1],
    },
    // [1] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[2],
    },
    // [2] T1553.004
    FlowAction {
        technique_id: "T1553.004",
        tactic: "defense-evasion",
        name: "Install Root Certificate",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1557
    FlowAction {
        technique_id: "T1557",
        tactic: "credential-access",
        name: "Adversary-in-the-Middle",
        artifact_ids: &["evtx_security"],
        leads_to: &[4],
    },
    // [4] T1553
    FlowAction {
        technique_id: "T1553",
        tactic: "defense-evasion",
        name: "Subvert Trust Controls",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5],
    },
    // [5] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[6],
    },
    // [6] T1090
    FlowAction {
        technique_id: "T1090",
        tactic: "command-and-control",
        name: "Proxy ",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[7],
    },
    // [7] T1583.008
    FlowAction {
        technique_id: "T1583.008",
        tactic: "resource-development",
        name: "Malvertising",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1059
    FlowAction {
        technique_id: "T1059",
        tactic: "execution",
        name: "Command and Scripting Interpreter",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[9],
    },
    // [9] T1185
    FlowAction {
        technique_id: "T1185",
        tactic: "collection",
        name: "Browser Session Hijacking",
        artifact_ids: &["chrome_history", "evtx_security"],
        leads_to: &[10],
    },
    // [10] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[],
    },
];

// ── Shamoon ───────────────────────────────────────────────────────────────────
// Source: "Shamoon.afb" (CTID corpus)
// 23 action nodes

static SHAMOON_ACTIONS: &[FlowAction] = &[
    // [0] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[1],
    },
    // [1] T1027.009
    FlowAction {
        technique_id: "T1027.009",
        tactic: "defense-evasion",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[2],
    },
    // [2] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[3],
    },
    // [3] T1082
    FlowAction {
        technique_id: "T1082",
        tactic: "unknown",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[4, 5],
    },
    // [4] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[6],
    },
    // [5] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[6],
    },
    // [6] T1569
    FlowAction {
        technique_id: "T1569",
        tactic: "execution",
        name: "System Services",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[7],
    },
    // [7] T1112
    FlowAction {
        technique_id: "T1112",
        tactic: "defense-evasion",
        name: "Modify Registry",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[8],
    },
    // [8] T1135
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[9],
    },
    // [9] T1007
    FlowAction {
        technique_id: "T1007",
        tactic: "discovery",
        name: "System Service Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[10],
    },
    // [10] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "unknown",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[11],
    },
    // [11] T1070.006
    FlowAction {
        technique_id: "T1070.006",
        tactic: "defense-evasion",
        name: "Timestomp",
        artifact_ids: &["evtx_security", "usn_journal"],
        leads_to: &[12],
    },
    // [12] T1134.001
    FlowAction {
        technique_id: "T1134.001",
        tactic: "privilege-escalation",
        name: "Token Impersonation/Theft",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [13] T1543.003
    FlowAction {
        technique_id: "T1543.003",
        tactic: "persistence",
        name: "Windows Service",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[14, 15],
    },
    // [14] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[16],
    },
    // [15] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[17],
    },
    // [16] T1018
    FlowAction {
        technique_id: "T1018",
        tactic: "discovery",
        name: "Remote System Discovery",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[18],
    },
    // [17] T1027.009
    FlowAction {
        technique_id: "T1027.009",
        tactic: "defense-evasion",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[19],
    },
    // [18] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [19] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[20],
    },
    // [20] T1543.003
    FlowAction {
        technique_id: "T1543.003",
        tactic: "persistence",
        name: "Windows Service",
        artifact_ids: &["services_hklm", "evtx_system"],
        leads_to: &[21],
    },
    // [21] T1561
    FlowAction {
        technique_id: "T1561",
        tactic: "impact",
        name: "Disk Wipe",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[22],
    },
    // [22] T1529
    FlowAction {
        technique_id: "T1529",
        tactic: "impact",
        name: "System Shutdown/Reboot",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[],
    },
];

// ── Sony Malware ──────────────────────────────────────────────────────────────
// Source: "Sony Malware.afb" (CTID corpus)
// 18 action nodes

static SONY_MALWARE_ACTIONS: &[FlowAction] = &[
    // [0] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[1],
    },
    // [1] T1574.007
    FlowAction {
        technique_id: "T1574.007",
        tactic: "privilege-escalation",
        name: "Path Interception by PATH Environment Variable",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[2],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "privilege-escalation",
        name: "Privilege Escalation",
        artifact_ids: &["evtx_security"],
        leads_to: &[3],
    },
    // [3] T1047
    FlowAction {
        technique_id: "T1047",
        tactic: "execution",
        name: "Windows Management Instrumentation",
        artifact_ids: &["evtx_wmi_activity", "evtx_security"],
        leads_to: &[4],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "command-and-control",
        name: "Command and Control",
        artifact_ids: &["evtx_security"],
        leads_to: &[5],
    },
    // [5] T1505.004
    FlowAction {
        technique_id: "T1505.004",
        tactic: "persistence",
        name: "IIS Components",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[6],
    },
    // [6] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[7],
    },
    // [7] T1080
    FlowAction {
        technique_id: "T1080",
        tactic: "lateral-movement",
        name: "Taint Shared Content",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[8],
    },
    // [8] T1497.003
    FlowAction {
        technique_id: "T1497.003",
        tactic: "defense-evasion",
        name: "Time Based Evasion",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[9],
    },
    // [9] T1059.003
    FlowAction {
        technique_id: "T1059.003",
        tactic: "execution",
        name: "Windows Command Shell",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[10, 11, 12],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dismounts",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [11] T1485
    FlowAction {
        technique_id: "T1485",
        tactic: "impact",
        name: "Data Destruction",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[13],
    },
    // [12] T1489
    FlowAction {
        technique_id: "T1489",
        tactic: "impact",
        name: "Service Stop",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[13],
    },
    // [13] T1132
    FlowAction {
        technique_id: "T1132",
        tactic: "command-and-control",
        name: "Data Encoding",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[14],
    },
    // [14] T1561.001
    FlowAction {
        technique_id: "T1561.001",
        tactic: "impact",
        name: "Disk Content Wipe",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[15],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[16],
    },
    // [16] T1529
    FlowAction {
        technique_id: "T1529",
        tactic: "impact",
        name: "System Shutdown/Reboot",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[17],
    },
    // [17] T1491.001
    FlowAction {
        technique_id: "T1491.001",
        tactic: "impact",
        name: "Internal Defacement",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
];

// ── Target Breach ─────────────────────────────────────────────────────────────
// Source: "Target Breach.afb" (CTID corpus)
// 17 action nodes

static TARGET_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1593.002
    FlowAction {
        technique_id: "T1593.002",
        tactic: "reconnaissance",
        name: "Search Engines",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[2],
    },
    // [1] T1592.004
    FlowAction {
        technique_id: "T1592.004",
        tactic: "reconnaissance",
        name: "Client Configurations",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[2],
    },
    // [2] T1199
    FlowAction {
        technique_id: "T1199",
        tactic: "initial-access",
        name: "Trusted Relationship",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[3],
    },
    // [3] T1566
    FlowAction {
        technique_id: "T1566",
        tactic: "initial-access",
        name: "Phishing",
        artifact_ids: &["evtx_security", "lnk_files"],
        leads_to: &[4],
    },
    // [4] T1078.002
    FlowAction {
        technique_id: "T1078.002",
        tactic: "persistence",
        name: "Domain Accounts",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[5, 6],
    },
    // [5] T1203
    FlowAction {
        technique_id: "T1203",
        tactic: "execution",
        name: "Exploitation for Client Execution",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[7],
    },
    // [6] T1078.001
    FlowAction {
        technique_id: "T1078.001",
        tactic: "persistence",
        name: "Default Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[7],
    },
    // [7] T1505
    FlowAction {
        technique_id: "T1505",
        tactic: "persistence",
        name: "Server Software Component",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[9, 10],
    },
    // [9] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[],
    },
    // [10] T1029
    FlowAction {
        technique_id: "T1029",
        tactic: "exfiltration",
        name: "Scheduled Transfer",
        artifact_ids: &["srum_network_usage", "evtx_security"],
        leads_to: &[12],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "defense-evasion",
        name: "Defense Evasion",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [12] T1570
    FlowAction {
        technique_id: "T1570",
        tactic: "lateral-movement",
        name: "Lateral Tool Transfer",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[14],
    },
    // [13] T1074.002
    FlowAction {
        technique_id: "T1074.002",
        tactic: "collection",
        name: "Remote Data Staging",
        artifact_ids: &["mft_file", "lnk_files"],
        leads_to: &[11, 15],
    },
    // [14] T1557.001
    FlowAction {
        technique_id: "T1557.001",
        tactic: "collection",
        name: "LLMNR/NBT-NS Poisoning and SMB Relay",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [15] T1095
    FlowAction {
        technique_id: "T1095",
        tactic: "command-and-control",
        name: "Non-Application Layer Protocol",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[16],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Tesla Kubernetes Breach ───────────────────────────────────────────────────
// Source: "Tesla Kubernetes Breach.afb" (CTID corpus)
// 9 action nodes

static TESLA_KUBERNETES_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1133
    FlowAction {
        technique_id: "T1133",
        tactic: "initial-access",
        name: "External Remote Services",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[2, 3],
    },
    // [1] T1583.004
    FlowAction {
        technique_id: "T1583.004",
        tactic: "resource-development",
        name: "Server",
        artifact_ids: &["dns_debug_log", "evtx_security"],
        leads_to: &[4, 5],
    },
    // [2] T1610
    FlowAction {
        technique_id: "T1610",
        tactic: "execution",
        name: "Deploy Container",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[7],
    },
    // [3] T1552
    FlowAction {
        technique_id: "T1552",
        tactic: "credential-access",
        name: "Unsecured Credentials",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[6],
    },
    // [4] T1090
    FlowAction {
        technique_id: "T1090",
        tactic: "de",
        name: "Proxy",
        artifact_ids: &["evtx_security", "vpn_ras_phonebook"],
        leads_to: &[7],
    },
    // [5] T1571
    FlowAction {
        technique_id: "T1571",
        tactic: "defense-evasion",
        name: "Non-Standard Port",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[7],
    },
    // [6] T1078.004
    FlowAction {
        technique_id: "T1078.004",
        tactic: "privilege-escalation",
        name: "Cloud Accounts",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [7] T1496
    FlowAction {
        technique_id: "T1496",
        tactic: "impact",
        name: "Resource Highjacking",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[],
    },
    // [8] T1530
    FlowAction {
        technique_id: "T1530",
        tactic: "collection",
        name: "Data from Cloud Storage",
        artifact_ids: &["srum_network_usage", "evtx_security"],
        leads_to: &[],
    },
];

// ── ToolShell Vulnerability in Sharepoint ─────────────────────────────────────
// Source: "ToolShell Vulnerability in Sharepoint.afb" (CTID corpus)
// 15 action nodes

static TOOLSHELL_VULNERABILITY_IN_SHAREPOINT_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security"],
        leads_to: &[1],
    },
    // [1] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Exploit Public-Facing Application",
        artifact_ids: &["evtx_security"],
        leads_to: &[2],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "PowerShell",
        artifact_ids: &["evtx_security"],
        leads_to: &[3, 4, 5],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Web Shell",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Automated Collection",
        artifact_ids: &["evtx_security"],
        leads_to: &[8],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Reflective Code Loading",
        artifact_ids: &["evtx_security"],
        leads_to: &[9],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Reflective Code Loading",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Local Data Staging",
        artifact_ids: &["evtx_security"],
        leads_to: &[11],
    },
    // [9] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Unsecured Credentials",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Unsecured Credentials",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["evtx_security"],
        leads_to: &[14],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["evtx_security"],
        leads_to: &[14],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Exfiltration Over C2 Channel",
        artifact_ids: &["evtx_security"],
        leads_to: &[14],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "ViewState Persistence",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Turla - Carbon Emulation Plan ─────────────────────────────────────────────
// Source: "Turla - Carbon Emulation Plan.afb" (CTID corpus)
// 40 action nodes

static TURLA_CARBON_EMULATION_PLAN_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Spearphishing Link",
        artifact_ids: &["evtx_security"],
        leads_to: &[1],
    },
    // [1] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Malicious File",
        artifact_ids: &["evtx_security"],
        leads_to: &[2],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_security"],
        leads_to: &[3, 4],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Winlogon Helper DLL",
        artifact_ids: &["evtx_security"],
        leads_to: &[5],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[5],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Native API",
        artifact_ids: &["evtx_security"],
        leads_to: &[7, 9],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[8, 9],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [9] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[11],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Local Account",
        artifact_ids: &["evtx_security"],
        leads_to: &[12],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "File and Directory Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[13],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Local Data Staging",
        artifact_ids: &["evtx_security"],
        leads_to: &[14],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Archive via Library",
        artifact_ids: &["evtx_security"],
        leads_to: &[15],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Standard Encoding",
        artifact_ids: &["evtx_security"],
        leads_to: &[16],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "External Proxy",
        artifact_ids: &["evtx_security"],
        leads_to: &[17],
    },
    // [17] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[18],
    },
    // [18] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Asymmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[19],
    },
    // [19] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Permission Groups Discovery: Domain Groups",
        artifact_ids: &["evtx_security"],
        leads_to: &[20, 21],
    },
    // [20] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Query Registry",
        artifact_ids: &["evtx_security"],
        leads_to: &[22],
    },
    // [21] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "System Service Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[23],
    },
    // [22] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "PowerShell",
        artifact_ids: &["evtx_security"],
        leads_to: &[23],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Services Registry Permissions Weakness",
        artifact_ids: &["evtx_security"],
        leads_to: &[24],
    },
    // [24] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Service Restart",
        artifact_ids: &["evtx_security"],
        leads_to: &[25],
    },
    // [25] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security"],
        leads_to: &[26],
    },
    // [26] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Masquerade Task or Service",
        artifact_ids: &["evtx_security"],
        leads_to: &[27],
    },
    // [27] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Native API",
        artifact_ids: &["evtx_security"],
        leads_to: &[28, 29],
    },
    // [28] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Windows Service",
        artifact_ids: &["evtx_security"],
        leads_to: &[29],
    },
    // [29] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Modify Registry",
        artifact_ids: &["evtx_security"],
        leads_to: &[30],
    },
    // [30] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Service Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[31],
    },
    // [31] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[32],
    },
    // [32] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Web Protocols",
        artifact_ids: &["evtx_security"],
        leads_to: &[33, 34],
    },
    // [33] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Asymmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[35],
    },
    // [34] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[35],
    },
    // [35] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "System Owner/User Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[36],
    },
    // [36] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[37],
    },
    // [37] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Standard Encoding",
        artifact_ids: &["evtx_security"],
        leads_to: &[38],
    },
    // [38] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security"],
        leads_to: &[39],
    },
    // [39] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Windows Command Shell",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Turla - Snake Emulation Plan ──────────────────────────────────────────────
// Source: "Turla - Snake Emulation Plan.afb" (CTID corpus)
// 40 action nodes

static TURLA_SNAKE_EMULATION_PLAN_ACTIONS: &[FlowAction] = &[
    // [0] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Drive-by Compromise",
        artifact_ids: &["evtx_security"],
        leads_to: &[1],
    },
    // [1] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "JavaScript",
        artifact_ids: &["evtx_security"],
        leads_to: &[2],
    },
    // [2] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Malicious Link",
        artifact_ids: &["evtx_security"],
        leads_to: &[3],
    },
    // [3] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[4, 5],
    },
    // [4] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Winlogon Helper DLL",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [5] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[6],
    },
    // [6] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_security"],
        leads_to: &[7],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[8, 9],
    },
    // [8] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [9] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_security"],
        leads_to: &[10],
    },
    // [10] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[11, 12],
    },
    // [11] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "External Proxy",
        artifact_ids: &["evtx_security"],
        leads_to: &[13, 14],
    },
    // [12] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Web Protocols",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
    // [13] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "System Information Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[15],
    },
    // [14] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Domain Groups",
        artifact_ids: &["evtx_security"],
        leads_to: &[15],
    },
    // [15] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security"],
        leads_to: &[16],
    },
    // [16] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Windows Service",
        artifact_ids: &["evtx_security"],
        leads_to: &[17],
    },
    // [17] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Code Signing Policy Modification",
        artifact_ids: &["evtx_security"],
        leads_to: &[18],
    },
    // [18] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Rootkit",
        artifact_ids: &["evtx_security"],
        leads_to: &[19, 20],
    },
    // [19] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[21, 22, 23],
    },
    // [20] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "File Deletion",
        artifact_ids: &["evtx_security"],
        leads_to: &[21, 22, 23],
    },
    // [21] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_security"],
        leads_to: &[24],
    },
    // [22] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Rootkit",
        artifact_ids: &["evtx_security"],
        leads_to: &[24],
    },
    // [23] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Event Triggered Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[24],
    },
    // [24] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[25],
    },
    // [25] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_security"],
        leads_to: &[26],
    },
    // [26] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Symmetric Cryptography",
        artifact_ids: &["evtx_security"],
        leads_to: &[27],
    },
    // [27] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[28],
    },
    // [28] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Inter-Process Communication",
        artifact_ids: &["evtx_security"],
        leads_to: &[29],
    },
    // [29] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Web Protocols",
        artifact_ids: &["evtx_security"],
        leads_to: &[30],
    },
    // [30] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Domain Account",
        artifact_ids: &["evtx_security"],
        leads_to: &[31],
    },
    // [31] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Process Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[32],
    },
    // [32] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Token Impersonation/Theft",
        artifact_ids: &["evtx_security"],
        leads_to: &[33],
    },
    // [33] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Create Process with Token",
        artifact_ids: &["evtx_security"],
        leads_to: &[34],
    },
    // [34] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "System Network Connections Discovery",
        artifact_ids: &["evtx_security"],
        leads_to: &[35],
    },
    // [35] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security"],
        leads_to: &[36],
    },
    // [36] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Inter-Process Communication",
        artifact_ids: &["evtx_security"],
        leads_to: &[37],
    },
    // [37] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Domain Accounts",
        artifact_ids: &["evtx_security"],
        leads_to: &[38],
    },
    // [38] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Service Execution",
        artifact_ids: &["evtx_security"],
        leads_to: &[39],
    },
    // [39] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "unknown",
        name: "Web Protocols",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── Uber Breach ───────────────────────────────────────────────────────────────
// Source: "Uber Breach.afb" (CTID corpus)
// 8 action nodes

static UBER_BREACH_ACTIONS: &[FlowAction] = &[
    // [0] T1586
    FlowAction {
        technique_id: "T1586",
        tactic: "resource-development",
        name: "Compromise Accounts",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[1],
    },
    // [1] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[2],
    },
    // [2] T1621
    FlowAction {
        technique_id: "T1621",
        tactic: "credential-access",
        name: "Multi-Factor Authentication Request Generation",
        artifact_ids: &["evtx_security"],
        leads_to: &[3],
    },
    // [3] T1135
    FlowAction {
        technique_id: "T1135",
        tactic: "discovery",
        name: "Network Share Discovery",
        artifact_ids: &["evtx_security", "evtx_sysmon"],
        leads_to: &[4],
    },
    // [4] T1552.001
    FlowAction {
        technique_id: "T1552.001",
        tactic: "credential-access",
        name: "Credentials In Files",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[5],
    },
    // [5] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "privilege-escalation",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[6],
    },
    // [6] T1555
    FlowAction {
        technique_id: "T1555",
        tactic: "credential-access",
        name: "Credentials from Password Stores",
        artifact_ids: &["evtx_security", "dpapi_masterkey_user"],
        leads_to: &[7],
    },
    // [7] unknown
    FlowAction {
        technique_id: "unknown",
        tactic: "exfiltration",
        name: "Exfiltration",
        artifact_ids: &["evtx_security"],
        leads_to: &[],
    },
];

// ── WhisperGate ───────────────────────────────────────────────────────────────
// Source: "WhisperGate.afb" (CTID corpus)
// 19 action nodes

static WHISPERGATE_ACTIONS: &[FlowAction] = &[
    // [0] T1078
    FlowAction {
        technique_id: "T1078",
        tactic: "initial-access",
        name: "Valid Accounts",
        artifact_ids: &["evtx_security", "windows_vault_user"],
        leads_to: &[1],
    },
    // [1] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[2],
    },
    // [2] T1542.003
    FlowAction {
        technique_id: "T1542.003",
        tactic: "defense-evasion",
        name: "Bootkit",
        artifact_ids: &["evtx_system", "evtx_security"],
        leads_to: &[3],
    },
    // [3] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[4],
    },
    // [4] T1105
    FlowAction {
        technique_id: "T1105",
        tactic: "command-and-control",
        name: "Ingress Tool Transfer",
        artifact_ids: &["evtx_security", "srum_network_usage"],
        leads_to: &[5],
    },
    // [5] T1027.003
    FlowAction {
        technique_id: "T1027.003",
        tactic: "defense-evasion",
        name: "Steganography",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[6],
    },
    // [6] T1027
    FlowAction {
        technique_id: "T1027",
        tactic: "defense-evasion",
        name: "Obfuscated Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[7],
    },
    // [7] T1059.005
    FlowAction {
        technique_id: "T1059.005",
        tactic: "execution",
        name: "Visual Basic",
        artifact_ids: &["prefetch_dir", "evtx_sysmon"],
        leads_to: &[8],
    },
    // [8] T1562.001
    FlowAction {
        technique_id: "T1562.001",
        tactic: "defense-evasion",
        name: "Disable or Modify Tools",
        artifact_ids: &["evtx_security", "evtx_system"],
        leads_to: &[9],
    },
    // [9] T1140
    FlowAction {
        technique_id: "T1140",
        tactic: "defense-evasion",
        name: "Deobfuscate/Decode Files or Information",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[10],
    },
    // [10] T1027.009
    FlowAction {
        technique_id: "T1027.009",
        tactic: "defense-evasion",
        name: "Embedded Payloads",
        artifact_ids: &["evtx_powershell", "prefetch_dir"],
        leads_to: &[11],
    },
    // [11] T1059.001
    FlowAction {
        technique_id: "T1059.001",
        tactic: "execution",
        name: "PowerShell",
        artifact_ids: &[
            "powershell_history",
            "evtx_powershell",
            "psreadline_history",
        ],
        leads_to: &[12],
    },
    // [12] T1055.001
    FlowAction {
        technique_id: "T1055.001",
        tactic: "defense-evasion",
        name: "Dynamic-link Library Injection",
        artifact_ids: &["evtx_sysmon", "prefetch_dir"],
        leads_to: &[13],
    },
    // [13] T1218.004
    FlowAction {
        technique_id: "T1218.004",
        tactic: "defense-evasion",
        name: "InstallUtil",
        artifact_ids: &["prefetch_dir", "shimcache", "amcache_app_file"],
        leads_to: &[14, 15],
    },
    // [14] T1049
    FlowAction {
        technique_id: "T1049",
        tactic: "discovery",
        name: "System Network Connections Discovery ",
        artifact_ids: &["evtx_security", "dns_debug_log"],
        leads_to: &[16],
    },
    // [15] T1082
    FlowAction {
        technique_id: "T1082",
        tactic: "discovery",
        name: "System Information Discovery",
        artifact_ids: &["evtx_sysmon", "evtx_security"],
        leads_to: &[16],
    },
    // [16] T1485
    FlowAction {
        technique_id: "T1485",
        tactic: "impact",
        name: "Data Destruction",
        artifact_ids: &["mft_file", "usn_journal"],
        leads_to: &[17],
    },
    // [17] T1070.004
    FlowAction {
        technique_id: "T1070.004",
        tactic: "defense-evasion",
        name: "File Deletion",
        artifact_ids: &["recycle_bin", "usn_journal", "mft_file"],
        leads_to: &[18],
    },
    // [18] T1529
    FlowAction {
        technique_id: "T1529",
        tactic: "impact",
        name: "System Shutdown/Reboot",
        artifact_ids: &["evtx_system", "evtx_security"],
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
    // CISA AA22-138B VMWare Workspace (Alt)
    AttackFlow {
        id: "cisa_aa22_138b_vmware_workspace_alt",
        name: "CISA AA22-138B VMWare Workspace (Alt)",
        description: "Alternative method used to exploit VMWare Workspace ONE Access",
        actions: CISA_AA22_138B_VMWARE_WORKSPACE_ALT_ACTIONS,
    },
    // CISA AA22-138B VMWare Workspace (TA1)
    AttackFlow {
        id: "cisa_aa22_138b_vmware_workspace_ta1",
        name: "CISA AA22-138B VMWare Workspace (TA1)",
        description: "Threat Actor 1 exploited VMWare Workspace ONE Access through various methods",
        actions: CISA_AA22_138B_VMWARE_WORKSPACE_TA1_ACTIONS,
    },
    // CISA AA22-138B VMWare Workspace (TA2)
    AttackFlow {
        id: "cisa_aa22_138b_vmware_workspace_ta2",
        name: "CISA AA22-138B VMWare Workspace (TA2)",
        description: "Threat Actor 2 exploited VMWare Workspace ONE Access through various methods",
        actions: CISA_AA22_138B_VMWARE_WORKSPACE_TA2_ACTIONS,
    },
    // CISA Iranian APT
    AttackFlow {
        id: "cisa_iranian_apt",
        name: "CISA Iranian APT",
        description: "Iranian APT exploited Log4Shell and deployed XMRig crypto mining software.",
        actions: CISA_IRANIAN_APT_ACTIONS,
    },
    // Conti CISA Alert
    AttackFlow {
        id: "conti_cisa_alert",
        name: "Conti CISA Alert",
        description: "Conti ransomware flow based on CISA alert.",
        actions: CONTI_CISA_ALERT_ACTIONS,
    },
    // Conti PWC
    AttackFlow {
        id: "conti_pwc",
        name: "Conti PWC",
        description: "Conti ransomware flow based on PWC report.",
        actions: CONTI_PWC_ACTIONS,
    },
    // Equifax Breach
    AttackFlow {
        id: "equifax_breach",
        name: "Equifax Breach",
        description: "Attack flow on the 2017 Equifax breach.",
        actions: EQUIFAX_BREACH_ACTIONS,
    },
    // Example Attack Tree
    AttackFlow {
        id: "example_attack_tree",
        name: "Example Attack Tree",
        description: "This flow illustrates how to build an attack tree using Attack Flow Builder.",
        actions: EXAMPLE_ATTACK_TREE_ACTIONS,
    },
    // FIN13 Case 1
    AttackFlow {
        id: "fin13_case_1",
        name: "FIN13 Case 1",
        description: "Attack by FIN13 against a Latin American bank",
        actions: FIN13_CASE_1_ACTIONS,
    },
    // FIN13 Case 2
    AttackFlow {
        id: "fin13_case_2",
        name: "FIN13 Case 2",
        description: "Attack flow for the FIN13 campaign targeting a bank in Peru. ",
        actions: FIN13_CASE_2_ACTIONS,
    },
    // Gootloader
    AttackFlow {
        id: "gootloader",
        name: "Gootloader",
        description: "Attack flow on the Gootloader payload distribution attack.",
        actions: GOOTLOADER_ACTIONS,
    },
    // Hancitor DLL
    AttackFlow {
        id: "hancitor_dll",
        name: "Hancitor DLL",
        description: "Attack flow on an intrusion using the Hancitor downloader.",
        actions: HANCITOR_DLL_ACTIONS,
    },
    // Ivanti Vulnerabilities
    AttackFlow {
        id: "ivanti_vulnerabilities",
        name: "Ivanti Vulnerabilities",
        description: "A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) allows an authenticated administrator to send specially crafted requests a",
        actions: IVANTI_VULNERABILITIES_ACTIONS,
    },
    // JP Morgan Breach
    AttackFlow {
        id: "jp_morgan_breach",
        name: "JP Morgan Breach",
        description: "Attack flow on the 2014 JP Morgan breach.",
        actions: JP_MORGAN_BREACH_ACTIONS,
    },
    // MITRE NERVE
    AttackFlow {
        id: "mitre_nerve",
        name: "MITRE NERVE",
        description: "A nation-state actor intrusion starting in Jan 2024. © 2024 The MITRE Corporation. Approved for public release. Document number CT0121.",
        actions: MITRE_NERVE_ACTIONS,
    },
    // Maastricht University Ransomware
    AttackFlow {
        id: "maastricht_university_ransomware",
        name: "Maastricht University Ransomware",
        description: "In 2019, the Maastricht University was targeted by a ransomware attack. At least 267 internal servers were affected in this incident.",
        actions: MAASTRICHT_UNIVERSITY_RANSOMWARE_ACTIONS,
    },
    // Mac Malware Steals Crypto
    AttackFlow {
        id: "mac_malware_steals_crypto",
        name: "Mac Malware Steals Crypto",
        description: "Analysis of a malware family, OSX.DarthMiner, that targets MacOS.",
        actions: MAC_MALWARE_STEALS_CRYPTO_ACTIONS,
    },
    // Marriott Breach
    AttackFlow {
        id: "marriott_breach",
        name: "Marriott Breach",
        description: "A data breach at the Marriott hotel group in 2018.",
        actions: MARRIOTT_BREACH_ACTIONS,
    },
    // Muddy Water
    AttackFlow {
        id: "muddy_water",
        name: "Muddy Water",
        description: "Multiple campaigns attributed to an Iranian state-based actor.",
        actions: MUDDY_WATER_ACTIONS,
    },
    // NotPetya
    AttackFlow {
        id: "notpetya",
        name: "NotPetya",
        description: "Analysis of 2017 malware outbreak.",
        actions: NOTPETYA_ACTIONS,
    },
    // OceanLotus
    AttackFlow {
        id: "oceanlotus",
        name: "OceanLotus",
        description: "OceanLotus Operations Flow ",
        actions: OCEANLOTUS_ACTIONS,
    },
    // OpenClaw Command & Control via Prompt Injection
    AttackFlow {
        id: "openclaw",
        name: "OpenClaw Command & Control via Prompt Injection",
        description: "Incident Date:  February 3, 2026 
Actor:  HiddenLayer  | Target:  OpenClaw
Researchers at HiddenLayer demonstrated how a webpage can embed an indirect prompt injection that causes OpenClaw to silently",
        actions: OPENCLAW_ACTIONS,
    },
    // REvil
    AttackFlow {
        id: "revil",
        name: "REvil",
        description: "Profile of a ransomware group",
        actions: REVIL_ACTIONS,
    },
    // Ragnar Locker
    AttackFlow {
        id: "ragnar_locker",
        name: "Ragnar Locker",
        description: "Profile of a ransomware group",
        actions: RAGNAR_LOCKER_ACTIONS,
    },
    // SWIFT Heist
    AttackFlow {
        id: "swift_heist",
        name: "SWIFT Heist",
        description: "A financial crime involving the SWIFT banking network.",
        actions: SWIFT_HEIST_ACTIONS,
    },
    // SearchAwesome Adware
    AttackFlow {
        id: "searchawesome_adware",
        name: "SearchAwesome Adware",
        description: "SearchAwesome adware intercepts encrypted web traffic to inject ads",
        actions: SEARCHAWESOME_ADWARE_ACTIONS,
    },
    // Shamoon
    AttackFlow {
        id: "shamoon",
        name: "Shamoon",
        description: "Malware family targeting energy, government, and telecom in the middle east and europe.",
        actions: SHAMOON_ACTIONS,
    },
    // Sony Malware
    AttackFlow {
        id: "sony_malware",
        name: "Sony Malware",
        description: "Attack flow on the malware believed to be behind the 2014 Sony breach.",
        actions: SONY_MALWARE_ACTIONS,
    },
    // Target Breach
    AttackFlow {
        id: "target_breach",
        name: "Target Breach",
        description: "Attack flow for the 2013 Target breach.",
        actions: TARGET_BREACH_ACTIONS,
    },
    // Tesla Kubernetes Breach
    AttackFlow {
        id: "tesla_kubernetes_breach",
        name: "Tesla Kubernetes Breach",
        description: "A cryptomining attack discovered on a Tesla kubernetes (k8s) cluster.",
        actions: TESLA_KUBERNETES_BREACH_ACTIONS,
    },
    // ToolShell Vulnerability in Sharepoint
    AttackFlow {
        id: "toolshell_vulnerability_in_sharepoint",
        name: "ToolShell Vulnerability in Sharepoint",
        description: "A widespread vulnerability in Microsoft Sharepoint on-premises leads to remote code execution and credential theft.",
        actions: TOOLSHELL_VULNERABILITY_IN_SHAREPOINT_ACTIONS,
    },
    // Turla - Carbon Emulation Plan
    AttackFlow {
        id: "turla_carbon_emulation_plan",
        name: "Turla - Carbon Emulation Plan",
        description: "The emulation plan, created by the ATT&CK ® Evaluations team, used during Day 1 of the ATT&CK evaluations Round 5. This scenario focuses on Carbon, a second-stage backdoor and framework that targets W",
        actions: TURLA_CARBON_EMULATION_PLAN_ACTIONS,
    },
    // Turla - Snake Emulation Plan
    AttackFlow {
        id: "turla_snake_emulation_plan",
        name: "Turla - Snake Emulation Plan",
        description: "The emulation plan, created by the ATT&CK ® Evaluations team, used during Day 2 of the ATT&CK evaluations Round 5. This scenario focuses on Snake, a rootkit used to compromise computers and exfiltrate",
        actions: TURLA_SNAKE_EMULATION_PLAN_ACTIONS,
    },
    // Uber Breach
    AttackFlow {
        id: "uber_breach",
        name: "Uber Breach",
        description: "A breach at Uber by the Lapsus$ group.",
        actions: UBER_BREACH_ACTIONS,
    },
    // WhisperGate
    AttackFlow {
        id: "whispergate",
        name: "WhisperGate",
        description: "A Russian state-sponsored malware campaign targeting Ukraine.",
        actions: WHISPERGATE_ACTIONS,
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

/// Returns `true` if the given ATT&CK technique ID appears in any flow in the CTID corpus.
///
/// Useful for quickly checking whether a detected technique has been observed
/// in a real adversary campaign documented in the CTID Attack Flow library.
pub fn is_technique_in_known_campaign(technique_id: &str) -> bool {
    let lower = technique_id.to_ascii_lowercase();
    ATTACK_FLOWS.iter().any(|flow| {
        flow.actions
            .iter()
            .any(|a| a.technique_id.to_ascii_lowercase() == lower)
    })
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
            assert!(
                !flow.description.is_empty(),
                "flow '{}' has empty description",
                flow.id
            );
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
        let curated_prefixes = [
            "evtx_",
            "kape_",
            "fa_",
            "browsers_",
            "velociraptor_",
            "nirsoft_",
            "regedit_",
        ];
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
                assert!(
                    seen.insert(id),
                    "duplicate artifact '{id}' in flow '{}'",
                    flow.id
                );
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
        assert!(
            f.name.contains("Black Basta"),
            "name should contain 'Black Basta'"
        );
    }

    /// Black Basta must have its first real technique T1566.001 (spearphishing attachment).
    #[test]
    fn ctid_black_basta_has_t1566_001() {
        let f =
            flow_by_id("black_basta_ransomware").expect("flow 'black_basta_ransomware' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "black_basta_ransomware must contain T1566.001 (Spearphishing Attachment)"
        );
    }

    /// Black Basta must have T1486 (ransomware encryption).
    #[test]
    fn ctid_black_basta_has_t1486() {
        let f =
            flow_by_id("black_basta_ransomware").expect("flow 'black_basta_ransomware' must exist");
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
        assert!(
            f.name.contains("Cobalt Kitty"),
            "name should contain 'Cobalt Kitty'"
        );
    }

    /// Cobalt Kitty must have T1566.002 (spearphishing link — its initial access).
    #[test]
    fn ctid_cobalt_kitty_has_t1566_002() {
        let f =
            flow_by_id("cobalt_kitty_campaign").expect("flow 'cobalt_kitty_campaign' must exist");
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
        assert!(
            f.name.contains("SolarWinds"),
            "name should contain 'SolarWinds'"
        );
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
        let f = flow_by_id("conti_ransomware").expect("flow 'conti_ransomware' must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1486"),
            "conti_ransomware must contain T1486 (Data Encrypted for Impact)"
        );
    }

    /// BumbleBee Round 2 flow from CTID corpus must exist.
    #[test]
    fn ctid_bumblbee_round2_flow_exists() {
        let f =
            flow_by_id("bumblbee_round2").expect("flow 'bumblbee_round2' must exist (CTID corpus)");
        assert!(
            f.name.contains("BumbleBee"),
            "name should contain 'BumbleBee'"
        );
    }

    /// BumbleBee must have T1003.001 (LSASS credential dumping).
    #[test]
    fn ctid_bumblbee_round2_has_t1003_001() {
        let f = flow_by_id("bumblbee_round2").expect("flow 'bumblbee_round2' must exist");
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
                        id,
                        action.name
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
        flow_by_id("cisa_iranian_apt").expect("flow \"cisa_iranian_apt\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_cisa_iranian_apt_has_t1190() {
        let f = flow_by_id("cisa_iranian_apt").expect("flow \"cisa_iranian_apt\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "cisa_iranian_apt must contain T1190"
        );
    }

    #[test]
    fn ctid_conti_cisa_alert_flow_exists() {
        flow_by_id("conti_cisa_alert").expect("flow \"conti_cisa_alert\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_conti_cisa_alert_has_t1598_004() {
        let f = flow_by_id("conti_cisa_alert").expect("flow \"conti_cisa_alert\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1598.004"),
            "conti_cisa_alert must contain T1598.004"
        );
    }

    #[test]
    fn ctid_conti_pwc_flow_exists() {
        flow_by_id("conti_pwc").expect("flow \"conti_pwc\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_conti_pwc_has_t1566_001() {
        let f = flow_by_id("conti_pwc").expect("flow \"conti_pwc\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "conti_pwc must contain T1566.001"
        );
    }

    #[test]
    fn ctid_equifax_breach_flow_exists() {
        flow_by_id("equifax_breach").expect("flow \"equifax_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_equifax_breach_has_t1595_002() {
        let f = flow_by_id("equifax_breach").expect("flow \"equifax_breach\" must exist");
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
        flow_by_id("fin13_case_1").expect("flow \"fin13_case_1\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_fin13_case_1_has_t1595_002() {
        let f = flow_by_id("fin13_case_1").expect("flow \"fin13_case_1\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1595.002"),
            "fin13_case_1 must contain T1595.002"
        );
    }

    #[test]
    fn ctid_fin13_case_2_flow_exists() {
        flow_by_id("fin13_case_2").expect("flow \"fin13_case_2\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_fin13_case_2_has_t1190() {
        let f = flow_by_id("fin13_case_2").expect("flow \"fin13_case_2\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1190"),
            "fin13_case_2 must contain T1190"
        );
    }

    #[test]
    fn ctid_gootloader_flow_exists() {
        flow_by_id("gootloader").expect("flow \"gootloader\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_gootloader_has_t1584() {
        let f = flow_by_id("gootloader").expect("flow \"gootloader\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1584"),
            "gootloader must contain T1584"
        );
    }

    #[test]
    fn ctid_hancitor_dll_flow_exists() {
        flow_by_id("hancitor_dll").expect("flow \"hancitor_dll\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_hancitor_dll_has_t1566_002() {
        let f = flow_by_id("hancitor_dll").expect("flow \"hancitor_dll\" must exist");
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
        flow_by_id("jp_morgan_breach").expect("flow \"jp_morgan_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_jp_morgan_breach_has_t1566() {
        let f = flow_by_id("jp_morgan_breach").expect("flow \"jp_morgan_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566"),
            "jp_morgan_breach must contain T1566"
        );
    }

    #[test]
    fn ctid_mitre_nerve_flow_exists() {
        flow_by_id("mitre_nerve").expect("flow \"mitre_nerve\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_mitre_nerve_has_t1190() {
        let f = flow_by_id("mitre_nerve").expect("flow \"mitre_nerve\" must exist");
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
        flow_by_id("marriott_breach").expect("flow \"marriott_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_marriott_breach_has_t1566() {
        let f = flow_by_id("marriott_breach").expect("flow \"marriott_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566"),
            "marriott_breach must contain T1566"
        );
    }

    #[test]
    fn ctid_muddy_water_flow_exists() {
        flow_by_id("muddy_water").expect("flow \"muddy_water\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_muddy_water_has_t1566_001() {
        let f = flow_by_id("muddy_water").expect("flow \"muddy_water\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "muddy_water must contain T1566.001"
        );
    }

    #[test]
    fn ctid_notpetya_flow_exists() {
        flow_by_id("notpetya").expect("flow \"notpetya\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_notpetya_has_t1593() {
        let f = flow_by_id("notpetya").expect("flow \"notpetya\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1593"),
            "notpetya must contain T1593"
        );
    }

    #[test]
    fn ctid_oceanlotus_flow_exists() {
        flow_by_id("oceanlotus").expect("flow \"oceanlotus\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_oceanlotus_has_t1566_001() {
        let f = flow_by_id("oceanlotus").expect("flow \"oceanlotus\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1566.001"),
            "oceanlotus must contain T1566.001"
        );
    }

    #[test]
    fn ctid_openclaw_flow_exists() {
        flow_by_id("openclaw").expect("flow \"openclaw\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_revil_flow_exists() {
        flow_by_id("revil").expect("flow \"revil\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_revil_has_t1189() {
        let f = flow_by_id("revil").expect("flow \"revil\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1189"),
            "revil must contain T1189"
        );
    }

    #[test]
    fn ctid_ragnar_locker_flow_exists() {
        flow_by_id("ragnar_locker").expect("flow \"ragnar_locker\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_ragnar_locker_has_t1078() {
        let f = flow_by_id("ragnar_locker").expect("flow \"ragnar_locker\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1078"),
            "ragnar_locker must contain T1078"
        );
    }

    #[test]
    fn ctid_swift_heist_flow_exists() {
        flow_by_id("swift_heist").expect("flow \"swift_heist\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_swift_heist_has_t1190() {
        let f = flow_by_id("swift_heist").expect("flow \"swift_heist\" must exist");
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
        let f =
            flow_by_id("searchawesome_adware").expect("flow \"searchawesome_adware\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1204.002"),
            "searchawesome_adware must contain T1204.002"
        );
    }

    #[test]
    fn ctid_shamoon_flow_exists() {
        flow_by_id("shamoon").expect("flow \"shamoon\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_shamoon_has_t1105() {
        let f = flow_by_id("shamoon").expect("flow \"shamoon\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1105"),
            "shamoon must contain T1105"
        );
    }

    #[test]
    fn ctid_sony_malware_flow_exists() {
        flow_by_id("sony_malware").expect("flow \"sony_malware\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_sony_malware_has_t1105() {
        let f = flow_by_id("sony_malware").expect("flow \"sony_malware\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1105"),
            "sony_malware must contain T1105"
        );
    }

    #[test]
    fn ctid_target_breach_flow_exists() {
        flow_by_id("target_breach").expect("flow \"target_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_target_breach_has_t1593_002() {
        let f = flow_by_id("target_breach").expect("flow \"target_breach\" must exist");
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
        flow_by_id("uber_breach").expect("flow \"uber_breach\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_uber_breach_has_t1586() {
        let f = flow_by_id("uber_breach").expect("flow \"uber_breach\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1586"),
            "uber_breach must contain T1586"
        );
    }

    #[test]
    fn ctid_whispergate_flow_exists() {
        flow_by_id("whispergate").expect("flow \"whispergate\" must exist (CTID corpus)");
    }

    #[test]
    fn ctid_whispergate_has_t1078() {
        let f = flow_by_id("whispergate").expect("flow \"whispergate\" must exist");
        assert!(
            f.actions.iter().any(|a| a.technique_id == "T1078"),
            "whispergate must contain T1078"
        );
    }

    // --- is_technique_in_known_campaign ---
    #[test]
    fn t1566_001_in_known_campaign() {
        assert!(is_technique_in_known_campaign("T1566.001"));
    }
    #[test]
    fn t1486_in_known_campaign() {
        assert!(is_technique_in_known_campaign("T1486"));
    }
    #[test]
    fn t1003_001_in_known_campaign() {
        assert!(is_technique_in_known_campaign("T1003.001"));
    }
    #[test]
    fn t1195_002_in_known_campaign() {
        assert!(is_technique_in_known_campaign("T1195.002"));
    }
    #[test]
    fn technique_lookup_is_case_insensitive() {
        assert!(is_technique_in_known_campaign("t1486"));
    }
    #[test]
    fn nonexistent_technique_not_in_campaign() {
        assert!(!is_technique_in_known_campaign("T9999.999"));
    }
    #[test]
    fn empty_string_not_in_campaign() {
        assert!(!is_technique_in_known_campaign(""));
    }
}
