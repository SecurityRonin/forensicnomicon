//! ATT&CK identifier currency guard.
//!
//! Every MITRE ATT&CK technique ID compiled into this workspace must be a
//! *live* ID in the ATT&CK release the catalog conforms to. A revoked ID is
//! worse than a stale one: it silently resolves (via MITRE's redirect) to a
//! technique page whose scope may no longer match the artifact, and downstream
//! detection content keyed on it fails lookup against current STIX.
//!
//! # Provenance
//!
//! Conformance target: **MITRE ATT&CK v19.2** (Enterprise, Mobile and ICS
//! collections, all at 19.2), checked 2026-09-22 against MITRE's own
//! machine-readable STIX data:
//! <https://github.com/mitre-attack/attack-stix-data>
//!
//! `DEAD_ATTACK_IDS` lists every `attack-pattern` object carrying
//! `revoked: true` (successor = the target of its `revoked-by` relationship,
//! resolved transitively where the successor was itself later revoked) or
//! `x_mitre_deprecated: true` (empty successor — deprecated techniques have
//! none). Cross-checked against the official v19 release notes:
//! <https://attack.mitre.org/resources/updates/updates-april-2026/>
//!
//! # Maintenance
//!
//! When adopting a newer ATT&CK release, regenerate this table from the three
//! STIX bundles (filter `attack-pattern` objects on `revoked` /
//! `x_mitre_deprecated`, join `revoked-by` relationships for successors) and
//! update the version + date above. Do NOT hand-edit entries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// `(dead_id, live_successor)` — successor is empty for deprecated techniques.
///
/// Generated from ATT&CK v19.2 STIX (see module docs). Three chained
/// revocations are resolved to their live end point:
/// T1073 → (T1574.002) → T1574.001, T1150/T1162 → (T1547.011) → T1647.
const DEAD_ATTACK_IDS: &[(&str, &str)] = &[
    ("T0803", "T1691.001"),     // Block Command Message
    ("T0804", "T1691.002"),     // Block Reporting Message
    ("T0805", "T1695.001"),     // Block Serial COM
    ("T0812", "T1694.001"),     // Default Credentials
    ("T0839", "T1693.002"),     // Module Firmware
    ("T0855", "T1692.001"),     // Unauthorized Command Message
    ("T0856", "T1692.002"),     // Spoof Reporting Message
    ("T0857", "T1693.001"),     // System Firmware
    ("T0891", "T1694.002"),     // Hardcoded Credentials
    ("T1002", "T1560"),         // Data Compressed
    ("T1004", "T1547.004"),     // Winlogon Helper DLL
    ("T1009", "T1027.001"),     // Binary Padding
    ("T1013", "T1547.010"),     // Port Monitors
    ("T1015", "T1546.008"),     // Accessibility Features
    ("T1017", "T1072"),         // Application Deployment Software
    ("T1019", "T1542.001"),     // System Firmware
    ("T1022", "T1560"),         // Data Encrypted
    ("T1023", "T1547.009"),     // Shortcut Modification
    ("T1024", "T1573"),         // Custom Cryptographic Protocol
    ("T1026", ""),              // Multiband Communication (deprecated)
    ("T1028", "T1021.006"),     // Windows Remote Management
    ("T1031", "T1543.003"),     // Modify Existing Service
    ("T1032", "T1573"),         // Standard Cryptographic Protocol
    ("T1034", ""),              // Path Interception (deprecated)
    ("T1035", "T1569.002"),     // Service Execution
    ("T1038", "T1574.001"),     // DLL Search Order Hijacking
    ("T1042", "T1546.001"),     // Change Default File Association
    ("T1043", ""),              // Commonly Used Port (deprecated)
    ("T1044", "T1574.010"),     // File System Permissions Weakness
    ("T1045", "T1027.002"),     // Software Packing
    ("T1050", "T1543.003"),     // New Service
    ("T1051", ""),              // Shared Webroot (deprecated)
    ("T1053.001", "T1053.002"), // At (Linux)
    ("T1053.004", ""),          // Launchd (deprecated)
    ("T1054", "T1685"),         // Indicator Blocking
    ("T1058", "T1574.011"),     // Service Registry Permissions Weakness
    ("T1060", "T1547.001"),     // Registry Run Keys / Startup Folder
    ("T1061", ""),              // Graphical User Interface (deprecated)
    ("T1062", ""),              // Hypervisor (deprecated)
    ("T1063", "T1518.001"),     // Security Software Discovery
    ("T1064", ""),              // Scripting (deprecated)
    ("T1065", "T1571"),         // Uncommonly Used Port
    ("T1066", "T1027.005"),     // Indicator Removal from Tools
    ("T1067", "T1542.003"),     // Bootkit
    ("T1070.001", "T1685.005"), // Clear Windows Event Logs
    ("T1070.002", "T1685.006"), // Clear Linux or Mac System Logs
    ("T1073", "T1574.001"),     // DLL Side-Loading (via revoked T1574.002)
    ("T1075", "T1550.002"),     // Pass the Hash
    ("T1076", "T1021.001"),     // Remote Desktop Protocol
    ("T1077", "T1021.002"),     // Windows Admin Shares
    ("T1079", "T1573"),         // Multilayer Encryption
    ("T1081", "T1552.001"),     // Credentials in Files
    ("T1084", "T1546.003"),     // WMI Event Subscription
    ("T1085", "T1218.011"),     // Rundll32
    ("T1086", "T1059.001"),     // PowerShell
    ("T1088", "T1548.002"),     // Bypass User Account Control
    ("T1089", "T1685"),         // Disabling Security Tools
    ("T1093", "T1055.012"),     // Process Hollowing
    ("T1094", "T1095"),         // Custom Command and Control Protocol
    ("T1096", "T1564.004"),     // NTFS File Attributes
    ("T1097", "T1550.003"),     // Pass the Ticket
    ("T1099", "T1070.006"),     // Timestomp
    ("T1100", "T1505.003"),     // Web Shell
    ("T1101", "T1547.005"),     // Security Support Provider
    ("T1103", "T1546.010"),     // AppInit DLLs
    ("T1107", "T1070.004"),     // File Deletion
    ("T1108", ""),              // Redundant Access (deprecated)
    ("T1109", "T1542.002"),     // Component Firmware
    ("T1116", "T1553.002"),     // Code Signing
    ("T1117", "T1218.010"),     // Regsvr32
    ("T1118", "T1218.004"),     // InstallUtil
    ("T1121", "T1218.009"),     // Regsvcs/Regasm
    ("T1122", "T1546.015"),     // Component Object Model Hijacking
    ("T1126", "T1070.005"),     // Network Share Connection Removal
    ("T1128", "T1546.007"),     // Netsh Helper DLL
    ("T1130", "T1553.004"),     // Install Root Certificate
    ("T1131", "T1547.002"),     // Authentication Package
    ("T1138", "T1546.011"),     // Application Shimming
    ("T1139", "T1552.003"),     // Bash History
    ("T1141", "T1056.002"),     // Input Prompt
    ("T1142", "T1555.001"),     // Keychain
    ("T1143", "T1564.003"),     // Hidden Window
    ("T1144", "T1553.001"),     // Gatekeeper Bypass
    ("T1145", "T1552.004"),     // Private Keys
    ("T1146", "T1070.003"),     // Clear Command History
    ("T1147", "T1564.002"),     // Hidden Users
    ("T1148", "T1690"),         // HISTCONTROL
    ("T1149", ""),              // LC_MAIN Hijacking (deprecated)
    ("T1150", "T1647"),         // Plist Modification (via revoked T1547.011)
    ("T1151", "T1036.006"),     // Space after Filename
    ("T1152", "T1569.001"),     // Launchctl
    ("T1153", ""),              // Source (deprecated)
    ("T1154", "T1546.005"),     // Trap
    ("T1155", "T1059.002"),     // AppleScript
    ("T1156", "T1546.004"),     // Malicious Shell Modification
    ("T1157", "T1574.004"),     // Dylib Hijacking
    ("T1158", "T1564.001"),     // Hidden Files and Directories
    ("T1159", "T1543.001"),     // Launch Agent
    ("T1160", "T1543.004"),     // Launch Daemon
    ("T1161", "T1546.006"),     // LC_LOAD_DYLIB Addition
    ("T1162", "T1647"),         // Login Item (via revoked T1547.011)
    ("T1163", "T1037.004"),     // Rc.common
    ("T1164", "T1547.007"),     // Re-opened Applications
    ("T1165", "T1037.005"),     // Startup Items
    ("T1166", "T1548.001"),     // Setuid and Setgid
    ("T1167", "T1555.002"),     // Securityd Memory
    ("T1168", "T1053"),         // Local Job Scheduling
    ("T1169", "T1548.003"),     // Sudo
    ("T1170", "T1218.005"),     // Mshta
    ("T1171", "T1557.001"),     // LLMNR/NBT-NS Poisoning and Relay
    ("T1172", "T1090.004"),     // Domain Fronting
    ("T1173", "T1559.002"),     // Dynamic Data Exchange
    ("T1174", "T1556.002"),     // Password Filter DLL
    ("T1175", ""),              // COM and Distributed COM (deprecated)
    ("T1177", "T1547.008"),     // LSASS Driver
    ("T1178", "T1134.005"),     // SID-History Injection
    ("T1179", "T1056.004"),     // Hooking
    ("T1180", "T1546.002"),     // Screensaver
    ("T1181", "T1055.011"),     // Extra Window Memory Injection
    ("T1182", "T1546.009"),     // AppCert DLLs
    ("T1183", "T1546.012"),     // Image File Execution Options Injection
    ("T1184", "T1563.001"),     // SSH Hijacking
    ("T1186", "T1055.013"),     // Process Doppelgänging
    ("T1188", "T1090.003"),     // Multi-hop Proxy
    ("T1191", "T1218.003"),     // CMSTP
    ("T1192", "T1566.002"),     // Spearphishing Link
    ("T1193", "T1566.001"),     // Spearphishing Attachment
    ("T1194", "T1566.003"),     // Spearphishing via Service
    ("T1196", "T1218.002"),     // Control Panel Items
    ("T1198", "T1553.003"),     // SIP and Trust Provider Hijacking
    ("T1206", "T1548.003"),     // Sudo Caching
    ("T1208", "T1558.003"),     // Kerberoasting
    ("T1209", "T1547.003"),     // Time Providers
    ("T1214", "T1552.002"),     // Credentials in Registry
    ("T1215", "T1547.006"),     // Kernel Modules and Extensions
    ("T1223", "T1218.001"),     // Compiled HTML File
    ("T1399", ""),              // Modify Trusted Execution Environment (deprecated)
    ("T1400", "T1625.001"),     // Modify System Partition
    ("T1401", "T1626.001"),     // Device Administrator Permissions
    ("T1402", "T1624.001"),     // Broadcast Receivers
    ("T1403", ""),              // Modify Cached Executable Code (deprecated)
    ("T1405", ""),              // Exploit TEE Vulnerability (deprecated)
    ("T1408", "T1630.003"),     // Disguise Root/Jailbreak Indicators
    ("T1410", "T1638"),         // Network Traffic Capture or Redirection
    ("T1411", "T1417.002"),     // Input Prompt
    ("T1412", "T1636.004"),     // Capture SMS Messages
    ("T1413", ""),              // Access Sensitive Data in Device Logs (deprecated)
    ("T1415", "T1635.001"),     // URL Scheme Hijacking
    ("T1416", "T1635.001"),     // URI Hijacking
    ("T1419", "T1426"),         // Device Type Discovery
    ("T1427", ""),              // Attack PC via USB Connection (deprecated)
    ("T1432", "T1636.003"),     // Access Contact List
    ("T1433", "T1636.002"),     // Access Call Log
    ("T1435", "T1636.001"),     // Access Calendar Entries
    ("T1436", ""),              // Commonly Used Port (deprecated)
    ("T1438", "T1644"),         // Exfiltration Over Other Network Medium
    ("T1439", "T1638"),         // Eavesdrop on Insecure Network Communication
    ("T1444", ""),              // Masquerade as Legitimate Application (deprecated)
    ("T1446", "T1629.002"),     // Device Lockout
    ("T1447", "T1630.002"),     // Delete Device Data
    ("T1448", "T1643"),         // Carrier Billing Fraud
    ("T1449", ""),              // Exploit SS7 to Redirect Phone Calls/SMS (deprecated)
    ("T1450", "T1430.002"),     // Exploit SS7 to Track Device Location
    ("T1452", "T1643"),         // Manipulate App Store Rankings or Ratings
    ("T1454", ""),              // Malicious SMS Message (deprecated)
    ("T1463", "T1638"),         // Manipulate Device Communication
    ("T1465", "T1638"),         // Rogue Wi-Fi Access Points
    ("T1466", "T1638"),         // Downgrade to Insecure Protocols
    ("T1467", "T1638"),         // Rogue Cellular Base Station
    ("T1468", "T1430.001"),     // Remotely Track Device Without Authorization
    ("T1469", ""),              // Remotely Wipe Data Without Authorization (deprecated)
    ("T1470", ""),              // Obtain Device Cloud Backups (deprecated)
    ("T1472", "T1643"),         // Generate Fraudulent Advertising Revenue
    ("T1475", ""),              // Deliver Malicious App via Authorized App Store (deprecated)
    ("T1476", ""),              // Deliver Malicious App via Other Means (deprecated)
    ("T1477", ""),              // Exploit via Radio Interfaces (deprecated)
    ("T1478", "T1632.001"),     // Install Insecure or Malicious Configuration
    ("T1483", "T1568.002"),     // Domain Generation Algorithms
    ("T1487", "T1561.002"),     // Disk Structure Wipe
    ("T1488", "T1561.001"),     // Disk Content Wipe
    ("T1492", "T1565.001"),     // Stored Data Manipulation
    ("T1493", "T1565.002"),     // Transmitted Data Manipulation
    ("T1494", "T1565.003"),     // Runtime Data Manipulation
    ("T1500", "T1027.004"),     // Compile After Delivery
    ("T1501", "T1543.002"),     // Systemd Service
    ("T1502", "T1134.004"),     // Parent PID Spoofing
    ("T1503", "T1555.003"),     // Credentials from Web Browsers
    ("T1504", "T1546.013"),     // PowerShell Profile
    ("T1506", "T1550.004"),     // Web Session Cookie
    ("T1507", "T1421"),         // Network Information Discovery
    ("T1508", "T1628.001"),     // Suppress Application Icon
    ("T1510", "T1641.001"),     // Clipboard Modification
    ("T1514", "T1548.004"),     // Elevated Execution with Prompt
    ("T1519", "T1546.014"),     // Emond
    ("T1520", "T1637.001"),     // Domain Generation Algorithms
    ("T1522", "T1552.005"),     // Cloud Instance Metadata API
    ("T1523", "T1633.001"),     // Evade Analysis Environment
    ("T1527", "T1550.001"),     // Application Access Token
    ("T1536", "T1578.004"),     // Revert Cloud Instance
    ("T1540", "T1631.001"),     // Code Injection
    ("T1547.011", "T1647"),     // Plist Modification
    ("T1562", "T1685"),         // Impair Defenses
    ("T1562.001", "T1685"),     // Disable or Modify Tools
    ("T1562.002", "T1685.001"), // Disable Windows Event Logging
    ("T1562.003", "T1690"),     // Impair Command History Logging
    ("T1562.004", "T1686"),     // Disable or Modify System Firewall
    ("T1562.006", "T1685"),     // Indicator Blocking
    ("T1562.007", "T1686.001"), // Disable or Modify Cloud Firewall
    ("T1562.008", "T1685.002"), // Disable or Modify Cloud Logs
    ("T1562.009", "T1688"),     // Safe Mode Boot
    ("T1562.010", "T1689"),     // Downgrade Attack
    ("T1562.011", "T1685.003"), // Spoof Security Alerting
    ("T1562.012", "T1685.004"), // Disable or Modify Linux Audit System
    ("T1562.013", "T1686.002"), // Disable or Modify Network Device Firewall
    ("T1574.002", "T1574.001"), // DLL Side-Loading
    ("T1576", "T1630.001"),     // Uninstall Malicious Application
    ("T1579", "T1634.001"),     // Keychain
    ("T1581", "T1627.001"),     // Geofencing
    ("T1605", "T1623.001"),     // Command-Line Interface
    ("T1618", "T1628.002"),     // User Evasion
    ("T1656", "T1684.001"),     // Impersonation
    ("T1672", "T1684.002"),     // Email Spoofing
];

/// Source roots scanned, relative to the workspace root.
const SCAN_ROOTS: &[&str] = &[
    "src",
    "crates/core/src",
    "crates/data/src",
    "crates/ingest/src",
    "crates/4n6query/src",
];

/// Files allowed to name dead IDs: forward-remap tables whose *keys* are
/// necessarily the old IDs.
const EXEMPT_PATHS: &[&str] = &["crates/ingest/src/attack_remap.rs"];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("scan root must be readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Occurrences of `id` in `text` at technique-ID boundaries: the preceding
/// character must not be alphanumeric (rejects `CT0121`), and the ID must not
/// continue as a longer ID (`T1562` inside `T1562.001` is the sub-technique's
/// hit, not the parent's; `T1053.001` must not match inside `T1053.0011`).
fn boundary_hits(text: &str, id: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    for (start, _) in text.match_indices(id) {
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        let end = start + id.len();
        let next = bytes.get(end).copied();
        if next.is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        if !id.contains('.')
            && next == Some(b'.')
            && bytes.get(end + 1).is_some_and(u8::is_ascii_digit)
        {
            continue;
        }
        hits.push(text[..start].bytes().filter(|&b| b == b'\n').count() + 1);
    }
    hits
}

fn workspace_sources() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for scan_root in SCAN_ROOTS {
        collect_rs_files(&root.join(scan_root), &mut files);
    }
    assert!(
        files.len() >= 40,
        "scanner denominator collapsed: only {} .rs files found — broken walk?",
        files.len()
    );
    files
        .into_iter()
        .filter(|p| {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            !EXEMPT_PATHS.contains(&rel.as_str())
        })
        .map(|p| {
            let text = fs::read_to_string(&p).expect("source file must be UTF-8 readable");
            (p, text)
        })
        .collect()
}

/// Control: prove the instrument can find technique IDs at all before trusting
/// any negative result from it. `T1059` (Command and Scripting Interpreter) is
/// live in v19 and ubiquitous in this corpus.
#[test]
fn scanner_control_finds_live_ids() {
    let total: usize = workspace_sources()
        .iter()
        .map(|(_, text)| boundary_hits(text, "T1059").len())
        .sum();
    assert!(
        total > 0,
        "control failed: scanner found zero occurrences of live id T1059 — \
         the guard's negative results cannot be trusted"
    );
}

#[test]
fn no_revoked_or_deprecated_attack_ids_in_source() {
    let mut violations = Vec::new();
    for (path, text) in workspace_sources() {
        for (dead, successor) in DEAD_ATTACK_IDS {
            for line in boundary_hits(&text, dead) {
                let advice = if successor.is_empty() {
                    "deprecated in ATT&CK with no successor — remove or re-curate".to_string()
                } else {
                    format!("revoked — use {successor}")
                };
                violations.push(format!("{}:{line}: {dead} is {advice}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "dead MITRE ATT&CK technique IDs found (conformance: ATT&CK v19.2):\n{}",
        violations.join("\n")
    );
}
