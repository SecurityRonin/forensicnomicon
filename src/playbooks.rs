//! Investigation playbook engine.
//!
//! Provides directed investigation paths: given a trigger artifact or MITRE
//! technique, what artifacts to examine next, in what order, and why.

/// One step in an investigation playbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InvestigationStep {
    /// Catalog artifact ID to examine.
    pub artifact_id: &'static str,
    /// Why this step matters in context.
    pub rationale: &'static str,
    /// What specific indicators or values to look for.
    pub look_for: &'static str,
    /// Artifact IDs that become relevant if this step yields results.
    pub unlocks: &'static [&'static str],
}

/// A directed investigation path for a specific scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InvestigationPath {
    /// Unique playbook identifier.
    pub id: &'static str,
    /// What triggers this path (artifact ID or MITRE technique).
    pub trigger: &'static str,
    /// Human-readable scenario name.
    pub name: &'static str,
    /// Ordered investigation steps.
    pub steps: &'static [InvestigationStep],
    /// ATT&CK tactics this path covers.
    pub tactics_covered: &'static [&'static str],
    /// Brief description of the scenario.
    pub description: &'static str,
}

pub static PLAYBOOKS: &[InvestigationPath] = &[
    InvestigationPath {
        id: "lateral_movement_rdp",
        trigger: "rdp_client_servers",
        name: "Lateral Movement via RDP",
        description: "Investigate RDP-based lateral movement: source, destination, credentials used, and post-exploitation activity.",
        tactics_covered: &["TA0008", "TA0003"],
        steps: &[
            InvestigationStep {
                artifact_id: "rdp_client_servers",
                rationale: "Establishes which hosts were connected TO from this machine.",
                look_for: "Unfamiliar internal IPs, jump hosts, sequential targeting pattern.",
                unlocks: &["evtx_security", "lnk_files"],
            },
            InvestigationStep {
                artifact_id: "networklist_profiles",
                rationale: "Identifies networks the machine connected to; corroborates RDP destinations.",
                look_for: "Network names matching target subnets.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "Event 4624 Type 10 = RemoteInteractive logon; 4648 = explicit credential use.",
                look_for: "4624 with LogonType=10, 4648 with target server matching RDP MRU entries.",
                unlocks: &["dpapi_masterkey_user", "lsa_secrets"],
            },
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "mstsc.exe prefetch proves local RDP client was run and when.",
                look_for: "MSTSC.EXE-*.pf with timestamps matching logon events.",
                unlocks: &["jump_list_auto"],
            },
            InvestigationStep {
                artifact_id: "jump_list_auto",
                rationale: "mstsc.exe jump list may contain target hostnames.",
                look_for: "Recent items in mstsc jump list; correlate with Security log.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "bam_user",
                rationale: "Background Activity Monitor records last execution time for mstsc.exe.",
                look_for: "mstsc.exe entry with timestamp matching attack window.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "credential_harvesting",
        trigger: "lsa_secrets",
        name: "Credential Harvesting",
        description: "Investigate credential theft: which credentials were targeted, how they were extracted, and what access was gained.",
        tactics_covered: &["TA0006"],
        steps: &[
            InvestigationStep {
                artifact_id: "lsa_secrets",
                rationale: "Service account passwords and cached domain credentials stored in SYSTEM hive.",
                look_for: "Unexpected service credentials, recently modified LSA secrets.",
                unlocks: &["dpapi_masterkey_user", "dcc2_cache"],
            },
            InvestigationStep {
                artifact_id: "dpapi_masterkey_user",
                rationale: "Master keys protect DPAPI-encrypted credentials; attacker may target these.",
                look_for: "Master key access events, unusual modification timestamps.",
                unlocks: &["dpapi_cred_user", "chrome_login_data"],
            },
            InvestigationStep {
                artifact_id: "dpapi_cred_user",
                rationale: "Encrypted credential blobs for Windows Credential Manager.",
                look_for: "Credential blobs accessed/modified outside normal user session.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "dcc2_cache",
                rationale: "Cached domain credentials allow offline cracking without DC access.",
                look_for: "Presence of domain admin account hashes in cache.",
                unlocks: &["ntds_dit"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "4672=Special logon, 4768/4769=Kerberos TGT/service ticket requests.",
                look_for: "4672 for admin accounts, 4768 with RC4 encryption (downgrade attack).",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "sam_users",
                rationale: "Local account hashes; attacker with SYSTEM can extract all local credentials.",
                look_for: "Unusual local admin accounts, recently created accounts.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "persistence_hunt",
        trigger: "run_key_hklm",
        name: "Persistence Mechanism Hunt",
        description: "Systematic enumeration of persistence mechanisms: registry autoruns, services, scheduled tasks, and boot persistence.",
        tactics_covered: &["TA0003"],
        steps: &[
            InvestigationStep {
                artifact_id: "run_key_hklm",
                rationale: "HKLM Run key executes entries for all users at login.",
                look_for: "Unsigned executables, unusual paths (Temp, AppData, Downloads).",
                unlocks: &["run_key_hkcu", "prefetch_file"],
            },
            InvestigationStep {
                artifact_id: "run_key_hkcu",
                rationale: "HKCU Run key executes entries for the current user at login.",
                look_for: "Same suspicious patterns; note which user profile.",
                unlocks: &["shellbags_user"],
            },
            InvestigationStep {
                artifact_id: "active_setup_hklm",
                rationale: "Active Setup runs per-user first login; abused for persistence after privilege escalation.",
                look_for: "StubPath values pointing to unusual executables.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "winlogon_shell",
                rationale: "Shell value replaces or supplements explorer.exe at login.",
                look_for: "Any value other than 'explorer.exe' is highly suspicious.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "boot_execute",
                rationale: "Runs before Windows subsystem initializes; used by rootkits.",
                look_for: "Anything other than 'autocheck autochk *' is suspicious.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "appinit_dlls",
                rationale: "DLLs injected into every process loading user32.dll.",
                look_for: "Any non-empty value; verify each DLL is signed.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "ifeo_debugger",
                rationale: "IFEO Debugger hijacks process execution at launch.",
                look_for: "Debugger pointing to malware or cmd.exe for accessibility binary hijack.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "com_hijack_clsid_hkcu",
                rationale: "HKCU CLSID overrides load user-controlled DLLs without UAC.",
                look_for: "CLSIDs in HKCU overriding HKLM entries; unsigned DLL paths.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "scheduled_tasks_dir",
                rationale: "Scheduled tasks provide persistence with flexible triggers.",
                look_for: "Tasks with random/GUID names, tasks running from Temp or AppData.",
                unlocks: &["evtx_security"],
            },
            InvestigationStep {
                artifact_id: "services_imagepath",
                rationale: "Services run as SYSTEM; malware frequently registers services.",
                look_for: "Services with ImagePath in non-standard locations, recently created.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "data_exfiltration",
        trigger: "chrome_login_data",
        name: "Data Exfiltration Investigation",
        description: "Investigate data exfiltration: what was accessed, staged, and sent where.",
        tactics_covered: &["TA0010", "TA0009"],
        steps: &[
            InvestigationStep {
                artifact_id: "chrome_login_data",
                rationale: "Browser credentials stolen first to access additional resources.",
                look_for: "Access timestamps on login.db outside normal business hours.",
                unlocks: &["firefox_logins"],
            },
            InvestigationStep {
                artifact_id: "network_drives",
                rationale: "Mapped network shares may be staging areas or exfiltration targets.",
                look_for: "Unusual drive mappings, external/cloud share paths.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "usn_journal",
                rationale: "USN journal records file create/modify/delete; reveals staging activity.",
                look_for: "Bulk file copy operations, archive creation (zip/rar/7z), large file moves.",
                unlocks: &["recycle_bin"],
            },
            InvestigationStep {
                artifact_id: "recycle_bin",
                rationale: "Deleted files after exfiltration may still be in Recycle Bin.",
                look_for: "Deleted archives, bulk deletions after staging window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "lnk_files",
                rationale: "LNK files created when files are opened; proves attacker accessed specific files.",
                look_for: "LNK files pointing to sensitive documents, unusual file paths.",
                unlocks: &["jump_list_auto"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "5140/5145 = network share access events; proves remote file access.",
                look_for: "5145 with sensitive share names accessed by unfamiliar accounts.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "execution_trace",
        trigger: "prefetch_file",
        name: "Malware Execution Trace",
        description: "Reconstruct malware execution: what ran, when, from where, and what it accessed.",
        tactics_covered: &["TA0002"],
        steps: &[
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "Definitive execution proof; records run count, last run time, and loaded DLLs.",
                look_for: "Unknown executables, tools run from Temp/Downloads, single-run counts.",
                unlocks: &["shimcache", "amcache_app_file"],
            },
            InvestigationStep {
                artifact_id: "shimcache",
                rationale: "Records all executables that touched shimcache; proves file existed on disk.",
                look_for: "Files in Prefetch not in Shimcache (deleted after run).",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "amcache_app_file",
                rationale: "Records SHA1 hash of executed files; enables hash lookup even if file deleted.",
                look_for: "Hash lookups on VirusTotal for any matches in Prefetch.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "userassist_exe",
                rationale: "GUI application launches with run count and timestamp.",
                look_for: "Unusual GUI tools (network scanners, dumpers) launched by user.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "bam_user",
                rationale: "Background Activity Monitor; precise last execution time per binary.",
                look_for: "Execution times outside business hours, correlation with other timestamps.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "4688 = process creation (if audit policy enabled); 4689 = process exit.",
                look_for: "4688 events for malware executables; CommandLine field if enabled.",
                unlocks: &["evtx_sysmon"],
            },
            InvestigationStep {
                artifact_id: "evtx_sysmon",
                rationale: "Sysmon Event 1 = process creation with full command line and hashes.",
                look_for: "Sysmon 1 for malware hashes; Sysmon 3 for network connections; Sysmon 11 for file drops.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "defense_evasion",
        trigger: "usn_journal",
        name: "Defense Evasion Detection",
        description: "Detect anti-forensic actions: log clearing, timestomping, prefetch disabling, and tool deletion.",
        tactics_covered: &["TA0005"],
        steps: &[
            InvestigationStep {
                artifact_id: "evtx_system",
                rationale: "Event 104 = Security log cleared (or any channel cleared from System).",
                look_for: "Event 104 or 1102; gap in event timestamps indicates clearing.",
                unlocks: &["evtx_security"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "Event 1102 = audit log cleared; compare log size and oldest event timestamp.",
                look_for: "Event 1102; compare oldest event time against known attack window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "usn_journal",
                rationale: "USN journal deletions may catch tool cleanup (attacker deleting malware).",
                look_for: "File deletions immediately after execution events; *.exe, *.ps1 in Temp.",
                unlocks: &["recycle_bin"],
            },
            InvestigationStep {
                artifact_id: "mft_file",
                rationale: "Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps; differences indicate timestomping.",
                look_for: "$SI Create before $FN Create; $SI earlier than Volume Create = timestomped.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "Missing Prefetch for known tools may indicate anti-forensics (folder cleared or disabled).",
                look_for: "Check HKLM\\SYSTEM\\...\\PrefetchParameters\\EnablePrefetcher = 0 (disabled).",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "ransomware",
        trigger: "ransomware",
        name: "Ransomware Investigation",
        description: "Collection and analysis checklist for a ransomware incident. \
            RFC 3227 order: volatile first, then persistent artifacts. \
            Focus: encryption timeline, initial access, lateral movement, anti-forensics.",
        tactics_covered: &["TA0040", "TA0001", "TA0008", "TA0005"],
        steps: &[
            InvestigationStep {
                artifact_id: "mft",
                rationale: "$MFT records every file creation, modification, and deletion. \
                    Encrypted files show a mass-modification wave in $SI timestamps. \
                    Compare $SI vs $FN timestamps to detect timestomping before encryption.",
                look_for: "Mass $SI modification timestamps within a tight window (minutes). \
                    Files in %TEMP%, %APPDATA%, Recycle Bin created just before encryption. \
                    New filenames matching ransom note patterns (HOW_TO_DECRYPT, RECOVER_*).",
                unlocks: &["usnjrnl", "recycle_bin"],
            },
            InvestigationStep {
                artifact_id: "usnjrnl",
                rationale: "$UsnJrnl:$J logs every file-system operation with reason codes. \
                    FILE_CREATE + FILE_DELETE bursts identify the staging and encryption sweep.",
                look_for: "Bulk RENAME_OLD_NAME entries (attacker renaming original files). \
                    FILE_DELETE immediately after FILE_CREATE (encrypt-then-delete pattern). \
                    Tool cleanup: malware executable deleted after encryption completes.",
                unlocks: &["mft"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "Event 4688 = process creation (if audited). \
                    4624/4625 = logon success/failure — establishes attack timeline. \
                    4648 = explicit credential use (attacker moving laterally before encryption).",
                look_for: "4688 for ransomware binary process name. \
                    4648 targeting file servers (attacker encrypting network shares). \
                    4624 LogonType 3 (network) from unfamiliar hosts before encryption wave.",
                unlocks: &["evtx_sysmon", "prefetch_file"],
            },
            InvestigationStep {
                artifact_id: "evtx_system",
                rationale: "Event 7045 = new service installed. \
                    1102/104 = log clearing (attacker removing evidence after encryption). \
                    6005/6006 = system start/stop (forced reboots to apply encryption).",
                look_for: "Service installations in the attack window (PsExec creates services). \
                    Log clearing event before or after encryption. \
                    Multiple reboots during off-hours.",
                unlocks: &["services_imagepath"],
            },
            InvestigationStep {
                artifact_id: "vss_files_not_to_backup",
                rationale: "Ransomware frequently adds exclusions to prevent VSS from \
                    backing up files it is about to encrypt, or deletes shadow copies entirely.",
                look_for: "Additions to FilesNotToBackup or FilesNotToSnapshot registry keys. \
                    vssadmin delete shadows /all in prefetch or event logs. \
                    wmic shadowcopy delete in PowerShell history.",
                unlocks: &["psreadline_history"],
            },
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "Prefetch proves the ransomware binary executed and records \
                    the exact timestamp of first and last run plus all DLLs loaded.",
                look_for: "Unknown executable with single run count (execute-and-delete). \
                    Tools: vssadmin.exe, wbadmin.exe, bcdedit.exe (shadow/backup deletion). \
                    Dual-use: net.exe, whoami.exe, ipconfig.exe (recon before encryption).",
                unlocks: &["amcache_app_file", "shimcache"],
            },
            InvestigationStep {
                artifact_id: "recycle_bin",
                rationale: "Ransomware may stage or briefly store files in Recycle Bin. \
                    Attacker tools deleted post-encryption sometimes land here.",
                look_for: "Deleted executables, scripts, or configuration files. \
                    Deletion timestamps coinciding with the encryption window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "run_key_hklm",
                rationale: "Ransomware may establish persistence to resume encryption \
                    after reboots (common in multi-stage ransomware like LockBit).",
                look_for: "Entries added to HKLM\\Run or RunOnce during the attack window. \
                    Unusual executable paths in Temp, AppData, or ProgramData.",
                unlocks: &["run_key_hkcu", "scheduled_tasks_dir"],
            },
            InvestigationStep {
                artifact_id: "windows_defender_disabled_av",
                rationale: "Most ransomware disables Windows Defender before encrypting. \
                    Registry key changes leave forensic evidence even if logs were cleared.",
                look_for: "DisableAntiVirus=1 or DisableRealtimeMonitoring=1. \
                    Check modification timestamp against known attack window.",
                unlocks: &["windows_defender_exclusions_local"],
            },
            InvestigationStep {
                artifact_id: "srum_db",
                rationale: "SRUM records hourly CPU, network, and storage usage per process. \
                    Ransomware encryption produces a spike in disk write activity.",
                look_for: "Process with massive disk write activity in the attack window. \
                    Network bytes sent from an unknown process (exfiltration before encryption).",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "data_breach",
        trigger: "data_breach",
        name: "Data Exfiltration / Breach Investigation",
        description: "What was accessed, staged, compressed, and sent where. \
            Focus: data staging, exfil mechanisms, cloud sync abuse, and browser credential theft.",
        tactics_covered: &["TA0010", "TA0009", "TA0006"],
        steps: &[
            InvestigationStep {
                artifact_id: "usnjrnl",
                rationale: "USN journal records bulk file copies and archive creation. \
                    Staging activity shows mass FILE_CREATE events for compressed archives.",
                look_for: "Bulk file copy operations. ZIP/RAR/7z archive creation. \
                    Files staged in unusual locations (Desktop, Temp, USB mount points).",
                unlocks: &["recycle_bin", "lnk_files"],
            },
            InvestigationStep {
                artifact_id: "lnk_files",
                rationale: "Windows creates LNK files when files are opened. \
                    Proves attacker accessed specific sensitive files.",
                look_for: "LNK files pointing to sensitive documents (PII, financials, source code). \
                    Unusual file paths: HR shares, exec folders, R&D directories.",
                unlocks: &["jump_list_auto"],
            },
            InvestigationStep {
                artifact_id: "chrome_login_data",
                rationale: "Browser credential store is a primary target for credential theft. \
                    Modification timestamp outside working hours is highly suspicious.",
                look_for: "SQLite access timestamp outside normal user session. \
                    Logins.json copies staged elsewhere.",
                unlocks: &["firefox_logins"],
            },
            InvestigationStep {
                artifact_id: "network_drives",
                rationale: "Mapped drives reveal staging areas and potential exfil targets. \
                    External cloud share mappings indicate attacker-controlled endpoints.",
                look_for: "Drive letters mapped to external or unusual UNC paths. \
                    New drive mappings created during the attack window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "onedrive_metadata",
                rationale: "OneDrive sync automatically exfiltrates staged files. \
                    Metadata database records which files were synced and when.",
                look_for: "Files synced to OneDrive outside normal business hours. \
                    Bulk sync of sensitive directories.",
                unlocks: &["google_drive_fs_metadata"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "5140/5145 = network share access events. \
                    4663 = file access audit (if configured). \
                    4648 = explicit credential use to access remote shares.",
                look_for: "5145 with sensitive share names accessed from unfamiliar accounts. \
                    Bulk file reads from a single process in a short window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "srum_network_usage",
                rationale: "SRUM tracks bytes sent per process per hour. \
                    Large outbound bytes from a non-network process = exfiltration.",
                look_for: "Unusual process with > 100MB sent in a single SRUM interval. \
                    Process name does not match a known network application.",
                unlocks: &["srum_db"],
            },
        ],
    },
    InvestigationPath {
        id: "bec",
        trigger: "bec",
        name: "Business Email Compromise (BEC) Investigation",
        description: "Account takeover, inbox manipulation, and financial fraud. \
            Focus: authentication anomalies, mail rules, forwarding, and browser artifacts.",
        tactics_covered: &["TA0001", "TA0006", "TA0009"],
        steps: &[
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "4624 with LogonType 8 (NetworkCleartext) or Type 10 (RemoteInteractive) \
                    from anomalous source IPs indicates credential compromise.",
                look_for: "Failed logins (4625) followed by successful login (4624) from same IP. \
                    Logons from unexpected geographic locations (requires IP correlation). \
                    New browser session outside known working hours.",
                unlocks: &["chrome_login_data"],
            },
            InvestigationStep {
                artifact_id: "chrome_login_data",
                rationale: "Compromised email accounts often have credentials saved in the browser. \
                    Credential theft precedes or accompanies email account takeover.",
                look_for: "SQLite access timestamps during the suspected compromise window. \
                    Saved credentials for O365, banking portals, or payment systems.",
                unlocks: &["firefox_logins"],
            },
            InvestigationStep {
                artifact_id: "networklist_profiles",
                rationale: "Records network names (including mobile hotspot names) the machine \
                    connected to. Attacker-controlled hotspots leave a distinct profile name.",
                look_for: "Network names not matching the corporate environment. \
                    Profile timestamps correlating with the suspect logon window.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "psreadline_history",
                rationale: "PowerShell command history reveals O365/Exchange manipulation. \
                    BEC actors use PowerShell to set inbox rules and forwarding.",
                look_for: "Set-InboxRule, New-TransportRule, Set-Mailbox ForwardingSmtpAddress. \
                    Connect-ExchangeOnline from an unusual host or account.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "MFA bypass tools (Evilginx, Modlishka) or email-scraping tools \
                    leave prefetch entries if run locally.",
                look_for: "Unknown executables run during the suspect window. \
                    Credential-dumping tools: mimikatz.exe, procdump.exe, pypykatz.",
                unlocks: &["amcache_app_file"],
            },
            InvestigationStep {
                artifact_id: "lnk_files",
                rationale: "LNK files in the user profile reveal which files the actor opened \
                    after gaining access — financial data, org charts, email templates.",
                look_for: "LNK files pointing to financial, HR, or executive documents \
                    opened outside normal hours or from an unusual path.",
                unlocks: &[],
            },
        ],
    },
    InvestigationPath {
        id: "insider",
        trigger: "insider",
        name: "Insider Threat Investigation",
        description: "Unauthorised data access, IP theft, or sabotage by a current or former employee. \
            Focus: data access patterns, removable media, cloud sync, and communication channels.",
        tactics_covered: &["TA0010", "TA0009"],
        steps: &[
            InvestigationStep {
                artifact_id: "usb_enum",
                rationale: "USBSTOR registry key records every USB storage device ever connected. \
                    Device serial numbers map to specific hardware owned by the insider.",
                look_for: "USB devices connected outside business hours or during the suspect window. \
                    Devices not in the approved device list.",
                unlocks: &["setupapi_dev_log", "mountpoints2"],
            },
            InvestigationStep {
                artifact_id: "lnk_files",
                rationale: "LNK files prove specific files were opened and provide timestamps. \
                    Cross-reference with file servers to identify what data was accessed.",
                look_for: "Sensitive documents (IP, PII, customer data, source code). \
                    Files accessed shortly before resignation or termination notice.",
                unlocks: &["jump_list_auto"],
            },
            InvestigationStep {
                artifact_id: "onedrive_metadata",
                rationale: "Personal cloud sync (OneDrive personal, Google Drive, MEGA, Dropbox, Box) \
                    is the most common exfiltration path for insiders. Each client leaves \
                    metadata artifacts. Corporate DLP rarely inspects personal sync traffic, \
                    and MEGA uses end-to-end encryption that proxy inspection cannot see.",
                look_for: "OneDrive: onedrive_metadata — sync DB, check personal vs corporate account path. \
                    Google Drive: google_drive_fs_metadata — content_cache.db, metadata_sqlite_db. \
                    MEGA: megasync_data — MEGAsync profile, sync timestamps. \
                    Dropbox: %APPDATA%\\Dropbox\\info.json — account type (personal vs business). \
                    Any bulk sync activity during off-hours or in the weeks before departure.",
                unlocks: &["google_drive_fs_metadata", "megasync_data"],
            },
            InvestigationStep {
                artifact_id: "usnjrnl",
                rationale: "USN journal reconstructs file staging activity. \
                    Archive creation before USB insertion or cloud sync = deliberate staging.",
                look_for: "ZIP/RAR/7z creation followed by USB device attach within minutes. \
                    Bulk file copies to Desktop or temp folder.",
                unlocks: &["recycle_bin"],
            },
            InvestigationStep {
                artifact_id: "evtx_security",
                rationale: "5145 = network share file access. 4663 = object access (if audited). \
                    Bulk access to shares outside the employee's normal job function.",
                look_for: "File server share access for directories unrelated to the employee's role. \
                    Access during non-working hours (pre-dawn, weekends).",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "srum_network_usage",
                rationale: "SRUM tracks bytes sent per process. \
                    Large outbound bytes correlating with USB events = staging + exfil.",
                look_for: "Browser or sync agent with abnormally high upload bytes. \
                    Process correlation: which application was sending data.",
                unlocks: &["srum_db"],
            },
        ],
    },
    InvestigationPath {
        id: "supply_chain",
        trigger: "supply_chain",
        name: "Supply Chain Compromise Investigation",
        description: "Malicious software delivered via a trusted vendor update or build pipeline. \
            Focus: installation artifacts, software inventory, code signing, and lateral movement after.",
        tactics_covered: &["TA0001", "TA0003", "TA0008"],
        steps: &[
            InvestigationStep {
                artifact_id: "amcache_app_file",
                rationale: "AmCache records SHA1 hash of every file that touched the cache. \
                    The hash identifies the exact malicious binary even if deleted.",
                look_for: "Hash lookup on VirusTotal for any software installed in the suspect window. \
                    Version mismatch: same filename as a known good binary but different hash.",
                unlocks: &["shimcache"],
            },
            InvestigationStep {
                artifact_id: "prefetch_file",
                rationale: "Prefetch proves the software ran and records DLLs it loaded. \
                    Malicious updates often side-load a weaponized DLL alongside the installer.",
                look_for: "Installer executable with unexpected DLL references. \
                    Execution of the compromised software at the time of the first malicious action.",
                unlocks: &["evtx_sysmon"],
            },
            InvestigationStep {
                artifact_id: "evtx_sysmon",
                rationale: "Sysmon 1 = process creation with full command line and parent process. \
                    Sysmon 7 = image loaded. Sysmon 11 = file created. \
                    Supply chain payloads spawn unexpected child processes from trusted parents.",
                look_for: "Trusted parent process (solarwinds.exe, 3cx.exe) spawning cmd.exe, \
                    powershell.exe, or network tools. DNS queries to unexpected domains from the process.",
                unlocks: &["networklist_profiles"],
            },
            InvestigationStep {
                artifact_id: "services_imagepath",
                rationale: "Supply chain implants often register as services for persistence. \
                    Service ImagePath in a non-standard location is a strong indicator.",
                look_for: "Services pointing to the compromised vendor software directory. \
                    Service names matching the vendor product but ImagePath is different.",
                unlocks: &["scheduled_tasks_dir"],
            },
            InvestigationStep {
                artifact_id: "networklist_profiles",
                rationale: "Records C2 domains resolved as network names in some environments. \
                    More importantly: identifies new external connections after software installation.",
                look_for: "Network connections to unknown external hosts originating from the \
                    compromised software. DNS-over-HTTPS usage to bypass proxy logs.",
                unlocks: &[],
            },
            InvestigationStep {
                artifact_id: "run_key_hklm",
                rationale: "Supply chain implants may add persistence via Run keys alongside \
                    the legitimate software. The key timestamp reveals the implant installation time.",
                look_for: "Run key entries added at the same time as the compromised software update. \
                    Entries with the same vendor name but pointing to a different binary.",
                unlocks: &["scheduled_tasks_dir"],
            },
        ],
    },
];

/// Returns all scenario playbooks (ransomware, data-breach, bec, insider, supply-chain).
/// These are structured collection checklists, not artifact-triggered paths.
pub fn scenario_playbooks() -> Vec<&'static InvestigationPath> {
    PLAYBOOKS
        .iter()
        .filter(|pb| {
            matches!(
                pb.id,
                "ransomware" | "data_breach" | "bec" | "insider" | "supply_chain"
            )
        })
        .collect()
}

/// Returns the playbook with the given ID.
pub fn playbook_by_id(id: &str) -> Option<&'static InvestigationPath> {
    PLAYBOOKS.iter().find(|p| p.id == id)
}

/// Returns all playbooks whose trigger matches the given artifact ID or MITRE technique.
pub fn playbooks_for_trigger(trigger: &str) -> Vec<&'static InvestigationPath> {
    PLAYBOOKS.iter().filter(|p| p.trigger == trigger).collect()
}

/// Returns all playbooks that reference the given artifact ID in any step.
pub fn playbooks_for_artifact(artifact_id: &str) -> Vec<&'static InvestigationPath> {
    PLAYBOOKS
        .iter()
        .filter(|p| p.steps.iter().any(|s| s.artifact_id == artifact_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn six_artifact_triggered_playbooks_defined() {
        let artifact_triggered: Vec<_> = PLAYBOOKS
            .iter()
            .filter(|pb| {
                !matches!(
                    pb.id,
                    "ransomware" | "data_breach" | "bec" | "insider" | "supply_chain"
                )
            })
            .collect();
        assert_eq!(
            artifact_triggered.len(),
            6,
            "Expected 6 artifact-triggered playbooks"
        );
    }

    #[test]
    fn path_by_id_works() {
        let pb = path_by_id("lateral_movement").expect("lateral_movement path must exist");
        assert!(!pb.steps.is_empty());
        assert!(!pb.tactics_covered.is_empty());
    }

    #[test]
    fn paths_for_trigger_rdp() {
        let pbs = paths_for_trigger("rdp_client_servers");
        assert!(
            !pbs.is_empty(),
            "Should find paths triggered by rdp_client_servers"
        );
    }

    #[test]
    fn playbooks_for_artifact_evtx_security() {
        let pbs = playbooks_for_artifact("evtx_security");
        assert!(
            pbs.len() >= 2,
            "evtx_security should appear in multiple playbooks"
        );
    }

    #[test]
    fn all_step_artifact_ids_exist_in_catalog() {
        for pb in PLAYBOOKS {
            for step in pb.steps {
                assert!(
                    CATALOG.by_id(step.artifact_id).is_some(),
                    "playbook '{}' step references unknown artifact: {}",
                    pb.id,
                    step.artifact_id
                );
            }
        }
    }

    #[test]
    fn all_unlocks_reference_valid_artifacts() {
        for pb in PLAYBOOKS {
            for step in pb.steps {
                for unlocked_id in step.unlocks {
                    assert!(
                        CATALOG.by_id(unlocked_id).is_some(),
                        "playbook '{}' step '{}' unlocks unknown artifact: {}",
                        pb.id,
                        step.artifact_id,
                        unlocked_id
                    );
                }
            }
        }
    }

    #[test]
    fn all_playbooks_have_nonempty_steps_and_tactics() {
        for pb in PLAYBOOKS {
            assert!(!pb.steps.is_empty(), "Playbook '{}' has no steps", pb.id);
            assert!(
                !pb.tactics_covered.is_empty(),
                "Playbook '{}' has no tactics",
                pb.id
            );
            assert!(
                !pb.description.is_empty(),
                "Playbook '{}' has no description",
                pb.id
            );
        }
    }

    #[test]
    fn unknown_playbook_returns_none() {
        assert!(playbook_by_id("does_not_exist").is_none());
    }

    // ── scenario playbooks ────────────────────────────────────────────────────

    #[test]
    fn playbooks_contains_only_five_scenarios() {
        assert_eq!(
            PLAYBOOKS.len(),
            5,
            "PLAYBOOKS must contain exactly the 5 scenario checklists"
        );
    }

    #[test]
    fn investigation_paths_contains_six_artifact_triggered() {
        assert_eq!(
            INVESTIGATION_PATHS.len(),
            6,
            "INVESTIGATION_PATHS must contain the 6 artifact-triggered paths"
        );
    }

    #[test]
    fn ransomware_playbook_exists_and_has_steps() {
        let pb = playbook_by_id("ransomware").expect("ransomware playbook must exist");
        assert!(pb.steps.len() >= 6, "ransomware must have at least 6 steps");
    }

    #[test]
    fn data_breach_playbook_exists() {
        assert!(playbook_by_id("data_breach").is_some());
    }

    #[test]
    fn bec_playbook_exists() {
        assert!(playbook_by_id("bec").is_some());
    }

    #[test]
    fn insider_playbook_exists() {
        assert!(playbook_by_id("insider").is_some());
    }

    #[test]
    fn supply_chain_playbook_exists() {
        assert!(playbook_by_id("supply_chain").is_some());
    }

    #[test]
    fn ransomware_playbook_covers_mft_and_usnjrnl() {
        let pb = playbook_by_id("ransomware").expect("ransomware playbook must exist");
        let ids: Vec<&str> = pb.steps.iter().map(|s| s.artifact_id).collect();
        assert!(ids.contains(&"mft"), "ransomware must check $MFT");
        assert!(ids.contains(&"usnjrnl"), "ransomware must check $UsnJrnl");
    }

    #[test]
    fn scenario_playbooks_steps_all_valid_catalog_ids() {
        for pb in PLAYBOOKS {
            for step in pb.steps {
                assert!(
                    CATALOG.by_id(step.artifact_id).is_some(),
                    "playbook '{}' step references unknown artifact: {}",
                    pb.id,
                    step.artifact_id
                );
            }
        }
    }

    #[test]
    fn investigation_paths_steps_all_valid_catalog_ids() {
        for path in INVESTIGATION_PATHS {
            for step in path.steps {
                assert!(
                    CATALOG.by_id(step.artifact_id).is_some(),
                    "investigation path '{}' step references unknown artifact: {}",
                    path.id,
                    step.artifact_id
                );
            }
        }
    }

    #[test]
    fn lateral_movement_is_investigation_path_not_playbook() {
        assert!(
            INVESTIGATION_PATHS.iter().any(|p| p.id == "lateral_movement"),
            "lateral_movement must be in INVESTIGATION_PATHS"
        );
        assert!(
            !PLAYBOOKS.iter().any(|p| p.id == "lateral_movement"),
            "lateral_movement must NOT be in PLAYBOOKS"
        );
    }

    #[test]
    fn persistence_is_investigation_path_not_playbook() {
        assert!(
            INVESTIGATION_PATHS.iter().any(|p| p.id == "persistence"),
            "persistence must be in INVESTIGATION_PATHS (not persistence_hunt)"
        );
        assert!(
            !PLAYBOOKS.iter().any(|p| p.id == "persistence"),
            "persistence must NOT be in PLAYBOOKS"
        );
    }
}
