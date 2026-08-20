//! Extended Windows registry artifact descriptors.
//!
//! Sourced from: RECmd batch files (EricZimmerman), Sysinternals Autoruns,
//! libyal/winreg-kb, SigmaHQ registry rules, Hayabusa field mappings.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── Autoruns gaps: persistence locations not yet in catalog ──────────────────

pub(crate) static SAFEBOOT_MINIMAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "safeboot_minimal",
    name: "SafeBoot Minimal Services",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\SafeBoot\\Minimal",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Defines which drivers and services run in Safe Mode (Minimal). Malware registers here to persist through Safe Mode boots, bypassing endpoint security tools that don't load in Safe Mode.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema { name: "service_name", value_type: ValueType::Text, description: "Service/driver name permitted in Safe Mode", is_uid_component: true }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["services_imagepath", "boot_execute"],
    sources: &[
        "https://www.microsoftpressstore.com/articles/article.aspx?p=2762082",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some legitimate security tools (AV, EDR) also register here"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static SAFEBOOT_NETWORK: ArtifactDescriptor = ArtifactDescriptor {
    id: "safeboot_network",
    name: "SafeBoot Network Services",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\SafeBoot\\Network",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Defines services permitted in Safe Mode with Networking. Attacker-registered services here persist through Safe Mode boots with network access, enabling C2 communication while endpoint tools are disabled.",
    mitre_techniques: &["T1547.001"],
    fields: &[FieldSchema { name: "service_name", value_type: ValueType::Text, description: "Service/driver name permitted in Safe Mode with Networking", is_uid_component: true }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["safeboot_minimal", "services_imagepath"],
    sources: &[
        "https://www.microsoftpressstore.com/articles/article.aspx?p=2762082",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some legitimate networking and security drivers also register here"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static KNOWN_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "known_dlls",
    name: "KnownDLLs",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Lists DLLs pre-loaded into \\KnownDlls object namespace to speed startup and prevent DLL search-order hijacking. Removing a DLL from this list re-enables search-order hijacking for that library.",
    mitre_techniques: &["T1574.001"],
    fields: &[FieldSchema { name: "dll_name", value_type: ValueType::Text, description: "DLL name mapped into KnownDlls namespace", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["services_imagepath"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Modifications to KnownDLLs are rare; baseline comparison required"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static CMD_AUTORUN_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "cmd_autorun_hklm",
    name: "Command Processor AutoRun (HKLM)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Command Processor",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AutoRun value under Command Processor executes a command every time cmd.exe starts system-wide. Used by attackers to maintain persistence and execute payloads whenever a shell is opened.",
    mitre_techniques: &["T1059.003", "T1547.001"],
    fields: &[FieldSchema { name: "autorun_command", value_type: ValueType::Text, description: "Command executed on every cmd.exe launch (system-wide)", is_uid_component: true }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["cmd_autorun_hkcu", "run_key_hklm"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some legitimate enterprise scripts and developer tooling configure AutoRun"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit deletion",
};

pub(crate) static CMD_AUTORUN_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "cmd_autorun_hkcu",
    name: "Command Processor AutoRun (HKCU)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Command Processor",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user AutoRun value executed on every cmd.exe launch. Lower-privilege equivalent of the HKLM variant; easier for non-admin attackers to set.",
    mitre_techniques: &["T1059.003", "T1547.001"],
    fields: &[FieldSchema { name: "autorun_command", value_type: ValueType::Text, description: "Command executed on every cmd.exe launch (per user)", is_uid_component: true }],
    retention: Some("Persistent until registry modification"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["cmd_autorun_hklm", "run_key_hkcu"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some developer environments and aliases configure AutoRun benignly"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit deletion",
};

pub(crate) static CREDENTIAL_PROVIDERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "credential_providers",
    name: "Credential Providers",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Registers credential provider DLLs used at the Windows logon screen. Attackers register malicious credential providers to capture plaintext credentials or bypass authentication entirely (T1556.001).",
    mitre_techniques: &["T1556.001"],
    fields: &[FieldSchema { name: "provider_clsid", value_type: ValueType::Text, description: "CLSID of the registered credential provider", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["lsa_auth_pkgs", "lsa_security_pkgs"],
    sources: &[
        "https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Registry key; may be modified by legitimate security products"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until deleted",
};

pub(crate) static NETWORK_PROVIDER_ORDER: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_provider_order",
    name: "Network Provider Order",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\NetworkProvider\\Order",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Controls the order in which network providers (including credential managers) are queried. A malicious network provider DLL registered here intercepts credentials for every network authentication attempt.",
    mitre_techniques: &["T1556", "T1003"],
    fields: &[FieldSchema { name: "provider_order", value_type: ValueType::Text, description: "Comma-separated list of network provider names in query order", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["credential_providers", "lsa_auth_pkgs"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Enterprise SSO and credential manager extensions legitimately add network providers"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static SHELL_EXECUTE_HOOKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "shell_execute_hooks",
    name: "Shell Execute Hooks",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "COM objects registered as ShellExecuteHooks are invoked for every ShellExecute call. Malicious hooks intercept application launches and can spawn additional processes or modify execution.",
    mitre_techniques: &["T1546.013"],
    fields: &[FieldSchema { name: "clsid", value_type: ValueType::Text, description: "CLSID of the registered ShellExecuteHook COM object", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["com_hijack_clsid_hkcu", "browser_helper_objects"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["A small number of legitimate shell extensions register here"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static WER_RUNTIME_EXCEPTION_HELPER: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_runtime_exception_helper",
    name: "WER RuntimeExceptionHelperModules",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows\\Windows Error Reporting\\RuntimeExceptionHelperModules",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "DLLs registered here are loaded by WER into any crashing process as a debugger helper. Malicious entries execute arbitrary code in the context of crashed processes — a covert DLL injection technique.",
    mitre_techniques: &["T1574.002"],
    fields: &[FieldSchema { name: "helper_dll_path", value_type: ValueType::Text, description: "Full path of the registered WER helper DLL", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ifeo_debugger"],
    sources: &[
        "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Rare legitimate registrations exist — baseline against clean image"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static IFEO_GLOBAL_FLAG: ArtifactDescriptor = ArtifactDescriptor {
    id: "ifeo_global_flag",
    name: "IFEO GlobalFlag / .NET Profiler Abuse",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Beyond the Debugger value (already cataloged), IFEO entries with GlobalFlag=0x200 combined with COR_ENABLE_PROFILING and COR_PROFILER env vars load arbitrary DLLs into .NET processes. Used for stealthy code injection without hooking.",
    mitre_techniques: &["T1546.012", "T1055"],
    fields: &[FieldSchema { name: "process_name", value_type: ValueType::Text, description: "Target process executable name", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ifeo_debugger"],
    sources: &[
        "https://blog.xpnsec.com/hiding-your-dotnet-etw/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate developer/profiling use of GlobalFlag is possible",
        "Requires correlation with COR_PROFILER environment variables for definitive injection evidence",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static SCHEDULED_TASK_REGISTRY_CACHE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "task_guid",
        value_type: ValueType::Text,
        description: "Task GUID subkey name; used to correlate with the XML file in \
            \\Windows\\System32\\Tasks and the TaskCache\\Tree key",
        is_uid_component: true,
    },
    FieldSchema {
        name: "action_clsid",
        value_type: ValueType::Text,
        description: "COM handler CLSID embedded in the Actions binary blob for tasks \
            whose action type is ComHandler. Look up via \
            Software\\Classes\\CLSID\\{GUID}\\InprocServer32 to find the DLL. \
            Abuse: TA505 replaced the legitimate RegIdleBackup CLSID \
            {CA767AA8-9157-4604-B64B-40747123D5F2} (regidle.dll) with a malicious handler. \
            Source: windowsir.blogspot.com/2022/12/why-i-love-regripper.html",
        is_uid_component: false,
    },
    FieldSchema {
        name: "action_dll",
        value_type: ValueType::Text,
        description: "DLL path resolved from Software\\Classes\\CLSID\\{GUID}\\InprocServer32 \
            for the action_clsid value. Legitimate built-in COM handler DLLs reside in \
            %SystemRoot%\\System32; a DLL path in a user-writable directory is a strong \
            indicator of T1053.005 COM handler hijacking.",
        is_uid_component: false,
    },
];

pub(crate) static SCHEDULED_TASK_REGISTRY_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "scheduled_task_registry_cache",
    name: "Scheduled Task Registry Cache (TaskCache)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::BinaryRecord(&[]),
    meaning: "Registry cache of scheduled task definitions, complementing the XML files in \
        \\Windows\\System32\\Tasks. An attacker who creates a task via the Task Scheduler API \
        populates this cache; recovering it after XML deletion reveals ghost tasks. \
        For ComHandler tasks, the Actions binary blob contains the CLSID of the COM object \
        to invoke. Cross-reference that CLSID against Software\\Classes\\CLSID\\{GUID}\\\
        InprocServer32 to find the actual DLL — a DLL path outside System32 is a strong \
        indicator of COM handler hijacking (T1053.005). TA505 and GraceWire abused the \
        built-in RegIdleBackup task ({CA767AA8-9157-4604-B64B-40747123D5F2} → regidle.dll) \
        by replacing the task XML/registry entry with a malicious handler.",
    mitre_techniques: &["T1053.005", "T1218"],
    fields: SCHEDULED_TASK_REGISTRY_CACHE_FIELDS,
    retention: Some("Persists even if XML task file is deleted"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["scheduled_tasks_dir", "com_hijack_clsid_hkcu"],
    sources: &[
        "https://blog.jpcert.or.jp/2023/06/task-scheduler.html",
        // Source: RegIdleBackup COM handler abuse; CLSID→DLL cross-reference technique
        "https://windowsir.blogspot.com/2022/12/why-i-love-regripper.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Survives XML task file deletion; high-fidelity persistence evidence",
        "COM handler CLSID lookup requires Software hive from same acquisition; \
         cross-hive correlation needed to resolve action_dll",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry cache; survives XML task file deletion",
};

pub(crate) static GROUP_POLICY_STARTUP_SCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "group_policy_startup_scripts",
    name: "Group Policy Startup Scripts (HKLM)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Registry-backed startup scripts applied via Group Policy. Scripts here run at system startup with SYSTEM privileges. Attackers target this on domain controllers or via GPO abuse for persistent high-privilege execution.",
    mitre_techniques: &["T1037.001", "T1484.001"],
    fields: &[FieldSchema { name: "script_path", value_type: ValueType::Text, description: "Path to the startup script", is_uid_component: true }],
    retention: Some("Persistent until GPO removal"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["logon_scripts", "run_key_hklm"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789189(v=ws.11)",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Legitimate enterprise administration uses startup scripts heavily — baseline against expected GPO"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion or GPO refresh",
};

pub(crate) static GROUP_POLICY_LOGON_SCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "group_policy_logon_scripts",
    name: "Group Policy Logon Scripts (HKCU)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user Group Policy logon scripts. Execute at user logon with user privileges. Provides persistence that survives Group Policy refresh cycles.",
    mitre_techniques: &["T1037.001"],
    fields: &[FieldSchema { name: "script_path", value_type: ValueType::Text, description: "Path to the logon script", is_uid_component: true }],
    retention: Some("Persistent until GPO removal"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["group_policy_startup_scripts", "logon_scripts"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789189(v=ws.11)",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Legitimate enterprise administration uses logon scripts heavily — baseline against expected GPO"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion or GPO refresh",
};

pub(crate) static WINLOGON_NOTIFY: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_notify",
    name: "Winlogon Notification Packages",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "DLLs registered here receive Winlogon event notifications (logon, logoff, lock, unlock, shutdown). A classic rootkit/APT persistence technique; the DLL loads into winlogon.exe SYSTEM context.",
    mitre_techniques: &["T1547.004"],
    fields: &[FieldSchema { name: "notify_dll", value_type: ValueType::Text, description: "DLL registered to receive Winlogon events", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["winlogon_shell", "winlogon_userinit", "lsa_auth_pkgs"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Obsolete on Vista+; presence itself is highly suspicious"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persistent until deleted",
};

pub(crate) static COM_SERVER_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "com_server_hklm",
    name: "COM InProcServer32 (HKLM — hijackable)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Classes\\CLSID",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "System-wide COM server registrations. When a CLSID listed here is missing its DLL, an attacker who places a malicious DLL at the expected path wins the load (COM hijacking). Also covers CLSIDs with LocalServer32 pointing to executables.",
    mitre_techniques: &["T1546.015"],
    fields: &[FieldSchema { name: "clsid", value_type: ValueType::Text, description: "COM class identifier (GUID)", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["com_hijack_clsid_hkcu"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://www.hexacorn.com/blog/2013/07/04/beyond-good-ol-run-key-part-15/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Vast majority of CLSID entries are legitimate",
        "Hijack proof requires confirming missing/orphaned DLL paths or anomalous server paths",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static OFFICE_ADDINS: ArtifactDescriptor = ArtifactDescriptor {
    id: "office_addins",
    name: "Microsoft Office Add-ins Registry",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Office",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Registry entries under HKLM\\SOFTWARE\\Microsoft\\Office\\<version>\\<app>\\Addins register COM add-ins loaded into Office applications. Malicious add-ins (T1137.001) execute whenever Word, Excel, or Outlook opens — a persistent phishing-to-execution path.",
    mitre_techniques: &["T1137.001"],
    fields: &[FieldSchema { name: "addin_progid", value_type: ValueType::Text, description: "ProgID or CLSID of the registered Office add-in", is_uid_component: true }],
    retention: Some("Persistent until uninstall"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["office_normal_dotm", "com_server_hklm"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://learn.microsoft.com/en-us/office/dev/add-ins/concepts/add-in-development-best-practices",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Many legitimate productivity add-ins register here (Adobe, Grammarly, enterprise tools)"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static TERMINAL_SERVER_INITIAL_PROGRAM: ArtifactDescriptor = ArtifactDescriptor {
    id: "terminal_server_initial_program",
    name: "Terminal Server InitialProgram (RDP auto-launch)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "InitialProgram value specifies a program that auto-launches when any user connects via RDP, replacing the normal desktop. Used to force specific application launch on RDP sessions — abused for persistence or to trap users in restricted sessions.",
    mitre_techniques: &["T1021.001", "T1547"],
    fields: &[FieldSchema { name: "initial_program", value_type: ValueType::Text, description: "Program path launched automatically on RDP session start", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["rdp_client_default", "rdp_client_servers"],
    sources: &[
        "https://www.sans.org/blog/opensecurity-persistence/",
        "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Some kiosk/locked-down enterprise deployments legitimately set InitialProgram"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value; persists until explicit deletion",
};

// ── RECmd batch: user activity & execution evidence ──────────────────────────

pub(crate) static RECENTAPPS: ArtifactDescriptor = ArtifactDescriptor {
    id: "recentapps",
    name: "RecentApps (Windows 10 search history)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records recently launched applications from the Windows Start menu search. Each subkey holds the app name, executable path, launch count, and last access time. Reliable execution evidence — persists even when prefetch is disabled.",
    mitre_techniques: &["T1059"],
    fields: &[
        FieldSchema { name: "app_name", value_type: ValueType::Text, description: "Application display name", is_uid_component: true },
        FieldSchema { name: "last_access", value_type: ValueType::Timestamp, description: "Last launch timestamp", is_uid_component: false },
    ],
    retention: Some("Persists across sessions; limited count kept"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["userassist_exe", "muicache", "bam_user"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://www.magnetforensics.com/blog/artifact-profile-recentapps/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Only records apps launched via Start menu search, not all execution paths",
        "Cleared when user clears Windows search history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated per user search/launch interaction; entries rotate as new apps are launched",
};

pub(crate) static NETWORK_SHARES_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_shares_hkcu",
    name: "Network Share Mapped Drive Cache (HKCU)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Network",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user mapped network drives. Each subkey (drive letter) stores the remote UNC path, connection type, and provider. Shows lateral movement targets and data exfiltration paths via network shares.",
    mitre_techniques: &["T1021.002", "T1039"],
    fields: &[
        FieldSchema { name: "drive_letter", value_type: ValueType::Text, description: "Mapped drive letter", is_uid_component: true },
        FieldSchema { name: "remote_path", value_type: ValueType::Text, description: "UNC path of the remote share", is_uid_component: false },
    ],
    retention: Some("Persists until drive is disconnected and mapping removed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["network_drives", "mountpoints2"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Persists historical mappings even after disconnect — may represent past activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static DEFAULT_BROWSER: ArtifactDescriptor = ArtifactDescriptor {
    id: "default_browser",
    name: "Default Browser Association",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records the user's default browser via ProgID. Used for browser artifact correlation — knowing the default browser determines which browser history, cache, and credential files to prioritize.",
    mitre_techniques: &[],
    fields: &[FieldSchema { name: "prog_id", value_type: ValueType::Text, description: "ProgID of the default browser handler", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["chrome_cookies", "firefox_logins", "edge_webcache"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["ProgID alone does not confirm browser usage — cross-reference with browser history artifacts"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until user changes default browser",
};

pub(crate) static PROXY_SETTINGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "proxy_settings",
    name: "Internet Settings Proxy Configuration",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Stores proxy server settings (ProxyServer, ProxyEnable, ProxyOverride). Attackers configure a local proxy to intercept and relay traffic; also used by malware that needs proxy-aware C2 communication or to detect corporate network environments.",
    mitre_techniques: &["T1090", "T1071"],
    fields: &[
        FieldSchema { name: "proxy_server", value_type: ValueType::Text, description: "Proxy server address:port", is_uid_component: true },
        FieldSchema { name: "proxy_enable", value_type: ValueType::UnsignedInt, description: "1 = proxy enabled, 0 = disabled", is_uid_component: false },
    ],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["wifi_profiles", "networklist_profiles"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Many enterprise environments legitimately configure proxies via GPO or PAC files"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit deletion",
};

pub(crate) static SYSTEM_TIMEZONE: ArtifactDescriptor = ArtifactDescriptor {
    id: "system_timezone",
    name: "System Timezone",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\TimeZoneInformation",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records the system timezone (TimeZoneKeyName, Bias, DaylightBias). Critical for timestamp normalization in timeline analysis — all FILETIME artifacts must be offset-corrected using this value to produce accurate UTC timestamps.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "timezone_name", value_type: ValueType::Text, description: "Windows timezone key name (e.g. 'Eastern Standard Time')", is_uid_component: true },
        FieldSchema { name: "bias_minutes", value_type: ValueType::Integer, description: "UTC offset in minutes (negative = east of UTC)", is_uid_component: false },
    ],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["userassist_exe", "bam_user"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["An attacker with SYSTEM privileges can change the timezone to manipulate all subsequent timestamps; cross-validate against NTP sync logs or external sources"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit timezone change",
};

pub(crate) static COMPUTER_NAME: ArtifactDescriptor = ArtifactDescriptor {
    id: "computer_name",
    name: "Computer Name",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\ComputerName\\ComputerName",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Stores the NetBIOS computer name (ComputerName value). Used to correlate evidence across multiple forensic artifacts (event logs, network captures, NTLM auth) to the same machine. Previous names indicate hostname changes.",
    mitre_techniques: &[],
    fields: &[FieldSchema { name: "computer_name", value_type: ValueType::Text, description: "Current NetBIOS computer name", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["system_timezone", "networklist_profiles"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Only reflects the current name; prior hostnames are not retained here — check domain join logs or SCCM/Intune records for name history"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit rename",
};

pub(crate) static SHUTDOWN_TIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "shutdown_time",
    name: "Last Shutdown Time",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Control\\Windows",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "ShutdownTime value stores the FILETIME of the last clean shutdown. Establishes system power-off timeline, useful for correlating with event log gaps and identifying unplanned shutdowns (malware, power loss, or evidence destruction).",
    mitre_techniques: &["T1070"],
    fields: &[FieldSchema { name: "shutdown_time", value_type: ValueType::Timestamp, description: "Last clean shutdown time as ISO 8601 UTC", is_uid_component: true }],
    retention: Some("Overwritten on each clean shutdown"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["evtx_system"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Only records the most recent clean shutdown; unclean shutdowns leave stale value"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value overwritten on each clean shutdown",
};

pub(crate) static USB_STOR_ENUM: ArtifactDescriptor = ArtifactDescriptor {
    id: "usb_stor_enum",
    name: "USBSTOR Device Enumeration",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: "CurrentControlSet\\Enum\\USBSTOR",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Complete USB storage device connection history: device type, vendor, model, serial number, and per-device connection timestamps. On Windows 8+ the connect/disconnect times are stored directly under USBSTOR\\<device>\\<serial>\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\ as decimal-named subkeys 0064-0067 (hex 0x64-0x67), each a REG_BINARY little-endian FILETIME and all documented DEVPKEYs (DEVPROP_TYPE_FILETIME): 0064 InstallDate, 0065 FirstInstallDate, 0066 LastArrivalDate (last connect), 0067 LastRemovalDate (last disconnect). setupapi.dev.log remains the corroborating first-install source. The primary artifact for USB data theft investigations — persists after device removal.",
    mitre_techniques: &["T1052.001", "T1025"],
    fields: &[
        FieldSchema { name: "device_id", value_type: ValueType::Text, description: "USB device instance ID including serial number", is_uid_component: true },
        FieldSchema { name: "friendly_name", value_type: ValueType::Text, description: "Vendor and model string", is_uid_component: false },
        FieldSchema { name: "install_date", value_type: ValueType::Timestamp, description: "DEVPKEY_Device_InstallDate (property 0x64, FILETIME) — when the device driver was installed on this machine (present on Win7 under the nested {GUID}\\00xx\\00000000\\Data path; flattened to Properties\\{GUID}\\0064 on Win8+)", is_uid_component: false },
        FieldSchema { name: "first_install_date", value_type: ValueType::Timestamp, description: "DEVPKEY_Device_FirstInstallDate (property 0x65, FILETIME) — first time this device was connected to this machine; present since Windows 7 (nested path pre-Win8, flattened on Win8+)", is_uid_component: false },
        FieldSchema { name: "last_arrival_date", value_type: ValueType::Timestamp, description: "DEVPKEY_Device_LastArrivalDate (property 0x66, FILETIME) — the authoritative LAST-CONNECT time; a Windows 8+ addition", is_uid_component: false },
        FieldSchema { name: "last_removal_date", value_type: ValueType::Timestamp, description: "DEVPKEY_Device_LastRemovalDate (property 0x67, FILETIME) — the last DISCONNECT time; a Windows 8+ addition", is_uid_component: false },
    ],
    retention: Some("Persists until device entry is manually deleted"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["usb_enum", "portable_devices", "setupapi_dev_log", "mountpoints2", "mounted_devices"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
        "https://www.sans.org/blog/computer-forensic-guide-to-profiling-usb-device-thumbdrives-on-win7-xp-2003/",
        // Microsoft Windows 10 SDK devpkey.h — GUID {83da6326-...} + property IDs 0x64-0x67 = DEVPROP_TYPE_FILETIME:
        "https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/devpkey.h",
        // Yogesh Khatri — RE writeup: forensic Last-Insertion/Last-Removal meaning + Win8 introduction:
        "https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html",
        // libyal winreg-kb — Enum\USBSTOR\...\Properties layout RE reference:
        "https://github.com/libyal/winreg-kb/blob/main/documentation/USB%20storage%20device%20keys.asciidoc",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Device serial numbers persist; device may have been removed",
        "Last-connect three-source corroboration: 0066 LastArrivalDate (documented FILETIME) is the authoritative last-connect; it should agree with the LastWrite time of the USBSTOR\\<device>\\<serial> subkey and the LastWrite of the per-user NTUSER MountPoints2 subkey for the same volume GUID (which also attributes the connection to a specific user). Registry subkey LastWrite times are corroborative (any write updates them), not equal in precision to the 0066 FILETIME",
        "The FLAT Properties\\{GUID}\\0064-0067 layout is Windows 8+; on Windows 7 InstallDate/FirstInstallDate live under the nested {GUID}\\00xx\\00000000\\Data path, and LastArrivalDate/LastRemovalDate (0066/0067) are Win8 additions — on Win7/XP fall back to USBSTOR subkey LastWrite plus setupapi.dev.log for first-connect",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; survives device removal",
};

pub(crate) static SETUPAPI_DEV_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "setupapi_dev_log",
    name: "SetupAPI Device Installation Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("%SystemRoot%\\INF\\setupapi.dev.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Plain-text log of all device driver installations with timestamps. Cross-reference with USBSTOR registry to establish first USB connection time — the log timestamp is the first time a device was ever seen on this system.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "device_id", value_type: ValueType::Text, description: "Device instance ID", is_uid_component: true },
        FieldSchema { name: "install_time", value_type: ValueType::Timestamp, description: "First installation timestamp", is_uid_component: false },
    ],
    retention: Some("Rotated; setupapi.dev.log.bak may exist"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["usb_stor_enum", "usb_enum"],
    sources: &[
        "https://www.sans.org/blog/computer-forensic-guide-to-profiling-usb-device-thumbdrives-on-win7-xp-2003/",
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["First connection timestamps are reliable; log may be cleared"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Log file; retained until manually cleared",
};

pub(crate) static UNINSTALL_KEYS: ArtifactDescriptor = ArtifactDescriptor {
    id: "uninstall_keys",
    name: "Installed Software (Uninstall Registry)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows\\CurrentVersion\\Uninstall",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Registry of all installed software with install date (InstallDate), version, publisher, and uninstall string. Establishes software baseline; newly appearing or anomalous entries indicate attacker tool installation. InstallDate in YYYYMMDD format.",
    mitre_techniques: &["T1072", "T1518"],
    fields: &[
        FieldSchema { name: "display_name", value_type: ValueType::Text, description: "Software display name", is_uid_component: true },
        FieldSchema { name: "install_date", value_type: ValueType::Text, description: "Install date (YYYYMMDD)", is_uid_component: false },
        FieldSchema { name: "install_location", value_type: ValueType::Text, description: "Installation directory", is_uid_component: false },
    ],
    retention: Some("Removed on uninstall; InstallDate persists in external logs"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["amcache_app_file", "muicache"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Portable apps and self-extracting installers may not register here",
        "Malware can suppress its own uninstall entry",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists until explicit uninstall removes entry",
};

pub(crate) static USER_ACCOUNT_SID: ArtifactDescriptor = ArtifactDescriptor {
    id: "user_account_sid",
    name: "User Account SID to Name Mapping",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    value_name: None,    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Maps SIDs to user profile paths and metadata. Resolves numeric SIDs in event logs, registry owner fields, and NTFS ACLs to human-readable usernames. Critical for cross-artifact correlation.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "sid", value_type: ValueType::Text, description: "User SID (subkey name)", is_uid_component: true },
        FieldSchema { name: "profile_image_path", value_type: ValueType::Text, description: "Path to user profile directory", is_uid_component: false },
    ],
    retention: Some("Persists after account deletion until profile is removed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["sam_users", "evtx_security"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Subkeys linger after account deletion until the profile directory is removed; presence of a SID subkey does not prove the account still exists"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists for life of user profile",
};

pub(crate) static TERMINAL_SERVER_CLIENT_SERVERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "terminal_server_client_servers_ext",
    name: "RDP MRU: Terminal Server Client Servers (extended)",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Terminal Server Client\\Servers",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Extended RDP connection history including per-server UsernameHint (username used to connect). Complements rdp_client_servers by exposing the credential used — critical for lateral movement analysis.",
    mitre_techniques: &["T1021.001"],
    fields: &[
        FieldSchema { name: "server", value_type: ValueType::Text, description: "RDP target hostname or IP", is_uid_component: true },
        FieldSchema { name: "username_hint", value_type: ValueType::Text, description: "Username hint stored for this connection", is_uid_component: false },
    ],
    retention: Some("Persists until cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["rdp_client_servers", "rdp_client_default", "rdp_bitmap_cache"],
    sources: &[
        "https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Reveals UsernameHint used for RDP — near-definitive lateral movement evidence"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry key; persists across sessions",
};

pub(crate) static INTERNET_EXPLORER_TYPED_URLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ie_typed_urls",
    name: "Internet Explorer Typed URLs",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: "Software\\Microsoft\\Internet Explorer\\TypedURLs",
    value_name: None,    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "URLs manually typed into Internet Explorer or legacy Edge. Separate from the newer TypedURLs key; may persist on systems with IE compatibility mode. Reveals attacker research activity and C2 domain access.",
    mitre_techniques: &["T1217"],
    fields: &[FieldSchema { name: "url", value_type: ValueType::Text, description: "Manually typed URL", is_uid_component: true }],
    retention: Some("Up to 25 most recent entries"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["typed_urls", "typed_urls_time"],
    sources: &["https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Only populated when IE/legacy Edge is used; obsolete on modern Windows",
        "User can manually clear typed URL history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated per user URL typing; FIFO eviction as new URLs are typed",
};

/// EMDMgmt / ReadyBoost external-device volume cache — USB iSerialNumber ↔ volume
/// serial number (VSN) linkage.
///
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk> (GUID_DEVINTERFACE_DISK embedded in subkey names)
/// Source: <https://github.com/woanware/usbdeviceforensics/blob/master/usbdeviceforensics.py> (parse oracle: key path, subkey format, decimal VSN)
/// Source: <https://github.com/keydet89/RegRipper3.0/blob/master/plugins/emdmgmt.pl> (second independent parse oracle)
pub(crate) static EMDMGMT_READYBOOST: ArtifactDescriptor = ArtifactDescriptor {
    id: "emdmgmt_readyboost",
    name: "EMDMgmt / ReadyBoost External Device Volume Cache",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "EMDMgmt (External Memory Device Management) is the registry store written by the \
ReadyBoost service (Emdmgmt.dll). When a non-system-drive external volume is attached, ReadyBoost \
profiles it and writes a subkey whose NAME embeds three forensically valuable fields: the device \
instance ID (e.g. _??_USBSTOR#Disk&Ven_...#<iSerialNumber>#), the GUID_DEVINTERFACE_DISK class GUID \
{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}, the volume label, then the volume serial number in DECIMAL. \
It is one of the few registry locations (besides MountedDevices/MountPoints) that ties a device's \
USB iSerialNumber to a volume serial number (VSN), letting an examiner correlate the device to VSNs \
recorded in LNK files and Jump Lists — decisive when a drive letter has been reused across several \
devices. The same iSerialNumber appearing with multiple different VSNs is consistent with the volume \
having been reformatted (a new VSN is generated on each format).",
    mitre_techniques: &["T1052.001", "T1025"],
    fields: &[
        FieldSchema {
            name: "device_instance_id",
            value_type: ValueType::Text,
            description: "USBSTOR/USB device instance ID embedded in the subkey name, including enumerator prefix, vendor/product/revision, and iSerialNumber",
            is_uid_component: true,
        },
        FieldSchema {
            name: "volume_label",
            value_type: ValueType::Text,
            description: "Volume label string, taken from the subkey name between the disk class GUID and the trailing underscore",
            is_uid_component: false,
        },
        FieldSchema {
            name: "volume_serial_number",
            value_type: ValueType::Text,
            description: "Volume serial number (VSN), stored in DECIMAL as the final underscore-delimited component of the subkey name; convert to hex (XXXX-XXXX) to match VSNs in LNK/Jump List records",
            is_uid_component: true,
        },
    ],
    retention: Some("Persists after device removal; entries are not cleared automatically"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usb_stor_enum", "mounted_devices", "lnk_files", "setupapi_dev_log"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk",
        "https://github.com/woanware/usbdeviceforensics/blob/master/usbdeviceforensics.py",
        "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/emdmgmt.pl",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Volume serial number is stored in DECIMAL in the subkey name — convert to hex (compare as XXXX-XXXX) before matching against LNK/Jump List VSNs",
        "Populated only by the ReadyBoost service, which Windows DISABLES when the system drive is an SSD or is deemed fast enough; an absent or empty key on such systems is EXPECTED and is NOT evidence of tampering/anti-forensics",
        "ReadyBoost was removed in Windows 11 22H2, so the key may be unpopulated on that build and later regardless of drive type",
        "Records non-system EXTERNAL volumes broadly (USB, eSATA, FireWire, non-system local disks) — not USB-only; MTP/PTP devices (phones, cameras) are not captured",
        "Corroborate with USBSTOR, MountedDevices, setupapi.dev.log, and Microsoft-Windows-Partition/Diagnostic; do not treat EMDMgmt absence in isolation as an investigative conclusion",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry subkeys survive device removal and reboot until manually deleted",
};
