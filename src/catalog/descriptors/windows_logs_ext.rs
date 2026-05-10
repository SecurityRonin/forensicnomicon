//! Extended Windows crash dump, WER, and miscellaneous artifact descriptors — Batch I.
//!
//! Sources: Microsoft documentation, SANS FOR508, KAPE targets (EricZimmerman/KapeFiles),
//! DFIR research on BYOVD and Windows Error Reporting forensics.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static WINDOWS_CRASH_DUMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_crash_dump",
    name: "Windows Kernel/Complete Memory Dump",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\MEMORY.DMP"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows kernel/complete memory dump generated on BSOD or manual trigger. Contains full RAM contents at crash time including running processes, network connections, encryption keys, and credential material in LSASS address space. Attackers may trigger BSODs to erase volatile evidence or interfere with forensic collection.",
    mitre_techniques: &["T1529", "T1006"],
    fields: &[],
    retention: Some("Overwritten on each subsequent BSOD unless renamed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["windows_minidump"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/complete-memory-dump",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static WINDOWS_MINIDUMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_minidump",
    name: "Windows BSOD Minidump Files",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\Minidump\\*.dmp"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Minidump files generated automatically for each BSOD. Smaller than full dumps; contain the kernel crash context including stack traces and module list. Useful for identifying driver crashes caused by BYOVD (bring-your-own-vulnerable-driver) exploitation attempts or rootkit-induced kernel panics.",
    mitre_techniques: &["T1068", "T1014"],
    fields: &[],
    retention: Some("Kept up to configured count (default 50) in %SystemRoot%\\Minidump\\"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["windows_crash_dump", "evtx_system"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/minidump-files",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static AMCACHE_DRIVER: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_driver",
    name: "AmCache InventoryDriverBinary",
    artifact_type: ArtifactType::RegistryKey,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\AppCompat\\Programs\\Amcache.hve"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AmCache InventoryDriverBinary section: records installed driver binaries with SHA1 hash, version, product, and first-seen timestamp. Unlike Shimcache, AmCache hashes persist even after binary deletion — a deleted malicious driver's SHA1 remains as evidence. Critical for BYOVD attack investigation.",
    mitre_techniques: &["T1068", "T1553.006"],
    fields: &[
        FieldSchema { name: "DriverId", value_type: ValueType::Text, description: "Driver binary hash identifier", is_uid_component: true },
        FieldSchema { name: "DriverName", value_type: ValueType::Text, description: "Driver filename", is_uid_component: false },
        FieldSchema { name: "DriverVersion", value_type: ValueType::Text, description: "Driver version string", is_uid_component: false },
    ],
    retention: Some("Persists until AmCache.hve is manually cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["amcache_app_file", "shimcache", "evtx_code_integrity"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/intelligence/criteria",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Records driver load time, not execution time; SHA1 hash allows reputation lookup"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Amcache hive persists on disk; survives reboot",
};

pub(crate) static WER_REPORT_QUEUE: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_report_queue",
    name: "Windows Error Reporting Queue",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Error Reporting queued crash reports waiting for upload. Each report contains a Report.wer text file with the faulting module, exception code, and timestamp. Process crash artifacts indicate: (1) AV/EDR crashes induced by attackers, (2) injected process crashes revealing injection target, (3) exploit-crashed processes showing the attacked binary.",
    mitre_techniques: &["T1562.001", "T1055"],
    fields: &[
        FieldSchema { name: "FaultingModule", value_type: ValueType::Text, description: "Module that caused the crash", is_uid_component: true },
        FieldSchema { name: "ExceptionCode", value_type: ValueType::Text, description: "Win32 exception code", is_uid_component: false },
    ],
    retention: Some("Queued reports retained until uploaded or manually cleared"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["windows_minidump", "evtx_system"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static WINDOWS_NOTIFICATION_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_notification_db",
    name: "Windows Push Notification Database",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%LocalAppData%\\Microsoft\\Windows\\Notifications\\wpndatabase.db"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Push Notification Platform (WPN) SQLite database. Records application toast notifications with timestamps. Provides a secondary activity timeline: notification receipt times correlate with user activity periods and can reveal when specific applications (email, browser, Teams) were actively used — useful for alibi verification.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "HandlerId", value_type: ValueType::Text, description: "Notification handler application identifier", is_uid_component: true },
        FieldSchema { name: "Payload", value_type: ValueType::Text, description: "Notification content payload", is_uid_component: false },
    ],
    retention: Some("Retained per-user; cleared on notification dismissal or app uninstall"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["srum_push_notification"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/windows-push-notification-services--wns--overview",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static AMCACHE_SHORTCUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_shortcut",
    name: "AmCache InventoryApplicationShortcut",
    artifact_type: ArtifactType::RegistryKey,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\AppCompat\\Programs\\Amcache.hve"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AmCache InventoryApplicationShortcut section: records shortcut (.lnk) files that launch applications, with the target application path and timestamps. Reveals installed application shortcuts created by malware installers — persistence mechanism evidence when a shortcut was created without user action.",
    mitre_techniques: &["T1547.009", "T1204.002"],
    fields: &[
        FieldSchema { name: "ShortcutPath", value_type: ValueType::Text, description: "Path to the .lnk shortcut file", is_uid_component: true },
        FieldSchema { name: "TargetPath", value_type: ValueType::Text, description: "Resolved target executable path", is_uid_component: false },
    ],
    retention: Some("Persists until AmCache.hve is manually cleared"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["amcache_app_file", "lnk_files", "jump_list_auto"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/compatibility/application-compatibility-toolkit-documentation",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};
