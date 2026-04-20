//! Static [`ArtifactDescriptor`] instances and the [`CATALOG_ENTRIES`] slice.
//!
//! All descriptor statics live here to avoid const-concatenation limitations.
//! The content is organised with section comments matching the original
//! `artifact.rs` structure so `grep -n "^// ──"` still navigates cleanly.

#![allow(clippy::too_many_lines)]

use super::types::{
    ArtifactDescriptor, ArtifactType, BinaryField, BinaryFieldType, DataScope, Decoder,
    FieldSchema, HiveTarget, OsScope, TriagePriority, ValueType,
};

/// UserAssist 72-byte binary value fields (Win7+ EXE GUID).
pub(crate) static USERASSIST_BINARY_FIELDS: &[BinaryField] = &[
    BinaryField {
        name: "run_count",
        offset: 4,
        field_type: BinaryFieldType::U32Le,
        description: "Number of times the program was launched",
    },
    BinaryField {
        name: "focus_count",
        offset: 8,
        field_type: BinaryFieldType::U32Le,
        description: "Number of times the program received input focus",
    },
    BinaryField {
        name: "focus_duration_ms",
        offset: 12,
        field_type: BinaryFieldType::U32Le,
        description: "Total focus time in milliseconds",
    },
    BinaryField {
        name: "last_run",
        offset: 60,
        field_type: BinaryFieldType::FiletimeLe,
        description: "FILETIME of the last execution",
    },
];

/// UserAssist field schema (decoded output description).
pub(crate) static USERASSIST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "program",
        value_type: ValueType::Text,
        description: "ROT13-decoded program path or name",
        is_uid_component: true,
    },
    FieldSchema {
        name: "run_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of times launched",
        is_uid_component: false,
    },
    FieldSchema {
        name: "focus_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of times received focus",
        is_uid_component: false,
    },
    FieldSchema {
        name: "focus_duration_ms",
        value_type: ValueType::UnsignedInt,
        description: "Total focus time in milliseconds",
        is_uid_component: false,
    },
    FieldSchema {
        name: "last_run",
        value_type: ValueType::Timestamp,
        description: "FILETIME of last execution as ISO 8601",
        is_uid_component: false,
    },
];

/// UserAssist EXE entries (NTUSER.DAT).
///
/// GUID: `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`
/// Key: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
/// Decoder: ROT13 the value name + parse 72-byte binary value.
pub static USERASSIST_EXE: ArtifactDescriptor = ArtifactDescriptor {
    id: "userassist_exe",
    name: "UserAssist (EXE)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
    value_name: None, // enumerate all values
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Rot13NameWithBinaryValue(USERASSIST_BINARY_FIELDS),
    meaning: "Program execution history with launch counts and timestamps",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: USERASSIST_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["prefetch_dir", "shimcache", "srum_app_resource"],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-userassist/",
        "https://windowsir.blogspot.com/2004/02/userassist.html",
        "http://windowsir.blogspot.com/2007/09/more-on-userassist-keys.html",
        "https://www.magnetforensics.com/blog/artifact-profile-userassist/",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

/// Run key field schema.
pub(crate) static RUN_KEY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "value",
    value_type: ValueType::Text,
    description: "Autostart command or path",
    is_uid_component: false,
}];

/// HKLM SOFTWARE Run key -- system-wide autostart persistence.
pub static RUN_KEY_HKLM_RUN: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hklm",
    name: "Run Key (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "System-wide autostart entry executed at every user logon",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "run_key_hklm_once",
        "services_imagepath",
        "scheduled_tasks_dir",
    ],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys",
        "https://windowsir.blogspot.com/2013/01/run-mru.html",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
    ],
};

/// TypedURLs field schema.
pub(crate) static TYPED_URLS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "value",
    value_type: ValueType::Text,
    description: "URL typed into the IE/Edge address bar",
    is_uid_component: true,
}];

/// Internet Explorer / Edge TypedURLs (NTUSER.DAT).
pub static TYPED_URLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "typed_urls",
    name: "TypedURLs (IE/Edge)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Internet Explorer\TypedURLs",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "URLs manually typed into the Internet Explorer or Edge address bar",
    mitre_techniques: &["T1071.001"],
    fields: TYPED_URLS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1071/001/",
        "https://www.sans.org/blog/digital-forensics-windows-registry-forensics-part-6-internet-explorer-user-typed-urls/",
        "https://windowsir.blogspot.com/2006/04/typed-urls.html",
        "https://crucialsecurity.wordpress.com/2011/03/14/typedurls-part-1/",
    ],
};

/// PCA AppLaunch.dic pipe-delimited fields.
pub(crate) static PCA_FIELDS_SCHEMA: &[FieldSchema] = &[
    FieldSchema {
        name: "exe_path",
        value_type: ValueType::Text,
        description: "Full path to the executable",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Text,
        description: "Launch timestamp string",
        is_uid_component: false,
    },
];

pub(crate) static PCA_PIPE_FIELDS: &[&str] = &["exe_path", "timestamp"];

/// Program Compatibility Assistant AppLaunch.dic (Win11 22H2+).
///
/// A pipe-delimited text file where each line records an application launch.
pub static PCA_APPLAUNCH_DIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "pca_applaunch_dic",
    name: "PCA AppLaunch.dic",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\appcompat\pca\AppLaunch.dic"),
    scope: DataScope::System,
    os_scope: OsScope::Win11_22H2,
    decoder: Decoder::PipeDelimited {
        fields: PCA_PIPE_FIELDS,
    },
    meaning: "Program execution evidence from the Program Compatibility Assistant",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: PCA_FIELDS_SCHEMA,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/",
        "https://www.sygnia.co/blog/new-windows-11-pca-artifact/",
        "https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/program-compatibility-assistant.md",
    ],
};

// ── Run key HKCU variants ────────────────────────────────────────────────────

/// HKCU Run key — per-user autostart persistence.
pub static RUN_KEY_HKCU_RUN: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hkcu",
    name: "Run Key (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user autostart programs executed at every logon without elevation. \
              Lower-privilege than HKLM Run — writable by the user account itself, \
              making it a common unprivileged persistence location that survives password resets.",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["run_key_hklm", "startup_folder_user"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys",
        "https://windowsir.blogspot.com/2013/01/run-mru.html",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/02_Detection_Rules/2.2_sigma_rules/HKCU%20Run%20Key%20Written%20by%20Unusual%20Process.yml",
    ],
};

/// HKCU RunOnce — per-user one-shot autostart (deleted after execution).
pub static RUN_KEY_HKCU_RUNONCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hkcu_once",
    name: "RunOnce Key (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user one-time autostart, deleted after first execution",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys",
    ],
};

/// HKLM RunOnce — system-wide one-shot autostart.
pub static RUN_KEY_HKLM_RUNONCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hklm_once",
    name: "RunOnce Key (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\RunOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "System-wide one-time autostart, deleted after first execution",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys",
    ],
};

// ── IFEO ──────────────────────────────────────────────────────────────────────

pub(crate) static IFEO_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "debugger",
    value_type: ValueType::Text,
    description: "Debugger path that hijacks the target process launch",
    is_uid_component: false,
}];

/// Image File Execution Options — Debugger value hijack (T1546.012).
///
/// Attacker sets `Debugger` under a target EXE's IFEO key to redirect
/// its launch to an arbitrary binary (e.g., `cmd.exe`).
pub static IFEO_DEBUGGER: ArtifactDescriptor = ArtifactDescriptor {
    id: "ifeo_debugger",
    name: "IFEO Debugger Hijack",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    value_name: Some("Debugger"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Redirects target-process launch to an attacker-controlled binary",
    mitre_techniques: &["T1546.012"],
    fields: IFEO_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/012/",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/enabling-postmortem-debugging",
        "https://www.sans.org/blog/malware-persistence-without-the-windows-registry/",
    ],
};

// ── UserAssist (Folder GUID) ─────────────────────────────────────────────────

/// UserAssist Folder GUID entries (NTUSER.DAT).
///
/// GUID: `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` — records folder access.
pub static USERASSIST_FOLDER: ArtifactDescriptor = ArtifactDescriptor {
    id: "userassist_folder",
    name: "UserAssist (Folder)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Rot13NameWithBinaryValue(USERASSIST_BINARY_FIELDS),
    meaning: "Folder navigation history with access counts and timestamps",
    mitre_techniques: &["T1083"],
    fields: USERASSIST_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-userassist/",
        "https://windowsir.blogspot.com/2004/02/userassist.html",
        "http://windowsir.blogspot.com/2007/09/more-on-userassist-keys.html",
        "https://www.magnetforensics.com/blog/artifact-profile-userassist/",
    ],
};

// ── ShellBags ─────────────────────────────────────────────────────────────────

pub(crate) static SHELLBAGS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "indices",
    value_type: ValueType::List,
    description: "MRU order of accessed shell folder slots",
    is_uid_component: false,
}];

/// ShellBags — folder navigation history in UsrClass.dat.
///
/// Records folders the user browsed via Explorer, including deleted, network,
/// and removable-media paths. Survives folder deletion.
pub static SHELLBAGS_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "shellbags_user",
    name: "ShellBags (User)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MruListEx,
    meaning: "Folder access history; persists paths even after folder deletion",
    mitre_techniques: &["T1083", "T1005"],
    fields: SHELLBAGS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://attack.mitre.org/techniques/T1005/",
        "https://www.sans.org/blog/shell-bag-forensics/",
        "https://windowsir.blogspot.com/2009/07/shellbag-analysis.html",
        "https://ericzimmerman.github.io/#!index.md",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
        "https://www.sans.org/white-papers/34545/",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

// ── Amcache ───────────────────────────────────────────────────────────────────

pub(crate) static AMCACHE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "file_id",
        value_type: ValueType::Text,
        description: "Volume GUID + MFT file reference (unique file identity)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "sha1",
        value_type: ValueType::Text,
        description: "SHA1 of the first 31.25 MB (0000-prefixed)",
        is_uid_component: false,
    },
];

/// Amcache InventoryApplicationFile — program execution evidence with hashes.
pub static AMCACHE_APP_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_app_file",
    name: "Amcache InventoryApplicationFile",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::Amcache),
    key_path: r"Root\InventoryApplicationFile",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning: "Program execution evidence with file hash; persists after binary deletion",
    mitre_techniques: &["T1218", "T1204.002"],
    fields: AMCACHE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["shimcache", "prefetch_dir", "srum_app_resource"],
    sources: &[
        "https://attack.mitre.org/techniques/T1218/",
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://www.sans.org/blog/new-amcache-hve-in-windows-8-1-update-1/",
        "https://www.sansforensics.com/blog/amcache-hive-forensics/",
        "https://www.researchgate.net/publication/317258237_Leveraging_the_Windows_Amcachehve_File_in_Forensic_Investigations",
        "https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/",
        "https://github.com/EricZimmerman/AmcacheParser",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

// ── ShimCache (AppCompatCache) ────────────────────────────────────────────────

pub(crate) static SHIMCACHE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "raw",
    value_type: ValueType::Bytes,
    description: "Raw AppCompatCache binary blob (parsed by shimcache module)",
    is_uid_component: false,
}];

/// ShimCache — application compatibility cache with executable metadata.
///
/// Stored as a single binary value `AppCompatCache` under the SYSTEM hive.
/// Contains executable paths and last-modified timestamps (NOT execution times
/// on Win8+). Parsed by the shimcache module.
pub static SHIMCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "shimcache",
    name: "ShimCache (AppCompatCache)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager\AppCompatCache",
    value_name: Some("AppCompatCache"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executable metadata cache; presence proves binary existed on disk",
    mitre_techniques: &["T1218", "T1059"],
    fields: SHIMCACHE_FIELDS,
    retention: Some("written at clean shutdown only; lost on crash/hard-power-off"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["amcache_app_file", "prefetch_dir", "bam_user"],
    sources: &[
        "https://attack.mitre.org/techniques/T1218/",
        "https://attack.mitre.org/techniques/T1059/",
        "https://www.sans.org/blog/digital-forensics-shimcache/",
        "https://redcanary.com/blog/threat-detection/appcompatcache/",
        "https://www.sans.org/blog/mass-triage-part-4-processing-returned-files-appcache-shimcache/",
        "https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/",
        "https://github.com/EricZimmerman/AppCompatCacheParser",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
    ],
};

// ── BAM / DAM ─────────────────────────────────────────────────────────────────

pub(crate) static BAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "last_exec",
    value_type: ValueType::Timestamp,
    description: "FILETIME of last background execution",
    is_uid_component: false,
}];

/// Background Activity Moderator — per-user background process execution times.
///
/// Each value under a SID sub-key is the executable path; value data is an
/// 8-byte FILETIME of the last execution. Win10 1709+.
pub static BAM_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "bam_user",
    name: "BAM (Background Activity Moderator)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\bam\State\UserSettings",
    value_name: None,
    file_path: None,
    scope: DataScope::Mixed,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Last execution time of background/UWP processes per-user SID",
    mitre_techniques: &["T1059", "T1204"],
    fields: BAM_FIELDS,
    retention: Some("~7 days rolling window"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["dam_user", "shimcache", "prefetch_dir"],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/",
        "https://www.sans.org/blog/background-activity-moderator-bam-forensics/",
        "https://www.13cubed.com/downloads/windows10_forensics_cheat_sheet.pdf",
        "https://forensafe.com/blogs/bam.html",
        "https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/bam-dam.md",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

pub(crate) static DAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "last_exec",
    value_type: ValueType::Timestamp,
    description: "FILETIME of last desktop application execution",
    is_uid_component: false,
}];

/// Desktop Activity Moderator — per-user desktop application execution times.
pub static DAM_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dam_user",
    name: "DAM (Desktop Activity Moderator)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\dam\State\UserSettings",
    value_name: None,
    file_path: None,
    scope: DataScope::Mixed,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Last execution time of desktop applications per-user SID",
    mitre_techniques: &["T1059", "T1204"],
    fields: DAM_FIELDS,
    retention: Some("~7 days rolling window"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["bam_user", "shimcache"],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/",
        "https://www.sans.org/blog/background-activity-moderator-bam-forensics/",
        "https://forensafe.com/blogs/bam.html",
        "https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/bam-dam.md",
    ],
};

// ── SAM ───────────────────────────────────────────────────────────────────────

pub(crate) static SAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "username",
    value_type: ValueType::Text,
    description: "Local account username (sub-key name)",
    is_uid_component: true,
}];

/// SAM local user account enumeration.
///
/// Each sub-key under `Names` is a local account username. The adjacent
/// `Users\<RID>` keys contain F/V binary records with password hash metadata.
pub static SAM_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "sam_users",
    name: "SAM User Accounts",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSam),
    key_path: r"SAM\Domains\Account\Users\Names",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Local Windows accounts; F/V records contain login counts and NTLM hash metadata",
    mitre_techniques: &["T1003.002", "T1087.001"],
    fields: SAM_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["lsa_secrets", "dcc2_cache"],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/002/",
        "https://attack.mitre.org/techniques/T1087/001/",
        "https://www.sans.org/blog/windows-credential-storage-for-penetration-testers/",
        "https://windowsir.blogspot.com/2010/11/recovering-passwords.html",
        "http://windowsir.blogspot.com/2013/07/howto-determine-users-on-system.html",
    ],
};

// ── LSA Secrets / DCC2 ───────────────────────────────────────────────────────

pub(crate) static LSA_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "secret_name",
    value_type: ValueType::Text,
    description: "LSA secret key name (e.g. _SC_*, DPAPI_SYSTEM, DefaultPassword)",
    is_uid_component: true,
}];

/// LSA Secrets — encrypted service credentials and DPAPI material.
pub static LSA_SECRETS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_secrets",
    name: "LSA Secrets",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSecurity),
    key_path: r"Policy\Secrets",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Encrypted service credentials, auto-logon passwords, and DPAPI master key",
    mitre_techniques: &["T1003.004", "T1552.002"],
    fields: LSA_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["sam_users", "dpapi_system_masterkey", "dcc2_cache"],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/004/",
        "https://attack.mitre.org/techniques/T1552/002/",
        "https://www.sans.org/blog/lsa-secrets/",
    ],
};

pub(crate) static DCC2_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "slot_name",
    value_type: ValueType::Text,
    description: "Cache slot name (NL$1 through NL$25)",
    is_uid_component: true,
}];

/// Domain Cached Credentials 2 (MS-Cache v2 / DCC2).
///
/// PBKDF2-SHA1 hashes of the last N domain logons, enabling offline logon
/// when no DC is reachable. Crackable offline.
pub static DCC2_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "dcc2_cache",
    name: "Domain Cached Credentials 2 (DCC2)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSecurity),
    key_path: r"Cache",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "MS-Cache v2 (PBKDF2-SHA1) hashes enabling offline domain logon",
    mitre_techniques: &["T1003.005"],
    fields: DCC2_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/005/",
        "https://www.sans.org/blog/windows-credential-storage-for-penetration-testers/",
    ],
};

// ── TypedURLsTime ─────────────────────────────────────────────────────────────

pub(crate) static TYPED_URLS_TIME_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "timestamp",
    value_type: ValueType::Timestamp,
    description: "FILETIME when the URL slot was typed",
    is_uid_component: false,
}];

/// IE/Edge TypedURLsTime — FILETIME timestamps parallel to TypedURLs.
pub static TYPED_URLS_TIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "typed_urls_time",
    name: "TypedURLsTime (IE/Edge)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Internet Explorer\TypedURLsTime",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Timestamps of URLs typed into IE/Edge address bar (paired with TypedURLs)",
    mitre_techniques: &["T1071.001"],
    fields: TYPED_URLS_TIME_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1071/001/",
        "https://www.sans.org/blog/digital-forensics-windows-registry-forensics-part-6-internet-explorer-user-typed-urls/",
    ],
};

// ── MRU RecentDocs ────────────────────────────────────────────────────────────

pub(crate) static MRU_RECENT_DOCS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "indices",
    value_type: ValueType::List,
    description: "MRUListEx order indices of recently accessed documents",
    is_uid_component: false,
}];

/// Explorer RecentDocs MRU — most-recently-used document list.
pub static MRU_RECENT_DOCS: ArtifactDescriptor = ArtifactDescriptor {
    id: "mru_recent_docs",
    name: "MRU RecentDocs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Most-recently-used documents list (MRUListEx order of shell32 items)",
    mitre_techniques: &["T1005", "T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1005/",
        "https://attack.mitre.org/techniques/T1083/",
        "https://windowsir.blogspot.com/2006/11/recent-docs-mru.html",
        "https://www.sans.org/blog/windows-mru-registry-keys/",
        "https://www.sans.org/blog/opensavemru-and-lastvisitedmru/",
        "https://forensics.wiki/opensavemru/",
    ],
};

// ── USB device enumeration ────────────────────────────────────────────────────

pub(crate) static USB_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "device_id",
    value_type: ValueType::Text,
    description: "USB device instance ID (VID&PID sub-key name)",
    is_uid_component: true,
}];

/// USBSTOR — USB storage device connection history.
///
/// Each sub-key records a device that was ever connected. Survives device removal.
pub static USB_ENUM: ArtifactDescriptor = ArtifactDescriptor {
    id: "usb_enum",
    name: "USB Device Enumeration (USBSTOR)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Enum\USBSTOR",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "USB storage device connection history; persists after device removal",
    mitre_techniques: &["T1200", "T1052.001"],
    fields: USB_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1200/",
        "https://attack.mitre.org/techniques/T1052/001/",
        "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-usb-device-tracking/",
        "https://windowsir.blogspot.com/2013/07/usb-device-tracking-in-windows-7.html",
        "https://www.magnetforensics.com/blog/artifact-profile-usb-devices/",
    ],
};

// ── MUICache ──────────────────────────────────────────────────────────────────

pub(crate) static MUICACHE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "display_name",
    value_type: ValueType::Text,
    description: "Localized display name of the executed application",
    is_uid_component: false,
}];

/// MUICache — cached display names of executed applications.
///
/// Value name is the full executable path; data is the localized display name
/// (UTF-16 LE). Program execution evidence that survives log clearing.
pub static MUICACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "muicache",
    name: "MUICache",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"Local Settings\MuiCache",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Utf16Le,
    meaning: "Cached display names keyed by executable path; program execution evidence",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: MUICACHE_FIELDS,
    retention: Some("persists until registry cleanup"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://windowsir.blogspot.com/2012/08/no-more-mr-nice-guy.html",
        "https://www.sans.org/blog/digital-forensics-windows-muicache/",
        "http://windowsir.blogspot.com/2005/12/mystery-of-muicachesolved.html",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-muicache-files-in-windows/",
        "https://forensafe.com/blogs/muicache.html",
    ],
};

// ── AppInit_DLLs ──────────────────────────────────────────────────────────────

pub(crate) static APPINIT_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "dll_list",
    value_type: ValueType::Text,
    description: "Comma/space-separated DLL paths injected into user32.dll consumers",
    is_uid_component: false,
}];

/// AppInit_DLLs — DLL injection into every user-mode process (T1546.010).
///
/// Disabled by Secure Boot; still active on systems without it.
pub static APPINIT_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "appinit_dlls",
    name: "AppInit_DLLs",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Windows",
    value_name: Some("AppInit_DLLs"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs injected into every process that loads user32.dll",
    mitre_techniques: &["T1546.010"],
    fields: APPINIT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/010/",
        "https://learn.microsoft.com/en-us/windows/win32/dlls/registry-keys-for-appinit-dlls",
    ],
};

// ── Winlogon Userinit ─────────────────────────────────────────────────────────

pub(crate) static WINLOGON_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "userinit",
    value_type: ValueType::Text,
    description: "Comma-separated executables launched by Winlogon at logon",
    is_uid_component: false,
}];

/// Winlogon Userinit — process launched after user authentication (T1547.004).
///
/// Default value: `C:\Windows\System32\userinit.exe,`
/// Attackers append `,malware.exe` or replace entirely.
pub static WINLOGON_USERINIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_userinit",
    name: "Winlogon Userinit",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("Userinit"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Process(es) launched by Winlogon at logon; default is userinit.exe,",
    mitre_techniques: &["T1547.004"],
    fields: WINLOGON_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/004/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/winlogon-and-gina",
    ],
};

// ── Screensaver persistence ───────────────────────────────────────────────────

pub(crate) static SCREENSAVER_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Path to the screensaver executable (.scr)",
    is_uid_component: false,
}];

/// Screensaver executable persistence (T1546.002).
///
/// `.scr` files are PE executables; an attacker can replace the screensaver
/// path with a malicious binary that executes when the screen locks.
pub static SCREENSAVER_EXE: ArtifactDescriptor = ArtifactDescriptor {
    id: "screensaver_exe",
    name: "Screensaver Executable",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Control Panel\Desktop",
    value_name: Some("SCRNSAVE.EXE"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Screensaver path; malicious .scr enables persistence on screen lock",
    mitre_techniques: &["T1546.002"],
    fields: SCREENSAVER_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/002/",
        "https://www.sans.org/blog/screensaver-registry-key-for-persistence/",
    ],
};

// ═══════════════════════════════════════════════════════════════════════════
// Batch C — Windows persistence / execution / credential artifacts
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared field schemas (reused across multiple descriptors) ─────────────

/// Generic "command or path" field — suitable for persistence value descriptors.
pub(crate) static PERSIST_CMD_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "command",
    value_type: ValueType::Text,
    description: "Command, DLL path, or executable registered for execution",
    is_uid_component: false,
}];

/// Generic "DLL path" field.
pub(crate) static DLL_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "dll_path",
    value_type: ValueType::Text,
    description: "Path to the DLL registered for injection or loading",
    is_uid_component: false,
}];

/// Generic "directory listing" field for filesystem directory artifacts.
pub(crate) static DIR_ENTRY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "entry_name",
    value_type: ValueType::Text,
    description: "Name of the file or shortcut present in this directory",
    is_uid_component: true,
}];

/// Generic "file path" for single-file artifacts.
pub(crate) static FILE_PATH_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Full path to the artifact file",
    is_uid_component: true,
}];

// ── Windows persistence: advanced registry ────────────────────────────────

/// Winlogon Shell value — replaceable Windows Explorer shell (T1547.004).
///
/// Default: `explorer.exe`. Attackers replace or append to gain persistence
/// that launches their binary as the user's shell at logon.
pub static WINLOGON_SHELL: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_shell",
    name: "Winlogon Shell",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("Shell"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Windows shell process(es) launched by Winlogon; default is explorer.exe",
    mitre_techniques: &["T1547.004"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/004/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/winlogon-and-gina",
    ],
};

/// Windows Services — ImagePath value indicates binary launched as a service.
///
/// Each sub-key under `Services\*` has `ImagePath` (the executable) and
/// `Start` (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled).
pub static SERVICES_IMAGEPATH: ArtifactDescriptor = ArtifactDescriptor {
    id: "services_imagepath",
    name: "Services ImagePath",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services",
    value_name: Some("ImagePath"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executable path of a Windows service; auto-started services persist across reboots",
    mitre_techniques: &["T1543.003"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1543/003/",
        "https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager",
        "https://redcanary.com/threat-detection-report/techniques/t1543/",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
    ],
};

pub(crate) static ACTIVE_SETUP_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "stub_path",
    value_type: ValueType::Text,
    description: "StubPath command executed once per user at logon for new installs",
    is_uid_component: false,
}];

/// Active Setup HKLM — system-side component registration (T1547.014).
///
/// Each CLSID sub-key has `StubPath`. Windows compares HKLM and HKCU versions;
/// if HKCU is missing or older, StubPath is executed as the user at logon.
pub static ACTIVE_SETUP_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "active_setup_hklm",
    name: "Active Setup (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Active Setup\Installed Components",
    value_name: Some("StubPath"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user setup command executed by HKLM Active Setup; malicious StubPath = user-context persistence",
    mitre_techniques: &["T1547.014"],
    fields: ACTIVE_SETUP_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/014/",
        "https://www.sans.org/blog/active-setup-registry-persistence/",
    ],
};

/// Active Setup HKCU — user-side Active Setup version tracking.
///
/// Attacker may delete HKCU entry to trigger HKLM StubPath re-execution.
pub static ACTIVE_SETUP_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "active_setup_hkcu",
    name: "Active Setup (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Active Setup\Installed Components",
    value_name: Some("Version"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "User-side Active Setup version; mismatch with HKLM triggers StubPath re-execution",
    mitre_techniques: &["T1547.014"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1547/014/"],
};

/// COM Hijacking via HKCU CLSID registration (T1546.015).
///
/// When an application resolves a CLSID, Windows checks HKCU\Classes before
/// HKLM. Registering a malicious InprocServer32 in HKCU wins the race
/// without requiring admin privileges.
pub static COM_HIJACK_CLSID_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "com_hijack_clsid_hkcu",
    name: "COM Hijack CLSID (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"CLSID",
    value_name: Some("InprocServer32"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "User-space CLSID registration overriding system COM server; no admin needed",
    mitre_techniques: &["T1546.015"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/015/",
        "https://redcanary.com/threat-detection-report/techniques/t1546/",
    ],
};

/// AppCert DLLs — DLL injected into every process calling CreateProcess (T1546.009).
///
/// Unlike AppInit_DLLs, these are loaded into more process types. Rarely
/// legitimate; any non-empty value is highly suspicious.
pub static APPCERT_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "appcert_dlls",
    name: "AppCertDlls",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager\AppCertDlls",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs injected into every process that calls CreateProcess-family APIs",
    mitre_techniques: &["T1546.009"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/009/",
        "https://learn.microsoft.com/en-us/windows/win32/devnotes/appcertdlls",
    ],
};

pub(crate) static BOOT_EXECUTE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "commands",
    value_type: ValueType::List,
    description: "Commands executed by Session Manager before Win32 subsystem starts",
    is_uid_component: false,
}];

/// Boot Execute — commands run by smss.exe before Win32 subsystem (T1547.001).
///
/// Default: `autocheck autochk *`. Additional entries run native NT executables
/// at boot, before antivirus and most defences are loaded.
pub static BOOT_EXECUTE: ArtifactDescriptor = ArtifactDescriptor {
    id: "boot_execute",
    name: "Boot Execute",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager",
    value_name: Some("BootExecute"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Native executables run by smss.exe at boot; executes before most security software",
    mitre_techniques: &["T1547.001"],
    fields: BOOT_EXECUTE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/boot-time-global-flag-settings",
    ],
};

/// LSA Security Support Providers — SSPs injected into LSASS (T1547.005).
///
/// Legitimate SSPs: kerberos, msv1_0, schannel, wdigest. Extra entries
/// indicate credential-harvesting or persistence.
pub static LSA_SECURITY_PKGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_security_pkgs",
    name: "LSA Security Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Security Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Security Support Providers loaded into LSASS; malicious SSP = persistent LSASS credential access",
    mitre_techniques: &["T1547.005"],
    fields: BOOT_EXECUTE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/005/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication",
    ],
};

/// LSA Authentication Packages — loaded by LSASS for auth (T1547.002).
pub static LSA_AUTH_PKGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_auth_pkgs",
    name: "LSA Authentication Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Authentication Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Authentication packages loaded by LSASS; extra DLLs intercept logon credentials",
    mitre_techniques: &["T1547.002"],
    fields: BOOT_EXECUTE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/002/",
        "https://attack.mitre.org/techniques/T1547/005/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication",
    ],
};

/// Print Monitors — DLL loaded by the spooler service (T1547.010).
///
/// Requires admin. DLL runs as SYSTEM inside spoolsv.exe across reboots.
pub static PRINT_MONITORS: ArtifactDescriptor = ArtifactDescriptor {
    id: "print_monitors",
    name: "Print Monitors",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Print\Monitors",
    value_name: Some("Driver"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLL loaded into spoolsv.exe (SYSTEM); extra monitors = SYSTEM persistence",
    mitre_techniques: &["T1547.010"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/010/",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/print/print-monitor",
    ],
};

/// Time Provider DLLs — loaded into svchost as part of W32Time (T1547.003).
pub static TIME_PROVIDERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "time_providers",
    name: "W32Time Time Provider DLLs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\W32Time\TimeProviders",
    value_name: Some("DllName"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs loaded by the Windows Time service; malicious entry = SYSTEM persistence",
    mitre_techniques: &["T1547.003"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/003/",
        "https://learn.microsoft.com/en-us/windows/win32/sysinfo/time-provider",
    ],
};

/// Netsh Helper DLLs — COM-like DLLs loaded by netsh.exe (T1546.007).
pub static NETSH_HELPER_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "netsh_helper_dlls",
    name: "Netsh Helper DLLs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\NetSh",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs loaded whenever netsh.exe is invoked; attacker DLL runs in user's netsh context",
    mitre_techniques: &["T1546.007"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/007/",
        "https://learn.microsoft.com/en-us/windows/win32/netmgmt/network-management-functions",
    ],
};

pub(crate) static BHO_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "clsid",
    value_type: ValueType::Text,
    description: "CLSID of the Browser Helper Object (sub-key name)",
    is_uid_component: true,
}];

/// Browser Helper Objects — COM components loaded by IE (T1176).
///
/// BHOs run inside iexplore.exe and can intercept HTTP traffic, steal
/// credentials, and maintain persistence via the COM registry.
pub static BROWSER_HELPER_OBJECTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "browser_helper_objects",
    name: "Internet Explorer Browser Helper Objects",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "COM components auto-loaded into IE; can intercept browsing and steal credentials",
    mitre_techniques: &["T1176"],
    fields: BHO_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1176/",
        "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa753582(v=vs.85)",
    ],
};

// ── Windows persistence: filesystem ──────────────────────────────────────

/// User Startup Folder — files/LNKs here execute at user logon (T1547.001).
pub static STARTUP_FOLDER_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_folder_user",
    name: "User Startup Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executables and LNKs here run at user logon; no admin required",
    mitre_techniques: &["T1547.001"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/shell/csidl",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

/// System Startup Folder — files/LNKs here execute for all users at logon.
pub static STARTUP_FOLDER_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_folder_system",
    name: "System Startup Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executables and LNKs run for every user at logon; requires admin to plant",
    mitre_techniques: &["T1547.001"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/001/",
        "https://learn.microsoft.com/en-us/windows/win32/shell/csidl",
    ],
};

/// Windows Task Scheduler task XML files (T1053.005).
///
/// Each task is stored as an XML file; key elements: `<Actions>` (what runs),
/// `<Triggers>` (when), `<Principal>` (which user/privileges).
pub static SCHEDULED_TASKS_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "scheduled_tasks_dir",
    name: "Scheduled Tasks Directory",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\Tasks"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "XML task definitions; malicious tasks can run at boot, logon, or arbitrary intervals",
    mitre_techniques: &["T1053.005"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/005/",
        "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page",
        "https://redcanary.com/threat-detection-report/techniques/t1053/",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
    ],
};

/// WDigest credential caching control (T1003.001).
///
/// Setting `UseLogonCredential` = 1 re-enables cleartext credential caching
/// in LSASS memory on Windows 8.1+ (disabled by default since KB2871997).
pub static WDIGEST_CACHING: ArtifactDescriptor = ArtifactDescriptor {
    id: "wdigest_caching",
    name: "WDigest UseLogonCredential",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\SecurityProviders\WDigest",
    value_name: Some("UseLogonCredential"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning:
        "1 = cleartext creds in LSASS; attackers set this before Mimikatz to harvest passwords",
    mitre_techniques: &["T1003.001"],
    fields: RUN_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/001/",
        "https://redcanary.com/threat-detection-report/techniques/t1003/",
    ],
};

// ── Windows execution evidence ────────────────────────────────────────────

/// WordWheelQuery — Explorer search bar history (MRUListEx).
pub static WORDWHEEL_QUERY: ArtifactDescriptor = ArtifactDescriptor {
    id: "wordwheel_query",
    name: "WordWheelQuery (Explorer Search)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MruListEx,
    meaning:
        "Search terms entered into Windows Explorer search bar; reveals attacker reconnaissance",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://windowsir.blogspot.com/2012/08/wordwheelquery.html",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

/// OpenSaveMRU — files opened/saved via Windows common dialog (T1083).
///
/// Each file extension has a sub-key containing an MRU list of paths.
/// The `*` sub-key shows all extensions combined.
pub static OPENSAVE_MRU: ArtifactDescriptor = ArtifactDescriptor {
    id: "opensave_mru",
    name: "OpenSaveMRU (Common Dialog)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Paths of files opened or saved via Win32 common dialog boxes; per-extension history",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://windowsir.blogspot.com/2006/11/recent-docs-mru.html",
        "https://www.sans.org/blog/opensavemru-and-lastvisitedmru/",
        "https://forensics.wiki/opensavemru/",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

/// LastVisitedMRU — last folder visited in common dialog per-application.
pub static LASTVISITED_MRU: ArtifactDescriptor = ArtifactDescriptor {
    id: "lastvisited_mru",
    name: "LastVisitedMRU (Common Dialog)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Application + last-used folder from common dialog; reveals programs accessing files",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://windowsir.blogspot.com/2006/11/recent-docs-mru.html",
        "https://www.sans.org/blog/opensavemru-and-lastvisitedmru/",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

/// Windows Prefetch files directory — execution evidence (T1204.002).
///
/// Each `.pf` file records: executable name, run count, last 8 run timestamps,
/// and volume/file references. Requires Prefetch service enabled.
pub static PREFETCH_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "prefetch_dir",
    name: "Prefetch Files Directory",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\Prefetch"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Binary .pf files recording 30-day program execution history with timestamps",
    mitre_techniques: &["T1204.002"],
    fields: DIR_ENTRY_FIELDS,
    retention: Some("128 entries; oldest evicted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["shimcache", "amcache_app_file", "bam_user"],
    sources: &[
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-prefetch-files/",
        "https://13cubed.com/downloads/Windows_Forensic_Analysis_Poster.pdf",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier",
        "https://isc.sans.edu/diary/Forensic+Value+of+Prefetch/29168",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/",
        "https://github.com/EricZimmerman/PECmd",
        "https://github.com/EricZimmerman/Prefetch",
    ],
};

pub(crate) static SRUM_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_name",
        value_type: ValueType::Text,
        description: "Application executable path or service name",
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_sid",
        value_type: ValueType::Text,
        description: "SID of the user who ran the application",
        is_uid_component: false,
    },
];

/// System Resource Usage Monitor database — rich execution timeline (Win8+).
///
/// SQLite database at `C:\Windows\System32\sru\SRUDB.dat`. Key tables:
/// `{D10CA2FE-...}` = Application Resource Usage (network, CPU per app),
/// `{5C8CF1C7-...}` = Network Data Usage. Retains ~30-60 days of history.
pub static SRUM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_db",
    name: "SRUM Database (SRUDB.dat)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat"),
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning:
        "Per-app CPU, network, and energy usage records; execution timeline survives log clearing",
    mitre_techniques: &["T1204.002"],
    fields: SRUM_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://www.sans.org/white-papers/36660/",
        "https://www.sans.org/blog/srum-forensics/",
        "https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/",
        "https://github.com/MarkBaggett/srum-dump",
    ],
};

/// Windows Timeline / Activities Cache — cross-device activity history (Win10+).
///
/// SQLite database; `Activity` table records application focus events,
/// file opens, and clipboard content with timestamps.
pub static WINDOWS_TIMELINE: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_timeline",
    name: "Windows Timeline (ActivitiesCache.db)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning:
        "Application activity timeline including focus time, file access, and clipboard events",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: SRUM_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1204/002/",
        "https://www.sans.org/blog/windows-10-timeline-forensic-artifacts/",
        "https://aboutdfir.com/windows-10-timeline/",
        "http://windowsir.blogspot.com/2019/11/activitescachedb-vs-ntuserdat.html",
        "https://kacos2000.github.io/WindowsTimeline/",
        "https://github.com/EricZimmerman/WxTCmd",
    ],
};

/// PowerShell PSReadLine command history (T1059.001).
///
/// Plain-text file; contains full command history including sensitive strings,
/// filenames, and lateral movement commands typed interactively.
pub static POWERSHELL_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_history",
    name: "PowerShell PSReadLine History",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    ),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Line-by-line PowerShell interactive command history; attackers often clear this",
    mitre_techniques: &["T1059.001", "T1552"],
    fields: FILE_PATH_FIELDS,
    retention: Some("4096 commands; oldest evicted when limit reached"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://attack.mitre.org/techniques/T1552/",
        "https://www.sans.org/blog/powershell-forensics/",
        "https://redcanary.com/threat-detection-report/techniques/t1059.001/",
        "https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

/// Recycle Bin ($I metadata files) — deletion evidence (T1070.004).
///
/// Each `$I{RAND}` file (8 bytes header + original path) records file size,
/// deletion timestamp, and original full path of the deleted file.
pub static RECYCLE_BIN: ArtifactDescriptor = ArtifactDescriptor {
    id: "recycle_bin",
    name: "Recycle Bin ($I Metadata)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\$Recycle.Bin\*"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "$I files reveal original path and deletion time even after Recycle Bin is emptied",
    mitre_techniques: &["T1070.004", "T1083"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://attack.mitre.org/techniques/T1083/",
        "https://www.sans.org/blog/digital-forensics-recycle-bin-forensics/",
        "https://windowsir.blogspot.com/2010/02/more-on-recycle-bin.html",
        "https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/",
        "https://andreafortuna.org/2019/09/26/windows-forensics-analysis-of-recycle-bin-artifacts/",
        "https://github.com/EricZimmerman/RBCmd",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

/// Windows Explorer Thumbnail Cache — file-access and image evidence.
///
/// Proprietary binary format; contains thumbnails for files browsed via
/// Explorer, including since-deleted images/documents.
pub static THUMBCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "thumbcache",
    name: "Explorer Thumbnail Cache",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Windows\Explorer"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Cached thumbnails including deleted files; proves files were viewed via Explorer",
    mitre_techniques: &["T1083"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://www.sans.org/blog/thumbnail-cache-forensics/",
        "https://www.nirsoft.net/utils/thumbcache_viewer.html",
        "https://www.pentestpartners.com/security-blog/thumbnail-forensics-dfir-techniques-for-analysing-windows-thumbcache/",
        "https://thumbcacheviewer.github.io/",
        "https://forensics.wiki/windows_thumbcache/",
    ],
};

/// Windows Search database — indexed file/content search history.
///
/// ESE/JET database at the system level recording filenames, content excerpts,
/// and metadata for all indexed items. Survives file deletion.
pub static SEARCH_DB_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "search_db_user",
    name: "Windows Search Database (Windows.db)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "ESE database of indexed file metadata; reveals filenames and content even after deletion",
    mitre_techniques: &["T1083"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1083/",
        "https://www.sans.org/blog/windows-search-index-forensics/",
        "https://learn.microsoft.com/en-us/windows/win32/search/windows-search",
        "https://cyber.aon.com/aon_cyber_labs/windows-search-index-the-forensic-artifact-youve-been-searching-for/",
        "https://github.com/EricZimmerman/SQLECmd",
    ],
};

// ── Windows credential artifacts ──────────────────────────────────────────

pub(crate) static DPAPI_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "guid",
    value_type: ValueType::Text,
    description: "GUID filename of the DPAPI master key or credential blob",
    is_uid_component: true,
}];

/// DPAPI User Master Keys — key material protecting all user-encrypted data.
///
/// Each file is named by a GUID; the content is the DPAPI master key encrypted
/// with the user's password hash. Decrypting unlocks all DPAPI-protected secrets.
pub static DPAPI_MASTERKEY_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_masterkey_user",
    name: "DPAPI User Master Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Protect\*"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Master keys protecting all DPAPI-encrypted user secrets (credentials, browser passwords, WiFi PSKs)",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["dpapi_cred_user", "dpapi_credhist", "chrome_login_data"],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/004/",
        "https://www.sans.org/blog/dpapi-forensics-credentials-stored-in-windows/",
        "https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107",
        "https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/",
    ],
};

/// DPAPI Credential Blobs (Local) — encrypted credential store entries.
///
/// GUID-named binary files; each contains a DPAPI-encrypted credential blob
/// protecting a username/password pair for a network resource or application.
pub static DPAPI_CRED_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_cred_user",
    name: "DPAPI Credential Blobs (Local)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Credentials"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "DPAPI-encrypted credential blobs for network resources; decryptable with DPAPI master key",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["dpapi_masterkey_user", "windows_vault_user"],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/004/",
        "https://www.sans.org/blog/dpapi-forensics-credentials-stored-in-windows/",
        "https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107",
        "https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/",
    ],
};

/// DPAPI Credential Blobs (Roaming) — roaming profile credential store.
pub static DPAPI_CRED_ROAMING: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_cred_roaming",
    name: "DPAPI Credential Blobs (Roaming)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Credentials"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "Roaming DPAPI credential blobs; same structure as Local, synced across domain machines",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/004/",
        "https://www.sans.org/blog/dpapi-forensics-credentials-stored-in-windows/",
        "https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107",
    ],
};

pub(crate) static VAULT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "policy_file",
        value_type: ValueType::Text,
        description: ".vpol policy file containing encryption key material",
        is_uid_component: false,
    },
    FieldSchema {
        name: "vcrd_file",
        value_type: ValueType::Text,
        description: ".vcrd credential file containing the encrypted credential",
        is_uid_component: true,
    },
];

/// Windows Vault (User) — Windows Credential Manager per-user vault.
///
/// `.vpol` file stores encrypted vault key; `.vcrd` files store individual
/// credentials. Credential Manager UI entries live here.
pub static WINDOWS_VAULT_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_vault_user",
    name: "Windows Vault (User)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Vault"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user Credential Manager vault (.vpol + .vcrd); contains WEB and WINDOWS saved credentials",
    mitre_techniques: &["T1555.004"],
    fields: VAULT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/004/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-manager",
        "https://blog.digital-forensics.it/2016/01/windows-revaulting.html",
    ],
};

/// Windows Vault (System) — system-wide Windows Credential Manager vault.
pub static WINDOWS_VAULT_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_vault_system",
    name: "Windows Vault (System)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Vault"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-level Windows Credential Manager vault; contains machine-scoped credentials",
    mitre_techniques: &["T1555.004"],
    fields: VAULT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/004/",
        "https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-manager",
        "https://blog.digital-forensics.it/2016/01/windows-revaulting.html",
    ],
};

pub(crate) static RDP_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "username_hint",
    value_type: ValueType::Text,
    description: "Last username used to connect to this RDP server",
    is_uid_component: false,
}];

/// RDP Saved Server Connections — lateral movement evidence (T1021.001).
///
/// Each sub-key is a hostname/IP; the `UsernameHint` value shows the username
/// used for that connection. Evidence of RDP-based lateral movement.
pub static RDP_CLIENT_SERVERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_client_servers",
    name: "RDP Client Saved Servers",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Terminal Server Client\Servers",
    value_name: Some("UsernameHint"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "Hostnames and usernames of previously-connected RDP servers; lateral movement evidence",
    mitre_techniques: &["T1021.001"],
    fields: RDP_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1021/001/",
        "https://www.sans.org/blog/windows-rdp-forensics/",
        "https://forensafe.com/blogs/rdc.html",
        "https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/",
    ],
};

pub(crate) static RDP_MRU_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "server",
    value_type: ValueType::Text,
    description: "RDP server address from the most-recently-used list",
    is_uid_component: true,
}];

/// RDP Client Default MRU — ordered list of recently connected RDP servers.
pub static RDP_CLIENT_DEFAULT: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_client_default",
    name: "RDP Client Default MRU",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Terminal Server Client\Default",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "MRU0-MRU9 ordered list of RDP server addresses; confirms specific hosts were targeted",
    mitre_techniques: &["T1021.001"],
    fields: RDP_MRU_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1021/001/",
        "https://www.sans.org/blog/windows-rdp-forensics/",
        "https://forensafe.com/blogs/rdc.html",
        "https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/",
    ],
};

pub(crate) static NTDS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Full path to the NTDS.dit file",
    is_uid_component: true,
}];

/// NTDS.dit — Active Directory database (DC only) (T1003.003).
///
/// Contains all domain user account hashes. Extracting and cracking these
/// grants access to every domain account. Requires VSS or offline access.
pub static NTDS_DIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntds_dit",
    name: "Active Directory Database (NTDS.dit)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\NTDS\NTDS.dit"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Domain controller AD database; contains NTLM hashes for all domain accounts",
    mitre_techniques: &["T1003.003"],
    fields: NTDS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/003/",
        "https://www.sans.org/blog/protecting-ad-from-credential-theft/",
    ],
};

pub(crate) static BROWSER_CRED_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "origin_url",
        value_type: ValueType::Text,
        description: "URL the credential is associated with",
        is_uid_component: true,
    },
    FieldSchema {
        name: "username_value",
        value_type: ValueType::Text,
        description: "Saved username",
        is_uid_component: false,
    },
];

/// Chrome/Edge Login Data — SQLite database of saved browser passwords (T1555.003).
pub static CHROME_LOGIN_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_login_data",
    name: "Chrome/Edge Login Data (SQLite)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "SQLite DB with DPAPI-encrypted passwords for saved Chrome/Edge credentials",
    mitre_techniques: &["T1555.003"],
    fields: BROWSER_CRED_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["chrome_cookies", "dpapi_masterkey_user"],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/003/",
        "https://redcanary.com/threat-detection-report/techniques/t1555/",
        "https://atropos4n6.com/windows/chrome-login-data-forensics/",
        "https://www.foxtonforensics.com/blog/post/analysing-chrome-login-data",
        "https://github.com/EricZimmerman/SQLECmd",
    ],
};

pub(crate) static FIREFOX_CRED_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "hostname",
    value_type: ValueType::Text,
    description: "Hostname the Firefox credential is associated with",
    is_uid_component: true,
}];

/// Firefox logins.json — JSON credential store (T1555.003).
///
/// NSS3-encrypted credentials; decryptable with `key4.db` and user's Firefox password.
pub static FIREFOX_LOGINS: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_logins",
    name: "Firefox logins.json",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning:
        "NSS3-encrypted Firefox saved credentials; decryptable with key4.db and master password",
    mitre_techniques: &["T1555.003"],
    fields: FIREFOX_CRED_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1555/003/",
        "https://redcanary.com/threat-detection-report/techniques/t1555/",
        "https://atropos4n6.com/windows/chrome-login-data-forensics/",
    ],
};

pub(crate) static WIFI_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "ssid",
        value_type: ValueType::Text,
        description: "WiFi network SSID (network name)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "key_material",
        value_type: ValueType::Text,
        description: "Pre-shared key or 802.1X EAP credentials (may be DPAPI-encrypted)",
        is_uid_component: false,
    },
];

/// Wireless Network Profiles — contains PSKs for previously joined networks (T1552.001).
///
/// XML files; `<keyMaterial>` field may contain the plaintext PSK or a
/// DPAPI-encrypted blob depending on profile type.
pub static WIFI_PROFILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "wifi_profiles",
    name: "Wireless Network Profiles (WLAN)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "XML profiles for previously joined WiFi networks; may contain plaintext PSKs",
    mitre_techniques: &["T1552.001"],
    fields: WIFI_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1552/001/",
        "https://www.sans.org/blog/wireless-forensics/",
        "https://forensafe.com/blogs/winwirelessnetworks.html",
    ],
};

// ═══════════════════════════════════════════════════════════════════════════
// Batch D — Linux persistence / execution / credential artifacts
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared Linux field schemas ────────────────────────────────────────────

/// Cron / script line — single scheduled command or shell line.
pub(crate) static CRON_LINE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "schedule_line",
    value_type: ValueType::Text,
    description: "Cron schedule expression and command, or shell script line",
    is_uid_component: false,
}];

/// SSH public key entry.
pub(crate) static SSH_KEY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "public_key",
    value_type: ValueType::Text,
    description: "SSH public key entry (key-type base64 comment)",
    is_uid_component: true,
}];

/// Linux account entry (colon-delimited fields).
pub(crate) static ACCOUNT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "username",
        value_type: ValueType::Text,
        description: "Account username",
        is_uid_component: true,
    },
    FieldSchema {
        name: "uid",
        value_type: ValueType::UnsignedInt,
        description: "Numeric user ID (0 = root)",
        is_uid_component: false,
    },
];

/// Log line / journal entry.
pub(crate) static LOG_LINE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "log_line",
    value_type: ValueType::Text,
    description: "Log line or structured journal entry",
    is_uid_component: false,
}];

// ── Linux persistence: cron ───────────────────────────────────────────────

/// System-wide crontab at `/etc/crontab` (T1053.003).
///
/// Format: `minute hour dom month dow user command`. Field `user` distinguishes
/// this from per-user crontabs. Any non-root `user` with unusual commands is suspicious.
pub static LINUX_CRONTAB_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_crontab_system",
    name: "System Crontab (/etc/crontab)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/crontab"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "System-wide scheduled job definitions; user field allows cross-account execution",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/003/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/5/crontab",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
    ],
};

/// Drop-in cron jobs directory `/etc/cron.d/` (T1053.003).
///
/// Files here follow the same format as `/etc/crontab` (with user field).
/// Attackers drop files here for system-level persistence without editing crontab.
pub static LINUX_CRON_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_cron_d",
    name: "Cron Drop-in Directory (/etc/cron.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/cron.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Drop-in cron files with full crontab format; easy to add without touching crontab",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/003/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
    ],
};

/// Periodic cron directories (daily/hourly/weekly/monthly) (T1053.003).
///
/// Scripts placed here are executed by run-parts at the named interval.
/// No schedule expression needed — just a plain executable script.
pub static LINUX_CRON_PERIODIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_cron_periodic",
    name: "Cron Periodic Directories (/etc/cron.{daily,hourly,weekly,monthly}/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/cron.daily"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Shell scripts executed periodically by crond/anacron; no schedule syntax required",
    mitre_techniques: &["T1053.003"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1053/003/"],
};

/// Per-user crontab spool at `/var/spool/cron/crontabs/{user}` (T1053.003).
///
/// Each file is owned by and runs commands as the named user.
/// `crontab -e` edits this file. Direct edits by root are possible.
pub static LINUX_USER_CRONTAB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_user_crontab",
    name: "Per-User Crontab Spool",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/spool/cron/crontabs/*"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-user scheduled jobs; attacker can set up recurring execution without admin",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/003/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
    ],
};

/// Anacron configuration at `/etc/anacrontab`.
///
/// Anacron runs jobs that were missed due to system downtime — useful for
/// laptops. Format: `period delay job-id command`.
pub static LINUX_ANACRONTAB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_anacrontab",
    name: "Anacrontab (/etc/anacrontab)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/anacrontab"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Deferred cron jobs for irregular uptime; period-based rather than time-based",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/003/",
        "https://linux.die.net/man/8/anacron",
    ],
};

// ── Linux persistence: systemd ────────────────────────────────────────────

/// System-level systemd service units (T1543.002).
///
/// `.service` files in `/etc/systemd/system/` (admin-installed, highest priority)
/// or `/lib/systemd/system/` (package-installed). Key fields: `ExecStart`,
/// `WantedBy`, `After`. Malicious units often `WantedBy=multi-user.target`.
pub static LINUX_SYSTEMD_SYSTEM_UNIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_system_unit",
    name: "systemd System Service Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/systemd/system"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning:
        "Service definitions executed as root at boot; WantedBy=multi-user.target = auto-start",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1543/002/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://www.freedesktop.org/software/systemd/man/systemd.unit.html",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
        "https://www.elastic.co/security-labs/primer-on-persistence-mechanisms",
    ],
};

/// Per-user systemd service units (T1543.002).
///
/// Stored in `~/.config/systemd/user/*.service`; executed as the user's
/// session starts. No root required. `systemctl --user enable` activates.
pub static LINUX_SYSTEMD_USER_UNIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_user_unit",
    name: "systemd User Service Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/systemd/user"),
    scope: DataScope::User,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "User-scope service definitions; executed without root on user login",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1543/002/",
        "https://www.freedesktop.org/software/systemd/man/systemd.unit.html",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
    ],
};

/// systemd timer units — cron-like scheduling (T1053.006).
///
/// `.timer` files trigger associated `.service` units on a schedule.
/// More flexible than cron: supports calendar expressions and monotonic timers.
pub static LINUX_SYSTEMD_TIMER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_timer",
    name: "systemd Timer Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/systemd/system"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Timer-based scheduled execution; malicious timers trigger services on a schedule",
    mitre_techniques: &["T1053.006"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1053/006/",
        "https://www.freedesktop.org/software/systemd/man/systemd.timer.html",
        "https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/",
    ],
};

// ── Linux persistence: init / rc.local ───────────────────────────────────

/// `/etc/rc.local` — legacy startup script (T1037.004).
///
/// Executed at the end of each multiuser runlevel. Still supported on most
/// distros. Must be executable (+x). Any command here runs as root at boot.
pub static LINUX_RC_LOCAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rc_local",
    name: "rc.local Startup Script",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/rc.local"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Legacy boot-time script executed as root; simple and widely supported",
    mitre_techniques: &["T1037.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1037/004/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
        "https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms",
    ],
};

/// SysV init scripts directory `/etc/init.d/`.
///
/// Scripts here are executed by the init system at specific runlevels.
/// Symlinks in `/etc/rc{N}.d/` control when they run. Legacy but still present.
pub static LINUX_INIT_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_init_d",
    name: "SysV Init Scripts (/etc/init.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/init.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SysV init scripts; malicious script here runs at boot across reboots",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1543/002/",
        "https://attack.mitre.org/techniques/T1037/004/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

// ── Linux persistence: shell startup files ────────────────────────────────

/// `~/.bashrc` — per-user Bash interactive shell startup (T1546.004).
///
/// Sourced for every non-login interactive bash shell. Attackers add aliases,
/// functions, or background processes here. Survives reboots.
pub static LINUX_BASHRC_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bashrc_user",
    name: "User ~/.bashrc",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bashrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on every interactive bash session; persistent aliases, functions, or background processes",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
        "https://www.elastic.co/guide/en/security/current/bash-shell-profile-modification.html",
    ],
};

/// `~/.bash_profile` — Bash login shell startup (T1546.004).
pub static LINUX_BASH_PROFILE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bash_profile_user",
    name: "User ~/.bash_profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bash_profile"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on Bash login shells; runs at SSH login and console login",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

/// `~/.profile` — POSIX login shell startup.
pub static LINUX_PROFILE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_user",
    name: "User ~/.profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.profile"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "POSIX login shell startup; sourced by sh, dash, and bash on login",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

/// `~/.zshrc` — per-user Zsh interactive startup (T1546.004).
pub static LINUX_ZSHRC_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_zshrc_user",
    name: "User ~/.zshrc",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.zshrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on every interactive Zsh session; same persistence vector as .bashrc",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

/// `/etc/profile` — system-wide login shell startup.
pub static LINUX_PROFILE_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_system",
    name: "System /etc/profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/profile"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "System-wide login shell startup; modifications affect all users",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

/// `/etc/profile.d/` — drop-in system-wide shell startup scripts.
pub static LINUX_PROFILE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_d",
    name: "System /etc/profile.d/ Drop-ins",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/profile.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Shell scripts sourced by /etc/profile for all users at login; drop-in persistence",
    mitre_techniques: &["T1546.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/",
    ],
};

// ── Linux persistence: dynamic linker ────────────────────────────────────

/// `/etc/ld.so.preload` — system-wide library preload (T1574.006).
///
/// Libraries listed here are loaded into EVERY process before any other
/// library, including setuid binaries. This is a classic rootkit technique.
/// An empty or absent file is normal; ANY entry is highly suspicious.
pub static LINUX_LD_SO_PRELOAD: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ld_so_preload",
    name: "Dynamic Linker Preload (/etc/ld.so.preload)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ld.so.preload"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Libraries preloaded into EVERY process system-wide; standard rootkit hiding mechanism",
    mitre_techniques: &["T1574.006"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1574/006/",
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://www.wiz.io/blog/linux-rootkits-explained-part-1-dynamic-linker-hijacking",
        "https://www.sentinelone.com/labs/leveraging-ld_audit-to-beat-the-traditional-linux-library-preloading-technique/",
    ],
};

/// `/etc/ld.so.conf.d/` — linker search path configuration (T1574.006).
///
/// Adding a directory containing malicious `.so` files here allows library
/// hijacking without needing LD_PRELOAD.
pub static LINUX_LD_SO_CONF_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ld_so_conf_d",
    name: "Linker Config Directory (/etc/ld.so.conf.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ld.so.conf.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Library search path config; malicious entry adds attacker directory to ldconfig paths",
    mitre_techniques: &["T1574.006"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1574/006/"],
};

// ── Linux persistence: SSH ────────────────────────────────────────────────

/// SSH authorized_keys — persistent backdoor public keys (T1098.004).
///
/// Any public key listed here allows passwordless SSH login as the owner.
/// Attackers add their key for persistent remote access.
pub static LINUX_SSH_AUTHORIZED_KEYS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_authorized_keys",
    name: "SSH authorized_keys",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/authorized_keys"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Public keys permitting passwordless SSH login; attacker key = permanent backdoor",
    mitre_techniques: &["T1098.004"],
    fields: SSH_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1098/004/",
        "https://www.sans.org/blog/ssh-backdoors/",
        "https://sandflysecurity.com/blog/detecting-unauthorized-ssh-keys-in-linux/",
    ],
};

// ── Linux persistence: PAM / privilege / kernel ───────────────────────────

/// `/etc/pam.d/` — PAM module configuration (T1556.003).
///
/// Each file configures authentication for a service (e.g., `sshd`, `sudo`,
/// `su`). Replacing `pam_unix.so` or adding a malicious module intercepts
/// ALL authentication for that service.
pub static LINUX_PAM_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_pam_d",
    name: "PAM Configuration (/etc/pam.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/pam.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "PAM module configs per service; malicious module intercepts and logs all passwords",
    mitre_techniques: &["T1556.003"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1556/003/"],
};

/// `/etc/sudoers.d/` — drop-in sudoers rules (T1548.003).
///
/// `NOPASSWD` entries allow sudo without password. Attackers add entries for
/// specific commands or ALL commands without password prompting.
pub static LINUX_SUDOERS_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sudoers_d",
    name: "Sudoers Drop-ins (/etc/sudoers.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/sudoers.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Drop-in sudoers rules; NOPASSWD entries enable privilege escalation without credentials",
    mitre_techniques: &["T1548.003"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1548/003/"],
};

/// `/etc/modules-load.d/` — kernel modules loaded at boot (T1547.006).
///
/// Each `.conf` file lists module names to load. Attackers register a
/// rootkit or malicious kernel module here for persistent kernel-level access.
pub static LINUX_MODULES_LOAD_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_modules_load_d",
    name: "Kernel Module Load Config (/etc/modules-load.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/modules-load.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Kernel modules auto-loaded at boot; rootkit module here = persistent kernel access",
    mitre_techniques: &["T1547.006"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1547/006/"],
};

/// `/etc/update-motd.d/` — dynamic MOTD scripts executed on login (Debian/Ubuntu).
///
/// Every script here runs as root at SSH login to generate the MOTD.
/// A persistent backdoor can be hidden here as it looks like a status script.
pub static LINUX_MOTD_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_motd_d",
    name: "Dynamic MOTD Scripts (/etc/update-motd.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/update-motd.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "Scripts run as root at SSH login for MOTD generation; covert execution vector",
    mitre_techniques: &["T1037.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1037/004/"],
};

/// `/etc/udev/rules.d/` — udev device event rules (T1546).
///
/// Rules can execute commands when devices are connected. An attacker can
/// create a rule that runs a payload whenever a USB is inserted or a network
/// interface comes up.
pub static LINUX_UDEV_RULES_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_udev_rules_d",
    name: "udev Rules (/etc/udev/rules.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/udev/rules.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Device event rules; RUN+= directive executes payload on device attach/detach",
    mitre_techniques: &["T1546"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1546/"],
};

// ── Linux execution evidence ──────────────────────────────────────────────

/// `~/.bash_history` — Bash interactive command history (T1059.004).
///
/// Contains commands entered in interactive Bash sessions. Attackers often
/// clear this with `history -c` or `unset HISTFILE`. An absent or empty file
/// is itself suspicious.
pub static LINUX_BASH_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bash_history",
    name: "Bash History (~/.bash_history)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bash_history"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Interactive Bash command history; reveals lateral movement, exfil, and recon commands",
    mitre_techniques: &["T1059.004", "T1552"],
    fields: CRON_LINE_FIELDS,
    retention: Some("HISTSIZE limit; default 500-2000 commands"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/004/",
        "https://attack.mitre.org/techniques/T1552/",
    ],
};

/// `~/.zsh_history` — Zsh interactive command history.
pub static LINUX_ZSH_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_zsh_history",
    name: "Zsh History (~/.zsh_history)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.zsh_history"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Interactive Zsh command history; extended format optionally includes timestamps",
    mitre_techniques: &["T1059.004", "T1552"],
    fields: CRON_LINE_FIELDS,
    retention: Some("HISTSIZE limit; default 500-2000 commands"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/004/",
        "https://attack.mitre.org/techniques/T1552/",
    ],
};

/// `/var/log/wtmp` — binary successful login history (T1078).
///
/// Utmp-format binary file; `last` command reads it. Records login, logout,
/// reboot, and shutdown events. Tampered by log-clearing tools.
pub static LINUX_WTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_wtmp",
    name: "Login History (/var/log/wtmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/wtmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Binary record of all successful logins/logouts/reboots; evidence of valid-account abuse",
    mitre_techniques: &["T1078", "T1021.004"],
    fields: LOG_LINE_FIELDS,
    retention: Some("until rotated by logrotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1078/",
        "https://attack.mitre.org/techniques/T1021/004/",
        "https://linux.die.net/man/5/wtmp",
        "https://www.sans.org/blog/linux-forensics-artifacts/",
        "https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28",
        "https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering",
    ],
};

/// `/var/log/btmp` — binary failed login attempts.
///
/// Utmp-format binary; `lastb` command reads it. Brute-force evidence.
pub static LINUX_BTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_btmp",
    name: "Failed Login Attempts (/var/log/btmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/btmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary record of failed authentication attempts; brute-force and credential-stuffing evidence",
    mitre_techniques: &["T1110"],
    fields: LOG_LINE_FIELDS,
    retention: Some("until rotated by logrotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1110/",
        "https://linux.die.net/man/5/wtmp",
        "https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28",
        "https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering",
    ],
};

/// `/var/log/lastlog` — binary last-login-per-UID database.
///
/// Fixed-offset binary file indexed by UID. `lastlog` command reads it.
/// Each entry records last login time and source IP.
pub static LINUX_LASTLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_lastlog",
    name: "Last Login Database (/var/log/lastlog)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/lastlog"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-UID last-login record including source IP; never-logged-in vs recent entries",
    mitre_techniques: &["T1078"],
    fields: LOG_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1078/"],
};

/// `/var/log/auth.log` — authentication and sudo event log (Debian/Ubuntu).
///
/// Contains PAM authentication events, sudo commands, SSH logins, and su usage.
/// Red Hat equivalent: `/var/log/secure`.
pub static LINUX_AUTH_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_auth_log",
    name: "Auth Log (/var/log/auth.log)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/auth.log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "PAM auth events, SSH logins, sudo commands, su usage; primary lateral-movement log",
    mitre_techniques: &["T1078", "T1548.003"],
    fields: LOG_LINE_FIELDS,
    retention: Some("until rotated by logrotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1078/",
        "https://attack.mitre.org/techniques/T1548/003/",
    ],
};

/// systemd journal directory `/var/log/journal/`.
///
/// Binary journal files; `journalctl` reads them. Contains all system and
/// service log messages. More tamper-resistant than syslog text files.
pub static LINUX_JOURNAL_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_journal_dir",
    name: "systemd Journal (/var/log/journal/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/journal"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning:
        "Structured binary system journal; includes boot IDs, service crashes, and audit events",
    mitre_techniques: &["T1078", "T1059.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: Some("50MB or 1 month default; configurable in journald.conf"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1078/",
        "https://attack.mitre.org/techniques/T1059/004/",
    ],
};

// ── Linux credential artifacts ────────────────────────────────────────────

/// `/etc/passwd` — local user account database (T1087.001).
///
/// World-readable; fields: `user:x:uid:gid:gecos:home:shell`.
/// UID=0 duplicates, unusual shells (`/bin/bash` for service accounts),
/// and accounts with homedir `/` are suspicious.
pub static LINUX_PASSWD: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_passwd",
    name: "User Account Database (/etc/passwd)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/passwd"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Local user enumeration; UID=0 duplicates or unusual shells indicate backdoor accounts",
    mitre_techniques: &["T1087.001", "T1136.001"],
    fields: ACCOUNT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1087/001/",
        "https://attack.mitre.org/techniques/T1136/001/",
        "https://linux.die.net/man/5/passwd",
        "https://bromiley.medium.com/torvalds-tuesday-user-accounts-597b4ca9dcaf",
    ],
};

/// `/etc/shadow` — password hash database (T1003.008).
///
/// Root-readable only. Hash formats: `$1$`=MD5, `$5$`=SHA256, `$6$`=SHA512,
/// `$y$`=yescrypt (modern). `*` or `!` prefix = locked account.
pub static LINUX_SHADOW: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_shadow",
    name: "Shadow Password File (/etc/shadow)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/shadow"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Password hashes for all local accounts; crackable offline once read",
    mitre_techniques: &["T1003.008"],
    fields: ACCOUNT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1003/008/",
        "https://www.sans.org/blog/linux-password-security/",
        "https://bromiley.medium.com/torvalds-tuesday-user-accounts-597b4ca9dcaf",
    ],
};

/// SSH private key files — stolen keys enable impersonation (T1552.004).
///
/// Unencrypted keys (no `Proc-Type: ENCRYPTED` header) are immediately usable.
/// Encrypted keys require the passphrase but are still high-value targets.
pub static LINUX_SSH_PRIVATE_KEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_private_key",
    name: "SSH Private Keys (~/.ssh/id_*)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/id_*"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "Private key material for SSH authentication; unencrypted keys = immediate lateral movement",
    mitre_techniques: &["T1552.004"],
    fields: SSH_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/004/"],
};

/// `~/.ssh/known_hosts` — previously connected SSH server fingerprints (T1021.004).
///
/// Records host key fingerprints of servers the user has connected to.
/// Reveals lateral movement destinations and external access patterns.
pub static LINUX_SSH_KNOWN_HOSTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_known_hosts",
    name: "SSH Known Hosts (~/.ssh/known_hosts)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/known_hosts"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Previously-connected SSH server fingerprints; lateral movement destination history",
    mitre_techniques: &["T1021.004", "T1083"],
    fields: SSH_KEY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1021/004/",
        "https://attack.mitre.org/techniques/T1083/",
    ],
};

/// `~/.gnupg/private-keys-v1.d/` — GnuPG private key store (T1552.004).
///
/// Modern GnuPG (2.1+) stores one `.key` file per secret key.
/// Exporting these enables code-signing forgery and decryption of PGP messages.
pub static LINUX_GNUPG_PRIVATE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gnupg_private",
    name: "GnuPG Private Key Store (~/.gnupg/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.gnupg"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GnuPG private keys; enables message decryption and code-signing forgery",
    mitre_techniques: &["T1552.004"],
    fields: DPAPI_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/004/"],
};

/// `~/.aws/credentials` — AWS access key material (T1552.001).
///
/// INI-format file with `aws_access_key_id` and `aws_secret_access_key`.
/// May also contain `aws_session_token` for temporary credentials.
pub static LINUX_AWS_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_aws_credentials",
    name: "AWS Credentials (~/.aws/credentials)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.aws/credentials"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "AWS long-term or temporary credentials; enables cloud infrastructure compromise",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

/// `~/.docker/config.json` — Docker registry auth tokens (T1552.001).
///
/// Contains base64-encoded `auth` tokens or `credsStore` references for
/// container registries. Grants push/pull access to private registries.
pub static LINUX_DOCKER_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_config",
    name: "Docker Config (~/.docker/config.json)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.docker/config.json"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Docker registry credentials; enables container image exfil or malicious image push",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

// ── Batch E — Windows execution / persistence / credential ───────────────────

// ── Execution evidence ────────────────────────────────────────────────────────

pub static LNK_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "lnk_files",
    name: "LNK / Shell Link Recent Files",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Shell Link (.lnk) files record target path, MAC timestamps, volume serial, and \
              NetBIOS host — evidence of file access even after target deletion. T1547.009.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["jump_list_auto", "mru_recent_docs"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/009/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://github.com/EricZimmerman/LECmd",
        "https://github.com/EricZimmerman/Lnk",
    ],
};

pub static JUMP_LIST_AUTO: ArtifactDescriptor = ArtifactDescriptor {
    id: "jump_list_auto",
    name: "Jump Lists — AutomaticDestinations",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "OLE Compound Document storing per-AppID MRU lists; reveals recently opened files \
              for each application including timestamps and target metadata.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["lnk_files", "mru_recent_docs"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/009/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://github.com/EricZimmerman/JLECmd",
        "https://github.com/EricZimmerman/JumpList",
    ],
};

pub static JUMP_LIST_CUSTOM: ArtifactDescriptor = ArtifactDescriptor {
    id: "jump_list_custom",
    name: "Jump Lists — CustomDestinations",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Application-pinned and custom jump list entries; may persist after file deletion, \
              revealing attacker-pinned tools or exfiltrated document access.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["lnk_files", "jump_list_auto"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/009/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://github.com/EricZimmerman/JLECmd",
        "https://github.com/EricZimmerman/JumpList",
    ],
};

pub static EVTX_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_dir",
    name: "Windows Event Log Directory (EVTX)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\winevt\Logs\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Binary EVTX log files — Security.evtx (4624/4625/4688), System.evtx, \
              PowerShell/Operational.evtx. Primary execution, logon, and process-creation record.",
    mitre_techniques: &["T1070.001", "T1059.001"],
    fields: DIR_ENTRY_FIELDS,
    retention: Some("configurable; default ~20MB rolling per channel"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1070/001/",
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://github.com/EricZimmerman/evtx",
    ],
};

pub static MFT_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "mft_file",
    name: "Master File Table ($MFT)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\$MFT"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Primary NTFS metadata file containing timestamps, attributes, parent-child relationships, and deleted-entry evidence for every file record on the volume.",
    mitre_techniques: &["T1070.004", "T1083"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["usn_journal", "recycle_bin", "prefetch_file"],
    sources: &[
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://attack.mitre.org/techniques/T1083/",
        "https://github.com/EricZimmerman/MFTECmd",
    ],
};

pub static USN_JOURNAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "usn_journal",
    name: "USN Journal ($UsnJrnl:$J)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"\\.\C:\$Extend\$UsnJrnl:$J"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "NTFS change journal records file create/delete/rename operations with USN sequence \
              number; persists even after file deletion, proving prior file existence.",
    mitre_techniques: &["T1070.004", "T1059"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://attack.mitre.org/techniques/T1059/",
        "https://github.com/EricZimmerman/MFTECmd",
    ],
};

// ── Persistence ───────────────────────────────────────────────────────────────

pub static WMI_MOF_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_mof_dir",
    name: "WMI MOF Subscription Repository",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\wbem\Repository\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "WMI CIM repository stores EventFilter, EventConsumer, and FilterToConsumerBinding \
              objects; persistence survives reboots and is invisible to registry-only tools.",
    mitre_techniques: &["T1546.003"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/003/",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-and-responding-to-events-with-standard-consumers",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding",
    ],
};

pub static BITS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "bits_db",
    name: "BITS Job Queue Database",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Network\Downloader\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Background Intelligent Transfer Service queue DB (qmgr0.dat); records download \
              jobs including URL, destination, and command-to-notify — abused for stealthy malware staging.",
    mitre_techniques: &["T1197"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1197/",
        "https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal",
        "https://learn.microsoft.com/en-us/powershell/module/bitstransfer/get-bitstransfer?view=windowsserver2025-ps",
        "https://www.sans.org/white-papers/39195",
    ],
};

pub(crate) static WMI_SUB_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "filter_name",
        description: "WMI EventFilter name",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "consumer_type",
        description: "Consumer type (Script/CommandLine)",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_value",
        description: "Script or command executed on trigger",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "query",
        description: "WQL query that triggers the subscription",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static WMI_SUBSCRIPTIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_subscriptions",
    name: "WMI Event Subscriptions (Registry)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\WBEM\ESS\//./root/subscription",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MultiSz,
    meaning: "Registry-side index of WMI subscriptions; cross-reference with MOF repository for \
              complete picture of WMI-based persistence.",
    mitre_techniques: &["T1546.003"],
    fields: WMI_SUB_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/003/",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-and-responding-to-events-with-standard-consumers",
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding",
    ],
};

pub static LOGON_SCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "logon_scripts",
    name: "Logon Scripts (UserInitMprLogonScript)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Environment",
    value_name: Some("UserInitMprLogonScript"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Script executed at logon via WinLogon; per-user value allowing unprivileged \
              persistence that survives password resets.",
    mitre_techniques: &["T1037.001"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1037/001/"],
};

pub static WINSOCK_LSP: ArtifactDescriptor = ArtifactDescriptor {
    id: "winsock_lsp",
    name: "Winsock Layered Service Provider",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "LSP DLLs intercept all Winsock traffic; malicious LSPs can log credentials from \
              plaintext protocols. Rare but high-signal indicator of network interception.",
    mitre_techniques: &["T1547.010"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1547/010/"],
};

pub static APPSHIM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "appshim_db",
    name: "Application Shim Database",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\apppatch\Custom\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Custom SDB shim databases; attackers inject shims to redirect API calls, \
              disable security checks, or load malicious DLLs without modifying the target binary.",
    mitre_techniques: &["T1546.011"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1546/011/"],
};

pub static PASSWORD_FILTER_DLL: ArtifactDescriptor = ArtifactDescriptor {
    id: "password_filter_dll",
    name: "Password Filter DLL (Notification Packages)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Notification Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MultiSz,
    meaning: "DLLs registered here receive cleartext passwords during every password change; \
              malicious filter captures and exfiltrates credentials.",
    mitre_techniques: &["T1556.002"],
    fields: DLL_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1556/002/"],
};

pub static OFFICE_NORMAL_DOTM: ArtifactDescriptor = ArtifactDescriptor {
    id: "office_normal_dotm",
    name: "Office Normal Template (Normal.dotm)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Templates\Normal.dotm"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Global Word template auto-loaded on every document open; malicious macros \
              embedded here achieve persistence across all Word sessions.",
    mitre_techniques: &["T1137.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1137/001/"],
};

pub static POWERSHELL_PROFILE_ALL: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_profile_all",
    name: "PowerShell All-Users Profile (profile.ps1)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-wide PowerShell profile executed for every user on every PS session start; \
              SYSTEM-writable, provides privileged persistence without registry modification.",
    mitre_techniques: &["T1546.013"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1546/013/"],
};

// ── Credentials ───────────────────────────────────────────────────────────────

pub static DPAPI_SYSTEM_MASTERKEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_system_masterkey",
    name: "DPAPI System Master Key",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "DPAPI master keys for the SYSTEM account; used to decrypt SYSTEM-scope secrets \
              such as LSA secrets, service credentials, and scheduled task credentials.",
    mitre_techniques: &["T1555.004"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["lsa_secrets", "dpapi_masterkey_user"],
    sources: &["https://attack.mitre.org/techniques/T1555/004/"],
};

pub static DPAPI_CREDHIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_credhist",
    name: "DPAPI CREDHIST File",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Protect\CREDHIST"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Chain of previous DPAPI master key derivation entries; enables decryption of \
              secrets encrypted with old passwords after a password change.",
    mitre_techniques: &["T1555.004"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["dpapi_masterkey_user"],
    sources: &["https://attack.mitre.org/techniques/T1555/004/"],
};

pub static CHROME_COOKIES: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_cookies",
    name: "Chrome/Edge Cookies (SQLite)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database of browser session/authentication cookies; adversaries can replay \
              these to bypass MFA and impersonate authenticated sessions (pass-the-cookie).",
    mitre_techniques: &["T1539", "T1185"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["chrome_login_data"],
    sources: &[
        "https://attack.mitre.org/techniques/T1539/",
        "https://attack.mitre.org/techniques/T1185/",
        "https://github.com/EricZimmerman/SQLECmd",
    ],
};

pub static EDGE_WEBCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_webcache",
    name: "IE/Edge Legacy WebCacheV01.dat",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "ESE database recording all IE/Edge Legacy web history, downloads, and cached \
              content; reveals browsing patterns and potential data exfiltration URLs.",
    mitre_techniques: &["T1539", "T1217"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Low,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1539/",
        "https://attack.mitre.org/techniques/T1217/",
    ],
};

pub static VPN_RAS_PHONEBOOK: ArtifactDescriptor = ArtifactDescriptor {
    id: "vpn_ras_phonebook",
    name: "VPN Credentials — RAS Phonebook",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Plain-text INI phonebook storing VPN connection entries including server address \
              and saved credential references; reveals network pivoting paths.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Low,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

pub static WINDOWS_HELLO_NGC: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_hello_ngc",
    name: "Windows Hello / NGC Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Ngc\"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Stores Windows Hello credential provider keys (PIN protectors, biometric keys); \
              compromise reveals authentication material bypassing traditional password forensics.",
    mitre_techniques: &["T1555"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1555/"],
};

pub static USER_CERT_PRIVATE_KEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "user_cert_private_key",
    name: "User Certificate Private Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\SystemCertificates\My\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "DPAPI-protected user certificate private keys for code signing, S/MIME, and \
              smart-card emulation; exfiltration enables impersonation and signing of malicious artifacts.",
    mitre_techniques: &["T1552.004"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1552/004/",
    ],
};

pub static MACHINE_CERT_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "machine_cert_store",
    name: "Machine Certificate Private Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Machine-scope RSA private keys protected by DPAPI SYSTEM; used for TLS mutual \
              auth, code signing, and IPSec — high-value credential exfiltration target.",
    mitre_techniques: &["T1552.004"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/004/"],
};

// ── Batch F — Linux extended credentials / execution ─────────────────────────

pub static LINUX_AT_QUEUE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_at_queue",
    name: "AT Job Queue (/var/spool/at/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/spool/at/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "One-shot delayed execution jobs from the `at` command; each file contains a shell \
              script to run at a specified time, used for stealthy one-shot persistence.",
    mitre_techniques: &["T1053.001"],
    fields: CRON_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1053/001/"],
};

pub static LINUX_SSHD_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sshd_config",
    name: "SSH Daemon Configuration (/etc/ssh/sshd_config)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ssh/sshd_config"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SSH server config; look for unauthorized AuthorizedKeysFile overrides, \
              ForceCommand bypass, PermitRootLogin yes, or AllowUsers modifications.",
    mitre_techniques: &["T1098.004", "T1021.004"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1098/004/",
        "https://attack.mitre.org/techniques/T1021/004/",
    ],
};

pub static LINUX_ETC_GROUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_etc_group",
    name: "Group Accounts (/etc/group)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/group"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Group membership database; cross-reference with /etc/passwd and sudo log to \
              detect unauthorized group additions (e.g., added to `sudo` or `docker` group).",
    mitre_techniques: &["T1087.001", "T1078.003"],
    fields: ACCOUNT_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1087/001/",
        "https://attack.mitre.org/techniques/T1078/003/",
    ],
};

pub static LINUX_GNOME_KEYRING: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gnome_keyring",
    name: "GNOME Keyring (keyrings/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.local/share/keyrings/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GNOME keyring stores WiFi PSK, SSH passphrases, web service passwords, and \
              browser master passwords encrypted with user login credential.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1555/003/"],
};

pub static LINUX_KDE_KWALLET: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kde_kwallet",
    name: "KDE KWallet (kwalletd/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.local/share/kwalletd/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "KDE wallet encrypted credential store; stores passwords, SSH keys, and browser \
              credentials for KDE applications.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1555/003/"],
};

pub static LINUX_CHROME_LOGIN_LINUX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_chrome_login_linux",
    name: "Chrome/Chromium Login Data (Linux)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/google-chrome/Default/Login Data"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SQLite database of saved Chrome passwords on Linux; encryption key stored in \
              GNOME Keyring or plaintext depending on configuration.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1555/003/"],
};

pub static LINUX_FIREFOX_LOGINS_LINUX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_firefox_logins_linux",
    name: "Firefox logins.json (Linux)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.mozilla/firefox/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "JSON-encoded saved Firefox credentials protected by NSS (key4.db); \
              can be decrypted with master password or via memory forensics of the Firefox process.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1555/003/"],
};

pub static LINUX_UTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_utmp",
    name: "Current Login Sessions (/run/utmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/run/utmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary utmp records of currently logged-in users; cross-reference with wtmp \
              to detect sessions not present in persistent logs (anti-forensics via utmp wiper).",
    mitre_techniques: &["T1078"],
    fields: LOG_LINE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1078/",
        "https://linux.die.net/man/5/utmp",
        "https://www.sans.org/blog/linux-forensics-artifacts/",
        "https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28",
        "https://sandflysecurity.com/blog/using-linux-utmpdump-for-forensics-and-detecting-log-file-tampering",
    ],
};

pub static LINUX_GCP_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gcp_credentials",
    name: "GCP Application Default Credentials",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/gcloud/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GCP access tokens and service account keys stored by gcloud CLI; \
              exfiltration enables cloud resource takeover without password.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

pub static LINUX_AZURE_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_azure_credentials",
    name: "Azure CLI Credentials (~/.azure/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.azure/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Azure CLI access tokens and service principal credentials; \
              msal_token_cache.json contains active OAuth tokens enabling lateral movement in Azure.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1552/001/",
    ],
};

pub static LINUX_KUBE_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kube_config",
    name: "Kubernetes Config (~/.kube/config)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.kube/config"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "kubectl cluster credentials including bearer tokens, client certificates, \
              and cluster API endpoints; enables full cluster takeover if exfiltrated.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

pub static LINUX_GIT_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_git_credentials",
    name: "Git Credential Store (~/.git-credentials)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.git-credentials"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Plaintext git credential store: URL + username + PAT/password per line; \
              personal access tokens here can access source repositories and CI/CD pipelines.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

pub static LINUX_NETRC: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_netrc",
    name: "Netrc Credential File (~/.netrc)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.netrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Auto-authentication file for ftp, curl, and legacy tools; stores plaintext \
              hostname/login/password triplets, often forgotten and highly sensitive.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &["https://attack.mitre.org/techniques/T1552/001/"],
};

// ── Batch G — LinuxPersist-sourced persistence artifacts ─────────────────────
// Source: https://github.com/GuyEldad/LinuxPersist

pub static LINUX_ETC_ENVIRONMENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_etc_environment",
    name: "System Environment Variables (/etc/environment)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/environment"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "System-wide environment variable definitions loaded for every login session and \
              PAM-based authentication. Attackers inject PATH hijacks or LD_PRELOAD values here \
              to redirect binary execution system-wide without modifying shell configuration files.",
    mitre_techniques: &["T1546.004"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://linux.die.net/man/7/environ",
    ],
};

pub static LINUX_XDG_AUTOSTART_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_xdg_autostart_user",
    name: "XDG User Autostart (.desktop files)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/autostart/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-user XDG autostart .desktop files executed when a desktop session starts \
              (GNOME/KDE/XFCE). Exec= field runs arbitrary commands at GUI login without \
              root privileges — frequently overlooked by server-focused forensic checklists.",
    mitre_techniques: &["T1547.014"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/014/",
        "https://specifications.freedesktop.org/autostart-spec/autostart-spec-latest.html",
    ],
};

pub static LINUX_XDG_AUTOSTART_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_xdg_autostart_system",
    name: "XDG System Autostart (.desktop files)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/xdg/autostart/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning:
        "System-wide XDG autostart .desktop entries executed for all users at desktop session \
              start. Provides privileged persistence targeting all GUI logins on a workstation.",
    mitre_techniques: &["T1547.014"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/014/",
        "https://specifications.freedesktop.org/autostart-spec/autostart-spec-latest.html",
    ],
};

pub static LINUX_NETWORKMANAGER_DISPATCHER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_networkmanager_dispatcher",
    name: "NetworkManager Dispatcher Scripts",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/NetworkManager/dispatcher.d/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Scripts executed by NetworkManager when network interfaces change state (up/down). \
              Provides network-event-triggered persistence — scripts fire on VPN connect, \
              WiFi association, or interface cycling, making detection harder than at-boot persistence.",
    mitre_techniques: &["T1547.013"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/013/",
        "https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html",
    ],
};

pub static LINUX_APT_HOOKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apt_hooks",
    name: "APT Package Manager Hook Scripts",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/apt/apt.conf.d/"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "APT configuration snippets that can define DPkg::Pre-Install-Pkgs, \
              DPkg::Post-Invoke, or APT::Update::Post-Invoke hooks; execute as root during \
              every package install or update — long-lived trigger-based privilege persistence.",
    mitre_techniques: &["T1546.004"],
    fields: PERSIST_CMD_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1546/004/",
        "https://attack.mitre.org/techniques/T1546/016/",
        "https://wiki.debian.org/DpkgTriggers",
    ],
};

// ── Batch H — Jump List / LNK / Prefetch / SRUM tables / EVTX channels ──────

pub static JUMP_LIST_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "jump_list_system",
    name: "Jump Lists — System AutomaticDestinations",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Windows\Recent\AutomaticDestinations\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-scope jump lists shared across all users; distinct from per-user \
              %APPDATA% copies. Each .automaticDestinations-ms is an OLE CFB containing \
              a DestList stream (AppID → target MRU) plus embedded LNK blocks.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["jump_list_auto", "jump_list_custom"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/009/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://www.sans.org/blog/computer-forensics-windows-7-jump-lists/",
        "https://windowsir.blogspot.com/2011/05/jump-lists-in-win7.html",
        "https://github.com/EricZimmerman/JLECmd",
        "https://github.com/EricZimmerman/JumpList",
        "https://forensics.wiki/jump_lists/",
    ],
};

pub static LNK_FILES_OFFICE: ArtifactDescriptor = ArtifactDescriptor {
    id: "lnk_files_office",
    name: "Office Recent LNK Files",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Office\Recent\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Office-specific shell link files created for every document opened via Office. \
              Separate from Windows Recent; survives clearing of Windows Recent Items. \
              Reveals document access including network shares and USB paths.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["lnk_files", "mru_recent_docs"],
    sources: &[
        "https://attack.mitre.org/techniques/T1547/009/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://www.sans.org/blog/lnk-files-analysis-in-windows/",
        "https://windowsir.blogspot.com/2009/01/lnk-files-are-your-friends.html",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/",
        "https://github.com/EricZimmerman/LECmd",
        "https://github.com/EricZimmerman/Lnk",
        "https://forensics.wiki/lnk/",
    ],
};

pub(crate) static PREFETCH_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "executable_name",
        description: "Name of the prefetched executable (up to 29 chars)",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "run_count",
        description: "Number of times the executable has run",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "last_run_time",
        description: "Most recent execution timestamp (FILETIME)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "previous_run_times",
        description: "Up to 7 prior execution timestamps (Win 8+)",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "volume_path",
        description: "Volume device path at time of execution",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "referenced_files",
        description: "DLLs and files loaded during first 10 seconds",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "prefetch_hash",
        description: "8-hex path hash appended to filename",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
];

pub static PREFETCH_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "prefetch_file",
    name: "Prefetch File (.pf)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\Prefetch\*.pf"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Binary execution record: executable name, 8-run-timestamp history (Win8+), \
              run count, path hash, and referenced DLL list. Win10+ files are MAM-compressed \
              (4-byte magic 0x4D 0x41 0x4D 0x04) — decompress with xpress_huff before parsing. \
              Versions: v17 (XP), v23 (Vista/7), v26 (Win8), v30/v31 (Win10+).",
    mitre_techniques: &["T1059", "T1070.004"],
    fields: PREFETCH_FIELDS,
    retention: Some("128 entries; oldest evicted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "shimcache",
        "amcache_app_file",
        "evtx_security",
        "srum_app_resource",
    ],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://www.sans.org/blog/computer-forensic-artifacts-windows-7-prefetch-files/",
        "https://13cubed.com/downloads/Windows_Forensic_Analysis_Poster.pdf",
        "https://isc.sans.edu/diary/Forensic+Value+of+Prefetch/29168",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/",
        "https://github.com/EricZimmerman/PECmd",
        "https://github.com/EricZimmerman/Prefetch",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
    ],
};

pub(crate) static SRUM_NET_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_id",
        description: "Application identifier (path or service name)",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_id",
        description: "SID of the user account",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        description: "ESE column TimeStamp (UTC)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "bytes_sent",
        description: "Total bytes sent by this app in the interval",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "bytes_received",
        description: "Total bytes received by this app in the interval",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "interface_luid",
        description: "Network interface LUID",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
];

pub static SRUM_NETWORK_USAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_network_usage",
    name: "SRUM Network Data Usage Table",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat:{973F5D5C-1D90-11D3-AE08-00A0C90F57DA}"),
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning:
        "ESE table {973F5D5C-1D90-11D3-AE08-00A0C90F57DA} records per-app bytes sent/received \
              per network interface per hour. ~30-day retention. Proves data exfiltration volume \
              even after log deletion; correlate AppId + UserId + BytesSent for exfil attribution.",
    mitre_techniques: &["T1049", "T1048"],
    fields: SRUM_NET_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "srum_app_resource", "prefetch_file"],
    sources: &[
        "https://attack.mitre.org/techniques/T1049/",
        "https://attack.mitre.org/techniques/T1048/",
        "https://www.sans.org/white-papers/36660/",
        "https://www.sans.org/blog/srum-forensics/",
        "https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/",
        "https://github.com/EricZimmerman/Srum",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
    ],
};

pub(crate) static SRUM_APP_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_id",
        description: "Application path or service name",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_id",
        description: "SID of the user account",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        description: "Interval timestamp (UTC)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "foreground_cpu_time",
        description: "CPU time used in foreground (100ns units)",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "background_cpu_time",
        description: "CPU time used in background (100ns units)",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "foreground_cycles",
        description: "CPU cycle count in foreground",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "background_cycles",
        description: "CPU cycle count in background",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
];

pub static SRUM_APP_RESOURCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_app_resource",
    name: "SRUM Application Resource Usage Table",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat:{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"),
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning: "ESE table {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} records per-app CPU cycles \
              (foreground + background) per hour per user. Proves execution even without Prefetch \
              or Event Log entries — CPU cycles are non-zero only if the process actually ran.",
    mitre_techniques: &["T1059", "T1070.004"],
    fields: SRUM_APP_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["srum_network_usage", "prefetch_file", "evtx_security"],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1070/004/",
        "https://www.sans.org/white-papers/36660/",
        "https://www.sans.org/blog/srum-forensics/",
        "https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/",
        "https://github.com/EricZimmerman/Srum",
    ],
};

pub(crate) static SRUM_ENERGY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_id",
        description: "Application path",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_id",
        description: "SID of the user account",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        description: "Interval timestamp (UTC)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "charge_level",
        description: "Battery charge level at sample time",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "designed_capacity",
        description: "Battery designed capacity (mWh)",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "full_charge_capacity",
        description: "Current full charge capacity (mWh)",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
];

pub static SRUM_ENERGY_USAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_energy_usage",
    name: "SRUM Energy Usage Table",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat:{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"),
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning: "ESE table {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} records battery charge levels \
              at each sampling interval — enables timeline reconstruction of device on/off events \
              and correlates app activity with physical device presence.",
    mitre_techniques: &["T1059"],
    fields: SRUM_ENERGY_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://www.sans.org/white-papers/36660/",
        "https://github.com/EricZimmerman/Srum",
    ],
};

pub(crate) static SRUM_PUSH_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_id",
        description: "Application that received notification",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_id",
        description: "SID of the user account",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        description: "Notification timestamp (UTC)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "notification_type",
        description: "WNS notification type code",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
    FieldSchema {
        name: "payload_size",
        description: "Notification payload size in bytes",
        value_type: ValueType::UnsignedInt,
        is_uid_component: false,
    },
];

pub static SRUM_PUSH_NOTIFICATION: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_push_notification",
    name: "SRUM Push Notification Activity Table",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat:{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "ESE table {D10CA2FE-6FCF-4F6D-848E-B2E99266FA86} records Windows Push Notification \
              (WNS) activity per app — reveals C2-style notification-triggered execution in \
              malicious UWP/PWA apps and confirms app network activity.",
    mitre_techniques: &["T1059"],
    fields: SRUM_PUSH_FIELDS,
    retention: Some("~30 days"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://www.sans.org/white-papers/36660/",
        "https://github.com/EricZimmerman/Srum",
    ],
};

pub(crate) static EVTX_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        description: "Windows Event ID",
        value_type: ValueType::UnsignedInt,
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        description: "Event timestamp (UTC)",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
    FieldSchema {
        name: "computer",
        description: "Source computer name",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "subject_user_sid",
        description: "SID of the subject user",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "subject_user_name",
        description: "Username of the subject",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "message",
        description: "Full event message XML",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static EVTX_SECURITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_security",
    name: "Security Event Log (Security.evtx)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\winevt\Logs\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Primary security audit log. Key event IDs: 4624/4625 (logon success/fail), \
              4634/4647 (logoff), 4648 (explicit-cred logon), 4688/4689 (process create/exit), \
              4698/4702 (scheduled task create/modify), 4720/4732 (account create/group add), \
              1102 (audit log cleared — high-priority anti-forensics indicator).",
    mitre_techniques: &["T1070.001", "T1059", "T1078"],
    fields: EVTX_FIELDS,
    retention: Some("configurable; default ~20MB rolling per channel"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "srum_network_usage",
        "srum_app_resource",
        "prefetch_file",
        "shimcache",
    ],
    sources: &[
        "https://attack.mitre.org/techniques/T1070/001/",
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1078/",
        "https://www.sans.org/posters/windows-forensic-analysis/",
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-security-audit-policies",
        "https://www.13cubed.com/downloads/windows_event_log_cheat_sheet.pdf",
        "https://www.magnetforensics.com/blog/the-importance-of-powershell-logs-in-digital-forensics/",
        "https://github.com/EricZimmerman/evtx",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.3_Windows_Event_Core.md",
    ],
};

pub static EVTX_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_system",
    name: "System Event Log (System.evtx)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\winevt\Logs\System.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning:
        "System-level events. Key IDs: 7045 (service installed), 7036 (service state change), \
              6005/6006 (event log start/stop — boot/shutdown boundary), \
              104 (System log cleared). Service installation (7045) is a primary \
              lateral-movement and persistence indicator.",
    mitre_techniques: &["T1543.003", "T1070.001"],
    fields: EVTX_FIELDS,
    retention: Some("configurable; default ~20MB rolling per channel"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_security", "scheduled_tasks_dir", "services_imagepath"],
    sources: &[
        "https://attack.mitre.org/techniques/T1543/003/",
        "https://attack.mitre.org/techniques/T1070/001/",
        "https://www.sans.org/posters/windows-forensic-analysis/",
        "https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging",
        "https://github.com/EricZimmerman/evtx",
    ],
};

pub static EVTX_POWERSHELL: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_powershell",
    name: "PowerShell Operational Log",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
    ),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning:
        "PowerShell script execution telemetry. Event 4103 (module logging — pipeline output), \
              4104 (ScriptBlock logging — full script text including deobfuscated content). \
              4104 captures AMSI-deobfuscated scripts even when encoded; \
              highest-fidelity PS forensic source when enabled.",
    mitre_techniques: &["T1059.001", "T1027"],
    fields: EVTX_FIELDS,
    retention: Some("configurable; default ~20MB rolling per channel"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "evtx_security",
        "powershell_history",
        "powershell_profile_all",
    ],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://attack.mitre.org/techniques/T1027/",
        "https://www.sans.org/blog/detecting-malicious-powershell/",
        "https://redcanary.com/threat-detection-report/techniques/t1059.001/",
        "https://github.com/EricZimmerman/evtx",
    ],
};

pub static EVTX_SYSMON: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_sysmon",
    name: "Sysmon Operational Log",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning:
        "Sysmon telemetry (requires deployment). Event 1 (process create + hashes + cmdline), \
              3 (network connection), 7 (image load), 8 (CreateRemoteThread), \
              10 (ProcessAccess — LSASS reads), 11 (file create), 22 (DNS query). \
              Gold standard for EDR-quality forensics without commercial tooling.",
    mitre_techniques: &["T1059", "T1055", "T1003.001"],
    fields: EVTX_FIELDS,
    retention: Some("configurable; default ~20MB rolling per channel"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "prefetch_file", "srum_app_resource"],
    sources: &[
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1055/",
        "https://attack.mitre.org/techniques/T1003/001/",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        "https://www.sans.org/blog/threat-hunting-using-sysmon/",
        "https://www.thedfirspot.com/post/sysmon-when-visibility-is-key",
        "https://github.com/EricZimmerman/evtx",
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.3_Windows_Event_Core.md",
    ],
};

pub(crate) static TYPED_PATHS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "typed_path",
    description: "Path manually entered into Explorer address bar history",
    value_type: ValueType::Text,
    is_uid_component: true,
}];

pub static TYPED_PATHS: ArtifactDescriptor = ArtifactDescriptor {
    id: "typed_paths",
    name: "Explorer Typed Paths",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Explorer address-bar history of manually entered local, removable, UNC, or shell paths; useful for proving interactive navigation to shares and staged locations.",
    mitre_techniques: &["T1083", "T1135"],
    fields: TYPED_PATHS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["typed_urls", "opensave_mru", "lastvisited_mru"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/typed_paths.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static RUN_MRU_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "mru_order",
        description: "Run dialog MRU letter ordering string",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "command",
        description: "Command line entered via the Run dialog",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
];

pub static RUN_MRU: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_mru",
    name: "Run Dialog MRU",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "History of commands launched from the Windows Run dialog, including the user-maintained MRU ordering string and typed execution targets.",
    mitre_techniques: &["T1059"],
    fields: RUN_MRU_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["wordwheel_query", "powershell_history", "prefetch_file"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/runmru.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static NETWORK_DRIVES_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "drive_letter",
        description: "Mapped drive letter under HKCU\\Network",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "remote_path",
        description: "UNC path of the mapped network drive",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static NETWORK_DRIVES: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_drives",
    name: "Mapped Network Drives",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Network",
    value_name: Some("RemotePath"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user mapped network drives including drive letter to UNC mapping; useful for share-access reconstruction and lateral movement scoping.",
    mitre_techniques: &["T1135"],
    fields: NETWORK_DRIVES_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["rdp_client_servers", "networklist_profiles"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/network_drives.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
    ],
};

pub(crate) static APP_PATHS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "application",
        description: "Executable name registered under App Paths",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "path",
        description: "Default executable path resolved for the application name",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "architecture",
        description: "Architecture bucket inferred from x64 or Wow6432Node path",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static APP_PATHS: ArtifactDescriptor = ArtifactDescriptor {
    id: "app_paths",
    name: "App Paths Registry Entries",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\App Paths",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executable name resolution entries under App Paths and Wow6432Node App Paths; useful for installed-software discovery and hijack-style execution redirection review.",
    mitre_techniques: &["T1574"],
    fields: APP_PATHS_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["services_imagepath", "winlogon_shell"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/software/apppaths.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static MOUNTED_DEVICES_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "value_name",
        description: "MountedDevices value name such as a drive letter or volume GUID",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "mount_point",
        description: "Resolved drive letter or volume mount point",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "device_path",
        description: "Decoded device path or partition signature data",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static MOUNTED_DEVICES: ArtifactDescriptor = ArtifactDescriptor {
    id: "mounted_devices",
    name: "Mounted Devices",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"MountedDevices",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Drive-letter and volume mappings including device paths, signatures, and removable-media assignments preserved under HKLM\\SYSTEM\\MountedDevices.",
    mitre_techniques: &["T1091"],
    fields: MOUNTED_DEVICES_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["usb_enum", "wifi_profiles"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/system/mountdev.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static NETWORKLIST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "profile_guid",
        description: "GUID of a network profile under NetworkList",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "profile_name",
        description: "Human-readable network profile name",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "date_last_connected",
        description: "Timestamp of the most recent recorded connection",
        value_type: ValueType::Timestamp,
        is_uid_component: false,
    },
];

pub static NETWORKLIST_PROFILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "networklist_profiles",
    name: "Network List Profiles",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Network profile history including profile names, categories, and created/last-connected dates for wired and wireless networks.",
    mitre_techniques: &["T1016"],
    fields: NETWORKLIST_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["wifi_profiles", "network_drives"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/software/networklist.py",
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/validated_plugins.json",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static PUTTY_SESSION_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "session_name",
        description: "Saved PuTTY session name",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "hostname",
        description: "Target host configured in the PuTTY session",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "username",
        description: "User name configured for the saved session",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static PUTTY_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "putty_sessions",
    name: "PuTTY Saved Sessions",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\SimonTatham\PuTTY\Sessions",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "PuTTY saved sessions, including target hostname, port, protocol, and optional proxy or keyfile settings for SSH and other remote connections.",
    mitre_techniques: &["T1021.004"],
    fields: PUTTY_SESSION_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["rdp_client_servers", "winscp_saved_sessions"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/putty.py",
        "https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static WINSCP_SESSION_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "session_name",
        description: "Saved WinSCP session name",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "host_name",
        description: "Target host configured in the saved WinSCP session",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "user_name",
        description: "User name configured for the saved WinSCP session",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static WINSCP_SAVED_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "winscp_saved_sessions",
    name: "WinSCP Saved Sessions",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Martin Prikryl\WinSCP 2\Sessions",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "WinSCP saved sessions, including host, username, protocol, and optionally recoverable obfuscated credentials or connection defaults.",
    mitre_techniques: &["T1021.004", "T1555"],
    fields: WINSCP_SESSION_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["putty_sessions", "rdp_client_servers"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/winscp_saved_sessions.py",
        "https://winscp.net/eng/docs/ui_pref_storage",
        "https://az4n6.blogspot.com/2013/03/winscp-saved-password.html",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static WINRAR_HISTORY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "operation",
        description: "Archive opened, created, or extracted",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_path",
        description: "Archive or extraction path from WinRAR history",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
];

pub static WINRAR_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "winrar_history",
    name: "WinRAR Archive History",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"SOFTWARE\WinRAR",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "WinRAR registry history of archive opens, archive creation targets, and extraction paths; useful for exfiltration staging and archive reconstruction.",
    mitre_techniques: &["T1560.001"],
    fields: WINRAR_HISTORY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["powershell_history", "opensave_mru"],
    sources: &[
        "https://github.com/mkorman90/regipy/blob/master/regipy/plugins/ntuser/winrar.py",
        "https://www.win-rar.com/switches/settings.htm",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static NETWORK_INTERFACE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "interface_guid",
        description: "TCP/IP interface GUID under the Interfaces key",
        value_type: ValueType::Text,
        is_uid_component: true,
    },
    FieldSchema {
        name: "ip_address",
        description: "Static or DHCP-assigned address values associated with the interface",
        value_type: ValueType::Text,
        is_uid_component: false,
    },
];

pub static NETWORK_INTERFACES: ArtifactDescriptor = ArtifactDescriptor {
    id: "network_interfaces",
    name: "TCP/IP Network Interfaces",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Interface GUIDs with DHCP or static addressing details used to tie network activity and lease information back to a host and adapter.",
    mitre_techniques: &["T1016"],
    fields: NETWORK_INTERFACE_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["networklist_profiles", "srum_network_usage"],
    sources: &[
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub static PAGEFILE_SYS: ArtifactDescriptor = ArtifactDescriptor {
    id: "pagefile_sys",
    name: "Pagefile.sys",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\pagefile.sys"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Virtual memory paging file containing memory-resident strings and fragments from paged-out processes when full RAM capture is unavailable.",
    mitre_techniques: &["T1005"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["hiberfil_sys", "evtx_security"],
    sources: &["https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv", "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md"],
};

pub static HIBERFIL_SYS: ArtifactDescriptor = ArtifactDescriptor {
    id: "hiberfil_sys",
    name: "Hibernation File (hiberfil.sys)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\hiberfil.sys"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Compressed hibernation snapshot containing a point-in-time copy of system memory, including processes, sockets, and in-memory strings.",
    mitre_techniques: &["T1005"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::High,
    related_artifacts: &["pagefile_sys", "evtx_security"],
    sources: &[
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://forensics.wiki/hiberfil.sys/",
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/storport/nf-storport-storportmarkdumpmemory",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub(crate) static MOUNTPOINTS2_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "mount_point",
    description: "Per-user mount point or device reference cached by Explorer",
    value_type: ValueType::Text,
    is_uid_component: true,
}];

pub static MOUNTPOINTS2: ArtifactDescriptor = ArtifactDescriptor {
    id: "mountpoints2",
    name: "MountPoints2",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user record of mounted removable media and mapped resources, useful for attributing USB or volume interaction to a specific logged-in user.",
    mitre_techniques: &["T1091"],
    fields: MOUNTPOINTS2_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["mounted_devices", "usb_enum"],
    sources: &[
        "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv",
        "https://github.com/EricZimmerman/RECmd",
        "https://github.com/EricZimmerman/RegistryPlugins",
    ],
};

pub static PORTABLE_DEVICES: ArtifactDescriptor = ArtifactDescriptor {
    id: "portable_devices",
    name: "Windows Portable Devices Mapping",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows Portable Devices\Devices",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Maps portable device identities to user-visible names or drive assignments, helping correlate USB serials and mounted letters during media analysis.",
    mitre_techniques: &["T1091"],
    fields: FILE_PATH_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["mounted_devices", "mountpoints2", "usb_enum"],
    sources: &["https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv"],
};

pub static RDP_BITMAP_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_bitmap_cache",
    name: "RDP Bitmap Cache",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Client-side cached bitmap fragments from RDP sessions that can reveal what was rendered on screen during remote administration or attacker activity.",
    mitre_techniques: &["T1021.001"],
    fields: DIR_ENTRY_FIELDS,
    retention: None,
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["rdp_client_servers", "rdp_client_default"],
    sources: &["https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/01_Hunting_Cheatsheets/1.5_Forensics_Artifacts_Map.csv"],
};

// ── macOS artifacts ───────────────────────────────────────────────────────────

/// Apple Unified Logging system (`/var/db/diagnostics/`). macOS 10.12+.
///
/// Provides timestamped, structured log entries for process activity, crashes,
/// and security events. Primary timeline source on macOS.
pub static MACOS_UNIFIED_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_unified_log",
    name: "macOS Unified Log",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/db/diagnostics/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "Apple Unified Logging system. Contains all system and application logs since macOS 10.12. Provides timestamped, structured log entries for process activity, crashes, and security events.",
    mitre_techniques: &["T1070.001", "T1059"],
    fields: &[],
    retention: Some("Rotated by OS; typically weeks to months"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_install_history"],
    sources: &[
        "https://www.mandiant.com/resources/blog/reviewing-macos-unified-logs",
        "https://developer.apple.com/documentation/os/logging",
    ],
};

/// Per-user LaunchAgent plist files (`~/Library/LaunchAgents/`).
///
/// Loaded automatically at user login. Primary persistence mechanism for
/// malware targeting individual users.
pub static MACOS_LAUNCH_AGENTS_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_launch_agents_user",
    name: "macOS User LaunchAgents",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/LaunchAgents/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-user LaunchAgent plist files. Automatically loaded at user login. Primary persistence mechanism for malware targeting individual users.",
    mitre_techniques: &["T1543.001"],
    fields: &[],
    retention: Some("Persistent until removed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_launch_agents_system", "macos_launch_daemons"],
    sources: &[
        "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
        "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
    ],
};

/// System-wide LaunchAgent plist files (`/Library/LaunchAgents/`).
///
/// Requires root to install; used by system-level malware and legitimate software.
pub static MACOS_LAUNCH_AGENTS_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_launch_agents_system",
    name: "macOS System LaunchAgents",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/LaunchAgents/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "System-wide LaunchAgent plist files loaded for all users. Requires root to install; used by system-level malware and legitimate software.",
    mitre_techniques: &["T1543.001"],
    fields: &[],
    retention: Some("Persistent until removed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_launch_agents_user", "macos_launch_daemons"],
    sources: &[
        "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
        "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
    ],
};

/// System LaunchDaemon plist files (`/Library/LaunchDaemons/`).
///
/// Run as root at system boot, independent of user login. High-value
/// persistence for privileged malware.
pub static MACOS_LAUNCH_DAEMONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_launch_daemons",
    name: "macOS LaunchDaemons",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/LaunchDaemons/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "System LaunchDaemon plist files. Run as root at system boot, independent of user login. High-value persistence for privileged malware.",
    mitre_techniques: &["T1543.004"],
    fields: &[],
    retention: Some("Persistent until removed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_launch_agents_system"],
    sources: &[
        "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
        "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
    ],
};

/// Transparency, Consent, and Control database (`~/Library/Application Support/com.apple.TCC/TCC.db`).
///
/// Records which applications have been granted privacy permissions. Attackers
/// may modify TCC.db to bypass privacy controls.
pub static MACOS_TCC_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_tcc_db",
    name: "macOS TCC Database",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Application Support/com.apple.TCC/TCC.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Transparency, Consent, and Control database. Records which applications have been granted permissions (camera, microphone, Full Disk Access, etc.). Attackers may modify TCC.db to bypass privacy controls.",
    mitre_techniques: &["T1548"],
    fields: &[],
    retention: Some("Persistent; updated on permission grant/revoke"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_launch_agents_user"],
    sources: &[
        "https://www.sentinelone.com/blog/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/",
        "https://eclecticlight.co/2020/11/04/tcc-in-big-sur-more-permissions-issues/",
    ],
};

/// Quarantine events database (`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`).
///
/// SQLite database recording all files downloaded from the internet. Proves a
/// file was downloaded even after deletion from Downloads.
pub static MACOS_QUARANTINE_EVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_quarantine_events",
    name: "macOS Quarantine Events Database",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SQLite database recording all files downloaded from the internet with their origin URL, download date, and quarantine agent. Proves a file was downloaded even after deletion.",
    mitre_techniques: &["T1204.002"],
    fields: &[],
    retention: Some("Persistent; entries accumulate unless cleared"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_safari_downloads"],
    sources: &[
        "https://www.jaiminton.com/cheatsheet/DFIR/#quarantine-events",
        "https://eclecticlight.co/2021/06/05/checking-quarantine-flags-in-big-sur/",
    ],
};

/// Safari browser history SQLite database (`~/Library/Safari/History.db`).
///
/// Contains URLs, timestamps, and visit counts. Key artifact for establishing
/// attacker research, C2 communication attempts, and data exfiltration.
pub static MACOS_SAFARI_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_history",
    name: "macOS Safari Browser History",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Safari/History.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SQLite database containing Safari browsing history with URLs, timestamps, and visit counts. Key artifact for establishing attacker research, C2 communication attempts, and data exfiltration.",
    mitre_techniques: &["T1217"],
    fields: &[],
    retention: Some("Rotated; typically weeks to months of history"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_safari_downloads", "macos_quarantine_events"],
    sources: &[
        "https://www.sans.org/blog/mac-artifact-safari/",
        "https://www.magnetforensics.com/blog/artifacts-for-ios-investigations/",
    ],
};

/// Safari downloads plist (`~/Library/Safari/Downloads.plist`).
///
/// Records all files downloaded via Safari. Corroborates quarantine events database.
pub static MACOS_SAFARI_DOWNLOADS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_downloads",
    name: "macOS Safari Downloads",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Safari/Downloads.plist"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Plist file recording all files downloaded via Safari with source URL, local path, and download date. Corroborates quarantine events database.",
    mitre_techniques: &["T1217"],
    fields: &[],
    retention: Some("Persistent; entries accumulate"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_safari_history", "macos_quarantine_events"],
    sources: &[
        "https://www.sans.org/blog/mac-artifact-safari/",
    ],
};

/// KnowledgeC database (`~/Library/Application Support/Knowledge/knowledgeC.db`).
///
/// Maintained by the Duet Activity Scheduler. Rich timeline source for user
/// activity reconstruction including app usage and device lock events.
pub static MACOS_KNOWLEDGEC: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_knowledgec",
    name: "macOS KnowledgeC Database",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Application Support/Knowledge/knowledgeC.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database maintained by the Duet Activity Scheduler. Records application usage, device lock/unlock events, browser activity, and screen time. Rich timeline source for user activity reconstruction.",
    mitre_techniques: &["T1083"],
    fields: &[],
    retention: Some("Rolling window; typically 30 days"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log"],
    sources: &[
        "https://www.mac4n6.com/blog/2018/8/5/knowledge-is-power-using-the-knowledgecdb-database-on-macos-ios-to-determine-precise-user-and-application-usage",
        "https://github.com/mac4n6/APOLLO",
    ],
};

/// Per-session bash history files (`~/.bash_sessions/`).
///
/// Contains command history per terminal session. macOS Catalina+ uses zsh by
/// default but bash_sessions may persist for users who previously used bash.
pub static MACOS_BASH_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_bash_sessions",
    name: "macOS Bash Session History",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bash_sessions/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-session bash history files. macOS Catalina+ uses zsh by default but bash_sessions may persist for users who used bash previously. Contains command history per terminal session.",
    mitre_techniques: &["T1059.004"],
    fields: &[],
    retention: Some("Persistent per session"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_unified_log"],
    sources: &[
        "https://eclecticlight.co/2019/07/08/why-mojave-could-be-your-last-bash/",
    ],
};

/// Software package install history plist (`/Library/Receipts/InstallHistory.plist`).
///
/// Records all software packages installed via macOS installer. Useful for
/// identifying unauthorized software installation.
pub static MACOS_INSTALL_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_install_history",
    name: "macOS Software Install History",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Receipts/InstallHistory.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Plist recording all software packages installed via macOS installer. Includes package name, version, date, and source. Useful for identifying unauthorized software installation.",
    mitre_techniques: &["T1204"],
    fields: &[],
    retention: Some("Persistent; accumulates over system lifetime"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_launch_daemons"],
    sources: &[
        "https://www.forensicmike1.com/2019/12/17/macos-forensic-artifacts-install-history/",
    ],
};

/// Gatekeeper policy database (`/var/db/SystemPolicy-prefs.plist`).
///
/// Records which applications were allowed or blocked by Gatekeeper. Useful
/// for detecting Gatekeeper bypass attempts.
pub static MACOS_GATEKEEPER_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_gatekeeper_logs",
    name: "macOS Gatekeeper Assessment Logs",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/db/SystemPolicy-prefs.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Gatekeeper policy database and assessment logs. Records which applications were allowed or blocked by Gatekeeper. Useful for detecting Gatekeeper bypass attempts.",
    mitre_techniques: &["T1553.001"],
    fields: &[],
    retention: Some("Persistent; updated on policy decisions"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_tcc_db"],
    sources: &[
        "https://support.apple.com/en-us/102445",
        "https://www.sentinelone.com/blog/gatekeeper-bypass-macos-security/",
    ],
};

/// User keychain database (`~/Library/Keychains/login.keychain-db`).
///
/// Stores passwords, certificates, and private keys. Unlocked at login with
/// user password. Attackers with user access can dump all stored credentials.
pub static MACOS_KEYCHAIN_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_keychain_user",
    name: "macOS User Keychain",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/Library/Keychains/login.keychain-db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "User keychain database storing passwords, certificates, and private keys. Unlocked at login with user password. Attackers with user access can dump all stored credentials.",
    mitre_techniques: &["T1555.001"],
    fields: &[],
    retention: Some("Persistent; updated on credential add/remove"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_tcc_db"],
    sources: &[
        "https://www.hexnode.com/blogs/macos-keychain-forensics/",
        "https://github.com/n0fate/chainbreaker",
    ],
};

/// emond plist rules directory (`/etc/emond.d/rules/`).
///
/// Rules executed by the Event Monitor Daemon. Deprecated in macOS 12 but
/// exploited for persistence on older versions via event-triggered commands.
pub static MACOS_EMOND: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_emond",
    name: "macOS Event Monitor Daemon Rules",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/emond.d/rules/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "emond plist rules executed by the Event Monitor Daemon. Deprecated in macOS 12 but exploited for persistence on older versions. Rules can execute commands on system events.",
    mitre_techniques: &["T1546"],
    fields: &[],
    retention: Some("Persistent until removed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_launch_daemons"],
    sources: &[
        "https://www.xorrior.com/emond-persistence/",
        "https://attack.mitre.org/techniques/T1546/014/",
    ],
};

/// CoreAnalytics execution reports directory (`/Library/Logs/DiagnosticReports/`).
///
/// CoreAnalytics `.ca_report` files record process execution metadata including
/// SHA256 hashes. Provides execution evidence similar to Windows Prefetch.
pub static MACOS_COREANALYTICS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_coreanalytics",
    name: "macOS CoreAnalytics Execution Reports",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Logs/DiagnosticReports/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Execution reports generated by macOS diagnostics. CoreAnalytics .ca_report files record process execution metadata including SHA256 hashes. Provides execution evidence similar to Windows Prefetch.",
    mitre_techniques: &["T1059"],
    fields: &[],
    retention: Some("Rolling; older reports auto-deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log"],
    sources: &[
        "https://www.crowdstrike.com/blog/reconstructing-command-line-activity-on-macos/",
        "https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/",
    ],
};

// ── Global catalog entries ────────────────────────────────────────────────────

/// All descriptor instances that make up the global catalog.
///
/// Maintainer note:
/// New descriptors should be researched against the curated DFIR source corpus
/// documented in this module header, then anchored with artifact-specific URLs in
/// the descriptor's `sources` field. Archived source corpora are discovery input;
/// they do not replace per-artifact attribution.
pub(crate) static CATALOG_ENTRIES: &[ArtifactDescriptor] = &[
    USERASSIST_EXE,
    USERASSIST_FOLDER,
    RUN_KEY_HKLM_RUN,
    RUN_KEY_HKCU_RUN,
    RUN_KEY_HKCU_RUNONCE,
    RUN_KEY_HKLM_RUNONCE,
    TYPED_URLS,
    TYPED_URLS_TIME,
    PCA_APPLAUNCH_DIC,
    IFEO_DEBUGGER,
    SHELLBAGS_USER,
    AMCACHE_APP_FILE,
    SHIMCACHE,
    BAM_USER,
    DAM_USER,
    SAM_USERS,
    LSA_SECRETS,
    DCC2_CACHE,
    MRU_RECENT_DOCS,
    USB_ENUM,
    MUICACHE,
    APPINIT_DLLS,
    WINLOGON_USERINIT,
    SCREENSAVER_EXE,
    // Batch C — Windows persistence
    WINLOGON_SHELL,
    SERVICES_IMAGEPATH,
    ACTIVE_SETUP_HKLM,
    ACTIVE_SETUP_HKCU,
    COM_HIJACK_CLSID_HKCU,
    APPCERT_DLLS,
    BOOT_EXECUTE,
    LSA_SECURITY_PKGS,
    LSA_AUTH_PKGS,
    PRINT_MONITORS,
    TIME_PROVIDERS,
    NETSH_HELPER_DLLS,
    BROWSER_HELPER_OBJECTS,
    STARTUP_FOLDER_USER,
    STARTUP_FOLDER_SYSTEM,
    SCHEDULED_TASKS_DIR,
    WDIGEST_CACHING,
    // Batch C — Windows execution evidence
    WORDWHEEL_QUERY,
    OPENSAVE_MRU,
    LASTVISITED_MRU,
    PREFETCH_DIR,
    SRUM_DB,
    WINDOWS_TIMELINE,
    POWERSHELL_HISTORY,
    RECYCLE_BIN,
    THUMBCACHE,
    SEARCH_DB_USER,
    // Batch C — Windows credentials
    DPAPI_MASTERKEY_USER,
    DPAPI_CRED_USER,
    DPAPI_CRED_ROAMING,
    WINDOWS_VAULT_USER,
    WINDOWS_VAULT_SYSTEM,
    RDP_CLIENT_SERVERS,
    RDP_CLIENT_DEFAULT,
    NTDS_DIT,
    CHROME_LOGIN_DATA,
    FIREFOX_LOGINS,
    WIFI_PROFILES,
    // Batch I — regipy-aligned registry coverage
    TYPED_PATHS,
    RUN_MRU,
    NETWORK_DRIVES,
    APP_PATHS,
    MOUNTED_DEVICES,
    NETWORKLIST_PROFILES,
    PUTTY_SESSIONS,
    WINSCP_SAVED_SESSIONS,
    WINRAR_HISTORY,
    // Batch J — Blue Team field-note and artifact-map coverage
    NETWORK_INTERFACES,
    PAGEFILE_SYS,
    HIBERFIL_SYS,
    MOUNTPOINTS2,
    PORTABLE_DEVICES,
    RDP_BITMAP_CACHE,
    // Batch D — Linux cron / init persistence
    LINUX_CRONTAB_SYSTEM,
    LINUX_CRON_D,
    LINUX_CRON_PERIODIC,
    LINUX_USER_CRONTAB,
    LINUX_ANACRONTAB,
    // Batch D — Linux systemd persistence
    LINUX_SYSTEMD_SYSTEM_UNIT,
    LINUX_SYSTEMD_USER_UNIT,
    LINUX_SYSTEMD_TIMER,
    // Batch D — Linux SysV init
    LINUX_RC_LOCAL,
    LINUX_INIT_D,
    // Batch D — Linux shell startup persistence
    LINUX_BASHRC_USER,
    LINUX_BASH_PROFILE_USER,
    LINUX_PROFILE_USER,
    LINUX_ZSHRC_USER,
    LINUX_PROFILE_SYSTEM,
    LINUX_PROFILE_D,
    // Batch D — Linux dynamic linker hijack
    LINUX_LD_SO_PRELOAD,
    LINUX_LD_SO_CONF_D,
    // Batch D — Linux SSH persistence
    LINUX_SSH_AUTHORIZED_KEYS,
    // Batch D — Linux auth / privilege escalation
    LINUX_PAM_D,
    LINUX_SUDOERS_D,
    LINUX_MODULES_LOAD_D,
    LINUX_MOTD_D,
    LINUX_UDEV_RULES_D,
    // Batch D — Linux execution evidence
    LINUX_BASH_HISTORY,
    LINUX_ZSH_HISTORY,
    LINUX_WTMP,
    LINUX_BTMP,
    LINUX_LASTLOG,
    LINUX_AUTH_LOG,
    LINUX_JOURNAL_DIR,
    // Batch D — Linux credentials
    LINUX_PASSWD,
    LINUX_SHADOW,
    LINUX_SSH_PRIVATE_KEY,
    LINUX_SSH_KNOWN_HOSTS,
    LINUX_GNUPG_PRIVATE,
    LINUX_AWS_CREDENTIALS,
    LINUX_DOCKER_CONFIG,
    // Batch E — Windows execution evidence
    LNK_FILES,
    JUMP_LIST_AUTO,
    JUMP_LIST_CUSTOM,
    EVTX_DIR,
    MFT_FILE,
    USN_JOURNAL,
    // Batch E — Windows persistence
    WMI_MOF_DIR,
    BITS_DB,
    WMI_SUBSCRIPTIONS,
    LOGON_SCRIPTS,
    WINSOCK_LSP,
    APPSHIM_DB,
    PASSWORD_FILTER_DLL,
    OFFICE_NORMAL_DOTM,
    POWERSHELL_PROFILE_ALL,
    // Batch E — Windows credentials
    DPAPI_SYSTEM_MASTERKEY,
    DPAPI_CREDHIST,
    CHROME_COOKIES,
    EDGE_WEBCACHE,
    VPN_RAS_PHONEBOOK,
    WINDOWS_HELLO_NGC,
    USER_CERT_PRIVATE_KEY,
    MACHINE_CERT_STORE,
    // Batch F — Linux extended
    LINUX_AT_QUEUE,
    LINUX_SSHD_CONFIG,
    LINUX_ETC_GROUP,
    LINUX_GNOME_KEYRING,
    LINUX_KDE_KWALLET,
    LINUX_CHROME_LOGIN_LINUX,
    LINUX_FIREFOX_LOGINS_LINUX,
    LINUX_UTMP,
    LINUX_GCP_CREDENTIALS,
    LINUX_AZURE_CREDENTIALS,
    LINUX_KUBE_CONFIG,
    LINUX_GIT_CREDENTIALS,
    LINUX_NETRC,
    // Batch G — LinuxPersist-sourced
    LINUX_ETC_ENVIRONMENT,
    LINUX_XDG_AUTOSTART_USER,
    LINUX_XDG_AUTOSTART_SYSTEM,
    LINUX_NETWORKMANAGER_DISPATCHER,
    LINUX_APT_HOOKS,
    // Batch H — JL / LNK / Prefetch / SRUM / EVTX
    JUMP_LIST_SYSTEM,
    LNK_FILES_OFFICE,
    PREFETCH_FILE,
    SRUM_NETWORK_USAGE,
    SRUM_APP_RESOURCE,
    SRUM_ENERGY_USAGE,
    SRUM_PUSH_NOTIFICATION,
    EVTX_SECURITY,
    EVTX_SYSTEM,
    EVTX_POWERSHELL,
    EVTX_SYSMON,
    // Batch macOS — persistence, execution, credentials, privacy
    MACOS_UNIFIED_LOG,
    MACOS_LAUNCH_AGENTS_USER,
    MACOS_LAUNCH_AGENTS_SYSTEM,
    MACOS_LAUNCH_DAEMONS,
    MACOS_TCC_DB,
    MACOS_QUARANTINE_EVENTS,
    MACOS_SAFARI_HISTORY,
    MACOS_SAFARI_DOWNLOADS,
    MACOS_KNOWLEDGEC,
    MACOS_BASH_SESSIONS,
    MACOS_INSTALL_HISTORY,
    MACOS_GATEKEEPER_LOGS,
    MACOS_KEYCHAIN_USER,
    MACOS_EMOND,
    MACOS_COREANALYTICS,
];
