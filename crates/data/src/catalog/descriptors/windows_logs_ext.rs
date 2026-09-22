//! Extended Windows crash dump, WER, and miscellaneous artifact descriptors — Batch I.
//!
//! Sources: Microsoft Learn documentation, KAPE targets (EricZimmerman/KapeFiles),
//! DFIR research on BYOVD and Windows Error Reporting forensics.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static WINDOWS_CRASH_DUMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_crash_dump",
    name: "Windows Kernel/Complete Memory Dump",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only present after BSOD or manual trigger; may be disabled or set to minidump-only",
        "Single dump overwritten on next BSOD",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Single dump file overwritten on each BSOD",
};

pub(crate) static WINDOWS_MINIDUMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_minidump",
    name: "Windows BSOD Minidump Files",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Limited to kernel context; user-mode crash details require WER reports"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Minidumps accumulate in directory; oldest deleted by retention policy",
};

/// Field schema for one `Root\InventoryDriverBinary` subkey in `Amcache.hve`.
///
/// The names are the registry values the Compatibility Appraiser writes per
/// driver binary. Microsoft documents every one of them except `DriverId` and
/// `DriverLastWriteTime` as fields of the
/// `Microsoft.Windows.Inventory.Core.InventoryDriverBinaryAdd` diagnostic
/// event, which is the citable definition of what each value means and the
/// source of the `DriverType` bit constants below. Those two, and the subkey
/// name itself, are registry-side only; they are taken from the two
/// independent open-source readers of this key — Volatility 3's
/// `windows.registry.amcache` plugin and Eric Zimmerman's `AmcacheParser` —
/// which agree on the `0000` prefix on `DriverId`, on `DriverTimeStamp` being
/// Unix epoch seconds, and on `DriverLastWriteTime` being a text date string.
///
/// The four values that decide a BYOVD triage — was it signed, did it ship
/// with Windows, does it carry vendor version metadata at all, and where was
/// it loaded from — are `DriverSigned`/`DriverType`, `DriverInBox`,
/// `DriverCompany`/`Product`/`ProductVersion`, and `KeyName`.
///
/// Source: <https://learn.microsoft.com/en-us/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/registry/amcache.py>
/// Source: <https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/Classes/DriverBinary.cs>
pub(crate) static AMCACHE_DRIVER_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "KeyName",
        value_type: ValueType::Text,
        description: "Subkey name — the record identity, and its form depends on the Windows build: on some builds it is the driver's full path written with FORWARD slashes (so a `/` in the name is the discriminator), on others it is the driver's SHA-1. Check which form is in front of you before keying anything off it, because a reader that assumes one silently drops every record of the other. In the path form this is where a driver loaded from a non-standard directory — anywhere other than the system driver store — becomes visible",
        is_uid_component: true,
    },
    FieldSchema {
        name: "DriverId",
        value_type: ValueType::Text,
        description: "SHA-1 of the driver binary, carried with four leading `0` characters. Strip that prefix before comparing against a hash list or reputation feed, or nothing matches. It survives deletion of the file, so a driver already wiped from disk still leaves a hash here to look up",
        is_uid_component: true,
    },
    FieldSchema {
        name: "DriverName",
        value_type: ValueType::Text,
        description: "File name of the driver binary. Attacker-chosen text, so read it against `KeyName` and `Inf` rather than alone — a name imitating an in-box driver is the cheap masquerade",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverVersion",
        value_type: ValueType::Text,
        description: "Version of the driver file. The BYOVD pivot: match it against the published vulnerable-version ranges for that vendor driver, because the build being abused is usually an old and legitimately signed one",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverSigned",
        value_type: ValueType::Bool,
        description: "Whether the driver carried a digital signature. An unsigned kernel-mode driver is the loud case. A signed one is not exculpatory — the whole point of BYOVD is that the driver is genuinely signed — so pair it with `DriverType` to see WHICH kind of signature was seen",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverInBox",
        value_type: ValueType::Bool,
        description: "Whether the driver shipped with the operating system. The fastest cut across a driver list: everything a third party put on the machine is false, so split on this before reading anything else",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverIsKernelMode",
        value_type: ValueType::Bool,
        description: "Whether the binary is a kernel-mode driver rather than user-mode. Scopes the blast radius — a kernel-mode load runs in Ring 0, which is what a BYOVD chain is buying",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverCompany",
        value_type: ValueType::Text,
        description: "Company name carried by the driver file. Read the ABSENCE, not the content: vendor drivers fill this in, so an empty company on a kernel-mode driver is itself worth writing down",
        is_uid_component: false,
    },
    FieldSchema {
        name: "Service",
        value_type: ValueType::Text,
        description: "Name of the service installed for the device. Pivot straight into `SYSTEM\\CurrentControlSet\\Services\\<name>` for the start type and image path, and into the service-installation event record for when it was created",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverTimeStamp",
        value_type: ValueType::Timestamp,
        description: "Link timestamp taken from the driver file (Microsoft documents it as the low 32 bits of the file's time stamp), stored as Unix epoch seconds. A property of the BINARY rather than an observation by the OS, so whoever built the file chose it: a zero, a future date, or one that disagrees with `DriverLastWriteTime` is a lead, not a fact",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverLastWriteTime",
        value_type: ValueType::Timestamp,
        description: "Last-write time of the driver FILE, stored as a text date string (month/day/year ordering — the reference readers parse it with invariant-culture rules) rather than a binary timestamp. Compare it against the file's current filesystem times: a driver replaced or timestomped after this record was written no longer agrees with it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverCheckSum",
        value_type: ValueType::Integer,
        description: "Checksum recorded for the driver file. Treat as a cheap secondary handle only — `DriverId` is the authoritative one — but two records sharing a name and version while differing here mean two different files",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverType",
        value_type: ValueType::Integer,
        description: "Bitfield of driver attributes, and the single most informative value in the subkey. Microsoft documents the bits as 0x0001 printer, 0x0002 kernel, 0x0004 user, 0x0008 signed, 0x0010 in-box, 0x0020 self-signed, 0x0040 WinQual, 0x0080 CI-signed, 0x0100 has boot service, 0x800000 time-stamped, with the architecture in the high bits (0x10000 i386, 0x20000 IA64, 0x40000 AMD64, 0x100000 ARM, 0x200000 THUMB, 0x400000 ARMNT). It is where `DriverSigned` stops being a yes/no: self-signed (0x0020) on a kernel-mode driver, or a boot-service driver (0x0100) that is not in-box, is worth reading in full",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ImageSize",
        value_type: ValueType::Integer,
        description: "Size of the driver file. With `DriverId` it separates two builds that share a name and a version string",
        is_uid_component: false,
    },
    FieldSchema {
        name: "Inf",
        value_type: ValueType::Text,
        description: "Name of the INF file. Joins this record to `Root\\InventoryDriverPackage`, where the package provider, device class and submission ID live — so check whether a driver package exists for the binary at all, since an INF-installed driver and a directly created kernel service arrive by different routes",
        is_uid_component: false,
    },
    FieldSchema {
        name: "Product",
        value_type: ValueType::Text,
        description: "Product name included in the driver file. Like `DriverCompany`, the useful reading is whether it is populated: hand-built drivers routinely ship with this empty while vendor drivers do not",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ProductVersion",
        value_type: ValueType::Text,
        description: "Product version included in the driver file. May disagree with `DriverVersion` — the two come from different parts of the file's metadata, so quote whichever the vulnerable-driver advisory uses rather than assuming they match",
        is_uid_component: false,
    },
    FieldSchema {
        name: "WdfVersion",
        value_type: ValueType::Text,
        description: "Windows Driver Framework version, populated for drivers built on WDF. Narrows the build toolchain when the other version metadata is missing",
        is_uid_component: false,
    },
    FieldSchema {
        name: "DriverPackageStrongName",
        value_type: ValueType::Text,
        description: "Strong name of the driver package. Groups every binary that arrived in the same package and is the second pivot (alongside `Inf`) into `Root\\InventoryDriverPackage`",
        is_uid_component: false,
    },
];

/// AmCache `Root\InventoryDriverBinary` — the per-driver inventory record.
///
/// How ABSENCE is represented decides how much weight the BYOVD triage axes can
/// carry, and it is not a marker word. Both independent reference readers
/// initialise every text value to the empty string and both date values to
/// null, then overwrite only what the subkey actually carries — so a value that
/// was written empty and a value that is not present at all are the same thing
/// by the time they reach the analyst. The three booleans are stored as the
/// TEXT `1`/`0` rather than a numeric type, and the readers admit only an exact
/// `1` as true, which is what makes an absent `DriverSigned` indistinguishable
/// from a recorded `0`. Read those three as "not observed to be true" rather
/// than as negative findings.
///
/// Source: <https://learn.microsoft.com/en-us/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004>
/// Source: <https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/AmcacheNew.cs>
pub(crate) static AMCACHE_DRIVER: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_driver",
    name: "AmCache InventoryDriverBinary",
    artifact_type: ArtifactLocation::RegistryKey,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\AppCompat\\Programs\\Amcache.hve"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AmCache InventoryDriverBinary section: records installed driver binaries with SHA1 hash, version, product, and first-seen timestamp. Unlike Shimcache, AmCache hashes persist even after binary deletion — a deleted malicious driver's SHA1 remains as evidence. Critical for BYOVD attack investigation.",
    mitre_techniques: &["T1068", "T1553.006"],
    fields: AMCACHE_DRIVER_FIELDS,
    retention: Some("Persists until AmCache.hve is manually cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["amcache_app_file", "shimcache", "evtx_code_integrity"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/intelligence/criteria",
        "https://learn.microsoft.com/en-us/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/registry/amcache.py (build-dependent subkey naming — a `/` in the name means the path form, otherwise the name is the SHA-1; the `0000` prefix stripped from DriverId; DriverTimeStamp read as Unix epoch seconds)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/registry/amcache.py",
        // Source: https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/Classes/DriverBinary.cs (the per-record field set, and the nullable typing of DriverLastWriteTime/DriverTimeStamp against non-nullable strings and ints)
        "https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/Classes/DriverBinary.cs",
        // Source: https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/AmcacheNew.cs (the InventoryDriverBinary read loop: text fields initialised to string.Empty and dates to null with no sentinel word; DriverSigned/DriverInBox/DriverIsKernelMode compared against the literal text "1"; DriverId taken as Substring(4); DriverLastWriteTime parsed with InvariantInfo; a DriverTimeStamp of 0 left unset)
        "https://github.com/EricZimmerman/AmcacheParser/blob/master/Amcache/AmcacheNew.cs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Records driver load time, not execution time; SHA1 hash allows reputation lookup",
        "DriverId is the SHA-1 with four leading `0` characters — comparing it raw against a hash list or reputation feed matches nothing",
        "Subkey naming is build-dependent: on some Windows versions the subkey name is the driver's full path (forward-slash separated), on others it is the SHA-1. A reader keyed on one form silently returns nothing for the other",
        "DriverTimeStamp is the link timestamp carried inside the binary, not an OS-recorded event: it is whatever the file's builder put there, so it neither dates the load nor corroborates DriverLastWriteTime",
        "DriverSigned/DriverType record what the inventory scan observed about the file, not a re-verification at analysis time — and a validly signed driver is the normal BYOVD case rather than an exclusion",
        "Absence carries no sentinel value: the reference readers initialise every text field to the empty string and both date fields to null, so an empty DriverCompany/Product/ProductVersion/WdfVersion does not separate `the appraiser recorded nothing here` from `this subkey never held the value`. Reading an empty vendor field as evidence of a hand-built driver requires a known-good subkey from the same build to show the field is normally populated",
        "DriverSigned/DriverInBox/DriverIsKernelMode are stored as the TEXT `1` or `0`, and the reference readers admit only an exact `1` as true — so an absent value collapses silently into false. A false in parsed output means `not observed to be true`, never `observed to be untrue`: an apparently unsigned kernel-mode driver has to be confirmed against the binary itself or a code-integrity record before it is reported as unsigned",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Amcache hive persists on disk; survives reboot",
};

pub(crate) static WER_REPORT_QUEUE: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_report_queue",
    name: "Windows Error Reporting Queue",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Error Reporting queued crash reports waiting for upload. Each report contains a Report.wer text file with the faulting module, exception code, and timestamp. Process crash artifacts indicate: (1) AV/EDR crashes induced by attackers, (2) injected process crashes revealing injection target, (3) exploit-crashed processes showing the attacked binary.",
    mitre_techniques: &["T1685", "T1055"],
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Queue drained when reports successfully upload; surviving entries are bounded"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Queue drained as reports upload to Microsoft; transient retention",
};

pub(crate) static WINDOWS_NOTIFICATION_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_notification_db",
    name: "Windows Push Notification Database",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Notifications can be disabled per-app or system-wide",
        "User can clear notification history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "SQLite database with FIFO eviction as new notifications arrive",
};

pub(crate) static AMCACHE_SHORTCUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_shortcut",
    name: "AmCache InventoryApplicationShortcut",
    artifact_type: ArtifactLocation::RegistryKey,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Presence indicates a shortcut existed, not necessarily that the target was executed",
        "Periodic AmCache rebuild may lose history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "AmCache hive persists in registry; rebuilt periodically by Compatibility Appraiser",
};
