//! Windows WMI-persistence descriptors (CIM repository + WMI-Activity log, and
//! the repository-recovery MOF registration).
//!
//! WMI permanent event subscriptions are often used as fileless persistence: an
//! __EventFilter (the trigger query) bound via a __FilterToConsumerBinding to an
//! __EventConsumer (the payload) survives reboots; the execution context depends
//! on the consumer configuration. The subscription objects live in the CIM
//! repository on disk
//! (OBJECTS.DATA / INDEX.BTR / MAPPING[1-3].MAP), and the WMI-Activity/
//! Operational event log records the runtime traces. This closes the GCFA gap
//! where __EventFilter/__EventConsumer existed only as MITRE technique names.
//!
//! The second WMI surface here is the *registration* side rather than the object
//! store: `Autorecover MOFs` lists the source paths of every MOF file WMI
//! recompiles when it has to rebuild a damaged repository. It is a persistent
//! record of a compilation that outlives the MOF file itself, and a MOF
//! registered there can put a subscription back after the repository is reset.
//!
//! Field descriptions are written from the Microsoft WMI event-subscription and
//! MOF-compiler documentation, the settled reverse-engineered CIM-repository
//! reference (Mandiant flare-wmi / python-cim), and the default value lists
//! published in open DFIR tooling; no third-party prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

/// Field schema for a WMI permanent event subscription recovered from the CIM repository.
///
/// The subscription triple (filter / consumer / binding) and the consumer
/// payload come from the CIM repository objects; the runtime field
/// (`wmi_activity_operation`) comes from the WMI-Activity/Operational event log
/// — a separate source that records execution, not the persistence definition.
///
/// The ActiveScriptEventConsumer payload splits across three of these fields
/// because Microsoft defines ScriptText and ScriptFileName as mutually
/// exclusive (each must be NULL when the other is not; both set or both NULL is
/// an error) and ScriptingEngine as never NULL. The stock filter/consumer names
/// carried in the `filter_name` / `consumer_name` / `filter_query`
/// descriptions are the default known-good lists published by open DFIR tooling
/// — a starting baseline, not an allowlist.
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer>
/// Source: <https://github.com/mandiant/flare-wmi/tree/master/python-cim>
/// Source: <https://docs.velociraptor.app/exchange/artifacts/pages/suspiciouswmiconsumers/>
/// Source: <https://github.com/woanware/wmi-parser>
pub(crate) static WMI_PERSISTENCE_CIM_REPOSITORY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "namespace",
        value_type: ValueType::Text,
        description: "CIM namespace the subscription is registered in. Permanent subscriptions are recommended in root\\subscription, but any namespace can host them — check all",
        is_uid_component: true,
    },
    FieldSchema {
        name: "filter_name",
        value_type: ValueType::Text,
        description: "__EventFilter instance name — the trigger. Names the persistence entry. The filter names that ship with Windows or with common vendor tooling are a short, checkable set — `SCM Event Log Filter`, `BVTFilter`, `TSLogonFilter`, `RmAssistEventFilter` — so a name outside it is worth reading in full; a name inside it still has to be cleared on `filter_query` and `consumer_type`, because the name is attacker-chosen free text",
        is_uid_component: true,
    },
    FieldSchema {
        name: "filter_query",
        value_type: ValueType::Text,
        description: "__EventFilter Query (WQL) — the event that fires the payload (e.g. an __InstanceModificationEvent on Win32_LocalTime for time-based triggering, or process/logon events). The query encodes the trigger condition. The stock Service Control Manager subscription is the baseline worth knowing exactly: filter `SCM Event Log Filter` running `select * from MSFT_SCMEventLogEvent`, bound to an NTEventLogEventConsumer named `SCM Event Log Consumer`. That whole triple is the discriminator — a CommandLineEventConsumer or ActiveScriptEventConsumer wearing the `SCM Event Log Consumer` name is a masquerade, not the stock entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_type",
        value_type: ValueType::Text,
        description: "__EventConsumer subclass — CommandLineEventConsumer (runs a command), ActiveScriptEventConsumer (runs VBScript/JScript), LogFileEventConsumer, SMTPEventConsumer, etc. CommandLine and ActiveScript are the offensive-favourite payload carriers",
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_name",
        value_type: ValueType::Text,
        description: "__EventConsumer instance name — the payload object bound to the filter. The consumer names that ship with Windows or with common vendor tooling are few — `NTEventLogConsumer`, `SCM Event Log Consumer` — as are the script/binary bodies seen behind them (`TSLogonEvents.vbs`, `RAevent.vbs`, `KernCap.vbs`, `WSCEAA.exe`). Treat that as a triage baseline only: the name is free text the creator chose, so clear an entry on `consumer_type` plus `consumer_payload`, never on the name alone",
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_payload",
        value_type: ValueType::Text,
        description: "The executed content: CommandLineEventConsumer CommandLineTemplate (the command line) or ActiveScriptEventConsumer ScriptText (the inline script). This is the highest-signal field — the actual code run on trigger. For ActiveScriptEventConsumer, ScriptText and ScriptFileName are mutually exclusive, so when the consumer reads its body from a file this field is empty and the code is named in `consumer_script_file` instead",
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_script_file",
        value_type: ValueType::Text,
        description: "ActiveScriptEventConsumer ScriptFileName — the file the script text is READ FROM, the documented alternative to inlining it in ScriptText. This is the consumer configuration whose payload does land on disk, so a populated value is a file-system pivot: hash and timeline the named file, and carve for it if it has since been deleted. Microsoft's own guidance is that the file needs a strong ACL, because whoever can replace it controls what the subscription runs — so a script file in a user-writable location is worth checking against its directory's permissions",
        is_uid_component: false,
    },
    FieldSchema {
        name: "scripting_engine",
        value_type: ValueType::Text,
        description: "ActiveScriptEventConsumer ScriptingEngine — the Active Scripting engine the body is handed to (`VBScript`, `JScript`). Microsoft documents it can never be NULL, so a recovered ActiveScriptEventConsumer without one is a partial or stale object rather than a complete subscription. It tells the analyst which language to read `consumer_payload`/`consumer_script_file` as, and it bounds what the body can call directly: the consumer does not run under Windows Script Host, so the WScript object's own methods are unavailable inside it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "binding",
        value_type: ValueType::Text,
        description: "__FilterToConsumerBinding — the link joining one __EventFilter to one __EventConsumer. A subscription is active only when all three objects (filter, consumer, binding) exist; the binding is what makes the pair fire",
        is_uid_component: false,
    },
    FieldSchema {
        name: "wmi_activity_operation",
        value_type: ValueType::Text,
        description: "SEPARATE SOURCE (not the CIM repository): the Microsoft-Windows-WMI-Activity/Operational event-log trace of subscription operations (e.g. Event ID 5861 records permanent-consumer registration), corroborating when the persistence was installed or fired",
        is_uid_component: false,
    },
];

/// WMI persistence — permanent event subscription in the CIM repository.
///
/// A WMI permanent event subscription is a reboot-surviving persistence
/// mechanism, often used filelessly, built from three linked objects: an
/// __EventFilter holding a WQL trigger query, an __EventConsumer holding the
/// payload (CommandLineEventConsumer runs a command; ActiveScriptEventConsumer
/// runs an inline script), and a __FilterToConsumerBinding joining the two. All
/// three are stored in the CIM repository on disk — OBJECTS.DATA (the object
/// store), INDEX.BTR (the B-tree index), and MAPPING[1-3].MAP (the logical-to-
/// physical page maps) under `%SystemRoot%\System32\wbem\Repository`. When a
/// standard consumer carries an inline command/script payload no script/EXE need
/// land on disk, so it evades casual file-system triage; custom consumers may
/// instead rely on registered COM/executable components, and the execution
/// context depends on the consumer/provider configuration (commonly the WMI
/// service context for standard consumers). Recovery parses the CIM
/// repository (the settled reference is Mandiant's flare-wmi / python-cim) to
/// enumerate the subscription objects and their payloads, and correlates with
/// the Microsoft-Windows-WMI-Activity/Operational event log, which records
/// subscription operations at runtime. A subscription is *active* only when all
/// three objects are present and bound.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events>
/// Source: <https://github.com/mandiant/flare-wmi/tree/master/python-cim>
pub(crate) static WMI_PERSISTENCE_CIM_REPOSITORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_persistence_cim_repository",
    name: "WMI Persistence (CIM Repository Event Subscription)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\wbem\\Repository\\OBJECTS.DATA"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "WMI permanent event subscription persistence recovered from the on-disk CIM \
repository. The mechanism is a triple: an __EventFilter (WQL trigger query) linked by a \
__FilterToConsumerBinding to an __EventConsumer (payload — CommandLineEventConsumer runs a command, \
ActiveScriptEventConsumer runs an inline script). All three objects live in the CIM repository \
files OBJECTS.DATA (object store), INDEX.BTR (B-tree index), and MAPPING[1-3].MAP (page maps) under \
%SystemRoot%\\System32\\wbem\\Repository. It is often used as fileless persistence when a standard \
consumer stores an inline command/script payload; custom consumers may rely on registered \
COM/executable components. It is reboot-surviving, and the execution context depends on the \
consumer/provider configuration (commonly the WMI service context for standard consumers). \
Recovery parses the CIM repository (settled reference: Mandiant flare-wmi / python-cim) to \
enumerate the filter query, consumer subclass, and consumer payload (CommandLineTemplate or \
ScriptText — the actual code run), and correlates with the Microsoft-Windows-WMI-Activity/\
Operational event log (e.g. Event ID 5861 records permanent-consumer registration), which is a \
SEPARATE runtime source, not the persistence definition. A subscription is active only when the \
filter, consumer, AND binding all exist. Cross-reference evtx_sysmon (Sysmon Event IDs 19/20/21 \
log WMI filter/consumer/binding activity) for a corroborating live-log view.",
    mitre_techniques: &[
        "T1546.003", // Event Triggered Execution: WMI Event Subscription
        "T1047",     // Windows Management Instrumentation
    ],
    fields: WMI_PERSISTENCE_CIM_REPOSITORY_FIELDS,
    retention: Some("Persistent in the CIM repository until the subscription is removed; WMI-Activity/Operational log entries rotate"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_sysmon"],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events (permanent event consumer: __EventFilter + __EventConsumer + __FilterToConsumerBinding, ActiveScriptEventConsumer, root\subscription)
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events",
        // Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event (permanent vs temporary consumers; permanent consumer persists in the WMI repository across reboots)
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event",
        // Source: https://github.com/mandiant/flare-wmi/tree/master/python-cim (CIM repository format — OBJECTS.DATA / INDEX.BTR / MAPPING[1-3].MAP; recovers __FilterToConsumerBindings and deleted objects)
        "https://github.com/mandiant/flare-wmi/tree/master/python-cim",
        // Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer (ScriptText and ScriptFileName mutually exclusive — each NULL when the other is not; ScriptingEngine never NULL; runs outside Windows Script Host)
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer",
        // Source: https://docs.velociraptor.app/exchange/artifacts/pages/suspiciouswmiconsumers/ (published default known-good filter names BVTFilter/TSLogonFilter/RmAssistEventFilter, consumer names NTEventLogConsumer/"SCM Event Log Consumer", script-and-binary names TSLogonEvents.vbs/RAevent.vbs/KernCap.vbs/WSCEAA.exe, and scripting engines VBScript/JScript)
        "https://docs.velociraptor.app/exchange/artifacts/pages/suspiciouswmiconsumers/",
        // Source: https://github.com/woanware/wmi-parser (sample output of the stock triple: NTEventLogEventConsumer "SCM Event Log Consumer" bound to filter "SCM Event Log Filter" querying MSFT_SCMEventLogEvent)
        "https://github.com/woanware/wmi-parser",
        // Source: https://github.com/davidpany/WMI_Forensics (PyWMIPersistenceFinder — treats only the binding names "BVTConsumer-BVTFilter" and "SCM Event Log Consumer-SCM Event Log Filter" as commonly legitimate)
        "https://github.com/davidpany/WMI_Forensics",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Legitimate software and management tools (SCCM, antivirus, monitoring agents) also create permanent subscriptions — the payload content, not the mere presence of a subscription, is the signal",
        "A subscription is inert without the binding; a stray filter or consumer alone is not active persistence",
        "CIM repository parsing recovers deleted/partial objects that may be stale — corroborate a recovered binding against the WMI-Activity log before concluding it was active",
        "Name-based allowlisting is defeated by one added or dropped word: the stock names published by DFIR tooling (BVTFilter, TSLogonFilter, RmAssistEventFilter, NTEventLogConsumer, `SCM Event Log Consumer`) are a triage baseline, and the genuine Service Control Manager entry is identifiable only as the whole triple — an NTEventLogEventConsumer bound to `select * from MSFT_SCMEventLogEvent`. A CommandLineEventConsumer or ActiveScriptEventConsumer carrying that name is the masquerade the baseline exists to expose",
        "The fileless framing holds only for the inline-payload variant: an ActiveScriptEventConsumer with ScriptFileName set reads its body from a file on disk, so that subscription does have a file-system footprint to hash, timeline and carve for",
        "The published known-good script and binary names (TSLogonEvents.vbs, RAevent.vbs, KernCap.vbs, WSCEAA.exe) reflect what tool authors observed on the systems they saw, not a Microsoft-documented shipping list — validate against a known-good build of the same OS and vendor stack before clearing an entry on them",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "CIM repository objects persist on disk until the subscription is explicitly removed; the mechanism survives reboots by design",
};

/// Field schema for one entry in the WMI repository-recovery MOF list.
///
/// The value is a multi-string, so each decoded record is one registered MOF
/// source path. `file_present` is the analyst's resolve-against-the-image
/// check — Microsoft's own recompile script performs exactly that test and
/// logs a missing file rather than failing, which is why an entry naming a MOF
/// that no longer exists is an ordinary state and not a parse error.
/// `mof_source_file` is a separate source: the MOF on disk, when it survives.
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/pragma-autorecover>
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-compile-registered-mof-files>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp>
pub(crate) static WMI_AUTORECOVER_MOFS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "mof_path",
        value_type: ValueType::Text,
        description: "One multi-string entry — the source path of a MOF file registered for recompilation when WMI rebuilds the repository. Paths are stored with %windir% and %ProgramFiles% tokens (Microsoft's own recompile script expands both before use), so expand them before resolving against the image. Microsoft describes most registered MOFs as sitting under %windir%\\System32\\wbem with applications registering further MOFs from their own install folders, so an entry pointing somewhere a non-administrator can write is the one to go and read",
        is_uid_component: true,
    },
    FieldSchema {
        name: "file_present",
        value_type: ValueType::Bool,
        description: "Does `mof_path` still resolve on the image? Microsoft's recompile script runs this same check and logs a missing file for entries whose MOF has gone, so absence is a normal state — uninstalled software leaves it, and so does a MOF deleted after it was compiled. Either way the registration outlives the file, which is what makes the entry worth reading when the file itself is unrecoverable",
        is_uid_component: false,
    },
    FieldSchema {
        name: "mof_uninstall_entry",
        value_type: ValueType::Bool,
        description: "Does the path name an uninstall MOF? Microsoft ships `*_uninstall.mof` files whose compilation REMOVES the classes they name, and its recompile guidance skips any entry containing `uninstall`. Read one as a removal instruction, never as a registration of capability — and expect them in the list rather than treating their presence as tampering",
        is_uid_component: false,
    },
    FieldSchema {
        name: "mof_source_file",
        value_type: ValueType::Text,
        description: "SEPARATE SOURCE (not the registry value): the MOF file at `mof_path`, when it still exists. Reading it is what turns a path into evidence — its statements declare the classes and class instances a recovery compile would put back, so a MOF declaring __EventFilter/__EventConsumer/__FilterToConsumerBinding instances is subscription persistence that reinstates itself. A recovery compile cannot be given command-line switches, so the target namespace has to be set inside the file with `#pragma namespace`; read it to learn where the objects land. A Unicode MOF opens with a U+FFFE or U+FEFF signature — not corruption",
        is_uid_component: false,
    },
];

/// WMI repository-recovery MOF registration — `Autorecover MOFs`.
///
/// `HKLM\SOFTWARE\Microsoft\Wbem\CIMOM` holds a multi-string value named
/// `Autorecover MOFs` listing the source paths of every MOF file registered for
/// automatic recompilation. Microsoft documents two routes into that list:
/// compiling with `mofcomp -autorecover`, or a `#pragma autorecover` line in the
/// MOF itself (mofcomp warns when the pragma is absent that the file's contents
/// will not survive a repository rebuild). WMI checks repository integrity when
/// it starts; if the repository is damaged it creates a new empty repository and
/// recompiles every MOF named here. Because compiling a MOF adds the classes
/// *and the class instances* it declares, a MOF that declares subscription
/// objects and is registered here reinstates that persistence after the
/// repository is rebuilt or reset — the subscription comes back without the
/// attacker returning. Only local paths work: WMI cannot recover a MOF held on
/// another machine.
///
/// The forensic property is that this is a registration record which outlives
/// the file it names. Microsoft's own recompile script has a missing-file branch
/// for entries whose MOF is gone, so a MOF compiled and then deleted still has
/// its path, and often its original directory, recorded here. Read it beside
/// `wmi_persistence_cim_repository`, which holds the subscription objects
/// themselves.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/wmisdk/pragma-autorecover>
/// Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-compile-registered-mof-files>
pub(crate) static WMI_AUTORECOVER_MOFS: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_autorecover_mofs",
    name: "WMI Autorecover MOFs (Repository-Recovery MOF Registration)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: "Microsoft\\Wbem\\CIMOM",
    value_name: Some("Autorecover MOFs"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "The list of MOF source paths WMI recompiles when it has to rebuild the CIM \
repository — the registration side of WMI persistence, as distinct from the object store in \
wmi_persistence_cim_repository. A path enters the list either by compiling the MOF with \
`mofcomp -autorecover` or by a `#pragma autorecover` line inside the MOF; mofcomp warns at compile \
time when the pragma is missing, because such a file will not survive a rebuild. WMI checks \
repository integrity at start-up and, on finding it damaged, creates a new empty repository and \
compiles every MOF named here. Compiling a MOF adds the classes AND the class instances it \
declares, so a MOF that declares __EventFilter / __EventConsumer / __FilterToConsumerBinding \
instances and is registered in this value REINSTATES that subscription after a repository rebuild \
or `winmgmt /resetrepository` — removing the objects from the repository alone does not remove the \
persistence. Only local paths are recoverable; WMI cannot recover a MOF on a remote machine. The \
value's forensic weight is that it is a registration record which outlives the file it names: \
Microsoft's own recompile script has a missing-file branch for entries whose MOF is gone, so the \
path (and original directory) of a MOF deleted after compilation is still recorded. Entries are \
stored with %windir% and %ProgramFiles% tokens that must be expanded before the path is resolved \
against the image, and Microsoft describes stock entries as living under %windir%\\System32\\wbem \
with applications registering MOFs from their own install folders.",
    mitre_techniques: &[
        "T1546.003", // Event Triggered Execution: WMI Event Subscription
        "T1047",     // Windows Management Instrumentation
    ],
    fields: WMI_AUTORECOVER_MOFS_FIELDS,
    retention: Some("Persistent registry value; an entry survives deletion of the MOF file it names and is removed only when the value is rewritten"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "wmi_persistence_cim_repository",
        "wmi_mof_dir",
        "wmi_subscriptions",
    ],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp (-autorecover adds the named MOF to the list compiled during repository recovery, stored under HKLM\SOFTWARE\Microsoft\WBEM\CIMOM; local paths only; the compile-time warning when #PRAGMA AUTORECOVER is absent; Unicode MOF BOM; mofcomp adds classes and class instances)
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp",
        // Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/pragma-autorecover (WMI checks repository integrity at start-up and, if damaged, rebuilds and recompiles the MOFs listed in this key; a recovery compile cannot be given command-line switches, so #pragma namespace must set the namespace)
        "https://learn.microsoft.com/en-us/windows/win32/wmisdk/pragma-autorecover",
        // Source: https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-compile-registered-mof-files (names the value exactly — HKLM\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs; most MOFs under C:\Windows\System32\wbem with others in the registering application's folder; the sample script expands %windir%/%ProgramFiles%, skips entries containing "uninstall", and logs a missing file when the path does not resolve)
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-compile-registered-mof-files",
        // Source: https://learn.microsoft.com/en-us/archive/blogs/yongrhee/wmi-stop-hurting-yourself-by-using-for-f-s-in-dir-s-b-mof-mfl-do-mofcomp-s (Microsoft engineering blog: names the value's type as Multi-String, and records that a third-party installer may overwrite the list instead of appending to it)
        "https://learn.microsoft.com/en-us/archive/blogs/yongrhee/wmi-stop-hurting-yourself-by-using-for-f-s-in-dir-s-b-mof-mfl-do-mofcomp-s",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Registration is not installation: an entry says the MOF is recompiled IF the repository is rebuilt, not that its objects are in the repository now. Confirm current state against wmi_persistence_cim_repository before concluding a subscription is live",
        "A path outside %windir%\\System32\\wbem is not by itself anomalous — Microsoft documents applications registering MOFs from their own install directories, so a vendor path is expected and only a user-writable or temporary location is the outlier",
        "An entry whose file is missing is ordinary: uninstalled software leaves exactly the same trace as a MOF deleted after compilation. The entry proves a compilation happened, not who did it or what the file contained",
        "Microsoft records that a third-party installer can OVERWRITE this value rather than append to it, so the absence of an expected entry is not evidence it was never registered, and the list is not a complete compilation history",
        "The list legitimately contains `*_uninstall.mof` entries whose compilation removes classes — their presence is normal, and reading one as a capability registration inverts its meaning",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "A registry value that persists until explicitly rewritten; entries outlive the MOF files they name",
};
