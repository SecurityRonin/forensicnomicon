//! Windows WMI-persistence descriptor (CIM repository + WMI-Activity log).
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
//! Field descriptions are written from the Microsoft WMI event-subscription
//! documentation and the settled reverse-engineered CIM-repository reference
//! (Mandiant flare-wmi / python-cim); no third-party prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

/// Field schema for a WMI permanent event subscription recovered from the CIM repository.
///
/// The subscription triple (filter / consumer / binding) and the consumer
/// payload come from the CIM repository objects; the runtime field
/// (`wmi_activity_operation`) comes from the WMI-Activity/Operational event log
/// — a separate source that records execution, not the persistence definition.
/// Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events
/// Source: https://github.com/mandiant/flare-wmi/tree/master/python-cim
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
        description: "__EventFilter instance name — the trigger. Names the persistence entry",
        is_uid_component: true,
    },
    FieldSchema {
        name: "filter_query",
        value_type: ValueType::Text,
        description: "__EventFilter Query (WQL) — the event that fires the payload (e.g. an __InstanceModificationEvent on Win32_LocalTime for time-based triggering, or process/logon events). The query encodes the trigger condition",
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
        description: "__EventConsumer instance name — the payload object bound to the filter",
        is_uid_component: false,
    },
    FieldSchema {
        name: "consumer_payload",
        value_type: ValueType::Text,
        description: "The executed content: CommandLineEventConsumer CommandLineTemplate (the command line) or ActiveScriptEventConsumer ScriptText (the inline script). This is the highest-signal field — the actual code run on trigger",
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
/// Source: https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events
/// Source: https://github.com/mandiant/flare-wmi/tree/master/python-cim
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
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate software and management tools (SCCM, antivirus, monitoring agents) also create permanent subscriptions — the payload content, not the mere presence of a subscription, is the signal",
        "A subscription is inert without the binding; a stray filter or consumer alone is not active persistence",
        "CIM repository parsing recovers deleted/partial objects that may be stale — corroborate a recovered binding against the WMI-Activity log before concluding it was active",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "CIM repository objects persist on disk until the subscription is explicitly removed; the mechanism survives reboots by design",
};
