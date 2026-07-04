//! Windows memory-forensics artifact descriptors (VAD/malfind, netscan,
//! handles/threads, kernel callbacks, DKOM-hidden processes).
//!
//! These artifacts live only in a RAM image (or a page/hibernation/crash dump
//! projected into one) and are recovered by walking or pool-tag-scanning kernel
//! structures — `_MMVAD`, `_TCP_ENDPOINT`/`_TCP_LISTENER`/`_UDP_ENDPOINT`,
//! `_HANDLE_TABLE`/`_OBJECT_HEADER`, the notify-routine callback arrays, and
//! `_EPROCESS`. All are `Volatile`: they vanish on power-off, so they must be
//! acquired before shutdown. They complement the coarse `mem_running_processes`,
//! `mem_network_connections`, and `mem_loaded_modules` descriptors with the
//! specific structures and detection cross-views that a GCFA/FOR508-class
//! memory analysis relies on.
//!
//! Field descriptions are written from the kernel structure definitions and the
//! Volatility3 plugin logic; no third-party prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Code injection / malicious VAD regions (malfind-class) ──────────────────

/// Field schema for private, executable VAD regions flagged as injected code.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py
pub(crate) static MEM_PROCESS_INJECTION_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier (from the containing _EPROCESS)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process",
        value_type: ValueType::Text,
        description: "Image name of the process hosting the region (ImageFileName)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "start_vpn",
        value_type: ValueType::UnsignedInt,
        description: "Region start virtual address, derived from _MMVAD StartingVpn (page number << 12)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "end_vpn",
        value_type: ValueType::UnsignedInt,
        description: "Region end virtual address, derived from _MMVAD EndingVpn",
        is_uid_component: false,
    },
    FieldSchema {
        name: "protection",
        value_type: ValueType::Text,
        description: "VAD page protection from the VadS/VadF Flags.Protection field (e.g. PAGE_EXECUTE_READWRITE); RWX private memory is the primary injection signal",
        is_uid_component: false,
    },
    FieldSchema {
        name: "commit_charge",
        value_type: ValueType::UnsignedInt,
        description: "Pages committed to the region (_MMVAD Flags.CommitCharge)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "private_memory",
        value_type: ValueType::Bool,
        description: "True when Flags.PrivateMemory is set — region is not backed by an image/data file on disk, so it has no mapped module",
        is_uid_component: false,
    },
    FieldSchema {
        name: "vad_tag",
        value_type: ValueType::Text,
        description: "Pool tag of the VAD node (VadS for short private VADs, Vad/Vadl for others)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "disasm_header",
        value_type: ValueType::Bytes,
        description: "First bytes of the region; a leading MZ header or valid x86/x64 prologue in private RWX memory indicates a mapped PE or shellcode",
        is_uid_component: false,
    },
];

/// Injected code regions in memory — private, executable VADs (malfind-class).
///
/// malfind enumerates each process' Virtual Address Descriptor (VAD) tree and
/// flags regions whose page protection permits execution and write while the
/// memory is *private* (not backed by a mapped image or data file). Classic
/// injection — `VirtualAllocEx` + `WriteProcessMemory`, reflective DLL loading,
/// process hollowing, `.text` overwrites — leaves exactly this footprint:
/// PAGE_EXECUTE_READWRITE private memory with no corresponding on-disk module,
/// often beginning with an `MZ` header or a bare code prologue. The signal comes
/// from the `_MMVAD` node's `Flags.Protection`, `Flags.PrivateMemory`, and
/// `Flags.CommitCharge` fields, plus the pool tag (`VadS` marks the short,
/// private VADs that injected regions frequently use).
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py
/// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad
pub(crate) static MEM_PROCESS_INJECTION: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_process_injection",
    name: "Injected Code Regions (Memory VAD / malfind)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Private, executable memory regions recovered by walking each process' VAD tree \
(malfind-class analysis). Injected code — VirtualAllocEx+WriteProcessMemory, reflective DLL \
loading, process hollowing, in-place .text patching — produces private (non-file-backed) VADs \
with execute+write protection (PAGE_EXECUTE_READWRITE) and no mapped module on disk. \
The determination is made from the _MMVAD node's Flags.Protection, Flags.PrivateMemory, and \
Flags.CommitCharge fields together with the VAD pool tag (VadS for short private VADs). \
A region beginning with an MZ header or a valid instruction prologue in private RWX memory is a \
strong indicator of a mapped PE or shellcode. Cross-reference mem_loaded_modules (a region with \
no corresponding module is unbacked) and mem_hidden_processes (injection often targets a hidden \
or hollowed process). Absence of a disk-backed module for executable memory is the core anomaly.",
    mitre_techniques: &[
        "T1055",     // Process Injection
        "T1055.001", // Dynamic-link Library Injection
        "T1055.002", // Portable Executable Injection
        "T1055.012", // Process Hollowing
        "T1620",     // Reflective Code Loading
    ],
    fields: MEM_PROCESS_INJECTION_FIELDS,
    retention: Some("RAM only; lost on power-off. Also recoverable from hiberfil.sys / crash dumps"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "mem_loaded_modules",
        "mem_running_processes",
        "mem_hidden_processes",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py (VAD walk, protection/PrivateMemory flags, MZ/prologue check)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad (!vad — _MMVAD tree, protection, commit charge)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate JIT engines (JavaScript, .NET, Java) also allocate private RWX memory — corroborate with the region contents and the hosting process",
        "Modern injection may set RW then flip to RX (avoiding a persistent RWX VAD), so an RWX filter alone can miss it — inspect RX private regions too",
        "Region contents are the ground truth; protection flags alone are circumstantial",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Lives in process VADs in RAM; lost on power-off unless captured in a memory image, hibernation file, or crash dump",
};

// ── Network connections & sockets from RAM (netscan-class) ──────────────────

/// Field schema for network endpoints recovered by pool-tag scanning.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py
pub(crate) static MEM_NETWORK_SCAN_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "proto",
        value_type: ValueType::Text,
        description:
            "Protocol/object recovered — TCPv4/TCPv6 endpoint or listener, or UDPv4/UDPv6 endpoint",
        is_uid_component: true,
    },
    FieldSchema {
        name: "local_addr",
        value_type: ValueType::Text,
        description: "Local IP address (from the endpoint's local address object)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "local_port",
        value_type: ValueType::UnsignedInt,
        description: "Local port (byte-swapped from network order)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "foreign_addr",
        value_type: ValueType::Text,
        description: "Remote IP address; unset for listeners",
        is_uid_component: true,
    },
    FieldSchema {
        name: "foreign_port",
        value_type: ValueType::UnsignedInt,
        description: "Remote port; unset for listeners",
        is_uid_component: false,
    },
    FieldSchema {
        name: "state",
        value_type: ValueType::Text,
        description:
            "TCP state string (ESTABLISHED, LISTENING, CLOSED, TIME_WAIT, etc.); blank for UDP",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier from the endpoint's owning-process reference",
        is_uid_component: false,
    },
    FieldSchema {
        name: "owner",
        value_type: ValueType::Text,
        description: "Owning process image name, resolved via the owning-process pointer",
        is_uid_component: false,
    },
    FieldSchema {
        name: "created",
        value_type: ValueType::Timestamp,
        description: "Endpoint creation time (_TCP_ENDPOINT CreateTime as FILETIME), when present",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pool_offset",
        value_type: ValueType::UnsignedInt,
        description: "Physical offset of the pool allocation the object was carved from",
        is_uid_component: false,
    },
];

/// Network endpoints from RAM by pool-tag scanning (netscan-class).
///
/// netscan recovers TCP and UDP endpoints and listeners by scanning the pool
/// for the allocation tags of the network objects (`TcpE` for `_TCP_ENDPOINT`,
/// `TcpL` for `_TCP_LISTENER`, `UdpA` for `_UDP_ENDPOINT`) rather than walking a
/// live table via OS APIs. Because it is a pool scan, it recovers endpoints that
/// have already been closed (their allocations not yet reused) and connections
/// hidden from `netstat`/API-based enumeration — the RAM equivalent of carving.
/// Each object yields the local/foreign address and port, TCP state, owning PID
/// and process, and — for TCP endpoints — a creation FILETIME. This exposes C2
/// channels, beaconing, and lateral-movement sessions that on-host tooling can
/// miss.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py
/// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused
pub(crate) static MEM_NETWORK_SCAN: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_network_scan",
    name: "Network Endpoints (Memory Pool Scan / netscan)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::Network,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "TCP and UDP endpoints and listeners recovered by scanning kernel pool allocations \
for the network-object tags (TcpE for _TCP_ENDPOINT, TcpL for _TCP_LISTENER, UdpA for \
_UDP_ENDPOINT), rather than by walking a live table through OS APIs. Pool scanning recovers \
recently-closed connections whose allocations are not yet reused, and connections hidden from \
netstat/API enumeration — the memory analogue of carving. Each object provides local and foreign \
IP/port, TCP state, the owning PID and process image, and (for TCP endpoints) a creation FILETIME. \
Reveals C2 channels, beaconing, and lateral-movement sessions. Cross-reference \
mem_network_connections for the coarse in-memory connection view, and mem_running_processes to \
attribute an endpoint to a suspicious or hidden owning process. An endpoint whose owning process \
no longer appears in the active process list is a strong hiding indicator.",
    mitre_techniques: &[
        "T1049", // System Network Connections Discovery
        "T1071", // Application Layer Protocol
        "T1571", // Non-Standard Port
    ],
    fields: MEM_NETWORK_SCAN_FIELDS,
    retention: Some("RAM only; closed endpoints survive only until the pool allocation is reused"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["mem_network_connections", "mem_running_processes"],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py (TcpE/TcpL/UdpA pool-tag scan, address/port/state/owner extraction)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused (kernel pool tags and allocation tagging)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Pool scanning yields false positives from stale/overwritten allocations — validate address/port/state sanity before relying on a carved endpoint",
        "A recovered endpoint proves a socket existed, not that data flowed; correlate with process and payload evidence",
        "Owning-process resolution can fail if the referenced _EPROCESS allocation was already reused",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Network objects live in non-paged pool in RAM; lost on power-off and overwritten as the pool is recycled",
};

// ── Process handles & threads enumeration ───────────────────────────────────

/// Field schema for open handles and threads owned by a process.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py
pub(crate) static MEM_HANDLES_THREADS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier (_EPROCESS UniqueProcessId)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process",
        value_type: ValueType::Text,
        description: "Owning process image name",
        is_uid_component: false,
    },
    FieldSchema {
        name: "handle_value",
        value_type: ValueType::UnsignedInt,
        description: "Handle value (index into the process' _HANDLE_TABLE)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "object_type",
        value_type: ValueType::Text,
        description: "Object type name resolved from the _OBJECT_HEADER TypeIndex (e.g. Process, Thread, File, Key, Mutant, Event, Token, Section)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "granted_access",
        value_type: ValueType::UnsignedInt,
        description: "Granted-access mask on the handle (e.g. PROCESS_ALL_ACCESS 0x1FFFFF; PROCESS_VM_WRITE/PROCESS_VM_OPERATION signal injection targeting)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "object_name",
        value_type: ValueType::Text,
        description: "Object name where the type carries one (file path, registry key path, mutant/event name); empty for unnamed objects",
        is_uid_component: false,
    },
    FieldSchema {
        name: "tid",
        value_type: ValueType::UnsignedInt,
        description: "Thread identifier for _ETHREAD enumeration of the process (thread rows)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "start_address",
        value_type: ValueType::UnsignedInt,
        description: "Thread start address (_ETHREAD StartAddress); a start address in unbacked private memory indicates an injected thread",
        is_uid_component: false,
    },
    FieldSchema {
        name: "create_time",
        value_type: ValueType::Timestamp,
        description: "Thread creation time (_ETHREAD CreateTime as FILETIME)",
        is_uid_component: false,
    },
];

/// Open handles and threads per process (handles/threads enumeration).
///
/// Walking a process' `_HANDLE_TABLE` yields every open kernel object handle;
/// each `_HANDLE_TABLE_ENTRY` points at an `_OBJECT_HEADER` whose `TypeIndex`
/// resolves the object type (Process, Thread, File, Key, Mutant, Event, Token,
/// Section, …), and named objects expose their name. Handles reveal what a
/// process touches: a mutant naming a known malware family, a handle to another
/// process opened with `PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION` (an injection
/// target), file and registry handles held open. Enumerating the process'
/// threads (`_ETHREAD`) complements this: a thread whose `StartAddress` lies in
/// private, unbacked memory is a hallmark of `CreateRemoteThread`-style code
/// injection.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py
/// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles
pub(crate) static MEM_HANDLES_THREADS: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_handles_threads",
    name: "Process Handles & Threads (Memory)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Open kernel-object handles and threads owned by a process, recovered from its \
_HANDLE_TABLE and _ETHREAD list. Each handle-table entry references an _OBJECT_HEADER whose \
TypeIndex resolves the object type (Process, Thread, File, Key, Mutant, Event, Token, Section, \
Semaphore, etc.), and named objects expose their name. Handles show what a process touches: a \
malware-family mutant, a File/Key handle held open, or a Process handle opened with \
PROCESS_VM_WRITE/PROCESS_VM_OPERATION — a direct indicator of injection targeting. Thread \
enumeration adds the _ETHREAD StartAddress and CreateTime; a thread starting in private, \
unbacked memory is a hallmark of CreateRemoteThread injection. Cross-reference \
mem_process_injection (the injected region) and mem_running_processes. The granted-access mask \
and the object name are the highest-signal fields for attributing intent.",
    mitre_techniques: &[
        "T1057",     // Process Discovery
        "T1055",     // Process Injection
        "T1055.003", // Thread Execution Hijacking
    ],
    fields: MEM_HANDLES_THREADS_FIELDS,
    retention: Some("RAM only; lost on power-off"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "mem_running_processes",
        "mem_process_injection",
        "mem_loaded_modules",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py (_HANDLE_TABLE walk, _OBJECT_HEADER type resolution, granted access, object name)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles (Object Manager handles and handle tables)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Legitimate processes hold many handles; a handle alone is context, not proof — weight the object name and access mask",
        "A rootkit that unlinks or corrupts the handle table can hide handles from a table walk",
        "TypeIndex-to-name resolution depends on the correct symbol/profile; a wrong profile mislabels object types",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Handle tables and thread objects live in RAM; lost on power-off",
};

// ── Kernel callbacks / SSDT hooks / driver-object scan (rootkit) ─────────────

/// Field schema for registered kernel callbacks and driver hooks.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py
pub(crate) static MEM_KERNEL_CALLBACKS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "callback_type",
        value_type: ValueType::Text,
        description: "Notification family — PsSetCreateProcessNotifyRoutine(Ex), PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine, CmRegisterCallback (registry), or a Bugcheck/Shutdown callback",
        is_uid_component: true,
    },
    FieldSchema {
        name: "callback",
        value_type: ValueType::UnsignedInt,
        description: "Address of the registered callback routine",
        is_uid_component: true,
    },
    FieldSchema {
        name: "module",
        value_type: ValueType::Text,
        description: "Owning driver/module resolved by locating the callback address within a loaded module's range; UNKNOWN when the address falls outside every known module (a rootkit signal)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "detail",
        value_type: ValueType::Text,
        description: "Extra context where applicable (e.g. registry callback Altitude string, or the associated component)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ssdt_index",
        value_type: ValueType::UnsignedInt,
        description: "For SSDT rows: the KiServiceTable entry index",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ssdt_target",
        value_type: ValueType::UnsignedInt,
        description: "For SSDT rows: the service-routine address; a target outside ntoskrnl indicates a hooked service entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "driver_name",
        value_type: ValueType::Text,
        description: "For driverscan/modscan rows: the _DRIVER_OBJECT name (\\Driver\\...) recovered by scanning the pool for driver objects",
        is_uid_component: false,
    },
];

/// Kernel callbacks, SSDT entries, and driver-object scan (rootkit detection).
///
/// Rootkits and EDR-evasion drivers register themselves in the kernel's
/// notification arrays — process/thread creation (`PsSetCreateProcessNotify‑
/// RoutineEx`, `PsSetCreateThreadNotifyRoutine`), image load
/// (`PsSetLoadImageNotifyRoutine`), and registry operations (`CmRegisterCallback`)
/// — or hook the System Service Descriptor Table (`KiServiceTable`). Enumerating
/// these arrays and resolving each callback address back to its owning loaded
/// module is a general integrity check: a callback whose address falls outside
/// every known module, or an SSDT entry pointing outside `ntoskrnl`, is a strong
/// tampering/rootkit signal. Pool-scanning for `_DRIVER_OBJECT` allocations
/// (driverscan/modscan) additionally recovers drivers unlinked from the loaded-
/// module list.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py
/// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
pub(crate) static MEM_KERNEL_CALLBACKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_kernel_callbacks",
    name: "Kernel Callbacks / SSDT / Driver Scan (Memory)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Registered kernel notification callbacks, SSDT service entries, and driver objects \
recovered from a memory image for rootkit and driver-tampering detection. The kernel exposes \
notification arrays for process/thread creation (PsSetCreateProcessNotifyRoutineEx, \
PsSetCreateThreadNotifyRoutine), image load (PsSetLoadImageNotifyRoutine), and registry operations \
(CmRegisterCallback); the System Service Descriptor Table (KiServiceTable) holds the syscall \
service routines. Enumerating these and resolving each target address to its owning loaded module \
is a general integrity check: a callback or SSDT target that resolves to no known module (or \
outside ntoskrnl) is a strong rootkit/hook signal. Pool-scanning for _DRIVER_OBJECT allocations \
(driverscan/modscan) recovers drivers unlinked from PsLoadedModuleList. Cross-reference \
mem_loaded_modules (a driver present in the pool but absent from the module list is hidden). \
An UNKNOWN owning module for any callback is the core anomaly to chase.",
    mitre_techniques: &[
        "T1547.006", // Boot or Logon Autostart Execution: Kernel Modules and Extensions
        "T1014",     // Rootkit
        "T1562.001", // Impair Defenses: Disable or Modify Tools
        "T1068",     // Exploitation for Privilege Escalation (vulnerable-driver loading)
    ],
    fields: MEM_KERNEL_CALLBACKS_FIELDS,
    retention: Some("RAM only; lost on power-off"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["mem_loaded_modules", "mem_hidden_processes"],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py (notify-routine arrays, CmRegisterCallback, module resolution of callback addresses)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex (process-creation notify-routine registration)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate security products (AV/EDR) register the same callbacks — an UNKNOWN or unsigned owning module, not the mere presence of a callback, is the signal",
        "SSDT hooking is rare on x64 with PatchGuard; absence of SSDT hooks does not clear a host of kernel tampering",
        "Module resolution depends on an accurate loaded-module list; a driver that hides its module entry can also evade address-to-module attribution",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Callback arrays, the SSDT, and driver objects reside in kernel RAM; lost on power-off",
};

// ── DKOM-hidden process detection (psscan vs pslist cross-view) ──────────────

/// Field schema for processes recovered by _EPROCESS pool scanning.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py
pub(crate) static MEM_HIDDEN_PROCESSES_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Process identifier (_EPROCESS UniqueProcessId)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "ppid",
        value_type: ValueType::UnsignedInt,
        description: "Parent process identifier (_EPROCESS InheritedFromUniqueProcessId)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "name",
        value_type: ValueType::Text,
        description: "Process image name (_EPROCESS ImageFileName, up to 15 chars)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "offset",
        value_type: ValueType::UnsignedInt,
        description: "Physical offset of the _EPROCESS pool allocation the object was carved from",
        is_uid_component: true,
    },
    FieldSchema {
        name: "create_time",
        value_type: ValueType::Timestamp,
        description: "Process creation time (_EPROCESS CreateTime as FILETIME)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "exit_time",
        value_type: ValueType::Timestamp,
        description: "Process exit time (_EPROCESS ExitTime as FILETIME); non-zero means the process has terminated but its allocation is not yet reused",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_pslist",
        value_type: ValueType::Bool,
        description: "True when the same process also appears in the active-process linked-list walk (pslist); False marks a process visible only to the pool scan — the DKOM-hidden / unlinked signal",
        is_uid_component: false,
    },
];

/// DKOM-hidden process detection — `_EPROCESS` pool scan vs pslist cross-view.
///
/// Direct Kernel Object Manipulation hides a process by unlinking its
/// `_EPROCESS` from the doubly-linked `ActiveProcessLinks` list that the OS (and
/// a list-walking `pslist`) enumerates — while the object itself remains
/// allocated and schedulable. psscan finds it anyway by scanning the pool for
/// the `_EPROCESS` allocation pattern rather than trusting the list. The
/// detection is the *cross-view*: a process present in the pool scan but absent
/// from the list walk is unlinked (hidden or recently exited). The same scan
/// recovers terminated processes whose allocations are not yet reused (non-zero
/// `ExitTime`), giving historical process evidence beyond the live list.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py
/// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess
pub(crate) static MEM_HIDDEN_PROCESSES: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_hidden_processes",
    name: "DKOM-Hidden Processes (Memory psscan Cross-View)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Processes recovered by scanning kernel pool for _EPROCESS allocations (psscan) and \
compared against the active-process linked-list walk (pslist). Direct Kernel Object Manipulation \
(DKOM) hides a running process by unlinking its _EPROCESS from the ActiveProcessLinks list that \
the OS and list-based enumeration follow, while the object stays allocated and schedulable. Pool \
scanning does not trust that list, so it still finds the object; the detection is the cross-view — \
a process seen by psscan but not by pslist is unlinked (actively hidden or recently exited). The \
scan also recovers terminated processes whose _EPROCESS allocation is not yet reused (non-zero \
ExitTime), providing historical process evidence. Each object yields PID, PPID, image name, \
physical offset, and create/exit FILETIMEs. Cross-reference mem_running_processes (the list view) \
and mem_kernel_callbacks (DKOM frequently accompanies a loaded rootkit driver). A False in_pslist \
with a zero ExitTime is the strongest hidden-process indicator.",
    mitre_techniques: &[
        "T1014",     // Rootkit
        "T1055",     // Process Injection (hollowed/hidden host)
        "T1564",     // Hide Artifacts
    ],
    fields: MEM_HIDDEN_PROCESSES_FIELDS,
    retention: Some("RAM only; exited processes survive only until the _EPROCESS pool allocation is reused"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "mem_running_processes",
        "mem_kernel_callbacks",
        "mem_process_injection",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py (_EPROCESS pool scan, physical/virtual offset, create/exit time)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess (!process — _EPROCESS fields, ActiveProcessLinks)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "A psscan-only hit is often a legitimately exited process (allocation not yet reused), not a hidden one — check ExitTime before concluding DKOM",
        "Pool scanning yields false positives from stale/overwritten _EPROCESS allocations; validate PID/name/pointers before trusting a carved object",
        "Absence of an unlinked process does not prove no rootkit — some hide via callback filtering rather than DKOM (see mem_kernel_callbacks)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "_EPROCESS objects live in kernel pool in RAM; lost on power-off and overwritten as the pool is recycled",
};
