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
        description: "VAD page protection from the VadS/VadF Flags.Protection field (e.g. PAGE_EXECUTE_READWRITE); an executable, non-image-backed region is consistent with injection — corroborate with the region contents",
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
        description: "First bytes of the region; a leading MZ header or valid x86/x64 prologue in an executable private region is consistent with a mapped PE or shellcode",
        is_uid_component: false,
    },
];

/// Injected code regions in memory — private, executable VADs (malfind-class).
///
/// malfind enumerates each process' Virtual Address Descriptor (VAD) tree and
/// flags regions consistent with injection. Its filter is not simply "private
/// RWX": it considers executable, non-image-backed VADs (a private short VAD
/// with `Flags.PrivateMemory == 1` and pool tag `VadS`, or a region whose
/// protection is not `PAGE_EXECUTE_WRITECOPY`), and reports one only when its
/// protection is write+execute OR it contains a *dirty* executable page in an
/// otherwise non-writable region (write-then-protect injection); a clean
/// execute-only region is not reported. Classic injection — `VirtualAllocEx` + `WriteProcessMemory`,
/// reflective DLL loading, process hollowing, `.text` overwrites — often leaves
/// this footprint, frequently beginning with an `MZ` header or a bare code
/// prologue. The signal comes from the `_MMVAD` node's `Flags.Protection`,
/// `Flags.PrivateMemory`, and `Flags.CommitCharge` fields, plus the pool tag.
/// Columns emitted: PID, Process, Start VPN, End VPN, Tag, Protection,
/// CommitCharge, PrivateMemory, plus a hexdump/disassembly of the region head.
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
    meaning: "Executable memory regions recovered by walking each process' VAD tree \
(malfind-class analysis). malfind considers executable, non-image-backed VADs (a private short VAD \
with Flags.PrivateMemory == 1 and pool tag VadS, or a region whose protection is not \
PAGE_EXECUTE_WRITECOPY) and reports one only when its protection is write+execute OR it contains a \
dirty executable page in an otherwise non-writable region (write-then-protect injection); a clean \
execute-only region is not reported. Injected code — VirtualAllocEx+WriteProcessMemory, reflective DLL \
loading, process hollowing, in-place .text patching — often produces such regions with no mapped \
module on disk. The determination is made from the _MMVAD node's Flags.Protection, \
Flags.PrivateMemory, and Flags.CommitCharge fields together with the VAD pool tag. A region \
beginning with an MZ header or a valid instruction prologue in executable private memory is \
consistent with a mapped PE or shellcode. Cross-reference mem_loaded_modules (a region with no \
corresponding module is unbacked) and mem_hidden_processes (injection often targets a hidden or \
hollowed process). Absence of a disk-backed module for executable memory is the core anomaly.",
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
        description: "Endpoint creation time (CreateTime as FILETIME) when the object carries one — vol3 emits it for UDP endpoints and TCP listeners as well as TCP endpoints",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pool_offset",
        value_type: ValueType::UnsignedInt,
        description: "Offset of the pool allocation the object was carved from (netscan Offset column)",
        is_uid_component: false,
    },
];

/// Network endpoints from RAM by pool-tag scanning (netscan-class).
///
/// netscan recovers TCP and UDP endpoints and listeners by scanning the pool
/// for the allocation tags of the network objects (`TcpE` and `TTcb` for
/// `_TCP_ENDPOINT` — `TTcb` on win10/20348 symbol builds — `TcpL` for
/// `_TCP_LISTENER`, `UdpA` for `_UDP_ENDPOINT`) rather than walking a live table
/// via OS APIs. Because it is a pool scan, it recovers endpoints that have
/// already been closed (their allocations not yet reused) and connections hidden
/// from `netstat`/API-based enumeration — the RAM equivalent of carving. Each
/// object yields the local/foreign address and port, TCP state, owning PID and
/// process, and a creation FILETIME when available (emitted for UDP endpoints and
/// TCP listeners too, not TCP endpoints alone). Columns emitted: Offset, Proto,
/// LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created.
/// This exposes C2 channels, beaconing, and lateral-movement sessions that
/// on-host tooling can miss.
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
for the network-object tags (TcpE and TTcb for _TCP_ENDPOINT, TcpL for _TCP_LISTENER, UdpA for \
_UDP_ENDPOINT), rather than by walking a live table through OS APIs. Pool scanning recovers \
recently-closed connections whose allocations are not yet reused, and connections hidden from \
netstat/API enumeration — the memory analogue of carving. Each object provides local and foreign \
IP/port, TCP state, the owning PID and process image, and a creation FILETIME when available \
(vol3 emits it for UDP endpoints and TCP listeners too, not TCP endpoints alone). Reveals C2 \
channels, beaconing, and lateral-movement sessions. Cross-reference mem_network_connections for \
the coarse in-memory connection view, and mem_running_processes to attribute an endpoint to a \
suspicious or hidden owning process. An endpoint whose owning process no longer appears in the \
active process list is suspicious; corroborate with the owning-process validity (psscan vs \
pslist) before concluding the process is hidden.",
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
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py (TcpE/TTcb/TcpL/UdpA pool-tag scan, address/port/state/owner extraction)
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
///
/// Handle fields (pid/process/handle_value/object_type/granted_access/
/// object_name) come from `windows.handles`; the thread fields (tid/
/// start_address/create_time) come from `windows.threads` / `windows.thrdscan`,
/// which handles.py does not emit.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py
pub(crate) static MEM_HANDLES_THREADS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier (_EPROCESS UniqueProcessId; handles PID column)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process",
        value_type: ValueType::Text,
        description: "Owning process image name (handles Process column)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "handle_value",
        value_type: ValueType::UnsignedInt,
        description: "Handle value taken from the _HANDLE_TABLE_ENTRY (handles HandleValue column); its decoding into a table index is Windows-version-dependent",
        is_uid_component: true,
    },
    FieldSchema {
        name: "object_type",
        value_type: ValueType::Text,
        description: "Object type name resolved from the _OBJECT_HEADER TypeIndex (handles Type column; e.g. Process, Thread, File, Key, Mutant, Event, Token, Section)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "granted_access",
        value_type: ValueType::UnsignedInt,
        description: "Granted-access mask on the handle (handles GrantedAccess column; e.g. PROCESS_ALL_ACCESS 0x1FFFFF; PROCESS_VM_WRITE/PROCESS_VM_OPERATION are consistent with injection targeting)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "object_name",
        value_type: ValueType::Text,
        description: "Object name where the type carries one (handles Name column: file path, registry key path, mutant/event name); empty for unnamed objects",
        is_uid_component: false,
    },
    FieldSchema {
        name: "tid",
        value_type: ValueType::UnsignedInt,
        description: "Thread identifier — from windows.threads/windows.thrdscan (TID column), not handles.py",
        is_uid_component: false,
    },
    FieldSchema {
        name: "start_address",
        value_type: ValueType::UnsignedInt,
        description: "Thread start address (_ETHREAD StartAddress; threads/thrdscan StartAddress column); a start address in unbacked private memory is consistent with an injected thread",
        is_uid_component: false,
    },
    FieldSchema {
        name: "create_time",
        value_type: ValueType::Timestamp,
        description: "Thread creation time (_ETHREAD CreateTime as FILETIME; threads/thrdscan CreateTime column)",
        is_uid_component: false,
    },
];

/// Open handles and threads per process (handles + threads enumeration).
///
/// Walking a process' `_HANDLE_TABLE` (`windows.handles`) yields every open
/// kernel object handle; each `_HANDLE_TABLE_ENTRY` points at an `_OBJECT_HEADER`
/// whose `TypeIndex` resolves the object type (Process, Thread, File, Key,
/// Mutant, Event, Token, Section, …), and named objects expose their name.
/// handles.py lists open handles only — it does NOT enumerate threads. Handles
/// reveal what a process touches: a mutant naming a known malware family, a
/// handle to another process opened with `PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION`
/// (an injection target), file and registry handles held open. The thread view
/// is a separate plugin: `windows.threads`/`windows.thrdscan` enumerate `_ETHREAD`
/// objects and their `StartAddress`/`CreateTime`. A thread whose `StartAddress`
/// lies in private, unbacked memory is consistent with `CreateRemoteThread`-style
/// code injection. handles columns emitted: PID, Process, Offset, HandleValue,
/// Type, GrantedAccess, Name.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/thrdscan.py
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
    meaning: "Open kernel-object handles owned by a process (from windows.handles, which walks the \
_HANDLE_TABLE) together with the process' threads (from windows.threads/windows.thrdscan, which \
enumerate _ETHREAD objects — handles.py itself lists handles only, not threads). Each handle-table \
entry references an _OBJECT_HEADER whose TypeIndex resolves the object type (Process, Thread, File, \
Key, Mutant, Event, Token, Section, Semaphore, etc.), and named objects expose their name. Handles \
show what a process touches: a malware-family mutant, a File/Key handle held open, or a Process \
handle opened with PROCESS_VM_WRITE/PROCESS_VM_OPERATION — consistent with injection targeting, not \
proof. Thread enumeration adds the _ETHREAD StartAddress and CreateTime; a thread starting in \
private, unbacked memory is consistent with CreateRemoteThread injection. Cross-reference \
mem_process_injection (the injected region) and mem_running_processes. The granted-access mask and \
the object name are the highest-signal fields for attributing intent.",
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
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py (_HANDLE_TABLE walk, _OBJECT_HEADER type resolution, granted access, object name — handles only, no threads)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py (_ETHREAD enumeration per process — TID/StartAddress/CreateTime)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/thrdscan.py (_ETHREAD pool scan — Offset/PID/TID/StartAddress/CreateTime/ExitTime)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/thrdscan.py",
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

/// Field schema for registered kernel callbacks and (related-plugin) SSDT/driver rows.
///
/// The callback/module/symbol/detail fields come from `windows.callbacks`; the
/// ssdt_index/ssdt_target fields come from `windows.ssdt`, and driver_name from
/// `windows.driverscan` — callbacks.py itself neither enumerates SSDT rows nor
/// scans _DRIVER_OBJECT allocations.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/ssdt.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/driverscan.py
pub(crate) static MEM_KERNEL_CALLBACKS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "callback_type",
        value_type: ValueType::Text,
        description: "Notification family (callbacks Type column) — process/thread-creation, load-image, or registry (Cm) callback, or a Bugcheck/Shutdown callback",
        is_uid_component: true,
    },
    FieldSchema {
        name: "callback",
        value_type: ValueType::UnsignedInt,
        description: "Address of the registered callback routine (callbacks Callback column)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "module",
        value_type: ValueType::Text,
        description: "Owning driver/module resolved by locating the callback address within a loaded module's range (callbacks Module column); UNKNOWN when the address falls outside every known module",
        is_uid_component: false,
    },
    FieldSchema {
        name: "symbol",
        value_type: ValueType::Text,
        description: "Symbol vol3 resolves for the callback ROUTINE ADDRESS via owning-module symbol lookup (callbacks Symbol column) — the target the callback points to, not the array name; the notify-array itself (PspLoadImageNotifyRoutine, PspCreateThreadNotifyRoutine, PspCreateProcessNotifyRoutine, CmRegisterCallback/Ex) is reflected in the Type column",
        is_uid_component: false,
    },
    FieldSchema {
        name: "detail",
        value_type: ValueType::Text,
        description: "Extra context where applicable (callbacks Detail column; e.g. registry callback Altitude string, or the associated component)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ssdt_index",
        value_type: ValueType::UnsignedInt,
        description: "From windows.ssdt (not callbacks.py): the KiServiceTable entry index",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ssdt_target",
        value_type: ValueType::UnsignedInt,
        description: "From windows.ssdt (not callbacks.py): the service-routine address; a target outside ntoskrnl is consistent with a hooked service entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "driver_name",
        value_type: ValueType::Text,
        description: "From windows.driverscan (not callbacks.py): the _DRIVER_OBJECT name (\\Driver\\...) recovered by pool-scanning for driver objects",
        is_uid_component: false,
    },
];

/// Kernel callbacks (callbacks plugin) plus related SSDT and driver-object scans.
///
/// Rootkits and EDR-evasion drivers register themselves in the kernel's
/// notification arrays — process/thread creation (`PspCreateProcessNotifyRoutine`,
/// `PspCreateThreadNotifyRoutine`), image load (`PspLoadImageNotifyRoutine`), and
/// registry operations (`CmRegisterCallback`/`CmRegisterCallbackEx`). The
/// `windows.callbacks` plugin lists these callback routines and resolves each
/// address to its owning loaded module (emitting Type, Callback, Module, Symbol,
/// Detail); it does NOT enumerate SSDT rows or scan for `_DRIVER_OBJECT`
/// allocations. Those are separate plugins: `windows.ssdt` walks the System
/// Service Descriptor Table (`KiServiceTable`), and `windows.driverscan`
/// pool-scans for driver objects (recovering drivers unlinked from
/// `PsLoadedModuleList`). Resolving a callback or SSDT target to no known module
/// (or outside `ntoskrnl`) is suspicious — but it can also reflect a symbol or
/// module-list resolution failure or an unloaded-driver context, so corroborate
/// before concluding a hook.
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
    meaning: "Registered kernel notification callbacks (from windows.callbacks), and — via the \
related windows.ssdt and windows.driverscan plugins — SSDT service entries and pooled driver \
objects, recovered from a memory image for rootkit and driver-tampering detection. The kernel \
exposes notification arrays for process/thread creation (PspCreateProcessNotifyRoutine, \
PspCreateThreadNotifyRoutine), image load (PspLoadImageNotifyRoutine), and registry operations \
(CmRegisterCallback/CmRegisterCallbackEx); windows.callbacks lists these routines and resolves \
each address to its owning module (Type, Callback, Module, Symbol, Detail). It does not itself \
enumerate the System Service Descriptor Table or scan _DRIVER_OBJECT allocations — windows.ssdt \
walks KiServiceTable and windows.driverscan pool-scans for driver objects (recovering drivers \
unlinked from PsLoadedModuleList). A callback or SSDT target that resolves to no known module (or \
outside ntoskrnl) is suspicious; it can also reflect a symbol/module-list resolution failure or \
an unloaded-driver context, so corroborate before concluding a hook. Cross-reference \
mem_loaded_modules (a driver present in the pool but absent from the module list is consistent with \
hiding — corroborate, as pool scans can surface stale or partially-valid driver objects).",
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
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py (notify-routine arrays, CmRegisterCallback, module resolution of callback addresses — Type/Callback/Module/Symbol/Detail)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/ssdt.py (KiServiceTable / SSDT enumeration and module resolution)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/ssdt.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/driverscan.py (_DRIVER_OBJECT pool scan — driver name recovery)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/driverscan.py",
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
///
/// pid/ppid/name/offset/create_time/exit_time come from `windows.psscan` (which
/// defaults to a VIRTUAL offset, physical only with `--physical`); `in_pslist`
/// is a DERIVED cross-view against `windows.pslist`, not a psscan column.
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py
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
        description: "Offset of the _EPROCESS allocation (psscan Offset column) — virtual by default, physical only with --physical",
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
        description: "DERIVED cross-view, not a psscan column: True when the same _EPROCESS also appears in the active-process linked-list walk (windows.pslist); False marks a process visible only to the pool scan — the DKOM-hidden / unlinked signal. Computed by the analyst/tool by diffing psscan against pslist.",
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
/// `ExitTime`), giving historical process evidence beyond the live list. psscan
/// columns emitted: PID, PPID, ImageFileName, Offset (virtual by default,
/// physical with `--physical`), Threads, Handles, SessionId, Wow64, CreateTime,
/// ExitTime. `in_pslist` is not a psscan column — it is the derived psscan-vs-
/// pslist diff.
///
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py
/// Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py
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
offset (virtual by default, physical with --physical), and create/exit FILETIMEs; in_pslist is a \
derived psscan-vs-pslist cross-view, not a psscan column. Cross-reference mem_running_processes \
(the list view) and mem_kernel_callbacks (DKOM frequently accompanies a loaded rootkit driver). A \
False in_pslist with a zero ExitTime is suspicious; corroborate with the process-object validity \
(sane PID/PPID/pointers) and ExitTime before concluding DKOM rather than a recently-exited process.",
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
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py (_EPROCESS pool scan; Offset column is virtual by default, physical with --physical; create/exit time)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py (ActiveProcessLinks list walk — the pslist half of the in_pslist cross-view)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py",
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
