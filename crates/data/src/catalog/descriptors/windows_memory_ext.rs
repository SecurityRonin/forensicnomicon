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
///
/// `protection` is the allocation-time value recorded in the `_MMVAD`;
/// `pte_protection`, `vad_pte_mismatch` and `image_page_privatized` come from
/// the per-page hardware page-table entries, which carry the protection the CPU
/// actually enforces and the private-vs-prototype backing of each page.
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py>
/// Source: <https://doi.org/10.1016/j.diin.2019.04.008>
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
        description: "VAD page protection from the VadS/VadF Flags.Protection field (e.g. PAGE_EXECUTE_READWRITE) — the protection requested when the region was ALLOCATED or mapped, not the protection in force now; an executable, non-image-backed region is consistent with injection — corroborate with the region contents",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pte_protection",
        value_type: ValueType::Text,
        description: "CURRENT per-page protection decoded from the hardware page-table entries covering the region (the no-execute and write bits the CPU enforces). This is the ground truth for what can execute right now; read it, not the VAD, when deciding whether a region is executable",
        is_uid_component: false,
    },
    FieldSchema {
        name: "vad_pte_mismatch",
        value_type: ValueType::Bool,
        description: "True when a page's PTE-derived protection differs from the VAD's recorded protection. Allocating a region without WRITE or EXECUTE and adding the right per-page afterwards (VirtualProtect/NtProtectVirtualMemory) leaves the VAD untouched, so the mismatch is itself the artifact — and a VAD-protection filter is structurally blind to it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "image_page_privatized",
        value_type: ValueType::Bool,
        description: "True when a page inside a file-backed IMAGE mapping resolves to a process-private physical page instead of the shared page the kernel's prototype PTE points at — consistent with the image having been modified after it was loaded (module stomping / DLL hollowing). A debugger breakpoint or a relocation fixup privatises a page the same way, so diff the page against the on-disk image before calling it a patch",
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
/// with `Flags.PrivateMemory == 1` and pool tag `VadS`, or a non-private region
/// (`Flags.PrivateMemory == 0`) whose protection is not `PAGE_EXECUTE_WRITECOPY`),
/// and reports one only when its
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
/// The VAD and the page tables answer different questions, and the gap between
/// them is itself evidence. `Flags.Protection` records what was requested when
/// the region was allocated or mapped; the protection the CPU enforces lives in
/// the per-page hardware PTE and can be changed afterwards
/// (`VirtualProtect`/`NtProtectVirtualMemory`) without the VAD following. Code
/// can therefore be written into a region allocated without WRITE or EXECUTE —
/// or into unused space in an existing benign VAD — and the execute right added
/// page by page, which is invisible to a VAD-protection filter (Block & Dewald,
/// DFRWS USA 2019). Enumerating PTEs recovers both the current protection and
/// the backing of each page, so an image page served by a process-private
/// physical page rather than the shared page its prototype PTE names stands out
/// as an image modified after load.
///
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad>
/// Source: <https://doi.org/10.1016/j.diin.2019.04.008>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect>
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
with Flags.PrivateMemory == 1 and pool tag VadS, or a non-private region (Flags.PrivateMemory == 0) \
whose protection is not PAGE_EXECUTE_WRITECOPY) and reports one only when its protection is \
write+execute OR it contains a \
dirty executable page in an otherwise non-writable region (write-then-protect injection); a clean \
execute-only region is not reported. Injected code — VirtualAllocEx+WriteProcessMemory, reflective DLL \
loading, process hollowing, in-place .text patching — often produces such regions with no mapped \
module on disk. The determination is made from the _MMVAD node's Flags.Protection, \
Flags.PrivateMemory, and Flags.CommitCharge fields together with the VAD pool tag. A region \
beginning with an MZ header or a valid instruction prologue in executable private memory is \
consistent with a mapped PE or shellcode. The VAD answers what was requested at allocation time and \
the hardware page-table entry answers what the CPU enforces now: a later \
VirtualProtect/NtProtectVirtualMemory changes the PTE without updating the VAD, so code can be \
written into a region allocated without WRITE or EXECUTE (or into unused space in an existing \
benign VAD) and the execute right added page by page, defeating a VAD-protection filter. That makes \
a VAD-vs-PTE protection mismatch an artifact in its own right, and makes PTE enumeration — not the \
VAD — the ground truth for what is executable. The same page-level view separates a clean image \
mapping from a patched one: an image page served by a process-private physical page instead of the \
shared page its prototype PTE names is consistent with the image having been modified after load \
(module stomping / DLL hollowing), though copy-on-write from a debugger breakpoint or a relocation \
fixup privatises a page the same way. Cross-reference mem_loaded_modules (a region with no \
corresponding module is unbacked), mem_hidden_modules (an executable mapping absent from some or \
all of the three PEB module lists), and mem_hidden_processes (injection often targets a hidden or hollowed process). \
Absence of a disk-backed module for executable memory is the core anomaly.",
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
        "mem_hidden_modules",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py (VAD walk, protection/PrivateMemory flags, MZ/prologue check)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad (!vad — _MMVAD tree, protection, commit charge)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad",
        // Source: Block & Dewald, "Windows Memory Forensics: Detecting (Un)Intentionally Hidden Injected Code by Examining Page Table Entries", Digital Investigation 29(S), DFRWS USA 2019 (VAD protection is allocation-time and attacker-controllable; per-page PTE bits are the ground truth)
        "https://doi.org/10.1016/j.diin.2019.04.008",
        // Source: https://github.com/f-block/DFRWS-USA-2019 (paper repository — the ptenum PTE-enumeration implementation)
        "https://github.com/f-block/DFRWS-USA-2019",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect (protection of committed pages can be changed after allocation)
        "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-pte (!pte — the hardware page-table entry behind a virtual address)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-pte",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Legitimate JIT engines (JavaScript, .NET, Java) also allocate private RWX memory — corroborate with the region contents and the hosting process",
        "Modern injection may set RW then flip to RX (avoiding a persistent RWX VAD), so an RWX filter alone can miss it — inspect RX private regions too",
        "The VAD records the protection requested at allocation/mapping time and is not updated when protection is changed later, so a VAD-only view can report a region as non-executable while its pages are executable — read the per-page PTE before calling a region clean",
        "A VAD-vs-PTE protection mismatch is an anomaly, not a verdict: legitimate loaders and JITs also allocate writable and re-protect executable, so weight the region contents and the owning module",
        "An image page backed by a private physical page instead of its prototype page is consistent with a post-load patch, but copy-on-write from a debugger breakpoint or a relocation fixup produces the identical divergence — diff against the on-disk image",
        "Region contents are the ground truth; protection flags alone are circumstantial",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Lives in process VADs in RAM; lost on power-off unless captured in a memory image, hibernation file, or crash dump",
};

// ── Network connections & sockets from RAM (netscan-class) ──────────────────

/// Field schema for network endpoints recovered by pool-tag scanning.
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py>
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
        description: "Remote IP address; unset for listeners. On a UDP row vol3 emits the literal '*' — a hard-coded placeholder meaning 'a datagram socket has no peer', never 'the address failed to decode'",
        is_uid_component: true,
    },
    FieldSchema {
        name: "foreign_port",
        value_type: ValueType::UnsignedInt,
        description: "Remote port; unset for listeners. Emitted as 0 on UDP rows for the same not-applicable reason as foreign_addr, so a 0 there is not a decode failure",
        is_uid_component: false,
    },
    FieldSchema {
        name: "state",
        value_type: ValueType::Text,
        description:
            "TCP state decoded through the tcpip.sys state enumeration (LISTENING=1, SYN_SENT=2, SYN_RCVD=3, ESTABLISHED=4, …, TIME_WAIT=12, DELETE_TCB=13). CLOSED is the enumeration's ZERO value, which is also what a zeroed, freed or partly-overwritten allocation decodes to — so a carved CLOSED row carries materially less weight than an ESTABLISHED one and must not be read as 'a connection that completed'. Blank on UDP rows by construction: a datagram socket has no state to report",
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
        description: "Owning process image name, resolved via the owning-process pointer — the kernel's fixed-width _EPROCESS.ImageFileName copy (15 bytes on current x64 public symbols, so at most 14 characters survive). Match it as a PREFIX, never by equality: a long name loses its extension here, and two binaries sharing the leading characters are indistinguishable. Resolve the endpoint's owner against mem_process_command_line before naming a program",
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
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused>
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
    related_artifacts: &[
        "mem_network_connections",
        "mem_running_processes",
        "mem_process_command_line",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py (TcpE/TTcb/TcpL/UdpA pool-tag scan, address/port/state/owner extraction; the _UDP_ENDPOINT branch emits the literal "*" and an empty State)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/windows/netscan/netscan-win10-19041-x64.json (TCPStateEnum — CLOSED=0, LISTENING=1, SYN_SENT=2, SYN_RCVD=3, ESTABLISHED=4, TIME_WAIT=12, DELETE_TCB=13)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/windows/netscan/netscan-win10-19041-x64.json",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused (kernel pool tags and allocation tagging)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolused",
        // Source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm (_EPROCESS layout per build — ImageFileName is a fixed-width byte array)
        "https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Pool scanning yields false positives from stale/overwritten allocations — validate address/port/state sanity before relying on a carved endpoint",
        "CLOSED is the zero value of the TCP state enumeration, so a zeroed or partly-overwritten allocation decodes to CLOSED: grade a carved CLOSED row below an ESTABLISHED one and corroborate before reporting it as a completed connection",
        "On UDP rows the '*' foreign address and blank State are hard-coded placeholders for 'not applicable', not fields that failed to decode — do not report them as missing data",
        "The owner name is the kernel's truncated fixed-width ImageFileName copy; distinct binaries sharing the leading characters collide, so treat it as a prefix and resolve the full path elsewhere",
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
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py>
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
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/handles.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/threads.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/thrdscan.py>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles>
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
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/ssdt.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/driverscan.py>
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
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/callbacks.py>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex>
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
/// is a DERIVED cross-view against `windows.pslist`, not a psscan column. The
/// remaining `in_*` booleans are the other independent enumeration sources a
/// psxview-class cross-view consults — vol3's plugin implements four of them
/// (pslist, psscan, thrdscan, csrss handles) and states in its own source that
/// the PspCidTable, session and desktop-thread methods are omitted; the vol2
/// plugin implements all seven and carries the known-good rules recorded in the
/// field descriptions.
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/psxview.py>
/// Source: <https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/psxview.py>
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
        description: "Process image name (_EPROCESS ImageFileName) — a fixed-width, NUL-terminated byte array (15 bytes on current x64 public symbols, so at most 14 characters survive). The KERNEL truncates it at process creation, so it is a lossy PREFIX, not an identity: a long name loses its extension, a hunt written as 'name ends in .exe' misses every long-named process, and two binaries sharing the leading characters are indistinguishable here — a masquerading surface. A stored value at the ceiling is the truncation tell. The untruncated name lives in _EPROCESS.SeAuditProcessCreationInfo.ImageFileName (a kernel-resident full NT path) or, attacker-writable, in the PEB's RTL_USER_PROCESS_PARAMETERS.ImagePathName",
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
    FieldSchema {
        name: "in_thrdscan",
        value_type: ValueType::Bool,
        description: "DERIVED: True when a scanned _ETHREAD names this process as its owner (Cid.UniqueProcess). Threads are allocated separately from the process object, so a rootkit that unlinks _EPROCESS usually leaves its threads discoverable — an independent witness to a process the list walk denies",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_csrss_handles",
        value_type: ValueType::Bool,
        description: "DERIVED: True when csrss.exe holds an open handle to this process. csrss does not open handles to System, smss.exe or csrss.exe itself, so a False on those is structurally normal and not an anomaly; a False on an exited process is likewise expected",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_pspcid",
        value_type: ValueType::Bool,
        description: "DERIVED: True when the process is present in the kernel's PspCidTable (the PID-to-object handle table). Hiding from it takes more than an ActiveProcessLinks unlink, so a True here beside a False in_pslist narrows the technique to a plain list unlink",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_session",
        value_type: ValueType::Bool,
        description: "DERIVED: True when the process appears in a session's process list. Processes that start before smss.exe (System, smss.exe) have no session entry, so a False on those is expected — as it is for an exited process",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_deskthrd",
        value_type: ValueType::Bool,
        description: "DERIVED: True when a desktop-attached thread belongs to this process. Shares the pre-smss.exe blind spot (System, smss.exe) and returns nothing for processes with no GUI thread, so it confirms rather than refutes",
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
/// Two sources make the cross-view binary; more make it diagnostic. Beyond
/// pslist and psscan there are five further independent enumerations — thread
/// owners (`_ETHREAD.Cid.UniqueProcess`), the kernel's `PspCidTable`, csrss.exe's
/// handle table, the session process lists, and desktop-attached threads — and
/// the PATTERN of which ones see a process narrows WHICH technique hid it: a
/// process missing only from pslist while present in the thread, PspCidTable,
/// csrss and session views is an `ActiveProcessLinks` unlink specifically, since
/// a technique that also unhooked `PspCidTable` would flip that column. Several
/// sources have documented benign blind spots — csrss.exe holds no handle to
/// System, smss.exe or csrss.exe, and processes started before smss.exe have no
/// session or desktop entry — so a False there is expected, not suspicious, and
/// an exited process is legitimately absent from most of them.
///
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py>
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/psxview.py>
/// Source: <https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/psxview.py>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess>
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
derived psscan-vs-pslist cross-view, not a psscan column. Five further independent enumerations \
turn the cross-view from binary into diagnostic — thread owners (_ETHREAD.Cid.UniqueProcess), the \
kernel's PspCidTable, csrss.exe's handle table, the session process lists, and desktop-attached \
threads — because the PATTERN of which sources see a process narrows which technique hid it: absent \
from pslist but present in the thread, PspCidTable, csrss and session views is an \
ActiveProcessLinks unlink specifically, while a technique that also unhooked PspCidTable would flip \
that column. Some sources have documented benign blind spots: csrss.exe holds no handle to System, \
smss.exe or csrss.exe, and processes started before smss.exe have no session or desktop entry, so a \
False there is normal rather than suspicious. The image name is the kernel's truncated fixed-width \
copy and must be treated as a prefix, not an identity. Cross-reference mem_running_processes (the \
list view), mem_process_command_line (the untruncated image path and arguments), and \
mem_kernel_callbacks (DKOM frequently accompanies a loaded rootkit driver). A False in_pslist with \
a zero ExitTime is suspicious; corroborate with the process-object validity (sane PID/PPID/pointers) \
and ExitTime before concluding DKOM rather than a recently-exited process.",
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
        "mem_process_command_line",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py (_EPROCESS pool scan; Offset column is virtual by default, physical with --physical; create/exit time)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/psscan.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py (ActiveProcessLinks list walk — the pslist half of the in_pslist cross-view)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/pslist.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/psxview.py (cross-view over four sources — pslist, psscan, thrdscan, csrss handles; documents the omission of the PspCidTable, session and desktop-thread methods)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/psxview.py",
        // Source: https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/psxview.py (all seven sources — pslist/psscan/thrdproc/pspcid/csrss/session/deskthrd — and the known-good rules: System, smss.exe and csrss.exe absent from the csrss view; System and smss.exe absent from the session and desktop views; exited processes absent from most)
        "https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/psxview.py",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess (!process — _EPROCESS fields, ActiveProcessLinks)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-eprocess",
        // Source: https://github.com/reactos/reactos/blob/master/sdk/include/ndk/setypes.h (SE_AUDIT_PROCESS_CREATION_INFO carries a POBJECT_NAME_INFORMATION — the full NT image path, kernel-resident and not attacker-writable)
        "https://github.com/reactos/reactos/blob/master/sdk/include/ndk/setypes.h",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "A psscan-only hit is often a legitimately exited process (allocation not yet reused), not a hidden one — check ExitTime before concluding DKOM",
        "Pool scanning yields false positives from stale/overwritten _EPROCESS allocations; validate PID/name/pointers before trusting a carved object",
        "Several cross-view sources have benign blind spots: csrss.exe holds no handle to System, smss.exe or csrss.exe, and processes started before smss.exe have no session or desktop-thread entry — a False in those columns for those processes is expected, not evidence of hiding",
        "An exited process is legitimately absent from most enumeration sources, so read the ExitTime column before reading the True/False pattern",
        "The image name is a kernel-truncated fixed-width prefix; two binaries agreeing on the leading characters look identical in this view — resolve the full path before attributing behaviour to a named program",
        "Absence of an unlinked process does not prove no rootkit — some hide via callback filtering rather than DKOM (see mem_kernel_callbacks)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "_EPROCESS objects live in kernel pool in RAM; lost on power-off and overwritten as the pool is recycled",
};

// ── Process command line from the PEB (cmdline-class) ───────────────────────

/// Field schema for the process parameters block reached through the PEB.
///
/// Every field below is read out of `_RTL_USER_PROCESS_PARAMETERS`, which the
/// loader allocates in the process' OWN user-mode address space. Microsoft
/// documents only `ImagePathName` and `CommandLine` (everything else in the
/// published `winternl.h` layout is declared `Reserved`); the remaining members
/// — `CurrentDirectory`, `DllPath`, `Environment`, `WindowTitle`, `DesktopInfo`,
/// `ShellInfo`, `RuntimeData` — are taken from the NT layout reproduced in the
/// ReactOS NDK headers.
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/cmdline.py>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters>
/// Source: <https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtltypes.h>
pub(crate) static MEM_PROCESS_COMMAND_LINE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier (_EPROCESS UniqueProcessId; cmdline PID column)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process",
        value_type: ValueType::Text,
        description: "Process image name from the kernel's fixed-width _EPROCESS.ImageFileName copy (cmdline Process column) — a lossy prefix (15 bytes on current x64 public symbols, so at most 14 characters survive); command_line and image_path_name in this same record are the untruncated strings it is a prefix of",
        is_uid_component: false,
    },
    FieldSchema {
        name: "command_line",
        value_type: ValueType::Text,
        description: "The full, untruncated invocation — image path and every argument — held as a UNICODE_STRING at _RTL_USER_PROCESS_PARAMETERS.CommandLine and emitted as the cmdline Args column. \
                      Read it as what the process CURRENTLY PRESENTS, never as the launch value: the structure lives in the process' own user-mode memory, so the process itself, or anything holding PROCESS_VM_WRITE on it, can overwrite the string after start",
        is_uid_component: false,
    },
    FieldSchema {
        name: "image_path_name",
        value_type: ValueType::Text,
        description: "_RTL_USER_PROCESS_PARAMETERS.ImagePathName — the image path the loader recorded, in the same user-writable storage as command_line. Its kernel-resident counterpart is _EPROCESS.SeAuditProcessCreationInfo.ImageFileName (a POBJECT_NAME_INFORMATION holding the full NT path), which an in-process rewrite does not reach; a disagreement between the two is the cross-view worth reporting",
        is_uid_component: false,
    },
    FieldSchema {
        name: "current_directory",
        value_type: ValueType::Text,
        description: "_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory — a CURDIR carrying a UNICODE_STRING DosPath plus an open directory handle. It resolves the relative paths in command_line and names the directory the process was working from, which is frequently the staging directory a payload ran out of",
        is_uid_component: false,
    },
    FieldSchema {
        name: "window_title",
        value_type: ValueType::Text,
        description: "_RTL_USER_PROCESS_PARAMETERS.WindowTitle — the string the creator passed as STARTUPINFO.lpTitle (for a console process the title bar text; NULL means the executable name is used instead), so it is set INDEPENDENTLY of the command line and need not agree with a rewritten one. \
                      Two documented dwFlags make it evidential rather than cosmetic: STARTF_TITLEISLINKNAME (0x00000800) means lpTitle holds the PATH OF THE .LNK the user invoked — Microsoft states the shell typically sets this when a shortcut is double-clicked — and STARTF_TITLEISAPPID (0x00001000) means it holds an AppUserModelID instead. Neither flag is readable from this string alone, so treat a path-shaped title as a lead and corroborate against the LNK and Jump List artifacts",
        is_uid_component: false,
    },
    FieldSchema {
        name: "environment",
        value_type: ValueType::Text,
        description: "The environment block pointed at by _RTL_USER_PROCESS_PARAMETERS.Environment, in Microsoft's documented format Var1=Value1\\0Var2=Value2\\0...\\0\\0 (NUL-separated NAME=VALUE pairs closed by a double NUL). \
                      A child inherits its parent's block by default, so it carries the launching context — USERNAME, USERDOMAIN, COMPUTERNAME, TEMP, PATH — plus anything a launcher injected. It sits in the same user-writable region as command_line and inherits the same rewrite caveat",
        is_uid_component: false,
    },
];

/// Untruncated process command line recovered from the PEB (cmdline-class).
///
/// `windows.cmdline` resolves each process' own address space, reads
/// `_EPROCESS.Peb` as a `_PEB`, follows `ProcessParameters` to an
/// `_RTL_USER_PROCESS_PARAMETERS`, and returns `CommandLine` — a
/// `UNICODE_STRING` — as the Args column (PID, Process, Args). That recovers the
/// whole invocation, image path and arguments, where `_EPROCESS.ImageFileName`
/// offers only a 15-byte-ceiling prefix. It matters most when the log-side
/// witnesses are not there: Security event 4688 carries a Process Command Line
/// field only when the "Include command line in process creation events" policy
/// is enabled, and Microsoft documents that policy's default as Not Configured
/// (not enabled), so on a default host the command line was never written to the
/// event log at all. Sysmon EID 1 does log the full command line for both the
/// process and its parent, but only where Sysmon is installed — and either log
/// can be cleared.
///
/// The load-bearing caveat is where the bytes live. `_RTL_USER_PROCESS_PARAMETERS`
/// is allocated in the process' OWN user-mode address space, not in kernel
/// memory, so a process can rewrite its own `CommandLine` after it has started,
/// and so can anything holding `PROCESS_VM_WRITE` on it. The documented
/// technique is to spawn suspended with benign arguments, let the PEB be
/// initialised and logged, then patch it — ATT&CK calls it Process Argument
/// Spoofing (T1564.010). The in-memory string is therefore what the process
/// currently PRESENTS, not necessarily what it was launched with: corroborate it
/// against the kernel-resident `SeAuditProcessCreationInfo.ImageFileName`, the
/// parent's own recorded invocation of the child, 4688 / Sysmon EID 1 where they
/// exist, and the on-disk execution artifacts of the same run.
///
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/cmdline.py>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters>
/// Source: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing>
pub(crate) static MEM_PROCESS_COMMAND_LINE: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_process_command_line",
    name: "Process Command Line (Memory PEB / cmdline)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "The complete command line of a running process, recovered from memory by resolving the \
process address space, reading _EPROCESS.Peb as a _PEB, following ProcessParameters to an \
_RTL_USER_PROCESS_PARAMETERS, and decoding the CommandLine UNICODE_STRING (windows.cmdline emits \
PID, Process, Args). The same structure carries ImagePathName, CurrentDirectory, WindowTitle and \
the Environment block, so one read yields the full invocation, the working directory, the title the \
creator supplied — which under STARTF_TITLEISLINKNAME is the path of the .LNK that was invoked — \
and the inherited environment. This is the untruncated counterpart to the kernel's fixed-width \
_EPROCESS.ImageFileName, which stops at 14 usable characters. Its value in an investigation is that \
it survives the log-side gaps: Microsoft documents the 'Include command line in process creation \
events' policy as Not Configured by default, so a default host's 4688 records carry NO command line \
at all, and Sysmon EID 1 (which does log the full command line for the process and its parent) \
exists only where Sysmon was deployed; both channels can also be cleared. \
THE CAVEAT IS STRUCTURAL, NOT INCIDENTAL: _RTL_USER_PROCESS_PARAMETERS is allocated in the \
process' OWN user-mode address space. A process can overwrite its own CommandLine after start, and \
anything holding PROCESS_VM_WRITE on it can do the same from outside — spawn suspended with benign \
arguments, let the PEB be initialised and logged, then patch it (MITRE ATT&CK T1564.010, Process \
Argument Spoofing). The in-memory value is therefore what the process CURRENTLY PRESENTS, not \
necessarily what it was launched with, and it must be reported that way. Corroborate against the \
kernel-resident _EPROCESS.SeAuditProcessCreationInfo.ImageFileName (not writable from user mode), \
the parent's own recorded invocation of the child, 4688 and Sysmon EID 1 where they exist, and the \
on-disk artifacts of the same execution. Cross-reference mem_running_processes and \
mem_hidden_processes (which name the process by the truncated kernel prefix this artifact expands), \
mem_process_injection (a rewritten command line and injected code often accompany each other), and \
evtx_security / evtx_sysmon for the log-side view.",
    mitre_techniques: &[
        "T1059",     // Command and Scripting Interpreter — what the arguments evidence
        "T1564.010", // Hide Artifacts: Process Argument Spoofing — the PEB rewrite
        "T1036.005", // Masquerading: Match Legitimate Name or Location
        "T1070.001", // Indicator Removal: Clear Windows Event Logs — why memory outlives 4688
    ],
    fields: MEM_PROCESS_COMMAND_LINE_FIELDS,
    retention: Some("RAM only; lost on power-off. Also recoverable from hiberfil.sys / crash dumps"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "mem_running_processes",
        "mem_hidden_processes",
        "mem_process_injection",
        "evtx_security",
        "evtx_sysmon",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/cmdline.py (_EPROCESS.Peb -> _PEB.ProcessParameters -> CommandLine.get_string(); PID/Process/Args columns; unreadable reads rendered as UnreadableValue rather than an empty string)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/cmdline.py",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb (PEB.ProcessParameters — "a pointer to an RTL_USER_PROCESS_PARAMETERS structure that contains process parameter information such as the command line")
        "https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters (the documented members — ImagePathName and CommandLine as UNICODE_STRINGs; everything else Reserved)
        "https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters",
        // Source: https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtltypes.h (the full NT RTL_USER_PROCESS_PARAMETERS layout — CurrentDirectory (CURDIR), DllPath, ImagePathName, CommandLine, Environment, WindowTitle, DesktopInfo, ShellInfo, RuntimeData)
        "https://github.com/reactos/reactos/blob/master/sdk/include/ndk/rtltypes.h",
        // Source: https://github.com/reactos/reactos/blob/master/sdk/include/ndk/setypes.h (SE_AUDIT_PROCESS_CREATION_INFO — the kernel-resident full NT image path that a user-mode PEB rewrite cannot reach)
        "https://github.com/reactos/reactos/blob/master/sdk/include/ndk/setypes.h",
        // Source: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing ("Include command line in process creation events" — Default setting: Not Configured (not enabled); without it 4688 carries no command line)
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        // Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (Sysmon "logs process creation with full command line for both current and parent processes"; Event ID 1 process creation)
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow (lpTitle semantics; STARTF_TITLEISLINKNAME = lpTitle holds the path of the .lnk invoked, STARTF_TITLEISAPPID = an AppUserModelID)
        "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow",
        // Source: https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables (environment block format Var1=Value1\0...\0\0 and inheritance from the parent process)
        "https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory (an outside process holding PROCESS_VM_WRITE can write the target's user-mode memory, which is where the process parameters live)
        "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "_RTL_USER_PROCESS_PARAMETERS lives in the process' own USER-writable memory, so the recovered command line is what the process CURRENTLY PRESENTS — argument/command-line spoofing rewrites it after start (spawn suspended with benign arguments, let the PEB be logged, then patch), and the rewritten value is indistinguishable from an honest one in this artifact alone",
        "An unreadable command line is a READ FAILURE, not an empty invocation: vol3 renders a swapped-out page, an exited process or an incomplete memory layer as UnreadableValue, and a process with no user-mode PEB yields nothing by construction — none of those states means the program ran without arguments",
        "Agreement with 4688 or Sysmon EID 1 is corroboration only up to the moment the PEB was patched; a spoof applied after the creation event was written reproduces exactly that agreement, so matching logs raise confidence without settling it",
        "Absence of a command line in the event log is a policy fact, not an anti-forensic one: Microsoft documents 'Include command line in process creation events' as Not Configured by default, so on a default host 4688 never carried the command line to begin with",
        "The Process column is still the truncated fixed-width kernel name; use the recovered command line and image_path_name for identity, and compare against the kernel-resident SeAuditProcessCreationInfo.ImageFileName before naming a program",
        "Command lines routinely contain credentials, tokens and keys passed as arguments — Microsoft warns of exactly this for the 4688 policy; handle the extracted text as sensitive material",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "The process parameters block lives in pageable user-mode memory; lost on power-off and reclaimed when the process exits and its address space is torn down",
};

// ── Unlinked / hidden modules — PEB list vs VAD cross-view (ldrmodules) ──────

/// Field schema for the PEB-list-vs-VAD module cross-view.
///
/// The three booleans are membership tests, one per `_PEB_LDR_DATA` list, keyed
/// on `DllBase`; `base` and `mapped_path` come from the VAD side of the
/// comparison. None of them is a verdict on its own — see the descriptor's
/// caveats for the states that produce a legitimate `false`.
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/ldrmodules.py>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data>
pub(crate) static MEM_HIDDEN_MODULES_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pid",
        value_type: ValueType::UnsignedInt,
        description: "Owning process identifier (_EPROCESS UniqueProcessId; ldrmodules Pid column)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process",
        value_type: ValueType::Text,
        description: "Owning process image name from the kernel's fixed-width _EPROCESS.ImageFileName copy (ldrmodules Process column) — a truncated prefix, not an identity",
        is_uid_component: false,
    },
    FieldSchema {
        name: "base",
        value_type: ValueType::UnsignedInt,
        description: "Base virtual address of the mapped image (ldrmodules Base column) — the VAD start address, which is also the key each PEB list is searched on (LDR_DATA_TABLE_ENTRY.DllBase). The row exists because this VAD begins with an MZ DOS header (_IMAGE_DOS_HEADER.e_magic == 0x5A4D); VADs that do not are skipped before any list is consulted",
        is_uid_component: true,
    },
    FieldSchema {
        name: "in_load",
        value_type: ValueType::Bool,
        description: "Membership in _PEB_LDR_DATA.InLoadOrderModuleList — the loader's load-order list. The process EXE, ntdll and every normally-loaded DLL appear here, so a false is the strongest of the three: it means the loader has no load-order record of an image that is nevertheless mapped and MZ-headed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_init",
        value_type: ValueType::Bool,
        description: "Membership in _PEB_LDR_DATA.InInitializationOrderModuleList. EXPECT A LEGITIMATE FALSE FOR THE MAIN EXECUTABLE: at process start the loader links the image's entry through the routine that inserts into the load-order and memory-order lists ONLY, and an entry reaches the initialisation-order list when it goes through DLL initialisation (ntdll is linked in explicitly). A DLL captured mid-load shows the same false for the same reason — it is inserted into the other two lists first",
        is_uid_component: false,
    },
    FieldSchema {
        name: "in_mem",
        value_type: ValueType::Bool,
        description: "Membership in _PEB_LDR_DATA.InMemoryOrderModuleList — the one list of the three Microsoft documents publicly. Populated from the same routine as the load-order list, so in_load and in_mem normally agree; a disagreement between them is itself worth reading as list tampering rather than as a loader state",
        is_uid_component: false,
    },
    FieldSchema {
        name: "mapped_path",
        value_type: ValueType::Text,
        description: "File name recorded on the VAD for this mapping (ldrmodules MappedPath column). It names the FILE the section was created from, never what the bytes in the region are now — a stomped or hollowed module keeps its original path. Empty for a mapping the VAD has no file object for, which is the normal state for manually mapped images",
        is_uid_component: false,
    },
];

/// Unlinked / hidden modules — PEB module lists versus the VAD tree.
///
/// `windows.ldrmodules` builds the cross-view from both sides. From the VAD
/// side it walks each process' VAD tree and keeps only regions that begin with
/// an `MZ` DOS header (`_IMAGE_DOS_HEADER.e_magic == 0x5A4D`) — a mapped image,
/// whoever mapped it. From the PEB side it builds three dictionaries keyed on
/// `LDR_DATA_TABLE_ENTRY.DllBase`, one per `_PEB_LDR_DATA` list:
/// `InLoadOrderModuleList`, `InInitializationOrderModuleList`, and
/// `InMemoryOrderModuleList`. Each mapped base is then looked up in all three,
/// and the row (Pid, Process, Base, InLoad, InInit, InMem, MappedPath) records
/// which lists own it. A mapping present in the VAD but missing from some or all
/// of the lists is consistent with DLL unlinking (the entry was spliced out of
/// the doubly-linked lists after load) or with reflective / manual mapping (the
/// image was placed without the loader, so it was never listed at all).
///
/// The false positives are structural and must be applied before the finding.
/// The main executable is legitimately absent from
/// `InInitializationOrderModuleList`: at process start the loader inserts the
/// image entry through the routine that links the load-order and memory-order
/// lists only, while the initialisation-order list is populated for modules that
/// go through DLL initialisation (ntdll being linked in explicitly). A DLL
/// caught mid-load produces the same shape for the same reason. And because the
/// lists record loader activity, ANY image placed by a section mapping rather
/// than by the loader is absent from all three by construction, whether the
/// placer was malicious or not. The blind spot runs the other way too: the VAD
/// side keeps only regions that still carry an `MZ` header, so an image whose
/// DOS header has been zeroed — routine in manual mapping — produces no row at
/// all. Absence from a list is a lead; absence of a row is not absence of a
/// hidden module.
///
/// Source: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/ldrmodules.py>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data>
/// Source: <https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrutils.c>
/// Source: <https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrinit.c>
pub(crate) static MEM_HIDDEN_MODULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "mem_hidden_modules",
    name: "Unlinked / Hidden Modules (Memory PEB-vs-VAD Cross-View)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Mapped PE images in a process compared against the loader's own record of them. \
windows.ldrmodules walks the VAD tree, keeps every region whose first bytes are an MZ DOS header \
(_IMAGE_DOS_HEADER.e_magic == 0x5A4D), and looks each base up — by LDR_DATA_TABLE_ENTRY.DllBase — \
in the three _PEB_LDR_DATA lists: InLoadOrderModuleList, InInitializationOrderModuleList and \
InMemoryOrderModuleList. The emitted row is Pid, Process, Base, InLoad, InInit, InMem, MappedPath. \
An image the VAD shows as mapped but that some or all of the lists do not own is consistent with \
DLL unlinking (the LDR entry spliced out of the doubly-linked lists after load, so API-based module \
enumeration no longer sees it) or with reflective / manual mapping (the image placed without the \
loader, so it was never listed at all). The lists and the VAD answer different questions, which is \
why the comparison works: the VAD is the memory manager's record of what is mapped, the PEB lists \
are the loader's record of what it loaded, and only the second is a user-mode data structure an \
attacker can edit. \
THE FALSE POSITIVES ARE STRUCTURAL AND COME FIRST. The MAIN EXECUTABLE is legitimately absent from \
InInitializationOrderModuleList: at process start the loader inserts the image's entry via the \
routine that links the load-order and memory-order lists only, and entries reach the \
initialisation-order list through DLL initialisation (ntdll is linked into it explicitly) — so \
InInit = false on the process EXE is the expected state, not an anomaly. A DLL captured mid-load \
shows the same pattern, because insertion into the other two lists happens first. Any image placed \
by a SECTION MAPPING rather than by the loader — benign or not — is absent from all three lists by \
construction, since the lists record loader activity and nothing else. And the cross-view has a \
blind spot in the opposite direction: only VADs that still begin with MZ are examined, so an image \
whose DOS header has been zeroed or overwritten (an ordinary step in manual mapping) yields NO ROW, \
and absence of a row is not absence of a hidden module. MappedPath names the file the section came \
from, not what the bytes are now, so a stomped module still reports its original path. Absence from \
a list is a lead to be corroborated — dump the region and compare it against the named file, check \
whether anything executes there, and read it beside mem_process_injection (the VAD/PTE view of the \
same region), mem_loaded_modules (the list-based view this artifact refutes), mem_extracted_pe_images \
(the recovered bytes) and mem_findevil (which flags the same unbacked-executable condition from \
another tool's rule set).",
    mitre_techniques: &[
        "T1055.001", // Process Injection: Dynamic-link Library Injection
        "T1055.012", // Process Injection: Process Hollowing
        "T1620",     // Reflective Code Loading
        "T1564",     // Hide Artifacts (module unlinking)
    ],
    fields: MEM_HIDDEN_MODULES_FIELDS,
    retention: Some("RAM only; lost on power-off. Also recoverable from hiberfil.sys / crash dumps"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "mem_loaded_modules",
        "mem_process_injection",
        "mem_extracted_pe_images",
        "mem_findevil",
    ],
    sources: &[
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/ldrmodules.py (the three DllBase-keyed dictionaries built from load_order_modules(), init_order_modules() and mem_order_modules(); the MZ filter on VADs; Pid/Process/Base/InLoad/InInit/InMem/MappedPath columns)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/ldrmodules.py",
        // Source: https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/vadinfo.py (VadInfo.list_vads — the VAD side of the cross-view and the mapped file name)
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/vadinfo.py",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data (PEB_LDR_DATA and the LDR_DATA_TABLE_ENTRY entries the lists link; InMemoryOrderModuleList is the one member Microsoft documents)
        "https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb (PEB.Ldr — the pointer the three lists hang off)
        "https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb",
        // Source: https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrutils.c (LdrpInsertMemoryTableEntry inserts into InLoadOrderModuleList and InMemoryOrderModuleList ONLY; insertion into InInitializationOrderModuleList happens later, in the DLL load path)
        "https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrutils.c",
        // Source: https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrinit.c (LdrpInitializeProcess — the main image entry is inserted via LdrpInsertMemoryTableEntry, while ntdll is additionally linked into InInitializationOrderModuleList by hand; that asymmetry is why the process EXE is absent from the init-order list)
        "https://github.com/reactos/reactos/blob/master/dll/ntdll/ldr/ldrinit.c",
        // Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad (!vad — the _MMVAD tree that supplies the mapped-image side of the comparison)
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-vad",
        // Source: https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing (module stomping / DLL hollowing — a file-backed, correctly-listed module whose bytes no longer match the named file, i.e. the case this cross-view does not catch)
        "https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "The MAIN EXECUTABLE is legitimately absent from InInitializationOrderModuleList: the loader inserts the process image's entry through the routine that links only the load-order and memory-order lists, and the initialisation-order list is populated through DLL initialisation. InInit = false on the process EXE is the expected state and must not be reported as unlinking",
        "A module captured mid-load is legitimately absent from InInitializationOrderModuleList for the same reason — it enters the load-order and memory-order lists first — so a memory image taken during a load shows a transient, benign mismatch",
        "The PEB lists record LOADER activity, so any image placed by a section mapping rather than by the loader is absent from all three by construction whether or not it is malicious; absence from a list measures 'the loader did not load this', never 'this is malicious'",
        "The cross-view only examines VADs that still begin with an MZ header, so an image whose DOS header has been zeroed or overwritten — routine in manual mapping — produces no row at all: absence of a row is not absence of a hidden module",
        "MappedPath is the name of the file the section was created from, not a statement about the bytes now resident: a stomped or hollowed module reports its original, legitimate path, and this cross-view will not flag it because its LDR entry is intact",
        "All three booleans are read out of user-mode structures in the process' own address space, so a sufficiently thorough attacker can repair the lists as well as unlink from them; agreement across all three is weak evidence of legitimacy",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "PEB module lists and the VAD tree live in RAM; lost on power-off, and an unlinked entry survives only while the process does",
};
