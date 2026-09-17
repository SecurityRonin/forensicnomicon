//! Windows interprocess-communication descriptors — the named pipe as an
//! artifact class, and the registry value that bounds unauthenticated reach to
//! one.
//!
//! Named pipes were previously reachable in this catalog only incidentally: the
//! coercion pipes named inside an NTLM event descriptor, and a passing clause in
//! the PsExec entry. Neither gives an analyst the object itself. These two
//! descriptors do.
//!
//! Two properties make named pipes worth cataloguing as a class rather than as a
//! list of interesting names. First, the same object has two spellings — the NT
//! object-namespace form the kernel and a memory-image handle table use, and the
//! Win32 form a command line, a log line and a Sysmon event use — so a hunt
//! string written in one form returns zero against output printed in the other.
//! Second, the implementing driver is a file system (NPFS), so a pipe handle is a
//! File-typed object in a handle table rather than a distinct type: filtering a
//! handle listing by object type alone never isolates pipes, and the name prefix
//! is the working filter.
//!
//! `null_session_pipes` is the configuration half — the `REG_MULTI_SZ` list that,
//! together with its `RestrictNullSessAccess` gate, decides which pipes an
//! unauthenticated SMB client may open over the IPC$ tree. It survives in an
//! offline SYSTEM hive, so it answers what anonymous reach the host permitted at
//! the time of acquisition.
//!
//! Field descriptions are written from the Microsoft Win32 IPC documentation, the
//! filter-manager and Sysinternals references for the NPFS namespace, the
//! Microsoft Open Specifications for named pipes over SMB and RPC, the published
//! security-policy references for the null-session values, and the PowerShell
//! source that mints its host pipe name; no third-party prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── Named pipe object (NPFS namespace) ───────────────────────────────────────

/// Field schema for one named pipe recovered from a live system or a memory image.
///
/// The name/instance-count fields come from the NPFS directory listing, which is
/// what PipeList reads with `NtQueryDirectoryFile`; the owning-process and
/// handle-type fields come from a handle-table walk; `sysmon_pipe_event` is a
/// separate source — Sysmon's own telemetry, which records creation and
/// connection rather than present state.
///
/// The naming rules carried in the `pipe_name` description are Microsoft's, and
/// they matter for tool behaviour rather than for trivia: an unrestricted
/// character set means a pipe name may contain spaces, GUIDs or shell
/// metacharacters, and case-insensitivity means a case-sensitive grep over pipe
/// names can miss a match that the kernel would have resolved.
/// Source: <https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea>
/// Source: <https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist>
/// Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatenamedpipefile>
/// Source: <https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/remoting/common/RemoteSessionNamedPipe.cs>
pub(crate) static NAMED_PIPE_OBJECT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pipe_name",
        value_type: ValueType::Text,
        description: "The pipe's own name, as it appears under the NPFS root — the `PipeName` part, without any prefix. Microsoft's rules bound what may appear here: the entire pipe name string can be up to 256 characters, it may contain any character EXCEPT a backslash (numbers and special characters included), and pipe names are not case-sensitive. Two consequences for hunting: a case-sensitive match over this field can miss a name the kernel would have resolved, and because almost nothing is excluded, a name may carry spaces, a GUID, or an encoded payload",
        is_uid_component: true,
    },
    FieldSchema {
        name: "nt_object_path",
        value_type: ValueType::Text,
        description: "The same object written in the NT object namespace: \\Device\\NamedPipe\\<name>. Microsoft's own kernel documentation gives \"\\Device\\NamedPipe\\mypipe\" and \"\\??\\pipe\\mypipe\" as equally valid specifications for one pipe. Record BOTH this and `win32_path` — a hunt string written in one spelling returns zero against a tool that prints the other, and that zero reads as absence rather than as a malformed query",
        is_uid_component: false,
    },
    FieldSchema {
        name: "win32_path",
        value_type: ValueType::Text,
        description: "The same object in the Win32 form a command line, a script and most telemetry use: \\\\.\\pipe\\<name> locally, or \\\\<ServerName>\\pipe\\<name> against a remote host. The period is not optional cosmetics — Microsoft documents that a pipe server cannot create a pipe on another computer, so CreateNamedPipe must use a period, and a remote server name in this field therefore belongs to a CLIENT connection, never to the pipe's creation",
        is_uid_component: false,
    },
    FieldSchema {
        name: "owning_pid",
        value_type: ValueType::UnsignedInt,
        description: "PID of the process holding the server-side handle — the pipe server. Resolved by walking the process handle table, not from the pipe name; treat it as the attribution anchor and pivot to the process's image path and command line before reading anything into the name",
        is_uid_component: true,
    },
    FieldSchema {
        name: "owning_process",
        value_type: ValueType::Text,
        description: "Image name of the pipe server process. The pairing is what carries signal: a stock pipe name under an unexpected image, or a stock image serving a name it never serves on a known-good build of the same OS, is the discriminator — the name alone is attacker-chosen free text",
        is_uid_component: false,
    },
    FieldSchema {
        name: "handle_object_type",
        value_type: ValueType::Text,
        description: "Object type as a handle table reports it — for a named pipe this is `File`, NOT a distinct pipe type, because the driver implementing named pipes is a file system (NPFS.SYS) and its handles are file handles on the named-pipe volume. Filtering a handle listing by type alone therefore never isolates pipes; filter on the \\Device\\NamedPipe name prefix instead",
        is_uid_component: false,
    },
    FieldSchema {
        name: "max_instances",
        value_type: ValueType::Integer,
        description: "Maximum instance count fixed by the first CreateNamedPipe call, which every later instance must repeat. Microsoft bounds it to 1 through PIPE_UNLIMITED_INSTANCES (255), where the unlimited value means the count is capped only by system resources. A pipe created with FILE_FLAG_FIRST_PIPE_INSTANCE fails any second creation attempt with ERROR_ACCESS_DENIED — a squatting defence whose failure is what an attacker racing a known pipe name would hit",
        is_uid_component: false,
    },
    FieldSchema {
        name: "active_instances",
        value_type: ValueType::UnsignedInt,
        description: "Instances currently open. The NPFS directory listing carries both this and `max_instances`, which is why PipeList can report them without opening anything. Read it as concurrency at the instant of capture, not as a session count over time — an instance is always deleted when its last handle closes, so a finished conversation leaves nothing here",
        is_uid_component: false,
    },
    FieldSchema {
        name: "embedded_process_start_time",
        value_type: ValueType::Timestamp,
        description: "Process start time PARSED OUT OF the pipe name, where the implementation embeds one. PowerShell is the documented case: its host pipe is minted as PSHost.<start-time>.<PID>.<AppDomain>.<process name>, with the start time a FILETIME rendered in decimal, so the name alone dates the host process — and the PowerShell source states the start time is there specifically to stop another process guessing the name and squatting on it. Derived, so it is only as trustworthy as the creator: a name is free text and can be fabricated wholesale",
        is_uid_component: false,
    },
    FieldSchema {
        name: "embedded_process_id",
        value_type: ValueType::UnsignedInt,
        description: "PID parsed out of the pipe name (the PowerShell PSHost form carries it after the start time). Compare it against `owning_pid`: agreement corroborates that the name describes its own server, and a MISMATCH is the interesting result — a name that claims a process it does not belong to. On non-Windows PowerShell hosts the same field is built differently (an 8-character hex slice of the start time, under a CoreFxPipe_ prefix), so do not decode a Linux/macOS host pipe with the Windows rule",
        is_uid_component: false,
    },
    FieldSchema {
        name: "rpc_endpoint",
        value_type: ValueType::Text,
        description: "Set when the pipe is an RPC endpoint rather than a private channel. The Microsoft RPC extensions define ncacn_np as RPC directly over SMB with no intermediate protocol, where the endpoint MUST be a named pipe name and the endpoint mapper's well-known endpoint is \\pipe\\epmapper. All RPC PDUs travel as ordinary named-pipe writes and reads, so pipe traffic here is an RPC conversation and the interface — not the pipe — is what names the capability being invoked",
        is_uid_component: false,
    },
    FieldSchema {
        name: "sysmon_pipe_event",
        value_type: ValueType::Text,
        description: "SEPARATE SOURCE (not the live object): the Sysmon Operational log, where Event ID 17 records a named pipe being CREATED and Event ID 18 a client CONNECTING to one. This is the only routine way to see a pipe that has already closed, since the object itself is gone once its last handle is released. Absence proves nothing unless Sysmon was installed and its PipeEvent filter was configured to include the name",
        is_uid_component: false,
    },
];

/// Named pipe object — `\Device\NamedPipe\<name>` / `\\.\pipe\<name>`.
///
/// A named pipe is a named, one-way or duplex channel between a pipe server and
/// one or more clients; any process can open one subject to security checks, and
/// all instances of a pipe share one name while each instance has its own buffers
/// and handles. The driver that implements them is a file system — NPFS.SYS,
/// "Named Pipe File System" — which is why a pipe handle appears in a process
/// handle table as an object of type `File` and why the namespace can be listed as
/// a directory at all. Microsoft's kernel documentation treats
/// `\Device\NamedPipe\mypipe` and `\??\pipe\mypipe` as two valid specifications
/// for the same object, and the Win32 form is `\\.\pipe\<name>` locally or
/// `\\<ServerName>\pipe\<name>` remotely. Recording only one spelling is how a
/// true positive becomes a zero-result query.
///
/// Remote reach is not an optional extra: Microsoft states plainly that if the
/// Server service is running, ALL named pipes are accessible remotely, and
/// advises denying NT AUTHORITY\NETWORK or switching to local RPC for a pipe
/// intended to stay local. SMB clients reach pipe endpoints through the share
/// named IPC$, which accepts only named-pipe operations and DFS referrals. What
/// an UNAUTHENTICATED client can reach over that tree is bounded by the
/// `null_session_pipes` registry value and its gate.
///
/// The object is entirely volatile. Its buffers are allocated from nonpaged pool,
/// and an instance is always deleted when the last handle to it closes — so a
/// finished conversation leaves no object to find, and the durable trace is
/// Sysmon Event ID 17/18 or a memory image captured while it was open.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names>
/// Source: <https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/4de75e21-36fd-440a-859b-75accc74487c>
pub(crate) static NAMED_PIPE_OBJECT: ArtifactDescriptor = ArtifactDescriptor {
    id: "named_pipe_object",
    name: "Named Pipe Object (NPFS \\Device\\NamedPipe)",
    artifact_type: ArtifactLocation::MemoryRegion,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "A named pipe — the Windows interprocess-communication channel used for local \
control channels, for SMB-borne RPC, and by most remote-execution tooling. ONE OBJECT HAS TWO \
SPELLINGS: the NT object-namespace form \\Device\\NamedPipe\\<name> (Microsoft's own kernel \
documentation also accepts \\??\\pipe\\<name>) and the Win32 form \\\\.\\pipe\\<name>, or \
\\\\<ServerName>\\pipe\\<name> from a client against a remote host. Record both; a hunt string \
written in one form returns zero against output printed in the other, and that zero reads as \
absence rather than as a malformed query. The implementing driver is a file system (NPFS.SYS, \
\"Named Pipe File System\"), so a pipe handle appears in a process handle table as an object of \
type File, NOT as a distinct pipe type — filtering a handle listing by type alone never isolates \
pipes, and the \\Device\\NamedPipe name prefix is the working filter. Because NPFS is a file \
system, its root can be listed as a directory: that is how Sysinternals PipeList enumerates live \
pipes with NtQueryDirectoryFile (undocumented, and not reachable through the Win32 API), and the \
listing carries each pipe's maximum and active instance counts. Naming is nearly unconstrained — \
any character except a backslash, up to 256 characters for the whole pipe name string, \
case-insensitive — so a name may embed arbitrary state, and some implementations do: PowerShell \
mints its host pipe as PSHost.<process start time>.<PID>.<AppDomain>.<process name>, with the \
start time a decimal FILETIME, so the pipe name ALONE yields a process start time, a PID and an \
image name. REMOTE REACH IS THE DEFAULT: Microsoft states that if the Server service is running, \
all named pipes are accessible remotely, and SMB clients reach them through the IPC$ tree, which \
accepts only named-pipe operations and DFS referrals; RPC over SMB (ncacn_np) rides the same \
mechanism with \\pipe\\epmapper as its well-known endpoint mapper. Which pipes an UNAUTHENTICATED \
client may open is bounded by null_session_pipes. The object is volatile: buffers come from \
nonpaged pool and an instance is always deleted when its last handle closes, so a closed \
conversation leaves nothing to enumerate — the surviving trace is Sysmon Event ID 17 (pipe \
created) and 18 (pipe connected), or a memory image taken while the pipe was open. Cross-reference \
mem_handles_threads for the handle-table view and evtx_sysmon for the telemetry view.",
    mitre_techniques: &[
        "T1559",     // Inter-Process Communication
        "T1021.002", // Remote Services: SMB/Windows Admin Shares
    ],
    fields: NAMED_PIPE_OBJECT_FIELDS,
    retention: Some("RAM only; the instance is deleted when its last handle closes, and the whole namespace is gone at power-off — Sysmon Event ID 17/18 is the only routine durable record"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["mem_handles_threads", "evtx_sysmon", "null_session_pipes"],
    sources: &[
        // Named pipe definition, instances sharing one name, and the load-bearing remote-access
        // statement: if the Server service is running, all named pipes are accessible remotely.
        "https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes",
        // Naming rules: \\ServerName\pipe\PipeName, any character except a backslash, entire pipe
        // name string up to 256 characters, not case-sensitive, and the period-for-local rule.
        "https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names",
        // Instance lifetime ("an instance of a named pipe is always deleted when the last handle
        // to the instance is closed"), nonpaged-pool buffers, nMaxInstances 1..255,
        // FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS, and the default ACL that
        // grants read access to Everyone and the anonymous account.
        "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea",
        // NPFS.SYS is a file system driver; the pipe namespace can be listed as a directory using
        // NtQueryDirectoryFile (undocumented, not possible via the Win32 API); the listing reports
        // maximum and active instance counts per pipe.
        "https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist",
        // Kernel-side naming: "\Device\NamedPipe\mypipe" and "\??\pipe\mypipe" are both valid file
        // specifications for a pipe, and the named-pipe volume is obtained by passing
        // "\Device\NamedPipe" to FltGetVolumeFromName.
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatenamedpipefile",
        // MS-WPO: SMB clients access named pipe endpoints using the share named IPC$, which allows
        // only named-pipe operations and DFS referrals; the pipe name is the endpoint, as a port
        // number is for TCP.
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/4de75e21-36fd-440a-859b-75accc74487c",
        // MS-RPCE 2.1.1.2: ncacn_np is RPC directly over SMB with no intermediate protocol; the
        // endpoint MUST be a named pipe name; the endpoint mapper well-known endpoint is
        // \pipe\epmapper; PDUs are sent as named pipe writes and received as named pipe reads.
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/7063c7bd-b48b-42e7-9154-3c2ec4113c0d",
        // Sysmon Event ID 17 (PipeEvent, pipe created) and 18 (PipeEvent, pipe connected), and the
        // Operational channel they are written to.
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        // ImpersonateNamedPipeClient: a pipe server thread can assume the access token of the user
        // on the client end, reverting with RevertToSelf; a client can constrain the server's
        // impersonation level with SECURITY_SQOS_PRESENT on its CreateFile call.
        "https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client",
        // PowerShell mints its host pipe as PSHost.<process start time>.<PID>.<AppDomain>.<process
        // name>; the start time is included to stop another process guessing the name and squatting
        // on it; the non-Windows build uses a hex-sliced start time and a CoreFxPipe_ prefix.
        "https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/remoting/common/RemoteSessionNamedPipe.cs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "A pipe name is free text chosen by whoever created it — any character but a backslash, up to 256 characters, case-insensitive. It can impersonate a stock name exactly, so a name is a lead and the owning process is the attribution",
        "Named pipes are ordinary Windows plumbing: the operating system, RPC, printing, SQL Server and most endpoint agents all create them. Volume alone is meaningless; the discriminator is a name/owner pairing absent from a known-good build of the same OS and vendor stack",
        "A closed pipe leaves NO object. The instance is deleted when its last handle closes, so absence from a live listing or a memory image says nothing about what ran an hour earlier — that question is answerable only from Sysmon Event ID 17/18 or equivalent telemetry",
        "Filtering a handle table by object type does not find pipes: NPFS is a file system, so the type reads as `File`. A sweep that filtered on a pipe-specific type and returned nothing measured the filter, not the host",
        "A pipe name embedding process state is a convention of one implementation, not a guarantee. The PowerShell PSHost form yields a start time and PID, but both are attacker-supplied strings in any pipe an attacker created — compare the embedded PID against the handle's actual owner rather than trusting the name",
        "Impersonation makes the server side security-relevant, not just the channel: a pipe server thread can assume the access token of whoever connects. That is documented, ordinary behaviour used by legitimate services, so the presence of an impersonating server is not itself a finding",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Pipe buffers are allocated from nonpaged pool and the instance is deleted when its last handle closes; the namespace does not survive power-off",
};

// ── Anonymous (null-session) reach to named pipes ────────────────────────────

/// Field schema for one entry in the anonymously-accessible named-pipe list.
///
/// The value is a multi-string, so each decoded record is one pipe name. The
/// remaining fields are the context a single name cannot carry: whether the
/// gating `RestrictNullSessAccess` value is set (without it the list bounds
/// nothing), and whether the entry is one of the names Microsoft publishes as a
/// domain-controller default.
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously>
pub(crate) static NULL_SESSION_PIPES_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "pipe_name",
        value_type: ValueType::Text,
        description: "One multi-string entry — a pipe name an unauthenticated (null-session) SMB client is permitted to open over the IPC$ tree. Entries are bare names, not paths: the on-the-wire open is of \\pipe\\<name>, so match this field against the pipe's `pipe_name`, never against a \\\\.\\pipe\\ string. Microsoft's own reference table gives purposes for the legacy names — COMNAP and COMNODE (SNA Server), SQL\\QUERY (SQL Server's default pipe), SPOOLSS (Print Spooler), EPMAPPER (RPC endpoint mapper), LOCATOR (RPC Locator service), TrlWks and TrkSvr (Distributed Link Tracking client and server) — and states these were granted anonymous access in earlier Windows versions",
        is_uid_component: true,
    },
    FieldSchema {
        name: "is_dc_default",
        value_type: ValueType::Bool,
        description: "Is the entry one of the names Microsoft publishes as the domain-controller effective default — Netlogon, samr, lsarpc? On a DC those three are expected and their presence is not a finding. Anything OUTSIDE that set on a DC, or any entry at all on a member server or client (whose effective default is `not defined`), is the entry to read in full",
        is_uid_component: false,
    },
    FieldSchema {
        name: "restrict_null_sess_access",
        value_type: ValueType::Bool,
        description: "SEPARATE VALUE (the gate, not this list): `RestrictNullSessAccess` in the same key. Microsoft documents the restriction as taking effect by setting that value to 1, at which point null-session access is denied to all server pipes and shared folders EXCEPT those named in NullSessionPipes and NullSessionShares. Read the list only after reading the gate — with the gate off, an empty list restricts nothing and a populated one grants nothing extra, so the list on its own supports no conclusion about exposure",
        is_uid_component: false,
    },
    FieldSchema {
        name: "null_session_shares",
        value_type: ValueType::Text,
        description: "SEPARATE VALUE: the sibling `NullSessionShares` list, which does for shared folders what this value does for pipes. The same gate governs both, so an exposure assessment that reads one and not the other describes half the anonymous surface",
        is_uid_component: false,
    },
];

/// `NullSessionPipes` — named pipes reachable without authentication.
///
/// `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` holds a
/// multi-string value named `NullSessionPipes` listing the pipes an
/// unauthenticated SMB client may open. It is the registry form of the security
/// policy "Network access: Named Pipes that can be accessed anonymously", and it
/// is meaningful only in company with its gate: the sibling
/// `RestrictNullSessAccess`, set to 1, is what denies null-session access to
/// everything NOT named in `NullSessionPipes` and `NullSessionShares`.
///
/// The value matters because remote pipe access is the default rather than the
/// exception — Microsoft states that if the Server service is running, all named
/// pipes are accessible remotely, and SMB clients reach them through the IPC$
/// tree. This list is therefore the boundary between "reachable by an
/// authenticated principal" and "reachable by nobody in particular", which is the
/// distinction an analyst is usually trying to draw.
///
/// Microsoft publishes the effective defaults: `Netlogon, samr, lsarpc` on a
/// domain controller, and `not defined` on member servers and clients. One
/// historical adjustment is worth knowing before reading an old build's list as
/// deliberate: before Windows Server 2003 SP1 a hardcoded list (netlogon, lsarpc,
/// samr, browser, srvsvc, wkssvc) was combined with the registry value, and the
/// SP1 upgrade removed the hardcoded list, dropped trkwks, trksvr, epmapper and
/// locator from the registry value, added browser, and wrote
/// `AdjustedNullSessionPipes = 1` in the same key to record that it had done so.
///
/// Recoverable from an offline SYSTEM hive; read it beside `named_pipe_object`,
/// which is the pipe itself.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously>
pub(crate) static NULL_SESSION_PIPES: ArtifactDescriptor = ArtifactDescriptor {
    id: "null_session_pipes",
    name: "NullSessionPipes (Anonymously Accessible Named Pipes)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\LanmanServer\Parameters",
    value_name: Some("NullSessionPipes"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "The REG_MULTI_SZ list of named pipes an unauthenticated (null-session) SMB client is \
permitted to open on this host — the registry form of the security policy 'Network access: Named \
Pipes that can be accessed anonymously'. It bounds the anonymous half of a surface that is \
otherwise open by default: Microsoft states that if the Server service is running, all named pipes \
are accessible remotely, and SMB clients reach pipe endpoints through the share named IPC$, which \
accepts only named-pipe operations and DFS referrals. THE LIST IS INERT WITHOUT ITS GATE. The \
sibling value RestrictNullSessAccess, set to 1, is what restricts null-session access to \
unauthenticated users for all server pipes and shared folders EXCEPT those named in \
NullSessionPipes and NullSessionShares; with the gate absent or 0, neither an empty list nor a \
populated one supports a conclusion about exposure, so read both values or neither. Microsoft \
publishes the effective defaults — Netlogon, samr and lsarpc on a domain controller, 'not defined' \
on member servers and client computers — and separately documents the legacy names and their \
purposes: COMNAP and COMNODE (SNA Server), SQL\\QUERY (SQL Server's default pipe), SPOOLSS (Print \
Spooler), EPMAPPER (RPC endpoint mapper), LOCATOR (RPC Locator), TrlWks and TrkSvr (Distributed \
Link Tracking client and server), noting these were granted anonymous access in earlier Windows \
versions and that some legacy applications still use them. Entries are bare pipe names, so compare \
them against a pipe's own name and not against a \\\\.\\pipe\\ path. One historical adjustment \
prevents misreading an older host's list as deliberate: before Windows Server 2003 SP1 a hardcoded \
list (netlogon, lsarpc, samr, browser, srvsvc, wkssvc) was combined with this value; the SP1 \
upgrade removed the hardcoded list, dropped trkwks, trksvr, epmapper and locator from the value, \
added browser, and wrote AdjustedNullSessionPipes = 1 in the same key to record the migration. \
Recoverable from an offline SYSTEM hive. Cross-reference named_pipe_object for the pipe itself.",
    mitre_techniques: &[
        "T1021.002", // Remote Services: SMB/Windows Admin Shares
    ],
    fields: NULL_SESSION_PIPES_FIELDS,
    retention: Some("Persistent registry value; changes take effect without a restart, so the value reflects the configuration at acquisition and carries no history of earlier lists"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "named_pipe_object",
        "smb_server_require_signing",
        "network_shares_server",
    ],
    sources: &[
        // Names the gate exactly: RestrictNullSessAccess = 1 under
        // HKLM\System\CurrentControlSet\Services\LanManServer\Parameters, and states that enabling
        // it restricts null-session access to everything except the pipes and folders listed in the
        // NullSessionPipes and NullSessionShares entries. Also the per-role default table.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
        // The list side of the policy: DC effective default "Netlogon, samr, lsarpc", stand-alone
        // server default "Null", member server and client "Not defined"; and the reference table of
        // legacy pipe names with their purposes (COMNAP, COMNODE, SQL\QUERY, SPOOLSS, EPMAPPER,
        // LOCATOR, TrlWks, TrkSvr) granted anonymous access in earlier Windows versions.
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously",
        // Microsoft engineering blog: the pre-Windows Server 2003 SP1 hardcoded list (netlogon,
        // lsarpc, samr, browser, srvsvc, wkssvc), its removal at SP1, the removal of trkwks/trksvr/
        // epmapper/locator and addition of browser in the registry value, and the
        // AdjustedNullSessionPipes = 1 marker written under the same key.
        "https://learn.microsoft.com/en-us/archive/blogs/spatdsg/fyi-changes-to-null-session-pipes-post-2k3-sp1",
        // Why the list matters at all: if the Server service is running, all named pipes are
        // accessible remotely.
        "https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes",
        // MS-WPO: SMB clients access named pipe endpoints using the named pipe share named "IPC$".
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/4de75e21-36fd-440a-859b-75accc74487c",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "The list without its gate supports no conclusion. RestrictNullSessAccess set to 1 is what makes the list exhaustive; absent or 0, reporting a short list as 'anonymous access restricted' inverts the actual state",
        "A populated list is configuration, not activity: it records what an anonymous client was PERMITTED to open, never that one did. Pair it with authentication and share-access telemetry before describing anything as anonymous access having occurred",
        "Netlogon, samr and lsarpc on a domain controller are Microsoft's own effective default — their presence there is expected, and treating them as a weakening finding manufactures one",
        "Entries added by the pre-SP1-to-SP1 migration are not administrator choices: that upgrade rewrote the value, removing trkwks, trksvr, epmapper and locator and adding browser, and left AdjustedNullSessionPipes = 1 behind. Check for that marker before reading an older host's list as intent",
        "The value carries no history. Changes take effect without a restart and overwrite in place, so an absent name is not evidence it was never listed — corroborate against a registry transaction log or a Volume Shadow Copy of the SYSTEM hive if the timeline matters",
        "This value governs unauthenticated reach only. A pipe missing from the list is still reachable remotely by any principal whose token satisfies the pipe's own security descriptor, and Microsoft notes the DEFAULT descriptor on a pipe created without explicit security attributes grants read access to Everyone and to the anonymous account",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value in the SYSTEM hive; persists until explicitly rewritten and survives reboot",
};
