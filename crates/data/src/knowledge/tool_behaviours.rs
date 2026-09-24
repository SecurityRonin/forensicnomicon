//! Static [`ToolBehaviour`] instances and the [`TOOL_BEHAVIOURS`] slice.
//!
//! Memory-forensics batch: how the tools an examiner actually runs depart
//! from the memory image they present — above all where they fail SILENTLY,
//! so that a missed artifact is indistinguishable from an absent one. Every
//! entry was verified by reading the tool's own source (all three tools are
//! open source; the code and the project's own release notes are the primary
//! sources cited).
//!
//! Each doc comment separates BUG from DESIGN LIMIT: a list-walking or
//! pool-scanning plugin missing what its method cannot see is the documented
//! consequence of the method, and filing it as a defect would mislead.
//!
//! Cross-platform examination-tool batch: the general-purpose readers an
//! examiner reaches for on any platform (SQLite, qpdf, poppler, praudit, ZIP
//! decoders, RIR whois). None of these is a forensic tool, and each one's
//! default behaviour is correct for its ordinary users and wrong for evidence.
//! Every entry was reproduced on the stated version with a positive control
//! (the same run shown to return the data when it is read correctly), and the
//! mechanism was read in the tool's own source or documentation.

use super::{ToolBehaviour, ToolBehaviourKind};
use forensicnomicon_core::evidence::EvidenceTier;

/// Volatility 2 `netscan`: silently shorter connection lists on Windows
/// builds newer than its frozen structure definitions.
///
/// # Verification
///
/// - `volatility/plugins/netscan.py`: `netscan` pool-scans for the
///   `tcpip.sys` pool tags (`TcpE`, `TcpL`, `UdpA`) and decodes candidates
///   against hard-coded vtypes; `_TCP_ENDPOINT.is_valid()` rejects any
///   candidate whose decoded fields fail sanity checks (state enum, owner
///   PID range) and the scan simply does not yield it — no diagnostic.
/// - `README.txt`: the project is archived ("See Volatility 3 for modern
///   investigations") and Windows support stops at "64-bit Windows 10
///   (including at least 10.0.19041)".
/// - Issue #763 (still open): on build 18363, netscan decoded UDP
///   addresses and ports incorrectly until `tcpip_vtypes.py` offsets were
///   hand-patched — public record that the structures move per build and
///   the plugin neither notices nor warns.
/// - Issue #29 (title of record): "Netscan no TCP Endpoints on Windows
///   8/2012" — the silent-zero-rows shape reported in the wild.
///
/// Design limit, not a bug: pool scanning requires per-build structure
/// definitions, and an archived tool's definitions stopped moving while
/// `tcpip.sys` did not.
pub static VOL2_NETSCAN_SILENT_GAPS: ToolBehaviour = ToolBehaviour {
    id: "vol2_netscan_silent_gaps",
    tool: "Volatility 2 netscan",
    version_range: Some("Volatility 2.x through 2.6.1 (final release; project archived)"),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "netscan pool-scans for tcpip.sys pool tags (TcpE, TcpL, UdpA) and decodes \
             candidates against per-build structure definitions (tcpip_vtypes.py) that \
             stopped being updated when the project was archived (declared support ends at \
             Windows 10 build 19041). When tcpip.sys structures move between builds — \
             publicly documented for build 18363, where UDP addresses and ports decoded \
             incorrectly until offsets were hand-patched (issue #763, never merged) — \
             candidates decode wrongly or fail the plugin's is_valid() sanity checks and are \
             dropped without any diagnostic: the scan completes cleanly with whatever subset \
             still decodes (issue #29 records the zero-TCP-endpoints shape). This is the \
             documented consequence of pool scanning with an archived tool's vtypes, not a \
             defect in the scan.",
    consequence: "The examiner reads the listing as the complete set of network endpoints in \
                  the image: an endpoint missing because its structure no longer decodes is \
                  indistinguishable from an endpoint that never existed, and a wrongly \
                  decoded address or port renders as confidently as a correct one — with no \
                  diagnostic in either case, on exactly the OS generations (recent Windows \
                  10/11) where the frozen definitions fit worst.",
    mitigation: "Use Volatility 3 windows.netscan / windows.netstat (symbol-table driven \
                 from Microsoft's debug symbols) on any post-2016 Windows image, and treat a \
                 Volatility 2 listing as a floor, never a census. If two tools disagree on \
                 row count, the disagreement is the finding to chase.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility/issues/363",
        "https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/netscan.py",
        "https://github.com/volatilityfoundation/volatility/blob/master/README.txt",
        "https://github.com/volatilityfoundation/volatility/issues/763",
        "https://github.com/volatilityfoundation/volatility/issues/29",
    ],
};

/// Volatility 3 on a bare `.vmem`: a missing `.vmsn`/`.vmss` downgrades to a
/// raw read with (at most) a log line, never a failure.
///
/// # Verification
///
/// - `volatility3/framework/layers/vmware.py`: `VmwareLayer.stack()` probes
///   for `<base>.vmss` then `<base>.vmsn`; when neither opens it returns
///   `None` — the VMware layer is simply not stacked and the `.vmem` falls
///   through to raw-image handling. The run continues and exits 0.
/// - Commit `310b6508db30` ("vmware: Add warning when no metadata file is
///   found for a vmem file", 2023-10-11): the user-visible warning's birth;
///   releases up to v2.5.0 (2023-09-27) predate it and record the miss only
///   at the VVVV debug log level.
/// - The sidecar carries the snapshot's region table (`regionsCount` /
///   `regionPPN` tags in `_read_header`) mapping file offsets to physical
///   pages; a bare `.vmem` is read without it.
pub static VOL3_VMWARE_VMEM_MISSING_METADATA: ToolBehaviour = ToolBehaviour {
    id: "vol3_vmware_vmem_missing_metadata",
    tool: "Volatility 3 (VMware .vmem ingestion)",
    version_range: Some(
        "Volatility 3 <=2.5.0: debug-level log only; since commit 310b6508 (2023-10-11): \
         console warning, still non-fatal. Verified at v2.28.2 (2026-09-17)",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "When a .vmem is analysed without its sidecar snapshot metadata (.vmss/.vmsn), \
             VmwareLayer.stack() declines and the file is processed as a raw flat image \
             instead. The run continues and exits 0. Through v2.5.0 the only trace was a \
             maximum-verbosity debug log; commit 310b6508db30 (2023-10-11) added a console \
             warning, but processing still proceeds. The sidecar is what carries the \
             snapshot's region table mapping file offsets to physical pages, so on VMs whose \
             .vmem is not a flat physical map the raw fallback places reads at wrong \
             physical addresses and downstream plugins silently return incomplete or wrong \
             results.",
    consequence: "Sparse or empty plugin output is read as 'this memory contains no such \
                  artifacts' when it means 'the address space was assembled without the \
                  snapshot's region map'. A negative finding is manufactured by a missing \
                  sidecar file, and on affected versions nothing on screen says so.",
    mitigation: "Always collect and co-locate the .vmsn/.vmss with the .vmem (same basename, \
                 same directory). Treat near-empty plugin output from a bare .vmem as an \
                 ingestion failure to re-run with metadata, not as a negative finding — and \
                 read the warnings before the rows.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/vmware.py",
        "https://github.com/volatilityfoundation/volatility3/commit/310b6508db30",
        "https://github.com/volatilityfoundation/volatility3/releases",
    ],
};

/// Volatility 3 `windows.malware.hollowprocesses`: heuristic coverage with
/// silent per-process check skips and smear-driven false positives.
///
/// # Verification (all read from `hollowprocesses.py`, develop branch)
///
/// - Three checks: PEB `ImageBaseAddress` vs `EPROCESS.SectionBaseAddress`;
///   a VAD must exist at the exe base with `PAGE_EXECUTE_WRITECOPY`
///   protection; DLL protection cross-checks.
/// - Silent miss: `_get_image_base()` returns `None` on
///   `InvalidAddressException` (paged-out or smeared PEB) and the
///   load-address check is then skipped for that process with no output.
/// - Own-source false-positive admission: the DLL-protection check is
///   deliberately narrowed because full checking "triggers too many FPs
///   from smear" (verbatim comment).
/// - The docstring's references (cysinfo "deceptive hollowing techniques")
///   document variants that keep PEB and VAD consistent — outside all three
///   checks by design.
pub static VOL3_HOLLOWPROCESSES_HEURISTIC_COVERAGE: ToolBehaviour = ToolBehaviour {
    id: "vol3_hollowprocesses_heuristic_coverage",
    tool: "Volatility 3 windows.malware.hollowprocesses",
    version_range: Some(
        "Volatility 3, plugin v1.0.0 (requires framework >=2.4.0), as of develop 2025",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "The plugin runs three heuristics (PEB image base vs kernel SectionBaseAddress; \
             VAD present at the exe base with PAGE_EXECUTE_WRITECOPY protection; DLL \
             protection checks). When the PEB is unreadable — paged out or smeared — \
             _get_image_base() returns None and the strongest check is silently skipped for \
             that process: no row, no note. Hollowing variants that keep the PEB and VAD \
             consistent fall outside all three checks. In the other direction, the source \
             itself narrows the DLL check because it 'triggers too many FPs from smear': \
             hits on smeared images are expected noise.",
    consequence: "An empty result is read as 'no process hollowing in this image', including \
                  for processes where the decisive check never ran; a hit on a smeared image \
                  is read as hollowing when it is acquisition artefact. Both directions \
                  mislead, and neither is signalled in the output.",
    mitigation: "Treat rows as leads and empty output as 'nothing detected by these three \
                 heuristics', never as clearance. Corroborate hits by comparing the mapped \
                 image against the file on disk, and re-check processes with unreadable PEBs \
                 by other means (VAD walk, psscan cross-reference), especially on images \
                 acquired from a running system (smear).",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/hollowprocesses.py",
    ],
};

/// Volatility 3 `windows.dumpfiles`: zero-filled gaps with no marker, and an
/// error string that is not the outcome.
///
/// # Verification (all read from `dumpfiles.py`, develop branch)
///
/// - `dump_file_producer()` iterates `get_available_pages()` and reads each
///   with `pad=True`: unreadable ranges inside a run are silently
///   zero-filled in the written file. Nothing in the output marks which
///   ranges are padding.
/// - On `InvalidAddressException` mid-loop the producer returns `None` and
///   the row renders the single string "Error dumping file" — the same
///   string used when nothing was cached at all. Pages read before the
///   failure were already written through the file handler (whether the
///   partial file persists depends on the front-end's handler).
///
/// Design limit, not a bug: the plugin reconstructs a file from whatever
/// cache pages are resident; it cannot dump what memory does not hold.
pub static VOL3_DUMPFILES_ZERO_FILL: ToolBehaviour = ToolBehaviour {
    id: "vol3_dumpfiles_zero_fill",
    tool: "Volatility 3 windows.dumpfiles",
    version_range: Some(
        "Volatility 3, plugin v1.0.0 (requires framework >=2.0.0), as of develop 2025",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::OutputHidesDetail,
    detail: "dumpfiles reconstructs files from cache-resident pages only. Each available \
             page is read with pad=True, so unreadable ranges are written as zeros with no \
             per-file record of which bytes are padding. The output string 'Error dumping \
             file' conflates two different outcomes — nothing cached, and failed partway \
             after pages were already written through the file handler — so the error line \
             is not the verdict on whether usable content was recovered. By design the \
             plugin can only dump what the cache held at acquisition time.",
    consequence: "A dumped file is hashed or diffed as if byte-identical to the on-disk \
                  original — the zero-filled gaps guarantee a hash mismatch that gets read \
                  as tampering or corruption. Symmetrically, an 'Error dumping file' row is \
                  read as 'nothing recovered' when partial content may exist.",
    mitigation: "Never full-file-hash-match a dumpfiles extraction against a disk file; \
                 compare per-region or via the disk artifact directly. After an error row, \
                 inspect what the file handler actually wrote before concluding nothing was \
                 recovered.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/dumpfiles.py",
    ],
};

/// MemProcFS FindEvil: the built-in Elastic YARA rules run only behind a
/// license-acceptance flag, and acceptance is sticky per machine.
///
/// # Verification
///
/// - `vmm/vmmdll_core.c`: `-license-accept-elastic-license-2.0` (and the
///   `-2-0` spelling) sets `fLicenseAcceptElasticV2`, which gates the
///   built-in Elastic rules; acceptance is also cached in per-user config
///   (`LicenseAcceptElasticLicense2.0`) and re-read on later forensic runs.
///   The flag IS listed in the usage text in the same file — a claim that
///   it is hidden from `-h` did not survive reading the source.
/// - `vmm/modules/m_fc_findevil.c`: FindEvil's `readme.txt` states the
///   Elastic License 2.0 must be accepted for the built-in rules.
/// - `README.md` changelog: built-in Elastic rules (from
///   elastic/protections-artifacts) introduced in v5.6.
pub static MEMPROCFS_FINDEVIL_ELASTIC_GATE: ToolBehaviour = ToolBehaviour {
    id: "memprocfs_findevil_elastic_gate",
    tool: "MemProcFS FindEvil",
    version_range: Some("MemProcFS >=5.6 (built-in Elastic YARA rules introduced)"),
    artifact_id: None,
    kind: ToolBehaviourKind::RequiresFlag,
    detail: "FindEvil's built-in YARA detections (largely Elastic Security's \
             protections-artifacts) execute only when the Elastic License 2.0 has been \
             accepted via -license-accept-elastic-license-2.0. Without it, FindEvil still \
             runs its non-YARA checks and produces normal-looking findevil.txt output. \
             Acceptance is additionally cached in per-user configuration, so the identical \
             command line yields YARA-inclusive results on a machine where the flag was once \
             passed and YARA-free results on a fresh one. The flag is documented in the \
             command-line usage text and in FindEvil's own readme.txt.",
    consequence: "A clean FindEvil result from a run without license acceptance is read as \
                  'FindEvil found nothing' when its highest-signal rule set never executed \
                  — and two examiners running the same command on different machines get \
                  different results without either invocation looking different.",
    mitigation: "Pass -license-accept-elastic-license-2.0 explicitly on every forensic run \
                 rather than relying on cached acceptance, and record in the case notes \
                 whether the Elastic rules were active for the run being reported.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/ufrisk/MemProcFS/blob/master/vmm/vmmdll_core.c",
        "https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/m_fc_findevil.c",
        "https://github.com/ufrisk/MemProcFS/blob/master/README.md",
    ],
};

/// Volatility 3 `windows.malfind`: a candidate generator whose hits include
/// routine benign allocations — a false-positive profile, not a detector.
///
/// # Verification (read from `malfind.py`, develop branch)
///
/// - The plugin's own docstring claims only ranges "that potentially
///   contain injected code": private+executable+committed memory matching
///   the kernel's `_injection_filter` criteria.
/// - The source carries explicit false-positive suppression:
///   `is_vad_empty()` exists (per its own docstring) to "ignore false
///   positives whose VAD flags match" but hold no data — the heuristic
///   over-triggers by construction and the authors say so in code.
/// - Legitimate JIT runtimes (.NET, script engines) allocate private
///   executable memory as normal operation; such regions satisfy the filter.
pub static VOL3_MALFIND_FP_PROFILE: ToolBehaviour = ToolBehaviour {
    id: "vol3_malfind_fp_profile",
    tool: "Volatility 3 windows.malfind",
    version_range: Some(
        "All versions (the heuristic is the plugin's design); plugin v1.1.0, framework \
         >=2.22.0, as of develop 2025",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::FalsePositiveProne,
    detail: "malfind lists process memory ranges that are private, committed and executable \
             — the same VAD characteristics the kernel's injection filter describes. That \
             filter matches legitimate just-in-time compilation and runtime code generation \
             as readily as injection, and the plugin's source acknowledges the over-trigger: \
             is_vad_empty() exists specifically to suppress 'false positives whose VAD flags \
             match' but contain no data. Hits on well-known benign processes are expected \
             output of the heuristic, not detections.",
    consequence: "Each malfind row is reported as evidence of code injection, when the \
                  listing is a candidate set in which benign JIT and runtime allocations \
                  routinely appear. An examiner who baselines on a quiet image once will \
                  recognise the regulars; one who does not will paper a report with \
                  'injections' that are the OS working normally.",
    mitigation: "Treat every hit as a lead: check the rendered hexdump/disassembly for a PE \
                 header or coherent code, compare against a known-good baseline of the same \
                 OS and application set, and corroborate with an independent detector before \
                 the word 'injection' enters a report.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malware/malfind.py",
    ],
};

/// `stat` prints no Birth time for an ext4 file whose crtime the filesystem
/// is holding perfectly well.
///
/// Verified against:
/// - kernel ext4 documentation, verbatim: "Neither crtime nor dtime are
///   accessible through the regular stat() interface, though debugfs will
///   report them". The field lives at `i_crtime`/`i_crtime_extra` in the
///   extra inode space, so a 128-byte inode has nowhere to store it at all.
/// - coreutils NEWS: `stat` gained `statx()` - and with it Birth - in 8.32
///   (2020-03-05). Older builds have no route to the field.
/// - statx(2) HISTORY: the syscall arrived in Linux 4.11 and glibc 2.28, so
///   the kernel and libc floors bind independently of the coreutils version.
/// - e2fsprogs `debugfs.c`: prints crtime, gated on the inode being large
///   enough to carry it.
pub static COREUTILS_STAT_EXT4_BIRTH_BLANK: ToolBehaviour = ToolBehaviour {
    id: "coreutils_stat_ext4_birth_blank",
    tool: "GNU coreutils stat (ext4 crtime)",
    version_range: Some(
        "Blank on coreutils <8.32, Linux <4.11 or glibc <2.28; also blank on any \
         128-byte-inode ext4 filesystem regardless of tool version",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyDropsField,
    detail: "ext4 stores a creation time (crtime) in the extra inode space, but the \
             stat() interface has never exposed it; `stat` reads Birth through statx() \
             instead, which it only gained in coreutils 8.32, and which itself needs \
             Linux 4.11 and glibc 2.28. Where any of those floors is unmet the Birth \
             line renders empty - or as '-' - with no error and no indication that the \
             value exists on disk. `debugfs -R \"stat <inode>\"` reads the same field \
             from the same filesystem. Separately, an ext4 volume formatted with \
             128-byte inodes genuinely has no crtime, and that case is \
             indistinguishable from the tooling one by looking at `stat` alone.",
    consequence: "A blank Birth field is read as 'this filesystem does not record \
                  creation time' when it usually means 'this build of stat cannot ask \
                  for it'. An examiner then reports a creation time as unavailable, or \
                  - worse for the timestomping case - concludes that mtime cannot be \
                  compared against crtime, and abandons the one comparison that catches \
                  a touch-based stomp. Confirm with debugfs before recording the \
                  absence; only a 128-byte inode makes it a real absence.",
    mitigation: "Read the field with `debugfs -R \"stat <inode>\" /dev/<dev>` before \
                 recording a creation time as unavailable; it reports crtime out of the \
                 same inode stat() declines to expose. Check the three floors \
                 independently - coreutils >=8.32, Linux >=4.11, glibc >=2.28 - since any \
                 one of them blanks the field on its own. Only a 128-byte-inode \
                 filesystem, confirmed with `tune2fs -l`, makes the absence real.",
    evidence_tier: EvidenceTier::VendorDocumented,
    sources: &[
        "https://docs.kernel.org/filesystems/ext4/inodes.html",
        "https://git.savannah.gnu.org/cgit/coreutils.git/plain/NEWS",
        "https://man7.org/linux/man-pages/man2/statx.2.html",
        "https://github.com/tytso/e2fsprogs/blob/master/debugfs/debugfs.c",
    ],
};

/// The claim that malfind's benign hits are a KNOWN, NAMEABLE set.
///
/// Recorded rather than dropped. The false-positive mechanism is documented
/// and lives in `vol3_malfind_fp_profile`; what no source establishes is the
/// specific list of processes an examiner should expect to see and wave past.
///
/// WHERE THE SEARCH ALREADY WENT, so the next attempt can go somewhere new:
/// - Volatility 3 `malware/malfind.py`: no allowlist of any kind. The plugin
///   flags every committed private+executable VAD by construction, which is
///   precisely why it cannot name its own false positives.
/// - The Volatility 2 wiki's Command-Reference-Mal page: documents the
///   detection logic, names no benign processes.
/// - Published practitioner writeups: report that the benign hits are
///   "practically always the same" across images, and attribute them to JIT
///   and .NET runtimes allocating private executable memory legitimately -
///   but stop short of listing the processes.
///
/// So the SHAPE of the false positives is established (JIT-heavy and managed
/// runtimes) while the roster is folklore. Naming processes in a catalog on
/// that basis would hand an examiner a list to wave past - and an attacker a
/// list of names to borrow.
pub static MALFIND_BENIGN_PROCESS_NAMES: ToolBehaviour = ToolBehaviour {
    id: "malfind_benign_process_names",
    tool: "Volatility 3 windows.malfind (benign-hit roster)",
    version_range: Some("Claim examined against Volatility 3 v2.28.2 (2026-09-17)"),
    artifact_id: None,
    kind: ToolBehaviourKind::FalsePositiveProne,
    detail: "UNVERIFIED LEAD, searched and not sourced. It is widely said that malfind's \
             benign hits are a stable, nameable set - Defender's engine, RuntimeBroker and \
             similar - such that an examiner can recognise and skip them. Searched: the \
             plugin's own source, which carries no allowlist and flags every committed \
             private+executable VAD by construction; the Volatility 2 wiki's malware \
             command reference, which documents the logic and names nothing; and published \
             practitioner writeups, which report the benign hits are 'practically always \
             the same' and attribute them to JIT and managed runtimes, without listing \
             them. The MECHANISM is established; the roster is not.",
    consequence: "Treating a remembered roster as authoritative invites two errors. An \
                  examiner may wave past a process because its name is on a list they half \
                  recall, when the list was never established - and an attacker who \
                  masquerades under one of those names inherits the same free pass. Build \
                  the expected set per environment from a known-clean baseline and diff \
                  against it; that is checkable, and a remembered list is not.",
    mitigation: "Baseline malfind output on a known-clean host of the same build and image \
                 the diff, rather than recalling names. For any individual hit, dump the \
                 full region rather than reading the 64-byte preview, and check whether it \
                 carries a PE header - private executable memory holding a PE is a far \
                 stronger signal than the RWX permission alone.",
    evidence_tier: EvidenceTier::SearchedNotFound,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/malfind.py",
        "https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal",
    ],
};

/// SQLite `immutable=1`: the write-ahead log is never opened, so rows
/// committed to the WAL but not yet checkpointed are invisible.
///
/// # Verification
///
/// - `src/pager.c`, `sqlite3PagerOpen()`: when the `immutable` URI boolean is
///   set the pager jumps to `act_like_temp_file`, which sets `tempFile = 1`;
///   `pagerOpenWalIfPresent()` begins `if( !pPager->tempFile )`, so the WAL
///   existence check is never made for an immutable database.
/// - sqlite.org/uri.html: `immutable=1` declares the file "held on read-only
///   media and cannot be modified", and SQLite "skips all file locking and
///   change detection". It says nothing about the WAL, which is why it reads
///   as the safe evidence-reading option.
/// - Reproduced (SQLite 3.50.4, Python 3.11): a copied db + `-wal` + `-shm`
///   trio holding 5 WAL-only rows returned 0 rows under `immutable=1` and 5
///   under `mode=ro` on the same copy (the positive control).
/// - Field observation, reported by the examiner who ran it and not re-run
///   for this entry: on one real macOS Big Sur image, 168 of 207 databases
///   with a non-empty WAL gave different row counts with and without the WAL
///   applied, including a Notes store (3 more note bodies with the WAL) and a
///   keychain trusted-peer store (0 peers without, 5 with).
///
/// Design, not a bug: an immutable file is by definition one nobody is
/// writing, and SQLite reads it as such. The error is using it on a database
/// that was live when imaged. Supersedes an earlier note that recommended
/// `immutable=1` as the safe read pattern with no stated limit.
pub static SQLITE_IMMUTABLE_URI_IGNORES_WAL: ToolBehaviour = ToolBehaviour {
    id: "sqlite_immutable_uri_ignores_wal",
    tool: "SQLite (immutable=1 URI parameter; any binding: sqlite3 CLI, Python sqlite3)",
    version_range: Some(
        "Reproduced on SQLite 3.50.4; the WAL skip is in pager.c on master as of 2026-09. \
         The immutable parameter was added in 3.8.5 (2014-06-04)",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "Opening a database with the URI parameter immutable=1 makes the pager treat \
             it like a temporary file (pager.c: immutable -> act_like_temp_file -> \
             tempFile = 1), and pagerOpenWalIfPresent() only looks for a -wal file when \
             tempFile is 0. The WAL is therefore never read: every transaction committed \
             to the WAL but not yet checkpointed into the main file is invisible, and the \
             query succeeds with no warning. On a copy of a live database this is common, \
             not rare - WAL-mode stores checkpoint only at about 1000 pages or when the \
             last connection closes, and a device imaged while running rarely got that \
             close. SQLite's own documentation of immutable=1 speaks of read-only media \
             and skipped locking, and does not mention the WAL.",
    consequence: "Recent rows - the newest messages, notes, history entries, keychain \
                  records - are reported as absent when they are sitting in the -wal file \
                  beside the database. Because immutable=1 looks like the most \
                  evidence-preserving option available, the loss is chosen deliberately \
                  and then trusted: a negative ('no such record') and a count ('N rows') \
                  are both understated with nothing on screen to say so.",
    mitigation: "Copy the database together with its -wal and -shm files (same basename, \
                 same directory) to scratch storage, and open the copy normally or with \
                 mode=ro - never the original, because the last connection to close \
                 checkpoints and deletes the WAL. Where the uncommitted state matters, \
                 report both views: main-file-only and WAL-applied row counts, per table.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/sqlite/sqlite/blob/master/src/pager.c",
        "https://www.sqlite.org/uri.html",
        "https://www.sqlite.org/wal.html",
    ],
};

/// A SQLite database copied without its `-wal` (and `-shm`) is the
/// checkpointed state only; the newest committed rows stay behind.
///
/// # Verification
///
/// - sqlite.org/wal.html: in WAL mode changes are appended to the separate
///   WAL file and moved into the database only at a checkpoint (by default at
///   about 1000 pages, or when the last connection closes); "When the last
///   connection to a database closes, that connection does one last
///   checkpoint and then deletes the WAL and its associated shared-memory
///   file".
/// - Reproduced (SQLite 3.50.4): the main file copied alone returned 0 of 5
///   committed rows under `mode=ro`; the same main file copied with its
///   `-wal` and `-shm` returned all 5 (the positive control).
///
/// Design, not a bug: the WAL is part of the database while the database is
/// in WAL mode. The failure is in the collection step, which is why the
/// consequence belongs to every tool that opens the copy.
pub static SQLITE_MAIN_FILE_ONLY_COPY_DROPS_WAL: ToolBehaviour = ToolBehaviour {
    id: "sqlite_main_file_only_copy_drops_wal",
    tool: "SQLite (any reader of a copied main database file)",
    version_range: Some("All WAL-capable versions (3.7.0 onward); reproduced on SQLite 3.50.4"),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "In WAL mode a commit is written to <db>-wal and reaches the main file only \
             at a checkpoint. Copying or exporting only <db> - a file-by-file extraction \
             that selects by name or extension, a manual cp of the .db/.sqlite file, an \
             artifact collector that knows only the main path - produces a database that \
             opens cleanly and contains only the last checkpointed state. SQLite has no \
             way to know a WAL existed, so no reader can warn. Opening the ORIGINAL with \
             write access to 'apply' the WAL is not a fix: the last connection to close \
             runs a checkpoint and deletes the WAL and -shm, altering the evidence.",
    consequence: "Rows committed after the last checkpoint are reported as never having \
                  existed, and two examiners reading the 'same' database get different \
                  counts depending on whether their extraction carried the sidecars. \
                  Anyone who then opens the original to reconcile the difference may \
                  checkpoint it and destroy the WAL they needed.",
    mitigation: "Collect <db>, <db>-wal and <db>-shm together, hash all three, and open \
                 only a scratch copy of the trio. Never open the original read-write: \
                 closing it checkpoints and deletes the WAL. When given an extraction, \
                 check whether the sidecars came with it before relying on any count or \
                 negative, and state which state (checkpointed or WAL-applied) a finding \
                 was read from.",
    evidence_tier: EvidenceTier::VendorDocumented,
    sources: &["https://www.sqlite.org/wal.html"],
};

/// Opening a SQLite path that does not exist creates an empty database, so a
/// typo reads as "no such table" instead of "no such file".
///
/// # Verification
///
/// - sqlite.org/c3ref/open.html: the default flags for `sqlite3_open()` are
///   `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE`.
/// - sqlite.org/uri.html: `mode=ro` opens read-only (`mode=rwc` is the
///   create-if-missing mode).
/// - Python `sqlite3` documentation: `mode=rw` on a missing file raises
///   `OperationalError: unable to open database file` instead of creating it.
/// - Reproduced (SQLite 3.50.4, Python 3.11): `sqlite3.connect("missing.db")`
///   then `SELECT * FROM t` raised `no such table: t` and left a new empty file
///   with 0 schema rows; `file:missing2.db?mode=ro` raised `unable to open
///   database file` and created nothing.
pub static SQLITE_OPEN_MISSING_PATH_CREATES_EMPTY_DB: ToolBehaviour = ToolBehaviour {
    id: "sqlite_open_missing_path_creates_empty_db",
    tool: "SQLite default open (sqlite3 CLI, Python sqlite3.connect and other bindings)",
    version_range: Some(
        "All versions using the default SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE flags; \
         reproduced on SQLite 3.50.4 via Python 3.11",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "The default open mode is read-write-create. A path that does not exist - a \
             mistyped mount point, a copy that failed with its error discarded, a \
             database that is absent on this image - is created as a new, empty \
             database, and the open succeeds. The first query then fails with 'no such \
             table', or a query against sqlite_master returns zero rows, both of which \
             read as facts about the evidence's schema. The stray empty file is also \
             left behind, where a later run can find it.",
    consequence: "A missing or mis-addressed database is reported as present-but-empty or \
                  as a schema change between versions ('no such table' reads like an app \
                  that never used that table), and a negative finding is written about \
                  evidence that was never opened.",
    mitigation: "Open evidence databases with a URI and mode=ro (for example \
                 file:/path/db?mode=ro with uri=True), which refuses a missing file with \
                 'unable to open database file'. Assert the path exists and is non-empty \
                 before opening, and never discard the stderr of the copy step that \
                 produced it.",
    evidence_tier: EvidenceTier::VendorDocumented,
    sources: &[
        "https://www.sqlite.org/c3ref/open.html",
        "https://www.sqlite.org/uri.html",
        "https://docs.python.org/3/library/sqlite3.html",
    ],
};

/// qpdf `--show-encryption` prints `User password = ` blank for a PDF whose
/// open password it simply does not know.
///
/// # Verification
///
/// - `libqpdf/QPDFJob.cc`: on a password exception with `--show-encryption`
///   set, `createQPDF()` logs "Incorrect password supplied" and still calls
///   `showEncryption()`, which prints `"User password = " <<
///   getTrimmedUserPassword()` - empty when nothing was recovered - and prints
///   "Supplied password is user password" only when the supplied password
///   matched.
/// - qpdf manual (cli.html): `--show-encryption` "also shows the document's
///   user password if the owner password is given"; `--requires-password`
///   exits 0 when a password is required, 3 when encrypted but openable
///   without one, 2 when not encrypted.
/// - Reproduced (qpdf 12.4.1, pikepdf-made R=4 files): with a real user
///   password, output began "Incorrect password supplied" then "User password
///   = " (blank), exit 0, all on stdout; with an owner-only file the blank line
///   was followed by "Supplied password is user password". `--requires-password`
///   exited 0 and 3 respectively, and 2 on an unencrypted control.
pub static QPDF_SHOW_ENCRYPTION_BLANK_USER_PASSWORD: ToolBehaviour = ToolBehaviour {
    id: "qpdf_show_encryption_blank_user_password",
    tool: "qpdf --show-encryption",
    version_range: Some("Reproduced on qpdf 12.4.1; logic read in QPDFJob.cc on main, 2026-09"),
    artifact_id: None,
    kind: ToolBehaviourKind::OutputHidesDetail,
    detail: "Run without a password on an encrypted PDF, qpdf --show-encryption prints \
             the line 'User password = ' with an empty value in two different \
             situations: when the file has NO open password (owner-password-only \
             restrictions), and when it HAS one that qpdf does not know. In the second \
             case the output is preceded by 'Incorrect password supplied'; in the first \
             it is followed by 'Supplied password is user password'. The field shows the \
             recovered value, not whether one exists, and the command exits 0 in both \
             cases.",
    consequence: "A file protected by a real open password is recorded as 'no user \
                  password' from the blank field, so the examiner reports it as readable \
                  (or its unreadability as a tool fault) instead of as locked evidence \
                  needing a password or a recovery attempt.",
    mitigation: "Read the discriminating line, not the field: 'Incorrect password \
                 supplied' means an open password exists and is unknown. For scripts, use \
                 qpdf --requires-password (exit 0 = password required, 3 = encrypted but \
                 openable, 2 = not encrypted), and confirm by attempting \
                 --password= --decrypt on a copy.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/qpdf/qpdf/blob/main/libqpdf/QPDFJob.cc",
        "https://qpdf.readthedocs.io/en/stable/cli.html",
    ],
};

/// poppler `pdftotext` on a user-password PDF writes nothing to stdout and
/// reports only on stderr and the exit status.
///
/// # Verification
///
/// - `utils/pdftotext.cc`: after `createPDFDoc(fileName, ownerPW, userPW)`,
///   `if (!doc->isOk()) { return 1; }` - before any output is opened.
/// - `utils/pdftotext.1`, EXIT CODES: "1 Error opening a PDF file".
/// - Reproduced (poppler 26.09.0): on a pikepdf-made R=4 file with a user
///   password, stdout was empty, stderr read "Command Line Error: Incorrect
///   password", exit 1, and with an output path no .txt file was created. The
///   same text in an unencrypted control and an owner-password-only file was
///   extracted normally. `file` described the locked file only as "PDF
///   document, version 1.6", with no mention of encryption.
///
/// The tool is loud; the silence is in any pipeline that reads only stdout,
/// which is the ordinary way a bulk text sweep is written. That is why the
/// kind is SilentlyIncomplete and not a tool bug.
pub static POPPLER_PDFTOTEXT_ENCRYPTED_PDF_EMPTY_STDOUT: ToolBehaviour = ToolBehaviour {
    id: "poppler_pdftotext_encrypted_pdf_empty_stdout",
    tool: "poppler pdftotext",
    version_range: Some("Reproduced on poppler 26.09.0; exit-code contract in pdftotext.1"),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "Given a PDF with an open (user) password and no -upw, pdftotext writes \
             nothing to stdout, prints 'Command Line Error: Incorrect password' to \
             stderr and exits 1; writing to a file, it creates no output file at all. \
             A bulk sweep that captures stdout (or globs the .txt outputs) and discards \
             stderr sees exactly what it would see for a PDF with no text layer: empty \
             text. `file` does not flag the encryption, so nothing earlier in a typical \
             pipeline distinguishes the two.",
    consequence: "A password-protected document is recorded as blank or image-only and \
                  drops out of every keyword search and review list, so the locked \
                  documents - often the ones someone chose to protect - are the ones a \
                  text sweep reports as containing nothing.",
    mitigation: "Check pdftotext's exit status and stderr for every file and count \
                 non-zero exits separately from empty text. Test encryption first with \
                 qpdf --requires-password or pdfinfo, list locked files as their own \
                 category, and only call a PDF blank when it opened cleanly and still \
                 yielded no text.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://gitlab.freedesktop.org/poppler/poppler/-/raw/master/utils/pdftotext.cc",
        "https://gitlab.freedesktop.org/poppler/poppler/-/raw/master/utils/pdftotext.1",
    ],
};

/// OpenBSM `praudit` prints audit-record user and group ids as names looked
/// up on the machine running praudit, and times in that machine's zone.
///
/// # Verification
///
/// - `libbsm/bsm_io.c`, `print_user()`: unless `AU_OFLAG_RAW` or
///   `AU_OFLAG_NORESOLVE` is set it calls `getpwuid(usr)` and prints the name
///   found, falling back to the number only when the lookup fails; group ids
///   are handled the same way. Timestamps go through `ctime_r()`, i.e. local
///   time with no zone printed.
/// - `bin/praudit/praudit.c`: `-n` sets `AU_OFLAG_NORESOLVE`. praudit(1): "-n
///   Do not convert user and group IDs to their names but leave in their
///   numeric forms."
/// - Reproduced (macOS praudit, 2026-09): a synthetic trail with a subject
///   token for uid 501 / gid 20 printed the analysis machine's own account and
///   group names by default and "501,501,20,501,20" with -n; the header time
///   rendered in the analysis host's zone, and as UTC under TZ=UTC.
pub static PRAUDIT_RESOLVES_IDS_ON_ANALYSIS_HOST: ToolBehaviour = ToolBehaviour {
    id: "praudit_resolves_ids_on_analysis_host",
    tool: "OpenBSM praudit (macOS, FreeBSD)",
    version_range: Some(
        "OpenBSM praudit on master as of 2026-09; reproduced with macOS praudit (where the \
         man page marks the tool deprecated)",
    ),
    artifact_id: Some("macos_openbsm_audit"),
    kind: ToolBehaviourKind::RequiresFlag,
    detail: "praudit renders the uid/gid fields of subject, process and attribute tokens \
             by calling getpwuid()/getgrgid() on the machine running praudit, printing \
             the name found there. For an audit trail copied off another system, uid 501 \
             is printed as whichever account holds 501 on the examiner's workstation, \
             and a number is printed only when the workstation has no such id. Record \
             times are printed through ctime_r() in the workstation's time zone with no \
             zone marker. Only -n (or -r) keeps the ids numeric.",
    consequence: "Audit events are attributed to account names that belong to the \
                  examiner's own machine - on macOS, where the first user is uid 501 on \
                  almost every system, the examiner's own username appears as the actor \
                  in someone else's audit trail - and event times silently shift by the \
                  offset between the analysis host and the evidence.",
    mitigation: "Always run praudit -n (for machine parsing, praudit -xn) under TZ=UTC, \
                 then resolve uids and gids against the EVIDENCE system's own account \
                 database (for macOS, the dslocal user records on the image) rather than \
                 the analysis host's.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/openbsm/openbsm/blob/master/libbsm/bsm_io.c",
        "https://github.com/openbsm/openbsm/blob/master/bin/praudit/praudit.c",
        "https://man.freebsd.org/cgi/man.cgi?query=praudit&sektion=1",
    ],
};

/// ZIP member names written in a legacy code page (GBK, Shift-JIS, ...)
/// without the UTF-8 flag decode as CP437 mojibake - differently in each tool.
///
/// # Verification
///
/// - PKWARE APPNOTE 6.3.10 §4.4.4: general-purpose bit 11 (EFS) set means the
///   file name "MUST be encoded using UTF-8"; Appendix D: without it the name
///   is in the original IBM PC code page (CP437).
/// - CPython `Lib/zipfile/__init__.py`: `filename.decode(self.metadata_encoding
///   or 'cp437')` when bit 11 is clear; the zipfile documentation adds the
///   `metadata_encoding` parameter in 3.11.
/// - Reproduced: a zip whose single member name was GBK-encoded with bit 11
///   clear listed under Python 3.11 zipfile as CP437 mojibake (a search for
///   the original characters returned no match), and as two further, different
///   garblings under macOS unzip and bsdtar; ZipFile(..., metadata_encoding=
///   "gbk") recovered the name. A Python-written zip with the same name set
///   bit 11 (0x800).
///
/// Spec-conformant, not a bug: CP437 is the specified default. The archiver
/// that wrote a local code page without saying so is the source; every reader
/// is then guessing.
pub static ZIP_LEGACY_CODEPAGE_MEMBER_NAMES_MISDECODED: ToolBehaviour = ToolBehaviour {
    id: "zip_legacy_codepage_member_names_misdecoded",
    tool: "ZIP readers (Python zipfile, Info-ZIP unzip, bsdtar/libarchive)",
    version_range: Some(
        "Python zipfile all versions (metadata_encoding override from 3.11); reproduced on \
         Python 3.11 and the macOS unzip/bsdtar of 2026-09",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::MisreadsStructure,
    detail: "A ZIP member name is UTF-8 only when general-purpose flag bit 11 (0x800) is \
             set; otherwise the specification says CP437. Archives made by tools on \
             systems with a legacy default code page (for example GBK or Shift-JIS \
             Windows locales) store names in that code page without setting bit 11, so \
             a conforming reader decodes them as CP437 and produces mojibake. Readers \
             disagree on the fallback: the same GBK name came out as three different \
             garblings in Python zipfile, unzip and bsdtar. The file content is intact; \
             only the names are wrong.",
    consequence: "A filename keyword search in the original script returns zero hits \
                  against an archive that contains exactly that file, and listings from \
                  two tools cannot be matched name-for-name, so a member looks missing \
                  from one of them. Reported names in a listing are not the names the \
                  user saw.",
    mitigation: "Read each member's flag bits before trusting its name. Where bit 11 is \
                 clear and names contain bytes >= 0x80, decode the raw name bytes with \
                 the likely source code page (Python: ZipFile(path, \
                 metadata_encoding='gbk'), or the -O option of Info-ZIP unzip builds that \
                 support it), record the encoding chosen, and keep the raw name bytes in \
                 the listing.",
    evidence_tier: EvidenceTier::VendorDocumented,
    sources: &[
        "https://pkwaredownloads.blob.core.windows.net/pem/APPNOTE.txt",
        "https://github.com/python/cpython/blob/main/Lib/zipfile/__init__.py",
        "https://docs.python.org/3/library/zipfile.html",
    ],
};

/// APNIC whois for an AS number returns the enclosing `as-block` and APNIC's
/// own administrative objects first, so the first `country:` line is often
/// not the ASN holder's.
///
/// # Verification
///
/// - APNIC whois object templates: `as-block` and `aut-num` both carry an
///   optional `country:` attribute, so a response holding both objects holds
///   two or more `country:` lines.
/// - Observed live (whois.apnic.net, 2026-09-24): for six of seven
///   Asia-Pacific ASNs queried, the response opened with the enclosing
///   `as-block` ("APNIC ASN block") and its APNIC administrative objects, and
///   the first `country:` line was AU; each `aut-num` object further down
///   carried the holder's own country. The seventh returned the `aut-num`
///   first. So the order depends on the record and cannot be assumed.
/// - RIPEstat as-overview returns the holder name from the registry directly.
pub static APNIC_WHOIS_FIRST_COUNTRY_IS_NOT_THE_ASN_HOLDER: ToolBehaviour = ToolBehaviour {
    id: "apnic_whois_first_country_is_not_the_asn_holder",
    tool: "whois (whois.apnic.net ASN queries)",
    version_range: Some("APNIC whois responses as observed 2026-09-24; response layout may change"),
    artifact_id: None,
    kind: ToolBehaviourKind::OutputHidesDetail,
    detail: "whois -h whois.apnic.net AS<n> often returns the enclosing as-block object \
             ('APNIC ASN block', 'further assigned by APNIC to APNIC members') and \
             APNIC's own contact objects before the aut-num object. Those carry APNIC's \
             country (AU), so the first country: line in the response is the registry's, \
             not the network holder's. Other responses start with the aut-num, so the \
             position of the right line is not fixed.",
    consequence: "A script or examiner taking the first country: line attributes an \
                  Asia-Pacific network to Australia, and an IP-attribution or \
                  jurisdiction finding is built on the registry's own address.",
    mitigation: "Parse the aut-num object explicitly (the block beginning 'aut-num:') and \
                 read its as-name, descr and country, or query RIPEstat as-overview for \
                 the holder. Record the query time: registration data changes, and it \
                 states who holds the number, not where traffic originated.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://www.apnic.net/manage-ip/using-whois/guide/as-block/",
        "https://www.apnic.net/manage-ip/using-whois/guide/aut-num/",
        "https://stat.ripe.net/docs/data-api/api-endpoints/as-overview",
    ],
};

/// Every registered tool behaviour. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static TOOL_BEHAVIOURS: &[ToolBehaviour] = &[
    VOL2_NETSCAN_SILENT_GAPS,
    VOL3_VMWARE_VMEM_MISSING_METADATA,
    VOL3_HOLLOWPROCESSES_HEURISTIC_COVERAGE,
    VOL3_DUMPFILES_ZERO_FILL,
    MEMPROCFS_FINDEVIL_ELASTIC_GATE,
    VOL3_MALFIND_FP_PROFILE,
    COREUTILS_STAT_EXT4_BIRTH_BLANK,
    MALFIND_BENIGN_PROCESS_NAMES,
    SQLITE_IMMUTABLE_URI_IGNORES_WAL,
    SQLITE_MAIN_FILE_ONLY_COPY_DROPS_WAL,
    SQLITE_OPEN_MISSING_PATH_CREATES_EMPTY_DB,
    QPDF_SHOW_ENCRYPTION_BLANK_USER_PASSWORD,
    POPPLER_PDFTOTEXT_ENCRYPTED_PDF_EMPTY_STDOUT,
    PRAUDIT_RESOLVES_IDS_ON_ANALYSIS_HOST,
    ZIP_LEGACY_CODEPAGE_MEMBER_NAMES_MISDECODED,
    APNIC_WHOIS_FIRST_COUNTRY_IS_NOT_THE_ASN_HOLDER,
];
