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
/// - Commit history of that file: the user-visible warning ("No metadata
///   file found alongside VMEM file…") was added 2023-10-11; releases up to
///   v2.5.0 (2023-09-27) predate it and record the miss only at the VVVV
///   debug log level.
pub static VOL3_VMWARE_VMEM_MISSING_METADATA: ToolBehaviour = ToolBehaviour {
    id: "vol3_vmware_vmem_missing_metadata",
    tool: "Volatility 3 (VMware .vmem ingestion)",
    version_range: Some(
        "Volatility 3 <=2.5.0: debug-level log only; later releases (warning added \
         2023-10-11): console warning, still non-fatal",
    ),
    artifact_id: None,
    kind: ToolBehaviourKind::SilentlyIncomplete,
    detail: "When a .vmem is analysed without its sidecar snapshot metadata (.vmss/.vmsn), \
             VmwareLayer.stack() declines and the file is processed as a raw flat image \
             instead. The run continues and exits 0. Through v2.5.0 the only trace was a \
             maximum-verbosity debug log; since the 2023-10-11 change a console warning is \
             printed, but processing still proceeds. On VMs whose .vmem is not a flat \
             physical map, the resulting address space is assembled without the snapshot's \
             region table, and plugins render their column headers with few or zero rows.",
    consequence: "Headers-plus-zero-rows is read as 'this memory contains no such artifacts' \
                  when it means 'the address space was assembled wrongly'. A negative \
                  finding is manufactured by the missing sidecar file, and (on affected \
                  versions) nothing on screen says so.",
    mitigation: "Always collect and co-locate the .vmsn/.vmss with the .vmem (same basename, \
                 same directory). Treat near-empty plugin output from a bare .vmem as an \
                 ingestion failure to re-run with metadata, not as a negative finding — and \
                 read the warnings before the rows.",
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    sources: &[
        "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/vmware.py",
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

/// Every registered tool behaviour. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static TOOL_BEHAVIOURS: &[ToolBehaviour] = &[
    VOL2_NETSCAN_SILENT_GAPS,
    VOL3_VMWARE_VMEM_MISSING_METADATA,
    VOL3_HOLLOWPROCESSES_HEURISTIC_COVERAGE,
    VOL3_DUMPFILES_ZERO_FILL,
    MEMPROCFS_FINDEVIL_ELASTIC_GATE,
    VOL3_MALFIND_FP_PROFILE,
];
