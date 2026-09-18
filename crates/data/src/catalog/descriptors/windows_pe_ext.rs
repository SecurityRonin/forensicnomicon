//! Windows PE/COFF header timestamp descriptor — the build stamp an executable
//! carries inside its own bytes.
//!
//! Every Windows executable and DLL stores a 32-bit `TimeDateStamp` in its COFF
//! file header. The path to it is fixed by the format: a 4-byte file offset at
//! 0x3c (written during linking) points at the PE signature — the letters P and
//! E followed by two NUL bytes — the COFF file header begins immediately after
//! that signature, and `TimeDateStamp` is 4 bytes into the header. So the field
//! sits at file offset `(value at 0x3c) + 8`.
//!
//! It is the one timestamp that travels WITH the file. Copying, moving,
//! downloading, archiving or restoring a binary rewrites the file system's
//! $STANDARD_INFORMATION times and leaves the header untouched, which makes the
//! stamp a timestomp cross-view that needs neither a second artifact nor a
//! journal: the comparison is between a file's own content and its own
//! directory entry. Three further date/time stamps sit elsewhere in the same
//! image (debug directory, export directory, resource directory), so a partial
//! forgery that rewrites only the COFF field leaves the others behind.
//!
//! The field is also a trap in the other direction. Reproducible-build
//! toolchains deliberately store something that is not a time — Microsoft's
//! specification documents IMAGE_DEBUG_TYPE_REPRO for exactly this — so a
//! value that looks wrong may be a correct, deliberate build artifact.
//!
//! Field descriptions are written from Microsoft's PE/COFF specification, the
//! ExifTool EXE tag reference, and the linker sources that show what a
//! deterministic build writes into the field. No third-party prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── PE COFF header TimeDateStamp (build stamp vs on-disk file times) ─────────

/// Field schema for the PE COFF `TimeDateStamp` and its cross-views.
///
/// The stored fields are the COFF header values and the three secondary
/// date/time stamps the format defines elsewhere in the same image. The
/// comparison flags (`stamp_disagreement`, `file_times_precede_stamp`) and
/// `deterministic_build` are DERIVED — nothing on disk records them.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
/// Source: <https://exiftool.org/TagNames/EXE.html>
pub(crate) static PE_COFF_TIMEDATESTAMP_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "image_path",
        value_type: ValueType::Text,
        description: "Path of the PE image the header was read from. Carry it, because the whole check is a comparison between THIS file's content and THIS file's directory entry — a stamp reported without the file it came from cannot be cross-viewed by anyone else",
        is_uid_component: true,
    },
    FieldSchema {
        name: "pe_signature_offset",
        value_type: ValueType::UnsignedInt,
        description: "The 4-byte value at file offset 0x3c, which the linker writes to locate the PE signature. The COFF file header starts 4 bytes past that signature, so TimeDateStamp is at file offset (this value + 8). Record it: a header read at a guessed offset is not evidence, and this is the number that makes the read reproducible",
        is_uid_component: false,
    },
    FieldSchema {
        name: "machine",
        value_type: ValueType::UnsignedInt,
        description: "COFF Machine field at header offset 0 — the target architecture (0x014c Intel 386 and compatibles, 0x8664 AMD64, 0xAA64 ARM64 little endian, among others). Read it as the parse anchor: a Machine value that is not a defined type means the offset chain from 0x3c landed somewhere other than a COFF header, and every field taken from that header is then meaningless",
        is_uid_component: false,
    },
    FieldSchema {
        name: "time_date_stamp",
        value_type: ValueType::Timestamp,
        description: "COFF TimeDateStamp at header offset 4, rendered as a UTC time. Microsoft defines it as the low 32 bits of the number of seconds since 00:00 1 January 1970 (a C run-time time_t value) indicating when the file was created — that is, the binary's own claim about when it was built. ExifTool surfaces the same field as the EXE group's TimeStamp tag, and Sysinternals sigcheck reports timestamp information for a file",
        is_uid_component: false,
    },
    FieldSchema {
        name: "time_date_stamp_raw",
        value_type: ValueType::UnsignedInt,
        description: "The stored 32-bit value exactly as it sits in the file, kept ALONGSIDE the rendered time because not every value is a time. The specification states that a stamp of 0 or 0xFFFFFFFF does not represent a real or meaningful date/time stamp, and a deterministic build stores hash bits in this field. A renderer that turns a raw 0 into '1970-01-01 00:00:00' manufactures a date the binary never claimed — report the raw value so the reader can tell the two apart",
        is_uid_component: false,
    },
    FieldSchema {
        name: "deterministic_build",
        value_type: ValueType::Bool,
        description: "DERIVED (not a stored flag): true when the image's debug directory carries an entry of type IMAGE_DEBUG_TYPE_REPRO (value 16, 'PE determinism or reproducibility'). Microsoft states that in such an image the date/time stamp fields are filled with part or all of the bits of a hash computed over the file's content and no longer represent when the file was produced. When this is true the stamp is not a build time at all, so every earlier/later comparison below must be abandoned rather than reported — check this field FIRST",
        is_uid_component: false,
    },
    FieldSchema {
        name: "debug_directory_timestamp",
        value_type: ValueType::Timestamp,
        description: "TimeDateStamp at offset 4 of a debug directory entry — the time and date the debug data was created. A second, independently written stamp in the same image, and the one most often left behind by a tool that edits only the COFF field",
        is_uid_component: false,
    },
    FieldSchema {
        name: "export_directory_timestamp",
        value_type: ValueType::Timestamp,
        description: "Time/Date Stamp at offset 4 of the export directory table — the time and date the export data was created. Present in DLLs and any image that exports symbols; a third stamp to compare against the COFF field",
        is_uid_component: false,
    },
    FieldSchema {
        name: "resource_directory_timestamp",
        value_type: ValueType::Timestamp,
        description: "Time/Date Stamp at offset 4 of a resource directory table — the time the resource compiler created the resource data. As with every stamp in this format, 0 or 0xFFFFFFFF is documented as not a real date, so only a non-zero value is a usable comparison partner",
        is_uid_component: false,
    },
    FieldSchema {
        name: "stamp_disagreement",
        value_type: ValueType::Bool,
        description: "DERIVED cross-view (not stored): true when the COFF TimeDateStamp disagrees with the debug, export or resource stamps that are present and non-zero in the same image. One build writes them all, so a COFF field edited in isolation surfaces here — the usual footprint of a tool that knows about the header stamp and nothing else. Not a verdict on its own: a deterministic build fills several stamp fields from the same hash, and a linker can be told to write a specific value",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_created",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION creation time of the file on this volume — the cross-view partner. Copying, extracting or downloading a binary sets this to the moment it landed here, so on a legitimately built and delivered executable it normally falls at or after the build stamp",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_modified",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION last-modification time of the file — the second comparison partner, and the value ShimCache records for an executable, which lets the same comparison be made for a binary that is no longer on disk",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_times_precede_stamp",
        value_type: ValueType::Bool,
        description: "DERIVED cross-view (not stored): true when a $SI time on the file is EARLIER than the image's own TimeDateStamp — the file claims to have reached this volume before it was compiled. No ordinary build-and-deliver sequence produces that ordering, which makes it the highest-signal state here, and it points at a back-dated $SI (see ntfs_timestomping_si_fn) rather than at the header. Establish that deterministic_build is false and the raw stamp is a real value before reading anything into it; a wrong host clock and a restore that preserved an old modification time produce the same ordering innocently",
        is_uid_component: false,
    },
    FieldSchema {
        name: "authenticode_state",
        value_type: ValueType::Text,
        description: "unsigned | signed_and_verifies | signed_and_fails — load-bearing, because the COFF TimeDateStamp lies INSIDE the Authenticode hashed region. The specification's exclusion ranges are the optional header CheckSum field, the Certificate Table directory entry with the certificates it points at, and the area past the end of the last section; the COFF header is not among them. Editing the stamp of a signed binary therefore breaks its signature, so signed_and_verifies anchors the value as the signer's, and signed_and_fails on a file whose stamp looks edited is the pair worth reporting together",
        is_uid_component: false,
    },
];

/// PE COFF header TimeDateStamp — the build stamp, cross-viewed against the
/// file's own on-disk timestamps.
///
/// The COFF file header of every PE image carries a 32-bit `TimeDateStamp` that
/// Microsoft defines as the low 32 bits of the seconds since 00:00 1 January
/// 1970, indicating when the file was created. Reaching it is deterministic:
/// read the 4-byte offset at 0x3c, skip the 4-byte PE signature it points at,
/// and the field is 4 bytes into the COFF header that follows.
///
/// Its forensic use is that it is *content*, not metadata. A file system
/// timestamp is rewritten by copying, extraction and restore; this stamp is
/// not. So an executable whose $STANDARD_INFORMATION times precede its own
/// build stamp is claiming to have arrived on the volume before it was built —
/// an ordering no ordinary build-and-deliver sequence produces, and one that
/// needs no second artifact and no journal to observe. The image carries three
/// further date/time stamps (debug directory, export directory, resource
/// directory), so a forgery limited to the COFF field is visible against them.
///
/// The check detects carelessness rather than proving competence. The field is
/// an ordinary writable header value, a linker can be told to write a specific
/// one, and a deterministic build stores hash bits there by design — so a
/// consistent, plausible-looking stamp is not exculpatory.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
/// Source: <https://exiftool.org/TagNames/EXE.html>
/// Source: <https://github.com/llvm/llvm-project/blob/main/lld/COFF/Options.td>
/// Source: <https://github.com/golang/go/blob/master/src/cmd/link/internal/ld/pe.go>
pub(crate) static PE_COFF_TIMEDATESTAMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "pe_coff_timedatestamp",
    name: "PE COFF Header TimeDateStamp (Build Stamp vs File Times)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"<any PE image: .exe, .dll, .sys, .ocx, .cpl, .scr>"),
    scope: DataScope::Mixed,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The build stamp a Windows executable carries inside its own bytes, and the cross-view \
it supports against the file's on-disk timestamps. Every PE image stores a 32-bit TimeDateStamp in \
its COFF file header, which Microsoft defines as the low 32 bits of the number of seconds since \
00:00 1 January 1970 (a C run-time time_t value) indicating when the file was created. The path to \
it is fixed by the format: a 4-byte offset at file offset 0x3c locates the PE signature (the \
letters P and E followed by two NUL bytes), the COFF file header begins immediately after it, and \
TimeDateStamp is 4 bytes into that header — file offset (value at 0x3c) + 8. Machine sits at header \
offset 0 and is the parse anchor: an undefined Machine value means the offset chain landed \
somewhere other than a COFF header. THE FORENSIC POINT IS THAT THIS STAMP IS CONTENT, NOT METADATA. \
Copying, extracting, downloading or restoring a binary rewrites its $STANDARD_INFORMATION times and \
leaves the header alone, so an executable whose $SI creation or modification time PRECEDES its own \
build stamp is claiming to have reached the volume before it was compiled — an ordering no ordinary \
build-and-deliver sequence produces, observable from the single file with no second artifact and no \
journal, and pointing at a back-dated $SI rather than at the header. The image carries three \
further date/time stamps the same build writes — the debug directory entry (offset 4), the export \
directory table (offset 4) and a resource directory table (offset 4) — so a forgery confined to the \
COFF field shows up as disagreement among them. TWO DOCUMENTED WAYS THE FIELD IS LEGITIMATELY NOT A \
TIME, both of which must be excluded before any comparison is reported: a stamp of 0 or 0xFFFFFFFF \
is specified as not a real or meaningful date; and an image whose debug directory carries an \
IMAGE_DEBUG_TYPE_REPRO entry (type 16, PE determinism or reproducibility) has its date/time stamp \
fields filled with part or all of a content hash, so they no longer represent when it was produced. \
Reproducible-build toolchains do this deliberately — the LLVM lld COFF driver's /Brepro writes a \
hash of the executable as the PE header timestamp and its /timestamp option writes a specified \
value, and the Go linker writes 0 outright, its source stating that identical output for identical \
input is worth more than a build time in the header. The stamp also sits inside the Authenticode \
hashed region (the documented exclusions are the optional header CheckSum field, the Certificate \
Table entry with its certificates, and the area past the last section), so editing it on a signed \
binary breaks the signature — a valid signature anchors the value as the signer's. An examiner \
reads the field with ExifTool, which reports it as the EXE group's TimeStamp tag, or with \
Sysinternals sigcheck, which shows a file's timestamp information. A consistent, plausible stamp is \
NOT exculpatory: the value is attacker-writable and can be copied wholesale from a legitimate \
system binary. Cross-reference ntfs_timestomping_si_fn for the $SI-vs-$FN view of the same file, \
shimcache (whose entry timestamp is the executable's $SI last-modified) for a binary no longer on \
disk, and mem_extracted_pe_images when the header was recovered from RAM rather than read from the \
volume. The Court may draw its own conclusions from the pattern.",
    mitre_techniques: &[
        "T1070.006", // Indicator Removal: Timestomp
        "T1036",     // Masquerading
    ],
    fields: PE_COFF_TIMEDATESTAMP_FIELDS,
    retention: Some("Part of the file's own bytes: unchanged by copy, move, archive round-trip or restore, every one of which resets the file-system timestamps. It survives as long as the file does"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "ntfs_timestomping_si_fn",
        "mft",
        "mft_file",
        "shimcache",
        "amcache_app_file",
        "mem_extracted_pe_images",
    ],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format (MS-DOS stub: file offset to the PE signature at location 0x3c; the 4-byte "PE" + two-NUL signature; COFF File Header — Machine at offset 0, TimeDateStamp at offset 4 as "the low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value)"; date/time stamp concept — 0 or 0xFFFFFFFF is not a real or meaningful stamp; Debug Directory TimeDateStamp at entry offset 4; Debug Type IMAGE_DEBUG_TYPE_REPRO = 16, "PE determinism or reproducibility", whose date/time stamp fields hold hash bits; .edata Export Directory Table Time/Date Stamp at offset 4; .rsrc Resource Directory Table Time/Date Stamp at offset 4; Appendix A Authenticode exclusion ranges — CheckSum field, Certificate Table entry and certificates, area past the last section)
        "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
        // Source: https://exiftool.org/TagNames/EXE.html (EXE Tags — the first table is the Windows PE EXE/DLL header; Index2 word 0 = MachineType, word 2 = TimeStamp, i.e. byte offset 4 of the COFF file header)
        "https://exiftool.org/TagNames/EXE.html",
        // Source: https://github.com/llvm/llvm-project/blob/main/lld/COFF/Options.td (/Brepro — "Use a hash of the executable as the PE header timestamp"; /timestamp — "Specify the PE header timestamp")
        "https://github.com/llvm/llvm-project/blob/main/lld/COFF/Options.td",
        // Source: https://github.com/golang/go/blob/master/src/cmd/link/internal/ld/pe.go (the Go linker sets fh.TimeDateStamp = 0, preferring identical output for identical input over a build timestamp in the header)
        "https://github.com/golang/go/blob/master/src/cmd/link/internal/ld/pe.go",
        // Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck (sigcheck "shows file version number, timestamp information, and digital signature details")
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "A deterministic build makes the field meaningless as a time: where the debug directory carries an IMAGE_DEBUG_TYPE_REPRO entry, the stamp holds bits of a content hash by design. Comparing that value against a file time is a category error, not a finding — test for the REPRO entry before reporting any ordering",
        "A stamp of 0 or 0xFFFFFFFF is documented as not a real or meaningful date. The Go linker writes 0 into every PE it produces, so a zero stamp on a Go binary is the toolchain behaving correctly and says nothing about timestomping",
        "A linker can be told to write a specific value (LLVM lld-link's /timestamp), so a stamp that fits no plausible build window may be a deliberate, benign build choice rather than tampering",
        "A consistent, plausible-looking stamp is NOT exculpatory. The field is an ordinary writable header value with no integrity protection of its own, and a value copied from a legitimate system binary looks entirely normal — absence of the anomaly is absence of carelessness, not absence of forgery",
        "$SI times earlier than the build stamp have innocent causes: a host whose clock was wrong when the file was written, a restore or archive extraction that reinstated an older modification time, and a build machine whose own clock was ahead. Establish the host's clock history before treating the ordering as forgery",
        "The field is 32 bits of seconds, so it renders only in UTC and cannot express a time past 2038-01-19 without wrapping; a rendered date far in the past or future is usually a non-time value rather than a claim about a build",
        "Where the header was reconstructed from a memory image rather than read from the volume, the bytes may have been altered in memory or zero-filled from a paged-out region — prefer the on-disk file whenever one exists, and say which source the stamp came from",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "The stamp is file content, not file-system metadata: it persists in the image's own bytes until the file is deleted or rewritten, and is untouched by the copy and restore operations that reset $SI timestamps",
};
