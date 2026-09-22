//! EVTX *format-level* descriptors — the integrity surface of the file itself,
//! and the records that are resident in it but unreachable by a parse chain.
//!
//! The sibling `windows_evtx_ext` file catalogues event-log **channels**: what a
//! provider writes and what its event IDs mean. Nothing there describes the
//! container. These two descriptors do, and they answer the question a channel
//! descriptor cannot — *is this log file complete, and does the parser's record
//! list account for every record physically present in it?*
//!
//! Two distinct surfaces, deliberately kept apart because one does not detect
//! the other:
//!
//! - `evtx_file_structure_integrity` — the file header (dirty/full flags, the
//!   CRC-32 over its first 120 bytes, the declared chunk count) and the per-chunk
//!   header (its own CRC-32 plus a separate CRC-32 over the event-records data).
//!   This is what an integrity check compares, and what a damaged or truncated
//!   log trips.
//! - `evtx_record_unlinking` — per-record removal performed by editing the
//!   *preceding* record's size field so the walk steps over the target. The
//!   target record's bytes, including its full header, stay where they are.
//!   Fox-IT's analysis of the DanderSpritz `eventlogedit` module records that
//!   the tool also renumbers the following records and recalculates both header
//!   checksums, so a log carrying an unlinked record passes every check in the
//!   first descriptor. A chain-following parser reports it as clean and
//!   complete.
//!
//! Field offsets, sizes, flag values and checksum coverage are taken from the
//! libyal libevtx format analysis; the record-unlinking mechanism and its
//! recovery arithmetic from the Fox-IT write-up and the tool the authors
//! published alongside it. The BinXml encoding inside a record is specified in
//! `[MS-EVEN6]`. No third-party prose is copied.
//!
//! Source: <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>
//! Source: <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
//! Source: <https://github.com/fox-it/danderspritz-evtx>
//! Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b>

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

/// Field schema for the EVTX file-header and chunk-header integrity state.
///
/// One record per `.evtx` file. The file-level fields come from the 4096-byte
/// file header: signature at 0, first/last chunk number at 8/16, next record
/// identifier at 24, format version at 36 (minor) and 38 (major), declared chunk
/// count at 42, file flags at 120, and the header checksum at 124. The
/// chunk-level fields are read across every 65536-byte chunk that follows, whose
/// 512-byte header carries a free-space offset at 48, a CRC-32 over the event
/// records at 52, and its own CRC-32 at 124.
///
/// Both checksums are the RFC 1952 CRC-32 with an initial value of zero. The
/// file-header checksum covers the first 120 bytes only; the chunk checksum
/// covers the chunk's first 120 bytes plus bytes 128 to 512 — so neither one
/// covers a record body, and the chunk's second checksum (offset 52) is what
/// does.
/// Source: <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>
/// Source: <https://www.rfc-editor.org/rfc/rfc1952>
pub(crate) static EVTX_FILE_STRUCTURE_INTEGRITY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "log_file",
        value_type: ValueType::Text,
        description: "The .evtx file this header state was read from — integrity is a property of one file, not of a channel. An archived or backed-up copy of the same channel carries its own independent header, so read every copy present on the image rather than the live one alone",
        is_uid_component: true,
    },
    FieldSchema {
        name: "format_version",
        value_type: ValueType::Text,
        description: "Major.minor format version from file-header offsets 38 and 36. Version 3.1 is seen from Windows Vista onward and 3.2 from Windows 10 (2004) onward, so the version is a coarse check that the file matches the build it is claimed to have come from — and a parser that only knows 3.1 is the likelier explanation for an unreadable modern log than tampering is",
        is_uid_component: false,
    },
    FieldSchema {
        name: "first_chunk_number",
        value_type: ValueType::UnsignedInt,
        description: "First chunk number, file-header offset 8 (8 bytes). Read it together with `last_chunk_number`: the pair should be ordered, and the libevtx analysis records a genuine file where the first (206) exceeded the last (205) while the header checksum verified. Field sanity and checksum validity are separate questions",
        is_uid_component: false,
    },
    FieldSchema {
        name: "last_chunk_number",
        value_type: ValueType::UnsignedInt,
        description: "Last chunk number, file-header offset 16 (8 bytes). Bounds the range the header claims; compare against `chunks_present` before trusting a parser that stops here",
        is_uid_component: false,
    },
    FieldSchema {
        name: "number_of_chunks",
        value_type: ValueType::UnsignedInt,
        description: "Declared chunk count, file-header offset 42 (4 bytes). This is a claim by the header, not a measurement of the file — the documented dirty-file state is a count LOWER than the number of chunks actually present, and a parser that trusts it silently drops every record beyond it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "chunks_present",
        value_type: ValueType::UnsignedInt,
        description: "Chunks actually found by walking the file from offset 4096 in 65536-byte steps and matching the `ElfChnk\\0` signature — the measurement that `number_of_chunks` is checked against. Where it exceeds the declared count, the extra chunks hold ordinary records: libevtx keeps scanning past the header's last chunk and does NOT mark what it finds there as recovered, so those records are as good as any other",
        is_uid_component: false,
    },
    FieldSchema {
        name: "next_record_identifier",
        value_type: ValueType::UnsignedInt,
        description: "Identifier the next record written to this file will take, file-header offset 24 (8 bytes). It bounds how many records the channel has issued, so the distance between it and the highest identifier still present tells you roughly how much this file has shed. That distance is ordinary on a channel that has wrapped — treat it as a rotation measure, not as a tamper indicator",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_flags",
        value_type: ValueType::UnsignedInt,
        description: "File flags, file-header offset 120 (4 bytes). 0x0001 marks the file dirty — it was not closed cleanly — and 0x0002 marks it full. Dirty is the flag analysts reach for and the one most often over-read: a crash, a power loss, or imaging the volume while the service held the file open all set it, and so does copying a live log. It says the file was left mid-write, and nothing about why",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_header_checksum",
        value_type: ValueType::UnsignedInt,
        description: "Stored file-header checksum, offset 124 (4 bytes) — the CRC-32 (RFC 1952, initial value 0) of the first 120 bytes of the header. Record the stored value alongside the recomputed one rather than only a verdict, so a later reader can re-derive the comparison instead of trusting it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_header_checksum_valid",
        value_type: ValueType::Bool,
        description: "Does `file_header_checksum` match a CRC-32 recomputed over the header's first 120 bytes? A mismatch says those 120 bytes were changed by something that did not recalculate the CRC. It does not say what changed, and its converse carries no weight at all — a match covers 120 bytes of a file that may be tens of megabytes",
        is_uid_component: false,
    },
    FieldSchema {
        name: "chunk_checksum_mismatches",
        value_type: ValueType::List,
        description: "Chunk numbers failing either per-chunk CRC-32: the chunk-header checksum at chunk offset 124 (covering the chunk's first 120 bytes and bytes 128 to 512), or the event-records checksum at chunk offset 52 (covering the event-records data). The second is the one that reaches record content, so it is the mismatch worth reading in full — it localises damage or alteration to a single 64 KB chunk, which is where to start scanning for recoverable records",
        is_uid_component: false,
    },
    FieldSchema {
        name: "chunk_free_space_offset",
        value_type: ValueType::UnsignedInt,
        description: "Free-space offset in a chunk header, chunk offset 48, relative to the start of the chunk. It is not reliably the end of the record data — the libevtx analysis records archived files where it points at the chunk end because the space after the last record was zero-filled. The bytes between the last parsed record and this offset are chunk slack, and that is the region a free-space record scan covers",
        is_uid_component: false,
    },
    FieldSchema {
        name: "chunk_record_number_span",
        value_type: ValueType::Text,
        description: "First and last event record number (chunk offsets 8 and 16) and first and last event record identifier (offsets 24 and 32). The chunk should hold last-minus-first-plus-one records, and successive chunks were observed to carry successive record numbers — two cheap arithmetic checks over the whole file. Treat a break as a lead to explain, not a finding: whether identifier gaps are normal is left open in the format analysis itself",
        is_uid_component: false,
    },
];

/// EVTX file and chunk header integrity — dirty flag, CRC-32 pairs, chunk count.
///
/// An EVTX file is a 4096-byte header followed by 65536-byte chunks, each of
/// which is a 512-byte chunk header followed by variable-length event records
/// and unused space. Three things in that structure are checkable without
/// interpreting a single event: the file header's flags (dirty, full), the two
/// stored CRC-32 values (one over the file header's first 120 bytes, one per
/// chunk over the chunk header, plus a third per chunk over the event-records
/// data), and the declared chunk count against the chunks actually present.
///
/// The value of encoding this is mostly in what it rules out. A dirty flag is
/// set by an unclean close of any cause, so it survives as a question rather
/// than an answer. A verifying header checksum covers 120 bytes and is
/// documented to have verified over a header whose chunk numbers were
/// self-contradictory. A declared chunk count lower than the real one is a known
/// dirty-file state whose only real consequence is that a parser trusting the
/// header drops records it could have read.
///
/// The load-bearing limit is at the other end: none of these checks sees
/// record-level unlinking, because the published tooling for that recalculates
/// both header checksums after editing. Read `evtx_record_unlinking` before
/// concluding from a clean integrity pass that a log is complete.
///
/// Source: <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>
/// Source: <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
pub(crate) static EVTX_FILE_STRUCTURE_INTEGRITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_file_structure_integrity",
    name: "EVTX File/Chunk Header Integrity (Dirty Flag, CRC-32, Chunk Count)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\*.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Container-level integrity state of a Windows XML Event Log file, read from the \
structure rather than from the events. The file is a 4096-byte header (signature `ElfFile\\0`, \
first/last chunk number at 8/16, next record identifier at 24, minor/major format version at \
36/38, declared chunk count at 42, file flags at 120, checksum at 124) followed by 65536-byte \
chunks, each opening with a 512-byte chunk header (signature `ElfChnk\\0`, first/last event record \
number at 8/16, first/last event record identifier at 24/32, free-space offset at 48, \
event-records CRC-32 at 52, chunk CRC-32 at 124). Both stored checksums are the RFC 1952 CRC-32 \
with initial value 0; the file-header value covers only its first 120 bytes, the chunk value covers \
the chunk's first 120 bytes plus bytes 128-512, and only the separate offset-52 value reaches \
record data. Three checks fall out: the file flags (0x0001 dirty — not closed cleanly; 0x0002 \
full), the stored-versus-recomputed CRC-32 pairs, and the declared chunk count against the chunks \
actually found by walking the file. Each is better at excluding than at accusing. A dirty flag is \
produced by an ordinary crash, a power loss, or imaging a live volume. A verifying header checksum \
proves nothing about the 120 bytes being sensible — the libevtx analysis documents a real file \
whose first chunk number exceeded its last with the checksum intact. A declared chunk count below \
the number of chunks present is a documented dirty-file state, and libevtx's response is to keep \
scanning past the header's last chunk and treat what it finds as ordinary, not recovered, records; \
a parser that stops at the declared count loses them silently. The limit that matters most: \
none of this detects per-record unlinking, which recalculates both header checksums as part of the \
edit — see evtx_record_unlinking.",
    mitre_techniques: &[
        "T1685.005", // Clear Windows Event Logs
    ],
    fields: EVTX_FILE_STRUCTURE_INTEGRITY_FIELDS,
    retention: Some("Header and chunk fields persist for the life of the .evtx file; an archived or backed-up copy of a channel carries its own independent header state"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "evtx_record_unlinking",
        "evtx_dir",
        "evtx_security",
        "evtx_system",
    ],
    sources: &[
        // Source: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
        // (file header 4096 bytes: signature offset 0, first/last chunk number 8/16, next record identifier 24,
        // minor/major version 36/38, number of chunks 42, file flags 120, checksum 124 = CRC-32 of the first 120 bytes;
        // file flags 0x0001 Is dirty / 0x0002 Is full; format versions 3.1 Vista+ and 3.2 Windows 10 2004+;
        // chunk 65536 bytes with a 512-byte header: signature 0, first/last record number 8/16, first/last record
        // identifier 24/32, last record data offset 44, free space offset 48, event records CRC-32 52, chunk CRC-32 124
        // over the first 120 bytes and bytes 128-512; corrupted-header-with-correct-checksum and dirty-file-with-
        // invalid-chunk-count scenarios; libevtx keeps scanning past the declared last chunk and does not mark those
        // records recovered; records-per-chunk = last - first + 1 and successive chunks carry successive record numbers;
        // identifier gaps left as an open question)
        "https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc",
        // Source: https://www.rfc-editor.org/rfc/rfc1952 (the CRC-32 definition both stored checksums use)
        "https://www.rfc-editor.org/rfc/rfc1952",
        // Source: https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/
        // (record-level unlinking renumbers the following records and recalculates the checksums in both the file and
        // chunk header — the reason a clean integrity pass here does not establish completeness)
        "https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "A set dirty flag (0x0001) records only that the file was not closed cleanly. A crash, a power cut, or acquiring the volume while the Event Log service held the file open all produce it, and so does copying a live log — it is a question to answer, never a finding on its own",
        "A verifying file-header checksum covers 120 bytes and does not police whether those bytes are coherent: the libevtx analysis documents a genuine file whose first chunk number (206) exceeded its last (205) with the CRC intact. Check the field relationships separately from the CRC",
        "A declared chunk count below the number of chunks actually present is a documented dirty-file state, not proof that records were removed. libevtx's answer is to keep scanning past the header's last chunk, and the records found there are ordinary records rather than recovered ones — a parser that honours the declared count drops them with no error",
        "CHECKSUMS DO NOT DETECT RECORD UNLINKING. Fox-IT's analysis of the DanderSpritz eventlogedit module records that it renumbers every following record and recalculates the checksums in both the file and chunk header, so a log with records unlinked verifies clean on every field here. A clean pass is consistent with a complete log and equally consistent with an edited one",
        "Whether gaps in event record identifiers are normal is left as an open question in the format analysis itself, so a gap is a lead to explain rather than evidence of deletion",
        "Reading integrity from a live system reads a file the service is actively writing; header state captured that way may be mid-update. Prefer the acquired image, and where both exist, note that they can legitimately differ",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Header and chunk-header fields are stored in the .evtx file and survive reboot; they change only as the service writes to the log or when the channel is cleared or rolled",
};

/// Field schema for a record that is resident in an EVTX file but absent from
/// the parser's record list.
///
/// The unlinking fields describe one hidden record found inside a visible
/// ("host") record: its offset from the host record's start, the two 4-byte size
/// values that confirm it, and the header fields recovered from it (identifier
/// at record offset 8, written FILETIME at offset 16, BinXml body from offset 24
/// to the trailing copy-of-size).
///
/// `chunk_slack_records` is a SEPARATE mechanism kept in the same schema because
/// it answers the same analyst question — what is in this file that the parser
/// did not list — and must not be reported as unlinking.
/// `forwarded_copy_present` is a separate SOURCE entirely.
/// Source: <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
/// Source: <https://github.com/fox-it/danderspritz-evtx>
/// Source: <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>
pub(crate) static EVTX_RECORD_UNLINKING_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "host_record_number",
        value_type: ValueType::UnsignedInt,
        description: "The visible record whose size field was enlarged to span the hidden one — the record a normal parser reports, and inside whose data the hidden record physically sits. It is the anchor for re-finding the hit, and it is also the record immediately BEFORE the removed one in the original log, which is what dates the removal to a point in the timeline",
        is_uid_component: true,
    },
    FieldSchema {
        name: "hidden_record_offset",
        value_type: ValueType::UnsignedInt,
        description: "Byte offset, from the start of `host_record_number`, of an embedded 2A 2A 00 00 record signature. The search starts past the host record's 24-byte header and stops short of its trailing copy-of-size, so a hit is a signature sitting where only record data should be. On its own it is a candidate, not a finding — BinXml data can contain those four bytes by chance, which is what `size_merge_confirmed` exists to rule out",
        is_uid_component: true,
    },
    FieldSchema {
        name: "restored_host_size",
        value_type: ValueType::UnsignedInt,
        description: "The little-endian u32 in the four bytes immediately BEFORE the embedded signature — the host record's original trailing copy-of-size, left in place by the edit. This is the recovery key: it is the host record's true length, so it both confirms the find and is the value written back into the host's size field to restore the chain",
        is_uid_component: false,
    },
    FieldSchema {
        name: "hidden_record_size",
        value_type: ValueType::UnsignedInt,
        description: "The little-endian u32 four bytes AFTER the embedded signature — the hidden record's own size field, still intact, giving its full extent. Restoring it means writing this value into the last four bytes of the merged span, where the hidden record's trailing copy-of-size belongs",
        is_uid_component: false,
    },
    FieldSchema {
        name: "size_merge_confirmed",
        value_type: ValueType::Bool,
        description: "The two-part arithmetic test that turns a candidate into a finding: `hidden_record_offset` equals `restored_host_size`, AND `restored_host_size` plus `hidden_record_size` equals the host record's current size field. Both must hold. A stray signature inside BinXml fails them; a genuine merge satisfies both by construction, because the host's size field is exactly the two original records added together",
        is_uid_component: false,
    },
    FieldSchema {
        name: "hidden_record_identifier",
        value_type: ValueType::UnsignedInt,
        description: "Event record identifier read from offset 8 of the recovered record header — the number the removed event carried before it was unlinked. Read it against the surrounding live records: it is the removed event's original position in the sequence, which is not the same as its position after the following records were renumbered",
        is_uid_component: false,
    },
    FieldSchema {
        name: "hidden_record_written_time",
        value_type: ValueType::Timestamp,
        description: "FILETIME at offset 16 of the recovered record header — when the removed event was written. Untouched by the edit, so it places the removed event in the timeline exactly as any live record would be, and it brackets when the removal itself must have happened (after this, before the log was acquired)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "hidden_record_xml",
        value_type: ValueType::Text,
        description: "The recovered record's body, decoded from the BinXml token stream that runs from record offset 24 to the trailing copy-of-size. The whole event survives — provider, event ID, level, and every EventData field — because the edit rewrote size values around the record and nothing inside it. This is what was worth hiding, and it is the field to read in full",
        is_uid_component: false,
    },
    FieldSchema {
        name: "record_identifier_sequence_intact",
        value_type: ValueType::Bool,
        description: "Does the visible record sequence run without a gap? True is the EXPECTED result on an edited log and must not be read as reassurance: renumbering the following records is part of the documented removal, exactly so that a missing number does not show. Use it to record that the obvious check was run and came back clean, never to close the question",
        is_uid_component: false,
    },
    FieldSchema {
        name: "chunk_slack_records",
        value_type: ValueType::List,
        description: "SEPARATE MECHANISM (not unlinking): records recovered by scanning a chunk's free space for the 2A 2A 00 00 signature and keeping those whose size and trailing copy-of-size agree. The documented rule is to discard any whose identifier is already present, because free space commonly holds a former version of a record that is still live. Report these as chunk-slack recoveries — presenting them as unlinked records overstates what they show",
        is_uid_component: false,
    },
    FieldSchema {
        name: "forwarded_copy_present",
        value_type: ValueType::Bool,
        description: "SEPARATE SOURCE (not this file): is the recovered event also on a Windows Event Collector or SIEM that received it at write time? A match independently corroborates both the event and the fact that it is missing locally. Absence proves little — an attacker who expects forwarding compromises the collector first, which is the documented reason not to treat a central copy as a safety net",
        is_uid_component: false,
    },
];

/// EVTX record unlinking — records resident in the file but off the parse chain.
///
/// An event record is a 24-byte header (signature `2A 2A 00 00`, size, record
/// identifier, written FILETIME), a BinXml body, and a trailing copy of the
/// size. A parser walks a chunk by reading a record's size field and stepping
/// that far forward. Removal exploits exactly that: rather than erase the target
/// record, the DanderSpritz `eventlogedit` module adds the target's size to the
/// PRECEDING record's size field, merging the two. The walk now steps over both,
/// and the target — header, timestamps, identifier and full BinXml body — is
/// just trailing bytes of a record the parser thinks it has already read. Fox-IT
/// reported that every viewer they tested, Windows Event Viewer included, parses
/// the BinXml to its first end tag and moves on, so nothing is displayed.
///
/// The edit is deliberately quiet everywhere an integrity check looks: following
/// records are renumbered so no identifier gap appears, and the file- and
/// chunk-header checksums are recalculated so no CRC fails.
///
/// What it does not repair is the arithmetic. The host record's original
/// trailing copy-of-size is still sitting in the four bytes immediately before
/// the hidden record's signature, and the hidden record's own size field is four
/// bytes after it. A find is confirmed when the signature's offset equals that
/// preceding value AND those two sizes sum to the host record's current size —
/// a two-part identity that a chance `2A 2A 00 00` inside BinXml does not
/// satisfy. Repair writes the recovered size back into the host record's size
/// field and the hidden record's size into the last four bytes of the merged
/// span, restoring the chain; the pass then repeats, because consecutive
/// removals nest.
///
/// The second, unrelated route to an unreported record is chunk slack: scanning
/// a chunk's free space for records whose size and copy-of-size agree and
/// discarding those whose identifier is already live. Same analyst question,
/// different mechanism, and much weaker — free space routinely holds a previous
/// version of a record that is still present.
///
/// Source: <https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/>
/// Source: <https://github.com/fox-it/danderspritz-evtx>
/// Source: <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>
pub(crate) static EVTX_RECORD_UNLINKING: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_record_unlinking",
    name: "EVTX Record Unlinking (Resident Records Off the Parse Chain)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\*.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Individual event records that are physically present in an EVTX file but absent from \
what a parser reports, and the recovery of their full content. An event record is a 24-byte header \
(signature 2A 2A 00 00, size at 4, record identifier at 8, written FILETIME at 16), a BinXml body \
from offset 24, and a trailing copy of the size; a parser walks a chunk by reading each size field \
and stepping forward by it. Fox-IT's analysis of the DanderSpritz eventlogedit module found that \
per-record removal never touches the target record: the size of the record to be removed is ADDED \
to the size field of the PRECEDING record, merging the two, so the walk steps straight over the \
target and treats it as trailing data of a record already consumed. Every viewer tested, Windows \
Event Viewer among them, parsed the BinXml to its first end tag and moved on, displaying nothing. \
The edit is quiet where integrity checks look — following records are renumbered so no identifier \
gap shows, and the file- and chunk-header checksums are recalculated so no CRC fails — which is \
why evtx_file_structure_integrity passes clean on an edited log. What survives is the arithmetic: \
the host record's ORIGINAL trailing copy-of-size is still in the four bytes immediately before the \
hidden record's signature, and the hidden record's own size field is four bytes after it. A \
candidate is confirmed when the signature's offset from the host record start equals that preceding \
value AND those two sizes sum to the host record's current size — a two-part identity a chance \
2A 2A 00 00 in BinXml does not meet. Because the record body was never altered, recovery is total: \
record identifier, written timestamp, provider, event ID and every EventData field. Repair restores \
the host's size field and the hidden record's trailing copy-of-size, then repeats, since \
consecutive removals nest. A SECOND and much weaker route to an unreported record is chunk slack — \
scanning a chunk's free space for records whose size and copy-of-size agree, discarding those whose \
identifier is already live, because free space commonly holds a superseded version of a record \
still in the log. Report the two separately.",
    mitre_techniques: &[
        "T1685.005", // Clear Windows Event Logs
        "T1565.001", // Data Manipulation: Stored Data Manipulation
    ],
    fields: EVTX_RECORD_UNLINKING_FIELDS,
    retention: Some("An unlinked record's bytes stay resident until its 64 KB chunk is rewritten — i.e. until the channel wraps at its configured maximum size, or the log is cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_file_structure_integrity",
        "evtx_dir",
        "evtx_security",
        "evtx_system",
    ],
    sources: &[
        // Source: https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/
        // (eventlogedit unreferences rather than removes: the target's size is added to the preceding record's size,
        // merging them; the record and its header are left in their original state, so identifier, event ID, timestamps
        // and message recover in full; tested viewers including Windows Event Viewer parse the BinXml to the first end
        // tag and move on; following record numbers are renumbered and file- and chunk-header checksums recalculated;
        // the script also handles consecutive removals, the first record of the file, and the first record of a chunk;
        // a forwarded copy on a central log server may hold the record, but an advanced attacker compromises it first)
        "https://blog.fox-it.com/2017/12/08/detection-and-recovery-of-nsas-covered-up-tracks/",
        // Source: https://github.com/fox-it/danderspritz-evtx (the published detection and repair: search for the record
        // magic inside each parsed record's data starting past the 24-byte header; read old_size from the 4 bytes before
        // the magic and del_size from the 4 bytes after; confirm when magic_offset == old_size and
        // old_size + del_size == the host record's size; repair by writing old_size into the host size field and
        // del_size into the last 4 bytes of the merged span, looping until no further correction is made)
        "https://github.com/fox-it/danderspritz-evtx",
        // Source: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
        // (event record layout: signature 0, size 4, record identifier 8, written FILETIME 16, BinXml from 24, trailing
        // copy of size; recovery = scan chunk free space for records whose size and copy of size match, ignoring any
        // identifier that already exists because free space often holds former versions of existing records)
        "https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc",
        // Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b
        // (EventLog Remoting Protocol Version 6.0 — specifies the BinXml encoding the recovered record body decodes as)
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b",
        // Source: https://github.com/williballenthin/python-evtx (the reference EVTX parser the published detection tool
        // builds on — a chain-following record walk, which is the parse model unlinking is designed to defeat)
        "https://github.com/williballenthin/python-evtx",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "The finding rests on arithmetic, not on a signature. A 2A 2A 00 00 sequence occurs inside BinXml data by chance, so a hit is only a candidate until BOTH tests pass: the signature's offset equals the u32 in the four bytes before it, and that u32 plus the hidden record's size field equals the host record's current size. Decode the recovered BinXml before reporting a single match",
        "An intact record-identifier sequence is the EXPECTED state of an edited log, not an absence of editing — renumbering the following records is part of the documented mechanism. The same goes for valid checksums: both header CRCs are recalculated by the edit",
        "Chunk-slack recoveries are a different mechanism and a much weaker one. Free space commonly holds a superseded version of a record that is still live, which is why the documented rule discards any recovered identifier already present. Reporting a slack recovery as an unlinked record overstates it",
        "Recovery depends on the bytes still being there. Once the channel wraps at its size limit or the log is cleared, the chunk is rewritten and nothing here is recoverable; a shadow copy, a backup, or a forwarded copy on a collector is then the only route",
        "A forwarded copy on a central collector corroborates strongly when it exists, but its absence shows little: the published analysis notes that an attacker expecting forwarding compromises the log server before operating on the target",
        "The tool's authors state it also handles consecutive removals, the first record of a file, and the first record of a chunk, but the write-up does not describe the mechanism for the chunk-boundary cases — validate any implementation against a known-good sample before relying on a negative result at a chunk boundary",
        "This descriptor addresses record-level removal. Wholesale clearing of a channel is a different act with its own trace (the clear event in the new log and the service-side record of it), and finding no unlinked records says nothing about whether the log was cleared",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "The unlinked record survives only as long as its chunk does; the channel wrapping at its configured maximum size, or a log clear, rewrites the chunk and destroys it",
};
