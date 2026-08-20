//! Windows NTFS-internals artifact descriptors (timestomping $SI-vs-$FN
//! discrepancy detection, $LogFile transaction-record analysis).
//!
//! Both artifacts are recovered by parsing NTFS metadata files: the $MFT
//! ($STANDARD_INFORMATION and $FILE_NAME attributes) for the timestamp
//! cross-view, and $LogFile (the metadata transaction journal) for the
//! operation-record stream. They complement the coarse `mft`/`mft_file`
//! descriptors and the `logfile_ntfs` file-collection stub with the specific
//! decode and detection cross-views a GCFA/FOR508-class NTFS timeline analysis
//! relies on.
//!
//! Field descriptions are written from the NTFS on-disk structure definitions
//! (libyal libfsntfs, Carrier File System Forensic Analysis) and the settled
//! reverse-engineered $LogFile reference (LogFileParser); no third-party prose
//! is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Timestomping detection ($STANDARD_INFORMATION vs $FILE_NAME) ─────────────

/// Field schema for the $SI-vs-$FN timestamp cross-view used to detect timestomping.
///
/// The four $SI timestamps live in the $STANDARD_INFORMATION attribute at
/// offsets 0/8/16/24 (creation, modification, MFT-entry modification, access);
/// the four $FN timestamps live in the $FILE_NAME attribute at offsets
/// 8/16/24/32 (after the 8-byte parent file reference at offset 0). The
/// discrepancy flags are DERIVED from comparing the two sets — they are not
/// stored on disk.
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
pub(crate) static NTFS_TIMESTOMPING_SI_FN_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "mft_record",
        value_type: ValueType::UnsignedInt,
        description: "MFT entry number the two timestamp sets belong to",
        is_uid_component: true,
    },
    FieldSchema {
        name: "file_name",
        value_type: ValueType::Text,
        description: "File or directory name from the $FILE_NAME attribute",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_created",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION creation time (FILETIME at $SI offset 0). User-space APIs (SetFileTime) can rewrite this freely — the field timestomping targets",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_modified",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION last-modification time (FILETIME at $SI offset 8)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_mft_modified",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION MFT-entry modification time (FILETIME at $SI offset 16; the 'C'/change time)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_accessed",
        value_type: ValueType::Timestamp,
        description: "$STANDARD_INFORMATION last-access time (FILETIME at $SI offset 24)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fn_created",
        value_type: ValueType::Timestamp,
        description: "$FILE_NAME creation time (FILETIME at $FN offset 8). Updated by the kernel on file create/rename/move, not by SetFileTime — harder to forge than $SI",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fn_modified",
        value_type: ValueType::Timestamp,
        description: "$FILE_NAME last-modification time (FILETIME at $FN offset 16)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fn_mft_modified",
        value_type: ValueType::Timestamp,
        description: "$FILE_NAME MFT-entry modification time (FILETIME at $FN offset 24)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fn_accessed",
        value_type: ValueType::Timestamp,
        description: "$FILE_NAME last-access time (FILETIME at $FN offset 32)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_before_fn",
        value_type: ValueType::Bool,
        description: "DERIVED cross-view (not stored): true when a $SI timestamp predates the corresponding $FN timestamp on the same record. Because $FN is set at creation and $SI can be back-dated, $SI earlier than $FN is consistent with back-dating timestomping — corroborate, as legitimate archive extraction and volume provisioning also produce this",
        is_uid_component: false,
    },
    FieldSchema {
        name: "si_subsecond_zeroed",
        value_type: ValueType::Bool,
        description: "DERIVED cross-view (not stored): true when the $SI FILETIME sub-second (100 ns) fraction is exactly zero while $FN carries a non-zero fraction. Many timestomping tools write only whole-second values, so a zeroed $SI fraction against a precise $FN is consistent with forgery",
        is_uid_component: false,
    },
];

/// Timestomping detection — $STANDARD_INFORMATION vs $FILE_NAME timestamp cross-view.
///
/// Every NTFS file record carries two independent MACB timestamp sets: four in
/// the $STANDARD_INFORMATION ($SI) attribute (offsets 0/8/16/24: creation,
/// modification, MFT-entry modification, access) and four in the $FILE_NAME
/// ($FN) attribute (offsets 8/16/24/32, after the parent file reference).
/// Windows exposes the $SI timestamps to user space, and `SetFileTime` /
/// timestomping tools can rewrite them at will. The $FN timestamps are updated
/// by the kernel on file create, rename, and move — there is no documented
/// user-space API to set them directly — so they are far harder to forge. The
/// detection is the *cross-view*: a $SI timestamp earlier than the
/// corresponding $FN timestamp, or a $SI value whose sub-second fraction is
/// zeroed while $FN carries precision, is consistent with back-dating. Neither
/// flag is stored on disk; both are derived by comparing the two attributes.
///
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
pub(crate) static NTFS_TIMESTOMPING_SI_FN: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_timestomping_si_fn",
    name: "Timestomping Detection ($SI vs $FN Timestamps)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$MFT"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The $SI-vs-$FN timestamp cross-view for detecting timestamp forgery (timestomping). \
Each MFT record stores two MACB sets: four timestamps in $STANDARD_INFORMATION ($SI offsets \
0/8/16/24 — creation, modification, MFT-entry modification, access) and four in $FILE_NAME ($FN \
offsets 8/16/24/32, after the 8-byte parent file reference). The $SI set is writable from user \
space (SetFileTime), which is exactly what timestomping tools alter; the $FN set is updated only \
by the kernel on create/rename/move, with no documented user-space setter, so it is much harder to \
forge. The anomaly is the cross-view: a $SI timestamp earlier than its $FN counterpart, or a $SI \
value with a zeroed sub-second (100 ns) fraction while $FN carries precision, is consistent with \
back-dating. Both discrepancy flags are DERIVED by comparing the two attributes, not stored on \
disk. Corroborate before concluding forgery: archive extraction (which restores $SI from the \
archive while $FN reflects extraction time) and volume provisioning legitimately produce $SI \
earlier than $FN. Cross-reference mft/mft_file for the full record and usnjrnl for the change \
history. The Court may draw its own conclusions from the pattern.",
    mitre_techniques: &[
        "T1070.006", // Indicator Removal: Timestomp
        "T1070",     // Indicator Removal on Host
    ],
    fields: NTFS_TIMESTOMPING_SI_FN_FIELDS,
    retention: Some("Persistent while the MFT record exists; the $FN copy survives even when $SI is overwritten"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["mft", "mft_file", "usnjrnl", "usn_journal"],
    sources: &[
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc ($STANDARD_INFORMATION and $FILE_NAME attribute layouts, timestamp offsets; cites Carrier FSFA page 363)
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "$SI earlier than $FN is NOT proof of timestomping — archive extraction, restore-from-backup, and volume provisioning legitimately produce it; corroborate with other evidence",
        "A sophisticated actor can forge $FN too (e.g. by creating the file with pre-set $SI then relying on $FN inheritance), so matching $SI/$FN does not clear a host",
        "Sub-second-zeroing detection assumes the tool wrote whole seconds; tools that copy a real high-precision timestamp evade it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "$MFT is always present on a mounted NTFS volume; the $FN timestamps persist even after $SI is altered",
};

// ── $LogFile (NTFS transaction log) record analysis ─────────────────────────

/// Field schema for a decoded $LogFile transaction record.
///
/// $LogFile is the NTFS metadata transaction journal. Its restart area and log
/// records carry $LogFile Sequence Numbers (LSN), and each record describes a
/// redo/undo operation on a metadata structure. Field names follow the settled
/// reverse-engineered reference (LogFileParser) and the libyal NTFS spec.
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://github.com/jschicht/LogFileParser>
pub(crate) static NTFS_LOGFILE_RECORDS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "lsn",
        value_type: ValueType::UnsignedInt,
        description: "$LogFile Sequence Number of this record — a monotonically increasing 64-bit identifier locating the record in the journal",
        is_uid_component: true,
    },
    FieldSchema {
        name: "previous_lsn",
        value_type: ValueType::UnsignedInt,
        description: "LSN of the previous log record in the same transaction chain (client previous LSN)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "undo_next_lsn",
        value_type: ValueType::UnsignedInt,
        description: "LSN of the next record to process during undo/rollback (client undo next LSN, at the transaction-record offset 16)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "redo_op",
        value_type: ValueType::Text,
        description: "Redo operation code — the action to REPLAY to roll the change forward (e.g. AddIndexEntryAllocation, DeleteIndexEntryAllocation, InitializeFileRecordSegment, SetBitsInNonresidentBitMap, UpdateResidentValue)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "undo_op",
        value_type: ValueType::Text,
        description: "Undo operation code — the inverse action to REPLAY to roll the change back; the redo/undo pair can reconstruct before and after metadata for interpretable records (payloads may be complete or partial depending on opcode and NTFS version)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_mft_record",
        value_type: ValueType::UnsignedInt,
        description: "MFT entry the operation targets (derived from the record's target attribute/cluster reference), tying the transaction to a specific file or directory",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_attribute",
        value_type: ValueType::Text,
        description: "The metadata structure the operation modifies (e.g. $FILE_NAME index entry, $DATA run, $STANDARD_INFORMATION), used to attribute the change",
        is_uid_component: false,
    },
    FieldSchema {
        name: "redo_data",
        value_type: ValueType::Bytes,
        description: "Redo payload — the bytes written by the forward operation. For file creation/rename records this contains the $FILE_NAME with the name and timestamps, enabling recovery of a deleted or renamed file's original entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "undo_data",
        value_type: ValueType::Bytes,
        description: "Undo payload — the pre-change bytes, giving the prior value of the modified structure (e.g. the old name before a rename)",
        is_uid_component: false,
    },
];

/// $LogFile (NTFS transaction log) record analysis.
///
/// $LogFile is the NTFS metadata transaction journal — the write-ahead log the
/// file system uses to keep its metadata consistent across crashes. Every
/// metadata change (create/delete/rename a file, grow a $DATA run, update an
/// index) is written as a log record before the change is committed, and each
/// record carries a $LogFile Sequence Number (LSN) plus a redo operation (the
/// action to roll the change forward) and an undo operation (the inverse to
/// roll it back), each with its own data payload. Because before (undo) and
/// after (redo) images are logged for many operations, `$LogFile` can often help
/// an analyst recover short-lived metadata that the live $MFT no longer shows:
/// deleted files whose MFT entry was reused, the original name behind a rename,
/// and the sequence of index operations in a directory (records may be partial
/// or version-dependent). The journal is a fixed-size
/// circular buffer, so only recent transactions survive. Field names follow the
/// settled reverse-engineered reference (LogFileParser) and the libyal NTFS
/// on-disk spec.
///
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://github.com/jschicht/LogFileParser>
pub(crate) static NTFS_LOGFILE_RECORDS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_logfile_records",
    name: "$LogFile Transaction Records (NTFS Journal)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$LogFile"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Decoded transaction records from $LogFile, the NTFS metadata write-ahead journal. \
Each metadata change (file create/delete/rename, $DATA run growth, directory index update) is \
logged as a record before it commits. A record carries a $LogFile Sequence Number (LSN), the \
previous-LSN and undo-next-LSN chain links, and a paired redo operation (roll forward) and undo \
operation (roll back), each with its own data payload. Because pre-change (undo) and post-change \
(redo) images are recorded for many operations, $LogFile can often recover metadata the live $MFT \
no longer shows: deleted files whose MFT entry was reused, the original name behind a rename (from \
the undo payload), and the operation sequence in a directory (payloads may be complete or partial \
depending on opcode and NTFS version). Redo/undo payloads for file-name operations \
contain the $FILE_NAME structure with its name and timestamps, enabling reconstruction of a \
deleted entry. The journal is a fixed-size circular buffer, so only recent transactions survive — \
it is higher-volatility than the $MFT. Cross-reference usnjrnl (a coarser, longer-retained change \
log), mft/mft_file (the live record), and ntfs_timestomping_si_fn (the timestamps a recovered \
$FILE_NAME carries).",
    mitre_techniques: &[
        "T1070",     // Indicator Removal on Host (recovering evidence of deletion/renaming)
        "T1070.004", // File Deletion
    ],
    fields: NTFS_LOGFILE_RECORDS_FIELDS,
    retention: Some("Fixed-size circular journal (default tens of MB); only recent transactions survive before wraparound"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usnjrnl", "usn_journal", "mft", "mft_file"],
    sources: &[
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc ($LogFile metadata transaction journal; restart area, LSN, undo-next-LSN at offset 16)
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
        // Source: https://github.com/jschicht/LogFileParser (settled reverse-engineered $LogFile reference — record layout, redo/undo opcodes, deleted-file/rename recovery)
        "https://github.com/jschicht/LogFileParser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "The journal wraps quickly on a busy volume; absence of a transaction proves only that it aged out, not that the operation never happened",
        "Redo/undo opcode semantics are version-dependent and not fully documented by Microsoft; some records are only partially interpretable",
        "A recovered $FILE_NAME's timestamps are $FN timestamps (kernel-set) — treat them as such, not as the user-facing $SI times",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "$LogFile is a fixed-size circular buffer; older transactions are overwritten as new metadata operations occur",
};
