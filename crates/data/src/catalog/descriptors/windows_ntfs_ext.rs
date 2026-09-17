//! Windows NTFS-internals artifact descriptors — the decode and cross-view
//! detail behind the coarse `mft` / `logfile_ntfs` / `usnjrnl` collection
//! entries.
//!
//! Every artifact here is recovered by parsing an NTFS metadata file:
//!
//! - `$MFT` ($STANDARD_INFORMATION vs $FILE_NAME) for the timestomping
//!   cross-view, and its multi-sector fix-up (update sequence array) framing,
//!   which any carver must undo before a record's bytes mean anything;
//! - `$LogFile` (the metadata transaction journal) for the redo/undo operation
//!   stream, its RSTR/RCRD page framing, and cluster-run recovery;
//! - `$Extend\$UsnJrnl` — the `:$J` change stream (the full USN_REASON_\*
//!   bitmask, and the SDelete wipe signature it carries) and the `:$Max`
//!   configuration stream that bounds the journal's retention window;
//! - `$Secure:$SDS` with its `$SDH` / `$SII` indexes, joined to an MFT record
//!   by the $STANDARD_INFORMATION security identifier.
//!
//! Field descriptions are written from the primary structure definitions —
//! Microsoft's `winioctl.h` documentation for the USN structures, the libyal
//! libfsntfs NTFS on-disk specification, the Linux `ntfs3` and `ntfs-3g`
//! drivers for the $LogFile opcode and record-magic constants, and the settled
//! reverse-engineered $LogFile reference (LogFileParser). No third-party prose
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
/// reverse-engineered reference (LogFileParser) and the libyal NTFS spec; the
/// operation-code values are the constants the Linux `ntfs3` driver defines in
/// `enum NTFS_LOG_OPERATION`.
///
/// Note the load-bearing NEGATIVE: the Log File Service record header is three
/// LSNs (this record's, the previous record's, the undo-next) and carries NO
/// time field of any kind. LSN is the only ordering key the header offers;
/// wall-clock time has to be lifted from the logged payload.
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://github.com/jschicht/LogFileParser>
/// Source: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ntfs3/fslog.c>
pub(crate) static NTFS_LOGFILE_RECORDS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "lsn",
        value_type: ValueType::UnsignedInt,
        description: "$LogFile Sequence Number of this record — a monotonically increasing 64-bit identifier locating the record in the journal. The record header has no time field, so the LSN is the ONLY ordering key $LogFile itself supplies; order by it and derive wall-clock time from the payload (see logfile_time_source)",
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
        name: "page_signature",
        value_type: ValueType::Text,
        description: "Four-byte signature of the $LogFile page this record was read from — \"RSTR\" (restart page: the Log File Service restart header holding the log/system page sizes and the format version) or \"RCRD\" (log record page: the pages that actually carry transaction records). \"CHKD\" marks a page rewritten by chkdsk. Both page types are multi-sector-protected, so a page carved from unallocated space or a shadow copy is valid only once its fix-ups reconcile — that reconciliation is the accept/reject test for carved $LogFile pages (see ntfs_multi_sector_fixup)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "redo_op",
        value_type: ValueType::Text,
        description: "Redo operation code — the action to REPLAY to roll the change forward. The opcode space is contiguous: 0x00 Noop, 0x01 CompensationLogRecord, 0x02 InitializeFileRecordSegment, 0x03 DeallocateFileRecordSegment, 0x04 WriteEndOfFileRecordSegment, 0x05 CreateAttribute, 0x06 DeleteAttribute, 0x07 UpdateResidentValue, 0x08 UpdateNonresidentValue, 0x09 UpdateMappingPairs, 0x0A DeleteDirtyClusters, 0x0B SetNewAttributeSizes, 0x0C AddIndexEntryRoot, 0x0D DeleteIndexEntryRoot, 0x0E AddIndexEntryAllocation, 0x0F DeleteIndexEntryAllocation, 0x10 WriteEndOfIndexBuffer, 0x11 SetIndexEntryVcnRoot, 0x12 SetIndexEntryVcnAllocation, 0x13 UpdateFileNameRoot, 0x14 UpdateFileNameAllocation, 0x15 SetBitsInNonresidentBitMap, 0x16 ClearBitsInNonresidentBitMap, 0x17 HotFix, 0x18 EndTopLevelAction, 0x19 PrepareTransaction, 0x1A CommitTransaction, 0x1B ForgetTransaction, 0x1C OpenNonresidentAttribute, 0x1D OpenAttributeTableDump, 0x1E AttributeNamesDump, 0x1F DirtyPageTableDump, 0x20 TransactionTableDump, 0x21 UpdateRecordDataRoot, 0x22 UpdateRecordDataAllocation, 0x23 UpdateRelativeDataInIndex, 0x24 UpdateRelativeDataInIndex2, 0x25 ZeroEndOfFileRecord. File creation is 0x02 (+0x05/0x07 as attributes land) and deletion 0x03; directory-entry churn is the Add/Delete IndexEntry pairs. FILTER ON BOTH HALVES OF EACH Root/Allocation PAIR: a directory small enough to keep its index resident in the MFT record emits the ...Root variants (0x0C/0x0D/0x11/0x13/0x21), and only a directory large enough to need an $INDEX_ALLOCATION emits the ...Allocation variants (0x0E/0x0F/0x12/0x14/0x22) — a query written against the Allocation names alone silently misses every creation, deletion, rename and move in small directories",
        is_uid_component: false,
    },
    FieldSchema {
        name: "undo_op",
        value_type: ValueType::Text,
        description: "Undo operation code — the inverse action to REPLAY to roll the change back, drawn from the same 0x00-0x25 space as redo_op. Both codes ride in the SAME record header, so one record contributes two opcodes, not one: a parser that reports a single 'operation' per record is discarding half the signal, and the redo/undo pair is what reconstructs before-and-after metadata (payloads may be complete or partial depending on opcode and NTFS version)",
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
    FieldSchema {
        name: "data_runs",
        value_type: ValueType::Text,
        description: "DERIVED (not a single stored field): the $DATA cluster-run list reconstructed by replaying the attribute operations (0x05 CreateAttribute, 0x08 UpdateNonresidentValue, 0x09 UpdateMappingPairs, 0x0B SetNewAttributeSizes) for one MFT entry. This is the capability nothing else offers — $LogFile preserves where a deleted file's clusters WERE after its MFT record has been reallocated to a different file, so a fragmented deleted file that signature carving cannot reassemble can still be extracted run by run. Pair with the initialised stream size for the correct extraction length, and with the compression-unit size where the attribute was compressed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logfile_time_source",
        value_type: ValueType::Text,
        description: "Which payload supplied this record's wall-clock time, and it must be named because $LogFile's own header supplies none. Two routes: (a) an $INDEX_ROOT/$INDEX_ALLOCATION entry or $FILE_NAME structure inside a redo/undo payload, carrying four FILETIMEs — note these are $FN (kernel-set) times, not the user-facing $SI times; (b) a $UsnJrnl update logged as a transaction, whose USN_RECORD_V2.TimeStamp is a FILETIME. Route (b) has a PRECONDITION an examiner must state: USN records exist only while the change journal is enabled on the volume, so `fsutil usn deletejournal` removes the primary timing source for $LogFile analysis from that moment forward. Records with neither payload can be ordered by LSN but not dated",
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
deleted entry. Replaying the attribute opcodes for one MFT entry also reconstructs a deleted \
file's $DATA CLUSTER RUNS after its MFT record has been reallocated — the one route to a \
fragmented deleted file that signature carving cannot reassemble. Opcodes are the contiguous \
0x00-0x25 space the Linux ntfs3 driver names; each record carries a redo code AND an undo code, \
and the Root/Allocation opcode pairs must both be queried, since a small resident directory index \
emits only the ...Root variants. Records live in \"RCRD\" pages (with \"RSTR\" restart pages at the \
head of the journal); both page types are multi-sector-protected, so a page carved from \
unallocated space or a shadow copy is valid only once its fix-ups reconcile. The record header \
carries NO time field — three LSNs and nothing else — so any wall-clock time is lifted from \
payload ($FILE_NAME FILETIMEs, or a logged USN record's TimeStamp, the latter available only while \
the change journal is enabled). The journal is a fixed-size circular buffer, so only recent \
transactions survive — it is higher-volatility than the $MFT, and `chkdsk <volume> /L` reports the \
volume's actual size so the window can be stated rather than assumed. Cross-reference usnjrnl (a \
coarser, longer-retained change log), mft/mft_file (the live record), \
ntfs_multi_sector_fixup (the fix-up rule carving depends on), and ntfs_timestomping_si_fn (the \
timestamps a recovered $FILE_NAME carries).",
    mitre_techniques: &[
        "T1070",     // Indicator Removal on Host (recovering evidence of deletion/renaming)
        "T1070.004", // File Deletion
    ],
    fields: NTFS_LOGFILE_RECORDS_FIELDS,
    retention: Some("Fixed-size circular journal; only recent transactions survive before wraparound. MEASURE IT, do not assume: `chkdsk <volume> /L` reports the volume's CURRENT $LogFile size (NTFS-only switch; `/L:<size>` changes it), which bounds the window an absence argument is allowed to cover"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "usnjrnl",
        "usn_journal",
        "mft",
        "mft_file",
        "ntfs_multi_sector_fixup",
        "ntfs_usnjrnl_max",
    ],
    sources: &[
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc ($LogFile metadata transaction journal; LFS_RESTART_PAGE_HEADER "RSTR"/"RCRD"/"CHKD" signature at offset 0; LFS_RECORD_HEADER = LSN / previous LSN / undo-next LSN at offset 16, and no time field)
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
        // Source: https://github.com/jschicht/LogFileParser (settled reverse-engineered $LogFile reference — record layout, redo/undo opcodes, deleted-file/rename recovery, and the reconstructed data-run list for files whose MFT record has been reused)
        "https://github.com/jschicht/LogFileParser",
        // Source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ntfs3/fslog.c (enum NTFS_LOG_OPERATION — the redo/undo opcode constants 0x00-0x25 by name and value)
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ntfs3/fslog.c",
        // Source: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk (/l[:<size>] — NTFS only; displays the current log-file size, or changes it)
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "The journal wraps quickly on a busy volume; absence of a transaction proves only that it aged out, not that the operation never happened — and that argument is only defensible once the window is bounded by reporting the volume's actual $LogFile size (chkdsk /L)",
        "Redo/undo opcode semantics are version-dependent and not fully documented by Microsoft; some records are only partially interpretable",
        "A recovered $FILE_NAME's timestamps are $FN timestamps (kernel-set) — treat them as such, not as the user-facing $SI times",
        "$LogFile records carry no timestamp of their own — the Log File Service record header is three LSNs and nothing else. Any wall-clock time attached to a $LogFile record was lifted from a payload ($FILE_NAME FILETIMEs, or a logged USN record's TimeStamp); say which, because route and reliability differ",
        "Records logged from $UsnJrnl activity exist only while the change journal is enabled; once it is deleted, later $LogFile records lose that dating route entirely",
        "A $LogFile page carved from unallocated space or a shadow copy is not usable until its multi-sector fix-ups are applied and reconcile — an unfixed page carries 2 corrupted bytes per 512-byte sector",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "$LogFile is a fixed-size circular buffer; older transactions are overwritten as new metadata operations occur",
};

// ── NTFS multi-sector fix-ups (update sequence array) ────────────────────────

/// Field schema for the multi-sector transfer protection every NTFS record
/// header carries.
///
/// The three header fields live at fixed offsets in the `MULTI_SECTOR_HEADER`
/// that opens a FILE (MFT entry), INDX (index allocation block), RSTR and RCRD
/// ($LogFile page) record: the four-byte signature at 0x00, the fix-up (update
/// sequence) array offset at 0x04, and the number of array ELEMENTS at 0x06.
/// The remaining fields are derived by applying the array.
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://github.com/tuxera/ntfs-3g/blob/edge/include/ntfs-3g/layout.h>
pub(crate) static NTFS_MULTI_SECTOR_FIXUP_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "signature",
        value_type: ValueType::Text,
        description: "Four-byte record signature at offset 0x00: \"FILE\" (MFT entry), \"INDX\" (index allocation block), \"RSTR\" / \"RCRD\" ($LogFile restart and record pages), \"CHKD\" (rewritten by chkdsk), or \"BAAD\". BAAD is written IN PLACE OF the original signature when a fix-up check fails, i.e. when an incomplete multi-sector transfer was detected — so a carver keyed on the literal \"FILE\" string skips exactly the torn-write records, which are the ones worth looking at",
        is_uid_component: true,
    },
    FieldSchema {
        name: "fixup_values_offset",
        value_type: ValueType::UnsignedInt,
        description: "Offset of the fix-up (update sequence) array, as a 16-bit value at record offset 0x04, relative to the start of the record. Read the array from here rather than assuming a constant — it moved between NTFS versions (the NT4 1.2 MFT entry header is 42 bytes, later ones 48)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fixup_values_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of 16-bit ELEMENTS in the fix-up array, at record offset 0x06 — elements, not bytes, and the count INCLUDES the placeholder itself, so the number of fix-ups is count minus 1. The identity is count == 1 + (record size / 512): a 1024-byte MFT entry gives 3, a 4096-byte INDX gives 9. Treating it as a byte count (which some older documentation does) mis-sizes the array and corrupts the read",
        is_uid_component: false,
    },
    FieldSchema {
        name: "update_sequence_number",
        value_type: ValueType::UnsignedInt,
        description: "The placeholder value — the first element of the array. It is a cyclic counter of how many times the record has been written to disk (0 and 0xFFFF are not used). Before each write NTFS stamps this value over the LAST TWO BYTES OF EVERY 512-byte sector of the record; on read, all of those trailing values must equal it, and any that does not means the write was torn mid-transfer",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fixup_original_values",
        value_type: ValueType::Bytes,
        description: "The remaining array elements: the ORIGINAL two bytes displaced from the end of each sector, in sector order. Applying the fix-up means writing element N back over the last two bytes of sector N — at 0x1FE, 0x3FE, 0x5FE, ... A record read without this step is silently wrong by 2 bytes per 512-byte sector, wherever those offsets happen to land inside an attribute",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fixups_applied",
        value_type: ValueType::Bool,
        description: "DERIVED (not stored): whether this record's fix-ups were verified and reversed before its contents were interpreted. Record it per record, because it is the accept/reject test that splits carver output — a record whose trailing sector values all match the placeholder is a complete write and can be trusted; one that does not is a detected torn write (the condition NTFS marks BAAD)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "array_bounds_valid",
        value_type: ValueType::Bool,
        description: "DERIVED sanity check on the header before the array is trusted: the record size must be a whole number of 512-byte sectors, the array offset must be even, the count must equal 1 + (size / 512), and the array must end before the last 16-bit value of the FIRST sector (offset + count*2 <= 510). A fragment failing these is a false positive from the signature scan, not a damaged record",
        is_uid_component: false,
    },
];

/// NTFS multi-sector fix-ups (update sequence array) and the BAAD signature.
///
/// Every multi-sector NTFS structure — the MFT FILE record, the INDX index
/// allocation block, and the RSTR/RCRD pages of $LogFile — is protected against
/// torn writes by the same mechanism. Before writing, NTFS increments a
/// placeholder counter, stores it as the first element of a fix-up array, and
/// stamps it over the last two bytes of every 512-byte sector in the record,
/// saving each displaced original into the following array element. On reading,
/// every sector's trailing value must equal the placeholder; if one does not,
/// the write was incomplete and the record is marked "BAAD".
///
/// This is a decode prerequisite, not a curiosity. **A tool that carves an MFT
/// or INDX record out of raw or unallocated space and reads it without
/// reversing the fix-ups produces silently wrong output** — two corrupted bytes
/// per 512-byte sector, at 0x1FE, 0x3FE and onward, landing wherever they land
/// inside an attribute. And a carver keyed on the literal "FILE" signature
/// skips every record NTFS already flagged as damaged, because their signature
/// is no longer "FILE".
///
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://github.com/tuxera/ntfs-3g/blob/edge/libntfs-3g/mst.c>
pub(crate) static NTFS_MULTI_SECTOR_FIXUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_multi_sector_fixup",
    name: "NTFS Multi-Sector Fix-Ups (Update Sequence Array) and BAAD",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$MFT"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The multi-sector transfer protection that every NTFS record header carries, and the \
decode step a carver must perform before the record's bytes mean anything. The header is a \
four-byte signature at offset 0x00 (\"FILE\" for an MFT entry, \"INDX\" for an index allocation \
block, \"RSTR\"/\"RCRD\" for $LogFile pages), a fix-up array offset at 0x04, and a count of 16-bit \
array ELEMENTS at 0x06. The count includes the placeholder itself and equals 1 + (record size / \
512) — 3 for a 1024-byte MFT entry, 9 for a 4096-byte INDX — so the number of fix-ups is count \
minus 1. On write, NTFS stamps the placeholder over the LAST TWO BYTES OF EVERY 512-byte sector \
and stores each displaced original in the array; on read, every sector's trailing value must equal \
the placeholder, and the originals are written back. TWO CONSEQUENCES DRIVE TOOLING. First, a \
record carved from raw or unallocated space and read WITHOUT reversing the fix-ups is silently \
corrupt by two bytes per 512-byte sector, at 0x1FE, 0x3FE, 0x5FE and onward — no error is raised \
and the damage falls inside whatever attribute spans the offset. Second, when the check fails NTFS \
replaces the signature with \"BAAD\", so a carver that scans for the literal string \"FILE\" skips \
precisely the records with a detected torn write; scan for BAAD and CHKD too. Whether the fix-ups \
reconciled is also the accept/reject test that separates trustworthy carved records from \
fragments. Cross-reference mft/mft_file (the records protected this way), ntfs_logfile_records \
(RSTR/RCRD pages carry the same array), and file_carving.",
    mitre_techniques: &[],
    fields: NTFS_MULTI_SECTOR_FIXUP_FIELDS,
    retention: Some("Structural — present in every multi-sector NTFS record for as long as the record exists, including in unallocated copies"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["mft", "mft_file", "ntfs_logfile_records", "file_carving"],
    sources: &[
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc (MULTI_SECTOR_HEADER: signature "FILE"/"BAAD" at 0x00, fix-up values offset at 0x04, number of fix-up values at 0x06; "on disk the last 2 bytes for each 512 bytes block is replaced by the fix-up placeholder value")
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
        // Source: https://github.com/tuxera/ntfs-3g/blob/edge/include/ntfs-3g/layout.h (NTFS_RECORD_TYPES magic_FILE/INDX/RSTR/RCRD/CHKD/BAAD; struct NTFS_RECORD usa_ofs/usa_count, "the number of fixups is the usa_count minus 1"; NTFS_BLOCK_SIZE 512)
        "https://github.com/tuxera/ntfs-3g/blob/edge/include/ntfs-3g/layout.h",
        // Source: https://github.com/tuxera/ntfs-3g/blob/edge/libntfs-3g/mst.c (ntfs_mst_post_read_fixup: is_valid_record requires usa_count == 1 + size/512 and usa_ofs + usa_count*2 <= 510; sets the magic to BAAD when a sector's trailing value does not match the USN)
        "https://github.com/tuxera/ntfs-3g/blob/edge/libntfs-3g/mst.c",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "BAAD records the file system's own detection of an incomplete multi-sector transfer — a storage-integrity event. It is not by itself evidence of tampering and should not be reported as one",
        "The 512-byte stride is the logical sector size NTFS uses for this protection, independent of the physical sector size of the media; do not recompute it from the drive's reported geometry",
        "Reconciled fix-ups prove the record was written completely, not that its contents are truthful — a timestomped record fixes up perfectly",
        "A fragment that passes a signature scan but fails the header bounds checks (size not a multiple of 512, count != 1 + size/512, array running past offset 510) is a false positive, not a damaged record; report the two cases differently",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "The fix-up array is part of every multi-sector record's own bytes, so it survives wherever the record survives, including in unallocated space",
};

// ── $UsnJrnl:$J — the full USN_RECORD_V2 Reason bitmask ─────────────────────

/// Field schema for the USN change-journal reason bitmask, decomposed.
///
/// `USN_RECORD_V2.Reason` is a single 32-bit field. The fields below group the
/// 23 documented `USN_REASON_*` flags by what an analyst uses them for; every
/// value is the constant Microsoft documents for the `Reason` member.
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>
pub(crate) static NTFS_USN_REASON_FLAGS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "reason",
        value_type: ValueType::UnsignedInt,
        description: "The raw 32-bit Reason value. IT ACCUMULATES: Microsoft defines it as the reasons that have built up for this file since it was opened, so the flags OR together across the life of the handle and a closing record commonly carries several at once — the final record of an ordinary file creation is FILE_CREATE|DATA_EXTEND|CLOSE = 0x80000102, not 0x100. Always test with a bitwise AND; an equality test against a single flag silently discards most real events",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_close",
        value_type: ValueType::Bool,
        description: "USN_REASON_CLOSE (0x80000000) — the file or directory was closed. This is the terminator: Microsoft specifies that a final record is generated with CLOSE set when the handle closes, and that the next change starts a new record with a new set of reason flags. The CLOSE record therefore carries the accumulated summary of what happened and is the natural unit to reason about, rather than the intermediate records",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_data",
        value_type: ValueType::Text,
        description: "Unnamed ($DATA) stream content changes: DATA_OVERWRITE 0x00000001 (data overwritten in place), DATA_EXTEND 0x00000002 (file extended), DATA_TRUNCATION 0x00000004 (file truncated). DATA_OVERWRITE together with DATA_EXTEND and DATA_TRUNCATION on one entry is the shape of a wipe-then-shrink pass, which is what an overwriting tool does to a file's contents before unlinking it — whereas a plain delete touches no data flag at all",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_named_data",
        value_type: ValueType::Text,
        description: "Alternate data stream (named $DATA) content changes: NAMED_DATA_OVERWRITE 0x00000010, NAMED_DATA_EXTEND 0x00000020, NAMED_DATA_TRUNCATION 0x00000040. These are distinct flags from the unnamed-stream trio above, so ADS writes are separable from ordinary file writes. Data hidden in an ADS appears here and nowhere in the file's visible size — pair with STREAM_CHANGE, which records the stream being added",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_namespace",
        value_type: ValueType::Text,
        description: "Name and existence changes: FILE_CREATE 0x00000100, FILE_DELETE 0x00000200, RENAME_OLD_NAME 0x00001000, RENAME_NEW_NAME 0x00002000, HARD_LINK_CHANGE 0x00010000. Microsoft specifies that a rename or move generates TWO records — one recording the old parent directory, one the new — so the OLD_NAME/NEW_NAME pair on a single MFT entry reconstructs a rename and the parent references in each reconstruct a move. HARD_LINK_CHANGE means another directory entry now points at the same file, one way to keep content reachable after the visible name is deleted",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_metadata",
        value_type: ValueType::Text,
        description: "Metadata changes that do not touch content: BASIC_INFO_CHANGE 0x00008000 (a file attribute — read-only, hidden, system, archive, sparse — OR ONE OR MORE TIMESTAMPS changed; this is the flag that records a timestomp, and it fires with no data flag set), EA_CHANGE 0x00000400 (extended attributes), SECURITY_CHANGE 0x00000800 (access rights changed — join to $Secure:$SDS for what they became), INDEXABLE_CHANGE 0x00004000 (the content-indexing attribute was toggled), OBJECT_ID_CHANGE 0x00080000 (the object identifier changed)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "reason_storage",
        value_type: ValueType::Text,
        description: "Storage-form and stream-shape changes: STREAM_CHANGE 0x00200000 (a named stream was ADDED TO, removed from, or renamed on the file — ADS creation shows as STREAM_CHANGE followed by NAMED_DATA_EXTEND as the stream is filled), REPARSE_POINT_CHANGE 0x00100000 (a reparse point was set, changed or removed, covering symlink and junction redirection), COMPRESSION_CHANGE 0x00020000, ENCRYPTION_CHANGE 0x00040000 (the file was encrypted or decrypted), TRANSACTED_CHANGE 0x00400000 (modified through a TxF transaction), INTEGRITY_CHANGE 0x00800000 (the integrity-stream attribute changed)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "source_info",
        value_type: ValueType::UnsignedInt,
        description: "A SEPARATE field from Reason (USN_RECORD_V2.SourceInfo), set by the writer via FSCTL_MARK_HANDLE, saying the change came from the system rather than a user: USN_SOURCE_DATA_MANAGEMENT 0x00000001 (an OS-driven move such as hierarchical storage — Microsoft notes such a move adds DATA_OVERWRITE although the data did not change from the user's point of view), USN_SOURCE_AUXILIARY_DATA 0x00000002 (a private stream added by something like an antivirus checksum), USN_SOURCE_REPLICATION_MANAGEMENT 0x00000004, USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT 0x00000008 (cloud sync). Check it before attributing a write to a person — it is the documented way to separate housekeeping from user activity",
        is_uid_component: false,
    },
];

/// $UsnJrnl:$J — the full USN_RECORD_V2 Reason bitmask.
///
/// The `Reason` member of a USN record is a 32-bit bitmask of 23 documented
/// `USN_REASON_*` flags, and two properties of it decide whether an analysis
/// works at all.
///
/// It **accumulates**: Microsoft defines `Reason` as the reasons that have built
/// up since the file was opened, so flags OR together and the closing record
/// carries the summary. An ordinary file creation closes as
/// `FILE_CREATE|DATA_EXTEND|CLOSE` (0x80000102), so a filter written as
/// `reason == 0x100` finds almost nothing. Test with a bitwise AND.
///
/// And `USN_REASON_CLOSE` (0x80000000) is the **terminator** — a final record is
/// emitted when the handle closes, and the next change begins a fresh record
/// with a new flag set, which makes the CLOSE record the natural unit of
/// analysis.
///
/// The flags beyond create/delete/rename are where the detections live:
/// `BASIC_INFO_CHANGE` fires when a timestamp is rewritten with no data flag
/// set; `STREAM_CHANGE` plus `NAMED_DATA_EXTEND` is an alternate data stream
/// being created and filled; `DATA_OVERWRITE` with `DATA_TRUNCATION` is content
/// being destroyed rather than merely unlinked.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>
pub(crate) static NTFS_USN_REASON_FLAGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_usn_reason_flags",
    name: "USN Change Journal Reason Bitmask (USN_RECORD_V2.Reason)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$Extend\\$UsnJrnl:$J"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The complete decode of USN_RECORD_V2.Reason — the 32-bit bitmask that says WHAT \
happened to a file, and the field most change-journal analysis is actually built on. Two \
properties come first. (1) IT ACCUMULATES. Microsoft defines Reason as the reasons that have built \
up for the file since it was opened, so flags OR together over the life of the handle: an ordinary \
file creation closes as FILE_CREATE|DATA_EXTEND|CLOSE = 0x80000102, and a filter written as \
'reason == 0x100' silently misses it. Test with a bitwise AND, always. (2) USN_REASON_CLOSE \
(0x80000000) IS THE TERMINATOR — a final record is generated when the file or directory closes, \
and the next change starts a new record with a new set of flags, so the CLOSE record carries the \
accumulated summary and is the natural unit of analysis. The 23 documented flags: DATA_OVERWRITE \
0x00000001, DATA_EXTEND 0x00000002, DATA_TRUNCATION 0x00000004, NAMED_DATA_OVERWRITE 0x00000010, \
NAMED_DATA_EXTEND 0x00000020, NAMED_DATA_TRUNCATION 0x00000040, FILE_CREATE 0x00000100, \
FILE_DELETE 0x00000200, EA_CHANGE 0x00000400, SECURITY_CHANGE 0x00000800, RENAME_OLD_NAME \
0x00001000, RENAME_NEW_NAME 0x00002000, INDEXABLE_CHANGE 0x00004000, BASIC_INFO_CHANGE 0x00008000, \
HARD_LINK_CHANGE 0x00010000, COMPRESSION_CHANGE 0x00020000, ENCRYPTION_CHANGE 0x00040000, \
OBJECT_ID_CHANGE 0x00080000, REPARSE_POINT_CHANGE 0x00100000, STREAM_CHANGE 0x00200000, \
TRANSACTED_CHANGE 0x00400000, INTEGRITY_CHANGE 0x00800000, CLOSE 0x80000000. The detections that \
matter live in the flags past create/delete/rename: BASIC_INFO_CHANGE fires when an attribute or \
ONE OR MORE TIMESTAMPS is rewritten, so a timestomp appears as BASIC_INFO_CHANGE with no data flag \
set; STREAM_CHANGE (a named stream added, removed or renamed) followed by NAMED_DATA_EXTEND is an \
alternate data stream being created and filled; DATA_OVERWRITE together with DATA_TRUNCATION is \
content destroyed in place rather than merely unlinked; SECURITY_CHANGE marks an access-rights \
edit, resolvable against $Secure:$SDS. Check SourceInfo before attributing any of it to a person — \
it is the documented marker for OS-driven changes such as replication and cloud sync. \
Cross-reference usnjrnl (the record stream), ntfs_usnjrnl_max (the retention window), \
ntfs_timestomping_si_fn (the $SI/$FN cross-view BASIC_INFO_CHANGE points at), and \
ntfs_sdelete_rename_chain (a named pattern built from these flags).",
    mitre_techniques: &[
        "T1070.004", // Indicator Removal: File Deletion
        "T1070.006", // Indicator Removal: Timestomp (BASIC_INFO_CHANGE)
        "T1564.004", // Hide Artifacts: NTFS File Attributes (STREAM_CHANGE / NAMED_DATA_*)
        "T1036.003", // Masquerading: Rename System Utilities (RENAME_OLD_NAME/NEW_NAME)
        "T1485",     // Data Destruction (DATA_OVERWRITE|DATA_TRUNCATION)
    ],
    fields: NTFS_USN_REASON_FLAGS_FIELDS,
    retention: Some("As long as the record survives in $UsnJrnl:$J — a rolling window bounded by the journal's configured maximum size (read it from $Max, or `fsutil usn queryjournal`)"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "usnjrnl",
        "usn_journal",
        "ntfs_usnjrnl_max",
        "ntfs_timestomping_si_fn",
        "ntfs_sdelete_rename_chain",
        "ntfs_ads",
        "ntfs_secure_sds",
    ],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2 (the authoritative USN_REASON_* constant list and values; the Reason member's accumulate-until-CLOSE semantics; the two-record rename rule; SourceInfo and the USN_SOURCE_* values)
        "https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2",
        // Source: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn (fsutil usn readjournal / enumdata / queryjournal — reading the records these flags live in)
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Reason accumulates per open handle, so a flag on a record says the reason occurred at some point in that handle's life — not that it happened at the instant of that record's TimeStamp",
        "A flag records that a CLASS of change occurred, never its content: BASIC_INFO_CHANGE does not say which attribute or timestamp moved, and SECURITY_CHANGE does not say to what. Resolve the value elsewhere ($MFT, $Secure:$SDS) before stating it",
        "BASIC_INFO_CHANGE is generated by ordinary activity — setting the archive bit, toggling read-only, an installer stamping attributes — so it is a lead, not a timestomping finding",
        "SourceInfo can mark a change as system-driven (replication, cloud sync, storage management); ignoring it attributes routine housekeeping to a user",
        "The journal can be deleted and recreated by an administrator, which restarts the record history; check the journal identifier in $Max before treating a gap as inactivity",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "The flags live in $UsnJrnl:$J records, which age out of the journal's rolling window as the head is deallocated",
};

// ── $Extend\$UsnJrnl:$Max — journal configuration and retention bound ────────

/// Field schema for the `$UsnJrnl:$Max` configuration stream.
///
/// The on-disk `$Max` stream is 32 bytes: maximum size (offset 0), allocation
/// delta (offset 8) and the journal identifier (offset 16); the remaining 8
/// bytes are unused. The trailing fields below are NOT in the stream — they come
/// from querying a live volume (`FSCTL_QUERY_USN_JOURNAL` / `fsutil usn
/// queryjournal`) and are marked as such.
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v2>
pub(crate) static NTFS_USNJRNL_MAX_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "usn_journal_id",
        value_type: ValueType::UnsignedInt,
        description: "The 64-bit journal identifier at $Max offset 16. A journal is assigned a new identifier when it is created and stamped with a new one if it is recreated — which is the ANTI-FORENSIC TELL: an identifier that differs from one cached or recorded earlier means the journal was deleted and remade, every prior USN was invalidated, and the record history restarts from that point. The libyal NTFS documentation records this field as holding a FILETIME-shaped value",
        is_uid_component: true,
    },
    FieldSchema {
        name: "maximum_size",
        value_type: ValueType::UnsignedInt,
        description: "Target maximum journal size in bytes, at $Max offset 0 (set by `fsutil usn createjournal m=<maxsize>`). This is the number that bounds retention — read it off the evidence instead of quoting a default. It is a target, not a hard cap: Microsoft documents that the journal may grow past it and is truncated at the next NTFS checkpoint, and that NTFS trims it once its size exceeds maximum_size plus allocation_delta",
        is_uid_component: false,
    },
    FieldSchema {
        name: "allocation_delta",
        value_type: ValueType::UnsignedInt,
        description: "Bytes added to the end and removed from the beginning of the journal per allocation step, at $Max offset 8 (`fsutil usn createjournal a=<allocationdelta>`). This is the quantum in which the journal grows and shrinks — and it explains where deleted USN records go: $J is a sparse stream, NTFS appends at the tail and deallocates from the head in these units, replacing the head with a sparse run. The clusters released that way are unallocated space still holding parsable USN records, so this value governs how much carving yield to expect",
        is_uid_component: false,
    },
    FieldSchema {
        name: "first_usn",
        value_type: ValueType::UnsignedInt,
        description: "LIVE QUERY ONLY (USN_JOURNAL_DATA, from FSCTL_QUERY_USN_JOURNAL / `fsutil usn queryjournal`) — not present in the $Max stream. The number of the first record that can still be read from the journal, i.e. the current head of the retained window",
        is_uid_component: false,
    },
    FieldSchema {
        name: "next_usn",
        value_type: ValueType::UnsignedInt,
        description: "LIVE QUERY ONLY — the number of the next record to be written. With first_usn it brackets the window that actually survives on the volume, turning the retention caveat into a measured range",
        is_uid_component: false,
    },
    FieldSchema {
        name: "lowest_valid_usn",
        value_type: ValueType::UnsignedInt,
        description: "LIVE QUERY ONLY — the first record written for THIS journal instance. Microsoft states the corroborating rule explicitly: if enumeration returns a USN below this value, the journal has been stamped with a new identifier since that USN was written, and lowest_valid_usn marks a DISCONTINUITY across which changes to some or all files may simply not have been recorded. That is a second, independent route to detecting journal recreation",
        is_uid_component: false,
    },
    FieldSchema {
        name: "max_usn",
        value_type: ValueType::UnsignedInt,
        description: "LIVE QUERY ONLY — the largest USN the change journal supports; an administrator must delete the journal as next_usn approaches it. Useful for bounding, not for dating",
        is_uid_component: false,
    },
];

/// `$Extend\$UsnJrnl:$Max` — USN change journal configuration.
///
/// `$Max` is the 32-byte configuration stream beside the `$J` record stream, and
/// it answers two questions `$J` cannot.
///
/// **Was the journal deleted and recreated?** A journal gets a new identifier on
/// creation and can be re-stamped, and re-stamping invalidates every cached USN
/// and restarts the record history. Comparing the identifier against an earlier
/// one — or, on a live volume, seeing an enumerated USN fall below
/// `LowestValidUsn` — detects that. The deletion itself is expensive and noisy:
/// Microsoft notes the system must walk the whole MFT setting each record's last
/// USN attribute to zero, which can run for minutes and continue past a restart.
///
/// **How far back does the journal reach?** `MaximumSize` and `AllocationDelta`
/// bound retention per volume, so an absence argument can be stated rather than
/// assumed. They also explain carving yield: `$J` is sparse, NTFS appends at the
/// tail and deallocates the head in allocation-delta units, and the clusters
/// released still hold parsable USN records in unallocated space.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v2>
/// Source: <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn>
pub(crate) static NTFS_USNJRNL_MAX: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_usnjrnl_max",
    name: "USN Change Journal Configuration ($Extend\\$UsnJrnl:$Max)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$Extend\\$UsnJrnl:$Max"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The 32-byte configuration stream that sits beside $UsnJrnl:$J and answers the two \
questions the record stream cannot. LAYOUT: maximum size at offset 0 (8 bytes), allocation delta \
at offset 8 (8 bytes), journal identifier at offset 16 (8 bytes), remainder unused. (1) WAS THE \
JOURNAL DELETED AND RECREATED? A journal is assigned an identifier on creation and stamped with a \
new one if it is remade, and a new identifier invalidates every previously cached USN and restarts \
the record history — so an identifier differing from one recorded earlier is evidence of journal \
destruction, an anti-forensic act rather than a wrap. On a live volume the same conclusion is \
reachable a second way: Microsoft specifies that an enumerated USN below LowestValidUsn means the \
journal has been re-stamped, and marks a discontinuity in which changes to some or all files went \
unrecorded. Deleting a journal is also expensive and observable in its own right — the system must \
walk every MFT record setting its last USN attribute to zero, which can take minutes and continue \
after a restart. (2) HOW FAR BACK DOES IT REACH? MaximumSize (set by `fsutil usn createjournal \
m=`) is the target size and AllocationDelta (`a=`) the quantum in which the journal grows and \
shrinks; Microsoft notes the journal can exceed the target and is truncated at the next NTFS \
checkpoint, once its size passes MaximumSize plus AllocationDelta. Together they let an examiner \
state the retention window FOR THE VOLUME IN EVIDENCE rather than quote a default, which is what \
makes any 'it is not in the journal' argument defensible. AllocationDelta also predicts carving \
yield: $J is a sparse stream, NTFS appends at the tail and deallocates the head in these units, \
replacing it with a sparse run — the released clusters are unallocated space that still holds \
parsable USN records. FirstUsn / NextUsn / LowestValidUsn / MaxUsn are NOT in this stream; they \
come from FSCTL_QUERY_USN_JOURNAL (`fsutil usn queryjournal`) on a live volume. Cross-reference \
usnjrnl and ntfs_usn_reason_flags.",
    mitre_techniques: &[
        "T1070",     // Indicator Removal on Host (journal deletion)
        "T1070.004", // Indicator Removal: File Deletion
    ],
    fields: NTFS_USNJRNL_MAX_FIELDS,
    retention: Some("Persistent while the journal exists — the stream is rewritten on creation or reconfiguration and removed when the journal is deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["usnjrnl", "usn_journal", "ntfs_usn_reason_flags", "mft"],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v2 (UsnJournalID re-stamping and its integrity-check role; the LowestValidUsn discontinuity rule; MaximumSize as a target truncated at the next checkpoint; AllocationDelta as the add-to-tail / remove-from-head unit)
        "https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v2",
        // Source: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn (createjournal m=/a=, deletejournal, queryjournal; trimming once the size exceeds maxsize + allocationdelta; deletion walks the MFT setting each record's last USN attribute to zero)
        "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn",
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc ($UsnJrnl:$Max on-disk layout — 32 bytes: maximum size at 0, allocation delta at 8, journal identifier at 16; $J is sparse and the earliest entries are replaced with a sparse data run)
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "A changed journal identifier proves the journal was recreated, not who did it or why — enabling a service, a volume operation, or an OS action can also recreate a journal",
        "MaximumSize is a target, not a ceiling: the journal can exceed it between NTFS checkpoints, so a retention estimate derived from it is a bound and should be reported as one",
        "$Max records the configuration in force when it was last written; it does not record earlier configurations, so a journal reconfigured mid-incident shows only the current values",
        "FirstUsn / NextUsn / LowestValidUsn / MaxUsn are live-query values, absent from a dead-box image — do not report them as read from $Max",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "$Max persists unchanged for the life of the journal; it is rewritten only on journal creation or reconfiguration",
};

// ── $Secure:$SDS — shared security descriptors ──────────────────────────────

/// Field schema for a `$Secure:$SDS` security-descriptor entry.
///
/// `$Secure` is MFT entry 9. Its `$SDS` data stream holds every security
/// descriptor on the volume, each preceded by a header of hash, security
/// identifier, offset within `$SDS` and entry size, followed by the
/// self-relative security descriptor itself. The `$SDH` (hash) and `$SII`
/// (identifier) indexes are the lookup paths into it. The join key from a file
/// is the $STANDARD_INFORMATION security identifier at $SI offset 52 (0x34).
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
pub(crate) static NTFS_SECURE_SDS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "security_id",
        value_type: ValueType::UnsignedInt,
        description: "The security descriptor identifier — THE JOIN KEY. It is stored per file in $STANDARD_INFORMATION at $SI OFFSET 52 (0x34), in the NTFS 3.0+ portion of the 72-byte attribute, and it indexes into $Secure via the $SII index. That join is what turns an MFT record from a name and four timestamps into an owner and an access-control list; without it the $MFT says nothing about who could reach the file",
        is_uid_component: true,
    },
    FieldSchema {
        name: "security_descriptor_hash",
        value_type: ValueType::UnsignedInt,
        description: "Hash of the descriptor, stored alongside the identifier in the $SDS entry header and used as the $SDH index key. It is how NTFS de-duplicates: identical descriptors collapse to one $SDS entry shared by every file that uses it, which is why one security_id commonly covers a whole directory tree",
        is_uid_component: false,
    },
    FieldSchema {
        name: "sds_offset",
        value_type: ValueType::UnsignedInt,
        description: "The entry's own offset within the $SDS stream, recorded in its header and in both index values. Being self-referential, it doubles as a consistency check when an entry is recovered from a fragment — an entry whose recorded offset does not match where it was found came from somewhere else, e.g. a superseded copy",
        is_uid_component: false,
    },
    FieldSchema {
        name: "entry_size",
        value_type: ValueType::UnsignedInt,
        description: "Size of the $SDS entry, header included, from the entry header and the index values. Needed to walk the stream, since entries are variable-length and padded for alignment",
        is_uid_component: false,
    },
    FieldSchema {
        name: "owner_sid",
        value_type: ValueType::Text,
        description: "Owner SID from the self-relative security descriptor that follows the entry header — the account that owns the file. Resolve against the SAM or Active Directory for a name; an unresolvable SID is itself informative (a deleted local account, or a domain principal not present on this host)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "group_sid",
        value_type: ValueType::Text,
        description: "Primary group SID from the same security descriptor",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dacl",
        value_type: ValueType::Text,
        description: "Discretionary access control list — the ordered ACEs granting or denying access, each with a trustee SID and an access mask. This is where permission weakening shows: a grant of full control to Everyone or Authenticated Users on a sensitive path, or an inherited ACE replaced by an explicit one",
        is_uid_component: false,
    },
    FieldSchema {
        name: "sacl",
        value_type: ValueType::Text,
        description: "System access control list — the audit ACEs that decide which accesses generate Security-log object-access events. Removing SACL entries suppresses auditing for a path while leaving access itself unchanged, so an absent SACL where policy expects one is worth stating",
        is_uid_component: false,
    },
    FieldSchema {
        name: "superseded",
        value_type: ValueType::Bool,
        description: "DERIVED (not stored): whether this entry is still referenced by any live MFT record. $SDS IS APPEND-ONLY — a permission change writes a NEW descriptor entry and repoints the file's security_id, it does not edit the old one. Unreferenced entries are therefore PRIOR states of an ACL, still present in the stream, which is what makes an access-control change recoverable from a dead-box image at all",
        is_uid_component: false,
    },
];

/// `$Secure:$SDS` — the shared security-descriptor stream, with `$SDH` / `$SII`.
///
/// `$Secure` is MFT entry 9, and it is where every security descriptor on the
/// volume actually lives. A file's $STANDARD_INFORMATION carries only a 32-bit
/// security identifier at $SI offset 52 (0x34); `$SDS` holds the descriptor that
/// identifier points at, and the `$SII` (by identifier) and `$SDH` (by hash)
/// indexes are the two lookup paths. Descriptors are de-duplicated by hash, so
/// one entry is typically shared by many files.
///
/// Two capabilities follow. Resolving the join turns an MFT record into an owner
/// SID and a DACL/SACL — otherwise an examiner can say a file existed but not
/// who could reach it. And because **`$SDS` is append-only**, a permission change
/// writes a new entry and repoints the file rather than editing the old one, so
/// superseded descriptors remain in the stream and a historical ACL is
/// recoverable from a dead-box image.
///
/// Source: <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20>(NTFS).asciidoc
pub(crate) static NTFS_SECURE_SDS: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_secure_sds",
    name: "NTFS Security Descriptors ($Secure:$SDS, $SDH / $SII)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$Secure:$SDS"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The volume's shared security-descriptor store — who owns each file and who may reach \
it. $Secure is MFT entry 9 and holds three streams: the $SDS data stream containing every security \
descriptor on the volume, the $SII index mapping a security descriptor identifier to that \
descriptor's offset and size in $SDS, and the $SDH index doing the same by descriptor hash. Each \
$SDS entry begins with a header of hash, security identifier, offset within $SDS and entry size, \
followed by the self-relative security descriptor (owner SID, group SID, DACL, SACL). THE JOIN KEY \
IS IN THE MFT: $STANDARD_INFORMATION carries a 32-bit security descriptor identifier at $SI OFFSET \
52 (0x34), in the NTFS 3.0+ portion of the 72-byte attribute. Resolving it is what turns an MFT \
record from a name and four timestamps into an owner and an access-control list — without it an \
examiner can establish that a file existed but not who could reach it. Descriptors are \
de-duplicated by hash, so one entry is typically shared across a directory tree and a single \
changed security_id on one file stands out. $SDS IS APPEND-ONLY: changing a file's permissions \
writes a NEW descriptor entry and repoints the file's security_id rather than editing the existing \
one, so superseded descriptors persist in the stream and the PRIOR state of an ACL is recoverable \
from a dead-box image — the route to showing that access was widened (a grant to Everyone or \
Authenticated Users on a sensitive path) or that auditing was weakened (SACL entries removed, \
suppressing Security-log object-access events for that path). Cross-reference mft/mft_file (the \
records carrying the identifier), ntfs_timestomping_si_fn (the same $SI attribute), and \
ntfs_usn_reason_flags (USN_REASON_SECURITY_CHANGE 0x800 records WHEN rights changed, while $SDS \
records what they became).",
    mitre_techniques: &[
        "T1222.001", // File and Directory Permissions Modification: Windows
        "T1562.002", // Impair Defenses: Disable Windows Event Logging (SACL removal)
        "T1070",     // Indicator Removal on Host
    ],
    fields: NTFS_SECURE_SDS_FIELDS,
    retention: Some("Append-only for the life of the volume: entries persist after the files referencing them are deleted and after the permissions they describe are superseded"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "mft",
        "mft_file",
        "ntfs_timestomping_si_fn",
        "ntfs_usn_reason_flags",
        "usnjrnl",
    ],
    sources: &[
        // Source: https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc ($Secure = MFT entry 9 with the $SDS data stream, $SDH hash index and $SII identifier index; the $SDS entry header fields — hash, security descriptor identifier, data offset in $SDS, data size; $STANDARD_INFORMATION security descriptor identifier at offset 52)
        "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
        // Source: https://github.com/libyal/libfwnt/blob/main/documentation/Security%20Descriptor.asciidoc (the self-relative security descriptor an $SDS entry contains — owner SID, group SID, DACL, SACL and the ACE layouts)
        "https://github.com/libyal/libfwnt/blob/main/documentation/Security%20Descriptor.asciidoc",
        // Source: https://github.com/tuxera/ntfs-3g/blob/edge/include/ntfs-3g/layout.h (FILE_Secure = 9 in NTFS_SYSTEM_FILES; the $SII index sorts by security identifier and $SDH by hash)
        "https://github.com/tuxera/ntfs-3g/blob/edge/include/ntfs-3g/layout.h",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "$SDS records the descriptor, never when it was applied or by whom — date an ACL change from USN_REASON_SECURITY_CHANGE or a Security-log event, not from $SDS",
        "Because descriptors are de-duplicated by hash, an entry is shared by every file with identical permissions; an entry alone does not identify which file it describes without the reverse join from $SI security identifiers",
        "A superseded entry proves a descriptor once existed on the volume, not that any particular file carried it — the identifier-to-file mapping survives only for files whose MFT record still holds the old identifier",
        "Group memberships are not in the descriptor: an ACE grants to a SID, so effective access still depends on SAM/AD group data that is not on this volume",
        "Permissive ACLs are routine on many paths (shared data, public temp directories, installer staging) — the finding is a change on a sensitive path, not a permissive ACL as such",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "$Secure is present on every NTFS volume and its $SDS stream is append-only, so entries accumulate rather than being overwritten",
};

// ── SDelete rename chain (secure-delete signature in $UsnJrnl) ──────────────

/// Field schema for the SDelete file-wiping signature in the USN change journal.
///
/// Microsoft documents the behaviour that produces it: to overwrite the name of
/// a file it deletes, SDelete renames the file 26 times, each rename replacing
/// every character of the name with a successive alphabetic character (the first
/// rename of `foo.txt` becomes `AAA.AAA`).
/// Source: <https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>
pub(crate) static NTFS_SDELETE_RENAME_CHAIN_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "mft_record",
        value_type: ValueType::UnsignedInt,
        description: "The MFT entry number the whole chain belongs to. THE PATTERN IS PER-ENTRY: group USN records by file reference, then look for the ladder. Twenty-six renames spread across different entries is ordinary churn; twenty-six on ONE entry, in sequence, is the signature",
        is_uid_component: true,
    },
    FieldSchema {
        name: "original_name",
        value_type: ValueType::Text,
        description: "The file name in the FIRST RENAME_OLD_NAME record of the chain — the only place the real name survives, because the point of the renames is to overwrite it in the directory index. Recovering this is the main investigative yield: it names what was destroyed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "rename_chain",
        value_type: ValueType::List,
        description: "The ordered names from the RENAME_OLD_NAME / RENAME_NEW_NAME pairs. Microsoft documents 26 renames, each replacing EVERY character of the name with a successive letter of the alphabet — the first rename of \"foo.txt\" produces \"AAA.AAA\" — so the chain is a monotone alphabet ladder in which every name keeps the length shape of the original and carries a single repeated letter advancing A, B, C, ... That shape, not the count alone, is what makes the match specific",
        is_uid_component: false,
    },
    FieldSchema {
        name: "rename_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of rename pairs observed on the entry. Twenty-six is the documented figure; expect FEWER in practice, because the journal may have wrapped mid-chain or the volume may have been imaged partway through. Treat a truncated ladder as a partial match to corroborate, not as a non-match",
        is_uid_component: false,
    },
    FieldSchema {
        name: "wipe_reason_flags",
        value_type: ValueType::UnsignedInt,
        description: "The USN reason flags on the records preceding the ladder — the data-layer wipe. Overwriting the file's contents sets DATA_OVERWRITE (0x00000001), and passes that change the length add DATA_EXTEND (0x00000002) or DATA_TRUNCATION (0x00000004). Content destruction followed by a rename ladder on the same entry is the two-layer shape; a plain delete sets no data flag at all",
        is_uid_component: false,
    },
    FieldSchema {
        name: "final_delete",
        value_type: ValueType::Bool,
        description: "Whether the chain terminates in FILE_DELETE (0x00000200), normally with CLOSE (0x80000000) set on the same accumulated record. This is the chain's end marker and the point to date the destruction from",
        is_uid_component: false,
    },
    FieldSchema {
        name: "deletion_time",
        value_type: ValueType::Timestamp,
        description: "USN_RECORD_V2.TimeStamp (a FILETIME) of the terminating FILE_DELETE record — when the file ceased to exist. The chain's first and last timestamps also bracket how long the wipe took, which separates a single targeted file from a bulk run",
        is_uid_component: false,
    },
    FieldSchema {
        name: "tool_execution_evidence",
        value_type: ValueType::Text,
        description: "SEPARATE SOURCES (not the journal): execution artifacts for the tool itself — Prefetch, ShimCache/AmCache, console history, a service installation. SDelete is distributed by Microsoft as part of Sysinternals, so it is a legitimately obtainable, publisher-trusted utility that allow-listing by publisher will not block; its presence is not anomalous on its own, and the journal pattern is what makes the use evidential",
        is_uid_component: false,
    },
];

/// SDelete secure-delete rename chain — the wipe signature in `$UsnJrnl`.
///
/// Microsoft documents SDelete's name-overwriting behaviour precisely: to
/// destroy the file name as well as the data, it **renames the file 26 times,
/// each rename replacing every character of the name with a successive
/// alphabetic character** — the first rename of `foo.txt` becomes `AAA.AAA`.
///
/// Those renames are file-system operations, so each lands in the change journal
/// as a `RENAME_OLD_NAME` / `RENAME_NEW_NAME` pair against a single MFT entry.
/// The resulting pattern — data-layer overwrite, then a monotone alphabet ladder
/// of names, then `FILE_DELETE|CLOSE` — is narrow enough to be a detection, and
/// it **survives the wipe by construction**: the tool destroys the file's
/// contents and its directory entry, but every step is recorded in a journal it
/// does not touch. The first `RENAME_OLD_NAME` record is usually the only
/// surviving copy of the real name.
///
/// SDelete is a Microsoft-distributed Sysinternals utility, so it is a
/// living-off-the-land candidate: publisher-based allow-listing does not stop
/// it, and its presence alone is unremarkable.
///
/// Source: <https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete>
pub(crate) static NTFS_SDELETE_RENAME_CHAIN: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntfs_sdelete_rename_chain",
    name: "SDelete Secure-Delete Rename Chain ($UsnJrnl Signature)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$Extend\\$UsnJrnl:$J"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The USN change-journal signature of secure deletion by SDelete, and the route to \
naming a file that was wiped. Microsoft documents the behaviour that creates it: to overwrite the \
NAME of a file it deletes, SDelete renames the file 26 times, each rename replacing every \
character of the file's name with a successive alphabetic character — the first rename of \
\"foo.txt\" becomes \"AAA.AAA\". Every one of those renames is a file-system operation, so each \
lands in $UsnJrnl:$J as a RENAME_OLD_NAME (0x1000) / RENAME_NEW_NAME (0x2000) pair on a SINGLE MFT \
entry number. The full shape is three-layered: DATA_OVERWRITE (0x1), with DATA_EXTEND (0x2) or \
DATA_TRUNCATION (0x4) where a pass changes the length, as the contents are destroyed; then the \
26-step rename ladder, in which each name keeps the length shape of the original and carries a \
single repeated letter advancing A, B, C, ...; then FILE_DELETE (0x200) with CLOSE (0x80000000). \
It is specific because the ladder's monotone alphabet structure is not something ordinary activity \
produces, and it SURVIVES THE WIPE BY CONSTRUCTION — the tool overwrites the data and the \
directory entry but not the journal recording each step. The first RENAME_OLD_NAME record usually \
holds the only surviving copy of the real file name, which is the main investigative yield: the \
wipe succeeds and still tells you what was wiped. Expect fewer than 26 pairs in practice (journal \
wrap, or imaging partway through) and treat a truncated ladder as partial corroboration. SDelete \
is distributed by Microsoft as part of Sysinternals, so it is a legitimately obtainable, \
publisher-trusted binary that allow-listing by publisher will not stop — treat its presence as \
unremarkable and the journal pattern as the evidence. Note also the documented limit: SDelete \
securely deletes file data, and file names only for files it deletes directly — cleaning free \
space does not erase file names already sitting in directory free space. Cross-reference usnjrnl, \
ntfs_usn_reason_flags (the flag semantics), prefetch_file and shimcache (execution of the tool \
itself), and ntfs_logfile_records (the same renames as $LogFile transactions).",
    mitre_techniques: &[
        // Deliberately narrow. T1036.003 does not apply: the renames here are of
        // the TARGET file, not of a system utility being disguised. Nor does
        // T1218 — SDelete is downloaded, not shipped with Windows.
        "T1070.004", // Indicator Removal: File Deletion
        "T1485",     // Data Destruction
    ],
    fields: NTFS_SDELETE_RENAME_CHAIN_FIELDS,
    retention: Some("Only while the constituent USN records remain in $UsnJrnl:$J; the chain is many records long, so a wrapping journal truncates it from the front — losing the original name first"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "usnjrnl",
        "usn_journal",
        "ntfs_usn_reason_flags",
        "ntfs_logfile_records",
        "prefetch_file",
        "shimcache",
    ],
    sources: &[
        // Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete ("SDelete renames the file 26 times, each time replacing each character of the file's name with a successive alphabetic character ... the first rename of \"foo.txt\" would be to \"AAA.AAA\""; the free-space and MFT-filling behaviour; the note that SDelete securely deletes file data but not file names located in free disk space)
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2 (RENAME_OLD_NAME / RENAME_NEW_NAME, DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION, FILE_DELETE and CLOSE values; the rule that a rename generates two records)
        "https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "The pattern identifies the BEHAVIOUR, not the binary: any tool implementing the same documented rename scheme produces the same journal trace, and SDelete itself may have been renamed. Say 'consistent with SDelete-style secure deletion' unless execution artifacts corroborate the tool",
        "A truncated ladder is the normal case — the journal may have wrapped, or the image may have been taken mid-run. Fewer than 26 pairs is partial corroboration, not a refutation",
        "Secure deletion is a legitimate operation: disposal procedures, privacy policy and decommissioning all use it. Intent comes from what was wiped and when relative to other events, never from the pattern alone",
        "SDelete's free-space and MFT-filling modes leave no per-file rename chain, so absence of this pattern does not mean no secure deletion occurred on the volume",
        "On a wiped file the data is genuinely unrecoverable; this artifact recovers the NAME and the timing, and must not be reported as recovering content",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "The chain is reconstructed from many $UsnJrnl:$J records, which age out of the journal's rolling window oldest-first",
};
