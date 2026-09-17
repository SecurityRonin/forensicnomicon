//! Windows Volume Shadow Copy (VSS) snapshot-analysis descriptor.
//!
//! From Windows Vista onward, VSS stores persistent shadow copies on the local
//! NTFS volume as a catalog plus per-snapshot stores holding a differential
//! (copy-on-write) area. Recovering prior versions of files means parsing the
//! catalog (which stores each snapshot's identity), the store block descriptors
//! (which map original-volume offsets to the pre-change data blocks kept in the
//! diff area), and applying the relevant newer stores in order onto the current
//! volume. This
//! complements the registry-only `vss_files_not_to_backup` exclusion keys with
//! the on-disk store/diff-area analysis used to recover deleted or timestomped
//! prior file states.
//!
//! Field descriptions are written from the libyal libvshadow on-disk format
//! specification and the Microsoft VSS documentation (the service overview and
//! the `VSS_VOLUME_SNAPSHOT_ATTRIBUTES` enumeration in `vss.h`); no third-party
//! prose is copied.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

/// Field schema for a Volume Shadow Copy snapshot recovered via catalog + store analysis.
///
/// The snapshot identity fields (store GUID, shadow-copy set GUID, snapshot
/// context) come from the catalog entry (type 0x02) and the store information;
/// the differential-recovery fields (original/store data-block offsets) come
/// from the store block descriptors that implement copy-on-write. The attribute
/// flags at store-information offset 56 are the `VSS_VOLUME_SNAPSHOT_ATTRIBUTES`
/// (`VSS_VOLSNAP_ATTR_*`) bitmask declared in `vss.h`.
/// Source: <https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20>(VSS)%20format.asciidoc
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/vss/ne-vss-vss_volume_snapshot_attributes>
pub(crate) static VSS_SNAPSHOT_ANALYSIS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "store_guid",
        value_type: ValueType::Guid,
        description: "Store identifier GUID (catalog entry type 0x02, offset 16). This GUID names the on-disk store file that holds the snapshot's diff area",
        is_uid_component: true,
    },
    FieldSchema {
        name: "shadow_copy_guid",
        value_type: ValueType::Guid,
        description: "Shadow copy identifier GUID (store information, offset 16) — the snapshot's own identity",
        is_uid_component: true,
    },
    FieldSchema {
        name: "shadow_copy_set_guid",
        value_type: ValueType::Guid,
        description: "Shadow copy set identifier GUID (store information, offset 32) — groups snapshots created in one VSS operation",
        is_uid_component: false,
    },
    FieldSchema {
        name: "creation_time",
        value_type: ValueType::Timestamp,
        description: "Snapshot creation time (FILETIME) — the point-in-time the shadow copy represents",
        is_uid_component: false,
    },
    FieldSchema {
        name: "volume_size",
        value_type: ValueType::UnsignedInt,
        description: "Size of the original volume the snapshot was taken of (catalog entry type 0x02, offset 8)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "snapshot_context",
        value_type: ValueType::UnsignedInt,
        description: "Snapshot context value (store information, offset 48) describing how the snapshot was created (e.g. client-accessible persistent copy)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "attribute_flags",
        value_type: ValueType::UnsignedInt,
        description: "Store attribute flags (store information, offset 56) — a VSS_VOLUME_SNAPSHOT_ATTRIBUTES \
(VSS_VOLSNAP_ATTR_*) bitmask giving the snapshot's provenance: 0x00000001 PERSISTENT (survives reboot), \
0x00000004 CLIENT_ACCESSIBLE (a Previous Versions / Shared Folders copy), 0x00000008 NO_AUTO_RELEASE \
(outlives the requesting process), 0x00000010 NO_WRITERS (created without VSS writer coordination, so not a \
writer-coordinated application-consistent backup), 0x00020000 DIFFERENTIAL (copy-on-write provider), \
0x00400000 AUTORECOVER. Two stores on one volume whose flags differ were made by different mechanisms",
        is_uid_component: false,
    },
    FieldSchema {
        name: "original_block_offset",
        value_type: ValueType::UnsignedInt,
        description: "Original data-block offset (store block descriptor, offset 0), relative to the start of the volume — the location on the CURRENT volume whose prior content this descriptor preserves",
        is_uid_component: false,
    },
    FieldSchema {
        name: "store_block_offset",
        value_type: ValueType::UnsignedInt,
        description: "Store data-block offset (store block descriptor, offset 16), relative to the start of the volume — where the pre-change (copy-on-write) bytes are kept. Reconstructing snapshot-time state applies the relevant newer stores in order (most recent down to the target, respecting each descriptor's flags), not a flat overlay",
        is_uid_component: false,
    },
    FieldSchema {
        name: "block_flags",
        value_type: ValueType::UnsignedInt,
        description: "Store block descriptor flags (offset 24) governing how the block mapping is applied (e.g. whether the allocation bitmap at offset 28 is used)",
        is_uid_component: false,
    },
];

/// Volume Shadow Copy (VSS) snapshot analysis — catalog, store, and diff-area recovery.
///
/// From Windows Vista onward, VSS keeps persistent shadow copies on the local
/// NTFS volume. The on-disk structure is a catalog (16 KiB catalog blocks whose
/// type-0x02 entries name each store by GUID and record the volume size) plus,
/// per snapshot, a store holding the store information (shadow-copy and set
/// GUIDs, snapshot context, attribute flags) and a set of store block
/// descriptors that implement copy-on-write: each descriptor maps an
/// original-volume block offset to the store block that preserves that block's
/// content as it was when the snapshot was taken. Recovering a prior file
/// version means applying the relevant newer stores in order (most recent down
/// to the target snapshot, respecting each block descriptor's flags) onto the
/// current volume, so blocks changed since the snapshot resolve to their
/// preserved copy-on-write copies.
/// This exposes deleted files, pre-timestomp/pre-wipe file states, and prior
/// registry hives that exist only inside the shadow copy. The registry-only
/// `vss_files_not_to_backup` keys are the exclusion list, not the snapshot data;
/// this descriptor is the store/diff-area analysis itself.
///
/// Source: <https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20>(VSS)%20format.asciidoc
/// Source: <https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview>
pub(crate) static VSS_SNAPSHOT_ANALYSIS: ArtifactDescriptor = ArtifactDescriptor {
    id: "vss_snapshot_analysis",
    name: "Volume Shadow Copy Snapshot Analysis (VSS Store / Diff Area)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("\\System Volume Information\\{3808876b-c176-4e48-b7ae-04046e6cc752}"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "On-disk Volume Shadow Copy (VSS) analysis: recovering prior file versions by parsing \
the snapshot catalog, per-snapshot stores, and the differential (copy-on-write) area. Since Windows \
Vista, VSS persists shadow copies on the NTFS volume as a catalog (16 KiB catalog blocks; type-0x02 \
entries name each store by GUID and record the volume size) plus per-snapshot stores. A store holds \
the store information (shadow-copy identifier GUID at offset 16, shadow-copy set GUID at offset 32, \
snapshot context at offset 48, attribute flags at offset 56) and store block descriptors that \
implement copy-on-write: each descriptor maps an original-volume block offset (offset 0) to the \
store data-block offset (offset 16) preserving that block's pre-change content. Recovering a prior \
file version applies the relevant newer stores in order (most recent down to the target snapshot, \
respecting each block descriptor's flags) onto the current volume, so changed blocks resolve to \
their preserved copy-on-write copies. This recovers deleted files, pre-timestomp/pre-wipe states, \
and prior registry hives that live only inside the shadow copy. The attribute flags are a \
VSS_VOLUME_SNAPSHOT_ATTRIBUTES (VSS_VOLSNAP_ATTR_*) bitmask and carry per-snapshot provenance: \
0x00000001 PERSISTENT (persists across reboots), 0x00000002 NO_AUTORECOVERY (frozen read-only at \
creation, with no writer/application post-snapshot update), 0x00000004 CLIENT_ACCESSIBLE (a Shadow \
Copies for Shared Folders / Previous Versions copy), 0x00000008 NO_AUTO_RELEASE (not deleted when the \
requesting process ends — removal takes an explicit DeleteSnapshots call), 0x00000010 NO_WRITERS \
(created with no VSS writer involvement, so not a writer-coordinated application-consistent backup), \
0x00000020 TRANSPORTABLE, 0x00000040 NOT_SURFACED (set unless the copy is explicitly exposed or \
mounted), 0x00000080 NOT_TRANSACTED, 0x00010000 HARDWARE_ASSISTED (hardware provider), 0x00020000 \
DIFFERENTIAL (differential/copy-on-write provider — the software-provider case this descriptor \
parses), 0x00040000 PLEX (mirror-split provider), 0x00080000 IMPORTED (imported onto this machine \
rather than created on it), 0x00100000 EXPOSED_LOCALLY and 0x00200000 EXPOSED_REMOTELY (neither set \
means the copy is hidden), 0x00400000 AUTORECOVER, 0x00800000 ROLLBACK_RECOVERY (created for a \
non-backup purpose such as data mining), 0x01000000 DELAYED_POSTSNAPSHOT, 0x02000000 TXF_RECOVERY, \
0x04000000 FILE_SHARE. VSS sets most bits from the creation context, and the snapshot context at \
offset 48 is itself a combination of these bits, so the two fields corroborate each other and two \
stores on one volume with differing flags were produced by different mechanisms. Cross-reference \
vss_files_not_to_backup (the registry exclusion list, NOT the snapshot data), mft/mft_file, and \
ntfs_timestomping_si_fn (a snapshot that predates a forgery may preserve earlier timestamp state).",
    mitre_techniques: &[
        "T1490", // Inhibit System Recovery (attackers delete shadow copies)
        "T1006", // Direct Volume Access
    ],
    fields: VSS_SNAPSHOT_ANALYSIS_FIELDS,
    retention: Some("Persistent until VSS retention policy, disk-space pressure, or an attacker (vssadmin delete shadows) removes the snapshot"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["vss_files_not_to_backup", "mft", "mft_file", "ntfs_timestomping_si_fn"],
    sources: &[
        // Source: https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc (catalog 16 KiB blocks, type-0x02 entry store GUID offset 16, store information GUID offsets, store block descriptor original/store offsets)
        "https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc",
        // Source: https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview (VSS copy-on-write differential model, shadow-copy set semantics)
        "https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview",
        // Source: https://learn.microsoft.com/en-us/windows/win32/api/vss/ne-vss-vss_volume_snapshot_attributes (VSS_VOLUME_SNAPSHOT_ATTRIBUTES in vss.h — the store attribute-flag bit values and their documented meanings)
        "https://learn.microsoft.com/en-us/windows/win32/api/vss/ne-vss-vss_volume_snapshot_attributes",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "A shadow copy captures only blocks changed since the snapshot; unchanged blocks read through to the live volume, so a 'recovered' file may mix snapshot and current data if the mapping is misapplied",
        "vssadmin/wmic shadow-copy deletion (T1490) removes the diff area — absence of snapshots can itself be evidence of anti-forensics, not evidence of no prior activity",
        "Store-block offset semantics carry low-bit sub-fields (libvshadow notes bits reused for other purposes); validate the flags before trusting a raw offset",
        "Microsoft documents most VSS_VOLSNAP_ATTR_* bits as ones a requester should not set explicitly — VSS derives them from the snapshot context — so the attribute flags evidence the mechanism that created the snapshot, not an operator's stated intent",
        "The libvshadow format notes mark 0x00000002 NO_AUTORECOVERY, 0x00000080 NOT_TRANSACTED, 0x01000000 DELAYED_POSTSNAPSHOT and 0x02000000 TXF_RECOVERY as not shown by vssadmin, so a live-tool listing understates the on-disk flags; read them from the store information",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Shadow-copy stores persist on the volume until retention policy, space pressure, or deliberate deletion removes them",
};
