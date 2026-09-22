//! Static [`CorrelationHint`] instances and the [`CORRELATION_HINTS`] slice.
//!
//! Each entry names an OBSERVABLE join between artifacts — a value that can
//! be read from both sides and compared — and states what agreement and
//! disagreement each support. A hint is never a conclusion: "the same volume
//! identifier appears in both" is observable; who created either file is not.
//! Every entry was verified against an independent primary source (a
//! normative specification or a maintained open-source implementation's
//! format documentation), cited in `sources`.

use super::{CorrelationHint, CorrelationRelation};
use forensicnomicon_core::evidence::EvidenceTier;

/// The same droid volume identifier in two Windows shortcuts' tracker
/// blocks: an observable join placing both link targets on one volume.
///
/// # Verification
///
/// - MS-SHLLINK §2.5.10 TrackerDataBlock (normative): signature 0xA0000003,
///   size 0x60; after a 16-byte MachineID come `Droid` (32 bytes) and
///   `DroidBirth` (32 bytes) — each two GUIDs.
/// - liblnk's LNK format documentation names the four GUIDs: droid volume
///   identifier, droid file identifier, birth droid volume identifier,
///   birth droid file identifier — and records that the droid volume
///   identifier is the NTFS $OBJECT_ID of the volume's $Volume metadata
///   file, and the droid file identifier the $OBJECT_ID of the target
///   file itself.
/// - MS-SHLLINK §2.3.1 VolumeID (normative): `DriveSerialNumber`, a 32-bit
///   volume serial, is a second, weaker join key carried by the LinkInfo
///   structure of shortcuts whose target was on a local volume.
pub static LNK_TRACKER_DROID_VOLUME_MATCH: CorrelationHint = CorrelationHint {
    id: "lnk_tracker_droid_volume_match",
    name: "Same droid volume GUID in two shortcut (.lnk) tracker blocks",
    artifacts: &["lnk_files", "ntfs_objid"],
    relation: CorrelationRelation::Corroborates,
    agreement_means: "Two .lnk files whose TrackerDataBlocks carry the same droid volume \
                      identifier (offset 32, 16 bytes) is consistent with both link targets \
                      residing on the same NTFS volume — the GUID is the $OBJECT_ID of that \
                      volume's $Volume metadata file, so it can also be matched against the \
                      volume itself when the filesystem is in evidence (ntfs_objid). The droid \
                      file identifier alongside it ties a shortcut to one specific target \
                      file's $OBJECT_ID. This is an observable join across files and media; \
                      it says nothing about WHO created either shortcut.",
    divergence_means: "Different droid volume identifiers place the two targets on different \
                       volumes even when their paths render identically — refuting an assumed \
                       common origin. Within one shortcut, Droid differing from DroidBirth is \
                       consistent with the target having been tracked across a move since \
                       creation (the birth pair records the original volume/file identity). An \
                       all-zero or absent tracker block means the join is simply unavailable — \
                       not that the targets were unrelated.",
    evidence_tier: EvidenceTier::VendorDocumented,
    mitre_techniques: &[],
    sources: &[
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/df8e3748-fba5-4524-968a-f72be06d71fc",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a",
        "https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc",
    ],
};

/// Every registered correlation hint. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static CORRELATION_HINTS: &[CorrelationHint] = &[LNK_TRACKER_DROID_VOLUME_MATCH];
