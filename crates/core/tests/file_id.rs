//! Relocation guard for [`FileId`] (ADR 0009): the fleet's filesystem-object
//! identity now lives in `forensicnomicon-core` beside `FsKind`, so a second
//! consumer (the `[P]` evidential address in `state-history-forensic`) can reuse
//! it verbatim instead of mirroring a partial copy.
//!
//! These tests pin its shape — all six variants — and the `Eq`/`Hash` identity
//! that makes it a component of an evidential-address key by construction. The
//! second field on each slotted variant (`seq`/`gen`/`xid`/`index`) is the
//! slot-reuse discriminator: a reallocated record must never compare equal to the
//! original.

use forensicnomicon_core::FileId;
use std::collections::HashSet;

#[test]
fn all_six_variants_construct() {
    let _ = FileId::NtfsRef { entry: 5, seq: 2 };
    let _ = FileId::ExtInode { ino: 5, gen: 2 };
    let _ = FileId::ApfsOid { oid: 5, xid: 2 };
    let _ = FileId::FatDirEntry {
        cluster: 5,
        index: 2,
    };
    let _ = FileId::IsoExtent { block: 5 };
    let _ = FileId::Opaque(5);
}

#[test]
fn seq_is_a_slot_reuse_discriminator() {
    // A reallocated MFT record (same entry, bumped sequence) must never equal the
    // original — this is the discriminator the [P] address relies on to tell a
    // reused slot from the object that first occupied it.
    let original = FileId::NtfsRef { entry: 42, seq: 1 };
    let reallocated = FileId::NtfsRef { entry: 42, seq: 2 };
    assert_ne!(original, reallocated);

    let mut seen = HashSet::new();
    seen.insert(original);
    assert!(seen.contains(&original));
    assert!(
        !seen.contains(&reallocated),
        "a bumped sequence must hash/compare as a distinct object"
    );
}

#[test]
fn ext_generation_is_a_slot_reuse_discriminator() {
    // The ext inode-generation counter plays the same role as the NTFS sequence.
    let original = FileId::ExtInode { ino: 7, gen: 1 };
    let reallocated = FileId::ExtInode { ino: 7, gen: 2 };
    assert_ne!(original, reallocated);
}

#[test]
fn eq_hash_and_copy_hold() {
    let a = FileId::ApfsOid { oid: 1, xid: 9 };
    let b = a; // Copy — FileId is a cheap value type.
    assert_eq!(a, b);

    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}
