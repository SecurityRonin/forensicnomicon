//! Filesystem-object identity — the stable name each filesystem gives one node.
//!
//! Relocated here from `forensic-vfs` per ADR 0009 (the `FsKind` keystone
//! precedent): [`FileId`] is pure, format-defined identity *structure* — how each
//! filesystem names an object — which is KNOWLEDGE, not VFS machinery. Keeping it
//! beside [`FsKind`](crate::filesystems::FsKind) lets every fleet crate depend
//! **down** onto the zero-dep leaf: `forensic-vfs` re-exports it unchanged (so
//! `forensic_vfs::FileId` keeps working), and `state-history-forensic` reuses it
//! verbatim as a component of the `[P]` evidential-address key rather than
//! mirroring a partial copy.
//!
//! The address domain matches each filesystem's real identity primitive, so a
//! reused slot is never confused with the original: the second field on each
//! slotted variant (`seq`/`gen`/`xid`/`index`) is the slot-reuse discriminator.

/// Filesystem-specific stable identity. The address domain matches each FS's real
/// identity primitive, so a reused slot is never confused with the original.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileId {
    /// NTFS MFT reference: record number + sequence.
    NtfsRef { entry: u64, seq: u16 },
    /// ext2/3/4 inode + generation.
    ExtInode { ino: u64, gen: u32 },
    /// APFS object id + transaction id.
    ApfsOid { oid: u64, xid: u64 },
    /// FAT/exFAT physical directory-entry address (no stable inode).
    FatDirEntry { cluster: u32, index: u16 },
    /// ISO 9660 path-table / extent address.
    IsoExtent { block: u32 },
    /// A filesystem with a plain inode and nothing finer.
    Opaque(u64),
}
