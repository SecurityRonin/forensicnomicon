//! Chromium **IndexedDB** LevelDB key-coding scheme constants.
//!
//! Chromium backs the IndexedDB API with a LevelDB store on disk
//! (`IndexedDB/<origin>.indexeddb.leveldb/`). Every record's key begins with a
//! space-optimised **`KeyPrefix`** that names the `(database id, object store id,
//! index id)` the record belongs to, followed by a type-specific tail. This is
//! the format that holds the actual messages for Electron messengers that persist
//! chats client-side (Wire, WhatsApp Web, Teams).
//!
//! This module is **facts only** — the first-byte length encoding of `KeyPrefix`,
//! the reserved global / database / object-store metadata type bytes, and the
//! reserved index ids. It decodes a single prefix byte into field lengths (a pure
//! spec rule, like `decmpfs::classify`), but does **not** parse a LevelDB stream,
//! walk IDBKeys, or deserialize values — that lives in the consuming reader.
//!
//! The stored object-store record **value** is a version `VarInt` followed by a
//! V8/Blink structured-clone blob — see [`crate::v8_serialization`] for the tag
//! tables that decode it.
//!
//! # `KeyPrefix` first-byte encoding
//!
//! To save space the three ids are **not** fixed-width. The first byte is a
//! length descriptor: the **top 3 bits** are `(database_id length − 1)`, the
//! **next 3 bits** are `(object_store_id length − 1)`, and the **bottom 2 bits**
//! are `(index_id length − 1)`, all in bytes. So database/object-store ids span
//! 1–8 bytes and index ids span 1–4 bytes. The three ids then follow as
//! big-endian integers of those lengths. An all-zero prefix (`00 00 00 00`)
//! identifies global metadata.
//!
//! # Authoritative sources
//!
//! - Chromium `content/browser/indexed_db/docs/leveldb_coding_scheme.md` — the
//!   canonical spec for the prefix bit layout, the metadata type bytes, and the
//!   record key formats:
//!   <https://github.com/chromium/chromium/blob/main/content/browser/indexed_db/docs/leveldb_coding_scheme.md>
//! - Chromium `content/browser/indexed_db/indexed_db_leveldb_coding.cc` — the
//!   `KeyPrefix` encode/decode and the reserved index-id constants:
//!   <https://chromium.googlesource.com/chromium/src/+/main/content/browser/indexed_db/indexed_db_leveldb_coding.cc>
//! - CCL Solutions, *IndexedDB on Chromium* — the settled forensic write-up:
//!   <https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium>

// ── Global metadata type bytes (KeyPrefix 0,0,0 then this byte) ───────────────

/// `SchemaVersion` — backing-store schema version (Int).
pub const GLOBAL_SCHEMA_VERSION: u8 = 0x00;
/// `MaxDatabaseId` — highest allocated database id (Int).
pub const GLOBAL_MAX_DATABASE_ID: u8 = 0x01;
/// `DataVersion` — on-disk data format version (Int).
pub const GLOBAL_DATA_VERSION: u8 = 0x02;
/// `RecoveryBlobJournal` — blob files pending deletion after a crash.
pub const GLOBAL_RECOVERY_BLOB_JOURNAL: u8 = 0x03;
/// `ActiveBlobJournal` — blob files referenced by live handles.
pub const GLOBAL_ACTIVE_BLOB_JOURNAL: u8 = 0x04;
/// `EarliestSweepTime` — next tombstone-sweep time (microseconds, Int).
pub const GLOBAL_EARLIEST_SWEEP_TIME: u8 = 0x05;

// ── Database metadata type bytes (KeyPrefix db,0,0 then this byte) ────────────

/// Origin name (String).
pub const DB_META_ORIGIN_NAME: u8 = 0;
/// Database name (String).
pub const DB_META_DATABASE_NAME: u8 = 1;
/// User string version (obsolete).
pub const DB_META_USER_STRING_VERSION: u8 = 2;
/// Maximum allocated object-store id (Int).
pub const DB_META_MAX_OBJECT_STORE_ID: u8 = 3;
/// IndexedDB integer version (VarInt).
pub const DB_META_INTEGER_VERSION: u8 = 4;
/// Blob key generator current number (VarInt).
pub const DB_META_BLOB_KEY_GENERATOR: u8 = 5;

/// The database-metadata type byte introducing an object-store metadata record:
/// the key is `KeyPrefix(db,0,0)` + [`OBJECT_STORE_META_TYPE`] + object-store id +
/// one of the `OS_META_*` bytes.
pub const OBJECT_STORE_META_TYPE: u8 = 50;

// ── Object-store metadata sub-type bytes ─────────────────────────────────────

/// Object-store name (String).
pub const OS_META_NAME: u8 = 0;
/// Key path (IDBKeyPath).
pub const OS_META_KEY_PATH: u8 = 1;
/// Auto-increment flag (Bool).
pub const OS_META_AUTO_INCREMENT: u8 = 2;
/// Is-evictable flag (obsolete Bool).
pub const OS_META_IS_EVICTABLE: u8 = 3;
/// Last version number (Int).
pub const OS_META_LAST_VERSION: u8 = 4;
/// Maximum allocated index id (Int).
pub const OS_META_MAX_INDEX_ID: u8 = 5;
/// Has-key-path flag (obsolete Bool).
pub const OS_META_HAS_KEY_PATH: u8 = 6;
/// Key generator current number (Int).
pub const OS_META_KEY_GENERATOR: u8 = 7;

// ── Reserved index ids (the index_id field of KeyPrefix) ─────────────────────

/// `kObjectStoreDataIndexId` — primary record store (key → version + value).
pub const INDEX_ID_OBJECT_STORE_DATA: u32 = 1;
/// `kExistsEntryIndexId` — existence/version index (key → version).
pub const INDEX_ID_EXISTS_ENTRY: u32 = 2;
/// `kBlobEntryIndexId` — external blob/file references for a record.
pub const INDEX_ID_BLOB_ENTRY: u32 = 3;

/// The decoded field lengths carried by a `KeyPrefix` first byte. Each length is
/// in bytes: database/object-store ids are 1–8, index id is 1–4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPrefixLengths {
    /// Length in bytes of the database id field.
    pub database_id_len: u8,
    /// Length in bytes of the object-store id field.
    pub object_store_id_len: u8,
    /// Length in bytes of the index id field.
    pub index_id_len: u8,
}

/// Decode a `KeyPrefix` first byte into the three field byte-lengths.
///
/// Top 3 bits → `database_id_len − 1`, next 3 bits → `object_store_id_len − 1`,
/// bottom 2 bits → `index_id_len − 1` (each stored value is length minus one).
#[must_use]
pub const fn decode_key_prefix_lengths(first_byte: u8) -> KeyPrefixLengths {
    KeyPrefixLengths {
        database_id_len: (first_byte >> 5) + 1,
        object_store_id_len: ((first_byte >> 2) & 0b111) + 1,
        index_id_len: (first_byte & 0b11) + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_metadata_type_bytes() {
        assert_eq!(GLOBAL_SCHEMA_VERSION, 0x00);
        assert_eq!(GLOBAL_MAX_DATABASE_ID, 0x01);
        assert_eq!(GLOBAL_DATA_VERSION, 0x02);
        assert_eq!(GLOBAL_RECOVERY_BLOB_JOURNAL, 0x03);
        assert_eq!(GLOBAL_ACTIVE_BLOB_JOURNAL, 0x04);
        assert_eq!(GLOBAL_EARLIEST_SWEEP_TIME, 0x05);
    }

    #[test]
    fn object_store_metadata_prefix_byte_is_50() {
        assert_eq!(OBJECT_STORE_META_TYPE, 50);
    }

    #[test]
    fn reserved_index_ids() {
        assert_eq!(INDEX_ID_OBJECT_STORE_DATA, 1);
        assert_eq!(INDEX_ID_EXISTS_ENTRY, 2);
        assert_eq!(INDEX_ID_BLOB_ENTRY, 3);
    }

    #[test]
    fn prefix_all_zero_is_one_byte_each() {
        // 0x00 ⇒ every field length descriptor is 0 ⇒ each id is 1 byte.
        assert_eq!(
            decode_key_prefix_lengths(0x00),
            KeyPrefixLengths {
                database_id_len: 1,
                object_store_id_len: 1,
                index_id_len: 1,
            }
        );
    }

    #[test]
    fn prefix_max_lengths() {
        // Top 3 bits = 7 (db len 8), next 3 bits = 7 (os len 8), low 2 = 3 (idx 4).
        // 0b111_111_11 = 0xFF.
        assert_eq!(
            decode_key_prefix_lengths(0xFF),
            KeyPrefixLengths {
                database_id_len: 8,
                object_store_id_len: 8,
                index_id_len: 4,
            }
        );
    }

    #[test]
    fn prefix_mixed_fields() {
        // db len 2 (bits 001), os len 3 (bits 010), idx len 1 (bits 00):
        // 001_010_00 = 0b0010_1000 = 0x28.
        assert_eq!(
            decode_key_prefix_lengths(0b0010_1000),
            KeyPrefixLengths {
                database_id_len: 2,
                object_store_id_len: 3,
                index_id_len: 1,
            }
        );
    }
}
