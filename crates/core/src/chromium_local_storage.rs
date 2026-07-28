//! Chromium **Local Storage** (DOM Storage on LevelDB) key-schema constants.
//!
//! Since Chromium 61 the DOM `localStorage` API is backed by a per-profile
//! LevelDB store (`Local Storage/leveldb/`), replacing the old one-SQLite-file-
//! per-origin scheme. Records take one of two shapes: a `META:` record per origin
//! (a protobuf of storage size + last-modified time) and one data record per
//! stored key. Each value — and each string embedded in a data key — carries a
//! one-byte **encoding marker** so 8-bit and UTF-16 text can share the store.
//!
//! This module is **facts only** — the `META:` prefix, the data-key prefix and
//! separator, and the value encoding markers. It maps a marker byte to its
//! encoding (a pure spec rule); it does **not** read LevelDB, decode protobufs,
//! or transcode text — that lives in the consuming reader.
//!
//! # Key schema
//!
//! - **Metadata key**: `"META:"` + `<origin>` → protobuf `{ size, last_modified }`
//!   (the `META:` literal is ISO-8859-1).
//! - **Data key**: `"_"` (`0x5F`) + `<origin>` + `0x00` (NUL) + `<script key>`
//!   → `<encoding marker byte>` + text.
//! - **Value encoding marker**: leading byte `0x00` ⇒ UTF-16LE, `0x01` ⇒ Latin-1
//!   (ISO-8859-1).
//!
//! Unlike Session Storage, Local Storage has **no** static `"version"` key —
//! a common point of confusion, since Session Storage *does* open with a
//! `"version"` → `"1"` record.
//!
//! # Authoritative sources
//!
//! - CCL Solutions, *Chromium Session Storage and Local Storage* — the settled
//!   forensic reference for the key shapes and the encoding markers:
//!   <https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage>
//! - Chromium `components/services/storage/dom_storage/` — the LevelDB-backed
//!   DOM Storage implementation:
//!   <https://chromium.googlesource.com/chromium/src/+/main/components/services/storage/dom_storage/>

/// Metadata-key prefix: `"META:"` + `<origin>` addresses the per-origin
/// size/last-modified protobuf record.
pub const META_PREFIX: &[u8] = b"META:";

/// Data-key prefix byte: a leading `'_'` (`0x5F`) introduces a per-key record
/// (`"_"` + origin + NUL + script key).
pub const DATA_KEY_PREFIX: u8 = b'_';

/// The NUL byte (`0x00`) separating the origin from the script key inside a data
/// key.
pub const KEY_SEPARATOR: u8 = 0x00;

/// Value encoding marker for UTF-16 little-endian text.
pub const ENCODING_UTF16LE: u8 = 0x00;

/// Value encoding marker for Latin-1 / ISO-8859-1 (8-bit) text.
pub const ENCODING_LATIN1: u8 = 0x01;

/// The text encoding a Local Storage value (or key string) marker selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueEncoding {
    /// UTF-16 little-endian (`0x00`).
    Utf16Le,
    /// Latin-1 / ISO-8859-1 (`0x01`).
    Latin1,
}

/// Classify a Local Storage value/key encoding marker byte.
///
/// Returns `None` for any byte other than the two documented markers — the caller
/// must fail loud rather than guess a transcoding.
#[must_use]
pub const fn value_encoding(_marker: u8) -> Option<ValueEncoding> {
    None // RED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schema_constants() {
        assert_eq!(META_PREFIX, b"META:");
        assert_eq!(DATA_KEY_PREFIX, b'_');
        assert_eq!(DATA_KEY_PREFIX, 0x5F);
        assert_eq!(KEY_SEPARATOR, 0x00);
    }

    #[test]
    fn encoding_markers() {
        assert_eq!(ENCODING_UTF16LE, 0x00);
        assert_eq!(ENCODING_LATIN1, 0x01);
    }

    #[test]
    fn value_encoding_maps_documented_markers() {
        assert_eq!(value_encoding(0x00), Some(ValueEncoding::Utf16Le));
        assert_eq!(value_encoding(0x01), Some(ValueEncoding::Latin1));
    }

    #[test]
    fn value_encoding_rejects_unknown_markers() {
        assert_eq!(value_encoding(0x02), None);
        assert_eq!(value_encoding(0xFF), None);
    }
}
