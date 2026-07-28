//! **V8 / Blink structured-clone** serialization tag tables.
//!
//! When Chromium persists a JavaScript value — an IndexedDB record value, a
//! `postMessage` payload cached to disk, a Service Worker cache entry — it uses
//! V8's *structured clone* wire format. A stream opens with a version tag
//! (`0xFF` + a `VarInt` version) and is then a sequence of one-byte
//! **serialization tags**, each introducing a typed value. V8 owns the core JS
//! types; **Blink** layers DOM/platform types (Blob, File, DOMPoint, crypto keys,
//! streams) on top, emitting them inside V8's [`HOST_OBJECT_TAG`] escape.
//!
//! This module is **facts only** — the two tag→name tables, the current V8
//! version, and the special framing tags. It maps a tag byte to its documented
//! name; it does **not** deserialize a stream, read `VarInt`s, or reconstruct
//! objects — that lives in the consuming reader (an IndexedDB value decoder).
//!
//! The V8 and Blink tag *bytes* overlap (both draw from printable ASCII), but
//! they live in **different namespaces**: a Blink tag is only meaningful in the
//! payload that follows a V8 [`HOST_OBJECT_TAG`]. Use [`v8_tag_name`] at the top
//! level and [`blink_tag_name`] inside a host-object body.
//!
//! # Authoritative sources
//!
//! - V8 `src/objects/value-serializer.cc` — the `SerializationTag` enum and
//!   `kLatestVersion`:
//!   <https://github.com/v8/v8/blob/main/src/objects/value-serializer.cc>
//! - Blink `third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h`
//!   — the Blink `SerializationTag` enum (DOM/platform types):
//!   <https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h>

/// `kLatestVersion` — the current V8 structured-clone format version written
/// after the `0xFF` version tag.
pub const V8_LATEST_VERSION: u32 = 0; // RED

/// `kVersion` / `kVersionTag` — leads a stream, followed by a `VarInt` version.
/// Shared byte between the V8 and Blink enums.
pub const VERSION_TAG: u8 = 0xFF;

/// `kHostObject` (`'\\'`) — V8 escape hatch; the following bytes are a Blink
/// (embedder) serialization, decoded with [`blink_tag_name`].
pub const HOST_OBJECT_TAG: u8 = b'\\';

/// Blink `kTrailerOffsetTag` — introduces the stream trailer offset.
pub const BLINK_TRAILER_OFFSET_TAG: u8 = 0xFE;

/// Blink `kTrailerRequiresInterfacesTag` — trailer marker for required
/// interfaces.
pub const BLINK_TRAILER_REQUIRES_INTERFACES_TAG: u8 = 0xA0;

/// The V8 core `SerializationTag` table: tag byte → C++ enumerator name.
pub const V8_TAGS: &[(u8, &str)] = &[]; // RED

/// The Blink `SerializationTag` table: tag byte → C++ enumerator name. Meaningful
/// only inside a V8 [`HOST_OBJECT_TAG`] payload.
pub const BLINK_TAGS: &[(u8, &str)] = &[]; // RED

/// Resolve a top-level V8 structured-clone tag byte to its enumerator name.
#[must_use]
pub fn v8_tag_name(_tag: u8) -> Option<&'static str> {
    None // RED
}

/// Resolve a Blink (host-object) serialization tag byte to its enumerator name.
#[must_use]
pub fn blink_tag_name(_tag: u8) -> Option<&'static str> {
    None // RED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_version_and_framing_tags() {
        assert_eq!(V8_LATEST_VERSION, 16);
        assert_eq!(VERSION_TAG, 0xFF);
        assert_eq!(HOST_OBJECT_TAG, b'\\');
        assert_eq!(BLINK_TRAILER_OFFSET_TAG, 0xFE);
        assert_eq!(BLINK_TRAILER_REQUIRES_INTERFACES_TAG, 0xA0);
    }

    #[test]
    fn v8_core_tags_resolve() {
        assert_eq!(v8_tag_name(0xFF), Some("kVersion"));
        assert_eq!(v8_tag_name(b'o'), Some("kBeginJSObject"));
        assert_eq!(v8_tag_name(b'{'), Some("kEndJSObject"));
        assert_eq!(v8_tag_name(b'I'), Some("kInt32"));
        assert_eq!(v8_tag_name(b'N'), Some("kDouble"));
        assert_eq!(v8_tag_name(b'S'), Some("kUtf8String"));
        assert_eq!(v8_tag_name(b'"'), Some("kOneByteString"));
        assert_eq!(v8_tag_name(b'\\'), Some("kHostObject"));
        assert_eq!(v8_tag_name(b';'), Some("kBeginJSMap"));
        assert_eq!(v8_tag_name(b'\''), Some("kBeginJSSet"));
        assert_eq!(v8_tag_name(b'B'), Some("kArrayBuffer"));
    }

    #[test]
    fn v8_unknown_tag_is_none() {
        // 0x01 is not a documented V8 tag.
        assert_eq!(v8_tag_name(0x01), None);
    }

    #[test]
    fn blink_dom_tags_resolve() {
        assert_eq!(blink_tag_name(b'b'), Some("kBlobTag"));
        assert_eq!(blink_tag_name(b'f'), Some("kFileTag"));
        assert_eq!(blink_tag_name(b'K'), Some("kCryptoKeyTag"));
        assert_eq!(blink_tag_name(b'Q'), Some("kDOMPointTag"));
        assert_eq!(blink_tag_name(b'k'), Some("kRTCCertificateTag"));
        assert_eq!(blink_tag_name(0xFF), Some("kVersionTag"));
        assert_eq!(blink_tag_name(0xFE), Some("kTrailerOffsetTag"));
    }

    #[test]
    fn tables_are_populated_and_deduplicated() {
        // V8's enum has 50+ tags; Blink's 40+.
        assert!(V8_TAGS.len() >= 50, "V8 table too small");
        assert!(BLINK_TAGS.len() >= 40, "Blink table too small");
        for table in [V8_TAGS, BLINK_TAGS] {
            let mut bytes: Vec<u8> = table.iter().map(|(b, _)| *b).collect();
            bytes.sort_unstable();
            let before = bytes.len();
            bytes.dedup();
            assert_eq!(before, bytes.len(), "duplicate tag byte in a table");
        }
    }

    #[test]
    fn lookup_matches_tables() {
        for (byte, name) in V8_TAGS {
            assert_eq!(v8_tag_name(*byte), Some(*name));
        }
        for (byte, name) in BLINK_TAGS {
            assert_eq!(blink_tag_name(*byte), Some(*name));
        }
    }
}
