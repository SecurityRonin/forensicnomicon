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
pub const V8_LATEST_VERSION: u32 = 16;

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
///
/// Verbatim from V8's `SerializationTag : uint8_t` enum, including the fourteen
/// `kLegacyReserved*` bytes V8 keeps unusable so a modern stream never collides
/// with a pre-2017 Blink serialization. Every byte is distinct.
// Source: https://github.com/v8/v8/blob/main/src/objects/value-serializer.cc
pub const V8_TAGS: &[(u8, &str)] = &[
    (0xFF, "kVersion"),
    (b'\0', "kPadding"),
    (b'?', "kVerifyObjectCount"),
    (b'-', "kTheHole"),
    (b'_', "kUndefined"),
    (b'0', "kNull"),
    (b'T', "kTrue"),
    (b'F', "kFalse"),
    (b'I', "kInt32"),
    (b'U', "kUint32"),
    (b'N', "kDouble"),
    (b'Z', "kBigInt"),
    (b'S', "kUtf8String"),
    (b'"', "kOneByteString"),
    (b'c', "kTwoByteString"),
    (b'^', "kObjectReference"),
    (b'o', "kBeginJSObject"),
    (b'{', "kEndJSObject"),
    (b'a', "kBeginSparseJSArray"),
    (b'@', "kEndSparseJSArray"),
    (b'A', "kBeginDenseJSArray"),
    (b'$', "kEndDenseJSArray"),
    (b'D', "kDate"),
    (b'y', "kTrueObject"),
    (b'x', "kFalseObject"),
    (b'n', "kNumberObject"),
    (b'z', "kBigIntObject"),
    (b's', "kStringObject"),
    (b'R', "kRegExp"),
    (b';', "kBeginJSMap"),
    (b':', "kEndJSMap"),
    (b'\'', "kBeginJSSet"),
    (b',', "kEndJSSet"),
    (b'B', "kArrayBuffer"),
    (b'C', "kImmutableArrayBuffer"),
    (b'~', "kResizableArrayBuffer"),
    (b't', "kArrayBufferTransfer"),
    (b'V', "kArrayBufferView"),
    (b'u', "kSharedArrayBuffer"),
    (b'p', "kSharedObject"),
    (b'w', "kWasmModuleTransfer"),
    (b'\\', "kHostObject"),
    (b'm', "kWasmMemoryTransfer"),
    (b'r', "kError"),
    (b'M', "kLegacyReservedMessagePort"),
    (b'b', "kLegacyReservedBlob"),
    (b'i', "kLegacyReservedBlobIndex"),
    (b'f', "kLegacyReservedFile"),
    (b'e', "kLegacyReservedFileIndex"),
    (b'd', "kLegacyReservedDOMFileSystem"),
    (b'l', "kLegacyReservedFileList"),
    (b'L', "kLegacyReservedFileListIndex"),
    (b'#', "kLegacyReservedImageData"),
    (b'g', "kLegacyReservedImageBitmap"),
    (b'G', "kLegacyReservedImageBitmapTransfer"),
    (b'H', "kLegacyReservedOffscreenCanvas"),
    (b'K', "kLegacyReservedCryptoKey"),
    (b'k', "kLegacyReservedRTCCertificate"),
];

/// The Blink `SerializationTag` table: tag byte → C++ enumerator name. Meaningful
/// only inside a V8 [`HOST_OBJECT_TAG`] payload.
///
/// Verbatim from Blink's `SerializationTag : uint8_t` enum. The bytes overlap the
/// V8 table numerically but occupy a distinct namespace — a Blink tag is only
/// valid after a V8 [`HOST_OBJECT_TAG`] (`'\\'`). `kVersionTag`/`kTrailerOffsetTag`/
/// `kTrailerRequiresInterfacesTag` are the framing bytes exported above.
// Source: https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h
pub const BLINK_TAGS: &[(u8, &str)] = &[
    (b'M', "kMessagePortTag"),
    (b'h', "kMojoHandleTag"),
    (b'b', "kBlobTag"),
    (b'i', "kBlobIndexTag"),
    (b'f', "kFileTag"),
    (b'e', "kFileIndexTag"),
    (b'd', "kDOMFileSystemTag"),
    (b'n', "kFileSystemFileHandleTag"),
    (b'N', "kFileSystemDirectoryHandleTag"),
    (b'l', "kFileListTag"),
    (b'L', "kFileListIndexTag"),
    (b'#', "kImageDataTag"),
    (b'g', "kImageBitmapTag"),
    (b'G', "kImageBitmapTransferTag"),
    (b'J', "kElementImageTransferTag"),
    (b'H', "kOffscreenCanvasTransferTag"),
    (b'r', "kReadableStreamTransferTag"),
    (b'm', "kTransformStreamTransferTag"),
    (b'w', "kWritableStreamTransferTag"),
    (b's', "kMediaStreamTrack"),
    (b'Q', "kDOMPointTag"),
    (b'W', "kDOMPointReadOnlyTag"),
    (b'E', "kDOMRectTag"),
    (b'R', "kDOMRectReadOnlyTag"),
    (b'T', "kDOMQuadTag"),
    (b'Y', "kDOMMatrixTag"),
    (b'U', "kDOMMatrixReadOnlyTag"),
    (b'I', "kDOMMatrix2DTag"),
    (b'O', "kDOMMatrix2DReadOnlyTag"),
    (b'K', "kCryptoKeyTag"),
    (b'k', "kRTCCertificateTag"),
    (b'A', "kRTCEncodedAudioFrameTag"),
    (b'V', "kRTCEncodedVideoFrameTag"),
    (b'p', "kRTCDataChannel"),
    (b'a', "kAudioDataTag"),
    (b'v', "kVideoFrameTag"),
    (b'y', "kEncodedAudioChunkTag"),
    (b'z', "kEncodedVideoChunkTag"),
    (b'c', "kCropTargetTag"),
    (b'D', "kRestrictionTargetTag"),
    (b'S', "kMediaSourceHandleTag"),
    (b'B', "kDeprecatedDetectedBarcodeTag"),
    (b'F', "kDeprecatedDetectedFaceTag"),
    (b't', "kDeprecatedDetectedTextTag"),
    (b'C', "kFencedFrameConfigTag"),
    (b'x', "kDOMExceptionTag"),
    (b'q', "kQuotaExceededErrorTag"),
    (0xFE, "kTrailerOffsetTag"),
    (0xFF, "kVersionTag"),
    (0xA0, "kTrailerRequiresInterfacesTag"),
];

/// Resolve a top-level V8 structured-clone tag byte to its enumerator name.
#[must_use]
pub fn v8_tag_name(tag: u8) -> Option<&'static str> {
    V8_TAGS
        .iter()
        .find(|(byte, _)| *byte == tag)
        .map(|(_, name)| *name)
}

/// Resolve a Blink (host-object) serialization tag byte to its enumerator name.
#[must_use]
pub fn blink_tag_name(tag: u8) -> Option<&'static str> {
    BLINK_TAGS
        .iter()
        .find(|(byte, _)| *byte == tag)
        .map(|(_, name)| *name)
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
