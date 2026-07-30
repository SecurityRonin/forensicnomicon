#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Facade-contract test: every public `forensicnomicon-core` module must resolve
//! through the umbrella `forensicnomicon` crate.
//!
//! `forensicnomicon-core`'s own crate docs promise that "the umbrella
//! `forensicnomicon` crate re-exports everything here, so existing imports such as
//! `forensicnomicon::report::Finding` … continue to resolve unchanged". A module
//! added to core but not re-exported here silently breaks that promise: the path
//! `forensicnomicon_core::v8_serialization` resolves while
//! `forensicnomicon::v8_serialization` does not. These tests fail to *compile* if a
//! re-export is missing, and assert a real value from each module so the path is
//! exercised rather than merely named.

use forensicnomicon::catalog::types::Platform;

#[test]
fn report_resolves_through_facade() {
    // The finding vocabulary every `*-forensic` analyzer emits.
    assert!(forensicnomicon::report::Severity::Critical > forensicnomicon::report::Severity::Info);
}

#[test]
fn chromium_simple_cache_resolves_through_facade() {
    assert_eq!(
        forensicnomicon::chromium_simple_cache::INITIAL_MAGIC,
        0xfcfb_6d1b_a772_5c30
    );
    assert!(forensicnomicon::chromium_simple_cache::has_crc32(
        forensicnomicon::chromium_simple_cache::FLAG_HAS_CRC32
    ));
}

#[test]
fn chromium_indexeddb_resolves_through_facade() {
    assert_eq!(
        forensicnomicon::chromium_indexeddb::GLOBAL_DATA_VERSION,
        0x02
    );
    assert_eq!(
        forensicnomicon::chromium_indexeddb::INDEX_ID_OBJECT_STORE_DATA,
        1
    );
    // Each packed field stores length-minus-one, so an all-zero prefix byte means
    // the minimum 1-byte database / object-store / index id.
    let lens = forensicnomicon::chromium_indexeddb::decode_key_prefix_lengths(0x00);
    assert_eq!(
        (
            lens.database_id_len,
            lens.object_store_id_len,
            lens.index_id_len
        ),
        (1, 1, 1)
    );
}

#[test]
fn chromium_local_storage_resolves_through_facade() {
    assert_eq!(
        forensicnomicon::chromium_local_storage::META_PREFIX,
        b"META:"
    );
    assert_eq!(
        forensicnomicon::chromium_local_storage::value_encoding(0x01),
        Some(forensicnomicon::chromium_local_storage::ValueEncoding::Latin1)
    );
}

#[test]
fn v8_serialization_resolves_through_facade() {
    assert_eq!(forensicnomicon::v8_serialization::VERSION_TAG, 0xFF);
    assert_eq!(
        forensicnomicon::v8_serialization::v8_tag_name(0xFF),
        Some("kVersion")
    );
    assert_eq!(
        forensicnomicon::v8_serialization::blink_tag_name(
            forensicnomicon::v8_serialization::BLINK_TRAILER_OFFSET_TAG
        ),
        Some("kTrailerOffsetTag")
    );
}

#[test]
fn messenger_desktop_resolves_through_facade() {
    use forensicnomicon::messenger_desktop::{spec, StoreRole, WebClient};

    let signal = spec("Signal Desktop").expect("Signal Desktop is in DESKTOP_MESSENGERS");
    assert_eq!(
        signal.base_dir(Platform::MacOS),
        Some("~/Library/Application Support/Signal")
    );
    assert_eq!(
        signal.store(StoreRole::Messages).map(|s| s.relative_path),
        Some("sql/db.sqlite")
    );
    // Signal ships desktop + mobile only — no browser-hosted web client.
    assert!(signal.web.is_none());

    let discord = spec("Discord").expect("Discord is in DESKTOP_MESSENGERS");
    let web: &WebClient = discord.web.as_ref().expect("Discord has a web client");
    assert_eq!(web.origin, "https://discord.com");
    assert_eq!(
        web.indexeddb_dir(),
        "IndexedDB/https_discord.com_0.indexeddb.leveldb"
    );
}

#[test]
fn usb_vendors_resolves_through_facade() {
    assert_eq!(
        forensicnomicon::usb_vendors::vendor_name(0x0781),
        Some("SanDisk Corp.")
    );
    assert!(forensicnomicon::usb_vendors::COMMON_USB_VENDORS
        .iter()
        .any(|v| v.vid == 0x04e8));
}

#[test]
fn file_id_resolves_through_facade() {
    // Re-exported both as a module and at the facade root, mirroring core.
    let by_module = forensicnomicon::file_id::FileId::NtfsRef { entry: 42, seq: 3 };
    let by_root = forensicnomicon::FileId::NtfsRef { entry: 42, seq: 3 };
    assert_eq!(by_module, by_root);
}
