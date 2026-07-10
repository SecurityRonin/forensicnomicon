//! Catalog invariants for the temporal-format table — the *knowledge* half of the
//! timeglyph knowledge/engine split. forensicnomicon owns the authoritative
//! `&'static` table of timestamp encodings (epochs, units, packed-layout tags);
//! timeglyph is the decoder that consumes it. These assertions pin the table's
//! size, id-uniqueness, a spot-checked FILETIME encoding, the `Unit::nanos`
//! conversion table, and the cross-table invariant that every artifact→format
//! mapping in [`ARTIFACT_TIMESTAMPS`] resolves to a real format.

use forensicnomicon::temporal_formats::{
    time_format, Encoding, TzSemantics, Unit, FILETIME_EPOCH_NS, TIME_FORMATS,
};
use forensicnomicon::timestamp_artifacts::ARTIFACT_TIMESTAMPS;

#[test]
fn catalog_has_45_formats() {
    assert_eq!(TIME_FORMATS.len(), 45);
}

#[test]
fn all_ids_are_unique() {
    let mut ids: Vec<&str> = TIME_FORMATS.iter().map(|f| f.id).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "duplicate format id(s) present");
}

#[test]
fn filetime_is_linearint_hundrednanos_since_1601_utc() {
    // FILETIME: LinearInt, 100-ns ticks, 1601-01-01 epoch, UTC — the epoch offset
    // stated as the raw literal so a wrong sign/scale fails here, not silently.
    let expected = (
        TzSemantics::Utc,
        Encoding::LinearInt {
            epoch_ns: -11_644_473_600_i128 * 1_000_000_000,
            unit: Unit::HundredNanos,
        },
    );
    assert_eq!(
        time_format("filetime").map(|f| (f.tz, f.encoding)),
        Some(expected),
        "filetime must be LinearInt(HundredNanos, 1601-01-01, UTC)"
    );
    // The named epoch constant matches the literal (public knowledge API).
    assert_eq!(FILETIME_EPOCH_NS, -11_644_473_600_i128 * 1_000_000_000);
}

#[test]
fn unit_nanos_table_is_exact() {
    assert_eq!(Unit::Seconds.nanos(), 1_000_000_000);
    assert_eq!(Unit::Millis.nanos(), 1_000_000);
    assert_eq!(Unit::CentiSecond.nanos(), 10_000_000);
    assert_eq!(Unit::Micros.nanos(), 1_000);
    assert_eq!(Unit::HundredNanos.nanos(), 100);
    assert_eq!(Unit::Nanos.nanos(), 1);
    assert_eq!(Unit::Days.nanos(), 86_400 * 1_000_000_000);
}

#[test]
fn every_artifact_format_resolves_to_a_catalogued_format() {
    for a in ARTIFACT_TIMESTAMPS {
        assert!(
            time_format(a.format).is_some(),
            "artifact {:?} references unknown format {:?}",
            a.artifact,
            a.format
        );
    }
}
