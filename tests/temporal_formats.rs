//! Catalog invariants for the temporal-format table — the *knowledge* half of the
//! timeglyph knowledge/engine split. forensicnomicon owns the authoritative
//! `&'static` table of timestamp encodings (epochs, units, packed-layout tags);
//! timeglyph is the decoder that consumes it. These assertions pin the table's
//! size, id-uniqueness, a spot-checked FILETIME encoding, the `Unit::nanos`
//! conversion table, and the cross-table invariant that every artifact→format
//! mapping in [`ARTIFACT_TIMESTAMPS`] resolves to a real format.

use forensicnomicon::temporal_formats::{time_format, Encoding, TzSemantics, Unit, TIME_FORMATS};
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
    let f = match time_format("filetime") {
        Some(f) => f,
        None => panic!("filetime must be catalogued"),
    };
    assert_eq!(f.tz, TzSemantics::Utc);
    match f.encoding {
        Encoding::LinearInt { epoch_ns, unit } => {
            assert_eq!(epoch_ns, -11_644_473_600_i128 * 1_000_000_000);
            assert_eq!(unit, Unit::HundredNanos);
        }
        other => panic!("filetime must be LinearInt, got {other:?}"),
    }
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
