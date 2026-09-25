//! Catalog invariants for the temporal-format table — the *knowledge* half of the
//! timeglyph knowledge/engine split. forensicnomicon owns the authoritative
//! `&'static` table of timestamp encodings (epochs, units, packed-layout tags);
//! timeglyph is the decoder that consumes it. These assertions pin the table's
//! size, id-uniqueness, a spot-checked FILETIME encoding, the `Unit::nanos`
//! conversion table, and the cross-table invariant that every artifact→format
//! mapping in [`ARTIFACT_TIMESTAMPS`] resolves to a real format.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::temporal_formats::{
    time_format, token_format, Encoding, TokenLayout, TzSemantics, Unit, FILETIME_EPOCH_NS,
    TIME_FORMATS, TOKEN_FORMATS,
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
fn google_ei_is_a_catalogued_url_token_format() {
    let f = token_format("google_ei").expect("google_ei catalogued");
    assert_eq!(f.layout, TokenLayout::GoogleEi);
    // `sei` carries the same layout (Cheeky4n6Monkey 2014: an sei and ei from one
    // session share their leading timestamp bytes).
    assert_eq!(f.url_params, &["ei", "sei"]);
    assert_eq!(f.tz, TzSemantics::Utc);
    // The instant is when Google served the page, NOT necessarily the query time
    // in the same URL (unfurl #56) — the caveat an analyst most needs.
    assert!(
        f.caveats.iter().any(|c| c.contains("not necessarily")),
        "{:?}",
        f.caveats
    );
}

#[test]
fn google_ei_worked_examples_come_from_their_cited_sources() {
    // Deed Poll Office (2013) publishes all four fields of tci4UszSJeLN7Ab9xYD4CQ:
    // 1387841717 s and 616780 (conjectured µs). The unfurl #56 URL's ei decodes to
    // 1587403446 s + 540099 µs, which the same URL's `ved` carries as one µs value.
    let f = token_format("google_ei").unwrap();
    let got: Vec<(&str, i64)> = f
        .examples
        .iter()
        .map(|e| (e.token, e.unix_micros))
        .collect();
    assert_eq!(
        got,
        vec![
            ("tci4UszSJeLN7Ab9xYD4CQ", 1_387_841_717_616_780),
            ("ttqdXsP7IMKZk74Pgv-k6AY", 1_587_403_446_540_099),
        ]
    );
    for e in f.examples {
        assert!(
            f.sources.contains(&e.source),
            "{} cites an uncatalogued source",
            e.token
        );
    }
}

#[test]
fn token_formats_are_unique_sourced_and_distinct_from_integer_formats() {
    let mut ids: Vec<&str> = TOKEN_FORMATS.iter().map(|f| f.id).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "duplicate token format id(s)");
    for f in TOKEN_FORMATS {
        assert!(
            time_format(f.id).is_none(),
            "{} is also an integer format",
            f.id
        );
        assert!(!f.sources.is_empty() && !f.caveats.is_empty(), "{}", f.id);
        assert!(
            f.sources.iter().all(|s| s.starts_with("https://")),
            "{}",
            f.id
        );
    }
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
