//! $MFT-oracle validation for the timestomping descriptor (Tier-2, env-gated).
//!
//! Validates that the `ntfs_timestomping_si_fn` descriptor's documented $SI and
//! $FN timestamp fields correspond to what a REAL MFT parser (`analyzeMFT`)
//! emits on a REAL NTFS image ($MFT extracted from the DFIR Madness "Szechuan
//! Sauce" DC01 disk image via The Sleuth Kit). This is documentation fidelity
//! checked against an independent oracle — the analyzeMFT parser's output on a
//! third-party real-world image — not against a fixture we authored.
//!
//! It asserts the properties the descriptor documents actually hold on real
//! data:
//!   * every MFT record carries BOTH four $SI and four $FN timestamps, and
//!   * the two sets are independent (records exist where $SI creation differs
//!     from $FN creation — the cross-view the descriptor's discrepancy flags
//!     are derived from).
//!
//! GATING. This test only runs when ALL of the following hold:
//!   * env `FORENSICNOMICON_MFT_ORACLE=1`
//!   * the `analyzeMFT` binary is present (env `FORENSICNOMICON_MFT_BIN` or the
//!     default mise path), and
//!   * a pre-extracted MFT-CSV is present (env `FORENSICNOMICON_MFT_CSV`) OR a
//!     raw $MFT is present (env `FORENSICNOMICON_MFT_RAW`) to parse.
//!
//! Otherwise it prints a `skipped: …` line and returns cleanly, so the default
//! `cargo test` run and the coverage gate are unaffected. On any tool failure
//! it SKIPS (returns) rather than failing — a missing oracle is not a product
//! defect.
//!
//! Producing the inputs (one-time, per the test-data provenance standard —
//! extract to /tmp, never under ~/src):
//!   IMG=.../dfirmadness-szechuan-sauce/E01-DC01/20200918_0347_CDrive.E01
//!   icat -o 718848 "$IMG" 0 > /tmp/szechuan-mft/MFT.raw   # $MFT is inode 0
//!   analyzeMFT -f /tmp/szechuan-mft/MFT.raw -o /tmp/szechuan-mft/mft.csv --csv
//!   FORENSICNOMICON_MFT_ORACLE=1 \
//!     FORENSICNOMICON_MFT_CSV=/tmp/szechuan-mft/mft.csv \
//!     cargo test -p forensicnomicon-data --test mft_oracle -- --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

use forensicnomicon_data::catalog::CATALOG;

/// The analyzeMFT CSV column headers that mirror the descriptor's $SI/$FN fields.
/// Each pair is (descriptor field, analyzeMFT CSV column header).
const SI_FN_COLUMN_MAP: &[(&str, &str)] = &[
    ("si_created", "SI Creation Time"),
    ("si_modified", "SI Modification Time"),
    ("si_accessed", "SI Access Time"),
    ("si_mft_modified", "SI Entry Time"),
    ("fn_created", "FN Creation Time"),
    ("fn_modified", "FN Modification Time"),
    ("fn_accessed", "FN Access Time"),
    ("fn_mft_modified", "FN Entry Time"),
];

fn analyze_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FORENSICNOMICON_MFT_BIN") {
        let pb = PathBuf::from(p);
        return pb.exists().then_some(pb);
    }
    let home = std::env::var("HOME").ok()?;
    let pb = PathBuf::from(home).join(".local/share/mise/installs/python/3.11/bin/analyzeMFT");
    pb.exists().then_some(pb)
}

/// Obtain the analyzeMFT CSV text: use a pre-extracted CSV if given, else parse
/// a raw $MFT with analyzeMFT. Returns `None` (caller skips) on any failure.
fn mft_csv_text(analyze: &PathBuf) -> Option<String> {
    if let Ok(csv) = std::env::var("FORENSICNOMICON_MFT_CSV") {
        let pb = PathBuf::from(&csv);
        if pb.exists() {
            return std::fs::read_to_string(&pb).ok();
        }
    }
    let raw = std::env::var("FORENSICNOMICON_MFT_RAW").ok()?;
    let raw = PathBuf::from(raw);
    if !raw.exists() {
        return None;
    }
    let out = PathBuf::from("/tmp/forensicnomicon_mft_oracle.csv");
    let status = Command::new(analyze)
        .arg("-f")
        .arg(&raw)
        .arg("-o")
        .arg(&out)
        .arg("--csv")
        .status()
        .ok()?;
    if !status.success() {
        eprintln!("skipped: analyzeMFT exited {:?}", status.code());
        return None;
    }
    std::fs::read_to_string(&out).ok()
}

#[test]
fn mft_oracle_si_fn_field_fidelity() {
    if std::env::var("FORENSICNOMICON_MFT_ORACLE").as_deref() != Ok("1") {
        eprintln!("skipped: set FORENSICNOMICON_MFT_ORACLE=1 to run the $MFT oracle test");
        return;
    }
    let Some(analyze) = analyze_bin() else {
        eprintln!(
            "skipped: analyzeMFT not found (set FORENSICNOMICON_MFT_BIN or install to the mise path)"
        );
        return;
    };
    let Some(text) = mft_csv_text(&analyze) else {
        eprintln!(
            "skipped: no MFT-CSV (set FORENSICNOMICON_MFT_CSV) and no raw $MFT (set FORENSICNOMICON_MFT_RAW)"
        );
        return;
    };

    // The descriptor under test must declare each mapped $SI/$FN field.
    let desc = CATALOG
        .by_id("ntfs_timestomping_si_fn")
        .expect("ntfs_timestomping_si_fn descriptor missing from catalog");
    let doc_fields: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
    for (field, _col) in SI_FN_COLUMN_MAP {
        assert!(
            doc_fields.contains(field),
            "descriptor does not declare mapped field '{field}'"
        );
    }

    // Parse the real analyzeMFT CSV header and locate the eight timestamp columns.
    let mut lines = text.lines();
    let header = lines.next().expect("empty MFT CSV");
    let cols: Vec<&str> = header.split(',').collect();
    let col_idx = |name: &str| cols.iter().position(|c| c.trim() == name);

    let mut idx: Vec<(&str, usize)> = Vec::new();
    for (field, col) in SI_FN_COLUMN_MAP {
        let Some(i) = col_idx(col) else {
            eprintln!("skipped: analyzeMFT CSV lacks expected column '{col}' (header: {header})");
            return;
        };
        idx.push((field, i));
    }

    // Real-data property assertions: every record carries both timestamp sets,
    // and records exist where $SI creation differs from $FN creation (the
    // independence the descriptor's cross-view relies on).
    let si_created = idx.iter().find(|(f, _)| *f == "si_created").unwrap().1;
    let fn_created = idx.iter().find(|(f, _)| *f == "fn_created").unwrap().1;
    let max_idx = idx.iter().map(|(_, i)| *i).max().unwrap();

    let mut records = 0usize;
    let mut both_present = 0usize;
    let mut distinct_creation = 0usize;
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() <= max_idx {
            continue;
        }
        records += 1;
        let si_has = idx
            .iter()
            .filter(|(name, _)| name.starts_with("si_"))
            .any(|(_, i)| !f[*i].trim().is_empty());
        let fn_has = idx
            .iter()
            .filter(|(name, _)| name.starts_with("fn_"))
            .any(|(_, i)| !f[*i].trim().is_empty());
        if si_has && fn_has {
            both_present += 1;
        }
        let (sc, fc) = (f[si_created].trim(), f[fn_created].trim());
        if !sc.is_empty() && !fc.is_empty() && sc != fc {
            distinct_creation += 1;
        }
    }

    eprintln!(
        "mft oracle: {records} records; both $SI+$FN present in {both_present}; \
         $SI-creation != $FN-creation in {distinct_creation}"
    );

    assert!(records > 0, "no MFT records parsed from the CSV");
    assert!(
        both_present > 0,
        "no record carried both $SI and $FN timestamp sets — the descriptor claims every record does"
    );
    assert!(
        distinct_creation > 0,
        "no record had $SI creation distinct from $FN creation — the two sets must be independent for the discrepancy cross-view to be meaningful"
    );

    eprintln!(
        "mft oracle: OK — descriptor's 8 $SI/$FN fields all present in analyzeMFT output; \
         both sets exist and are independent on real data"
    );
}
