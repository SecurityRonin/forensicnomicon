//! Cross-source triage consistency.
//!
//! Triage priority is a property of the artifact text (its name and its
//! description), not of which upstream project happened to catalogue it. The
//! same wording fed through any adapter must therefore come out with the same
//! `TriagePriority`, and no generated record may exceed the documented ceiling.
//!
//! The ceiling is stated in the fleet catalog rules: `Critical` means
//! "credential access, direct evidence of compromise, must-have for any IR" and
//! is reserved for a handwritten descriptor that also carries a curated
//! `volatility` / `evidence_strength` assessment. Generated records carry
//! neither (see `codegen::generate_static`, which emits `evidence_strength:
//! None` and `volatility: None`), so they cap at `High`.

use crate::sources::{fa, kape, regedit, velociraptor};

/// Build the four source-specific documents that all carry the *same* artifact
/// name and the *same* descriptive text, and return each adapter's triage
/// verdict as `(source, priority)`.
fn triage_across_sources(name: &str, text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();

    let reb = format!(
        "Description: fixture\nKeys:\n    -\n        Description: {name}\n        HiveType: HKLM\n        Category: Fixture\n        KeyPath: Software\\Fixture\\Key\n        Recursive: false\n        Comment: {text}\n"
    );
    let recs = regedit::parse_reb(&reb);
    assert_eq!(recs.len(), 1, "regedit fixture must yield one record");
    out.push(("regedit", recs[0].triage_priority.clone()));

    let tkape = format!(
        "Description: fixture\nTargets:\n    -\n        Name: {name}\n        Category: Fixture\n        Path: C:\\Fixture\\\n        FileMask: sample.bin\n        IsDirectory: false\n        Comment: {text}\n"
    );
    let recs = kape::parse_tkape(&tkape, "Fixture");
    assert_eq!(recs.len(), 1, "kape fixture must yield one record");
    out.push(("kape", recs[0].triage_priority.clone()));

    let fa_yaml = format!(
        "---\nname: {name}\ndoc: {text}\nsources:\n- type: REGISTRY_KEY\n  attributes:\n    keys:\n    - 'HKEY_LOCAL_MACHINE\\Software\\Fixture\\Key'\nsupported_os: [Windows]\nurls: []\n"
    );
    let recs = fa::parse_fa_yaml(&fa_yaml);
    assert_eq!(recs.len(), 1, "fa fixture must yield one record");
    out.push(("fa", recs[0].triage_priority.clone()));

    let velo_yaml = format!(
        "name: {name}\ndescription: {text}\nparameters:\n  - name: FixtureKey\n    default: HKEY_LOCAL_MACHINE\\Software\\Fixture\\Key\n"
    );
    let recs = velociraptor::parse_velociraptor_yaml(&velo_yaml);
    assert_eq!(recs.len(), 1, "velociraptor fixture must yield one record");
    out.push(("velociraptor", recs[0].triage_priority.clone()));

    out
}

/// Artifact wordings that four independently-written ladders disagreed on.
const CASES: &[(&str, &str)] = &[
    // credential access — fa capped at High, the other three said Critical
    ("Cached Domain Credentials", "Cached credential material"),
    // execution evidence — kape's ladder knew none of these words
    ("Shimcache", "AppCompatCache execution evidence"),
    // lsass — present in fa/velociraptor, absent from kape/regedit
    ("LSASS Process Memory", "Dumps lsass memory"),
    // lateral movement — only regedit's ladder knew the word
    (
        "PortProxy v4ToV4",
        "Port proxying, a lateral movement indicator",
    ),
];

#[test]
fn same_artifact_text_gets_the_same_triage_from_every_source() {
    for (name, text) in CASES {
        let verdicts = triage_across_sources(name, text);
        let (first_source, first) = &verdicts[0];
        for (source, priority) in &verdicts[1..] {
            assert_eq!(
                priority, first,
                "'{name} / {text}': {source} says {priority} but {first_source} says {first} \
                 — triage must depend on the artifact text, not on which source catalogued it"
            );
        }
    }
}

#[test]
fn no_source_exceeds_the_documented_high_ceiling() {
    for (name, text) in CASES {
        for (source, priority) in triage_across_sources(name, text) {
            assert_ne!(
                priority, "Critical",
                "'{name} / {text}': {source} emitted Critical; generated records carry no \
                 curated volatility/evidence assessment, so they cap at High"
            );
        }
    }
}
