//! The normalized cross-scheme forensic report vocabulary — superset model.
//!
//! These tests pin the shared model every SecurityRonin analyzer normalizes
//! into: a 5-level `Severity` (optional, so "unrated" is distinct from `Info`),
//! a builder-first `Finding` carrying MITRE/confidence/occurrence/subject
//! context, and the `Observation` producer trait analyzers implement on their
//! own typed anomaly kinds.

use forensicnomicon::report::{
    Category, Confidence, ExternalRef, Finding, Location, Observation, Provenance, Report, Severity,
    Source, SubjectRef, TimelineEvent,
};

fn src() -> Source {
    Source {
        analyzer: "vmdk-forensic".to_string(),
        scope: "extent".to_string(),
        version: Some("0.6.0".to_string()),
    }
}

#[test]
fn severity_orders_info_below_critical() {
    assert!(Severity::Critical > Severity::Info);
    assert!(Severity::High > Severity::Medium);
    assert_eq!(
        [Severity::Low, Severity::Critical, Severity::Medium]
            .into_iter()
            .max(),
        Some(Severity::Critical)
    );
}

#[test]
fn confidence_rejects_out_of_range_and_nan() {
    assert!(Confidence::new(-0.1).is_none());
    assert!(Confidence::new(1.1).is_none());
    assert!(Confidence::new(f32::NAN).is_none());
    assert_eq!(Confidence::new(0.8).map(Confidence::get), Some(0.8));
}

#[test]
fn finding_builder_assembles_a_rated_observation() {
    let f = Finding::observation(Severity::High, Category::Integrity, "VMDK-RGD-MISMATCH")
        .note("redundant GD diverges from primary; grain-table contents differ")
        .source(src())
        .evidence_at("primary_gte", "0x1234", Location::Lba(64))
        .evidence("redundant_gte", "0x5678")
        .mitre("T1565.001")
        .confidence(Confidence::new(0.9).unwrap())
        .occurrences(3)
        .tag("rgd")
        .build();

    assert_eq!(f.severity, Some(Severity::High));
    assert_eq!(f.category, Category::Integrity);
    assert_eq!(f.code, "VMDK-RGD-MISMATCH");
    assert_eq!(f.evidence.len(), 2);
    assert_eq!(f.evidence[0].location, Some(Location::Lba(64)));
    assert_eq!(f.evidence[1].location, None);
    assert_eq!(
        f.context.external_refs,
        vec![ExternalRef::mitre_attack("T1565.001")]
    );
    assert_eq!(f.context.confidence.map(Confidence::get), Some(0.9));
    assert_eq!(f.context.occurrences.map(|n| n.get()), Some(3));
    assert_eq!(f.context.tags, vec!["rgd"]);
}

#[test]
fn finding_can_be_explicitly_unrated() {
    // exec-pe / state-history emit findings they deliberately do not score.
    let f = Finding::unrated(Category::Structure, "PE-WX-SECTION")
        .note("section is simultaneously writable and executable")
        .source(Source {
            analyzer: "exec-pe-forensic".to_string(),
            scope: ".text".to_string(),
            version: None,
        })
        .build();
    assert_eq!(f.severity, None, "unrated is distinct from Info");
}

#[test]
fn new_location_variants_cover_non_disk_media() {
    assert_ne!(Location::Rva(0x0040_1000), Location::ByteOffset(0x0040_1000));
    assert_ne!(Location::RecordId(4624), Location::Lba(4624));
    let _ = Location::Key("HKLM\\SYSTEM\\CurrentControlSet".to_string());
    let _ = Location::Other {
        space: "memory:va".to_string(),
        value: 0xdead_beef,
    };
}

#[test]
fn subjects_carry_non_disk_entities() {
    let f = Finding::observation(Severity::Critical, Category::Threat, "MEM-PROC-HOLLOW")
        .note("process image differs from on-disk backing")
        .source(src())
        .subject(SubjectRef {
            scheme: "memory".to_string(),
            kind: "process".to_string(),
            id: "pid:4242".to_string(),
            label: Some("evil.exe".to_string()),
        })
        .build();
    assert_eq!(f.subjects.len(), 1);
    assert_eq!(f.subjects[0].kind, "process");
}

/// A demo analyzer-local anomaly kind, exercising the producer trait the way
/// every migrated crate will implement it on its own `AnomalyKind`.
#[derive(Clone, Copy)]
enum DemoKind {
    Mismatch,
    Clean,
}

impl Observation for DemoKind {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            DemoKind::Mismatch => Severity::High,
            DemoKind::Clean => Severity::Info,
        })
    }
    fn category(&self) -> Category {
        Category::Integrity
    }
    fn code(&self) -> &'static str {
        match self {
            DemoKind::Mismatch => "DEMO-MISMATCH",
            DemoKind::Clean => "DEMO-CLEAN",
        }
    }
    fn note(&self) -> String {
        "demo observation".to_string()
    }
    fn mitre(&self) -> &'static [&'static str] {
        match self {
            DemoKind::Mismatch => &["T1565.001"],
            DemoKind::Clean => &[],
        }
    }
}

#[test]
fn observation_trait_produces_a_canonical_finding() {
    let f = DemoKind::Mismatch.to_finding(src());
    assert_eq!(f.severity, Some(Severity::High));
    assert_eq!(f.category, Category::Integrity);
    assert_eq!(f.code, "DEMO-MISMATCH");
    assert_eq!(f.source.analyzer, "vmdk-forensic");
    assert_eq!(
        f.context.external_refs,
        vec![ExternalRef::mitre_attack("T1565.001")]
    );
}

#[test]
fn report_helpers_filter_by_severity_and_unrated() {
    let mut r = Report::default();
    assert_eq!(r.max_severity(), None, "empty report is clean");
    r.findings.push(
        Finding::observation(Severity::Low, Category::Structure, "X-LOW")
            .source(src())
            .build(),
    );
    r.findings.push(
        Finding::observation(Severity::High, Category::Structure, "X-HIGH")
            .source(src())
            .build(),
    );
    r.findings.push(
        Finding::unrated(Category::Structure, "X-UNRATED")
            .source(src())
            .build(),
    );
    assert_eq!(r.max_severity(), Some(Severity::High));
    assert_eq!(r.findings_at_least(Severity::Medium).count(), 1);
    assert_eq!(r.unrated_findings().count(), 1);
}

#[test]
fn report_holds_provenance_and_timeline() {
    let mut r = Report::default();
    r.provenance.push(Provenance {
        label: "alignment".to_string(),
        value: "LBA 2048 (1 MiB) — Vista+ era".to_string(),
        source: "mbr-forensic".to_string(),
    });
    r.timeline.push(TimelineEvent {
        when: Some("2019".to_string()),
        source: "gpt-forensic".to_string(),
        event: "EFI System Partition created".to_string(),
    });
    assert_eq!(r.provenance.len(), 1);
    assert_eq!(r.timeline.len(), 1);
}

#[test]
fn mitre_external_ref_is_consistent_with_language() {
    // MITRE refs are "consistent with", never a verdict — the type carries a
    // technique id, the narration stays observational.
    let r = ExternalRef::mitre_attack("T1003");
    assert_eq!(r.scheme, "mitre-attack");
    assert_eq!(r.id, "T1003");
    assert_eq!(r.url, None);
}

#[test]
fn category_from_code_classifies_by_keyword() {
    use forensicnomicon::report::Category;
    assert_eq!(Category::from_code("GPT-HEADER-CRC-INVALID"), Category::Integrity);
    assert_eq!(Category::from_code("MBR-PART-OVERLAP"), Category::Structure);
    assert_eq!(Category::from_code("MBR-PART-OOB"), Category::Structure);
    assert_eq!(Category::from_code("MBR-GAP-SLACK"), Category::Residue);
    assert_eq!(Category::from_code("MBR-GAP-WIPED"), Category::Concealment);
    assert_eq!(Category::from_code("MBR-BOOT-MALWARE"), Category::Threat);
    assert_eq!(Category::from_code("UNCLASSIFIED-CODE"), Category::Structure);
}

/// A kind that does NOT override category() — it must fall back to code-classification.
struct DefaultCatKind;
impl Observation for DefaultCatKind {
    fn severity(&self) -> Option<Severity> {
        Some(Severity::Low)
    }
    fn code(&self) -> &'static str {
        "DEMO-PART-OVERLAP"
    }
    fn note(&self) -> String {
        "x".to_string()
    }
}

#[test]
fn observation_category_defaults_to_code_classification() {
    let f = DefaultCatKind.to_finding(src());
    assert_eq!(f.category, Category::Structure);
}
