//! The normalized cross-scheme forensic report vocabulary.

use forensicnomicon::report::{
    Category, Evidence, Finding, Location, Provenance, Report, Severity, Source, TimelineEvent,
};

fn finding(sev: Severity, code: &str) -> Finding {
    Finding {
        severity: sev,
        category: Category::Structure,
        code: code.to_string(),
        note: "observation".to_string(),
        source: Source {
            analyzer: "gpt-forensic".to_string(),
            scope: "partition 1".to_string(),
        },
        evidence: vec![Evidence {
            field: "first_lba".to_string(),
            value: "2048".to_string(),
            location: Some(Location::Lba(2048)),
        }],
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
fn report_reports_max_severity() {
    let mut r = Report::default();
    assert_eq!(r.max_severity(), None, "empty report is clean");
    r.findings.push(finding(Severity::Low, "X-LOW"));
    r.findings.push(finding(Severity::High, "X-HIGH"));
    assert_eq!(r.max_severity(), Some(Severity::High));
}

#[test]
fn report_holds_findings_provenance_and_timeline() {
    let mut r = Report::default();
    r.findings.push(finding(Severity::Medium, "X-MED"));
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
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.provenance.len(), 1);
    assert_eq!(r.timeline.len(), 1);
    assert_eq!(r.findings[0].evidence[0].location, Some(Location::Lba(2048)));
}

#[test]
fn location_variants_span_partition_and_filesystem_positions() {
    assert_ne!(Location::ByteOffset(0), Location::Lba(0));
    assert_ne!(
        Location::Path("/x".to_string()),
        Location::Field("x".to_string())
    );
}
