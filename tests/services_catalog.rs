//! Unit-level assertions for the known-good Windows service-binary catalog.
//!
//! These run with no external data — they pin the catalog API surface and a
//! representative cross-section of the documented entries. The real-data
//! isolation proof against the DC01 SYSTEM hive lives in
//! `services_dc01_isolation.rs` (env-gated).

use forensicnomicon::services::{is_known_service_binary, KNOWN_WINDOWS_SERVICE_BINARIES};

#[test]
fn catalog_is_non_trivial() {
    // A comprehensive catalog spans core OS + AD DS + server roles + MS platform.
    assert!(
        KNOWN_WINDOWS_SERVICE_BINARIES.len() >= 40,
        "catalog should be comprehensive across OS / DC / server-role / MS-platform binaries, got {}",
        KNOWN_WINDOWS_SERVICE_BINARIES.len()
    );
}

#[test]
fn catalog_entries_are_lowercase_basenames() {
    for &b in KNOWN_WINDOWS_SERVICE_BINARIES {
        assert_eq!(b, b.to_ascii_lowercase(), "entry must be lowercase: {b}");
        assert!(
            b.ends_with(".exe"),
            "entry must be a bare .exe basename: {b}"
        );
        assert!(
            !b.contains('\\') && !b.contains('/'),
            "entry must be a basename, not a path: {b}"
        );
    }
}

#[test]
fn catalog_has_no_duplicates() {
    let mut seen = std::collections::BTreeSet::new();
    for &b in KNOWN_WINDOWS_SERVICE_BINARIES {
        assert!(seen.insert(b), "duplicate catalog entry: {b}");
    }
}

// --- the six legit DC01 System32-root OwnProcess service binaries MUST be present ---
#[test]
fn covers_dc01_legit_six() {
    for legit in [
        "dfssvc.exe",
        "dfsrs.exe",
        "dns.exe",
        "ismserv.exe",
        "msdtc.exe",
        "sppsvc.exe",
    ] {
        assert!(
            is_known_service_binary(legit),
            "legit DC service binary must be catalogued: {legit}"
        );
    }
}

// --- core OS standalone OwnProcess services ---
#[test]
fn covers_core_os() {
    for b in [
        "services.exe",
        "svchost.exe",
        "spoolsv.exe",
        "lsass.exe",
        "msdtc.exe",
        "vssvc.exe",
        "searchindexer.exe",
        "sppsvc.exe",
        "dllhost.exe",
        "alg.exe",
        "locator.exe",
        "snmptrap.exe",
        "vds.exe",
    ] {
        assert!(is_known_service_binary(b), "core OS service missing: {b}");
    }
}

// --- AD DS / domain-controller role services ---
#[test]
fn covers_dc_roles() {
    for b in [
        "dns.exe",
        "dfssvc.exe",
        "dfsrs.exe",
        "ismserv.exe",
        "ntfrs.exe",
        "certsrv.exe",
        "wins.exe",
    ] {
        assert!(is_known_service_binary(b), "DC-role service missing: {b}");
    }
}

// --- common Microsoft platform services ---
#[test]
fn covers_ms_platform() {
    for b in ["msmpeng.exe", "nissrv.exe"] {
        assert!(
            is_known_service_binary(b),
            "MS-platform service missing: {b}"
        );
    }
}

#[test]
fn is_known_service_binary_is_case_insensitive() {
    assert!(is_known_service_binary("MSDTC.EXE"));
    assert!(is_known_service_binary("Dns.Exe"));
    assert!(is_known_service_binary("SppSvc.exe"));
}

#[test]
fn is_known_service_binary_accepts_with_or_without_exe() {
    assert!(is_known_service_binary("msdtc"));
    assert!(is_known_service_binary("msdtc.exe"));
    assert!(is_known_service_binary("DNS"));
}

#[test]
fn the_implant_is_not_known() {
    assert!(!is_known_service_binary("coreupdater.exe"));
    assert!(!is_known_service_binary("coreupdater"));
}

#[test]
fn random_name_is_not_known() {
    assert!(!is_known_service_binary("totally-not-a-service.exe"));
    assert!(!is_known_service_binary(""));
}
