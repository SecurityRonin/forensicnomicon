//! Unit-level assertions for the known-good svchost `ServiceDll` catalog.
//!
//! These run with no external data — they pin the catalog API surface, a
//! representative cross-section of the documented entries, and the synthetic
//! masquerade case (an `evil.dll` / a `\Temp\`-resident ServiceDll is NOT in the
//! baseline, so a downstream analyzer would flag it as a T1543.003 / T1036.005
//! lead). The real-data baseline-completeness proof against the DC01 SYSTEM hive
//! lives in `service_dlls_dc01_baseline.rs` (env-gated).

use forensicnomicon::services::{is_known_service_dll, KNOWN_WINDOWS_SERVICE_DLLS};

#[test]
fn catalog_is_non_trivial() {
    // Spans core OS + networking + AD DS + platform svchost ServiceDlls (the
    // full 106 unique basenames observed on the real DC01 hive, plus headroom).
    assert!(
        KNOWN_WINDOWS_SERVICE_DLLS.len() >= 100,
        "ServiceDll catalog should cover the real DC01 baseline (106 unique), got {}",
        KNOWN_WINDOWS_SERVICE_DLLS.len()
    );
}

#[test]
fn catalog_entries_are_lowercase_dll_basenames() {
    for &d in KNOWN_WINDOWS_SERVICE_DLLS {
        assert_eq!(d, d.to_ascii_lowercase(), "entry must be lowercase: {d}");
        assert!(
            d.ends_with(".dll"),
            "entry must be a bare .dll basename: {d}"
        );
        assert!(
            !d.contains('\\') && !d.contains('/'),
            "entry must be a basename, not a path: {d}"
        );
    }
}

#[test]
fn catalog_has_no_duplicates() {
    let mut seen = std::collections::BTreeSet::new();
    for &d in KNOWN_WINDOWS_SERVICE_DLLS {
        assert!(seen.insert(d), "duplicate catalog entry: {d}");
    }
}

// --- canonical svchost ServiceDlls cited in the task brief ---
#[test]
fn covers_brief_examples() {
    for d in ["dnsrslvr.dll", "schedsvc.dll", "qmgr.dll"] {
        assert!(
            is_known_service_dll(d),
            "brief example must be catalogued: {d}"
        );
    }
}

// --- core OS / RPC / networking svchost ServiceDlls ---
#[test]
fn covers_core_os() {
    for d in [
        "rpcss.dll",
        "cryptsvc.dll",
        "bfe.dll",
        "mpssvc.dll",
        "dhcpcore.dll",
        "dnsrslvr.dll",
        "iphlpsvc.dll",
        "nlasvc.dll",
        "wuaueng.dll",
        "profsvc.dll",
        "gpsvc.dll",
        "wmisvc.dll",
        "schedsvc.dll",
        "termsrv.dll",
        "lsm.dll",
    ] {
        assert!(is_known_service_dll(d), "core OS ServiceDll missing: {d}");
    }
}

// --- AD DS / domain-controller-role svchost ServiceDlls ---
#[test]
fn covers_dc_roles() {
    for d in [
        "ntdsa.dll",     // NTDS (Active Directory Domain Services)
        "kdcsvc.dll",    // Kerberos Key Distribution Center
        "netlogon.dll",  // Netlogon
        "dsrolesrv.dll", // DS Role Server
        "kdssvc.dll",    // Microsoft Key Distribution Service
    ] {
        assert!(is_known_service_dll(d), "DC-role ServiceDll missing: {d}");
    }
}

#[test]
fn is_known_service_dll_is_case_insensitive() {
    assert!(is_known_service_dll("DNSRSLVR.DLL"));
    assert!(is_known_service_dll("SchedSvc.Dll"));
    assert!(is_known_service_dll("Qmgr.dll"));
}

#[test]
fn is_known_service_dll_accepts_with_or_without_dll() {
    assert!(is_known_service_dll("dnsrslvr"));
    assert!(is_known_service_dll("dnsrslvr.dll"));
    assert!(is_known_service_dll("QMGR"));
}

// --- the masquerade: an unknown ServiceDll is NOT in the catalog (the lead a
//     downstream analyzer would flag as T1543.003 / T1036.005). ---
#[test]
fn planted_evil_dll_is_unknown() {
    assert!(!is_known_service_dll("evil.dll"));
    assert!(!is_known_service_dll("evil"));
}

#[test]
fn servicedll_in_temp_basename_is_unknown() {
    // A downstream analyzer keys off both the path (\Temp\) AND the unknown
    // basename. The basename alone of a planted DLL is not catalogued.
    assert!(!is_known_service_dll("svchost_update.dll"));
    assert!(!is_known_service_dll("backdoor.dll"));
}

#[test]
fn random_name_is_not_known() {
    assert!(!is_known_service_dll("totally-not-a-service.dll"));
    assert!(!is_known_service_dll(""));
}

#[test]
fn whitespace_is_trimmed() {
    assert!(is_known_service_dll("  qmgr.dll  "));
}
