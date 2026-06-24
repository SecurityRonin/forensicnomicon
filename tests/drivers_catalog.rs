//! Synthetic unit tests for the LOLDrivers BYOVD **denylist**
//! ([`KNOWN_VULNERABLE_DRIVERS`] / [`is_known_vulnerable_driver`]).
//!
//! These cover the committed positive/negative cases (a real LOLDriver name ⇒
//! flagged; an ordinary Windows driver ⇒ not flagged) and the lookup mechanics
//! (case-insensitivity, optional `.sys` suffix). The real-corpus true-negative
//! confirmation against the DC01 SYSTEM hive lives in
//! `tests/drivers_dc01_clean.rs` (env-gated).
//!
//! Tier note (honest): the denylist is sourced from the authoritative LOLDrivers
//! dataset (independent third party). `rtcore64.sys` and `dbutil_2_3.sys` are
//! both well-known, real LOLDrivers entries (RTCore64 — the MSI Afterburner
//! driver abused by RobbinHood/many BYOVD campaigns; DBUtil_2_3 — the Dell
//! firmware-update driver, CVE-2021-21551).

use forensicnomicon::drivers::{is_known_vulnerable_driver, KNOWN_VULNERABLE_DRIVERS};

#[test]
fn denylist_is_non_trivial() {
    // The LOLDrivers dataset carries hundreds of distinct real driver basenames.
    assert!(
        KNOWN_VULNERABLE_DRIVERS.len() >= 500,
        "expected the full LOLDrivers basename set, got {}",
        KNOWN_VULNERABLE_DRIVERS.len()
    );
}

#[test]
fn all_entries_lowercase_bare_sys() {
    for &d in KNOWN_VULNERABLE_DRIVERS {
        assert_eq!(d, d.to_ascii_lowercase(), "not lowercase: {d}");
        assert!(d.ends_with(".sys"), "not a .sys basename: {d}");
        assert!(
            !d.contains('\\') && !d.contains('/'),
            "basename contains a path separator: {d}"
        );
    }
}

#[test]
fn no_duplicate_entries() {
    let mut seen = std::collections::BTreeSet::new();
    for &d in KNOWN_VULNERABLE_DRIVERS {
        assert!(seen.insert(d), "duplicate: {d}");
    }
}

// --- positive: real LOLDrivers entries flagged ---

#[test]
fn flags_rtcore64() {
    assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"rtcore64.sys"));
    assert!(is_known_vulnerable_driver("rtcore64.sys"));
    assert!(is_known_vulnerable_driver("rtcore64")); // .sys optional
}

#[test]
fn flags_dbutil_2_3() {
    assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"dbutil_2_3.sys"));
    assert!(is_known_vulnerable_driver("dbutil_2_3.sys"));
}

#[test]
fn flags_case_insensitively() {
    assert!(is_known_vulnerable_driver("RTCore64.sys"));
    assert!(is_known_vulnerable_driver("DBUTIL_2_3.SYS"));
}

#[test]
fn flags_trimmed() {
    assert!(is_known_vulnerable_driver("  rtcore64.sys  "));
}

// --- negative: ordinary Windows drivers NOT flagged ---

#[test]
fn does_not_flag_ntfs() {
    assert!(!KNOWN_VULNERABLE_DRIVERS.contains(&"ntfs.sys"));
    assert!(!is_known_vulnerable_driver("ntfs.sys"));
    assert!(!is_known_vulnerable_driver("NTFS.SYS"));
}

#[test]
fn does_not_flag_tcpip() {
    assert!(!KNOWN_VULNERABLE_DRIVERS.contains(&"tcpip.sys"));
    assert!(!is_known_vulnerable_driver("tcpip.sys"));
}

#[test]
fn does_not_flag_empty_or_random() {
    assert!(!is_known_vulnerable_driver(""));
    assert!(!is_known_vulnerable_driver("totally-not-a-driver.sys"));
}

// --- GentleKiller / Gentlemen RaaS BYOVD drop-names (ESET, 18 Jun 2026) ---
// https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
#[test]
fn flags_gentlekiller_byovd_drivers() {
    // Driver filenames GentleKiller's 8 variants + bundled third-party tools
    // drop to disk (ESET Tables 3-4 + IoC file table). Names-only leads.
    for d in [
        "eb.sys",              // Kaspersky variant (custom rootkit)
        "nseckrnl.sys",        // FACEIT variant (NSecsoft NSecKrnl)
        "gamedriverx64.sys",   // Valorant variant (Tower of Fantasy anti-cheat)
        "vgk.sys",             // Valorant variant drop name (masquerades as Vanguard)
        "stpm_old.sys",        // Javelin variant (Safetica ProcessMonitor, old)
        "stpm_new.sys",        // Javelin variant (Safetica ProcessMonitor, new)
        "dmx.sys",             // WatchDog variant (Zemana, CVE-2022-42045)
        "360netmon_wfp.sys",   // Network Blocker variant (Qihoo 360)
        "g11.sys",             // G11 variant drop name
        "poisonx.sys",         // G11 variant (PoisonX rootkit)
        "googleapiutil64.sys", // HexKiller (Baidu BdApi)
        "throttleblood.sys",   // ThrottleBlood (ThrottleStop drop name)
        "havoc.sys",           // HavocKiller (Huawei Audio)
    ] {
        assert!(is_known_vulnerable_driver(d), "GentleKiller driver not flagged: {d}");
    }
}

// --- Unified BYOVD catalog: drift invariants (basename ↔ service-name) ---
#[test]
fn byovd_curated_basenames_are_in_denylist() {
    // Every curated BYOVD driver's file basename MUST be in the image denylist,
    // so the two match surfaces (image basename vs EVTX service name) can't drift.
    for d in forensicnomicon::drivers::BYOVD_CURATED {
        assert!(
            KNOWN_VULNERABLE_DRIVERS.contains(&d.file_basename),
            "curated BYOVD basename not in denylist: {} ({})",
            d.file_basename, d.label
        );
        assert!(!d.service_names.is_empty(), "no service names: {}", d.file_basename);
    }
}

#[test]
fn byovd_driver_names_are_derived_from_curated() {
    use forensicnomicon::drivers::BYOVD_CURATED;
    use forensicnomicon::heuristics::evtx::BYOVD_DRIVER_NAMES;
    let derived: Vec<&str> = BYOVD_CURATED
        .iter()
        .flat_map(|d| d.service_names.iter().copied())
        .collect();
    assert_eq!(BYOVD_DRIVER_NAMES, derived.as_slice());
}

#[test]
fn byovd_driver_names_preserved() {
    use forensicnomicon::heuristics::evtx::BYOVD_DRIVER_NAMES;
    for s in ["RTCore64", "dbutil_2_3", "WinRing0_1_2_0", "ZemanaAntiMalware", "speedfan"] {
        assert!(BYOVD_DRIVER_NAMES.contains(&s), "lost service name: {s}");
    }
}
