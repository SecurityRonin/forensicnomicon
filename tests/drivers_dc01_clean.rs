//! Real-data true-negative confirmation for the LOLDrivers BYOVD **denylist**
//! (Doer-Checker; **Tier 2** — authoritative third-party denylist validated
//! against a real corpus that contains no BYOVD).
//!
//! Parses the genuine DFIRMadness "Szechuan Sauce" DC01 `SYSTEM` hive and
//! collects every driver service's image basename — `Type` `0x01`
//! (`SERVICE_KERNEL_DRIVER`) or `0x02` (`SERVICE_FILE_SYSTEM_DRIVER`), `.sys`
//! image — then asserts that **none** of them is in the LOLDrivers denylist
//! ([`is_known_vulnerable_driver`]).
//!
//! This DC is clean of BYOVD (its implant is a user-mode OwnProcess service,
//! `coreupdater.exe`, covered by the exe catalog), so the expected result is
//! **0 matches** — a true-negative confirmation that the denylist does not
//! false-flag a real domain controller's ~250 legitimate third-party + Windows
//! drivers. If any driver DOES match, the test surfaces it loudly: that would be
//! a genuine BYOVD finding, not a test bug.
//!
//! The hive is a large gitignored corpus owned by `issen`; this test is
//! env-gated on `ISSEN_DC01_SYSTEM_HIVE` (or the well-known fleet path) and
//! skips loud when absent — it never copies evidence into this repo.
//!
//! Corpus provenance: <https://github.com/securitygeeks/szechuan-sauce> /
//! DFIRMadness — see `docs/validation.md` and issen `docs/corpus-catalog.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use forensicnomicon::drivers::is_known_vulnerable_driver;
use winreg_core::hive::Hive;

/// Kernel device driver (`SERVICE_KERNEL_DRIVER`).
const SERVICE_KERNEL_DRIVER: u32 = 0x01;
/// File-system driver (`SERVICE_FILE_SYSTEM_DRIVER`).
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x02;

fn hive_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ISSEN_DC01_SYSTEM_HIVE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Well-known fleet corpus location (issen-owned, gitignored).
    let home = std::env::var("HOME").ok()?;
    let pb = PathBuf::from(home).join(
        "src/issen/tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/SYSTEM",
    );
    if pb.exists() {
        Some(pb)
    } else {
        None
    }
}

/// Lowercase `.sys` basename of a driver `ImagePath` (a `REG_EXPAND_SZ` like
/// `\SystemRoot\System32\drivers\ntfs.sys` or `system32\DRIVERS\foo.sys`).
/// Returns `None` if the image is not a `.sys` file.
fn sys_basename(image_path: &str) -> Option<String> {
    let lower = image_path.trim().to_ascii_lowercase().replace('/', "\\");
    let base = lower.rsplit('\\').next()?.trim().to_string();
    if base.ends_with(".sys") {
        Some(base)
    } else {
        None
    }
}

#[test]
fn no_dc01_driver_is_known_vulnerable() {
    let Some(path) = hive_path() else {
        eprintln!(
            "SKIP: DC01 SYSTEM hive not found. Set ISSEN_DC01_SYSTEM_HIVE or place the \
             szechuan-sauce corpus under ~/src/issen/tests/data/."
        );
        return;
    };

    let hive = Hive::from_path(&path).expect("open DC01 SYSTEM hive");

    let current = hive
        .open_key("Select")
        .expect("open Select")
        .expect("Select key present")
        .value("Current")
        .expect("read Current")
        .expect("Current value present")
        .as_u32()
        .expect("Current as u32");
    let services_path = format!("ControlSet{current:03}\\Services");

    let services = hive
        .open_key(&services_path)
        .expect("open Services")
        .expect("Services key present");

    let subkeys = services.subkeys().expect("enumerate services");
    assert!(
        subkeys.len() >= 400,
        "expected the full ~453-service DC01 hive, got {}",
        subkeys.len()
    );

    // Collect every driver-service `.sys` basename (Type 1 or 2).
    let mut basenames: Vec<String> = Vec::new();
    for sk in &subkeys {
        let stype = sk
            .value("Type")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32().ok());
        let image = sk
            .value("ImagePath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok());

        let Some(stype) = stype else { continue };
        if stype != SERVICE_KERNEL_DRIVER && stype != SERVICE_FILE_SYSTEM_DRIVER {
            continue;
        }
        // Driver services without an explicit ImagePath default to
        // System32\drivers\<servicename>.sys; fall back to the key name.
        let base = match image.as_deref().and_then(sys_basename) {
            Some(b) => b,
            None => format!("{}.sys", sk.name().to_ascii_lowercase()),
        };
        basenames.push(base);
    }
    basenames.sort();
    basenames.dedup();

    // Ground truth: this DC carries hundreds of driver services.
    assert!(
        basenames.len() >= 200,
        "expected the DC01 driver set (~250), got {}",
        basenames.len()
    );

    // True-negative: a clean DC has no BYOVD. Any match is a real finding —
    // surface it loudly rather than silently passing.
    let matches: Vec<&String> = basenames
        .iter()
        .filter(|b| is_known_vulnerable_driver(b))
        .collect();

    assert!(
        matches.is_empty(),
        "BYOVD denylist matched {} DC01 driver(s) — investigate (a clean DC \
         should have 0): {matches:?}",
        matches.len()
    );
}
