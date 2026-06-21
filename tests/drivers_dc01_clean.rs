//! Real-data validation for the LOLDrivers BYOVD **denylist**
//! (Doer-Checker; **Tier 2** — authoritative third-party denylist validated
//! against a real corpus that contains no BYOVD).
//!
//! Parses the genuine DFIRMadness "Szechuan Sauce" DC01 `SYSTEM` hive and
//! collects every driver service's image basename — `Type` `0x01`
//! (`SERVICE_KERNEL_DRIVER`) or `0x02` (`SERVICE_FILE_SYSTEM_DRIVER`), `.sys`
//! image — then runs each through the LOLDrivers denylist
//! ([`is_known_vulnerable_driver`]).
//!
//! This DC is clean of BYOVD (its implant is a user-mode OwnProcess service,
//! `coreupdater.exe`, covered by the exe catalog), so the *intent* is a
//! true-negative confirmation. The real-data result, however, exposes the
//! known limitation of **name-only** matching: exactly three of the DC's ~250
//! legitimate drivers carry names that LOLDrivers *also* tracks as
//! vulnerable/malicious samples — `afd.sys` (WinSock Ancillary Function
//! Driver), `monitor.sys` (Monitor Class Function Driver), and `usbxhci.sys`
//! (USB 3.0 xHCI controller). These are genuine, Microsoft-shipped OS drivers
//! on this host; the hits are **false positives of name-matching**, not BYOVD.
//! They are the empirical demonstration of the module-doc caveat: a name match
//! is a *lead* a legitimate namesake can trip, and hash-matching is the precise
//! form. The test asserts this *exact* collision set, so any **new, unexpected**
//! match (a real BYOVD whose name is not one of these three legit OS drivers)
//! still fails loudly.
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

    // A clean DC carries no BYOVD, but name-only matching collides with three
    // legitimate, Microsoft-shipped OS drivers whose names LOLDrivers also
    // tracks as vulnerable/malicious samples (see the module docs). Those are
    // false positives of name-matching, NOT findings on this host. Assert the
    // EXACT collision set: a new, unexpected match (a real BYOVD not named like
    // one of these legit OS drivers) must still fail loudly.
    let mut matches: Vec<&String> = basenames
        .iter()
        .filter(|b| is_known_vulnerable_driver(b))
        .collect();
    matches.sort();

    // Ground truth (verified against the real hive): exactly these three legit
    // OS drivers collide by name with LOLDrivers entries on a clean DC.
    let expected_collisions = ["afd.sys", "monitor.sys", "usbxhci.sys"];
    let got: Vec<&str> = matches.iter().map(|s| s.as_str()).collect();

    assert_eq!(
        got, expected_collisions,
        "BYOVD name-match set changed. Expected only the known legit-OS-driver \
         name collisions {expected_collisions:?}; any OTHER match is a real BYOVD \
         lead — investigate. Got: {got:?}"
    );
}
