//! Real-data isolation proof (Doer-Checker, tier-1 ground truth).
//!
//! Parses the genuine DFIRMadness "Szechuan Sauce" DC01 `SYSTEM` hive (453
//! services) and asserts that the known-good service-binary catalog isolates the
//! `coreupdater.exe` implant: of every standalone-OwnProcess (type `0x10`),
//! auto/boot/system-start service whose `ImagePath` is a *bare* `.exe` directly
//! in the `System32` root, all are catalogued EXCEPT `coreupdater.exe`.
//!
//! The hive is a large gitignored corpus owned by `issen`. This test is
//! env-gated on `ISSEN_DC01_SYSTEM_HIVE` (or the well-known fleet path) and
//! skips loud when absent — it never copies evidence into this repo.
//!
//! Corpus provenance: <https://github.com/securitygeeks/szechuan-sauce> /
//! DFIRMadness — see `docs/validation.md` and issen `docs/corpus-catalog.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use forensicnomicon::services::is_known_service_binary;
use winreg_core::hive::Hive;

/// Win32 own-process service type (`SERVICE_WIN32_OWN_PROCESS`).
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;

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

/// If `image_path` resolves to a bare `<name>.exe` living directly in the
/// `System32` root, return its lowercase basename; otherwise `None`.
fn system32_bare_exe(image_path: &str) -> Option<String> {
    let ip = image_path.trim();
    let exe = if let Some(stripped) = ip.strip_prefix('"') {
        stripped.split('"').next().unwrap_or("").to_string()
    } else {
        ip.split_whitespace().next().unwrap_or("").to_string()
    };
    let lower = exe.to_ascii_lowercase().replace('/', "\\");
    let lower = lower.trim_start_matches("\\??\\");
    if !lower.ends_with(".exe") {
        return None;
    }
    let needle = "system32\\";
    let after = lower.split(needle).nth(1)?;
    // directly in System32 root: no further path separator
    if after.is_empty() || after.contains('\\') {
        return None;
    }
    Some(after.to_string())
}

#[test]
fn catalog_isolates_coreupdater_on_real_dc01_hive() {
    let Some(path) = hive_path() else {
        eprintln!(
            "SKIP: DC01 SYSTEM hive not found. Set ISSEN_DC01_SYSTEM_HIVE or place the \
             szechuan-sauce corpus under ~/src/issen/tests/data/."
        );
        return;
    };

    let hive = Hive::from_path(&path).expect("open DC01 SYSTEM hive");

    // Resolve the current control set via Select\Current.
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

    let mut gate_set: Vec<String> = Vec::new();
    for sk in &subkeys {
        let stype = sk
            .value("Type")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32().ok());
        let start = sk
            .value("Start")
            .ok()
            .flatten()
            .and_then(|v| v.as_u32().ok());
        let image = sk
            .value("ImagePath")
            .ok()
            .flatten()
            .and_then(|v| v.as_string().ok());

        let (Some(SERVICE_WIN32_OWN_PROCESS), Some(start), Some(image)) = (stype, start, image)
        else {
            continue;
        };
        // Start: 0=Boot, 1=System, 2=Automatic (3=Manual, 4=Disabled excluded).
        if start > 2 {
            continue;
        }
        if let Some(base) = system32_bare_exe(&image) {
            gate_set.push(base);
        }
    }
    gate_set.sort();
    gate_set.dedup();

    // Ground truth (verified against the real hive): exactly these 7.
    assert!(
        gate_set.contains(&"coreupdater.exe".to_string()),
        "the implant must be in the gate set; got {gate_set:?}"
    );

    let unknown: Vec<&String> = gate_set
        .iter()
        .filter(|b| !is_known_service_binary(b))
        .collect();

    assert_eq!(
        unknown,
        vec![&"coreupdater.exe".to_string()],
        "the catalog must isolate coreupdater.exe as the LONE unknown; \
         every legit System32-root OwnProcess service must be catalogued. \
         Unexpected unknowns (catalog gaps): {unknown:?}"
    );

    // And the implant itself is correctly NOT in the catalog.
    assert!(!is_known_service_binary("coreupdater.exe"));
}
