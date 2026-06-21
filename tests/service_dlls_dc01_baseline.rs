//! Real-data baseline-completeness proof for the svchost `ServiceDll` catalog
//! (Doer-Checker; **Tier 2** — real-corpus baseline completeness, not a
//! masquerade-isolation proof).
//!
//! Parses the genuine DFIRMadness "Szechuan Sauce" DC01 `SYSTEM` hive and
//! collects every svchost-hosted service's `Parameters\ServiceDll` (117 rows →
//! 106 unique DLL basenames on this hive). It then asserts the known-good
//! catalog [`is_known_service_dll`] recognises **all** of them — i.e. the
//! baseline is complete against the real DC's loaded service DLLs, so a future
//! *unknown* ServiceDll is a genuine masquerade lead rather than a catalog gap.
//!
//! ## Tier note (honest)
//!
//! Unlike the standalone-exe catalog — where the real DC01 corpus contains the
//! `coreupdater.exe` OwnProcess implant and the test proves the catalog isolates
//! it as the lone unknown — **this hive carries no malicious `ServiceDll`** (its
//! implant is OwnProcess, covered by the exe catalog). So this is **not** a
//! real-masquerade-isolation proof. The real-data claim here is narrower and
//! honest: *baseline completeness over the genuine 106 unique ServiceDlls*. The
//! masquerade case (an `evil.dll` / a `\Temp\` ServiceDll flagged as unknown) is
//! covered by synthetic unit tests in `tests/service_dlls_catalog.rs`.
//!
//! The hive is a large gitignored corpus owned by `issen`; this test is
//! env-gated on `ISSEN_DC01_SYSTEM_HIVE` (or the well-known fleet path) and
//! skips loud when absent — it never copies evidence into this repo.
//!
//! Corpus provenance: <https://github.com/securitygeeks/szechuan-sauce> /
//! DFIRMadness — see `docs/validation.md` and issen `docs/corpus-catalog.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use forensicnomicon::services::is_known_service_dll;
use winreg_core::hive::Hive;

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

/// Lowercase `.dll` basename of a `ServiceDll` value (which may be a raw
/// `REG_EXPAND_SZ` like `%SystemRoot%\System32\dnsrslvr.dll`).
fn dll_basename(service_dll: &str) -> Option<String> {
    let lower = service_dll.trim().to_ascii_lowercase().replace('/', "\\");
    let base = lower.rsplit('\\').next()?.trim().to_string();
    if base.ends_with(".dll") {
        Some(base)
    } else {
        None
    }
}

#[test]
fn catalog_covers_every_real_dc01_service_dll() {
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

    // Collect every svchost-hosted ServiceDll (Parameters\ServiceDll).
    let mut rows = 0usize;
    let mut basenames: Vec<String> = Vec::new();
    for sk in &subkeys {
        let dll = sk
            .subkey("Parameters")
            .ok()
            .flatten()
            .and_then(|p| p.value("ServiceDll").ok().flatten())
            .and_then(|v| v.as_string().ok());
        let Some(dll) = dll else { continue };
        if let Some(base) = dll_basename(&dll) {
            rows += 1;
            basenames.push(base);
        }
    }
    basenames.sort();
    basenames.dedup();

    // Ground truth verified against the real hive: 117 ServiceDll rows resolve
    // to 106 unique DLL basenames (several DLLs host multiple services, e.g.
    // rpcss.dll → DcomLaunch + RpcSs, icsvc.dll → 7 Hyper-V integration svcs).
    assert_eq!(rows, 117, "expected 117 ServiceDll rows on the DC01 hive");
    assert_eq!(
        basenames.len(),
        106,
        "expected 106 unique ServiceDll basenames on the DC01 hive"
    );

    // Baseline-completeness: every real ServiceDll must be in the catalog.
    let unknown: Vec<&String> = basenames
        .iter()
        .filter(|b| !is_known_service_dll(b))
        .collect();

    assert!(
        unknown.is_empty(),
        "catalog gap — these real DC01 ServiceDlls are NOT covered (add them): {unknown:?}"
    );
}
