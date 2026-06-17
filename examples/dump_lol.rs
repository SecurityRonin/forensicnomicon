#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Serialize the full forensicnomicon catalog to JSON snapshots under `data/`.
//!
//! Run with:
//! ```text
//! cargo run --example dump_lol --features serde
//! ```
//!
//! Produces:
//! - `data/lolbas_windows.json`
//! - `data/lolbas_linux.json`
//! - `data/lolbas_macos.json`
//! - `data/lolbas_windows_cmdlets.json`
//! - `data/lolbas_windows_mmc.json`
//! - `data/lolbas_windows_wmi.json`
//! - `data/abusable_sites.json`
//! - `data/all.json` — combined object with all keys

use forensicnomicon::abusable_sites::ABUSABLE_SITES;
use forensicnomicon::lolbins::{
    LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS, LOLBAS_WINDOWS_MMC,
    LOLBAS_WINDOWS_WMI,
};
use std::fs;
use std::path::Path;

fn write_json<T: serde::Serialize + ?Sized>(path: &str, value: &T) {
    let json = serde_json::to_string_pretty(value).unwrap();
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, json).unwrap();
    println!("wrote {path}");
}

fn main() {
    write_json("data/lolbas_windows.json", LOLBAS_WINDOWS);
    write_json("data/lolbas_linux.json", LOLBAS_LINUX);
    write_json("data/lolbas_macos.json", LOLBAS_MACOS);
    write_json("data/lolbas_windows_cmdlets.json", LOLBAS_WINDOWS_CMDLETS);
    write_json("data/lolbas_windows_mmc.json", LOLBAS_WINDOWS_MMC);
    write_json("data/lolbas_windows_wmi.json", LOLBAS_WINDOWS_WMI);
    write_json("data/abusable_sites.json", ABUSABLE_SITES);

    let all = serde_json::json!({
        "lolbas_windows": LOLBAS_WINDOWS,
        "lolbas_linux": LOLBAS_LINUX,
        "lolbas_macos": LOLBAS_MACOS,
        "lolbas_windows_cmdlets": LOLBAS_WINDOWS_CMDLETS,
        "lolbas_windows_mmc": LOLBAS_WINDOWS_MMC,
        "lolbas_windows_wmi": LOLBAS_WINDOWS_WMI,
        "abusable_sites": ABUSABLE_SITES,
    });
    write_json("data/all.json", &all);

    println!(
        "done — {} lolbas_windows, {} lolbas_linux, {} lolbas_macos, \
         {} cmdlets, {} mmc, {} wmi, {} sites",
        LOLBAS_WINDOWS.len(),
        LOLBAS_LINUX.len(),
        LOLBAS_MACOS.len(),
        LOLBAS_WINDOWS_CMDLETS.len(),
        LOLBAS_WINDOWS_MMC.len(),
        LOLBAS_WINDOWS_WMI.len(),
        ABUSABLE_SITES.len(),
    );
}
