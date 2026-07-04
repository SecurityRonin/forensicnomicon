//! Volatility3-oracle validation (Tier-2, env-gated).
//!
//! Validates that each Windows memory-forensics descriptor's documented FIELDS
//! and their attributed source plugin faithfully match what the REAL `vol`
//! (Volatility3) plugin emits on a REAL memory image. This is documentation
//! fidelity checked against an independent oracle — the running Volatility3
//! engine — not against a fixture we authored. It is designed to catch exactly
//! the source-fidelity errors a code review can miss:
//!
//! - a descriptor claiming a column (e.g. thread `StartAddress`/`CreateTime`)
//!   from a plugin (`windows.handles`) that does not emit it, and
//! - a descriptor field (e.g. `in_pslist`) presented as a plugin column when it
//!   is actually a DERIVED cross-view the plugin never emits.
//!
//! GATING. This test only runs when ALL of the following hold:
//!   * env `FORENSICNOMICON_VOL3_ORACLE=1`
//!   * the `vol` binary is present (env `FORENSICNOMICON_VOL3_BIN` or the
//!     default mise path), and
//!   * the Windows memory image is present (env `FORENSICNOMICON_VOL3_IMAGE`
//!     or the default extracted memlabs-lab1 path).
//!
//! Otherwise it prints a `skipped: …` line and returns cleanly, so the default
//! `cargo test` run and the coverage gate are unaffected. On any vol failure or
//! timeout it SKIPS (returns) rather than failing — a missing oracle is not a
//! product defect.
//!
//! vol3 may download symbol tables on first run (needs network) and can be slow;
//! per-plugin runs use a generous timeout and their stdout is cached under /tmp
//! so reruns are fast.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use forensicnomicon_data::catalog::CATALOG;

/// A vol3 plugin and its real output column set, populated at runtime by running
/// the plugin and parsing the header row.
struct PluginColumns {
    /// Real TitleCase column headers emitted by the plugin, lowercased and with
    /// spaces stripped for tolerant matching (e.g. `Start VPN` -> `startvpn`).
    columns_norm: Vec<String>,
    /// The raw header line, for diagnostics.
    raw_header: String,
}

/// One documented descriptor field and where it is supposed to come from.
struct FieldOrigin {
    /// Descriptor field name (snake_case).
    field: &'static str,
    /// The vol3 plugin whose column this field mirrors, or `None` if the field
    /// is a DERIVED value that NO plugin emits as a column (e.g. `in_pslist`,
    /// which is the psscan-vs-pslist cross-view). A `None` field is asserted to
    /// be ABSENT from the primary plugin's real columns.
    plugin: Option<&'static str>,
    /// Expected real column (normalized) this field maps to when `plugin` is
    /// `Some`. Normalized the same way as `columns_norm`.
    expect_column_norm: &'static str,
    /// When `plugin` is `None` (derived), the primary plugin whose columns must
    /// NOT contain `expect_column_norm` (the miss-attribution guard).
    absent_from_plugin: Option<&'static str>,
}

/// The full mapping under test: descriptor id -> its fields' documented origins.
/// This table is the machine-checkable statement of "every field maps to a real
/// column of the plugin it is attributed to, and no field is attributed to a
/// plugin that doesn't emit it".
fn descriptor_field_map() -> Vec<(&'static str, Vec<FieldOrigin>)> {
    let f = |field, plugin, col| FieldOrigin {
        field,
        plugin: Some(plugin),
        expect_column_norm: col,
        absent_from_plugin: None,
    };
    let derived = |field, col, absent_from| FieldOrigin {
        field,
        plugin: None,
        expect_column_norm: col,
        absent_from_plugin: Some(absent_from),
    };
    vec![
        (
            "mem_process_injection",
            vec![
                f("pid", "windows.malfind", "pid"),
                f("process", "windows.malfind", "process"),
                f("start_vpn", "windows.malfind", "startvpn"),
                f("end_vpn", "windows.malfind", "endvpn"),
                f("protection", "windows.malfind", "protection"),
                f("commit_charge", "windows.malfind", "commitcharge"),
                f("private_memory", "windows.malfind", "privatememory"),
                f("vad_tag", "windows.malfind", "tag"),
                f("disasm_header", "windows.malfind", "disasm"),
            ],
        ),
        (
            "mem_network_scan",
            vec![
                f("proto", "windows.netscan", "proto"),
                f("local_addr", "windows.netscan", "localaddr"),
                f("local_port", "windows.netscan", "localport"),
                f("foreign_addr", "windows.netscan", "foreignaddr"),
                f("foreign_port", "windows.netscan", "foreignport"),
                f("state", "windows.netscan", "state"),
                f("pid", "windows.netscan", "pid"),
                f("owner", "windows.netscan", "owner"),
                f("created", "windows.netscan", "created"),
                f("pool_offset", "windows.netscan", "offset"),
            ],
        ),
        (
            "mem_handles_threads",
            vec![
                // Handle fields come from windows.handles.
                f("pid", "windows.handles", "pid"),
                f("process", "windows.handles", "process"),
                f("handle_value", "windows.handles", "handlevalue"),
                f("object_type", "windows.handles", "type"),
                f("granted_access", "windows.handles", "grantedaccess"),
                f("object_name", "windows.handles", "name"),
                // Thread fields come from windows.threads/thrdscan, NOT handles.
                // These both assert the column exists in threads AND (implicitly,
                // via the handles primary-plugin absence check below) that they
                // are not handles columns.
                f("tid", "windows.threads", "tid"),
                f("start_address", "windows.threads", "startaddress"),
                f("create_time", "windows.threads", "createtime"),
                // Guard: the thread columns must NOT appear in handles.py output
                // (the handles != threads misattribution that review must catch).
                derived("start_address", "startaddress", "windows.handles"),
                derived("create_time", "createtime", "windows.handles"),
            ],
        ),
        (
            "mem_kernel_callbacks",
            vec![
                f("callback_type", "windows.callbacks", "type"),
                f("callback", "windows.callbacks", "callback"),
                f("module", "windows.callbacks", "module"),
                f("symbol", "windows.callbacks", "symbol"),
                f("detail", "windows.callbacks", "detail"),
                // SSDT / driver fields come from separate plugins, not callbacks.
                f("ssdt_index", "windows.ssdt", "index"),
                f("ssdt_target", "windows.ssdt", "address"),
                f("driver_name", "windows.driverscan", "drivername"),
                // Guard: SSDT/driver columns must NOT be callbacks.py columns.
                derived("ssdt_index", "index", "windows.callbacks"),
                derived("driver_name", "drivername", "windows.callbacks"),
            ],
        ),
        (
            "mem_hidden_processes",
            vec![
                f("pid", "windows.psscan", "pid"),
                f("ppid", "windows.psscan", "ppid"),
                f("name", "windows.psscan", "imagefilename"),
                f("offset", "windows.psscan", "offset"),
                f("create_time", "windows.psscan", "createtime"),
                f("exit_time", "windows.psscan", "exittime"),
                // in_pslist is a DERIVED cross-view, NOT a psscan column.
                derived("in_pslist", "inpslist", "windows.psscan"),
            ],
        ),
    ]
}

fn normalize(col: &str) -> String {
    // Lowercase, drop spaces and any parenthesised offset-type suffix like
    // "Offset(V)" / "Offset(P)" so `offset` matches regardless of address space.
    let mut s = col.trim().to_ascii_lowercase();
    if let Some(paren) = s.find('(') {
        s.truncate(paren);
    }
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn vol_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FORENSICNOMICON_VOL3_BIN") {
        let pb = PathBuf::from(p);
        return pb.exists().then_some(pb);
    }
    let home = std::env::var("HOME").ok()?;
    let pb = PathBuf::from(home).join(".local/share/mise/installs/python/3.11/bin/vol");
    pb.exists().then_some(pb)
}

fn image_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FORENSICNOMICON_VOL3_IMAGE") {
        let pb = PathBuf::from(p);
        return pb.exists().then_some(pb);
    }
    let pb = PathBuf::from("/tmp/memlabs-lab1/MemoryDump_Lab1.raw");
    pb.exists().then_some(pb)
}

/// Run a vol3 plugin, caching stdout to /tmp so reruns are cheap. Returns the
/// normalized column header set, or `None` on any failure/timeout (caller skips).
fn run_plugin(vol: &Path, image: &Path, plugin: &str) -> Option<PluginColumns> {
    let cache = PathBuf::from(format!("/tmp/voloracle_{plugin}.txt"));
    let text = if cache.exists() && std::fs::metadata(&cache).map_or(0, |m| m.len()) > 0 {
        std::fs::read_to_string(&cache).ok()?
    } else {
        // vol has no per-run timeout flag; wrap in `timeout` when available so a
        // stuck symbol download cannot hang the suite. `timeout` exists on the
        // Linux CI images; on macOS it may be `gtimeout` or absent — fall back to
        // invoking vol directly (still bounded by the harness).
        let output = if which("timeout").is_some() {
            Command::new("timeout")
                .arg("900")
                .arg(vol)
                .arg("-q")
                .arg("-f")
                .arg(image)
                .arg(plugin)
                .output()
        } else {
            Command::new(vol)
                .arg("-q")
                .arg("-f")
                .arg(image)
                .arg(plugin)
                .output()
        };
        let output = output.ok()?;
        if !output.status.success() {
            eprintln!(
                "skipped-plugin: vol {plugin} exited {:?}; stderr tail: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .last()
                    .unwrap_or("")
            );
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let _ = std::fs::write(&cache, &text);
        text
    };

    // The header is the first tab-containing line after the "Volatility 3
    // Framework" banner. Progress/banner lines have no tabs.
    let header = text.lines().find(|l| l.contains('\t'))?;
    let columns_norm = header.split('\t').map(normalize).collect();
    Some(PluginColumns {
        columns_norm,
        raw_header: header.to_string(),
    })
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let cand = dir.join(bin);
        cand.exists().then_some(cand)
    })
}

#[test]
fn vol3_oracle_field_fidelity() {
    if std::env::var("FORENSICNOMICON_VOL3_ORACLE").as_deref() != Ok("1") {
        eprintln!("skipped: set FORENSICNOMICON_VOL3_ORACLE=1 to run the Volatility3 oracle test");
        return;
    }
    let Some(vol) = vol_bin() else {
        eprintln!(
            "skipped: vol binary not found (set FORENSICNOMICON_VOL3_BIN or install to the mise path)"
        );
        return;
    };
    let Some(image) = image_path() else {
        eprintln!(
            "skipped: Windows memory image not found (set FORENSICNOMICON_VOL3_IMAGE or extract memlabs-lab1 to /tmp/memlabs-lab1/MemoryDump_Lab1.raw)"
        );
        return;
    };
    eprintln!(
        "vol3 oracle: vol={} image={}",
        vol.display(),
        image.display()
    );

    let map = descriptor_field_map();

    // Collect the distinct plugins we need and run each once.
    let mut needed: Vec<&'static str> = map
        .iter()
        .flat_map(|(_, fields)| {
            fields
                .iter()
                .flat_map(|fo| fo.plugin.into_iter().chain(fo.absent_from_plugin))
        })
        .collect();
    needed.sort_unstable();
    needed.dedup();

    let mut cols: BTreeMap<&'static str, PluginColumns> = BTreeMap::new();
    for plugin in &needed {
        if let Some(pc) = run_plugin(&vol, &image, plugin) {
            eprintln!("  ran {plugin}: columns = [{}]", pc.raw_header);
            cols.insert(*plugin, pc);
        } else {
            eprintln!("skipped: vol plugin {plugin} did not produce a header (see above)");
            return;
        }
    }

    let mut failures: Vec<String> = Vec::new();

    for (id, fields) in &map {
        let desc = CATALOG
            .by_id(id)
            .unwrap_or_else(|| panic!("descriptor '{id}' missing from catalog"));
        let doc_fields: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();

        for fo in fields {
            // Every mapped field must actually be a documented field of the
            // descriptor (keeps this table honest against future edits).
            assert!(
                doc_fields.contains(&fo.field),
                "descriptor '{id}' mapping references field '{}' that the descriptor does not declare",
                fo.field
            );

            if let Some(plugin) = fo.plugin {
                let pc = &cols[plugin];
                let present = pc.columns_norm.iter().any(|c| c == fo.expect_column_norm);
                if !present {
                    failures.push(format!(
                        "descriptor '{id}' field '{}' is attributed to {plugin} column '{}', \
                         but {plugin}'s real columns are [{}]",
                        fo.field, fo.expect_column_norm, pc.raw_header
                    ));
                }
            } else {
                // Derived field: assert the column is ABSENT from the primary
                // plugin's real output (miss-attribution guard).
                let plugin = fo
                    .absent_from_plugin
                    .expect("derived field must name the plugin it must be absent from");
                let pc = &cols[plugin];
                let wrongly_present = pc.columns_norm.iter().any(|c| c == fo.expect_column_norm);
                if wrongly_present {
                    failures.push(format!(
                        "descriptor '{id}' field '{}' is DERIVED and must not be a {plugin} \
                         column, but {plugin} emits it: [{}]",
                        fo.field, pc.raw_header
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "vol3 oracle found {} descriptor/plugin mismatch(es):\n{}",
        failures.len(),
        failures.join("\n")
    );

    eprintln!(
        "vol3 oracle: OK — {} descriptors validated against {} real vol3 plugins",
        map.len(),
        cols.len()
    );
}
