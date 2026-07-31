#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::needless_raw_string_hashes
    )
)]
mod codegen;
mod dedup;
mod github;
mod hive;
mod normalize;
mod record;
mod sources;
mod triage;

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{fs, io};

use codegen::{generate_module_header, generate_static};
use dedup::{load_catalog, load_catalog_excluding, CatalogIndex};
use record::IngestRecord;

/// CLI options parsed from argv.
struct Opts {
    sources: Vec<String>,
    output_dir: PathBuf,
    dry_run: bool,
    limit: Option<usize>,
    verbose: bool,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut sources = Vec::new();
        let mut output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../data/src/catalog/descriptors/generated");
        let mut dry_run = false;
        let mut limit = None;
        let mut verbose = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--source" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--source requires a value".to_string());
                    }
                    for s in args[i].split(',') {
                        sources.push(s.trim().to_string());
                    }
                }
                "--output" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--output requires a value".to_string());
                    }
                    output_dir = PathBuf::from(&args[i]);
                }
                "--dry-run" => dry_run = true,
                "--limit" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--limit requires a value".to_string());
                    }
                    limit = Some(
                        args[i]
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --limit value: {}", args[i]))?,
                    );
                }
                "-v" | "--verbose" => verbose = true,
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
            i += 1;
        }

        if sources.is_empty() {
            sources.push("all".to_string());
        }

        Ok(Opts {
            sources,
            output_dir,
            dry_run,
            limit,
            verbose,
        })
    }
}

/// A source's fetcher: everything it takes to turn an upstream corpus into
/// records.
type Fetcher = fn() -> Vec<IngestRecord>;

/// Every ingestable source. Registering one here is the only edit needed — the
/// lookup, the `--source all` expansion and the `--help` text all derive from
/// this table.
const SOURCES: &[(&str, Fetcher)] = &[
    ("regedit", sources::regedit::fetch_regedit_records),
    ("kape", fetch_kape),
    ("fa", sources::fa::fetch_all_fa_artifacts),
    (
        "velociraptor",
        sources::velociraptor::fetch_velociraptor_artifacts,
    ),
    ("evtx", sources::evtx::fetch_evtx_records),
    ("browsers", sources::browsers::browser_artifacts),
    ("nirsoft", sources::nirsoft::nirsoft_artifacts),
    (
        "dfir_scripts",
        sources::dfir_scripts::fetch_dfir_scripts_artifacts,
    ),
];

/// KAPE reports a failed fetch; the other sources warn internally and return
/// what they have.
fn fetch_kape() -> Vec<IngestRecord> {
    sources::kape::fetch_kape_targets().unwrap_or_else(|e| {
        eprintln!("WARN: kape fetch error: {e}");
        Vec::new()
    })
}

/// The fetcher registered under `name`, if any.
fn fetcher_for(name: &str) -> Option<Fetcher> {
    SOURCES
        .iter()
        .find(|(registered, _)| *registered == name)
        .map(|(_, fetcher)| *fetcher)
}

/// Resolve the requested source names, expanding `all` to every registered
/// source.
fn expand_sources(requested: &[String]) -> Vec<&'static str> {
    if requested.iter().any(|s| s == "all") {
        return SOURCES.iter().map(|(name, _)| *name).collect();
    }
    requested
        .iter()
        .filter_map(|name| {
            let resolved = SOURCES.iter().find(|(registered, _)| registered == name);
            if resolved.is_none() {
                eprintln!("WARN: unknown source '{name}', skipping");
            }
            resolved.map(|(name, _)| *name)
        })
        .collect()
}

fn usage() -> String {
    let names: Vec<&str> = SOURCES.iter().map(|(name, _)| *name).collect();
    format!(
        r"forensicnomicon ingest pipeline

Usage: ingest [OPTIONS]

Options:
  --source <SOURCE>   {}|all
                      (comma-separated for multiple)
  --output <DIR>      Output directory for .rs files
                      [default: crates/data/src/catalog/descriptors/generated]
  --dry-run           Print stats without writing files
  --limit <N>         Max records per source (for testing)
  -v, --verbose       Verbose output
  -h, --help          Show this help
",
        names.join("|")
    )
}

fn print_usage() {
    println!("{}", usage());
}

fn run_source(name: &str, limit: Option<usize>, verbose: bool) -> Vec<IngestRecord> {
    if verbose {
        eprintln!("  Fetching source: {name}");
    }
    let Some(fetch) = fetcher_for(name) else {
        eprintln!("WARN: unknown source '{name}', skipping");
        return Vec::new();
    };
    let mut records = fetch();

    if let Some(n) = limit {
        records.truncate(n);
    }

    if verbose {
        eprintln!("    → {} records fetched", records.len());
    }

    records
}

struct SourceSummary {
    source: String,
    fetched: usize,
    new: usize,
    written: bool,
}

/// The file a source's records are generated into.
fn generated_file_name(source_name: &str) -> String {
    format!("{source_name}_generated.rs")
}

/// The dedup baseline for regenerating `source_name`.
///
/// A regeneration rewrites the source's module in full, so that module is not a
/// prior claim on its own records — including it would make every record the
/// source already contributed look like a duplicate of itself and the rewrite
/// would drop it. The rest of the catalog (hand-written descriptors and the
/// other sources' modules) still dedups normally.
fn baseline_for_source(catalog_dir: &Path, source_name: &str) -> io::Result<CatalogIndex> {
    load_catalog_excluding(catalog_dir, &[generated_file_name(source_name)])
}

/// The records of `records` the catalog does not already carry: not an id the
/// `baseline` knows, not a registry key path it already covers, and not
/// something an earlier source in this same run has just generated.
fn select_new_records(
    records: Vec<IngestRecord>,
    baseline: &CatalogIndex,
    already_generated: &mut HashSet<String>,
) -> Vec<IngestRecord> {
    records
        .into_iter()
        .filter(|r| {
            !baseline.ids.is_duplicate(&r.id)
                && !baseline.paths.covers(&r.key_path)
                && !already_generated.contains(&r.id)
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let opts = match Opts::parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {e}");
            print_usage();
            std::process::exit(1);
        }
    };

    // Resolve the output dir relative to the workspace root
    let output_dir = if opts.output_dir.is_absolute() {
        opts.output_dir.clone()
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|e| {
            eprintln!("WARN: could not resolve current dir: {e}; using \".\"");
            PathBuf::from(".")
        });
        cwd.join(&opts.output_dir)
    };

    // Load the existing catalog for deduplication
    let catalog_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/src/catalog/descriptors");
    let catalog = load_catalog(&catalog_dir).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: could not read the catalog at {}: {e}",
            catalog_dir.display()
        );
        eprintln!("       Every record would look net-new; refusing to generate duplicates.");
        std::process::exit(1);
    });

    if opts.verbose {
        eprintln!(
            "Loaded {} existing catalog IDs and {} key paths",
            catalog.ids.len(),
            catalog.paths.len()
        );
    }

    let source_names = expand_sources(&opts.sources);

    if !opts.dry_run {
        fs::create_dir_all(&output_dir).unwrap_or_else(|e| {
            eprintln!(
                "ERROR: could not create output dir {}: {e}",
                output_dir.display()
            );
            std::process::exit(1);
        });
    }

    let mut summaries: Vec<SourceSummary> = Vec::new();
    let mut all_generated_ids: HashSet<String> = HashSet::new();

    for source_name in &source_names {
        let records = run_source(source_name, opts.limit, opts.verbose);
        let fetched = records.len();

        // Deduplicate against the catalog — by id, and by the registry key path
        // a sibling source may already have catalogued under another id — and
        // against what this run has already generated. The baseline is re-read
        // per source so it reflects the modules rewritten earlier in this run,
        // and it excludes this source's own module, which is about to be
        // rewritten in full.
        let baseline = baseline_for_source(&catalog_dir, source_name).unwrap_or_else(|e| {
            eprintln!(
                "ERROR: could not read the catalog at {}: {e}",
                catalog_dir.display()
            );
            eprintln!("       Every record would look net-new; refusing to generate duplicates.");
            std::process::exit(1);
        });
        let new_records = select_new_records(records, &baseline, &mut all_generated_ids);
        let new_count = new_records.len();

        for r in &new_records {
            all_generated_ids.insert(r.id.clone());
        }

        if opts.verbose && new_count < fetched {
            eprintln!(
                "  [{source_name}] {} duplicates skipped",
                fetched - new_count
            );
        }

        let written = if !opts.dry_run && !new_records.is_empty() {
            let out_path = output_dir.join(generated_file_name(source_name));

            let header = generate_module_header(source_name, new_records.len());
            let mut content = header;

            let mut static_names: Vec<String> = Vec::new();
            for rec in &new_records {
                content.push_str(&generate_static(rec));
                content.push('\n');
                static_names.push(rec.id.to_ascii_uppercase());
            }

            // Summary comment listing all statics
            let _ = writeln!(
                content,
                "// ── Generated entries ({}) ─────────────────────────────────────────────────",
                new_records.len()
            );
            let _ = writeln!(
                content,
                "// pub(crate) static GENERATED_{}_ENTRIES: &[&ArtifactDescriptor] = &[",
                source_name.to_ascii_uppercase()
            );
            for name in &static_names {
                let _ = writeln!(content, "//     &{name},");
            }
            content.push_str("// ];\n");

            match fs::write(&out_path, &content) {
                Ok(()) => {
                    if opts.verbose {
                        eprintln!(
                            "  [{source_name}] Written {} records to {}",
                            new_count,
                            out_path.display()
                        );
                    }
                    true
                }
                Err(e) => {
                    eprintln!("ERROR: failed to write {}: {e}", out_path.display());
                    false
                }
            }
        } else {
            false
        };

        summaries.push(SourceSummary {
            source: (*source_name).to_string(),
            fetched,
            new: new_count,
            written,
        });
    }

    // Print summary table
    println!();
    println!(
        "{:<16} {:>8} {:>8} {:>8}",
        "Source", "Fetched", "New", "Written"
    );
    println!("{}", "-".repeat(44));
    let mut total_fetched = 0;
    let mut total_new = 0;
    for s in &summaries {
        let written_str = if s.written {
            "yes"
        } else if opts.dry_run {
            "dry-run"
        } else {
            "no"
        };
        println!(
            "{:<16} {:>8} {:>8} {:>8}",
            s.source, s.fetched, s.new, written_str
        );
        total_fetched += s.fetched;
        total_new += s.new;
    }
    println!("{}", "-".repeat(44));
    println!("{:<16} {:>8} {:>8}", "TOTAL", total_fetched, total_new);
    println!();

    if opts.dry_run {
        println!("(dry-run: no files written)");
    } else if total_new > 0 {
        println!("Output written to: {}", output_dir.display());
        println!();
        println!("To wire into the catalog, add to crates/data/src/catalog/descriptors/mod.rs:");
        for s in summaries.iter().filter(|s| s.written) {
            println!(
                "  mod generated {{ pub(super) mod {}_generated; }}",
                s.source
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_source_resolves_to_a_fetcher() {
        assert!(!SOURCES.is_empty(), "no sources registered");
        for (name, _) in SOURCES {
            assert!(
                fetcher_for(name).is_some(),
                "registered source '{name}' does not resolve"
            );
        }
    }

    #[test]
    fn source_names_are_unique() {
        let mut seen = HashSet::new();
        for (name, _) in SOURCES {
            assert!(seen.insert(*name), "'{name}' is registered twice");
        }
    }

    #[test]
    fn an_unregistered_name_resolves_to_nothing() {
        assert!(fetcher_for("not_a_source").is_none());
    }

    #[test]
    fn every_registered_source_runs_under_source_all() {
        // A source missing from the "all" expansion is silently never run.
        let all = expand_sources(&["all".to_string()]);
        for (name, _) in SOURCES {
            assert!(all.contains(name), "'{name}' is never run by --source all");
        }
        assert_eq!(all.len(), SOURCES.len());
    }

    /// Write a catalog dir holding one hand-written descriptor plus a
    /// `<source>_generated.rs` carrying `ids`, exactly as a prior run left it.
    fn catalog_with_generated_module(source: &str, ids: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("mod.rs"),
            "    id: \"handwritten_run_key\",\n    key_path: \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",\n",
        )
        .expect("write hand-written");
        let mut generated = String::new();
        for (id, key_path) in ids {
            let _ = writeln!(
                generated,
                "pub(crate) static {}: ArtifactDescriptor = ArtifactDescriptor {{",
                id.to_ascii_uppercase()
            );
            let _ = writeln!(generated, "    id: \"{id}\",");
            let _ = writeln!(
                generated,
                "    key_path: \"{}\",",
                key_path.replace('\\', "\\\\")
            );
            generated.push_str("};\n");
        }
        std::fs::create_dir_all(dir.path().join("generated")).expect("mkdir generated");
        std::fs::write(
            dir.path()
                .join("generated")
                .join(generated_file_name(source)),
            generated,
        )
        .expect("write generated");
        dir
    }

    #[test]
    fn regenerating_a_source_keeps_its_whole_corpus() {
        // The destructive-rewrite bug: each `{source}_generated.rs` is rebuilt
        // from the *new* records only and written whole. If the dedup baseline
        // includes the source's own previously-generated module, every record
        // the source already contributed is treated as a duplicate of itself,
        // and the rewrite empties the file — deleting thousands of descriptors
        // that `descriptors/mod.rs` still references by name.
        let dir = catalog_with_generated_module(
            "regedit",
            &[
                ("regedit_portproxy", r"CurrentControlSet\Services\PortProxy"),
                ("regedit_safeboot", r"CurrentControlSet\Control\SafeBoot"),
                (
                    "regedit_appinit",
                    r"Microsoft\Windows NT\CurrentVersion\Windows",
                ),
            ],
        );
        let fetched = vec![
            IngestRecord::registry_key(
                "regedit_portproxy",
                "PortProxy",
                "regedit",
                Some("HKLM\\SYSTEM".to_string()),
                r"CurrentControlSet\Services\PortProxy",
                "netsh portproxy mappings",
            ),
            IngestRecord::registry_key(
                "regedit_safeboot",
                "SafeBoot",
                "regedit",
                Some("HKLM\\SYSTEM".to_string()),
                r"CurrentControlSet\Control\SafeBoot",
                "safe-mode service allow-list",
            ),
            IngestRecord::registry_key(
                "regedit_appinit",
                "AppInit_DLLs",
                "regedit",
                Some("HKLM\\SOFTWARE".to_string()),
                r"Microsoft\Windows NT\CurrentVersion\Windows",
                "DLL injection persistence",
            ),
        ];

        let baseline = baseline_for_source(dir.path(), "regedit").expect("baseline");
        let kept = select_new_records(fetched, &baseline, &mut HashSet::new());

        assert_eq!(
            kept.len(),
            3,
            "regenerating regedit must rewrite its module with the full corpus, \
             not the delta against itself; kept: {:?}",
            kept.iter().map(|r| r.id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_source_that_yields_one_id_twice_generates_it_once() {
        // Two upstream entries can reduce to the same id — velociraptor yields
        // 44 such collisions across 26 ids (five distinct rules all name
        // `velociraptor_file_users`). Emitting each one writes two
        // `pub(crate) static` items with the same name, and the generated
        // module stops compiling. The run-scoped id set is what makes an id
        // generatable at most once, so it has to be consulted and extended per
        // record, not once per finished source.
        let dir = catalog_with_generated_module("velociraptor", &[]);
        let twice = |key: &str| {
            IngestRecord::registry_key(
                "velociraptor_file_users",
                "Users",
                "velociraptor",
                Some("HKLM\\SOFTWARE".to_string()),
                key,
                "collides on id",
            )
        };
        let fetched = vec![twice(r"Alpha\Users"), twice(r"Beta\Users")];

        let baseline = baseline_for_source(dir.path(), "velociraptor").expect("baseline");
        let mut generated = HashSet::new();
        let kept = select_new_records(fetched, &baseline, &mut generated);

        assert_eq!(
            kept.len(),
            1,
            "an id may be generated once per run; a second record carrying it \
             would emit a duplicate static name"
        );
    }

    #[test]
    fn regenerating_a_source_still_dedups_against_the_rest_of_the_catalog() {
        // The twin of the test above: excluding the source's own module must not
        // blind the run to a hand-written descriptor or a sibling source that
        // already covers the same id or registry key path.
        let dir = catalog_with_generated_module(
            "regedit",
            &[("regedit_portproxy", r"CurrentControlSet\Services\PortProxy")],
        );
        // A sibling source's module — not the one being regenerated.
        std::fs::write(
            dir.path()
                .join("generated")
                .join(generated_file_name("kape")),
            "    id: \"kape_amcache\",\n    key_path: \"\",\n",
        )
        .expect("write sibling");

        let fetched = vec![
            // duplicate id of a sibling source's record
            IngestRecord::registry_key("kape_amcache", "Amcache", "regedit", None, "", "dup id"),
            // duplicate key path of the hand-written descriptor
            IngestRecord::registry_key(
                "regedit_run_key",
                "Run",
                "regedit",
                Some("HKLM\\SOFTWARE".to_string()),
                r"Microsoft\Windows\CurrentVersion\Run",
                "dup path",
            ),
            // genuinely new
            IngestRecord::registry_key(
                "regedit_portproxy",
                "PortProxy",
                "regedit",
                Some("HKLM\\SYSTEM".to_string()),
                r"CurrentControlSet\Services\PortProxy",
                "its own prior record",
            ),
        ];

        let baseline = baseline_for_source(dir.path(), "regedit").expect("baseline");
        let kept = select_new_records(fetched, &baseline, &mut HashSet::new());
        let kept_ids: Vec<&str> = kept.iter().map(|r| r.id.as_str()).collect();

        assert_eq!(
            kept_ids,
            vec!["regedit_portproxy"],
            "only the source's own prior record survives; the sibling id and the \
             hand-written key path must still dedup"
        );
    }

    #[test]
    fn help_lists_every_registered_source() {
        // The help text is the only place a user learns a source exists.
        let help = usage();
        for (name, _) in SOURCES {
            assert!(help.contains(name), "'{name}' is missing from --help");
        }
        assert!(help.contains("all"), "--help omits the 'all' pseudo-source");
    }
}
