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
use std::fs;
use std::path::PathBuf;

use codegen::{generate_module_header, generate_static};
use dedup::load_catalog;
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
        // against what this run has already generated.
        let new_records: Vec<IngestRecord> = records
            .into_iter()
            .filter(|r| {
                !catalog.ids.is_duplicate(&r.id)
                    && !catalog.paths.covers(&r.key_path)
                    && !all_generated_ids.contains(&r.id)
            })
            .collect();
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
            let module_name = format!("{source_name}_generated");
            let file_name = format!("{module_name}.rs");
            let out_path = output_dir.join(&file_name);

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
