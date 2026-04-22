mod codegen;
mod dedup;
mod normalize;
mod record;
mod sources;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use codegen::{generate_module_header, generate_static};
use dedup::load_catalog_ids;
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
        let mut output_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/catalog/descriptors/generated");
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

fn print_usage() {
    println!(
        r#"forensicnomicon ingest pipeline

Usage: ingest [OPTIONS]

Options:
  --source <SOURCE>   regedit|kape|fa|velociraptor|evtx|browsers|nirsoft|all
                      (comma-separated for multiple)
  --output <DIR>      Output directory for .rs files
                      [default: src/catalog/descriptors/generated]
  --dry-run           Print stats without writing files
  --limit <N>         Max records per source (for testing)
  -v, --verbose       Verbose output
  -h, --help          Show this help
"#
    );
}

fn run_source(name: &str, limit: Option<usize>, verbose: bool) -> Vec<IngestRecord> {
    if verbose {
        eprintln!("  Fetching source: {name}");
    }
    let mut records = match name {
        "regedit" => sources::regedit::fetch_regedit_records(),
        "kape" => sources::kape::fetch_kape_targets().unwrap_or_else(|e| {
            eprintln!("WARN: kape fetch error: {e}");
            Vec::new()
        }),
        "fa" => sources::fa::fetch_all_fa_artifacts(),
        "velociraptor" => sources::velociraptor::fetch_velociraptor_artifacts(),
        "evtx" => sources::evtx::fetch_evtx_records(),
        "browsers" => sources::browsers::browser_artifacts(),
        "nirsoft" => sources::nirsoft::nirsoft_artifacts(),
        other => {
            eprintln!("WARN: unknown source '{other}', skipping");
            Vec::new()
        }
    };

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
        std::env::current_dir()
            .expect("cwd")
            .join(&opts.output_dir)
    };

    // Load existing catalog IDs for deduplication
    let catalog_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../src/catalog/descriptors");
    let existing_ids = load_catalog_ids(&catalog_dir).unwrap_or_else(|e| {
        eprintln!("WARN: could not load catalog IDs: {e}");
        dedup::IdSet::default()
    });

    if opts.verbose {
        eprintln!("Loaded {} existing catalog IDs", existing_ids.len());
    }

    // Expand "all" to every source
    let all_sources = ["regedit", "kape", "fa", "velociraptor", "evtx", "browsers", "nirsoft"];
    let source_names: Vec<&str> = if opts.sources.iter().any(|s| s == "all") {
        all_sources.iter().copied().collect()
    } else {
        opts.sources.iter().map(String::as_str).collect()
    };

    if !opts.dry_run {
        fs::create_dir_all(&output_dir).unwrap_or_else(|e| {
            eprintln!("ERROR: could not create output dir {}: {e}", output_dir.display());
            std::process::exit(1);
        });
    }

    let mut summaries: Vec<SourceSummary> = Vec::new();
    let mut all_generated_ids: HashSet<String> = HashSet::new();

    for source_name in &source_names {
        let records = run_source(source_name, opts.limit, opts.verbose);
        let fetched = records.len();

        // Deduplicate against catalog AND against already-generated this run
        let new_records: Vec<IngestRecord> = records
            .into_iter()
            .filter(|r| {
                !existing_ids.is_duplicate(&r.id) && !all_generated_ids.contains(&r.id)
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
            content.push_str(&format!(
                "// ── Generated entries ({}) ─────────────────────────────────────────────────\n",
                new_records.len()
            ));
            content.push_str(&format!(
                "// pub(crate) static GENERATED_{}_ENTRIES: &[&ArtifactDescriptor] = &[\n",
                source_name.to_ascii_uppercase()
            ));
            for name in &static_names {
                content.push_str(&format!("//     &{name},\n"));
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
                    eprintln!(
                        "ERROR: failed to write {}: {e}",
                        out_path.display()
                    );
                    false
                }
            }
        } else {
            false
        };

        summaries.push(SourceSummary {
            source: source_name.to_string(),
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
        println!(
            "Output written to: {}",
            output_dir.display()
        );
        println!();
        println!("To wire into the catalog, add to src/catalog/descriptors/mod.rs:");
        for s in summaries.iter().filter(|s| s.written) {
            println!("  mod generated {{ pub(super) mod {}_generated; }}", s.source);
        }
    }
}
