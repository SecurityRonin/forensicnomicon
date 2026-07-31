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
use dedup::{load_catalog, load_catalog_excluding, CatalogIndex, PathSet};
use record::IngestRecord;

/// CLI options parsed from argv.
struct Opts {
    sources: Vec<String>,
    output_dir: PathBuf,
    dry_run: bool,
    limit: Option<usize>,
    verbose: bool,
    /// Let a regenerated module shrink past the tolerance the partial-fetch
    /// guard enforces. For a contraction the operator already intends.
    allow_shrink: bool,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut sources = Vec::new();
        let mut output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../data/src/catalog/descriptors/generated");
        let mut dry_run = false;
        let mut limit = None;
        let mut verbose = false;
        let mut allow_shrink = false;

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
                "--allow-shrink" => allow_shrink = true,
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
            allow_shrink,
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
  --allow-shrink      Permit a module to lose more records than the
                      partial-fetch guard allows (deliberate contraction)
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

/// How much of a module a regeneration may drop before it looks like a failed
/// fetch rather than an upstream change.
const SHRINK_TOLERANCE: f64 = 0.10;

/// Descriptor statics already committed in `module`, or `None` when there is no
/// module yet to compare against.
fn committed_statics(module: &Path) -> Option<usize> {
    let source = fs::read_to_string(module).ok()?;
    Some(
        source
            .split("pub(crate) static ")
            .skip(1)
            .filter(|block| block.contains("id: \""))
            .count(),
    )
}

/// Why a rewrite of `source_name` must not proceed, if it must not.
///
/// A rewrite emits the source's whole corpus, so a fetch that returns only part
/// of one — a rate limit part-way through a paged listing, an upstream outage —
/// silently replaces the module with the fragment it managed to collect. The
/// records it dropped are indistinguishable from records upstream removed, so
/// nothing downstream can tell the difference: the run exits 0 and the catalog
/// is quietly smaller. Losing more than [`SHRINK_TOLERANCE`] of what is already
/// committed is treated as that failure and refused; `--allow-shrink` is how a
/// deliberate contraction says so.
#[allow(clippy::cast_precision_loss)]
fn shrink_refusal(source_name: &str, committed: usize, regenerated: usize) -> Option<String> {
    if committed == 0 {
        return None;
    }
    let floor = (committed as f64 * (1.0 - SHRINK_TOLERANCE)).floor();
    if (regenerated as f64) >= floor {
        return None;
    }
    let module = generated_file_name(source_name);
    let lost = committed - regenerated;
    let pct = (lost as f64 / committed as f64) * 100.0;
    let tol = SHRINK_TOLERANCE * 100.0;
    Some(format!(
        "ERROR: [{source_name}] refusing to rewrite {module}: {regenerated} records regenerated \
         against {committed} already committed — a loss of {lost} ({pct:.1}%), past the \
         {tol:.0}% tolerance.\n       \
         A full-corpus rewrite cannot tell a partial fetch from an upstream removal, so this is \
         treated as a failed fetch and the module is left untouched.\n       \
         Re-run once the source is reachable, or pass --allow-shrink if the contraction is \
         intended."
    ))
}

/// The dedup baseline for a run that regenerates `sources`.
///
/// A regeneration rewrites each of those modules in full, so none of them is a
/// prior claim on its own records — including one would make every record its
/// source already contributed look like a duplicate of itself and the rewrite
/// would drop it. Excluding all of them at once also takes the *order* the
/// sources happen to run in out of the result: a record no longer loses to a
/// sibling merely for having been written first, it competes in
/// [`select_records`]. The rest of the catalog — hand-written descriptors and
/// the modules this run leaves alone — still dedups normally.
fn baseline_for_run(catalog_dir: &Path, sources: &[&str]) -> io::Result<CatalogIndex> {
    let regenerated: Vec<String> = sources.iter().map(|s| generated_file_name(s)).collect();
    load_catalog_excluding(catalog_dir, &regenerated)
}

/// What a run fetched, per source, in source order.
type Fetched = Vec<(&'static str, Vec<IngestRecord>)>;

/// How much an ingested record tells an analyst, largest first.
///
/// Two sources describing one registry key rarely describe it equally well: one
/// maps it to an ATT&CK technique and says what the key is evidence of, the
/// other gives a bare label. When both cannot survive, that — not which source
/// happened to be fetched first — is what should decide, or a technique
/// mapping disappears from the catalog with the record that carried it.
///
/// A technique mapping outranks everything: it is the only field an analyst can
/// query the catalog *by*. Length of `meaning` then stands in for how much the
/// source actually says. `source_rank` breaks the remaining ties so the order is
/// total and the run reproducible.
fn richness(rec: &IngestRecord, source_rank: usize) -> (bool, usize, std::cmp::Reverse<usize>) {
    (
        !rec.mitre_techniques.is_empty(),
        rec.meaning.len(),
        std::cmp::Reverse(source_rank),
    )
}

/// Carry `retired`'s ATT&CK techniques over to the record that displaced it.
///
/// Sources disagree about which technique a key serves rather than about the
/// key: dfir-scripts maps `…\CurrentVersion\Policies\System` to credential
/// access under one entry, to defense evasion under another and to privilege
/// escalation under a third, all of them true. Picking a survivor and dropping
/// the rest would silently narrow which techniques the catalog can answer for
/// that key, so the survivor absorbs them. Its own come first and duplicates are
/// skipped, so the result is stable.
fn absorb_techniques(winner: &mut IngestRecord, retired: &IngestRecord) {
    for technique in &retired.mitre_techniques {
        if !winner.mitre_techniques.contains(technique) {
            winner.mitre_techniques.push(technique.clone());
        }
    }
}

/// Two key paths collide when either would suppress the other.
///
/// [`PathSet::covers`] is directional — a catalogued path covers any key that is
/// its suffix at a path boundary, which is how a hive-qualified path matches a
/// hive-relative one. Competing records have no established direction, so a
/// collision is the symmetric closure of that.
fn paths_collide(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let mut one = PathSet::default();
    one.insert(a);
    if one.covers(b) {
        return true;
    }
    let mut other = PathSet::default();
    other.insert(b);
    other.covers(a)
}

/// The records of `fetched` the catalog does not already carry, keyed back to
/// the source that produced them.
///
/// Three claims retire a record outright: an id the `baseline` already uses, a
/// registry key path it already covers, and an id this run has already
/// generated — the last covering a collision with another source *and* one
/// inside a source's own corpus, so two records that reduce to one id cannot
/// emit the same static name twice.
///
/// What remains competes for shared registry key paths by [`richness`], and each
/// source's survivors come back in the order it produced them.
fn select_records(fetched: &Fetched, baseline: &CatalogIndex) -> Fetched {
    let mut generated_ids: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(usize, usize, IngestRecord)> = Vec::new();

    for (rank, (_, records)) in fetched.iter().enumerate() {
        for (position, rec) in records.iter().enumerate() {
            if baseline.ids.is_duplicate(&rec.id)
                || baseline.paths.covers(&rec.key_path)
                || !generated_ids.insert(rec.id.clone())
            {
                continue;
            }
            candidates.push((rank, position, rec.clone()));
        }
    }

    // Richest first, so a record only ever loses a key path to a better one.
    candidates.sort_by(|(a_rank, a_pos, a), (b_rank, b_pos, b)| {
        richness(b, *b_rank)
            .cmp(&richness(a, *a_rank))
            .then(a_rank.cmp(b_rank))
            .then(a_pos.cmp(b_pos))
    });

    let mut kept: Vec<(usize, usize, IngestRecord)> = Vec::new();
    for candidate in candidates {
        if let Some((_, _, winner)) = kept
            .iter_mut()
            .find(|(_, _, k)| paths_collide(&k.key_path, &candidate.2.key_path))
        {
            absorb_techniques(winner, &candidate.2);
            continue;
        }
        kept.push(candidate);
    }

    // Back into per-source fetch order: the competition decides *which* records
    // survive, never how a module is laid out.
    kept.sort_by_key(|(rank, position, _)| (*rank, *position));
    let mut out: Fetched = fetched
        .iter()
        .map(|(name, _)| (*name, Vec::new()))
        .collect();
    for (rank, _, rec) in kept {
        out[rank].1.push(rec);
    }
    out
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
    let mut refused = false;

    // Every source is fetched before any is selected: a record must not lose a
    // shared key path to a sibling merely for having been fetched later.
    let fetched: Fetched = source_names
        .iter()
        .map(|name| (*name, run_source(name, opts.limit, opts.verbose)))
        .collect();
    let fetched_counts: Vec<usize> = fetched.iter().map(|(_, r)| r.len()).collect();

    let baseline = baseline_for_run(&catalog_dir, &source_names).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: could not read the catalog at {}: {e}",
            catalog_dir.display()
        );
        eprintln!("       Every record would look net-new; refusing to generate duplicates.");
        std::process::exit(1);
    });
    let selected = select_records(&fetched, &baseline);

    for ((source_name, new_records), fetched) in selected.into_iter().zip(fetched_counts) {
        let source_name = &source_name;
        let new_count = new_records.len();

        if opts.verbose && new_count < fetched {
            eprintln!(
                "  [{source_name}] {} duplicates skipped",
                fetched - new_count
            );
        }

        let out_path = output_dir.join(generated_file_name(source_name));
        if !opts.allow_shrink {
            if let Some(refusal) = committed_statics(&out_path)
                .and_then(|committed| shrink_refusal(source_name, committed, new_count))
            {
                eprintln!("{refusal}");
                refused = true;
                summaries.push(SourceSummary {
                    source: (*source_name).to_string(),
                    fetched,
                    new: new_count,
                    written: false,
                });
                continue;
            }
        }

        let written = if !opts.dry_run && !new_records.is_empty() {
            // The body is built first: the header's import list is derived from
            // which types the statics actually reference.
            let mut body = String::new();
            let mut static_names: Vec<String> = Vec::new();
            for rec in &new_records {
                body.push_str(&generate_static(rec));
                body.push('\n');
                static_names.push(rec.id.to_ascii_uppercase());
            }

            let mut content = generate_module_header(source_name, new_records.len(), &body);
            content.push_str(&body);

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

    // A refused module is a failed run, not a quiet skip: exiting 0 here is
    // exactly the silence the guard exists to break.
    if refused {
        std::process::exit(1);
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

    /// The survivors of a single-source selection.
    fn only(selected: Fetched) -> Vec<IngestRecord> {
        assert_eq!(selected.len(), 1, "expected one source");
        selected.into_iter().next().expect("one source").1
    }

    /// A record naming a registry key, with whatever meaning and techniques the
    /// source in question happens to supply.
    fn described(
        id: &str,
        source: &'static str,
        key_path: &str,
        meaning: &str,
        mitre: &[&str],
    ) -> IngestRecord {
        let mut rec = IngestRecord::registry_key(
            id,
            "Shell Folders",
            source,
            Some("HKLM\\SOFTWARE".to_string()),
            key_path,
            meaning,
        );
        rec.mitre_techniques = mitre.iter().map(|t| (*t).to_string()).collect();
        rec
    }

    #[test]
    fn the_survivor_absorbs_the_techniques_of_what_it_displaced() {
        // Sources disagree about which technique a key serves, not about the key.
        // dfir-scripts maps ...\CurrentVersion\Policies\System to credential
        // access under one entry, defense evasion under another and privilege
        // escalation under a third — all true of that key. Keeping one and
        // discarding the rest narrows which techniques the catalog can answer
        // for it, whichever one wins.
        let dir = catalog_with_generated_module("dfir_scripts", &[]);
        let key = r"Software\Microsoft\Windows\CurrentVersion\Policies\System";
        let fetched: Fetched = vec![(
            "dfir_scripts",
            vec![
                described(
                    "dfir_scripts_currentversion_policies_system",
                    "dfir_scripts",
                    key,
                    "Policies System — a longer meaning, so this record wins the key path.",
                    &["T1562.001", "T1003.001"],
                ),
                described(
                    "dfir_scripts_currentversion_policies_system_2",
                    "dfir_scripts",
                    key,
                    "Policies System — a middling meaning, second richest of the three.",
                    &["T1486", "T1003.001"],
                ),
                described(
                    "dfir_scripts_currentversion_policies_system_3",
                    "dfir_scripts",
                    key,
                    "Policies System — terse.",
                    &["T1548.002"],
                ),
            ],
        )];

        let baseline = baseline_for_run(dir.path(), &["dfir_scripts"]).expect("baseline");
        let kept = only(select_records(&fetched, &baseline));

        assert_eq!(kept.len(), 1, "one descriptor per key path");
        assert_eq!(
            kept[0].mitre_techniques,
            vec!["T1562.001", "T1003.001", "T1486", "T1548.002"],
            "the survivor must answer for every technique the key was mapped to, \
             its own first and without repeats"
        );
    }

    #[test]
    fn a_partial_fetch_may_not_rewrite_the_module() {
        // The rate-limited run that started this work fetched 0 records for four
        // sources; the empty-corpus check caught that. A fetch that returns
        // *part* of a corpus — a rate limit part-way through a paged listing —
        // has nothing to catch it: the module is rewritten with the fragment and
        // the run exits 0, so a silently smaller catalog is indistinguishable
        // from upstream having removed the records.
        let refusal = shrink_refusal("kape", 2435, 900).expect("a 63% loss must be refused");
        assert!(refusal.contains("2435"), "must name what is committed");
        assert!(refusal.contains("900"), "must name what was regenerated");
        assert!(
            refusal.contains("--allow-shrink"),
            "must name the way to proceed deliberately"
        );
    }

    #[test]
    fn an_ordinary_upstream_change_is_not_a_partial_fetch() {
        // Upstream corpora gain and lose a handful of entries between runs; only
        // a loss big enough to look like a failed fetch is refused.
        assert!(
            shrink_refusal("fa", 2604, 2603).is_none(),
            "one record fewer"
        );
        assert!(shrink_refusal("evtx", 995, 1014).is_none(), "a gain");
        assert!(
            shrink_refusal("browsers", 0, 36).is_none(),
            "a module that does not exist yet has nothing to shrink from"
        );
    }

    #[test]
    fn committed_statics_counts_only_descriptors() {
        // The trailing summary block of a generated module is a commented-out
        // `pub(crate) static`; counting it would inflate the floor.
        let dir = catalog_with_generated_module(
            "regedit",
            &[("regedit_a", r"Alpha"), ("regedit_b", r"Beta")],
        );
        let module = dir.path().join("generated").join("regedit_generated.rs");
        assert_eq!(committed_statics(&module), Some(2));
        assert_eq!(
            committed_statics(&dir.path().join("generated").join("absent_generated.rs")),
            None
        );
    }

    #[test]
    fn the_record_carrying_mitre_techniques_wins_a_shared_key_path() {
        // fa and dfir-scripts both catalogue the Explorer Shell Folders startup
        // key. fa calls it "The Shell Folders information for Windows users."
        // and maps it to nothing; dfir-scripts names it as startup persistence
        // and maps it to T1547.001. fa is fetched first, so first-come-wins
        // retires the only record that answers a T1547.001 query — the analyst
        // asking which artifacts show that technique stops being told about
        // Shell Folders. Which source ran first is not evidence.
        let dir = catalog_with_generated_module("fa", &[]);
        let fetched: Fetched = vec![
            (
                "fa",
                vec![described(
                    "fa_currentversion_explorer_shell_folders",
                    "fa",
                    r"HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    "The Shell Folders information for Windows users.",
                    &[],
                )],
            ),
            (
                "dfir_scripts",
                vec![described(
                    "dfir_scripts_currentversion_explorer_shell_folders",
                    "dfir_scripts",
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    "Startup Folder Paths — Windows registry artifact (autostart and persistence).",
                    &["T1547.001"],
                )],
            ),
        ];

        let baseline = baseline_for_run(dir.path(), &["fa", "dfir_scripts"]).expect("baseline");
        let survivors: Vec<String> = select_records(&fetched, &baseline)
            .into_iter()
            .flat_map(|(_, recs)| recs)
            .map(|r| format!("{} mitre={:?}", r.id, r.mitre_techniques))
            .collect();

        assert_eq!(
            survivors,
            vec![
                "dfir_scripts_currentversion_explorer_shell_folders mitre=[\"T1547.001\"]"
                    .to_string()
            ],
            "the survivor of a shared key path must be the record that carries the technique"
        );
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

        let baseline = baseline_for_run(dir.path(), &["regedit"]).expect("baseline");
        let kept = only(select_records(&vec![("regedit", fetched)], &baseline));

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

        let baseline = baseline_for_run(dir.path(), &["velociraptor"]).expect("baseline");
        let kept = only(select_records(&vec![("velociraptor", fetched)], &baseline));

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

        let baseline = baseline_for_run(dir.path(), &["regedit"]).expect("baseline");
        let kept = only(select_records(&vec![("regedit", fetched)], &baseline));
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
