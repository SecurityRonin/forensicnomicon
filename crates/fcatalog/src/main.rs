//! fnomicon — CLI explorer for the ForensicNomicon artifact catalog.
//!
//! Subcommands:
//!   list              List all artifacts (id, name, priority)
//!   search <keyword>  Filter artifacts by keyword
//!   show <id>         Print full descriptor for a single artifact
//!   triage            List Critical and High priority artifacts

use forensicnomicon::catalog::{ArtifactDescriptor, ForensicCatalog, TriagePriority, CATALOG};
use std::env;

// ── ANSI colour helpers ───────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";

fn priority_colour(p: TriagePriority) -> &'static str {
    match p {
        TriagePriority::Critical => RED,
        TriagePriority::High => YELLOW,
        TriagePriority::Medium => GREEN,
        TriagePriority::Low => DIM,
        _ => DIM,
    }
}

fn priority_label(p: TriagePriority) -> &'static str {
    match p {
        TriagePriority::Critical => "CRITICAL",
        TriagePriority::High => "HIGH",
        TriagePriority::Medium => "MEDIUM",
        TriagePriority::Low => "LOW",
        _ => "UNKNOWN",
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn print_row(d: &ArtifactDescriptor) {
    let col = priority_colour(d.triage_priority);
    let label = priority_label(d.triage_priority);
    println!(
        "  {CYAN}{id:<30}{RESET}  {col}{label:<8}{RESET}  {name}",
        id = d.id,
        col = col,
        label = label,
        name = d.name,
        CYAN = CYAN,
        RESET = RESET,
    );
}

fn print_detail(d: &ArtifactDescriptor) {
    let col = priority_colour(d.triage_priority);
    let label = priority_label(d.triage_priority);
    println!();
    println!("{BOLD}{CYAN}Artifact: {id}{RESET}", BOLD = BOLD, CYAN = CYAN, id = d.id, RESET = RESET);
    println!("  Name     : {}", d.name);
    println!("  Priority : {col}{label}{RESET}", col = col, label = label, RESET = RESET);
    println!("  Meaning  : {}", d.meaning);

    if let Some(fp) = d.file_path {
        println!("  Path     : {}", fp);
    }
    if !d.key_path.is_empty() {
        println!("  RegKey   : {}", d.key_path);
    }
    if !d.mitre_techniques.is_empty() {
        println!("  MITRE    : {}", d.mitre_techniques.join(", "));
    }
    if !d.related_artifacts.is_empty() {
        println!("  Related  : {}", d.related_artifacts.join(", "));
    }
    if !d.sources.is_empty() {
        println!("  Sources  :");
        for s in d.sources {
            println!("    - {}", s);
        }
    }
    println!();
}

fn print_header(title: &str, count: usize) {
    println!();
    println!("{BOLD}{title}{RESET}  {DIM}({count} artifact(s)){RESET}",
        BOLD = BOLD, title = title, RESET = RESET, DIM = DIM, count = count);
    println!("{}", "─".repeat(70));
}

// ── Subcommand implementations ────────────────────────────────────────────────

fn cmd_list(catalog: &'static ForensicCatalog) {
    let all = catalog.list();
    print_header("All Artifacts", all.len());
    for d in all {
        print_row(d);
    }
    println!();
}

fn cmd_search(catalog: &'static ForensicCatalog, keyword: &str) {
    let results = catalog.filter_by_keyword(keyword);
    print_header(&format!("Search: {keyword}"), results.len());
    if results.is_empty() {
        println!("  {DIM}No results for \"{keyword}\".{RESET}", DIM = DIM, keyword = keyword, RESET = RESET);
    } else {
        for d in results {
            print_row(d);
        }
    }
    println!();
}

fn cmd_show(catalog: &'static ForensicCatalog, id: &str) {
    match catalog.by_id(id) {
        Some(d) => print_detail(d),
        None => {
            eprintln!("{RED}Error:{RESET} artifact '{id}' not found.", RED = RED, RESET = RESET, id = id);
            std::process::exit(1);
        }
    }
}

fn cmd_triage(catalog: &'static ForensicCatalog) {
    let all = catalog.for_triage();
    let critical: Vec<_> = all.iter().filter(|d| d.triage_priority == TriagePriority::Critical).collect();
    let high: Vec<_> = all.iter().filter(|d| d.triage_priority == TriagePriority::High).collect();

    print_header("Triage — Critical", critical.len());
    for d in &critical {
        print_row(d);
    }

    print_header("Triage — High", high.len());
    for d in &high {
        print_row(d);
    }
    println!();
}

fn usage() {
    println!("{BOLD}fnomicon{RESET} — forensic artifact catalog explorer", BOLD = BOLD, RESET = RESET);
    println!();
    println!("USAGE:");
    println!("  fnomicon list");
    println!("  fnomicon search <keyword>");
    println!("  fnomicon show <artifact-id>");
    println!("  fnomicon triage");
    println!();
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("list") => cmd_list(&CATALOG),
        Some("search") => {
            let keyword = args.get(2).map(String::as_str).unwrap_or("");
            if keyword.is_empty() {
                eprintln!("Usage: fnomicon search <keyword>");
                std::process::exit(1);
            }
            cmd_search(&CATALOG, keyword);
        }
        Some("show") => {
            let id = args.get(2).map(String::as_str).unwrap_or("");
            if id.is_empty() {
                eprintln!("Usage: fnomicon show <artifact-id>");
                std::process::exit(1);
            }
            cmd_show(&CATALOG, id);
        }
        Some("triage") => cmd_triage(&CATALOG),
        _ => usage(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use forensicnomicon::catalog::{TriagePriority, CATALOG};

    #[test]
    fn catalog_accessible_from_binary() {
        assert!(CATALOG.list().len() > 100);
    }

    #[test]
    fn search_prefetch_returns_results() {
        let results = CATALOG.filter_by_keyword("prefetch");
        assert!(!results.is_empty());
    }

    #[test]
    fn triage_critical_nonempty() {
        let critical: Vec<_> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == TriagePriority::Critical)
            .collect();
        assert!(!critical.is_empty());
    }

    #[test]
    fn list_returns_sorted_or_nonempty() {
        let all = CATALOG.list();
        assert!(!all.is_empty());
    }

    #[test]
    fn by_id_lookup_works() {
        // Grab the first artifact id and verify round-trip lookup
        let first = CATALOG.list().first().expect("catalog is nonempty");
        let found = CATALOG.by_id(first.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, first.id);
    }

    #[test]
    fn triage_high_nonempty() {
        let high: Vec<_> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == TriagePriority::High)
            .collect();
        assert!(!high.is_empty());
    }
}
