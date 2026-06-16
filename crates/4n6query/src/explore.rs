//! Catalog explorer subcommands ported from the former `fnomicon` CLI.
//!
//! Provides the `list`, `search`, `show`, and `triage` views over the
//! ForensicNomicon artifact catalog with ANSI-coloured human output.

use forensicnomicon::catalog::{ArtifactDescriptor, ForensicCatalog, TriagePriority, CATALOG};

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
    println!(
        "{BOLD}{CYAN}Artifact: {id}{RESET}",
        BOLD = BOLD,
        CYAN = CYAN,
        id = d.id,
        RESET = RESET
    );
    println!("  Name     : {}", d.name);
    println!(
        "  Priority : {col}{label}{RESET}",
        col = col,
        label = label,
        RESET = RESET
    );
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
    println!(
        "{BOLD}{title}{RESET}  {DIM}({count} artifact(s)){RESET}",
        BOLD = BOLD,
        title = title,
        RESET = RESET,
        DIM = DIM,
        count = count
    );
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
        println!(
            "  {DIM}No results for \"{keyword}\".{RESET}",
            DIM = DIM,
            keyword = keyword,
            RESET = RESET
        );
    } else {
        for d in results {
            print_row(d);
        }
    }
    println!();
}

fn cmd_show(catalog: &'static ForensicCatalog, id: &str) -> i32 {
    match catalog.by_id(id) {
        Some(d) => {
            print_detail(d);
            0
        }
        None => {
            eprintln!(
                "{RED}Error:{RESET} artifact '{id}' not found.",
                RED = RED,
                RESET = RESET,
                id = id
            );
            1
        }
    }
}

fn cmd_triage(catalog: &'static ForensicCatalog) {
    let all = catalog.for_triage();
    let critical: Vec<_> = all
        .iter()
        .filter(|d| d.triage_priority == TriagePriority::Critical)
        .collect();
    let high: Vec<_> = all
        .iter()
        .filter(|d| d.triage_priority == TriagePriority::High)
        .collect();

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

// ── Public entry points (wired into the clap dispatch) ─────────────────────────

pub fn run_list() -> i32 {
    cmd_list(&CATALOG);
    0
}

pub fn run_search(keyword: &str) -> i32 {
    cmd_search(&CATALOG, keyword);
    0
}

pub fn run_show(id: &str) -> i32 {
    cmd_show(&CATALOG, id)
}

pub fn run_triage_view() -> i32 {
    cmd_triage(&CATALOG);
    0
}
