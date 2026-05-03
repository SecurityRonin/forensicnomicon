//! `4n6query` — DFIR CLI for the forensicnomicon catalog.
//!
//! # Subcommands
//!
//! ```text
//! 4n6query lolbas lookup <platform> <name> [--format json]
//! 4n6query sites lookup <domain>           [--format json]
//! 4n6query catalog search <keyword>        [--format json]
//! 4n6query catalog show <id>               [--format json]
//! 4n6query catalog mitre <technique>       [--format json]
//! 4n6query catalog triage                  [--format json]
//! 4n6query catalog list                    [--format json]
//! 4n6query dump --format json|yaml         [--dataset all|lolbas|sites|catalog]
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use forensicnomicon::abusable_sites::{
    abusable_site_info, BlockingRisk, SiteCategory, ABUSABLE_SITES,
};
use forensicnomicon::catalog::CATALOG;
use forensicnomicon::lolbins::{
    lolbas_entry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS,
    LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
};
use std::process;

// ---------------------------------------------------------------------------
// CLI types
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "4n6query",
    version,
    about = "DFIR query tool for the forensicnomicon catalog",
    long_about = "Query LOL/LOFL binaries across all platforms, abusable sites, \
                  and dump machine-readable snapshots for SIEM/SOAR integration."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Look up LOL/LOFL binaries across platforms
    Lolbas {
        #[command(subcommand)]
        action: LolbasAction,
    },
    /// Look up abusable cloud/CDN sites
    Sites {
        #[command(subcommand)]
        action: SitesAction,
    },
    /// Query the 6,548-entry forensic artifact catalog
    Catalog {
        #[command(subcommand)]
        action: CatalogAction,
    },
    /// Dump all data as machine-readable JSON or YAML
    Dump {
        /// Output format
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        /// Which dataset(s) to include
        #[arg(long, value_enum, default_value = "all")]
        dataset: Dataset,
    },
}

#[derive(Subcommand)]
enum LolbasAction {
    /// Check if a binary/cmdlet/class is in the LOL/LOFL catalog
    Lookup {
        /// Platform: windows | linux | macos | windows-cmdlet | windows-mmc | windows-wmi
        platform: Platform,
        /// Binary name, cmdlet name, .msc filename, or WMI class (case-insensitive)
        name: String,
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
}

#[derive(Subcommand)]
enum SitesAction {
    /// Look up a domain in the abusable sites catalog
    Lookup {
        /// Domain or wildcard pattern (e.g. raw.githubusercontent.com)
        domain: String,
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Platform {
    Windows,
    Linux,
    Macos,
    #[value(name = "windows-cmdlet")]
    WindowsCmdlet,
    #[value(name = "windows-mmc")]
    WindowsMmc,
    #[value(name = "windows-wmi")]
    WindowsWmi,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Yaml,
}

#[derive(Subcommand)]
enum CatalogAction {
    /// Keyword search across artifact name and meaning
    Search {
        /// Search keyword (case-insensitive)
        keyword: String,
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
    /// Look up a single artifact by its ID
    Show {
        /// Artifact ID (e.g. userassist_exe)
        id: String,
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
    /// List artifacts associated with a MITRE ATT&CK technique
    Mitre {
        /// ATT&CK technique ID (e.g. T1547.001)
        technique: String,
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
    /// List artifacts by triage priority (Critical first)
    Triage {
        /// Output format (default: human-readable)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
    /// List all artifact IDs in the catalog
    List {
        /// Output format (default: one ID per line)
        #[arg(long, value_enum)]
        format: Option<Format>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Dataset {
    All,
    Lolbas,
    Sites,
    Catalog,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Commands::Lolbas { action } => run_lolbas(action),
        Commands::Sites { action } => run_sites(action),
        Commands::Catalog { action } => run_catalog(action),
        Commands::Dump { format, dataset } => run_dump(format, dataset),
    };
    process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// lolbas lookup
// ---------------------------------------------------------------------------

fn run_lolbas(action: LolbasAction) -> i32 {
    match action {
        LolbasAction::Lookup {
            platform,
            name,
            format,
        } => lolbas_lookup(&name, platform, format),
    }
}

fn lolbas_lookup(name: &str, platform: Platform, format: Option<Format>) -> i32 {
    let dataset = match platform {
        Platform::Windows => LOLBAS_WINDOWS,
        Platform::Linux => LOLBAS_LINUX,
        Platform::Macos => LOLBAS_MACOS,
        Platform::WindowsCmdlet => LOLBAS_WINDOWS_CMDLETS,
        Platform::WindowsMmc => LOLBAS_WINDOWS_MMC,
        Platform::WindowsWmi => LOLBAS_WINDOWS_WMI,
    };

    if let Some(entry) = lolbas_entry(dataset, name) {
        let platform_label = platform_label(platform);
        match format {
            Some(Format::Json) => {
                let v = serde_json::json!({
                    "name": entry.name,
                    "platform": platform_label,
                    "mitre_techniques": entry.mitre_techniques,
                    "use_cases": entry.use_cases,
                    "description": entry.description,
                    "found": true
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
            Some(Format::Yaml) => {
                let v = serde_json::json!({
                    "name": entry.name,
                    "platform": platform_label,
                    "mitre_techniques": entry.mitre_techniques,
                    "use_cases": entry.use_cases,
                    "description": entry.description,
                    "found": true
                });
                print!("{}", serde_yaml::to_string(&v).unwrap());
            }
            None => {
                println!("FOUND  {}  [{}]", entry.name, platform_label);
                if !entry.description.is_empty() {
                    println!("       {}", entry.description);
                }
                if !entry.mitre_techniques.is_empty() {
                    println!("       MITRE: {}", entry.mitre_techniques.join(", "));
                }
                println!(
                    "       LOL/LOFL binary catalogued in forensicnomicon {}",
                    env!("CARGO_PKG_VERSION")
                );
            }
        }
        0
    } else {
        let platform_label = platform_label(platform);
        eprintln!("Not found: '{name}' in {platform_label} LOL/LOFL catalog");
        1
    }
}

fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::Macos => "macos",
        Platform::WindowsCmdlet => "windows-cmdlet",
        Platform::WindowsMmc => "windows-mmc",
        Platform::WindowsWmi => "windows-wmi",
    }
}

// ---------------------------------------------------------------------------
// sites lookup
// ---------------------------------------------------------------------------

fn run_sites(action: SitesAction) -> i32 {
    match action {
        SitesAction::Lookup { domain, format } => sites_lookup(&domain, format),
    }
}

fn sites_lookup(domain: &str, format: Option<Format>) -> i32 {
    if let Some(site) = abusable_site_info(domain) {
        match format {
            Some(Format::Json) => {
                let v = serde_json::to_string_pretty(site).unwrap();
                println!("{v}");
            }
            Some(Format::Yaml) => {
                print!("{}", serde_yaml::to_string(site).unwrap());
            }
            None => {
                println!("FOUND  {}", site.domain);
                println!("       Provider  : {}", site.provider);
                println!(
                    "       Category  : {}",
                    category_label(site.legitimate_category)
                );
                println!("       Risk      : {}", risk_label(site.blocking_risk));
                println!("       MITRE     : {}", site.mitre_techniques.join(", "));
                let tags = abuse_tag_labels(site.abuse_tags);
                if !tags.is_empty() {
                    println!("       Abuse     : {}", tags.join(", "));
                }
            }
        }
        0
    } else {
        eprintln!("Not found: '{domain}' — not in abusable sites catalog");
        1
    }
}

fn category_label(c: SiteCategory) -> &'static str {
    match c {
        SiteCategory::CodeRepository => "Code Repository",
        SiteCategory::CloudStorage => "Cloud Storage",
        SiteCategory::Cdn => "CDN",
        SiteCategory::Messaging => "Messaging",
        SiteCategory::PasteService => "Paste Service",
        SiteCategory::CloudHosting => "Cloud Hosting",
        SiteCategory::Collaboration => "Collaboration",
        SiteCategory::UrlShortener => "URL Shortener",
        SiteCategory::DnsService => "DNS Service",
        SiteCategory::Other => "Other",
    }
}

fn risk_label(r: BlockingRisk) -> &'static str {
    match r {
        BlockingRisk::Low => "low",
        BlockingRisk::Medium => "medium",
        BlockingRisk::High => "high",
        BlockingRisk::Critical => "critical",
    }
}

fn abuse_tag_labels(tags: u8) -> Vec<&'static str> {
    use forensicnomicon::abusable_sites::{
        TAG_C2, TAG_DOWNLOAD, TAG_EXFIL, TAG_EXPLOIT, TAG_PHISHING,
    };
    let mut out = Vec::new();
    if tags & TAG_PHISHING != 0 {
        out.push("phishing");
    }
    if tags & TAG_C2 != 0 {
        out.push("c2");
    }
    if tags & TAG_DOWNLOAD != 0 {
        out.push("download");
    }
    if tags & TAG_EXFIL != 0 {
        out.push("exfil");
    }
    if tags & TAG_EXPLOIT != 0 {
        out.push("exploit");
    }
    out
}

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

fn run_catalog(action: CatalogAction) -> i32 {
    match action {
        CatalogAction::Search { keyword, format } => catalog_search(&keyword, format),
        CatalogAction::Show { id, format } => catalog_show(&id, format),
        CatalogAction::Mitre { technique, format } => catalog_mitre(&technique, format),
        CatalogAction::Triage { format } => catalog_triage(format),
        CatalogAction::List { format } => catalog_list(format),
    }
}

fn descriptor_to_json(d: &forensicnomicon::catalog::ArtifactDescriptor) -> serde_json::Value {
    serde_json::json!({
        "id": d.id,
        "name": d.name,
        "meaning": d.meaning,
        "triage_priority": triage_label(d.triage_priority),
        "mitre_techniques": d.mitre_techniques,
        "os_scope": format!("{:?}", d.os_scope),
        "sources": d.sources,
    })
}

fn triage_label(p: forensicnomicon::catalog::TriagePriority) -> &'static str {
    use forensicnomicon::catalog::TriagePriority;
    match p {
        TriagePriority::Critical => "critical",
        TriagePriority::High => "high",
        TriagePriority::Medium => "medium",
        TriagePriority::Low => "low",
        _ => "unknown",
    }
}

fn print_descriptor_human(d: &forensicnomicon::catalog::ArtifactDescriptor) {
    println!("ID       : {}", d.id);
    println!("Name     : {}", d.name);
    println!("Priority : {}", triage_label(d.triage_priority));
    if !d.mitre_techniques.is_empty() {
        println!("MITRE    : {}", d.mitre_techniques.join(", "));
    }
    if !d.meaning.is_empty() {
        println!("Meaning  : {}", d.meaning);
    }
}

fn print_descriptors_human(hits: &[&forensicnomicon::catalog::ArtifactDescriptor]) {
    for d in hits {
        println!("[{}]  {}  ({})", triage_label(d.triage_priority), d.id, d.name);
    }
}

fn catalog_search(keyword: &str, format: Option<Format>) -> i32 {
    let hits = CATALOG.filter_by_keyword(keyword);
    if hits.is_empty() {
        eprintln!("Not found: no artifacts match '{keyword}'");
        return 1;
    }
    match format {
        Some(Format::Json) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Some(Format::Yaml) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            print!("{}", serde_yaml::to_string(&arr).unwrap());
        }
        None => print_descriptors_human(&hits),
    }
    0
}

fn catalog_show(id: &str, format: Option<Format>) -> i32 {
    // Exact ID match
    if let Some(d) = CATALOG.by_id(id) {
        match format {
            Some(Format::Json) => {
                println!("{}", serde_json::to_string_pretty(&descriptor_to_json(d)).unwrap());
            }
            Some(Format::Yaml) => {
                print!("{}", serde_yaml::to_string(&descriptor_to_json(d)).unwrap());
            }
            None => print_descriptor_human(d),
        }
        return 0;
    }

    // Fallback: keyword search — unambiguous single hit → show it; multiple → suggest
    let hits = CATALOG.filter_by_keyword(id);
    match hits.len() {
        0 => {
            eprintln!("Not found: no artifact with id or keyword '{id}'");
            1
        }
        1 => {
            let d = hits[0];
            match format {
                Some(Format::Json) => {
                    println!("{}", serde_json::to_string_pretty(&descriptor_to_json(d)).unwrap());
                }
                Some(Format::Yaml) => {
                    print!("{}", serde_yaml::to_string(&descriptor_to_json(d)).unwrap());
                }
                None => print_descriptor_human(d),
            }
            0
        }
        n => {
            eprintln!("Ambiguous: '{id}' matches {n} artifacts. Use `catalog search {id}` to list them, then `catalog show <id>` with the exact ID.");
            for h in &hits[..hits.len().min(5)] {
                eprintln!("  {}", h.id);
            }
            if n > 5 {
                eprintln!("  … and {} more", n - 5);
            }
            1
        }
    }
}

fn catalog_mitre(technique: &str, format: Option<Format>) -> i32 {
    let hits = CATALOG.by_mitre(technique);
    if hits.is_empty() {
        eprintln!("Not found: no artifacts match technique '{technique}'");
        return 1;
    }
    match format {
        Some(Format::Json) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Some(Format::Yaml) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            print!("{}", serde_yaml::to_string(&arr).unwrap());
        }
        None => print_descriptors_human(&hits),
    }
    0
}

fn catalog_triage(format: Option<Format>) -> i32 {
    let hits = CATALOG.for_triage();
    match format {
        Some(Format::Json) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Some(Format::Yaml) => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            print!("{}", serde_yaml::to_string(&arr).unwrap());
        }
        None => print_descriptors_human(&hits),
    }
    0
}

fn catalog_list(format: Option<Format>) -> i32 {
    let all = CATALOG.list();
    match format {
        Some(Format::Json) => {
            let arr: Vec<_> = all.iter().map(|d| descriptor_to_json(d)).collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Some(Format::Yaml) => {
            let arr: Vec<_> = all.iter().map(|d| descriptor_to_json(d)).collect();
            print!("{}", serde_yaml::to_string(&arr).unwrap());
        }
        None => {
            for d in all {
                println!("{}", d.id);
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

fn run_dump(format: Format, dataset: Dataset) -> i32 {
    let mut obj = serde_json::Map::new();

    if matches!(dataset, Dataset::All | Dataset::Lolbas) {
        obj.insert(
            "lolbas_windows".into(),
            serde_json::to_value(LOLBAS_WINDOWS).unwrap(),
        );
        obj.insert(
            "lolbas_linux".into(),
            serde_json::to_value(LOLBAS_LINUX).unwrap(),
        );
        obj.insert(
            "lolbas_macos".into(),
            serde_json::to_value(LOLBAS_MACOS).unwrap(),
        );
        obj.insert(
            "lolbas_windows_cmdlets".into(),
            serde_json::to_value(LOLBAS_WINDOWS_CMDLETS).unwrap(),
        );
        obj.insert(
            "lolbas_windows_mmc".into(),
            serde_json::to_value(LOLBAS_WINDOWS_MMC).unwrap(),
        );
        obj.insert(
            "lolbas_windows_wmi".into(),
            serde_json::to_value(LOLBAS_WINDOWS_WMI).unwrap(),
        );
    }

    if matches!(dataset, Dataset::All | Dataset::Sites) {
        obj.insert(
            "abusable_sites".into(),
            serde_json::to_value(ABUSABLE_SITES).unwrap(),
        );
    }

    if matches!(dataset, Dataset::All | Dataset::Catalog) {
        let arr: Vec<_> = CATALOG.list().iter().map(|d| descriptor_to_json(d)).collect();
        obj.insert("catalog".into(), serde_json::Value::Array(arr));
    }

    let value = serde_json::Value::Object(obj);

    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Format::Yaml => print!("{}", serde_yaml::to_string(&value).unwrap()),
    }

    0
}
