//! `4n6query` — DFIR query tool for the forensicnomicon catalog.
//!
//! # Usage
//!
//! ```text
//! # Universal lookup — binary, domain, MITRE technique, or keyword
//! 4n6query certutil.exe
//! 4n6query certutil.exe --platform windows
//! 4n6query raw.githubusercontent.com
//! 4n6query userassist
//! 4n6query T1547.001
//!
//! # Machine-readable output
//! 4n6query certutil.exe --format json
//! 4n6query T1547.001 --format yaml
//!
//! # Triage list (Critical artifacts first)
//! 4n6query --triage
//! 4n6query --triage --format json
//!
//! # Bulk export for SIEM/SOAR
//! 4n6query dump
//! 4n6query dump --dataset lolbas|sites|catalog|all
//! 4n6query dump --format yaml
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use forensicnomicon::abusable_sites::{
    abusable_site_info, BlockingRisk, SiteCategory, ABUSABLE_SITES,
};
use forensicnomicon::catalog::{TriagePriority, CATALOG};
use forensicnomicon::lolbins::{
    lolbas_entry, LolbasEntry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS,
    LOLBAS_WINDOWS_CMDLETS, LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
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
    long_about = "Look up any binary, domain, MITRE technique, or keyword across all forensicnomicon datasets.\n\n\
                  Examples:\n  \
                  4n6query certutil.exe\n  \
                  4n6query raw.githubusercontent.com\n  \
                  4n6query userassist\n  \
                  4n6query T1547.001\n  \
                  4n6query --triage\n  \
                  4n6query dump --dataset lolbas --format json"
)]
struct Cli {
    /// Binary name, domain, MITRE technique (T1547.001), or keyword to look up.
    term: Option<String>,

    /// Restrict LOL/LOFL binary search to a specific platform.
    #[arg(long, short = 'p', value_enum)]
    platform: Option<Platform>,

    /// Output format.
    #[arg(long, short = 'f', value_enum, default_value = "human")]
    format: Format,

    /// List all artifacts ordered by triage priority (Critical first).
    #[arg(long)]
    triage: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Export all data as machine-readable JSON or YAML for SIEM/SOAR integration.
    Dump {
        /// Output format.
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        /// Which dataset(s) to include.
        #[arg(long, value_enum, default_value = "all")]
        dataset: Dataset,
    },
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
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

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Format {
    Human,
    Json,
    Yaml,
}

#[derive(Clone, Copy, ValueEnum)]
enum Dataset {
    All,
    Lolbas,
    Sites,
    Catalog,
}

const ALL_PLATFORMS: &[(Platform, &str, &[LolbasEntry])] = &[
    (Platform::Windows, "windows", LOLBAS_WINDOWS),
    (Platform::Macos, "macos", LOLBAS_MACOS),
    (Platform::Linux, "linux", LOLBAS_LINUX),
    (Platform::WindowsCmdlet, "windows-cmdlet", LOLBAS_WINDOWS_CMDLETS),
    (Platform::WindowsMmc, "windows-mmc", LOLBAS_WINDOWS_MMC),
    (Platform::WindowsWmi, "windows-wmi", LOLBAS_WINDOWS_WMI),
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let exit_code = if let Some(cmd) = cli.command {
        match cmd {
            Commands::Dump { format, dataset } => run_dump(format, dataset),
        }
    } else if cli.triage {
        run_triage(cli.format)
    } else if let Some(term) = cli.term {
        run_query(&term, cli.platform, cli.format)
    } else {
        eprintln!("Usage: 4n6query <term> [--platform <p>] [--format json|yaml]");
        eprintln!("       4n6query --triage");
        eprintln!("       4n6query dump [--dataset all|lolbas|sites|catalog]");
        eprintln!("       4n6query --help");
        1
    };

    process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Universal query
// ---------------------------------------------------------------------------

/// Detect whether `term` looks like a MITRE ATT&CK technique ID.
fn is_mitre_id(term: &str) -> bool {
    let t = term.as_bytes();
    // T\d{4} or T\d{4}.\d{3}
    if t.len() < 5 || (t[0] != b'T' && t[0] != b't') {
        return false;
    }
    let digits: &[u8] = &t[1..];
    let base_ok = digits.len() >= 4 && digits[..4].iter().all(|b| b.is_ascii_digit());
    if !base_ok {
        return false;
    }
    // Allow exactly T1234 or T1234.567
    digits.len() == 4
        || (digits.len() == 8 && digits[4] == b'.' && digits[5..].iter().all(|b| b.is_ascii_digit()))
}

fn run_query(term: &str, platform: Option<Platform>, format: Format) -> i32 {
    // 1. LOLBin search
    let lolbas_hits: Vec<(&LolbasEntry, &str)> = ALL_PLATFORMS
        .iter()
        .filter(|(p, _, _)| platform.map_or(true, |pf| pf == *p))
        .filter_map(|(_, label, dataset)| {
            lolbas_entry(dataset, term).map(|e| (e, *label))
        })
        .collect();

    // 2. Abusable site lookup
    let site_hit = abusable_site_info(term);

    // 3. MITRE technique or keyword search for catalog artifacts.
    // Suppressed when --platform is specified: the user is asking about a
    // specific LOLBin platform, not doing a broad keyword search.
    let artifact_hits = if platform.is_none() {
        if is_mitre_id(term) {
            CATALOG.by_mitre(term)
        } else {
            CATALOG.filter_by_keyword(term)
        }
    } else {
        vec![]
    };

    if lolbas_hits.is_empty() && site_hit.is_none() && artifact_hits.is_empty() {
        eprintln!("Not found: '{term}' — no matches in LOLBins, abusable sites, or artifact catalog");
        return 1;
    }

    match format {
        Format::Json | Format::Yaml => {
            let mut obj = serde_json::Map::new();
            if !lolbas_hits.is_empty() {
                let arr: Vec<_> = lolbas_hits
                    .iter()
                    .map(|(e, label)| lolbas_to_json(e, label))
                    .collect();
                obj.insert("lolbas".into(), serde_json::Value::Array(arr));
            }
            if let Some(site) = site_hit {
                let arr = vec![site_to_json(site)];
                obj.insert("sites".into(), serde_json::Value::Array(arr));
            }
            if !artifact_hits.is_empty() {
                let arr: Vec<_> = artifact_hits.iter().map(|d| descriptor_to_json(d)).collect();
                obj.insert("artifacts".into(), serde_json::Value::Array(arr));
            }
            let val = serde_json::Value::Object(obj);
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&val).unwrap()),
                Format::Yaml => print!("{}", serde_yaml::to_string(&val).unwrap()),
                Format::Human => unreachable!(),
            }
        }
        Format::Human => {
            if !lolbas_hits.is_empty() {
                for (entry, label) in &lolbas_hits {
                    println!("LOL/LOFL  {}  [{}]", entry.name, label);
                    if !entry.description.is_empty() {
                        println!("          {}", entry.description);
                    }
                    if !entry.mitre_techniques.is_empty() {
                        println!("          MITRE: {}", entry.mitre_techniques.join(", "));
                    }
                }
            }
            if let Some(site) = site_hit {
                println!("SITE  {}  [{}]", site.domain, risk_label(site.blocking_risk));
                println!("      Provider : {}", site.provider);
                println!("      Category : {}", category_label(site.legitimate_category));
                println!("      MITRE    : {}", site.mitre_techniques.join(", "));
            }
            if !artifact_hits.is_empty() {
                for d in &artifact_hits {
                    println!(
                        "ARTIFACT  {}  [{}]  {}",
                        d.id,
                        triage_label(d.triage_priority),
                        d.name
                    );
                    if !d.meaning.is_empty() {
                        println!("          {}", d.meaning);
                    }
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

fn run_triage(format: Format) -> i32 {
    let hits = CATALOG.for_triage();
    match format {
        Format::Json | Format::Yaml => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            let val = serde_json::json!({ "artifacts": arr });
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&val).unwrap()),
                Format::Yaml => print!("{}", serde_yaml::to_string(&val).unwrap()),
                Format::Human => unreachable!(),
            }
        }
        Format::Human => {
            for d in &hits {
                println!("[{}]  {}  {}", triage_label(d.triage_priority), d.id, d.name);
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------

fn run_dump(format: Format, dataset: Dataset) -> i32 {
    let mut obj = serde_json::Map::new();

    if matches!(dataset, Dataset::All | Dataset::Lolbas) {
        obj.insert("lolbas_windows".into(), serde_json::to_value(LOLBAS_WINDOWS).unwrap());
        obj.insert("lolbas_linux".into(), serde_json::to_value(LOLBAS_LINUX).unwrap());
        obj.insert("lolbas_macos".into(), serde_json::to_value(LOLBAS_MACOS).unwrap());
        obj.insert("lolbas_windows_cmdlets".into(), serde_json::to_value(LOLBAS_WINDOWS_CMDLETS).unwrap());
        obj.insert("lolbas_windows_mmc".into(), serde_json::to_value(LOLBAS_WINDOWS_MMC).unwrap());
        obj.insert("lolbas_windows_wmi".into(), serde_json::to_value(LOLBAS_WINDOWS_WMI).unwrap());
    }
    if matches!(dataset, Dataset::All | Dataset::Sites) {
        obj.insert("abusable_sites".into(), serde_json::to_value(ABUSABLE_SITES).unwrap());
    }
    if matches!(dataset, Dataset::All | Dataset::Catalog) {
        let arr: Vec<_> = CATALOG.list().iter().map(|d| descriptor_to_json(d)).collect();
        obj.insert("catalog".into(), serde_json::Value::Array(arr));
    }

    let val = serde_json::Value::Object(obj);
    match format {
        Format::Json | Format::Human => println!("{}", serde_json::to_string_pretty(&val).unwrap()),
        Format::Yaml => print!("{}", serde_yaml::to_string(&val).unwrap()),
    }
    0
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn lolbas_to_json(e: &LolbasEntry, platform: &str) -> serde_json::Value {
    serde_json::json!({
        "name": e.name,
        "platform": platform,
        "mitre_techniques": e.mitre_techniques,
        "use_cases": e.use_cases,
        "description": e.description,
    })
}

fn site_to_json(s: &forensicnomicon::abusable_sites::AbusableSite) -> serde_json::Value {
    serde_json::json!({
        "domain": s.domain,
        "provider": s.provider,
        "blocking_risk": risk_label(s.blocking_risk),
        "mitre_techniques": s.mitre_techniques,
        "abuse_tags": s.abuse_tags,
    })
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

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

fn triage_label(p: TriagePriority) -> &'static str {
    match p {
        TriagePriority::Critical => "critical",
        TriagePriority::High => "high",
        TriagePriority::Medium => "medium",
        TriagePriority::Low => "low",
        _ => "unknown",
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
