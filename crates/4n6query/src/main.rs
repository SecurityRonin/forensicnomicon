//! `4n6query` — DFIR CLI for the forensicnomicon catalog.
//!
//! # Subcommands
//!
//! ```text
//! 4n6query lolbas lookup <platform> <name> [--format json]
//! 4n6query sites lookup <domain>          [--format json]
//! 4n6query dump --format json|yaml        [--dataset all|lolbas|sites]
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use forensicnomicon::abusable_sites::{
    abusable_site_info, BlockingRisk, SiteCategory, ABUSABLE_SITES,
};
use forensicnomicon::lolbins::{
    is_lolbas_linux, is_lolbas_macos, is_lolbas_windows, is_lolbas_windows_cmdlet,
    is_lolbas_windows_mmc, is_lolbas_windows_wmi, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS,
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

#[derive(Clone, Copy, ValueEnum)]
enum Dataset {
    All,
    Lolbas,
    Sites,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Commands::Lolbas { action } => run_lolbas(action),
        Commands::Sites { action } => run_sites(action),
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
    let (dataset, checker): (&[&str], fn(&str) -> bool) = match platform {
        Platform::Windows => (LOLBAS_WINDOWS, is_lolbas_windows),
        Platform::Linux => (LOLBAS_LINUX, is_lolbas_linux),
        Platform::Macos => (LOLBAS_MACOS, is_lolbas_macos),
        Platform::WindowsCmdlet => (LOLBAS_WINDOWS_CMDLETS, is_lolbas_windows_cmdlet),
        Platform::WindowsMmc => (LOLBAS_WINDOWS_MMC, is_lolbas_windows_mmc),
        Platform::WindowsWmi => (LOLBAS_WINDOWS_WMI, is_lolbas_windows_wmi),
    };
    let _ = checker; // used via dataset lookup; fn pointer kept for future --all-platforms

    let name_lower = name.to_lowercase();
    let found = dataset
        .iter()
        .find(|&&entry| entry.to_lowercase() == name_lower);

    if let Some(&matched) = found {
        let platform_label = platform_label(platform);
        match format {
            Some(Format::Json) => {
                let v = serde_json::json!({
                    "name": matched,
                    "platform": platform_label,
                    "found": true
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
            Some(Format::Yaml) => {
                let v = serde_json::json!({
                    "name": matched,
                    "platform": platform_label,
                    "found": true
                });
                print!("{}", serde_yaml::to_string(&v).unwrap());
            }
            None => {
                println!("FOUND  {matched}  [{platform_label}]");
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

    let value = serde_json::Value::Object(obj);

    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Format::Yaml => print!("{}", serde_yaml::to_string(&value).unwrap()),
    }

    0
}
