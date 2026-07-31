#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `4n6query` — DFIR query tool for the forensicnomicon catalog.
//!
//! # Usage
//!
//! ```text
//! # Universal lookup — binary, domain, MITRE technique, or keyword
//! 4n6query certutil.exe
//! 4n6query rtcore64.sys          # BYOVD vulnerable driver (CVE / MITRE / SHA-256)
//! 4n6query mimikatz             # threat indicator (credential-access tool, …)
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
//! 4n6query dump --dataset lolbas|sites|catalog|drivers|indicators|all
//! 4n6query dump --format yaml
//! ```

mod explore;
mod indicators;
mod tui;

use clap::{Parser, Subcommand, ValueEnum};
use forensicnomicon::abusable_sites::{
    abusable_site_info, BlockingRisk, SiteCategory, ABUSABLE_SITES,
};
use forensicnomicon::attack_flow::{all_flows, AttackFlow};
use forensicnomicon::catalog::{TriagePriority, CATALOG};
use forensicnomicon::drivers::{DriverCategory, VulnerableDriver, BYOVD_DRIVERS};
use forensicnomicon::eventids::{event_entry, EventIdEntry, EVENT_ID_TABLE};
use forensicnomicon::lolbins::{
    lolbas_entry, LolbasEntry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS,
    LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
};
use forensicnomicon::playbooks::{
    path_by_id, playbook_by_id, InvestigationPath, INVESTIGATION_PATHS, PLAYBOOKS,
};
use forensicnomicon::sigma::{SigmaRef, SIGMA_TABLE};
use forensicnomicon::threat_intel::profile::{MalwareClass, MalwareProfile};
use forensicnomicon::threat_intel::profiles::ALL_PROFILES;
use std::process;

use crate::indicators::{IndicatorKind, IndicatorSource, INDICATOR_SOURCES};

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
                  4n6query rtcore64.sys\n  \
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

    /// Incident scenario filter (use with --triage).
    /// Valid values: ransomware, data-breach, bec, insider, supply-chain
    #[arg(long, value_name = "SCENARIO")]
    scenario: Option<String>,

    /// ATT&CK tactic filter (use with --triage).
    /// Valid values: execution, persistence, lateral-movement, credential-access,
    /// defense-evasion, discovery, collection, exfiltration, command-and-control,
    /// privilege-escalation
    #[arg(long = "type", value_name = "TACTIC")]
    tactic: Option<String>,

    /// Triage priority filter (use with --triage).
    /// Comma-separated list: critical, high, medium, low
    /// Example: --priority critical,high
    #[arg(long, value_name = "PRIORITY")]
    priority: Option<String>,

    /// List investigation playbooks, or show steps for a specific playbook ID.
    /// Without a value: list all 6 playbooks.
    /// With a value: show the full step-by-step investigation path.
    #[arg(long, value_name = "PLAYBOOK_ID", num_args = 0..=1, default_missing_value = "")]
    playbook: Option<String>,

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

    /// List all catalog artifacts (id, name, triage priority).
    List,

    /// Filter catalog artifacts by keyword.
    Search {
        /// Keyword to match against artifacts.
        keyword: String,
    },

    /// Print the full descriptor for a single artifact by id.
    Show {
        /// Artifact id to display.
        id: String,
    },

    /// List Critical and High priority artifacts for triage.
    Triage,
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
    Drivers,
    Indicators,
    EventIds,
    Sigma,
    Flows,
    Profiles,
}

const ALL_PLATFORMS: &[(Platform, &str, &[LolbasEntry])] = &[
    (Platform::Windows, "windows", LOLBAS_WINDOWS),
    (Platform::Macos, "macos", LOLBAS_MACOS),
    (Platform::Linux, "linux", LOLBAS_LINUX),
    (
        Platform::WindowsCmdlet,
        "windows-cmdlet",
        LOLBAS_WINDOWS_CMDLETS,
    ),
    (Platform::WindowsMmc, "windows-mmc", LOLBAS_WINDOWS_MMC),
    (Platform::WindowsWmi, "windows-wmi", LOLBAS_WINDOWS_WMI),
];

fn norm(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// A BYOVD driver lookup: match `term` to a basename or a service name.
fn lookup_drivers(term: &str) -> Vec<&'static VulnerableDriver> {
    let t = norm(term);
    let t_sys = if t.ends_with(".sys") {
        t.clone()
    } else {
        format!("{t}.sys")
    };
    BYOVD_DRIVERS
        .iter()
        .filter(|d| {
            d.file_basename == t
                || d.file_basename == t_sys
                || d.service_names.iter().any(|s| norm(s) == t)
        })
        .collect()
}

/// Indicator-table lookup: returns (source, matched-entry) for each hit.
fn lookup_indicators(term: &str) -> Vec<(&'static IndicatorSource, &'static str)> {
    let t = norm(term);
    if t.len() < 3 {
        return vec![];
    }
    let mut hits = Vec::new();
    for src in INDICATOR_SOURCES {
        for &entry in src.table {
            let e = norm(entry);
            let m = match src.kind {
                IndicatorKind::Name => {
                    t == e || (t.len() >= 3 && e.len() >= 3 && (t.contains(&e) || e.contains(&t)))
                }
                IndicatorKind::Pattern => {
                    // require >=4-char patterns to avoid short-substring false positives
                    t.len() >= 4 && e.len() >= 4 && (t.contains(&e) || e.contains(&t))
                }
            };
            if m {
                hits.push((src, entry));
            }
        }
    }
    hits
}

fn driver_to_json(d: &VulnerableDriver) -> serde_json::Value {
    serde_json::json!({
        "file_basename": d.file_basename,
        "label": d.label,
        "category": match d.category { DriverCategory::Malicious => "malicious", DriverCategory::Vulnerable => "vulnerable driver" },
        "loldrivers_id": d.loldrivers_id,
        "cve": d.cve,
        "mitre_techniques": d.mitre,
        "sha256": d.sha256,
        "service_names": d.service_names,
        "loads_despite_hvci": d.loads_despite_hvci,
        "edr_killer": d.edr_killer,
    })
}

fn indicator_to_json(src: &IndicatorSource, matched: &str) -> serde_json::Value {
    serde_json::json!({
        "matched": matched,
        "category": src.label,
        "mitre_techniques": src.mitre,
    })
}

/// Windows Event ID lookup: an all-digit term is matched against the table.
fn lookup_events(term: &str) -> Vec<&'static EventIdEntry> {
    match term.trim().parse::<u32>() {
        Ok(id) => event_entry(id).into_iter().collect(),
        Err(_) => vec![],
    }
}

/// Sigma rule lookup: substring match on rule title or log-source category.
fn lookup_sigma(term: &str) -> Vec<&'static SigmaRef> {
    let t = norm(term);
    if t.len() < 3 {
        return vec![];
    }
    SIGMA_TABLE
        .iter()
        .filter(|r| norm(r.title).contains(&t) || norm(r.logsource_category).contains(&t))
        .collect()
}

/// Attack-flow lookup: substring match on flow id or name.
fn lookup_flows(term: &str) -> Vec<&'static AttackFlow> {
    let t = norm(term);
    if t.len() < 3 {
        return vec![];
    }
    all_flows()
        .iter()
        .filter(|f| norm(f.id).contains(&t) || norm(f.name).contains(&t))
        .collect()
}

/// Malware-profile lookup: substring match on id, family, or any alias.
fn lookup_profiles(term: &str) -> Vec<&'static MalwareProfile> {
    let t = norm(term);
    if t.len() < 3 {
        return vec![];
    }
    ALL_PROFILES
        .iter()
        .copied()
        .filter(|p| {
            norm(p.id).contains(&t)
                || norm(p.family).contains(&t)
                || p.aliases.iter().any(|a| norm(a).contains(&t))
        })
        .collect()
}

fn event_to_json(e: &EventIdEntry) -> serde_json::Value {
    serde_json::json!({
        "event_id": e.event_id,
        "channel": e.channel,
        "description": e.description,
        "mitre_techniques": e.mitre_techniques,
        "artifact_ids": e.artifact_ids,
        "high_value": e.high_value,
    })
}

fn sigma_to_json(r: &SigmaRef) -> serde_json::Value {
    serde_json::json!({
        "rule_id": r.rule_id,
        "title": r.title,
        "artifact_id": r.artifact_id,
        "logsource_category": r.logsource_category,
        "mitre_techniques": r.mitre_techniques,
    })
}

fn flow_to_json(f: &AttackFlow) -> serde_json::Value {
    serde_json::json!({
        "id": f.id,
        "name": f.name,
        "description": f.description,
        "action_count": f.actions.len(),
    })
}

fn malware_class_label(c: MalwareClass) -> &'static str {
    match c {
        MalwareClass::LdPreloadProcessHider => "ld_preload process hider",
        MalwareClass::LdPreloadPamHooker => "ld_preload PAM hooker",
        MalwareClass::LdPreloadNetworkHider => "ld_preload network hider",
        MalwareClass::LdPreloadFullRootkit => "ld_preload full rootkit",
        MalwareClass::LkmRootkit => "LKM rootkit",
        MalwareClass::CryptoMiner => "crypto miner",
        MalwareClass::GenericLdPreload => "generic ld_preload",
    }
}

fn profile_to_json(p: &MalwareProfile) -> serde_json::Value {
    serde_json::json!({
        "id": p.id,
        "family": p.family,
        "aliases": p.aliases,
        "description": p.description,
        "malware_class": malware_class_label(p.malware_class),
        "mitre_techniques": p.mitre_techniques,
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let exit_code = if let Some(cmd) = cli.command {
        match cmd {
            Commands::Dump { format, dataset } => run_dump(format, dataset),
            Commands::List => explore::run_list(),
            Commands::Search { keyword } => explore::run_search(&keyword),
            Commands::Show { id } => explore::run_show(&id),
            Commands::Triage => explore::run_triage_view(),
        }
    } else if cli.triage {
        run_triage(
            cli.format,
            cli.scenario.as_deref(),
            cli.tactic.as_deref(),
            cli.priority.as_deref(),
        )
    } else if let Some(pb_arg) = cli.playbook {
        run_playbook(&pb_arg, cli.format)
    } else if let Some(term) = cli.term {
        run_query(&term, cli.platform, cli.format)
    } else if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        // No args, stdout is a TTY → launch the interactive navigator
        tui::run()
    } else {
        eprintln!("Usage: 4n6query <term> [--platform <p>] [--format json|yaml]");
        eprintln!("       4n6query --triage");
        eprintln!("       4n6query --playbook [<id>]");
        eprintln!("       4n6query dump [--dataset all|lolbas|sites|catalog|drivers|indicators]");
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
    let base_ok = digits.len() >= 4 && digits[..4].iter().all(u8::is_ascii_digit);
    if !base_ok {
        return false;
    }
    // Allow exactly T1234 or T1234.567
    digits.len() == 4
        || (digits.len() == 8 && digits[4] == b'.' && digits[5..].iter().all(u8::is_ascii_digit))
}

fn run_query(term: &str, platform: Option<Platform>, format: Format) -> i32 {
    // 1. LOLBin search
    let lolbas_hits: Vec<(&LolbasEntry, &str)> = ALL_PLATFORMS
        .iter()
        .filter(|(p, _, _)| platform.map_or(true, |pf| pf == *p))
        .filter_map(|(_, label, dataset)| lolbas_entry(dataset, term).map(|e| (e, *label)))
        .collect();

    // 2. Abusable site lookup
    let site_hit = abusable_site_info(term);

    // 2b. BYOVD vulnerable-driver + threat-indicator lookups.
    let driver_hits = lookup_drivers(term);
    let indicator_hits = lookup_indicators(term);
    let event_hits = lookup_events(term);
    let sigma_hits = lookup_sigma(term);
    let flow_hits = lookup_flows(term);
    let profile_hits = lookup_profiles(term);

    // 3. MITRE technique or keyword search for catalog artifacts.
    // Suppressed when --platform is specified: the user is asking about a
    // specific LOLBin platform, not doing a broad keyword search.
    let artifact_hits = if platform.is_none() {
        if is_mitre_id(term) {
            // Roll up the ATT&CK hierarchy: a parent ID (T1053) must reach the
            // artifacts tagged with its sub-techniques (T1053.005), which is
            // where the catalog actually tags them.
            CATALOG.by_mitre_including_subtechniques(term)
        } else {
            CATALOG.filter_by_keyword(term)
        }
    } else {
        vec![]
    };

    // 4. Relevant investigation paths (artifact-triggered chains) for matched artifacts.
    let path_hits: Vec<&InvestigationPath> = if artifact_hits.is_empty() {
        vec![]
    } else {
        let hit_ids: Vec<&str> = artifact_hits.iter().map(|d| d.id).collect();
        INVESTIGATION_PATHS
            .iter()
            .filter(|p| p.steps.iter().any(|s| hit_ids.contains(&s.artifact_id)))
            .collect()
    };

    if lolbas_hits.is_empty()
        && site_hit.is_none()
        && artifact_hits.is_empty()
        && driver_hits.is_empty()
        && indicator_hits.is_empty()
        && event_hits.is_empty()
        && sigma_hits.is_empty()
        && flow_hits.is_empty()
        && profile_hits.is_empty()
    {
        eprintln!(
            "Not found: '{term}' — no matches in LOLBins, abusable sites, or artifact catalog"
        );
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
            if !driver_hits.is_empty() {
                let arr: Vec<_> = driver_hits.iter().map(|d| driver_to_json(d)).collect();
                obj.insert("drivers".into(), serde_json::Value::Array(arr));
            }
            if !indicator_hits.is_empty() {
                let arr: Vec<_> = indicator_hits
                    .iter()
                    .map(|(src, m)| indicator_to_json(src, m))
                    .collect();
                obj.insert("indicators".into(), serde_json::Value::Array(arr));
            }
            if !event_hits.is_empty() {
                let arr: Vec<_> = event_hits.iter().map(|e| event_to_json(e)).collect();
                obj.insert("events".into(), serde_json::Value::Array(arr));
            }
            if !sigma_hits.is_empty() {
                let arr: Vec<_> = sigma_hits.iter().map(|r| sigma_to_json(r)).collect();
                obj.insert("sigma".into(), serde_json::Value::Array(arr));
            }
            if !flow_hits.is_empty() {
                let arr: Vec<_> = flow_hits.iter().map(|f| flow_to_json(f)).collect();
                obj.insert("flows".into(), serde_json::Value::Array(arr));
            }
            if !profile_hits.is_empty() {
                let arr: Vec<_> = profile_hits.iter().map(|p| profile_to_json(p)).collect();
                obj.insert("profiles".into(), serde_json::Value::Array(arr));
            }
            if !artifact_hits.is_empty() {
                let arr: Vec<_> = artifact_hits
                    .iter()
                    .map(|d| descriptor_to_json(d))
                    .collect();
                obj.insert("artifacts".into(), serde_json::Value::Array(arr));
            }
            if !path_hits.is_empty() {
                let arr: Vec<_> = path_hits.iter().map(|pb| playbook_to_json(pb)).collect();
                obj.insert("playbooks".into(), serde_json::Value::Array(arr));
            }
            let val = serde_json::Value::Object(obj);
            match format {
                Format::Json => println!("{}", json_pretty(&val)),
                Format::Yaml => print!("{}", yaml_str(&val)),
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
                println!(
                    "SITE  {}  [{}]",
                    site.domain,
                    risk_label(site.blocking_risk)
                );
                println!("      Provider : {}", site.provider);
                println!(
                    "      Category : {}",
                    category_label(site.legitimate_category)
                );
                println!("      MITRE    : {}", site.mitre_techniques.join(", "));
            }
            for d in &driver_hits {
                let cat = match d.category {
                    DriverCategory::Malicious => "malicious",
                    DriverCategory::Vulnerable => "vulnerable driver",
                };
                let ek = if d.edr_killer { "  EDR-killer" } else { "" };
                println!("BYOVD  {}  [{cat}]{ek}", d.file_basename);
                if !d.label.is_empty() {
                    println!("       {}", d.label);
                }
                if !d.cve.is_empty() {
                    println!("       CVE: {}", d.cve.join(", "));
                }
                if !d.mitre.is_empty() {
                    println!("       MITRE: {}", d.mitre.join(", "));
                }
                if !d.service_names.is_empty() {
                    println!("       Service names: {}", d.service_names.join(", "));
                }
                if d.loads_despite_hvci {
                    println!("       Loads despite HVCI");
                }
                if !d.loldrivers_id.is_empty() {
                    println!("       LOLDrivers: {}", d.loldrivers_id);
                }
                if let Some(h) = d.sha256.first() {
                    println!("       SHA256: {h}");
                }
            }
            let mut seen_labels: Vec<&str> = Vec::new();
            for (src, _) in &indicator_hits {
                if seen_labels.contains(&src.label) {
                    continue;
                }
                seen_labels.push(src.label);
                let mut matches: Vec<&str> = indicator_hits
                    .iter()
                    .filter(|(s, _)| s.label == src.label)
                    .map(|(_, m)| *m)
                    .collect();
                matches.dedup();
                let shown = if matches.len() > 8 {
                    format!(
                        "{}, … (+{} more)",
                        matches[..8].join(", "),
                        matches.len() - 8
                    )
                } else {
                    matches.join(", ")
                };
                println!("INDICATOR  [{}]  matched: {shown}", src.label);
                if !src.mitre.is_empty() {
                    println!("           MITRE: {}", src.mitre.join(", "));
                }
            }
            for e in &event_hits {
                println!("EVENT  {}  [{}]  {}", e.event_id, e.channel, e.description);
                if !e.mitre_techniques.is_empty() {
                    println!("       MITRE: {}", e.mitre_techniques.join(", "));
                }
            }
            for r in &sigma_hits {
                println!("SIGMA  {}  [{}]", r.title, r.logsource_category);
                if !r.mitre_techniques.is_empty() {
                    println!("       MITRE: {}", r.mitre_techniques.join(", "));
                }
            }
            for f in &flow_hits {
                println!("FLOW   {}  —  {}", f.id, f.name);
                println!("       Actions: {}", f.actions.len());
            }
            for p in &profile_hits {
                println!(
                    "PROFILE  {}  [{}]",
                    p.family,
                    malware_class_label(p.malware_class)
                );
                if !p.mitre_techniques.is_empty() {
                    println!("         MITRE: {}", p.mitre_techniques.join(", "));
                }
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
            if !path_hits.is_empty() {
                println!();
                println!("Playbooks:");
                for pb in &path_hits {
                    println!("  {}  —  {}", pb.id, pb.name);
                    println!("    Run: 4n6query --playbook {}", pb.id);
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Scenario / tactic filtering
// ---------------------------------------------------------------------------

/// Map an incident scenario name to relevant MITRE technique prefixes.
fn techniques_for_scenario(scenario: &str) -> Option<&'static [&'static str]> {
    match scenario {
        "ransomware" => Some(&[
            "T1486", "T1490", "T1489", "T1059", "T1204", "T1070", "T1562", "T1003",
        ]),
        "data-breach" => Some(&[
            "T1048", "T1041", "T1537", "T1567", "T1005", "T1003", "T1555",
        ]),
        "bec" => Some(&["T1566", "T1078", "T1534", "T1114", "T1087"]),
        "insider" => Some(&["T1005", "T1039", "T1048", "T1083", "T1217"]),
        "supply-chain" => Some(&["T1195", "T1199", "T1553", "T1059", "T1027"]),
        _ => None,
    }
}

/// Map an ATT&CK tactic name to relevant MITRE technique prefixes.
fn techniques_for_tactic(tactic: &str) -> Option<&'static [&'static str]> {
    match tactic {
        "execution" => Some(&[
            "T1059", "T1053", "T1204", "T1047", "T1569", "T1106", "T1129",
        ]),
        "persistence" => Some(&[
            "T1053", "T1547", "T1543", "T1546", "T1136", "T1505", "T1197",
        ]),
        "privilege-escalation" => Some(&["T1548", "T1134", "T1611", "T1068"]),
        "defense-evasion" => Some(&[
            "T1027", "T1036", "T1055", "T1070", "T1218", "T1562", "T1564",
        ]),
        "credential-access" => Some(&["T1003", "T1040", "T1555", "T1552", "T1558", "T1110"]),
        "discovery" => Some(&["T1012", "T1018", "T1082", "T1083", "T1087", "T1217"]),
        "lateral-movement" => Some(&["T1021", "T1080", "T1534", "T1563", "T1570"]),
        "collection" => Some(&[
            "T1005", "T1039", "T1056", "T1074", "T1114", "T1113", "T1560",
        ]),
        "exfiltration" => Some(&["T1048", "T1041", "T1537", "T1567", "T1011"]),
        "command-and-control" => Some(&["T1071", "T1090", "T1095", "T1102", "T1105", "T1571"]),
        _ => None,
    }
}

/// Returns true if any of the artifact's MITRE techniques start with any prefix in `prefixes`.
fn artifact_matches_prefixes(mitre_techniques: &[&'static str], prefixes: &[&'static str]) -> bool {
    mitre_techniques
        .iter()
        .any(|t| prefixes.iter().any(|p| t.starts_with(p)))
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

fn run_triage(
    format: Format,
    scenario: Option<&str>,
    tactic: Option<&str>,
    priority: Option<&str>,
) -> i32 {
    // Validate scenario if provided
    let scenario_prefixes: Option<&'static [&'static str]> = if let Some(s) = scenario {
        if let Some(prefixes) = techniques_for_scenario(s) {
            Some(prefixes)
        } else {
            eprintln!(
                "error: unknown scenario '{s}'. Valid values: ransomware, data-breach, bec, insider, supply-chain"
            );
            return 1;
        }
    } else {
        None
    };

    // Validate tactic if provided
    let tactic_prefixes: Option<&'static [&'static str]> = if let Some(t) = tactic {
        if let Some(prefixes) = techniques_for_tactic(t) {
            Some(prefixes)
        } else {
            eprintln!(
                "error: unknown tactic '{t}'. Valid values: execution, persistence, lateral-movement, \
                 credential-access, defense-evasion, discovery, collection, exfiltration, \
                 command-and-control, privilege-escalation"
            );
            return 1;
        }
    } else {
        None
    };

    // Parse --priority filter (comma-separated: critical,high,medium,low)
    let priority_set: Option<Vec<TriagePriority>> = if let Some(p) = priority {
        let mut levels = Vec::new();
        for token in p.split(',') {
            match token.trim() {
                "critical" => levels.push(TriagePriority::Critical),
                "high" => levels.push(TriagePriority::High),
                "medium" => levels.push(TriagePriority::Medium),
                "low" => levels.push(TriagePriority::Low),
                other => {
                    eprintln!(
                        "error: unknown priority '{other}'. Valid values: critical, high, medium, low"
                    );
                    return 1;
                }
            }
        }
        Some(levels)
    } else {
        None
    };

    // Start from full triage-sorted list
    let all_hits = CATALOG.for_triage();

    // Apply filters (AND logic: artifact must match all supplied filters)
    let hits: Vec<_> = all_hits
        .into_iter()
        .filter(|d| {
            if let Some(sp) = scenario_prefixes {
                if !artifact_matches_prefixes(d.mitre_techniques, sp) {
                    return false;
                }
            }
            if let Some(tp) = tactic_prefixes {
                if !artifact_matches_prefixes(d.mitre_techniques, tp) {
                    return false;
                }
            }
            if let Some(ref ps) = priority_set {
                if !ps.contains(&d.triage_priority) {
                    return false;
                }
            }
            true
        })
        .collect();

    match format {
        Format::Json | Format::Yaml => {
            let arr: Vec<_> = hits.iter().map(|d| descriptor_to_json(d)).collect();
            let val = serde_json::json!({ "artifacts": arr });
            match format {
                Format::Json => println!("{}", json_pretty(&val)),
                Format::Yaml => print!("{}", yaml_str(&val)),
                Format::Human => unreachable!(),
            }
        }
        Format::Human => {
            for d in &hits {
                println!(
                    "[{}]  {}  {}",
                    triage_label(d.triage_priority),
                    d.id,
                    d.name
                );
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------

// Serialization helpers. The values rendered here (catalog descriptors, LOLBAS
// tables, playbooks) are always serializable in practice; these degrade to an
// error note / `null` rather than panic, keeping the CLI panic-free.
fn to_json_value<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn json_pretty<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|e| format!("{{\"error\":\"JSON serialization failed: {e}\"}}"))
}

fn yaml_str<T: serde::Serialize>(value: &T) -> String {
    serde_yaml::to_string(value)
        .unwrap_or_else(|e| format!("error: YAML serialization failed: {e}\n"))
}

fn run_dump(format: Format, dataset: Dataset) -> i32 {
    let mut obj = serde_json::Map::new();

    if matches!(dataset, Dataset::All | Dataset::Lolbas) {
        obj.insert("lolbas_windows".into(), to_json_value(&LOLBAS_WINDOWS));
        obj.insert("lolbas_linux".into(), to_json_value(&LOLBAS_LINUX));
        obj.insert("lolbas_macos".into(), to_json_value(&LOLBAS_MACOS));
        obj.insert(
            "lolbas_windows_cmdlets".into(),
            to_json_value(&LOLBAS_WINDOWS_CMDLETS),
        );
        obj.insert(
            "lolbas_windows_mmc".into(),
            to_json_value(&LOLBAS_WINDOWS_MMC),
        );
        obj.insert(
            "lolbas_windows_wmi".into(),
            to_json_value(&LOLBAS_WINDOWS_WMI),
        );
    }
    if matches!(dataset, Dataset::All | Dataset::Sites) {
        obj.insert("abusable_sites".into(), to_json_value(&ABUSABLE_SITES));
    }
    if matches!(dataset, Dataset::All | Dataset::Catalog) {
        let arr: Vec<_> = CATALOG.list().iter().map(descriptor_to_json).collect();
        obj.insert("catalog".into(), serde_json::Value::Array(arr));
    }
    if matches!(dataset, Dataset::All | Dataset::Drivers) {
        let arr: Vec<_> = BYOVD_DRIVERS.iter().map(driver_to_json).collect();
        obj.insert("byovd_drivers".into(), serde_json::Value::Array(arr));
    }
    if matches!(dataset, Dataset::All | Dataset::Indicators) {
        let mut ind = serde_json::Map::new();
        for src in INDICATOR_SOURCES {
            ind.insert(
                src.label.into(),
                serde_json::json!({
                    "kind": match src.kind { IndicatorKind::Name => "name", IndicatorKind::Pattern => "pattern" },
                    "mitre": src.mitre,
                    "entries": src.table,
                }),
            );
        }
        obj.insert("indicators".into(), serde_json::Value::Object(ind));
    }
    if matches!(dataset, Dataset::All | Dataset::EventIds) {
        let arr: Vec<_> = EVENT_ID_TABLE.iter().map(event_to_json).collect();
        obj.insert("event_ids".into(), serde_json::Value::Array(arr));
    }
    if matches!(dataset, Dataset::All | Dataset::Sigma) {
        let arr: Vec<_> = SIGMA_TABLE.iter().map(sigma_to_json).collect();
        obj.insert("sigma_rules".into(), serde_json::Value::Array(arr));
    }
    if matches!(dataset, Dataset::All | Dataset::Flows) {
        let arr: Vec<_> = all_flows().iter().map(flow_to_json).collect();
        obj.insert("attack_flows".into(), serde_json::Value::Array(arr));
    }
    if matches!(dataset, Dataset::All | Dataset::Profiles) {
        let arr: Vec<_> = ALL_PROFILES.iter().map(|p| profile_to_json(p)).collect();
        obj.insert("malware_profiles".into(), serde_json::Value::Array(arr));
    }

    let val = serde_json::Value::Object(obj);
    match format {
        Format::Json | Format::Human => println!("{}", json_pretty(&val)),
        Format::Yaml => print!("{}", yaml_str(&val)),
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

// ---------------------------------------------------------------------------
// Playbook
// ---------------------------------------------------------------------------

fn run_playbook(id_arg: &str, format: Format) -> i32 {
    if id_arg.is_empty() {
        // List scenario playbooks only (not investigation paths)
        match format {
            Format::Json => {
                let arr: Vec<serde_json::Value> = PLAYBOOKS.iter().map(playbook_to_json).collect();
                println!("{}", json_pretty(&arr));
            }
            Format::Yaml => {
                for pb in PLAYBOOKS {
                    println!("- id: {}", pb.id);
                    println!("  name: {}", pb.name);
                    println!("  description: {}", pb.description);
                    println!("  steps: {}", pb.steps.len());
                    println!();
                }
            }
            Format::Human => {
                println!("Investigation Playbooks ({}):", PLAYBOOKS.len());
                println!();
                for pb in PLAYBOOKS {
                    println!("  {:30}  {}", pb.id, pb.name);
                    println!("    {}", pb.description);
                    println!(
                        "    Steps: {}  |  Tactics: {}",
                        pb.steps.len(),
                        pb.tactics_covered.join(", ")
                    );
                    println!();
                }
                println!("Run: 4n6query --playbook <id>  to see full step-by-step path");
                println!();
                println!("Investigation Paths ({}):", INVESTIGATION_PATHS.len());
                println!(
                    "(ATT&CK-tactic-focused artifact chains — shown when you query an artifact)"
                );
                for p in INVESTIGATION_PATHS {
                    println!("  {:30}  {}", p.id, p.name);
                }
            }
        }
        return 0;
    }

    // Show specific playbook OR investigation path — search both
    let found = playbook_by_id(id_arg).or_else(|| path_by_id(id_arg));
    match found {
        None => {
            eprintln!("Not found: playbook '{id_arg}'");
            eprintln!("Run: 4n6query --playbook  to list available playbooks");
            1
        }
        Some(pb) => {
            match format {
                Format::Json => {
                    println!("{}", json_pretty(&playbook_to_json(pb)));
                }
                Format::Yaml => {
                    println!("id: {}", pb.id);
                    println!("name: {}", pb.name);
                    println!("description: {}", pb.description);
                    println!("tactics_covered: [{}]", pb.tactics_covered.join(", "));
                    println!("steps:");
                    for (i, step) in pb.steps.iter().enumerate() {
                        println!("  - step: {}", i + 1);
                        println!("    artifact_id: {}", step.artifact_id);
                        println!("    tactic: {}", step.tactic);
                        println!("    rationale: {}", step.rationale);
                        println!("    look_for: {}", step.look_for);
                        if !step.unlocks.is_empty() {
                            println!("    unlocks: [{}]", step.unlocks.join(", "));
                        }
                    }
                }
                Format::Human => {
                    println!("Playbook: {} — {}", pb.id, pb.name);
                    println!("{}", pb.description);
                    println!("Tactics: {}", pb.tactics_covered.join(", "));
                    println!();
                    for (i, step) in pb.steps.iter().enumerate() {
                        println!("Step {} [{}]: {}", i + 1, step.tactic, step.artifact_id);
                        println!("  Why:      {}", step.rationale);
                        println!("  Look for: {}", step.look_for);
                        if !step.unlocks.is_empty() {
                            println!("  Unlocks:  {}", step.unlocks.join(", "));
                        }
                        println!();
                    }
                }
            }
            0
        }
    }
}

fn playbook_to_json(pb: &InvestigationPath) -> serde_json::Value {
    serde_json::json!({
        "id": pb.id,
        "name": pb.name,
        "description": pb.description,
        "tactics_covered": pb.tactics_covered,
        "steps": pb.steps.iter().map(|s| serde_json::json!({
            "artifact_id": s.artifact_id,
            "tactic": s.tactic,
            "rationale": s.rationale,
            "look_for": s.look_for,
            "unlocks": s.unlocks,
        })).collect::<Vec<_>>(),
    })
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

#[cfg(test)]
mod indicator_tests {
    use super::*;

    #[test]
    fn finds_byovd_driver_by_basename() {
        let h = lookup_drivers("rtcore64.sys");
        assert!(h
            .iter()
            .any(|d| d.file_basename == "rtcore64.sys" && !d.loldrivers_id.is_empty()));
        assert!(!lookup_drivers("rtcore64").is_empty()); // .sys optional
    }

    #[test]
    fn finds_byovd_driver_by_service_name() {
        assert!(lookup_drivers("RTCore64")
            .iter()
            .any(|d| d.file_basename == "rtcore64.sys"));
    }

    #[test]
    fn finds_lateral_movement_pattern() {
        assert!(lookup_indicators("wmiexec")
            .iter()
            .any(|(s, _)| s.label.contains("lateral")));
    }

    #[test]
    fn short_term_yields_nothing() {
        assert!(lookup_indicators("a").is_empty());
    }

    #[test]
    fn unknown_term_no_hits() {
        assert!(lookup_drivers("definitely-not-a-driver").is_empty());
        assert!(lookup_indicators("zzqxnotarealthing").is_empty());
    }
}

#[cfg(test)]
mod event_lookup_tests {
    use super::*;

    /// A bare number is all the CLI has — no channel — so the honest answer is
    /// every channel that defines it. Returning only the first (the old
    /// behaviour) means someone typing 21 for the Sysmon WMI binding silently
    /// gets an RDP session logon instead.
    #[test]
    fn bare_number_returns_every_channel_defining_it() {
        let hits = lookup_events("21");
        assert_eq!(hits.len(), 2, "21 is defined on two channels");
        let channels: Vec<&str> = hits.iter().map(|e| e.channel).collect();
        assert!(channels.contains(&"Microsoft-Windows-Sysmon/Operational"));
        assert!(channels
            .contains(&"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"));
    }

    #[test]
    fn unique_number_still_returns_exactly_one() {
        let hits = lookup_events("4624");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].channel, "Security");
    }

    #[test]
    fn non_numeric_and_unknown_numbers_return_nothing() {
        assert!(lookup_events("certutil.exe").is_empty());
        assert!(lookup_events("99999").is_empty());
    }
}
