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
    lolbas_entry, LolbasEntry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS,
    LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
};
use forensicnomicon::playbooks::{playbook_by_id, InvestigationPath, PLAYBOOKS};
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
    (
        Platform::WindowsCmdlet,
        "windows-cmdlet",
        LOLBAS_WINDOWS_CMDLETS,
    ),
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
        run_triage(cli.format, cli.scenario.as_deref(), cli.tactic.as_deref())
    } else if let Some(pb_arg) = cli.playbook {
        run_playbook(&pb_arg, cli.format)
    } else if let Some(term) = cli.term {
        run_query(&term, cli.platform, cli.format)
    } else {
        eprintln!("Usage: 4n6query <term> [--platform <p>] [--format json|yaml]");
        eprintln!("       4n6query --triage");
        eprintln!("       4n6query --playbook [<id>]");
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
        || (digits.len() == 8
            && digits[4] == b'.'
            && digits[5..].iter().all(|b| b.is_ascii_digit()))
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

    // 4. Relevant playbooks: any playbook that mentions a matched artifact in its steps.
    let playbook_hits: Vec<&InvestigationPath> = if !artifact_hits.is_empty() {
        let hit_ids: Vec<&str> = artifact_hits.iter().map(|d| d.id).collect();
        PLAYBOOKS
            .iter()
            .filter(|pb| pb.steps.iter().any(|s| hit_ids.contains(&s.artifact_id)))
            .collect()
    } else {
        vec![]
    };

    if lolbas_hits.is_empty() && site_hit.is_none() && artifact_hits.is_empty() {
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
            if !artifact_hits.is_empty() {
                let arr: Vec<_> = artifact_hits
                    .iter()
                    .map(|d| descriptor_to_json(d))
                    .collect();
                obj.insert("artifacts".into(), serde_json::Value::Array(arr));
            }
            if !playbook_hits.is_empty() {
                let arr: Vec<_> = playbook_hits
                    .iter()
                    .map(|pb| playbook_to_json(pb))
                    .collect();
                obj.insert("playbooks".into(), serde_json::Value::Array(arr));
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
            if !playbook_hits.is_empty() {
                println!();
                println!("Playbooks:");
                for pb in &playbook_hits {
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

fn run_triage(format: Format, scenario: Option<&str>, tactic: Option<&str>) -> i32 {
    // Validate scenario if provided
    let scenario_prefixes: Option<&'static [&'static str]> = if let Some(s) = scenario {
        match techniques_for_scenario(s) {
            Some(prefixes) => Some(prefixes),
            None => {
                eprintln!(
                    "error: unknown scenario '{}'. Valid values: ransomware, data-breach, bec, insider, supply-chain",
                    s
                );
                return 1;
            }
        }
    } else {
        None
    };

    // Validate tactic if provided
    let tactic_prefixes: Option<&'static [&'static str]> = if let Some(t) = tactic {
        match techniques_for_tactic(t) {
            Some(prefixes) => Some(prefixes),
            None => {
                eprintln!(
                    "error: unknown tactic '{}'. Valid values: execution, persistence, lateral-movement, \
                     credential-access, defense-evasion, discovery, collection, exfiltration, \
                     command-and-control, privilege-escalation",
                    t
                );
                return 1;
            }
        }
    } else {
        None
    };

    // Start from Critical+High triage list
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
            true
        })
        .collect();

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
        let arr: Vec<_> = CATALOG
            .list()
            .iter()
            .map(|d| descriptor_to_json(d))
            .collect();
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

// ---------------------------------------------------------------------------
// Playbook
// ---------------------------------------------------------------------------

fn run_playbook(id_arg: &str, format: Format) -> i32 {
    if id_arg.is_empty() {
        // List all playbooks
        match format {
            Format::Json => {
                let arr: Vec<serde_json::Value> = PLAYBOOKS.iter().map(playbook_to_json).collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
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
            }
        }
        return 0;
    }

    // Show specific playbook
    match playbook_by_id(id_arg) {
        None => {
            eprintln!("Not found: playbook '{id_arg}'");
            eprintln!("Run: 4n6query --playbook  to list available playbooks");
            1
        }
        Some(pb) => {
            match format {
                Format::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&playbook_to_json(pb)).unwrap()
                    );
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
                        println!("Step {}: {}", i + 1, step.artifact_id);
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
