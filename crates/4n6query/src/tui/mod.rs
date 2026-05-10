pub mod app;
pub mod dataset;
pub mod guards;
pub mod heatmap;
pub mod keys;
pub mod search;
pub mod theme;
pub mod ui;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(dataset: usize, query: &str, _preset: usize) -> app::App {
        let mut a = app::App::new();
        a.switch_dataset(dataset);
        a.search_query = query.to_string();
        a
    }

    #[test]
    fn build_render_data_catalog_full_length() {
        let a = make_app(0, "", 0);
        let rd = build_render_data(&a);
        assert!(
            rd.list_items.len() > 100,
            "catalog must have >100 items, got {}",
            rd.list_items.len()
        );
    }

    #[test]
    fn dataset_count_is_9() {
        assert_eq!(app::App::DATASET_COUNT, 9, "9 datasets: catalog, lolbas, abusable sites, cmdlets, mmc, wmi, playbooks, malware profiles, attack flows");
    }

    #[test]
    fn lolbas_dataset_no_platform_shows_all_three_sources() {
        use forensicnomicon::lolbins::{LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS};
        let a = make_app(1, "", 0);
        let rd = build_render_data(&a);
        let combined = LOLBAS_WINDOWS.len() + LOLBAS_LINUX.len() + LOLBAS_MACOS.len();
        assert_eq!(
            rd.list_items.len(),
            combined,
            "no platform filter → all 3 lolbas sources combined"
        );
    }

    #[test]
    fn lolbas_dataset_windows_platform_shows_only_win_lolbas() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        use forensicnomicon::lolbins::LOLBAS_WINDOWS;
        let mut a = make_app(1, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        let rd = build_render_data(&a);
        assert_eq!(rd.list_items.len(), LOLBAS_WINDOWS.len());
    }

    #[test]
    fn lolbas_dataset_macos_platform_shows_only_macos_lolbas() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        use forensicnomicon::lolbins::LOLBAS_MACOS;
        let mut a = make_app(1, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::MacOS);
        let rd = build_render_data(&a);
        assert_eq!(rd.list_items.len(), LOLBAS_MACOS.len());
    }

    #[test]
    fn lolbas_dataset_linux_platform_shows_only_linux_lolbas() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        use forensicnomicon::lolbins::LOLBAS_LINUX;
        let mut a = make_app(1, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Linux);
        let rd = build_render_data(&a);
        assert_eq!(rd.list_items.len(), LOLBAS_LINUX.len());
    }

    #[test]
    fn build_render_data_lolbas_dataset_is_non_empty() {
        let a = make_app(1, "", 0);
        let rd = build_render_data(&a);
        assert!(!rd.list_items.is_empty(), "lolbas dataset must be non-empty");
    }

    #[test]
    fn build_render_data_windows_crit_filter_combo() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        a.crit_filter = app::CritFilter::Critical;
        let rd = build_render_data(&a);
        let full_count = build_render_data(&make_app(0, "", 0)).list_items.len();
        assert!(
            rd.list_items.len() < full_count,
            "Windows+Critical must filter catalog; got {} vs full {}",
            rd.list_items.len(),
            full_count
        );
        for item in &rd.list_items {
            assert!(item.contains("Critical"), "item must be Critical: {item}");
        }
    }

    #[test]
    fn build_render_data_search_filters_catalog() {
        let a = make_app(0, "prefetch", 0);
        let rd = build_render_data(&a);
        let full = build_render_data(&make_app(0, "", 0)).list_items.len();
        assert!(
            !rd.list_items.is_empty(),
            "search 'prefetch' must match something"
        );
        assert!(
            rd.list_items.len() < full,
            "search must reduce results: {} vs full {}",
            rd.list_items.len(),
            full
        );
        // Display strings show the artifact id — prefetch artifacts have
        // "prefetch" in their id, so this check holds for the primary matches.
        // (Meaning-only matches may appear too, which is correct behaviour.)
        assert!(
            rd.list_items
                .iter()
                .any(|s| s.to_lowercase().contains("prefetch")),
            "at least one result must be a prefetch artifact"
        );
    }

    #[test]
    fn build_render_data_search_matches_human_name_with_space() {
        // "Prefetch File" (space) is NOT in the id "prefetch_file" (underscore).
        // Only works when d.name is in the search index.
        let a = make_app(0, "Prefetch File", 0);
        let rd = build_render_data(&a);
        assert!(
            !rd.list_items.is_empty(),
            "search 'Prefetch File' must match via d.name; got 0 results"
        );
    }

    #[test]
    fn build_render_data_search_matches_file_path_fragment() {
        // "AppData" appears in d.file_path of several artifacts, not in their ids.
        let a = make_app(0, "AppData", 0);
        let rd = build_render_data(&a);
        assert!(
            !rd.list_items.is_empty(),
            "search 'AppData' must match via d.file_path; got 0 results"
        );
    }

    #[test]
    fn build_render_data_search_matches_meaning_text() {
        // "lateral" appears in d.meaning of several artifacts, not in their ids.
        let a = make_app(0, "lateral", 0);
        let rd = build_render_data(&a);
        assert!(
            !rd.list_items.is_empty(),
            "search 'lateral' must match via d.meaning; got 0 results"
        );
    }

    #[test]
    fn build_render_data_search_matches_registry_key_path() {
        // "HKEY_LOCAL_MACHINE" appears in d.key_path, not in artifact ids.
        let a = make_app(0, "HKEY_LOCAL_MACHINE", 0);
        let rd = build_render_data(&a);
        assert!(
            !rd.list_items.is_empty(),
            "search 'HKEY_LOCAL_MACHINE' must match via d.key_path; got 0 results"
        );
    }

    #[test]
    fn build_render_data_empty_query_returns_all() {
        let a = make_app(0, "", 0);
        let rd = build_render_data(&a);
        let expected = forensicnomicon::catalog::CATALOG.list().len();
        assert_eq!(rd.list_items.len(), expected);
    }

    #[test]
    fn build_render_data_detail_shows_selected_artifact() {
        let mut a = make_app(0, "prefetch_file", 0);
        a.selected = 0; // first search result
        let rd = build_render_data(&a);
        let combined = rd.detail_lines.join("\n");
        assert!(
            combined.contains("prefetch") || combined.contains("Prefetch"),
            "detail must mention selected artifact; got: {combined}"
        );
    }

    #[test]
    fn load_theme_returns_default_on_missing_file() {
        let t = load_theme();
        assert_ne!(t.crit_fg, ratatui::style::Color::Reset);
    }

    // ── Platform mask filter ──────────────────────────────────────────────

    #[test]
    fn build_render_data_platform_mask_linux_reduces_results() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let full = build_render_data(&make_app(0, "", 0)).list_items.len();
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Linux);
        let linux_count = build_render_data(&a).list_items.len();
        assert!(
            linux_count < full,
            "Linux-only filter must reduce results: {} vs full {}",
            linux_count,
            full
        );
    }

    #[test]
    fn build_render_data_platform_mask_windows_reduces_results() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let full = build_render_data(&make_app(0, "", 0)).list_items.len();
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        let win_count = build_render_data(&a).list_items.len();
        assert!(
            win_count < full,
            "Windows-only filter must reduce results: {} vs full {}",
            win_count,
            full
        );
    }

    #[test]
    fn build_render_data_win10_filter_shows_fewer_than_all_windows() {
        use crate::tui::app::WinVersionFilter;
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let win_all = {
            let mut a = make_app(0, "", 0);
            a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
            build_render_data(&a).list_items.len()
        };
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        a.win_version = WinVersionFilter::Win10Plus;
        let win10_count = build_render_data(&a).list_items.len();
        assert!(
            win10_count < win_all,
            "Win10+ must show fewer results than all-Windows: {} vs {}",
            win10_count,
            win_all
        );
    }

    #[test]
    fn build_render_data_win11_filter_shows_fewer_than_win10() {
        use crate::tui::app::WinVersionFilter;
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let win10_count = {
            let mut a = make_app(0, "", 0);
            a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
            a.win_version = WinVersionFilter::Win10Plus;
            build_render_data(&a).list_items.len()
        };
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        a.win_version = WinVersionFilter::Win11Plus;
        let win11_count = build_render_data(&a).list_items.len();
        assert!(
            win11_count < win10_count,
            "Win11+ must show fewer results than Win10+: {} vs {}",
            win11_count,
            win10_count
        );
    }

    // ── CritFilter integration ────────────────────────────────────────────

    #[test]
    fn build_render_data_crit_filter_critical_shows_only_critical() {
        let mut a = make_app(0, "", 0);
        a.crit_filter = app::CritFilter::Critical;
        let rd = build_render_data(&a);
        assert!(!rd.list_items.is_empty(), "must have some critical items");
        for item in &rd.list_items {
            assert!(item.contains("[Critical]"), "expected [Critical]: {item}");
        }
    }

    #[test]
    fn build_render_data_crit_filter_high_shows_critical_and_high_only() {
        let mut a = make_app(0, "", 0);
        a.crit_filter = app::CritFilter::High;
        let rd = build_render_data(&a);
        let full = build_render_data(&make_app(0, "", 0)).list_items.len();
        assert!(!rd.list_items.is_empty());
        assert!(rd.list_items.len() < full, "high filter must reduce results");
        for item in &rd.list_items {
            assert!(
                item.contains("[Critical]") || item.contains("[High]"),
                "expected Critical or High only: {item}"
            );
        }
    }

    #[test]
    fn build_render_data_crit_filter_all_shows_full_catalog() {
        let mut a = make_app(0, "", 0);
        a.crit_filter = app::CritFilter::All;
        let rd = build_render_data(&a);
        let expected = forensicnomicon::catalog::CATALOG.list().len();
        assert_eq!(rd.list_items.len(), expected, "All filter must show full catalog");
    }

    #[test]
    fn build_render_data_platform_mask_none_shows_all_unfiltered() {
        use forensicnomicon::catalog::PlatformMask;
        let mut a = make_app(0, "", 0);
        a.platform_mask = PlatformMask::NONE;
        let rd = build_render_data(&a);
        let expected = forensicnomicon::catalog::CATALOG.list().len();
        assert_eq!(
            rd.list_items.len(),
            expected,
            "empty mask must show full catalog"
        );
    }

    // ── non-catalog detail panes ──────────────────────────────────────────

    #[test]
    fn lolbas_detail_not_placeholder() {
        let rd = build_render_data(&make_app(1, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            !combined.contains("Select an item"),
            "lolbas detail must show entry info, not placeholder; got: {combined}"
        );
    }

    #[test]
    fn lolbas_detail_contains_mitre_technique() {
        let rd = build_render_data(&make_app(1, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            combined.contains("T1"),
            "lolbas detail must contain a MITRE technique; got: {combined}"
        );
    }

    #[test]
    fn cmdlets_detail_not_placeholder() {
        let rd = build_render_data(&make_app(3, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            !combined.contains("Select an item"),
            "cmdlets detail must show entry info; got: {combined}"
        );
    }

    fn label_colon_positions(lines: &[String]) -> Vec<usize> {
        // Only consider lines where the colon appears within the first 12 chars —
        // that's where padded label fields live; body text colons are further right.
        lines.iter()
            .filter(|l| !l.starts_with(' ') && !l.contains("://"))
            .filter_map(|l| {
                let pos = l.find(": ")?;
                if pos <= 12 { Some(pos) } else { None }
            })
            .collect()
    }

    #[test]
    fn abusable_sites_detail_label_values_column_aligned() {
        let rd = build_render_data(&make_app(2, "", 0));
        let positions = label_colon_positions(&rd.detail_lines);
        assert!(positions.len() >= 2, "need at least 2 label lines to check alignment");
        let first = positions[0];
        for pos in &positions {
            assert_eq!(*pos, first,
                "all label-value lines must have colon at same column; lines:\n{}",
                rd.detail_lines.join("\n"));
        }
    }

    #[test]
    fn catalog_detail_label_values_column_aligned() {
        let rd = build_render_data(&make_app(0, "", 0));
        let positions = label_colon_positions(&rd.detail_lines);
        assert!(positions.len() >= 2, "need at least 2 label lines to check alignment");
        let first = positions[0];
        for pos in &positions {
            assert_eq!(*pos, first,
                "all label-value lines must have colon at same column; lines:\n{}",
                rd.detail_lines.join("\n"));
        }
    }

    #[test]
    fn abusable_sites_detail_not_placeholder() {
        let rd = build_render_data(&make_app(2, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            !combined.contains("Select an item"),
            "abusable sites detail must show entry info; got: {combined}"
        );
    }

    #[test]
    fn playbooks_detail_not_placeholder() {
        let rd = build_render_data(&make_app(6, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            !combined.contains("Select an item"),
            "playbooks detail must show entry info; got: {combined}"
        );
    }

    #[test]
    fn playbooks_detail_contains_step_info() {
        let rd = build_render_data(&make_app(6, "", 0));
        let combined = rd.detail_lines.join("\n");
        assert!(
            combined.to_lowercase().contains("step"),
            "playbooks detail must mention steps; got: {combined}"
        );
    }

    // ── dataset ordering: abusable sites must be idx 2 (adjacent to lolbas) ─

    #[test]
    fn malware_profiles_is_at_idx_7() {
        use forensicnomicon::threat_intel::profiles::ALL_PROFILES;
        let rd = build_render_data(&make_app(7, "", 0));
        assert!(
            !rd.list_items.is_empty(),
            "dataset idx 7 must be malware profiles (non-empty list)"
        );
        let first_id = ALL_PROFILES[0].id;
        assert!(
            rd.list_items.iter().any(|s| s.contains(first_id)),
            "malware profiles list must contain '{}'; got: {:?}",
            first_id,
            &rd.list_items[..rd.list_items.len().min(3)]
        );
    }

    #[test]
    fn malware_profile_detail_contains_family_info() {
        let rd = build_render_data(&make_app(7, "", 0));
        assert!(!rd.detail_lines.is_empty(), "malware profile detail must be non-empty");
        let combined = rd.detail_lines.join("\n").to_lowercase();
        assert!(
            combined.contains("class") || combined.contains("mitre") || combined.contains("family"),
            "malware profile detail must contain class/mitre/family info; got: {combined}"
        );
    }

    #[test]
    fn attack_flows_is_at_idx_8() {
        use forensicnomicon::attack_flow::all_flows;
        let rd = build_render_data(&make_app(8, "", 0));
        assert!(
            !rd.list_items.is_empty(),
            "dataset idx 8 must be attack flows (non-empty list)"
        );
        let first_id = all_flows()[0].id;
        assert!(
            rd.list_items.iter().any(|s| s.contains(first_id)),
            "attack flows list must contain '{}'; got: {:?}",
            first_id,
            &rd.list_items[..rd.list_items.len().min(3)]
        );
    }

    #[test]
    fn attack_flow_detail_contains_step_count() {
        let rd = build_render_data(&make_app(8, "", 0));
        assert!(!rd.detail_lines.is_empty(), "attack flow detail must be non-empty");
        let combined = rd.detail_lines.join("\n").to_lowercase();
        assert!(
            combined.contains("step") || combined.contains("action") || combined.contains("technique"),
            "attack flow detail must contain step/action/technique info; got: {combined}"
        );
    }

    #[test]
    fn abusable_sites_is_at_idx_2() {
        use forensicnomicon::abusable_sites::ABUSABLE_SITES;
        let rd = build_render_data(&make_app(2, "", 0));
        let first_domain = ABUSABLE_SITES[0].domain;
        assert!(
            rd.list_items.iter().any(|s| s.as_str() == first_domain),
            "dataset idx 2 must be abusable sites; '{}' not in list: {:?}",
            first_domain,
            &rd.list_items[..rd.list_items.len().min(3)]
        );
    }

    #[test]
    fn cmdlets_is_at_idx_3() {
        use forensicnomicon::lolbins::LOLBAS_WINDOWS_CMDLETS;
        let rd = build_render_data(&make_app(3, "", 0));
        let first = LOLBAS_WINDOWS_CMDLETS[0].name;
        assert!(
            rd.list_items.iter().any(|s| s.as_str() == first),
            "dataset idx 3 must be cmdlets; '{}' not in list: {:?}",
            first,
            &rd.list_items[..rd.list_items.len().min(3)]
        );
    }
}

use crate::tui::app::WinVersionFilter;
use crossterm::{
    event::{self, EnableMouseCapture, DisableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use forensicnomicon::{
    abusable_sites::{
        ABUSABLE_SITES, TAG_C2, TAG_DOWNLOAD, TAG_EXFIL, TAG_EXPLOIT, TAG_PHISHING,
    },
    attack_flow::all_flows,
    catalog::{ArtifactDescriptor, OsScope, Platform, CATALOG},
    lolbins::{
        lolbas_entry, LolbasEntry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS,
        LOLBAS_WINDOWS_CMDLETS, LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI, UC_ARCHIVE, UC_BYPASS,
        UC_CREDENTIALS, UC_DECODE, UC_DEFENSE_EVASION, UC_DOWNLOAD, UC_EXECUTE, UC_NETWORK,
        UC_PERSIST, UC_PROXY, UC_RECON, UC_UPLOAD,
    },
    playbooks::PLAYBOOKS,
    threat_intel::profiles::ALL_PROFILES,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

/// Frame-local render data built from App state on every tick.
pub struct RenderData {
    pub list_items: Vec<String>,
    pub detail_lines: Vec<String>,
}

fn use_cases_str(uc: u16) -> String {
    let mut tags: Vec<&str> = Vec::new();
    if uc & UC_EXECUTE != 0 { tags.push("Execute"); }
    if uc & UC_DOWNLOAD != 0 { tags.push("Download"); }
    if uc & UC_UPLOAD != 0 { tags.push("Upload"); }
    if uc & UC_BYPASS != 0 { tags.push("Bypass"); }
    if uc & UC_PERSIST != 0 { tags.push("Persist"); }
    if uc & UC_RECON != 0 { tags.push("Recon"); }
    if uc & UC_PROXY != 0 { tags.push("Proxy"); }
    if uc & UC_DECODE != 0 { tags.push("Decode"); }
    if uc & UC_ARCHIVE != 0 { tags.push("Archive"); }
    if uc & UC_CREDENTIALS != 0 { tags.push("Credentials"); }
    if uc & UC_NETWORK != 0 { tags.push("Network"); }
    if uc & UC_DEFENSE_EVASION != 0 { tags.push("DefEvasion"); }
    tags.join("  ")
}

fn lolbas_detail_lines(entry: &LolbasEntry) -> Vec<String> {
    let mut lines = vec![
        entry.name.to_string(),
        "─".repeat(40),
        entry.description.to_string(),
    ];
    if !entry.mitre_techniques.is_empty() {
        lines.push(String::new());
        lines.push(format!("MITRE: {}", entry.mitre_techniques.join("  ")));
    }
    let uc = use_cases_str(entry.use_cases);
    if !uc.is_empty() {
        lines.push(String::new());
        lines.push(format!("Use cases: {uc}"));
    }
    lines
}

fn malware_class_label(class: forensicnomicon::threat_intel::MalwareClass) -> &'static str {
    use forensicnomicon::threat_intel::MalwareClass;
    match class {
        MalwareClass::LdPreloadProcessHider => "LD_PRELOAD/process-hider",
        MalwareClass::LdPreloadPamHooker    => "LD_PRELOAD/PAM-hooker",
        MalwareClass::LdPreloadNetworkHider => "LD_PRELOAD/network-hider",
        MalwareClass::LdPreloadFullRootkit  => "LD_PRELOAD/full-rootkit",
        MalwareClass::LkmRootkit            => "LKM/rootkit",
        MalwareClass::CryptoMiner           => "crypto-miner",
        MalwareClass::GenericLdPreload      => "LD_PRELOAD/generic",
    }
}

fn abuse_tags_str(tags: u8) -> String {
    let mut v: Vec<&str> = Vec::new();
    if tags & TAG_PHISHING != 0 { v.push("Phishing"); }
    if tags & TAG_C2 != 0 { v.push("C2"); }
    if tags & TAG_DOWNLOAD != 0 { v.push("Download"); }
    if tags & TAG_EXFIL != 0 { v.push("Exfil"); }
    if tags & TAG_EXPLOIT != 0 { v.push("Exploit"); }
    v.join("  ")
}

/// Catalog filter predicate — platform mask + criticality filter.
///
/// Factored out so the same logic is used for both display-list construction
/// and rich search-index construction.
fn catalog_passes(app: &app::App, d: &ArtifactDescriptor) -> bool {
    let platform_ok = if !app.platform_mask.is_empty() {
        if app.platform_mask.contains(Platform::Windows)
            && d.os_scope.platform() == Platform::Windows
        {
            match app.win_version {
                WinVersionFilter::All => true,
                WinVersionFilter::Win10Plus => matches!(
                    d.os_scope,
                    OsScope::Win10Plus | OsScope::Win11Plus | OsScope::Win11_22H2
                ),
                WinVersionFilter::Win11Plus => {
                    matches!(d.os_scope, OsScope::Win11Plus | OsScope::Win11_22H2)
                }
            }
        } else {
            app.platform_mask.matches(d.os_scope.platform())
        }
    } else {
        true
    };
    platform_ok && app.crit_filter.passes(d.triage_priority)
}

fn build_render_data(app: &app::App) -> RenderData {
    // Build the raw display list applying platform + crit filters for catalog (dataset 0).
    let all_display: Vec<String> = match app.dataset_idx {
        0 => CATALOG
            .list()
            .iter()
            .filter(|d| catalog_passes(app, d))
            .map(|d| format!("{:<36} [{:?}]", d.id, d.triage_priority))
            .collect(),
        1 => {
            // Merged cross-platform lolbas — platform filter selects source.
            if app.platform_mask.is_empty() {
                let mut v: Vec<String> =
                    LOLBAS_WINDOWS.iter().map(|e| e.name.to_string()).collect();
                v.extend(LOLBAS_LINUX.iter().map(|e| e.name.to_string()));
                v.extend(LOLBAS_MACOS.iter().map(|e| e.name.to_string()));
                v
            } else if app.platform_mask.contains(Platform::MacOS) {
                LOLBAS_MACOS.iter().map(|e| e.name.to_string()).collect()
            } else if app.platform_mask.contains(Platform::Linux) {
                LOLBAS_LINUX.iter().map(|e| e.name.to_string()).collect()
            } else {
                LOLBAS_WINDOWS.iter().map(|e| e.name.to_string()).collect()
            }
        }
        2 => ABUSABLE_SITES
            .iter()
            .map(|s| s.domain.to_string())
            .collect(),
        3 => LOLBAS_WINDOWS_CMDLETS
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        4 => LOLBAS_WINDOWS_MMC
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        5 => LOLBAS_WINDOWS_WMI
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        6 => PLAYBOOKS.iter().map(|p| p.id.to_string()).collect(),
        7 => ALL_PROFILES
            .iter()
            .map(|p| format!("{:<24}  [{}]", p.id, malware_class_label(p.malware_class)))
            .collect(),
        8 => all_flows()
            .iter()
            .map(|f| format!("{:<40}  {}", f.id, f.name))
            .collect(),
        _ => vec![],
    };

    // Apply search filter if query is non-empty.
    let list_items = if app.search_query.is_empty() {
        all_display
    } else {
        let entries: Vec<search::SearchEntry> = if app.dataset_idx == 0 {
            // Catalog: rich multi-field index (id + name + meaning + file_path + key_path).
            // Re-iterate with the same filter — all 'static data, no I/O.
            CATALOG
                .list()
                .iter()
                .filter(|d| catalog_passes(app, d))
                .enumerate()
                .map(|(i, d)| {
                    let mut parts: Vec<&str> = vec![d.id, d.name, d.meaning];
                    if let Some(fp) = d.file_path {
                        parts.push(fp);
                    }
                    if !d.key_path.is_empty() {
                        parts.push(d.key_path);
                    }
                    search::SearchEntry::new(parts.join(" ").to_ascii_lowercase(), i)
                })
                .collect()
        } else {
            all_display
                .iter()
                .enumerate()
                .map(|(i, s)| search::SearchEntry::new(s.to_ascii_lowercase(), i))
                .collect()
        };
        let matched_indices = search::filter(&app.search_query, &entries);
        matched_indices
            .into_iter()
            .map(|i| all_display[i].clone())
            .collect()
    };

    let selected_name = list_items.get(app.selected).map(|s| s.trim());

    let detail_lines: Vec<String> = match app.dataset_idx {
        0 => {
            let desc = selected_name
                .and_then(|s| s.split_whitespace().next())
                .and_then(|id| CATALOG.by_id(id));
            match desc {
                Some(d) => {
                    const CW: usize = 8; // "Priority" = longest label
                    let mut lines = vec![
                        d.name.to_string(),
                        "─".repeat(40),
                        format!("{:<CW$}: {:?}", "Type", d.artifact_type),
                        format!("{:<CW$}: {:?}", "OS", d.os_scope),
                        format!("{:<CW$}: {:?}", "Priority", d.triage_priority),
                    ];
                    if let Some(fp) = d.file_path {
                        lines.push(format!("{:<CW$}: {fp}", "Path"));
                    }
                    if !d.key_path.is_empty() {
                        lines.push(format!("{:<CW$}: {}", "Key", d.key_path));
                    }
                    lines.push(String::new());
                    lines.push(d.meaning.to_string());
                    if !d.mitre_techniques.is_empty() {
                        lines.push(String::new());
                        lines.push(format!("{:<CW$}: {}", "MITRE", d.mitre_techniques.join("  ")));
                    }
                    if !d.fields.is_empty() {
                        lines.push(String::new());
                        lines.push("Fields:".into());
                        for f in d.fields {
                            lines.push(format!("  {}  — {}", f.name, f.description));
                        }
                    }
                    if !d.sources.is_empty() {
                        lines.push(String::new());
                        lines.push("Sources:".into());
                        for s in d.sources {
                            lines.push(format!("  {s}"));
                        }
                    }
                    lines
                }
                None => vec!["Select an item to see details.".into()],
            }
        }
        // Lolbas: search platform-appropriate source(s).
        1 => {
            let entry = selected_name.and_then(|name| {
                if app.platform_mask.contains(Platform::MacOS) {
                    lolbas_entry(LOLBAS_MACOS, name)
                } else if app.platform_mask.contains(Platform::Linux) {
                    lolbas_entry(LOLBAS_LINUX, name)
                } else if !app.platform_mask.is_empty() {
                    lolbas_entry(LOLBAS_WINDOWS, name)
                } else {
                    lolbas_entry(LOLBAS_WINDOWS, name)
                        .or_else(|| lolbas_entry(LOLBAS_LINUX, name))
                        .or_else(|| lolbas_entry(LOLBAS_MACOS, name))
                }
            });
            entry.map(lolbas_detail_lines).unwrap_or_else(|| vec!["Select an item.".into()])
        }
        2 => {
            let site = selected_name.and_then(|name| {
                ABUSABLE_SITES.iter().find(|s| s.domain.eq_ignore_ascii_case(name))
            });
            match site {
                Some(s) => {
                    const CW: usize = 10; // "Block risk" = longest label
                    let mut lines = vec![
                        s.domain.to_string(),
                        "─".repeat(40),
                        format!("{:<CW$}: {}", "Provider", s.provider),
                        format!("{:<CW$}: {:?}", "Category", s.legitimate_category),
                        format!("{:<CW$}: {:?}", "Block risk", s.blocking_risk),
                    ];
                    let tags = abuse_tags_str(s.abuse_tags);
                    if !tags.is_empty() {
                        lines.push(format!("{:<CW$}: {tags}", "Abuse"));
                    }
                    if !s.mitre_techniques.is_empty() {
                        lines.push(String::new());
                        lines.push(format!("{:<CW$}: {}", "MITRE", s.mitre_techniques.join("  ")));
                    }
                    lines
                }
                None => vec!["Select an item.".into()],
            }
        }
        3 => selected_name
            .and_then(|n| lolbas_entry(LOLBAS_WINDOWS_CMDLETS, n))
            .map(lolbas_detail_lines)
            .unwrap_or_else(|| vec!["Select an item.".into()]),
        4 => selected_name
            .and_then(|n| lolbas_entry(LOLBAS_WINDOWS_MMC, n))
            .map(lolbas_detail_lines)
            .unwrap_or_else(|| vec!["Select an item.".into()]),
        5 => selected_name
            .and_then(|n| lolbas_entry(LOLBAS_WINDOWS_WMI, n))
            .map(lolbas_detail_lines)
            .unwrap_or_else(|| vec!["Select an item.".into()]),
        6 => {
            let pb = selected_name.and_then(|id| PLAYBOOKS.iter().find(|p| p.id == id));
            match pb {
                Some(p) => {
                    let mut lines = vec![
                        p.name.to_string(),
                        "─".repeat(40),
                        p.description.to_string(),
                        String::new(),
                        format!("Steps: {}", p.steps.len()),
                    ];
                    for (i, step) in p.steps.iter().enumerate() {
                        lines.push(String::new());
                        lines.push(format!("  {}. {} — {}", i + 1, step.artifact_id, step.tactic));
                        lines.push(format!("     {}", step.rationale));
                    }
                    lines
                }
                None => vec!["Select an item.".into()],
            }
        }
        7 => {
            let profile = selected_name
                .and_then(|s| s.split_whitespace().next())
                .and_then(|id| ALL_PROFILES.iter().copied().find(|p| p.id == id));
            match profile {
                Some(p) => {
                    let mut lines = vec![
                        p.family.to_string(),
                        "─".repeat(40),
                        p.description.to_string(),
                        String::new(),
                        format!("Family  : {}", p.family),
                        format!("Class   : {}", malware_class_label(p.malware_class)),
                    ];
                    if !p.mitre_techniques.is_empty() {
                        lines.push(format!("MITRE   : {}", p.mitre_techniques.join("  ")));
                    }
                    lines.push(String::new());
                    lines.push(format!("Thresholds — class:{} probable:{} confirmed:{}",
                        p.class_threshold, p.probable_threshold, p.confirmed_threshold));
                    lines.push(String::new());
                    lines.push("Signals:".into());
                    for s in p.signals {
                        let req = if s.required { " [required]" } else { "" };
                        lines.push(format!("  {:>3}  {}{}", s.weight, s.id, req));
                    }
                    if !p.exclusions.is_empty() {
                        lines.push(String::new());
                        lines.push("Exclusions:".into());
                        for e in p.exclusions {
                            lines.push(format!("  -{:>3}  {}", e.penalty, e.id));
                        }
                    }
                    lines
                }
                None => vec!["Select a profile to see details.".into()],
            }
        }
        8 => {
            let flow = selected_name
                .and_then(|s| s.split_whitespace().next())
                .and_then(|id| all_flows().iter().find(|f| f.id == id));
            match flow {
                Some(f) => {
                    let mut lines = vec![
                        f.name.to_string(),
                        "─".repeat(40),
                        f.description.to_string(),
                        String::new(),
                        format!("Actions : {}", f.actions.len()),
                        String::new(),
                        "Steps:".into(),
                    ];
                    for (i, a) in f.actions.iter().enumerate() {
                        lines.push(format!("  {:>2}. [{}] {} — {}", i + 1, a.technique_id, a.tactic, a.name));
                        if !a.artifact_ids.is_empty() {
                            lines.push(format!("      Artifacts: {}", a.artifact_ids.join(", ")));
                        }
                    }
                    lines
                }
                None => vec!["Select a flow to see details.".into()],
            }
        }
        _ => vec!["Select an item to see details.".into()],
    };

    RenderData {
        list_items,
        detail_lines,
    }
}

fn load_theme() -> &'static theme::Theme {
    let config_path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("4n6query")
        .join("theme.toml");

    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        if let Ok(t) = theme::load_user_config(&contents) {
            return t;
        }
    }
    theme::ALL_THEMES[0]
}

/// Launch the interactive TUI navigator.
///
/// Called when `4n6query` is invoked with no arguments on a TTY.
/// Returns 0 on clean exit, 1 on error.
pub fn run() -> i32 {
    if let Err(e) = run_inner() {
        eprintln!("tui error: {e}");
        1
    } else {
        0
    }
}

fn run_inner() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::App::new();
    let theme = load_theme();

    loop {
        app.tick_flash();
        let rd = build_render_data(&app);

        terminal.draw(|f| {
            ui::draw(f, &app, theme, &rd.list_items, &rd.detail_lines);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    if keys::handle_key(&mut app, key, rd.list_items.len()) {
                        break;
                    }
                }
                Event::Mouse(mouse) => {
                    keys::handle_mouse(&mut app, mouse, rd.list_items.len());
                }
                _ => {}
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}
