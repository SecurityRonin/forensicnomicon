pub mod app;
pub mod dataset;
pub mod guards;
pub mod heatmap;
pub mod keys;
pub mod presets;
pub mod search;
pub mod theme;
pub mod ui;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(dataset: usize, query: &str, preset: usize) -> app::App {
        let mut a = app::App::new();
        a.switch_dataset(dataset);
        a.search_query = query.to_string();
        a.preset_idx = preset;
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
    fn build_render_data_windows_lolbins_dataset() {
        let a = make_app(1, "", 0);
        let rd = build_render_data(&a);
        assert!(
            !rd.list_items.is_empty(),
            "windows lolbins must be non-empty"
        );
    }

    #[test]
    fn build_render_data_preset_windows_crit_filters() {
        let a = make_app(0, "", 1); // preset 1 = Windows CRIT
        let rd = build_render_data(&a);
        let full_count = {
            let a2 = make_app(0, "", 0);
            build_render_data(&a2).list_items.len()
        };
        assert!(
            rd.list_items.len() < full_count,
            "Windows CRIT preset must filter catalog; got {} vs full {}",
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
        assert!(
            !rd.list_items.is_empty(),
            "search 'prefetch' must match something"
        );
        for item in &rd.list_items {
            assert!(
                item.to_lowercase().contains("prefetch"),
                "filtered item must contain query: {item}"
            );
        }
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
}

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use forensicnomicon::{
    abusable_sites::ABUSABLE_SITES,
    catalog::CATALOG,
    lolbins::{
        LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS, LOLBAS_WINDOWS_MMC,
        LOLBAS_WINDOWS_WMI,
    },
    playbooks::PLAYBOOKS,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

/// Frame-local render data built from App state on every tick.
pub struct RenderData {
    pub list_items: Vec<String>,
    pub detail_lines: Vec<String>,
}

fn build_render_data(app: &app::App) -> RenderData {
    let preset = presets::active(app.preset_idx);

    // Build the raw display list, applying preset filter for catalog (dataset 0).
    let all_display: Vec<String> = match app.dataset_idx {
        0 => CATALOG
            .list()
            .iter()
            .filter(|d| {
                preset.os.map_or(true, |os| d.os_scope == os)
                    && (preset.priorities.is_empty()
                        || preset.priorities.contains(&d.triage_priority))
            })
            .map(|d| format!("{:<36} [{:?}]", d.id, d.triage_priority))
            .collect(),
        1 => LOLBAS_WINDOWS.iter().map(|e| e.name.to_string()).collect(),
        2 => LOLBAS_LINUX.iter().map(|e| e.name.to_string()).collect(),
        3 => LOLBAS_MACOS.iter().map(|e| e.name.to_string()).collect(),
        4 => LOLBAS_WINDOWS_CMDLETS
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        5 => LOLBAS_WINDOWS_MMC
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        6 => LOLBAS_WINDOWS_WMI
            .iter()
            .map(|e| e.name.to_string())
            .collect(),
        7 => ABUSABLE_SITES
            .iter()
            .map(|s| s.domain.to_string())
            .collect(),
        8 => PLAYBOOKS.iter().map(|p| p.id.to_string()).collect(),
        _ => vec![],
    };

    // Apply search filter if query is non-empty.
    let list_items = if app.search_query.is_empty() {
        all_display
    } else {
        let entries: Vec<search::SearchEntry> = all_display
            .iter()
            .enumerate()
            .map(|(i, s)| search::SearchEntry::new(s.clone(), i))
            .collect();
        let matched_indices = search::filter(&app.search_query, &entries);
        matched_indices
            .into_iter()
            .map(|i| all_display[i].clone())
            .collect()
    };

    // Build detail pane for catalog dataset.
    let detail_lines = if app.dataset_idx == 0 {
        let selected_descriptor = list_items
            .get(app.selected)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|id| CATALOG.by_id(id));

        match selected_descriptor {
            Some(d) => {
                let mut lines = vec![
                    d.name.to_string(),
                    "─".repeat(40),
                    format!("Type:     {:?}", d.artifact_type),
                    format!("OS:       {:?}", d.os_scope),
                    format!("Priority: {:?}", d.triage_priority),
                ];
                if let Some(fp) = d.file_path {
                    lines.push(format!("Path: {fp}"));
                }
                if !d.key_path.is_empty() {
                    lines.push(format!("Key:  {}", d.key_path));
                }
                lines.push(String::new());
                lines.push(d.meaning.to_string());
                if !d.mitre_techniques.is_empty() {
                    lines.push(String::new());
                    lines.push(format!("MITRE: {}", d.mitre_techniques.join("  ")));
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
    } else {
        vec!["Select an item to see details.".into()]
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
    execute!(stdout, EnterAlternateScreen)?;
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
            if let Event::Key(key) = event::read()? {
                if keys::handle_key(&mut app, key, rd.list_items.len()) {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
