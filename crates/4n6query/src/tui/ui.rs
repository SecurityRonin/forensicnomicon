/// Rendering layer — pure functions from (&App, theme, data) → Frame.
///
/// Nothing here mutates App. All side-effects are terminal draws.
/// Tests use ratatui TestBackend so no real terminal is required.
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use forensicnomicon::catalog::Platform;

use crate::tui::app::{App, Focus, Mode, WinVersionFilter};
use crate::tui::heatmap::{render_bar, tactic_mask, BLOCK_HIT, BLOCK_MISS};
use crate::tui::presets::active as active_preset;
use crate::tui::theme::Theme;

/// Version string shown in the about modal.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compute the dual-pane split ratio.
///
/// - Width ≥ 100: 38 % list / 62 % detail (classic MC split)
/// - Width < 100 : 50 / 50 (adaptive)
pub fn pane_constraints(width: u16) -> [Constraint; 2] {
    if width >= 100 {
        [Constraint::Percentage(38), Constraint::Percentage(62)]
    } else {
        [Constraint::Percentage(50), Constraint::Percentage(50)]
    }
}

/// Build the header line showing dataset + preset + search query.
pub fn header_text<'a>(app: &'a App, theme: &'a Theme) -> Line<'a> {
    let preset = active_preset(app.preset_idx);
    let dataset_label = crate::tui::dataset::Dataset::from_idx(app.dataset_idx)
        .map(|d| d.label())
        .unwrap_or("unknown");

    let mut spans = vec![
        Span::styled(
            " forensicnomicon ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ "),
        Span::styled(dataset_label, Style::default().fg(theme.dataset_fg)),
        Span::raw(" │ "),
        Span::styled(preset.label, Style::default().fg(theme.header_fg)),
    ];

    if !app.platform_mask.is_empty() {
        let label = if app.platform_mask.contains(Platform::Windows) {
            match app.win_version {
                WinVersionFilter::All => "[Win]",
                WinVersionFilter::Win10Plus => "[W10]",
                WinVersionFilter::Win11Plus => "[W11]",
            }
        } else if app.platform_mask.contains(Platform::MacOS) {
            "[Mac]"
        } else if app.platform_mask.contains(Platform::Linux) {
            "[Lin]"
        } else {
            ""
        };
        if !label.is_empty() {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(label, Style::default().fg(theme.header_fg)));
        }
    }

    if !app.search_query.is_empty() || app.mode == Mode::Search {
        spans.push(Span::raw("  /"));
        spans.push(Span::styled(
            app.search_query.as_str(),
            Style::default().fg(theme.match_hl),
        ));
        if app.mode == Mode::Search {
            spans.push(Span::raw("█")); // cursor
        }
    }

    Line::from(spans)
}

/// Build the hint bar line.
///
/// If a flash message is active and not expired, show it (possibly in
/// warning colour). Otherwise show the static keybinding hint.
pub fn hint_text<'a>(app: &'a App, theme: &'a Theme) -> Line<'a> {
    if let Some(flash) = &app.flash {
        if !flash.is_expired() {
            return Line::from(Span::styled(
                flash.text.as_str(),
                Style::default().fg(theme.hint_warn_fg),
            ));
        }
    }

    let mode_hint = match app.mode {
        Mode::Search => " Esc: finish  ↑↓: navigate  Enter: confirm",
        Mode::About => " Esc/q: close  ↑↓/jk: scroll",
        Mode::Normal => " /: search  j/k: navigate  Tab: focus  Ctrl-R: preset  p: platform  ?: about  q: quit",
    };
    Line::from(Span::styled(mode_hint, Style::default().fg(theme.hint_fg)))
}

/// Render a 14-char ATT&CK tactic heatmap bar from a slice of technique IDs.
pub fn render_heatmap(techniques: &[&str], theme: &Theme) -> Line<'static> {
    let mask = tactic_mask(techniques);
    let bar = render_bar(mask);
    let spans: Vec<Span<'static>> = bar
        .chars()
        .map(|c| {
            let color = if c == BLOCK_HIT {
                theme.heatmap_hit
            } else {
                theme.heatmap_miss
            };
            Span::styled(c.to_string(), Style::default().fg(color))
        })
        .collect();
    Line::from(spans)
}

/// Draw the full TUI frame.
///
/// `list_items` — pre-rendered display strings for the current filtered view.
/// `detail_lines` — pre-rendered lines for the detail pane.
pub fn draw(
    f: &mut Frame,
    app: &App,
    theme: &Theme,
    list_items: &[String],
    detail_lines: &[String],
) {
    let area = f.area();

    if app.mode == Mode::About {
        draw_about(f, theme, area);
        return;
    }

    // ── Outer layout: header (1) / body / hint (1) ──────────────────────
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let header_line = header_text(app, theme);
    f.render_widget(Paragraph::new(header_line), outer[0]);

    // ── Body: list pane / detail pane ────────────────────────────────────
    let constraints = pane_constraints(area.width);
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(outer[1]);

    draw_list_pane(f, app, theme, list_items, panes[0]);

    if app.detail_fullscreen {
        draw_detail_pane(f, app, theme, detail_lines, outer[1]);
    } else {
        draw_detail_pane(f, app, theme, detail_lines, panes[1]);
    }

    // ── Hint bar ─────────────────────────────────────────────────────────
    let hint_line = hint_text(app, theme);
    f.render_widget(Paragraph::new(hint_line), outer[2]);
}

fn draw_list_pane(f: &mut Frame, app: &App, theme: &Theme, items: &[String], area: Rect) {
    let border_style = if app.focus == Focus::List {
        Style::default().fg(theme.border_active)
    } else {
        Style::default().fg(theme.border_inactive)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(format!(" {} results ", items.len()));

    let list_items: Vec<ListItem> = items.iter().map(|s| ListItem::new(s.as_str())).collect();

    let list = List::new(list_items).block(block).highlight_style(
        Style::default()
            .fg(theme.selected_fg)
            .bg(theme.selected_bg)
            .add_modifier(Modifier::BOLD),
    );

    let mut state = ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_detail_pane(f: &mut Frame, app: &App, theme: &Theme, lines: &[String], area: Rect) {
    let border_style = if app.focus == Focus::Detail {
        Style::default().fg(theme.border_active)
    } else {
        Style::default().fg(theme.border_inactive)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" detail ");

    let text: Vec<Line> = lines
        .iter()
        .skip(app.detail_scroll.into())
        .map(|s| Line::from(s.as_str()))
        .collect();

    let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });

    f.render_widget(para, area);
}

fn draw_about(f: &mut Frame, theme: &Theme, area: Rect) {
    // Centre a 60×18 modal
    let modal_w = 60u16.min(area.width.saturating_sub(4));
    let modal_h = 21u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(modal_w)) / 2;
    let y = (area.height.saturating_sub(modal_h)) / 2;
    let modal_area = Rect::new(x, y, modal_w, modal_h);

    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border_active))
        .title(" about ");

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  forensicnomicon",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  version {VERSION}")),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("4n6h4x0r", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("  Security Ronin  "),
            Span::styled(
                "https://securityronin.com",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]),
        Line::from(""),
        Line::from("  DFIR artifact catalog + LOLBin navigator"),
        Line::from("  Offline. Zero I/O at runtime."),
        Line::from(""),
        Line::from("  Keybindings"),
        Line::from("  ──────────────────────────────────────"),
        Line::from("  /        search (filter-as-you-type)"),
        Line::from("  j/k ↑↓   navigate list"),
        Line::from("  Tab      toggle list / detail focus"),
        Line::from("  h/l ←→   move focus left / right"),
        Line::from("  Ctrl-R   cycle triage preset"),
        Line::from("  Alt-1…9  jump to Nth result"),
        Line::from("  p        cycle platform filter (Win/W10/W11/Mac/Lin)"),
        Line::from("  f        fullscreen detail pane"),
        Line::from("  q/Esc    quit / close modal"),
    ];

    let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, modal_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use crate::tui::theme::ALL_THEMES;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn terminal(w: u16, h: u16) -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(w, h)).unwrap()
    }

    fn default_theme() -> &'static Theme {
        ALL_THEMES[0]
    }

    // ── pane_constraints ─────────────────────────────────────────────────

    #[test]
    fn wide_terminal_uses_38_62_split() {
        let [a, b] = pane_constraints(120);
        assert!(matches!(a, Constraint::Percentage(38)));
        assert!(matches!(b, Constraint::Percentage(62)));
    }

    #[test]
    fn narrow_terminal_uses_50_50_split() {
        let [a, b] = pane_constraints(80);
        assert!(matches!(a, Constraint::Percentage(50)));
        assert!(matches!(b, Constraint::Percentage(50)));
    }

    #[test]
    fn exactly_100_cols_uses_38_62() {
        let [a, _] = pane_constraints(100);
        assert!(matches!(a, Constraint::Percentage(38)));
    }

    // ── header_text ───────────────────────────────────────────────────────

    #[test]
    fn header_contains_forensicnomicon() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("forensicnomicon"));
    }

    #[test]
    fn header_shows_search_query_when_in_search_mode() {
        let mut app = App::new();
        app.enter_search_mode();
        app.search_push('p');
        app.search_push('f');
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("pf"), "search query should appear in header");
    }

    #[test]
    fn header_shows_cursor_block_in_search_mode() {
        let mut app = App::new();
        app.enter_search_mode();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains('█'),
            "cursor block should appear in search mode"
        );
    }

    #[test]
    fn header_no_cursor_when_not_in_search_mode() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(!text.contains('█'));
    }

    // ── hint_text ─────────────────────────────────────────────────────────

    #[test]
    fn hint_shows_normal_mode_keys_by_default() {
        let app = App::new();
        let line = hint_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("search"),
            "normal mode hint should mention search"
        );
        assert!(
            text.contains("quit"),
            "normal mode hint should mention quit"
        );
    }

    #[test]
    fn hint_shows_search_mode_keys_in_search_mode() {
        let mut app = App::new();
        app.enter_search_mode();
        let line = hint_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Esc"), "search mode hint should mention Esc");
    }

    #[test]
    fn hint_shows_flash_message_when_active() {
        let mut app = App::new();
        app.flash("no matches — refine your query");
        let line = hint_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("no matches"),
            "flash message should appear in hint bar"
        );
    }

    // ── render_heatmap ────────────────────────────────────────────────────

    #[test]
    fn heatmap_always_14_spans() {
        let line = render_heatmap(&["T1059"], default_theme());
        assert_eq!(line.spans.len(), 14);
    }

    #[test]
    fn heatmap_empty_techniques_all_miss() {
        let line = render_heatmap(&[], default_theme());
        let all_miss = line
            .spans
            .iter()
            .all(|s| s.content == BLOCK_MISS.to_string());
        assert!(all_miss);
    }

    #[test]
    fn heatmap_t1059_sets_execution_span() {
        // T1059 → TA0002 Execution → index 3
        let line = render_heatmap(&["T1059"], default_theme());
        assert_eq!(line.spans[3].content, BLOCK_HIT.to_string());
        assert_eq!(line.spans[0].content, BLOCK_MISS.to_string());
    }

    // ── Platform filter header indicators ────────────────────────────────

    #[test]
    fn header_shows_win_when_windows_all_filter_active() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[Win]"), "header must show [Win]; got: {text}");
    }

    #[test]
    fn header_shows_w10_when_win10_filter_active() {
        use crate::tui::app::WinVersionFilter;
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        app.win_version = WinVersionFilter::Win10Plus;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[W10]"), "header must show [W10]; got: {text}");
        assert!(!text.contains("[Win]"), "must not show [Win] in W10 state; got: {text}");
    }

    #[test]
    fn header_shows_w11_when_win11_filter_active() {
        use crate::tui::app::WinVersionFilter;
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        app.win_version = WinVersionFilter::Win11Plus;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[W11]"), "header must show [W11]; got: {text}");
    }

    #[test]
    fn header_shows_mac_when_macos_filter_active() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::MacOS);
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[Mac]"), "header must show [Mac]; got: {text}");
    }

    #[test]
    fn header_no_platform_brackets_when_mask_empty() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !text.contains("[Win]") && !text.contains("[Mac]") && !text.contains("[Lin]"),
            "no platform brackets when mask is empty; got: {text}"
        );
    }

    // ── draw (TestBackend smoke tests) ────────────────────────────────────

    #[test]
    fn draw_does_not_panic_with_empty_lists() {
        let mut term = terminal(120, 30);
        let app = App::new();
        term.draw(|f| {
            draw(f, &app, default_theme(), &[], &[]);
        })
        .unwrap();
    }

    #[test]
    fn draw_does_not_panic_with_items() {
        let mut term = terminal(120, 30);
        let app = App::new();
        let items: Vec<String> = (0..10).map(|i| format!("artifact_{i}")).collect();
        let details: Vec<String> = vec!["detail line 1".into(), "detail line 2".into()];
        term.draw(|f| {
            draw(f, &app, default_theme(), &items, &details);
        })
        .unwrap();
    }

    #[test]
    fn draw_about_modal_does_not_panic() {
        let mut term = terminal(120, 30);
        let mut app = App::new();
        app.open_about();
        term.draw(|f| {
            draw(f, &app, default_theme(), &[], &[]);
        })
        .unwrap();
    }

    #[test]
    fn draw_narrow_terminal_does_not_panic() {
        let mut term = terminal(60, 20);
        let app = App::new();
        term.draw(|f| {
            draw(f, &app, default_theme(), &["item".to_string()], &[]);
        })
        .unwrap();
    }

    #[test]
    fn draw_very_small_terminal_does_not_panic() {
        let mut term = terminal(20, 5);
        let app = App::new();
        term.draw(|f| {
            draw(f, &app, default_theme(), &[], &[]);
        })
        .unwrap();
    }
}
