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

/// Build the header line showing dataset + active filters + search query.
pub fn header_text<'a>(app: &'a App, theme: &'a Theme) -> Line<'a> {
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
    ];

    // Platform badge
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
            spans.push(Span::styled(label, Style::default().fg(theme.header_fg)));
        }
    }

    // Criticality badge
    if let Some(badge) = app.crit_filter.badge() {
        if !app.platform_mask.is_empty() {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(badge, Style::default().fg(theme.header_fg)));
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
        Mode::Normal => {
            " /: search  j/k: navigate  Tab: focus  p: platform  c: criticality  ?: about  q: quit"
        }
    };
    Line::from(Span::styled(mode_hint, Style::default().fg(theme.hint_fg)))
}

/// Build a styled `Line` for one list-item display string.
///
/// Applies priority colour to the whole row based on the `[Priority]` suffix
/// that `build_render_data` appends. When `query` is non-empty and a
/// case-insensitive substring match is found in the display string, wraps that
/// substring in a yellow-background highlight span.
pub fn styled_line_for_item<'a>(s: &'a str, query: &str, theme: &Theme) -> Line<'a> {
    let priority_style = if s.contains("[Critical]") {
        Style::default().fg(theme.crit_fg)
    } else if s.contains("[High]") {
        Style::default().fg(theme.high_fg)
    } else if s.contains("[Medium]") {
        Style::default().fg(theme.med_fg)
    } else if s.contains("[Low]") {
        Style::default().fg(theme.low_fg)
    } else {
        Style::default()
    };

    if query.is_empty() {
        return Line::from(Span::styled(s, priority_style));
    }

    let lower_s = s.to_ascii_lowercase();
    let lower_q = query.to_ascii_lowercase();
    let hl_style = Style::default().bg(Color::Yellow).fg(Color::Black);

    if let Some(pos) = lower_s.find(lower_q.as_str()) {
        let end = pos + lower_q.len();
        Line::from(vec![
            Span::styled(&s[..pos], priority_style),
            Span::styled(&s[pos..end], hl_style),
            Span::styled(&s[end..], priority_style),
        ])
    } else {
        Line::from(Span::styled(s, priority_style))
    }
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

    let list_items: Vec<ListItem> = items
        .iter()
        .map(|s| ListItem::new(styled_line_for_item(s, &app.search_query, theme)))
        .collect();

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
    let modal_h = 24u16.min(area.height.saturating_sub(4));
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
        Line::from("  p        cycle platform  (Win/W10/W11/Mac/Lin)"),
        Line::from("  c        cycle criticality  (Crit/High/Med/All)"),
        Line::from("  Alt-1…9  jump to Nth result"),
        Line::from("  f        fullscreen detail pane"),
        Line::from("  q/Esc    quit / close modal"),
        Line::from(""),
        Line::from("  Mouse"),
        Line::from("  scroll   navigate list"),
        Line::from("  click    select item  |  header: toggle filters"),
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
    use ratatui::style::Color;
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
        assert!(
            text.contains("[Win]"),
            "header must show [Win]; got: {text}"
        );
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
        assert!(
            text.contains("[W10]"),
            "header must show [W10]; got: {text}"
        );
        assert!(
            !text.contains("[Win]"),
            "must not show [Win] in W10 state; got: {text}"
        );
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
        assert!(
            text.contains("[W11]"),
            "header must show [W11]; got: {text}"
        );
    }

    #[test]
    fn header_shows_mac_when_macos_filter_active() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::MacOS);
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("[Mac]"),
            "header must show [Mac]; got: {text}"
        );
    }

    // ── CritFilter header badges ──────────────────────────────────────────

    #[test]
    fn header_shows_crit_badge_when_filter_critical() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::Critical;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[Crit]"), "header must show [Crit]; got: {text}");
    }

    #[test]
    fn header_shows_high_badge_when_filter_high() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::High;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[High]"), "header must show [High]; got: {text}");
    }

    #[test]
    fn header_shows_med_badge_when_filter_medium() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::Medium;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("[Med]"), "header must show [Med]; got: {text}");
    }

    #[test]
    fn header_no_crit_badge_when_filter_all() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !text.contains("[Crit]") && !text.contains("[High]") && !text.contains("[Med]"),
            "no crit badge when filter is All; got: {text}"
        );
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

    // ── header — no preset labels ─────────────────────────────────────────

    #[test]
    fn header_never_shows_preset_labels() {
        // Presets are gone; header must not contain preset-era text
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(!text.contains("Windows · CRIT"), "no preset label; got: {text}");
        assert!(!text.contains("Linux · CRIT"), "no preset label; got: {text}");
    }

    #[test]
    fn header_clean_when_no_filters_active() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        // No filter badges when everything is at default
        assert!(!text.contains("[Win]"), "no platform badge; got: {text}");
        assert!(!text.contains("[Crit]"), "no crit badge; got: {text}");
    }

    // ── styled_line_for_item ──────────────────────────────────────────────

    #[test]
    fn styled_line_critical_item_has_crit_fg() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "",
            theme,
        );
        let has_crit_fg = line.spans.iter().any(|s| s.style.fg == Some(theme.crit_fg));
        assert!(has_crit_fg, "critical item must apply crit_fg");
    }

    #[test]
    fn styled_line_high_item_has_high_fg() {
        let theme = default_theme();
        let line = styled_line_for_item("run_key_hklm                         [High]", "", theme);
        let has_high_fg = line.spans.iter().any(|s| s.style.fg == Some(theme.high_fg));
        assert!(has_high_fg, "high item must apply high_fg");
    }

    #[test]
    fn styled_line_medium_item_has_med_fg() {
        let theme = default_theme();
        let line = styled_line_for_item("some_artifact                        [Medium]", "", theme);
        let has_med_fg = line.spans.iter().any(|s| s.style.fg == Some(theme.med_fg));
        assert!(has_med_fg, "medium item must apply med_fg");
    }

    #[test]
    fn styled_line_low_item_has_low_fg() {
        let theme = default_theme();
        let line = styled_line_for_item("some_artifact                        [Low]", "", theme);
        let has_low_fg = line.spans.iter().any(|s| s.style.fg == Some(theme.low_fg));
        assert!(has_low_fg, "low item must apply low_fg");
    }

    #[test]
    fn styled_line_plain_item_has_no_priority_fg() {
        let theme = default_theme();
        let line = styled_line_for_item("some_plain_item", "", theme);
        let has_priority_fg = line.spans.iter().any(|s| {
            matches!(
                s.style.fg,
                Some(c) if c == theme.crit_fg || c == theme.high_fg
                        || c == theme.med_fg  || c == theme.low_fg
            )
        });
        assert!(!has_priority_fg, "plain item must not have priority fg");
    }

    #[test]
    fn styled_line_highlights_query_match_with_yellow_bg() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "prefetch",
            theme,
        );
        let has_yellow_bg = line.spans.iter().any(|s| s.style.bg == Some(Color::Yellow));
        assert!(has_yellow_bg, "matching query must produce yellow-bg highlight span");
    }

    #[test]
    fn styled_line_highlighted_span_text_equals_query() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "prefetch",
            theme,
        );
        let hl = line
            .spans
            .iter()
            .find(|s| s.style.bg == Some(Color::Yellow));
        assert!(hl.is_some(), "must have a highlighted span");
        assert_eq!(
            hl.unwrap().content.as_ref(),
            "prefetch",
            "highlighted span must contain the query text"
        );
    }

    #[test]
    fn styled_line_no_highlight_when_query_empty() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "",
            theme,
        );
        let has_yellow_bg = line.spans.iter().any(|s| s.style.bg == Some(Color::Yellow));
        assert!(!has_yellow_bg, "no yellow bg when query is empty");
    }

    #[test]
    fn styled_line_no_highlight_when_query_not_in_display() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "some_artifact                        [Critical]",
            "lateral",
            theme,
        );
        let has_yellow_bg = line.spans.iter().any(|s| s.style.bg == Some(Color::Yellow));
        assert!(!has_yellow_bg, "no yellow bg when query not in display string");
    }

    #[test]
    fn styled_line_highlight_is_case_insensitive() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "PREFETCH",
            theme,
        );
        let has_yellow_bg = line.spans.iter().any(|s| s.style.bg == Some(Color::Yellow));
        assert!(has_yellow_bg, "highlight must be case-insensitive");
    }
}
