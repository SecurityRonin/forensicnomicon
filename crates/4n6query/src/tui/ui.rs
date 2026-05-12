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

use crate::tui::app::{App, CritFilter, Focus, Mode, WinVersionFilter};
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
        Span::styled(
            format!("Type: {dataset_label}"),
            Style::default().fg(theme.dataset_fg),
        ),
        Span::raw(" │ "),
    ];

    // Platform badge
    if !app.platform_mask.is_empty() {
        let label = if app.platform_mask.contains(Platform::Windows) {
            match app.win_version {
                WinVersionFilter::All => "[Platform: Win]",
                WinVersionFilter::Win10Plus => "[Platform: W10]",
                WinVersionFilter::Win11Plus => "[Platform: W11]",
            }
        } else if app.platform_mask.contains(Platform::MacOS) {
            "[Platform: Mac]"
        } else if app.platform_mask.contains(Platform::Linux) {
            "[Platform: Lin]"
        } else {
            ""
        };
        if !label.is_empty() {
            spans.push(Span::styled(label, Style::default().fg(theme.dataset_fg)));
        }
    }

    // Severity badge with semantic color
    let (sev_label, sev_style) = match app.crit_filter {
        CritFilter::All => ("", None),
        CritFilter::Critical => ("[Severity: Crit]", Some(Style::default().fg(theme.crit_fg))),
        CritFilter::High => ("[Severity: High]", Some(Style::default().fg(theme.high_fg))),
        CritFilter::Medium => ("[Severity: Med]", Some(Style::default().fg(theme.med_fg))),
    };
    if let Some(style) = sev_style {
        if !app.platform_mask.is_empty() {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(sev_label, style));
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

    match app.mode {
        Mode::Search => Line::from(Span::styled(
            " Esc: finish  ↑↓: navigate  Enter: confirm",
            Style::default().fg(theme.hint_fg),
        )),
        Mode::About => Line::from(Span::styled(
            " Esc/q: close  ↑↓/jk: scroll",
            Style::default().fg(theme.hint_fg),
        )),
        Mode::Normal => Line::from(vec![
            Span::styled(
                " /: search  j/k: navigate  Tab: focus  f: fullscreen  ?: about  q: quit",
                Style::default().fg(theme.hint_fg),
            ),
            Span::styled("  │  ", Style::default().fg(theme.border_inactive)),
            Span::styled(
                "t: type  p: platform  s: severity",
                Style::default().fg(theme.header_fg),
            ),
        ]),
    }
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
    let hl_style = Style::default().bg(theme.match_hl).fg(Color::Black);

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

/// Returns the position of the label-ending `:` in a label-value line.
///
/// Returns `None` for separators, section headers, indented lines, or URLs.
fn label_colon_pos(s: &str) -> Option<usize> {
    if s.starts_with(' ') {
        return None;
    }
    let pos = s.find(':')?;
    let after = s.get(pos + 1..)?;
    // `: ` (space after colon) → label-value; `://` → URL; `` (end) → header
    if after.starts_with(' ') || after.starts_with('\t') {
        Some(pos)
    } else {
        None
    }
}

/// Split highlight-overlay over already-styled spans (owned, for lifetime freedom).
fn apply_search_highlight(spans: Vec<Span<'static>>, query: &str, hl: Style) -> Vec<Span<'static>> {
    if query.is_empty() {
        return spans;
    }
    let lower_q = query.to_ascii_lowercase();
    let mut result = Vec::new();
    for span in spans {
        let text = span.content.into_owned();
        let lower_t = text.to_ascii_lowercase();
        let base = span.style;
        if let Some(pos) = lower_t.find(lower_q.as_str()) {
            let end = pos + lower_q.len();
            if pos > 0 {
                result.push(Span::styled(text[..pos].to_string(), base));
            }
            result.push(Span::styled(text[pos..end].to_string(), hl));
            if end < text.len() {
                result.push(Span::styled(text[end..].to_string(), base));
            }
        } else {
            result.push(Span::styled(text, base));
        }
    }
    result
}

/// Semantic colorization for a single detail-pane line.
///
/// Pre-attentive hierarchy: red = critical, gold = high, cyan = reference/MITRE,
/// bold = scannable header, dim = scaffolding. Search query overlaid on top.
fn colorize_detail_line(s: &str, query: &str, theme: &Theme) -> Line<'static> {
    let dim = Style::default().fg(theme.hint_fg);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let crit = Style::default().fg(theme.crit_fg);
    let high = Style::default().fg(theme.high_fg);
    let med = Style::default().fg(theme.med_fg);
    let low = Style::default().fg(theme.low_fg);
    let url_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::UNDERLINED);

    let spans: Vec<Span<'static>> = if !s.is_empty() && s.chars().all(|c| c == '─') {
        vec![Span::styled(s.to_string(), dim)]
    } else if !s.starts_with(' ') && s.ends_with(':') && !s.contains("://") {
        // Section headers: "Fields:", "Sources:", "Use cases:", "Steps:"
        vec![Span::styled(s.to_string(), bold)]
    } else if s.starts_with("     ") {
        // Deep-indented rationale text (5+ spaces) → dim
        vec![Span::styled(s.to_string(), dim)]
    } else if let Some(colon) = label_colon_pos(s) {
        // Label: value — dim the label, semantically color the value
        let label_end = colon + 1;
        let rest = &s[label_end..];
        let spacer = rest.len() - rest.trim_start().len();
        let value_start = label_end + spacer;
        let label_part = s[..value_start].to_string();
        let value = &s[value_start..];

        let mut sp: Vec<Span<'static>> = vec![Span::styled(label_part, dim)];

        if s.starts_with("MITRE") {
            for (i, id) in value.split_whitespace().enumerate() {
                if i > 0 {
                    sp.push(Span::raw("  "));
                }
                sp.push(Span::styled(id.to_string(), med));
            }
        } else if s.starts_with("Use cases") || s.starts_with("Abuse") {
            for (i, tag) in value.split_whitespace().enumerate() {
                if i > 0 {
                    sp.push(Span::raw("  "));
                }
                sp.push(Span::styled(tag.to_string(), high));
            }
        } else {
            let val_style = match value.trim() {
                "Critical" => crit,
                "High" => high,
                "Medium" => med,
                "Low" => low,
                v if v.starts_with("https://") || v.starts_with("http://") => url_style,
                _ => Style::default(),
            };
            sp.push(Span::styled(value.to_string(), val_style));
        }
        sp
    } else if s.starts_with("  ") && s.contains(" — ") {
        // Indented field / step entry: "  name  — description"
        let arrow = " — ";
        if let Some(pos) = s.find(arrow) {
            vec![
                Span::styled(s[..pos].to_string(), bold),
                Span::styled(arrow.to_string(), dim),
                Span::raw(s[pos + arrow.len()..].to_string()),
            ]
        } else {
            vec![Span::raw(s.to_string())]
        }
    } else {
        vec![Span::raw(s.to_string())]
    };

    let hl = Style::default().bg(theme.match_hl).fg(Color::Black);
    Line::from(apply_search_highlight(spans, query, hl))
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

    if app.detail_fullscreen {
        f.render_widget(Clear, outer[1]);
        draw_detail_pane(f, app, theme, detail_lines, outer[1]);
    } else {
        draw_list_pane(f, app, theme, list_items, panes[0]);
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
        .map(|s| colorize_detail_line(s, &app.search_query, theme))
        .collect();

    let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });

    f.render_widget(para, area);
}

fn draw_about(f: &mut Frame, theme: &Theme, area: Rect) {
    let modal_w = 64u16.min(area.width.saturating_sub(4));
    let modal_h = 52u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(modal_w)) / 2;
    let y = (area.height.saturating_sub(modal_h)) / 2;
    let modal_area = Rect::new(x, y, modal_w, modal_h);

    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border_active))
        .title(" about / legend ");

    let hdr = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let cyan = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::UNDERLINED);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled("  forensicnomicon", hdr)),
        Line::from(format!("  version {VERSION}")),
        Line::from(""),
        Line::from("  DFIR artifact catalog + LOLBin navigator"),
        Line::from("  Offline. Zero I/O at runtime."),
        Line::from(""),
        Line::from(Span::styled("  Keybindings", hdr)),
        Line::from(Span::styled(
            "  ──────────────────────────────────────────",
            dim,
        )),
        Line::from("  /        search (filter-as-you-type)"),
        Line::from("  j/k ↑↓   navigate list"),
        Line::from("  Tab      toggle list / detail focus"),
        Line::from("  h/l ←→   move focus left / right"),
        Line::from("  t        cycle type  (catalog/lolbas/sites/…)"),
        Line::from("  p        cycle platform  (Win/W10/W11/Mac/Lin)"),
        Line::from("  s        cycle severity  (Crit/High/Med/All)"),
        Line::from("  f        fullscreen detail pane"),
        Line::from("  q/Esc    quit / close modal"),
        Line::from(""),
        Line::from(Span::styled("  Mouse", hdr)),
        Line::from(Span::styled(
            "  ──────────────────────────────────────────",
            dim,
        )),
        Line::from("  scroll   navigate list"),
        Line::from("  click    select item  |  header: toggle filters"),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("4n6h4x0r", hdr),
            Span::raw(" @ Security Ronin  "),
            Span::styled("https://securityronin.com", cyan),
        ]),
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
    fn hint_normal_mode_has_separator_before_filter_keys() {
        let app = App::new();
        let line = hint_text(&app, default_theme());
        let spans_text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            spans_text.contains('│'),
            "hint bar must have │ separator between nav and filter keys; got: {spans_text}"
        );
        let sep_pos = spans_text.find('│').unwrap();
        let t_pos = spans_text.find("t:").unwrap();
        assert!(
            sep_pos < t_pos,
            "│ must appear before t: filter key; got: {spans_text}"
        );
    }

    #[test]
    fn hint_filter_keys_use_distinct_style_from_nav_keys() {
        let app = App::new();
        let theme = default_theme();
        let line = hint_text(&app, theme);
        let distinct: std::collections::HashSet<_> =
            line.spans.iter().map(|s| s.style.fg).collect();
        assert!(
            distinct.len() >= 2,
            "hint bar must use ≥2 distinct fg styles to visually separate filter keys"
        );
    }

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
            text.contains("[Platform: Win]"),
            "header must show [Platform: Win]; got: {text}"
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
            text.contains("[Platform: W10]"),
            "header must show [Platform: W10]; got: {text}"
        );
        assert!(
            !text.contains("[Platform: W11]"),
            "must not show [Platform: W11] in W10 state; got: {text}"
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
            text.contains("[Platform: W11]"),
            "header must show [Platform: W11]; got: {text}"
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
            text.contains("[Platform: Mac]"),
            "header must show [Platform: Mac]; got: {text}"
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
        assert!(
            text.contains("[Severity: Crit]"),
            "header must show [Severity: Crit]; got: {text}"
        );
    }

    #[test]
    fn header_shows_high_badge_when_filter_high() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::High;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("[Severity: High]"),
            "header must show [Severity: High]; got: {text}"
        );
    }

    #[test]
    fn header_shows_med_badge_when_filter_medium() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::Medium;
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("[Severity: Med]"),
            "header must show [Severity: Med]; got: {text}"
        );
    }

    #[test]
    fn header_no_crit_badge_when_filter_all() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !text.contains("[Severity:"),
            "no severity badge when filter is All; got: {text}"
        );
    }

    #[test]
    fn header_no_platform_brackets_when_mask_empty() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !text.contains("[Platform:"),
            "no platform badge when mask is empty; got: {text}"
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
        assert!(
            !text.contains("Windows · CRIT"),
            "no preset label; got: {text}"
        );
        assert!(
            !text.contains("Linux · CRIT"),
            "no preset label; got: {text}"
        );
    }

    #[test]
    fn header_clean_when_no_filters_active() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        // No filter badges when everything is at default
        assert!(
            !text.contains("[Platform:"),
            "no platform badge; got: {text}"
        );
        assert!(
            !text.contains("[Severity:"),
            "no severity badge; got: {text}"
        );
    }

    // ── styled_line_for_item ──────────────────────────────────────────────

    #[test]
    fn styled_line_critical_item_has_crit_fg() {
        let theme = default_theme();
        let line =
            styled_line_for_item("prefetch_file                        [Critical]", "", theme);
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
    fn styled_line_highlights_query_match_with_theme_hl_bg() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "prefetch",
            theme,
        );
        let has_hl_bg = line
            .spans
            .iter()
            .any(|s| s.style.bg == Some(theme.match_hl));
        assert!(
            has_hl_bg,
            "matching query must produce theme.match_hl highlight span"
        );
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
            .find(|s| s.style.bg == Some(theme.match_hl));
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
        let line =
            styled_line_for_item("prefetch_file                        [Critical]", "", theme);
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
        assert!(
            !has_yellow_bg,
            "no yellow bg when query not in display string"
        );
    }

    #[test]
    fn styled_line_highlight_is_case_insensitive() {
        let theme = default_theme();
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "PREFETCH",
            theme,
        );
        let has_match_hl_bg = line
            .spans
            .iter()
            .any(|s| s.style.bg == Some(theme.match_hl));
        assert!(has_match_hl_bg, "highlight must be case-insensitive");
    }

    // ── hint bar ──────────────────────────────────────────────────────────

    #[test]
    fn hint_bar_shows_t_key_for_type() {
        let app = App::new();
        let line = hint_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("t:"),
            "hint bar must advertise t key; got: {text}"
        );
    }

    // ── colorize_detail_line ──────────────────────────────────────────────

    #[test]
    fn colorize_separator_is_dim() {
        let theme = default_theme();
        let line = colorize_detail_line("────────────────────────────────────────", "", theme);
        let fg = line.spans[0].style.fg;
        assert_eq!(fg, Some(theme.hint_fg), "separator must use hint_fg (dim)");
    }

    #[test]
    fn colorize_section_header_is_bold() {
        let theme = default_theme();
        let line = colorize_detail_line("Fields:", "", theme);
        let is_bold = line.spans[0].style.add_modifier.contains(Modifier::BOLD);
        assert!(is_bold, "section header 'Fields:' must be bold");
    }

    #[test]
    fn colorize_critical_value_has_crit_color() {
        let theme = default_theme();
        let line = colorize_detail_line("Priority: Critical", "", theme);
        let val_span = line.spans.iter().find(|s| s.content.contains("Critical"));
        assert_eq!(
            val_span.and_then(|s| s.style.fg),
            Some(theme.crit_fg),
            "Priority: Critical must use crit_fg"
        );
    }

    #[test]
    fn colorize_mitre_ids_have_accent_color() {
        let theme = default_theme();
        let line = colorize_detail_line("MITRE: T1218.004  T1059", "", theme);
        let mitre_span = line.spans.iter().find(|s| s.content.contains("T1218"));
        assert_eq!(
            mitre_span.and_then(|s| s.style.fg),
            Some(theme.med_fg),
            "MITRE IDs must use med_fg (accent)"
        );
    }

    #[test]
    fn colorize_search_match_highlighted_in_detail() {
        let theme = default_theme();
        let line = colorize_detail_line("Priority: Critical", "crit", theme);
        let hl = line
            .spans
            .iter()
            .find(|s| s.content.to_ascii_lowercase().contains("crit") && s.style.bg.is_some());
        assert!(
            hl.is_some(),
            "query 'crit' must be highlighted in detail line"
        );
    }

    #[test]
    fn colorize_field_entry_name_is_bold() {
        let theme = default_theme();
        let line = colorize_detail_line("  run_count  — number of executions", "", theme);
        let name_span = line.spans.iter().find(|s| s.content.contains("run_count"));
        assert!(
            name_span.map(|s| s.style.add_modifier.contains(Modifier::BOLD)) == Some(true),
            "field entry name must be bold"
        );
    }

    #[test]
    fn styled_line_uses_theme_match_hl_not_hardcoded_yellow() {
        use crate::tui::theme::THEME_ONE_DARK;
        let line = styled_line_for_item(
            "prefetch_file                        [Critical]",
            "prefetch",
            &THEME_ONE_DARK,
        );
        let hl_span = line.spans.iter().find(|s| s.style.bg.is_some());
        assert_eq!(
            hl_span.and_then(|s| s.style.bg),
            Some(THEME_ONE_DARK.match_hl),
            "highlight bg must be theme.match_hl, not hardcoded Color::Yellow"
        );
    }

    // ── header — Type prefix and severity coloring ────────────────────────

    #[test]
    fn header_shows_type_prefix_before_dataset_label() {
        let app = App::new();
        let line = header_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("Type: catalog"),
            "header must show 'Type: catalog'; got: {text}"
        );
    }

    #[test]
    fn header_platform_badge_uses_dataset_fg_color() {
        use forensicnomicon::catalog::{Platform, PlatformMask};
        let mut app = App::new();
        app.platform_mask = PlatformMask::NONE.with(Platform::Windows);
        let theme = default_theme();
        let line = header_text(&app, theme);
        let badge_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Platform: Win"));
        assert_eq!(
            badge_span.and_then(|s| s.style.fg),
            Some(theme.dataset_fg),
            "[Platform: Win] badge must use dataset_fg (same as type label)"
        );
    }

    #[test]
    fn header_crit_badge_uses_crit_fg_color() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::Critical;
        let theme = default_theme();
        let line = header_text(&app, theme);
        let sev_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Severity: Crit"));
        assert_eq!(
            sev_span.and_then(|s| s.style.fg),
            Some(theme.crit_fg),
            "Critical severity badge must use crit_fg"
        );
    }

    #[test]
    fn header_high_badge_uses_high_fg_color() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::High;
        let theme = default_theme();
        let line = header_text(&app, theme);
        let sev_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Severity: High"));
        assert_eq!(
            sev_span.and_then(|s| s.style.fg),
            Some(theme.high_fg),
            "High severity badge must use high_fg"
        );
    }

    #[test]
    fn header_med_badge_uses_med_fg_color() {
        use crate::tui::app::CritFilter;
        let mut app = App::new();
        app.crit_filter = CritFilter::Medium;
        let theme = default_theme();
        let line = header_text(&app, theme);
        let sev_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Severity: Med"));
        assert_eq!(
            sev_span.and_then(|s| s.style.fg),
            Some(theme.med_fg),
            "Med severity badge must use med_fg"
        );
    }

    #[test]
    fn hint_bar_shows_s_key_for_severity() {
        let app = App::new();
        let line = hint_text(&app, default_theme());
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("s:"),
            "hint bar must advertise s key for severity; got: {text}"
        );
    }

    // ── fullscreen clears list area ───────────────────────────────────────

    #[test]
    fn fullscreen_does_not_show_list_content() {
        // Use many list items but only 1 detail line so rows below the detail
        // content would show list text if the Paragraph doesn't fill trailing rows.
        let mut term = terminal(120, 30);
        let mut app = App::new();
        let items: Vec<String> = (0..25)
            .map(|i| format!("xyzzy_item_{i:02} [Critical]"))
            .collect();
        let details = vec!["detail only line".to_string()];

        // Frame 1: normal render (list + detail side-by-side)
        term.draw(|f| draw(f, &app, default_theme(), &items, &details))
            .unwrap();

        // Frame 2: fullscreen — list content must not bleed through
        app.toggle_detail_fullscreen();
        term.draw(|f| draw(f, &app, default_theme(), &items, &details))
            .unwrap();

        let buf = term.backend().buffer().clone();
        let rendered: String = (0..buf.area.height)
            .flat_map(|row| (0..buf.area.width).map(move |col| (col, row)))
            .map(|(col, row)| buf.cell((col, row)).unwrap().symbol().to_string())
            .collect();
        assert!(
            !rendered.contains("xyzzy_item"),
            "fullscreen must clear list area; list text still visible:\n{rendered}"
        );
    }

    // ── about dialog attribution ──────────────────────────────────────────

    fn about_lines() -> Vec<String> {
        // Render the about modal and collect all span text per line.
        // We drive draw_about directly by inspecting the paragraph content
        // through the public draw fn with about mode open.
        use ratatui::{backend::TestBackend, Terminal};
        let backend = TestBackend::new(80, 40);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_about();
        term.draw(|f| draw(f, &app, default_theme(), &[], &[]))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut lines: Vec<String> = Vec::new();
        for row in 0..buf.area.height {
            let mut s = String::new();
            for col in 0..buf.area.width {
                s.push(
                    buf.cell((col, row))
                        .unwrap()
                        .symbol()
                        .chars()
                        .next()
                        .unwrap_or(' '),
                );
            }
            lines.push(s.trim_end().to_string());
        }
        lines
    }

    #[test]
    fn about_attribution_uses_at_separator() {
        let lines = about_lines();
        let joined = lines.join("\n");
        assert!(
            joined.contains("4n6h4x0r @ Security Ronin"),
            "attribution must use '@' separator; got:\n{joined}"
        );
    }

    #[test]
    fn about_attribution_is_near_bottom() {
        let lines = about_lines();
        let attr_row = lines
            .iter()
            .position(|l| l.contains("4n6h4x0r @ Security Ronin"))
            .expect("attribution line not found");
        let mouse_row = lines
            .iter()
            .position(|l| l.contains("Mouse"))
            .expect("Mouse section not found");
        assert!(
            attr_row > mouse_row,
            "attribution (row {attr_row}) must appear after Mouse section (row {mouse_row})"
        );
    }
}
