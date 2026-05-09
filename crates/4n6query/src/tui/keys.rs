/// Keybinding dispatch — maps crossterm KeyEvents → App mutations.
///
/// Every keybinding is checked against its guards before the action fires.
/// If a guard fails, a flash message is shown in the hint bar for 1.5 s.
///
/// # Design (lazygit pattern)
///
/// Disabled-reason messages live here, not in the UI. The UI just renders
/// `app.flash` if one is set. This keeps rendering pure and testable.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use forensicnomicon::catalog::Platform;

use crate::tui::app::{App, Focus, Mode};
use crate::tui::guards::{evaluate, Guard};

/// Page size for Ctrl-D / Ctrl-U.
const PAGE_SIZE: usize = 10;

/// Process a single key event and mutate `app` accordingly.
///
/// `list_len` is the number of filtered results currently visible — needed
/// to evaluate `Guard::HasResults` without coupling to the render state.
///
/// Returns `true` if the application should quit.
pub fn handle_key(app: &mut App, event: KeyEvent, list_len: usize) -> bool {
    // About modal eats all keys except close keys
    if app.mode == Mode::About {
        match event.code {
            KeyCode::Char('?') | KeyCode::F(1) | KeyCode::Esc | KeyCode::Char('q') => {
                app.close_about();
            }
            KeyCode::Char('j') | KeyCode::Down => app.scroll_detail_down(),
            KeyCode::Char('k') | KeyCode::Up => app.scroll_detail_up(),
            _ => {}
        }
        return false;
    }

    // Search mode intercepts printable keys for query building
    if app.mode == Mode::Search {
        match event.code {
            KeyCode::Esc => app.exit_search_clear(),
            KeyCode::Char(c) => app.search_push(c),
            KeyCode::Backspace => app.search_pop(),
            KeyCode::Enter => app.exit_search_keep(),
            KeyCode::Up => app.move_up(),
            KeyCode::Down => app.move_down(list_len),
            _ => {}
        }
        return false;
    }

    // Normal mode — full keybinding table
    match (event.code, event.modifiers) {
        // ── Quit ─────────────────────────────────────────────────────────
        (KeyCode::Char('q'), KeyModifiers::NONE) | (KeyCode::Char('Q'), KeyModifiers::NONE) => {
            return true
        }

        // ── About modal ───────────────────────────────────────────────────
        (KeyCode::Char('?'), KeyModifiers::NONE) | (KeyCode::F(1), KeyModifiers::NONE) => {
            app.open_about()
        }

        // ── Search ────────────────────────────────────────────────────────
        (KeyCode::Char('/'), KeyModifiers::NONE) => app.enter_search_mode(),

        // ── Navigation ────────────────────────────────────────────────────
        (KeyCode::Char('j'), KeyModifiers::NONE) | (KeyCode::Down, KeyModifiers::NONE) => {
            app.move_down(list_len)
        }
        (KeyCode::Char('k'), KeyModifiers::NONE) | (KeyCode::Up, KeyModifiers::NONE) => {
            app.move_up()
        }
        (KeyCode::Char('g'), KeyModifiers::NONE) | (KeyCode::Home, KeyModifiers::NONE) => {
            app.move_to_top()
        }
        (KeyCode::Char('G'), KeyModifiers::NONE) | (KeyCode::End, KeyModifiers::NONE) => {
            app.move_to_bottom(list_len)
        }
        (KeyCode::PageDown, KeyModifiers::NONE) | (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
            app.page_down(list_len, PAGE_SIZE)
        }
        (KeyCode::PageUp, KeyModifiers::NONE) | (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
            app.page_up(PAGE_SIZE)
        }

        // ── Detail pane scroll ────────────────────────────────────────────
        (KeyCode::Char('J'), KeyModifiers::NONE) => {
            if let Some(r) = evaluate(&[Guard::DetailFocused], app, list_len) {
                app.flash(r);
            } else {
                app.scroll_detail_down();
            }
        }
        (KeyCode::Char('K'), KeyModifiers::NONE) => {
            if let Some(r) = evaluate(&[Guard::DetailFocused], app, list_len) {
                app.flash(r);
            } else {
                app.scroll_detail_up();
            }
        }

        // ── Focus / fullscreen ────────────────────────────────────────────
        (KeyCode::Tab, KeyModifiers::NONE) => {
            if app.focus == Focus::List {
                app.focus_detail();
            } else {
                app.focus_list();
            }
        }
        (KeyCode::Char('l'), KeyModifiers::NONE) | (KeyCode::Right, KeyModifiers::NONE) => {
            app.focus_detail()
        }
        (KeyCode::Char('h'), KeyModifiers::NONE) | (KeyCode::Left, KeyModifiers::NONE) => {
            app.focus_list()
        }
        (KeyCode::Char('f'), KeyModifiers::NONE) => app.toggle_detail_fullscreen(),

        // ── Alt-1…Alt-9 Nth result jump ───────────────────────────────────
        (KeyCode::Char(c), KeyModifiers::ALT) if ('1'..='9').contains(&c) => {
            let n = (c as usize) - ('0' as usize);
            if let Some(r) = evaluate(&[Guard::HasResults], app, list_len) {
                app.flash(r);
            } else {
                app.alt_jump(n, list_len);
            }
        }

        // ── Platform filter (Alt-w/m/l) ───────────────────────────────────
        (KeyCode::Char('w'), KeyModifiers::ALT) => app.toggle_platform(Platform::Windows),
        (KeyCode::Char('m'), KeyModifiers::ALT) => app.toggle_platform(Platform::MacOS),
        (KeyCode::Char('l'), KeyModifiers::ALT) => app.toggle_platform(Platform::Linux),

        // ── Dataset cycle (d) ─────────────────────────────────────────────
        (KeyCode::Char('d'), KeyModifiers::NONE) => {
            if let Some(r) = evaluate(&[Guard::NotInSearchMode], app, list_len) {
                app.flash(r);
            } else {
                let next = (app.dataset_idx + 1) % App::DATASET_COUNT;
                app.switch_dataset(next);
            }
        }

        // ── Preset cycle (Ctrl-R) ─────────────────────────────────────────
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
            if let Some(r) = evaluate(&[Guard::NotInSearchMode], app, list_len) {
                app.flash(r);
            } else {
                app.cycle_preset();
            }
        }

        _ => {}
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    fn app() -> App {
        App::new()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn alt_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
    }

    fn ctrl_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    // ── Quit ──────────────────────────────────────────────────────────────

    #[test]
    fn q_returns_true() {
        let mut a = app();
        assert!(handle_key(&mut a, key(KeyCode::Char('q')), 10));
    }

    #[test]
    fn shift_q_returns_true() {
        let mut a = app();
        assert!(handle_key(&mut a, key(KeyCode::Char('Q')), 10));
    }

    #[test]
    fn other_key_returns_false() {
        let mut a = app();
        assert!(!handle_key(&mut a, key(KeyCode::Char('j')), 10));
    }

    // ── About modal ───────────────────────────────────────────────────────

    #[test]
    fn question_mark_opens_about() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Char('?')), 10);
        assert_eq!(a.mode, Mode::About);
    }

    #[test]
    fn f1_opens_about() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::F(1)), 10);
        assert_eq!(a.mode, Mode::About);
    }

    #[test]
    fn esc_closes_about() {
        let mut a = app();
        a.open_about();
        handle_key(&mut a, key(KeyCode::Esc), 10);
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn q_closes_about_without_quitting() {
        let mut a = app();
        a.open_about();
        let quit = handle_key(&mut a, key(KeyCode::Char('q')), 10);
        assert!(!quit, "q in about modal should close, not quit");
        assert_eq!(a.mode, Mode::Normal);
    }

    // ── Search ────────────────────────────────────────────────────────────

    #[test]
    fn slash_enters_search_mode() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Char('/')), 10);
        assert_eq!(a.mode, Mode::Search);
    }

    #[test]
    fn esc_exits_search_mode_and_clears_query() {
        let mut a = app();
        a.enter_search_mode();
        a.search_push('p');
        handle_key(&mut a, key(KeyCode::Esc), 10);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.search_query, "");
    }

    #[test]
    fn enter_exits_search_mode_keeping_query() {
        let mut a = app();
        a.enter_search_mode();
        a.search_push('p');
        handle_key(&mut a, key(KeyCode::Enter), 10);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.search_query, "p");
    }

    #[test]
    fn char_in_search_mode_appends_to_query() {
        let mut a = app();
        a.enter_search_mode();
        handle_key(&mut a, key(KeyCode::Char('p')), 10);
        handle_key(&mut a, key(KeyCode::Char('f')), 10);
        assert_eq!(a.search_query, "pf");
    }

    #[test]
    fn backspace_in_search_pops_char() {
        let mut a = app();
        a.enter_search_mode();
        a.search_push('p');
        a.search_push('f');
        handle_key(&mut a, key(KeyCode::Backspace), 10);
        assert_eq!(a.search_query, "p");
    }

    // ── Navigation ────────────────────────────────────────────────────────

    #[test]
    fn j_moves_down() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Char('j')), 10);
        assert_eq!(a.selected, 1);
    }

    #[test]
    fn k_at_top_stays_at_zero() {
        let mut a = app();
        a.selected = 0;
        handle_key(&mut a, key(KeyCode::Char('k')), 10);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn g_jumps_to_top() {
        let mut a = app();
        a.selected = 5;
        handle_key(&mut a, key(KeyCode::Char('g')), 10);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn capital_g_jumps_to_bottom() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Char('G')), 20);
        assert_eq!(a.selected, 19);
    }

    // ── Guard: Alt-jump on empty list ─────────────────────────────────────

    #[test]
    fn alt_jump_on_empty_list_flashes_reason() {
        let mut a = app();
        handle_key(&mut a, alt_key('3'), 0); // list_len = 0 → HasResults guard fails
        assert!(a.has_flash(), "should have flash message");
    }

    #[test]
    fn alt_jump_with_results_moves_selection() {
        let mut a = app();
        handle_key(&mut a, alt_key('3'), 10); // guard passes
        assert_eq!(a.selected, 2); // alt_jump(3, 10) → index 2
    }

    // ── Guard: dataset switch in search mode ──────────────────────────────

    #[test]
    fn dataset_switch_blocked_in_search_mode() {
        let mut a = app();
        a.enter_search_mode();
        let before_ds = a.dataset_idx;
        handle_key(&mut a, key(KeyCode::Char('d')), 10);
        // In search mode, 'd' would go through search path as char input
        // Actually in search mode, 'd' is handled as a char push, not dataset switch
        // The search mode path adds 'd' to query; dataset guard is only in normal mode
        assert_eq!(
            a.dataset_idx, before_ds,
            "dataset should not change in search mode"
        );
    }

    // ── Focus ─────────────────────────────────────────────────────────────

    #[test]
    fn tab_toggles_focus() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Tab), 10);
        assert_eq!(a.focus, Focus::Detail);
    }

    #[test]
    fn tab_toggles_focus_back() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Tab), 10);
        handle_key(&mut a, key(KeyCode::Tab), 10);
        assert_eq!(a.focus, Focus::List);
    }

    #[test]
    fn l_moves_focus_to_detail() {
        let mut a = app();
        handle_key(&mut a, key(KeyCode::Char('l')), 10);
        assert_eq!(a.focus, Focus::Detail);
    }

    #[test]
    fn h_moves_focus_to_list() {
        let mut a = app();
        a.focus_detail();
        handle_key(&mut a, key(KeyCode::Char('h')), 10);
        assert_eq!(a.focus, Focus::List);
    }

    // ── Preset cycle ──────────────────────────────────────────────────────

    #[test]
    fn ctrl_r_cycles_preset_in_normal_mode() {
        let mut a = app();
        handle_key(&mut a, ctrl_key('r'), 10);
        assert_eq!(a.preset_idx, 1);
    }

    #[test]
    fn ctrl_r_blocked_in_search_mode_by_guard() {
        let mut a = app();
        a.enter_search_mode();
        // Ctrl-R in search mode: 'r' is Char key with CONTROL modifier
        // The search mode handler only processes Char keys WITHOUT modifiers
        // So Ctrl-R falls through to no-op in search mode (not a handled key)
        // The preset does NOT change
        handle_key(&mut a, ctrl_key('r'), 10);
        assert_eq!(a.preset_idx, 0, "preset should not change in search mode");
    }

    // ── Platform filter (Alt-w/m/l) ───────────────────────────────────────

    #[test]
    fn alt_w_toggles_windows_platform() {
        use forensicnomicon::catalog::Platform;
        let mut a = app();
        handle_key(&mut a, alt_key('w'), 10);
        assert!(!a.platform_mask.is_empty(), "mask should be non-empty after toggle");
        assert!(a.platform_mask.matches(Platform::Windows));
        assert!(!a.platform_mask.matches(Platform::MacOS));
    }

    #[test]
    fn alt_m_toggles_macos_platform() {
        use forensicnomicon::catalog::Platform;
        let mut a = app();
        handle_key(&mut a, alt_key('m'), 10);
        assert!(!a.platform_mask.is_empty());
        assert!(a.platform_mask.matches(Platform::MacOS));
        assert!(!a.platform_mask.matches(Platform::Windows));
    }

    #[test]
    fn alt_l_toggles_linux_platform() {
        use forensicnomicon::catalog::Platform;
        let mut a = app();
        handle_key(&mut a, alt_key('l'), 10);
        assert!(!a.platform_mask.is_empty());
        assert!(a.platform_mask.matches(Platform::Linux));
    }

    #[test]
    fn alt_w_twice_clears_windows_filter() {
        let mut a = app();
        handle_key(&mut a, alt_key('w'), 10);
        handle_key(&mut a, alt_key('w'), 10);
        assert!(a.platform_mask.is_empty(), "second toggle should clear the filter");
    }

    #[test]
    fn alt_w_and_alt_m_produces_two_platform_filter() {
        use forensicnomicon::catalog::Platform;
        let mut a = app();
        handle_key(&mut a, alt_key('w'), 10);
        handle_key(&mut a, alt_key('m'), 10);
        assert!(a.platform_mask.matches(Platform::Windows));
        assert!(a.platform_mask.matches(Platform::MacOS));
        assert!(!a.platform_mask.matches(Platform::Linux));
    }
}
