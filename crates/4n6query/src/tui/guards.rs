/// Guard conditions on keybindings.
///
/// Each guard returns `None` (passes) or `Some(&str)` (fails with a reason
/// that flashes in the hint bar for 1.5 s).
use crate::tui::app::{App, Focus, Mode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Blocked while in Search mode.
    NotInSearchMode,
    /// Blocked when the filtered result list is empty.
    HasResults,
    /// Blocked when the detail pane does not have focus.
    DetailFocused,
}

impl Guard {
    /// Returns `None` if the guard passes, or `Some(reason)` if it fails.
    pub fn check(self, app: &App, list_len: usize) -> Option<&'static str> {
        match self {
            Self::NotInSearchMode => {
                if app.mode == Mode::Search {
                    Some("finish search first (Esc), then switch dataset")
                } else {
                    None
                }
            }
            Self::HasResults => {
                if list_len == 0 {
                    Some("no matches — refine your query")
                } else {
                    None
                }
            }
            Self::DetailFocused => {
                if app.focus != Focus::Detail {
                    Some("not in detail pane — press Tab or l to switch")
                } else {
                    None
                }
            }
        }
    }
}

/// Evaluate a slice of guards. Returns the first failure reason, or `None`
/// if all pass.
pub fn evaluate(guards: &[Guard], app: &App, list_len: usize) -> Option<&'static str> {
    guards.iter().find_map(|g| g.check(app, list_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    fn normal_app() -> App {
        App::new()
    }

    fn search_app() -> App {
        let mut a = App::new();
        a.enter_search_mode();
        a
    }

    fn detail_app() -> App {
        let mut a = App::new();
        a.focus_detail();
        a
    }

    // ── NotInSearchMode ───────────────────────────────────────────────────

    #[test]
    fn not_in_search_mode_passes_in_normal_mode() {
        assert!(Guard::NotInSearchMode.check(&normal_app(), 10).is_none());
    }

    #[test]
    fn not_in_search_mode_fails_in_search_mode() {
        let reason = Guard::NotInSearchMode.check(&search_app(), 10);
        assert!(reason.is_some(), "should fail in search mode");
        assert!(reason.unwrap().contains("finish search"));
    }

    #[test]
    fn not_in_search_mode_passes_in_about_mode() {
        let mut a = App::new();
        a.open_about();
        // About mode is not Search mode — guard should pass
        assert!(Guard::NotInSearchMode.check(&a, 10).is_none());
    }

    // ── HasResults ────────────────────────────────────────────────────────

    #[test]
    fn has_results_passes_when_list_nonempty() {
        assert!(Guard::HasResults.check(&normal_app(), 5).is_none());
    }

    #[test]
    fn has_results_fails_when_list_empty() {
        let reason = Guard::HasResults.check(&normal_app(), 0);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("no matches"));
    }

    // ── DetailFocused ─────────────────────────────────────────────────────

    #[test]
    fn detail_focused_fails_when_list_has_focus() {
        let reason = Guard::DetailFocused.check(&normal_app(), 10);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("not in detail pane"));
    }

    #[test]
    fn detail_focused_passes_when_detail_has_focus() {
        assert!(Guard::DetailFocused.check(&detail_app(), 10).is_none());
    }

    // ── evaluate (multi-guard) ────────────────────────────────────────────

    #[test]
    fn evaluate_returns_none_when_all_guards_pass() {
        let guards = [Guard::HasResults];
        assert!(evaluate(&guards, &normal_app(), 5).is_none());
    }

    #[test]
    fn evaluate_returns_first_failure() {
        let guards = [Guard::HasResults, Guard::NotInSearchMode];
        // list empty → HasResults fails first
        let reason = evaluate(&guards, &normal_app(), 0);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("no matches"));
    }

    #[test]
    fn evaluate_empty_guards_always_passes() {
        assert!(evaluate(&[], &normal_app(), 0).is_none());
    }
}
