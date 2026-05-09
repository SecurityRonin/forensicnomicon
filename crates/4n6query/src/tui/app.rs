/// App state machine for the TUI navigator.
///
/// All fields are public within the crate so `ui.rs` can read them
/// without getters. All mutations go through the methods below so
/// state transitions stay testable.
use forensicnomicon::catalog::{Platform, PlatformMask};
use std::time::Instant;

/// Windows version sub-filter — active only when `platform_mask` contains Windows.
///
/// Alt-w cycles: off → [`All`] → [`Win10Plus`] → [`Win11Plus`] → off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinVersionFilter {
    /// All Windows versions (XP / 7 / 8 / 10 / 11).
    All,
    /// Windows 10 and later only.
    Win10Plus,
    /// Windows 11 and later only.
    Win11Plus,
}

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Detail,
}

/// Input / interaction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    About,
}

/// Flash message shown in the hint bar (replaces static key map briefly).
#[derive(Debug, Clone)]
pub struct Flash {
    pub text: String,
    pub born: Instant,
    /// How many milliseconds the flash is visible.
    pub duration_ms: u64,
}

impl Flash {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            born: Instant::now(),
            duration_ms: 1500,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.born.elapsed().as_millis() as u64 >= self.duration_ms
    }
}

/// Central application state. Pure: no I/O, no terminal interaction.
pub struct App {
    pub mode: Mode,
    pub focus: Focus,
    /// Zero-based index into the *filtered* result list.
    pub selected: usize,
    /// Scroll offset for the detail pane.
    pub detail_scroll: u16,
    /// Current search query (empty = no filter).
    pub search_query: String,
    /// Whether the detail pane is expanded to full-screen.
    pub detail_fullscreen: bool,
    /// Flash message in the hint bar, if any.
    pub flash: Option<Flash>,
    /// Active dataset index (0-based, maps to Dataset variants).
    pub dataset_idx: usize,
    /// Active triage preset index (cycles via Ctrl-R).
    pub preset_idx: usize,
    /// Active platform filter bitmask (0 = all platforms shown).
    pub platform_mask: PlatformMask,
    /// Windows version sub-filter — only meaningful when `platform_mask` contains Windows.
    pub win_version: WinVersionFilter,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            mode: Mode::Normal,
            focus: Focus::List,
            selected: 0,
            detail_scroll: 0,
            search_query: String::new(),
            detail_fullscreen: false,
            flash: None,
            dataset_idx: 0,
            preset_idx: 0,
            platform_mask: PlatformMask::NONE,
            win_version: WinVersionFilter::All,
        }
    }

    /// Advance the platform filter one step forward.
    ///
    /// Cycle: off → [Win] → [W10] → [W11] → [Mac] → [Lin] → off.
    /// Only one platform is active at a time (no multi-select).
    pub fn cycle_platform_filter(&mut self) {
        if self.platform_mask.is_empty() {
            self.platform_mask = self.platform_mask.with(Platform::Windows);
            self.win_version = WinVersionFilter::All;
        } else if self.platform_mask.contains(Platform::Windows) {
            match self.win_version {
                WinVersionFilter::All => self.win_version = WinVersionFilter::Win10Plus,
                WinVersionFilter::Win10Plus => self.win_version = WinVersionFilter::Win11Plus,
                WinVersionFilter::Win11Plus => {
                    self.platform_mask = PlatformMask::NONE.with(Platform::MacOS);
                    self.win_version = WinVersionFilter::All;
                }
            }
        } else if self.platform_mask.contains(Platform::MacOS) {
            self.platform_mask = PlatformMask::NONE.with(Platform::Linux);
        } else {
            self.platform_mask = PlatformMask::NONE;
            self.win_version = WinVersionFilter::All;
        }
        self.selected = 0;
        self.detail_scroll = 0;
    }

    // ── Navigation ────────────────────────────────────────────────────────

    pub fn move_down(&mut self, list_len: usize) {
        if list_len == 0 {
            return;
        }
        if self.selected + 1 < list_len {
            self.selected += 1;
            self.detail_scroll = 0;
        }
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.detail_scroll = 0;
        }
    }

    pub fn move_to_top(&mut self) {
        self.selected = 0;
        self.detail_scroll = 0;
    }

    pub fn move_to_bottom(&mut self, list_len: usize) {
        if list_len > 0 {
            self.selected = list_len - 1;
            self.detail_scroll = 0;
        }
    }

    pub fn page_down(&mut self, list_len: usize, page: usize) {
        if list_len == 0 {
            return;
        }
        self.selected = (self.selected + page).min(list_len - 1);
        self.detail_scroll = 0;
    }

    pub fn page_up(&mut self, page: usize) {
        self.selected = self.selected.saturating_sub(page);
        self.detail_scroll = 0;
    }

    pub fn scroll_detail_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    pub fn scroll_detail_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    // ── Focus ─────────────────────────────────────────────────────────────

    pub fn focus_detail(&mut self) {
        self.focus = Focus::Detail;
    }

    pub fn focus_list(&mut self) {
        self.focus = Focus::List;
        self.detail_scroll = 0;
    }

    pub fn toggle_detail_fullscreen(&mut self) {
        self.detail_fullscreen = !self.detail_fullscreen;
    }

    // ── Search ────────────────────────────────────────────────────────────

    pub fn enter_search_mode(&mut self) {
        self.mode = Mode::Search;
    }

    /// Exit search mode, keeping the current query as an active filter.
    pub fn exit_search_keep(&mut self) {
        self.mode = Mode::Normal;
    }

    /// Exit search mode and clear the query.
    pub fn exit_search_clear(&mut self) {
        self.mode = Mode::Normal;
        self.search_query.clear();
        self.selected = 0;
        self.detail_scroll = 0;
    }

    pub fn search_push(&mut self, ch: char) {
        self.search_query.push(ch);
        self.selected = 0;
    }

    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.selected = 0;
    }

    pub fn has_search(&self) -> bool {
        !self.search_query.is_empty()
    }

    // ── Dataset ───────────────────────────────────────────────────────────

    pub const DATASET_COUNT: usize = 9;

    pub fn switch_dataset(&mut self, idx: usize) {
        if idx < Self::DATASET_COUNT {
            self.dataset_idx = idx;
            self.selected = 0;
            self.detail_scroll = 0;
        }
    }

    // ── Preset ────────────────────────────────────────────────────────────

    pub const PRESET_COUNT: usize = 5;

    pub fn cycle_preset(&mut self) {
        self.preset_idx = (self.preset_idx + 1) % Self::PRESET_COUNT;
        self.selected = 0;
        self.detail_scroll = 0;
    }

    // ── Alt-N jump ────────────────────────────────────────────────────────

    /// Jump to the Nth result (1-based). Clamps to last result.
    pub fn alt_jump(&mut self, n: usize, list_len: usize) {
        if list_len == 0 {
            return;
        }
        self.selected = (n - 1).min(list_len - 1);
        self.detail_scroll = 0;
    }

    // ── Flash ─────────────────────────────────────────────────────────────

    pub fn flash(&mut self, msg: impl Into<String>) {
        self.flash = Some(Flash::new(msg));
    }

    pub fn tick_flash(&mut self) {
        if let Some(f) = &self.flash {
            if f.is_expired() {
                self.flash = None;
            }
        }
    }

    pub fn has_flash(&self) -> bool {
        self.flash.is_some()
    }

    // ── About modal ───────────────────────────────────────────────────────

    pub fn open_about(&mut self) {
        self.mode = Mode::About;
    }

    pub fn close_about(&mut self) {
        self.mode = Mode::Normal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new()
    }

    // ── Initial state ─────────────────────────────────────────────────────

    #[test]
    fn new_app_starts_in_normal_mode() {
        assert_eq!(app().mode, Mode::Normal);
    }

    #[test]
    fn new_app_focus_is_list() {
        assert_eq!(app().focus, Focus::List);
    }

    #[test]
    fn new_app_selected_is_zero() {
        assert_eq!(app().selected, 0);
    }

    #[test]
    fn new_app_search_query_is_empty() {
        assert!(app().search_query.is_empty());
    }

    #[test]
    fn new_app_dataset_is_zero() {
        assert_eq!(app().dataset_idx, 0);
    }

    #[test]
    fn new_app_preset_is_zero() {
        assert_eq!(app().preset_idx, 0);
    }

    // ── Navigation ────────────────────────────────────────────────────────

    #[test]
    fn move_down_increments_selected() {
        let mut a = app();
        a.move_down(10);
        assert_eq!(a.selected, 1);
    }

    #[test]
    fn move_down_clamps_at_last() {
        let mut a = app();
        a.selected = 9;
        a.move_down(10);
        assert_eq!(a.selected, 9);
    }

    #[test]
    fn move_down_on_empty_list_does_nothing() {
        let mut a = app();
        a.move_down(0);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn move_up_decrements_selected() {
        let mut a = app();
        a.selected = 5;
        a.move_up();
        assert_eq!(a.selected, 4);
    }

    #[test]
    fn move_up_clamps_at_zero() {
        let mut a = app();
        a.move_up();
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn move_to_top_sets_zero() {
        let mut a = app();
        a.selected = 42;
        a.move_to_top();
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn move_to_bottom_sets_last() {
        let mut a = app();
        a.move_to_bottom(10);
        assert_eq!(a.selected, 9);
    }

    #[test]
    fn move_to_bottom_empty_list_does_nothing() {
        let mut a = app();
        a.move_to_bottom(0);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn page_down_advances_by_page_size() {
        let mut a = app();
        a.page_down(100, 10);
        assert_eq!(a.selected, 10);
    }

    #[test]
    fn page_down_clamps_at_last() {
        let mut a = app();
        a.selected = 95;
        a.page_down(100, 10);
        assert_eq!(a.selected, 99);
    }

    #[test]
    fn page_up_retreats_by_page_size() {
        let mut a = app();
        a.selected = 20;
        a.page_up(10);
        assert_eq!(a.selected, 10);
    }

    #[test]
    fn page_up_clamps_at_zero() {
        let mut a = app();
        a.selected = 3;
        a.page_up(10);
        assert_eq!(a.selected, 0);
    }

    // ── Focus ─────────────────────────────────────────────────────────────

    #[test]
    fn focus_detail_changes_focus() {
        let mut a = app();
        a.focus_detail();
        assert_eq!(a.focus, Focus::Detail);
    }

    #[test]
    fn focus_list_changes_focus_back() {
        let mut a = app();
        a.focus_detail();
        a.focus_list();
        assert_eq!(a.focus, Focus::List);
    }

    #[test]
    fn toggle_detail_fullscreen_flips() {
        let mut a = app();
        assert!(!a.detail_fullscreen);
        a.toggle_detail_fullscreen();
        assert!(a.detail_fullscreen);
        a.toggle_detail_fullscreen();
        assert!(!a.detail_fullscreen);
    }

    // ── Search mode ───────────────────────────────────────────────────────

    #[test]
    fn enter_search_mode_sets_mode() {
        let mut a = app();
        a.enter_search_mode();
        assert_eq!(a.mode, Mode::Search);
    }

    #[test]
    fn exit_search_keep_returns_to_normal_preserving_query() {
        let mut a = app();
        a.enter_search_mode();
        a.search_query = "pref".into();
        a.exit_search_keep();
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.search_query, "pref");
    }

    #[test]
    fn exit_search_clear_clears_query() {
        let mut a = app();
        a.enter_search_mode();
        a.search_query = "pref".into();
        a.exit_search_clear();
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.search_query.is_empty());
    }

    #[test]
    fn search_push_appends_char() {
        let mut a = app();
        a.search_push('p');
        a.search_push('r');
        assert_eq!(a.search_query, "pr");
    }

    #[test]
    fn search_pop_removes_last_char() {
        let mut a = app();
        a.search_query = "pref".into();
        a.search_pop();
        assert_eq!(a.search_query, "pre");
    }

    #[test]
    fn has_search_false_when_empty() {
        assert!(!app().has_search());
    }

    #[test]
    fn has_search_true_when_nonempty() {
        let mut a = app();
        a.search_query = "x".into();
        assert!(a.has_search());
    }

    // ── Dataset switching ─────────────────────────────────────────────────

    #[test]
    fn switch_dataset_updates_idx() {
        let mut a = app();
        a.switch_dataset(3);
        assert_eq!(a.dataset_idx, 3);
    }

    #[test]
    fn switch_dataset_resets_selection() {
        let mut a = app();
        a.selected = 42;
        a.switch_dataset(1);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn switch_dataset_out_of_range_ignored() {
        let mut a = app();
        a.switch_dataset(99);
        assert_eq!(a.dataset_idx, 0);
    }

    // ── Preset cycling ────────────────────────────────────────────────────

    #[test]
    fn cycle_preset_increments() {
        let mut a = app();
        a.cycle_preset();
        assert_eq!(a.preset_idx, 1);
    }

    #[test]
    fn cycle_preset_wraps_around() {
        let mut a = app();
        for _ in 0..App::PRESET_COUNT {
            a.cycle_preset();
        }
        assert_eq!(a.preset_idx, 0);
    }

    // ── Alt-N jump ────────────────────────────────────────────────────────

    #[test]
    fn alt_jump_selects_nth_zero_based() {
        let mut a = app();
        a.alt_jump(3, 10);
        assert_eq!(a.selected, 2);
    }

    #[test]
    fn alt_jump_1_selects_first() {
        let mut a = app();
        a.selected = 7;
        a.alt_jump(1, 10);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn alt_jump_clamps_to_last_when_n_exceeds_len() {
        let mut a = app();
        a.alt_jump(9, 3);
        assert_eq!(a.selected, 2);
    }

    #[test]
    fn alt_jump_on_empty_list_does_nothing() {
        let mut a = app();
        a.selected = 0;
        a.alt_jump(1, 0);
        assert_eq!(a.selected, 0);
    }

    // ── Flash ─────────────────────────────────────────────────────────────

    #[test]
    fn flash_sets_message() {
        let mut a = app();
        a.flash("hello");
        assert!(a.has_flash());
        assert_eq!(a.flash.as_ref().unwrap().text, "hello");
    }

    #[test]
    fn tick_flash_removes_expired() {
        let mut a = app();
        let mut f = Flash::new("x");
        // force expire by setting duration to 0
        f.duration_ms = 0;
        a.flash = Some(f);
        a.tick_flash();
        assert!(!a.has_flash());
    }

    // ── About modal ───────────────────────────────────────────────────────

    #[test]
    fn open_about_sets_mode() {
        let mut a = app();
        a.open_about();
        assert_eq!(a.mode, Mode::About);
    }

    #[test]
    fn close_about_returns_to_normal() {
        let mut a = app();
        a.open_about();
        a.close_about();
        assert_eq!(a.mode, Mode::Normal);
    }

    // ── CritFilter ────────────────────────────────────────────────────────

    #[test]
    fn crit_filter_all_cycles_to_critical() {
        assert_eq!(CritFilter::All.cycle(), CritFilter::Critical);
    }

    #[test]
    fn crit_filter_critical_cycles_to_high() {
        assert_eq!(CritFilter::Critical.cycle(), CritFilter::High);
    }

    #[test]
    fn crit_filter_high_cycles_to_medium() {
        assert_eq!(CritFilter::High.cycle(), CritFilter::Medium);
    }

    #[test]
    fn crit_filter_medium_cycles_to_all() {
        assert_eq!(CritFilter::Medium.cycle(), CritFilter::All);
    }

    #[test]
    fn crit_filter_all_passes_every_priority() {
        use forensicnomicon::catalog::TriagePriority;
        assert!(CritFilter::All.passes(TriagePriority::Low));
        assert!(CritFilter::All.passes(TriagePriority::Medium));
        assert!(CritFilter::All.passes(TriagePriority::High));
        assert!(CritFilter::All.passes(TriagePriority::Critical));
    }

    #[test]
    fn crit_filter_critical_passes_only_critical() {
        use forensicnomicon::catalog::TriagePriority;
        assert!(CritFilter::Critical.passes(TriagePriority::Critical));
        assert!(!CritFilter::Critical.passes(TriagePriority::High));
        assert!(!CritFilter::Critical.passes(TriagePriority::Medium));
        assert!(!CritFilter::Critical.passes(TriagePriority::Low));
    }

    #[test]
    fn crit_filter_high_passes_critical_and_high_only() {
        use forensicnomicon::catalog::TriagePriority;
        assert!(CritFilter::High.passes(TriagePriority::Critical));
        assert!(CritFilter::High.passes(TriagePriority::High));
        assert!(!CritFilter::High.passes(TriagePriority::Medium));
        assert!(!CritFilter::High.passes(TriagePriority::Low));
    }

    #[test]
    fn crit_filter_medium_excludes_only_low() {
        use forensicnomicon::catalog::TriagePriority;
        assert!(CritFilter::Medium.passes(TriagePriority::Critical));
        assert!(CritFilter::Medium.passes(TriagePriority::High));
        assert!(CritFilter::Medium.passes(TriagePriority::Medium));
        assert!(!CritFilter::Medium.passes(TriagePriority::Low));
    }

    #[test]
    fn new_app_crit_filter_is_all() {
        assert_eq!(app().crit_filter, CritFilter::All);
    }

    #[test]
    fn cycle_crit_filter_advances_from_all() {
        let mut a = app();
        a.cycle_crit_filter();
        assert_eq!(a.crit_filter, CritFilter::Critical);
    }

    #[test]
    fn cycle_crit_filter_full_cycle() {
        let mut a = app();
        a.cycle_crit_filter(); // All → Critical
        a.cycle_crit_filter(); // Critical → High
        a.cycle_crit_filter(); // High → Medium
        a.cycle_crit_filter(); // Medium → All
        assert_eq!(a.crit_filter, CritFilter::All);
    }

    #[test]
    fn cycle_crit_filter_resets_selection() {
        let mut a = app();
        a.selected = 42;
        a.cycle_crit_filter();
        assert_eq!(a.selected, 0);
    }
}
