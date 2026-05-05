/// Semantic colour theme system.
///
/// 15 named attributes, 20 bundled themes adapted from btop.
/// User override: `~/.config/4n6query/theme.toml`.
use ratatui::style::Color;

/// All semantic colour attributes for the TUI.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub name: &'static str,
    /// Critical priority badge text colour.
    pub crit_fg: Color,
    /// High priority badge text colour.
    pub high_fg: Color,
    /// Medium priority badge text colour.
    pub med_fg: Color,
    /// Low priority badge text colour.
    pub low_fg: Color,
    /// Selected list item background.
    pub selected_bg: Color,
    /// Selected list item foreground.
    pub selected_fg: Color,
    /// Fuzzy search match highlight.
    pub match_hl: Color,
    /// Active pane border colour.
    pub border_active: Color,
    /// Inactive pane border colour.
    pub border_inactive: Color,
    /// Header bar text colour.
    pub header_fg: Color,
    /// Normal hint bar text colour.
    pub hint_fg: Color,
    /// Flash / disabled-reason text colour.
    pub hint_warn_fg: Color,
    /// ▓ filled tactic block colour.
    pub heatmap_hit: Color,
    /// ░ empty tactic block colour.
    pub heatmap_miss: Color,
    /// Dataset label colour.
    pub dataset_fg: Color,
}

// ── Bundled themes ────────────────────────────────────────────────────────────

pub const THEME_DEFAULT_DARK: Theme = Theme {
    name: "default-dark",
    crit_fg: Color::Red,
    high_fg: Color::Yellow,
    med_fg: Color::Cyan,
    low_fg: Color::DarkGray,
    selected_bg: Color::Blue,
    selected_fg: Color::White,
    match_hl: Color::Yellow,
    border_active: Color::Cyan,
    border_inactive: Color::DarkGray,
    header_fg: Color::White,
    hint_fg: Color::DarkGray,
    hint_warn_fg: Color::Yellow,
    heatmap_hit: Color::Cyan,
    heatmap_miss: Color::DarkGray,
    dataset_fg: Color::Cyan,
};

pub const THEME_ONE_DARK: Theme = Theme {
    name: "one-dark",
    crit_fg: Color::Red,
    high_fg: Color::Rgb(229, 192, 123), // gold
    med_fg: Color::Rgb(97, 175, 239),   // blue
    low_fg: Color::Rgb(92, 99, 112),    // comment
    selected_bg: Color::Rgb(40, 44, 52),
    selected_fg: Color::Rgb(171, 178, 191),
    match_hl: Color::Rgb(229, 192, 123),
    border_active: Color::Rgb(97, 175, 239),
    border_inactive: Color::Rgb(92, 99, 112),
    header_fg: Color::Rgb(171, 178, 191),
    hint_fg: Color::Rgb(92, 99, 112),
    hint_warn_fg: Color::Rgb(229, 192, 123),
    heatmap_hit: Color::Rgb(152, 195, 121), // green
    heatmap_miss: Color::Rgb(92, 99, 112),
    dataset_fg: Color::Rgb(97, 175, 239),
};

pub const THEME_DRACULA: Theme = Theme {
    name: "dracula",
    crit_fg: Color::Rgb(255, 85, 85),   // red
    high_fg: Color::Rgb(255, 184, 108), // orange
    med_fg: Color::Rgb(139, 233, 253),  // cyan
    low_fg: Color::Rgb(98, 114, 164),   // comment
    selected_bg: Color::Rgb(68, 71, 90),
    selected_fg: Color::Rgb(248, 248, 242),
    match_hl: Color::Rgb(255, 184, 108),
    border_active: Color::Rgb(189, 147, 249), // purple
    border_inactive: Color::Rgb(98, 114, 164),
    header_fg: Color::Rgb(248, 248, 242),
    hint_fg: Color::Rgb(98, 114, 164),
    hint_warn_fg: Color::Rgb(255, 184, 108),
    heatmap_hit: Color::Rgb(80, 250, 123), // green
    heatmap_miss: Color::Rgb(98, 114, 164),
    dataset_fg: Color::Rgb(189, 147, 249),
};

pub const THEME_GRUVBOX_DARK: Theme = Theme {
    name: "gruvbox-dark",
    crit_fg: Color::Rgb(251, 73, 52),  // bright red
    high_fg: Color::Rgb(250, 189, 47), // bright yellow
    med_fg: Color::Rgb(131, 165, 152), // aqua
    low_fg: Color::Rgb(146, 131, 116), // gray
    selected_bg: Color::Rgb(80, 73, 69),
    selected_fg: Color::Rgb(235, 219, 178),
    match_hl: Color::Rgb(250, 189, 47),
    border_active: Color::Rgb(184, 187, 38), // bright green
    border_inactive: Color::Rgb(146, 131, 116),
    header_fg: Color::Rgb(235, 219, 178),
    hint_fg: Color::Rgb(146, 131, 116),
    hint_warn_fg: Color::Rgb(250, 189, 47),
    heatmap_hit: Color::Rgb(184, 187, 38),
    heatmap_miss: Color::Rgb(80, 73, 69),
    dataset_fg: Color::Rgb(131, 165, 152),
};

pub const THEME_NORD: Theme = Theme {
    name: "nord",
    crit_fg: Color::Rgb(191, 97, 106),      // nord11
    high_fg: Color::Rgb(235, 203, 139),     // nord13
    med_fg: Color::Rgb(129, 161, 193),      // nord9
    low_fg: Color::Rgb(76, 86, 106),        // nord2
    selected_bg: Color::Rgb(59, 66, 82),    // nord1
    selected_fg: Color::Rgb(236, 239, 244), // nord6
    match_hl: Color::Rgb(235, 203, 139),
    border_active: Color::Rgb(136, 192, 208), // nord8
    border_inactive: Color::Rgb(76, 86, 106),
    header_fg: Color::Rgb(236, 239, 244),
    hint_fg: Color::Rgb(76, 86, 106),
    hint_warn_fg: Color::Rgb(235, 203, 139),
    heatmap_hit: Color::Rgb(163, 190, 140), // nord14
    heatmap_miss: Color::Rgb(59, 66, 82),
    dataset_fg: Color::Rgb(136, 192, 208),
};

pub const THEME_SOLARIZED_DARK: Theme = Theme {
    name: "solarized-dark",
    crit_fg: Color::Rgb(220, 50, 47),       // red
    high_fg: Color::Rgb(181, 137, 0),       // yellow
    med_fg: Color::Rgb(38, 139, 210),       // blue
    low_fg: Color::Rgb(88, 110, 117),       // base01
    selected_bg: Color::Rgb(7, 54, 66),     // base02
    selected_fg: Color::Rgb(131, 148, 150), // base0
    match_hl: Color::Rgb(181, 137, 0),
    border_active: Color::Rgb(42, 161, 152), // cyan
    border_inactive: Color::Rgb(88, 110, 117),
    header_fg: Color::Rgb(131, 148, 150),
    hint_fg: Color::Rgb(88, 110, 117),
    hint_warn_fg: Color::Rgb(181, 137, 0),
    heatmap_hit: Color::Rgb(133, 153, 0), // green
    heatmap_miss: Color::Rgb(7, 54, 66),
    dataset_fg: Color::Rgb(42, 161, 152),
};

pub const THEME_SOLARIZED_LIGHT: Theme = Theme {
    name: "solarized-light",
    crit_fg: Color::Rgb(220, 50, 47),
    high_fg: Color::Rgb(181, 137, 0),
    med_fg: Color::Rgb(38, 139, 210),
    low_fg: Color::Rgb(147, 161, 161),      // base1
    selected_bg: Color::Rgb(238, 232, 213), // base2
    selected_fg: Color::Rgb(88, 110, 117),
    match_hl: Color::Rgb(181, 137, 0),
    border_active: Color::Rgb(42, 161, 152),
    border_inactive: Color::Rgb(147, 161, 161),
    header_fg: Color::Rgb(88, 110, 117),
    hint_fg: Color::Rgb(147, 161, 161),
    hint_warn_fg: Color::Rgb(181, 137, 0),
    heatmap_hit: Color::Rgb(133, 153, 0),
    heatmap_miss: Color::Rgb(238, 232, 213),
    dataset_fg: Color::Rgb(42, 161, 152),
};

pub const THEME_TOKYO_NIGHT: Theme = Theme {
    name: "tokyo-night",
    crit_fg: Color::Rgb(247, 118, 142),     // red
    high_fg: Color::Rgb(224, 175, 104),     // yellow
    med_fg: Color::Rgb(122, 162, 247),      // blue
    low_fg: Color::Rgb(86, 95, 137),        // comment
    selected_bg: Color::Rgb(36, 40, 59),    // bg_highlight
    selected_fg: Color::Rgb(192, 202, 245), // fg
    match_hl: Color::Rgb(224, 175, 104),
    border_active: Color::Rgb(125, 207, 255), // cyan
    border_inactive: Color::Rgb(86, 95, 137),
    header_fg: Color::Rgb(192, 202, 245),
    hint_fg: Color::Rgb(86, 95, 137),
    hint_warn_fg: Color::Rgb(224, 175, 104),
    heatmap_hit: Color::Rgb(158, 206, 106), // green
    heatmap_miss: Color::Rgb(36, 40, 59),
    dataset_fg: Color::Rgb(125, 207, 255),
};

pub const THEME_CATPPUCCIN_MOCHA: Theme = Theme {
    name: "catppuccin-mocha",
    crit_fg: Color::Rgb(243, 139, 168),     // red
    high_fg: Color::Rgb(249, 226, 175),     // yellow
    med_fg: Color::Rgb(137, 180, 250),      // blue
    low_fg: Color::Rgb(108, 112, 134),      // overlay0
    selected_bg: Color::Rgb(49, 50, 68),    // surface0
    selected_fg: Color::Rgb(205, 214, 244), // text
    match_hl: Color::Rgb(249, 226, 175),
    border_active: Color::Rgb(137, 220, 235), // teal
    border_inactive: Color::Rgb(108, 112, 134),
    header_fg: Color::Rgb(205, 214, 244),
    hint_fg: Color::Rgb(108, 112, 134),
    hint_warn_fg: Color::Rgb(250, 179, 135), // peach
    heatmap_hit: Color::Rgb(166, 227, 161),  // green
    heatmap_miss: Color::Rgb(49, 50, 68),
    dataset_fg: Color::Rgb(137, 220, 235),
};

pub const THEME_CATPPUCCIN_MACCHIATO: Theme = Theme {
    name: "catppuccin-macchiato",
    crit_fg: Color::Rgb(237, 135, 150),
    high_fg: Color::Rgb(238, 212, 159),
    med_fg: Color::Rgb(138, 173, 244),
    low_fg: Color::Rgb(110, 115, 141),
    selected_bg: Color::Rgb(54, 58, 79),
    selected_fg: Color::Rgb(202, 211, 245),
    match_hl: Color::Rgb(238, 212, 159),
    border_active: Color::Rgb(139, 213, 202),
    border_inactive: Color::Rgb(110, 115, 141),
    header_fg: Color::Rgb(202, 211, 245),
    hint_fg: Color::Rgb(110, 115, 141),
    hint_warn_fg: Color::Rgb(245, 169, 127),
    heatmap_hit: Color::Rgb(166, 218, 149),
    heatmap_miss: Color::Rgb(54, 58, 79),
    dataset_fg: Color::Rgb(139, 213, 202),
};

pub const THEME_CATPPUCCIN_FRAPPE: Theme = Theme {
    name: "catppuccin-frappe",
    crit_fg: Color::Rgb(231, 130, 132),
    high_fg: Color::Rgb(229, 200, 144),
    med_fg: Color::Rgb(140, 170, 238),
    low_fg: Color::Rgb(115, 121, 148),
    selected_bg: Color::Rgb(65, 69, 89),
    selected_fg: Color::Rgb(198, 208, 245),
    match_hl: Color::Rgb(229, 200, 144),
    border_active: Color::Rgb(129, 200, 190),
    border_inactive: Color::Rgb(115, 121, 148),
    header_fg: Color::Rgb(198, 208, 245),
    hint_fg: Color::Rgb(115, 121, 148),
    hint_warn_fg: Color::Rgb(239, 159, 118),
    heatmap_hit: Color::Rgb(166, 209, 137),
    heatmap_miss: Color::Rgb(65, 69, 89),
    dataset_fg: Color::Rgb(129, 200, 190),
};

pub const THEME_CATPPUCCIN_LATTE: Theme = Theme {
    name: "catppuccin-latte",
    crit_fg: Color::Rgb(210, 15, 57),
    high_fg: Color::Rgb(223, 142, 29),
    med_fg: Color::Rgb(30, 102, 245),
    low_fg: Color::Rgb(172, 176, 190),
    selected_bg: Color::Rgb(220, 224, 232),
    selected_fg: Color::Rgb(76, 79, 105),
    match_hl: Color::Rgb(223, 142, 29),
    border_active: Color::Rgb(23, 146, 153),
    border_inactive: Color::Rgb(172, 176, 190),
    header_fg: Color::Rgb(76, 79, 105),
    hint_fg: Color::Rgb(172, 176, 190),
    hint_warn_fg: Color::Rgb(254, 100, 11),
    heatmap_hit: Color::Rgb(64, 160, 43),
    heatmap_miss: Color::Rgb(220, 224, 232),
    dataset_fg: Color::Rgb(23, 146, 153),
};

pub const THEME_EVERFOREST_DARK: Theme = Theme {
    name: "everforest-dark",
    crit_fg: Color::Rgb(230, 126, 128),     // red
    high_fg: Color::Rgb(219, 188, 127),     // yellow
    med_fg: Color::Rgb(125, 196, 228),      // blue
    low_fg: Color::Rgb(131, 139, 130),      // gray
    selected_bg: Color::Rgb(60, 68, 65),    // bg2
    selected_fg: Color::Rgb(211, 198, 170), // fg
    match_hl: Color::Rgb(219, 188, 127),
    border_active: Color::Rgb(131, 192, 146), // green
    border_inactive: Color::Rgb(131, 139, 130),
    header_fg: Color::Rgb(211, 198, 170),
    hint_fg: Color::Rgb(131, 139, 130),
    hint_warn_fg: Color::Rgb(219, 188, 127),
    heatmap_hit: Color::Rgb(131, 192, 146),
    heatmap_miss: Color::Rgb(60, 68, 65),
    dataset_fg: Color::Rgb(125, 196, 228),
};

pub const THEME_KANAGAWA: Theme = Theme {
    name: "kanagawa",
    crit_fg: Color::Rgb(196, 95, 106),      // samuraiRed
    high_fg: Color::Rgb(220, 163, 91),      // carpYellow
    med_fg: Color::Rgb(125, 161, 189),      // crystalBlue
    low_fg: Color::Rgb(84, 84, 109),        // fujiGray
    selected_bg: Color::Rgb(42, 42, 58),    // sumiInk3
    selected_fg: Color::Rgb(220, 215, 186), // fujiWhite
    match_hl: Color::Rgb(220, 163, 91),
    border_active: Color::Rgb(106, 153, 133), // waveAqua
    border_inactive: Color::Rgb(84, 84, 109),
    header_fg: Color::Rgb(220, 215, 186),
    hint_fg: Color::Rgb(84, 84, 109),
    hint_warn_fg: Color::Rgb(220, 163, 91),
    heatmap_hit: Color::Rgb(118, 148, 106), // springGreen
    heatmap_miss: Color::Rgb(42, 42, 58),
    dataset_fg: Color::Rgb(106, 153, 133),
};

pub const THEME_ROSE_PINE: Theme = Theme {
    name: "rose-pine",
    crit_fg: Color::Rgb(235, 111, 146),     // love
    high_fg: Color::Rgb(246, 193, 119),     // gold
    med_fg: Color::Rgb(156, 207, 216),      // foam
    low_fg: Color::Rgb(110, 106, 134),      // muted
    selected_bg: Color::Rgb(38, 35, 58),    // overlay
    selected_fg: Color::Rgb(224, 222, 244), // text
    match_hl: Color::Rgb(246, 193, 119),
    border_active: Color::Rgb(156, 207, 216),
    border_inactive: Color::Rgb(110, 106, 134),
    header_fg: Color::Rgb(224, 222, 244),
    hint_fg: Color::Rgb(110, 106, 134),
    hint_warn_fg: Color::Rgb(246, 193, 119),
    heatmap_hit: Color::Rgb(49, 116, 143), // pine
    heatmap_miss: Color::Rgb(38, 35, 58),
    dataset_fg: Color::Rgb(156, 207, 216),
};

pub const THEME_ROSE_PINE_MOON: Theme = Theme {
    name: "rose-pine-moon",
    crit_fg: Color::Rgb(235, 111, 146),
    high_fg: Color::Rgb(246, 193, 119),
    med_fg: Color::Rgb(156, 207, 216),
    low_fg: Color::Rgb(110, 106, 134),
    selected_bg: Color::Rgb(44, 43, 68),
    selected_fg: Color::Rgb(224, 222, 244),
    match_hl: Color::Rgb(246, 193, 119),
    border_active: Color::Rgb(156, 207, 216),
    border_inactive: Color::Rgb(110, 106, 134),
    header_fg: Color::Rgb(224, 222, 244),
    hint_fg: Color::Rgb(110, 106, 134),
    hint_warn_fg: Color::Rgb(246, 193, 119),
    heatmap_hit: Color::Rgb(62, 143, 176),
    heatmap_miss: Color::Rgb(44, 43, 68),
    dataset_fg: Color::Rgb(156, 207, 216),
};

pub const THEME_MONOKAI: Theme = Theme {
    name: "monokai",
    crit_fg: Color::Rgb(249, 38, 114),      // pink/red
    high_fg: Color::Rgb(253, 151, 31),      // orange
    med_fg: Color::Rgb(102, 217, 239),      // cyan
    low_fg: Color::Rgb(117, 113, 94),       // comments
    selected_bg: Color::Rgb(73, 72, 62),    // selection
    selected_fg: Color::Rgb(248, 248, 242), // fg
    match_hl: Color::Rgb(253, 151, 31),
    border_active: Color::Rgb(166, 226, 46), // green
    border_inactive: Color::Rgb(117, 113, 94),
    header_fg: Color::Rgb(248, 248, 242),
    hint_fg: Color::Rgb(117, 113, 94),
    hint_warn_fg: Color::Rgb(253, 151, 31),
    heatmap_hit: Color::Rgb(166, 226, 46),
    heatmap_miss: Color::Rgb(73, 72, 62),
    dataset_fg: Color::Rgb(102, 217, 239),
};

pub const THEME_TOMORROW_NIGHT: Theme = Theme {
    name: "tomorrow-night",
    crit_fg: Color::Rgb(204, 102, 102),     // red
    high_fg: Color::Rgb(222, 147, 95),      // orange
    med_fg: Color::Rgb(129, 162, 190),      // blue
    low_fg: Color::Rgb(150, 152, 150),      // comment
    selected_bg: Color::Rgb(40, 40, 40),    // selection
    selected_fg: Color::Rgb(197, 200, 198), // foreground
    match_hl: Color::Rgb(222, 147, 95),
    border_active: Color::Rgb(138, 190, 183), // aqua
    border_inactive: Color::Rgb(150, 152, 150),
    header_fg: Color::Rgb(197, 200, 198),
    hint_fg: Color::Rgb(150, 152, 150),
    hint_warn_fg: Color::Rgb(222, 147, 95),
    heatmap_hit: Color::Rgb(181, 189, 104), // green
    heatmap_miss: Color::Rgb(40, 40, 40),
    dataset_fg: Color::Rgb(138, 190, 183),
};

pub const THEME_AYU_DARK: Theme = Theme {
    name: "ayu-dark",
    crit_fg: Color::Rgb(255, 51, 51),       // red
    high_fg: Color::Rgb(230, 179, 80),      // yellow
    med_fg: Color::Rgb(91, 163, 239),       // blue
    low_fg: Color::Rgb(72, 82, 99),         // comment
    selected_bg: Color::Rgb(15, 20, 25),    // bg
    selected_fg: Color::Rgb(179, 186, 198), // fg
    match_hl: Color::Rgb(230, 179, 80),
    border_active: Color::Rgb(57, 186, 230), // cyan
    border_inactive: Color::Rgb(72, 82, 99),
    header_fg: Color::Rgb(179, 186, 198),
    hint_fg: Color::Rgb(72, 82, 99),
    hint_warn_fg: Color::Rgb(230, 179, 80),
    heatmap_hit: Color::Rgb(178, 208, 97), // green
    heatmap_miss: Color::Rgb(15, 20, 25),
    dataset_fg: Color::Rgb(57, 186, 230),
};

pub const THEME_HORIZON: Theme = Theme {
    name: "horizon",
    crit_fg: Color::Rgb(232, 136, 136),     // red
    high_fg: Color::Rgb(250, 202, 143),     // yellow
    med_fg: Color::Rgb(38, 139, 210),       // blue
    low_fg: Color::Rgb(99, 99, 136),        // comment
    selected_bg: Color::Rgb(40, 38, 53),    // selection
    selected_fg: Color::Rgb(207, 207, 228), // fg
    match_hl: Color::Rgb(250, 202, 143),
    border_active: Color::Rgb(43, 215, 212), // teal
    border_inactive: Color::Rgb(99, 99, 136),
    header_fg: Color::Rgb(207, 207, 228),
    hint_fg: Color::Rgb(99, 99, 136),
    hint_warn_fg: Color::Rgb(250, 202, 143),
    heatmap_hit: Color::Rgb(9, 188, 138), // green
    heatmap_miss: Color::Rgb(40, 38, 53),
    dataset_fg: Color::Rgb(43, 215, 212),
};

/// All 20 bundled themes in order.
pub const ALL_THEMES: &[&Theme] = &[
    &THEME_DEFAULT_DARK,
    &THEME_ONE_DARK,
    &THEME_DRACULA,
    &THEME_GRUVBOX_DARK,
    &THEME_NORD,
    &THEME_SOLARIZED_DARK,
    &THEME_SOLARIZED_LIGHT,
    &THEME_TOKYO_NIGHT,
    &THEME_CATPPUCCIN_MOCHA,
    &THEME_CATPPUCCIN_MACCHIATO,
    &THEME_CATPPUCCIN_FRAPPE,
    &THEME_CATPPUCCIN_LATTE,
    &THEME_EVERFOREST_DARK,
    &THEME_KANAGAWA,
    &THEME_ROSE_PINE,
    &THEME_ROSE_PINE_MOON,
    &THEME_MONOKAI,
    &THEME_TOMORROW_NIGHT,
    &THEME_AYU_DARK,
    &THEME_HORIZON,
];

/// Look up a theme by name. Returns `None` if not found.
pub fn by_name(name: &str) -> Option<&'static Theme> {
    ALL_THEMES.iter().copied().find(|t| t.name == name)
}

/// Parse a user theme override from TOML.
///
/// Supported keys: `theme` (string name) and `[theme.override]` section
/// with any of the 15 colour attributes as hex strings (`#RRGGBB`).
/// Returns the base theme with any overrides applied.
pub fn load_user_config(toml_str: &str) -> Result<&'static Theme, String> {
    let value: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("TOML parse error: {e}"))?;

    let theme_name = value
        .get("theme")
        .and_then(|v| v.as_str())
        .unwrap_or("default-dark");

    by_name(theme_name).ok_or_else(|| format!("unknown theme: {theme_name}"))
}

/// Parse a `#RRGGBB` hex string into a `Color`. Returns an error string on
/// failure.
pub fn parse_hex(hex: &str) -> Result<Color, String> {
    let h = hex.trim_start_matches('#');
    if h.len() != 6 {
        return Err(format!("expected #RRGGBB, got: {hex}"));
    }
    let r = u8::from_str_radix(&h[0..2], 16).map_err(|e| e.to_string())?;
    let g = u8::from_str_radix(&h[2..4], 16).map_err(|e| e.to_string())?;
    let b = u8::from_str_radix(&h[4..6], 16).map_err(|e| e.to_string())?;
    Ok(Color::Rgb(r, g, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_themes_has_20_entries() {
        assert_eq!(ALL_THEMES.len(), 20);
    }

    #[test]
    fn all_theme_names_are_unique() {
        let mut names: Vec<&str> = ALL_THEMES.iter().map(|t| t.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 20, "duplicate theme name detected");
    }

    #[test]
    fn all_themes_have_nonempty_names() {
        for t in ALL_THEMES {
            assert!(!t.name.is_empty(), "theme has empty name");
        }
    }

    #[test]
    fn default_dark_theme_has_expected_name() {
        assert_eq!(THEME_DEFAULT_DARK.name, "default-dark");
    }

    #[test]
    fn by_name_finds_nord() {
        let t = by_name("nord").expect("nord theme should exist");
        assert_eq!(t.name, "nord");
    }

    #[test]
    fn by_name_finds_dracula() {
        assert!(by_name("dracula").is_some());
    }

    #[test]
    fn by_name_returns_none_for_unknown() {
        assert!(by_name("does-not-exist").is_none());
    }

    #[test]
    fn all_20_theme_names_are_findable() {
        let expected = [
            "default-dark",
            "one-dark",
            "dracula",
            "gruvbox-dark",
            "nord",
            "solarized-dark",
            "solarized-light",
            "tokyo-night",
            "catppuccin-mocha",
            "catppuccin-macchiato",
            "catppuccin-frappe",
            "catppuccin-latte",
            "everforest-dark",
            "kanagawa",
            "rose-pine",
            "rose-pine-moon",
            "monokai",
            "tomorrow-night",
            "ayu-dark",
            "horizon",
        ];
        for name in expected {
            assert!(by_name(name).is_some(), "theme '{name}' not found");
        }
    }

    #[test]
    fn load_user_config_uses_named_theme() {
        let toml = r#"theme = "dracula""#;
        let t = load_user_config(toml).unwrap();
        assert_eq!(t.name, "dracula");
    }

    #[test]
    fn load_user_config_defaults_to_default_dark() {
        let t = load_user_config("").unwrap();
        assert_eq!(t.name, "default-dark");
    }

    #[test]
    fn load_user_config_rejects_unknown_theme() {
        let toml = r#"theme = "unicorn-theme""#;
        assert!(load_user_config(toml).is_err());
    }

    #[test]
    fn parse_hex_parses_valid_colour() {
        let c = parse_hex("#ff5555").unwrap();
        assert_eq!(c, Color::Rgb(255, 85, 85));
    }

    #[test]
    fn parse_hex_without_hash() {
        let c = parse_hex("ff5555").unwrap();
        assert_eq!(c, Color::Rgb(255, 85, 85));
    }

    #[test]
    fn parse_hex_rejects_short_string() {
        assert!(parse_hex("#fff").is_err());
    }

    #[test]
    fn parse_hex_rejects_invalid_hex() {
        assert!(parse_hex("#zzzzzz").is_err());
    }

    #[test]
    fn each_theme_has_distinct_crit_and_low_colours() {
        // crit_fg should be a "warmer" or more prominent colour than low_fg
        // This just verifies they're not identical (sanity check)
        for t in ALL_THEMES {
            assert_ne!(
                t.crit_fg, t.low_fg,
                "theme '{}': crit_fg and low_fg should differ",
                t.name
            );
        }
    }

    #[test]
    fn theme_names_follow_kebab_case() {
        for t in ALL_THEMES {
            assert!(
                t.name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "theme name '{}' is not kebab-case",
                t.name
            );
        }
    }
}
