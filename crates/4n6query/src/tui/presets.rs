/// Triage presets — cycled with Ctrl-R.
///
/// Each preset specifies an OS filter and a triage-priority mask.
/// The App's `preset_idx` selects which preset is active.
use forensicnomicon::catalog::{OsScope, TriagePriority};

/// A named filter preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub label: &'static str,
    /// `None` = no OS filter (show all platforms).
    pub os: Option<OsScope>,
    /// Empty slice = no priority filter (show all priorities).
    pub priorities: &'static [TriagePriority],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        label: "All",
        os: None,
        priorities: &[],
    },
    Preset {
        label: "Windows · CRIT",
        os: Some(OsScope::Win7Plus),
        priorities: &[TriagePriority::Critical],
    },
    Preset {
        label: "Windows · CRIT+HIGH",
        os: Some(OsScope::Win7Plus),
        priorities: &[TriagePriority::Critical, TriagePriority::High],
    },
    Preset {
        label: "Linux · CRIT",
        os: Some(OsScope::Linux),
        priorities: &[TriagePriority::Critical],
    },
    Preset {
        label: "macOS · CRIT",
        os: Some(OsScope::MacOS),
        priorities: &[TriagePriority::Critical],
    },
];

/// Return the active preset for the given index.
pub fn active(preset_idx: usize) -> &'static Preset {
    &PRESETS[preset_idx % PRESETS.len()]
}

/// Return the next preset index (wraps around).
pub fn next_idx(current: usize) -> usize {
    (current + 1) % PRESETS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_has_five_entries() {
        assert_eq!(PRESETS.len(), 5);
    }

    #[test]
    fn first_preset_is_all() {
        assert_eq!(PRESETS[0].label, "All");
        assert!(PRESETS[0].os.is_none());
        assert!(PRESETS[0].priorities.is_empty());
    }

    #[test]
    fn second_preset_is_windows_critical() {
        let p = &PRESETS[1];
        assert_eq!(p.label, "Windows · CRIT");
        assert_eq!(p.os, Some(OsScope::Win7Plus));
        assert_eq!(p.priorities, &[TriagePriority::Critical]);
    }

    #[test]
    fn third_preset_is_windows_critical_high() {
        let p = &PRESETS[2];
        assert_eq!(p.label, "Windows · CRIT+HIGH");
        assert_eq!(p.priorities.len(), 2);
        assert!(p.priorities.contains(&TriagePriority::Critical));
        assert!(p.priorities.contains(&TriagePriority::High));
    }

    #[test]
    fn fourth_preset_is_linux_critical() {
        let p = &PRESETS[3];
        assert_eq!(p.os, Some(OsScope::Linux));
        assert_eq!(p.priorities, &[TriagePriority::Critical]);
    }

    #[test]
    fn fifth_preset_is_macos_critical() {
        let p = &PRESETS[4];
        assert_eq!(p.os, Some(OsScope::MacOS));
    }

    #[test]
    fn next_idx_increments() {
        assert_eq!(next_idx(0), 1);
        assert_eq!(next_idx(3), 4);
    }

    #[test]
    fn next_idx_wraps_at_end() {
        assert_eq!(next_idx(4), 0);
    }

    #[test]
    fn active_returns_correct_preset() {
        assert_eq!(active(0).label, "All");
        assert_eq!(active(1).label, "Windows · CRIT");
    }

    #[test]
    fn active_wraps_on_out_of_range() {
        // preset_idx is kept in range by App, but active() is defensive
        assert_eq!(active(5).label, "All"); // 5 % 5 == 0
    }
}
