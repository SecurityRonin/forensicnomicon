# TUI Navigator Design — forensicnomicon

**Date:** 2026-05-05  
**Status:** Approved → implementing

---

## Entry Point

`4n6query` with no arguments on a TTY launches the TUI.  
`4n6query <args>` always uses existing CLI behaviour.  
Pipelines never see the TUI (`isatty(stdout)` check).

---

## Layout

MC dual-pane, 38/62 split, adaptive:

```
┌─ 4n6query ──────────── catalog · 6574 entries · /prefetch · 4 matches ──┐
│ > prefetch_file        [CRIT] ║  prefetch_file                           │
│   prefetch_hash_mismatch[HIGH]║  ──────────────────────────────────────  │
│   prefetch_volume       [MED] ║  Windows Prefetch execution artifacts    │
│   prefetch_dir          [LOW] ║                                          │
│                               ║  Type:     File                          │
│                               ║  OS:       Windows                       │
│                               ║  Priority: CRITICAL                      │
│                               ║  Path: C:\Windows\Prefetch\*.pf         │
│                               ║                                          │
│                               ║  MITRE: T1059  T1204.002  T1547.001    │
│                               ║  Tactics: ▓░░░▓░░░▓░░░░░               │
│                               ║                                          │
│                               ║  Fields:                                 │
│                               ║    exec_count  last_run_time[8]         │
│                               ║    format_version  mft_record_number    │
│                               ║                                          │
│                               ║  Sources:                                │
│                               ║    kacos2000/Prefetch-Browser           │
│                               ║    libyal/libscca                       │
├───────────────────────────────╨──────────────────────────────────────────┤
│ hjkl/↑↓: nav  Tab·l·h: pane  /: search  Ctrl-R: preset  ?: about  q: quit│
└──────────────────────────────────────────────────────────────────────────┘
```

Below 100 cols: right pane collapses; `Enter` toggles it full-screen.

---

## Nine Datasets (keys 1–9)

1. Catalog (6,574 artifacts)
2. Windows LOLBins (189)
3. Linux LOLBins (479)
4. macOS LOOBins (139)
5. Windows Cmdlets (289)
6. Windows MMC (63)
7. Windows WMI (30)
8. Abusable Sites (52)
9. Playbooks (11)

---

## Keybindings

### Normal Mode

| Key | Action | Guard |
|-----|--------|-------|
| `j`/`↓` | move down | — |
| `k`/`↑` | move up | — |
| `g`/`G` | top / bottom | — |
| `Ctrl-D`/`Ctrl-U` | half-page | — |
| `Ctrl-F`/`Ctrl-B`/`PgDn`/`PgUp` | full page | — |
| `/` | enter search mode | — |
| `n`/`N` | next/prev match | HasResults |
| `Tab`/`l` | focus detail pane | — |
| `h`/`Tab`/`Esc` | focus list pane | DetailFocused |
| `Enter` | toggle detail full-screen | HasResults |
| `1`–`9` | switch dataset | NotInSearchMode |
| `Ctrl-R` | cycle triage preset | — |
| `Alt-1`–`Alt-9` | jump to Nth result | HasResults |
| `?`/`F1` | about modal | — |
| `q`/`Ctrl-C` | quit | — |

### Search Mode (`/` pressed)

| Key | Action |
|-----|--------|
| printable | append to query, live filter |
| `Backspace` | delete last char |
| `↑`/`↓` | navigate without leaving search |
| `Alt-1`–`Alt-9` | select Nth result immediately |
| `Esc`/`Enter` | exit, keep filter |
| `Ctrl-C` | exit, clear filter |

### Detail Pane Focused

| Key | Action |
|-----|--------|
| `j`/`k` | scroll detail |
| `h`/`Tab`/`Esc` | return to list |
| `Enter` | toggle full-screen |
| `q` | quit |

---

## Feature 1: Disabled-Reason Hint Bar (lazygit-inspired)

Every keybinding has an optional guard. When a guard fails, the action is blocked and the reason flashes in the hint bar for 1.5 seconds instead of the static key map.

Example flash messages:
- `n` with no search → `no active search — press / to start`
- `n` with 0 results → `no matches — refine your query`
- `1`–`9` in search mode → `finish search first (Esc), then switch dataset`
- `Enter` on empty list → `no entries to expand`

After 1.5 s the hint bar returns to the static key map.

---

## Feature 2: Ctrl-R Triage Preset Cycling (atuin-inspired)

One key cycles through curated triage presets:

```
All → [Windows · CRIT] → [Windows · CRIT+HIGH] → [Linux · CRIT] → [macOS · CRIT] → All
```

Each preset sets OS filter + priority filter atomically. Header shows active preset name.

---

## Feature 3: Alt-1–Alt-9 Nth Result Jump (atuin-inspired)

`Alt-1` selects the 1st visible (filtered) result, `Alt-2` the 2nd, etc.  
If N > result count, selects the last result.  
Works in both Normal and Search mode.

---

## Feature 4: Guard-Aware Keybindings

Guards defined per keybinding:

| Guard | Fails when |
|-------|-----------|
| `NotInSearchMode` | mode == Search |
| `HasResults` | filtered list is empty |
| `DetailFocused` | focus == List |

Failed guard → reason string → flash in hint bar 1.5 s.

---

## Feature 5: Semantic Colour Theme (btop-inspired)

Fifteen semantic attributes:

| Attribute | Meaning |
|-----------|---------|
| `crit_fg` | Critical badge text |
| `high_fg` | High badge text |
| `med_fg` | Medium badge text |
| `low_fg` | Low badge text |
| `selected_bg` | Selected list item background |
| `selected_fg` | Selected list item foreground |
| `match_hl` | Search match highlight |
| `border_active` | Active pane border |
| `border_inactive` | Inactive pane border |
| `header_fg` | Header bar text |
| `hint_fg` | Normal hint bar text |
| `hint_warn_fg` | Flash/disabled reason text |
| `heatmap_hit` | ▓ filled tactic |
| `heatmap_miss` | ░ empty tactic |
| `dataset_fg` | Dataset label |

Ships with 20 bundled themes (btop-adapted). User override: `~/.config/4n6query/theme.toml`.

Theme names: `default-dark`, `one-dark`, `dracula`, `gruvbox-dark`, `nord`, `solarized-dark`,
`solarized-light`, `tokyo-night`, `catppuccin-mocha`, `catppuccin-macchiato`, `catppuccin-frappe`,
`catppuccin-latte`, `everforest-dark`, `kanagawa`, `rose-pine`, `rose-pine-moon`, `monokai`,
`tomorrow-night`, `ayu-dark`, `horizon`.

---

## Feature 6: ATT&CK Tactic Heatmap (btop-repurposed)

14-char braille bar in the detail pane, below MITRE techniques:

```
Tactics: ▓░░░▓░░░▓░░░░░   TA0002 TA0005 TA0009
```

One char per tactic in ATT&CK Enterprise order:
`TA0043 TA0042 TA0001 TA0002 TA0003 TA0004 TA0005 TA0006 TA0007 TA0008 TA0009 TA0010 TA0011 TA0040`

Filled (`▓`, `heatmap_hit` colour) if any technique on this artifact maps to that tactic.  
Empty (`░`, `heatmap_miss` colour) otherwise.  
Active tactic IDs printed after the bar.

Technique → tactic mapping is prefix-based: `T1059.*` → TA0002.

---

## Feature 7: About Modal (`?` or `F1`)

Centred overlay, any key dismisses:

```
╭─────────────────────────────────────────╮
│           forensicnomicon TUI           │
│                                         │
│  Version:  0.1.0                        │
│  Catalog:  6,574 artifacts              │
│            1,190 LOLBin entries         │
│               52 abusable sites         │
│               11 playbooks              │
│                                         │
│  Author:   Albert Hui                   │
│  GitHub:   SecurityRonin/forensicnomicon│
│  License:  Apache-2.0                   │
│                                         │
│  Theme:    nord                         │
│                                         │
│          [press any key to close]       │
╰─────────────────────────────────────────╯
```

---

## Crate Structure

All TUI code in `crates/4n6query/src/tui/`:

```
tui/
  mod.rs       pub fn run() → Result<()>
  app.rs       App struct, pure state transitions (fully unit-testable)
  dataset.rs   Dataset enum, item adapters for all 9 sources
  search.rs    substring filter + scoring, flattened index
  guards.rs    Guard enum, evaluation → Option<&'static str>
  presets.rs   TriagePreset enum, cycling, filter application
  heatmap.rs   technique → tactic mask, braille renderer
  theme.rs     Theme struct, 20 bundled themes, user config loading
  ui.rs        ratatui render functions
  keys.rs      keybinding table, dispatch
```

New deps in `crates/4n6query/Cargo.toml`:
- `ratatui = "0.29"`
- `crossterm = "0.28"`
- `toml = "0.8"` (theme config parsing)

No feature flag — the binary always includes TUI. Library crate gets no new deps.

---

## Testing Strategy

- `app.rs`, `guards.rs`, `presets.rs`, `search.rs`, `heatmap.rs`, `theme.rs`: pure unit tests in `#[cfg(test)]` blocks, no terminal needed.
- `ui.rs`: ratatui `TestBackend` for render assertions.
- `main.rs`: TTY detection — tested by checking `run_tui` is called when `Cli` has no args (unit test, mocked TTY).

---

## Commit Plan

Each phase: one RED commit (failing tests) + one GREEN commit (minimal implementation).

1. chore: add ratatui, crossterm, toml deps
2. RED/GREEN: App state machine (`app.rs`)
3. RED/GREEN: Guard system (`guards.rs`)
4. RED/GREEN: Triage presets (`presets.rs`)
5. RED/GREEN: Search + Alt-N jump (`search.rs`)
6. RED/GREEN: ATT&CK tactic heatmap (`heatmap.rs`)
7. RED/GREEN: Theme system + 20 bundled themes (`theme.rs`)
8. RED/GREEN: About modal state (`app.rs` extension)
9. feat: TUI rendering + TTY dispatch (`ui.rs`, `keys.rs`, `mod.rs`, `main.rs`)
