# TUI Data Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the TUI navigator to real data — replace placeholder `.take(100)` with full, live catalog + 8 other datasets, apply search/preset filters, and render actual artifact detail.

**Architecture:** `run_inner()` in `mod.rs` builds `RenderData` (a plain struct of `Vec<String>` slices) from the current `App` state on every frame. All filtering (preset + search) happens in `build_render_data()`, a pure function that reads `CATALOG`, `LOLBAS_*`, `ABUSABLE_SITES`, `PLAYBOOKS`, and the active `Preset`. No data stored in `App`; it stays a pure state machine.

**Tech Stack:** Rust, ratatui 0.29, forensicnomicon catalog API, `search::filter()`, `presets::active()`

---

## Current state (what exists)

```
crates/4n6query/src/tui/mod.rs  — run_inner() has:
  list_items: Vec<String> = CATALOG.list().iter().take(100)...
  detail_lines: Vec<String> = ["Select an item to see details."]
  // Neither search, preset, nor dataset switching has any effect on data
```

## What changes

Only `crates/4n6query/src/tui/mod.rs` changes for Tasks 1–4.
No other TUI module is touched (they're already correct).

---

### Task 1: Add `RenderData` struct and `build_render_data()` skeleton

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`

**Step 1: Write the failing test**

Add to `mod.rs` in `#[cfg(test)]`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(dataset: usize, query: &str, preset: usize) -> app::App {
        let mut a = app::App::new();
        a.switch_dataset(dataset);
        a.query = query.to_string();
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
        assert!(!rd.list_items.is_empty(), "windows lolbins must be non-empty");
    }
}
```

**Step 2: Run to verify RED**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep -E "FAILED|error"
```

Expected: compile error — `build_render_data` doesn't exist yet.

**Step 3: Add `RenderData` struct + stub `build_render_data()`**

```rust
/// Frame-local render data built from App state on every tick.
pub struct RenderData {
    pub list_items: Vec<String>,
    pub detail_lines: Vec<String>,
    pub entry_count: usize,
}

fn build_render_data(app: &app::App) -> RenderData {
    RenderData {
        list_items: vec![],
        detail_lines: vec!["Select an item to see details.".into()],
        entry_count: 0,
    }
}
```

**Step 4: Run — still fails** (list_items is empty, asserts fail)

**Step 5: Commit (RED)**

```bash
git add crates/4n6query/src/tui/mod.rs
git commit -m "test(RED): build_render_data — full catalog + dataset routing"
```

---

### Task 2: Wire all 9 datasets into `build_render_data()`

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`

**Step 1: Implement dataset routing**

Replace the stub with:

```rust
fn build_render_data(app: &app::App) -> RenderData {
    use forensicnomicon::{
        abusable_sites::ABUSABLE_SITES,
        lolbins::{
            LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS, LOLBAS_WINDOWS_CMDLETS,
            LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
        },
        playbooks::PLAYBOOKS,
        catalog::CATALOG,
    };

    let list_items: Vec<String> = match app.dataset_idx {
        0 => CATALOG
            .list()
            .iter()
            .map(|d| format!("{:<36} [{:?}]", d.id, d.triage_priority))
            .collect(),
        1 => LOLBAS_WINDOWS.iter().map(|e| e.name.to_string()).collect(),
        2 => LOLBAS_LINUX.iter().map(|e| e.name.to_string()).collect(),
        3 => LOLBAS_MACOS.iter().map(|e| e.name.to_string()).collect(),
        4 => LOLBAS_WINDOWS_CMDLETS.iter().map(|e| e.name.to_string()).collect(),
        5 => LOLBAS_WINDOWS_MMC.iter().map(|e| e.name.to_string()).collect(),
        6 => LOLBAS_WINDOWS_WMI.iter().map(|e| e.name.to_string()).collect(),
        7 => ABUSABLE_SITES.iter().map(|s| s.domain.to_string()).collect(),
        8 => PLAYBOOKS.iter().map(|p| p.id.to_string()).collect(),
        _ => vec![],
    };

    let entry_count = list_items.len();

    RenderData {
        list_items,
        detail_lines: vec!["Select an item to see details.".into()],
        entry_count,
    }
}
```

**Step 2: Run to verify GREEN**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep "test result"
```

Expected: all tests pass.

**Step 3: Also update `run_inner()` to use `build_render_data()`**

Replace the placeholder block in `run_inner()`:

```rust
loop {
    app.tick_flash();
    let rd = build_render_data(&app);          // ← replaces hardcoded list_items

    terminal.draw(|f| {
        ui::draw(f, &app, theme, &rd.list_items, &rd.detail_lines);
    })?;
    // ...
}
```

Remove the old `let list_items` and `let detail_lines` bindings before the loop.

**Step 4: Compile check**

```bash
cargo build -p forensicnomicon-tui 2>&1 | grep "error"
```

**Step 5: Commit (GREEN)**

```bash
git add crates/4n6query/src/tui/mod.rs
git commit -m "feat(GREEN): wire all 9 datasets into build_render_data()"
```

---

### Task 3: Apply preset filter to catalog dataset

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn build_render_data_preset_windows_crit_filters() {
    let mut a = make_app(0, "", 1); // preset 1 = Windows CRIT
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
    // Every item must be a CRIT artifact
    for item in &rd.list_items {
        assert!(item.contains("Critical"), "item must be Critical: {item}");
    }
}
```

**Step 2: Run to verify RED**

```bash
cargo test -p forensicnomicon-tui --lib build_render_data_preset 2>&1 | tail -5
```

**Step 3: Apply preset in catalog branch**

```rust
use forensicnomicon::artifact::OsScope;

0 => {
    let preset = presets::active(app.preset_idx);
    CATALOG
        .list()
        .iter()
        .filter(|d| {
            // OS filter
            preset.os.map_or(true, |os| d.os_scope == os)
            // Priority filter
            && (preset.priorities.is_empty()
                || preset.priorities.contains(&d.triage_priority))
        })
        .map(|d| format!("{:<36} [{:?}]", d.id, d.triage_priority))
        .collect()
}
```

**Step 4: Verify GREEN**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep "test result"
```

**Step 5: Commit**

```bash
git add crates/4n6query/src/tui/mod.rs
git commit -m "feat(GREEN): apply preset filter (OS + priority) to catalog dataset"
```

---

### Task 4: Apply search filter across all datasets

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn build_render_data_search_filters_catalog() {
    let a = make_app(0, "prefetch", 0);
    let rd = build_render_data(&a);
    assert!(!rd.list_items.is_empty(), "search 'prefetch' must match something");
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
```

**Step 2: Run to verify RED**

**Step 3: Apply search after preset filter**

```rust
fn build_render_data(app: &app::App) -> RenderData {
    // ... build raw_items: Vec<(String, String)> where .0 = search index, .1 = display
    // Then apply search::filter() if query non-empty

    let all_display: Vec<String> = match app.dataset_idx { /* ... */ };

    let list_items = if app.query.is_empty() {
        all_display
    } else {
        let entries: Vec<search::SearchEntry> = all_display
            .iter()
            .enumerate()
            .map(|(i, s)| search::SearchEntry::new(s.clone(), i))
            .collect();
        let matched_indices = search::filter(&app.query, &entries);
        matched_indices
            .into_iter()
            .map(|i| all_display[i].clone())
            .collect()
    };

    RenderData {
        entry_count: list_items.len(),
        list_items,
        detail_lines: vec!["Select an item to see details.".into()],
    }
}
```

**Step 4: Verify GREEN**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep "test result"
cargo build -p forensicnomicon-tui 2>&1 | grep "error"
```

**Step 5: Commit**

```bash
git add crates/4n6query/src/tui/mod.rs
git commit -m "feat(GREEN): apply search filter across all TUI datasets"
```

---

### Task 5: Render actual artifact detail for selected catalog item

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`

**Step 1: Write the failing test**

```rust
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
```

**Step 2: Run to verify RED**

**Step 3: Build detail lines from `ArtifactDescriptor`**

In `build_render_data()`, after building `list_items`, derive `detail_lines`:

```rust
let detail_lines = if app.dataset_idx == 0 {
    // Look up the descriptor for the selected (filtered) catalog item
    let selected_id = list_items
        .get(app.selected)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|id| forensicnomicon::catalog::CATALOG.by_id(id));

    match selected_id {
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
```

**Step 4: Verify GREEN**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep "test result"
```

**Step 5: Commit**

```bash
git add crates/4n6query/src/tui/mod.rs
git commit -m "feat(GREEN): render artifact detail pane from selected catalog entry"
```

---

### Task 6: Theme config loading from `~/.config/4n6query/theme.toml`

**Files:**
- Modify: `crates/4n6query/src/tui/mod.rs`
- Read: `crates/4n6query/src/tui/theme.rs` — `load_user_config(toml_str)`, `by_name()`

**Step 1: Write the failing test**

In `theme.rs` tests, already covered by `load_user_config`. In `mod.rs`, add:

```rust
#[test]
fn load_theme_returns_default_on_missing_file() {
    let theme = load_theme();
    // Must not panic; must return a valid theme (all colors populated)
    assert_ne!(theme.crit_fg, ratatui::style::Color::Reset);
}
```

**Step 2: Run to verify RED** (function doesn't exist)

**Step 3: Implement `load_theme()`**

```rust
fn load_theme() -> &'static theme::Theme {
    let config_path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("4n6query")
        .join("theme.toml");

    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        if let Some(t) = theme::load_user_config(&contents) {
            return t;
        }
    }
    theme::ALL_THEMES[0]
}
```

Add `dirs = "5"` to `crates/4n6query/Cargo.toml` dependencies.

In `run_inner()`:
```rust
let theme = load_theme();  // replaces `theme::ALL_THEMES[0]`
```

**Step 4: Verify GREEN**

```bash
cargo test -p forensicnomicon-tui --lib 2>&1 | grep "test result"
cargo build -p forensicnomicon-tui 2>&1 | grep "error"
```

**Step 5: Commit**

```bash
git add crates/4n6query/Cargo.toml crates/4n6query/src/tui/mod.rs Cargo.lock
git commit -m "feat(GREEN): load theme from ~/.config/4n6query/theme.toml"
```

---

## Final integration test

```bash
cargo test --workspace 2>&1 | grep "test result"
# Then smoke-test the real binary:
cargo run -p forensicnomicon-tui -- 2>&1 | head -3
```

The TUI should launch, show the full catalog (~6,600 entries), respond to `/` search and `Ctrl-R` preset cycling with live filtering.
