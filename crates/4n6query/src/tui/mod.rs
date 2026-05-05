pub mod app;
pub mod dataset;
pub mod guards;
pub mod heatmap;
pub mod keys;
pub mod presets;
pub mod search;
pub mod theme;
pub mod ui;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

/// Launch the interactive TUI navigator.
///
/// Called when `4n6query` is invoked with no arguments on a TTY.
/// Returns 0 on clean exit, 1 on error.
pub fn run() -> i32 {
    if let Err(e) = run_inner() {
        eprintln!("tui error: {e}");
        1
    } else {
        0
    }
}

fn run_inner() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::App::new();
    let theme = theme::ALL_THEMES[0]; // default theme

    // Placeholder data until full data integration
    let list_items: Vec<String> = forensicnomicon::catalog::CATALOG
        .list()
        .iter()
        .take(100)
        .map(|d| format!("{:<30} {:?}", d.id, d.triage_priority))
        .collect();
    let detail_lines: Vec<String> = vec!["Select an item to see details.".into()];

    loop {
        app.tick_flash();

        terminal.draw(|f| {
            ui::draw(f, &app, theme, &list_items, &detail_lines);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if keys::handle_key(&mut app, key, list_items.len()) {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
