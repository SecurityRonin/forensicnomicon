//! ID normalization for generated artifact identifiers.

use std::collections::HashSet;

/// Known hive prefixes (long and short forms) to strip from registry paths.
/// For per-user hives (HKCU/NTUSER) the common `Software\` sub-key is also
/// stripped since it adds no forensic discrimination.
const HIVE_PREFIXES: &[&str] = &[
    // HKCU / NTUSER — strip Software\ too (very common, adds no info)
    r"HKEY_CURRENT_USER\Software\",
    r"HKCU\Software\",
    // HKLM — keep sub-hive (SYSTEM\, SOFTWARE\, etc.) for disambiguation
    r"HKEY_LOCAL_MACHINE\",
    r"HKEY_CLASSES_ROOT\",
    r"HKEY_USERS\",
    r"HKLM\",
    r"HKCU\",
    r"HKCR\",
    r"HKU\",
];

/// Maximum allowed length for a generated ID.
const MAX_ID_LEN: usize = 60;

/// Strip hive prefix (case-insensitive) from a registry path.
/// Returns the portion after the hive prefix.
fn strip_hive_prefix(path: &str) -> &str {
    let upper = path.to_ascii_uppercase();
    for prefix in HIVE_PREFIXES {
        let prefix_upper = prefix.to_ascii_uppercase();
        if upper.starts_with(&prefix_upper) {
            return &path[prefix.len()..];
        }
    }
    path
}

/// Take the last N components of a backslash-separated path.
fn last_n_components(path: &str, n: usize) -> String {
    let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
    let take = parts.len().min(n);
    let start = parts.len().saturating_sub(take);
    parts[start..].join("_")
}

/// Convert an arbitrary string to snake_case safe for Rust identifiers.
pub fn to_snake_case(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '_',
        })
        .collect::<String>()
        // collapse consecutive underscores
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Generate a normalized ID for a registry artifact.
///
/// - Strips hive prefix
/// - Takes last 4 path components (to stay within 60 chars)
/// - Converts to snake_case
/// - Prepends source prefix
/// - Truncates to MAX_ID_LEN
pub fn normalize_registry_id(path: &str, source: &str) -> String {
    let stripped = strip_hive_prefix(path);
    let components = last_n_components(stripped, 3);
    let snake = to_snake_case(&components);
    let raw = format!("{source}_{snake}");
    truncate_id(raw)
}

/// Like `normalize_registry_id` but ensures uniqueness against an existing set.
/// Appends `_2`, `_3`, etc. until unique.
pub fn normalize_registry_id_unique(
    path: &str,
    source: &str,
    existing: &HashSet<String>,
) -> String {
    let base = normalize_registry_id(path, source);
    if !existing.contains(&base) {
        return base;
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}_{n}");
        if !existing.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Generate a normalized ID for a file or directory artifact.
///
/// - Takes the last 2–3 path components
/// - Converts to snake_case
/// - Prepends source + `_file_` or `_dir_`
/// - Truncates to MAX_ID_LEN
pub fn normalize_file_id(path: &str, source: &str, is_dir: bool) -> String {
    // Normalize separators to backslash for uniform splitting
    let unified = path.replace('/', "\\");
    let components = last_n_components(&unified, 2);
    let snake = to_snake_case(&components);
    let kind = if is_dir { "dir" } else { "file" };
    let raw = format!("{source}_{kind}_{snake}");
    truncate_id(raw)
}

/// Truncate an ID to MAX_ID_LEN, preserving the full prefix if possible.
fn truncate_id(id: String) -> String {
    if id.len() <= MAX_ID_LEN {
        id
    } else {
        id[..MAX_ID_LEN].trim_end_matches('_').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hklm_software_path() {
        let id = normalize_registry_id(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "kape",
        );
        assert_eq!(id, "kape_windows_currentversion_run");
    }

    #[test]
    fn normalize_hkcu_path() {
        let id =
            normalize_registry_id(r"HKCU\Software\Microsoft\Terminal Server Client", "regedit");
        assert_eq!(id, "regedit_microsoft_terminal_server_client");
    }

    #[test]
    fn normalize_hkey_local_machine_system_path() {
        let id = normalize_registry_id(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp",
            "regedit",
        );
        assert_eq!(id, "regedit_portproxy_v4tov4_tcp");
    }

    #[test]
    fn normalize_strips_hive_prefix() {
        let id = normalize_registry_id(r"HKLM\SYSTEM\Select", "kape");
        assert_eq!(id, "kape_system_select");
    }

    #[test]
    fn normalize_replaces_special_chars() {
        let id = normalize_registry_id(r"HKCU\Software\Classes\.exe\OpenWithProgids", "fa");
        // dots become underscores, backslashes become underscores
        assert!(id.starts_with("fa_"));
        assert!(!id.contains('\\'));
        assert!(!id.contains('.'));
    }

    #[test]
    fn normalize_truncates_long_ids() {
        let long_path = format!(
            r"HKLM\SOFTWARE\{}\{}\{}\{}\{}",
            "A".repeat(20),
            "B".repeat(20),
            "C".repeat(20),
            "D".repeat(20),
            "E".repeat(20)
        );
        let id = normalize_registry_id(&long_path, "test");
        assert!(id.len() <= 60, "ID too long: {} chars", id.len());
    }

    #[test]
    fn normalize_file_id_basic() {
        let id = normalize_file_id(
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            "fa",
            false,
        );
        assert_eq!(id, "fa_file_logs_security_evtx");
    }

    #[test]
    fn normalize_file_id_directory() {
        let id = normalize_file_id(
            r"C:\Users\%user%\AppData\Local\Google\Chrome\User Data",
            "kape",
            true,
        );
        assert_eq!(id, "kape_dir_chrome_user_data");
    }

    #[test]
    fn normalize_makes_snake_case() {
        let id = normalize_registry_id(r"HKLM\SOFTWARE\Microsoft Office\16.0", "regedit");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "ID contains non-snake-case chars: {id}"
        );
    }

    #[test]
    fn unique_suffix_on_collision() {
        // The base ID for this path is kape_windows_currentversion_run.
        // Simulate it already being in the set.
        let existing: HashSet<String> = ["kape_windows_currentversion_run".to_string()]
            .into_iter()
            .collect();
        let id = normalize_registry_id_unique(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "kape",
            &existing,
        );
        assert_eq!(id, "kape_windows_currentversion_run_2");
    }
}
