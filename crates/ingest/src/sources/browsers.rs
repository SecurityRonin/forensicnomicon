//! Static browser artifact definitions.
//!
//! Each browser has 3–5 artifacts: history DB, profile directory,
//! cache directory, cookies, extensions.

use crate::record::{IngestRecord, IngestType};

/// Return all static browser artifact records.
pub fn browser_artifacts() -> Vec<IngestRecord> {
    vec![
        // ── Chrome ────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_chrome_history".to_string(),
            name: "Chrome History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History".to_string(),
            ),
            meaning: "Chrome browsing history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![
                "https://forensicswiki.xyz/wiki/index.php?title=Google_Chrome".to_string(),
            ],
        },
        IngestRecord {
            id: "browsers_chrome_profile_dir".to_string(),
            name: "Chrome Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default".to_string()),
            meaning: "Chrome user profile directory containing history, cookies, extensions.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_chrome_cookies".to_string(),
            name: "Chrome Cookies".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies".to_string(),
            ),
            meaning: "Chrome cookies SQLite database — may contain session tokens.".to_string(),
            mitre_techniques: vec!["T1539".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_chrome_cache_dir".to_string(),
            name: "Chrome Cache Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache".to_string()),
            meaning: "Chrome disk cache. May contain cached pages and files from visited sites.".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_chrome_extensions_dir".to_string(),
            name: "Chrome Extensions".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions".to_string(),
            ),
            meaning: "Chrome extensions directory. Malicious extensions may harvest credentials or intercept traffic.".to_string(),
            mitre_techniques: vec!["T1176".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Edge (Chromium) ───────────────────────────────────────────────
        IngestRecord {
            id: "browsers_edge_history".to_string(),
            name: "Edge (Chromium) History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History".to_string(),
            ),
            meaning: "Microsoft Edge (Chromium-based) browsing history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_edge_cookies".to_string(),
            name: "Edge (Chromium) Cookies".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies".to_string(),
            ),
            meaning: "Edge cookies database — may contain session tokens.".to_string(),
            mitre_techniques: vec!["T1539".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_edge_profile_dir".to_string(),
            name: "Edge Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default".to_string(),
            ),
            meaning: "Microsoft Edge user profile directory.".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Firefox ───────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_firefox_profile_dir".to_string(),
            name: "Firefox Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release".to_string()),
            meaning: "Firefox user profile directory — contains places.sqlite, cookies, logins.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![
                "https://forensicswiki.xyz/wiki/index.php?title=Mozilla_Firefox".to_string(),
            ],
        },
        IngestRecord {
            id: "browsers_firefox_places_db".to_string(),
            name: "Firefox Places (History) DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\places.sqlite".to_string(),
            ),
            meaning: "Firefox history, bookmarks, and downloads SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_firefox_cookies".to_string(),
            name: "Firefox Cookies".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite".to_string(),
            ),
            meaning: "Firefox cookies database — may contain active session tokens.".to_string(),
            mitre_techniques: vec!["T1539".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_firefox_logins".to_string(),
            name: "Firefox Saved Logins".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\logins.json".to_string(),
            ),
            meaning: "Firefox saved passwords (encrypted). If master password not set, decryptable.".to_string(),
            mitre_techniques: vec!["T1555.003".to_string()],
            triage_priority: "Critical".to_string(),
            sources: vec![],
        },
        // ── Brave ─────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_brave_history".to_string(),
            name: "Brave History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History"
                    .to_string(),
            ),
            meaning: "Brave browser browsing history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_brave_cookies".to_string(),
            name: "Brave Cookies".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"
                    .to_string(),
            ),
            meaning: "Brave cookies — may contain session tokens.".to_string(),
            mitre_techniques: vec!["T1539".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        // ── Opera ─────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_opera_history".to_string(),
            name: "Opera History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\Opera Software\Opera Stable\History".to_string(),
            ),
            meaning: "Opera (Chromium-based) browsing history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_opera_profile_dir".to_string(),
            name: "Opera Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Opera Software\Opera Stable".to_string()),
            meaning: "Opera browser user profile directory.".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Vivaldi ───────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_vivaldi_history".to_string(),
            name: "Vivaldi History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Vivaldi\User Data\Default\History".to_string(),
            ),
            meaning: "Vivaldi browsing history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_vivaldi_profile_dir".to_string(),
            name: "Vivaldi Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Vivaldi\User Data\Default".to_string()),
            meaning: "Vivaldi browser user profile directory.".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Safari (macOS) ────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_safari_history".to_string(),
            name: "Safari History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"~/Library/Safari/History.db".to_string(),
            ),
            meaning: "Safari browsing history SQLite database (macOS).".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_safari_cookies".to_string(),
            name: "Safari Cookies".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"~/Library/Cookies/Cookies.binarycookies".to_string()),
            meaning: "Safari cookies binary file (macOS) — may contain session tokens.".to_string(),
            mitre_techniques: vec!["T1539".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_safari_downloads".to_string(),
            name: "Safari Downloads Plist".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"~/Library/Safari/Downloads.plist".to_string()),
            meaning: "Safari download history plist (macOS).".to_string(),
            mitre_techniques: vec![],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Internet Explorer ─────────────────────────────────────────────
        IngestRecord {
            id: "browsers_ie_history_dir".to_string(),
            name: "Internet Explorer History".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Microsoft\Windows\History".to_string(),
            ),
            meaning: "Internet Explorer cached history (WebCache). Contains visited URLs.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_ie_webcache_db".to_string(),
            name: "Internet Explorer WebCache DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat".to_string(),
            ),
            meaning: "Internet Explorer / Edge Legacy WebCache ESE database — contains history, cookies, downloads.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![
                "https://www.sans.org/blog/how-to-use-ie-history-as-a-forensic-artifact/".to_string(),
            ],
        },
        IngestRecord {
            id: "browsers_ie_typed_urls".to_string(),
            name: "Internet Explorer Typed URLs".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::RegistryKey,
            hive: Some("HKCU".to_string()),
            key_path: r"Software\Microsoft\Internet Explorer\TypedURLs".to_string(),
            value_name: None,
            file_path: None,
            meaning: "URLs manually typed into the IE address bar (NTUSER.DAT).".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Tor Browser ───────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_tor_profile_dir".to_string(),
            name: "Tor Browser Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\tor-browser\Browser\TorBrowser\Data\Browser\profile.default".to_string(),
            ),
            meaning: "Tor Browser Firefox profile — usage indicates anonymous browsing intent.".to_string(),
            mitre_techniques: vec!["T1090".to_string(), "T1217".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        IngestRecord {
            id: "browsers_tor_places_db".to_string(),
            name: "Tor Browser Places DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(
                r"%APPDATA%\tor-browser\Browser\TorBrowser\Data\Browser\profile.default\places.sqlite".to_string(),
            ),
            meaning: "Tor Browser history database — may contain .onion URLs.".to_string(),
            mitre_techniques: vec!["T1090".to_string()],
            triage_priority: "High".to_string(),
            sources: vec![],
        },
        // ── Waterfox ──────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_waterfox_profile_dir".to_string(),
            name: "Waterfox Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Waterfox\Profiles\*.default".to_string()),
            meaning: "Waterfox (Firefox fork) user profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── LibreWolf ─────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_librewolf_profile_dir".to_string(),
            name: "LibreWolf Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\librewolf\Profiles\*.default".to_string()),
            meaning: "LibreWolf (privacy-focused Firefox fork) user profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Chromium ──────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_chromium_history".to_string(),
            name: "Chromium History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Chromium\User Data\Default\History".to_string()),
            meaning: "Open-source Chromium browser browsing history database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Medium".to_string(),
            sources: vec![],
        },
        // ── Pale Moon ─────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_palemoon_profile_dir".to_string(),
            name: "Pale Moon Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Moonchild Productions\Pale Moon\Profiles\*.default".to_string()),
            meaning: "Pale Moon (Goanna-based) browser user profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── SeaMonkey ─────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_seamonkey_profile_dir".to_string(),
            name: "SeaMonkey Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Mozilla\SeaMonkey\Profiles\*.default".to_string()),
            meaning: "SeaMonkey internet suite (browser + email) profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Basilisk ──────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_basilisk_profile_dir".to_string(),
            name: "Basilisk Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Moonchild Productions\Basilisk\Profiles\*.default".to_string()),
            meaning: "Basilisk (Goanna-based Firefox fork) browser profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Falkon ────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_falkon_profile_dir".to_string(),
            name: "Falkon Profile Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\falkon\profiles\default".to_string()),
            meaning: "Falkon (formerly QupZilla) Qt-based browser profile directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Midori ────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_midori_config_dir".to_string(),
            name: "Midori Config Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"~/.config/midori".to_string()),
            meaning: "Midori lightweight browser configuration and history (Linux/macOS).".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Min ───────────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_min_history_db".to_string(),
            name: "Min Browser History".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\min\userdata\history.db".to_string()),
            meaning: "Min (Electron-based minimalist browser) history SQLite database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Maxthon ───────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_maxthon_user_data_dir".to_string(),
            name: "Maxthon User Data Directory".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::Directory,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%APPDATA%\Maxthon5\Users\guest\History".to_string()),
            meaning: "Maxthon browser history directory.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
        // ── Slimjet ───────────────────────────────────────────────────────
        IngestRecord {
            id: "browsers_slimjet_history".to_string(),
            name: "Slimjet History DB".to_string(),
            source_name: "browsers",
            artifact_type: IngestType::File,
            hive: None,
            key_path: String::new(),
            value_name: None,
            file_path: Some(r"%LOCALAPPDATA%\Slimjet\User Data\Default\History".to_string()),
            meaning: "Slimjet (Chromium-based) browsing history database.".to_string(),
            mitre_techniques: vec!["T1217".to_string()],
            triage_priority: "Low".to_string(),
            sources: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_at_least_15_browsers_worth_of_artifacts() {
        let artifacts = browser_artifacts();
        // We cover 20+ browsers, each with 2-5 artifacts
        assert!(
            artifacts.len() >= 15,
            "expected >= 15 browser artifacts, got {}",
            artifacts.len()
        );
    }

    #[test]
    fn all_ids_are_unique_and_snake_case() {
        let artifacts = browser_artifacts();
        let mut seen = std::collections::HashSet::new();
        for rec in &artifacts {
            assert!(
                seen.insert(rec.id.clone()),
                "duplicate browser artifact ID: {}",
                rec.id
            );
            assert!(
                rec.id.starts_with("browsers_"),
                "ID missing browsers_ prefix: {}",
                rec.id
            );
            assert!(
                rec.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ID not snake_case: {}",
                rec.id
            );
        }
    }

    #[test]
    fn all_source_names_are_browsers() {
        let artifacts = browser_artifacts();
        for rec in &artifacts {
            assert_eq!(
                rec.source_name, "browsers",
                "wrong source_name for {}",
                rec.id
            );
        }
    }

    #[test]
    fn chrome_history_is_file_type() {
        let artifacts = browser_artifacts();
        let chrome = artifacts
            .iter()
            .find(|r| r.id == "browsers_chrome_history")
            .expect("no chrome history");
        assert_eq!(chrome.artifact_type, IngestType::File);
        assert!(chrome.file_path.is_some());
        assert!(chrome.file_path.as_deref().unwrap().contains("Chrome"));
    }

    #[test]
    fn firefox_logins_is_critical() {
        let artifacts = browser_artifacts();
        let logins = artifacts
            .iter()
            .find(|r| r.id == "browsers_firefox_logins")
            .expect("no firefox logins");
        assert_eq!(logins.triage_priority, "Critical");
    }

    #[test]
    fn cookies_have_high_or_critical_priority() {
        let artifacts = browser_artifacts();
        let cookies: Vec<_> = artifacts
            .iter()
            .filter(|r| r.id.contains("cookie"))
            .collect();
        assert!(!cookies.is_empty(), "expected at least one cookie artifact");
        for cookie in cookies {
            assert!(
                cookie.triage_priority == "High" || cookie.triage_priority == "Critical",
                "cookie artifact {} has low priority: {}",
                cookie.id,
                cookie.triage_priority
            );
        }
    }

    #[test]
    fn tor_browser_has_high_priority() {
        let artifacts = browser_artifacts();
        let tor: Vec<_> = artifacts
            .iter()
            .filter(|r| r.id.starts_with("browsers_tor_"))
            .collect();
        assert!(!tor.is_empty(), "expected tor browser artifacts");
        for t in tor {
            assert!(
                t.triage_priority == "High" || t.triage_priority == "Critical",
                "tor artifact {} has low priority: {}",
                t.id,
                t.triage_priority
            );
        }
    }

    #[test]
    fn covers_browsers_chrome_edge_firefox_brave_opera_vivaldi_safari_ie_tor() {
        let artifacts = browser_artifacts();
        let ids: Vec<&str> = artifacts.iter().map(|r| r.id.as_str()).collect();
        for expected_prefix in &[
            "browsers_chrome_",
            "browsers_edge_",
            "browsers_firefox_",
            "browsers_brave_",
            "browsers_opera_",
            "browsers_vivaldi_",
            "browsers_safari_",
            "browsers_ie_",
            "browsers_tor_",
        ] {
            assert!(
                ids.iter().any(|id| id.starts_with(expected_prefix)),
                "no artifacts for prefix {expected_prefix}"
            );
        }
    }
}
