//! Browser & embedded-Chromium container profile shapes and app attribution.
//!
//! This is the *knowledge* half of the discovery knowledge/engine split: pure
//! `&'static` data (no I/O, no filesystem, no allocation) describing (a) the
//! on-disk *shape* that marks a directory as a Chromium or Firefox profile, and
//! (b) an attribution catalog naming the desktop apps — real browsers plus the
//! sprawling embedded-Chromium ecosystem (Electron, WebView2, CEF) — that ship a
//! Chromium profile inside their user-data folder. The discovery *engine* (the
//! [browser-forensic](https://github.com/SecurityRonin/browser-forensic)
//! `browser-forensic-discovery` crate) consumes this table: it sweeps an evidence
//! tree, applies the [`CHROMIUM_PROFILE_MARKERS`] / [`FIREFOX_PROFILE_MARKERS`]
//! structural gate to each directory, and calls [`attribute_container`] to name a
//! match — a *structural* sweep, not an app allow-list, so an unknown-named
//! Chromium-shaped directory is still discovered (just generically labelled).
//!
//! `no_std`-safe: only compile-time constant tables and an alloc-free byte scan.
//! MSRV 1.75 (no `LazyLock`, no `let`-else, no 1.80+ APIs).
//!
//! # Sources
//!
//! - Chromium profile markers & the per-OS "User Data" default locations:
//!   [Chromium `user_data_dir.md`](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md).
//! - Electron user-data path (`app.getPath('userData')` = `appData` + app name;
//!   `appData` = `%APPDATA%` on Windows, `$XDG_CONFIG_HOME`/`~/.config` on Linux,
//!   `~/Library/Application Support` on macOS):
//!   [Electron `app` docs](https://www.electronjs.org/docs/latest/api/app).
//! - WebView2 user-data-folder (UDF) concept; Microsoft first-party WebView2 apps
//!   (OneDrive, new Outlook "Olk", Widgets, Copilot) name their UDF `EBWebView`:
//!   [WebView2 user data folder](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder).
//! - Attribution path tokens seeded from the Browser-Reviewer discovery sweep
//!   (`gustavoparedes/Browser-Reviewer`) and expanded across the Electron/CEF
//!   desktop-app ecosystem from each app's documented user-data location.
//!
//! Paths marked below as version/OS-specific are exactly that: a *hint*, not a
//! guarantee. Notable honest caveats — Telegram Desktop is Qt/`tdata`-based, NOT
//! Chromium, so it is deliberately absent; the newest WhatsApp on Windows ships
//! as a WebView2/Store package rather than the older Electron app; "new" Teams is
//! WebView2 while classic Teams was Electron (both catalogued).

// ---------------------------------------------------------------------------
// Profile-shape knowledge
// ---------------------------------------------------------------------------

/// Whether a profile marker names a file or a directory on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum MarkerKind {
    /// The marker is a regular file (e.g. `History`, `key4.db`).
    File,
    /// The marker is a directory (e.g. `IndexedDB`, `Local Storage/leveldb`).
    Dir,
}

/// One structural marker whose presence contributes to a profile match.
///
/// `relative_path` is relative to the candidate profile directory and may be
/// nested (e.g. `Local Storage/leveldb`, `Network/Cookies`); `kind` says whether
/// the engine should test for a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ProfileMarker {
    /// Path of the marker relative to the profile directory.
    pub relative_path: &'static str,
    /// Whether `relative_path` names a file or a directory.
    pub kind: MarkerKind,
}

/// Chromium profile signature: a directory is a Chromium profile if it contains
/// **any** one of these markers. Ordered cheapest/most-common first so an engine
/// can short-circuit on the first hit.
pub const CHROMIUM_PROFILE_MARKERS: &[ProfileMarker] = &[
    ProfileMarker {
        relative_path: "History",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "Bookmarks",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "Login Data",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "Web Data",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "Cookies",
        kind: MarkerKind::File,
    },
    // Chromium ≥ M96 moved the cookie store under `Network/`.
    ProfileMarker {
        relative_path: "Network/Cookies",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "Local Storage/leveldb",
        kind: MarkerKind::Dir,
    },
    ProfileMarker {
        relative_path: "Session Storage",
        kind: MarkerKind::Dir,
    },
    ProfileMarker {
        relative_path: "IndexedDB",
        kind: MarkerKind::Dir,
    },
    ProfileMarker {
        relative_path: "Extensions",
        kind: MarkerKind::Dir,
    },
    ProfileMarker {
        relative_path: "Sessions",
        kind: MarkerKind::Dir,
    },
];

/// Canonical Chromium artifact *filenames* found inside a profile (naming, for
/// attribution/inventory — not the signature gate). Session/tab state also uses
/// the numbered forms in [`CHROMIUM_SESSION_FILE_PREFIXES`].
pub const CHROMIUM_ARTIFACT_FILES: &[&str] = &[
    "History",
    "Bookmarks",
    "Login Data",
    "Web Data",
    "Preferences",
    "Local State",
    "Last Session",
    "Last Tabs",
    "Current Session",
    "Current Tabs",
];

/// Prefixes of the numbered Chromium session/tab snapshot files
/// (`Session_<timestamp>`, `Tabs_<timestamp>`).
pub const CHROMIUM_SESSION_FILE_PREFIXES: &[&str] = &["Session_", "Tabs_"];

/// Firefox profile signature: a directory is a Firefox profile if it contains
/// **any** one of these markers (plus any file with a
/// [`FIREFOX_PROFILE_MARKER_SUFFIXES`] extension).
pub const FIREFOX_PROFILE_MARKERS: &[ProfileMarker] = &[
    ProfileMarker {
        relative_path: "places.sqlite",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "formhistory.sqlite",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "cookies.sqlite",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "webappsstore.sqlite",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "logins.json",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "key4.db",
        kind: MarkerKind::File,
    },
    ProfileMarker {
        relative_path: "extensions.json",
        kind: MarkerKind::File,
    },
];

/// Firefox profile marker *extensions*: any file ending in one of these
/// (mozLz4 session/bookmark snapshots) also marks a Firefox profile.
pub const FIREFOX_PROFILE_MARKER_SUFFIXES: &[&str] = &[".jsonlz4", ".baklz4"];

/// The Chromium profile signature markers.
#[must_use]
pub const fn chromium_profile_markers() -> &'static [ProfileMarker] {
    CHROMIUM_PROFILE_MARKERS
}

/// The Firefox profile signature markers.
#[must_use]
pub const fn firefox_profile_markers() -> &'static [ProfileMarker] {
    FIREFOX_PROFILE_MARKERS
}

// ---------------------------------------------------------------------------
// App-attribution catalog
// ---------------------------------------------------------------------------

/// How an app hosts its embedded Chromium profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AppKind {
    /// A real web browser (Chrome, Edge, Brave, Firefox, …).
    Browser,
    /// An Electron app (bundles Chromium + Node; user data under `appData`).
    Electron,
    /// A Microsoft WebView2 host app (UDF, often named `EBWebView`).
    WebView2,
    /// A Chromium Embedded Framework host app (e.g. Steam, Spotify).
    Cef,
}

/// One entry in the embedded-Chromium attribution catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ContainerApp {
    /// Human-readable app name (e.g. `"Slack"`, `"OneDrive"`).
    pub name: &'static str,
    /// Vendor / publisher (e.g. `"Microsoft"`, `"OpenAI"`).
    pub vendor: &'static str,
    /// How the app embeds Chromium.
    pub kind: AppKind,
    /// Lowercased, forward-slash path substrings that attribute a container to
    /// this app. Matched case- and separator-insensitively by
    /// [`attribute_container`], with the candidate path treated as if wrapped in
    /// leading/trailing `/` so a token like `/slack/` anchors on folder
    /// boundaries.
    pub path_tokens: &'static [&'static str],
    /// macOS user-data base hints, relative to the user home.
    pub macos_bases: &'static [&'static str],
    /// Linux user-data base hints, relative to the user home.
    pub linux_bases: &'static [&'static str],
    /// Windows user-data base hints (`%LOCALAPPDATA%` / `%APPDATA%` notation).
    pub windows_bases: &'static [&'static str],
}

/// The embedded-Chromium / browser attribution catalog.
///
/// Tokens are stored lowercased with `/` separators and (where the app name is a
/// generic word) wrapped in slashes so [`attribute_container`] anchors them on
/// folder boundaries. More-specific entries are ordered before broader ones so
/// first-match attribution stays correct.
pub static CONTAINER_APPS: &[ContainerApp] = &[
    // --- Real browsers -----------------------------------------------------
    ContainerApp {
        name: "Google Chrome",
        vendor: "Google",
        kind: AppKind::Browser,
        path_tokens: &["/google/chrome/", "/google-chrome/"],
        macos_bases: &["Library/Application Support/Google/Chrome"],
        linux_bases: &[".config/google-chrome"],
        windows_bases: &[r"%LOCALAPPDATA%\Google\Chrome\User Data"],
    },
    ContainerApp {
        name: "Microsoft Edge",
        vendor: "Microsoft",
        kind: AppKind::Browser,
        path_tokens: &["/microsoft edge/", "/microsoft/edge/", "/microsoft-edge/"],
        macos_bases: &["Library/Application Support/Microsoft Edge"],
        linux_bases: &[".config/microsoft-edge"],
        windows_bases: &[r"%LOCALAPPDATA%\Microsoft\Edge\User Data"],
    },
    ContainerApp {
        name: "Brave",
        vendor: "Brave Software",
        kind: AppKind::Browser,
        path_tokens: &["/bravesoftware/brave-browser/", "/brave-browser/"],
        macos_bases: &["Library/Application Support/BraveSoftware/Brave-Browser"],
        linux_bases: &[".config/BraveSoftware/Brave-Browser"],
        windows_bases: &[r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"],
    },
    ContainerApp {
        name: "Vivaldi",
        vendor: "Vivaldi Technologies",
        kind: AppKind::Browser,
        path_tokens: &["/vivaldi/"],
        macos_bases: &["Library/Application Support/Vivaldi"],
        linux_bases: &[".config/vivaldi"],
        windows_bases: &[r"%LOCALAPPDATA%\Vivaldi\User Data"],
    },
    ContainerApp {
        name: "Opera",
        vendor: "Opera Software",
        kind: AppKind::Browser,
        path_tokens: &[
            "/com.operasoftware.opera/",
            "/opera software/",
            "/opera stable/",
        ],
        macos_bases: &["Library/Application Support/com.operasoftware.Opera"],
        linux_bases: &[".config/opera"],
        windows_bases: &[r"%APPDATA%\Opera Software\Opera Stable"],
    },
    ContainerApp {
        name: "Arc",
        vendor: "The Browser Company",
        kind: AppKind::Browser,
        path_tokens: &["/arc/user data/"],
        macos_bases: &["Library/Application Support/Arc/User Data"],
        linux_bases: &[],
        windows_bases: &[
            r"%LOCALAPPDATA%\Packages\TheBrowserCompany.Arc_*\LocalCache\Local\Arc\User Data",
        ],
    },
    ContainerApp {
        name: "Yandex Browser",
        vendor: "Yandex",
        kind: AppKind::Browser,
        path_tokens: &["/yandex/yandexbrowser/", "/yandexbrowser/"],
        macos_bases: &["Library/Application Support/Yandex/YandexBrowser"],
        linux_bases: &[".config/yandex-browser"],
        windows_bases: &[r"%LOCALAPPDATA%\Yandex\YandexBrowser\User Data"],
    },
    ContainerApp {
        name: "Chromium",
        vendor: "The Chromium Project",
        kind: AppKind::Browser,
        path_tokens: &["/chromium/"],
        macos_bases: &["Library/Application Support/Chromium"],
        linux_bases: &[".config/chromium"],
        windows_bases: &[r"%LOCALAPPDATA%\Chromium\User Data"],
    },
    ContainerApp {
        name: "Mozilla Firefox",
        vendor: "Mozilla",
        kind: AppKind::Browser,
        path_tokens: &[
            "/firefox/profiles/",
            "/mozilla/firefox/",
            "/.mozilla/firefox/",
        ],
        macos_bases: &["Library/Application Support/Firefox/Profiles"],
        linux_bases: &[".mozilla/firefox"],
        windows_bases: &[r"%APPDATA%\Mozilla\Firefox\Profiles"],
    },
    // --- WebView2 (Microsoft first-party EBWebView hosts) ------------------
    ContainerApp {
        name: "OneDrive",
        vendor: "Microsoft",
        kind: AppKind::WebView2,
        // The UDF sits under a version subfolder (…\OneDrive\<version>\EBWebView),
        // so anchor on the OneDrive folder rather than requiring EBWebView adjacent.
        path_tokens: &["/microsoft/onedrive/", "/onedrive/ebwebview/"],
        macos_bases: &[],
        linux_bases: &[],
        windows_bases: &[r"%LOCALAPPDATA%\Microsoft\OneDrive\<version>\EBWebView"],
    },
    ContainerApp {
        name: "New Outlook",
        vendor: "Microsoft",
        kind: AppKind::WebView2,
        path_tokens: &["/microsoft/olk/", "/olk/ebwebview/"],
        macos_bases: &[],
        linux_bases: &[],
        windows_bases: &[r"%LOCALAPPDATA%\Microsoft\Olk\EBWebView"],
    },
    ContainerApp {
        name: "Windows Widgets",
        vendor: "Microsoft",
        kind: AppKind::WebView2,
        path_tokens: &[
            "/microsoftwindows.client.webexperience",
            "/widgets/ebwebview/",
        ],
        macos_bases: &[],
        linux_bases: &[],
        windows_bases: &[
            r"%LOCALAPPDATA%\Packages\MicrosoftWindows.Client.WebExperience_*\LocalState\EBWebView",
        ],
    },
    ContainerApp {
        name: "Microsoft Copilot",
        vendor: "Microsoft",
        kind: AppKind::WebView2,
        path_tokens: &["/microsoft.copilot", "/copilot/ebwebview/"],
        macos_bases: &[],
        linux_bases: &[],
        windows_bases: &[r"%LOCALAPPDATA%\Packages\Microsoft.Copilot_*\LocalCache\...\EBWebView"],
    },
    ContainerApp {
        name: "Microsoft Teams (new)",
        vendor: "Microsoft",
        kind: AppKind::WebView2,
        path_tokens: &["/msteams_", "/microsoft teams/ebwebview/"],
        macos_bases: &[],
        linux_bases: &[],
        windows_bases: &[r"%LOCALAPPDATA%\Packages\MSTeams_*\LocalCache\...\EBWebView"],
    },
    // --- Electron ----------------------------------------------------------
    ContainerApp {
        name: "Slack",
        vendor: "Slack Technologies",
        kind: AppKind::Electron,
        path_tokens: &["/slack/"],
        macos_bases: &["Library/Application Support/Slack"],
        linux_bases: &[".config/Slack"],
        windows_bases: &[r"%APPDATA%\Slack"],
    },
    ContainerApp {
        name: "Discord",
        vendor: "Discord",
        kind: AppKind::Electron,
        path_tokens: &["/discord/", "/discordcanary/", "/discordptb/"],
        macos_bases: &["Library/Application Support/discord"],
        linux_bases: &[".config/discord"],
        windows_bases: &[r"%APPDATA%\discord"],
    },
    ContainerApp {
        name: "Microsoft Teams (classic)",
        vendor: "Microsoft",
        kind: AppKind::Electron,
        path_tokens: &["/microsoft/teams/"],
        macos_bases: &["Library/Application Support/Microsoft/Teams"],
        linux_bases: &[".config/Microsoft/Microsoft Teams"],
        windows_bases: &[r"%APPDATA%\Microsoft\Teams"],
    },
    ContainerApp {
        name: "Signal Desktop",
        vendor: "Signal",
        kind: AppKind::Electron,
        path_tokens: &["/signal/"],
        macos_bases: &["Library/Application Support/Signal"],
        linux_bases: &[".config/Signal"],
        windows_bases: &[r"%APPDATA%\Signal"],
    },
    ContainerApp {
        // The older Electron WhatsApp; the newest Windows build ships as a
        // WebView2/Store package instead — path is version-specific.
        name: "WhatsApp Desktop",
        vendor: "Meta",
        kind: AppKind::Electron,
        path_tokens: &["/whatsapp/"],
        macos_bases: &["Library/Application Support/WhatsApp"],
        linux_bases: &[],
        windows_bases: &[r"%APPDATA%\WhatsApp"],
    },
    ContainerApp {
        name: "Visual Studio Code",
        vendor: "Microsoft",
        kind: AppKind::Electron,
        path_tokens: &["/code/", "/code - insiders/", "/vscode/"],
        macos_bases: &["Library/Application Support/Code"],
        linux_bases: &[".config/Code"],
        windows_bases: &[r"%APPDATA%\Code"],
    },
    ContainerApp {
        name: "OpenAI Codex",
        vendor: "OpenAI",
        kind: AppKind::Electron,
        path_tokens: &[
            "/openai.codex_",
            "/localcache/roaming/codex/",
            "/roaming/codex/",
        ],
        macos_bases: &["Library/Application Support/Codex"],
        linux_bases: &[".config/Codex"],
        windows_bases: &[r"%LOCALAPPDATA%\Packages\openai.codex_*\LocalCache\Roaming\Codex"],
    },
    ContainerApp {
        name: "Notion",
        vendor: "Notion Labs",
        kind: AppKind::Electron,
        path_tokens: &["/notion/"],
        macos_bases: &["Library/Application Support/Notion"],
        linux_bases: &[".config/Notion"],
        windows_bases: &[r"%APPDATA%\Notion"],
    },
    ContainerApp {
        name: "1Password",
        vendor: "AgileBits",
        kind: AppKind::Electron,
        path_tokens: &["/1password/"],
        macos_bases: &["Library/Application Support/1Password"],
        linux_bases: &[".config/1Password"],
        windows_bases: &[r"%LOCALAPPDATA%\1Password"],
    },
    ContainerApp {
        name: "Obsidian",
        vendor: "Obsidian",
        kind: AppKind::Electron,
        path_tokens: &["/obsidian/"],
        macos_bases: &["Library/Application Support/obsidian"],
        linux_bases: &[".config/obsidian"],
        windows_bases: &[r"%APPDATA%\obsidian"],
    },
    ContainerApp {
        name: "GitHub Desktop",
        vendor: "GitHub",
        kind: AppKind::Electron,
        path_tokens: &["/github desktop/"],
        macos_bases: &["Library/Application Support/GitHub Desktop"],
        linux_bases: &[".config/GitHub Desktop"],
        windows_bases: &[r"%APPDATA%\GitHub Desktop"],
    },
    ContainerApp {
        name: "Postman",
        vendor: "Postman",
        kind: AppKind::Electron,
        path_tokens: &["/postman/"],
        macos_bases: &["Library/Application Support/Postman"],
        linux_bases: &[".config/Postman"],
        windows_bases: &[r"%APPDATA%\Postman"],
    },
    ContainerApp {
        name: "Figma",
        vendor: "Figma",
        kind: AppKind::Electron,
        path_tokens: &["/figma/"],
        macos_bases: &["Library/Application Support/Figma"],
        linux_bases: &[],
        windows_bases: &[r"%APPDATA%\Figma"],
    },
    ContainerApp {
        name: "Element",
        vendor: "Element",
        kind: AppKind::Electron,
        path_tokens: &["/element/"],
        macos_bases: &["Library/Application Support/Element"],
        linux_bases: &[".config/Element"],
        windows_bases: &[r"%APPDATA%\Element"],
    },
    ContainerApp {
        name: "Skype",
        vendor: "Microsoft",
        kind: AppKind::Electron,
        path_tokens: &["/microsoft/skype for desktop/", "/skype for desktop/"],
        macos_bases: &["Library/Application Support/Microsoft/Skype for Desktop"],
        linux_bases: &[".config/skypeforlinux"],
        windows_bases: &[r"%APPDATA%\Microsoft\Skype for Desktop"],
    },
    // --- CEF (Chromium Embedded Framework) ---------------------------------
    ContainerApp {
        name: "Steam",
        vendor: "Valve",
        kind: AppKind::Cef,
        path_tokens: &["/steam/htmlcache/", "/steam/config/htmlcache/"],
        macos_bases: &["Library/Application Support/Steam/config/htmlcache"],
        linux_bases: &[".local/share/Steam/config/htmlcache"],
        windows_bases: &[
            r"%LOCALAPPDATA%\Steam\htmlcache",
            r"<SteamInstall>\config\htmlcache",
        ],
    },
    ContainerApp {
        name: "Spotify",
        vendor: "Spotify",
        kind: AppKind::Cef,
        path_tokens: &["/spotify/"],
        macos_bases: &["Library/Application Support/Spotify"],
        linux_bases: &[".config/spotify"],
        windows_bases: &[r"%APPDATA%\Spotify"],
    },
];

/// Normalize one path byte for matching: `\` → `/`, then ASCII-lowercase.
const fn norm_byte(b: u8) -> u8 {
    let b = if b == b'\\' { b'/' } else { b };
    b.to_ascii_lowercase()
}

/// Does `token` (already lowercased, `/`-separated) occur in `path`, matched
/// case- and separator-insensitively? The path is treated as if wrapped in a
/// leading and trailing `/` so a slash-anchored token (`/slack/`) hits on folder
/// boundaries without matching `/slackware/`. Zero-alloc / `no_std`-safe.
fn path_contains(path: &str, token: &str) -> bool {
    let t = token.as_bytes();
    if t.is_empty() {
        return true;
    }
    let h = path.as_bytes();
    // Virtual haystack = '/' + normalized(h) + '/', of length h.len() + 2.
    let vlen = h.len() + 2;
    if t.len() > vlen {
        return false;
    }
    let vbyte = |i: usize| -> u8 {
        if i == 0 || i == vlen - 1 {
            b'/'
        } else {
            norm_byte(h[i - 1])
        }
    };
    let last_start = vlen - t.len();
    let mut start = 0;
    while start <= last_start {
        let mut j = 0;
        let mut hit = true;
        while j < t.len() {
            if vbyte(start + j) != t[j] {
                hit = false;
                break;
            }
            j += 1;
        }
        if hit {
            return true;
        }
        start += 1;
    }
    false
}

/// Attribute a discovered container path to a known app by substring match.
///
/// Returns the first [`ContainerApp`] whose any `path_tokens` entry occurs in
/// `path` (case- and separator-insensitive). `None` means the container is
/// unattributed — the caller still treats it as a discovered profile, just with
/// a generic label.
#[must_use]
pub fn attribute_container(path: &str) -> Option<&'static ContainerApp> {
    CONTAINER_APPS
        .iter()
        .find(|app| app.path_tokens.iter().any(|t| path_contains(path, t)))
}

#[cfg(test)]
mod tests {

    #[test]
    fn path_contains_empty_token_is_true() {
        assert!(path_contains(r"c:\users\bob", ""));
    }
    use super::*;

    fn marker(markers: &[ProfileMarker], rel: &str) -> Option<MarkerKind> {
        markers
            .iter()
            .find(|m| m.relative_path == rel)
            .map(|m| m.kind)
    }

    #[test]
    fn chromium_markers_cover_signature_set() {
        let m = chromium_profile_markers();
        assert_eq!(marker(m, "History"), Some(MarkerKind::File));
        assert_eq!(marker(m, "Login Data"), Some(MarkerKind::File));
        assert_eq!(marker(m, "Web Data"), Some(MarkerKind::File));
        assert_eq!(marker(m, "Cookies"), Some(MarkerKind::File));
        assert_eq!(marker(m, "Network/Cookies"), Some(MarkerKind::File));
        assert_eq!(marker(m, "Local Storage/leveldb"), Some(MarkerKind::Dir));
        assert_eq!(marker(m, "Session Storage"), Some(MarkerKind::Dir));
        assert_eq!(marker(m, "IndexedDB"), Some(MarkerKind::Dir));
        assert_eq!(marker(m, "Extensions"), Some(MarkerKind::Dir));
        assert_eq!(marker(m, "Sessions"), Some(MarkerKind::Dir));
    }

    #[test]
    fn chromium_artifact_filenames_present() {
        for f in [
            "History",
            "Bookmarks",
            "Login Data",
            "Web Data",
            "Preferences",
            "Local State",
        ] {
            assert!(CHROMIUM_ARTIFACT_FILES.contains(&f), "missing {f}");
        }
        assert!(CHROMIUM_SESSION_FILE_PREFIXES.contains(&"Session_"));
        assert!(CHROMIUM_SESSION_FILE_PREFIXES.contains(&"Tabs_"));
    }

    #[test]
    fn firefox_markers_cover_signature_set() {
        let m = firefox_profile_markers();
        for rel in [
            "places.sqlite",
            "formhistory.sqlite",
            "cookies.sqlite",
            "webappsstore.sqlite",
            "logins.json",
            "key4.db",
            "extensions.json",
        ] {
            assert_eq!(marker(m, rel), Some(MarkerKind::File), "missing {rel}");
        }
        assert!(FIREFOX_PROFILE_MARKER_SUFFIXES.contains(&".jsonlz4"));
        assert!(FIREFOX_PROFILE_MARKER_SUFFIXES.contains(&".baklz4"));
    }

    #[test]
    fn catalog_is_reasonably_sized_with_unique_names() {
        assert!(
            CONTAINER_APPS.len() >= 25,
            "expected a broad catalog, got {}",
            CONTAINER_APPS.len() // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        for (i, a) in CONTAINER_APPS.iter().enumerate() {
            for b in &CONTAINER_APPS[i + 1..] {
                assert_ne!(a.name, b.name, "duplicate app name {}", a.name);
            }
        }
    }

    #[test]
    fn every_app_has_lowercase_forward_slash_tokens() {
        for a in CONTAINER_APPS {
            assert!(!a.path_tokens.is_empty(), "{} has no tokens", a.name);
            for t in a.path_tokens {
                assert!(!t.is_empty(), "{} has empty token", a.name);
                assert!(!t.contains('\\'), "{} token {t:?} uses a backslash", a.name);
                assert_eq!(
                    *t,
                    t.to_lowercase(),
                    "{} token {t:?} is not lowercased",
                    a.name
                );
            }
        }
    }

    #[test]
    fn catalog_covers_every_app_kind() {
        let has = |k: AppKind| CONTAINER_APPS.iter().any(|a| a.kind == k);
        assert!(has(AppKind::Browser));
        assert!(has(AppKind::Electron));
        assert!(has(AppKind::WebView2));
        assert!(has(AppKind::Cef));
    }

    #[test]
    fn attribute_onedrive_webview2() {
        let p =
            r"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\25.100.0511.0002\EBWebView\Default";
        let app = attribute_container(p).expect("OneDrive attributed");
        assert_eq!(app.name, "OneDrive");
        assert_eq!(app.kind, AppKind::WebView2);
    }

    #[test]
    fn attribute_new_outlook_olk() {
        let p =
            r"C:\Users\jdoe\AppData\Local\Microsoft\Olk\EBWebView\Default\Local Storage\leveldb";
        let app = attribute_container(p).expect("Outlook attributed");
        assert_eq!(app.vendor, "Microsoft");
        assert_eq!(app.kind, AppKind::WebView2);
    }

    #[test]
    fn attribute_openai_codex() {
        let p = r"C:\Users\jdoe\AppData\Local\Packages\openai.codex_2sxk9q1abc\LocalCache\Roaming\Codex";
        let app = attribute_container(p).expect("Codex attributed");
        assert_eq!(app.vendor, "OpenAI");
    }

    #[test]
    fn attribute_steam_htmlcache_is_cef() {
        let p = r"C:\Program Files (x86)\Steam\config\htmlcache\Local Storage\leveldb";
        let app = attribute_container(p).expect("Steam attributed");
        assert_eq!(app.name, "Steam");
        assert_eq!(app.kind, AppKind::Cef);
    }

    #[test]
    fn attribute_slack_electron_macos() {
        let p = "/Users/jdoe/Library/Application Support/Slack/Local Storage/leveldb";
        let app = attribute_container(p).expect("Slack attributed");
        assert_eq!(app.name, "Slack");
        assert_eq!(app.kind, AppKind::Electron);
    }

    #[test]
    fn attribute_is_case_and_separator_insensitive() {
        let a = attribute_container("/users/x/library/application support/slack");
        let b = attribute_container(r"C:\Users\X\AppData\Roaming\SLACK");
        assert_eq!(a.map(|c| c.name), Some("Slack"));
        assert_eq!(b.map(|c| c.name), Some("Slack"));
    }

    #[test]
    fn code_token_does_not_misattribute_codex() {
        // The VS Code `/code/` token must not swallow an `openai.codex_` path.
        let p = r"C:\Users\x\AppData\Local\Packages\openai.codex_abc\LocalCache\Roaming\Codex";
        let app = attribute_container(p).expect("attributed");
        assert_eq!(app.vendor, "OpenAI", "codex misattributed to {}", app.name);
    }

    #[test]
    fn attribute_unknown_returns_none() {
        assert!(attribute_container("/tmp/some/random/folder/Default").is_none());
        assert!(attribute_container("").is_none());
    }
}
