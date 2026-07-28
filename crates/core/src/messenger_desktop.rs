//! **Desktop instant-messenger** artifact specs — Discord, Signal, Wire, WhatsApp.
//!
//! Where each desktop messenger keeps its evidence on disk, per OS: the profile
//! base directory, and which store within it holds messages, the account
//! identity/token, contacts, attachments, and the encryption key. This is the
//! KNOWLEDGE leaf a chat-artifact reader consults before it opens anything.
//!
//! This module is **facts only** — path templates, store roles, formats, and the
//! encryption posture. It performs no I/O and decodes nothing; the reader that
//! opens the SQLCipher DB, walks the Chromium LevelDB, or carves the Simple Cache
//! lives in the consuming crate (`browser-forensic` / a messenger carver).
//!
//! # Two architectures, two storage shapes
//!
//! Discord, Signal, and Wire are **Electron/Chromium** apps: their data lives in
//! Chromium storage under the standard Electron `userData` directory (Windows
//! `%AppData%`, macOS `~/Library/Application Support`, Linux `~/.config`, each
//! appended with the app name). See [`chromium_simple_cache`], [`chromium_indexeddb`],
//! and [`chromium_local_storage`] for those on-disk formats. WhatsApp Desktop is a
//! **native** app (a Windows Store UWP/WebView2 client, a macOS Catalyst client)
//! that keeps SEE/DPAPI-encrypted SQLite instead.
//!
//! Not every messenger keeps messages locally: Discord holds **no local message
//! database** — chats are fetched from the server and only *cached* — so its
//! recoverable message evidence is the Simple Cache, not a chat DB.
//!
//! [`chromium_simple_cache`]: crate::chromium_simple_cache
//! [`chromium_indexeddb`]: crate::chromium_indexeddb
//! [`chromium_local_storage`]: crate::chromium_local_storage
//!
//! # Authoritative sources
//!
//! - Signal — Alexander Bilz, *A Forensic Gold Mine II: Forensic Analysis of
//!   Signal Messenger on Windows 10* (profile dirs, `sql/db.sqlite`, `config.json`,
//!   `attachments.noindex`, LevelDB/IndexedDB paths):
//!   <https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/>
//! - Discord — forensafe *Discord* artifact profile (`%AppData%\discord\Cache`):
//!   <https://www.forensafe.com/blogs/discord.html>; AhnLab ASEC (the
//!   `Local Storage\leveldb` token paths + `discordptb`/`discordcanary` variants):
//!   <https://asec.ahnlab.com/en/24512/>; Sankara Narayanan, *Simple Forensic
//!   Analysis on Discord in Windows 10* (the `%AppData%\discord` directory listing):
//!   <https://sankara-ns.medium.com/simple-forensic-analysis-on-discord-in-windows-10-d530506dcd81>
//! - Wire — hunjison, *Forensic Analysis of Wire Messenger in Windows OS* (the
//!   `IndexedDB\https_app.wire.com_0.indexeddb.leveldb` store + the `otr_key`):
//!   <https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS>
//! - WhatsApp — Alberto Magno, *WhatsApp Desktop (WEBVIEW2 and UWP Archs) and Web
//!   live forensics* (the `5319275A.WhatsAppDesktop` LocalState package,
//!   `genericStorageDB`, `Session.db`, SEE/DPAPI-NG encryption):
//!   <https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3>;
//!   Belkasoft, *WhatsApp Forensics on Computers* (the macOS
//!   `~/Library/Containers/desktop.WhatsApp` container):
//!   <https://belkasoft.com/whatsapp_forensics_on_computers>
//! - Electron `userData`/`appData` per-OS defaults (the macOS/Linux base dirs for
//!   the Electron messengers):
//!   <https://www.electronjs.org/docs/latest/api/app>

use crate::catalog::types::Platform;

/// How a desktop messenger packages itself — this decides the storage shape.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    /// Electron/Chromium wrapper — data lives in Chromium storage under the
    /// standard `userData` directory.
    Electron,
    /// Native client (Windows UWP/WebView2, macOS Catalyst) — SEE/DPAPI-encrypted
    /// SQLite rather than Chromium storage.
    Native,
}

/// The forensic role a store plays within a messenger profile.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRole {
    /// The chat/message record store.
    Messages,
    /// Account identity and/or the auth token.
    Account,
    /// The contact / conversation roster.
    Contacts,
    /// Attachment / media blobs.
    Attachments,
    /// Cached media & API responses (survives message deletion).
    MediaCache,
    /// The key material that unlocks the encrypted stores.
    EncryptionKey,
}

/// On-disk storage format of a messenger store.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFormat {
    /// SQLCipher-encrypted SQLite (Signal).
    SqlCipher,
    /// SQLite encrypted with the SQLite Encryption Extension / DPAPI (WhatsApp).
    EncryptedSqlite,
    /// Plain SQLite.
    Sqlite,
    /// Chromium LevelDB (Local Storage / IndexedDB).
    ChromiumLevelDb,
    /// Chromium Simple Cache (one file per entry + index).
    ChromiumSimpleCache,
    /// A JSON document (e.g. `config.json`).
    Json,
    /// A directory of individually-encrypted blob files.
    EncryptedFiles,
}

/// One store within a messenger profile — a path relative to the per-OS base dir.
///
/// `relative_path` always uses `/` separators for OS neutrality; on Windows the
/// separator is a backslash and the base dir (see [`ProfilePath`]) carries the
/// native form.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessengerStore {
    /// What this store holds.
    pub role: StoreRole,
    /// Path relative to the profile base dir (forward-slash separated).
    pub relative_path: &'static str,
    /// On-disk format.
    pub format: StoreFormat,
    /// Whether the store is encrypted at rest.
    pub encrypted: bool,
    /// Which platforms this store applies to (empty ⇒ all profiles of the spec).
    pub platforms: &'static [Platform],
    /// Analyst-facing note: what fields/tables live here, caveats.
    pub note: &'static str,
}

/// A per-OS profile base directory for a messenger.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfilePath {
    /// The platform this base directory is for.
    pub platform: Platform,
    /// The profile base directory (native path style for the platform).
    pub base_dir: &'static str,
}

/// A desktop messenger artifact spec.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessengerSpec {
    /// Canonical app name (lookup key).
    pub app: &'static str,
    /// Packaging kind — decides the storage shape.
    pub app_kind: AppKind,
    /// Per-OS profile base directories.
    pub profiles: &'static [ProfilePath],
    /// The stores within the profile.
    pub stores: &'static [MessengerStore],
    /// Spec-level caveat (e.g. "no local message DB").
    pub note: &'static str,
    /// Authoritative sources that informed this spec (all `https://`).
    pub sources: &'static [&'static str],
}

impl MessengerSpec {
    /// The profile base directory for `platform`, if the app runs there.
    #[must_use]
    pub fn base_dir(&self, platform: Platform) -> Option<&'static str> {
        self.profiles
            .iter()
            .find(|p| p.platform == platform)
            .map(|p| p.base_dir)
    }

    /// The first store playing `role`, if any.
    #[must_use]
    pub fn store(&self, role: StoreRole) -> Option<&'static MessengerStore> {
        self.stores.iter().find(|s| s.role == role)
    }
}

/// All platforms — a store present under every listed profile.
const ALL_PLATFORMS: &[Platform] = &[Platform::Windows, Platform::MacOS, Platform::Linux];

/// Every desktop-messenger spec, keyed by [`MessengerSpec::app`].
pub const DESKTOP_MESSENGERS: &[MessengerSpec] = &[
    // ── Signal Desktop (Electron; SQLCipher) ─────────────────────────────────
    MessengerSpec {
        app: "Signal Desktop",
        app_kind: AppKind::Electron,
        // Source: https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/
        profiles: &[
            ProfilePath {
                platform: Platform::Windows,
                base_dir: r"%AppData%\Signal",
            },
            ProfilePath {
                platform: Platform::MacOS,
                base_dir: "~/Library/Application Support/Signal",
            },
            ProfilePath {
                platform: Platform::Linux,
                base_dir: "~/.config/Signal",
            },
        ],
        stores: &[
            MessengerStore {
                role: StoreRole::Messages,
                relative_path: "sql/db.sqlite",
                format: StoreFormat::SqlCipher,
                encrypted: true,
                platforms: ALL_PLATFORMS,
                // Source: https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/
                note: "SQLCipher (use SQLCipher 4 defaults); `messages` table = chat body, `conversations` table = contacts/groups.",
            },
            MessengerStore {
                role: StoreRole::Contacts,
                relative_path: "sql/db.sqlite",
                format: StoreFormat::SqlCipher,
                encrypted: true,
                platforms: ALL_PLATFORMS,
                note: "Same DB as messages; the `conversations` table holds contact/group rows.",
            },
            MessengerStore {
                role: StoreRole::EncryptionKey,
                relative_path: "config.json",
                format: StoreFormat::Json,
                encrypted: true,
                platforms: ALL_PLATFORMS,
                // Source: https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/
                note: "Legacy: plaintext `key`. Modern: `encryptedKey` wrapped by the OS keystore via `Local State` (Windows DPAPI / macOS Keychain 'Signal Safe Storage' / Linux libsecret).",
            },
            MessengerStore {
                role: StoreRole::Attachments,
                relative_path: "attachments.noindex",
                format: StoreFormat::EncryptedFiles,
                encrypted: true,
                platforms: ALL_PLATFORMS,
                note: "Per-attachment key derived from the SQLCipher master key.",
            },
        ],
        note: "Also carries Chromium `Local Storage/leveldb` and `IndexedDB/file__0.indexeddb.leveldb` app-state stores.",
        sources: &["https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/"],
    },
    // ── Discord (Electron/Chromium; no local message DB) ─────────────────────
    MessengerSpec {
        app: "Discord",
        app_kind: AppKind::Electron,
        // Source: https://sankara-ns.medium.com/simple-forensic-analysis-on-discord-in-windows-10-d530506dcd81
        profiles: &[
            ProfilePath {
                platform: Platform::Windows,
                base_dir: r"%AppData%\discord",
            },
            // macOS/Linux follow the Electron userData convention.
            // Source: https://www.electronjs.org/docs/latest/api/app
            ProfilePath {
                platform: Platform::MacOS,
                base_dir: "~/Library/Application Support/discord",
            },
            ProfilePath {
                platform: Platform::Linux,
                base_dir: "~/.config/discord",
            },
        ],
        stores: &[
            MessengerStore {
                role: StoreRole::Account,
                relative_path: "Local Storage/leveldb",
                format: StoreFormat::ChromiumLevelDb,
                encrypted: true,
                platforms: ALL_PLATFORMS,
                // Source: https://asec.ahnlab.com/en/24512/
                note: "Auth token in the `.ldb`/`.log` files (DPAPI-protected in newer clients); prime info-stealer target. Test-build variants live under `discordptb` / `discordcanary`.",
            },
            MessengerStore {
                role: StoreRole::MediaCache,
                relative_path: "Cache/Cache_Data",
                format: StoreFormat::ChromiumSimpleCache,
                encrypted: false,
                platforms: ALL_PLATFORMS,
                // Source: https://www.forensafe.com/blogs/discord.html
                note: "Chromium Simple Cache: cached attachments, media, webhook URLs and API JSON. Survives message/channel/server deletion.",
            },
        ],
        // Source: https://sankara-ns.medium.com/simple-forensic-analysis-on-discord-in-windows-10-d530506dcd81
        note: "No local message database — chats are fetched from the server and only cached; recoverable message evidence is the Simple Cache, not a chat DB.",
        sources: &[
            "https://www.forensafe.com/blogs/discord.html",
            "https://asec.ahnlab.com/en/24512/",
            "https://sankara-ns.medium.com/simple-forensic-analysis-on-discord-in-windows-10-d530506dcd81",
        ],
    },
    // ── Wire (Electron/Chromium; messages in IndexedDB) ──────────────────────
    MessengerSpec {
        app: "Wire",
        app_kind: AppKind::Electron,
        // Source: https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS
        profiles: &[
            ProfilePath {
                platform: Platform::Windows,
                base_dir: r"%AppData%\Wire",
            },
            // macOS/Linux follow the Electron userData convention.
            // Source: https://www.electronjs.org/docs/latest/api/app
            ProfilePath {
                platform: Platform::MacOS,
                base_dir: "~/Library/Application Support/Wire",
            },
            ProfilePath {
                platform: Platform::Linux,
                base_dir: "~/.config/Wire",
            },
        ],
        stores: &[
            MessengerStore {
                role: StoreRole::Messages,
                relative_path: "IndexedDB/https_app.wire.com_0.indexeddb.leveldb",
                format: StoreFormat::ChromiumLevelDb,
                encrypted: false,
                platforms: ALL_PLATFORMS,
                // Source: https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS
                note: "Chat logs in the IndexedDB object stores: conversation id, sender, timestamp, message body.",
            },
            MessengerStore {
                role: StoreRole::Account,
                relative_path: "IndexedDB/https_app.wire.com_0.indexeddb.leveldb",
                format: StoreFormat::ChromiumLevelDb,
                encrypted: false,
                platforms: ALL_PLATFORMS,
                note: "Device class/model, verification status and account domain live in the same IndexedDB.",
            },
            MessengerStore {
                role: StoreRole::EncryptionKey,
                relative_path: "IndexedDB/https_app.wire.com_0.indexeddb.leveldb",
                format: StoreFormat::ChromiumLevelDb,
                encrypted: false,
                platforms: ALL_PLATFORMS,
                // Source: https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS
                note: "`otr_key` (stored as decimal, convert to hex) decrypts attachments.",
            },
        ],
        note: "Electron wrapper over the Wire web client; all evidence is in the Chromium IndexedDB.",
        sources: &["https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS"],
    },
    // ── WhatsApp Desktop (native; SEE/DPAPI-encrypted SQLite) ────────────────
    MessengerSpec {
        app: "WhatsApp Desktop",
        app_kind: AppKind::Native,
        profiles: &[
            // Windows Store UWP/WebView2 client.
            // Source: https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3
            ProfilePath {
                platform: Platform::Windows,
                base_dir: r"%LocalAppData%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState",
            },
            // macOS Catalyst client container.
            // Source: https://belkasoft.com/whatsapp_forensics_on_computers
            ProfilePath {
                platform: Platform::MacOS,
                base_dir: "~/Library/Containers/desktop.WhatsApp",
            },
        ],
        stores: &[
            MessengerStore {
                role: StoreRole::Messages,
                relative_path: "genericStorageDB",
                format: StoreFormat::EncryptedSqlite,
                encrypted: true,
                platforms: &[Platform::Windows],
                // Source: https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3
                note: "WebView2 arch: `genericStorageDB` holds messages, SEE + DPAPI-NG encrypted. Older UWP arch used SEE-encrypted SQLite with `nondb_settings[0-9]{2}.dat` key files.",
            },
            MessengerStore {
                role: StoreRole::EncryptionKey,
                relative_path: "Session.db",
                format: StoreFormat::EncryptedSqlite,
                encrypted: true,
                platforms: &[Platform::Windows],
                // Source: https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3
                note: "`Session.db`/`session.db-wal` store the session clientKeys; per-session `nativeSettings.db` holds further key material (DPAPI-NG protected).",
            },
        ],
        // The macOS Catalyst client mirrors the iOS Core Data schema (ChatStorage.sqlite /
        // ZWAMESSAGE), but the cited desktop sources did not confirm its exact on-disk path,
        // so only the container is asserted here.
        note: "macOS Catalyst client stores chats in a Core Data SQLite under the container; the exact desktop DB path was not confirmed by the cited sources.",
        sources: &[
            "https://medium.com/@alberto.magno/whatsapp-desktop-and-web-live-forensics-4n6-233f640e9fb3",
            "https://belkasoft.com/whatsapp_forensics_on_computers",
        ],
    },
];

/// Look up a desktop messenger spec by its canonical [`MessengerSpec::app`] name.
#[must_use]
pub fn spec(app: &str) -> Option<&'static MessengerSpec> {
    DESKTOP_MESSENGERS.iter().find(|m| m.app == app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_messengers_present() {
        assert!(spec("Signal Desktop").is_some());
        assert!(spec("Discord").is_some());
        assert!(spec("Wire").is_some());
        assert!(spec("WhatsApp Desktop").is_some());
        assert!(spec("does-not-exist").is_none());
        assert!(DESKTOP_MESSENGERS.len() >= 4);
    }

    #[test]
    fn signal_paths_and_stores() {
        let s = spec("Signal Desktop").expect("signal spec");
        assert_eq!(s.app_kind, AppKind::Electron);
        assert_eq!(s.base_dir(Platform::Windows), Some(r"%AppData%\Signal"));
        assert_eq!(
            s.base_dir(Platform::MacOS),
            Some("~/Library/Application Support/Signal")
        );
        assert_eq!(s.base_dir(Platform::Linux), Some("~/.config/Signal"));

        let msgs = s.store(StoreRole::Messages).expect("signal messages");
        assert_eq!(msgs.relative_path, "sql/db.sqlite");
        assert_eq!(msgs.format, StoreFormat::SqlCipher);
        assert!(msgs.encrypted);

        let key = s.store(StoreRole::EncryptionKey).expect("signal key");
        assert_eq!(key.relative_path, "config.json");
        assert_eq!(key.format, StoreFormat::Json);
    }

    #[test]
    fn discord_has_no_local_message_db() {
        let d = spec("Discord").expect("discord spec");
        assert_eq!(d.app_kind, AppKind::Electron);
        // No chat DB — messages are server-side, only cached.
        assert!(d.store(StoreRole::Messages).is_none());
        assert!(
            d.note.contains("server") || d.note.contains("cache") || d.note.contains("no local"),
            "discord note must explain the missing message DB: {:?}",
            d.note
        );

        let token = d.store(StoreRole::Account).expect("discord token");
        assert_eq!(token.relative_path, "Local Storage/leveldb");
        assert_eq!(token.format, StoreFormat::ChromiumLevelDb);

        let cache = d.store(StoreRole::MediaCache).expect("discord cache");
        assert_eq!(cache.format, StoreFormat::ChromiumSimpleCache);
    }

    #[test]
    fn wire_stores_messages_in_indexeddb() {
        let w = spec("Wire").expect("wire spec");
        assert_eq!(w.app_kind, AppKind::Electron);
        let msgs = w.store(StoreRole::Messages).expect("wire messages");
        assert!(msgs.relative_path.contains("wire.com"));
        assert!(msgs.relative_path.contains(".indexeddb.leveldb"));
        assert_eq!(msgs.format, StoreFormat::ChromiumLevelDb);
        assert!(w.store(StoreRole::EncryptionKey).is_some(), "otr_key store");
    }

    #[test]
    fn whatsapp_is_native_and_encrypted() {
        let wa = spec("WhatsApp Desktop").expect("whatsapp spec");
        assert_eq!(wa.app_kind, AppKind::Native);
        assert!(wa
            .base_dir(Platform::Windows)
            .expect("wa windows")
            .contains("5319275A.WhatsAppDesktop"));
        assert_eq!(
            wa.base_dir(Platform::MacOS),
            Some("~/Library/Containers/desktop.WhatsApp")
        );
        // No official Linux WhatsApp desktop client.
        assert_eq!(wa.base_dir(Platform::Linux), None);

        let msgs = wa.store(StoreRole::Messages).expect("wa messages");
        assert!(msgs.encrypted);
        assert_eq!(msgs.format, StoreFormat::EncryptedSqlite);
        assert_eq!(msgs.platforms, &[Platform::Windows]);
    }

    #[test]
    fn relative_paths_use_forward_slashes() {
        for m in DESKTOP_MESSENGERS {
            for s in m.stores {
                assert!(
                    !s.relative_path.contains('\\'),
                    "{}/{:?} relative_path must use '/': {:?}",
                    m.app,
                    s.role,
                    s.relative_path
                );
            }
        }
    }

    #[test]
    fn every_spec_cites_https_sources() {
        for m in DESKTOP_MESSENGERS {
            assert!(!m.sources.is_empty(), "{} has no sources", m.app);
            for url in m.sources {
                assert!(
                    url.starts_with("https://"),
                    "{} source is not an https URL: {url}",
                    m.app
                );
            }
        }
    }
}
