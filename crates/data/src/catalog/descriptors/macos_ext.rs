//! Extended macOS artifact descriptors.
//!
//! Sources: Velociraptor macOS artifacts, ForensicArtifacts/artifacts (macOS YAML),
//! APOLLO modules (mac4n6), Magnet Forensics, mac4n6.com, Sarah Edwards research.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static MACOS_FSEVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_fsevents",
    name: "FSEvents Log",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/.fseventsd/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "FSEvents daemon binary log records every file-system create/delete/rename/chmod event volume-wide with event flags and monotonic event ID. Critical for reconstructing file activity even after deletion — records outlive the files. Correlate with $MFT for Windows-equivalent timeline analysis.",
    mitre_techniques: &["T1070.004", "T1083"],
    fields: &[
        FieldSchema { name: "path", value_type: ValueType::Text, description: "File-system path of the event", is_uid_component: true },
        FieldSchema { name: "flags", value_type: ValueType::UnsignedInt, description: "FSEvent flags (Created/Removed/Modified/Renamed/etc.)", is_uid_component: false },
        FieldSchema { name: "event_id", value_type: ValueType::UnsignedInt, description: "Monotonic FSEvent ID for ordering", is_uid_component: false },
    ],
    retention: Some("Rotated by kernel; typically weeks to months of history"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_unified_log", "macos_spotlight_store"],
    sources: &[
        "https://www.mac4n6.com/blog/2016/2/1/the-hitchhikers-guide-to-the-fseventsd",
        "https://github.com/nicowillis/fseventparser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Kernel-level; not easily tampered; covers all file system activity"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "FSEvents log; rotated as volume fills",
};

pub(crate) static MACOS_BIOME_APP_MENUITEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_biome_app_menuitem",
    name: "Apple Biome App.MenuItem Stream (menu-selection intent)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Biome/streams/restricted/App.MenuItem/local"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "macOS Tahoe 26 Biome stream logging the exact text of menu items a user selected across the OS, each with a timestamp — a step-by-step user-intent trail (e.g. Go > Go to Folder, File > Save, Compress, Move to Trash, Empty Trash, Copy/Paste). Reconstructs deliberate workflow/intent that filesystem events alone do not show: data creation -> compression (staging for exfil) -> deletion -> trash-emptying (cleanup). SEGB-encapsulated protobuf; parse with ccl-segb (not handled by most commercial tools as of 2026).",
    mitre_techniques: &["T1074.001", "T1560.001", "T1070"],
    fields: &[
        FieldSchema { name: "application", value_type: ValueType::Text, description: "Application whose menu was used (e.g. Finder, TextEdit)", is_uid_component: true },
        FieldSchema { name: "menu_item", value_type: ValueType::Text, description: "Exact text of the menu item selected (e.g. Move to Trash)", is_uid_component: true },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "When the menu selection occurred", is_uid_component: false },
    ],
    retention: Some("Biome stream; rotated by the Biome subsystem (typically days to weeks)"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_fsevents", "macos_unified_log"],
    sources: &[
        "https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/",
        "https://github.com/cclgroupltd/ccl-segb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "User-scope; records UI menu selections, not programmatic file operations",
        "New in macOS Tahoe 26 — absent on earlier macOS versions",
        "SEGB+protobuf; requires ccl-segb-style tooling, not parsed by most commercial suites",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Biome stream; rotated by the Biome subsystem over time",
};

pub(crate) static MACOS_SPOTLIGHT_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_spotlight_store",
    name: "Spotlight Metadata Store",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/.Spotlight-V100/Store-V2/*/store.db"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Spotlight metadata database indexes file metadata (name, kind, dates, author, GPS) for every file ever seen by the volume, including deleted ones. Reveals user document activity, application usage, and file provenance well after file deletion.",
    mitre_techniques: &["T1083"],
    fields: &[
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Indexed file path", is_uid_component: true },
        FieldSchema { name: "last_used_date", value_type: ValueType::Timestamp, description: "Last access timestamp from metadata", is_uid_component: false },
    ],
    retention: Some("Rebuilt on re-index; history spans volume lifetime"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_fsevents", "macos_knowledgec"],
    sources: &[
        "https://www.mac4n6.com/blog/2016/2/22/spotlight-on-spotlight",
        "https://forensicswiki.xyz/wiki/index.php?title=Spotlight",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "User can disable Spotlight indexing for specific paths",
        "Encrypted volumes require unlock to access",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Spotlight metadata store persists until volume reindex",
};

pub(crate) static MACOS_DOCK_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_dock_plist",
    name: "Dock Configuration Plist (recent apps)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Preferences/com.apple.dock.plist"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Stores Dock layout including persistent items, recent apps/documents/servers, and minimized windows. The `recent-apps` array is a reliable execution artifact showing recently launched applications including those since removed from the system.",
    mitre_techniques: &["T1059"],
    fields: &[
        FieldSchema { name: "recent_app_path", value_type: ValueType::Text, description: "Bundle path of recently launched application", is_uid_component: true },
    ],
    retention: Some("Updated on each app launch; recent-apps list capped"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_knowledgec", "macos_sfl2_recent_items"],
    sources: &["https://www.mac4n6.com/blog/2016/6/2/ode-to-the-dock"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["recent-apps array bounded to ~10 entries; older launches evicted"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated per dock interaction; recent-apps rotates as new apps launched",
};

pub(crate) static MACOS_LOGIN_ITEMS_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_login_items_plist",
    name: "Login Items Plist",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Preferences/com.apple.loginitems.plist"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Records user-level Login Items (persistence mechanism). Each entry specifies a bundle or binary that launches at user login. Malware frequently abuses Login Items for persistence — a primary macOS persistence vector.",
    mitre_techniques: &["T1547.015"],
    fields: &[
        FieldSchema { name: "item_path", value_type: ValueType::Text, description: "Path of the login item", is_uid_component: true },
        FieldSchema { name: "hide", value_type: ValueType::Bool, description: "Whether the item launches hidden", is_uid_component: false },
    ],
    retention: Some("Persistent until item is removed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_launch_agents_user", "macos_launch_daemons"],
    sources: &[
        "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Persistence mechanism; SFL2 format varies by OS version"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Plist file; persistent until deleted",
};

pub(crate) static MACOS_SFL2_RECENT_ITEMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sfl2_recent_items",
    name: "SFL2 Recent Documents",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "SFL2 (Shared File List v2, macOS 10.12+) binary plist tracking recently opened documents system-wide. Reveals user document activity even for files since deleted. Supersedes com.apple.recentitems.plist on modern systems.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "file_path", value_type: ValueType::Text, description: "Bookmark-resolved path of recent document", is_uid_component: true },
    ],
    retention: Some("Capped list, rotated by system"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_dock_plist", "macos_knowledgec"],
    sources: &["https://www.mac4n6.com/blog/2016/6/21/introduction-to-sfl-and-sfl2-files"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "User can clear recent items via menu",
        "Some apps maintain their own recent lists outside SFL2",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated per document open; older entries evicted as new ones added",
};

pub(crate) static MACOS_SFL2_RECENT_SERVERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sfl2_recent_servers",
    name: "SFL2 Recent Servers",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "Tracks recently connected network servers (SMB, AFP, NFS, WebDAV). Critical for lateral movement and data exfiltration investigations — shows remote file server connections with server URLs.",
    mitre_techniques: &["T1021.002"],
    fields: &[
        FieldSchema { name: "server_url", value_type: ValueType::Text, description: "URL of the recently connected server", is_uid_component: true },
    ],
    retention: Some("Capped recent list"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_sfl2_recent_items"],
    sources: &["https://www.mac4n6.com/blog/2016/6/21/introduction-to-sfl-and-sfl2-files"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only records mounted servers, not connection attempts"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated per server connection; older entries evicted as new ones added",
};

pub(crate) static MACOS_WIFI_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_plist",
    name: "Known Wi-Fi Networks (airport preferences)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Ordered list of all known Wi-Fi networks: SSIDs, security type, last join time, BSSID. Reveals historical network connections and geolocation context. Key for placing a device at a location or identifying rogue access points. The store of macOS 10.15 and earlier; Big Sur (11) moved remembered networks to com.apple.wifi.known-networks.plist (macos_wifi_known_networks). On a Mac upgraded to Big Sur the legacy records can survive in com.apple.airport.preferences.plist.backup beside this file (macos_wifi_plist_backup); examine that file too.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "ssid", value_type: ValueType::Text, description: "Wi-Fi network SSID", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "Access point MAC address", is_uid_component: false },
        FieldSchema { name: "last_joined", value_type: ValueType::Timestamp, description: "Last connection timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent; manually cleared or limited by OS"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "macos_wifi_intelligence", "macos_wifi_known_networks", "macos_wifi_plist_backup"],
    sources: &[
        "https://www.mac4n6.com/blog/2016/6/3/ode-to-the-network",
        "https://www.alansiu.net/2021/01/27/known-networks-settings-moved-in-big-sur/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "User can manually remove networks from list",
        "After the upgrade to Big Sur this file can hold only Counter, DeviceUUID and Version, with no KnownNetworks; observed on one macOS Big Sur 11.7 image, where the full legacy store was in com.apple.airport.preferences.plist.backup. An empty live file is not evidence that no networks were ever joined",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Plist persists known networks until explicit removal",
};

pub(crate) static MACOS_SCREEN_TIME_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_screen_time_db",
    name: "Screen Time Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Application Support/com.apple.ScreenTime/RMAdminStore-Local.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "Screen Time SQLite database recording per-app and per-domain usage durations by day. Provides a granular timeline of application and web activity even when browser history is cleared — a secondary execution evidence source.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "bundle_id", value_type: ValueType::Text, description: "Application bundle ID", is_uid_component: true },
        FieldSchema { name: "usage_seconds", value_type: ValueType::UnsignedInt, description: "Time spent in app (seconds)", is_uid_component: false },
    ],
    retention: Some("Rolling 30-day window"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_knowledgec", "macos_dock_plist"],
    sources: &["https://www.mac4n6.com/blog/2019/6/20/screen-time-in-ios-12-macos-mojave"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires Screen Time enabled (default on macOS 12+)",
        "Data retention bounded by Screen Time settings (typically ~30 days)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Time-bounded retention; older days purged",
};

pub(crate) static MACOS_TCC_SYSTEM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_tcc_system_db",
    name: "TCC System Database (root-level)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Application Support/com.apple.TCC/TCC.db"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS12Plus,
    decoder: Decoder::Identity,
    meaning: "System-level TCC (Transparency Consent Control) database covering FDA, accessibility, camera, microphone, screen recording, and contacts permissions for system services and admin-granted access. Complements the per-user TCC.db — malware targeting root-level TCC can grant itself full-disk access.",
    mitre_techniques: &["T1548"],
    fields: &[
        FieldSchema { name: "client", value_type: ValueType::Text, description: "Bundle ID or binary path requesting permission", is_uid_component: true },
        FieldSchema { name: "service", value_type: ValueType::Text, description: "TCC service (kTCCServiceScreenCapture etc.)", is_uid_component: false },
        FieldSchema { name: "auth_value", value_type: ValueType::UnsignedInt, description: "0=denied, 2=allowed", is_uid_component: false },
    ],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_tcc_db"],
    sources: &[
        "https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["System-wide privacy permissions; requires SIP bypass to tamper"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persistent until reset",
};

pub(crate) static MACOS_SMS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sms_db",
    name: "iMessage / SMS Database (chat.db)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Messages/chat.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "iMessage and SMS SQLite database on macOS (mirrored from iPhone via Continuity). Contains message text, participants, timestamps, attachments, and read receipts. Critical for communications analysis in insider threat and fraud investigations.",
    mitre_techniques: &["T1530"],
    fields: &[
        FieldSchema { name: "handle_id", value_type: ValueType::Text, description: "Sender/recipient phone number or Apple ID", is_uid_component: true },
        FieldSchema { name: "message_date", value_type: ValueType::Timestamp, description: "Message send/receive timestamp (Mac absolute time)", is_uid_component: false },
        FieldSchema { name: "text", value_type: ValueType::Text, description: "Message body text", is_uid_component: false },
    ],
    retention: Some("Indefinite unless manually deleted or iCloud limit reached"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_knowledgec"],
    sources: &[
        "https://www.mac4n6.com/blog/2020/7/28/imessage-artifacts-in-macos-catalina",
        "https://github.com/mac4n6/APOLLO",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["iMessage/SMS content; may be partially encrypted or unavailable without cloud sync"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persistent until deleted",
};

/// Apple Notes store, `NoteStore.sqlite` in the `group.com.apple.notes` group
/// container (OS X El Capitan onward).
///
/// # Sources
/// - <http://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html> —
///   Khatri: two locations; NoteStore.sqlite seen on El Capitan, Sierra and High
///   Sierra; ZICNOTEDATA.ZDATA is gzip compressed; legacy NotesV1/V2/V4/V6/V7
///   .storedata in the com.apple.Notes container; attachment join via
///   ZICCLOUDSYNCINGOBJECT ZNOTE/ZMEDIA.
/// - <https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/> — the
///   decompressed ZDATA is a protobuf; parser rewrite.
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser> — Mac
///   mode takes the group.com.apple.notes folder and computes NoteStore.sqlite;
///   gunzips ZDATA and parses the protobuf inside.
pub(crate) static MACOS_NOTES_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notes_db",
    name: "Apple Notes Database (NoteStore.sqlite)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: http://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html ("Location 2")
    file_path: Some("/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Apple Notes Core Data store (SQLite, with -wal/-shm siblings that must be \
        collected together) in the group.com.apple.notes group container. Note, folder and \
        account metadata (titles, snippets, creation/modification times in Mac absolute \
        time) are rows in ZICCLOUDSYNCINGOBJECT; the note body is a gzip-compressed \
        protobuf in ZICNOTEDATA.ZDATA and must be gunzipped and protobuf-decoded to read \
        the text. Attachments are NOT stored in the database: ZICCLOUDSYNCINGOBJECT holds \
        attachment rows (ZNOTE points to the note, ZMEDIA to a media row whose \
        ZIDENTIFIER names the on-disk folder and ZFILENAME the file) while the bytes live \
        as separate files under the same group container. Frequently used to store \
        sensitive information (passwords, plans, communications).",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "title", value_type: ValueType::Text, description: "Note title (ZICCLOUDSYNCINGOBJECT; column suffix varies by version, e.g. ZTITLE1)", is_uid_component: true },
        FieldSchema { name: "modification_date", value_type: ValueType::Timestamp, description: "Last modification timestamp (Mac absolute time, seconds since 2001-01-01 UTC)", is_uid_component: false },
        FieldSchema { name: "note_data", value_type: ValueType::Bytes, description: "ZICNOTEDATA.ZDATA: gzip-compressed protobuf holding the note text and embedded-object references", is_uid_component: false },
    ],
    retention: Some("Persistent; syncs via iCloud"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_notes_attachment_media", "macos_notes_attachment_previews", "fa_file_notes_notesv_storedata", "macos_sms_db"],
    sources: &[
        "http://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html",
        "https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/",
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Version scope: NoteStore.sqlite is documented from OS X El Capitan onward; Mountain Lion to High Sierra also used legacy NotesV1/V2/V4/V6/V7.storedata stores under /Users/*/Library/Containers/com.apple.Notes/Data/Library/Notes/ (attachments under .../CoreData/Attachments/<UUID>/), so older or upgraded Macs can hold both",
        "Body text is not plaintext in the database: ZICNOTEDATA.ZDATA must be gunzipped and protobuf-decoded; a string search of the raw file misses note text",
        "Collect NoteStore.sqlite-wal and -shm with the database; recent edits may exist only in the WAL",
        "Locked (password-protected) notes are encrypted in the store and their attachments are encrypted on disk",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite store persists until note deletion",
};

/// Apple Notes attachment originals: `Accounts/<account-UUID>/Media/<media-UUID>/<file>`
/// in the `group.com.apple.notes` group container.
///
/// # Sources
/// - <http://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html> —
///   El Capitan to High Sierra: attachments in `group.com.apple.notes/Media/<UUID>/`;
///   SQL joining ZICCLOUDSYNCINGOBJECT attachment rows (ZNOTE, ZMEDIA, ZTYPEUTI)
///   to the media row (ZIDENTIFIER = media UUID, ZFILENAME).
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedObject.rb> —
///   `Accounts/<account>/Media/<media UUID>/[<generation>/]<ZFILENAME>`; locked
///   media named by the media UUID; UTI dispatch (public.url,
///   com.apple.notes.gallery, com.apple.notes.table, com.apple.paper.doc.scan,
///   com.apple.drawing).
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedGallery.rb> —
///   com.apple.notes.gallery = a document scanned in by taking a picture.
/// - <https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/> — sample
///   parser output listing `Accounts/LocalAccount/Media/<UUID>/<file>`.
pub(crate) static MACOS_NOTES_ATTACHMENT_MEDIA: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notes_attachment_media",
    name: "Apple Notes Attachment Originals (Accounts/*/Media)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Group Containers/group.com.apple.notes/Accounts/*/Media/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Original files attached to Apple Notes, one folder per media object: \
        Accounts/<account-UUID>/Media/<media-UUID>/<file name>. The bytes are not in \
        NoteStore.sqlite; the database links them. In ZICCLOUDSYNCINGOBJECT an attachment \
        row carries ZNOTE (the owning note), ZTYPEUTI (what kind of attachment) and ZMEDIA \
        (Z_PK of a media row); that media row's ZIDENTIFIER is the Media folder name and \
        its ZFILENAME the file inside it. ZTYPEUTI values include public.jpeg and other \
        image types (a photo or picture), public.url (a web link shared into the note), \
        com.apple.notes.gallery (a document-scanner item whose pages are child image \
        objects), com.apple.notes.table (a table; its content is in the database, not a \
        file), com.apple.paper.doc.scan and com.apple.drawing variants. Resolve every file \
        through this join before attributing it to a note.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "media_uuid", value_type: ValueType::Guid, description: "Media folder name = ZIDENTIFIER of the media row in ZICCLOUDSYNCINGOBJECT", is_uid_component: true },
        FieldSchema { name: "file_name", value_type: ValueType::Text, description: "File inside the media folder = ZFILENAME of the media row", is_uid_component: false },
        FieldSchema { name: "type_uti", value_type: ValueType::Text, description: "ZTYPEUTI of the attachment row (public.jpeg, public.url, com.apple.notes.gallery, com.apple.notes.table, ...)", is_uid_component: false },
        FieldSchema { name: "note_pk", value_type: ValueType::UnsignedInt, description: "ZNOTE of the attachment row: Z_PK of the owning note", is_uid_component: false },
    ],
    retention: Some("Kept while the attachment exists in a note; synced from iCloud for iCloud accounts"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_notes_db", "macos_notes_attachment_previews", "macos_notes_locked_notes"],
    sources: &[
        "http://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html",
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedObject.rb",
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedGallery.rb",
        "https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/",
        "https://www.ciofecaforensics.com/2020/07/31/apple-notes-revisited-encrypted-notes/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Version scope: on El Capitan to High Sierra Khatri documents group.com.apple.notes/Media/<UUID>/ with no Accounts/<UUID>/ level; the parser handles both layouts, and newer versions may add a generation sub-folder (Media/<UUID>/<generation>/<file>)",
        "File-system timestamps on a Mac's copy record when that Mac wrote the file (for an iCloud account, when it was synced down), not when a photo was taken; observed on one macOS Big Sur 11.7 image, not vendor-documented",
        "Capture device and capture time come from EXIF inside the image when present, not from the Notes database or the file dates",
        "Attachments of locked (password-protected) notes are stored encrypted, named by the media UUID rather than the original file name; the original name is in the encrypted ZENCRYPTEDVALUESJSON",
        "Scanner and gallery items are several rows: the gallery attachment plus child image objects; do not count files as separate user actions without the join",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Files persist with the attachment until removed from the note",
};

/// Apple Notes derived renders: `Accounts/<UUID>/Previews/` thumbnails and
/// `FallbackImages/` / `FallbackPDFs/` renders.
///
/// # Sources
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedThumbnail.rb> —
///   `Previews/{parent_uuid}-1-{W}x{H}-0.(png|jpg)`, `.encrypted` suffix for
///   locked notes, newer `-0/{generation}/Preview.png` / `OrientedPreview.jpeg`.
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedDrawing.rb> —
///   `FallbackImages/{uuid}.(jpeg|png|jpg)` for drawings.
/// - <https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/> — sample
///   output with Previews/ and FallbackImages/ files.
pub(crate) static MACOS_NOTES_ATTACHMENT_PREVIEWS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notes_attachment_previews",
    name: "Apple Notes Attachment Previews and Fallback Renders",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Group Containers/group.com.apple.notes/Accounts/*/Previews/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Images Notes generates from attachments, beside the originals in the same \
        account folder. Previews/ holds thumbnails named \
        <attachment-UUID>-1-<W>x<H>-0.jpg or .png (newer versions: a \
        <attachment-UUID>-1-<W>x<H>-0/<generation>/Preview.png or OrientedPreview.jpeg \
        folder); the UUID is the ZIDENTIFIER of the attachment row, which ties the \
        thumbnail to a note through ZICCLOUDSYNCINGOBJECT.ZNOTE. FallbackImages/ holds \
        rendered images of drawings and FallbackPDFs/ rendered PDFs of scanned \
        documents. These are renders derived from an attachment, not originals.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "attachment_uuid", value_type: ValueType::Guid, description: "Leading UUID of the preview name = ZIDENTIFIER of the attachment row", is_uid_component: true },
        FieldSchema { name: "dimensions", value_type: ValueType::Text, description: "<W>x<H> render size encoded in the file name", is_uid_component: false },
    ],
    retention: Some("Regenerated by Notes; persists with the attachment"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_notes_attachment_media", "macos_notes_db"],
    sources: &[
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedThumbnail.rb",
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser/blob/master/lib/AppleNotesEmbeddedDrawing.rb",
        "https://ciofecaforensics.com/2020/01/10/apple-notes-revisited/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "A preview can belong to a web-link (public.url) attachment and then shows a render of the linked page, not a photo the user took; check the attachment row's ZTYPEUTI before describing the image (observed on one macOS Big Sur 11.7 image)",
        "Previews of locked notes carry an .encrypted suffix and are not viewable without the note password",
        "File-system dates reflect when this Mac generated or synced the render, not when the attachment was created",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Render cache persists with the attachment; may be regenerated",
};

/// Locked (password-protected) Apple Notes and their encrypted attachments.
///
/// # Sources
/// - <https://support.apple.com/guide/security/secure-features-in-the-notes-app-sec1782bcab1/web> —
///   Apple Platform Security: 16-byte key from the passphrase via PBKDF2 +
///   SHA-256; note and attachments encrypted with AES-GCM; new records store
///   ciphertext, tag and IV, then the unencrypted originals are deleted.
/// - <https://support.apple.com/guide/notes/lock-your-notes-not28c5f5468/mac> —
///   which attachment kinds a locked note can hold (tables, images, drawings,
///   scanned documents, maps, web attachments; not video, audio, PDF or documents).
/// - <https://www.ciofecaforensics.com/2020/07/31/apple-notes-revisited-encrypted-notes/> —
///   ZCRYPTOSALT / ZCRYPTOITERATIONCOUNT / ZCRYPTOWRAPPEDKEY / ZCRYPTOTAG /
///   ZCRYPTOINITIALIZATIONVECTOR; image bytes encrypted in the file on disk
///   (ZASSETCRYPTOTAG / ZASSETCRYPTOINITIALIZATIONVECTOR), filename kept in
///   ZENCRYPTEDVALUESJSON; old rows marked for deletion and ZDATA overwritten.
/// - <https://github.com/threeplanetssoftware/apple_cloud_notes_parser> —
///   password-list decryption; iOS 16+ device-passcode mode not handled.
pub(crate) static MACOS_NOTES_LOCKED_NOTES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notes_locked_notes",
    name: "Apple Notes Locked (Password-Protected) Notes",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "A locked note is a ZICCLOUDSYNCINGOBJECT row with ZISPASSWORDPROTECTED = 1 \
        and its key material populated: ZCRYPTOSALT, ZCRYPTOITERATIONCOUNT and \
        ZCRYPTOWRAPPEDKEY (with ZCRYPTOTAG and ZCRYPTOINITIALIZATIONVECTOR). Apple \
        derives a 16-byte key from the user's passphrase with PBKDF2 and SHA-256 and \
        encrypts the note and its attachments with AES-GCM; the note's ZICNOTEDATA.ZDATA \
        is ciphertext, and each attachment's bytes on disk are encrypted too (media rows \
        carry their own ZASSETCRYPTOTAG / ZASSETCRYPTOINITIALIZATIONVECTOR, and the \
        original file name moves into encrypted ZENCRYPTEDVALUESJSON). The flag and \
        populated crypto columns prove a note was locked; its content needs the \
        passphrase. A locked note can hold only tables, images, drawings, scanned \
        documents, maps and web attachments, so its attachment rows are limited to those \
        kinds.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "is_password_protected", value_type: ValueType::Bool, description: "ZISPASSWORDPROTECTED = 1 on a locked note", is_uid_component: false },
        FieldSchema { name: "crypto_salt", value_type: ValueType::Bytes, description: "ZCRYPTOSALT: PBKDF2 salt", is_uid_component: false },
        FieldSchema { name: "crypto_iteration_count", value_type: ValueType::UnsignedInt, description: "ZCRYPTOITERATIONCOUNT: PBKDF2 iterations", is_uid_component: false },
        FieldSchema { name: "crypto_wrapped_key", value_type: ValueType::Bytes, description: "ZCRYPTOWRAPPEDKEY: key wrapped under the passphrase-derived key", is_uid_component: false },
    ],
    retention: Some("Persistent while the note exists; ciphertext syncs via iCloud"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_notes_db", "macos_notes_attachment_media", "macos_notes_attachment_previews"],
    sources: &[
        "https://support.apple.com/guide/security/secure-features-in-the-notes-app-sec1782bcab1/web",
        "https://support.apple.com/guide/notes/lock-your-notes-not28c5f5468/mac",
        "https://www.ciofecaforensics.com/2020/07/31/apple-notes-revisited-encrypted-notes/",
        "https://github.com/threeplanetssoftware/apple_cloud_notes_parser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "An encrypted attachment file has no image header; the file utility can misidentify it (observed on one macOS Big Sur 11.7 image: reported as \"OpenPGP Secret Key\"), consistent with a signature false match on random-looking ciphertext; it is not evidence of a PGP key",
        "Decoding encrypted attachment or ZDATA bytes as text yields noise; any \"words\" found that way are coincidence, not note content",
        "Recovery needs the note passphrase (the parser accepts a password list); notes locked with the device passcode (iOS 16 onward) are not handled by apple_cloud_notes_parser",
        "Locking creates new encrypted rows and marks the unencrypted ones for deletion with ZDATA overwritten, so plaintext remnants in the live store are not to be expected; freelist or WAL remnants are a separate question",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Rows and encrypted files persist until the note is deleted",
};

pub(crate) static MACOS_PHOTOS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_photos_db",
    name: "Photos Library Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Glob, not "Photos Library.photoslibrary": the bundle name is localised and user-choosable (see caveats).
    file_path: Some("/Users/*/Pictures/*.photoslibrary/database/Photos.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Photos app SQLite database recording all photos/videos with EXIF metadata, GPS coordinates, facial recognition tags, and import sources. Geolocation and timeline evidence — GPS data can place the device at a specific location.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "filename", value_type: ValueType::Text, description: "Photo/video filename", is_uid_component: true },
        FieldSchema { name: "gps_latitude", value_type: ValueType::Text, description: "GPS latitude from EXIF", is_uid_component: false },
        FieldSchema { name: "gps_longitude", value_type: ValueType::Text, description: "GPS longitude from EXIF", is_uid_component: false },
        FieldSchema { name: "capture_date", value_type: ValueType::Timestamp, description: "Photo capture timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent; syncs to iCloud Photos"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_knowledgec", "macos_photos_derivatives"],
    sources: &[
        "https://github.com/mac4n6/APOLLO",
        // Source: user reports of localised bundle names (zh-Hant, fr)
        "https://www.vedfolnir.com/technology/software/apple-photos-library-notice/",
        "https://forums.macg.co/threads/phototheque-photoslibrary.1401945/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "GPS metadata may be stripped if user disabled location for camera",
        "The library bundle name is localised and user-choosable, so match *.photoslibrary rather than the English \"Photos Library.photoslibrary\": a Traditional Chinese system was observed with 照片圖庫.photoslibrary on one macOS Big Sur 11.7 image, and user reports show the same name (vedfolnir.com) and French Photothèque.photoslibrary (forums.macg.co); no Apple document naming the localised bundle was found",
        "A library can live outside ~/Pictures (another folder or an external volume) and a user can have several; the glob covers only the default parent folder",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Photos library database persists until photo deletion",
};

/// Photos library render cache: `resources/derivatives/` inside the library
/// bundle.
///
/// # Sources
/// - <https://support.apple.com/guide/photos/optimize-storage-in-photos-on-mac-phta9b4673b4/mac> —
///   Apple: Optimize Mac Storage keeps smaller versions on the Mac and the
///   original, full-size photos in iCloud.
/// - <https://github.com/muxcmux/apple-photos-forensics> — originals in
///   `originals/<hex>/<ZUUID>.<ext>`; resized versions with latest edits in
///   `resources/derivatives/`, tiny thumbnails in `resources/derivatives/masters/`.
pub(crate) static MACOS_PHOTOS_DERIVATIVES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_photos_derivatives",
    name: "Photos Library Derivatives (resized renders and thumbnails)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Pictures/*.photoslibrary/resources/derivatives/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Resized copies Photos keeps inside the library bundle: medium renders \
        directly under resources/derivatives/ and small thumbnails under \
        resources/derivatives/masters/, named by the asset's ZUUID and reflecting the \
        latest edits; full originals live under originals/. With iCloud Photos and \
        Optimize Mac Storage on, Apple keeps smaller versions on the Mac and the \
        full-size originals in iCloud, so for some assets a derivative may be the only \
        image content on the disk. Join on ZUUID in Photos.sqlite to recover the asset's \
        dates and metadata.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "asset_uuid", value_type: ValueType::Guid, description: "ZUUID of the asset in Photos.sqlite, used as the file name stem", is_uid_component: true },
    ],
    retention: Some("Regenerated by Photos; persists with the asset"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_photos_db"],
    sources: &[
        "https://support.apple.com/guide/photos/optimize-storage-in-photos-on-mac-phta9b4673b4/mac",
        "https://github.com/muxcmux/apple-photos-forensics",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "Folder layout is from one community write-up (muxcmux/apple-photos-forensics), not Apple; Apple documents only that optimised libraries keep smaller versions locally",
        "Derivatives are reduced renders that include edits; they do not carry the original's full resolution and may not carry its EXIF",
        "Photos can regenerate derivatives, so their file-system dates reflect rendering, not capture",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Render cache persists with the library",
};

pub(crate) static MACOS_ICLOUD_DRIVE_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_icloud_drive_db",
    name: "iCloud Drive Local Metadata",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Application Support/CloudDocs/session/db/client.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "iCloud Drive local metadata database. Records files synced to/from iCloud, modification timestamps, and sync state. Critical for identifying cloud-based data exfiltration — shows what was uploaded even if local files are deleted.",
    mitre_techniques: &["T1567.002"],
    fields: &[
        FieldSchema { name: "relative_path", value_type: ValueType::Text, description: "File path relative to iCloud Drive root", is_uid_component: true },
        FieldSchema { name: "mtime", value_type: ValueType::Timestamp, description: "Last modification time", is_uid_component: false },
    ],
    retention: Some("Updated on sync; reflects cloud state"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_fsevents", "macos_spotlight_store"],
    sources: &["https://www.mac4n6.com/blog/2020/3/21/icloud-drive-forensics"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only reflects locally synced state; cloud-only files may not appear",
        "User can disable iCloud Drive",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Local sync metadata database persists until iCloud unlinked",
};

pub(crate) static MACOS_LOCATIOND_CLIENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_locationd_clients",
    name: "Location Services Client Authorization",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/private/var/db/locationd/clients.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Records which applications have requested location services and their authorization status. Reveals apps with location access — critical for detecting surveillance tools, stalkerware, or unauthorized location tracking apps.",
    mitre_techniques: &["T1430"],
    fields: &[
        FieldSchema { name: "bundle_id", value_type: ValueType::Text, description: "Application bundle ID", is_uid_component: true },
        FieldSchema { name: "authorized", value_type: ValueType::Bool, description: "Whether location access is authorized", is_uid_component: false },
    ],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_tcc_db", "macos_tcc_system_db"],
    sources: &["https://www.mac4n6.com/blog/2019/6/20/ios-and-macos-location-services"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Reflects authorization state, not actual location queries"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Plist persists until app uninstall or authorization reset",
};

pub(crate) static MACOS_LOCKDOWND_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_lockdownd_log",
    name: "Lockdownd Log (iOS device pairing)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/private/var/log/lockdownd.log"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Lockdown daemon log recording USB/Lightning device pairing events with iOS devices — establishes which iPhones/iPads were connected and when. Critical for mobile device investigations, establishing device-to-Mac relationships.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "device_udid", value_type: ValueType::Text, description: "iOS device UDID", is_uid_component: true },
        FieldSchema { name: "pair_event", value_type: ValueType::Text, description: "Pairing event type", is_uid_component: false },
    ],
    retention: Some("Rotated"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log"],
    sources: &["https://www.mac4n6.com/blog/2016/4/22/ios-device-pairing-records"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Log rotates and may not preserve full pairing history"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Daemon log rotates with size/time limits",
};

pub(crate) static MACOS_INSTALLER_RECEIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_installer_receipts",
    name: "Third-Party Package Receipts",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Receipts/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Package receipts for third-party pkg installs. Each plist records package name, version, install date, and file list. Reveals software installation history including malicious packages — install timestamp persists even after app removal.",
    mitre_techniques: &["T1072"],
    fields: &[
        FieldSchema { name: "package_id", value_type: ValueType::Text, description: "Package identifier", is_uid_component: true },
        FieldSchema { name: "install_date", value_type: ValueType::Timestamp, description: "Package installation timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent after install; removed by uninstallers that clean up"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_install_history", "macos_gatekeeper_logs"],
    sources: &["https://www.mac4n6.com/blog/2016/6/22/macos-application-installation-history"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only covers .pkg installs; drag-install .app bundles leave no receipt",
        "Some installers clean up their own receipts",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Receipt plist persists until explicit deletion",
};

pub(crate) static MACOS_SAFARI_LOCALSTORAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_localstorage",
    name: "Safari HTML5 LocalStorage",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Safari/LocalStorage/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Safari HTML5 LocalStorage databases (per origin). May contain session tokens, user credentials cached by web apps, and browsing state not visible in standard history — critical for web session hijacking investigations.",
    mitre_techniques: &["T1539"],
    fields: &[
        FieldSchema { name: "origin", value_type: ValueType::Text, description: "Web origin (scheme+host+port)", is_uid_component: true },
    ],
    retention: Some("Persistent until cleared"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_safari_history", "macos_safari_downloads"],
    sources: &["https://www.mac4n6.com/blog/2016/6/23/safari-history"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "User can clear LocalStorage via Safari preferences",
        "Private browsing does not write here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Per-origin storage updated by web apps; persists until cleared",
};

pub(crate) static MACOS_NOTIFICATION_CENTER_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notification_center_db",
    name: "Notification Center Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Application Support/com.apple.notificationcenter/db2/db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Notification Center SQLite database. Records all delivered notifications with app, title, body, and timestamp — provides a timeline of alerts even when the originating app logs are cleared. Captures security alerts, email previews, and messages.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "app_id", value_type: ValueType::Text, description: "Application that sent the notification", is_uid_component: true },
        FieldSchema { name: "delivered_date", value_type: ValueType::Timestamp, description: "Notification delivery timestamp", is_uid_component: false },
        FieldSchema { name: "body", value_type: ValueType::Text, description: "Notification body text", is_uid_component: false },
    ],
    retention: Some("Rolling window, typically days"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_knowledgec", "macos_sms_db"],
    sources: &["https://www.mac4n6.com/blog/2019/6/20/notification-center"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Notifications can be disabled per-app or system-wide",
        "Database periodically pruned",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "SQLite database with periodic pruning of old notifications",
};

pub(crate) static MACOS_MDM_ENROLLMENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_mdm_enrollment",
    name: "MDM Enrollment State",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Preferences/com.apple.mdmclient.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "MDM enrollment state plist recording MDM server URL, enrollment user, and push token. Establishes whether device is managed; important for enterprise investigations and detecting rogue MDM enrollment used as a persistence mechanism.",
    mitre_techniques: &["T1098"],
    fields: &[
        FieldSchema { name: "mdm_server_url", value_type: ValueType::Text, description: "MDM server URL", is_uid_component: true },
        FieldSchema { name: "enrolled_user", value_type: ValueType::Text, description: "Enrollment user identity", is_uid_component: false },
    ],
    retention: Some("Persistent until MDM unenrollment"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_tcc_system_db"],
    sources: &["https://www.mac4n6.com/blog/2020/9/15/mdm-forensics"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Rogue MDM enrollment (T1098 persistence) creates a legitimate-looking plist; cross-validate MDM server URL against known corporate MDM infrastructure"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Plist persists until MDM unenrollment",
};

pub(crate) static MACOS_ASL_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_asl_logs",
    name: "Apple System Log (ASL) Binary Logs",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/private/var/log/asl/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Legacy Apple System Log binary files (pre-Unified Log, macOS 10.11 and earlier, but may persist on upgraded systems). Contains authentication, kext load, sudo, and daemon messages useful for historical analysis on older Mac images.",
    mitre_techniques: &["T1685.006"], // v19: T1685.006 Clear Linux or Mac System Logs; the Windows-only predecessor never fit this artifact
    fields: &[
        FieldSchema { name: "sender", value_type: ValueType::Text, description: "Process that generated the message", is_uid_component: true },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Log message text", is_uid_component: false },
    ],
    retention: Some("Rotated periodically; older files compressed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_unified_log"],
    sources: &["https://www.mac4n6.com/blog/2016/2/5/asl-logging"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &["Legacy format; only relevant on pre-Sierra systems or upgraded systems retaining old logs"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Legacy ASL logs rotated by aslmanager",
};

pub(crate) static MACOS_DIAGNOSTIC_REPORTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_diagnostic_reports",
    name: "Diagnostic Reports (crash logs)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Logs/DiagnosticReports/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "System-wide crash and hang reports (.ips/.crash format). Reveals process names, code-signing info, entitlements, exception types, and exact timestamps of application failures — useful for anti-forensics and malware crash attribution. Unsigned processes appear clearly.",
    mitre_techniques: &["T1518"],
    fields: &[
        FieldSchema { name: "process_name", value_type: ValueType::Text, description: "Crashed process name", is_uid_component: true },
        FieldSchema { name: "crash_time", value_type: ValueType::Timestamp, description: "Crash timestamp", is_uid_component: false },
        FieldSchema { name: "code_signing_id", value_type: ValueType::Text, description: "Code signing identifier", is_uid_component: false },
    ],
    retention: Some("Up to ~100 reports retained"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_unified_log"],
    sources: &["https://www.mac4n6.com/blog/2016/4/18/crash-logs-in-os-x"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Reports may be cleared by user or system maintenance",
        "Only generated for processes that crash",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Crash reports accumulate; older reports purged by retention policy",
};

/// macOS QuickLook thumbnail cache — proves file was previewed.
///
/// macOS generates thumbnails proactively when Finder renders column view,
/// gallery view, or the user presses Space (Quick Look). The SQLite database
/// `index.sqlite` records the previewed file's path and last access time even
/// after the original file is deleted, making this a stronger evidentiary claim
/// than most file-accessed timestamps.
///
/// Two files coexist in `com.apple.QuickLook.thumbnailcache/`:
/// - `index.sqlite`    — metadata (file_path, last_hit_date, hit_count, volume_uuid)
/// - `thumbnails.data` — proprietary raw bitmap format; not standard image headers;
///   extractable via hex offset analysis (RGB Alpha bitmaps)
///
/// The directory location uses NSURL-style volatile temp paths
/// (`/private/var/folders/<random>/<random>/C/`) — enumerate all user subdirs.
///
/// # Sources
/// - <https://az4n6.blogspot.com/2016/10/quicklook-thumbnailsdata-parser.html> — thumbnails.data
///   bitmap format, hex extraction via GIMP raw importer
/// - <https://az4n6.blogspot.com/2016/05/quicklook-python-parser-all-your-blobs.html> — index.sqlite schema
/// - <http://iacis.org/iis/2014/10_iis_2014_421-430.pdf> — Sara Newcomer's IACIS white paper
pub(crate) static MACOS_QUICKLOOK_THUMBNAILS: ArtifactDescriptor = ArtifactDescriptor {
    id: "quicklook_thumbnails",
    name: "QuickLook Thumbnail Cache",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SQLite database recording every file for which macOS generated a Quick Look \
        thumbnail (Finder column/gallery view, Space-bar preview). Retains file_path and \
        last_hit_date even after the original file is deleted — stronger evidence of human \
        file access than MRU or accessed timestamps alone. hit_count indicates repeated access. \
        The files table version BLOB contains a binary plist with the original file's size, \
        last-modified date, and the QuickLook plugin that generated the thumbnail. \
        Records files from removable media (e.g. USB thumb drives) and persist after the \
        volume is ejected. The co-located thumbnails.data file contains raw RGB Alpha bitmaps \
        without standard headers; images recoverable via hex offset analysis or GIMP raw import. \
        Directory path uses volatile NSURL temp folders — enumerate all \
        /private/var/folders/*/*/C/ subdirectories.",
    mitre_techniques: &["T1005", "T1083"],
    fields: &[
        FieldSchema {
            name: "file_path",
            value_type: ValueType::Text,
            description: "Full path of the file whose thumbnail was generated; \
                persists after file deletion until cache is cleared",
            is_uid_component: true,
        },
        FieldSchema {
            name: "last_hit_date",
            value_type: ValueType::Timestamp,
            description: "Cocoa epoch (Jan 1 2001) timestamp of last thumbnail access \
                or generation; convert: unix_ts = cocoa_ts + 978307200",
            is_uid_component: false,
        },
        FieldSchema {
            name: "hit_count",
            value_type: ValueType::UnsignedInt,
            description: "Number of times a thumbnail was requested for this file; \
                > 1 indicates repeated viewing",
            is_uid_component: false,
        },
        FieldSchema {
            name: "volume_uuid",
            value_type: ValueType::Text,
            description: "UUID of the volume containing the original file; \
                pivot to mount history if file is on removable media",
            is_uid_component: false,
        },
        // Source: version BLOB plist fields documented in
        // https://az4n6.blogspot.com/2016/05/quicklook-python-parser-all-your-blobs.html
        FieldSchema {
            name: "original_file_size",
            value_type: ValueType::UnsignedInt,
            description: "Size in bytes of the original file at thumbnail generation time; \
                extracted from the binary plist stored in the files table version BLOB",
            is_uid_component: false,
        },
        FieldSchema {
            name: "original_last_modified",
            value_type: ValueType::Timestamp,
            description: "Last-modified date of the original file (Cocoa epoch); \
                extracted from the version BLOB plist — useful when the original file is deleted",
            is_uid_component: false,
        },
    ],
    retention: Some(
        "Cache cleared on logout/reboot rotation; survives across sessions \
        until macOS quota enforcement evicts entries",
    ),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_fsevents"],
    sources: &[
        // Source: thumbnails.data bitmap format, hex carving, GIMP raw import
        "https://az4n6.blogspot.com/2016/10/quicklook-thumbnailsdata-parser.html",
        // Source: index.sqlite schema (file_path, last_hit_date, hit_count, volume_uuid, version BLOB)
        "https://az4n6.blogspot.com/2016/05/quicklook-python-parser-all-your-blobs.html",
        // Source: Sara Newcomer IACIS white paper — detailed QuickLook artifact analysis
        "http://iacis.org/iis/2014/10_iis_2014_421-430.pdf",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Database in volatile NSURL temp folder — may be cleared on reboot or by tmpcleaner",
        "hit_count requires repeated previews to be meaningful",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale:
        "Updated on each Quick Look preview; entries persist until temp folder cleared",
};

/// Apple Intelligence WiFi context events database.
///
/// macOS 15.1+ (Sequoia) on Apple Silicon (M1+) creates an IntelligencePlatform
/// directory under ~/Library/. The `views.db` SQLite database contains a
/// `wifiContextEvents` table that logs every WiFi connect and disconnect event
/// with timestamps (Cocoa/NSDate epoch). The folder structure exists even on
/// macOS 14+ devices without Apple Silicon, though the database may be empty.
///
/// Data is periodically emptied — typically contains the current month but
/// sometimes spans a few months back.
///
/// Parsers: mac_apt WIFI_INTELLIGENCE plugin, Velociraptor artifact exchange.
// Source: https://www.swiftforensics.com/2025/01/new-wifi-database-from-apple.html
pub(crate) static MACOS_WIFI_INTELLIGENCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_intelligence",
    name: "Apple Intelligence WiFi Context Events",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: http://www.swiftforensics.com/2025/01/new-wifi-database-from-apple.html
    file_path: Some("/Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SQLite database (table wifiContextEvents) logging every WiFi network connect \
        and disconnect event with Cocoa/NSDate timestamps. Reveals network connection \
        history including SSIDs and connection/disconnection timing. Complements the \
        traditional com.apple.airport.preferences.plist which records known networks \
        but not granular connect/disconnect events. Requires macOS 15.1+ (Sequoia) on \
        Apple Silicon (M1+). Data is periodically emptied — typically covers the \
        current month.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema {
            name: "ssid",
            value_type: ValueType::Text,
            description: "WiFi network SSID for the connect/disconnect event",
            is_uid_component: true,
        },
        FieldSchema {
            name: "event_type",
            value_type: ValueType::Text,
            description: "Event type: connect or disconnect",
            is_uid_component: false,
        },
        FieldSchema {
            name: "timestamp",
            value_type: ValueType::Timestamp,
            description: "Cocoa/NSDate epoch timestamp (seconds since 2001-01-01); \
                convert: unix_ts = cocoa_ts + 978307200",
            is_uid_component: false,
        },
    ],
    retention: Some("Periodically emptied; typically current month, sometimes a few months"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_wifi_plist", "macos_knowledgec"],
    sources: &[
        // Source: Yogesh Khatri — discovery of wifiContextEvents table in views.db
        "https://www.swiftforensics.com/2025/01/new-wifi-database-from-apple.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires macOS 15.1+ on Apple Silicon (M1+)",
        "Data periodically emptied — typically only current month",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Database periodically purged; typically retains current month only",
};

/// APFS (Apple File System) container — the default macOS filesystem since
/// High Sierra (10.13). An APFS container is a whole-disk structure that holds
/// one or more APFS volumes (typically "Macintosh HD" and "Macintosh HD - Data"
/// on modern macOS). Each container has a UUID, checkpoint history, and
/// space-sharing across volumes.
///
/// Forensic acquisition requires identifying the APFS container partition within
/// a GPT layout. On a raw or E01 image, use `mmls` (Sleuthkit) to find the APFS
/// partition offset (typically after the EFI System Partition), then calculate
/// the byte offset (sector_offset * bytes_per_sector) for loopback mounting.
///
/// On Linux, the experimental `apfs-fuse` driver (sgan81/apfs-fuse) mounts APFS
/// containers read-only. It supports encrypted volumes (prompts for password).
/// Workflow: `ewfmount` (for E01) → `mmls` → `losetup -r -o <byte_offset>` →
/// `apfs-fuse /dev/loop0 /mnt/apfs`.
///
/// The partition start is in units of the DISK's logical sector size, as the
/// partition table reports it (mmls prints "Units are in N-byte sectors"):
/// 512 bytes on many Macs (observed on one Intel iMac, where the 200 MiB EFI
/// System Partition is 409,600 sectors), 4096 on 4K-sector disks such as the
/// one in the az4n6 Linux post. APFS's own block size (nx_block_size, default
/// 4096) is a separate quantity: Apple's reference says it can be an integer
/// multiple of the device's block size, so it is never the offset multiplier.
/// The container superblock ("NXSB") is at the start of the APFS partition.
///
/// On Windows, Paragon's "APFS for Windows" driver can mount APFS volumes
/// natively once the image is presented as a SCSI device via Arsenal Image
/// Mounter (sector size must be set to 4096). The Paragon driver auto-detects
/// the APFS volume. This does NOT work for FileVault-encrypted disks — Arsenal
/// only emulates a physical disk; decryption requires the actual APFS stack.
///
/// # Sources
/// - <https://az4n6.blogspot.com/2018/01/how-to-mount-mac-apfs-images-in-windows.html> —
///   Windows APFS mounting via Arsenal Image Mounter + Paragon APFS driver
/// - <https://az4n6.blogspot.com/2018/01/mounting-apfs-image-in-linux.html> —
///   step-by-step APFS mounting on Linux with apfs-fuse, mmls offset calculation
/// - <https://github.com/sgan81/apfs-fuse> — experimental Linux APFS driver
/// - <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf> —
///   nx_block_size: "often the same as the block size used by the underlying
///   storage device, but it can also be an integer multiple of the device's
///   block size"; NX_DEFAULT_BLOCK_SIZE 4096
/// - <https://www.mac4n6.com/blog/2017/11/26/mount-all-the-things-mounting-apfs-and-4k-disk-images-on-macos-1013>
///   — Macs moved from 512-byte to 4k blocks; hdiutil `-blocksize 4096` for
///   4k images
// Source: https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system
pub(crate) static APFS_CONTAINER: ArtifactDescriptor = ArtifactDescriptor {
    id: "apfs_container",
    name: "APFS Container (Apple File System)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Apple File System container — the whole-disk structure introduced in macOS \
        10.13 (High Sierra) that holds one or more APFS volumes with space-sharing, \
        snapshots, clones, and optional per-volume encryption. Forensic acquisition \
        requires locating the APFS partition via GPT partition table analysis (mmls), \
        calculating the byte offset (sector_offset * bytes_per_sector, where bytes_per_sector \
        is the disk's logical sector size as the partition table reports it: 512 on many \
        Macs, 4096 on 4K-sector disks; APFS's own block size, nx_block_size, default 4096, \
        is a different quantity and is not the multiplier), \
        and mounting with apfs-fuse on Linux or hdiutil/diskutil on macOS. On Windows, \
        Arsenal Image Mounter can present the image as a SCSI device (sector size 4096) \
        so that Paragon APFS for Windows auto-detects and mounts the volume — but this \
        does not work for FileVault-encrypted disks. The container superblock (magic \
        'NXSB') anchors all volume metadata. Encrypted volumes require the user password \
        or recovery key. For live acquisition of a FileVault2-encrypted Mac, the logged-in \
        system presents the decrypted logical volume (visible as 'Unlocked Encrypted' in \
        diskutil list output). Image via /dev/rdisk (raw, unbuffered device node) rather \
        than /dev/disk for significantly faster throughput — dd with rdisk completes in \
        ~15 minutes vs ~2 hours with FTK Imager CLI on equivalent hardware. Use \
        'dd if=/dev/rdisk1 bs=4k conv=sync,noerror | tee image.dd | md5' for simultaneous \
        imaging and hash verification. Critical for any macOS 10.13+ disk forensics — \
        without proper APFS support, the primary data volume is inaccessible.",
    mitre_techniques: &["T1005", "T1006"],
    fields: &[
        FieldSchema {
            name: "container_uuid",
            value_type: ValueType::Guid,
            description: "UUID identifying the APFS container; unique per physical \
                container instance",
            is_uid_component: true,
        },
        FieldSchema {
            name: "volume_name",
            value_type: ValueType::Text,
            description: "Name of each APFS volume within the container (e.g. \
                'Macintosh HD', 'Preboot', 'Recovery')",
            is_uid_component: false,
        },
        FieldSchema {
            name: "encryption_state",
            value_type: ValueType::Text,
            description: "Per-volume encryption status (encrypted/unencrypted); \
                encrypted volumes require password or recovery key for mounting",
            is_uid_component: false,
        },
        FieldSchema {
            name: "partition_offset_sectors",
            value_type: ValueType::UnsignedInt,
            description: "Starting sector offset of the APFS partition within the \
                disk image GPT layout; multiply by bytes_per_sector for byte offset",
            is_uid_component: false,
        },
        FieldSchema {
            name: "bytes_per_sector",
            value_type: ValueType::UnsignedInt,
            description: "The disk's logical sector size in bytes, from the partition \
                table (512 or 4096 depending on the disk); not APFS's block size. \
                Critical for correct offset calculation during acquisition",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent; exists for lifetime of the volume"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_fsevents", "macos_spotlight_store"],
    sources: &[
        // Source: https://az4n6.blogspot.com/2018/01/how-to-mount-mac-apfs-images-in-windows.html
        // — Windows APFS mounting via Arsenal Image Mounter (SCSI, 4096 sectors) + Paragon driver
        "https://az4n6.blogspot.com/2018/01/how-to-mount-mac-apfs-images-in-windows.html",
        // Source: https://az4n6.blogspot.com/2018/01/mounting-apfs-image-in-linux.html
        // — Linux APFS mounting workflow with mmls, losetup, apfs-fuse
        "https://az4n6.blogspot.com/2018/01/mounting-apfs-image-in-linux.html",
        // Source: https://github.com/sgan81/apfs-fuse — experimental Linux APFS FUSE driver
        "https://github.com/sgan81/apfs-fuse",
        // Source: Apple File System Reference — nx_block_size may be a multiple
        // of the device block size
        "https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf",
        // Source: mac4n6 — 512-byte vs 4k-block Mac disk images
        "https://www.mac4n6.com/blog/2017/11/26/mount-all-the-things-mounting-apfs-and-4k-disk-images-on-macos-1013",
        // Source: https://az4n6.blogspot.com/2016/09/mac-live-imaging-functionality-versus.html
        // — live imaging FileVault2 via dd + /dev/rdisk; speed comparison dd vs FTK Imager CLI
        "https://az4n6.blogspot.com/2016/09/mac-live-imaging-functionality-versus.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "FileVault-encrypted containers require unlock for analysis",
        "Snapshot history depends on Time Machine and APFS snapshot policy",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Disk container structure persists for life of the volume",
};

// ── iOS artifacts ─────────────────────────────────────────────────────────────

/// iOS Apple Unified Log — on-device AUL at `/private/var/db/diagnostics/`
/// and `/private/var/db/uuidtext/`.
///
/// The Apple Unified Logging system on iOS stores structured, timestamped log
/// entries in `.tracev3` binary files under `/private/var/db/diagnostics/`.
/// Supporting format-string tables live in `/private/var/db/uuidtext/` and
/// shared-cache DSC files. Together they form a `.logarchive` when combined
/// with a `timesync/` directory and an `Info.plist` containing
/// `OSArchiveVersion`.
///
/// This is distinct from `macos_unified_log` — same underlying format but
/// different OS scope, extraction workflow, and forensic context:
/// - **Extraction methods**: `sudo log collect --device` from connected Mac,
///   UFADE (github.com/prosch88/UFADE), iOS Logs Acquisition Tool
///   (ios-unifiedlogs.com), or direct pull from full file system extraction
/// - **Processing**: iLEAPP logarchive module → `_lava_artifacts.db` SQLite;
///   or `nfstream`/`log show` on macOS after reconstructing `.logarchive`
/// - **Forensic value**: device orientation, screen lock/unlock with biometrics,
///   navigation start with destination address, power on/off, app opening,
///   apps in focus, horizontal scrolling — all timestamped
///
/// The `.ini` file at session close → Prefetch correlation that works on
/// Windows has no analogue here; instead correlate with iOS `knowledgeC.db`
/// and `screentime` artifacts for usage timeline cross-validation.
///
/// # Sources
/// - <https://abrignoni.blogspot.com/2025/05/extraction-processing-querying-apple.html>
///   Complete extraction → processing → querying workflow for iOS AUL
/// - <https://www.ios-unifiedlogs.com>
///   Lionel Notari's aggregated iOS unified log artifact research
pub(crate) static IOS_UNIFIED_LOG_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "Log entry timestamp from .tracev3 record; nanosecond precision; \
            continuous time clock anchored via timesync/ calibration files",
        is_uid_component: true,
    },
    FieldSchema {
        name: "process_id",
        value_type: ValueType::Integer,
        description: "PID of the process that generated the log entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "subsystem",
        value_type: ValueType::Text,
        description: "Logging subsystem identifier (e.g. com.apple.locationd, \
            com.apple.springboard); primary filter for artifact-specific queries",
        is_uid_component: false,
    },
    FieldSchema {
        name: "category",
        value_type: ValueType::Text,
        description: "Category within the subsystem; narrows queries beyond subsystem alone",
        is_uid_component: false,
    },
    FieldSchema {
        name: "event_message",
        value_type: ValueType::Text,
        description: "Formatted log message after resolving format strings from uuidtext/DSC; \
            contains the human-readable event detail",
        is_uid_component: false,
    },
    FieldSchema {
        name: "trace_id",
        value_type: ValueType::UnsignedInt,
        description: "Activity trace identifier; correlates related log entries across \
            subsystems within a single user action or system event",
        is_uid_component: false,
    },
];

pub(crate) static IOS_UNIFIED_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_unified_log",
    name: "iOS Apple Unified Log",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/db/diagnostics/"),
    scope: DataScope::System,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Apple Unified Logging on iOS. Binary .tracev3 files under \
        /private/var/db/diagnostics/ with format-string support files in \
        /private/var/db/uuidtext/. Contains timestamped structured log entries \
        for all system and application activity: device orientation, screen \
        lock/unlock with biometrics, navigation with destination addresses, \
        power events, app launches and focus changes. Extraction via \
        'log collect --device', UFADE, iOS Logs Acquisition Tool, or full \
        file system pull. Process with iLEAPP logarchive module into \
        _lava_artifacts.db for querying. Primary timeline source on iOS — \
        equivalent to macos_unified_log but with iOS-specific subsystems \
        and extraction workflow.",
    mitre_techniques: &["T1685.006", "T1059"], // v19: T1685.006 (Mac system logs), not the Windows T1685.005
    fields: IOS_UNIFIED_LOG_FIELDS,
    retention: Some("Rotated by OS; typically days to weeks depending on device activity"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_unified_log"],
    sources: &[
        // Source: Abrignoni — complete iOS AUL extraction/processing/querying workflow
        "https://abrignoni.blogspot.com/2025/05/extraction-processing-querying-apple.html",
        // Source: Lionel Notari — aggregated iOS unified log artifact research
        "https://www.ios-unifiedlogs.com",
        // Source: Apple developer documentation — os/logging framework reference
        "https://developer.apple.com/documentation/os/logging",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires full file system extraction, sysdiagnose, or log collect --device for acquisition",
        "Log rotation on iOS is aggressive — days to weeks depending on device activity",
        "Format strings in uuidtext/ required for human-readable messages; without them, raw hex only",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "iOS aggressively rotates .tracev3 files; high-activity devices may retain only days of history",
};

// ── HEIC Image File (iOS 11+ / macOS High Sierra+) ─────────────────────────

/// HEIC (High Efficiency Image Container) files — `.heic` extension.
///
/// Introduced with iOS 11 and macOS High Sierra (10.13). Apple uses the HEIF
/// (High Efficiency Image File Format) container with HEVC/H.265 compression
/// for camera photos and Live Photos. The container is based on ISO Base Media
/// File Format (ISO 14496-12, same family as QuickTime `.mov`).
///
/// File structure uses a box/atom hierarchy:
/// - `ftyp` box: major_brand = `heic`, compatible_brands = `mif1`, `heic`
/// - `meta` box: contains `hdlr` (handler_type `pict`), `iinf` (item count),
///   `iloc` (item locations), `iprp` (item properties including EXIF)
/// - `mdat` box: raw HEVC-compressed image data
///
/// EXIF metadata (GPS, camera model, timestamps) is preserved inside the
/// container and extractable with ExifTool. A single HEIC can contain multiple
/// images (e.g., Apple Live Photo = still + short video + audio).
///
/// Forensic value: HEIC files from iOS devices contain full EXIF including GPS
/// coordinates, device model, lens info, and capture timestamps. Same metadata
/// as JPEG but in a newer container that some legacy tools may not parse.
///
/// # Sources
/// - <https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html> —
///   HEIC file structure walkthrough with hex analysis, ExifTool extraction
/// - <https://nokiatech.github.io/heif/technical.html> — Nokia HEIF technical spec
// Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
pub(crate) static HEIC_IMAGE_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "heic_image_file",
    name: "HEIC Image File (High Efficiency Image Container)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
    // iOS default photo format since iOS 11; also on macOS High Sierra+
    file_path: Some("/DCIM/**/*.heic"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "High Efficiency Image File Format (HEIF) container using HEVC/H.265 \
        compression, introduced in iOS 11 and macOS High Sierra (10.13). Based on \
        ISO Base Media File Format (ISO 14496-12). The ftyp box identifies the \
        major brand as 'heic'; the meta box contains hdlr (handler_type 'pict'), \
        iinf (item inventory with entry count), iloc (byte offsets to media data), \
        and iprp (item properties including embedded EXIF). A single HEIC file can \
        contain multiple images (burst, Live Photo still + video + audio). EXIF \
        metadata including GPS coordinates, camera model, lens info, and original \
        capture timestamp is preserved and extractable with ExifTool. Approximately \
        halves file size vs JPEG at equivalent quality. Some legacy forensic tools \
        may not parse HEIC — convert to JPEG via sips (macOS) or ffmpeg for \
        compatibility. For video, Apple uses HEVC in .mov containers with the same \
        H.265 codec.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema {
            name: "major_brand",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
            description: "ftyp box major brand identifier (typically 'heic' for Apple photos)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "compatible_brands",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
            description: "ftyp box compatible brands list (e.g. 'mif1', 'heic')",
            is_uid_component: false,
        },
        FieldSchema {
            name: "handler_type",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
            description: "hdlr box handler type: 'pict' for still image, 'vide' for video",
            is_uid_component: false,
        },
        FieldSchema {
            name: "item_count",
            value_type: ValueType::UnsignedInt,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
            description: "Number of items stored in the container (iinf entry_count); \
                > 1 indicates multi-image (Live Photo, burst)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "exif_gps_latitude",
            value_type: ValueType::Text,
            description: "GPS latitude from embedded EXIF metadata (decimal degrees)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "exif_gps_longitude",
            value_type: ValueType::Text,
            description: "GPS longitude from embedded EXIF metadata (decimal degrees)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "exif_datetime_original",
            value_type: ValueType::Timestamp,
            description: "Original capture date/time from EXIF DateTimeOriginal tag",
            is_uid_component: true,
        },
        FieldSchema {
            name: "exif_camera_model",
            value_type: ValueType::Text,
            description: "Camera model from EXIF Model tag (e.g. 'iPhone 8 Plus')",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until user deletion; syncs via iCloud Photos"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_photos_db"],
    sources: &[
        // Source: https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html
        // — HEIC file structure hex walkthrough, ExifTool extraction, ffmpeg conversion
        "https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html",
        // Source: https://nokiatech.github.io/heif/technical.html
        // — Nokia/MPEG HEIF technical specification and box structure reference
        "https://nokiatech.github.io/heif/technical.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "EXIF metadata can be stripped by the user or messaging apps",
        "Some legacy forensic tools may not parse HEIC",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Image file persists on storage until explicit deletion",
};

// ── iOS14 Apple Maps History (MapsSync_0.0.1) ────────────────────────────────

/// Field schema for the ZHISTORYITEM + ZMIXINMAPITEM tables in MapsSync_0.0.1.
/// SQL query from Heather Mahalik's research (adapted by cheeky4n6monkey):
///   SELECT ZHISTORYITEM.z_pk, z_ent, ZCREATETIME, ZMODIFICATIONTIME,
///          ZQUERY, ZLOCATIONDISPLAY, ZLATITUDE, ZLONGITUDE,
///          ZROUTEREQUESTSTORAGE, ZMAPITEMSTORAGE
///   FROM ZHISTORYITEM LEFT JOIN ZMIXINMAPITEM ON ZMIXINMAPITEM.Z_PK=ZHISTORYITEM.ZMAPITEM;
/// Source: <https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html>
pub(crate) static IOS14_MAPS_HISTORY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "z_pk",
        value_type: ValueType::Integer,
        description: "Primary key / item number in ZHISTORYITEM table",
        is_uid_component: true,
    },
    FieldSchema {
        name: "z_ent",
        value_type: ValueType::Integer,
        // Source: https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html
        description: "Entry type indicator: 14 = coordinates of search, \
            16 = location search (text), 12 = navigation journey. Determines \
            which BLOB columns are populated",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZCREATETIME",
        value_type: ValueType::Timestamp,
        // Source: https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html
        description: "Apple Cocoa epoch timestamp (seconds since 2001-01-01 00:00:00 UTC; \
            add 978307200 for UNIX epoch). Per Heather Mahalik's research, this is NOT \
            an accurate record of when the search was actually executed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZMODIFICATIONTIME",
        value_type: ValueType::Timestamp,
        description: "Apple Cocoa epoch timestamp of last modification (same caveat as \
            ZCREATETIME — may not reflect actual search execution time)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZQUERY",
        value_type: ValueType::Text,
        description: "Location search text entered by the user (populated for z_ent=16 \
            'location search' entries)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZLOCATIONDISPLAY",
        value_type: ValueType::Text,
        description: "Display name of the location city/area associated with the search",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZLATITUDE",
        value_type: ValueType::Text,
        description: "Latitude coordinate in decimal degrees (populated for z_ent=14 \
            'coordinates of search' entries)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZLONGITUDE",
        value_type: ValueType::Text,
        description: "Longitude coordinate in decimal degrees (populated for z_ent=14 \
            'coordinates of search' entries)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZROUTEREQUESTSTORAGE",
        value_type: ValueType::Bytes,
        description: "Protobuf BLOB containing start/end locations for navigation journeys \
            (z_ent=12). Can be decoded with protobuf_inspector. May contain destination \
            Yelp reviews and epoch millisecond timestamps after a GUID",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ZMAPITEMSTORAGE",
        value_type: ValueType::Bytes,
        description: "Protobuf BLOB from ZMIXINMAPITEM table containing map item storage \
            data (populated for z_ent=14 'coordinates of search' entries). Can be decoded \
            with protobuf_inspector",
        is_uid_component: false,
    },
];

pub(crate) static IOS14_MAPS_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios14_maps_history",
    name: "iOS14 Apple Maps History (MapsSync_0.0.1)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html
    file_path: Some("/private/var/mobile/Containers/Shared/AppGroup/<UUID>/MapsSync_0.0.1"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    retention: Some("Last 3-5 directions/searches retained"),
    meaning: "Apple Maps ZHISTORYITEM and ZMIXINMAPITEM tables in the MapsSync_0.0.1 SQLite \
        database on iOS 14+. Contains the last 3-5 map directions and searches. Three entry \
        types exist: 'location search' (z_ent=16, user-entered text query), 'coordinates of \
        search' (z_ent=14, lat/long with optional ZMAPITEMSTORAGE protobuf BLOB), and \
        'navigation journey' (z_ent=12, with ZROUTEREQUESTSTORAGE protobuf BLOB containing \
        start/end locations). Location searches are typically followed by coordinate entries. \
        Navigation journey entries may appear even without explicit user navigation requests. \
        Timestamps use Apple Cocoa epoch (add 978307200 for UNIX) but per Heather Mahalik's \
        research are NOT accurate records of when searches were executed. The database has \
        32 tables total but forensic value concentrates in ZHISTORYITEM. Protobuf BLOBs can \
        be decoded with protobuf_inspector for additional details including Yelp reviews \
        and potential timestamps.",
    mitre_techniques: &[],
    fields: IOS14_MAPS_HISTORY_FIELDS,
    triage_priority: TriagePriority::High,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html",
        // Source: Heather Mahalik's iOS14 research documenting the ZHISTORYITEM query
        "https://smarterforensics.com/2020/09/rotten-to-the-core-nah-ios14-is-mostly-sweet/",
        "https://github.com/cheeky4n6monkey/4n6-scripts",
    ],
    related_artifacts: &[],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Per Heather Mahalik's research, timestamps are NOT accurate records of when searches were executed",
        "Only retains last 3-5 entries",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Bounded to last 3-5 entries; FIFO eviction on new searches",
};

// ── Uber iOS LevelDB trip/location history ──────────────────────────────────

/// Field schema for Uber iOS LevelDB location records.
/// Source: <https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py>
pub(crate) static UBER_IOS_LEVELDB_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        // Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py
        description: "Record timestamp from jsonConformingObject.meta.time_ms (epoch ms)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "city",
        value_type: ValueType::Text,
        description: "City name from the location metadata",
        is_uid_component: false,
    },
    FieldSchema {
        name: "speed",
        value_type: ValueType::Text,
        description: "Speed value from the location metadata",
        is_uid_component: false,
    },
    FieldSchema {
        name: "gps_time",
        value_type: ValueType::Timestamp,
        // Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py
        description: "GPS fix timestamp from location.gps_time_ms (epoch ms)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "latitude",
        value_type: ValueType::Text,
        description: "GPS latitude coordinate",
        is_uid_component: false,
    },
    FieldSchema {
        name: "longitude",
        value_type: ValueType::Text,
        description: "GPS longitude coordinate",
        is_uid_component: false,
    },
    FieldSchema {
        name: "horizontal_accuracy",
        value_type: ValueType::Text,
        description: "Horizontal accuracy of the GPS fix in meters",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ui_timestamp",
        value_type: ValueType::Timestamp,
        description: "UI state timestamp from ui_state.timestamp_ms (epoch ms)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ui_metadata",
        value_type: ValueType::Text,
        description: "UI state metadata string",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ui_scene",
        value_type: ValueType::Text,
        description: "UI scene identifier (e.g. ride request, in-trip, idle)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "active_trips",
        value_type: ValueType::Text,
        description: "Active trip information from the record data payload",
        is_uid_component: false,
    },
    FieldSchema {
        name: "record_sequence",
        value_type: ValueType::Integer,
        description: "LevelDB record sequence number",
        is_uid_component: true,
    },
];

/// Uber iOS app LevelDB location and trip history.
///
/// The Uber rider app (com.ubercab.UberClient) stores JSON-serialized location
/// telemetry in a LevelDB database under the storagev2 directory. Each record
/// contains GPS coordinates, speed, city, horizontal accuracy, timestamps, UI
/// state, and active trip information. Parsed by iLEAPP's uberLeveldb module.
///
/// Source: <https://abrignoni.blogspot.com/2024/04/new-parser-for-uber-app-geo-locatios-in.html>
/// Source: <https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py>
pub(crate) static UBER_IOS_LEVELDB: ArtifactDescriptor = ArtifactDescriptor {
    id: "uber_ios_leveldb",
    name: "Uber iOS LevelDB Location/Trip History",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py
    file_path: Some(
        "/Data/Application/*/Library/Application Support/com.ubercab.UberClient/storagev2/*",
    ),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Uber iOS rider app LevelDB location and trip telemetry. Each JSON record \
in the storagev2 LevelDB contains: GPS coordinates (latitude/longitude), speed, city, \
horizontal accuracy, GPS fix timestamp, record timestamp, UI state (scene, metadata), \
and active trip information. Records are JSON-serialized under the key path \
jsonConformingObject.meta (timestamps, location) and jsonConformingObject.data \
(active_trips, ui_state, app_type_value_map). Timestamps are epoch milliseconds. \
Forensically valuable for establishing user location history, trip patterns, and \
movement timelines. Parsed by iLEAPP uberLeveldb module using CCL Solutions' \
LevelDB libraries.",
    mitre_techniques: &[
        "T1430", // Location Tracking (mobile)
    ],
    fields: UBER_IOS_LEVELDB_FIELDS,
    retention: Some("Persists until app data is cleared or app is uninstalled"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        // Source: https://abrignoni.blogspot.com/2024/04/new-parser-for-uber-app-geo-locatios-in.html (original blog post announcing the parser)
        "https://abrignoni.blogspot.com/2024/04/new-parser-for-uber-app-geo-locatios-in.html",
        // Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py (iLEAPP parser source with path and field extraction)
        "https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py",
        // Source: https://github.com/cclgroupltd/ccl_chrome_indexeddb (CCL LevelDB libraries used by the parser)
        "https://github.com/cclgroupltd/ccl_chrome_indexeddb",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "LevelDB compaction may purge older records",
        "Only present when Uber app is installed and used",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "LevelDB updated per app session; older records compacted away",
};

// ── iOS Google Chat cacheV0.db ──────────────────────────────────────────────

/// Field schema for the `cache` table in cacheV0.db.
/// Source: <https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html>
pub(crate) static IOS_GOOGLE_CHAT_CACHEV0_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "id",
        value_type: ValueType::Integer,
        // Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
        description: "Auto-incrementing integer primary key, sequentially assigned starting at 1",
        is_uid_component: true,
    },
    FieldSchema {
        name: "data",
        value_type: ValueType::Bytes,
        // Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
        description: "BLOB containing a thumbnail-resolution copy of an image rendered \
            by the app interface — includes chat-shared images, user avatars, and \
            images from deleted chats that no longer exist in the main image directory",
        is_uid_component: false,
    },
];

// iOS Google Chat (Dynamite) image thumbnail cache database.
//
// The `cacheV0.db` SQLite database is created by Google's image rendering
// pipeline (similar to Glide Image Manager Cache on Android). It contains a
// single `cache` table with `id` and `data` columns. Each `data` BLOB holds
// a reduced-resolution copy of every image the app has rendered in its UI,
// including user avatars and images from deleted chats.
//
// Key forensic insight: images from deleted conversations persist in this
// database even after the source files are removed from the main chat image
// directory. Also observed in Google Voice on iOS.
//
// Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
// ── macOS BTM (Background Task Management) ──────────────────────────────────

// macOS Background Task Management database — login items, launch agents/daemons,
// and background tasks tracked since macOS 13 Ventura. (Canonical descriptor:
// MACOS_BTM_BACKGROUND_TASKS, below.)
//
// NSKeyedArchive binary plist containing per-user dictionaries of all registered
// background tasks. Each item has a `type` flag (agent=0x08, daemon=0x10,
// login item=0x04, app=0x02, user item=0x01, developer=0x20, spotlight=0x40,
// quicklook=0x800, curated=0x80000, legacy=0x10000) and a `disposition` flag
// (Enabled=0x01, Allowed=0x02, Hidden=0x04, Notified=0x08). When a user
// toggles an item OFF in System Settings > Login Items & Extensions, the
// Allowed bit (0x02) is cleared.
//
// Multiple versioned .btm files may coexist (e.g. BackgroundItems-v9.btm from
// an older macOS and BackgroundItems-v13.btm from macOS 15). Older files are
// forensic snapshots of autostart state at that point in time.
//
// Source: http://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html
// Source: https://objective-see.org/blog/blog_0x31.html
// ── iOS Mobile Container Manager ─────────────────────────────────────────────

/// iOS containers.sqlite3 — maps apps to their extensions, AppGroups,
/// and entitlements.
///
/// Located at `/private/var/root/Library/MobileContainerManager/containers.sqlite3`.
/// Three main tables: `child_bundles` (extensions -> parent app), `code_signing_data`
/// (binary plist BLOBs with `com.apple.security.application-groups` entitlements),
/// and `containers` (base container info).
///
/// This is the authoritative mapping between iOS apps and their shared containers.
/// Without it, correlating UUID-based AppGroup folders to their owning app requires
/// reading individual `.com.apple.mobile_container_manager.metadata.plist` files
/// from each UUID folder under:
/// - `/private/var/containers/Shared/SystemGroup/<UUID>/`
/// - `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`
/// - `/private/var/mobile/Containers/Data/InternalDaemon/<UUID>/`
/// - `/private/var/mobile/Containers/Data/PluginKitPlugin/<UUID>/`
///
/// Source: <http://www.swiftforensics.com/2021/01/ios-application-groups-shared-data.html>
pub(crate) static IOS_MOBILE_CONTAINER_MANAGER: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_mobile_container_manager",
    name: "iOS Mobile Container Manager (containers.sqlite3)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: http://www.swiftforensics.com/2021/01/ios-application-groups-shared-data.html
    file_path: Some("/private/var/root/Library/MobileContainerManager/containers.sqlite3"),
    scope: DataScope::System,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "iOS Mobile Container Manager database mapping all installed apps to their \
        extensions, AppGroups, SystemGroups, and entitlements. The child_bundles table links \
        extensions to their parent app (e.g. com.apple.mobilenotes.SharingExtension -> \
        com.apple.mobilenotes). The code_signing_data table contains binary plist BLOBs \
        with com.apple.security.application-groups entitlements that identify shared \
        container groups. This is the only authoritative source on iOS for programmatically \
        resolving UUID-based shared container folders to their owning app — without it, \
        analysts must manually inspect .com.apple.mobile_container_manager.metadata.plist \
        files in each UUID folder. Critical for understanding data sharing between apps \
        and their extensions, and for locating app-specific databases stored in shared \
        AppGroup containers (e.g. the Notes database lives in group.com.apple.notes, not \
        the app's sandbox). Cross-reference with applicationState.db for sandbox paths.",
    mitre_techniques: &[
        "T1005", // Data from Local System
    ],
    fields: IOS_CONTAINER_MANAGER_FIELDS,
    retention: Some("Persists as long as apps are installed; updated on app install/uninstall"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        // Source: http://www.swiftforensics.com/2021/01/ios-application-groups-shared-data.html
        // (Yogesh Khatri documenting containers.sqlite3 structure, child_bundles table,
        // code_signing_data binary plist BLOBs, and AppGroup resolution methodology)
        "http://www.swiftforensics.com/2021/01/ios-application-groups-shared-data.html",
        // Source: https://github.com/ydkhatri/mac_apt (ios_apt APPS plugin implementing
        // automated AppGroup/extension/entitlement resolution)
        "https://github.com/ydkhatri/mac_apt",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Requires root/jailbreak or full filesystem extraction to access"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale:
        "iOS system database persists across reboots; updated on app install/uninstall",
};

pub(crate) static IOS_CONTAINER_MANAGER_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "bundle_id",
        value_type: ValueType::Text,
        description: "App bundle identifier (e.g. com.apple.mobilenotes)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "extension_bundle_id",
        value_type: ValueType::Text,
        description: "Extension bundle identifier from child_bundles table",
        is_uid_component: false,
    },
    FieldSchema {
        name: "parent_bundle_id",
        value_type: ValueType::Text,
        description: "Parent app bundle identifier that owns the extension",
        is_uid_component: false,
    },
    FieldSchema {
        name: "app_groups",
        value_type: ValueType::List,
        description: "List of com.apple.security.application-groups from code_signing_data \
            entitlements plist (e.g. group.com.apple.notes)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "system_groups",
        value_type: ValueType::List,
        description: "List of com.apple.security.system-groups from code_signing_data \
            entitlements plist",
        is_uid_component: false,
    },
];

pub(crate) static MACOS_BTM_BACKGROUND_TASKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_btm_background_tasks",
    name: "macOS Background Task Management (BTM)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: http://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html
    file_path: Some("/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm"),
    scope: DataScope::Mixed,
    os_scope: OsScope::MacOS13Plus,
    decoder: Decoder::Identity,
    meaning: "macOS Background Task Management database tracking login items, launch agents, \
        launch daemons, and background tasks since macOS 13 Ventura. NSKeyedArchive binary \
        plist with per-user dictionaries. Each item has a type flag (agent, daemon, login item, \
        app, user item, developer, spotlight, quicklook, curated, legacy) and a disposition \
        flag (Enabled, Allowed, Hidden, Notified). When a user disables an item in System \
        Settings > Login Items & Extensions, the Allowed bit is cleared. Multiple versioned \
        .btm files may coexist as forensic snapshots of prior autostart state. Key fields \
        include container (parent app bundle), developer identity, executableModifiedDate, \
        and AppArguments (full command line). Replaces the legacy backgrounditems.btm per-user \
        plist used before Ventura.",
    mitre_techniques: &[
        "T1543.001", // Create or Modify System Process: Launch Agent
        "T1543.004", // Create or Modify System Process: Launch Daemon
        "T1547.015", // Boot or Logon Autostart Execution: Login Items
    ],
    fields: MACOS_BTM_FIELDS,
    retention: Some(
        "Persists until macOS upgrade creates a new versioned .btm file; \
older versions remain on disk as forensic snapshots",
    ),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_login_items_plist"],
    sources: &[
        // Source: http://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html
        // (Yogesh Khatri's mac_apt AUTOSTART plugin update documenting BTM type/disposition flags,
        // versioned .btm files, and AppArguments parsing)
        "http://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html",
        // Source: https://objective-see.org/blog/blog_0x31.html (Patrick Wardle's analysis of BTM)
        "https://objective-see.org/blog/blog_0x31.html",
        // Source: https://forensics.wiki/mac_os_x_10.9_artifacts_location#autorun-locations-2
        "https://forensics.wiki/mac_os_x_10.9_artifacts_location#autorun-locations-2",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires macOS 13 Ventura or later",
        "Many legitimate apps install login items — context required",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale:
        "BTM database persists; versioned snapshots preserve prior autostart state",
};

pub(crate) static MACOS_BTM_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "item_type",
        value_type: ValueType::Text,
        description: "BTM item type flag: agent, daemon, login_item, app, user_item, \
            developer, spotlight, quicklook, curated, legacy",
        is_uid_component: false,
    },
    FieldSchema {
        name: "disposition",
        value_type: ValueType::Text,
        description: "BTM disposition flags: Enabled(0x01), Allowed(0x02), Hidden(0x04), \
            Notified(0x08); toggling OFF in System Settings clears Allowed bit",
        is_uid_component: false,
    },
    FieldSchema {
        name: "bundle_id",
        value_type: ValueType::Text,
        description: "Bundle identifier of the item (e.g. com.example.agent)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "container",
        value_type: ValueType::Text,
        description: "Parent app bundle containing this background task",
        is_uid_component: false,
    },
    FieldSchema {
        name: "developer",
        value_type: ValueType::Text,
        description: "Developer identity / team ID from code signature",
        is_uid_component: false,
    },
    FieldSchema {
        name: "executable_path",
        value_type: ValueType::Text,
        description: "Path to the executable binary",
        is_uid_component: false,
    },
    FieldSchema {
        name: "executable_modified_date",
        value_type: ValueType::Timestamp,
        description: "Modification timestamp of the executable binary",
        is_uid_component: false,
    },
    FieldSchema {
        name: "app_arguments",
        value_type: ValueType::Text,
        description: "Full command line arguments for the startup item",
        is_uid_component: false,
    },
];

pub(crate) static IOS_GOOGLE_CHAT_CACHEV0: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_google_chat_cachev0",
    name: "iOS Google Chat Image Cache (cacheV0.db)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
    file_path: Some(
        "/private/var/mobile/Data/Application/<GUID>/Library/Caches/\
         com.google.Dynamite/ImageFetcherCache/cacheV0.db",
    ),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Google Chat (Dynamite) image thumbnail cache on iOS. SQLite database with a \
        single 'cache' table containing sequentially numbered BLOBs of every image the app \
        has rendered in its UI. Includes chat-shared images, user avatars (not user-attributable), \
        and critically, images from deleted chats that no longer exist in the main image \
        directory. Functions similarly to Glide Image Manager Cache on Android. No direct \
        foreign key links the cached images to chat message records — correlation requires \
        visual comparison or hash matching. Also observed in Google Voice iOS app at a \
        similar path under com.google.Voice.",
    mitre_techniques: &["T1005"],
    fields: IOS_GOOGLE_CHAT_CACHEV0_FIELDS,
    retention: Some("Persists in SQLite until app data is cleared or app is uninstalled"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        // Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
        // (original research by Alexis Brignoni and Heather Charpentier documenting
        // cacheV0.db structure, deleted-image persistence, and iLEAPP parser)
        "https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html",
        // Source: https://github.com/abrignoni/iLEAPP (iLEAPP framework containing the Image CacheV0 parser)
        "https://github.com/abrignoni/iLEAPP",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "No foreign-key link to chat messages — visual/hash correlation required",
        "Cache may be evicted by app maintenance",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Image cache updated as UI renders images; older entries evicted",
};

// ── Apple ATX texture containers (iOS UI image caches) ─────────────────────
//
// ATX (`AAPL`) texture containers hold iOS UI image caches: PosterBoard /
// runtime snapshots, wallpapers, contact posters, and Animoji/Avatar renders.
// Forensically they are "what was on screen". Container layout and decode are
// reverse-engineered in iLEAPP's `apple_atx.py`; the format and locations were
// documented by James Habben (2026-06-26). The byte framing: an 8-byte magic
// `AAPL\r\n\x1a\n` followed by `[size u32 LE][4-byte tag][payload]` chunks
// (HEAD/FILL/astc/ASTC/LZFS/END). HEAD carries width, height, depth, array
// layers, mipmaps, a texture UUID, and a pixel-format discriminator pair. The
// payload is ASTC 4x4: a raw `astc`/`ASTC` chunk is macro-tiled (32x32-block
// tiles, Morton-ordered with a local X/Y swap — decoding it linearly yields a
// visually shuffled image), while an `LZFS` chunk is LZFSE-compressed linear
// ASTC (seen around avatar/Animoji resources). Discriminator `(3,5)` is
// confirmed ASTC 4x4; `(1,1)` and `(3,1)` are inferred ASTC 4x4 (decode +
// payload shape match, not asserted by the format).
//
// # Sources
// - <https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images> —
//   James Habben, format + iOS locations + the macro-tiling/Morton de-tile fix
// - <https://github.com/abrignoni/iLEAPP> — `leapp_functions/parsers/apple_atx.py`
//   reference parser/decoder and `scripts/artifacts/apple_atx_images.py` artifact

/// Generic Apple ATX (`AAPL`) texture container — the format umbrella that the
/// location-specific ATX artifacts share. iLEAPP enumerates these globally as
/// `**/*.atx`.
pub(crate) static APPLE_ATX_TEXTURE_CONTAINER: ArtifactDescriptor = ArtifactDescriptor {
    id: "apple_atx_texture_container",
    name: "Apple ATX Texture Container (AAPL)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images
    // iLEAPP's Apple ATX Images artifact searches globally for **/*.atx
    file_path: Some("**/*.atx"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Apple 'AAPL' texture container holding an iOS UI image cache. \
        Layout: 8-byte magic AAPL\\r\\n\\x1a\\n, then [size u32 LE][4-byte tag] \
        [payload] chunks (HEAD, FILL, astc/ASTC, LZFS, END). HEAD carries width, \
        height, depth, array-layer count, mipmap count, a texture UUID, and a \
        pixel-format discriminator pair. The payload is ASTC 4x4 texture data: a \
        raw astc/ASTC chunk is macro-tiled (32x32-block tiles, Morton-ordered \
        with a local X/Y swap) and decodes to a shuffled image if read linearly, \
        while an LZFS chunk is LZFSE-compressed linear ASTC (common for \
        avatar/Animoji resources). Discriminator (3,5) is confirmed ASTC 4x4; \
        (1,1) and (3,1) are inferred ASTC 4x4. Forensically these reconstruct \
        UI imagery — wallpapers, posters, snapshots, avatars — i.e. what the \
        device rendered. Decode to RGBA/PNG with iLEAPP's apple_atx parser or \
        the atx-core Rust reader.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema {
            name: "width",
            value_type: ValueType::UnsignedInt,
            description: "Texture width in pixels (HEAD offset 0x18)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "height",
            value_type: ValueType::UnsignedInt,
            description: "Texture height in pixels (HEAD offset 0x1C)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "depth",
            value_type: ValueType::UnsignedInt,
            description: "Texture depth (HEAD offset 0x20)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "array_layers",
            value_type: ValueType::UnsignedInt,
            description: "Array layer count (HEAD offset 0x28)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "mipmap_count",
            value_type: ValueType::UnsignedInt,
            description: "Mipmap level count (HEAD offset 0x2C)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "texture_uuid",
            value_type: ValueType::Text,
            description: "16-byte texture UUID from HEAD (offset 0x3C)",
            is_uid_component: true,
        },
        FieldSchema {
            name: "pixel_format",
            value_type: ValueType::Text,
            description: "Pixel-format discriminator pair, e.g. (3,5)/(1,1)/(3,1)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "pixel_format_confidence",
            value_type: ValueType::Text,
            // Source: https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images
            description: "'confirmed' for (3,5) ASTC 4x4; 'inferred' for (1,1)/(3,1)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "payload_type",
            value_type: ValueType::Text,
            description: "Texture payload chunk tag: astc, ASTC, or LZFS (LZFSE-wrapped)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "payload_size",
            value_type: ValueType::UnsignedInt,
            description: "Texture payload byte size as framed in the container",
            is_uid_component: false,
        },
        FieldSchema {
            name: "chunk_list",
            value_type: ValueType::Text,
            description: "Ordered list of chunk tags found while walking the container",
            is_uid_component: false,
        },
    ],
    retention: Some("On-disk cache; persists until the owning subsystem regenerates it or the app/poster is removed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "ios_atx_posterboard_runtime_snapshot",
        "ios_atx_poster_snapshot_cache",
        "ios_atx_avatar_animoji_texture",
        "heic_image_file",
    ],
    sources: &[
        // Source: James Habben — ATX format, iOS locations, Morton de-tile fix
        "https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images",
        // Source: iLEAPP — apple_atx.py reference parser + apple_atx_images.py artifact
        "https://github.com/abrignoni/iLEAPP",
        // Source: Crush Forensics — independent ATX previewer cited by the write-up
        "https://github.com/kalink0/crush-forensics",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Pixel format (1,1)/(3,1) is inferred ASTC 4x4 from decode + payload shape, not asserted by the format — never report it as confirmed",
        "Path is not assignment: an ATX in a PosterBoard-ish path is an available/rendered image, not proof of the active wallpaper at a given time",
        "Raw astc/ASTC blocks are macro-tiled; the Morton X/Y orientation is a heuristic, not a format flag, so a pathological texture could de-tile wrong",
        "Non-ASTC-4x4 or other-block-size textures, if present, are not decoded; metadata is still reported",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "On-disk texture cache files survive reboot; cleared when the subsystem regenerates the cache or the owning app/poster is removed",
};

/// iOS PosterBoard / WallpaperKit runtime poster snapshots stored as ATX —
/// rendered Lock/Home Screen and gallery images under `PRBPosterExtensionDataStore`.
pub(crate) static IOS_ATX_POSTERBOARD_RUNTIME_SNAPSHOT: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_atx_posterboard_runtime_snapshot",
    name: "iOS PosterBoard Runtime Snapshot (ATX)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images
    // Observed in the Hickman iOS 17 public image under PRBPosterExtensionDataStore;
    // RuntimeSnapshot-home/lock.atx and SNAPSHOT_GALLERY*.atx per poster provider.
    file_path: Some("/private/var/mobile/Containers/Data/Application/*/Library/Application Support/PRBPosterExtensionDataStore/*/Extensions/*/descriptors/*/versions/*/*.atx"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Rendered Lock Screen / Home Screen poster images cached as ATX \
        texture containers under the PosterBoard extension data store. Filenames \
        include RuntimeSnapshot-home.atx and RuntimeSnapshot-lock.atx (the \
        rendered home/lock poster) and SNAPSHOT_GALLERY / \
        SNAPSHOT_GALLERY_WITH_COMPLICATIONS variants (poster-picker previews). \
        The Extensions path segment names the poster provider — e.g. \
        com.apple.WallpaperKit.CollectionsPoster, \
        com.apple.EmojiPoster.EmojiPosterExtension, com.apple.weather.poster, \
        com.apple.PhotosUIPrivate.PhotosPosterProvider — so the directory shows \
        which poster types were configured. Payload is raw macro-tiled ASTC 4x4 \
        (decode with the apple_atx Morton de-tile). Per-versions/* directories \
        retain prior renders, giving a history of configured posters.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema {
            name: "poster_provider",
            value_type: ValueType::Text,
            description: "Poster extension bundle id from the path (e.g. com.apple.WallpaperKit.CollectionsPoster)",
            is_uid_component: true,
        },
        FieldSchema {
            name: "snapshot_role",
            value_type: ValueType::Text,
            description: "Render role from the filename: RuntimeSnapshot-home/-lock, SNAPSHOT_GALLERY, etc.",
            is_uid_component: true,
        },
        FieldSchema {
            name: "version",
            value_type: ValueType::Text,
            description: "versions/* segment — distinguishes successive renders of the same poster",
            is_uid_component: true,
        },
        FieldSchema {
            name: "texture_uuid",
            value_type: ValueType::Text,
            description: "Texture UUID from the ATX HEAD chunk",
            is_uid_component: false,
        },
    ],
    retention: Some("Re-rendered when the poster configuration changes; prior versions/* renders may persist"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["apple_atx_texture_container", "ios_atx_poster_snapshot_cache"],
    sources: &[
        // Source: James Habben — PosterBoard/PRBPosterExtensionDataStore ATX locations
        "https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images",
        "https://github.com/abrignoni/iLEAPP",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Path is not assignment: presence under PRBPosterExtensionDataStore shows a poster was configured/rendered, not that it was the active wallpaper at any given moment",
        "Macro-tiled ASTC; the Morton X/Y de-tile orientation is a heuristic, not a format flag",
        "Filenames may contain glob metacharacters (e.g. brackets) that confuse naive path matching",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Re-rendered when the poster/wallpaper configuration changes; versioned directories may retain earlier renders",
};

/// iOS poster snapshot caches stored as ATX — Ambient (lock screen) and
/// ShareNameAndPhoto (contact poster) rendered composites under `PosterSnapshots`.
pub(crate) static IOS_ATX_POSTER_SNAPSHOT_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_atx_poster_snapshot_cache",
    name: "iOS Poster Snapshot Cache (ATX)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images
    // Observed: /private/var/mobile/Library/Caches/Ambient/PosterSnapshots/... and
    // .../Caches/com.apple.ShareNameAndPhoto/PosterSnapshots/... (Composite/Foreground).
    file_path: Some("/private/var/mobile/**/PosterSnapshots/**/*.atx"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Rendered poster snapshots cached as ATX under PosterSnapshots trees. \
        Two notable sources: /private/var/mobile/Library/Caches/Ambient/ \
        PosterSnapshots/... (ambient/Lock Screen renders, with Composite.atx and \
        Foreground.atx layers inside each Snapshot.pks/Resources) and per-app \
        .../Caches/com.apple.ShareNameAndPhoto/PosterSnapshots/... (Contact \
        Poster renders for the Name & Photo sharing card). Snapshot directory \
        names encode orientation, scale, and a content hash. These reconstruct \
        the contact poster or lock-screen imagery the device rendered. Payload \
        is raw macro-tiled ASTC 4x4.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema {
            name: "snapshot_source",
            value_type: ValueType::Text,
            description: "Originating cache: Ambient (lock screen) or com.apple.ShareNameAndPhoto (contact poster)",
            is_uid_component: true,
        },
        FieldSchema {
            name: "layer",
            value_type: ValueType::Text,
            description: "Layer file within the snapshot bundle, e.g. Composite.atx or Foreground.atx",
            is_uid_component: true,
        },
        FieldSchema {
            name: "content_hash",
            value_type: ValueType::Text,
            description: "Content-hash directory segment identifying the rendered snapshot",
            is_uid_component: true,
        },
        FieldSchema {
            name: "texture_uuid",
            value_type: ValueType::Text,
            description: "Texture UUID from the ATX HEAD chunk",
            is_uid_component: false,
        },
    ],
    retention: Some("Regenerated when the poster/contact card changes; old snapshots may linger until cache maintenance"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["apple_atx_texture_container", "ios_atx_posterboard_runtime_snapshot"],
    sources: &[
        // Source: James Habben — PosterSnapshots ATX locations
        "https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images",
        "https://github.com/abrignoni/iLEAPP",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Path is not assignment: a cached snapshot shows a poster/contact card was rendered, not that it was active or currently displayed",
        "A contact-poster render reflects a contact card configured on the device; it does not by itself establish who set it or when it was shown",
        "Macro-tiled ASTC; Morton X/Y de-tile orientation is a heuristic",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Snapshots are re-rendered when the underlying poster or contact card changes; superseded renders persist until cache maintenance",
};

/// iOS Animoji / Avatar ATX textures — AvatarKit system assets and per-app
/// Animoji render caches, LZFSE-compressed ASTC.
pub(crate) static IOS_ATX_AVATAR_ANIMOJI_TEXTURE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_atx_avatar_animoji_texture",
    name: "iOS Animoji / Avatar Texture (ATX)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images
    // Observed: AvatarKit.framework/animoji/<creature>/*-camera{,Grid}.atx (system
    // assets) and PluginKitPlugin/*/Library/Caches/Animoji/*.atx (render caches).
    file_path: Some("/private/var/mobile/Containers/Data/PluginKitPlugin/*/Library/Caches/Animoji/*.atx"),
    scope: DataScope::User,
    os_scope: OsScope::IOS,
    decoder: Decoder::Identity,
    meaning: "Animoji/Memoji avatar texture renders stored as ATX. Two flavours: \
        Apple system assets under \
        /System/Library/PrivateFrameworks/AvatarKit.framework/animoji/<creature>/ \
        (e.g. fox-camera.atx, fox-cameraGrid.atx — stock, present on every device) \
        and per-app render caches under \
        Containers/Data/PluginKitPlugin/*/Library/Caches/Animoji/*.atx (avatars \
        actually rendered by an app/keyboard). These payloads are LZFS chunks — \
        LZFSE-compressed linear ASTC 4x4 — not macro-tiled, so no Morton de-tile \
        is needed. The per-app caches are the forensically interesting set: they \
        evidence which Animoji/Memoji were rendered in app context.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema {
            name: "avatar_kind",
            value_type: ValueType::Text,
            description: "Animoji creature / Memoji identifier parsed from the filename",
            is_uid_component: true,
        },
        FieldSchema {
            name: "asset_class",
            value_type: ValueType::Text,
            description: "'system' (AvatarKit.framework stock asset) or 'cache' (per-app render)",
            is_uid_component: true,
        },
        FieldSchema {
            name: "texture_uuid",
            value_type: ValueType::Text,
            description: "Texture UUID from the ATX HEAD chunk",
            is_uid_component: false,
        },
    ],
    retention: Some("System assets persist with the OS; per-app render caches persist until app cache eviction or uninstall"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["apple_atx_texture_container"],
    sources: &[
        // Source: James Habben — LZFS/avatar/Animoji ATX observation
        "https://leapps.org/blog-post?post=2026-06-26-decoding-apple-atx-images",
        "https://github.com/abrignoni/iLEAPP",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "AvatarKit.framework assets are stock OS files present on every device — no individuating value; only the per-app Caches/Animoji renders reflect user activity",
        "A rendered avatar texture does not establish who sent/used it or in which conversation; correlate with app data",
        "Pixel format is typically inferred ASTC 4x4 ((1,1)/(3,1)), not format-asserted",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "System assets are static; per-app render caches survive reboot until cache eviction or app uninstall",
};

// ── macOS document versions (.DocumentRevisions-V100) ──────────────────────
//
// Every APFS/HFS+ volume that holds working documents carries a hidden version
// store at its root, beside `.fseventsd` and `.Spotlight-V100`. AppKit's
// document architecture writes a new version each time a document is saved by
// an app whose NSDocument subclass reports `preservesVersions` /
// `autosavesInPlace` — the same versions a user reaches through File > Revert
// To and the Versions browser (`browseVersions(_:)`). A version is, in Apple's
// own words for NSFileVersion, "a snapshot of a file at a specific point in
// time". The daemon behind it is `revisiond(8)`, described by its macOS man
// page as the "storage manager for document revisions" and launched from
// GenerationalStorage.framework — which is where the `com.apple.genstore.*`
// extended attributes on the stored copies get their prefix.
//
// The store splits metadata from content:
//
// - `db-V1/db.sqlite` — the `files` / `generations` / `storage` tables saying
//   WHICH document was versioned, WHEN, and where the version copy sits.
// - `PerUID/<uid>/...` (some volumes: `AllUIDs/...`) — one dataless file per
//   version, named by UUID, carrying that version's own attributes.
// - `.cs/ChunkStoreDatabase` + `.cs/ChunkStorage` — the bytes, cut into
//   content-addressed chunks shared across versions and across files.
// - `LibraryStatus` / `metadata` — small plists holding
//   `databaseStateIsTrustable`, and `DISK_UUID` + `tookThinningOver`.
// - `purgatory` / `staging` — normally empty; `staging` is the sticky
//   drop-box directory versions arrive through.
//
// The forensic property is that this is a per-volume archive of prior document
// content held OUTSIDE the document: earlier bytes, the original name and the
// original path survive the document being edited, overwritten or renamed, so
// the store carries drafts that exist nowhere else on the volume. Survival past
// DELETION is a separate and much weaker claim: Apple ships
// `removeOtherVersionsOfItem(at:)` to clear a file's versions from the store,
// and freeing a document's inode is documented to take its versions with it —
// which is why duplicate-then-delete-the-original is published as the way to
// strip a file's version history. Read a row or copy recovered for a deleted
// document as residue that outlived a purge, never as guaranteed behaviour.
//
// # Sources
// - <https://developer.apple.com/documentation/appkit/nsdocument> — Apple:
//   `preservesVersions`, `autosavesInPlace`, `browseVersions(_:)`,
//   `revertToSaved(_:)` — the app-side feature that produces versions
// - <https://developer.apple.com/documentation/foundation/nsfileversion> —
//   Apple: NSFileVersion is "a snapshot of a file at a specific point in time"
// - <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/macos_document_versions.py>
//   — reference implementation carrying the verbatim `files` / `generations` /
//   `storage` CREATE TABLE text, the storage-id join, POSIX-epoch timestamp
//   handling, and the `/.DocumentRevisions-V100/` root prefix applied to
//   `generation_path`
// - <https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py>
//   — independent second implementation: both root paths, the `.cs` chunk
//   tables and on-disk chunk framing, the `com.apple.genstore.*` xattrs, the
//   `:QLThumbnailAdditionName` generation paths, and orphan-chunk recovery
// - <https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/>
//   — folder inventory, dataless-file-by-UUID storage, chunk sizing and
//   post-startup housekeeping, and the backup/restore behaviour

/// Field schema for one document-version record — one `generations` row joined
/// to its `files` row on `file_storage_id = generation_storage_id`.
///
/// Column names and types are the verbatim CREATE TABLE text carried by the
/// plaso plugin and independently queried by mac_apt; the two `genstore_*`
/// fields are extended attributes read from the stored version copy rather than
/// columns, and `version_exists_on_disk` is the analyst's resolve check.
///
/// Source: <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/macos_document_versions.py>
/// Source: <https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py>
/// Source: <https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/>
pub(crate) static MACOS_DOCUMENT_REVISIONS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "file_path",
        value_type: ValueType::Text,
        description: "files.file_path — the full path of the ORIGINAL document as revisiond last \
            recorded it. This is the field that makes the store worth reading: it survives the \
            document, so a version row can name a file (and the directory it sat in) that is no \
            longer on the volume. Treat it as the path at the moment of the last recorded save, \
            not the current path — a later rename or move is not written back",
        is_uid_component: true,
    },
    FieldSchema {
        name: "file_name",
        value_type: ValueType::Text,
        description: "files.file_name — the original document's file name, held separately from \
            the path. Use it to pivot when only the leaf name is known, and compare it against \
            genstore_origdisplayname on the stored copy: a mismatch means the document was \
            renamed between versions",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_inode",
        value_type: ValueType::UnsignedInt,
        description: "files.file_inode — the original document's inode (APFS file-system object \
            id). The stable handle when file_path has gone stale: resolve it against the \
            file-system catalog to recover the document's current path, or to establish that the \
            object no longer exists",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_last_seen",
        value_type: ValueType::Timestamp,
        description: "files.file_last_seen — Unix epoch seconds, the last time revisiond saw the \
            original file. Read beside generation_add_time: a last-seen far earlier than the \
            newest version is the signature of a document the daemon lost track of, typically \
            because it was deleted or moved off the volume",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_status",
        value_type: ValueType::Integer,
        description: "files.file_status — an integer flag defaulting to 1. Apple documents no \
            value meanings and neither open implementation interprets it, so record the raw \
            value and do NOT read deletion, trust or staleness out of it without validating \
            against a known-good volume",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_storage_id",
        value_type: ValueType::UnsignedInt,
        description: "files.file_storage_id — the join key to generations.generation_storage_id. \
            One storage id gathers every stored version of the same document, so it is the \
            grouping key for 'all versions of this file'",
        is_uid_component: true,
    },
    FieldSchema {
        name: "generation_id",
        value_type: ValueType::UnsignedInt,
        description: "generations.generation_id — the per-version row id. Ascending ids under one \
            storage id give the save ORDER independently of the clock, which is what to fall back \
            on when timestamps are equal or suspected of tampering",
        is_uid_component: true,
    },
    FieldSchema {
        name: "generation_add_time",
        value_type: ValueType::Timestamp,
        description: "generations.generation_add_time — Unix epoch seconds, when THIS version was \
            written to the store. The event time for the timeline: it dates a save of the named \
            document by an app that supports version management, and the series of them \
            reconstructs an editing session",
        is_uid_component: false,
    },
    FieldSchema {
        name: "generation_path",
        value_type: ValueType::Text,
        description: "generations.generation_path — the version copy's location, stored RELATIVE \
            to the .DocumentRevisions-V100 root, so prefix the root before resolving it. A path \
            ending in :QLThumbnailAdditionName names a QuickLook thumbnail addition rather than a \
            document body — the directory holds thumbnail.png on newer macOS and thumbnail.jpeg \
            on older, which is still a renderable picture of the document at that version",
        is_uid_component: true,
    },
    FieldSchema {
        name: "generation_client_id",
        value_type: ValueType::Text,
        description: "generations.generation_client_id — the client the version was filed under, \
            and a component of generation_path. It groups versions by the producing subsystem \
            (document versions against iCloud/ubiquity material, for example), so read it before \
            assuming every row is a user-visible document save",
        is_uid_component: false,
    },
    FieldSchema {
        name: "generation_name",
        value_type: ValueType::Text,
        description: "generations.generation_name — the version's own name within the store. \
            Carry it verbatim into the report so an extracted version file can be tied back to \
            its database row",
        is_uid_component: false,
    },
    FieldSchema {
        name: "generation_size",
        value_type: ValueType::UnsignedInt,
        description: "generations.generation_size — the version's size in bytes. It is the \
            integrity check on extraction: reassembling the chunks must yield exactly this many \
            bytes, and a short or long result means chunks are missing or mis-ordered, so report \
            the reconstruction as partial rather than as the version",
        is_uid_component: false,
    },
    FieldSchema {
        name: "generation_status",
        value_type: ValueType::Integer,
        description: "generations.generation_status — an integer flag defaulting to 1, with no \
            published value meanings. Record it; do not infer a version's validity from it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "generation_prunable",
        value_type: ValueType::Bool,
        description: "generations.generation_prunable — defaults to 0. A set flag marks the \
            version as eligible for thinning, i.e. content whose disappearance on the next \
            housekeeping pass is ordinary. Collect prunable versions FIRST, and expect them to be \
            absent from any image taken later",
        is_uid_component: false,
    },
    FieldSchema {
        name: "genstore_origdisplayname",
        value_type: ValueType::Text,
        description: "Extended attribute com.apple.genstore.origdisplayname on the stored version \
            copy — the original document's display name, recorded outside the database. It is the \
            fallback identity when the database row is gone or the file path is empty, and its \
            independence from files.file_name is what makes a rename visible",
        is_uid_component: false,
    },
    FieldSchema {
        name: "genstore_origposixname",
        value_type: ValueType::Text,
        description: "Extended attribute com.apple.genstore.origposixname on the stored version \
            copy — the original POSIX file name. Compare with genstore_origdisplayname: the two \
            diverge where the Finder-displayed name differs from the on-disk name, which is worth \
            noting when a document's apparent extension is not its real one",
        is_uid_component: false,
    },
    FieldSchema {
        name: "version_exists_on_disk",
        value_type: ValueType::Bool,
        description: "Does the .DocumentRevisions-V100 root plus generation_path resolve on the \
            image? A row whose copy is gone still evidences that the document existed and was \
            saved at generation_add_time — it just cannot yield content. Absence is ordinary \
            after thinning, so report the row as metadata-only rather than treating it as a \
            parsing failure",
        is_uid_component: false,
    },
];

/// macOS document versions database — `.DocumentRevisions-V100/db-V1/db.sqlite`.
///
/// The per-volume index of every document version macOS has saved: which file,
/// when, and where the stored copy lives. Its forensic weight is that the
/// record is kept APART from its subject — the original path, the original
/// name, the original inode and earlier content survive the document being
/// edited, overwritten or renamed, so the store holds drafts that exist nowhere
/// else. It is not an archive that deletion cannot reach: freeing the
/// document's inode is documented to remove its versions with it, so a row or
/// copy recovered for a deleted document is residue that outlived that purge
/// and has to be reported as such.
///
/// Two tables carry it. `files` holds the original document
/// (`file_name`, `file_path`, `file_inode`, `file_last_seen`, `file_status`,
/// `file_storage_id`); `generations` holds one row per saved version
/// (`generation_id`, `generation_path`, `generation_add_time`,
/// `generation_name`, `generation_client_id`, `generation_size`,
/// `generation_prunable`). They join on
/// `files.file_storage_id = generations.generation_storage_id`, and both
/// timestamps are Unix epoch seconds. `generation_path` is relative to the
/// `.DocumentRevisions-V100` root, so the root must be prefixed before it
/// resolves.
///
/// Source: <https://developer.apple.com/documentation/appkit/nsdocument>
/// Source: <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/macos_document_versions.py>
/// Source: <https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py>
pub(crate) static MACOS_DOCUMENT_REVISIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_document_revisions",
    name: "macOS Document Versions Database (.DocumentRevisions-V100/db-V1/db.sqlite)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Path is relative to the VOLUME root, which is where it appears on a
    // mounted image. On a live macOS 10.15+ system the Data volume is mounted
    // at /System/Volumes/Data and this directory is NOT firmlinked into /, so
    // the live path is /System/Volumes/Data/.DocumentRevisions-V100/...
    file_path: Some("/.DocumentRevisions-V100/db-V1/db.sqlite"),
    scope: DataScope::Mixed,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-volume index of every document version macOS has stored, and the route to \
prior content of documents that no longer exist. AppKit's document architecture writes a new \
version on every save by an app whose NSDocument subclass supports version management \
(preservesVersions / autosavesInPlace) — Preview, TextEdit, Pages, Numbers and most \
document-based apps — which is the same set of versions the user reaches through File > Revert \
To and the Versions browser. There is no per-app opt-out, so the store accumulates without the \
user electing to archive anything. The daemon is revisiond, documented by its man page as the \
storage manager for document revisions and shipped in GenerationalStorage.framework, which is \
also the origin of the com.apple.genstore.* extended attributes on the stored copies. \
db-V1/db.sqlite holds two joined tables: `files` (file_name, file_path, file_inode, \
file_last_seen, file_status, file_storage_id) naming the original document, and `generations` \
(generation_id, generation_storage_id, generation_name, generation_client_id, generation_path, \
generation_add_time, generation_size, generation_prunable, generation_status) holding one row per \
saved version, joined on file_storage_id = generation_storage_id. Both timestamps are Unix epoch \
seconds. generation_path is stored RELATIVE to the .DocumentRevisions-V100 root and points into \
the per-UID version tree (PerUID/<uid>/... on a multi-user Data volume, AllUIDs/... on some \
volumes), where each version is a DATALESS file named by UUID: it carries the version's \
attributes but not its bytes, which live in the sibling chunk store \
(macos_document_revisions_chunkstore) and must be reassembled from there. A generation_path \
ending in :QLThumbnailAdditionName is a QuickLook thumbnail addition rather than a document body. \
Beside the database sit LibraryStatus (databaseStateIsTrustable) and metadata (DISK_UUID, \
tookThinningOver), plus the normally-empty purgatory and staging directories. The whole tree is \
root-owned and unreadable by a normal user, and on macOS 10.15+ it lives on the Data volume at \
/System/Volumes/Data/.DocumentRevisions-V100 and is not firmlinked into /, so a collection that \
walks only / misses it entirely.",
    mitre_techniques: &[
        "T1005",     // Data from Local System
        "T1070.004", // Indicator Removal: File Deletion — version residue can outlive the document
        "T1565.001", // Data Manipulation: Stored Data Manipulation — prior content evidences the change
    ],
    fields: MACOS_DOCUMENT_REVISIONS_FIELDS,
    retention: Some(
        "Rows and version copies persist on the volume until the user deletes the versions or \
revisiond thinning prunes them; neither Time Machine nor third-party cloners restore the store, \
so versions exist only on the volume that created them",
    ),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "macos_document_revisions_chunkstore",
        "macos_fsevents",
        "quicklook_thumbnails",
        "macos_spotlight_store",
    ],
    sources: &[
        // Source: https://developer.apple.com/documentation/appkit/nsdocument (Apple: preservesVersions
        // "supports version management", autosavesInPlace, browseVersions(_:) "Opens the Versions
        // browser in the document's main window", revertToSaved(_:))
        "https://developer.apple.com/documentation/appkit/nsdocument",
        // Source: https://developer.apple.com/documentation/foundation/nsfileversion (Apple: a version is
        // "a snapshot of a file at a specific point in time", carrying the associated file's location and
        // the revision's modification date)
        "https://developer.apple.com/documentation/foundation/nsfileversion",
        // Source: https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/macos_document_versions.py
        // (verbatim CREATE TABLE text for files/generations/storage; the
        // file_storage_id = generation_storage_id join; POSIX-epoch timestamps; ROOT_VERSION_PATH
        // "/.DocumentRevisions-V100/" prefixed onto the relative generation_path)
        "https://github.com/log2timeline/plaso/blob/main/plaso/parsers/sqlite_plugins/macos_document_versions.py",
        // Source: https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py
        // (independent implementation: probes both /.DocumentRevisions-V100 and
        // /System/Volumes/Data/.DocumentRevisions-V100; db-V1/db.sqlite; reads
        // com.apple.genstore.origdisplayname / origposixname off the stored version; handles
        // :QLThumbnailAdditionName paths holding thumbnail.png or thumbnail.jpeg; iOS store at
        // /private/var/mobile/.DocumentRevisions-V100)
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py",
        // Source: https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/
        // (folder inventory .cs / AllUIDs / db-V1 / LibraryStatus / metadata / purgatory / staging;
        // each version stored as a dataless file named by UUID; no per-app way to disable versioning;
        // Time Machine backed the folder up until Catalina but has never restored it successfully, and
        // Carbon Copy Cloner skips it, so restore or migration loses every version; versions are not
        // carried by APFS clone files)
        "https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/",
        // Source: https://eclecticlight.co/2023/06/03/between-undo-and-backups-document-versions/
        // (the removal side, and the correction to "versions outlive deletion": deleting the
        // document by emptying the Trash or from Terminal "removes its inode from the file system,
        // and all previous versions should be removed from the Document Revisions database"; a
        // copy/move to another volume yields a new inode and "previous versions aren't copied
        // across", which is why duplicate-and-delete-the-original is the published way to strip a
        // file's version history)
        "https://eclecticlight.co/2023/06/03/between-undo-and-backups-document-versions/",
        // Source: https://eclecticlight.co/2024/04/04/a-short-history-of-versions/ (versions
        // arrived with NSFileVersion in OS X 10.7; "Versions are bound to the volume of the current
        // version of a file. When a file is moved to a different volume, its saved versions on the
        // original volume are lost")
        "https://eclecticlight.co/2024/04/04/a-short-history-of-versions/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "On macOS 10.15+ the store lives on the Data volume and is NOT listed in /usr/share/firmlinks, so it is reachable at /System/Volumes/Data/.DocumentRevisions-V100 and not at /. A live collection that enumerates only / returns nothing and looks like a clean result — probe both paths before recording absence",
        "Versions are NOT documented to outlive the document. Apple exposes removeOtherVersionsOfItem(at:) to clear a file's versions from the store, freeing a document's inode is documented to remove its versions with it, and duplicate-then-delete-the-original is published as the way to strip a version history because a clone carries none. So rows or copies recovered for a document that is gone are residue that outlived a purge — report them as recovered residue, and never read an empty result as proof the document was never versioned",
        "A generation row evidences that an app saved the named document at generation_add_time; it does not identify the human who saved it. The PerUID component yields a numeric uid, which is an account, not a person",
        "file_path is the path revisiond last recorded, not the current one — a document renamed or moved after its final version leaves a stale path. file_inode is the more stable handle for resolving the document's real location",
        "Absence of versions on a restored, migrated or cloned system is EXPECTED, not evidence of wiping: Time Machine backed the folder up only until Catalina and has never restored it successfully, third-party cloners skip it, and APFS clone files do not carry versions",
        "The database is metadata only. Each version copy is a dataless file whose bytes live in .cs/ChunkStorage, so a tree copied without the .cs directory yields rows and filenames with no recoverable content",
        "The sibling metadata plist binds the store to its volume via DISK_UUID; a store copied to another volume mis-resolves its dataless files, which is why an out-of-place .DocumentRevisions-V100 tree should not be trusted to describe the volume it was found on",
        "file_status and generation_status are integer flags with no published value meanings — record them, and do not read deletion, trust or validity out of them without validating against a known-good volume of the same macOS version",
        "Version count reflects app behaviour and save frequency, not user intent: versioning cannot be disabled per app, and files with well over 100 stored versions are unremarkable",
        "The tree is root-owned and mode-restricted, so acquisition needs privileged access or an image; the only world-readable members are the small LibraryStatus and metadata plists",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale:
        "Database rows and their version copies persist on the volume until the user deletes the \
versions or revisiond thinning prunes them; rows flagged generation_prunable are the ones to \
collect first",
};

/// Field schema for the document-versions chunk store — the content side of
/// `.DocumentRevisions-V100`.
///
/// Column names come from the two tables mac_apt queries in
/// `.cs/ChunkStoreDatabase`; the on-disk framing (a 25-byte header of a 4-byte
/// big-endian total length followed by the 21-byte content id) is the framing
/// its extractor verifies each chunk against before writing it out.
///
/// Source: <https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py>
/// Source: <https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/>
pub(crate) static MACOS_DOCUMENT_REVISIONS_CHUNKSTORE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "clt_inode",
        value_type: ValueType::UnsignedInt,
        description: "CSStorageChunkListTable.clt_inode — the inode of the dataless version file \
            this chunk list reassembles. It is the bridge from a generations row to actual bytes: \
            resolve generation_path to the version file, take its inode, and look it up here",
        is_uid_component: true,
    },
    FieldSchema {
        name: "clt_chunk_row_ids",
        value_type: ValueType::Bytes,
        description: "CSStorageChunkListTable.clt_chunkRowIDs — a packed array of little-endian \
            64-bit CSChunkTable row ids IN ORDER. Its length must be a multiple of 8; a remainder \
            means a truncated or corrupt list, and reassembling from it produces a plausible but \
            wrong file, so refuse the reconstruction rather than emit it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "clt_count",
        value_type: ValueType::UnsignedInt,
        description: "CSStorageChunkListTable.clt_count — how many chunks the version is built \
            from. Cross-check it against the number of ids decoded from clt_chunk_row_ids before \
            trusting a reconstruction",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ct_rowid",
        value_type: ValueType::UnsignedInt,
        description: "CSChunkTable.ct_rowid — the chunk's row id, the value a chunk list \
            references. Chunks are shared, so one row id appearing in several lists means the same \
            bytes back more than one version (and, across files, more than one document)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "ft_rowid",
        value_type: ValueType::UnsignedInt,
        description: "CSChunkTable.ft_rowid — names the numbered container file under \
            .cs/ChunkStorage that physically holds the chunk. The store nests those files four \
            levels deep with integer names, so this value plus the offset is the read address",
        is_uid_component: false,
    },
    FieldSchema {
        name: "offset",
        value_type: ValueType::UnsignedInt,
        description: "CSChunkTable.offset — byte offset of the chunk inside its ChunkStorage \
            container file. Seek here to find the chunk's 25-byte header",
        is_uid_component: false,
    },
    FieldSchema {
        name: "data_len",
        value_type: ValueType::UnsignedInt,
        description: "CSChunkTable.dataLen — bytes to read from offset, INCLUDING the 25-byte \
            header; the payload is what remains after it. Chunks commonly run up to a little over \
            20 MB, so a wildly larger value is a parse error rather than a large chunk",
        is_uid_component: false,
    },
    FieldSchema {
        name: "cid",
        value_type: ValueType::Bytes,
        description: "CSChunkTable.cid — the 21-byte content identifier, repeated verbatim in the \
            chunk's on-disk header at offset+4. Compare the two before accepting the payload: a \
            mismatch means the address is wrong or the store has drifted, and writing the bytes \
            anyway fabricates content that was never in that version",
        is_uid_component: true,
    },
    FieldSchema {
        name: "chunk_timestamp",
        value_type: ValueType::Timestamp,
        description: "CSChunkTable.timeStamp — a per-chunk time value. Neither Apple nor the open \
            implementations document its epoch, and mac_apt reads the column without normalising \
            it, so establish the epoch against a chunk of known age before putting it on a \
            timeline; generation_add_time is the dated event, this is not",
        is_uid_component: false,
    },
    FieldSchema {
        name: "orphan_chunk",
        value_type: ValueType::Bool,
        description: "Is this chunk present in ChunkStorage while no surviving chunk list \
            references its content id? Orphans are the residue of versions and documents already \
            removed from the database — recoverable content with no row to name it. Carve them \
            out, but report them as unattributed: an orphan chunk carries no path, no owner and \
            no time, and may be a fragment of a larger file",
        is_uid_component: false,
    },
];

/// macOS document-versions chunk store — `.DocumentRevisions-V100/.cs`.
///
/// The content half of the version store. A stored version is a dataless file:
/// its bytes are not in it, but in content-addressed chunks under
/// `.cs/ChunkStorage`, indexed by `.cs/ChunkStoreDatabase`. Recovering a
/// version means walking `CSStorageChunkListTable` from the version file's
/// inode to an ordered list of `CSChunkTable` rows, reading each chunk from its
/// numbered container file at the recorded offset, verifying the 21-byte
/// content id in the chunk's 25-byte header against the database, and
/// concatenating the payloads.
///
/// Two properties earn it a separate entry from the database. Chunks are SHARED
/// — one chunk can back several versions and content from different files lands
/// in the same chunk — so a chunk is not evidence about a single document.
/// And chunks are not reclaimed when a version is deleted: housekeeping runs
/// after start-up, so content of recently-deleted versions and documents
/// commonly survives in the store as orphans with no row to name it.
///
/// Source: <https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py>
/// Source: <https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/>
pub(crate) static MACOS_DOCUMENT_REVISIONS_CHUNKSTORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_document_revisions_chunkstore",
    name: "macOS Document Versions Chunk Store (.DocumentRevisions-V100/.cs)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Volume-root relative, as it appears on a mounted image; on a live macOS
    // 10.15+ system, /System/Volumes/Data/.DocumentRevisions-V100/.cs/...
    file_path: Some("/.DocumentRevisions-V100/.cs/ChunkStoreDatabase"),
    scope: DataScope::Mixed,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Where the BYTES of macOS document versions actually live, and the only place they \
can be recovered from. Each version listed in macos_document_revisions is stored as a dataless \
file named by UUID: it carries the version's attributes, not its content. The content is cut into \
content-addressed chunks (commonly up to a little over 20 MB each) held in numbered container \
files nested four levels deep under .cs/ChunkStorage, and indexed by .cs/ChunkStoreDatabase. That \
database has two tables that matter: CSStorageChunkListTable (clt_rowid, clt_inode, clt_count, \
clt_chunkRowIDs — clt_chunkRowIDs being a packed array of little-endian 64-bit CSChunkTable row \
ids in order) maps a version file's inode to its ordered chunk list, and CSChunkTable (ct_rowid, \
ft_rowid, offset, dataLen, cid, timeStamp) gives each chunk's container file, byte offset, length \
and 21-byte content id. On disk a chunk begins with a 25-byte header — a 4-byte big-endian total \
length followed by the 21-byte content id — and the id must match the database before the payload \
is accepted. Two properties drive the analysis. Chunks are SHARED: one chunk can back several \
versions, and content from different files is lumped into the same chunk, so a chunk in isolation \
is not evidence about one document. And chunks are NOT reclaimed when a version is deleted — \
housekeeping runs after start-up and at intervals thereafter, so chunks belonging to versions and \
documents already removed from the database routinely remain as ORPHANS, carvable content with no \
surviving row to name it. That is the recovery opportunity and the attribution limit in one.",
    mitre_techniques: &[
        "T1005",     // Data from Local System
        "T1070.004", // Indicator Removal: File Deletion — chunk content outlives the deleted version
    ],
    fields: MACOS_DOCUMENT_REVISIONS_CHUNKSTORE_FIELDS,
    retention: Some(
        "Chunks survive deletion of the version that referenced them until a housekeeping pass \
runs — observed after start-up and at intervals thereafter — so orphaned content is commonly \
present but should be collected before the system is restarted",
    ),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_document_revisions", "quicklook_thumbnails"],
    sources: &[
        // Source: https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py
        // (CSStorageChunkListTable clt_rowid/clt_inode/clt_count/clt_chunkRowIDs unpacked as
        // little-endian u64 row ids; CSChunkTable ct_rowid/ft_rowid/offset/dataLen/cid/timeStamp;
        // the 25-byte on-disk chunk header of a 4-byte big-endian length plus a 21-byte cid,
        // verified against the database before the payload is written; the four-level numbered
        // ChunkStorage directory tree; orphan-chunk extraction for chunks whose cid no chunk list
        // references)
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/documentrevisions.py",
        // Source: https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/
        // (.cs holds ChunkStorage with the ChunkStoreDatabase and deeply nested numbered chunk
        // folders; a version is a dataless file whose data are restored from the ChunkStore; chunk
        // sizes typically up to just over 20 MB; space taken by a deleted file's chunks was not
        // released until shutdown and restart, housekeeping running after start-up and possibly at
        // later intervals; content from different files is lumped together in the same chunk)
        "https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/",
        // Source: https://developer.apple.com/documentation/foundation/nsfileversion (Apple: the
        // version abstraction whose stored representation this is — a snapshot of a file at a
        // specific point in time)
        "https://developer.apple.com/documentation/foundation/nsfileversion",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "A chunk is not evidence about one document: chunks are shared between versions, and content from different files is lumped into the same chunk. Attribution runs chunk -> chunk list -> version file inode -> generations row, and breaks if any link is missing",
        "An ORPHAN chunk has no path, no owner and no reliable time — it is recoverable content with the attribution stripped off. Report it as unattributed residue, never as 'a version of file X'",
        "Reassembly is only as good as the ordering: clt_chunkRowIDs must decode to a whole number of 64-bit ids and the reconstructed length must equal the row's generation_size. A short or long result is a partial reconstruction and must be labelled as one",
        "The cid in the chunk's on-disk header is the read check. Writing a payload whose header cid does not match the database fabricates content — drop the chunk and record the mismatch instead",
        "CSChunkTable.timeStamp has no documented epoch and is not normalised by the open implementations; generation_add_time in the versions database is the dated event, and this column must be calibrated before it goes near a timeline",
        "Housekeeping destroys the opportunity: chunk space for deleted versions was observed to be released only after shutdown and restart, so a restart between discovery and acquisition can remove exactly the orphaned content that mattered",
        "The whole .cs tree is root-owned and unreadable by a normal user, so recovery needs privileged access or a disk image, and neither Time Machine nor third-party cloners preserve it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale:
        "Chunks persist past deletion of the versions that referenced them, but revisiond \
housekeeping after start-up and at later intervals prunes the unreferenced ones, so orphaned \
content degrades with ordinary system use",
};

// ── macOS download-provenance batch ──────────────────────────────────────────

/// The `com.apple.quarantine` extended attribute itself — the per-file mark
/// that drives Gatekeeper, distinct from the per-user QuarantineEventsV2
/// database (`macos_quarantine_events`) its UUID field points into.
///
/// Semicolon-delimited UTF-8 string: `flags;hex-epoch;agent;event-UUID`,
/// e.g. `0083;675d1b26;Safari;96C3F539-AC7D-4387-BD6C-286F90341408`.
///
/// # Sources
/// - <https://eclecticlight.co/2021/12/11/explainer-quarantine/> — after
///   Gatekeeper's first-run checks "the flag is changed to show that it has
///   passed those checks … but the flag remains"; quarantine introduced in
///   Mac OS X 10.5 (2007); scheme is voluntary (curl et al. do not set it).
/// - <https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/> —
///   flag values: 0081/0082/0083 on fresh downloads; 00c3 after an executable
///   passes Gatekeeper; 00e3 (passed + previously run) seen on Sierra and
///   earlier, discontinued by Mojave; string field layout; UUID joins
///   QuarantineEventsV2.
/// - <https://en.wikipedia.org/wiki/Gatekeeper_(macOS)> — Gatekeeper shipped in
///   phases: `spctl` CLI in Mac OS X Lion 10.7.3, GUI in OS X Mountain Lion
///   10.8, back-ported to Lion in the 10.7.5 update.
pub(crate) static MACOS_QUARANTINE_XATTR: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_quarantine_xattr",
    name: "Quarantine Extended Attribute (com.apple.quarantine)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-file extended attribute macOS attaches to downloaded content: a \
        semicolon-delimited string of hex flags, hex Unix-epoch download time, downloading \
        agent, and a UUID keying the per-user QuarantineEventsV2 database. Freshly \
        downloaded files carry flag values such as 0081/0082/0083. When the user approves a \
        quarantined executable and it passes Gatekeeper, the xattr is NOT removed: the flag \
        value is rewritten (0083 becomes 00c3 on modern macOS; 00e3 additionally marked \
        prior execution on Sierra and earlier, discontinued by Mojave) and the attribute is \
        retained as a record that checking succeeded. A claim that approval removes the \
        attribute circulates in training material and is contradicted by published \
        research — an approved-and-run file still carries its download provenance. The \
        scheme is voluntary: files fetched by curl/wget or other non-participating tools \
        carry no quarantine xattr, so absence proves nothing about origin. The flag \
        propagates aggressively — archive extraction and AirDrop transfer mark the \
        results. Quarantine dates to Mac OS X 10.5 (2007); Gatekeeper enforcement arrived \
        in phases (spctl CLI in 10.7.3, GUI in 10.8, back-ported to 10.7.5).",
    mitre_techniques: &["T1553.001"],
    fields: &[
        FieldSchema { name: "flags", value_type: ValueType::Text, description: "Hex flag field; 0081/0082/0083 fresh download, 00c3 passed Gatekeeper (00e3 passed+executed, pre-Mojave only)", is_uid_component: false },
        FieldSchema { name: "download_time", value_type: ValueType::Timestamp, description: "Download time as hex Unix epoch (second field of the xattr string)", is_uid_component: false },
        FieldSchema { name: "agent_name", value_type: ValueType::Text, description: "Application or agent that attached the flag (e.g. Safari, Chrome)", is_uid_component: false },
        FieldSchema { name: "event_uuid", value_type: ValueType::Guid, description: "UUID joining the per-user com.apple.LaunchServices.QuarantineEventsV2 database row, which holds the origin URL", is_uid_component: true },
    ],
    retention: Some("Persists with the file until explicitly stripped (xattr -d) or the file moves to a filesystem without xattr support"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_quarantine_events", "macos_gatekeeper_logs", "macos_wherefroms_xattr", "macos_exec_policy_db"],
    sources: &[
        "https://eclecticlight.co/2021/12/11/explainer-quarantine/",
        "https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/",
        "https://en.wikipedia.org/wiki/Gatekeeper_(macOS)",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Voluntary scheme: absence of the xattr does not mean the file was not downloaded (curl, wget and other non-participating tools set no flag)",
        "Trivially stripped by any user with write access (xattr -d com.apple.quarantine)",
        "Flag-value semantics are reverse-engineered and version-bound; Apple documents no normative flag table",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Extended attribute travels with the file; survives approval (value rewritten, not removed)",
};

/// Download-origin metadata xattrs: `com.apple.metadata:kMDItemWhereFroms`
/// (origin URL + referrer, binary plist) and
/// `com.apple.metadata:kMDItemDownloadedDate`.
///
/// # Sources
/// - <https://developer.apple.com/documentation/coreservices/kmditemwherefroms> —
///   Apple: where the item was obtained from; for downloaded files the URL of
///   the resource, and possibly the referrer.
/// - <https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/> —
///   co-occurrence with com.apple.quarantine on browser downloads.
pub(crate) static MACOS_WHEREFROMS_XATTR: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wherefroms_xattr",
    name: "Download Origin Xattrs (kMDItemWhereFroms / kMDItemDownloadedDate)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Spotlight metadata extended attributes attached to downloaded files: \
        com.apple.metadata:kMDItemWhereFroms is a binary plist array holding the download \
        URL and (when available) the referrer page; \
        com.apple.metadata:kMDItemDownloadedDate is a binary plist date of the download. \
        Together with com.apple.quarantine they establish where a specific file on disk \
        came from and when — provenance that survives after browser history is cleared, \
        and that rides along in AppleDouble (._) sidecar files when the file is copied to \
        non-APFS/HFS+ media such as FAT/exFAT USB sticks. Decode with \
        `xattr -px <attr> <file> | xxd -r -p | plutil -p -`.",
    mitre_techniques: &["T1105"],
    fields: &[
        FieldSchema { name: "wherefroms_urls", value_type: ValueType::Text, description: "Array of origin URLs (download URL, then referrer when recorded)", is_uid_component: true },
        FieldSchema { name: "downloaded_date", value_type: ValueType::Timestamp, description: "Download timestamp from kMDItemDownloadedDate (plist date, UTC)", is_uid_component: false },
    ],
    retention: Some("Persists with the file until stripped; not set on every download path"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_quarantine_xattr", "macos_quarantine_events", "macos_safari_downloads"],
    sources: &[
        "https://developer.apple.com/documentation/coreservices/kmditemwherefroms",
        "https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Set only by cooperating applications — a file downloaded by curl or a custom tool carries neither attribute",
        "User-writable metadata: can be edited or stripped with xattr, so corroborate against QuarantineEventsV2 and browser history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Extended attributes travel with the file until explicitly removed",
};

/// `com.apple.lastuseddate#PS` — last-used timestamp xattr behind Finder's
/// "Date Last Opened", named with the `#P` (persist) / `#S` (sync) xattr-flag
/// suffix convention.
///
/// # Sources
/// - <https://eclecticlight.co/2020/11/02/controlling-metadata-tricks-with-persistence/> —
///   the `#PS` suffix is Apple's xattr-flags mechanism controlling persistence
///   through copies; com.apple.lastuseddate#PS as the worked example.
/// - <https://mjtsai.com/blog/2025/12/18/extended-attributes-flags-in-tahoe/> —
///   the full name renders as com.apple.lastuseddate#PS; flag semantics.
///
/// Encoding accounts DISAGREE across secondary sources (16-byte timespec of
/// little-endian seconds + nanoseconds vs. "64-bit" single-value readings);
/// no Apple documentation of the payload was located. Tier is SingleSecondary
/// and the encoding must be validated against a known file before use.
pub(crate) static MACOS_LASTUSEDDATE_XATTR: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_lastuseddate_xattr",
    name: "Last-Used-Date Xattr (com.apple.lastuseddate#PS)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Extended attribute recording when a file was last opened/used — the value \
        behind Finder's 'Date Last Opened' column — kept even where POSIX atime is \
        unreliable. The '#PS' tail is not part of the attribute's base name but Apple's \
        xattr-flags suffix (P = persist through copies, S = sync), documented in public \
        research. The binary payload starts with a little-endian Unix-epoch seconds value; \
        secondary sources disagree on the full encoding (timespec seconds+nanoseconds vs a \
        single 64-bit value), and no Apple documentation of the payload was located — \
        validate the decode against a file whose last-open time is independently known \
        before relying on it. Useful as a user-interaction signal on documents and \
        applications, including files on read-only or externally-mounted evidence copies \
        where live atime is meaningless.",
    mitre_techniques: &["T1083"],
    fields: &[
        FieldSchema { name: "last_used_time", value_type: ValueType::Timestamp, description: "Last-used timestamp; little-endian Unix epoch seconds lead the payload — full encoding unsettled across sources, validate before use", is_uid_component: false },
    ],
    retention: Some("Persists with the file; #P flag keeps it through copies"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["quicklook_thumbnails", "macos_sfl2_recent_items"],
    sources: &[
        "https://eclecticlight.co/2020/11/02/controlling-metadata-tricks-with-persistence/",
        "https://mjtsai.com/blog/2025/12/18/extended-attributes-flags-in-tahoe/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "Payload encoding is not vendor-documented and secondary accounts conflict (timespec vs single 64-bit value) — validate against a known-time file before reporting a decoded value",
        "Updated by user-space frameworks, not the kernel: absence or staleness does not prove non-use",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten on each qualifying open; travels with the file via the #P persistence flag",
};

/// Screenshot provenance xattrs written by macOS's screen-capture tool:
/// `com.apple.metadata:kMDItemIsScreenCapture`, `kMDItemScreenCaptureType`,
/// `kMDItemScreenCaptureGlobalRect`.
///
/// # Sources
/// - <https://support.apple.com/en-hk/102646> — Apple: screenshots save to the
///   desktop by default as "Screen Shot [date] at [time]"; save location is
///   changeable.
/// - <https://eternalstorms.wordpress.com/2016/09/10/deconstructing-and-reimplementing-macos-screencapture-cli/> —
///   screencapture adds kMDItemIsScreenCapture (present only on screenshots),
///   kMDItemScreenCaptureType ("display"/"window"/"selection") and
///   kMDItemScreenCaptureGlobalRect.
/// - <https://www.cool3c.com/article/107337> — zh-Hant default name
///   "螢幕快照 <date/time>.png"; `defaults write com.apple.screencapture name|location`.
/// - <https://support.apple.com/en-us/109344> — Desktop & Documents Folders:
///   the Desktop is stored in iCloud Drive; a second Mac's Desktop appears in a
///   folder named after that Mac.
/// - <https://eclecticlight.co/2018/05/03/going-for-icloud-drive-or-the-whole-way-with-desktop-documents-folders/> —
///   on-disk placement relative to ~/Library/Mobile Documents is inconsistent.
///
/// Apple developer documentation for these three keys was searched for
/// (developer.apple.com/documentation/coreservices/kmditemisscreencapture
/// returned HTTP 404, 2026-09); the attribute semantics rest on the
/// reverse-engineering write-up above.
pub(crate) static MACOS_SCREENSHOT_XATTRS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_screenshot_xattrs",
    name: "Screenshot Provenance Xattrs (kMDItemIsScreenCapture)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Extended attributes the macOS screen-capture tool writes on the image it \
        saves: com.apple.metadata:kMDItemIsScreenCapture (true; absent rather than false \
        on other images), com.apple.metadata:kMDItemScreenCaptureType (\"display\" for \
        the whole screen, \"window\" for a window, \"selection\" for a dragged region) and \
        com.apple.metadata:kMDItemScreenCaptureGlobalRect (capture position on screen; \
        reported in 2016 to hold only the origin x value). Together they mark a file as a screenshot taken on a Mac and say which \
        capture mode was used, independent of the file name. Apple documents the default: \
        saved to the Desktop as \"Screen Shot [date] at [time]\", with the location \
        user-changeable. Read with `xattr -l` or `mdls` (Spotlight: \
        kMDItemIsScreenCapture:1).",
    mitre_techniques: &["T1113"],
    fields: &[
        FieldSchema { name: "is_screen_capture", value_type: ValueType::Bool, description: "kMDItemIsScreenCapture; present (true) only on screenshots", is_uid_component: false },
        FieldSchema { name: "capture_type", value_type: ValueType::Text, description: "kMDItemScreenCaptureType: display, window or selection", is_uid_component: false },
        FieldSchema { name: "capture_rect", value_type: ValueType::Text, description: "kMDItemScreenCaptureGlobalRect: capture coordinates (encoding not vendor-documented)", is_uid_component: false },
    ],
    retention: Some("Travels with the file on xattr-capable file systems until stripped or the image is re-saved"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_lastuseddate_xattr", "macos_spotlight_store", "macos_quarantine_xattr"],
    sources: &[
        "https://support.apple.com/en-hk/102646",
        "https://eternalstorms.wordpress.com/2016/09/10/deconstructing-and-reimplementing-macos-screencapture-cli/",
        "https://www.cool3c.com/article/107337",
        "https://support.apple.com/en-us/109344",
        "https://eclecticlight.co/2018/05/03/going-for-icloud-drive-or-the-whole-way-with-desktop-documents-folders/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "With iCloud Drive Desktop & Documents Folders on, the Desktop is stored in iCloud and shared across the user's Macs (Apple: a second Mac's Desktop appears in a folder named after that Mac), so a screenshot on the Desktop may have been taken on another Mac; establish whether the feature was on before attributing the capture to this machine. Where it sits on disk varies by macOS version: a ~/Library/Mobile Documents/com~apple~CloudDocs/Desktop folder was observed on one macOS Big Sur 11.7 image, while Eclectic Light (2018) reports Desktop and Documents are not placed consistently under ~/Library/Mobile Documents",
        "The default file-name prefix is localised and changeable (defaults write com.apple.screencapture name); older Traditional Chinese systems use 螢幕快照, so file-name searches miss screenshots that the xattr still identifies",
        "Semantics come from a 2016 reverse-engineering write-up, not Apple; kMDItemScreenCaptureGlobalRect's encoding in particular is unsettled, so validate against a known capture on the same macOS version",
        "Absence proves nothing: third-party capture tools need not set these attributes, and xattr -d removes them",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Extended attributes travel with the file until explicitly removed",
};

/// Sandboxed Safari's WebKit network cache in the com.apple.Safari container.
///
/// # Sources
/// - <https://www.cyberengage.org/post/analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos> —
///   macOS path `~/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/WebKitCache/`;
///   Records, Resources and Blobs directories.
/// - <https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/cache/NetworkCacheStorage.cpp> —
///   `Version <n>/Records/`, `Blobs/`, `-blob` suffix.
/// - <https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/cache/NetworkCache.cpp> —
///   cache key = partition, record type ("Resource"), range, request URL.
pub(crate) static MACOS_SAFARI_WEBKIT_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_webkit_cache",
    name: "Safari WebKit Network Cache (sandboxed container)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/WebKitCache/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "WebKit disk cache of sandboxed Safari: WebKitCache/Version <n>/Records/<partition \
        hash>/Resource/<key hash> record files (with -blob siblings) plus a Blobs/ directory \
        of larger bodies. Each record carries its cache key, which includes the cache \
        partition (top-level site) and the request URL, together with the stored \
        response headers and, for small bodies, the body itself. Recovers pages, images \
        and scripts the browser fetched, with their URLs, after history is cleared. The \
        container's Cache.db (CFNetwork cfurl_cache_response tables) sits beside it.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Request URL from the record's cache key", is_uid_component: true },
        FieldSchema { name: "partition", value_type: ValueType::Text, description: "Cache partition (top-level site) from the key", is_uid_component: false },
        FieldSchema { name: "response_headers", value_type: ValueType::Text, description: "Stored HTTP response headers (Date, Content-Type, ...)", is_uid_component: false },
    ],
    retention: Some("Size-capped cache; evicted as it fills and cleared with website data"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_safari_tab_snapshots", "fa_file_com_apple_safari_cache_db_2"],
    sources: &[
        "https://www.cyberengage.org/post/analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos",
        "https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/cache/NetworkCacheStorage.cpp",
        "https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/cache/NetworkCache.cpp",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "A cached resource shows the browser fetched it, not that the user viewed it: pages load images, scripts and prefetches the user never looked at",
        "Layout is read from current WebKit source; the Version <n> directory and record encoding change across Safari releases, so check the version on the image",
        "Older, unsandboxed Safari used ~/Library/Caches/com.apple.Safari/; collect both locations",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Cache entries are added and evicted with browsing",
};

/// Sandboxed Safari page-image caches: `TabSnapshots/` (+ `Metadata.db`) and
/// `Webpage Previews/` in the com.apple.Safari container.
///
/// # Sources
/// - <https://www.cyberengage.org/post/analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos> —
///   `~/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/TabSnapshots/Metadata.db`
///   stores cached tab screenshots with metadata; each snapshot's UUID links to its image file.
/// - <http://forensicsfromthesausagefactory.blogspot.com/2010/06/safari-internet-history-round-up.html> —
///   `Webpage Previews` holds Top Sites and Quick Look images of pages, named by the
///   MD5 of the URL (2010, unsandboxed Safari).
pub(crate) static MACOS_SAFARI_TAB_SNAPSHOTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_tab_snapshots",
    name: "Safari Tab Snapshots and Webpage Previews (sandboxed container)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/TabSnapshots/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Rendered images of web pages that sandboxed Safari keeps in its container \
        caches. TabSnapshots/ holds tab snapshot images with a Metadata.db SQLite \
        database whose rows link each snapshot UUID to its image file; the sibling \
        Webpage Previews/ folder holds page images used for Top Sites and Quick Look \
        previews, historically named by the MD5 of the page URL. These show what a page \
        looked like when Safari rendered it, which the history database alone cannot.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "snapshot_uuid", value_type: ValueType::Guid, description: "Snapshot identifier in Metadata.db linking to the image file", is_uid_component: true },
    ],
    retention: Some("Cache; replaced as tabs change and cleared with Safari caches"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["fa_file_tabsnapshots_metadata_db", "macos_safari_webkit_cache"],
    sources: &[
        "https://www.cyberengage.org/post/analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos",
        "http://forensicsfromthesausagefactory.blogspot.com/2010/06/safari-internet-history-round-up.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "The generated entry fa_file_tabsnapshots_metadata_db gives only the unsandboxed ~/Library/Caches/com.apple.Safari/ path; sandboxed Safari writes here, observed on one macOS Big Sur 11.7 image with PNG snapshots beside Metadata.db",
        "Webpage Previews naming (MD5 of URL) is from a 2010 account of unsandboxed Safari; confirm against the image before relying on it",
        "A snapshot or preview shows a page was rendered in Safari, not how long it was viewed or who viewed it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Snapshots are rewritten as tabs change",
};

/// syspolicyd's ExecPolicy database — Gatekeeper's own ledger of executable
/// evaluations, and (since Ventura) the store behind the com.apple.provenance
/// xattr.
///
/// # Sources
/// - <https://knight.sc/reverse%20engineering/2019/02/20/syspolicyd-internals.html> —
///   syspolicyd writes evaluation state into
///   /var/db/SystemPolicyConfiguration/ExecPolicy (legacy_exec_history_v4 and
///   related tables).
/// - <https://redcanary.com/blog/threat-detection/gatekeeper/> — tables include
///   executable_measurements_v2 and provenance_tracking.
/// - <https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/> —
///   macOS 13 Ventura's com.apple.provenance xattr, backed by the
///   provenance_tracking table (cdhash, team identifier).
pub(crate) static MACOS_EXEC_POLICY_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_exec_policy_db",
    name: "ExecPolicy Database (syspolicyd / Gatekeeper evaluations)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/db/SystemPolicyConfiguration/ExecPolicy"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SQLite database written by syspolicyd recording Gatekeeper's evaluations of \
        executables: measurement rows carrying code-directory hash (cdhash), signing \
        identifier, team identifier and evaluation timestamps \
        (executable_measurements_v2), historical execution-approval state \
        (legacy_exec_history_v4 and successors), and — from macOS 13 Ventura — the \
        provenance_tracking table that backs the com.apple.provenance extended attribute \
        stamped on apps at first launch. Evidence that a given binary was evaluated (and \
        so launched or staged for launch) on this system, surviving deletion of the binary \
        itself; the recorded team/signing identity distinguishes signed vendor software \
        from unsigned tooling. Root-owned and SIP-protected on a live system — read from \
        an image or a full-disk-access collection.",
    mitre_techniques: &["T1553.001", "T1204.002"],
    fields: &[
        FieldSchema { name: "cdhash", value_type: ValueType::Text, description: "Code-directory hash of the evaluated executable", is_uid_component: true },
        FieldSchema { name: "signing_identifier", value_type: ValueType::Text, description: "Code-signing identifier (bundle/binary identity) recorded at evaluation", is_uid_component: false },
        FieldSchema { name: "team_identifier", value_type: ValueType::Text, description: "Developer team ID; null/absent for unsigned code", is_uid_component: false },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Evaluation/measurement timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent database; rows survive deletion of the evaluated binaries"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_quarantine_xattr", "macos_gatekeeper_logs", "macos_unified_log"],
    sources: &[
        "https://knight.sc/reverse%20engineering/2019/02/20/syspolicyd-internals.html",
        "https://redcanary.com/blog/threat-detection/gatekeeper/",
        "https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Schema is reverse-engineered and churns across macOS releases (v2/v3/v4 table suffixes) — confirm the table set on the version at hand",
        "provenance_tracking and the com.apple.provenance xattr exist only on macOS 13 Ventura and later",
        "Records evaluation, not proof of successful execution — correlate with unified log syspolicyd/ExecPolicy messages",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite database accumulates evaluation rows; not routinely pruned",
};

// ── macOS usage-telemetry batch ──────────────────────────────────────────────

/// The Biome stream store as a whole — the successor to knowledgeC.db for
/// usage telemetry. The catalog's `macos_biome_app_menuitem` entry covers one
/// stream; this entry covers the store's layout.
///
/// # Sources
/// - <https://github.com/cclgroupltd/ccl-segb> — SEGB v1/v2 container format
///   reader (auto-detects version); records expose offset, Written/Deleted
///   state (deleted records typically zeroed), timestamp1 (+ timestamp2 on v1).
/// - <https://www.magnetforensics.com/blog/bringing-it-back-with-biome-data/> —
///   `local` folders hold this device's SEGB files; `remote` folders hold
///   streams synced from the user's other Apple devices, organised by
///   originating-device UUID.
/// - <https://blog.d204n6.com/2022/09/ios-16-breaking-down-biomes-part-4.html> —
///   the "Breaking Down the Biomes" series: streams/restricted layout and
///   per-stream protobuf content.
pub(crate) static MACOS_BIOME_STREAMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_biome_streams",
    name: "Apple Biome Stream Store (SEGB)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Biome/streams/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Apple's Biome framework stores usage telemetry as many per-topic streams of \
        SEGB (segmented binary) container files wrapping protobuf records — app focus, \
        app install state, device state, Safari activity and a growing stream list — the \
        data that migrated out of knowledgeC.db on modern macOS/iOS. Two roots exist and \
        both must be examined: the per-user store under ~/Library/Biome/streams/ and the \
        system store under /private/var/db/biome. Streams divide into public/ and \
        restricted/; inside a stream, local/ holds records generated on this machine \
        while remote/ holds records synced from the user's OTHER Apple devices on the \
        same Apple ID, organised in folders named by originating-device UUID — evidence \
        about an iPhone can therefore sit on the Mac being examined, and vice versa. \
        SEGB records carry a Written/Deleted state (deleted records are typically \
        zeroed) and one or two timestamps whose event-vs-write semantics differ per \
        stream — establish the meaning per stream before building a timeline. Parse with \
        ccl-segb or equivalent; most SEGB content is absent from Time Machine-style \
        backups, so full filesystem images or live full-disk-access collection are the \
        acquisition paths.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "stream_name", value_type: ValueType::Text, description: "Stream (topic) directory name, e.g. App.InFocus", is_uid_component: true },
        FieldSchema { name: "record_state", value_type: ValueType::Text, description: "SEGB record state: Written (live) or Deleted (typically zeroed)", is_uid_component: false },
        FieldSchema { name: "timestamp1", value_type: ValueType::Timestamp, description: "First SEGB record timestamp; event-time vs write-time semantics vary per stream", is_uid_component: false },
        FieldSchema { name: "origin_device", value_type: ValueType::Text, description: "local, or the originating-device UUID folder for remote (synced) records", is_uid_component: false },
    ],
    retention: Some("Streams rotate; retention varies per stream from days to months"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_biome_app_menuitem", "macos_knowledgec", "macos_screen_time_db"],
    sources: &[
        "https://github.com/cclgroupltd/ccl-segb",
        "https://www.magnetforensics.com/blog/bringing-it-back-with-biome-data/",
        "https://blog.d204n6.com/2022/09/ios-16-breaking-down-biomes-part-4.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Per-stream timestamp semantics (event time vs record-write time) must be established stream by stream",
        "remote/ records describe activity on ANOTHER device — attribute them to the originating device UUID, not this machine",
        "Stream set churns with every OS release; absence of a stream is not evidence of inactivity",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "SEGB stream files rotate; deleted records are zeroed in place before file rotation",
};

/// Saved Application State ("Resume") — per-app window-restoration state whose
/// window titles and Terminal contents reconstruct user activity.
///
/// # Sources
/// - <https://www.crowdstrike.com/en-us/blog/reconstructing-command-line-activity-on-macos/> —
///   UI Preservation state under ~/Library/Saved Application State/ used to
///   reconstruct Terminal command-line activity; data.data is encrypted with a
///   per-app key stored in windows.plist.
/// - <https://mothersruin.com/software/Archaeology/reverse/appstate.html> —
///   windows.plist holds top-level metadata about each restorable window
///   (including titles); data.data holds the encrypted per-window archives.
pub(crate) static MACOS_SAVED_APPLICATION_STATE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_saved_application_state",
    name: "Saved Application State (Resume)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Saved Application State/*.savedState/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-application window-restoration state written by macOS UI Preservation \
        (Resume): each <bundle-id>.savedState directory holds windows.plist — top-level \
        metadata for every restorable window, including window TITLES — and data.data, \
        encrypted per-window archives whose AES key is stored alongside in \
        windows.plist, making them recoverable offline. Window titles alone leak document \
        names, browsed folders and remote hosts; for Terminal, published research \
        reconstructs on-screen command-line activity from the decrypted state — a \
        substitute for shell history after the history file is cleared. Snapshot \
        reflects the state when each app last closed with the feature active.",
    mitre_techniques: &["T1083"],
    fields: &[
        FieldSchema { name: "bundle_id", value_type: ValueType::Text, description: "Application bundle id from the .savedState directory name", is_uid_component: true },
        FieldSchema { name: "window_title", value_type: ValueType::Text, description: "Restorable window title from windows.plist", is_uid_component: false },
        FieldSchema { name: "state_mtime", value_type: ValueType::Timestamp, description: "Filesystem mtime of the saved state — when the state was last written", is_uid_component: false },
    ],
    retention: Some("Rewritten as apps close; persists until the app next rewrites or the user clears it"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_bash_sessions", "macos_zsh_sessions", "macos_knowledgec"],
    sources: &[
        "https://www.crowdstrike.com/en-us/blog/reconstructing-command-line-activity-on-macos/",
        "https://mothersruin.com/software/Archaeology/reverse/appstate.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Apps can opt out of state restoration; secure-input fields are excluded",
        "Reflects last-close state only, not a continuous record",
        "On recent macOS (Sequoia 15.4-era onward) the directory has been reported absent or relocated into per-app containers — verify presence for the version at hand",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten on application close; prior state is overwritten",
};

/// Spotlight's per-user application inventory `appList.dat`.
///
/// # Sources
/// - <https://github.com/ydkhatri/mac_apt/blob/master/plugins/applist.py> —
///   reads `~/Library/Application Support/com.apple.spotlight/appList.dat` as
///   an NSKeyedArchiver plist and extracts displayName, bundleID and URL per
///   application (code-read).
pub(crate) static MACOS_APPLIST_DAT: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_applist_dat",
    name: "Spotlight Application List (appList.dat)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Application Support/com.apple.spotlight/appList.dat"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-user serialized plist (NSKeyedArchiver) maintained by Spotlight listing \
        applications known for that user: display name, bundle identifier and file URL \
        per app. A quick per-user software inventory that includes apps installed \
        outside /Applications (e.g. under ~/Applications), catching games, tooling and \
        unwanted software that a system-wide receipt sweep misses. Layout is established \
        by parser source (mac_apt appList plugin), not vendor documentation.",
    mitre_techniques: &["T1518"],
    fields: &[
        FieldSchema {
            name: "display_name",
            value_type: ValueType::Text,
            description: "Application display name",
            is_uid_component: false,
        },
        FieldSchema {
            name: "bundle_id",
            value_type: ValueType::Text,
            description: "Application bundle identifier",
            is_uid_component: true,
        },
        FieldSchema {
            name: "url",
            value_type: ValueType::Text,
            description: "File URL of the application bundle",
            is_uid_component: false,
        },
    ],
    retention: Some("Maintained by Spotlight; reflects current index state"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[
        "macos_install_history",
        "macos_installer_receipts",
        "macos_spotlight_store",
    ],
    sources: &["https://github.com/ydkhatri/mac_apt/blob/master/plugins/applist.py"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Reflects Spotlight's current view — uninstalled apps may drop out on reindex",
        "Format known from parser source only; no vendor documentation",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten by Spotlight as the application set changes",
};

/// Per-interface DHCP lease plists — network identity and SSID with lease
/// timing.
///
/// # Sources
/// - <https://github.com/ydkhatri/mac_apt/blob/master/plugins/networking.py> —
///   parses /private/var/db/dhcpclient/leases/ plists extracting IPAddress,
///   LeaseLength, LeaseStartDate, RouterIPAddress, RouterHardwareAddress,
///   SSID and raw PacketData (code-read).
/// - <https://github.com/apple-oss-distributions/bootp/blob/bootp-534.120.2/IPConfiguration.bproj/DHCPLease.c>
///   — `DHCPCLIENT_LEASE_FILE_FMT` is `DHCPCLIENT_LEASES_DIR "/%s.plist"`
///   (interface name only; also so at bootp-413.80.1); keys LeaseStartDate,
///   RouterHardwareAddress, SSID and NetworkID (Wi-Fi only), ClientIdentifier;
///   `DHCPLeaseListWrite` saves "the last (current) lease" and unlinks the
///   file when `DHCPLeaseListRemoveStaleLeases` has dropped every lease
///   (`current_time >= lease_start + lease_length`). The leases directory
///   is referenced nowhere else in that tree, so nothing removes files in the
///   older naming scheme (code-read).
/// - <https://github.com/apple-oss-distributions/bootp/blob/bootp-359.50.1/IPConfiguration.bproj/DHCPLease.c>
///   — `DHCPCLIENT_LEASE_FILE_FMT` is `DHCPCLIENT_LEASES_DIR "/%s-%s"`:
///   interface name and client identifier, one file per pair (code-read).
///
/// Observed on one macOS Big Sur 11.7 image: both formats for one interface,
/// the old-format file orphaned across the OS upgrade and holding a
/// pre-upgrade lease.
pub(crate) static MACOS_DHCP_LEASES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_dhcp_leases",
    name: "DHCP Client Lease Plists",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/db/dhcpclient/leases/*"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Plists written by IPConfiguration recording a DHCP lease: assigned IP address, \
        lease start time (LeaseStartDate) and length, gateway IP and MAC \
        (RouterHardwareAddress), the SSID and NetworkID for Wi-Fi interfaces, the \
        ClientIdentifier, and the raw DHCP packet. Places the machine on a named network with \
        a specific address at a specific time — the local half of a network-correlation with \
        router/DHCP-server logs, and corroboration for Wi-Fi join history. Apple's bootp \
        source names the file two ways: `<ifname>.plist` (bootp-413.80.1 and later) and \
        `<ifname>-<client-id>` (bootp-359.50.1 and earlier, e.g. en1-1,<client MAC>). Each \
        file holds one lease, the last one written for it, and is deleted when that lease \
        has expired at the next write. The newer code never touches old-format files, so a \
        Mac upgraded across the change can hold both for one interface, the old one orphaned \
        with the last lease from before the upgrade.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema {
            name: "ip_address",
            value_type: ValueType::Text,
            description: "IP address assigned by the lease",
            is_uid_component: false,
        },
        FieldSchema {
            name: "lease_start",
            value_type: ValueType::Timestamp,
            description: "Lease start timestamp",
            is_uid_component: false,
        },
        FieldSchema {
            name: "router_ip",
            value_type: ValueType::Text,
            description: "Gateway/router IP address",
            is_uid_component: false,
        },
        FieldSchema {
            name: "router_mac",
            value_type: ValueType::Text,
            description: "Gateway/router hardware (MAC) address",
            is_uid_component: false,
        },
        FieldSchema {
            name: "ssid",
            value_type: ValueType::Text,
            description: "Wi-Fi network SSID for wireless interfaces",
            is_uid_component: true,
        },
    ],
    retention: Some("One lease per file, replaced whenever IPConfiguration saves a lease and deleted once expired; an orphaned old-format file is left untouched"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_wifi_plist", "macos_wifi_intelligence"],
    sources: &[
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/networking.py",
        "https://github.com/apple-oss-distributions/bootp/blob/bootp-534.120.2/IPConfiguration.bproj/DHCPLease.c",
        "https://github.com/apple-oss-distributions/bootp/blob/bootp-359.50.1/IPConfiguration.bproj/DHCPLease.c",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Each file holds only the last lease written to it, so earlier leases on the same interface are gone; but an old-format `<ifname>-<client-id>` file can survive an OS upgrade holding a lease from before the upgrade (observed on one Big Sur 11.7 image). List the whole directory, and date the old file from its LeaseStartDate, not from the OS in use",
        "A file is deleted once its lease has expired at the next write, so a missing file does not mean the interface never held a lease",
        "Static-IP configurations leave no lease plist",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten on each DHCP renewal or network change",
};

/// Per-session zsh history — Apple Terminal's session-restoration mechanism,
/// which survives `.zsh_history` clearing.
///
/// # Sources
/// - <https://dfir.ch/posts/today_i_learned_zsh_sessions/> — ~/.zsh_sessions/
///   layout: UUID-named .history per-session command history and .session
///   restore metadata carrying a timestamp.
/// - <https://www.swiftforensics.com/2018/05/bash-sessions-in-macos.html> —
///   the Terminal session-persistence mechanism (documented for
///   ~/.bash_sessions, mirrored by zsh after Catalina): per-session history
///   files and how they outlive the main history file.
pub(crate) static MACOS_ZSH_SESSIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_zsh_sessions",
    name: "Zsh Per-Session History (.zsh_sessions)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/.zsh_sessions/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Apple Terminal's session-restoration store for zsh (the default shell since \
        Catalina), driven by the shipped /etc/zshrc_Apple_Terminal: for each Terminal \
        session a UUID-named .history file holds that session's command history and a \
        .session file holds restore metadata including a session timestamp. Because each \
        session's commands are duplicated here, a cleared or tampered ~/.zsh_history \
        does not remove them — per-session files are the redundancy that survives \
        history cleanup, and their file timestamps date each session. The \
        _expiration_check_timestamp file tracks the expiry sweep. The equivalent \
        ~/.bash_sessions mechanism (already cataloged) applies where bash was used.",
    mitre_techniques: &["T1059.004", "T1070.003"],
    fields: &[
        FieldSchema { name: "session_uuid", value_type: ValueType::Text, description: "Terminal session UUID (file stem of the .history/.session pair)", is_uid_component: true },
        FieldSchema { name: "command", value_type: ValueType::Text, description: "Command line from the per-session .history file", is_uid_component: false },
        FieldSchema { name: "session_time", value_type: ValueType::Timestamp, description: "Session timestamp from the .session metadata / file timestamps", is_uid_component: false },
    ],
    retention: Some("Per-session files pruned by Terminal's expiration sweep; window typically days to weeks"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_bash_sessions", "macos_saved_application_state"],
    sources: &[
        "https://dfir.ch/posts/today_i_learned_zsh_sessions/",
        "https://www.swiftforensics.com/2018/05/bash-sessions-in-macos.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Only Terminal.app sessions write here — SSH sessions and third-party terminals that do not source the Apple Terminal shell hooks leave nothing",
        "History is written on clean shell exit; a crashed or killed session may leave a partial or empty .history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Session files accumulate per Terminal session and are pruned by the expiration check",
};

/// XProtect's behavioural database (XPdb) — suspicious-behaviour events
/// recorded by XProtectBehaviorService against Apple's Bastion rules.
///
/// # Sources
/// - <https://eclecticlight.co/2024/06/28/what-do-xprotect-behaviourservice-and-bastion-rules-do/> —
///   XProtectBehaviorService records rule-violating behaviour (e.g. processes
///   touching browser cookie stores or other protected paths) into its
///   database rather than blocking.
/// - <https://www.picussecurity.com/resource/blog/securing-macos-a-closer-look-at-built-in-macos-application-security> —
///   database path /var/protected/xprotect/XPdb.
/// - <https://clo.ng/blog/osquery-xpdb/> — querying XPdb with osquery; row
///   content (violated rule, offending process path, timestamp).
pub(crate) static MACOS_XPROTECT_BEHAVIORAL_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_xprotect_behavioral_db",
    name: "XProtect Behavioural Database (XPdb)",
    artifact_type: ArtifactLocation::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/protected/xprotect/XPdb"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS13Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database in which XProtectBehaviorService records behaviour that \
        violates Apple's Bastion rules — for example a process reading another app's \
        protected data such as browser cookie stores — with the offending process path, \
        the rule violated, and a timestamp. Detection telemetry, not enforcement: events \
        are recorded silently with no user-visible alert, so the database can hold \
        evidence of information-stealer behaviour that nothing else surfaced. Present on \
        Ventura-era macOS onward as the behaviour service rolled out; a 2026 XProtect \
        update moved the file into a db/ subfolder under /var/protected/xprotect/ — \
        check both locations. Root-protected; read from an image or privileged \
        collection.",
    mitre_techniques: &["T1005", "T1555.003"],
    fields: &[
        FieldSchema { name: "process_path", value_type: ValueType::Text, description: "Path of the process whose behaviour matched a Bastion rule", is_uid_component: true },
        FieldSchema { name: "rule", value_type: ValueType::Text, description: "Bastion rule / protected resource involved", is_uid_component: false },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "When the behaviour was recorded", is_uid_component: false },
    ],
    retention: Some("Accumulates recorded events; pruning behaviour undocumented"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "macos_tcc_system_db"],
    sources: &[
        "https://eclecticlight.co/2024/06/28/what-do-xprotect-behaviourservice-and-bastion-rules-do/",
        "https://www.picussecurity.com/resource/blog/securing-macos-a-closer-look-at-built-in-macos-application-security",
        "https://clo.ng/blog/osquery-xpdb/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Rule set (Bastion) is Apple-updated and undocumented — an empty database means no rule matched, not that no theft occurred",
        "Location is version-bound: originally /var/protected/xprotect/XPdb, moved into a db/ subfolder by a 2026 XProtect update",
        "Records behaviour observations, not verdicts — corroborate before treating a row as malicious activity",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Event rows accumulate in the protected database until pruned by the service",
};

// ── macOS persistence + Finder batch ─────────────────────────────────────────

/// Root-running helper binaries installed via `SMJobBless` — a Launch Daemon
/// by another name, and a high-value persistence surface.
///
/// # Sources
/// - <https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)> —
///   Apple: the helper is installed into /Library/PrivilegedHelperTools and
///   registered with a launchd property list in /Library/LaunchDaemons.
/// - <https://www.sentinelone.com/blog/how-malware-persists-on-macos/> —
///   abuse of privileged helpers for persistence.
pub(crate) static MACOS_PRIVILEGED_HELPER_TOOLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_privileged_helper_tools",
    name: "Privileged Helper Tools",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/PrivilegedHelperTools/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Mach-O helper binaries installed through the ServiceManagement framework \
        (SMJobBless) so applications can perform privileged work without prompting each \
        time. Apple documents the pairing: the helper binary lives in \
        /Library/PrivilegedHelperTools and a launchd plist in /Library/LaunchDaemons \
        names it in Program/ProgramArguments (with MachServices entries) — the helper IS \
        a root Launch Daemon. Review triangle: code signature (legitimate helpers carry \
        a full Developer ID chain and TeamIdentifier — but a signature is necessary, not \
        sufficient, given stolen certificates), birth/modification timestamps against \
        the incident window, and the PLIST'S ACTUAL TARGET — a legitimately-named plist \
        edited to point at a different binary is the subtle variant. Root is required to \
        plant one; the payoff is root execution surviving reboot.",
    mitre_techniques: &["T1543.004", "T1548"],
    fields: &[
        FieldSchema { name: "helper_path", value_type: ValueType::Text, description: "Path of the helper binary under /Library/PrivilegedHelperTools", is_uid_component: true },
        FieldSchema { name: "team_identifier", value_type: ValueType::Text, description: "Code-signing team ID; unsigned or unexpected identity warrants inspection", is_uid_component: false },
        FieldSchema { name: "launchd_plist", value_type: ValueType::Text, description: "Paired plist in /Library/LaunchDaemons whose Program points at the helper", is_uid_component: false },
    ],
    retention: Some("Persistent until uninstalled"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["macos_launch_daemons", "macos_btm_background_tasks"],
    sources: &[
        "https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)",
        "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "A valid signature does not clear a helper — stolen certificates and compromised developer accounts defeat that check",
        "Verify the paired plist's Program target, not just the helper directory: a known-good plist name can point at a malicious binary",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Helper binary and paired plist persist on disk until removed",
};

/// The SystemExtensions activation database — which user-space extensions
/// (the kext successors, macOS 10.15+) are staged, approved and activated.
///
/// # Sources
/// - <https://developer.apple.com/documentation/systemextensions> — Apple:
///   the System Extensions framework (user-space replacements for kexts;
///   signing, notarization and user-approval requirements).
/// - <https://gist.github.com/nstrauss/ebca31a8110f6429ea4f2f91f4a7257b> —
///   community documentation of /Library/SystemExtensions/db.plist contents
///   (extension records with state, identifier, team) and the staged bundle
///   directories alongside it.
pub(crate) static MACOS_SYSTEM_EXTENSIONS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_system_extensions_db",
    name: "System Extensions Database (db.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/SystemExtensions/db.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Property list tracking system extensions (macOS 10.15+ user-space \
        successors to kernel extensions): per-extension records with bundle identifier, \
        team identifier, and activation state, alongside the staged extension bundles in \
        UUID-named directories under /Library/SystemExtensions/. An approved extension — \
        network filters and endpoint monitors included — reloads automatically at boot, \
        making this a reboot-surviving persistence and traffic-interception surface for \
        an attacker who obtains signing plus user approval (or social-engineers the \
        click-through). Enumerate live with `systemextensionsctl list`; on an image, \
        db.plist is the record. Unknown team IDs, extensions matching no installed \
        product, and activation timestamps inside the incident window are the flags. \
        The db.plist layout rests on community documentation, not vendor \
        documentation — the framework itself is Apple-documented.",
    mitre_techniques: &["T1547.006"],
    fields: &[
        FieldSchema { name: "bundle_id", value_type: ValueType::Text, description: "Extension bundle identifier", is_uid_component: true },
        FieldSchema { name: "team_id", value_type: ValueType::Text, description: "Developer team identifier of the extension's signer", is_uid_component: false },
        FieldSchema { name: "state", value_type: ValueType::Text, description: "Activation state (e.g. activated_enabled) recorded for the extension", is_uid_component: false },
    ],
    retention: Some("Persistent until the extension is uninstalled/deactivated"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_launch_daemons", "macos_btm_background_tasks"],
    sources: &[
        "https://developer.apple.com/documentation/systemextensions",
        "https://gist.github.com/nstrauss/ebca31a8110f6429ea4f2f91f4a7257b",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "db.plist internal layout is community-documented only — verify field readings against systemextensionsctl output on a matching macOS version",
        "Removal via systemextensionsctl does not clean associated files; a resident app can re-install its extension",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Activation records and staged bundles persist across reboots until deactivated",
};

/// Legacy loginwindow hooks — root-executed scripts at login/logout,
/// deprecated by Apple yet still honoured.
///
/// # Sources
/// - <https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html> —
///   Apple: LoginHook/LogoutHook keys in the loginwindow preferences run a
///   script as root at login/logout; deprecated in favour of launchd.
/// - <https://theevilbit.github.io/beyond/beyond_0022/> — abuse as a
///   persistence mechanism and where the setting lives on disk.
pub(crate) static MACOS_LOGIN_LOGOUT_HOOKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_login_logout_hooks",
    name: "Login / Logout Hooks (com.apple.loginwindow)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/root/Library/Preferences/com.apple.loginwindow.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Deprecated-but-functional mechanism: a LoginHook or LogoutHook key in the \
        loginwindow preferences (set via `sudo defaults write com.apple.loginwindow \
        LoginHook /path/to/script`) makes loginwindow execute the named script AS ROOT \
        at every user login or logout. Apple has deprecated the mechanism in favour of \
        launchd for two decades, which is precisely why it is overlooked: a hook \
        configured on an upgraded or long-lived system keeps firing. Any value present \
        is worth explaining — modern software has no legitimate reason to use it. Check \
        the root-domain preferences (sudo defaults read com.apple.loginwindow) and \
        per-user copies under ~/Library/Preferences, then chase the referenced script's \
        content and timestamps.",
    mitre_techniques: &["T1037.002"],
    fields: &[
        FieldSchema { name: "login_hook", value_type: ValueType::Text, description: "Path of the script run as root at login (LoginHook key)", is_uid_component: true },
        FieldSchema { name: "logout_hook", value_type: ValueType::Text, description: "Path of the script run as root at logout (LogoutHook key)", is_uid_component: false },
    ],
    retention: Some("Persistent until the key is cleared"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_launch_agents_user", "macos_launch_daemons", "macos_login_items_plist"],
    sources: &[
        "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html",
        "https://theevilbit.github.io/beyond/beyond_0022/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Deprecated mechanism — absence is the norm; any configured hook needs a documented justification",
        "The plist key names the script but the payload is the script file itself — preserve both",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Preference key persists until explicitly removed",
};

/// `.DS_Store` — Finder's per-folder metadata file, the closest macOS
/// analogue to ShellBags: proof of GUI interaction with a folder, and a
/// record of item names including items no longer present.
///
/// # Sources
/// - <https://eclecticlight.co/2021/11/27/explainer-ds_store-files/> —
///   what Finder stores per folder; Trash .DS_Store holds filenames and
///   original paths of trashed items.
/// - <https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf> —
///   Nicole Ibrahim, "DS_Stores: Like Shellbags but for Macs" (SANS DFIR
///   Summit 2019): record types incl. Iloc/put-back fields; forensic use.
/// - <https://ponderthebits.com/2017/01/mac-dumpster-diving-identifying-deleted-file-references-in-the-trash-ds_store-files-part-1/> —
///   deleted-file references recoverable from .DS_Store files.
pub(crate) static MACOS_DS_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_ds_store",
    name: ".DS_Store (Finder folder metadata)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/**/.DS_Store"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Hidden per-folder file in a bespoke binary B-tree format where Finder \
        stores folder-view state: view style, window geometry, sort keys, icon \
        positions, labels and comments — keyed BY ITEM NAME, so it names files and \
        subfolders of the folder, including items since deleted or moved (ghost \
        records). Presence is evidence the folder was interacted with through the \
        Finder GUI; a .DS_Store inside a zip or on a non-Mac system indicates the \
        content passed through a Mac. Absence proves little: Terminal-only access \
        writes none, and Finder does not create one for every view. The file itself \
        carries no internal timestamps — timing comes from its filesystem birth/mtime. \
        Also written to external media and network shares (unless disabled by \
        preference), leaving Mac fingerprints on foreign volumes.",
    mitre_techniques: &["T1083"],
    fields: &[
        FieldSchema { name: "item_name", value_type: ValueType::Text, description: "Name of a folder item the record describes — may reference items no longer present", is_uid_component: true },
        FieldSchema { name: "record_type", value_type: ValueType::Text, description: "Four-char record type (e.g. Iloc icon location, view-style records, ptbL/ptbN in the Trash)", is_uid_component: false },
    ],
    retention: Some("No rotation; stale entries persist until Finder rewrites the file"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_trash", "macos_fsevents", "macos_spotlight_store"],
    sources: &[
        "https://eclecticlight.co/2021/11/27/explainer-ds_store-files/",
        "https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf",
        "https://ponderthebits.com/2017/01/mac-dumpster-diving-identifying-deleted-file-references-in-the-trash-ds_store-files-part-1/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Ghost entries are weak, corroborating evidence — not a complete historical record of folder contents",
        "Absence proves nothing: Finder view mode and access path determine whether one is written",
        "No user attribution inside the file — the owning home directory and filesystem metadata supply it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten as Finder view state changes; stale item records linger until then",
};

/// The Trash — per-user on the boot volume, per-UID on other volumes, with
/// put-back records that outlive the trashed files.
///
/// # Sources
/// - <https://ponderthebits.com/2017/01/mac-dumpster-diving-identifying-deleted-file-references-in-the-trash-ds_store-files-part-1/> —
///   Trash .DS_Store put-back records give the pre-deletion path; references
///   persist for files no longer in the Trash.
/// - <https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf> —
///   Ibrahim: ptbL (put-back location) / ptbN (put-back name) record fields.
/// - <https://github.com/SecurityRonin/trash-forensic> — open-source parser
///   decoding macOS Trash .DS_Store put-back records (ptbN/ptbL).
pub(crate) static MACOS_TRASH: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_trash",
    name: "Trash (.Trash / .Trashes) with Put-Back Records",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/.Trash/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Finder deletion is a move into the per-user hidden ~/.Trash; on non-boot \
        volumes, into <volume>/.Trashes/<numeric-UID>/. Three reads in one place: the \
        trashed files themselves; the Trash's .DS_Store, whose per-item ptbL (put-back \
        location — the original parent path) and ptbN (put-back name) records power \
        Finder's Put Back and PERSIST AFTER the item leaves the Trash, naming files \
        that no longer exist anywhere; and POSIX timestamps — the move updates the \
        file's ctime while leaving mtime and birth time untouched, so ctime marks the \
        trashing moment. On FAT/exFAT media, AppleDouble ._ sidecars carry the xattrs \
        (quarantine, WhereFroms download URLs) the foreign filesystem cannot hold. \
        Where macOS keeps the put-back reference for files trashed FROM AN EXTERNAL \
        volume — Put Back stops being offered after the volume is ejected and \
        remounted — is not established by any source located (searched: Ibrahim's \
        DFIR-summit material, the ponderthebits series, Apple documentation); treat \
        that one mechanism as an open research question, not a place to assert from.",
    mitre_techniques: &["T1070.004"],
    fields: &[
        FieldSchema { name: "ptbl_original_path", value_type: ValueType::Text, description: "Put-back location: original parent directory of the trashed item (persists after the item is gone)", is_uid_component: false },
        FieldSchema { name: "ptbn_original_name", value_type: ValueType::Text, description: "Put-back name: original filename of the trashed item", is_uid_component: true },
        FieldSchema { name: "ctime", value_type: ValueType::Timestamp, description: "Metadata-change time of a trashed file — marks the trashing moment (mtime/birth stay untouched)", is_uid_component: false },
    ],
    retention: Some("Files until Trash is emptied; ptbL/ptbN ghost records until Finder rewrites the Trash .DS_Store"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_ds_store", "macos_fsevents", "macos_quarantine_xattr"],
    sources: &[
        "https://ponderthebits.com/2017/01/mac-dumpster-diving-identifying-deleted-file-references-in-the-trash-ds_store-files-part-1/",
        "https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf",
        "https://github.com/SecurityRonin/trash-forensic",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "TCC blocks live reads of another user's .Trash even for admins — grant Full Disk Access or work from an image",
        "Cloud-sync trashes exist separately (e.g. per-provider under ~/Library/CloudStorage); a remote-originated deletion may leave no local Trash entry",
        "External-volume put-back reference location is an open question — recorded here so the search is not repeated from zero",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Contents cleared on empty; ghost put-back records linger in the Trash .DS_Store until rewritten",
};

/// `/Users/Shared/Relocated Items/` and older `Previously Relocated Items`
/// folders left by macOS installs.
///
/// # Sources
/// - <https://support.apple.com/guide/mac-help/mchl8ae423a3/mac> — Apple: files
///   that could not be moved to their new locations during an upgrade are placed
///   in a Relocated Items folder in /Users/Shared, with a Desktop alias and an
///   explanatory PDF.
/// - <https://www.macrumors.com/guide/relocated-items/> — origin in Catalina's
///   read-only system volume / Data volume split.
/// - <https://www.jessesquires.com/blog/2020/04/11/previously-previously-previously-relocated-items-in-macos-catalina/> —
///   the folder reappears with point releases and supplemental updates, with
///   earlier ones kept as "Previously Relocated Items".
pub(crate) static MACOS_RELOCATED_ITEMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_relocated_items",
    name: "Relocated Items Folders (macOS install / upgrade)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://support.apple.com/guide/mac-help/mchl8ae423a3/mac
    file_path: Some("/Users/Shared/Relocated Items/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Folder the macOS installer creates in /Users/Shared when files (in user \
        reports, mostly modified system configuration files) cannot be moved to their new location during \
        an upgrade, with an alias on the Desktop and an explanatory PDF inside. It arrived \
        with Catalina's split into a read-only system volume and a Data volume, and \
        recurs on later installs, including point releases and supplemental updates; the \
        previous folder is kept alongside as \"Previously Relocated Items\", with further \
        numbered copies after repeated installs. The folders' creation dates therefore \
        mark macOS install or update events on this Data volume, independent of the \
        installer logs and install receipts, and the configuration files inside show \
        what had been customised before that install.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "folder_created", value_type: ValueType::Timestamp, description: "Creation time of each Relocated Items / Previously Relocated Items folder: an OS install or update event", is_uid_component: true },
    ],
    retention: Some("Persists until the user deletes it; accumulates across installs"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["macos_installer_receipts"],
    sources: &[
        "https://support.apple.com/guide/mac-help/mchl8ae423a3/mac",
        "https://www.macrumors.com/guide/relocated-items/",
        "https://www.jessesquires.com/blog/2020/04/11/previously-previously-previously-relocated-items-in-macos-catalina/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Apple documents the Relocated Items folder, not the Previously Relocated Items naming or numbering; that comes from user reports and was observed (with numbered folders and the notice PDF in several languages) on one macOS Big Sur 11.7 image",
        "Apple describes the folder as created when files could not be moved, so an install that relocates nothing need not leave one and absence does not prove no upgrade took place; corroborate with install receipts and the install log",
        "Folder dates are only as good as the clock at install time and move if the folder is copied off the volume",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Created at install time and left until the user deletes it",
};

/// CUPS print spool: per-job IPP control files (`c#####`) and submitted-document
/// data files (`d#####-###`) in `/private/var/spool/cups/`.
///
/// # Sources
/// - <https://www.cups.org/doc/spec-design.html> — control files are IPP
///   messages based on the original Print-Job or Create-Job request, data files
///   are the original print files submitted; control files normally cleaned out
///   after the 500th job, data files removed after a successful print, both
///   configurable.
/// - <https://www.cups.org/doc/man-cupsd.conf.html> — PreserveJobFiles default
///   "86400" (preserve 1 day); PreserveJobHistory default "Yes" (kept until the
///   MaxJobs limit); MaxJobs default "500".
/// - <https://github.com/apple/cups/blob/v2.3.3/scheduler/cupsd.h> —
///   `DEFAULT_FILES 86400`, the compiled default since CUPS 1.6 (previously 0).
/// - <https://digitalbitbybit.blogspot.com/2012/11/mac-osx-printer-forensics.html> —
///   decoded macOS control file: job-name, job-originating-user-name,
///   job-originating-host-name, printer-uri, time-at-* values,
///   com.apple.print.JobInfo.PMApplicationName.
/// - <https://papers.put.as/papers/macosx/2015/RHUL-MA-2015-8.pdf> — Moreno
///   Garijo, "Mac OS X Forensics" (RHUL MSc, 2015), section 6.6: binary IPP
///   layout, time-at-* stored as integers, most valuable attributes.
/// - <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/cups_ipp.py> —
///   independent parser mapping the same attributes and the three job times.
pub(crate) static MACOS_CUPS_SPOOL_JOBS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_cups_spool_jobs",
    name: "CUPS Print Spool Control and Data Files",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://www.cups.org/doc/man-cups-files.conf.html (RequestRoot default /var/spool/cups)
    file_path: Some("/private/var/spool/cups/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The CUPS scheduler's job spool. Each job known to the system has one control file \
        named c followed by the job number (c00001, c00002, ...), an IPP message based on the \
        original Print-Job or Create-Job request, and zero or more data files named d<job>-<doc> \
        (d00001-001) holding the documents as submitted for printing. Decoded control files carry \
        job-id, job-name (the title the printing application gave the job, usually the document \
        name), job-originating-user-name (the local account that submitted it), \
        job-originating-host-name (localhost for a job printed from this Mac), printer-uri and \
        job-printer-uri, document-format, copies, job-state, job-media-sheets-completed, and \
        time-at-creation, time-at-processing and time-at-completed as Unix-epoch integers. macOS \
        adds Apple print attributes such as com.apple.print.JobInfo.PMApplicationName (the \
        application that printed) and com.apple.print.JobInfo.PMJobOwner (the account's full \
        name). Because a local job is created on this host by a named account, each control file \
        is a timestamped record of on-machine activity. Retention is set in cupsd.conf: with \
        PreserveJobHistory at its default of Yes, control files are kept until the MaxJobs limit \
        (default 500) is reached, so a lightly used Mac can hold years of print history; \
        PreserveJobFiles controls data files. The CUPS design description says data files are \
        removed immediately after a successful print, but since CUPS 1.6 the compiled default for \
        PreserveJobFiles is 86400 seconds, keeping them for one day after printing. A data file \
        still present long after its job's time-at-completed therefore usually belongs to a job \
        that never completed (held, stopped, cancelled or failed) or to a non-default \
        configuration, and it may be the only surviving copy of the printed document. \
        job-state 9 is completed (RFC 8011 section 5.3.7; 3 pending, 4 pending-held, 5 \
        processing, 6 processing-stopped, 7 canceled, 8 aborted). A completed job to a network printer means the printer was \
        reachable from the Mac at time-at-completed; a job created in one period and completed \
        much later shows when the printer became reachable again, which for a dnssd .local. \
        queue (macos_cups_printers_conf) is when the Mac was back on the printer's local \
        network.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "job_id", value_type: ValueType::UnsignedInt, description: "job-id; also the number in the c#####/d#####-### file names", is_uid_component: true },
        FieldSchema { name: "job_name", value_type: ValueType::Text, description: "job-name: title supplied by the printing application, usually the document name, not its path", is_uid_component: false },
        FieldSchema { name: "job_originating_user_name", value_type: ValueType::Text, description: "Account that submitted the job", is_uid_component: false },
        FieldSchema { name: "job_originating_host_name", value_type: ValueType::Text, description: "Host the job came from: localhost for a job printed on this Mac, another host for a job received through printer sharing", is_uid_component: false },
        FieldSchema { name: "printer_uri", value_type: ValueType::Text, description: "printer-uri / job-printer-uri: the queue and the device the job went to", is_uid_component: false },
        FieldSchema { name: "document_format", value_type: ValueType::Text, description: "MIME type of the submitted document (e.g. application/pdf)", is_uid_component: false },
        FieldSchema { name: "time_at_creation", value_type: ValueType::Timestamp, description: "When the job was created (Unix seconds)", is_uid_component: false },
        FieldSchema { name: "time_at_processing", value_type: ValueType::Timestamp, description: "When the job started processing (Unix seconds)", is_uid_component: false },
        FieldSchema { name: "time_at_completed", value_type: ValueType::Timestamp, description: "When the job finished (Unix seconds); absent for a job that never completed", is_uid_component: false },
        FieldSchema { name: "job_media_sheets_completed", value_type: ValueType::UnsignedInt, description: "Sheets reported printed", is_uid_component: false },
        FieldSchema { name: "pm_application_name", value_type: ValueType::Text, description: "com.apple.print.JobInfo.PMApplicationName: application that printed", is_uid_component: false },
    ],
    retention: Some("Control files kept until MaxJobs (default 500) under the default PreserveJobHistory Yes; data files kept one day after printing under the default PreserveJobFiles 86400"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["fa_file_cache_job_cache_2", "macos_cups_printers_conf", "macos_cups_logs", "macos_wifi_driver_log"],
    sources: &[
        "https://www.cups.org/doc/spec-design.html",
        "https://www.cups.org/doc/man-cupsd.conf.html",
        "https://github.com/apple/cups/blob/v2.3.3/scheduler/cupsd.h",
        "https://digitalbitbybit.blogspot.com/2012/11/mac-osx-printer-forensics.html",
        "https://papers.put.as/papers/macosx/2015/RHUL-MA-2015-8.pdf",
        "https://github.com/log2timeline/plaso/blob/main/plaso/parsers/cups_ipp.py",
        "https://www.rfc-editor.org/rfc/rfc8011#section-5.3.7",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "The CUPS design description (data files removed immediately after a successful print) predates the CUPS 1.6 change of the PreserveJobFiles default to one day; read the image's cupsd.conf for PreserveJobFiles, PreserveJobHistory and MaxJobs before inferring anything from what is present or absent",
        "The reading of a long-retained data file as a job that never completed is an inference from the default retention rules, not a recorded flag; confirm with job-state and time-at-completed in the matching control file",
        "job-originating-user-name names the account that submitted the job, not the person at the keyboard; a job-originating-host-name other than localhost means the job came from another machine through printer sharing and is not activity on this Mac",
        "Apple com.apple.print.* attribute names come from decoded examples in secondary sources (2012-2015), not from Apple documentation; confirm they are present on the image",
        "job-name is whatever title the application supplied; it is not the document's path and may not match its file name",
        "A completed job shows the printer was reachable from the Mac, not who was at the keyboard; printing to a network printer does not identify the operator, and a job held until the network returned completes without anyone present",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Oldest control files are purged once MaxJobs is reached; data files expire after PreserveJobFiles",
};

/// CUPS printer list: `/private/etc/cups/printers.conf`.
///
/// # Sources
/// - <https://www.cups.org/doc/man-printers.conf.html> — defines the local
///   printers; maintained by cupsd, not meant to be edited; name, location and
///   format are an implementation detail.
/// - <https://www.cups.org/doc/man-cups-files.conf.html> — printers.conf is
///   masked to the scheduler user because device URIs can contain
///   authentication information.
/// - <https://www.cups.org/doc/network.html> — Bonjour (DNS-SD) device URIs of the
///   form `dnssd://<service name>._ipp._tcp.local./?uuid=<uuid>`.
/// - <https://www.magnetforensics.com/blog/cups-artifact-support-for-macos/> —
///   printers.conf and /Library/Preferences/org.cups.printers.plist as the
///   macOS printer list.
pub(crate) static MACOS_CUPS_PRINTERS_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_cups_printers_conf",
    name: "CUPS printers.conf (configured printers)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/etc/cups/printers.conf"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The scheduler-maintained list of local print queues, one section per printer, each \
        with its DeviceURI: the address the queue prints to. For network printers found over \
        Bonjour the DeviceURI takes the dnssd:// form, carrying the printer's advertised service \
        name and a uuid query parameter (dnssd://<name>._ipp._tcp.local./?uuid=<uuid>), which \
        identifies the device independently of its IP address; ipp://, ipps:// and \
        socket:// URIs carry a host name or address instead. Together with printer-uri \
        in the spool control files this ties a print job to a specific device, and the set of \
        queues shows which printers, and so which networks, the Mac was set up to use. \
        /Library/Preferences/org.cups.printers.plist stores similar information. A .local. \
        name is link-local under Multicast DNS (RFC 6762): it resolves only on the link where it \
        originates, so a job that reached a dnssd://....local. queue shows the printer was on \
        the Mac's local network at that time. The uuid is often a version-1 UUID, whose node \
        field is an IEEE 802 MAC address (RFC 9562), so it can carry the printer's MAC. The same \
        uuid reached while the Mac was on two different Wi-Fi networks ties the printer, and \
        plausibly the premises, to both networks, which links a network that cannot be \
        geolocated to one that can.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "printer_name", value_type: ValueType::Text, description: "Queue name; matches the /printers/<name> part of printer-uri in spool control files", is_uid_component: true },
        FieldSchema { name: "device_uri", value_type: ValueType::Text, description: "DeviceURI: dnssd service name and uuid, or host/address, of the device", is_uid_component: false },
    ],
    retention: Some("Queues persist until removed in Printers & Scanners"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["macos_cups_spool_jobs", "macos_cups_logs", "macos_wifi_driver_log", "macos_wifi_log"],
    sources: &[
        "https://www.cups.org/doc/man-printers.conf.html",
        "https://www.cups.org/doc/man-cups-files.conf.html",
        "https://www.cups.org/doc/network.html",
        "https://www.magnetforensics.com/blog/cups-artifact-support-for-macos/",
        "https://www.rfc-editor.org/rfc/rfc6762#section-3",
        "https://www.rfc-editor.org/rfc/rfc9562#section-5.1",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "CUPS documents the file's format as an implementation detail that can change between releases; parse it defensively",
        "A configured queue shows the printer was added, not that anything was printed on it; use the spool control files and logs for jobs",
        "DeviceURI values can contain credentials (CUPS masks the file to root for that reason); redact before reporting",
        "Only a version-1 uuid (third group starting 1) has a MAC node field, and RFC 9562 allows a randomly derived node instead; check the value against the IEEE OUI registry and any MAC fragment in the service name before reading it as the printer's MAC. A printer with wired and Wi-Fi interfaces may embed only one of their MACs",
        "Co-presence is of the printer, not of a place: a printer can be moved between premises, so the same uuid on two networks links the networks only for the period the printer stayed put",
        "An mDNS reflector or Bonjour gateway (common on enterprise Wi-Fi controllers) extends .local. discovery across subnets, so 'same local network' means the same mDNS domain, not necessarily the same link",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file rewritten when queues change",
};

/// CUPS logs: `/private/var/log/cups/{access_log,error_log,page_log}`.
///
/// # Sources
/// - <https://www.cups.org/doc/man-cups-files.conf.html> — AccessLog, ErrorLog,
///   PageLog defaults /var/log/cups/access_log, error_log, page_log.
/// - <https://www.cups.org/doc/man-cupsd.conf.html> — AccessLogLevel default
///   "actions" (jobs submitted, held, released, modified, cancelled); MaxLogSize
///   default 1 MB before rotation; PageLogFormat.
/// - <https://github.com/apple/cups/blob/v2.3.3/scheduler/conf.c> — compiled
///   PageLogFormat default "%p %u %j %T %P %C %{job-billing}
///   %{job-originating-host-name} %{job-name} %{media} %{sides}".
/// - <https://digitalbitbybit.blogspot.com/2012/11/mac-osx-printer-forensics.html> —
///   the three logs under /private/var/log/cups on macOS.
pub(crate) static MACOS_CUPS_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_cups_logs",
    name: "CUPS Access, Error and Page Logs",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/log/cups/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Text logs written by the CUPS scheduler. access_log records requests, by default at \
        AccessLogLevel actions: print jobs submitted, held, released, modified or cancelled, and \
        printer configuration changes. error_log records scheduler messages at LogLevel (default \
        warn), with far more detail at debug levels. page_log, when enabled, writes one \
        line per page or job in PageLogFormat; the CUPS 2.3 source's default format is printer, \
        user, job id, time, page number, copies, billing, originating host, job name, media and \
        sides. These logs corroborate the spool control files and outlast them once the job \
        history is purged, within the logs' own rotation.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Log time in common log format, local time with offset", is_uid_component: true },
        FieldSchema { name: "printer", value_type: ValueType::Text, description: "Queue name (page_log %p; access_log request path)", is_uid_component: false },
        FieldSchema { name: "user", value_type: ValueType::Text, description: "Submitting user (page_log %u; access_log user field)", is_uid_component: false },
        FieldSchema { name: "job_id", value_type: ValueType::UnsignedInt, description: "Job id linking to the c##### control file", is_uid_component: false },
    ],
    retention: Some("Rotated when a log reaches MaxLogSize (default 1 MB)"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_cups_spool_jobs", "macos_cups_printers_conf"],
    sources: &[
        "https://www.cups.org/doc/man-cups-files.conf.html",
        "https://www.cups.org/doc/man-cupsd.conf.html",
        "https://github.com/apple/cups/blob/v2.3.3/scheduler/conf.c",
        "https://digitalbitbybit.blogspot.com/2012/11/mac-osx-printer-forensics.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "The current cupsd.conf man page says the PageLogFormat default is empty (page logging disabled), while the CUPS 2.3.3 source sets the standard format by default; whether page_log exists depends on the CUPS build and configuration on the image",
        "Rotation at 1 MB by default means only recent activity survives on a heavily used system",
        "Log times are local time with an offset, unlike the Unix-epoch time-at-* values in control files",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Size-based rotation discards older entries",
};

/// Calendar's on-disk event store: `~/Library/Calendars/<UUID>.calendar/`
/// folders, each with `Info.plist` and `Events/*.ics`.
///
/// # Sources
/// - <https://stackoverflow.com/a/71159901> — script that iterates
///   `~/Library/Calendars/*.calendar`, matches the calendar's name as a
///   `<string>` in `<calendar>/Info.plist`, and copies `<calendar>/Events/*`;
///   a 2025 comment reports the store moved to
///   `~/Library/Group Containers/group.com.apple.calendar` on macOS 15.
/// - <https://apple.stackexchange.com/a/162262> — `find ~/Library/Calendars -name "*.ics"`
///   lists the events of all calendars, subscribed ones included.
/// - <https://www.rfc-editor.org/rfc/rfc5545> — iCalendar: UID (3.8.4.7),
///   CREATED (3.8.7.1), DTSTAMP (3.8.7.2), LAST-MODIFIED (3.8.7.3).
pub(crate) static MACOS_CALENDAR_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_calendar_store",
    name: "Calendar Event Store (.calendar folders and per-event .ics)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Calendars/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Per-calendar folders named <UUID>.calendar, each holding an Info.plist that describes the calendar (its title, and for a \
        subscribed calendar its type and subscription URL) and an Events/ folder with one \
        iCalendar .ics file per event. Each .ics is plain text carrying the event's UID, SUMMARY, \
        DTSTART/DTEND and, where set, LOCATION, ORGANIZER and ATTENDEE lines, with the iCalendar CREATED, DTSTAMP and \
        LAST-MODIFIED times, so events can be read without the Calendar Cache SQLite database \
        that sits beside them, and a deleted event's .ics may be recoverable from unallocated \
        space or backups. Subscribed calendars (holidays, sports, shared feeds) appear here too, \
        so the Info.plist type and URL separate calendars the user keeps from feeds they only \
        subscribe to.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "calendar_uuid", value_type: ValueType::Guid, description: "UUID in the <UUID>.calendar folder name", is_uid_component: true },
        FieldSchema { name: "calendar_title", value_type: ValueType::Text, description: "Calendar name from Info.plist", is_uid_component: false },
        FieldSchema { name: "event_uid", value_type: ValueType::Text, description: "iCalendar UID of the event (RFC 5545 3.8.4.7)", is_uid_component: true },
        FieldSchema { name: "summary", value_type: ValueType::Text, description: "Event title (SUMMARY)", is_uid_component: false },
        FieldSchema { name: "dtstart", value_type: ValueType::Timestamp, description: "Event start (DTSTART)", is_uid_component: false },
        FieldSchema { name: "created", value_type: ValueType::Timestamp, description: "CREATED: when the calendar user agent first created the event", is_uid_component: false },
        FieldSchema { name: "last_modified", value_type: ValueType::Timestamp, description: "LAST-MODIFIED: when the event was last revised", is_uid_component: false },
    ],
    retention: Some("Events persist until deleted; synced calendars mirror the server"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["fa_file_calendars_calendar_cache", "macos_calendar_archive_icbu"],
    sources: &[
        "https://stackoverflow.com/a/71159901",
        "https://apple.stackexchange.com/a/162262",
        "https://www.rfc-editor.org/rfc/rfc5545",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "Apple does not document this layout; the .calendar/Info.plist/Events structure comes from user reports, and the UUID folder names, one VEVENT per .ics, and the Info.plist Title/Type (e.g. Subscription)/subscription URL keys were observed on one macOS image from the 10.14-11.7 era",
        "A user report places the store in ~/Library/Group Containers/group.com.apple.calendar (with a Calendar.sqlitedb) on macOS 15; check both locations and the OS version",
        "For iCloud, Exchange or Google calendars these files are a local copy of server data, so an event present here may have been created on another device or by another person",
        "CREATED, DTSTAMP and LAST-MODIFIED are written by whichever client created or changed the event and carry that client's clock",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Event files persist until the event is deleted or the account removed",
};

/// Calendar Archive bundles (`.icbu`) written by File > Export > Calendar Archive.
///
/// # Sources
/// - <https://support.apple.com/guide/calendar/import-or-export-calendars-icl1023/mac> —
///   exporting all calendars writes a calendar archive (.icbu); importing one
///   replaces all current calendar information.
/// - <https://www.macworld.com/article/232324/what-you-get-when-you-export-calendar-and-reminders-in-macos.html> —
///   the .icbu is a package holding all calendars, events and reminders in ICS
///   form, named "Calendars and Reminders" plus the current date and time.
pub(crate) static MACOS_CALENDAR_ARCHIVE_ICBU: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_calendar_archive_icbu",
    name: "Calendar Archive (.icbu) backup bundle",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/**/*.icbu"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Package written when the user chooses File > Export > Calendar Archive: a .icbu \
        bundle containing every calendar, its events and reminders as ICS files, in the same \
        structure as the live store. Its default name is \"Calendars and Reminders\" followed by \
        the export date and time, so the name alone dates a deliberate backup by the user. An \
        archive preserves calendar content as it stood at export, including events since \
        deleted from the live store or the server, and can be imported on another Mac, where \
        it replaces all existing calendar data.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "archive_name", value_type: ValueType::Text, description: "Bundle name; default embeds the export date and time", is_uid_component: true },
        FieldSchema { name: "bundle_created", value_type: ValueType::Timestamp, description: "File-system creation time of the bundle", is_uid_component: false },
    ],
    retention: Some("Persists wherever the user saved it until deleted"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["macos_calendar_store", "fa_file_calendars_calendar_cache"],
    sources: &[
        "https://support.apple.com/guide/calendar/import-or-export-calendars-icl1023/mac",
        "https://www.macworld.com/article/232324/what-you-get-when-you-export-calendar-and-reminders-in-macos.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Apple documents the .icbu export and import; the default name with date and time and the inner ICS layout come from Macworld (2019), not Apple",
        "The name is editable in the save dialog, so a date in it is only the default and a renamed archive carries none; use file-system times as well",
        "A .icbu found on this Mac may have been copied from another machine; its contents describe the exporting Mac's calendars",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "User-created backup file; persists until deleted",
};

/// iWork '13-and-later document container (Pages `.pages`, Numbers `.numbers`,
/// Keynote `.key`): a package directory or a single zip file.
///
/// # Sources
/// - <https://github.com/obriensp/iWorkFileFormat/blob/master/Docs/index.md> —
///   bundle layout (Data/, Index.zip of Index/*.iwa, Metadata/
///   BuildVersionHistory.plist + DocumentIdentifier + Properties.plist,
///   preview.jpg / preview-web.jpg / preview-micro.jpg); IWA = Protobuf stream
///   in Snappy framing without the Stream Identifier chunk or CRC-32C;
///   password-locked documents AES-128 (PKCS7) encrypted.
/// - <https://github.com/masaccio/numbers-parser/blob/main/src/numbers_parser/iwork.py> —
///   opens both the package form (Index.zip) and the single-file zip form
///   (Index/*.iwa at the top level); reads fileFormatVersion from
///   Metadata/Properties.plist.
/// - <https://github.com/masaccio/numbers-parser/issues/89> — "Pre-BNC storage
///   is unsupported" raised for tables not last saved in BNC storage; maintainer:
///   not planned.
/// - <https://github.com/Cocoanetics/SwiftText/blob/main/Sources/SwiftTextPages/PagesImageCatalog.swift> —
///   treats Data/ files named PresetImageFill* and *bullet* as theme/template
///   decorations rather than document content.
pub(crate) static IWORK_DOCUMENT_PACKAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "iwork_document_package",
    name: "iWork Document Package (Pages / Numbers / Keynote, iWork '13+)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("<any iWork '13+ document: .pages, .numbers, .key (package directory or zip)>"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Container format of Pages, Numbers and Keynote since iWork '13, saved either as a \
        package directory or as a single zip file. The document's objects are stored as .iwa \
        (iWork Archive) files under Index/ (inside an uncompressed Index.zip in the package \
        form): each is a Protobuf stream wrapped in Snappy framing that omits the Stream \
        Identifier chunk and the CRC-32C checksums, so a strict Snappy framing decoder will not \
        accept it and the chunks must be read directly. Data/ holds media inserted into the document (images and \
        video), alongside theme and template media such as PresetImageFill*.jpg fills and \
        bullet images that ship with the template and are not user content. preview.jpg, \
        preview-web.jpg and preview-micro.jpg at the top level are ordinary JPEG renders of the \
        document, viewable when the .iwa objects cannot be parsed. Metadata/ holds \
        Properties.plist (including fileFormatVersion), DocumentIdentifier (the document's \
        identifier) and BuildVersionHistory.plist, the list of application builds that have \
        saved the document, which dates a document's editing history to app versions and shows \
        whether it was last saved by an older or newer iWork release than the one on this Mac.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "document_identifier", value_type: ValueType::Text, description: "Contents of Metadata/DocumentIdentifier", is_uid_component: true },
        FieldSchema { name: "file_format_version", value_type: ValueType::Text, description: "fileFormatVersion from Metadata/Properties.plist", is_uid_component: false },
        FieldSchema { name: "build_version_history", value_type: ValueType::List, description: "Application build strings from Metadata/BuildVersionHistory.plist", is_uid_component: false },
        FieldSchema { name: "data_media", value_type: ValueType::List, description: "Files under Data/, excluding template decorations (PresetImageFill*, bullets)", is_uid_component: false },
    ],
    retention: Some("Part of the document; persists as long as the file does"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        "https://github.com/obriensp/iWorkFileFormat/blob/master/Docs/index.md",
        "https://github.com/masaccio/numbers-parser/blob/main/src/numbers_parser/iwork.py",
        "https://github.com/masaccio/numbers-parser/issues/89",
        "https://github.com/Cocoanetics/SwiftText/blob/main/Sources/SwiftTextPages/PagesImageCatalog.swift",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Apple publishes no specification; the layout comes from reverse engineering (obriensp) and independent parsers (numbers-parser, SwiftText) that agree on it",
        "numbers-parser raises \"Pre-BNC storage is unsupported\" for Numbers tables not last saved in the newer BNC storage, which older iWork '13-era files can hit; the maintainer does not plan support, so fall back to the preview JPEGs and a raw IWA decode",
        "A password-locked document has nearly all files in the bundle AES-128 encrypted (PKCS7 padding); without the password only the unencrypted parts can be examined, and whether the previews survive encryption should be checked on the file",
        "The Metadata/BuildVersionHistory.plist reading as a list of saving app builds, and the previews as a render of the first page or slide, are observed behaviour rather than documented",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Stored inside the document itself",
};

/// OOXML (Word/Excel/PowerPoint 2007+) document properties:
/// `docProps/core.xml` (core properties) and `docProps/app.xml` (extended
/// properties) inside the document zip.
///
/// # Sources
/// - <https://ecma-international.org/publications-and-standards/standards/ecma-376/> —
///   ECMA-376; Part 2 (Open Packaging Conventions) defines the core properties.
/// - <https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.packageproperties> —
///   core-property semantics: Creator, LastModifiedBy, Revision, LastPrinted,
///   Created, Modified.
/// - <https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.extendedproperties.company> —
///   ap:Company, "the name of a company associated with the document"
///   (ISO/IEC 29500-1 §22.2); sibling Application and AppVersion elements.
/// - <https://exiftool.org/TagNames/OOXML.html> — properties read from the
///   "docProps" directory, incl. LastModifiedBy, LastPrinted, Company, AppVersion.
/// - <https://support.microsoft.com/en-us/word/change-the-author-name-for-documents-presentations-or-workbooks> —
///   Word, Excel and PowerPoint set Author on new documents from the User name
///   setting; editable per document.
pub(crate) static OOXML_CORE_PROPERTIES: ArtifactDescriptor = ArtifactDescriptor {
    id: "ooxml_core_properties",
    name: "OOXML Document Properties (docProps/core.xml, docProps/app.xml)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("<any OOXML document: .docx, .xlsx, .pptx and macro/template variants>"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Authorship metadata stored inside an Office Open XML package, which is a zip. \
        docProps/core.xml holds the ECMA-376 core properties: dc:creator (who created the \
        content), cp:lastModifiedBy (who last modified it), cp:revision (revision number), \
        cp:lastPrinted, dcterms:created and dcterms:modified, plus title, subject and keywords. \
        docProps/app.xml holds extended properties, among them Application (the producing \
        application), AppVersion and Company. These values travel with the file through \
        copying, email and download, so they record where and by whom, in the application's \
        terms, a document was written and saved, independently of the file-system times on \
        the machine where it is found. Comparing dcterms:created and dcterms:modified with file-system dates, and \
        creator with lastModifiedBy, shows whether a document was authored here or arrived \
        from elsewhere.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "creator", value_type: ValueType::Text, description: "dc:creator: author name as set by the creating application", is_uid_component: false },
        FieldSchema { name: "last_modified_by", value_type: ValueType::Text, description: "cp:lastModifiedBy: user name of the application that last saved", is_uid_component: false },
        FieldSchema { name: "revision", value_type: ValueType::Text, description: "cp:revision: revision number", is_uid_component: false },
        FieldSchema { name: "created", value_type: ValueType::Timestamp, description: "dcterms:created (W3CDTF)", is_uid_component: false },
        FieldSchema { name: "modified", value_type: ValueType::Timestamp, description: "dcterms:modified (W3CDTF)", is_uid_component: false },
        FieldSchema { name: "last_printed", value_type: ValueType::Timestamp, description: "cp:lastPrinted", is_uid_component: false },
        FieldSchema { name: "application", value_type: ValueType::Text, description: "app.xml Application", is_uid_component: false },
        FieldSchema { name: "app_version", value_type: ValueType::Text, description: "app.xml AppVersion", is_uid_component: false },
        FieldSchema { name: "company", value_type: ValueType::Text, description: "app.xml Company", is_uid_component: false },
    ],
    retention: Some("Part of the document; persists as long as the file does"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["ole2_summary_information"],
    sources: &[
        "https://ecma-international.org/publications-and-standards/standards/ecma-376/",
        "https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.packageproperties",
        "https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.extendedproperties.company",
        "https://exiftool.org/TagNames/OOXML.html",
        "https://support.microsoft.com/en-us/word/change-the-author-name-for-documents-presentations-or-workbooks",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Circumstantial),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "creator and lastModifiedBy are the user-name setting of the application that wrote them, not the person at the keyboard; Microsoft documents that Office sets Author from its User name setting and that the value can be edited per document",
        "A document downloaded or copied to the machine under examination carries the metadata of the machine that authored it elsewhere; its presence says nothing about authorship on the machine where it is found",
        "The docProps/ part names are the convention Office writes; the package relationships (_rels/.rels) are authoritative for where the core and extended properties live",
        "Times are written by the saving application from its own clock and can be edited or stripped without trace",
        "The format is platform-independent and applies equally to documents found on Windows, removable media or any other system; it is catalogued under macOS only because the catalogue's OsScope has no cross-platform value",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Stored inside the document itself",
};

/// OLE2 (Word/Excel/PowerPoint 97-2003) SummaryInformation property set in the
/// `\005SummaryInformation` stream.
///
/// # Sources
/// - <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/11b56127-35f4-4bfa-a23f-23935a6edf54> —
///   MS-OSHARED 2.3.3.2.1: FMTID_SummaryInformation, stream "\005SummaryInformation".
/// - <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/87667163-ea1e-4d67-9eec-47cad74e8030> —
///   PIDSI: AUTHOR 0x04, LASTAUTHOR 0x08, REVNUMBER 0x09, LASTPRINTED 0x0B,
///   CREATE_DTM 0x0C, LASTSAVE_DTM 0x0D (VT_FILETIME, UTC); CODEPAGE must be written.
/// - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/f7933d28-2cc4-4b36-bc23-8861cbcd37c4> —
///   MS-OLEPS SummaryInformation property table.
/// - <https://exiftool.org/TagNames/FlashPix.html> — the same properties read
///   from DOC/XLS/PPT (Author, LastModifiedBy, RevisionNumber, LastPrinted,
///   CreateDate, ModifyDate, CodePage).
/// - <https://support.microsoft.com/en-us/word/change-the-author-name-for-documents-presentations-or-workbooks> —
///   Author comes from the Office User name setting.
pub(crate) static OLE2_SUMMARY_INFORMATION: ArtifactDescriptor = ArtifactDescriptor {
    id: "ole2_summary_information",
    name: "OLE2 SummaryInformation Property Set (legacy .doc/.xls/.ppt)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("<any OLE2 compound file: .doc, .xls, .ppt and their template variants>"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Authorship metadata inside a Compound File Binary (OLE2) document, stored as the \
        SummaryInformation property set (FMTID {F29F85E0-4FF9-1068-AB91-08002B27B3D9}) in the \
        stream named \\005SummaryInformation. MS-OSHARED defines PIDSI_AUTHOR (0x04, document \
        author), PIDSI_LASTAUTHOR (0x08, who last modified it), PIDSI_REVNUMBER (0x09, revision \
        number), PIDSI_LASTPRINTED (0x0B), PIDSI_CREATE_DTM (0x0C, created) and \
        PIDSI_LASTSAVE_DTM (0x0D, last saved), the three times being FILETIME values in UTC. \
        The CODEPAGE property must be present and gives the code page of every 8-bit string in \
        the set, so author names written on a non-Latin system decode correctly only with it. \
        Like its OOXML successor, the set travels with the file and records the writing \
        application's view of who created and last saved the document and when.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "author", value_type: ValueType::Text, description: "PIDSI_AUTHOR (0x04)", is_uid_component: false },
        FieldSchema { name: "last_author", value_type: ValueType::Text, description: "PIDSI_LASTAUTHOR (0x08): last saved by", is_uid_component: false },
        FieldSchema { name: "revision_number", value_type: ValueType::Text, description: "PIDSI_REVNUMBER (0x09), a decimal string", is_uid_component: false },
        FieldSchema { name: "last_printed", value_type: ValueType::Timestamp, description: "PIDSI_LASTPRINTED (0x0B), FILETIME UTC", is_uid_component: false },
        FieldSchema { name: "create_dtm", value_type: ValueType::Timestamp, description: "PIDSI_CREATE_DTM (0x0C), FILETIME UTC", is_uid_component: false },
        FieldSchema { name: "lastsave_dtm", value_type: ValueType::Timestamp, description: "PIDSI_LASTSAVE_DTM (0x0D), FILETIME UTC", is_uid_component: false },
        FieldSchema { name: "codepage", value_type: ValueType::UnsignedInt, description: "CODEPAGE property (id 0x01): code page of the set's 8-bit strings", is_uid_component: false },
    ],
    retention: Some("Part of the document; persists as long as the file does"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["ooxml_core_properties"],
    sources: &[
        "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/11b56127-35f4-4bfa-a23f-23935a6edf54",
        "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/87667163-ea1e-4d67-9eec-47cad74e8030",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/f7933d28-2cc4-4b36-bc23-8861cbcd37c4",
        "https://exiftool.org/TagNames/FlashPix.html",
        "https://support.microsoft.com/en-us/word/change-the-author-name-for-documents-presentations-or-workbooks",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Circumstantial),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "PIDSI_AUTHOR and PIDSI_LASTAUTHOR are the user-name setting of the application that wrote them, not the person at the keyboard; the value can be edited per document",
        "A document downloaded or copied to the machine under examination carries the metadata of the machine that authored it elsewhere; its presence says nothing about authorship on the machine where it is found",
        "All properties are optional and writable by any tool; absent or blank values are not evidence of tampering by themselves",
        "Decode 8-bit strings with the set's CODEPAGE, not the examiner's locale, or names in non-Latin scripts are mis-rendered",
        "The format is platform-independent and applies equally to documents found on Windows, removable media or any other system; it is catalogued under macOS only because the catalogue's OsScope has no cross-platform value",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Stored inside the document itself",
};

/// iCloud Drive app-container list: per-container entries in
/// `~/Library/Application Support/CloudDocs/session/containers/`.
///
/// # Sources
/// - <https://developer.apple.com/documentation/xcode/configuring-icloud-services> —
///   iCloud container names must begin with `iCloud.` followed by a unique
///   reverse-DNS string.
/// - <https://www.mac4n6.com/blog/2018/11/25/do-it-live-dynamic-ios-forensic-testing> —
///   iOS: `.../CloudDocs/session/containers/57T9237FN3.net.whatsapp.WhatsApp` as an
///   iCloud artefact of the WhatsApp app (team-ID-prefixed container name).
/// - <https://forum.affinity.serif.com/index.php?/topic/195584-confusing-use-of-affinity-icloud-folders/> —
///   macOS: `iCloud.com.seriflabs.affinitypublisher.plist` in
///   `~/Library/Application Support/CloudDocs/session/containers/`, and the
///   matching `~/Library/Mobile Documents/iCloud~com~seriflabs~...` folders,
///   including ones for app versions no longer installed.
pub(crate) static MACOS_ICLOUD_DRIVE_CONTAINERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_icloud_drive_containers",
    name: "iCloud Drive App Container List (CloudDocs session)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Application Support/CloudDocs/session/containers/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The iCloud Drive daemon's per-container records for the signed-in account: one entry \
        (a folder and/or a <container>.plist) per iCloud Drive app container, named by the \
        container identifier, which is iCloud.<reverse-DNS bundle id> or, for some apps, \
        <Team ID>.<bundle id>. Containers belong to the iCloud account, not to \
        this Mac, so the list can name apps that store documents in the user's iCloud from \
        another device (an iPhone messaging app, for example) and apps since removed, which \
        points at devices and apps to look for elsewhere. The documents themselves sync to \
        ~/Library/Mobile Documents/<container with ~ for .>/; client.db in the sibling db/ folder \
        records item-level sync state.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "container_id", value_type: ValueType::Text, description: "Container identifier from the entry name (iCloud.<bundle id> or <Team ID>.<bundle id>)", is_uid_component: true },
        FieldSchema { name: "entry_mtime", value_type: ValueType::Timestamp, description: "File-system modification time of the container entry", is_uid_component: false },
    ],
    retention: Some("Undocumented; a user report shows entries lingering for app versions no longer installed"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["macos_icloud_drive_db"],
    sources: &[
        "https://developer.apple.com/documentation/xcode/configuring-icloud-services",
        "https://www.mac4n6.com/blog/2018/11/25/do-it-live-dynamic-ios-forensic-testing",
        "https://forum.affinity.serif.com/index.php?/topic/195584-confusing-use-of-affinity-icloud-folders/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Circumstantial),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "Apple does not document this folder; its macOS contents come from one user forum report and an iOS path from mac4n6, and the entries for apps not installed on the Mac (including a messaging app) were observed on one macOS 10.14-11.7-era image",
        "An entry shows the account has, or had, an iCloud Drive container for that app; it does not show the app was installed or used on this Mac, or when",
        "The plist keys inside each entry are undocumented; parse defensively and report them as observed",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Account session state; not rewritten by ordinary use",
};

// ── OpenBSM audit trail ──────────────────────────────────────────────────
//
// Curated for the examination-profile account-use gap: the artifact used to
// establish account creation, login/logout and boot history on a Mac.

pub(crate) static MACOS_OPENBSM_AUDIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_openbsm_audit",
    name: "OpenBSM Audit Trail (/var/audit)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/audit/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "OpenBSM (Basic Security Module) audit trail — macOS's kernel-level security \
        event log, the McAfee-authored OpenBSM implementation Apple ships. Trail files sit in \
        /private/var/audit named StartTime.EndTime in UTC (YYYYMMDDHHMMSS.YYYYMMDDHHMMSS); the \
        `current` symlink points at the active trail, and a still-open trail on an unclean \
        shutdown is renamed with a .crash_recovery suffix. Records are BSM token streams read \
        with praudit(1) (and reduced with auditreduce(1)); which events are captured is set by \
        the audit classes in /etc/security/audit_control. It records user login and logout \
        (login_logout class, including SSH, credential authentication and failed logins), \
        creation and removal of user accounts and other administrative actions (administrative \
        class), process exec, file and network events, and audit-subsystem start at boot — which \
        is why it is the artifact used to establish account creation and boot/login history on a \
        Mac. Deprecated since macOS Big Sur (11), disabled by default in Sonoma (14), and slated \
        for removal, so it may be absent or empty on newer systems; Apple's replacement is the \
        Endpoint Security framework.",
    mitre_techniques: &["T1136.001", "T1078.003", "T1070"],
    fields: &[
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Timestamp of the audited event (from the header token)", is_uid_component: true },
        FieldSchema { name: "event_type", value_type: ValueType::Text, description: "Audit event type (AUE_* event, e.g. AUE_lw_login, AUE_audit_startup)", is_uid_component: true },
        FieldSchema { name: "event_class", value_type: ValueType::Text, description: "Audit class the event belongs to (lo=login_logout, ad=administrative, pc=process, ...)", is_uid_component: false },
        FieldSchema { name: "auid", value_type: ValueType::UnsignedInt, description: "Audit user ID — the login identity, preserved across setuid, from the subject token", is_uid_component: false },
        FieldSchema { name: "uid", value_type: ValueType::UnsignedInt, description: "Effective user ID of the subject", is_uid_component: false },
        FieldSchema { name: "return_status", value_type: ValueType::Text, description: "Return token: success or failure of the operation", is_uid_component: false },
        FieldSchema { name: "subject", value_type: ValueType::Text, description: "Subject token: acting process, terminal and session", is_uid_component: false },
        FieldSchema { name: "text", value_type: ValueType::Text, description: "Text token: event-specific free text (e.g. the account name for a login)", is_uid_component: false },
    ],
    retention: Some("Finite: trails are rotated by auditd when the file fills or free space drops below audit_control minfree; only the retained trail files survive"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "macos_dslocal_users"],
    sources: &[
        "https://crucialsecurity.wordpress.com/2012/05/17/reading-mac-bsm-audit-logs-2/",
        "https://github.com/openbsm/openbsm",
        "https://leancrew.com/all-this/man/man4/audit.html",
        "https://theevilbit.github.io/beyond/beyond_0031/",
        "https://boberito.medium.com/auditd-the-logs-we-need-not-the-logs-we-deserve-cf1d8c83d15d",
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Deprecated since macOS Big Sur and disabled by default in Sonoma 14 — absent or empty on many modern systems, so absence is not proof of no login or account creation",
        "What is captured depends on the audit_control flags; an event class not selected leaves no record",
        "Trails are rotated and can be deleted or cleared, so the trail on the image is not necessarily the full history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Audit trails are rotated by auditd as they fill or as free space drops",
};

// ── dslocal local-account store ──────────────────────────────────────────
//
// Curated for the examination-profile account-use gap: the authoritative
// inventory of local user accounts on a Mac.

pub(crate) static MACOS_DSLOCAL_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_dslocal_users",
    name: "dslocal Local User Accounts",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/db/dslocal/nodes/Default/users/*.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Open Directory local (\"Default\") node account store: one binary plist per local \
        account under /private/var/db/dslocal/nodes/Default/users/, the authoritative inventory of \
        local users on the Mac (dscl and Directory Utility read the same records live). Each plist \
        holds the short name, uid, primary gid, realname (full name / GECOS), home directory, login \
        shell, and generateduid — the account's GUID that ties it to ACLs, keychains and group \
        membership across the system — plus the ShadowHashData blob holding the password hash \
        (SALTED-SHA512-PBKDF2). There is no explicit account-creation timestamp field: creation is \
        inferred from the plist's file-system birth/modification time or corroborated with the \
        OpenBSM audit trail. Establishes which accounts exist, admin vs standard, and their identity \
        attributes.",
    mitre_techniques: &["T1087.001", "T1136.001"],
    fields: &[
        FieldSchema { name: "name", value_type: ValueType::Text, description: "Account short name (record name)", is_uid_component: true },
        FieldSchema { name: "uid", value_type: ValueType::UnsignedInt, description: "Numeric user ID", is_uid_component: true },
        FieldSchema { name: "gid", value_type: ValueType::UnsignedInt, description: "Primary group ID", is_uid_component: false },
        FieldSchema { name: "realname", value_type: ValueType::Text, description: "Full name / GECOS", is_uid_component: false },
        FieldSchema { name: "home", value_type: ValueType::Text, description: "Home directory path", is_uid_component: false },
        FieldSchema { name: "shell", value_type: ValueType::Text, description: "Login shell", is_uid_component: false },
        FieldSchema { name: "generateduid", value_type: ValueType::Guid, description: "Account GUID (generateduid) used across ACLs, groups and keychains", is_uid_component: false },
        FieldSchema { name: "shadowhash_present", value_type: ValueType::Bool, description: "Whether a ShadowHashData password hash is stored for the account", is_uid_component: false },
    ],
    retention: Some("Persists for the life of the account; removed when the account is deleted"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_openbsm_audit", "macos_keychain_user"],
    sources: &[
        "https://hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-sensitive-locations.html",
        "https://medium.com/@piyushkkr12/task-5account-activity-e30497e89266",
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "No stored account-creation timestamp — creation time is inferred from the plist file's birth/modification time, which mounting or imaging tools can perturb",
        "A UID freed by a deleted account can be reused, so uid alone is not a durable identity — prefer generateduid",
        "ShadowHashData is a password hash, not an activity record; it says nothing about when the account was last used",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Account records change only when accounts are created, edited or deleted",
};

// ── AirDrop / sharingd activity ──────────────────────────────────────────
//
// Curated for the examination-profile gap. The unified log holds the
// transfer detail; the persistent per-file record of a RECEIVED AirDrop is
// the row sharingd leaves in QuarantineEventsV2 (macos_quarantine_events).
// Source: https://kieczkowska.wordpress.com/2020/06/29/airdrop-forensics-2/
// — LSQuarantineAgentName is sharingd for an AirDropped file and
// LSQuarantineSenderName names the sending device; persistent rows of that
// shape observed on one macOS Big Sur 11.7 image.

pub(crate) static MACOS_AIRDROP_SHARINGD: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_airdrop_sharingd",
    name: "AirDrop / sharingd Activity (Unified Log)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/db/diagnostics/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "AirDrop transfer detail on macOS is in the unified log (/var/db/diagnostics/), \
        attributed to the `sharingd` process, alongside the wirelessproxd, bluetoothd and AWDL (Apple Wireless Direct \
        Link) activity AirDrop rides on. The log records peer discovery, connections to a named \
        peer device / AirDrop ID, and file send/receive; query it with `log show --info --predicate \
        'process == \"sharingd\"'` (the --info/--debug levels are usually needed on macOS). The \
        per-user ~/Library/Preferences/com.apple.sharingd.plist holds the current AirDrop ID and \
        sharing configuration, but the AirDrop ID rotates and can be blank after inactivity, so it \
        is state, not history. A received file also leaves a persistent record that outlasts \
        log rotation: a row in the per-user QuarantineEventsV2 database \
        (~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2, table \
        LSQuarantineEvent) with LSQuarantineAgentName = 'sharingd' and LSQuarantineSenderName \
        naming the sending device (macos_quarantine_events), and the com.apple.quarantine and \
        kMDItemWhereFroms extended attributes on the saved file.",
    mitre_techniques: &["T1011"],
    fields: &[
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Unified-log timestamp of the sharingd event", is_uid_component: true },
        FieldSchema { name: "process", value_type: ValueType::Text, description: "Emitting process (sharingd)", is_uid_component: false },
        FieldSchema { name: "airdrop_id", value_type: ValueType::Text, description: "AirDrop ID of the local or peer device (rotates over time)", is_uid_component: false },
        FieldSchema { name: "peer_device_name", value_type: ValueType::Text, description: "Advertised name of the peer device in the transfer", is_uid_component: false },
        FieldSchema { name: "event_message", value_type: ValueType::Text, description: "Full unified-log event message", is_uid_component: false },
    ],
    retention: Some("Unified-log rotation window (typically days to a few weeks) for the transfer detail; QuarantineEventsV2 rows for received files persist until cleared; the sharingd.plist keeps configuration, not transfer history"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "macos_quarantine_events", "macos_quarantine_xattr", "macos_wherefroms_xattr"],
    sources: &[
        "https://www.mac4n6.com/blog/2018/12/3/airdrop-analysis-of-the-udp-unsolicited-dick-pic",
        "http://www.mac4n6.com/blog/2020/6/5/analysis-of-apple-unified-logs-quarantine-edition-entry-11-airdropping-some-knowledge",
        "https://www.jamf.com/blog/stop-potential-airdrop-transfer-data-leaks-with-jamf-protect/",
        "https://kieczkowska.wordpress.com/2020/06/29/airdrop-forensics-2/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The unified-log detail ages out on rotation; for received files check QuarantineEventsV2 (sharingd rows with LSQuarantineSenderName), which persists. Quarantine marks incoming files, so a file SENT from this Mac appears only in the unified log; absence in either store never proves a transfer did not happen",
        "The --info/--debug log levels needed for detail are not always retained",
        "The AirDrop ID rotates and can be blank; the com.apple.sharingd.plist path given is macOS per-user (iOS uses /private/var/mobile/Library/Preferences/)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Backed by the unified log, which rotates on a rolling window",
};

// ── USB mass-storage device history ──────────────────────────────────────
//
// Curated for the examination-profile gap: the honest macOS removable-media
// story — there is no USBSTOR-equivalent persistent registry.

pub(crate) static MACOS_USB_MASS_STORAGE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_usb_mass_storage_log",
    name: "USB Mass-Storage Device History (Unified Log)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/db/diagnostics/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "macOS has no USBSTOR-equivalent persistent registry of attached removable devices, so \
        per-device attach history is far weaker and shorter-lived than on Windows. The strongest \
        per-device record is the unified log (/var/db/diagnostics/): when a USB Mass Storage Class \
        device is inserted, entries containing the keyword `USBMSC` record a non-unique identifier \
        (usually, but not guaranteed to be, the device serial number), the vendor ID, product ID and \
        version — query with `log show --predicate \"eventMessage contains 'USBMSC'\"`. Because this \
        lives in the unified log it only covers the log's rotation window. Complementary evidence of \
        removable/external volume use: fseventsd mount and write records under /Volumes \
        (macos_fsevents), and recently connected network shares (macos_sfl2_recent_servers).",
    mitre_techniques: &["T1052.001", "T1091"],
    fields: &[
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Unified-log timestamp of the USBMSC attach event", is_uid_component: true },
        FieldSchema { name: "serial_number", value_type: ValueType::Text, description: "Device non-unique identifier — usually the serial number (Apple notes it may not be unique)", is_uid_component: false },
        FieldSchema { name: "vendor_id", value_type: ValueType::Text, description: "USB vendor ID", is_uid_component: false },
        FieldSchema { name: "product_id", value_type: ValueType::Text, description: "USB product ID", is_uid_component: false },
        FieldSchema { name: "version", value_type: ValueType::Text, description: "Device version reported in the USBMSC entry", is_uid_component: false },
    ],
    retention: Some("Unified-log rotation window only (typically days to a few weeks)"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_fsevents", "macos_unified_log", "macos_sfl2_recent_servers"],
    sources: &[
        "http://www.mac4n6.com/blog/2020/5/4/analysis-of-apple-unified-logs-quarantine-edition-entry-7-exploring-usbmsc-devices-with-style",
        "https://kieczkowska.wordpress.com/2020/05/11/usb-forensics/",
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "No persistent USBSTOR-equivalent registry on macOS — absence in the log is not proof a device was never attached, and history is limited to the unified-log rotation window",
        "The USBMSC identifier is explicitly non-unique per Apple; do not treat it as a guaranteed serial",
        "MTP/PTP devices (phones, cameras) do not present as USB Mass Storage and will not appear under USBMSC",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Backed by the unified log, which rotates on a rolling window",
};

// ── Safari cookies (macOS) ───────────────────────────────────────────────
//
// Curated to supersede the auto-generated `browsers_safari_cookies`, which is
// mis-scoped OsScope::Win7Plus in the generated catalog (fa/browsers). Safari
// is macOS/iOS; the generated file must not be hand-edited, so the correction
// lives here and the profile references this id.

pub(crate) static MACOS_SAFARI_COOKIES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_cookies",
    name: "Safari Cookies (macOS)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Safari's cookie jar in the proprietary Cookies.binarycookies binary format: per-site \
        cookies with name, value, domain, path and creation/expiry timestamps, and may include live \
        session tokens. Since Safari was sandboxed (Safari 13, macOS Catalina) the file lives inside \
        the app container at ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/; on Safari \
        12 and earlier it was at the legacy ~/Library/Cookies/Cookies.binarycookies. This curated \
        descriptor supersedes the auto-generated `browsers_safari_cookies`, which is mis-scoped \
        OsScope::Win7Plus in the generated catalog — Safari cookies are macOS/iOS, never Windows. On \
        iOS the equivalent lives in the MobileSafari/WebKit container.",
    mitre_techniques: &["T1539"],
    fields: &[
        FieldSchema { name: "domain", value_type: ValueType::Text, description: "Cookie domain / host", is_uid_component: true },
        FieldSchema { name: "name", value_type: ValueType::Text, description: "Cookie name", is_uid_component: true },
        FieldSchema { name: "value", value_type: ValueType::Text, description: "Cookie value (may be a session token)", is_uid_component: false },
        FieldSchema { name: "path", value_type: ValueType::Text, description: "Cookie path scope", is_uid_component: false },
        FieldSchema { name: "creation_time", value_type: ValueType::Timestamp, description: "Cookie creation time", is_uid_component: false },
        FieldSchema { name: "expiry_time", value_type: ValueType::Timestamp, description: "Cookie expiry time", is_uid_component: false },
    ],
    retention: Some("Until cookie expiry or user/site clearing"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_safari_history", "macos_safari_localstorage"],
    sources: &[
        "https://www.foxtonforensics.com/browser-history-examiner/safari-history-location",
        "https://lapcatsoftware.com/articles/containers.html",
        "https://github.com/mdegrazia/Safari-Binary-Cookie-Parser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Path moved into the sandbox container with Safari 13 / macOS Catalina; on Safari 12 and earlier it is at the legacy ~/Library/Cookies/Cookies.binarycookies",
        "Cookies.binarycookies is a proprietary, undocumented binary format — parse defensively",
        "The generated browsers_safari_cookies descriptor for the same file is mis-scoped OsScope::Win7Plus; this descriptor is the macOS-correct one",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rewritten as the user browses and as cookies are set, updated and expired",
};

// ── HEIC image (macOS) ───────────────────────────────────────────────────
//
// Curated companion to `heic_image_file` (OsScope::IOS). OsScope is a single
// value per descriptor and the HEIC container bytes are identical on iOS and
// macOS, so rather than drop iOS from the format descriptor, this adds the
// macOS-applicable image with the macOS paths and cross-references the format.

pub(crate) static MACOS_HEIC_IMAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_heic_image",
    name: "HEIC Image (macOS Photos / saved)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Pictures/*.photoslibrary/originals/**/*.heic"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "HEIF/HEIC images on macOS. macOS High Sierra (10.13) and later can view, edit and \
        store HEIC — the same ISO Base Media File Format container Apple captures on iPhones (see \
        heic_image_file for the ftyp/meta/iloc box structure and EXIF/GPS extraction; the bytes are \
        identical). On a Mac these land chiefly in the Photos library originals folder \
        (~/Pictures/<library>.photoslibrary/originals/) — imported from an iOS device via iCloud \
        Photos or Continuity Camera, or captured — and anywhere the user saves or exports HEIC. \
        macOS screenshots are PNG by default, not HEIC. Embedded EXIF including GPS, camera model \
        and original capture time is preserved and extractable (ExifTool; sips or ffmpeg to \
        transcode to JPEG for legacy tools).",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "major_brand", value_type: ValueType::Text, description: "ftyp box major brand (typically 'heic')", is_uid_component: false },
        FieldSchema { name: "handler_type", value_type: ValueType::Text, description: "hdlr box handler type ('pict' for still image)", is_uid_component: false },
        FieldSchema { name: "exif_gps_latitude", value_type: ValueType::Text, description: "GPS latitude from embedded EXIF, when present", is_uid_component: false },
        FieldSchema { name: "exif_gps_longitude", value_type: ValueType::Text, description: "GPS longitude from embedded EXIF, when present", is_uid_component: false },
        FieldSchema { name: "exif_datetime_original", value_type: ValueType::Timestamp, description: "Original capture time from EXIF DateTimeOriginal", is_uid_component: false },
        FieldSchema { name: "exif_camera_model", value_type: ValueType::Text, description: "Camera model from EXIF Model tag", is_uid_component: false },
    ],
    retention: Some("Persistent until user deletion; syncs via iCloud Photos"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["heic_image_file", "macos_photos_db", "macos_photos_derivatives"],
    sources: &[
        "https://support.apple.com/en-us/HT207022",
        "https://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html",
        "https://eshop.macsales.com/blog/45124-quick-tip-how-to-access-master-image-files-in-macos-photos-app/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "HEIC on a Mac is predominantly synced or imported from iOS rather than natively captured, so presence is not proof of capture on this device",
        "EXIF (including GPS) can be stripped on export or by messaging apps",
        "The container bytes are identical to iOS HEIC (heic_image_file); some legacy forensic tools do not parse HEIC",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Image file persists on storage until explicit deletion",
};

// ── Network configuration: interfaces, services, known Wi-Fi ──────────────
//
// Curated for the examination-profile Connections layer: which physical
// interfaces the Mac has and their MACs (NetworkInterfaces.plist), how the
// uplink is configured and which service is primary (preferences.plist), and
// the remembered Wi-Fi networks whose access-point BSSIDs are the geolocation
// handle (com.apple.wifi.known-networks.plist, Big Sur+). The DHCP lease store
// (MACOS_DHCP_LEASES) and the legacy airport preferences (MACOS_WIFI_PLIST)
// already exist; these complete the layer.

pub(crate) static MACOS_NETWORK_INTERFACES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_network_interfaces",
    name: "Network Interfaces (NetworkInterfaces.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SystemConfiguration store mapping each BSD interface name (enN, and bridge/utun \
        interfaces) to the underlying hardware. Per interface it records the IOMACAddress (the \
        interface's own hardware MAC, as a data blob), the SCNetworkInterfaceType (IEEE80211 for \
        Wi-Fi, Ethernet, Bluetooth PAN, Thunderbolt/bridge), the SCNetworkInterfaceInfo \
        UserDefinedName (\"Wi-Fi\", \"Ethernet\", ...), the Active flag, and the IOPathMatch \
        hardware path. Establishes which physical interfaces the Mac has and their MAC addresses \
        — the anchor for tying a captured MAC or a DHCP/router record to a specific interface. \
        The enN-to-hardware mapping is per-machine and must be read from SCNetworkInterfaceType / \
        IOMACAddress rather than assumed: en0 is the built-in Ethernet on Intel Macs but is often \
        Wi-Fi (IEEE80211) on Apple Silicon, where the wired port is a Thunderbolt/USB adapter.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "bsd_name", value_type: ValueType::Text, description: "BSD interface name (en0, en1, ...)", is_uid_component: true },
        FieldSchema { name: "interface_type", value_type: ValueType::Text, description: "SCNetworkInterfaceType (IEEE80211=Wi-Fi, Ethernet, Bluetooth PAN, ...)", is_uid_component: false },
        FieldSchema { name: "mac_address", value_type: ValueType::Text, description: "IOMACAddress — the interface's own hardware MAC", is_uid_component: false },
        FieldSchema { name: "user_defined_name", value_type: ValueType::Text, description: "SCNetworkInterfaceInfo UserDefinedName (\"Wi-Fi\", \"Ethernet\")", is_uid_component: false },
        FieldSchema { name: "active", value_type: ValueType::Bool, description: "Whether the interface is marked Active", is_uid_component: false },
    ],
    retention: Some("Persists until the interface set is reconfigured; historical interfaces linger"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_network_preferences", "macos_dhcp_leases", "macos_wifi_known_networks"],
    sources: &[
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/networking.py",
        "https://medium.com/@piyushkkr12/task-5account-activity-e30497e89266",
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The enN-to-hardware mapping is not fixed across models — read SCNetworkInterfaceType/IOMACAddress, never assume en0=Ethernet",
        "IOMACAddress is the interface hardware MAC; it is not the randomized per-network client MAC used for Wi-Fi association",
        "Retired interfaces can remain listed, so presence is not proof the interface is currently installed",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Rewritten only when network interfaces are added, removed or reconfigured",
};

pub(crate) static MACOS_NETWORK_PREFERENCES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_network_preferences",
    name: "Network Preferences (preferences.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/SystemConfiguration/preferences.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "SystemConfiguration store of configured network services and their priority. Under \
        NetworkServices, one entry per service keyed by UUID carries the bound Interface \
        (DeviceName such as en0, Hardware, Type, UserDefinedName), the per-service IPv4 and IPv6 \
        ConfigMethod (DHCP, Manual, BOOTP, INFORM), any statically configured addresses and \
        router when the method is Manual, DNS servers and Proxies. The active Set's ServiceOrder \
        array ranks the services, which determines the PrimaryInterface — the uplink actually \
        used for default traffic. Establishes how each interface obtains its address and which \
        service the Mac routed through, complementing the DHCP lease record and the interface \
        hardware map.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "service_uuid", value_type: ValueType::Guid, description: "NetworkServices entry UUID", is_uid_component: true },
        FieldSchema { name: "service_name", value_type: ValueType::Text, description: "Service UserDefinedName", is_uid_component: false },
        FieldSchema { name: "device_name", value_type: ValueType::Text, description: "Bound BSD interface (Interface.DeviceName, e.g. en0)", is_uid_component: false },
        FieldSchema { name: "ipv4_config_method", value_type: ValueType::Text, description: "IPv4 ConfigMethod (DHCP / Manual / BOOTP / INFORM)", is_uid_component: false },
        FieldSchema { name: "manual_address", value_type: ValueType::Text, description: "Statically configured IPv4 address, when ConfigMethod is Manual", is_uid_component: false },
    ],
    retention: Some("Persists until the network configuration is changed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_network_interfaces", "macos_dhcp_leases", "macos_wifi_known_networks"],
    sources: &[
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/networking.py",
        "https://medium.com/@piyushkkr12/task-5account-activity-e30497e89266",
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Records the CONFIGURED state, not a per-connection history — the current ConfigMethod, not every address ever held",
        "A DHCP ConfigMethod leaves the assigned address in the lease plist, not here; a Manual method records the static address here",
        "ServiceOrder sets priority, but link availability at runtime determines the interface actually used",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Rewritten only when the user or MDM changes the network configuration",
};

pub(crate) static MACOS_WIFI_KNOWN_NETWORKS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_known_networks",
    name: "Known Wi-Fi Networks (com.apple.wifi.known-networks.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/com.apple.wifi.known-networks.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The Big Sur (11) and later store of remembered Wi-Fi networks, one dict per network \
        keyed `wifi.network.ssid.<name>`: the SSID, SupportedSecurityTypes, AddedAt with an \
        AddReason (e.g. \"Cloud Sync\"), JoinedByUserAt and JoinedBySystemAtWeek join timestamps, \
        UpdatedAt, and an `__OSSpecific__` sub-dict holding ChannelHistory (Channel + Timestamp \
        pairs), CollocatedGroup and RoamingProfileType. The per-network access-point BSSID list — \
        stored under the internal `LEAKY_AP_BSSID` key — is the geolocation handle: each BSSID is \
        an access-point MAC that resolves to physical coordinates through a Wi-Fi positioning \
        system (see the wifi_bssid_geolocation technique). This supersedes the pre-Big Sur \
        com.apple.airport.preferences.plist (macos_wifi_plist), which held the same SSID/BSSID/ \
        last-join data in the older airport format; the upgrade to Big Sur populates this file by \
        migrating that legacy store, and the legacy records can survive in \
        com.apple.airport.preferences.plist.backup (macos_wifi_plist_backup). On iOS the \
        equivalent lives at /private/var/preferences/com.apple.wifi.known-networks.plist.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "ssid", value_type: ValueType::Text, description: "Network SSID (record key wifi.network.ssid.<name>)", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "Access-point MAC(s) the network was seen on (LEAKY_AP_BSSID) — the geolocation handle", is_uid_component: false },
        FieldSchema { name: "added_at", value_type: ValueType::Timestamp, description: "AddedAt: when the record was created; on a network migrated from the legacy airport store it can be the legacy last-join time, not a first-join date (see caveats)", is_uid_component: false },
        FieldSchema { name: "joined_by_user_at", value_type: ValueType::Timestamp, description: "JoinedByUserAt: last user-initiated join", is_uid_component: false },
        FieldSchema { name: "add_reason", value_type: ValueType::Text, description: "AddReason (e.g. \"Cloud Sync\") — how the entry was created", is_uid_component: false },
        FieldSchema { name: "channel_history", value_type: ValueType::Text, description: "__OSSpecific__ ChannelHistory: Channel + Timestamp of observations", is_uid_component: false },
    ],
    retention: Some("Persists until the network is forgotten; entries accrete across the device's life"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_wifi_plist", "macos_wifi_plist_backup", "macos_dhcp_leases", "macos_airdrop_sharingd"],
    sources: &[
        "https://forensafe.com/blogs/AppleKnownWifi.html",
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/airport_preferences.py",
        "https://www.alansiu.net/2021/01/27/known-networks-settings-moved-in-big-sur/",
        "https://forge-work.com/dfir/knowledge/artifacts/ios-wifi-known-networks",
        "https://medium.com/@piyushkkr12/task-5account-activity-e30497e89266",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "An entry with AddReason \"Cloud Sync\" was synced from another Apple device, not joined on this Mac, and often carries no BSSID — presence is not proof this device was at the location",
        "Client MAC randomization (macOS/iOS 14+) changes the device's own association MAC, not the AP BSSID recorded here, so the BSSID remains a valid location handle",
        "A shared SSID (e.g. a chain's guest Wi-Fi) spans many locations; only the BSSID ties a record to a specific access point",
        "AddedAt is not a first-join date for a network migrated from the legacy airport store at the upgrade to Big Sur: where the legacy record had no AddedAt, the migrated AddedAt (and JoinedBySystemAt) repeats the legacy last-join time (LastConnected, or LastAutoJoinAt); a legacy record that had AddedAt keeps it. Per-network __OSSpecific__ ChannelHistory timestamps, which can predate AddedAt by years, are better evidence of when the network was in use, and the legacy record in com.apple.airport.preferences.plist.backup should be compared. Observed on one macOS Big Sur 11.7 image (three networks agree); no public source found documenting it (searched mac_apt source, Alan Siu, Forensafe, forensicfocus)",
        "Each BSSIDList entry holds only LEAKY_AP_BSSID and an opaque LEAKY_AP_LEARNED_DATA blob (sometimes empty): no per-BSSID timestamp or channel. When a particular access point was used, or under which SSID when one BSSID is listed under two networks, cannot be read from BSSIDList; observed on one macOS Big Sur 11.7 image, consistent with mac_apt reading only LEAKY_AP_BSSID from it. mac_apt also parses a per-network BSSList (BSSID, LastAssociatedAt, Location) that was absent on that image; where present it does date an access point, so check for it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated as networks are joined, roamed and synced; entries removed only on forget",
};

pub(crate) static MACOS_WIFI_PLIST_BACKUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_plist_backup",
    name: "Known Wi-Fi Networks, legacy backup (com.apple.airport.preferences.plist.backup)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist.backup"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "A copy of the legacy airport preferences store beside the live \
        com.apple.airport.preferences.plist (macos_wifi_plist). On a Mac upgraded to Big Sur (11), \
        where remembered networks moved to com.apple.wifi.known-networks.plist \
        (macos_wifi_known_networks), it can be the only place the pre-upgrade records survive: the \
        live airport plist is reduced to Counter/DeviceUUID/Version. Top-level keys Counter, \
        DeviceUUID, KnownNetworks, PreferredOrder and Version; KnownNetworks is keyed \
        `wifi.ssid.<hex SSID>`, each record holding SSIDString, SecurityType, LastConnected / \
        LastAutoJoinAt / LastManualJoinAt / AddedAt, ChannelHistory and a BSSIDList of \
        access-point BSSIDs. These are the original legacy values, so they are the check on the \
        AddedAt that the migration writes into the current store.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "ssid", value_type: ValueType::Text, description: "SSIDString (record key wifi.ssid.<hex SSID>)", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "BSSIDList LEAKY_AP_BSSID values: access-point MACs, undated", is_uid_component: false },
        FieldSchema { name: "last_connected", value_type: ValueType::Timestamp, description: "LastConnected: legacy last-join time", is_uid_component: false },
        FieldSchema { name: "added_at", value_type: ValueType::Timestamp, description: "AddedAt, where the legacy record has one", is_uid_component: false },
        FieldSchema { name: "channel_history", value_type: ValueType::Text, description: "ChannelHistory: Channel + Timestamp entries", is_uid_component: false },
    ],
    retention: Some("Not rewritten as networks are joined; persists until deleted (e.g. by a Wi-Fi preferences reset)"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_wifi_plist", "macos_wifi_known_networks", "macos_dhcp_leases"],
    sources: &[
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/airport_preferences.py",
        "https://www.alansiu.net/2021/01/27/known-networks-settings-moved-in-big-sur/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "That the Big Sur migration leaves the full legacy store here while the live plist is reduced to Counter/DeviceUUID/Version is observed on one macOS Big Sur 11.7 image, not vendor-documented; mac_apt reads this path as a second airport store but does not describe how or when it is created, so compare its contents with the live plist rather than infer a migration from its presence",
        "BSSIDList entries hold only LEAKY_AP_BSSID and an opaque LEAKY_AP_LEARNED_DATA blob (sometimes empty), with no per-BSSID timestamp or channel (observed on one macOS Big Sur 11.7 image); mac_apt's source notes that plist Version 1900 carried a BSSIDHistory with timestamps, so check the Version",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "A static copy; not updated by later joins",
};

// ── macOS Wi-Fi presence timeline layer ─────────────────────────────────────
// The remembered-network stores above say which networks a Mac knows, and
// barely when. These two say on which days it was actually associated, for as
// long as each log is retained (see the wifi_presence_timeline technique).

/// Broadcom Wi-Fi driver entries in the unified log.
///
/// # Sources
/// - <https://developer.apple.com/documentation/os/generating-log-messages-from-your-code> —
///   "By default, the system doesn't redact integer, floating-point and
///   Boolean values, but it does redact the contents of dynamic strings and
///   complex dynamic objects": the general `<private>` redaction these driver
///   entries do not show.
/// - <https://github.com/mandiant/macos-UnifiedLogs> and its
///   `examples/unifiedlog_iterator/src/main.rs` — `Mode` is a clap
///   `ValueEnum` of `Live`, `LogArchive`, `SingleFile`, so the export is read
///   with `-m log-archive --input <dir>`.
///
/// The driver-message content itself (ARPT:, SetCryptoKey, "Roamed or
/// switched channel", BSSIDs in plain text) is observed on one Big Sur 11.7
/// image; no public source was found, hence `SearchedNotFound`.
pub(crate) static MACOS_WIFI_DRIVER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_driver_log",
    name: "Wi-Fi Driver Association Entries (Unified Log)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/db/diagnostics/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Entries written to the unified log by the Broadcom Wi-Fi kernel driver: messages \
        prefixed ARPT: from the process /kernel. Two carry the access point's BSSID in plain text: \
        `SetCryptoKey() bcmerr[0]: ea[<BSSID>] ...`, written when the pairwise key is installed \
        on association or reassociation, and `wl0: Roamed or switched channel, reason #N, bssid \
        <BSSID>, last RSSI -NN`, written on a roam or channel change; other driver entries carry \
        the SSID in plain text. That is unlike most of the unified log, where Apple's logging \
        API redacts dynamic strings as <private> by default, and it is why the common assumption \
        that the unified log always hides Wi-Fi network names fails for these entries. \
        Aggregated per day, the BSSIDs and SSIDs give a day-by-day record of which access points, \
        and so which networks, the Mac was associated with, for as long as the log is retained. \
        To read them from a disk image, export /private/var/db/diagnostics/ together with \
        /private/var/db/uuidtext/ (the format strings without which entries do not decode) into \
        one logarchive directory, parse it with Mandiant's macos-UnifiedLogs \
        `unifiedlog_iterator -m log-archive`, and filter for process /kernel and ARPT:.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Unified-log timestamp of the driver entry", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "Access-point BSSID from ea[...] or `bssid`; may be written with or without zero padding", is_uid_component: false },
        FieldSchema { name: "ssid", value_type: ValueType::Text, description: "SSID where the driver entry carries it", is_uid_component: false },
        FieldSchema { name: "rssi", value_type: ValueType::Text, description: "`last RSSI` on a roam entry", is_uid_component: false },
        FieldSchema { name: "event_message", value_type: ValueType::Text, description: "Full driver message", is_uid_component: false },
    ],
    retention: Some("Unified-log rotation window only; weeks on the observed image"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "fa_file__7", "macos_wifi_log", "macos_wifi_known_networks", "macos_dhcp_leases", "macos_network_interfaces"],
    sources: &[
        "https://developer.apple.com/documentation/os/generating-log-messages-from-your-code",
        "https://github.com/mandiant/macos-UnifiedLogs",
        "https://github.com/mandiant/macos-UnifiedLogs/blob/main/examples/unifiedlog_iterator/src/main.rs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SearchedNotFound),
    evidence_caveats: &[
        "The driver messages, and that they carry BSSIDs and SSIDs in plain text, are observed on one macOS Big Sur 11.7 image with a Broadcom Wi-Fi chip. Searched (2026-09) the web for ARPT and SetCryptoKey together with unified log, BSSID and forensics, the mandiant/macos-UnifiedLogs README, mac4n6 and the Mandiant/Google Cloud unified-log blog: no public description of these entries was found. Message text is driver-version-specific; other releases and non-Broadcom (Apple silicon) Wi-Fi may differ",
        "Verify per image with a control before reading a missing BSSID as absence: the Mac's own Wi-Fi MAC (macos_network_interfaces) or a BSSID known from the remembered-network store should appear in plain text in these entries; if it appears only as <private>, the image redacts them",
        "The same BSSID can be written zero-padded (0a:0b:...) and unpadded (a:b:...); normalise every octet to two hex digits before matching",
        "Retention is the unified log's rotation window, weeks on the observed image; absence before the oldest retained entry says nothing about association",
        "A BSSID locates the access point, not the Mac; association shows the Mac was in radio range of that AP at that time",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Backed by the unified log, which rotates on a rolling window",
};

/// The text Wi-Fi log, `/private/var/log/wifi.log`, and its rotated archives.
///
/// # Sources
/// - <https://discussions.apple.com/thread/7957554> — a macOS Sierra 10.12.3
///   user's Wi-Fi log excerpt containing `RSNSupplicant: Releasing
///   authenticator for <MAC>` (the line format).
/// - <https://blog.frd.mn/disable-wifi-debug-logging/> — `ls` of
///   /var/log/wifi.log beside wifi.log.0.bz2 ... wifi.log.10.bz2, each
///   archive dated 00:30 on consecutive days (nightly rotation, pre-Big Sur).
///
/// Both are single secondary sources on earlier releases; the Big Sur
/// content (BSSIDs unredacted, SSIDs redacted, `_bsdDriver_init` lines at
/// boot) is observed on one Big Sur 11.7 image.
pub(crate) static MACOS_WIFI_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_log",
    name: "Wi-Fi Text Log (/private/var/log/wifi.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/private/var/log/wifi.log*"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The Wi-Fi subsystem's plain-text log, the live wifi.log plus rotated archives \
        wifi.log.N.bz2 (rotated about daily, with a limited number of archives kept). Lines \
        `RSNSupplicant: Releasing authenticator for <BSSID>` are written when the WPA \
        supplicant for that access point is torn down, on disconnection, sleep or rejoin, so \
        they show the Mac was associated with that BSSID just before. Driver (re)initialisation \
        lines such as `_bsdDriver_init` and `Usb Host Notification ... driver available` \
        coincide with boots and can corroborate boot times from the audit trail \
        (macos_openbsm_audit). On the observed Big Sur image the SSIDs in this log are \
        redacted while BSSIDs are not, so it dates access points that the remembered-network \
        store or the driver entries in the unified log tie to a network name.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Text, description: "Local-time timestamp: weekday, month, day and time, with no year", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "Access-point BSSID from `Releasing authenticator for`", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Full log line", is_uid_component: false },
    ],
    retention: Some("Rotated about daily into wifi.log.N.bz2; only weeks retained on the observed image"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_wifi_driver_log", "macos_wifi_known_networks", "macos_openbsm_audit", "macos_dhcp_leases"],
    sources: &[
        "https://discussions.apple.com/thread/7957554",
        "https://blog.frd.mn/disable-wifi-debug-logging/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SingleSecondary),
    evidence_caveats: &[
        "Timestamps are local time with no year and no zone; take the year from the archive's position in the rotation sequence and the file times, and the zone from the image's configured time zone",
        "SSIDs are redacted in this log on the observed Big Sur 11.7 image while BSSIDs are not; map a BSSID to its network through the remembered-network store or the unified-log driver entries",
        "Retention is weeks: rotation keeps a limited number of wifi.log.N.bz2 archives, and older days are gone",
        "A Releasing authenticator line marks the end of an association, not its start; its time bounds presence from above only",
        "The line formats are sourced from single secondary sources on earlier macOS releases (Sierra; a 2016 blog) and observed on one Big Sur 11.7 image; confirm the lines on the image before relying on them",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated about daily, with only a limited number of archives kept",
};

// ── macOS network-neighbour / peer-device discovery layer ──────────────────
// The persisted traces of the Mac's immediate peer neighbourhood, complementing
// the remembered-network and DHCP layer above with the peer-device side. The
// Bluetooth store enumerates bonded and seen peripherals; the SMB identity is
// the name the Mac advertised to file-sharing neighbours; the connect-to-server
// history holds the remote hosts the user reached out to. All three are
// dead-disk-recoverable; the live ARP/neighbour table and the mDNS/Bonjour
// responder cache are in-memory and lost at power-off (see the
// network_neighbour_enumeration technique).

pub(crate) static MACOS_BLUETOOTH_DEVICES: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_bluetooth_devices",
    name: "Bluetooth Paired & Cached Devices (com.apple.Bluetooth.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/com.apple.Bluetooth.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "System Bluetooth preferences. PairedDevices is an array of the hardware MAC \
        addresses (dash-delimited, e.g. 00-1b-dc-06-cd-b8) of devices bonded to this Mac. \
        DeviceCache is a dict keyed by that same MAC, each entry carrying a user-assigned Name \
        and device attributes (VendorID, LMPVersion / LMPSubversion, page-scan parameters, and \
        LastServicesUpdate / LastInquiryUpdate times) — covering devices paired OR merely seen \
        nearby. Together they enumerate the peer devices in the Mac's immediate physical vicinity: \
        phones, laptops, keyboards, mice, headsets and speakers, each by name and MAC. This is the \
        peer-device layer of a network-neighbour reconstruction, placing named hardware beside the \
        Mac. On newer macOS the Bluetooth-LE side is held separately in a CoreBluetoothCache keyed \
        by an obscured device UUID rather than the MAC, and the DeviceCache key may be absent.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "device_mac", value_type: ValueType::Text, description: "Device hardware MAC — a PairedDevices array entry and the DeviceCache key (dash-delimited)", is_uid_component: true },
        FieldSchema { name: "name", value_type: ValueType::Text, description: "DeviceCache Name — the user-assigned device label, not a verified owner", is_uid_component: false },
        FieldSchema { name: "paired", value_type: ValueType::Bool, description: "Whether the MAC is in the PairedDevices (bonded) array, vs DeviceCache only (paired-or-seen)", is_uid_component: false },
        FieldSchema { name: "last_seen", value_type: ValueType::Timestamp, description: "LastInquiryUpdate / LastServicesUpdate — when the device was last seen or its services read", is_uid_component: false },
    ],
    retention: Some("Persists until the device is removed; the cache accretes seen devices and is not pruned on unpair"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_airdrop_sharingd", "macos_wifi_known_networks", "macos_network_interfaces"],
    sources: &[
        "https://github.com/bolodev/osxripper/blob/master/plugins/osx/BluetoothPlist.py",
        "https://forge-work.com/dfir/knowledge/artifacts/macos-bluetooth",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The Name is a user-assigned label on the peer device, not proof of who owns it or that it belongs to the Mac's user",
        "DeviceCache holds devices merely SEEN nearby as well as bonded ones — presence there is not proof of pairing; the PairedDevices array is the bonded set",
        "BLE MAC randomization inflates the cache with many entries for one physical device, and the BLE CoreBluetoothCache keys by an obscured UUID rather than the MAC",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Rewritten as devices are paired, seen or removed; entries linger after unpairing",
};

pub(crate) static MACOS_SMB_SERVER_IDENTITY: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_smb_server_identity",
    name: "SMB Server Identity (com.apple.smb.server.plist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The SMB / NetBIOS identity the Mac advertised to file-sharing neighbours. NetBIOSName \
        is the short name the Mac announced on the SMB / NetBIOS network; ServerDescription is the \
        human-readable label (usually derived from the computer name); DOSCodePage records the code \
        page used for legacy SMB (e.g. 437). Establishes how the Mac would have appeared in another \
        host's network browser or SMB connection log — the name to look for when correlating this \
        Mac against a peer's share-access records. A LocalKerberosRealm (LKDC:SHA1...) value, when \
        present, is a further semi-stable host identifier.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "netbios_name", value_type: ValueType::Text, description: "NetBIOSName — the SMB / NetBIOS short name the Mac advertised", is_uid_component: true },
        FieldSchema { name: "server_description", value_type: ValueType::Text, description: "ServerDescription — human-readable server label", is_uid_component: false },
        FieldSchema { name: "dos_code_page", value_type: ValueType::Text, description: "DOSCodePage — code page for legacy SMB (e.g. 437)", is_uid_component: false },
    ],
    retention: Some("Persists until the sharing name is changed; may be regenerated from the computer name"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["macos_network_preferences", "macos_connect_to_server_history", "macos_sfl2_recent_servers"],
    sources: &[
        "https://gist.github.com/algal/0dd167c196b4af3dc06c2b57d6f05245",
        "https://github.com/ydkhatri/mac_apt/blob/master/plugins/networking.py",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The value can be regenerated from the computer name and may revert after a reboot — cross-reference the SystemConfiguration preferences.plist rather than treating this plist as authoritative",
        "NetBIOSName is not necessarily derived from the hostname or Bonjour LocalHostName, so it need not match the Mac's other names",
        "Managed (MDM/Jamf) environments can reset these names on a schedule, which can explain an unexpected value or change time",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Rewritten only when the SMB sharing name is changed or regenerated",
};

pub(crate) static MACOS_CONNECT_TO_SERVER_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_connect_to_server_history",
    name: "Connect-to-Server History & Favourite Volumes (sharedfilelist)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentHosts.sfl"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "The user's Finder \"Connect to Server\" neighbourhood, held as SharedFileList bookmarks \
        under ~/Library/Application Support/com.apple.sharedfilelist/: RecentHosts.sfl is the list \
        of hosts entered into the Connect-to-Server dialog, and FavoriteVolumes.sfl2 the pinned \
        network volumes. Entries are NSKeyedArchiver bookmark blobs recording the smb://, afp:// or \
        nfs:// hosts and shares the user reached out to — the remote peers this Mac treated as file \
        servers. Complements the mounted-server list (macos_sfl2_recent_servers, RecentServers.sfl2): \
        RecentServers records servers actually mounted, RecentHosts the hosts entered. An empty or \
        absent archive is a meaningful negative — no Connect-to-Server neighbourhood was built.",
    mitre_techniques: &["T1021.002"],
    fields: &[
        FieldSchema { name: "host_or_volume", value_type: ValueType::Text, description: "smb/afp/nfs host or share URL from a RecentHosts / FavoriteVolumes bookmark", is_uid_component: true },
    ],
    retention: Some("Capped, undated list maintained only while the owning process runs; can retain very old URLs"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_sfl2_recent_servers", "macos_network_interfaces", "macos_dhcp_leases"],
    sources: &[
        "https://www.mac4n6.com/blog/2016/6/21/introduction-to-sfl-and-sfl2-files",
        "https://eclecticlight.co/2017/08/10/recent-items-launch-services-and-sharedfilelists/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "SFL / SFL2 entries are undated — only the file's own modification time bounds when the list last changed",
        "The list is maintained only while its owning process is open, so it can retain extremely old host URLs and is not a complete connection history",
        "RecentHosts records hosts ENTERED in the dialog, not necessarily successfully mounted — the mounted-server record is RecentServers (macos_sfl2_recent_servers)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Updated as the user connects to servers; entries evicted only as the capped list rolls",
};
