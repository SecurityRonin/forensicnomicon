//! Extended macOS artifact descriptors.
//!
//! Sources: Velociraptor macOS artifacts, ForensicArtifacts/artifacts (macOS YAML),
//! APOLLO modules (mac4n6), Magnet Forensics, mac4n6.com, Sarah Edwards research.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static MACOS_FSEVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_fsevents",
    name: "FSEvents Log",
    artifact_type: ArtifactType::Directory,
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
    evidence_caveats: &["Kernel-level; not easily tampered; covers all file system activity"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "FSEvents log; rotated as volume fills",
};

pub(crate) static MACOS_SPOTLIGHT_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_spotlight_store",
    name: "Spotlight Metadata Store",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_DOCK_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_dock_plist",
    name: "Dock Configuration Plist (recent apps)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_LOGIN_ITEMS_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_login_items_plist",
    name: "Login Items Plist",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Persistence mechanism; SFL2 format varies by OS version"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Plist file; persistent until deleted",
};

pub(crate) static MACOS_SFL2_RECENT_ITEMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sfl2_recent_items",
    name: "SFL2 Recent Documents",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_SFL2_RECENT_SERVERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sfl2_recent_servers",
    name: "SFL2 Recent Servers",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_WIFI_PLIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_wifi_plist",
    name: "Known Wi-Fi Networks (airport preferences)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Ordered list of all known Wi-Fi networks: SSIDs, security type, last join time, BSSID. Reveals historical network connections and geolocation context. Key for placing a device at a location or identifying rogue access points.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "ssid", value_type: ValueType::Text, description: "Wi-Fi network SSID", is_uid_component: true },
        FieldSchema { name: "bssid", value_type: ValueType::Text, description: "Access point MAC address", is_uid_component: false },
        FieldSchema { name: "last_joined", value_type: ValueType::Timestamp, description: "Last connection timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent; manually cleared or limited by OS"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_unified_log", "macos_wifi_intelligence"],
    sources: &["https://www.mac4n6.com/blog/2016/6/3/ode-to-the-network"],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_SCREEN_TIME_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_screen_time_db",
    name: "Screen Time Database",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_TCC_SYSTEM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_tcc_system_db",
    name: "TCC System Database (root-level)",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["System-wide privacy permissions; requires SIP bypass to tamper"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persistent until reset",
};

pub(crate) static MACOS_SMS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_sms_db",
    name: "iMessage / SMS Database (chat.db)",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["iMessage/SMS content; may be partially encrypted or unavailable without cloud sync"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persistent until deleted",
};

pub(crate) static MACOS_NOTES_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notes_db",
    name: "Apple Notes Database",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Library/Containers/com.apple.Notes/Data/Library/CoreData/ExternalRecords/"),
    scope: DataScope::User,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Apple Notes CoreData store. Notes content (including attachments) and modification timestamps. Frequently used by users to store sensitive information (passwords, plans, communications) — important for insider threat and fraud cases.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "title", value_type: ValueType::Text, description: "Note title", is_uid_component: true },
        FieldSchema { name: "modification_date", value_type: ValueType::Timestamp, description: "Last modification timestamp", is_uid_component: false },
    ],
    retention: Some("Persistent; syncs via iCloud"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["macos_sms_db"],
    sources: &["https://github.com/mac4n6/APOLLO"],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_PHOTOS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_photos_db",
    name: "Photos Library Database",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/Users/*/Pictures/Photos Library.photoslibrary/database/Photos.sqlite"),
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
    related_artifacts: &["macos_knowledgec"],
    sources: &["https://github.com/mac4n6/APOLLO"],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_ICLOUD_DRIVE_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_icloud_drive_db",
    name: "iCloud Drive Local Metadata",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_LOCATIOND_CLIENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_locationd_clients",
    name: "Location Services Client Authorization",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_LOCKDOWND_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_lockdownd_log",
    name: "Lockdownd Log (iOS device pairing)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_INSTALLER_RECEIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_installer_receipts",
    name: "Third-Party Package Receipts",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_SAFARI_LOCALSTORAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_safari_localstorage",
    name: "Safari HTML5 LocalStorage",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_NOTIFICATION_CENTER_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_notification_center_db",
    name: "Notification Center Database",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_MDM_ENROLLMENT: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_mdm_enrollment",
    name: "MDM Enrollment State",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_ASL_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_asl_logs",
    name: "Apple System Log (ASL) Binary Logs",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/private/var/log/asl/"),
    scope: DataScope::System,
    os_scope: OsScope::MacOS,
    decoder: Decoder::Identity,
    meaning: "Legacy Apple System Log binary files (pre-Unified Log, macOS 10.11 and earlier, but may persist on upgraded systems). Contains authentication, kext load, sudo, and daemon messages useful for historical analysis on older Mac images.",
    mitre_techniques: &["T1562.002"],
    fields: &[
        FieldSchema { name: "sender", value_type: ValueType::Text, description: "Process that generated the message", is_uid_component: true },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Log message text", is_uid_component: false },
    ],
    retention: Some("Rotated periodically; older files compressed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["macos_unified_log"],
    sources: &["https://www.mac4n6.com/blog/2016/2/5/asl-logging"],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static MACOS_DIAGNOSTIC_REPORTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "macos_diagnostic_reports",
    name: "Diagnostic Reports (crash logs)",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
///                       extractable via hex offset analysis (RGB Alpha bitmaps)
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
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
/// APFS uses 4096-byte sectors (not the legacy 512-byte HFS+ sectors), which
/// affects offset calculations. The container superblock ("NXSB") is at the
/// start of the APFS partition.
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
// Source: https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system
pub(crate) static APFS_CONTAINER: ArtifactDescriptor = ArtifactDescriptor {
    id: "apfs_container",
    name: "APFS Container (Apple File System)",
    artifact_type: ArtifactType::File,
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
        calculating the byte offset (sector_offset * bytes_per_sector, typically 4096), \
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
            description: "Sector size in bytes (typically 4096 for APFS, not 512); \
                critical for correct offset calculation during acquisition",
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
        // Source: https://az4n6.blogspot.com/2016/09/mac-live-imaging-functionality-versus.html
        // — live imaging FileVault2 via dd + /dev/rdisk; speed comparison dd vs FTK Imager CLI
        "https://az4n6.blogspot.com/2016/09/mac-live-imaging-functionality-versus.html",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
    artifact_type: ArtifactType::Directory,
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
    mitre_techniques: &["T1070.001", "T1059"],
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
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── iOS14 Apple Maps History (MapsSync_0.0.1) ────────────────────────────────

/// Field schema for the ZHISTORYITEM + ZMIXINMAPITEM tables in MapsSync_0.0.1.
/// SQL query from Heather Mahalik's research (adapted by cheeky4n6monkey):
///   SELECT ZHISTORYITEM.z_pk, z_ent, ZCREATETIME, ZMODIFICATIONTIME,
///          ZQUERY, ZLOCATIONDISPLAY, ZLATITUDE, ZLONGITUDE,
///          ZROUTEREQUESTSTORAGE, ZMAPITEMSTORAGE
///   FROM ZHISTORYITEM LEFT JOIN ZMIXINMAPITEM ON ZMIXINMAPITEM.Z_PK=ZHISTORYITEM.ZMAPITEM;
/// Source: https://cheeky4n6monkey.blogspot.com/2020/11/ios14-maps-history-blob-script.html
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
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Uber iOS LevelDB trip/location history ──────────────────────────────────

/// Field schema for Uber iOS LevelDB location records.
/// Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py
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
/// Source: https://abrignoni.blogspot.com/2024/04/new-parser-for-uber-app-geo-locatios-in.html
/// Source: https://github.com/abrignoni/iLEAPP/blob/main/scripts/artifacts/uberLeveldb.py
pub(crate) static UBER_IOS_LEVELDB: ArtifactDescriptor = ArtifactDescriptor {
    id: "uber_ios_leveldb",
    name: "Uber iOS LevelDB Location/Trip History",
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── iOS Google Chat cacheV0.db ──────────────────────────────────────────────

/// Field schema for the `cache` table in cacheV0.db.
/// Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
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

/// iOS Google Chat (Dynamite) image thumbnail cache database.
///
/// The `cacheV0.db` SQLite database is created by Google's image rendering
/// pipeline (similar to Glide Image Manager Cache on Android). It contains a
/// single `cache` table with `id` and `data` columns. Each `data` BLOB holds
/// a reduced-resolution copy of every image the app has rendered in its UI,
/// including user avatars and images from deleted chats.
///
/// Key forensic insight: images from deleted conversations persist in this
/// database even after the source files are removed from the main chat image
/// directory. Also observed in Google Voice on iOS.
///
/// Source: https://abrignoni.blogspot.com/2024/02/what-is-cachev0db-and-why-are-there.html
// ── macOS BTM (Background Task Management) ──────────────────────────────────

/// macOS Background Task Management database — login items, launch agents/daemons,
/// and background tasks tracked since macOS 13 Ventura.
///
/// NSKeyedArchive binary plist containing per-user dictionaries of all registered
/// background tasks. Each item has a `type` flag (agent=0x08, daemon=0x10,
/// login item=0x04, app=0x02, user item=0x01, developer=0x20, spotlight=0x40,
/// quicklook=0x800, curated=0x80000, legacy=0x10000) and a `disposition` flag
/// (Enabled=0x01, Allowed=0x02, Hidden=0x04, Notified=0x08). When a user
/// toggles an item OFF in System Settings > Login Items & Extensions, the
/// Allowed bit (0x02) is cleared.
///
/// Multiple versioned .btm files may coexist (e.g. BackgroundItems-v9.btm from
/// an older macOS and BackgroundItems-v13.btm from macOS 15). Older files are
/// forensic snapshots of autostart state at that point in time.
///
/// Source: http://www.swiftforensics.com/2025/01/macapt-update-to-btm-processing.html
/// Source: https://objective-see.org/blog/blog_0x31.html
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
/// Source: http://www.swiftforensics.com/2021/01/ios-application-groups-shared-data.html
pub(crate) static IOS_MOBILE_CONTAINER_MANAGER: ArtifactDescriptor = ArtifactDescriptor {
    id: "ios_mobile_container_manager",
    name: "iOS Mobile Container Manager (containers.sqlite3)",
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
    artifact_type: ArtifactType::DatabaseEntry,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};
