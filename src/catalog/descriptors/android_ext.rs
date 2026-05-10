//! Android mobile artifact descriptors.
//!
//! Samsung Gallery3d (com.sec.android.gallery3d) local.db — trash and log
//! tables documenting image deletion activity on Samsung devices.
//! Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Samsung Gallery3d Trash table ───────────────────────────────────────────

/// Field schema for the `trash` table in local.db.
/// Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
pub(crate) static SAMSUNG_GALLERY3D_TRASH_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "__absPath",
        value_type: ValueType::Text,
        description: "Current path and filename of the deleted file in the .Trash directory \
            (e.g. /storage/emulated/0/Android/data/com.sec.android.gallery3d/files/.Trash/<id>)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "__Title",
        value_type: ValueType::Text,
        description: "Current filename of the deleted file in the .Trash directory",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__absID",
        value_type: ValueType::Integer,
        description: "Integer identifier for the trashed item",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__mediaType",
        value_type: ValueType::Integer,
        description: "Media type indicator (image, video, etc.)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__width",
        value_type: ValueType::Integer,
        description: "Image/video width in pixels",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__height",
        value_type: ValueType::Integer,
        description: "Image/video height in pixels",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__orientation",
        value_type: ValueType::Integer,
        description: "EXIF-style orientation value of the media",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__originPath",
        value_type: ValueType::Text,
        description: "Original file path before deletion \
            (e.g. /storage/emulated/0/DCIM/Screenshots/Screenshot_20200530-054103_One UI Home.jpg); \
            proves where the file originally resided",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__originTitle",
        value_type: ValueType::Text,
        description: "Original filename before the item was moved to trash",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__deleteTime",
        value_type: ValueType::Timestamp,
        // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
        description: "UNIX millisecond timestamp in UTC when the file was moved to trash \
            (e.g. 1592678711438 = 2020-06-20T18:05:11.438Z)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__storageType",
        value_type: ValueType::Integer,
        description: "Storage type indicator (internal vs external SD)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__burstGroupID",
        value_type: ValueType::Integer,
        description: "Burst photo group identifier; links related burst shots",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__bestImage",
        value_type: ValueType::Integer,
        description: "Boolean flag indicating the best image in a burst group",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__cloudServerId",
        value_type: ValueType::Text,
        description: "Samsung Cloud server-side identifier for the item",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__cloudTP",
        value_type: ValueType::Text,
        description: "Samsung Cloud transport/sync parameter",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__restoreExtra",
        value_type: ValueType::Json,
        // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
        description: "JSON blob with rich metadata including __dateTaken (UNIX ms, local time), \
            __latitude, __longitude, __size, __isDrm, __isFavourite, __fileDuration, \
            __capturedAPP, __cloudTimestamp, __recordingMode. Provides geolocation and \
            temporal context for the deleted item",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__volumeName",
        value_type: ValueType::Text,
        description: "Storage volume name where the file was located",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__volumeValid",
        value_type: ValueType::Integer,
        description: "Whether the storage volume is currently mounted/valid",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__expiredPeriod",
        value_type: ValueType::Integer,
        description: "Trash retention period; items auto-deleted after this period expires \
            as configured in Gallery app settings",
        is_uid_component: false,
    },
];

pub(crate) static SAMSUNG_GALLERY3D_TRASH: ArtifactDescriptor = ArtifactDescriptor {
    id: "samsung_gallery3d_trash",
    name: "Samsung Gallery3d Trash Table",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
    file_path: Some("/data/com.sec.android.gallery3d/cache/databases/local.db"),
    scope: DataScope::User,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    meaning: "Samsung Gallery3d app 'trash' table in local.db SQLite database. Contains metadata \
        for images and videos moved to the Gallery trash bin. Each row preserves the original \
        file path (__originPath), original filename (__originTitle), deletion timestamp \
        (__deleteTime as UNIX ms UTC), and media dimensions. The __restoreExtra JSON field \
        embeds __dateTaken, GPS coordinates (__latitude/__longitude), file size, and \
        Samsung Cloud sync state. Actual trashed files reside at \
        /storage/emulated/0/Android/data/com.sec.android.gallery3d/files/.Trash/<id>. \
        Items are auto-deleted after a configurable retention period (EMPTY_EXPIRED). \
        Recovering deleted SQLite rows can reveal previously trashed items whose trash \
        records were purged. Tested on Samsung Gallery v10.2.00.21; schema may vary across \
        versions.",
    mitre_techniques: &["T1070.004", "T1485"],
    fields: SAMSUNG_GALLERY3D_TRASH_FIELDS,
    retention: Some(
        "Configurable in Gallery app settings; items auto-deleted after retention period expires",
    ),
    triage_priority: TriagePriority::High,
    related_artifacts: &["samsung_gallery3d_log"],
    sources: &[
        // Source: cheeky4n6monkey — full reverse engineering of local.db trash + log tables
        "https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Samsung Gallery3d Log table ─────────────────────────────────────────────

/// Field schema for the `log` table in local.db.
/// Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
pub(crate) static SAMSUNG_GALLERY3D_LOG_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "_id",
        value_type: ValueType::Integer,
        description: "Auto-incrementing primary key for the log entry",
        is_uid_component: true,
    },
    FieldSchema {
        name: "__category",
        value_type: ValueType::Integer,
        description: "Integer category code for the log entry type",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__timestamp",
        value_type: ValueType::Timestamp,
        // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
        description: "Text timestamp formatted as YYYY-MM-DD HH:MM:SS in local time \
            when the log action occurred",
        is_uid_component: false,
    },
    FieldSchema {
        name: "__log",
        value_type: ValueType::Text,
        // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
        description: "Proprietary bracket-delimited string containing the action type \
            (e.g. MOVE_TO_TRASH_SINGLE, MOVE_TO_TRASH_MULTIPLE, EMPTY_SINGLE, \
            EMPTY_MULTIPLE, EMPTY_EXPIRED, FROM_EXPAND) and base64-encoded file paths. \
            Format varies by APK version (v10 vs v11). Multiple base64 paths may appear \
            in a single entry",
        is_uid_component: false,
    },
];

pub(crate) static SAMSUNG_GALLERY3D_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "samsung_gallery3d_log",
    name: "Samsung Gallery3d Deletion Log Table",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html
    file_path: Some("/data/com.sec.android.gallery3d/cache/databases/local.db"),
    scope: DataScope::User,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    meaning: "Samsung Gallery3d app 'log' table in local.db SQLite database. Records timestamped \
        actions related to gallery trash operations. The __log field uses a proprietary \
        bracket-delimited format: [ACTION][count][0][location_uri][base64_encoded_paths]. \
        Known actions: MOVE_TO_TRASH_SINGLE (user trashes one file), \
        MOVE_TO_TRASH_MULTIPLE (user trashes multiple files), EMPTY_SINGLE (manual empty \
        with one file in trash), EMPTY_MULTIPLE (manual empty with multiple files), \
        EMPTY_EXPIRED (auto-delete after configured retention period), FROM_EXPAND \
        (deletion from expanded album view). File paths in __log are base64-encoded and \
        may contain non-standard padding characters that must be stripped before decoding. \
        __timestamp is local time formatted YYYY-MM-DD HH:MM:SS. Format of __log varies \
        between APK versions (v10 vs v11). Tested on Samsung Gallery v10.2.00.21.",
    mitre_techniques: &["T1070.004", "T1485"],
    fields: SAMSUNG_GALLERY3D_LOG_FIELDS,
    retention: Some("Persists in SQLite until database is cleared or app data is wiped"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["samsung_gallery3d_trash"],
    sources: &[
        // Source: cheeky4n6monkey — full reverse engineering of local.db log table with
        // base64 decoding methodology and v10/v11 format differences
        "https://cheeky4n6monkey.blogspot.com/2022/01/mike-monkey-dumpster-dive-into-samsung.html",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Android Tor Browser Thumbnails ──────────────────────────────────────────

/// Field schema for Tor Browser thumbnail files.
/// Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
pub(crate) static ANDROID_TOR_BROWSER_THUMBNAILS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "filename",
        value_type: ValueType::Text,
        // Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
        description:
            "GUID-format filename with .0 extension (e.g. 8c7defaa-12b9-44f4-ae78-cc8850b92ab4.0) \
            — each file corresponds to one opened Tor Browser tab",
        is_uid_component: true,
    },
    FieldSchema {
        name: "modified_time",
        value_type: ValueType::Timestamp,
        // Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
        description: "File system modified timestamp indicating when the tab thumbnail was \
            last captured or updated",
        is_uid_component: false,
    },
    FieldSchema {
        name: "file_path",
        value_type: ValueType::Text,
        description: "Full file system path to the thumbnail file",
        is_uid_component: false,
    },
    FieldSchema {
        name: "image_format",
        value_type: ValueType::Text,
        // Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
        description: "RIFF container with WEBP VP8 payload — viewable in Chrome browser or \
            convertible to PNG via PIL/Pillow",
        is_uid_component: false,
    },
];

/// Android Tor Browser tab thumbnail cache directory.
///
/// Tor Browser for Android (org.torproject.torbrowser) caches WEBP
/// thumbnails of every opened tab in a `mozac_browser_thumbnails/thumbnails/`
/// directory. Files are named with a GUID and `.0` extension. The thumbnails
/// are in RIFF/WEBP VP8 format and can be opened with Chrome or converted to
/// PNG for reporting.
///
/// This is significant because Tor Browser investigations typically yield
/// only bookmarks — these thumbnails provide visual evidence of pages actually
/// viewed in opened tabs.
///
/// Original discovery credited to Loicforensic@protonmail.com.
/// Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
pub(crate) static ANDROID_TOR_BROWSER_THUMBNAILS: ArtifactDescriptor = ArtifactDescriptor {
    id: "android_tor_browser_thumbnails",
    name: "Android Tor Browser Tab Thumbnails",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    // Two known paths; primary listed here, secondary in meaning.
    // Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
    file_path: Some(
        "/data/data/org.torproject.torbrowser/cache/mozac_browser_thumbnails/thumbnails/",
    ),
    scope: DataScope::User,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    meaning: "Tor Browser for Android tab thumbnail cache. Contains RIFF/WEBP VP8 image \
        files named in GUID format with .0 extension (e.g. 8c7defaa-12b9-44f4-ae78-cc8850b92ab4.0). \
        Each file is a thumbnail screenshot of an opened tab. This is forensically significant \
        because Tor Browser investigations typically yield only bookmarks — these thumbnails \
        provide visual evidence of pages the user actually viewed. A secondary path exists at \
        /data/user/0/org.torproject.torbrowser/cache/mozac_browser_thumbnails/thumbnails/ \
        which may be a symlink or multi-user alias. Files can be viewed directly in Chrome or \
        converted to PNG with PIL/Pillow for reporting. File modified timestamps indicate when \
        the tab was last active. Tested against Josh Hickman's Android 12 test image.",
    mitre_techniques: &["T1071.001"],
    fields: ANDROID_TOR_BROWSER_THUMBNAILS_FIELDS,
    retention: Some("Persists until Tor Browser cache is cleared or app is uninstalled"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &[],
    sources: &[
        // Source: https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html
        // (original research by Alexis Brignoni; discovery by Loicforensic; thumbnail
        // format, paths, ALEAPP parser, and Josh Hickman's Android 12 test image)
        "https://abrignoni.blogspot.com/2021/12/tor-thumbnails-what.html",
        // Source: https://github.com/abrignoni/ALEAPP (ALEAPP framework containing the Tor Thumbnails parser)
        "https://github.com/abrignoni/ALEAPP",
        // Source: https://thebinaryhick.blog/2021/12/17/android-12-image-now-available/
        // (Josh Hickman's Android 12 test image used to validate the artifact)
        "https://thebinaryhick.blog/2021/12/17/android-12-image-now-available/",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Gboard Training Cache ───────────────────────────────────────────────────

/// Field schema for Gboard training cache keystroke data.
pub(crate) static ANDROID_GBOARD_TRAININGCACHE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_package",
        value_type: ValueType::Text,
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        description: "Package name of the application that had input focus when keystrokes \
            were captured (e.g. com.whatsapp, com.google.android.gm)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "input_field",
        value_type: ValueType::Text,
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        description: "Name of the input field within the application where text was entered \
            (e.g. Email, Message, Search)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        description: "Timestamp of the input event recorded in the training_input_events_table \
            or derived from f1 session identifier in tf_table",
        is_uid_component: true,
    },
    FieldSchema {
        name: "typed_text",
        value_type: ValueType::Text,
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        description: "Reconstructed user-typed text extracted from protobuf _payload blobs \
            or concatenated from individual keystroke entries in tf_table (f3 column)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "suggestions",
        value_type: ValueType::Text,
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        description: "Spelling, grammar, contact name, or emoji suggestions offered by Gboard \
            alongside the typed text",
        is_uid_component: false,
    },
];

/// Android Gboard (Google Keyboard) training cache — keystroke recovery.
///
/// Gboard caches user keystrokes in SQLite databases named `trainingcache*.db`
/// within its app sandbox. Multiple database versions exist across Gboard
/// releases:
///
/// - `trainingcache2.db` (v 8.x): `training_input_events_table` with columns
///   for app package, field name, timestamp, and `_payload` (protobuf blob
///   containing typed text and suggestions).
/// - `trainingcache3.db` (v 10.x): `s_table` (app/field metadata) +
///   `tf_table` (individual keystrokes — `f1` = session ID, `f3` = character,
///   `f4` = keystroke order). Joinable to reconstruct full typed text.
/// - `trainingcachev2.db`: alternate format with similar keystroke data.
///
/// Forensic significance: recovers text typed into apps that have since been
/// deleted, messages from disappearing-message features (WhatsApp, Telegram),
/// and data entered into web forms that are never stored locally. Password
/// field input is excluded by the keyboard.
///
/// Tested on Pixel 3 (Android 10/11) and Josh Hickman's Android 10 image.
/// Verified that Telegram and WhatsApp sent messages appear in the cache.
///
/// Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
pub(crate) static ANDROID_GBOARD_TRAININGCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "android_gboard_trainingcache",
    name: "Android Gboard Training Cache (Keystroke Recovery)",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
    file_path: Some("/data/data/com.google.android.inputmethod.latin/databases/trainingcache*.db"),
    scope: DataScope::User,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    meaning: "Gboard keystroke training cache. Contains typed text from all apps including \
        deleted apps and disappearing-message conversations (WhatsApp, Telegram verified). \
        Data survives app uninstallation because it belongs to the Gboard sandbox, not the \
        originating app. Key tables: training_input_events_table (trainingcache2.db) stores \
        app package, input field name, timestamp, and protobuf _payload with full typed text; \
        tf_table (trainingcache3.db) stores individual keystrokes with session ID (f1), \
        character (f3), and order (f4) — joinable with s_table for app context. Password \
        fields are excluded by the keyboard. Caches are periodically pruned and size-limited, \
        so not all historical input is retained. Also captures text entered into web forms \
        and online apps that store nothing locally. ALEAPP includes a parser for this artifact.",
    mitre_techniques: &[
        "T1056.001", // Input Capture: Keylogging
        "T1005",     // Data from Local System
    ],
    fields: ANDROID_GBOARD_TRAININGCACHE_FIELDS,
    retention: Some("Periodically pruned; size-limited; survives originating app deletion"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[],
    sources: &[
        // Source: https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html
        // (Yogesh Khatri; original research on Gboard trainingcache*.db databases;
        // tables, protobuf structure, keystroke reconstruction, and ALEAPP parser)
        "https://www.swiftforensics.com/2021/01/gboard-has-some-interesting-data.html",
        // Source: https://github.com/abrignoni/ALEAPP (ALEAPP framework containing
        // the Gboard trainingcache parser module)
        "https://github.com/abrignoni/ALEAPP",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};
