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
};
