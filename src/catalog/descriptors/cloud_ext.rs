//! Cloud service artifact descriptors (Google Takeout, etc.).
//!
//! These artifacts represent data exported from cloud services via official
//! takeout/export mechanisms. They are cross-platform (OsScope::All) since
//! the data lives server-side and the export is OS-agnostic.

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Google Takeout Location Records ─────────────────────────────────────────

/// Field schema for Records.json location elements.
/// Source: https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html
pub(crate) static GOOGLE_TAKEOUT_LOCATION_RECORDS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "ISO 8601 UTC element timestamp (e.g. 2022-02-02T00:55:06.311Z); changes with each record",
        is_uid_component: true,
    },
    FieldSchema {
        name: "latitudeE7",
        value_type: ValueType::Integer,
        description: "Latitude in degrees scaled by 10,000,000 (divide by 1e7 for decimal degrees)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "longitudeE7",
        value_type: ValueType::Integer,
        description: "Longitude in degrees scaled by 10,000,000 (divide by 1e7 for decimal degrees)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "accuracy",
        value_type: ValueType::Integer,
        description: "Location accuracy estimate (suspected metres)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "altitude",
        value_type: ValueType::Integer,
        description: "Altitude in metres (not always present)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "heading",
        value_type: ValueType::Integer,
        description: "Heading in degrees clockwise from True North (0=N, 90=E, 180=S; not always present)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "velocity",
        value_type: ValueType::Integer,
        description: "Speed in metres per second (not always present)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "source",
        value_type: ValueType::Text,
        description: "Location source — usually UNKNOWN, also observed CELL",
        is_uid_component: false,
    },
    FieldSchema {
        name: "deviceTag",
        value_type: ValueType::Text,
        description: "Device identifier tag",
        is_uid_component: false,
    },
    FieldSchema {
        name: "platformType",
        value_type: ValueType::Text,
        description: "Platform type — usually ANDROID",
        is_uid_component: false,
    },
    FieldSchema {
        name: "formFactor",
        value_type: ValueType::Text,
        description: "Device form factor (e.g. PHONE)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "serverTimestamp",
        value_type: ValueType::Timestamp,
        description: "ISO 8601 UTC server-side timestamp; not always present, can repeat across elements",
        is_uid_component: false,
    },
    FieldSchema {
        name: "deviceTimestamp",
        value_type: ValueType::Timestamp,
        description: "ISO 8601 UTC device-side timestamp; not always present, can repeat across elements",
        is_uid_component: false,
    },
    FieldSchema {
        name: "verticalAccuracy",
        value_type: ValueType::Integer,
        description: "Vertical accuracy estimate (suspected metres; not always present)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "activity",
        value_type: ValueType::Json,
        description: "Array of DetectedActivity sub-objects, each with its own timestamp and type/confidence pairs",
        is_uid_component: false,
    },
];

/// Google Takeout Records.json — device location history with DetectedActivity.
///
/// Replaced "Location History.json" circa Jan-Feb 2022 (server-side change).
/// Contains an array of location elements, each with coordinates, timestamps,
/// and optional DetectedActivity classifications.
///
/// Source: https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html
pub(crate) static GOOGLE_TAKEOUT_LOCATION_RECORDS: ArtifactDescriptor = ArtifactDescriptor {
    id: "google_takeout_location_records",
    name: "Google Takeout Location Records",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("Takeout/Location History/Records.json"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Google Takeout location history with per-element DetectedActivity classifications. \
Each location element records latitudeE7/longitudeE7, timestamps (element, server, device), \
and optional activity lists. Each activity contains subactivities with type/confidence pairs: \
STILL, IN_VEHICLE, ON_FOOT, WALKING, RUNNING, ON_BICYCLE, TILTING, IN_ROAD_VEHICLE, \
IN_RAIL_VEHICLE, IN_FOUR_WHEELER_VEHICLE, IN_CAR, UNKNOWN. Confidence is a percentage (0-100). \
A transition from IN_VEHICLE to STILL indicates arrival at a location. \
Coordinates use E7 format (divide by 10,000,000 for decimal degrees). \
Formerly named 'Location History.json'; renamed to 'Records.json' circa early 2022 server-side. \
Files can be very large (hundreds of MB); use streaming JSON parsers (e.g. Python ijson).",
    mitre_techniques: &[],
    fields: GOOGLE_TAKEOUT_LOCATION_RECORDS_FIELDS,
    retention: Some("Indefinite — retained until user deletes from Google account"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["google_takeout_semantic_location_history"],
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html",
        // Source: https://thebinaryhick.blog/2021/02/20/using-google-takeout-for-dfir/ (Josh Hickman altitude/heading/velocity units)
        "https://thebinaryhick.blog/2021/02/20/using-google-takeout-for-dfir/",
    ],
};

// ── Google Takeout Semantic Location History ─────────────────────────────────

/// Field schema for Semantic Location History monthly JSON files.
/// Source: https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html
pub(crate) static GOOGLE_TAKEOUT_SEMANTIC_LOCATION_HISTORY_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "placeVisit",
        value_type: ValueType::Json,
        description: "Place visit object with location name, address, coordinates, duration (startTimestamp/endTimestamp), and place confidence",
        is_uid_component: false,
    },
    FieldSchema {
        name: "activitySegment",
        value_type: ValueType::Json,
        description: "Activity segment between place visits — start/end locations, distance, activity type, duration, and waypoints",
        is_uid_component: false,
    },
];

/// Google Takeout Semantic Location History — monthly JSON files with place
/// visits and activity segments derived from raw location data.
///
/// Organized by year/month under `Takeout/Location History/Semantic Location History/`.
/// Provides higher-level interpreted location data compared to Records.json.
///
/// Source: https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html
pub(crate) static GOOGLE_TAKEOUT_SEMANTIC_LOCATION_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "google_takeout_semantic_location_history",
    name: "Google Takeout Semantic Location History",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("Takeout/Location History/Semantic Location History/YYYY/YYYY-MM.json"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Monthly semantic location history derived from raw Google location data. \
Contains placeVisit objects (named locations with addresses, coordinates, and visit duration) \
and activitySegment objects (travel between places with distance, activity type, and waypoints). \
Higher-level than Records.json — Google's server-side inference of where the user went and how \
they traveled. Organized per-month under Semantic Location History/YYYY/YYYY-MM.json. \
Cross-reference with Records.json for raw coordinate and DetectedActivity detail.",
    mitre_techniques: &[],
    fields: GOOGLE_TAKEOUT_SEMANTIC_LOCATION_HISTORY_FIELDS,
    retention: Some("Indefinite — retained until user deletes from Google account"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["google_takeout_location_records"],
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html",
    ],
};
