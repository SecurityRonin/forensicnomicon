//! Cloud service artifact descriptors (Google Takeout, AWS CloudTrail, etc.).
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

// ── AWS CloudTrail IAM Events ───────────────────────────────────────────────

/// Field schema for AWS CloudTrail IAM management events.
/// Source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
pub(crate) static AWS_CLOUDTRAIL_IAM_EVENTS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "eventTime",
        value_type: ValueType::Timestamp,
        description: "UTC timestamp when the API call was made (ISO 8601)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "eventName",
        value_type: ValueType::Text,
        description: "IAM API action name (e.g. CreateUser, AddUserToGroup, RemoveUserFromGroup, \
AttachUserPolicy, DetachUserPolicy, CreateAccessKey)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "eventSource",
        value_type: ValueType::Text,
        description: "AWS service that processed the request — always iam.amazonaws.com for IAM events",
        is_uid_component: false,
    },
    FieldSchema {
        name: "awsRegion",
        value_type: ValueType::Text,
        description: "Region where the event was logged — always us-east-1 for IAM (global service)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "sourceIPAddress",
        value_type: ValueType::Text,
        description: "IP address of the caller; may be an AWS service endpoint for service-linked actions",
        is_uid_component: false,
    },
    FieldSchema {
        name: "userIdentity",
        value_type: ValueType::Json,
        description: "Identity of the caller — includes type (Root/IAMUser/AssumedRole/FederatedUser), \
ARN, accountId, accessKeyId, sessionContext",
        is_uid_component: false,
    },
    FieldSchema {
        name: "requestParameters",
        value_type: ValueType::Json,
        description: "Parameters sent with the API call (e.g. {\"userName\": \"...\", \"groupName\": \"...\"})",
        is_uid_component: false,
    },
    FieldSchema {
        name: "responseElements",
        value_type: ValueType::Json,
        description: "Response from the service (e.g. created user ARN, createDate); null on read-only calls",
        is_uid_component: false,
    },
    FieldSchema {
        name: "userAgent",
        value_type: ValueType::Text,
        description: "User agent string of the caller (e.g. aws-cli/2.x, console.amazonaws.com, Boto3)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "eventID",
        value_type: ValueType::Guid,
        description: "Unique GUID for this event record",
        is_uid_component: true,
    },
    FieldSchema {
        name: "eventType",
        value_type: ValueType::Text,
        description: "Event category — AwsApiCall for management events",
        is_uid_component: false,
    },
    FieldSchema {
        name: "errorCode",
        value_type: ValueType::Text,
        description: "AWS error code if the call failed (e.g. AccessDenied, EntityAlreadyExists); \
absent on success",
        is_uid_component: false,
    },
];

/// AWS CloudTrail IAM management events — user, group, and policy changes
/// logged to S3 in us-east-1.
///
/// IAM is a global AWS service; all IAM management events (CreateUser,
/// AddUserToGroup, RemoveUserFromGroup, AttachUserPolicy, CreateAccessKey, etc.)
/// are recorded in the us-east-1 region regardless of where the API call
/// originates.
///
/// Empirical latency measurements (David Cowen, HECF Blog #808-#812, April 2025):
///   - ConsoleLogin: ~90 sec (region-specific — logged in the console login region)
///   - CreateAccessKey: ~90 sec (IAM global — logged in us-east-1)
///   - CreateUser: ~2 minutes
///   - AddUserToGroup: ~2 minutes
///   - RemoveUserFromGroup: ~1 min 45 sec
/// All well within the 15-minute SLA and the 5-minute target for critical events.
/// Note: ConsoleLogin events are region-specific (logged in the region of the login
/// URL), unlike IAM management events which are always in us-east-1.
///
/// Source: https://www.hecfblog.com/2025/04/daily-blog-808-testing-aws-log-latency.html
/// Source: https://www.hecfblog.com/2025/04/daily-blog-809-testing-aws-log-latency.html
/// Source: https://www.hecfblog.com/2025/04/daily-blog-810-testing-aws-log-latency.html
/// Source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
pub(crate) static AWS_CLOUDTRAIL_IAM_EVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "aws_cloudtrail_iam_events",
    name: "AWS CloudTrail IAM Management Events",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("s3://<bucket>/AWSLogs/<account-id>/CloudTrail/us-east-1/<YYYY>/<MM>/<DD>/<account-id>_CloudTrail_us-east-1_<timestamp>_<random>.json.gz"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "AWS CloudTrail management events for IAM user, group, and policy changes. \
IAM is a global service — all IAM events (CreateUser, DeleteUser, AddUserToGroup, \
RemoveUserFromGroup, AttachUserPolicy, DetachUserPolicy, CreateAccessKey, DeleteAccessKey) \
are logged exclusively in us-east-1 regardless of the caller's region. \
ConsoleLogin events are region-specific (logged in the region of the login URL, not us-east-1). \
Empirical log delivery latency (HECF Blog, April 2025): ConsoleLogin ~90 sec, \
CreateAccessKey ~90 sec, CreateUser ~2 min, AddUserToGroup ~2 min, \
RemoveUserFromGroup ~1 min 45 sec — all within the 15-minute SLA and 5-minute \
critical-event target. \
Key forensic fields: userIdentity (who did it), sourceIPAddress (from where), \
requestParameters (what was changed), responseElements (result including new ARNs). \
Cross-reference with GuardDuty findings and AWS Config change items for full IR picture.",
    mitre_techniques: &[
        "T1136.003", // Create Account: Cloud Account
        "T1098.001", // Account Manipulation: Additional Cloud Credentials
        "T1078.004", // Valid Accounts: Cloud Accounts
    ],
    fields: AWS_CLOUDTRAIL_IAM_EVENTS_FIELDS,
    retention: Some("Configurable — default CloudTrail trail retains 90 days in S3; \
organization trails and custom S3 lifecycle policies may extend or shorten"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_aws_credentials"],
    sources: &[
        // Source: https://www.hecfblog.com/2025/04/daily-blog-808-testing-aws-log-latency.html (ConsoleLogin ~90 sec latency, region-specific)
        "https://www.hecfblog.com/2025/04/daily-blog-808-testing-aws-log-latency.html",
        // Source: https://www.hecfblog.com/2025/04/daily-blog-809-testing-aws-log-latency.html (CreateAccessKey ~90 sec latency in us-east-1)
        "https://www.hecfblog.com/2025/04/daily-blog-809-testing-aws-log-latency.html",
        // Source: https://www.hecfblog.com/2025/04/daily-blog-810-testing-aws-log-latency.html (CreateUser ~2 min latency)
        "https://www.hecfblog.com/2025/04/daily-blog-810-testing-aws-log-latency.html",
        // Source: https://www.hecfblog.com/2025/04/daily-blog-811-testing-aws-log-latency.html (AddUserToGroup ~2 min latency)
        "https://www.hecfblog.com/2025/04/daily-blog-811-testing-aws-log-latency.html",
        // Source: https://www.hecfblog.com/2025/04/daily-blog-812-testing-aws-log-latency.html (RemoveUserFromGroup ~1:45 latency)
        "https://www.hecfblog.com/2025/04/daily-blog-812-testing-aws-log-latency.html",
        // Source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html (event record schema)
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html",
        // Source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events (IAM events in us-east-1)
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events",
    ],
};
