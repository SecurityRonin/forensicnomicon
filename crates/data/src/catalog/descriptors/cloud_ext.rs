//! Cloud service artifact descriptors (Google Takeout, AWS CloudTrail, etc.).
//!
//! These artifacts represent data exported from cloud services via official
//! takeout/export mechanisms. They are cross-platform (OsScope::All) since
//! the data lives server-side and the export is OS-agnostic.
//!
//! One artifact here is not an export: the Security-log record a Microsoft
//! Entra joined Windows endpoint writes when a peer authenticates with a cloud
//! identity. It is filed with the cloud artifacts because the identity, the
//! certificate and the tenant belong to Entra — only the log file is Windows',
//! so that descriptor carries a Windows `OsScope` while the rest are
//! `OsScope::All`.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Google Takeout Location Records ─────────────────────────────────────────

/// Field schema for Records.json location elements.
/// Source: <https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html>
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
/// Source: <https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html>
pub(crate) static GOOGLE_TAKEOUT_LOCATION_RECORDS: ArtifactDescriptor = ArtifactDescriptor {
    id: "google_takeout_location_records",
    name: "Google Takeout Location Records",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires user-initiated Takeout export — not directly extractable from device",
        "User can delete location history server-side",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Static export file; persists as long as user retains it",
};

// ── Google Takeout Semantic Location History ─────────────────────────────────

/// Field schema for Semantic Location History monthly JSON files.
/// Source: <https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html>
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
/// Source: <https://cheeky4n6monkey.blogspot.com/2022/02/monkey-attempts-to-digest-some-google.html>
pub(crate) static GOOGLE_TAKEOUT_SEMANTIC_LOCATION_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "google_takeout_semantic_location_history",
    name: "Google Takeout Semantic Location History",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Server-side inferences may be inaccurate",
        "Requires user-initiated Takeout export",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Static export file; persists as long as user retains it",
};

// ── AWS CloudTrail IAM Events ───────────────────────────────────────────────

/// Field schema for AWS CloudTrail IAM management events.
/// Source: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
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
///
/// All well within the 15-minute SLA and the 5-minute target for critical events.
/// Note: ConsoleLogin events are region-specific (logged in the region of the login
/// URL), unlike IAM management events which are always in us-east-1.
///
/// Source: <https://www.hecfblog.com/2025/04/daily-blog-808-testing-aws-log-latency.html>
/// Source: <https://www.hecfblog.com/2025/04/daily-blog-809-testing-aws-log-latency.html>
/// Source: <https://www.hecfblog.com/2025/04/daily-blog-810-testing-aws-log-latency.html>
/// Source: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
pub(crate) static AWS_CLOUDTRAIL_IAM_EVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "aws_cloudtrail_iam_events",
    name: "AWS CloudTrail IAM Management Events",
    artifact_type: ArtifactLocation::File,
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
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "CloudTrail logs can be disabled or deleted by an attacker with sufficient IAM permissions",
        "Log delivery latency of 1-3 minutes means near-real-time events may not yet appear",
        "S3 bucket policy changes can prevent log delivery; check CloudTrail status before concluding absence",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "CloudTrail logs persist in S3 per retention policy (default indefinite); events appear within ~2 min of the action",
};

// ── Microsoft Entra Joined Endpoint Logon (Security 4624 via PKU2U) ──────────

/// Field schema for a Security event 4624 written on a Microsoft Entra joined
/// endpoint, where the session was authenticated by the PKU2U SSP under the
/// NegoExtender package instead of by Kerberos or NTLM.
///
/// Names in parentheses are the raw `EventData/Data@Name` attributes an EVTX
/// parser sees; the unparenthesised name is the field's snake_case catalog name.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4622>
/// Source: <https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localusersandgroups>
pub(crate) static EVTX_ENTRA_PKU2U_LOGON_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4624 — a logon session was created on this host. The cloud-identity variant is not a separate event id; it is read out of the authentication fields below",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the destination host created the session (UTC). On a tenancy with no on-premises directory this is the only authentication time available — there is no domain controller writing 4768/4769 to corroborate it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_process_name",
        value_type: ValueType::Text,
        description: "(LogonProcessName) The trusted logon process that handled the logon, under the name it registered with the LSA (event 4611). A PKU2U logon carries the PKU2U SSP's own name, Pku2uSsp — the string ships inside %SystemRoot%\\System32\\pku2u.dll — where an NTLM logon carries NtLmSsp, a Kerberos logon Kerberos, a console logon User32 and a service/API logon Advapi. Read it together with authentication_package_name: that pair, not the account name, is what separates a cloud-identity peer logon from NTLM",
        is_uid_component: false,
    },
    FieldSchema {
        name: "authentication_package_name",
        value_type: ValueType::Text,
        description: "(AuthenticationPackageName) NegoExtender is the negoexts.dll package — Microsoft lists it verbatim as 'C:\\Windows\\system32\\negoexts.DLL : NegoExtender' among the packages the LSA loads, alongside 'pku2u.DLL : pku2u'. NegoExts negotiates SSPs other than NTLM and Kerberos and is what calls the PKU2U SSP, so this value in place of NTLM, Kerberos or Negotiate says the identity was proven with an Entra-issued certificate rather than a domain ticket or a password hash. Treat NegoExtender as the documented anchor of the pair",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_user_name",
        value_type: ValueType::Text,
        description: "(TargetUserName) Account the session was created for. A Microsoft Entra principal on a Windows device is named in the AzureAD\\<UPN> form Microsoft documents for group and logon configuration (for example AzureAD\\user1@contoso.com), so the tenant is the UPN suffix. Take the identity and the tenant from here, never from the domain field",
        is_uid_component: true,
    },
    FieldSchema {
        name: "target_domain_name",
        value_type: ValueType::Text,
        description: "(TargetDomainName) Microsoft documents this field as a NetBIOS or DNS domain name, or the computer name for a local account — an Entra-only endpoint has no Active Directory domain for it to carry, so it does not identify the tenant. A cloud-logon filter written against domain names silently drops these records; filter on the logon-process/package pair instead",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_user_sid",
        value_type: ValueType::Text,
        description: "(TargetUserSid) SID of the principal the session belongs to. A Microsoft Entra principal serialises under the Entra identity authority as S-1-12-1-<four subauthorities>, which Microsoft's own local-group configuration examples set against the on-premises S-1-5-21-<domain>-<RID> form — so a parser keying on the raw SID never encounters the string 'AzureAD'. Resolve the SID to a directory object through the securityIdentifier property in Microsoft Graph to put a name to it",
        is_uid_component: true,
    },
    FieldSchema {
        name: "logon_type",
        value_type: ValueType::UnsignedInt,
        description: "(LogonType) The access vector, unchanged by the identity provider: 3 Network (SMB and similar), 10 RemoteInteractive (Remote Desktop), 2 Interactive at the console. PKU2U carries peer-to-peer access between devices, so device-to-device Entra activity lands mostly as 3 and 10 — use it to place the record on a lateral-movement timeline",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_guid",
        value_type: ValueType::Guid,
        description: "(LogonGuid) All-zero {00000000-0000-0000-0000-000000000000} when the value was not captured. PKU2U settles between the two peers with certificates and no KDC, so there is no ticket event to join to and the domain-style 4624-to-4769 correlation is unavailable. Do not read the zero GUID as a missing or tampered record; reach for the source address and the peer's own logs instead",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ip_address",
        value_type: ValueType::Text,
        description: "(IpAddress) Source network address of the peer that authenticated — the attribution field for device-to-device access, and the one to trust over workstation_name when the logon type is 10",
        is_uid_component: false,
    },
    FieldSchema {
        name: "workstation_name",
        value_type: ValueType::Text,
        description: "(WorkstationName) Machine name supplied for the logon attempt. Populated per authentication context, and its meaning flips by logon type (see evtx_security) — corroborate with ip_address before naming a source host",
        is_uid_component: false,
    },
    FieldSchema {
        name: "target_logon_id",
        value_type: ValueType::Text,
        description: "(TargetLogonId) Hexadecimal id of the created session. Joins this logon to the 4634/4647 logoff and to 4672 on the same host, which is how session duration is bounded when no directory-side record exists",
        is_uid_component: false,
    },
];

/// Microsoft Entra joined endpoint logon — Security 4624 authenticated by PKU2U
/// under the NegoExtender package.
///
/// PKU2U is an authentication protocol built on Kerberos v5 messages and the
/// Kerberos GSS-API mechanism that deliberately does not use a KDC; Windows
/// implements it as a Security Support Provider (pku2u.dll) for peer-to-peer
/// authentication between computers that are not members of a domain. The
/// Negotiate package reaches it through its extension SSP negoexts.dll
/// (NEGOEX, specified in [MS-NEGOEX] as a mechanism SPNEGO can negotiate):
/// when a device is configured to accept online identities, negoexts.dll calls
/// the PKU2U SSP, which obtains a local certificate, exchanges policy with the
/// peer, and binds the validated certificate to a security token. Microsoft
/// states this path is required for Microsoft Entra joined devices, which sign
/// in with an online identity and are issued certificates by Microsoft Entra
/// ID.
///
/// The forensic consequence is that a cloud-only tenancy leaves a logon record
/// whose shape no on-premises assumption matches: the authentication fields
/// name PKU2U and NegoExtender rather than Kerberos or NTLM, the principal is
/// an Entra SID in the S-1-12-1 authority range, the account is written in the
/// AzureAD\<UPN> form, and the Logon GUID is zero because no ticket was issued
/// anywhere to correlate against. There is also no domain controller log to
/// fall back on — the host's own Security channel is the whole record.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn759411%28v=ws.11%29>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-allow-pku2u-authentication-requests-to-this-computer-to-use-online-identities>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4622>
/// Source: <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/0ad7a003-ab56-4839-a204-b555ca6759a2>
pub(crate) static EVTX_ENTRA_PKU2U_LOGON: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_entra_pku2u_logon",
    name: "Microsoft Entra Joined Endpoint Logon (Security 4624, PKU2U/NegoExtender)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Host-side record of a logon to a Microsoft Entra joined Windows endpoint that was \
authenticated peer-to-peer with a cloud identity instead of against a directory. The event id is \
the ordinary 4624; what marks it is the Detailed Authentication block — Logon Process Pku2uSsp \
(the name the PKU2U SSP in %SystemRoot%\\System32\\pku2u.dll registers with the LSA) paired with \
Authentication Package NegoExtender (negoexts.dll, which Microsoft lists among the LSA security \
packages and which negotiates SSPs other than NTLM and Kerberos). PKU2U carries Kerberos v5 \
messages without a KDC: negoexts.dll calls the PKU2U SSP, a local certificate is exchanged and \
validated with the peer, and the validated certificate is bound to a security token — the path \
Microsoft documents as required for Entra joined devices, which are issued certificates by \
Microsoft Entra ID. Three further fields break on-premises assumptions. TargetUserSid is a \
Microsoft Entra SID in the S-1-12-1-<four subauthorities> authority form rather than \
S-1-5-21-<domain>-<RID>, so SID-based filters written for AD never match and the string 'AzureAD' \
never appears in the SID; resolve it through the directory object's securityIdentifier in \
Microsoft Graph. TargetUserName carries the AzureAD\\<UPN> form Microsoft documents for Entra \
accounts on Windows, which is where the tenant is readable — TargetDomainName has no Active \
Directory domain to name and must not be used as the tenant. LogonGuid is all zeros because no \
ticket was issued by any KDC, so the 4624-to-4769 correlation available for domain logons does not \
exist here; bound the session with TargetLogonId against 4634/4647 and attribute the source with \
IpAddress. On an Entra-only estate this pair is expected traffic and the endpoint's own Security \
channel is the entire authentication record; the same pair on a host that should only ever \
authenticate against an on-premises domain is the finding.",
    mitre_techniques: &[
        "T1078.004", // Valid Accounts: Cloud Accounts
        "T1021.001", // Remote Services: Remote Desktop Protocol
    ],
    fields: EVTX_ENTRA_PKU2U_LOGON_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; the record survives only while the configured log window holds it"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_security",
        "evtx_ntlm",
        "evtx_kerberos_tgt_request",
        "evtx_rdp_inbound",
    ],
    sources: &[
        // Microsoft — PKU2U Protocol Overview: Kerberos v5 messages and the Kerberos GSS-API
        // mechanism without a KDC, implemented as an SSP, peer-to-peer authentication between
        // non-domain computers; negoexts.dll (the Negotiate extension SSP) calls the PKU2U SSP,
        // which obtains a local certificate and exchanges policy with the peer:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn759411%28v=ws.11%29",
        // Microsoft — "Network security: Allow PKU2U authentication requests to this computer to
        // use online identities": the policy that gates the mechanism, its GPO location, the
        // "required for Microsoft Entra joined devices ... issued certificates by Microsoft Entra
        // ID" statement, unconfigured-behaves-as-disabled on domain-joined devices, and PKU2U
        // disabled by default on Windows Server (which breaks RDP to Entra joined devices):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-allow-pku2u-authentication-requests-to-this-computer-to-use-online-identities",
        // Microsoft — Event 4624: the Logon Process / Authentication Package / Logon GUID /
        // Account Domain field semantics, the logon-type table, and the statement that an
        // uncaptured Logon GUID renders as {00000000-0000-0000-0000-000000000000}:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
        // Microsoft — Event 4622: the LSA security-package list, verbatim
        // "C:\Windows\system32\negoexts.DLL : NegoExtender" and
        // "C:\Windows\system32\pku2u.DLL : pku2u" — the documented package names behind the pair:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4622",
        // Microsoft — Event 4611: the Logon Process field names a logon process registered with
        // the LSA, which is what the 4624 Logon Process value refers back to:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4611",
        // Microsoft — SSPI architecture: NegoExts is an authentication package that negotiates
        // SSPs other than NTLM and Kerberos (negoexts.dll); the PKU2U SSP is pku2u.dll and enables
        // peer-to-peer authentication between non-domain computers; SSPs under NegoExts are not
        // stand-alone, so a failure inside NegoExts has no renegotiation or fallback:
        "https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture",
        // Microsoft — LocalUsersAndGroups Policy CSP: the AzureAD\<userUPN> account-name form for
        // Entra accounts on Windows, and Entra group SIDs written as
        // S-1-12-1-<four subauthorities> against on-premises S-1-5-21-... SIDs, obtainable from
        // the securityIdentifier property via Microsoft Graph:
        "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localusersandgroups",
        // [MS-NEGOEX] — SPNEGO Extended Negotiation (NEGOEX) Security Mechanism: the mechanism
        // SPNEGO negotiates, which selects a common authentication protocol from metadata:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/0ad7a003-ab56-4839-a204-b555ca6759a2",
        // IETF draft-zhu-pku2u-09 — Public Key Cryptography Based User-to-User Authentication,
        // the protocol Windows implements in the PKU2U SSP:
        "https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Microsoft's 4624 reference names NTLM, Kerberos and Negotiate as the common authentication \
         packages and does not enumerate the PKU2U pair. NegoExtender is documented in the event-4622 \
         package list; Pku2uSsp is the name the PKU2U SSP itself carries (the string is present in \
         %SystemRoot%\\System32\\pku2u.dll). Confirm both against the examined build before a \
         detection is written on the exact strings",
        "On an Entra joined estate this pair is expected, not anomalous — it is the documented path \
         for remote connections to an Entra joined device. The signal is the pair appearing where the \
         host should only authenticate against an on-premises domain, or against an account the \
         tenant does not own",
        "Absence is often a policy fact rather than an activity fact: the PKU2U online-identities \
         policy is unconfigured (equivalent to disabled) on domain-joined devices and PKU2U is \
         disabled by default on Windows Server, in which case the logon never happens and no record \
         is written. Check the policy state before reading an empty result as no access",
        "The SSPs under NegoExts are not stand-alone, and Microsoft documents that a failure inside \
         NegoExts offers no renegotiation or fallback — so a failed cloud logon surfaces as a failure \
         record rather than as a downgraded NTLM success within the same exchange",
        "Logon GUID is zero, so the correlation to KDC ticket events that anchors domain logons is \
         unavailable; session bounding depends on TargetLogonId within this host's log and source \
         attribution on IpAddress plus the peer's own client-side channels",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Circular EVTX channel — the record is lost when the Security log wraps, and no directory-side copy exists in a cloud-only tenancy",
};
