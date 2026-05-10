//! Vehicle infotainment forensic artifact descriptors.
//!
//! Honda Accord (2016, USA) — Clarion-manufactured Android 4.2.2-based head unit
//! with Garmin navigation. Four SQLite databases on Partition4 (/data) contain
//! navigation history, trip telemetry, Bluetooth call/contact sync, and paired
//! device records.
//!
//! Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
//! Scripts: https://github.com/cheeky4n6monkey/Honda_Accord_2016_scripts

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Honda Accord RecentStops (Garmin navigation history) ─────────────────────

/// Field schema for the `history` table in RecentStops.db.
/// SQL: SELECT time, lat, lon, name FROM history ORDER BY time ASC;
/// Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
pub(crate) static HONDA_ACCORD_RECENTSTOPS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "time",
        value_type: ValueType::Timestamp,
        description: "Timestamp of the navigation stop entry; format not confirmed but \
            appears to be a numeric epoch value. Useful for establishing a timeline of \
            vehicle locations",
        is_uid_component: true,
    },
    FieldSchema {
        name: "lat",
        value_type: ValueType::Text,
        description: "Latitude coordinate of the stop location in decimal degrees",
        is_uid_component: false,
    },
    FieldSchema {
        name: "lon",
        value_type: ValueType::Text,
        description: "Longitude coordinate of the stop location in decimal degrees",
        is_uid_component: false,
    },
    FieldSchema {
        name: "name",
        value_type: ValueType::Text,
        description: "Name or label associated with the stop (e.g. address or POI name)",
        is_uid_component: false,
    },
];

pub(crate) static HONDA_ACCORD_RECENTSTOPS: ArtifactDescriptor = ArtifactDescriptor {
    id: "honda_accord_recentstops",
    name: "Honda Accord Garmin RecentStops (Navigation History)",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
    file_path: Some("/data/com.honda.displayaudio.navi/Garmin/sqlite/RecentStops.db"),
    scope: DataScope::System,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    retention: None,
    meaning: "Garmin navigation 'history' table in RecentStops.db on Honda Accord (2016) \
        Clarion Android-based infotainment. Contains timestamped latitude/longitude coordinates \
        documenting vehicle stops or navigation waypoints. Trigger for entry creation is not \
        confirmed but entries correlate with driven routes. High forensic value for placing a \
        vehicle at specific locations and times. The infotainment runs Android 4.2.2 on a \
        Clarion platform (ro.product.manufacturer=Clarion, ro.board.platform=r8a7791). \
        A companion quick_search_list.db exists at the same path but was found empty.",
    mitre_techniques: &[],
    fields: HONDA_ACCORD_RECENTSTOPS_FIELDS,
    triage_priority: TriagePriority::High,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html",
        "https://github.com/cheeky4n6monkey/Honda_Accord_2016_scripts",
    ],
    related_artifacts: &[
        "honda_accord_crm_eco_logs",
        "honda_accord_phonedb",
        "honda_accord_bluetooth",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Honda Accord CRM Eco Logs (trip telemetry) ──────────────────────────────

/// Field schema for the `eco_logs` table in crm.db.
/// SQL: SELECT _id, trip_date, trip_id, mileage, start_pos_time, start_pos_odo,
///      finish_pos_time, finish_pos_odo, fuel_used, driving_range
///      FROM eco_logs ORDER BY _id ASC;
/// Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
pub(crate) static HONDA_ACCORD_CRM_ECO_LOGS_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "_id",
        value_type: ValueType::Integer,
        description: "Auto-increment row identifier",
        is_uid_component: true,
    },
    FieldSchema {
        name: "trip_date",
        value_type: ValueType::Text,
        description: "Date of the trip leg",
        is_uid_component: false,
    },
    FieldSchema {
        name: "trip_id",
        value_type: ValueType::Integer,
        description: "Trip identifier grouping related journey legs",
        is_uid_component: false,
    },
    FieldSchema {
        name: "mileage",
        value_type: ValueType::Text,
        description: "Mileage for this trip leg (units not confirmed but usable for trending)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "start_pos_time",
        value_type: ValueType::Timestamp,
        description: "Timestamp when the trip leg started",
        is_uid_component: false,
    },
    FieldSchema {
        name: "start_pos_odo",
        value_type: ValueType::Text,
        description: "Odometer reading at trip start (units not confirmed)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "finish_pos_time",
        value_type: ValueType::Timestamp,
        description: "Timestamp when the trip leg ended",
        is_uid_component: false,
    },
    FieldSchema {
        name: "finish_pos_odo",
        value_type: ValueType::Text,
        description: "Odometer reading at trip end (units not confirmed)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "fuel_used",
        value_type: ValueType::Text,
        description: "Fuel consumed during the trip leg (units not confirmed)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "driving_range",
        value_type: ValueType::Text,
        description: "Driving range for the trip leg (units not confirmed but usable for trending)",
        is_uid_component: false,
    },
];

pub(crate) static HONDA_ACCORD_CRM_ECO_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "honda_accord_crm_eco_logs",
    name: "Honda Accord CRM Eco Logs (Trip Telemetry)",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
    file_path: Some("/data/com.honda.telematics.core/databases/crm.db"),
    scope: DataScope::System,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    retention: None,
    meaning: "Honda telematics 'eco_logs' table in crm.db on Honda Accord (2016) Clarion \
        Android-based infotainment. Logs timestamped journey legs with start/finish odometer \
        readings, mileage, fuel consumption, and driving range. Trip legs are grouped by \
        trip_id. Useful for establishing vehicle usage patterns and correlating trip times \
        with other evidence. Units for mileage, odometer, fuel, and range are not confirmed \
        but values are internally consistent and usable for trending analysis.",
    mitre_techniques: &[],
    fields: HONDA_ACCORD_CRM_ECO_LOGS_FIELDS,
    triage_priority: TriagePriority::Medium,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html",
        "https://github.com/cheeky4n6monkey/Honda_Accord_2016_scripts",
    ],
    related_artifacts: &[
        "honda_accord_recentstops",
        "honda_accord_phonedb",
        "honda_accord_bluetooth",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Honda Accord Phone DB (Bluetooth call history & contacts) ───────────────

/// Field schema for the `call_history` and `contact`/`contactnumber` tables in phonedb.db.
/// Call History SQL: SELECT _id, address, phonenum, calldate, calltype
///                   FROM call_history ORDER BY calldate ASC;
/// Contacts SQL: SELECT contact._id, contact.address, contact.firstName,
///               contact.lastName, contact.phonename, contactnumber.number,
///               contactnumber.numbertype
///               FROM contact JOIN contactnumber
///               ON contactnumber.contact_id = contact._id
///               ORDER BY contact._id ASC;
/// Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
pub(crate) static HONDA_ACCORD_PHONEDB_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "_id",
        value_type: ValueType::Integer,
        description: "Auto-increment row identifier",
        is_uid_component: true,
    },
    FieldSchema {
        name: "address",
        value_type: ValueType::Text,
        description: "MAC address of the Bluetooth device that synced this record",
        is_uid_component: false,
    },
    FieldSchema {
        name: "phonenum",
        value_type: ValueType::Text,
        description: "Phone number associated with the call (call_history table)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "calldate",
        value_type: ValueType::Timestamp,
        // Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
        description: "Call timestamp as milliseconds since 1 Jan 1970 (UTC). Displayed as \
            ISO-formatted string when parsed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "calltype",
        value_type: ValueType::Integer,
        description: "Call type indicator (observed values: 1, 2, 3). Likely maps to \
            incoming/outgoing/missed but exact mapping requires confirmation via call \
            charge records or device comparison",
        is_uid_component: false,
    },
    FieldSchema {
        name: "firstName",
        value_type: ValueType::Text,
        description: "Contact first name (from contact table JOIN)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "lastName",
        value_type: ValueType::Text,
        description: "Contact last name (from contact table JOIN)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "phonename",
        value_type: ValueType::Text,
        description: "Name of the phone that synced the contact (from contact table)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "contactnumber",
        value_type: ValueType::Text,
        description: "Contact phone number (from contactnumber table JOIN)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "contacttype",
        value_type: ValueType::Integer,
        description: "Contact number type; observed consistently as 3 in test data. \
            Likely maps to standard vCard TEL types",
        is_uid_component: false,
    },
];

pub(crate) static HONDA_ACCORD_PHONEDB: ArtifactDescriptor = ArtifactDescriptor {
    id: "honda_accord_phonedb",
    name: "Honda Accord Phone DB (Bluetooth Call History & Contacts)",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
    file_path: Some("/data/com.clarion.bluetooth/databases/phonedb.db"),
    scope: DataScope::User,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    retention: None,
    meaning: "Clarion Bluetooth 'call_history', 'contact', and 'contactnumber' tables in \
        phonedb.db on Honda Accord (2016) infotainment. Records call history and contacts \
        synced from paired phones via Bluetooth. Call timestamps are UNIX milliseconds (UTC). \
        The 'address' field contains the Bluetooth MAC of the syncing device. A Write-Ahead-Log \
        (phonedb.db-wal) may contain additional uncommitted records — parse both with and \
        without the WAL for completeness. High forensic value for communications evidence \
        and device attribution.",
    mitre_techniques: &[],
    fields: HONDA_ACCORD_PHONEDB_FIELDS,
    triage_priority: TriagePriority::High,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html",
        "https://github.com/cheeky4n6monkey/Honda_Accord_2016_scripts",
    ],
    related_artifacts: &[
        "honda_accord_bluetooth",
        "honda_accord_recentstops",
        "honda_accord_crm_eco_logs",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Honda Accord Bluetooth Settings (paired devices) ────────────────────────

/// Field schema for the `bluetooth_device` table in bluetoothsettings.db.
/// SQL: SELECT device_bank, device_addr, device_name FROM bluetooth_device
///      ORDER BY device_bank ASC;
/// Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
pub(crate) static HONDA_ACCORD_BLUETOOTH_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "device_bank",
        value_type: ValueType::Integer,
        description: "Index/bank number for each paired device entry",
        is_uid_component: true,
    },
    FieldSchema {
        name: "device_addr",
        value_type: ValueType::Text,
        description: "Bluetooth MAC address of the paired device",
        is_uid_component: false,
    },
    FieldSchema {
        name: "device_name",
        value_type: ValueType::Text,
        description: "User-visible name of the paired Bluetooth device (e.g. phone model \
            or user-assigned name)",
        is_uid_component: false,
    },
];

pub(crate) static HONDA_ACCORD_BLUETOOTH: ArtifactDescriptor = ArtifactDescriptor {
    id: "honda_accord_bluetooth",
    name: "Honda Accord Bluetooth Settings (Paired Devices)",
    artifact_type: ArtifactType::DatabaseEntry,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html
    file_path: Some("/data/com.clarion.bluetooth/databases/bluetoothsettings.db"),
    scope: DataScope::System,
    os_scope: OsScope::Android,
    decoder: Decoder::Identity,
    retention: None,
    meaning:
        "Clarion Bluetooth 'bluetooth_device' table in bluetoothsettings.db on Honda \
        Accord (2016) infotainment. Records Bluetooth MAC addresses and device names of all \
        phones/devices that have been paired with the vehicle. A companion 'speed_dial' table \
        exists but was found empty. Data is consistent with the paired_device_list.txt found \
        at /system/alps/evolution/paired_device_list.txt on Partition3. Useful for identifying \
        which phones connected to the vehicle and correlating with phonedb.db call/contact records.",
    mitre_techniques: &[],
    fields: HONDA_ACCORD_BLUETOOTH_FIELDS,
    triage_priority: TriagePriority::Medium,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2021/03/monkey-test-drives-honda-accord.html",
        "https://github.com/cheeky4n6monkey/Honda_Accord_2016_scripts",
    ],
    related_artifacts: &[
        "honda_accord_phonedb",
        "honda_accord_recentstops",
        "honda_accord_crm_eco_logs",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Garmin nuvi Voice Log (TTS navigation instructions) ─────────────────────

/// Field schema for parsed lines from vpm_log_all.log on Garmin nuvi devices.
/// Each log line follows the format:
///   D[YYYY/MM/DD HH:MM:SS] {hex_id} [source_file:function:line] Message
/// Source: https://cheeky4n6monkey.blogspot.com/2020/05/recovering-and-replaying-garmin-voice.html
pub(crate) static GARMIN_NUVI_VOICE_LOG_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "Log entry timestamp in D[YYYY/MM/DD HH:MM:SS] format. Uses Garmin \
            epoch (seconds since 31 Dec 1989). Add 631065600 to convert to UNIX epoch",
        is_uid_component: true,
    },
    FieldSchema {
        name: "hex_id",
        value_type: ValueType::Text,
        description: "4-byte hex identifier (possibly process or thread ID)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "source_function",
        value_type: ValueType::Text,
        description: "Source code reference indicating which TTS subsystem generated the entry \
            (e.g. vpm_tts_parse.c:vpm_tts_parse:3770 for navigation phrases, \
            vpm_tts_log.c:vpm_tts_log_phonetics:277 for phonetic output)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "voice_string",
        value_type: ValueType::Text,
        description: "The spoken navigation instruction text or phonetic representation. \
            Navigation phrases contain template variables like $USR_TO_NEXT_ROAD. \
            Phonetic entries use IPA-like notation for text-to-speech synthesis. \
            Both types together reconstruct the turn-by-turn directions given to the driver",
        is_uid_component: false,
    },
    FieldSchema {
        name: "mdb_lang",
        value_type: ValueType::Integer,
        description: "Language identifier from the map database (e.g. 23 observed in test data). \
            Indicates which language pack was used for voice synthesis",
        is_uid_component: false,
    },
];

pub(crate) static GARMIN_NUVI_VOICE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "garmin_nuvi_voice_log",
    name: "Garmin nuvi GPS Voice Instruction Log (vpm_log_all)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2020/05/recovering-and-replaying-garmin-voice.html
    file_path: Some("Voice/logs/vpm_log_all.log"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    retention: None,
    meaning: "Garmin nuvi GPS text-to-speech voice instruction log found on the FAT32 partition \
        at Voice/logs/vpm_log_all.log. Contains chronologically ordered, timestamped spoken \
        navigation instructions. Each line records either a navigation phrase (e.g. 'Keep right', \
        'Turn left') with template variables, or the corresponding phonetic representation used \
        for TTS synthesis. Tested on Garmin nuvi 56LM but may apply to other Garmin models. \
        The device typically has two partitions: FAT16 (128 MB) and FAT32 (main storage with \
        GPX tracklogs under Garmin/ and voice logs under Voice/). Timestamps use Garmin epoch \
        (seconds since 31 Dec 1989; add 631065600 for UNIX epoch). High forensic value for \
        reconstructing routes and navigation history from damaged or recovered GPS devices. \
        Voice strings can be converted to audio using espeak-ng for audible playback of the \
        navigation instructions.",
    mitre_techniques: &[],
    fields: GARMIN_NUVI_VOICE_LOG_FIELDS,
    triage_priority: TriagePriority::High,
    sources: &[
        "https://cheeky4n6monkey.blogspot.com/2020/05/recovering-and-replaying-garmin-voice.html",
        "https://github.com/cheeky4n6monkey/4n6-scripts",
    ],
    related_artifacts: &[],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};
