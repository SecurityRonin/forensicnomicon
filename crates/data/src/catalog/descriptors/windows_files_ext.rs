//! Extended Windows file and directory artifact descriptors — Phase 2.
//!
//! Sources: KAPE targets (EricZimmerman/KapeFiles), Velociraptor artifact definitions,
//! SANS FOR508, BlueTeamLabs, DFIR.blog, 13cubed research.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Browser History ───────────────────────────────────────────────────────────

pub(crate) static CHROME_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_history",
    name: "Chrome Browsing History (SQLite)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Google\Chrome\User Data\*\History"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database containing Chrome browsing history, downloads, and search queries. Key tables: urls (visited sites with timestamps), downloads (file downloads with source URL and target path), keyword_search_terms (typed search queries). Malware distribution via browser and C2 beacon URLs appear here.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Visited URL", is_uid_component: true },
        FieldSchema { name: "visit_time", value_type: ValueType::Timestamp, description: "Visit timestamp (WebKit microseconds)", is_uid_component: false },
        FieldSchema { name: "title", value_type: ValueType::Text, description: "Page title at visit time", is_uid_component: false },
    ],
    retention: Some("No automatic limit; grows until profile cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["chrome_login_data", "chrome_web_data"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Chrome.tkape",
        "https://www.sans.org/blog/google-chrome-forensics/",
        "https://13cubed.com/downloads/Windows_Forensic_Analysis_Poster.pdf",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["History may be cleared; private browsing not recorded; timestamps are WebKit microseconds requiring conversion"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten by browser activity; no size limit",
};

pub(crate) static CHROME_WEB_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_web_data",
    name: "Chrome Web Data (SQLite)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Web Data"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database storing Chrome autofill form data, saved payment cards (DPAPI-encrypted), and search engine history. Reveals identifiers (names, addresses, phone numbers) typed into web forms even after browsing history is cleared.",
    mitre_techniques: &["T1555.003"],
    fields: &[
        FieldSchema { name: "name", value_type: ValueType::Text, description: "Autofill field name", is_uid_component: true },
        FieldSchema { name: "value", value_type: ValueType::Text, description: "Autofill field value", is_uid_component: false },
    ],
    retention: Some("Persists until profile cleared"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["chrome_history", "chrome_login_data"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Chrome.tkape",
        "https://www.sans.org/blog/google-chrome-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "User can clear autofill data via browser settings",
        "Encrypted payment data requires DPAPI key to decrypt",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "SQLite database updated as user types form data; entries persist until cleared",
};

pub(crate) static EDGE_CHROMIUM_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_chromium_history",
    name: "Edge (Chromium) Browsing History (SQLite)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database with Edge Chromium browsing history. Identical schema to Chrome History (same Chromium codebase). Critical on enterprise networks where Edge is the corporate browser and may hold intranet portal access and SharePoint navigation.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Visited URL", is_uid_component: true },
        FieldSchema { name: "visit_time", value_type: ValueType::Timestamp, description: "Visit timestamp (WebKit microseconds)", is_uid_component: false },
    ],
    retention: Some("No automatic limit; grows until profile cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["edge_chromium_login_data", "chrome_history"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/MicrosoftEdge.tkape",
        "https://www.sans.org/blog/microsoft-edge-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Same caveats as Chrome History; profile switching means not all activity in default profile"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten by browser activity; no size limit",
};

pub(crate) static EDGE_CHROMIUM_LOGIN_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_chromium_login_data",
    name: "Edge (Chromium) Login Data (SQLite)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Login Data"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database with DPAPI-encrypted saved credentials from Edge (Chromium). Same schema as Chrome Login Data. On managed corporate devices, Edge may store SSO credentials for internal applications, making this high-value for lateral movement intelligence.",
    mitre_techniques: &["T1555.003"],
    fields: &[
        FieldSchema { name: "origin_url", value_type: ValueType::Text, description: "URL the credential is for", is_uid_component: true },
        FieldSchema { name: "username_value", value_type: ValueType::Text, description: "Stored username", is_uid_component: false },
    ],
    retention: Some("Persists until credential cleared or profile deleted"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["edge_chromium_history", "dpapi_masterkey_user"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/MicrosoftEdge.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["DPAPI encryption requires user context or masterkey to decrypt; credential presence proves account storage"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Persists until credential explicitly removed",
};

pub(crate) static FIREFOX_PLACES: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_places",
    name: "Firefox places.sqlite (History + Bookmarks)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Core Firefox history and bookmarks SQLite database. Tables: moz_places (all visited URLs with frecency score), moz_historyvisits (timestamped visit records with transition types), moz_bookmarks (saved bookmarks). Transition type 0=typed, 1=clicked link — distinguishes deliberate navigation from passive redirects.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Visited URL", is_uid_component: true },
        FieldSchema { name: "last_visit_date", value_type: ValueType::Timestamp, description: "Last visit timestamp (Unix microseconds)", is_uid_component: false },
        FieldSchema { name: "visit_count", value_type: ValueType::UnsignedInt, description: "Total number of visits", is_uid_component: false },
    ],
    retention: Some("No automatic limit; grows until profile cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["firefox_form_history", "firefox_session_restore", "firefox_logins"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Firefox.tkape",
        "https://www.sans.org/blog/firefox-history-and-what-it-tells-you/",
        "https://nicoleibrahim.com/mozilla-firefox-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["History may be manually cleared; private browsing not recorded; frecency scoring can obscure visit count accuracy"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten by browser activity; no size limit",
};

pub(crate) static FIREFOX_FORM_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_form_history",
    name: "Firefox formhistory.sqlite",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\formhistory.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Firefox autocomplete form-field history database. Records text typed into web form fields (search boxes, login fields, input boxes) with timestamps and usage counts. Reveals search terms, usernames, and any text ever typed into web forms in Firefox.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "fieldname", value_type: ValueType::Text, description: "HTML form field name", is_uid_component: true },
        FieldSchema { name: "value", value_type: ValueType::Text, description: "Text typed into the field", is_uid_component: false },
    ],
    retention: Some("Entries older than 180 days removed automatically"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["firefox_places", "firefox_logins"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Firefox.tkape",
        "https://nicoleibrahim.com/mozilla-firefox-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "User can clear form history via browser settings",
        "Private browsing sessions do not write here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "SQLite database updated per form-field input; entries persist until cleared",
};

pub(crate) static FIREFOX_SESSION_RESTORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_session_restore",
    name: "Firefox sessionstore.jsonlz4 (Session Restore)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\sessionstore.jsonlz4"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "LZ4-compressed JSON snapshot of all open Firefox tabs at last session close. Contains full URLs, scroll positions, and POST data for in-progress forms. Provides evidence of browser state at crash/shutdown — invaluable when history has been cleared but session was not manually saved.",
    mitre_techniques: &["T1217"],
    fields: &[
        FieldSchema { name: "url", value_type: ValueType::Text, description: "URL of open tab at session close", is_uid_component: true },
        FieldSchema { name: "title", value_type: ValueType::Text, description: "Tab title at session close", is_uid_component: false },
    ],
    retention: Some("Overwritten on each browser restart; previous version in sessionstore-backups/"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["firefox_places", "firefox_form_history"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Firefox.tkape",
        "https://nicoleibrahim.com/mozilla-firefox-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Only captures session at last graceful close; data lost if disabled or session-saving turned off"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Overwritten on each Firefox session close",
};

// ── PowerShell ────────────────────────────────────────────────────────────────

pub(crate) static PSREADLINE_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "psreadline_history",
    name: "PSReadLine Console History (User)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Plain-text file of all interactive PowerShell commands typed in the console, one command per line. Persists across sessions. Critical for attacker TTP reconstruction — commands including credential harvesting, lateral movement, and C2 beacon setup appear verbatim with no truncation.",
    mitre_techniques: &["T1059.001"],
    fields: &[
        FieldSchema { name: "command", value_type: ValueType::Text, description: "PowerShell command entered interactively", is_uid_component: true },
    ],
    retention: Some("Default 4096 lines; configurable via $MaximumHistoryCount"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["psreadline_history_system", "powershell_history", "evtx_powershell"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/PowerShellConsole.tkape",
        "https://www.sans.org/blog/powershell-forensics-auditing/",
        "https://13cubed.com/downloads/Windows_Forensic_Analysis_Poster.pdf",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["User can manually edit or clear file; oldest entries evicted at limit; does not capture non-interactive PS sessions"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Oldest lines evicted at 4096-line limit",
};

pub(crate) static PSREADLINE_HISTORY_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "psreadline_history_system",
    name: "PSReadLine Console History (SYSTEM account)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "PSReadLine history for the SYSTEM account. Attackers who escalate to SYSTEM and run PowerShell interactively leave commands here. Especially relevant for scheduled task abuse, WMI persistence scripts run as SYSTEM, and services spawning cmd/PS shells.",
    mitre_techniques: &["T1059.001"],
    fields: &[
        FieldSchema { name: "command", value_type: ValueType::Text, description: "PowerShell command entered interactively as SYSTEM", is_uid_component: true },
    ],
    retention: Some("Default 4096 lines; configurable via $MaximumHistoryCount"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["psreadline_history", "evtx_powershell", "evtx_task_scheduler"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/PowerShellConsole.tkape",
        "https://www.sans.org/blog/powershell-forensics-auditing/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Only populated when SYSTEM runs interactive PS; many SYSTEM PS sessions are non-interactive"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Oldest lines evicted at 4096-line limit",
};

pub(crate) static POWERSHELL_TRANSCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_transcripts",
    name: "PowerShell Transcript Logs",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\Documents"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "PowerShell transcript files (PowerShell_transcript.*.txt) generated when script block transcription is enabled via Group Policy or $Transcript. Contain timestamped full session output including command output — richer than PSReadLine history. Filenames include hostname and datetime. Malware cleanup operations often fail to delete these.",
    mitre_techniques: &["T1059.001"],
    fields: &[
        FieldSchema { name: "command", value_type: ValueType::Text, description: "PowerShell command with full output transcript", is_uid_component: true },
        FieldSchema { name: "username", value_type: ValueType::Text, description: "User context for the transcript session", is_uid_component: false },
    ],
    retention: Some("Persistent; accumulate indefinitely unless cleared by policy"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["psreadline_history", "evtx_powershell"],
    sources: &[
        "https://www.sans.org/blog/powershell-forensics-auditing/",
        "https://devblogs.microsoft.com/powershell/powershell-the-blue-team/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Requires transcript policy to be enabled; attacker may disable policy before activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Accumulate indefinitely; not auto-rotated",
};

// ── Remote Access Tools ───────────────────────────────────────────────────────

pub(crate) static TEAMVIEWER_CONNECTION_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "teamviewer_connection_log",
    name: "TeamViewer Incoming Connections Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Program Files*\TeamViewer\connections_incoming.txt"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Plain-text log of all inbound TeamViewer sessions with partner ID, display name, connection timestamps (start and end), and connection type. Critical for establishing timeline of remote access. Partner IDs can be traced back to accounts via TeamViewer's support portal.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "partner_id", value_type: ValueType::Text, description: "TeamViewer ID of the remote party", is_uid_component: true },
        FieldSchema { name: "start_time", value_type: ValueType::Timestamp, description: "Session start timestamp", is_uid_component: false },
        FieldSchema { name: "end_time", value_type: ValueType::Timestamp, description: "Session end timestamp", is_uid_component: false },
    ],
    retention: Some("Persists; appended with each connection"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["teamviewer_app_log"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/TeamViewer.tkape",
        "https://www.kroll.com/en/insights/publications/cyber/teamviewer-forensics",
        "https://dfir.blog/teamviewer-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["File may be deleted by attacker; timestamps correlate with partner ID that can be traced to account"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Appended per session; not auto-cleared",
};

pub(crate) static TEAMVIEWER_APP_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "teamviewer_app_log",
    name: "TeamViewer Application Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\TeamViewer\TeamViewer*_Logfile.log"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Verbose TeamViewer application log with session details, negotiated encryption, file transfers, and connection events. Complements connections_incoming.txt with richer diagnostic data. File transfer events and remote print spooling events are logged here.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "event", value_type: ValueType::Text, description: "TeamViewer log event description", is_uid_component: true },
    ],
    retention: Some("Rotated; multiple dated log files may exist"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["teamviewer_connection_log"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/TeamViewer.tkape",
        "https://dfir.blog/teamviewer-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "TeamViewer is widely used legitimately — distinguishing attacker use requires context",
        "Logs rotate based on size limit",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Application log file with size-based rotation",
};

pub(crate) static ANYDESK_TRACE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_trace_user",
    name: "AnyDesk Trace Log (User)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\AnyDesk\ad.trace"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Primary AnyDesk log file for per-user installation. Contains session events: incoming/outgoing connection requests, authentication attempts, session open/close with timestamps, remote host alias or ID, and file transfer events. AnyDesk is heavily abused in BEC/ransomware campaigns for persistent remote access.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "anydesk_id", value_type: ValueType::Text, description: "Remote AnyDesk client ID", is_uid_component: true },
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Log event timestamp", is_uid_component: false },
    ],
    retention: Some("Rotated at size limit; ad.trace.old retains previous session"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["anydesk_trace_system", "anydesk_connection_trace"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape",
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a",
        "https://dfir.blog/anydesk-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Rotated at size limit; attacker may clear ad.trace; session IDs in log can be used to request records from AnyDesk"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated at size limit; .old retains previous",
};

pub(crate) static ANYDESK_TRACE_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_trace_system",
    name: "AnyDesk Service Trace Log (System)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\AnyDesk\ad_svc.trace"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "AnyDesk service-mode (unattended access) log file. Generated when AnyDesk is installed as a Windows service for persistent access without user login. Most relevant for detecting unattended persistent backdoor installations. Records service start/stop, incoming sessions, and policy enforcement.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "anydesk_id", value_type: ValueType::Text, description: "Remote AnyDesk client ID", is_uid_component: true },
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "Log event timestamp", is_uid_component: false },
    ],
    retention: Some("Rotated at size limit"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["anydesk_trace_user", "anydesk_connection_trace"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape",
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a",
        "https://dfir.blog/anydesk-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Only present when AnyDesk installed as service; may be absent on per-user installs"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated at size limit",
};

pub(crate) static ANYDESK_CONNECTION_TRACE: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_connection_trace",
    name: "AnyDesk Connection Trace",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\AnyDesk\connection_trace.txt"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Structured log of inbound and outbound AnyDesk connections with remote ID, session type, timestamps, and duration. More terse than ad.trace but specifically designed for connection auditing. Contains outbound connections that prove the local user connected to remote hosts.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "remote_id", value_type: ValueType::Text, description: "Remote AnyDesk ID or alias", is_uid_component: true },
        FieldSchema { name: "session_start", value_type: ValueType::Timestamp, description: "Connection start time", is_uid_component: false },
        FieldSchema { name: "direction", value_type: ValueType::Text, description: "in/out — inbound or outbound connection", is_uid_component: false },
    ],
    retention: Some("Appended; grows until manually cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["anydesk_trace_user", "anydesk_file_transfer_log"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape",
        "https://dfir.blog/anydesk-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Structured format; attacker cleanup often misses this file; contains both inbound and outbound connections"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Appended; grows until manually cleared",
};

pub(crate) static ANYDESK_FILE_TRANSFER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_file_transfer_log",
    name: "AnyDesk File Transfer Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\AnyDesk\file_transfer_trace.txt"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Log of files transferred via AnyDesk file manager per session — filename, size, direction (sent/received), and timestamp. Direct evidence of data exfiltration (files sent to remote operator) or tooling delivery (files received from attacker). Persists even after remote session cleanup attempts.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "filename", value_type: ValueType::Text, description: "Name of file transferred", is_uid_component: true },
        FieldSchema { name: "direction", value_type: ValueType::Text, description: "sent or received", is_uid_component: false },
        FieldSchema { name: "transfer_time", value_type: ValueType::Timestamp, description: "Transfer timestamp", is_uid_component: false },
    ],
    retention: Some("Appended; grows until manually cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["anydesk_connection_trace", "anydesk_trace_user"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/AnyDesk.tkape",
        "https://dfir.blog/anydesk-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Proves exfiltration direction and filename; attacker cleanup often misses this file"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Appended; grows until manually cleared",
};

pub(crate) static SCREENCONNECT_SESSION_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "screenconnect_session_db",
    name: "ScreenConnect / ConnectWise Control Session Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Program Files*\ScreenConnect\App_Data\Session.db"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database for ConnectWise Control (formerly ScreenConnect) self-hosted server containing all session records with connecting client IP, session name, connection start/end timestamps, and operator identity. Critical when attackers deploy their own self-hosted ScreenConnect server on compromised infrastructure.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "session_name", value_type: ValueType::Text, description: "Session display name", is_uid_component: true },
        FieldSchema { name: "session_start", value_type: ValueType::Timestamp, description: "Session creation timestamp", is_uid_component: false },
        FieldSchema { name: "participant_ip", value_type: ValueType::Text, description: "Connecting client IP address", is_uid_component: false },
    ],
    retention: Some("Persistent; retained until database manually cleared or rotated"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["teamviewer_connection_log", "anydesk_trace_system"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/ScreenConnect.tkape",
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Only present on self-hosted deployments; cloud-hosted sessions leave no local DB"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; retained until manually cleared",
};

pub(crate) static RUSTDESK_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rustdesk_logs",
    name: "RustDesk Logs Directory",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\RustDesk"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Log and configuration directory for RustDesk open-source remote desktop tool. Increasingly used by threat actors as an alternative to AnyDesk (same protocol, self-hostable relay). Contains RustDesk.log with connection events, config.toml with relay server settings (attacker-controlled relay is a key IoC), and id/password files.",
    mitre_techniques: &["T1219"],
    fields: &[
        FieldSchema { name: "peer_id", value_type: ValueType::Text, description: "Remote RustDesk peer ID", is_uid_component: true },
    ],
    retention: Some("Log rotated at size limit; config files persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["anydesk_trace_user", "teamviewer_connection_log"],
    sources: &[
        "https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-and-batch-scripts/",
        "https://github.com/rustdesk/rustdesk",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Some legitimate users adopt RustDesk; attacker-controlled relay server is the key IOC"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Application log directory with rotation by RustDesk client",
};

// ── Cloud Storage ─────────────────────────────────────────────────────────────

pub(crate) static DROPBOX_INSTANCE_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "dropbox_instance_db",
    name: "Dropbox Instance Database Directory",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Dropbox\instance*"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Core Dropbox SQLite databases including sync.db (file sync history with server hashes), config.db (account configuration), and filecache.db (local file metadata). Contains complete listing of all files ever synced to Dropbox including deleted files. Critical for data exfiltration investigations.",
    mitre_techniques: &["T1567.002"],
    fields: &[
        FieldSchema { name: "server_path", value_type: ValueType::Text, description: "Dropbox server-side file path", is_uid_component: true },
        FieldSchema { name: "modified_time", value_type: ValueType::Timestamp, description: "File last modification timestamp", is_uid_component: false },
    ],
    retention: Some("Persists until Dropbox uninstalled or database pruned"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["onedrive_metadata", "google_drive_fs_metadata"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Dropbox.tkape",
        "https://www.sans.org/blog/cloud-storage-forensics-dropbox-google-drive-and-onedrive/",
        "https://dfir.blog/dropbox-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Requires Dropbox-specific SQLite parser (obfuscated schema); file hashes prove sync without local copy"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persists until Dropbox uninstalled",
};

pub(crate) static ONEDRIVE_METADATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "onedrive_metadata",
    name: "OneDrive Sync Client Metadata",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\OneDrive"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "OneDrive sync client databases and logs. Key files: SyncEngineDatabase.db (file sync history and metadata for all OneDrive files including cloud-only placeholders), *.odl log files (diagnostic activity). Exposes files uploaded to OneDrive even when not stored locally — including exfiltrated documents.",
    mitre_techniques: &["T1567.002"],
    fields: &[
        FieldSchema { name: "local_path", value_type: ValueType::Text, description: "Local file path", is_uid_component: true },
        FieldSchema { name: "sha1_hash", value_type: ValueType::Text, description: "File SHA-1 hash for cloud deduplication", is_uid_component: false },
    ],
    retention: Some("Persists; ODL log files rotate"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["dropbox_instance_db", "google_drive_fs_metadata"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/OneDrive.tkape",
        "https://www.sans.org/blog/cloud-storage-forensics-dropbox-google-drive-and-onedrive/",
        "https://github.com/barnettjw/ODL-Parser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["ODL log parsing complex; SyncEngineDatabase.db reveals cloud-only placeholders — strongest exfil evidence"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persists; ODL logs rotate",
};

// ── OneDrive ODL (Obfuscated Diagnostic Logs) ───────────────────────────────

/// OneDrive ODL binary diagnostic log files — records sync client activity
/// with obfuscated/encrypted personal strings.
///
/// Binary format with 256-byte header and data blocks. Found in user profile
/// at `\AppData\Local\Microsoft\OneDrive\logs\{Common,Business1,Personal}\`.
/// Active log is `.odl`; rotated logs are `.odlgz` (gzip-compressed).
/// Also `.odlsent` and `.aodl` variants.
///
/// Before April 2022: personal strings obfuscated via 3-word keys in
/// `ObfuscationStringMap.txt` (plaintext lookup table).
/// After April 2022: strings encrypted with AES-128-CBC using key from
/// `general.keystore` (JSON file with base64-encoded key). Encrypted blobs
/// are base64-encoded with `/` and `+` replaced by `_` and `-`.
///
/// macOS equivalent at `/Users/<USER>/Library/Logs/OneDrive/`.
///
/// Source: <http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html>
/// Source: <http://www.swiftforensics.com/2022/11/reading-onedrive-logs-part-2.html>
pub(crate) static ONEDRIVE_ODL_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "onedrive_odl_logs",
    name: "OneDrive ODL Diagnostic Logs",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\OneDrive\logs\*\*.odl"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning:
        "OneDrive sync client binary diagnostic logs (ODL format). 256-byte header \
        followed by data blocks containing sync operations, file upload/download events, \
        error codes, and file paths. Personal strings (file names, folder paths, credentials) \
        are obfuscated: pre-April 2022 via ObfuscationStringMap.txt (3-word key lookup table), \
        post-April 2022 via AES-128-CBC encryption using key from general.keystore JSON file. \
        The general.keystore holds a base64-encoded AES key; encrypted blobs use modified \
        base64 (/ and + replaced with _ and -). Rotated logs compressed as .odlgz. Also \
        present on macOS at /Users/<USER>/Library/Logs/OneDrive/. Cross-reference with \
        SyncEngineDatabase.db for file-level sync metadata. Critical for data exfiltration \
        investigations — logs record every file synced to cloud even when local copies are deleted.",
    mitre_techniques: &[
        "T1567.002", // Exfiltration Over Web Service: Exfiltration to Cloud Storage
        "T1530",     // Data from Cloud Storage
    ],
    fields: ONEDRIVE_ODL_FIELDS,
    retention: Some(
        "Active .odl rotates frequently; .odlgz retained until manually deleted or \
OneDrive reinstall; general.keystore persists alongside logs",
    ),
    triage_priority: TriagePriority::High,
    related_artifacts: &["onedrive_metadata"],
    sources: &[
        // Source: http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html
        // (Yogesh Khatri Part 1: ODL binary format, 256-byte header, file paths on Windows/macOS,
        // ObfuscationStringMap.txt deobfuscation scheme)
        "http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html",
        // Source: http://www.swiftforensics.com/2022/11/reading-onedrive-logs-part-2.html
        // (Part 2: April 2022 encryption change, general.keystore JSON, AES-128-CBC via
        // BCrypt APIs in LoggingPlatform.dll, modified base64 encoding)
        "http://www.swiftforensics.com/2022/11/reading-onedrive-logs-part-2.html",
        // Source: https://github.com/ydkhatri/OneDrive (Yogesh Khatri's ODL parser)
        "https://github.com/ydkhatri/OneDrive",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Encrypted/obfuscated payloads require key extraction to decode",
        "Logs rotate to .odlgz; older history may be lost",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Diagnostic log files rotate with size limit and compression",
};

pub(crate) static ONEDRIVE_ODL_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "Timestamp of the log entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "code_file",
        value_type: ValueType::Text,
        description: "Source code file name that generated the log entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "code_function",
        value_type: ValueType::Text,
        description: "Source function name that generated the log entry",
        is_uid_component: false,
    },
    FieldSchema {
        name: "log_level",
        value_type: ValueType::Text,
        description: "Log severity level (Info, Warning, Error, etc.)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "message",
        value_type: ValueType::Text,
        description: "Log message text, may contain obfuscated/encrypted personal strings",
        is_uid_component: false,
    },
    FieldSchema {
        name: "obfuscation_method",
        value_type: ValueType::Text,
        description: "Obfuscation method: 'string_map' (pre-Apr 2022, ObfuscationStringMap.txt) \
            or 'aes_keystore' (post-Apr 2022, general.keystore AES-128-CBC)",
        is_uid_component: false,
    },
];

pub(crate) static GOOGLE_DRIVE_FS_METADATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "google_drive_fs_metadata",
    name: "Google Drive for Desktop Metadata",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Google\DriveFS"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Google Drive for Desktop (formerly Backup and Sync) metadata database directory. Contains metadata.db with SQLite records of all files in the user's Drive including cloud-only files, their local sync status, content hash, and modification timestamps. Exposes exfiltrated data paths even when files are not cached locally.",
    mitre_techniques: &["T1567.002"],
    fields: &[
        FieldSchema { name: "stable_id", value_type: ValueType::Text, description: "Google Drive stable file identifier", is_uid_component: true },
        FieldSchema { name: "title", value_type: ValueType::Text, description: "File or folder name", is_uid_component: false },
        FieldSchema { name: "modified_date", value_type: ValueType::Timestamp, description: "Last modification timestamp", is_uid_component: false },
    ],
    retention: Some("Persists until Drive for Desktop uninstalled"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["dropbox_instance_db", "onedrive_metadata"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/GoogleDrive.tkape",
        "https://www.sans.org/blog/cloud-storage-forensics-dropbox-google-drive-and-onedrive/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["metadata.db schema may change between Drive for Desktop versions; requires version-appropriate parser"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLite DB; persists until Drive uninstalled",
};

pub(crate) static MEGASYNC_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "megasync_data",
    name: "MEGAsync Cloud Storage Data",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Mega Limited\MEGAsync"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "MEGA cloud storage client data directory. Contains sync configuration and logs. MEGA is frequently used by ransomware groups (BlackCat/ALPHV, LockBit) for data exfiltration prior to encryption due to its end-to-end encryption making detection harder. MEGAsync.log records file sync events.",
    mitre_techniques: &["T1567.002"],
    fields: &[
        FieldSchema { name: "sync_path", value_type: ValueType::Text, description: "Local path being synced to MEGA", is_uid_component: true },
    ],
    retention: Some("Log rotated at size; configuration persists"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["dropbox_instance_db", "onedrive_metadata"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/MEGAsync.tkape",
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["MEGAsync has legitimate users — attacker use established by correlated exfil indicators"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Application data directory persists until uninstall",
};

// ── Communications ────────────────────────────────────────────────────────────

pub(crate) static TEAMS_INDEXED_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "teams_indexed_db",
    name: "Microsoft Teams IndexedDB (Chat History)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "LevelDB database of Microsoft Teams desktop client containing cached chat messages, channel history, call logs, and file share metadata. Reconstructable with LevelDB parsers. Critical for insider threat investigations and social engineering chain reconstruction.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "conversation_id", value_type: ValueType::Text, description: "Teams conversation identifier", is_uid_component: true },
        FieldSchema { name: "message_content", value_type: ValueType::Text, description: "Message text content", is_uid_component: false },
    ],
    retention: Some("Cached locally; synced with Teams service; grows until cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["slack_indexed_db", "signal_database"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/MicrosoftTeams.tkape",
        "https://www.sans.org/blog/microsoft-teams-forensics/",
        "https://bsodtutorials.wordpress.com/2021/05/24/microsoft-teams-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["LevelDB parsing requires specialized tooling; data may be encrypted at rest on newer Teams versions"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "LevelDB cache; grows with Teams usage",
};

pub(crate) static SLACK_INDEXED_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "slack_indexed_db",
    name: "Slack IndexedDB (Message Cache)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Slack\IndexedDB"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "LevelDB cache of Slack desktop client containing channel messages, DMs, and workspace metadata. Provides investigative intelligence on attacker-impersonated employees in phishing chains and insider threat communication. File share metadata reveals exfiltrated file names.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "channel_id", value_type: ValueType::Text, description: "Slack channel identifier", is_uid_component: true },
        FieldSchema { name: "message_text", value_type: ValueType::Text, description: "Message content", is_uid_component: false },
    ],
    retention: Some("Locally cached; grows until Slack cache cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["teams_indexed_db", "discord_local_storage"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Slack.tkape",
        "https://www.sans.org/blog/slack-forensics-investigations-in-the-enterprise/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["LevelDB format; workspace data may be partially encrypted; availability depends on Slack plan retention settings"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "LevelDB cache; grows with Slack usage",
};

pub(crate) static DISCORD_LOCAL_STORAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "discord_local_storage",
    name: "Discord Local Storage (LevelDB)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\discord\Local Storage\leveldb"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "LevelDB local storage for Discord desktop client. May contain cached Discord authentication tokens recoverable via memory or disk parsing — a primary target for info-stealers. Discord is used as a C2 channel and exfiltration destination by multiple threat actors. Token theft enables account takeover.",
    mitre_techniques: &["T1539"],
    fields: &[
        FieldSchema { name: "token", value_type: ValueType::Text, description: "Discord authentication token (if recoverable)", is_uid_component: true },
    ],
    retention: Some("Persists until Discord uninstalled or localStorage cleared"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["slack_indexed_db", "chrome_login_data"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Discord.tkape",
        "https://www.bleepingcomputer.com/news/security/discord-token-stealers-on-the-rise-heres-what-you-can-do/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Token extraction may require memory analysis; Discord rotates tokens on detection; LevelDB parsing required"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Persists until Discord uninstalled or cleared",
};

pub(crate) static SIGNAL_DATABASE: ArtifactDescriptor = ArtifactDescriptor {
    id: "signal_database",
    name: "Signal Desktop Message Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Signal\sql\db.sqlite"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLCipher-encrypted SQLite database containing all Signal Desktop messages, contacts, and call history. Encrypted at rest with a key stored in config.json. When decryption key is recovered, provides full message plaintext. Relevant to investigations involving encrypted communication in drug trafficking, espionage, and organized crime.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "message_body", value_type: ValueType::Text, description: "Decrypted message content (when key recovered)", is_uid_component: true },
        FieldSchema { name: "sent_at", value_type: ValueType::Timestamp, description: "Message sent timestamp", is_uid_component: false },
    ],
    retention: Some("Persists until explicitly deleted by user"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["signal_config_json", "teams_indexed_db"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Signal.tkape",
        "https://www.cise.ufl.edu/~traynor/papers/signal-forensics.pdf",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-signal-desktop/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["SQLCipher encrypted; requires config.json key to decrypt; without key, message content is inaccessible"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SQLCipher SQLite; persists until user deletes",
};

pub(crate) static SIGNAL_CONFIG_JSON: ArtifactDescriptor = ArtifactDescriptor {
    id: "signal_config_json",
    name: "Signal Desktop config.json (DB Encryption Key)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Signal\config.json"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "JSON configuration file containing the plaintext SQLCipher encryption key for Signal's db.sqlite. The key field contains the hex-encoded 256-bit AES key required to decrypt all Signal messages. This is a critical vulnerability in Signal Desktop's security model on Windows — any process with user-level access can decrypt all messages.",
    mitre_techniques: &["T1552.001"],
    fields: &[
        FieldSchema { name: "key", value_type: ValueType::Text, description: "Hex-encoded AES-256 SQLCipher key for db.sqlite", is_uid_component: true },
    ],
    retention: Some("Persistent; regenerated only on fresh installation"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["signal_database"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Apps/Signal.tkape",
        "https://www.magnetforensics.com/blog/forensic-analysis-of-signal-desktop/",
        "https://www.bleepingcomputer.com/news/security/signal-desktop-app-stores-messages-in-plaintext-unencrypted-folder/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Contains plaintext decryption key; any process with user access can decrypt all Signal messages"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Regenerated only on fresh install; otherwise permanent",
};

// ── Windows Forensic Files ────────────────────────────────────────────────────

/// Windows Search index (ESE) — every indexed file with timestamp-independent gather time (Win7–10 21H2).
///
/// ESE database at:
/// `%PROGRAMDATA%\Microsoft\Windows Search\Data\Applications\Windows\Windows.edb`
///
/// Key table: `SystemIndex_0A` — one row per indexed file/folder.
/// `System_Search_GatherTime` is independent of NTFS timestamps — survives timestomping.
/// Win11 22H2+ silently migrates to SQLite3 at a different path — see `windows_search_db_win11`.
pub(crate) static WINDOWS_SEARCH_EDB: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_search_edb",
    name: "Windows Search Index (Windows.edb)",
    artifact_type: ArtifactLocation::EseDatabase,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        r"C:\ProgramData\Microsoft\Windows Search\Data\Applications\Windows\Windows.edb",
    ),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::EseDatabase,
    meaning: "Indexes every file and folder on the system. SystemIndex_0A table contains \
              System_Search_GatherTime — when Search last indexed each file. \
              This timestamp is independent of NTFS $MFT timestamps and can reveal \
              file existence after deletion or timestamp manipulation. Also indexes \
              email, IE history, and Office document metadata depending on Search scope.",
    mitre_techniques: &["T1083", "T1070.004", "T1070.006"],
    fields: &[
        FieldSchema {
            name: "file_path",
            value_type: ValueType::Text,
            description: "Indexed file or folder path",
            is_uid_component: true,
        },
        FieldSchema {
            name: "gather_time",
            value_type: ValueType::Timestamp,
            description: "System_Search_GatherTime — when Search last indexed this file; independent of NTFS timestamps",
            is_uid_component: false,
        },
        FieldSchema {
            name: "last_modified",
            value_type: ValueType::Timestamp,
            description: "System_DateModified as reported to Search",
            is_uid_component: false,
        },
        FieldSchema {
            name: "size",
            value_type: ValueType::Integer,
            description: "File size in bytes at last index time",
            is_uid_component: false,
        },
    ],
    retention: Some("Rebuilt on corruption; grows until disk pressure forces cleanup"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["mft", "usnjrnl", "windows_search_db_win11"],
    sources: &[
        "https://github.com/kacos2000/WinEDB",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsIndexSearch.tkape",
        "https://www.foxtonforensics.com/blog/post/analysing-the-windows-search-database",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Indexing scope depends on user/admin configuration",
        "Service may be disabled by attacker or admin",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "ESE database persists until rebuild or service reset",
};

pub(crate) static EVENT_TRANSCRIPT_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "event_transcript_db",
    name: "Windows Telemetry EventTranscript.db",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database collecting Windows Diagnostic Data (telemetry) events including application launches, census data, and diagnostic payloads in JSON format. The events table contains timestamped JSON blobs recording application execution and system activity — functions as an alternative execution timeline independent of prefetch and event logs.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "provider_group_guid", value_type: ValueType::Text, description: "Telemetry provider GUID", is_uid_component: true },
        FieldSchema { name: "logging_binary_name", value_type: ValueType::Text, description: "Application that generated the event", is_uid_component: false },
        FieldSchema { name: "event_keywords", value_type: ValueType::Text, description: "Event classification keywords", is_uid_component: false },
    ],
    retention: Some("Managed by DiagTrack; rotated automatically"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["srum_db", "windows_timeline"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsDiagnosticData.tkape",
        "https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/logapi/query.htm",
        "https://www.sans.org/blog/digital-forensics-dfir/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Only populated when telemetry level is Basic or higher",
        "Telemetry can be disabled via GPO on enterprise systems",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Telemetry database with size-based rotation as new events overwrite old",
};

pub(crate) static CERTUTIL_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "certutil_cache",
    name: "CertUtil URL Cache (certutil -urlcache)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Cache directory populated by certutil.exe when used to download files via HTTP/HTTPS (LOLBin technique). Files downloaded with `certutil -urlcache -split -f <url>` are stored here. Evidence of file download persists even after the downloaded file is deleted. File names are hashed but creation timestamps align with download time.",
    mitre_techniques: &["T1105"],
    fields: &[
        FieldSchema { name: "cached_file", value_type: ValueType::Text, description: "Hash-named cached file (content is the downloaded data)", is_uid_component: true },
        FieldSchema { name: "download_time", value_type: ValueType::Timestamp, description: "File creation time = download time", is_uid_component: false },
    ],
    retention: Some("Persists until CryptNet cache is flushed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_powershell", "psreadline_history"],
    sources: &[
        "https://lolbas-project.github.io/lolbas/Binaries/Certutil/",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/CertUtil.tkape",
        "https://www.sans.org/blog/certutil-is-a-lolbin/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Hash-named files require external resolution; creation timestamp = download time; survives downloaded file deletion"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "CryptNet cache; persists until explicitly flushed",
};

pub(crate) static SDB_CUSTOM_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "sdb_custom_files",
    name: "Custom AppCompat Shim Database Files",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\apppatch\Custom\"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Directory containing custom Application Compatibility shim databases (.sdb files). Attackers install custom SDB files as a persistence mechanism (T1546.011 — Application Shimming). Shims can redirect API calls, inject DLLs, or modify application behavior without modifying the target binary. Legitimately rare; any .sdb file here in an incident warrants investigation.",
    mitre_techniques: &["T1546.011"],
    fields: &[
        FieldSchema { name: "sdb_file", value_type: ValueType::Text, description: "Custom shim database filename", is_uid_component: true },
    ],
    retention: Some("Persistent until explicitly uninstalled"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["appshim_db"],
    sources: &[
        "https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/AppCompatSDBFiles.tkape",
        "https://www.hexacorn.com/blog/2015/07/17/beyond-good-ol-run-key-part-38/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Any .sdb file here is legitimately rare; requires sdbinst.exe or direct file copy — both leave evidence"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Installed SDB files persist until explicitly removed",
};

pub(crate) static WER_REPORTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports",
    name: "Windows Error Reporting Queue",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Queued Windows Error Reporting crash reports. Each report directory contains a Report.wer metadata file with the crashing application name, version, crash timestamp, and module name. WER reports prove execution of the crashing process even after binary deletion — injected processes crash frequently, generating WER artifacts.",
    mitre_techniques: &["T1055"],
    fields: &[
        FieldSchema { name: "app_name", value_type: ValueType::Text, description: "Name of the crashing application", is_uid_component: true },
        FieldSchema { name: "crash_time", value_type: ValueType::Timestamp, description: "Crash event timestamp", is_uid_component: false },
        FieldSchema { name: "module_name", value_type: ValueType::Text, description: "Faulting module name", is_uid_component: false },
    ],
    retention: Some("Queued reports purged after submission; max ~50 reports"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["evtx_system", "prefetch_dir"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsErrorReporting.tkape",
        "https://www.sans.org/blog/windows-error-reporting-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Reports are uploaded and deleted on success — only queued/failed uploads remain",
        "WER can be disabled via GPO",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Reports queued briefly then submitted/deleted; surviving reports are activity-bounded",
};

pub(crate) static IIS_W3SVC_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "iis_w3svc_logs",
    name: "IIS W3C HTTP Access Logs",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\LogFiles\W3SVC*"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "IIS web server W3C Extended Log Format access logs. Each log line records date, time, client IP, server IP, HTTP method, URI stem, URI query, HTTP status, bytes sent/received, time-taken, and user-agent. Primary source for web exploitation evidence including webshell activity, SQLi attempts, and LFI/path traversal.",
    mitre_techniques: &["T1190"],
    fields: &[
        FieldSchema { name: "client_ip", value_type: ValueType::Text, description: "Client IP address", is_uid_component: true },
        FieldSchema { name: "uri_stem", value_type: ValueType::Text, description: "Requested URI path", is_uid_component: false },
        FieldSchema { name: "uri_query", value_type: ValueType::Text, description: "URI query string (exploit payload often here)", is_uid_component: false },
        FieldSchema { name: "sc_status", value_type: ValueType::UnsignedInt, description: "HTTP response status code", is_uid_component: false },
    ],
    retention: Some("Rotated daily by default; retention per IIS configuration"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["iis_config_applicationhost", "evtx_system"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Logs/IISLogFiles.tkape",
        "https://www.sans.org/blog/iis-log-forensics/",
        "https://docs.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Attacker may clear logs; Managed Pipeline may not log all requests; X-Forwarded-For spoofing common"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated daily; retention per IIS config",
};

pub(crate) static IIS_CONFIG_APPLICATIONHOST: ArtifactDescriptor = ArtifactDescriptor {
    id: "iis_config_applicationhost",
    name: "IIS applicationHost.config",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\inetsrv\config\applicationHost.config"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Master IIS server configuration file defining all web sites, application pools, virtual directories, authentication, and handler mappings. Attacker-added script handlers (e.g., .aspx mapped to a malicious ISAPI DLL) and ISAPI extension registrations for native webshells appear here. Reveals full web root paths for evidence collection.",
    mitre_techniques: &["T1505.004"],
    fields: &[
        FieldSchema { name: "site_name", value_type: ValueType::Text, description: "IIS web site name", is_uid_component: true },
        FieldSchema { name: "physical_path", value_type: ValueType::Text, description: "Web root physical path", is_uid_component: false },
    ],
    retention: Some("Persistent; modified by IIS Manager or direct edit"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["iis_w3svc_logs"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Logs/IISLogFiles.tkape",
        "https://www.sans.org/blog/iis-log-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Handler additions persist until config reset; embedded webshell paths in handlers are definitive indicators"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Persistent IIS config; modified by admin or attacker",
};

pub(crate) static DNS_DEBUG_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "dns_debug_log",
    name: "DNS Server Debug Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\dns\dns.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows DNS Server verbose debug log recording all query requests with client IP, query name, query type, and response. Enables reconstruction of DNS-based C2 (beaconing patterns to suspicious domains), DNS tunneling (unusually long or encoded subdomains), and internal host enumeration. Requires debug logging to be enabled — check if disabled by attackers.",
    mitre_techniques: &["T1071.004"],
    fields: &[
        FieldSchema { name: "client_ip", value_type: ValueType::Text, description: "IP address of the DNS querying host", is_uid_component: true },
        FieldSchema { name: "query_name", value_type: ValueType::Text, description: "Domain name queried", is_uid_component: false },
        FieldSchema { name: "query_type", value_type: ValueType::Text, description: "DNS record type (A, AAAA, TXT, MX, etc.)", is_uid_component: false },
    ],
    retention: Some("Single file; rotated at configured size limit"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["dhcp_server_log", "evtx_system"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Logs/DNSServerLog.tkape",
        "https://www.sans.org/blog/dns-logging-in-windows-server/",
        "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Requires debug logging to be enabled; attacker may disable to evade; single-file rotation can overwrite evidence"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Single file rotated at configured size limit",
};

pub(crate) static DHCP_SERVER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "dhcp_server_log",
    name: "Windows DHCP Server Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\dhcp\DhcpSrvLog-*.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows DHCP Server audit log recording IP address assignments with MAC address, hostname, and timestamp. Critical for correlating IP addresses in other logs (firewall, IIS, DNS) with specific physical devices. Lease event 10=Assign, 11=Renew, 12=Release — timestamps anchor IP-to-host mapping windows.",
    mitre_techniques: &["T1016"],
    fields: &[
        FieldSchema { name: "ip_address", value_type: ValueType::Text, description: "IP address assigned", is_uid_component: true },
        FieldSchema { name: "mac_address", value_type: ValueType::Text, description: "Client MAC address", is_uid_component: false },
        FieldSchema { name: "hostname", value_type: ValueType::Text, description: "Client-reported hostname", is_uid_component: false },
        FieldSchema { name: "event_time", value_type: ValueType::Timestamp, description: "DHCP event timestamp", is_uid_component: false },
    ],
    retention: Some("One file per day; typically 7-day retention"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["dns_debug_log", "evtx_system"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Logs/DHCPServerLog.tkape",
        "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Only present on Windows DHCP Server role machines",
        "Daily log rotation; older days deleted",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Daily-rotating log files with bounded retention",
};

pub(crate) static SUM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "sum_db",
    name: "User Access Logging (SUM) Database",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\LogFiles\SUM\"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Server User Access Logging (UAL) database directory containing Current.mdb and {GUID}.mdb JET ESE databases. Records authenticated access to server roles (IIS, SMB/file sharing, RDS) with source IP, username, and first/last access timestamps. Retains up to 2 years of history. Critical for server compromise investigations — shows what accounts accessed what services and from where.",
    mitre_techniques: &["T1021"],
    fields: &[
        FieldSchema { name: "username", value_type: ValueType::Text, description: "Authenticated username", is_uid_component: true },
        FieldSchema { name: "ip_address", value_type: ValueType::Text, description: "Client IP address", is_uid_component: false },
        FieldSchema { name: "first_seen", value_type: ValueType::Timestamp, description: "First access timestamp for this username/IP pair", is_uid_component: false },
        FieldSchema { name: "last_seen", value_type: ValueType::Timestamp, description: "Last access timestamp", is_uid_component: false },
    ],
    retention: Some("Up to 2 years; rolled annually into yearly GUID-named DB"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["evtx_security", "dns_debug_log", "dhcp_server_log"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/UserAccessLogging.tkape",
        "https://www.sans.org/blog/windows-user-access-logging-sum/",
        "https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Windows Server only; requires ESE/JET parser; timestamps in local server time — convert to UTC"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Up to 2 years retention; rolled annually",
};

pub(crate) static COPILOT_RECALL_UKG: ArtifactDescriptor = ArtifactDescriptor {
    id: "copilot_recall_ukg",
    name: "Windows Recall Screenshot Index (ukg.db)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\CoreAIPlatform.00\UKP\*\ukg.db"),
    scope: DataScope::User,
    os_scope: OsScope::Win11Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Copilot+ Recall feature screenshot index database. Contains OCR-extracted text from periodic screenshots of all user activity, searchable by content. Provides near-complete reconstruction of user desktop activity including credential entry, browsing, and document editing. Protected by VBS/PPLA on compliant hardware, but accessible forensically from acquired images.",
    mitre_techniques: &["T1113"],
    fields: &[
        FieldSchema { name: "ocr_text", value_type: ValueType::Text, description: "OCR-extracted text from screenshot", is_uid_component: true },
        FieldSchema { name: "screenshot_time", value_type: ValueType::Timestamp, description: "Timestamp of the captured screenshot", is_uid_component: false },
        FieldSchema { name: "window_title", value_type: ValueType::Text, description: "Active window title at time of screenshot", is_uid_component: false },
    ],
    retention: Some("Rolling 90-day window by default; configurable"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["windows_timeline", "srum_db"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsRecall.tkape",
        "https://doublepulsar.com/recall-stealing-everything-youve-ever-typed-or-viewed-on-your-own-windows-pc-is-now-possible-da3e12e9465e",
        "https://www.bleepingcomputer.com/news/microsoft/microsoft-recall-now-available-to-all-windows-insiders/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Requires Copilot+ hardware with Recall enabled; VBS/PPLA protects live DB; accessible from acquired image"],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Rolling 90-day window; older screenshots purged",
};

pub(crate) static NTUSER_DAT_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntuser_dat_file",
    name: "NTUSER.DAT (Per-User Registry Hive)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\NTUSER.DAT"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user registry hive containing all HKEY_CURRENT_USER data for the user profile. Source for all HKCU-scoped artifacts: Run keys, UserAssist, TypedURLs, MRU lists, RecentDocs, shellbags, proxy settings, and thousands more. A single NTUSER.DAT file provides the complete user activity registry picture for offline forensics.",
    mitre_techniques: &["T1012"],
    fields: &[
        FieldSchema { name: "username", value_type: ValueType::Text, description: "Username inferred from profile path", is_uid_component: true },
    ],
    retention: Some("Exists for lifetime of user profile"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["usrclass_dat_file", "shellbags_user", "run_key_hkcu"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/RegistryHivesUser.tkape",
        "https://13cubed.com/downloads/Windows_Forensic_Analysis_Poster.pdf",
        "https://www.sans.org/blog/digital-forensics-artifacts-in-windows-registry/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Single hive provides all HKCU artifacts; transaction logs (.LOG1/.LOG2) must be applied for current state"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Exists for lifetime of user profile",
};

pub(crate) static USRCLASS_DAT_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "usrclass_dat_file",
    name: "UsrClass.dat (User Classes Registry Hive)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "User-specific COM class registration and shellbags hive (HKCU\\Software\\Classes). Primary source for shellbag artifacts covering virtual folders (Desktop, Libraries, Network, ZIP contents) that NTUSER.DAT shellbags miss. Shellbags persist folder access evidence long after files are deleted — critical for proving directory traversal.",
    mitre_techniques: &["T1083"],
    fields: &[
        FieldSchema { name: "username", value_type: ValueType::Text, description: "Username inferred from profile path", is_uid_component: true },
    ],
    retention: Some("Exists for lifetime of user profile"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ntuser_dat_file", "shellbags_user"],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/RegistryHivesUser.tkape",
        "https://www.sans.org/blog/windows-shellbag-forensics-in-depth/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Shellbag interpretation requires careful parsing of the binary structures"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry hive file persists for life of user profile",
};

// ── Group A: Windows Plaintext Logs ──────────────────────────────────────────

pub(crate) static CBS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "cbs_log",
    name: "CBS.log (Component Based Servicing Log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\Logs\CBS\CBS.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Component Based Servicing log recording Windows Update, hotfix, and feature-on-demand activity. Each entry includes a timestamp, severity (Info/Warning/Error), component name, and message. Forensically valuable for: (1) correlating KB installation times with compromise timelines, (2) detecting update suppression (expected patches absent), (3) identifying tampering with system binary integrity (CBS validates component hashes — corruption messages indicate file replacement). Rotates to CBS.persist.log when it exceeds ~50 MB.",
    mitre_techniques: &["T1562.001"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Log entry timestamp (YYYY-MM-DD HH:MM:SS, local time)", is_uid_component: false },
        FieldSchema { name: "severity", value_type: ValueType::Text, description: "Entry type: Info, Warning, Error", is_uid_component: false },
        FieldSchema { name: "component", value_type: ValueType::Text, description: "CBS component or package name", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Human-readable status or error message", is_uid_component: false },
    ],
    retention: Some("Rotates to CBS.persist.log at ~50 MB; persist.log may be deleted"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["windows_update_session", "setupapi_dev_log"],
    sources: &[
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/deployment/understanding-cbs-log-file",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsUpdateLogs.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Rotates to CBS.persist.log when over ~50 MB; older entries may be lost",
        "High-volume routine update activity creates noise",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file rotates at ~50 MB to CBS.persist.log",
};

pub(crate) static PFRO_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "pfro_log",
    name: "PFRO.log (Pending File Rename Operations Log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\PFRO.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Records file rename and delete operations scheduled via MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT. Created at reboot from the PendingFileRenameOperations registry value (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager). Malware uses this mechanism for staged deletion of dropper files or replacement of system binaries after reboot. Presence of this file alone is suspicious; each entry shows source path (blank = delete) and destination path. Compare entries against known-good binaries and MFT timestamps.",
    mitre_techniques: &["T1036.003", "T1070.004"],
    fields: &[
        FieldSchema { name: "source_path", value_type: ValueType::Text, description: "Path of file to be renamed or deleted (blank source = delete operation)", is_uid_component: true },
        FieldSchema { name: "destination_path", value_type: ValueType::Text, description: "Target path; empty string indicates deletion", is_uid_component: true },
    ],
    retention: Some("Written at each reboot; overwritten on next reboot"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["setupapi_dev_log", "mft_file"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw",
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-log-files-and-event-logs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Legitimate uninstallers and updaters also use MoveFileEx with delay-until-reboot"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Log file persists until manually cleared or rotation",
};

pub(crate) static SETUPERR_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "setuperr_log",
    name: "setuperr.log (Windows Setup Error Log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\setuperr.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Error-only companion to setupapi.dev.log; generated during Windows Setup (initial install or upgrade). Contains driver and hardware initialization errors during OS deployment. Useful for establishing the original OS install timeline and identifying hardware that was present at install time. Absence of this file on a running system is normal; presence indicates the system recently went through a Setup phase.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Entry timestamp in setup log format", is_uid_component: false },
        FieldSchema { name: "error_code", value_type: ValueType::Text, description: "Win32 error code or HRESULT", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Setup error message", is_uid_component: false },
    ],
    retention: Some("Retained from most recent Setup run; may be absent on stable systems"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["setupapi_dev_log", "setupapi_upgrade_log"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-log-files-and-event-logs",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &["Only present after recent Windows Setup; may be deleted after successful install"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Setup-time log file persists until manually deleted",
};

pub(crate) static SETUPAPI_UPGRADE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "setupapi_upgrade_log",
    name: "setupapi.upgrade.log (In-Place Upgrade Driver Log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\inf\setupapi.upgrade.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Records driver migration during Windows in-place upgrade (e.g., Win7→Win10, Win10→Win11). Format identical to setupapi.dev.log: timestamped sections per driver package with install/migrate result. Forensically useful for (1) establishing the upgrade timeline, (2) detecting drivers added or migrated that were not present in the original OS, (3) identifying USB devices connected during the upgrade window.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Section entry timestamp", is_uid_component: false },
        FieldSchema { name: "driver_name", value_type: ValueType::Text, description: "INF file name of migrated driver package", is_uid_component: false },
        FieldSchema { name: "result", value_type: ValueType::Text, description: "Migration outcome: Success or error code", is_uid_component: false },
    ],
    retention: Some("Retained from most recent upgrade; absent on clean-install systems"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["setupapi_dev_log", "setuperr_log"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-log-files-and-event-logs",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsUpdateLogs.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Only present after in-place Windows upgrade"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Upgrade log file persists until manually deleted",
};

// ── Group B: Windows Error Reporting Split ────────────────────────────────────

pub(crate) static WER_REPORTS_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports_user",
    name: "WER ReportArchive (User-scope Crash Reports)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\WER\ReportArchive"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user Windows Error Reporting archive. Each subdirectory contains a Report.wer (INI-like format) and optional memory dumps. Key fields: EventType, AppName, AppPath, AppVersion, ExceptionCode, ModuleName, ModuleVersion. Crash reports reveal: (1) malware crashes at unusual paths (C:\\Users\\...\\AppData), (2) exploitation attempts (ExceptionCode 0xC0000005 access violation = code injection gone wrong), (3) injected DLL names in ModuleName, (4) tool execution evidence even without process logs. Compare AppPath against known-good locations.",
    mitre_techniques: &["T1055", "T1059"],
    fields: &[
        FieldSchema { name: "event_type", value_type: ValueType::Text, description: "WER bucket type (e.g., APPCRASH, CLR20r3)", is_uid_component: false },
        FieldSchema { name: "app_name", value_type: ValueType::Text, description: "Crashing process executable name", is_uid_component: true },
        FieldSchema { name: "app_path", value_type: ValueType::Text, description: "Full path of crashing executable", is_uid_component: true },
        FieldSchema { name: "exception_code", value_type: ValueType::UnsignedInt, description: "Win32 exception code (0xC0000005 = access violation, injection indicator)", is_uid_component: false },
        FieldSchema { name: "module_name", value_type: ValueType::Text, description: "Faulting module (DLL) name", is_uid_component: true },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Crash report creation time", is_uid_component: false },
    ],
    retention: Some("Up to 10 reports per application; controlled by WER policy"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["wer_reports", "wer_reports_system", "evtx_application"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/wer/about-wer",
        "https://learn.microsoft.com/en-us/windows/win32/wer/wer-report-file-format",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Reports may be uploaded and deleted; surviving archive is bounded",
        "WER can be disabled via GPO",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Per-user crash archive with bounded retention as new reports replace old",
};

pub(crate) static WER_REPORTS_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports_system",
    name: "WER ReportArchive (System-scope Crash Reports)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%ProgramData%\Microsoft\Windows\WER\ReportArchive"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-wide Windows Error Reporting archive for crashes running as SYSTEM or elevated. Same .wer report format as user-scope. System-scope reports are particularly valuable for: (1) kernel-mode crashes from rootkits or driver exploits, (2) service crashes (svchost-hosted services) revealing injected payloads, (3) elevated process failures at unusual paths. Correlate ModuleName against known-good Windows binaries and check AppPath for non-standard locations.",
    mitre_techniques: &["T1055", "T1543.003"],
    fields: &[
        FieldSchema { name: "event_type", value_type: ValueType::Text, description: "WER bucket type (e.g., APPCRASH, BlueScreen)", is_uid_component: false },
        FieldSchema { name: "app_name", value_type: ValueType::Text, description: "Crashing process executable name", is_uid_component: true },
        FieldSchema { name: "app_path", value_type: ValueType::Text, description: "Full path of crashing executable", is_uid_component: true },
        FieldSchema { name: "exception_code", value_type: ValueType::UnsignedInt, description: "Win32 exception code", is_uid_component: false },
        FieldSchema { name: "module_name", value_type: ValueType::Text, description: "Faulting module (DLL) name", is_uid_component: true },
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Crash report creation time", is_uid_component: false },
    ],
    retention: Some("Up to 10 reports per application; controlled by WER policy"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["wer_reports", "wer_reports_user", "evtx_application"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/win32/wer/about-wer",
        "https://learn.microsoft.com/en-us/windows/win32/wer/wer-report-file-format",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Reports may be uploaded and deleted; surviving archive is bounded",
        "WER can be disabled via GPO",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "System crash archive with bounded retention as new reports replace old",
};

// ── Group F: Windows AppX/Modern App ─────────────────────────────────────────

pub(crate) static APPX_PACKAGES_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "appx_packages_user",
    name: "AppX/UWP Package Data Directory",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%LocalAppData%\Packages"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user UWP (Universal Windows Platform) application data directory. Each installed Store app gets a subdirectory named by its package family name (e.g., Microsoft.WindowsStore_8wekyb3d8bbwe). Subdirectories of interest: LocalCache (offline data), LocalState (app databases and settings), AC\\INetCache (browser-like caches for app WebViews), Settings\\settings.dat (roaming settings). Forensically relevant for: (1) identifying installed Store apps including sideloaded packages, (2) browser-like forensics on apps using WebView2, (3) detecting masquerading via lookalike store package names.",
    mitre_techniques: &["T1036", "T1059.007"],
    fields: &[
        FieldSchema { name: "package_family_name", value_type: ValueType::Text, description: "UWP package family name (Publisher_Hash format)", is_uid_component: true },
        FieldSchema { name: "app_display_name", value_type: ValueType::Text, description: "Human-readable app name from AppxManifest.xml", is_uid_component: false },
    ],
    retention: Some("Exists while app is installed; removed with app uninstall"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["usrclass_dat_file"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/uwp/design/app-settings/store-and-retrieve-app-data",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/AppsData.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Mostly populated by legitimate Store apps",
        "Sideloaded packages require admin enablement",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "App data directory persists until package uninstall",
};

pub(crate) static APPX_INSTALL_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "appx_install_log",
    name: "DISM.log (Deployment Image Servicing Log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\Logs\DISM\dism.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "DISM (Deployment Image Servicing and Management) operation log. Records Windows optional feature enable/disable, package install/remove, and image servicing operations. Forensically significant for: (1) LOLBin coverage — enabling Windows Subsystem for Linux, .NET Framework, Hyper-V, or IIS via DISM provides legitimate-looking infrastructure for staging attacks, (2) detecting feature manipulation to weaken defenses (disabling Windows Defender feature), (3) timeline of when WSL or other optional components were enabled.",
    mitre_techniques: &["T1218", "T1562.001"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Operation timestamp", is_uid_component: false },
        FieldSchema { name: "operation", value_type: ValueType::Text, description: "DISM operation type (EnableFeature, AddPackage, etc.)", is_uid_component: false },
        FieldSchema { name: "feature_name", value_type: ValueType::Text, description: "Windows optional feature or package name", is_uid_component: true },
        FieldSchema { name: "result", value_type: ValueType::Text, description: "Operation outcome (success or HRESULT error code)", is_uid_component: false },
    ],
    retention: Some("Appended continuously; no automatic rotation"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["setupapi_dev_log", "cbs_log"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deployment-image-servicing-and-management--dism--technical-reference",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsUpdateLogs.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["DISM activity is also generated by legitimate sysadmin and Windows Update operations"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file rotates when size limit reached",
};

// ── Group G: Windows Diagnostic/Telemetry ────────────────────────────────────

pub(crate) static DIAGNOSTIC_DATA_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "diagnostic_data_dir",
    name: "Windows Diagnostic Data ETL Directory",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%ProgramData%\Microsoft\Diagnosis\ETLLogs"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Windows diagnostic telemetry Event Trace Log (ETL) files collected by DiagTrack (Connected User Experiences and Telemetry). Contains AutoLogger, ShutdownLogger, and DiagTrack subdirectories with binary ETL files. Low forensic priority for most investigations, but relevant when: (1) telemetry exfiltration is suspected (T1005 data collection before exfil), (2) verifying which diagnostic data left the system, (3) parsing ETL files for application usage and connectivity events that lack other artifacts. Parse with Windows Performance Analyzer (WPA) or wevtutil.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "etl_filename", value_type: ValueType::Text, description: "ETL file name indicating logger (AutoLogger-DiagTrack-Listener.etl, etc.)", is_uid_component: false },
    ],
    retention: Some("Rotated by DiagTrack service; controlled by diagnostic data level setting"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["evtx_system"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/privacy/diagnostic-data-collection",
        "https://learn.microsoft.com/en-us/windows-hardware/test/wpt/recording-for-basic-system-diagnosis",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Binary ETL format requires specialized tooling to parse",
        "Telemetry can be disabled via GPO — directory may be sparse",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "ETL files rotate with size and time-based retention",
};

pub(crate) static WINDOWS_UPDATE_SESSION: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_update_session",
    name: "Windows Update ReportingEvents.log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%SystemRoot%\SoftwareDistribution\ReportingEvents.log"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Tab-delimited log of Windows Update agent operations. Each line: {timestamp}\\t{agent}\\t{status}\\t{update_title}\\t{kb_number}\\t{error_code}. Forensically critical for correlating the patch state of a system with the compromise timeline: if a known CVE was exploited, verify whether the relevant KB was installed before or after the intrusion. Absence of expected updates indicates suppression (T1562.001). Also reveals when Windows Defender definition updates were applied.",
    mitre_techniques: &["T1562.001", "T1190"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Update event time (ISO 8601 UTC)", is_uid_component: false },
        FieldSchema { name: "agent", value_type: ValueType::Text, description: "WU agent component (WindowsUpdateClient, AutomaticUpdates, etc.)", is_uid_component: false },
        FieldSchema { name: "status", value_type: ValueType::Text, description: "Operation result: Success, Failed, or error code", is_uid_component: false },
        FieldSchema { name: "update_title", value_type: ValueType::Text, description: "Human-readable update name", is_uid_component: false },
        FieldSchema { name: "kb_number", value_type: ValueType::Text, description: "KB article number (e.g., KB5034441)", is_uid_component: true },
    ],
    retention: Some("Appended continuously; no automatic rotation"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["cbs_log", "evtx_system"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs",
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Windows/WindowsUpdateLogs.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Format changed across Windows builds; parser must handle variations"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Append-only log file persists until rotation or cleanup",
};

// ── NTUSER.MAN Mandatory Profile Persistence ────────────────────────────────
/// NTUSER.MAN is a mandatory user profile hive that Windows loads *instead of*
/// NTUSER.DAT when present in the user's profile directory. This is an
/// intended Windows feature (originally for kiosk/shared workstations), but
/// attackers can abuse it to establish registry persistence that bypasses
/// EDR registry callbacks entirely.
///
/// The technique works because `CmRegisterCallbackEx` monitors registry API
/// calls (`RegSetValue`, `RegCreateKey`), but hive loading from disk is not
/// a registry operation — it's a filesystem operation. An attacker can:
/// 1. Export the target user's HKCU hive as .reg text (no elevation required)
/// 2. Add persistence keys (Run keys, COM hijacks, etc.) to the .reg file
/// 3. Convert to binary hive format (e.g. using HiveSwarming)
/// 4. Write the modified hive as NTUSER.MAN in %USERPROFILE%
/// 5. On next logon, Windows loads the poisoned hive — no registry callbacks fire
///
/// Medium integrity is sufficient (user writes to own profile directory).
/// The user hive is locked while the session is active, so activation
/// requires logoff/logon or reboot — making this a persistence mechanism,
/// not immediate execution.
///
/// Mandatory profiles are rare in modern environments. Their mere presence
/// outside kiosk/shared workstation configurations warrants investigation.
///
// Source: https://deceptiq.com/blog/ntuser-man-registry-persistence
// Source: https://windowsir.blogspot.com/2026/01/grab-bag.html
// Source: https://learn.microsoft.com/en-us/windows/client-management/client-tools/mandatory-user-profile
pub(crate) static NTUSER_MAN_PERSISTENCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntuser_man_persistence",
    name: "NTUSER.MAN Mandatory Profile Persistence",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://deceptiq.com/blog/ntuser-man-registry-persistence
    file_path: Some("%USERPROFILE%\\NTUSER.MAN"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "NTUSER.MAN is a mandatory profile hive that Windows loads instead of \
              NTUSER.DAT when present. Attackers abuse this to establish registry \
              persistence (Run keys, COM hijacks, shell extensions) that bypasses \
              EDR registry callbacks (CmRegisterCallbackEx). The hive is loaded \
              directly from disk — not through registry APIs — so endpoint security \
              products monitoring registry operations see nothing. Medium integrity \
              is sufficient since users can write to their own profile directory. \
              Activation requires logoff/logon or reboot. In environments not using \
              mandatory profiles, the mere existence of NTUSER.MAN is a high-confidence \
              indicator of compromise. Can also be used for lateral movement via \
              roaming profile shares or AD profilePath attribute modification.",
    mitre_techniques: &[
        "T1547.001", // Boot or Logon Autostart Execution: Registry Run Keys
        "T1112",     // Modify Registry
    ],
    fields: &[
        FieldSchema {
            name: "is_mandatory_profile",
            value_type: ValueType::Bool,
            description: "Whether NTUSER.MAN exists in the profile directory; \
                          its presence alone is the primary indicator — mandatory \
                          profiles are rare outside kiosk deployments",
            is_uid_component: false,
        },
        FieldSchema {
            name: "file_modified_time",
            value_type: ValueType::Timestamp,
            description: "Last modification timestamp of NTUSER.MAN; compare against \
                          NTUSER.DAT modification time — a recently created .MAN file \
                          alongside an older .DAT is suspicious",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent until file is deleted; survives reboots by design"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["run_key_hkcu", "run_key_hklm"],
    sources: &[
        // Source: DeceptIQ — technique discovery, EDR bypass via mandatory profile hive loading
        "https://deceptiq.com/blog/ntuser-man-registry-persistence",
        // Source: Harlan Carvey commentary and cross-reference
        "https://windowsir.blogspot.com/2026/01/grab-bag.html",
        // Source: Microsoft documentation on mandatory user profiles
        "https://learn.microsoft.com/en-us/windows/client-management/client-tools/mandatory-user-profile",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Presence of NTUSER.MAN in a non-kiosk environment is a high-confidence IOC",
        "File content is a full registry hive — parse it to extract persistence keys",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "File persists on disk until manually deleted; survives reboots by design",
};

// ── T1115 — Windows Clipboard History Data Files ─────────────────────────────

/// `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\`
///
/// On-disk persisted clipboard history (Win10 1809+, when the user has enabled
/// clipboard history via Win+V or Settings → System → Clipboard). The folder
/// contains two subfolders:
///
/// - `HistoryData\<GUID>\` — recent clipboard items (populated only when
///   cross-device sync is enabled via a Microsoft account)
/// - `Pinned\<GUID>\<item-GUID>\` — pinned items; one subfolder per pinned
///   item; the subfolder's *created* timestamp records when the item was pinned
///
/// Inside each item folder:
/// - A binary payload file (encrypted at rest — content is not directly readable)
/// - `metadata.json` — plaintext JSON with a `"timestamp"` field showing when
///   the item was copied and its format type (text, image, etc.)
///
/// Targeted by ClipboardHistoryThief (github.com/netero1010/ClipboardHistoryThief)
/// which calls the cbdhsvc service's COM interface to dump the full history.
/// The registry toggle `HKCU\...\ClipboardHistory` (Enable = 1) controls
/// whether this folder is created; see `windows_clipboard_history`.
///
/// Carvey (2026-01) documents this as an expanding IR collection target
/// given threat actor automation of clipboard enablement + periodic exfil.
pub(crate) static WINDOWS_CLIPBOARD_DATA_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_clipboard_data_files",
    name: "Windows Clipboard History Data Files",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Windows\Clipboard"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "On-disk persisted clipboard history under %LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard. \
        Requires clipboard history enabled (Win10 1809+). Contains HistoryData and Pinned subfolders, \
        each with GUID-named item folders. Each pinned item folder contains an encrypted binary payload \
        and a plaintext metadata.json with copy timestamp and format type. Payload files are encrypted \
        at rest — metadata.json is the primary plaintext forensic anchor. Folder creation timestamp \
        and item-folder created timestamps establish timeline. Targeted by ClipboardHistoryThief \
        (T1115) for automated clipboard exfiltration. Threat actors can silently enable clipboard \
        history if disabled, then periodically dump and clear the history. Correlate with \
        windows_clipboard_history registry key (enable toggle), windows_timeline \
        (ActivitiesCache.db CopyPaste activity type), and cbdhsvc service process memory.",
    mitre_techniques: &["T1115"],
    fields: &[
        FieldSchema {
            name: "metadata_json",
            value_type: ValueType::Json,
            description: "Plaintext JSON per item: timestamp (copy time), formatId (data type). \
                Located at Pinned\\<GUID>\\<item-GUID>\\metadata.json.",
            is_uid_component: false,
        },
        FieldSchema {
            name: "encrypted_payload",
            value_type: ValueType::Bytes,
            description: "Encrypted binary payload file inside each item GUID folder. \
                Not directly readable; requires cbdhsvc COM interface or memory extraction.",
            is_uid_component: false,
        },
    ],
    retention: Some("Persists until clipboard history cleared or feature disabled"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["windows_clipboard_history", "windows_timeline"],
    sources: &[
        // Source: Carvey 2026-01 — primary IR reference documenting clipboard as expanding attack surface
        "https://windowsir.blogspot.com/2026/01/whats-on-your-clipboard.html",
        // Source: ThinkDFIR 2018-10 — original folder layout research (Pinned/HistoryData structure)
        "https://thinkdfir.com/2018/10/14/clippy-history/",
        // Source: ClipboardHistoryThief — attack tool targeting cbdhsvc COM interface
        "https://github.com/netero1010/ClipboardHistoryThief",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Encrypted payloads require key material to decrypt",
        "Only present when clipboard history is enabled (not default)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Clipboard items rotate as new content copied; max 25 items retained",
};

/// Windows Defender MpWppTracing-*.bin support log files.
///
/// Defender writes WPP (Windows software trace preprocessor) binary trace files
/// into `C:\ProgramData\Microsoft\Windows Defender\Support\` with the naming
/// convention `MpWppTracing-YYYYMMDD-HHMMSS-00000003-fffffffeffffffff.bin`.
/// The trailing 64-bit hex pair is the WPP keyword/level mask. Despite the
/// `.bin` extension and what some posts call them ("diagnostic logs"), the
/// canonical Microsoft term is "support log" — these are WPP traces, not ETL,
/// and not the same as the text `MPLog-*.log` files (covered by
/// `fa_file_support_mplog_log_2`) in the same folder.
///
/// `strings` extracts string fragments but loses structure. The Intrinsec
/// `mplog_parser` Python tool (https://github.com/Intrinsec/mplog_parser) is
/// the community parser Carvey identifies in his 2026-01 post — it decodes
/// the WPP records into something analyst-readable.
///
/// Carvey reports having pulled these from endpoints during IR but not yet
/// surfacing incident-relevant content from them — meaning their evidentiary
/// value is opportunistic (process scans, real-time protection state, signature
/// updates, threat detections at WPP keyword level) rather than a reliable
/// every-incident anchor.
pub(crate) static WINDOWS_DEFENDER_MPWPPTRACING: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_defender_mpwpptracing",
    name: "Windows Defender Support Logs (MpWppTracing-*.bin, WPP traces)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Windows Defender\Support\MpWppTracing-*.bin"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "WPP (Windows software trace preprocessor) binary trace files written by \
        Defender into C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\. Naming \
        convention: MpWppTracing-YYYYMMDD-HHMMSS-00000003-fffffffeffffffff.bin where the \
        leading timestamp is the file rotation/creation time (UTC) and the trailing 64-bit \
        hex pair is the WPP keyword/level mask. Despite some community posts calling these \
        'diagnostic logs', Microsoft's canonical term is 'support log'. Distinct from the \
        text MPLog-*.log file in the same folder (text logger, not WPP). `strings` is the \
        crude fallback; the Intrinsec mplog_parser Python tool decodes the WPP records into \
        readable form. Opportunistic evidence value: Defender internal traces of process \
        scans, real-time protection state changes, signature updates, and threat detection \
        at the WPP keyword level — not always populated with incident-relevant content.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "filename_timestamp",
            value_type: ValueType::Timestamp,
            description: "YYYYMMDD-HHMMSS portion of the filename — UTC file rotation time \
                set at WPP session start. Anchors when the trace session began.",
            is_uid_component: true,
        },
        FieldSchema {
            name: "wpp_keyword_mask",
            value_type: ValueType::Text,
            description: "Trailing 64-bit hex pair (e.g. 00000003-fffffffeffffffff) encoding \
                the WPP keyword/level mask the session was opened with. 00000003 + \
                fffffffeffffffff is the standard Defender support trace mask.",
            is_uid_component: false,
        },
        FieldSchema {
            name: "wpp_records",
            value_type: ValueType::Bytes,
            description: "Binary WPP trace records — provider GUID, message ID, and arg \
                blob per record. Requires a TMF (trace message format) decoder or the \
                Intrinsec mplog_parser to render readable.",
            is_uid_component: false,
        },
    ],
    retention: Some("Rotated by Defender; older files persist until folder cleanup or reimage"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &[
        "kape_file_windows_defender_support",
        "fa_file_support_mplog_log_2",
        "windows_defender_disabled_av",
    ],
    sources: &[
        // Source: Carvey 2026-01 — primary post identifying the file, naming convention,
        // and pointing to mplog_parser as the community parser
        "https://windowsir.blogspot.com/2026/01/windows-defender-support-logs.html",
        // Source: Intrinsec mplog_parser — the Python parser Carvey identifies for
        // decoding the WPP binary records
        "https://github.com/Intrinsec/mplog_parser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "WPP binary format requires Microsoft TMF files or Intrinsec mplog_parser to decode",
        "Trace content depends on enabled WPP keywords; not always incident-relevant",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Defender support trace files rotate with size limits",
};

/// PSEXESVC.exe — the service binary Sysinternals PsExec drops on the TARGET host on
/// every remote run. Distinct from the generic 7045 service-installed event: this is
/// the on-disk file, whose presence and MFT birth (B) timestamp prove the host was the
/// target of PsExec and date the execution.
///
/// Source: <https://learn.microsoft.com/en-us/sysinternals/downloads/psexec> (behaviour)
/// Source: <https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive> (artifact set)
/// MITRE: T1569.002 (Service Execution), T1570 (Lateral Tool Transfer), T1021.002 (SMB/Admin Shares)
pub(crate) static PSEXESVC_DROPPED_BINARY: ArtifactDescriptor = ArtifactDescriptor {
    id: "psexesvc_dropped_binary",
    name: "PsExec service binary (PSEXESVC.exe) on target",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\PSEXESVC.exe"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "On a REMOTE PsExec run, the source host stages a service binary (default \
PSEXESVC.exe) to the target's ADMIN$ share, landing it in C:\\Windows, then installs and \
starts it as the PSEXESVC service running as NT AUTHORITY\\SYSTEM (generating a 7045) and \
deletes it when the command finishes. Its presence, and its MFT birth (B) timestamp, prove \
the host was the TARGET of PsExec and date the execution; because it is recreated fresh on \
every run and removed afterwards, the drop is a per-run artifact usually recovered from the \
USN journal ($j), $I30 directory-index slack, or unallocated $MFT rather than as a live file. \
LOCAL PsExec drops no binary (it uses the Service Control Manager APIs directly), so this \
artifact is specific to remote/lateral use. The name is not a reliable signature: the -r flag \
renames the service, binary and named pipes to an attacker-chosen string, and Impacket's \
psexec drops a RemCom-derived binary instead — identify by scanning the binary, and correlate \
a matching PSEXESVC prefetch entry and a Type 3 (4624) logon a few milliseconds before the \
service install.",
    mitre_techniques: &["T1569.002", "T1570", "T1021.002"],
    fields: &[
        FieldSchema {
            name: "binary_name",
            value_type: ValueType::Text,
            description: "Service binary filename. Default PSEXESVC.exe, but renamable with -r (attacker-chosen) and Impacket's psexec drops a RemCom-derived binary — treat the name as non-authoritative and confirm by scanning the binary",
            is_uid_component: true,
        },
        FieldSchema {
            name: "mft_birth_time",
            value_type: ValueType::Timestamp,
            description: "$STANDARD_INFORMATION / $FILE_NAME Created (B) timestamp of the dropped binary, dating the PsExec execution; a fresh value on each run",
            is_uid_component: false,
        },
        FieldSchema {
            name: "recovered_from",
            value_type: ValueType::Text,
            description: "Where the (usually deleted) binary was observed: live file, $MFT unallocated, USN journal $j record, or $I30 index slack — reflecting that it is removed after each run",
            is_uid_component: false,
        },
    ],
    retention: Some("Deleted at end of each run; recover from USN journal / $I30 slack / $MFT unallocated"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["prefetch_dir", "usnjrnl", "ntfs_i30_index", "sysinternals_eula"],
    sources: &[
        // Sysinternals PsExec — official tool behaviour (ADMIN$ staging, service install).
        "https://learn.microsoft.com/en-us/sysinternals/downloads/psexec",
        // SANS — PsExec deep-dive: the full target-side artifact set and -r caveat.
        "https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive",
        // AboutDFIR — identifying PsExec across source/target artifacts.
        "https://aboutdfir.com/the-key-to-identify-psexec/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Remote use only — LOCAL PsExec drops no binary (SCM APIs), so absence does not exclude PsExec on the host as a source",
        "The name is renamable with -r and Impacket drops RemCom instead, so the literal filename is not a reliable signature — scan the binary and correlate the service/prefetch/logon",
        "Deleted after each run; a live file may be absent even when PsExec ran — pivot to USN journal / $I30 slack / $MFT unallocated",
        "Proves the host was a PsExec target and dates the run; it does not by itself identify the source host or the command executed",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "Live binary exists only during a run; afterwards it survives as residual $MFT/USN/$I30 traces until overwritten",
};

/// Task-Manager LSASS dump file (`lsass.DMP`) — an on-disk credential-dump artifact.
///
/// Distinct from `mem_user_credentials` (live LSASS creds) and `windows_minidump`
/// (crash dumps): this is the attacker-produced full-memory dump that Task Manager's
/// "Create dump file" writes, from which credentials are extracted offline.
///
/// Source: <https://attack.mitre.org/techniques/T1003/001/> (LSASS Memory)
/// Source: <https://www.atomicredteam.io/docs/atomics/T1003.001> (Task Manager variant)
/// Source: <https://thedfirreport.com/> (Diavol case — taskmgr.exe -> lsass.DMP Sigma rule)
pub(crate) static LSASS_DUMP_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsass_dump_file",
    name: "Task-Manager LSASS dump (lsass.DMP)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\<user>\AppData\Local\Temp\lsass.DMP"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "A full-memory minidump of lsass.exe on disk — a high-fidelity credential-dump \
artifact. The simplest way to produce it is Task Manager (Details tab, right-click lsass.exe, \
\"Create dump file\"), which calls the legitimate MiniDumpWriteDump API (dbghelp.dll) and \
writes <process>.DMP (so lsass.DMP) to the user's %LOCALAPPDATA%\\Temp; Windows Defender does \
not flag this by default. The dump is normally exfiltrated and parsed OFFLINE with Mimikatz \
(sekurlsa::minidump) or pypykatz (pypykatz lsa minidump lsass.dmp) to recover plaintext \
passwords, NTLM hashes and Kerberos tickets. Because the filename is trivially changed (Task \
Manager's default is <process>.DMP; the -r style rename and other tools use arbitrary names), \
hunt by the minidump content signature MDMP (0x504D444D) plus a large file in a user-writable/\
Temp directory, not the literal name. Corroborate the Task-Manager method with a file-create \
event where the creating image is taskmgr.exe and the target ends in lsass.DMP, and the \
broader technique with a handle to lsass.exe whose call trace references dbgcore.dll/dbghelp.dll.",
    mitre_techniques: &["T1003.001"],
    fields: &[
        FieldSchema {
            name: "dump_filename",
            value_type: ValueType::Text,
            description: "Dump file name. Task Manager defaults to <process>.DMP (lsass.DMP), but it is trivially renamable and other tools use arbitrary names — treat the name as non-authoritative and confirm by the MDMP minidump signature",
            is_uid_component: true,
        },
        FieldSchema {
            name: "created_time",
            value_type: ValueType::Timestamp,
            description: "File creation (B) timestamp — the moment LSASS memory was captured",
            is_uid_component: false,
        },
        FieldSchema {
            name: "minidump_signature",
            value_type: ValueType::Text,
            description: "Minidump files begin with the ASCII signature MDMP (0x504D444D); a content check that identifies an LSASS dump even when the file has been renamed",
            is_uid_component: false,
        },
    ],
    retention: Some("Typically deleted after the dump is parsed/exfiltrated; recover from $MFT unallocated, USN journal, or $I30 slack"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["mem_user_credentials", "windows_minidump", "prefetch_dir"],
    sources: &[
        "https://www.atomicredteam.io/docs/atomics/T1003.001",
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md",
        "https://thedfirreport.com/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "The name is attacker-renamable (Task Manager's default is <process>.DMP; other tools use any name), so hunt by the MDMP minidump signature and a large file in a Temp/user-writable dir, not the literal name",
        "A dump on disk shows LSASS memory was captured; it does not by itself prove credentials were extracted (that happens offline) or identify who ran it",
        "Legitimate crash/debug tooling can also produce LSASS minidumps — corroborate with the creating process (file-create by taskmgr.exe -> lsass.DMP, or an lsass handle whose call trace hits dbgcore.dll/dbghelp.dll) and surrounding context",
        "Requires administrative privilege — its presence implies the host was already compromised to that level, usually a prelude to lateral movement",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "Usually deleted after offline parsing/exfiltration; recover from $MFT unallocated, USN journal, or $I30 slack",
};

// ── Assessed artifacts (moved out of descriptors/generated/) ──────────────────
//
// Each of these carries a curated evidence strength and volatility class. No
// upstream corpus supplies that judgement, so it used to be written into the
// generated module by hand after every run — which a full-corpus regeneration
// erased. Here the ingest pipeline sees the id is already catalogued and skips
// its own record, so the judgement survives, and the triage priority is the
// artifact's own rather than the generator's High ceiling.

pub(crate) static FA_FILE_PROGRAMS_RECENTFILECACHE_BCF: ArtifactDescriptor = ArtifactDescriptor {
    id: "fa_file_programs_recentfilecache_bcf",
    name: "WindowsRecentFileCacheBCF",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%%environ_systemroot%%\\AppCompat\\Programs\\RecentFileCache.bcf"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "RecentFileCache.bcf — the Windows 7 Application Experience (ProgramDataUpdater) \
inventory of executables newly encountered on the system, the predecessor of Amcache.hve. On-disk it \
is a variable-length file header beginning with a 4-byte signature at offset 0, followed by a sequence \
of entry records, each a 4-byte UTF-16 character count (including the null terminator) plus a UTF-16LE \
full-path string (per libyal dtformats). It records no timestamps and no hashes.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema {
            name: "entry_path",
            value_type: ValueType::Text,
            description: "UTF-16LE full path of an executable inventoried by Application Experience; the decoded record content (one per entry)",
            is_uid_component: true,
        },
        FieldSchema {
            name: "entry_char_count",
            value_type: ValueType::UnsignedInt,
            description: "UTF-16 character count of the entry's path string, including the null terminator (the 4-byte length prefix preceding each path)",
            is_uid_component: false,
        },
    ],
    retention: None,
    triage_priority: TriagePriority::Low,
    related_artifacts: &["amcache_app_file"],
    sources: &[
        "https://artifacts-kb.readthedocs.io/en/latest/sources/windows/RecentFileCache.html",
        // libyal dtformats — RecentFileCache.bcf on-disk format (RE reference):
        "https://raw.githubusercontent.com/libyal/dtformats/main/documentation/RecentFileCache.bcf%20format.asciidoc",
        // ANSSI CoRIIN 2019 — Amcache analysis; RecentFileCache.bcf is the Win7 predecessor:
        "https://cyber.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf",
        // Eric Zimmerman — RecentFileCacheParser (tool source):
        "https://github.com/EricZimmerman/RecentFileCacheParser",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &[
        "Windows 7 only — replaced by Amcache.hve on Windows 8 and later; absence on Win8+ is expected, not evidentiary (os_scope is stored as Win7Plus for enum compatibility, but the artifact is Win7-specific)",
        "Contains no embedded timestamps and no hashes; only the file's own MFT/last-write time bounds the entries — individual entries cannot be independently dated",
        "Lists executables the Application Experience inventory newly encountered; presence is consistent with the file having existed / been inventoried on the system, not proof a user executed it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "On-disk file in %SystemRoot%\\AppCompat\\Programs; persists until deleted",
};

pub(crate) static KAPE_FILE_1PASSWORD_DATA_1PASSWORD10_SQLITE: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_1password_data_1password10_sqlite",
    name: "1Password Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Local\\1password\\data'1Password10.sqlite'"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Database which holds information about 1Password installation, such as accounts, categories, settings and more\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/1Password.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_1PASSWORD_BACKUPS_1PASSWORD10_SQLITE: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "kape_file_1password_backups_1password10_sqlite",
        name: "1Password Backup Databases",
        artifact_type: ArtifactLocation::File,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some(
            "C:\\Users\\%user%\\AppData\\Local\\1password\\backups'1Password10.sqlite'",
        ),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "\"Backups of 1Password Database\"",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &[
            "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/1Password.tkape",
        ],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
        evidence_caveats: &[
            "Encrypted browser passwords; key in OS credential store; timestamp shows last use",
        ],
        volatility: Some(crate::volatility::VolatilityClass::Persistent),
        volatility_rationale: "Credential store persists until browser profile deletion",
    };

pub(crate) static KAPE_FILE_1PASSWORD_LOGS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_1password_logs_log",
    name: "1Password Logs",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Local\\1password\\logs'*.log'"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning:
        "\"Log of usage of 1Password - can be useful for identifying periods of user activity\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/1Password.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Encrypted browser passwords; key in OS credential store; timestamp shows last use",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_AWS_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_aws_credentials",
    name: "AWS CLI Credentials",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\.aws\\'credentials'"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Collects AWS CLI credential file\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/DeveloperCloudCredentials.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["AWS access key ID and secret; timestamp indicates when last modified"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential file persists until key rotation",
};

pub(crate) static KAPE_FILE_USER_GIT_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_user_git_credentials",
    name: "Git Credentials",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\'.git-credentials'"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Collects Git stored credentials\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/DeveloperCloudCredentials.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Repository tokens; check for non-corporate VCS hosts"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Git credential helper store persists until credential deletion",
};

pub(crate) static KAPE_FILE_FREE_DOWNLOAD_MANAGER_FDM_SQLITE: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_free_download_manager_fdm_sqlite",
    name: "FDM Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Local\\Free Download Manager\\\"fdm.sqlite\""),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"fdm.sqlite shows Torrents, downloads, folder history, auth credentials and more. Will also pull fdm.sqlite in db_backup/\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/FreeDownloadManager.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["May contain saved FTP/HTTP credentials; check for non-standard download sources"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Download manager credential database persists until uninstall",
};

pub(crate) static KAPE_FILE_MY_CERTIFICATES: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_my_certificates",
    name: "RDCMan Personal Certificate",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        "C:\\Users%user%\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates",
    ),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Encryption Certificate for stored passwords\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RDCMan.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Personal certificates including private keys; check for self-signed or unexpected issuers",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Certificate store persists until certificate deletion",
};

pub(crate) static KAPE_FILE_LOGINS_JSON: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_logins_json",
    name: "Mozilla Thunderbird logins.json",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Roaming\\Thunderbird\\Profiles\\*\\\"logins.json\""),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Holds last time online login used, last time password changed, hostname, HTTP(s) URL and more\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Thunderbird.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_MREMOTENG_CONFCONS_XML: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_mremoteng_confcons_xml",
    name: "mRemoteNG Connection Configuration and Backups",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Roaming\\mRemoteNG\\confCons.xml*"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Contains connection config, often with obfuscated credentials",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/mRemoteNG.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted vault; master password hash extractable for offline attack"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Password manager database persists until application uninstall",
};

pub(crate) static KAPE_FILE_KEY_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_key_db",
    name: "Password",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\key*.db"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted vault; master password hash extractable for offline attack"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Password manager database persists until application uninstall",
};

pub(crate) static KAPE_FILE_SIGNON: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_signon",
    name: "Password",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        "C:\\Users\\%user%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\signon*.*",
    ),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Encrypted browser passwords; key in OS credential store; timestamp shows last use",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_LOGINS_JSON_2: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_logins_json_2",
    name: "Password",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        "C:\\Users\\%user%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json",
    ),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Encrypted browser passwords; key in OS credential store; timestamp shows last use",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_PASSWORD_XP: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_password_xp",
    name: "Password XP",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Documents and Settings\\%user%\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\key*.db"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password XP — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_SIGNON_2: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_signon_2",
    name: "Password XP",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Documents and Settings\\%user%\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\signon*.*"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password XP — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_LOGINS_JSON_2_2: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_logins_json_2_2",
    name: "Password XP",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Documents and Settings\\%user%\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\logins.json"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Password XP — collected by KAPE Firefox target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Firefox.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_LOCAL_PUFFINSECUREBROWSERPASSWORDFORMS_DAT: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_local_puffinsecurebrowserpasswordforms_dat",
    name: "Puffin - Password Forms Data",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Local\\PuffinSecureBrowserpasswordForms.dat"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Grabs a file that stores some saved password data\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/PuffinSecureBrowser.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static KAPE_FILE_LOCAL_PUFFINSECUREBROWSERCREDENTIAL_DAT: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_local_puffinsecurebrowsercredential_dat",
    name: "Puffin - Password (Encrypted)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Users\\%user%\\AppData\\Local\\PuffinSecureBrowsercredential.dat"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "\"Grabs a file that stores passwords in an encrypted format\"",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/PuffinSecureBrowser.tkape"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Browser-saved form passwords; check timestamp against incident window"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Browser credential file persists until app data deletion",
};

pub(crate) static KAPE_FILE_WINDOWS_NTDS: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_windows_ntds",
    name: "NTDS",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows\\NTDS"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "NTDS — collected by KAPE ActiveDirectoryNTDS target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/ActiveDirectoryNTDS.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &[
        "Domain credential store; offline cracking risk; compare hash count against user count",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Active Directory database persists until DC decommission",
};

pub(crate) static KAPE_FILE_CONFIG_SAM_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_config_sam_log",
    name: "SAM registry transaction files",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows\\System32\\config\\SAM.LOG*"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry transaction files — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};

pub(crate) static KAPE_FILE_SAM_REGISTRY_TRANSAC: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_sam_registry_transac",
    name: "SAM registry transaction files",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows.old\\Windows\\System32\\config\\SAM.LOG*"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry transaction files — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Verify presence against incident timeline; correlate with other triage artifacts",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Artifact persists until explicit deletion",
};

pub(crate) static KAPE_FILE_CONFIG_SAM: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_config_sam",
    name: "SAM registry hive",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows\\System32\\config\\SAM"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry hive — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};

pub(crate) static KAPE_FILE_SAM_REGISTRY_HIVE: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_sam_registry_hive",
    name: "SAM registry hive",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows.old\\Windows\\System32\\config\\SAM"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry hive — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};

pub(crate) static KAPE_FILE_REGBACK_SAM: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_regback_sam",
    name: "SAM registry hive (RegBack)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows\\System32\\config\\RegBack\\SAM"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry hive (RegBack) — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Verify presence against incident timeline; correlate with other triage artifacts",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Artifact persists until explicit deletion",
};

pub(crate) static KAPE_FILE_SAM_REGISTRY_HIVE_RE: ArtifactDescriptor = ArtifactDescriptor {
    id: "kape_file_sam_registry_hive_re",
    name: "SAM registry hive (RegBack)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:\\Windows.old\\Windows\\System32\\config\\RegBack\\SAM"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SAM registry hive (RegBack) — collected by KAPE RegistryHivesSystem target",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        "https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/RegistryHivesSystem.tkape",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};

pub(crate) static NIRSOFT_NETWORK_PASSWORDS_CRED_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "nirsoft_network_passwords_cred_dir",
    name: "NetworkPasswordRecovery — Credentials Store",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%APPDATA%\\Microsoft\\Credentials"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Windows Credential Manager store. May contain cached network passwords and domain credentials. Parsed by NirSoft NetworkPasswordRecovery.",
    mitre_techniques: &["T1555.004"],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://www.nirsoft.net/utils/network_password_recovery.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Credential store persists until browser profile deletion",
};

pub(crate) static VELOCIRAPTOR_FILE_TMP_COLLECTION_ZIP: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_tmp_collection_zip",
    name: "Windows.Collectors.Remapping",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/tmp/collection.zip"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Calculates a remapping config for a collection container (zip).

The remapping allows Velociraptor to treat the collection container as a dead
disk image in a similar way to `Generic.Utils.DeadDiskRemapping`. This means
that you can directly analyze the files contained in the collection zip file,
without needing to extract or import it.

There are 2 ways to use the remapping generated by this artifact:

1. Non-interactive command line analysis, as per the example below. \\
   This approach only requires a Velociraptor binary, i.e. it  does not
   require a server or client, and then uses either the CLI `artifacts
   collect` or `query` commands.

2. Interactive \"virtual\" client managed via the Velociraptor GUI (see
   reference below). \\
   This approach uses a client which connects to the server. The client
   accesses the collection container as a simulated filesystem using the
   remapping that this artifact generates.

In both cases it uses the remapping impersonation feature to impersonate the
original endpoint's name and platform (Windows). Because of this
impersonation the virtual client can be run on Linux while still appearing as
Windows to artifacts and queries.

Collection containers are typically created by offline collectors using the
`Windows.Triage.Targets` or `Windows.KapeFiles.Targets` artifacts and contain
files collected from the endpoint, although any artifact that \"uploads\" files
as part of the collection can be used.

Collection containers can also be created by exporting collections from the
GUI, using the \"Download Results\" facility. This allows you to port
collections across servers - perhaps to allow an independent analyst to
examine some files and run further collections without giving them access to
your server. If they don't have their own Velociraptor server, they can do
serverless collections/queries as in the following example.

### Example - command line use

1. Collect files using a bulk file collection artifact - For example
   `Windows.Triage.Targets` with the `_BasicCollection` target is a good
   option.

2. Generate the remapping file:
   ```
   velociraptor artifacts collect -v Windows.Collectors.Remapping \\
     --args ZipPath=/path/to/collection.zip \\
     --args WriteRemappingPath=/tmp/remapping.yaml
   ```

3. Apply the remapping file when collecting further artifacts. These
   collections will target the files in the container:
   ```
   velociraptor --remap /tmp/remapping.yaml \\
     artifacts collect -v Windows.Registry.Hunter \\
     --args RemappingStrategy=None
   ```
   The CLI query command can also be used for running ad-hoc queries:
   ```
   velociraptor --remap /tmp/remapping.yaml query \"SELECT * FROM ... \"
   ```

### Notes

- Direct analysis of collection containers protected by fixed passwords or
  X.509 certificates is supported. For password-protected containers you'll
  need to provide the password explicitly as a parameter. For X.509-protected
  containers they are transparently decrypted _if they are secured with your
  servers cert and you are running this artifact in the GUI_. If you are
  running this artifact on the command line then you'll need to supply the
  server config as an additional command line argument (using the `-c` flag).
  Alternatively you can remove the protection from the container first using
  the `decrypt` CLI command. Removing the protection first is also necessary
  if the container was secured using an X.509 (or PGP) cert other than your
  server's one.

- If you want to run `Windows.Registry.Hunter` against the data, you'll need
  to disable its own remapping config (i.e. `RemappingStrategy: none`) so that
  it doesn't interfere with the remapping created by this artifact.

- The remapping currently doesn't support Volume Shadow Copies contained in
  the collection, however you can still access these files via VQL by
  specifying their paths (e.g.
  `GLOBALROOT\\DEVICE\\HARDDISKVOLUMESHADOWCOPY1\\Windows\\...`)
  which are located outside of any remapped drive roots.

- VFS browsing of the collection container currently doesn't work.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &[
        "Presence indicates active Velociraptor collection; metadata reveals scope",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Temporary collection ZIP is volatile and deleted after upload",
};

pub(crate) static VELOCIRAPTOR_FILE_LOGS_SECURITY_EVTX: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_logs_security_evtx",
    name: "Windows.EventLogs.AlternateLogon",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:/Windows/System32/Winevt/Logs/Security.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Logon specifying alternate credentials - if NLA enabled on
destination Current logged-on User Name Alternate User Name
Destination Host Name/IP Process Name",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Velociraptor-collected EVTX; check collection timestamp vs log timespan"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Collected EVTX rotates; velociraptor copy is point-in-time",
};

pub(crate) static VELOCIRAPTOR_FILE_LOGS_MICROSOFT_WINDOWS_TASKSCHEDULER_4OPER: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_logs_microsoft_windows_taskscheduler_4oper",
    name: "Windows.EventLogs.ScheduledTasks",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "This artifact will extract Event Logs related to ScheduledTasks and provide
a nice format for simplified review.

Adversaries may abuse tasks for execution, persistence, lateral movement or
privilege escalation. This artifact collates all events from
Microsoft-Windows-TaskScheduler/Operational event log channel and scheduled
task events from the Security log if configured.

A common hunting use case may be collection all deleted scheduled tasks (EID 141),
all modified scheduled tasks (EID 140) then run frequency analysis and chase
down any abnormalities for the environment. Similarly task execution (EID 129)
and registration (EID 106) can be a good collection hunting for unusual paths.

Pivoting can be via either: TaskSchedulerEventRegex, TaskName or IOC Regex
(e.g taskname|delete|created|update)

Note: Audit Other Object Access Events is required to be implemented to record
scheduled tasks being registered, modified or disabled in the Security event
log channel.
See: Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Object Access",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Scheduled task execution; correlate with persistence keys"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Task scheduler log rotates; collected copy is point-in-time",
};

pub(crate) static VELOCIRAPTOR_FILE_CONFIG_SAM: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_config_sam",
    name: "Windows.Forensics.SAM",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("C:/Windows/System32/Config/SAM"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Parses user account information from the SAM hive.

Based on Omer Yampel's parser",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "SAM hive persists across reboots; protected in-use by Windows",
};
