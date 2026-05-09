//! Extended Windows file and directory artifact descriptors — Phase 2.
//!
//! Sources: KAPE targets (EricZimmerman/KapeFiles), Velociraptor artifact definitions,
//! SANS FOR508, BlueTeamLabs, DFIR.blog, 13cubed research.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

// ── Browser History ───────────────────────────────────────────────────────────

pub(crate) static CHROME_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_history",
    name: "Chrome Browsing History (SQLite)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static CHROME_WEB_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_web_data",
    name: "Chrome Web Data (SQLite)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static EDGE_CHROMIUM_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_chromium_history",
    name: "Edge (Chromium) Browsing History (SQLite)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static EDGE_CHROMIUM_LOGIN_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_chromium_login_data",
    name: "Edge (Chromium) Login Data (SQLite)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static FIREFOX_PLACES: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_places",
    name: "Firefox places.sqlite (History + Bookmarks)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static FIREFOX_FORM_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_form_history",
    name: "Firefox formhistory.sqlite",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static FIREFOX_SESSION_RESTORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_session_restore",
    name: "Firefox sessionstore.jsonlz4 (Session Restore)",
    artifact_type: ArtifactType::File,
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
};

// ── PowerShell ────────────────────────────────────────────────────────────────

pub(crate) static PSREADLINE_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "psreadline_history",
    name: "PSReadLine Console History (User)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static PSREADLINE_HISTORY_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "psreadline_history_system",
    name: "PSReadLine Console History (SYSTEM account)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static POWERSHELL_TRANSCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_transcripts",
    name: "PowerShell Transcript Logs",
    artifact_type: ArtifactType::Directory,
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
};

// ── Remote Access Tools ───────────────────────────────────────────────────────

pub(crate) static TEAMVIEWER_CONNECTION_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "teamviewer_connection_log",
    name: "TeamViewer Incoming Connections Log",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static TEAMVIEWER_APP_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "teamviewer_app_log",
    name: "TeamViewer Application Log",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static ANYDESK_TRACE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_trace_user",
    name: "AnyDesk Trace Log (User)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static ANYDESK_TRACE_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_trace_system",
    name: "AnyDesk Service Trace Log (System)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static ANYDESK_CONNECTION_TRACE: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_connection_trace",
    name: "AnyDesk Connection Trace",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static ANYDESK_FILE_TRANSFER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "anydesk_file_transfer_log",
    name: "AnyDesk File Transfer Log",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static SCREENCONNECT_SESSION_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "screenconnect_session_db",
    name: "ScreenConnect / ConnectWise Control Session Database",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static RUSTDESK_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rustdesk_logs",
    name: "RustDesk Logs Directory",
    artifact_type: ArtifactType::Directory,
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
};

// ── Cloud Storage ─────────────────────────────────────────────────────────────

pub(crate) static DROPBOX_INSTANCE_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "dropbox_instance_db",
    name: "Dropbox Instance Database Directory",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static ONEDRIVE_METADATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "onedrive_metadata",
    name: "OneDrive Sync Client Metadata",
    artifact_type: ArtifactType::Directory,
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
/// Source: http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html
/// Source: http://www.swiftforensics.com/2022/11/reading-onedrive-logs-part-2.html
pub(crate) static ONEDRIVE_ODL_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "onedrive_odl_logs",
    name: "OneDrive ODL Diagnostic Logs",
    artifact_type: ArtifactType::File,
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
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static MEGASYNC_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "megasync_data",
    name: "MEGAsync Cloud Storage Data",
    artifact_type: ArtifactType::Directory,
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
};

// ── Communications ────────────────────────────────────────────────────────────

pub(crate) static TEAMS_INDEXED_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "teams_indexed_db",
    name: "Microsoft Teams IndexedDB (Chat History)",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static SLACK_INDEXED_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "slack_indexed_db",
    name: "Slack IndexedDB (Message Cache)",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static DISCORD_LOCAL_STORAGE: ArtifactDescriptor = ArtifactDescriptor {
    id: "discord_local_storage",
    name: "Discord Local Storage (LevelDB)",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static SIGNAL_DATABASE: ArtifactDescriptor = ArtifactDescriptor {
    id: "signal_database",
    name: "Signal Desktop Message Database",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static SIGNAL_CONFIG_JSON: ArtifactDescriptor = ArtifactDescriptor {
    id: "signal_config_json",
    name: "Signal Desktop config.json (DB Encryption Key)",
    artifact_type: ArtifactType::File,
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
    artifact_type: ArtifactType::EseDatabase,
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
};

pub(crate) static EVENT_TRANSCRIPT_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "event_transcript_db",
    name: "Windows Telemetry EventTranscript.db",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static CERTUTIL_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "certutil_cache",
    name: "CertUtil URL Cache (certutil -urlcache)",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static SDB_CUSTOM_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "sdb_custom_files",
    name: "Custom AppCompat Shim Database Files",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static WER_REPORTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports",
    name: "Windows Error Reporting Queue",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static IIS_W3SVC_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "iis_w3svc_logs",
    name: "IIS W3C HTTP Access Logs",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static IIS_CONFIG_APPLICATIONHOST: ArtifactDescriptor = ArtifactDescriptor {
    id: "iis_config_applicationhost",
    name: "IIS applicationHost.config",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static DNS_DEBUG_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "dns_debug_log",
    name: "DNS Server Debug Log",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static DHCP_SERVER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "dhcp_server_log",
    name: "Windows DHCP Server Log",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static SUM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "sum_db",
    name: "User Access Logging (SUM) Database",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static COPILOT_RECALL_UKG: ArtifactDescriptor = ArtifactDescriptor {
    id: "copilot_recall_ukg",
    name: "Windows Recall Screenshot Index (ukg.db)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static NTUSER_DAT_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntuser_dat_file",
    name: "NTUSER.DAT (Per-User Registry Hive)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static USRCLASS_DAT_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "usrclass_dat_file",
    name: "UsrClass.dat (User Classes Registry Hive)",
    artifact_type: ArtifactType::File,
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
};

// ── Group A: Windows Plaintext Logs ──────────────────────────────────────────

pub(crate) static CBS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "cbs_log",
    name: "CBS.log (Component Based Servicing Log)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static PFRO_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "pfro_log",
    name: "PFRO.log (Pending File Rename Operations Log)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static SETUPERR_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "setuperr_log",
    name: "setuperr.log (Windows Setup Error Log)",
    artifact_type: ArtifactType::File,
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
};

pub(crate) static SETUPAPI_UPGRADE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "setupapi_upgrade_log",
    name: "setupapi.upgrade.log (In-Place Upgrade Driver Log)",
    artifact_type: ArtifactType::File,
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
};

// ── Group B: Windows Error Reporting Split ────────────────────────────────────

pub(crate) static WER_REPORTS_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports_user",
    name: "WER ReportArchive (User-scope Crash Reports)",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static WER_REPORTS_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "wer_reports_system",
    name: "WER ReportArchive (System-scope Crash Reports)",
    artifact_type: ArtifactType::Directory,
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
};

// ── Group F: Windows AppX/Modern App ─────────────────────────────────────────

pub(crate) static APPX_PACKAGES_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "appx_packages_user",
    name: "AppX/UWP Package Data Directory",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static APPX_INSTALL_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "appx_install_log",
    name: "DISM.log (Deployment Image Servicing Log)",
    artifact_type: ArtifactType::File,
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
};

// ── Group G: Windows Diagnostic/Telemetry ────────────────────────────────────

pub(crate) static DIAGNOSTIC_DATA_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "diagnostic_data_dir",
    name: "Windows Diagnostic Data ETL Directory",
    artifact_type: ArtifactType::Directory,
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
};

pub(crate) static WINDOWS_UPDATE_SESSION: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_update_session",
    name: "Windows Update ReportingEvents.log",
    artifact_type: ArtifactType::File,
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
    artifact_type: ArtifactType::File,
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
    artifact_type: ArtifactType::File,
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
    artifact_type: ArtifactType::File,
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
};
