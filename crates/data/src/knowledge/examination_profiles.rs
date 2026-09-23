//! Static [`ExaminationProfile`] instances and the [`EXAMINATION_PROFILES`]
//! slice.
//!
//! A profile is a reusable examination checklist over the artifact catalog:
//! the artifacts to pull for a stated examination goal on one platform, each
//! member referencing an [`crate::catalog::ArtifactDescriptor`] by id and
//! carrying its own rationale, grouped by [`InvestigativeCategory`]. The core
//! crate owns the schema; this module owns the entries, the same core/data
//! split as `catalog` and the other knowledge types.
//!
//! Every member id MUST resolve to a real descriptor in
//! [`crate::catalog::CATALOG`]; that referential integrity is the load-bearing
//! correctness property and is enforced in `tests.rs`. Where an examination
//! area has no catalog descriptor yet, the gap is left out and recorded in the
//! review notes rather than papered over with an invented id.
//!
//! The macOS gaps this profile work first flagged — the OpenBSM audit trail
//! (`/var/audit`), the `dslocal` local account store, AirDrop/`sharingd`
//! transfer history, and removable/USB volume history — now have curated
//! descriptors (`macos_openbsm_audit`, `macos_dslocal_users`,
//! `macos_airdrop_sharingd`, `macos_usb_mass_storage_log`) and are wired in
//! below. Safari cookies are represented by the curated `macos_safari_cookies`
//! rather than the generated `browsers_safari_cookies`, which is mis-scoped
//! `OsScope::Win7Plus` in the auto-generated catalog (a known defect in the
//! generated data that must not be hand-edited; the curated descriptor carries
//! the correct macOS path and scope).
//!
//! Members prefer curated `macos_*` descriptors. A handful of auto-generated
//! `fa_file_*` descriptors remain where they are the only representation of a
//! named artifact (Accounts4, MobileMeAccounts, the loginwindow prefs, the Mail
//! envelope index, periodic/cron, kext Info.plist) and are correctly scoped to
//! macOS — no curated `macos_*` equivalent exists to replace them.

use super::{
    ExaminationFocus, ExaminationProfile, InvestigativeCategory, ProfileKind, ProfileMember,
};
use forensicnomicon_core::catalog::Platform;

use InvestigativeCategory as Cat;

/// Comprehensive macOS examination: the artifacts a full user-identity and
/// activity examination of a Mac touches, from accounts and application use
/// through file activity, communications, browsing, printing, and document
/// authorship.
pub static MACOS_FULL: ExaminationProfile = ExaminationProfile {
    id: "macos_full",
    name: "macOS full examination",
    platform: Platform::MacOS,
    kind: ProfileKind::Full,
    focus: ExaminationFocus::FullExamination,
    description: "Comprehensive macOS examination checklist spanning accounts and login, \
                  application use, file activity, connections, communications, web activity, \
                  cloud storage, printing, and document authorship. Intended as the starting \
                  scope for a broad user-identity and activity examination of a Mac, to be \
                  narrowed by the focused profiles when the question is specific.",
    members: &[
        // ── Account use & login ──────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_keychain_user",
            category: Cat::AccountUse,
            rationale: "User keychain: stored credentials and certificates, and the \
                        trusted-device / iCloud peer records tying the account to hardware.",
        },
        ProfileMember {
            artifact_id: "fa_file_accounts_accounts_sqlite",
            category: Cat::AccountUse,
            rationale: "Accounts4.sqlite: the system account inventory (iCloud, mail, social) \
                        configured for the user.",
        },
        ProfileMember {
            artifact_id: "fa_file_preferences_mobilemeaccounts_plist",
            category: Cat::AccountUse,
            rationale: "MobileMeAccounts.plist: the Apple ID / iCloud account bound to this \
                        user and the services it enables.",
        },
        ProfileMember {
            artifact_id: "fa_file_preferences_loginwindow_plist",
            category: Cat::AccountUse,
            rationale: "com.apple.loginwindow: last logged-in user and auto-login configuration.",
        },
        ProfileMember {
            artifact_id: "macos_dslocal_users",
            category: Cat::AccountUse,
            rationale: "dslocal account store: the authoritative inventory of local accounts on \
                        the Mac — uid, generateduid, realname, home, shell — establishing who has \
                        an account and their identity attributes.",
        },
        ProfileMember {
            artifact_id: "macos_openbsm_audit",
            category: Cat::AccountUse,
            rationale: "OpenBSM audit trail: login/logout, account creation, and boot/audit-start \
                        history — the artifact used to establish account creation and when the Mac \
                        was used (where still enabled; deprecated Big Sur, disabled Sonoma).",
        },
        ProfileMember {
            artifact_id: "macos_login_items_plist",
            category: Cat::AccountUse,
            rationale: "Per-user login items launched at sign-in — ties software to the user.",
        },
        ProfileMember {
            artifact_id: "macos_mdm_enrollment",
            category: Cat::AccountUse,
            rationale: "MDM enrollment: whether the device is managed, and by which organisation.",
        },
        // ── Application use ──────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_knowledgec",
            category: Cat::ApplicationUse,
            rationale: "knowledgeC: per-user application focus and usage intervals.",
        },
        ProfileMember {
            artifact_id: "macos_biome_streams",
            category: Cat::ApplicationUse,
            rationale: "Biome: the successor to knowledgeC; segmented app and activity streams.",
        },
        ProfileMember {
            artifact_id: "macos_biome_app_menuitem",
            category: Cat::ApplicationUse,
            rationale: "Biome app menu-item events: fine-grained in-application actions.",
        },
        ProfileMember {
            artifact_id: "macos_screen_time_db",
            category: Cat::ApplicationUse,
            rationale: "Screen Time: aggregated per-application usage attributable to the user.",
        },
        ProfileMember {
            artifact_id: "macos_coreanalytics",
            category: Cat::ApplicationUse,
            rationale: "CoreAnalytics: daily application launch and usage aggregates.",
        },
        ProfileMember {
            artifact_id: "macos_install_history",
            category: Cat::ApplicationUse,
            rationale: "InstallHistory.plist: software installed and updated over time.",
        },
        ProfileMember {
            artifact_id: "macos_installer_receipts",
            category: Cat::ApplicationUse,
            rationale: "Installer receipts (.bom/.plist): package installation provenance.",
        },
        ProfileMember {
            artifact_id: "macos_saved_application_state",
            category: Cat::ApplicationUse,
            rationale: "Saved application state: windows and documents open at last quit.",
        },
        ProfileMember {
            artifact_id: "macos_applist_dat",
            category: Cat::ApplicationUse,
            rationale: "applist.dat: the launch-services application inventory.",
        },
        ProfileMember {
            artifact_id: "macos_unified_log",
            category: Cat::ApplicationUse,
            rationale: "Unified log: process launches, sessions, and system activity (short \
                        retention, collect early).",
        },
        ProfileMember {
            artifact_id: "quicklook_thumbnails",
            category: Cat::ApplicationUse,
            rationale: "QuickLook thumbnail cache: files the user previewed, with their paths.",
        },
        // ── File activity ────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_fsevents",
            category: Cat::FileActivity,
            rationale: "fseventsd: directory-level change history, including external volume mounts.",
        },
        ProfileMember {
            artifact_id: "macos_spotlight_store",
            category: Cat::FileActivity,
            rationale: "Spotlight metadata store: indexed file inventory and rich metadata.",
        },
        ProfileMember {
            artifact_id: "fa_file_spotlight_v100_volumeconfiguration_plist",
            category: Cat::FileActivity,
            rationale: "Spotlight VolumeConfiguration.plist: which volumes were indexed — the \
                        scope and configuration of the index above.",
        },
        ProfileMember {
            artifact_id: "macos_sfl2_recent_items",
            category: Cat::FileActivity,
            rationale: "SFL2 recent items: recently opened documents and applications.",
        },
        ProfileMember {
            artifact_id: "macos_document_revisions",
            category: Cat::FileActivity,
            rationale: "DocumentRevisions: version history of edited documents.",
        },
        ProfileMember {
            artifact_id: "macos_document_revisions_chunkstore",
            category: Cat::FileActivity,
            rationale: "DocumentRevisions ChunkStorage: the actual revision content chunks.",
        },
        ProfileMember {
            artifact_id: "macos_ds_store",
            category: Cat::FileActivity,
            rationale: ".DS_Store: folders the user browsed in Finder, with view state.",
        },
        ProfileMember {
            artifact_id: "macos_trash",
            category: Cat::FileActivity,
            rationale: "Trash: deleted files pending purge, with original path context.",
        },
        ProfileMember {
            artifact_id: "macos_relocated_items",
            category: Cat::FileActivity,
            rationale: "Relocated Items: files moved by OS migration — evidence of an upgrade \
                        or account migration.",
        },
        ProfileMember {
            artifact_id: "macos_lastuseddate_xattr",
            category: Cat::FileActivity,
            rationale: "kMDItemLastUsedDate xattr: last-opened time recorded per file.",
        },
        ProfileMember {
            artifact_id: "macos_wherefroms_xattr",
            category: Cat::FileActivity,
            rationale: "kMDItemWhereFroms xattr: the download origin URL recorded per file.",
        },
        ProfileMember {
            artifact_id: "macos_screenshot_xattrs",
            category: Cat::FileActivity,
            rationale: "Screenshot xattrs: capture metadata marking user-taken screenshots.",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_xattr",
            category: Cat::FileActivity,
            rationale: "com.apple.quarantine xattr: which application downloaded a file, and when.",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_events",
            category: Cat::FileActivity,
            rationale: "LSQuarantineEvents db: system-wide log of downloaded / quarantined files.",
        },
        ProfileMember {
            artifact_id: "macos_photos_db",
            category: Cat::FileActivity,
            rationale: "Photos library database: the user's photo and video library and metadata.",
        },
        ProfileMember {
            artifact_id: "macos_photos_derivatives",
            category: Cat::FileActivity,
            rationale: "Photos derivatives: rendered thumbnails and edit renderings.",
        },
        // ── Connections ──────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_network_interfaces",
            category: Cat::Connections,
            rationale: "NetworkInterfaces.plist: which physical interfaces the Mac has and their \
                        hardware MACs (IOMACAddress) — the anchor tying a captured MAC or \
                        router record to a specific interface.",
        },
        ProfileMember {
            artifact_id: "macos_network_preferences",
            category: Cat::Connections,
            rationale: "preferences.plist: per-service IPv4 ConfigMethod (DHCP/Manual/BOOTP), \
                        static addresses, and the service order / primary interface — how the \
                        Mac was configured to reach the network.",
        },
        ProfileMember {
            artifact_id: "macos_wifi_plist",
            category: Cat::Connections,
            rationale: "Known Wi-Fi networks the Mac has joined (legacy pre-Big Sur airport \
                        preferences format).",
        },
        ProfileMember {
            artifact_id: "macos_wifi_known_networks",
            category: Cat::Connections,
            rationale: "com.apple.wifi.known-networks.plist (Big Sur+): remembered Wi-Fi networks \
                        with per-AP BSSID list (LEAKY_AP_BSSID), channel history and join times — \
                        the BSSIDs are the geolocation handle.",
        },
        ProfileMember {
            artifact_id: "macos_wifi_intelligence",
            category: Cat::Connections,
            rationale: "WiFi intelligence: association history and location hints.",
        },
        ProfileMember {
            artifact_id: "macos_dhcp_leases",
            category: Cat::Connections,
            rationale: "DHCP leases: internal IP, gateway and gateway MAC, the Wi-Fi SSID joined, \
                        and when — the LAN side of network correlation (macOS does not store the \
                        public IP).",
        },
        ProfileMember {
            artifact_id: "macos_locationd_clients",
            category: Cat::Connections,
            rationale: "locationd clients: applications that requested the device location.",
        },
        ProfileMember {
            artifact_id: "macos_lockdownd_log",
            category: Cat::Connections,
            rationale: "lockdownd log: iOS devices paired to this Mac over USB.",
        },
        ProfileMember {
            artifact_id: "macos_sfl2_recent_servers",
            category: Cat::Connections,
            rationale: "SFL2 recent servers: recently connected file-share servers.",
        },
        ProfileMember {
            artifact_id: "macos_usb_mass_storage_log",
            category: Cat::Connections,
            rationale: "USBMSC unified-log entries: removable USB mass-storage devices attached to \
                        the Mac, with vendor/product/serial — the honest (log-only, no USBSTOR) \
                        macOS record of external media use.",
        },
        ProfileMember {
            artifact_id: "macos_airdrop_sharingd",
            category: Cat::Connections,
            rationale: "AirDrop/sharingd activity in the unified log: peer devices files were \
                        AirDropped to or from, by device name and AirDrop ID.",
        },
        // ── Communications ───────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_sms_db",
            category: Cat::Communications,
            rationale: "Messages (chat.db): iMessage and SMS conversations and attachments.",
        },
        ProfileMember {
            artifact_id: "macos_notes_db",
            category: Cat::Communications,
            rationale: "Notes database: note content and metadata.",
        },
        ProfileMember {
            artifact_id: "macos_notes_attachment_media",
            category: Cat::Communications,
            rationale: "Notes attachment media: images and files embedded in notes.",
        },
        ProfileMember {
            artifact_id: "macos_notes_attachment_previews",
            category: Cat::Communications,
            rationale: "Notes attachment previews.",
        },
        ProfileMember {
            artifact_id: "macos_notes_locked_notes",
            category: Cat::Communications,
            rationale: "Locked (password-protected) notes: their presence and metadata.",
        },
        ProfileMember {
            artifact_id: "macos_notification_center_db",
            category: Cat::Communications,
            rationale: "Notification Center: notifications delivered across applications.",
        },
        ProfileMember {
            artifact_id: "fa_file_maildata_envelope_index",
            category: Cat::Communications,
            rationale: "Mail Envelope Index: message headers, senders, and mailbox structure.",
        },
        ProfileMember {
            artifact_id: "macos_calendar_store",
            category: Cat::Communications,
            rationale: "Calendar store: events attributable to the user.",
        },
        ProfileMember {
            artifact_id: "macos_calendar_archive_icbu",
            category: Cat::Communications,
            rationale: "Calendar .icbu archive exports.",
        },
        // ── Web activity ─────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_safari_history",
            category: Cat::WebActivity,
            rationale: "Safari history: visited URLs and visit times.",
        },
        ProfileMember {
            artifact_id: "macos_safari_downloads",
            category: Cat::WebActivity,
            rationale: "Safari Downloads.plist: files downloaded via Safari.",
        },
        ProfileMember {
            artifact_id: "macos_safari_webkit_cache",
            category: Cat::WebActivity,
            rationale: "Safari WebKit cache: cached page resources.",
        },
        ProfileMember {
            artifact_id: "macos_safari_tab_snapshots",
            category: Cat::WebActivity,
            rationale: "Safari tab snapshots: images of recently open tabs.",
        },
        ProfileMember {
            artifact_id: "macos_safari_localstorage",
            category: Cat::WebActivity,
            rationale: "Safari LocalStorage: per-site persisted web state.",
        },
        ProfileMember {
            artifact_id: "macos_safari_cookies",
            category: Cat::WebActivity,
            rationale: "Safari cookies (Cookies.binarycookies): sites visited and live session \
                        tokens; curated macOS-scoped descriptor, not the mis-scoped generated one.",
        },
        // ── Cloud storage ────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_icloud_drive_db",
            category: Cat::CloudStorage,
            rationale: "iCloud Drive server / client state database.",
        },
        ProfileMember {
            artifact_id: "macos_icloud_drive_containers",
            category: Cat::CloudStorage,
            rationale: "iCloud Drive per-application containers: app data synced to the cloud.",
        },
        // ── Printing ─────────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_cups_spool_jobs",
            category: Cat::Printing,
            rationale: "CUPS spool: queued and printed job data, including document content.",
        },
        ProfileMember {
            artifact_id: "macos_cups_printers_conf",
            category: Cat::Printing,
            rationale: "printers.conf: configured printers and destinations.",
        },
        ProfileMember {
            artifact_id: "macos_cups_logs",
            category: Cat::Printing,
            rationale: "CUPS logs: print job history (page_log / access_log).",
        },
        // ── Document authorship ──────────────────────────────────────────
        ProfileMember {
            artifact_id: "ooxml_core_properties",
            category: Cat::DocumentAuthorship,
            rationale: "OOXML core.xml: Office author, last-modified-by, revision, and timestamps.",
        },
        ProfileMember {
            artifact_id: "ole2_summary_information",
            category: Cat::DocumentAuthorship,
            rationale: "OLE2 SummaryInformation: legacy Office authorship metadata.",
        },
        ProfileMember {
            artifact_id: "iwork_document_package",
            category: Cat::DocumentAuthorship,
            rationale: "iWork package metadata: Pages / Numbers / Keynote authorship.",
        },
        // ── Execution control / privacy posture ──────────────────────────
        ProfileMember {
            artifact_id: "macos_tcc_db",
            category: Cat::ExecutionControl,
            rationale: "User TCC.db: privacy consents (microphone, camera, files) the user granted \
                        — attributes sensitive access to the user.",
        },
        ProfileMember {
            artifact_id: "macos_tcc_system_db",
            category: Cat::ExecutionControl,
            rationale: "System TCC.db: system-wide privacy grants.",
        },
    ],
    sources: &[
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
        "https://github.com/pstirparo/mac4n6",
        "https://support.apple.com/guide/security/welcome/web",
    ],
};

/// Focused macOS data-leakage examination: the paths by which data leaves a
/// Mac — removable and network volumes, cloud sync, printing, browser
/// downloads — and the download-provenance artifacts that trace file origin.
pub static MACOS_DATA_LEAKAGE: ExaminationProfile = ExaminationProfile {
    id: "macos_data_leakage",
    name: "macOS data-leakage triage",
    platform: Platform::MacOS,
    kind: ProfileKind::Focused,
    focus: ExaminationFocus::DataLeakage,
    description: "Focused macOS profile for suspected data exfiltration: external and network \
                  volume use, cloud-sync containers, printing, and browser downloads, plus the \
                  quarantine and where-from provenance that traces where a file came from. \
                  Removable/USB device history (USBMSC unified-log entries) and AirDrop/sharingd \
                  transfer activity are now carried by dedicated descriptors, with fseventsd and \
                  recent-servers still standing in for on-volume file activity and share access.",
    members: &[
        ProfileMember {
            artifact_id: "macos_fsevents",
            category: Cat::FileActivity,
            rationale: "fseventsd records mounts and writes under /Volumes — evidence of external \
                        or removable media use and files copied out to it.",
        },
        ProfileMember {
            artifact_id: "macos_usb_mass_storage_log",
            category: Cat::Connections,
            rationale: "USBMSC unified-log entries: which removable USB mass-storage devices were \
                        attached (vendor/product/serial) — the device side of copy-to-USB \
                        exfiltration, weaker and shorter-lived than Windows USBSTOR.",
        },
        ProfileMember {
            artifact_id: "macos_airdrop_sharingd",
            category: Cat::Connections,
            rationale: "AirDrop/sharingd activity in the unified log: files sent off-device to a \
                        peer over AirDrop — a wireless egress path invisible to network monitoring.",
        },
        ProfileMember {
            artifact_id: "macos_sfl2_recent_servers",
            category: Cat::Connections,
            rationale: "Recently connected file servers and network shares — a common exfiltration \
                        destination.",
        },
        ProfileMember {
            artifact_id: "macos_dhcp_leases",
            category: Cat::Connections,
            rationale: "DHCP leases: the internal IP, gateway and Wi-Fi SSID the Mac held, and \
                        when — placing the machine on a named network at a specific time for \
                        egress correlation (LAN side only; macOS stores no public IP).",
        },
        ProfileMember {
            artifact_id: "macos_wifi_known_networks",
            category: Cat::Connections,
            rationale: "Remembered Wi-Fi networks with per-AP BSSIDs — the location-exposure \
                        surface: the BSSIDs geolocate the networks the device was carried onto.",
        },
        ProfileMember {
            artifact_id: "macos_icloud_drive_db",
            category: Cat::CloudStorage,
            rationale: "iCloud Drive sync state: files pushed off-device to Apple's cloud.",
        },
        ProfileMember {
            artifact_id: "macos_icloud_drive_containers",
            category: Cat::CloudStorage,
            rationale: "Per-application iCloud containers: app data synced off the machine.",
        },
        ProfileMember {
            artifact_id: "macos_cups_spool_jobs",
            category: Cat::Printing,
            rationale: "Spooled print jobs can contain the full content of documents printed off \
                        the machine.",
        },
        ProfileMember {
            artifact_id: "macos_cups_printers_conf",
            category: Cat::Printing,
            rationale: "Configured printers reveal destinations, including network and print-to-PDF \
                        egress paths.",
        },
        ProfileMember {
            artifact_id: "macos_cups_logs",
            category: Cat::Printing,
            rationale: "Print job history: what was printed, and when.",
        },
        ProfileMember {
            artifact_id: "macos_safari_history",
            category: Cat::WebActivity,
            rationale: "Browsing history exposes webmail and file-sharing / upload sites used to \
                        move data out.",
        },
        ProfileMember {
            artifact_id: "macos_safari_downloads",
            category: Cat::WebActivity,
            rationale: "Safari downloads: an ingress vector, and a record of the upload endpoints \
                        visited.",
        },
        ProfileMember {
            artifact_id: "macos_safari_cookies",
            category: Cat::WebActivity,
            rationale: "Safari cookies: live session tokens for webmail and file-sharing sites, \
                        and evidence of authenticated sessions used to move data out.",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_xattr",
            category: Cat::FileActivity,
            rationale: "Quarantine xattr identifies which application introduced a file (download \
                        provenance).",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_events",
            category: Cat::FileActivity,
            rationale: "LSQuarantineEvents: system-wide record of downloaded files and their source.",
        },
        ProfileMember {
            artifact_id: "macos_wherefroms_xattr",
            category: Cat::FileActivity,
            rationale: "WhereFroms xattr: the origin URL of a file, tracing where it came from.",
        },
    ],
    sources: &[
        "https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/",
        "https://github.com/pstirparo/mac4n6",
    ],
};

/// Focused macOS malware examination: persistence mechanisms and the
/// execution-control surface (quarantine, Gatekeeper, XProtect, TCC) an
/// analyst triages when looking for a foothold and how it survives reboot.
pub static MACOS_MALWARE: ExaminationProfile = ExaminationProfile {
    id: "macos_malware",
    name: "macOS malware triage",
    platform: Platform::MacOS,
    kind: ProfileKind::Focused,
    focus: ExaminationFocus::Malware,
    description: "Focused macOS profile for malware and persistence triage: launchd agents and \
                  daemons, login items, background-task and helper-tool persistence, emond, \
                  periodic / cron scheduling, and kernel / system extensions, alongside the \
                  execution-control surface — quarantine, Gatekeeper, XProtect, and TCC — that \
                  records how code arrived and what it was allowed to do.",
    members: &[
        // ── Persistence ──────────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_launch_agents_user",
            category: Cat::Persistence,
            rationale: "Per-user LaunchAgents: the most common macOS persistence.",
        },
        ProfileMember {
            artifact_id: "macos_launch_agents_system",
            category: Cat::Persistence,
            rationale: "System LaunchAgents in /Library: persistence for all users.",
        },
        ProfileMember {
            artifact_id: "macos_launch_daemons",
            category: Cat::Persistence,
            rationale: "LaunchDaemons: root-level persistence that runs before login.",
        },
        ProfileMember {
            artifact_id: "macos_login_items_plist",
            category: Cat::Persistence,
            rationale: "Login items: GUI persistence at user sign-in.",
        },
        ProfileMember {
            artifact_id: "macos_login_logout_hooks",
            category: Cat::Persistence,
            rationale: "Login / logout hooks: legacy script-based persistence.",
        },
        ProfileMember {
            artifact_id: "macos_btm_background_tasks",
            category: Cat::Persistence,
            rationale: "BTM (Background Task Management) db: the modern record of registered \
                        agents, daemons, and login items — the single best persistence overview.",
        },
        ProfileMember {
            artifact_id: "macos_privileged_helper_tools",
            category: Cat::Persistence,
            rationale: "PrivilegedHelperTools: SMJobBless-installed root helpers, a persistence \
                        and privilege vector.",
        },
        ProfileMember {
            artifact_id: "macos_emond",
            category: Cat::Persistence,
            rationale:
                "emond rules: event-monitor persistence (deprecated but historically abused).",
        },
        ProfileMember {
            artifact_id: "fa_file_etc_periodic_conf",
            category: Cat::Persistence,
            rationale:
                "periodic.conf: scheduled periodic (daily / weekly / monthly) script execution.",
        },
        ProfileMember {
            artifact_id: "fa_file_etc_crontab_3",
            category: Cat::Persistence,
            rationale: "crontab: cron-based scheduled execution.",
        },
        ProfileMember {
            artifact_id: "fa_file_kext_info_plist",
            category: Cat::Persistence,
            rationale: "Kernel extension Info.plist: loaded kext identity (legacy kernel-mode \
                        persistence).",
        },
        ProfileMember {
            artifact_id: "macos_system_extensions_db",
            category: Cat::Persistence,
            rationale:
                "System Extensions db: the modern replacement for kexts (network / endpoint \
                        extensions).",
        },
        // ── Execution control ────────────────────────────────────────────
        ProfileMember {
            artifact_id: "macos_xprotect_behavioral_db",
            category: Cat::ExecutionControl,
            rationale: "XProtect Remediator behavioural db: Apple's malware-detection signals.",
        },
        ProfileMember {
            artifact_id: "macos_gatekeeper_logs",
            category: Cat::ExecutionControl,
            rationale: "Gatekeeper logs: allow / deny decisions on launched software.",
        },
        ProfileMember {
            artifact_id: "macos_exec_policy_db",
            category: Cat::ExecutionControl,
            rationale: "ExecPolicy db: Gatekeeper / notarization assessment records.",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_xattr",
            category: Cat::ExecutionControl,
            rationale: "Quarantine xattr: how a suspicious binary arrived on the system.",
        },
        ProfileMember {
            artifact_id: "macos_quarantine_events",
            category: Cat::ExecutionControl,
            rationale: "LSQuarantineEvents: the download source of suspicious files.",
        },
        ProfileMember {
            artifact_id: "macos_tcc_db",
            category: Cat::ExecutionControl,
            rationale:
                "User TCC.db: privacy grants malware abuses (screen recording, accessibility).",
        },
        ProfileMember {
            artifact_id: "macos_tcc_system_db",
            category: Cat::ExecutionControl,
            rationale: "System TCC.db: system-level privacy grants.",
        },
    ],
    sources: &[
        "https://taomm.org/",
        "https://objective-see.org/",
        "https://support.apple.com/guide/security/welcome/web",
    ],
};

/// Every registered examination profile. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static EXAMINATION_PROFILES: &[ExaminationProfile] =
    &[MACOS_FULL, MACOS_DATA_LEAKAGE, MACOS_MALWARE];
