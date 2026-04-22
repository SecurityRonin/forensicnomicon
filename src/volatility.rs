//! Artifact volatility model — RFC 3227 Order of Volatility encoded as data.
//!
//! Maps each catalog artifact to a [`VolatilityClass`], enabling tools to
//! sort collection order from most-volatile to least-volatile.

/// How quickly an artifact is overwritten or lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VolatilityClass {
    /// Survives deletion (journal, shadow copies, slack space).
    Residual = 0,
    /// Persistent until explicit deletion (registry keys, most files).
    Persistent = 1,
    /// Overwritten by user activity (MRU, recent docs, browser history).
    ActivityDriven = 2,
    /// Overwritten on rotation (event logs, prefetch circular buffer).
    RotatingBuffer = 3,
    /// Lost on reboot (RAM contents, process handles, network state).
    Volatile = 4,
}

/// Volatility entry for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VolatilityEntry {
    /// Catalog artifact ID.
    pub artifact_id: &'static str,
    pub volatility: VolatilityClass,
    /// One-line rationale for this classification.
    pub rationale: &'static str,
}

/// Volatility table for all catalog artifacts.
/// Sorted by artifact_id for determinism.
pub static VOLATILITY_TABLE: &[VolatilityEntry] = &[
    // ── Execution artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "amcache_app_file",
        volatility: VolatilityClass::Persistent,
        rationale: "Persists until Windows Update or manual clear",
    },
    VolatilityEntry {
        artifact_id: "bam_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated by OS on background activity manager flush",
    },
    VolatilityEntry {
        artifact_id: "dam_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated by OS on desktop activity monitor flush",
    },
    VolatilityEntry {
        artifact_id: "prefetch_file",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Max 1024 entries, FIFO eviction on Win10+",
    },
    VolatilityEntry {
        artifact_id: "shimcache",
        volatility: VolatilityClass::Volatile,
        rationale: "Written to registry only on shutdown; live state is in memory",
    },
    VolatilityEntry {
        artifact_id: "userassist_exe",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated per user GUI interaction; persists in NTUSER.DAT",
    },
    // ── Persistence artifacts ────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "active_setup_hklm",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "appinit_dlls",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "boot_execute",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "com_hijack_clsid_hkcu",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key per-user; persists in NTUSER.DAT",
    },
    VolatilityEntry {
        artifact_id: "ifeo_debugger",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "run_key_hkcu",
        volatility: VolatilityClass::Persistent,
        rationale: "Per-user registry key; persists in NTUSER.DAT",
    },
    VolatilityEntry {
        artifact_id: "run_key_hklm",
        volatility: VolatilityClass::Persistent,
        rationale: "System registry key; persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "run_key_hklm_once",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Deleted by OS after single execution",
    },
    VolatilityEntry {
        artifact_id: "scheduled_tasks_dir",
        volatility: VolatilityClass::Persistent,
        rationale: "XML files in tasks directory; persist until task deleted",
    },
    VolatilityEntry {
        artifact_id: "services_imagepath",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key under SYSTEM; persists until service removed",
    },
    VolatilityEntry {
        artifact_id: "winlogon_shell",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persists until explicit deletion",
    },
    // ── Credential artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "chrome_login_data",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "dcc2_cache",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rotated; last 10 cached credentials by default",
    },
    VolatilityEntry {
        artifact_id: "dpapi_cred_user",
        volatility: VolatilityClass::Persistent,
        rationale: "Encrypted credential blobs; persist until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "dpapi_masterkey_user",
        volatility: VolatilityClass::Persistent,
        rationale: "Master keys persist; old keys backed up in AD",
    },
    VolatilityEntry {
        artifact_id: "dpapi_system_masterkey",
        volatility: VolatilityClass::Persistent,
        rationale: "System DPAPI master key; persists in SYSTEM hive",
    },
    VolatilityEntry {
        artifact_id: "firefox_logins",
        volatility: VolatilityClass::Persistent,
        rationale: "JSON file; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "lsa_secrets",
        volatility: VolatilityClass::Persistent,
        rationale: "System hive registry; persists until credential removed",
    },
    VolatilityEntry {
        artifact_id: "ntds_dit",
        volatility: VolatilityClass::Persistent,
        rationale: "AD database; persists until account deleted",
    },
    VolatilityEntry {
        artifact_id: "sam_users",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM registry hive; persists until account deleted",
    },
    // ── Filesystem artifacts ─────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "jump_list_auto",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated on file access; max entries per app",
    },
    VolatilityEntry {
        artifact_id: "jump_list_custom",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Pinned by user; persists until app unpins",
    },
    VolatilityEntry {
        artifact_id: "lnk_files",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Created on file open; max ~150 recent items",
    },
    VolatilityEntry {
        artifact_id: "mft_file",
        volatility: VolatilityClass::Residual,
        rationale: "Metadata persists in unallocated MFT entries after deletion",
    },
    VolatilityEntry {
        artifact_id: "mru_recent_docs",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated per file open; fixed max MRU depth",
    },
    VolatilityEntry {
        artifact_id: "recycle_bin",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Deleted on permanent delete; survives recycle until purge",
    },
    VolatilityEntry {
        artifact_id: "shellbags_user",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated on folder access; persists in UsrClass.dat",
    },
    VolatilityEntry {
        artifact_id: "usn_journal",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular journal; oldest entries overwritten first",
    },
    // ── SRUM / telemetry artifacts ───────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "srum_app_resource",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM ESE database; rotated by Windows on schedule",
    },
    VolatilityEntry {
        artifact_id: "srum_db",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM ESE database; records rolled up and purged periodically",
    },
    VolatilityEntry {
        artifact_id: "srum_network_usage",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "SRUM network table; rotated by Windows on schedule",
    },
    // ── Network artifacts ────────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "network_drives",
        volatility: VolatilityClass::Persistent,
        rationale: "Mapped drive registry entry; persists until unmapped",
    },
    VolatilityEntry {
        artifact_id: "networklist_profiles",
        volatility: VolatilityClass::Persistent,
        rationale: "Network profiles persist in registry",
    },
    VolatilityEntry {
        artifact_id: "rdp_client_servers",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "MRU; rotated when max entries exceeded",
    },
    VolatilityEntry {
        artifact_id: "wifi_profiles",
        volatility: VolatilityClass::Persistent,
        rationale: "WiFi profiles persist in registry until deleted",
    },
    // ── Event log artifacts ──────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "evtx_powershell",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; oldest events overwritten at max size",
    },
    VolatilityEntry {
        artifact_id: "evtx_security",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; default 128 MB max",
    },
    VolatilityEntry {
        artifact_id: "evtx_sysmon",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; size depends on Sysmon config",
    },
    VolatilityEntry {
        artifact_id: "evtx_system",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Circular EVTX log; default 20 MB max",
    },
    // ── Linux artifacts ──────────────────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "linux_auth_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "logrotate weekly by default",
    },
    VolatilityEntry {
        artifact_id: "linux_bash_history",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Written at shell exit; max HISTSIZE entries",
    },
    VolatilityEntry {
        artifact_id: "linux_chrome_login_linux",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "linux_firefox_logins_linux",
        volatility: VolatilityClass::Persistent,
        rationale: "JSON file; credentials persist until deleted from browser",
    },
    VolatilityEntry {
        artifact_id: "linux_gnome_keyring",
        volatility: VolatilityClass::Persistent,
        rationale: "Keyring database file; persists until secrets removed",
    },
    VolatilityEntry {
        artifact_id: "linux_kde_kwallet",
        volatility: VolatilityClass::Persistent,
        rationale: "KWallet database file; persists until secrets removed",
    },
    VolatilityEntry {
        artifact_id: "linux_passwd",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until account deleted",
    },
    VolatilityEntry {
        artifact_id: "linux_shadow",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until account deleted or password changed",
    },
    VolatilityEntry {
        artifact_id: "linux_ssh_private_key",
        volatility: VolatilityClass::Persistent,
        rationale: "File; persists until explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "linux_sudoers_d",
        volatility: VolatilityClass::Persistent,
        rationale: "Files in /etc/sudoers.d/; persist until explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "linux_journal_dir",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "systemd journal; rotated by journald size/time limits",
    },
    VolatilityEntry {
        artifact_id: "linux_user_crontab",
        volatility: VolatilityClass::Persistent,
        rationale: "Crontab entry; persists until crontab -r",
    },
    VolatilityEntry {
        artifact_id: "linux_wtmp",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Rotated by logrotate",
    },
    // macOS Critical artifacts added after macOS coverage expansion (1.2)
    VolatilityEntry {
        artifact_id: "macos_launch_agents_user",
        volatility: VolatilityClass::Persistent,
        rationale: "LaunchAgent plist persists until deleted; survives reboots",
    },
    VolatilityEntry {
        artifact_id: "macos_launch_agents_system",
        volatility: VolatilityClass::Persistent,
        rationale: "System-wide LaunchAgent plist; requires root to modify",
    },
    VolatilityEntry {
        artifact_id: "macos_launch_daemons",
        volatility: VolatilityClass::Persistent,
        rationale: "LaunchDaemon plist; persists across reboots, requires root",
    },
    VolatilityEntry {
        artifact_id: "macos_keychain_user",
        volatility: VolatilityClass::Persistent,
        rationale: "Keychain DB; persists until item deletion or keychain reset",
    },
    // ── Memory forensics artifacts ───────────────────────────────────────────
    VolatilityEntry {
        artifact_id: "mem_running_processes",
        volatility: VolatilityClass::Volatile,
        rationale: "RAM; lost on power-off",
    },
    VolatilityEntry {
        artifact_id: "mem_network_connections",
        volatility: VolatilityClass::Volatile,
        rationale: "RAM; lost on power-off",
    },
    VolatilityEntry {
        artifact_id: "mem_loaded_modules",
        volatility: VolatilityClass::Volatile,
        rationale: "RAM; lost on power-off",
    },
    VolatilityEntry {
        artifact_id: "mem_registry_hives",
        volatility: VolatilityClass::Volatile,
        rationale: "RAM; lost on power-off",
    },
    VolatilityEntry {
        artifact_id: "mem_user_credentials",
        volatility: VolatilityClass::Volatile,
        rationale: "RAM; lost on power-off",
    },
    // Extended Windows registry Critical artifacts
    VolatilityEntry {
        artifact_id: "credential_providers",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until deleted",
    },
    VolatilityEntry {
        artifact_id: "scheduled_task_registry_cache",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry cache; survives XML task file deletion",
    },
    VolatilityEntry {
        artifact_id: "winlogon_notify",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until deleted",
    },
    VolatilityEntry {
        artifact_id: "usb_stor_enum",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; survives device removal",
    },
    VolatilityEntry {
        artifact_id: "setupapi_dev_log",
        volatility: VolatilityClass::Persistent,
        rationale: "Log file; retained until manually cleared",
    },
    VolatilityEntry {
        artifact_id: "terminal_server_client_servers_ext",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persists across sessions",
    },
    // Extended Windows EVTX Critical artifacts
    VolatilityEntry {
        artifact_id: "evtx_task_scheduler",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_rdp_client",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_rdp_inbound",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_rdp_session",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_winrm",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_wmi_activity",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_defender",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_netlogon",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    VolatilityEntry {
        artifact_id: "evtx_lsa_protection",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log; rotated on size limit",
    },
    // Extended macOS Critical artifacts
    VolatilityEntry {
        artifact_id: "macos_fsevents",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "FSEvents log; rotated as volume fills",
    },
    VolatilityEntry {
        artifact_id: "macos_login_items_plist",
        volatility: VolatilityClass::Persistent,
        rationale: "Plist file; persistent until deleted",
    },
    VolatilityEntry {
        artifact_id: "macos_tcc_system_db",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; persistent until reset",
    },
    VolatilityEntry {
        artifact_id: "macos_sms_db",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; persistent until deleted",
    },
    // Extended Linux Critical artifacts
    VolatilityEntry {
        artifact_id: "linux_auditd_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Log file; rotated by logrotate",
    },
    VolatilityEntry {
        artifact_id: "linux_secure_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Log file; rotated by logrotate",
    },
    VolatilityEntry {
        artifact_id: "linux_apache_access_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Log file; rotated by logrotate",
    },
    VolatilityEntry {
        artifact_id: "linux_nginx_access_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Log file; rotated by logrotate",
    },
    VolatilityEntry {
        artifact_id: "linux_selinux_config",
        volatility: VolatilityClass::Persistent,
        rationale: "Config file; persistent until modified",
    },
    VolatilityEntry {
        artifact_id: "linux_proc_modules",
        volatility: VolatilityClass::Volatile,
        rationale: "Virtual FS; lost on reboot",
    },
    // Phase-2 Windows registry Critical artifacts
    VolatilityEntry {
        artifact_id: "winlogon_autoadmin_logon",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until modification",
    },
    VolatilityEntry {
        artifact_id: "winlogon_default_password",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until modification",
    },
    VolatilityEntry {
        artifact_id: "portproxy_config",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until netsh portproxy delete",
    },
    VolatilityEntry {
        artifact_id: "windows_defender_exclusions_local",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until Defender policy change",
    },
    VolatilityEntry {
        artifact_id: "windows_defender_disabled_av",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until GPO refresh",
    },
    VolatilityEntry {
        artifact_id: "windows_defender_realtime",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until Defender reset",
    },
    VolatilityEntry {
        artifact_id: "ms_office_trusted_docs",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated when user enables Office document macros",
    },
    VolatilityEntry {
        artifact_id: "vss_files_not_to_snapshot",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until registry modification",
    },
    VolatilityEntry {
        artifact_id: "vss_files_not_to_backup",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until registry modification",
    },
    VolatilityEntry {
        artifact_id: "ifeo_silent_exit",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until modification",
    },
    VolatilityEntry {
        artifact_id: "exefile_shell_open_software",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "exefile_shell_open_usrclass",
        volatility: VolatilityClass::Persistent,
        rationale: "UsrClass.dat value; persistent until profile deletion",
    },
    VolatilityEntry {
        artifact_id: "rdp_shadow_sessions",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until policy modification",
    },
    VolatilityEntry {
        artifact_id: "restricted_admin_rdp",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value; persistent until explicit change",
    },
    VolatilityEntry {
        artifact_id: "network_shares_server",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until share removal",
    },
    VolatilityEntry {
        artifact_id: "ms_office_server_cache",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Updated on Office server connections; persists in NTUSER.DAT",
    },
    VolatilityEntry {
        artifact_id: "powershell_cobalt_info",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key created by Cobalt Strike; persistent until cleanup",
    },
    VolatilityEntry {
        artifact_id: "taskcache_tasks_path",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until task deletion",
    },
    VolatilityEntry {
        artifact_id: "event_log_channel_status",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key; persistent until channel re-enabled",
    },
    // Phase-2b Extended Windows file Critical artifacts
    VolatilityEntry {
        artifact_id: "chrome_history",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Overwritten by browser activity; no size limit",
    },
    VolatilityEntry {
        artifact_id: "edge_chromium_history",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Overwritten by browser activity; no size limit",
    },
    VolatilityEntry {
        artifact_id: "edge_chromium_login_data",
        volatility: VolatilityClass::Persistent,
        rationale: "Persists until credential explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "firefox_places",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Overwritten by browser activity; no size limit",
    },
    VolatilityEntry {
        artifact_id: "psreadline_history",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Oldest lines evicted at 4096-line limit",
    },
    VolatilityEntry {
        artifact_id: "psreadline_history_system",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Oldest lines evicted at 4096-line limit",
    },
    VolatilityEntry {
        artifact_id: "powershell_transcripts",
        volatility: VolatilityClass::Persistent,
        rationale: "Accumulate indefinitely; not auto-rotated",
    },
    VolatilityEntry {
        artifact_id: "teamviewer_connection_log",
        volatility: VolatilityClass::Persistent,
        rationale: "Appended per session; not auto-cleared",
    },
    VolatilityEntry {
        artifact_id: "anydesk_trace_user",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Rotated at size limit; .old retains previous",
    },
    VolatilityEntry {
        artifact_id: "anydesk_trace_system",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Rotated at size limit",
    },
    VolatilityEntry {
        artifact_id: "anydesk_connection_trace",
        volatility: VolatilityClass::Persistent,
        rationale: "Appended; grows until manually cleared",
    },
    VolatilityEntry {
        artifact_id: "anydesk_file_transfer_log",
        volatility: VolatilityClass::Persistent,
        rationale: "Appended; grows until manually cleared",
    },
    VolatilityEntry {
        artifact_id: "screenconnect_session_db",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; retained until manually cleared",
    },
    VolatilityEntry {
        artifact_id: "dropbox_instance_db",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; persists until Dropbox uninstalled",
    },
    VolatilityEntry {
        artifact_id: "onedrive_metadata",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; persists; ODL logs rotate",
    },
    VolatilityEntry {
        artifact_id: "google_drive_fs_metadata",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLite DB; persists until Drive uninstalled",
    },
    VolatilityEntry {
        artifact_id: "teams_indexed_db",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "LevelDB cache; grows with Teams usage",
    },
    VolatilityEntry {
        artifact_id: "slack_indexed_db",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "LevelDB cache; grows with Slack usage",
    },
    VolatilityEntry {
        artifact_id: "discord_local_storage",
        volatility: VolatilityClass::Persistent,
        rationale: "Persists until Discord uninstalled or cleared",
    },
    VolatilityEntry {
        artifact_id: "signal_database",
        volatility: VolatilityClass::Persistent,
        rationale: "SQLCipher SQLite; persists until user deletes",
    },
    VolatilityEntry {
        artifact_id: "signal_config_json",
        volatility: VolatilityClass::Persistent,
        rationale: "Regenerated only on fresh install; otherwise permanent",
    },
    VolatilityEntry {
        artifact_id: "certutil_cache",
        volatility: VolatilityClass::Persistent,
        rationale: "CryptNet cache; persists until explicitly flushed",
    },
    VolatilityEntry {
        artifact_id: "sdb_custom_files",
        volatility: VolatilityClass::Persistent,
        rationale: "Installed SDB files persist until explicitly removed",
    },
    VolatilityEntry {
        artifact_id: "iis_w3svc_logs",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Rotated daily; retention per IIS config",
    },
    VolatilityEntry {
        artifact_id: "iis_config_applicationhost",
        volatility: VolatilityClass::Persistent,
        rationale: "Persistent IIS config; modified by admin or attacker",
    },
    VolatilityEntry {
        artifact_id: "dns_debug_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Single file rotated at configured size limit",
    },
    VolatilityEntry {
        artifact_id: "sum_db",
        volatility: VolatilityClass::Persistent,
        rationale: "Up to 2 years retention; rolled annually",
    },
    VolatilityEntry {
        artifact_id: "copilot_recall_ukg",
        volatility: VolatilityClass::ActivityDriven,
        rationale: "Rolling 90-day window; older screenshots purged",
    },
    VolatilityEntry {
        artifact_id: "ntuser_dat_file",
        volatility: VolatilityClass::Persistent,
        rationale: "Exists for lifetime of user profile",
    },
    // Phase 3 — net-new Critical persistence artifacts
    VolatilityEntry {
        artifact_id: "active_setup",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until explicitly deleted",
    },
    VolatilityEntry {
        artifact_id: "lsa_auth_packages",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value persists across reboots; requires reboot to take effect",
    },
    VolatilityEntry {
        artifact_id: "lsa_security_packages",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry value persists across reboots; requires reboot to take effect",
    },
    VolatilityEntry {
        artifact_id: "print_monitor_dlls",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until explicitly deleted",
    },
    VolatilityEntry {
        artifact_id: "services_hklm",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until service key deletion",
    },
    // ── Generated mass-import Critical artifacts ──────────────────────────────
    VolatilityEntry {
        artifact_id: "browsers_firefox_logins",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_networksecurity_debug",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_smbclient_security",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_smbserver_security",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_adminless_operational",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_audit_configuration_client_d",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_audit_configuration_client_o",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_configuration_wizard_diagnos",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_configuration_wizard_operati",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_enterprisedata_filerevocatio",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_exchangeactivesyncprovisioni",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_identitystore_performance",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_lessprivilegedappcontainer_o",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_licensing_slc_perf",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_netlogon_operational",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_gc_analytic",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_genuinecenter_logging",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_notifications_actionc",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_analytic",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_perf",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_userconsentverifier_audit",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_security_vault_performance",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_perf",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_operational",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_admin",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Event log rotates on size limit; Security channel is high-value",
    },
    VolatilityEntry {
        artifact_id: "fa_file_log_esxtokend_log",
        volatility: VolatilityClass::Persistent,
        rationale: "ESXi token daemon log persists until rotation",
    },
    VolatilityEntry {
        artifact_id: "fa_file_etc_passwd",
        volatility: VolatilityClass::Persistent,
        rationale: "User account file persists until system decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_kernel_dmesg_restrict",
        volatility: VolatilityClass::Persistent,
        rationale: "Kernel sysctl setting persists across reboots when configured",
    },
    VolatilityEntry {
        artifact_id: "fa_file_kernel_kptr_restrict",
        volatility: VolatilityClass::Persistent,
        rationale: "Kernel sysctl setting persists across reboots when configured",
    },
    VolatilityEntry {
        artifact_id: "fa_file_users_plist",
        volatility: VolatilityClass::Persistent,
        rationale: "User account file persists until system decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_users_plist_2",
        volatility: VolatilityClass::Persistent,
        rationale: "User account file persists until system decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_3",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_4",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_5",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_6",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_7",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_8",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_9",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_10",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_11",
        volatility: VolatilityClass::Persistent,
        rationale: "Tomcat credential file persists until application reconfiguration",
    },
    VolatilityEntry {
        artifact_id: "fa_file_ntds_ntds_dit",
        volatility: VolatilityClass::Persistent,
        rationale: "Active Directory database persists until DC decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_ntds_dit",
        volatility: VolatilityClass::Persistent,
        rationale: "Active Directory database persists until DC decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_ntds_dit_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Active Directory database persists until DC decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_file_system32_ntds_dit",
        volatility: VolatilityClass::Persistent,
        rationale: "Active Directory database persists until DC decommission",
    },
    VolatilityEntry {
        artifact_id: "fa_authentication_credential_provider_filters",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until key deletion",
    },
    VolatilityEntry {
        artifact_id: "fa_authentication_credential_provider_filters_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until key deletion",
    },
    VolatilityEntry {
        artifact_id: "fa_authentication_credential_providers",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until key deletion",
    },
    VolatilityEntry {
        artifact_id: "fa_authentication_credential_providers_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Registry key persists until key deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_1password_data_1password10_sqlite",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_1password_backups_1password10_sqlite",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_1password_logs_log",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_aws_credentials",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential file persists until key rotation",
    },
    VolatilityEntry {
        artifact_id: "kape_file_user_git_credentials",
        volatility: VolatilityClass::Persistent,
        rationale: "Git credential helper store persists until credential deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_free_download_manager_fdm_sqlite",
        volatility: VolatilityClass::Persistent,
        rationale: "Download manager credential database persists until uninstall",
    },
    VolatilityEntry {
        artifact_id: "kape_file_my_certificates",
        volatility: VolatilityClass::Persistent,
        rationale: "Certificate store persists until certificate deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_logins_json",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_mremoteng_confcons_xml",
        volatility: VolatilityClass::Persistent,
        rationale: "Password manager database persists until application uninstall",
    },
    VolatilityEntry {
        artifact_id: "kape_file_key_db",
        volatility: VolatilityClass::Persistent,
        rationale: "Password manager database persists until application uninstall",
    },
    VolatilityEntry {
        artifact_id: "kape_file_signon",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_logins_json_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_password_xp",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_signon_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_logins_json_2_2",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_local_puffinsecurebrowserpasswordforms_dat",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_local_puffinsecurebrowsercredential_dat",
        volatility: VolatilityClass::Persistent,
        rationale: "Browser credential file persists until app data deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_windows_ntds",
        volatility: VolatilityClass::Persistent,
        rationale: "Active Directory database persists until DC decommission",
    },
    VolatilityEntry {
        artifact_id: "kape_file_config_sam_log",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "kape_file_sam_registry_transac",
        volatility: VolatilityClass::Persistent,
        rationale: "Artifact persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_config_sam",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "kape_file_sam_registry_hive",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "kape_file_regback_sam",
        volatility: VolatilityClass::Persistent,
        rationale: "Artifact persists until explicit deletion",
    },
    VolatilityEntry {
        artifact_id: "kape_file_sam_registry_hive_re",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "nirsoft_network_passwords_cred_dir",
        volatility: VolatilityClass::Persistent,
        rationale: "Credential store persists until browser profile deletion",
    },
    VolatilityEntry {
        artifact_id: "nirsoft_sam_hive_reg",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "regedit_domains_account_users",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM account registry persists until account deletion",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_log_auth_log",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Linux log rotates on size/time schedule",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_syslogtimestamp_timestamp_syslogfacility_s",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Linux log rotates on size/time schedule",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_ssh_pem_id_rsa_id_dsa",
        volatility: VolatilityClass::Persistent,
        rationale: "Private key files persist until explicitly deleted",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_usr",
        volatility: VolatilityClass::Persistent,
        rationale: "System binary directory persists until package update",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_tmp_collection_zip",
        volatility: VolatilityClass::Volatile,
        rationale: "Temporary collection ZIP is volatile and deleted after upload",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_logs_security_evtx",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Collected EVTX rotates; velociraptor copy is point-in-time",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_logs_microsoft_windows_taskscheduler_4oper",
        volatility: VolatilityClass::RotatingBuffer,
        rationale: "Task scheduler log rotates; collected copy is point-in-time",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_file_config_sam",
        volatility: VolatilityClass::Persistent,
        rationale: "SAM hive persists across reboots; protected in-use by Windows",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_currentversion_image_file_execution_options",
        volatility: VolatilityClass::Persistent,
        rationale: "IFEO GlobalFlag registry persists until key deletion",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_securityproviders_wdigest",
        volatility: VolatilityClass::Persistent,
        rationale: "WDigest registry value persists across reboots",
    },
    VolatilityEntry {
        artifact_id: "velociraptor_currentversion_profilelist",
        volatility: VolatilityClass::Persistent,
        rationale: "ProfileList registry persists until profile deletion",
    },
];

/// Returns the volatility entry for a given artifact ID, or `None` if unknown.
pub fn volatility_for(artifact_id: &str) -> Option<&'static VolatilityEntry> {
    VOLATILITY_TABLE
        .iter()
        .find(|e| e.artifact_id == artifact_id)
}

/// Returns all artifacts sorted most-volatile-first (Volatile → Residual).
/// Ties broken by artifact ID for determinism.
pub fn acquisition_order() -> Vec<&'static VolatilityEntry> {
    let mut entries: Vec<&VolatilityEntry> = VOLATILITY_TABLE.iter().collect();
    entries.sort_by(|a, b| {
        b.volatility
            .cmp(&a.volatility)
            .then(a.artifact_id.cmp(b.artifact_id))
    });
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CATALOG;

    #[test]
    fn shimcache_is_volatile() {
        let entry = volatility_for("shimcache").expect("shimcache should be in table");
        assert_eq!(entry.volatility, VolatilityClass::Volatile);
    }

    #[test]
    fn mft_is_residual() {
        let entry = volatility_for("mft_file").expect("mft_file should be in table");
        assert_eq!(entry.volatility, VolatilityClass::Residual);
    }

    #[test]
    fn evtx_security_is_rotating_buffer() {
        let entry = volatility_for("evtx_security").expect("evtx_security should be in table");
        assert_eq!(entry.volatility, VolatilityClass::RotatingBuffer);
    }

    #[test]
    fn acquisition_order_volatile_first() {
        let order = acquisition_order();
        assert!(!order.is_empty());
        // First entry must be the most volatile
        assert_eq!(
            order[0].volatility,
            VolatilityClass::Volatile,
            "acquisition_order should start with Volatile class"
        );
        // Last entry must be Residual
        assert_eq!(
            order.last().unwrap().volatility,
            VolatilityClass::Residual,
            "acquisition_order should end with Residual class"
        );
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(volatility_for("this_does_not_exist").is_none());
    }

    #[test]
    fn table_covers_critical_triage_artifacts() {
        // All Critical triage artifacts should be in the volatility table
        let missing: Vec<&str> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == crate::catalog::TriagePriority::Critical)
            .filter(|d| volatility_for(d.id).is_none())
            .map(|d| d.id)
            .collect();
        assert!(
            missing.is_empty(),
            "Critical-priority artifacts missing from volatility table: {missing:?}"
        );
    }

    #[test]
    fn all_table_artifact_ids_exist_in_catalog() {
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for entry in VOLATILITY_TABLE {
            assert!(
                catalog_ids.contains(entry.artifact_id),
                "volatility table references unknown catalog id: {}",
                entry.artifact_id
            );
        }
    }

    #[test]
    fn volatility_ordering_is_consistent() {
        // Volatile > RotatingBuffer > ActivityDriven > Persistent > Residual
        assert!(VolatilityClass::Volatile > VolatilityClass::RotatingBuffer);
        assert!(VolatilityClass::RotatingBuffer > VolatilityClass::ActivityDriven);
        assert!(VolatilityClass::ActivityDriven > VolatilityClass::Persistent);
        assert!(VolatilityClass::Persistent > VolatilityClass::Residual);
    }
}
