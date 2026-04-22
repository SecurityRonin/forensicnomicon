//! Evidence strength / confidence model for forensic artifacts.
//!
//! Maps each catalog artifact to an [`EvidenceStrength`] rating and known
//! interpretation caveats, helping analysts assess the weight of evidence
//! and communicate findings in reports.

/// How strongly an artifact proves a fact in isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvidenceStrength {
    /// Known false-positive generator; use only with strong corroboration.
    Unreliable = 0,
    /// Suggestive but easily explained by benign activity.
    Circumstantial = 1,
    /// Useful with other evidence; not standalone proof.
    Corroborative = 2,
    /// Strong evidence; edge-case alternative explanations exist.
    Strong = 3,
    /// Definitive proof of the claimed activity (e.g., Prefetch = execution occurred).
    Definitive = 4,
}

/// Evidence strength entry for one catalog artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EvidenceEntry {
    pub artifact_id: &'static str,
    pub strength: EvidenceStrength,
    /// Known caveats, edge cases, or false-positive scenarios.
    pub caveats: &'static [&'static str],
}

pub static EVIDENCE_TABLE: &[EvidenceEntry] = &[
    // ── Execution ────────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "prefetch_file",
        strength: EvidenceStrength::Definitive,
        caveats: &["Prefetch can be disabled via registry; absence does not mean no execution"],
    },
    EvidenceEntry {
        artifact_id: "shimcache",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "Presence proves file existed on disk, not necessarily executed",
            "Written only on reboot; live system shows stale data",
        ],
    },
    EvidenceEntry {
        artifact_id: "amcache_app_file",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "Presence proves file was on disk and touched by Windows; not always execution",
            "Can be populated by antivirus scans",
        ],
    },
    EvidenceEntry {
        artifact_id: "userassist_exe",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Counts GUI application launches; CLI-only execution not recorded",
            "ROT13 name encoding can be misread if decoder is missing",
        ],
    },
    EvidenceEntry {
        artifact_id: "bam_user",
        strength: EvidenceStrength::Strong,
        caveats: &["Granularity is per-day; precise execution time not available"],
    },
    EvidenceEntry {
        artifact_id: "dam_user",
        strength: EvidenceStrength::Corroborative,
        caveats: &["Device Activity Monitor; less studied than BAM"],
    },
    // ── Persistence ──────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "run_key_hklm",
        strength: EvidenceStrength::Strong,
        caveats: &["Legitimate software also uses Run keys; context required"],
    },
    EvidenceEntry {
        artifact_id: "run_key_hkcu",
        strength: EvidenceStrength::Strong,
        caveats: &["Per-user; requires knowing which user profile to examine"],
    },
    EvidenceEntry {
        artifact_id: "scheduled_tasks_dir",
        strength: EvidenceStrength::Definitive,
        caveats: &["Task XML may be deleted after execution; check event log 4698/4702"],
    },
    EvidenceEntry {
        artifact_id: "services_imagepath",
        strength: EvidenceStrength::Definitive,
        caveats: &["Many legitimate services present; focus on unsigned/unusual paths"],
    },
    EvidenceEntry {
        artifact_id: "winlogon_shell",
        strength: EvidenceStrength::Definitive,
        caveats: &["Default value is 'explorer.exe'; any deviation is highly suspicious"],
    },
    EvidenceEntry {
        artifact_id: "ifeo_debugger",
        strength: EvidenceStrength::Definitive,
        caveats: &["Legitimate debugger keys exist; focus on non-debugger executables"],
    },
    EvidenceEntry {
        artifact_id: "appinit_dlls",
        strength: EvidenceStrength::Definitive,
        caveats: &["Only effective when SecureBoot is disabled"],
    },
    EvidenceEntry {
        artifact_id: "com_hijack_clsid_hkcu",
        strength: EvidenceStrength::Strong,
        caveats: &["Some legitimate COM redirection exists; compare with HKLM entries"],
    },
    // ── Credential ───────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "lsa_secrets",
        strength: EvidenceStrength::Definitive,
        caveats: &["Requires SYSTEM privileges to read; encrypted at rest"],
    },
    EvidenceEntry {
        artifact_id: "dcc2_cache",
        strength: EvidenceStrength::Strong,
        caveats: &["Only proves domain user logged in; not current password"],
    },
    EvidenceEntry {
        artifact_id: "dpapi_masterkey_user",
        strength: EvidenceStrength::Corroborative,
        caveats: &["Presence expected for every user; useful for decrypting other artifacts"],
    },
    EvidenceEntry {
        artifact_id: "ntds_dit",
        strength: EvidenceStrength::Definitive,
        caveats: &["All domain hashes present; requires parsing with secretsdump or ntdsutil"],
    },
    EvidenceEntry {
        artifact_id: "sam_users",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Contains local account NTLM hashes; requires SYSTEM privilege to read",
            "Must be used with SYSTEM hive to decrypt",
        ],
    },
    EvidenceEntry {
        artifact_id: "dpapi_system_masterkey",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Required to decrypt SYSTEM-scope DPAPI blobs; requires SYSTEM privilege",
            "Loss of this key means DPAPI-protected data is unrecoverable",
        ],
    },
    EvidenceEntry {
        artifact_id: "chrome_login_data",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Credentials encrypted with DPAPI; require user masterkey to decrypt",
            "May contain stale or user-deleted passwords",
        ],
    },
    EvidenceEntry {
        artifact_id: "firefox_logins",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Encrypted with Firefox key4.db; requires key extraction for plaintext",
            "Primary password (master password) prevents access if set",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_gnome_keyring",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Encrypted with user login password; accessible after user session unlock",
            "Contains Wi-Fi keys, VPN credentials, and application secrets",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_kde_kwallet",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Encrypted; requires wallet password or auto-unlock to access",
            "Coverage depends on which KDE applications store credentials here",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_chrome_login_linux",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "On Linux, Chrome uses GNOME Keyring or KWallet for encryption key storage",
            "Plaintext accessible if keyring is unlocked",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_firefox_logins_linux",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Same format as Windows Firefox logins; key4.db required for decryption",
            "Primary password prevents access if set",
        ],
    },
    // ── Filesystem ───────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "mft_file",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "Timestamps susceptible to timestomping ($STANDARD_INFORMATION vs $FILE_NAME)",
            "$FILE_NAME timestamps harder to tamper; compare both",
        ],
    },
    EvidenceEntry {
        artifact_id: "usn_journal",
        strength: EvidenceStrength::Strong,
        caveats: &["Circular; entries overwritten; may not have full history"],
    },
    EvidenceEntry {
        artifact_id: "lnk_files",
        strength: EvidenceStrength::Strong,
        caveats: &["Can be spoofed; verify with corroborating artifacts"],
    },
    EvidenceEntry {
        artifact_id: "jump_list_auto",
        strength: EvidenceStrength::Strong,
        caveats: &["Application-specific; some apps don't integrate with jump lists"],
    },
    EvidenceEntry {
        artifact_id: "mru_recent_docs",
        strength: EvidenceStrength::Corroborative,
        caveats: &["Only tracks files opened via common dialog; programmatic access not recorded"],
    },
    EvidenceEntry {
        artifact_id: "recycle_bin",
        strength: EvidenceStrength::Strong,
        caveats: &["File name and deletion time available; original content may be overwritten"],
    },
    EvidenceEntry {
        artifact_id: "shellbags_user",
        strength: EvidenceStrength::Corroborative,
        caveats: &["Proves folder was browsed; does not prove file access or execution"],
    },
    // ── Network ──────────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "networklist_profiles",
        strength: EvidenceStrength::Strong,
        caveats: &["Profile name set by router; can be spoofed by attacker-controlled AP"],
    },
    EvidenceEntry {
        artifact_id: "rdp_client_servers",
        strength: EvidenceStrength::Strong,
        caveats: &["Proves RDP was initiated FROM this machine; does not confirm success"],
    },
    // ── SRUM ─────────────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "srum_db",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "Requires ESE database parsing; data is aggregated over time windows",
            "App paths may be partial; correlate with other execution artifacts",
        ],
    },
    EvidenceEntry {
        artifact_id: "srum_network_usage",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "Aggregated bytes sent/received per process; not per-connection detail",
            "Clock skew between SRUM and event logs possible",
        ],
    },
    EvidenceEntry {
        artifact_id: "srum_app_resource",
        strength: EvidenceStrength::Corroborative,
        caveats: &[
            "CPU and memory usage metrics; useful for corroborating execution, not proving it",
        ],
    },
    // ── Event Logs ───────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "evtx_security",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Log can be cleared (event 1102/104); absence of log is itself evidence",
            "Requires appropriate audit policy to be enabled",
        ],
    },
    EvidenceEntry {
        artifact_id: "evtx_sysmon",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Requires Sysmon to be installed and configured",
            "Sysmon config determines what is logged",
        ],
    },
    EvidenceEntry {
        artifact_id: "evtx_powershell",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Requires script block logging to be enabled (4104)",
            "AMSI bypass can prevent logging of obfuscated content",
        ],
    },
    EvidenceEntry {
        artifact_id: "evtx_system",
        strength: EvidenceStrength::Strong,
        caveats: &["Service install/start events useful; can be noisy with false positives"],
    },
    // ── Linux ────────────────────────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "linux_bash_history",
        strength: EvidenceStrength::Circumstantial,
        caveats: &[
            "Trivially disabled with HISTSIZE=0 or HISTFILE=/dev/null",
            "Written at shell exit; killed shells leave no history",
            "Root can modify or delete",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_auth_log",
        strength: EvidenceStrength::Strong,
        caveats: &["rsyslog/syslog-ng must be running; can be cleared by root"],
    },
    EvidenceEntry {
        artifact_id: "linux_wtmp",
        strength: EvidenceStrength::Strong,
        caveats: &["Binary format; utmpdump needed; can be edited by root"],
    },
    EvidenceEntry {
        artifact_id: "linux_sudoers_d",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Presence of unexpected rules is high-confidence privilege escalation indicator",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_passwd",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "World-readable; shows all accounts but no password hashes (those are in shadow)",
            "Added accounts may be backdoors; compare against baseline",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_shadow",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Requires root to read; contains hashed passwords",
            "Hash format determines crackability; check for weak algorithms (MD5, SHA-256)",
        ],
    },
    EvidenceEntry {
        artifact_id: "linux_ssh_private_key",
        strength: EvidenceStrength::Definitive,
        caveats: &[
            "Private key presence proves capability for lateral movement",
            "Passphrase-protected keys require cracking; unprotected keys are immediately usable",
        ],
    },
    // macOS Critical artifacts added after macOS coverage expansion (1.2)
    EvidenceEntry {
        artifact_id: "macos_launch_agents_user",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "LaunchAgent plists in ~/Library/LaunchAgents prove user-context persistence",
            "Legitimate software also uses LaunchAgents; cross-reference signing and bundle ID",
        ],
    },
    EvidenceEntry {
        artifact_id: "macos_launch_agents_system",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "System LaunchAgents require root installation; elevated-privilege persistence indicator",
            "Apple-signed plists are expected; unsigned or ad-hoc signed warrant investigation",
        ],
    },
    EvidenceEntry {
        artifact_id: "macos_launch_daemons",
        strength: EvidenceStrength::Strong,
        caveats: &[
            "LaunchDaemons run as root; highest-privilege persistence mechanism on macOS",
            "Correlate with install history and Gatekeeper records for origin attribution",
        ],
    },
    EvidenceEntry {
        artifact_id: "macos_keychain_user",
        strength: EvidenceStrength::Corroborative,
        caveats: &[
            "Keychain DB requires user unlock; credential entries show what accounts were stored",
            "Cannot be read without unlocking; useful post-acquisition with user password",
        ],
    },
    // ── Memory forensics artifacts ────────────────────────────────────────────
    EvidenceEntry {
        artifact_id: "mem_running_processes",
        strength: EvidenceStrength::Definitive,
        caveats: &["Live RAM only; requires active acquisition"],
    },
    EvidenceEntry {
        artifact_id: "mem_network_connections",
        strength: EvidenceStrength::Definitive,
        caveats: &["Volatile; connections may close during acquisition"],
    },
    EvidenceEntry {
        artifact_id: "mem_user_credentials",
        strength: EvidenceStrength::Definitive,
        caveats: &["Credentials in memory (LSASS); most valuable live artifact"],
    },
    // Extended Windows registry Critical artifacts
    EvidenceEntry { artifact_id: "credential_providers", strength: EvidenceStrength::Strong, caveats: &["Registry key; may be modified by legitimate security products"] },
    EvidenceEntry { artifact_id: "scheduled_task_registry_cache", strength: EvidenceStrength::Definitive, caveats: &["Survives XML task file deletion; high-fidelity persistence evidence"] },
    EvidenceEntry { artifact_id: "winlogon_notify", strength: EvidenceStrength::Definitive, caveats: &["Obsolete on Vista+; presence itself is highly suspicious"] },
    EvidenceEntry { artifact_id: "usb_stor_enum", strength: EvidenceStrength::Strong, caveats: &["Device serial numbers persist; device may have been removed"] },
    EvidenceEntry { artifact_id: "setupapi_dev_log", strength: EvidenceStrength::Strong, caveats: &["First connection timestamps are reliable; log may be cleared"] },
    EvidenceEntry { artifact_id: "terminal_server_client_servers_ext", strength: EvidenceStrength::Strong, caveats: &["Reveals UsernameHint used for RDP — near-definitive lateral movement evidence"] },
    // Extended Windows EVTX Critical artifacts
    EvidenceEntry { artifact_id: "evtx_task_scheduler", strength: EvidenceStrength::Definitive, caveats: &["Event log; may be cleared by attackers"] },
    EvidenceEntry { artifact_id: "evtx_rdp_client", strength: EvidenceStrength::Definitive, caveats: &["Outbound RDP; proves this host pivoted to another"] },
    EvidenceEntry { artifact_id: "evtx_rdp_inbound", strength: EvidenceStrength::Definitive, caveats: &["1149 events confirm source IP before session; not easily faked"] },
    EvidenceEntry { artifact_id: "evtx_rdp_session", strength: EvidenceStrength::Definitive, caveats: &["Session lifecycle with timestamps; event 39 = RDP hijack"] },
    EvidenceEntry { artifact_id: "evtx_winrm", strength: EvidenceStrength::Definitive, caveats: &["Confirms PowerShell Remoting lateral movement with account"] },
    EvidenceEntry { artifact_id: "evtx_wmi_activity", strength: EvidenceStrength::Definitive, caveats: &["5861 = permanent WMI subscription — near-certain persistence"] },
    EvidenceEntry { artifact_id: "evtx_defender", strength: EvidenceStrength::Definitive, caveats: &["Detection events survive file deletion; tamper events are highly suspicious"] },
    EvidenceEntry { artifact_id: "evtx_netlogon", strength: EvidenceStrength::Definitive, caveats: &["5827/5828 = ZeroLogon exploitation attempt — very low false-positive rate"] },
    EvidenceEntry { artifact_id: "evtx_lsa_protection", strength: EvidenceStrength::Strong, caveats: &["PPL changes indicate credential dumping preparation"] },
    // Extended macOS Critical artifacts
    EvidenceEntry { artifact_id: "macos_fsevents", strength: EvidenceStrength::Definitive, caveats: &["Kernel-level; not easily tampered; covers all file system activity"] },
    EvidenceEntry { artifact_id: "macos_login_items_plist", strength: EvidenceStrength::Strong, caveats: &["Persistence mechanism; SFL2 format varies by OS version"] },
    EvidenceEntry { artifact_id: "macos_tcc_system_db", strength: EvidenceStrength::Definitive, caveats: &["System-wide privacy permissions; requires SIP bypass to tamper"] },
    EvidenceEntry { artifact_id: "macos_sms_db", strength: EvidenceStrength::Strong, caveats: &["iMessage/SMS content; may be partially encrypted or unavailable without cloud sync"] },
    // Extended Linux Critical artifacts
    EvidenceEntry { artifact_id: "linux_auditd_log", strength: EvidenceStrength::Definitive, caveats: &["Kernel-level syscall auditing; attacker must disable auditd to evade"] },
    EvidenceEntry { artifact_id: "linux_secure_log", strength: EvidenceStrength::Strong, caveats: &["Authentication events; quality depends on PAM configuration"] },
    EvidenceEntry { artifact_id: "linux_apache_access_log", strength: EvidenceStrength::Definitive, caveats: &["Web exploitation primary source; attacker may delete or tamper"] },
    EvidenceEntry { artifact_id: "linux_nginx_access_log", strength: EvidenceStrength::Definitive, caveats: &["Web exploitation primary source; attacker may delete or tamper"] },
    EvidenceEntry { artifact_id: "linux_selinux_config", strength: EvidenceStrength::Strong, caveats: &["Disabled SELinux is itself a strong indicator of attacker activity"] },
    EvidenceEntry { artifact_id: "linux_proc_modules", strength: EvidenceStrength::Definitive, caveats: &["Live kernel modules; rootkit detection; lost on reboot"] },
    // Phase-2 Windows registry Critical artifacts
    EvidenceEntry { artifact_id: "winlogon_autoadmin_logon", strength: EvidenceStrength::Definitive, caveats: &["Legitimate on unattended kiosk/server builds; verify DefaultPassword also present"] },
    EvidenceEntry { artifact_id: "winlogon_default_password", strength: EvidenceStrength::Definitive, caveats: &["Presence proves plaintext credential stored; must confirm AutoAdminLogon=1 for context"] },
    EvidenceEntry { artifact_id: "portproxy_config", strength: EvidenceStrength::Strong, caveats: &["Legitimate uses exist (e.g., WSL2 port forwarding); verify rule targets are suspicious"] },
    EvidenceEntry { artifact_id: "windows_defender_exclusions_local", strength: EvidenceStrength::Strong, caveats: &["Legitimate AV exclusions common; suspicious if path matches known attacker staging directories"] },
    EvidenceEntry { artifact_id: "windows_defender_disabled_av", strength: EvidenceStrength::Definitive, caveats: &["Via policy key — Tamper Protection bypass required; near-certain indicator of deliberate disabling"] },
    EvidenceEntry { artifact_id: "windows_defender_realtime", strength: EvidenceStrength::Strong, caveats: &["Individual component flags may be legitimately set by MDM; check for combination of multiple disabled components"] },
    EvidenceEntry { artifact_id: "ms_office_trusted_docs", strength: EvidenceStrength::Strong, caveats: &["Legitimate macros also create entries; suspicious if document path is temp folder or remote share"] },
    EvidenceEntry { artifact_id: "vss_files_not_to_snapshot", strength: EvidenceStrength::Definitive, caveats: &["Non-Microsoft entries in this key are highly suspicious; verify against known software"] },
    EvidenceEntry { artifact_id: "vss_files_not_to_backup", strength: EvidenceStrength::Definitive, caveats: &["Non-Microsoft entries in this key are highly suspicious; verify against known software"] },
    EvidenceEntry { artifact_id: "ifeo_silent_exit", strength: EvidenceStrength::Definitive, caveats: &["Legitimate uses exist (WER config); suspicious if MonitorProcess points to unknown binary"] },
    EvidenceEntry { artifact_id: "exefile_shell_open_software", strength: EvidenceStrength::Definitive, caveats: &["Any deviation from default (%1 %*) is extremely suspicious; near-certain compromise indicator"] },
    EvidenceEntry { artifact_id: "exefile_shell_open_usrclass", strength: EvidenceStrength::Definitive, caveats: &["Any presence of this key is suspicious; no legitimate software sets per-user .exe handler"] },
    EvidenceEntry { artifact_id: "rdp_shadow_sessions", strength: EvidenceStrength::Strong, caveats: &["Shadow=2 or 4 (no consent) is particularly suspicious; verify against admin policy"] },
    EvidenceEntry { artifact_id: "restricted_admin_rdp", strength: EvidenceStrength::Strong, caveats: &["May be legitimately enabled for privileged access workstations; context required"] },
    EvidenceEntry { artifact_id: "network_shares_server", strength: EvidenceStrength::Strong, caveats: &["Legitimate shares common; suspicious if share path is attacker staging directory or C: root"] },
    EvidenceEntry { artifact_id: "ms_office_server_cache", strength: EvidenceStrength::Corroborative, caveats: &["URL presence requires correlation with known C2 domains; many legitimate Office URLs expected"] },
    EvidenceEntry { artifact_id: "powershell_cobalt_info", strength: EvidenceStrength::Definitive, caveats: &["Key is not created by legitimate software; presence is near-certain Cobalt Strike IOC"] },
    EvidenceEntry { artifact_id: "taskcache_tasks_path", strength: EvidenceStrength::Strong, caveats: &["Many legitimate tasks present; suspicious tasks have random names or reside outside \\Microsoft\\"] },
    EvidenceEntry { artifact_id: "event_log_channel_status", strength: EvidenceStrength::Definitive, caveats: &["Disabled Security or Sysmon channel during an incident is near-certain evidence of tampering"] },
    // Phase-2b Extended Windows file Critical artifacts
    EvidenceEntry { artifact_id: "chrome_history", strength: EvidenceStrength::Strong, caveats: &["History may be cleared; private browsing not recorded; timestamps are WebKit microseconds requiring conversion"] },
    EvidenceEntry { artifact_id: "edge_chromium_history", strength: EvidenceStrength::Strong, caveats: &["Same caveats as Chrome History; profile switching means not all activity in default profile"] },
    EvidenceEntry { artifact_id: "edge_chromium_login_data", strength: EvidenceStrength::Definitive, caveats: &["DPAPI encryption requires user context or masterkey to decrypt; credential presence proves account storage"] },
    EvidenceEntry { artifact_id: "firefox_places", strength: EvidenceStrength::Strong, caveats: &["History may be manually cleared; private browsing not recorded; frecency scoring can obscure visit count accuracy"] },
    EvidenceEntry { artifact_id: "psreadline_history", strength: EvidenceStrength::Strong, caveats: &["User can manually edit or clear file; oldest entries evicted at limit; does not capture non-interactive PS sessions"] },
    EvidenceEntry { artifact_id: "psreadline_history_system", strength: EvidenceStrength::Strong, caveats: &["Only populated when SYSTEM runs interactive PS; many SYSTEM PS sessions are non-interactive"] },
    EvidenceEntry { artifact_id: "powershell_transcripts", strength: EvidenceStrength::Definitive, caveats: &["Requires transcript policy to be enabled; attacker may disable policy before activity"] },
    EvidenceEntry { artifact_id: "teamviewer_connection_log", strength: EvidenceStrength::Definitive, caveats: &["File may be deleted by attacker; timestamps correlate with partner ID that can be traced to account"] },
    EvidenceEntry { artifact_id: "anydesk_trace_user", strength: EvidenceStrength::Strong, caveats: &["Rotated at size limit; attacker may clear ad.trace; session IDs in log can be used to request records from AnyDesk"] },
    EvidenceEntry { artifact_id: "anydesk_trace_system", strength: EvidenceStrength::Strong, caveats: &["Only present when AnyDesk installed as service; may be absent on per-user installs"] },
    EvidenceEntry { artifact_id: "anydesk_connection_trace", strength: EvidenceStrength::Definitive, caveats: &["Structured format; attacker cleanup often misses this file; contains both inbound and outbound connections"] },
    EvidenceEntry { artifact_id: "anydesk_file_transfer_log", strength: EvidenceStrength::Definitive, caveats: &["Proves exfiltration direction and filename; attacker cleanup often misses this file"] },
    EvidenceEntry { artifact_id: "screenconnect_session_db", strength: EvidenceStrength::Definitive, caveats: &["Only present on self-hosted deployments; cloud-hosted sessions leave no local DB"] },
    EvidenceEntry { artifact_id: "dropbox_instance_db", strength: EvidenceStrength::Definitive, caveats: &["Requires Dropbox-specific SQLite parser (obfuscated schema); file hashes prove sync without local copy"] },
    EvidenceEntry { artifact_id: "onedrive_metadata", strength: EvidenceStrength::Definitive, caveats: &["ODL log parsing complex; SyncEngineDatabase.db reveals cloud-only placeholders — strongest exfil evidence"] },
    EvidenceEntry { artifact_id: "google_drive_fs_metadata", strength: EvidenceStrength::Definitive, caveats: &["metadata.db schema may change between Drive for Desktop versions; requires version-appropriate parser"] },
    EvidenceEntry { artifact_id: "teams_indexed_db", strength: EvidenceStrength::Strong, caveats: &["LevelDB parsing requires specialized tooling; data may be encrypted at rest on newer Teams versions"] },
    EvidenceEntry { artifact_id: "slack_indexed_db", strength: EvidenceStrength::Strong, caveats: &["LevelDB format; workspace data may be partially encrypted; availability depends on Slack plan retention settings"] },
    EvidenceEntry { artifact_id: "discord_local_storage", strength: EvidenceStrength::Strong, caveats: &["Token extraction may require memory analysis; Discord rotates tokens on detection; LevelDB parsing required"] },
    EvidenceEntry { artifact_id: "signal_database", strength: EvidenceStrength::Definitive, caveats: &["SQLCipher encrypted; requires config.json key to decrypt; without key, message content is inaccessible"] },
    EvidenceEntry { artifact_id: "signal_config_json", strength: EvidenceStrength::Definitive, caveats: &["Contains plaintext decryption key; any process with user access can decrypt all Signal messages"] },
    EvidenceEntry { artifact_id: "certutil_cache", strength: EvidenceStrength::Definitive, caveats: &["Hash-named files require external resolution; creation timestamp = download time; survives downloaded file deletion"] },
    EvidenceEntry { artifact_id: "sdb_custom_files", strength: EvidenceStrength::Definitive, caveats: &["Any .sdb file here is legitimately rare; requires sdbinst.exe or direct file copy — both leave evidence"] },
    EvidenceEntry { artifact_id: "iis_w3svc_logs", strength: EvidenceStrength::Definitive, caveats: &["Attacker may clear logs; Managed Pipeline may not log all requests; X-Forwarded-For spoofing common"] },
    EvidenceEntry { artifact_id: "iis_config_applicationhost", strength: EvidenceStrength::Definitive, caveats: &["Handler additions persist until config reset; embedded webshell paths in handlers are definitive indicators"] },
    EvidenceEntry { artifact_id: "dns_debug_log", strength: EvidenceStrength::Definitive, caveats: &["Requires debug logging to be enabled; attacker may disable to evade; single-file rotation can overwrite evidence"] },
    EvidenceEntry { artifact_id: "sum_db", strength: EvidenceStrength::Definitive, caveats: &["Windows Server only; requires ESE/JET parser; timestamps in local server time — convert to UTC"] },
    EvidenceEntry { artifact_id: "copilot_recall_ukg", strength: EvidenceStrength::Definitive, caveats: &["Requires Copilot+ hardware with Recall enabled; VBS/PPLA protects live DB; accessible from acquired image"] },
    EvidenceEntry { artifact_id: "ntuser_dat_file", strength: EvidenceStrength::Definitive, caveats: &["Single hive provides all HKCU artifacts; transaction logs (.LOG1/.LOG2) must be applied for current state"] },
    // Phase 3 — net-new Critical persistence artifacts
    EvidenceEntry { artifact_id: "active_setup", strength: EvidenceStrength::Definitive, caveats: &["Rogue sub-key presence is definitive; compare StubPath against known-good baseline; last-write time indicates installation"] },
    EvidenceEntry { artifact_id: "lsa_auth_packages", strength: EvidenceStrength::Definitive, caveats: &["Any non-msv1_0 DLL is definitive IOC; requires reboot to activate; compare against Windows baseline"] },
    EvidenceEntry { artifact_id: "lsa_security_packages", strength: EvidenceStrength::Definitive, caveats: &["Any non-Microsoft SSP DLL is definitive IOC; cross-reference DLL hash with threat intel"] },
    EvidenceEntry { artifact_id: "print_monitor_dlls", strength: EvidenceStrength::Definitive, caveats: &["Rogue Driver value in any sub-key is definitive; PrintNightmare (CVE-2021-1675) may leave forensic artifacts"] },
    EvidenceEntry { artifact_id: "services_hklm", strength: EvidenceStrength::Definitive, caveats: &["New service sub-key creation time is definitive; ImagePath outside System32/SysWOW64 is suspicious; correlate with EVTX 7045"] },

    // ── Generated mass-import Critical artifacts ──────────────────────────────
    EvidenceEntry {
        artifact_id: "browsers_firefox_logins",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_networksecurity_debug",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_smbclient_security",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_smbserver_security",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_adminless_operational",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_audit_configuration_client_d",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_audit_configuration_client_o",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_configuration_wizard_diagnos",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_configuration_wizard_operati",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_enterprisedata_filerevocatio",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_exchangeactivesyncprovisioni",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_identitystore_performance",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_lessprivilegedappcontainer_o",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_licensing_slc_perf",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_netlogon_operational",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_gc_analytic",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_genuinecenter_logging",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_notifications_actionc",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_ux_analytic",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_spp_perf",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_userconsentverifier_audit",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_security_vault_performance",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_perf",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_operational",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "evtx_microsoft_windows_securitymitigationsbroker_admin",
        strength: EvidenceStrength::Strong,
        caveats: &["Windows Security audit log; check Policy log for channel disable events"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_log_esxtokend_log",
        strength: EvidenceStrength::Strong,
        caveats: &["Authentication events to vSphere; check for admin API token theft"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_etc_passwd",
        strength: EvidenceStrength::Strong,
        caveats: &["Check for UID 0 accounts not root; compare shadow file for password hash presence"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_kernel_dmesg_restrict",
        strength: EvidenceStrength::Strong,
        caveats: &["Tampered value (0=off) indicates attacker hardening-bypass; check sysctl.conf"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_kernel_kptr_restrict",
        strength: EvidenceStrength::Strong,
        caveats: &["Tampered value (0=off) indicates attacker hardening-bypass; check sysctl.conf"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_users_plist",
        strength: EvidenceStrength::Strong,
        caveats: &["Check for UID 0 accounts not root; compare shadow file for password hash presence"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_users_plist_2",
        strength: EvidenceStrength::Strong,
        caveats: &["Check for UID 0 accounts not root; compare shadow file for password hash presence"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_3",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_4",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_5",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_6",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_7",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_8",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_9",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_10",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_conf_tomcat_users_xml_11",
        strength: EvidenceStrength::Definitive,
        caveats: &["Plaintext credentials; check for admin-role accounts not in baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_ntds_ntds_dit",
        strength: EvidenceStrength::Definitive,
        caveats: &["Domain credential store; offline cracking risk; compare hash count against user count"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_ntds_dit",
        strength: EvidenceStrength::Definitive,
        caveats: &["Domain credential store; offline cracking risk; compare hash count against user count"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_ntds_dit_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Domain credential store; offline cracking risk; compare hash count against user count"],
    },
    EvidenceEntry {
        artifact_id: "fa_file_system32_ntds_dit",
        strength: EvidenceStrength::Definitive,
        caveats: &["Domain credential store; offline cracking risk; compare hash count against user count"],
    },
    EvidenceEntry {
        artifact_id: "fa_authentication_credential_provider_filters",
        strength: EvidenceStrength::Definitive,
        caveats: &["Non-default DLLs indicate credential interception; compare against known-good baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_authentication_credential_provider_filters_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Non-default DLLs indicate credential interception; compare against known-good baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_authentication_credential_providers",
        strength: EvidenceStrength::Definitive,
        caveats: &["Non-default DLLs indicate credential interception; compare against known-good baseline"],
    },
    EvidenceEntry {
        artifact_id: "fa_authentication_credential_providers_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Non-default DLLs indicate credential interception; compare against known-good baseline"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_1password_data_1password10_sqlite",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_1password_backups_1password10_sqlite",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_1password_logs_log",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_aws_credentials",
        strength: EvidenceStrength::Definitive,
        caveats: &["AWS access key ID and secret; timestamp indicates when last modified"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_user_git_credentials",
        strength: EvidenceStrength::Definitive,
        caveats: &["Repository tokens; check for non-corporate VCS hosts"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_free_download_manager_fdm_sqlite",
        strength: EvidenceStrength::Strong,
        caveats: &["May contain saved FTP/HTTP credentials; check for non-standard download sources"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_my_certificates",
        strength: EvidenceStrength::Definitive,
        caveats: &["Personal certificates including private keys; check for self-signed or unexpected issuers"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_logins_json",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_mremoteng_confcons_xml",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted vault; master password hash extractable for offline attack"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_key_db",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted vault; master password hash extractable for offline attack"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_signon",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_logins_json_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_password_xp",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_signon_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_logins_json_2_2",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_local_puffinsecurebrowserpasswordforms_dat",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_local_puffinsecurebrowsercredential_dat",
        strength: EvidenceStrength::Definitive,
        caveats: &["Browser-saved form passwords; check timestamp against incident window"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_windows_ntds",
        strength: EvidenceStrength::Definitive,
        caveats: &["Domain credential store; offline cracking risk; compare hash count against user count"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_config_sam_log",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_sam_registry_transac",
        strength: EvidenceStrength::Strong,
        caveats: &["Verify presence against incident timeline; correlate with other triage artifacts"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_config_sam",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_sam_registry_hive",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_regback_sam",
        strength: EvidenceStrength::Strong,
        caveats: &["Verify presence against incident timeline; correlate with other triage artifacts"],
    },
    EvidenceEntry {
        artifact_id: "kape_file_sam_registry_hive_re",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "nirsoft_network_passwords_cred_dir",
        strength: EvidenceStrength::Definitive,
        caveats: &["Encrypted browser passwords; key in OS credential store; timestamp shows last use"],
    },
    EvidenceEntry {
        artifact_id: "nirsoft_sam_hive_reg",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "regedit_domains_account_users",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account enumeration via registry; compare against expected user list"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_log_auth_log",
        strength: EvidenceStrength::Strong,
        caveats: &["Authentication events; check for brute-force patterns and privilege escalation"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_syslogtimestamp_timestamp_syslogfacility_s",
        strength: EvidenceStrength::Strong,
        caveats: &["Authentication events; check for brute-force patterns and privilege escalation"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_ssh_pem_id_rsa_id_dsa",
        strength: EvidenceStrength::Definitive,
        caveats: &["Private key presence proves access capability; verify authorized_keys for lateral movement"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_usr",
        strength: EvidenceStrength::Strong,
        caveats: &["Modified timestamps on system binaries indicate trojanized files"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_tmp_collection_zip",
        strength: EvidenceStrength::Strong,
        caveats: &["Presence indicates active Velociraptor collection; metadata reveals scope"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_logs_security_evtx",
        strength: EvidenceStrength::Strong,
        caveats: &["Velociraptor-collected EVTX; check collection timestamp vs log timespan"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_logs_microsoft_windows_taskscheduler_4oper",
        strength: EvidenceStrength::Strong,
        caveats: &["Scheduled task execution; correlate with persistence keys"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_file_config_sam",
        strength: EvidenceStrength::Definitive,
        caveats: &["Local account credential hashes; NTLM offline cracking risk"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_currentversion_image_file_execution_options",
        strength: EvidenceStrength::Definitive,
        caveats: &["Non-zero GlobalFlag with Debugger value indicates silent process exit / hijack"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_securityproviders_wdigest",
        strength: EvidenceStrength::Definitive,
        caveats: &["UseLogonCredential=1 enables plaintext credential caching in LSASS — critical IOC"],
    },
    EvidenceEntry {
        artifact_id: "velociraptor_currentversion_profilelist",
        strength: EvidenceStrength::Strong,
        caveats: &["User SID enumeration; compare against expected user base for rogue accounts"],
    },
];

/// Returns the evidence entry for a given artifact ID, or None if unknown.
pub fn evidence_for(artifact_id: &str) -> Option<&'static EvidenceEntry> {
    EVIDENCE_TABLE.iter().find(|e| e.artifact_id == artifact_id)
}

/// Returns all artifacts at or above the given strength threshold.
pub fn artifacts_with_strength(min_strength: EvidenceStrength) -> Vec<&'static EvidenceEntry> {
    EVIDENCE_TABLE
        .iter()
        .filter(|e| e.strength >= min_strength)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{TriagePriority, CATALOG};

    #[test]
    fn prefetch_is_definitive() {
        let e = evidence_for("prefetch_file").expect("prefetch_file must be in table");
        assert_eq!(e.strength, EvidenceStrength::Definitive);
    }

    #[test]
    fn bash_history_is_circumstantial() {
        let e = evidence_for("linux_bash_history").expect("linux_bash_history must be in table");
        assert_eq!(e.strength, EvidenceStrength::Circumstantial);
    }

    #[test]
    fn definitive_entries_have_caveats() {
        // Even definitive evidence should document its limitations
        for entry in EVIDENCE_TABLE {
            if entry.strength == EvidenceStrength::Definitive {
                assert!(
                    !entry.caveats.is_empty(),
                    "{} is Definitive but has no caveats documented",
                    entry.artifact_id
                );
            }
        }
    }

    #[test]
    fn strength_ordering_is_consistent() {
        assert!(EvidenceStrength::Definitive > EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong > EvidenceStrength::Corroborative);
        assert!(EvidenceStrength::Corroborative > EvidenceStrength::Circumstantial);
        assert!(EvidenceStrength::Circumstantial > EvidenceStrength::Unreliable);
    }

    #[test]
    fn filter_by_strength_returns_subset() {
        let definitive = artifacts_with_strength(EvidenceStrength::Definitive);
        let all = artifacts_with_strength(EvidenceStrength::Unreliable);
        assert!(definitive.len() < all.len());
        assert!(definitive
            .iter()
            .all(|e| e.strength == EvidenceStrength::Definitive));
    }

    #[test]
    fn unknown_artifact_returns_none() {
        assert!(evidence_for("this_does_not_exist").is_none());
    }

    #[test]
    fn all_table_ids_exist_in_catalog() {
        let catalog_ids: std::collections::HashSet<&str> =
            CATALOG.list().iter().map(|d| d.id).collect();
        for entry in EVIDENCE_TABLE {
            assert!(
                catalog_ids.contains(entry.artifact_id),
                "evidence table references unknown catalog id: {}",
                entry.artifact_id
            );
        }
    }

    #[test]
    fn critical_triage_artifacts_have_evidence_entries() {
        let missing: Vec<&str> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| d.triage_priority == TriagePriority::Critical)
            .filter(|d| evidence_for(d.id).is_none())
            .map(|d| d.id)
            .collect();
        assert!(
            missing.is_empty(),
            "Critical-priority artifacts missing from evidence table: {missing:?}"
        );
    }
}
