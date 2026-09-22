//! Extended Linux artifact descriptors.
//!
//! Sources: Velociraptor Linux artifacts, ForensicArtifacts/artifacts (linux.yaml),
//! auditd(8) and audit.rules(7) manual pages, Docker/container forensics resources.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static LINUX_AUDITD_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_auditd_log",
    name: "Auditd Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/audit/audit.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Linux Audit daemon log recording syscall-level events: file access, process execution (execve), privilege escalation, network connections, and authentication. The highest-fidelity forensic source on Linux when configured — provides a comprehensive record equivalent to Sysmon on Windows.",
    mitre_techniques: &["T1562.001", "T1059", "T1078"],
    fields: &[
        FieldSchema { name: "type", value_type: ValueType::Text, description: "Audit record type (SYSCALL, EXECVE, etc.)", is_uid_component: true },
        FieldSchema { name: "pid", value_type: ValueType::UnsignedInt, description: "Process ID", is_uid_component: false },
        FieldSchema { name: "comm", value_type: ValueType::Text, description: "Command name", is_uid_component: false },
        FieldSchema { name: "exe", value_type: ValueType::Text, description: "Executable path", is_uid_component: false },
    ],
    retention: Some("Rotated by logrotate; retain_num and max_log_file configurable"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_auth_log", "linux_syslog"],
    sources: &[
        "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Kernel-level syscall auditing; attacker must disable auditd to evade"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_AUDIT_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_audit_rules",
    name: "Auditd Rules Configuration",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/audit/rules.d/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Active auditd ruleset defining what syscalls and file accesses are monitored. Reviewing rules reveals coverage gaps and attacker-planted rule deletions that silently disable monitoring of specific activity.",
    mitre_techniques: &["T1562.001"],
    fields: &[FieldSchema { name: "rule", value_type: ValueType::Text, description: "Audit rule definition", is_uid_component: true }],
    retention: Some("Persistent configuration"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_auditd_log"],
    sources: &["https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Empty/missing rules indicate auditd not configured, not necessarily attacker tampering"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration files persist until explicit modification",
};

pub(crate) static LINUX_SYSLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_syslog",
    name: "Syslog",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/syslog"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Main system log on Debian/Ubuntu aggregating messages from most daemons (cron, NetworkManager, rsyslogd, kernel, etc.). Broad-spectrum timeline reconstruction source — often the first log checked in Linux IR.",
    mitre_techniques: &["T1562.002"],
    fields: &[
        FieldSchema { name: "facility", value_type: ValueType::Text, description: "Syslog facility (auth, kern, daemon, etc.)", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Log message body", is_uid_component: true },
    ],
    retention: Some("Rotated weekly; 4 rotations kept by default"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_auth_log", "linux_journal_dir"],
    sources: &["https://www.sans.org/blog/linux-forensics-from-basic-to-in-depth-evidence-collection/"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Easily cleared/modified by root attackers",
        "logrotate compresses and eventually deletes old entries",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Syslog file rotated daily/weekly by logrotate",
};

pub(crate) static LINUX_MESSAGES_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_messages_log",
    name: "Messages Log (RHEL/CentOS)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/messages"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Main system log on RHEL/CentOS/Fedora (equivalent to /var/log/syslog on Debian). Contains daemon messages, hardware events, and network activity. Primary starting point for Linux IR on Red Hat-family systems.",
    mitre_techniques: &["T1562.002"],
    fields: &[FieldSchema { name: "message", value_type: ValueType::Text, description: "Log message body", is_uid_component: true }],
    retention: Some("Rotated; 4 rotations kept"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_secure_log", "linux_journal_dir"],
    sources: &["https://www.sans.org/blog/linux-forensics-from-basic-to-in-depth-evidence-collection/"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Easily cleared/modified by root attackers",
        "logrotate compresses and eventually deletes old entries",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Messages log rotated by logrotate with bounded retention",
};

pub(crate) static LINUX_SECURE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_secure_log",
    name: "Secure Log (RHEL/CentOS authentication)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/secure"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Authentication and authorization log on RHEL/CentOS/Fedora (equivalent to auth.log on Debian). Contains su, sudo, sshd, and PAM events. Primary source for privilege escalation and lateral movement analysis on Red Hat-family systems.",
    mitre_techniques: &["T1078", "T1110", "T1021.004"],
    fields: &[
        FieldSchema { name: "process", value_type: ValueType::Text, description: "Process generating the auth event", is_uid_component: true },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Authentication event message", is_uid_component: false },
    ],
    retention: Some("Rotated; 4 rotations kept"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_auditd_log", "linux_journal_dir"],
    sources: &["https://www.sans.org/blog/linux-forensics-from-basic-to-in-depth-evidence-collection/"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Authentication events; quality depends on PAM configuration"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_APACHE_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apache_access_log",
    name: "Apache HTTP Server Access Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/apache2/access.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Apache access log recording client IP, request method, URI, response code, and user-agent. Critical for web attack investigation: SQL injection, LFI/RFI, webshell access, C2 beaconing, and data exfiltration via HTTP.",
    mitre_techniques: &["T1190", "T1505.003", "T1071.001"],
    fields: &[
        FieldSchema { name: "client_ip", value_type: ValueType::Text, description: "Client IP address", is_uid_component: true },
        FieldSchema { name: "request", value_type: ValueType::Text, description: "HTTP method + URI + protocol", is_uid_component: false },
        FieldSchema { name: "status_code", value_type: ValueType::UnsignedInt, description: "HTTP response status code", is_uid_component: false },
        FieldSchema { name: "user_agent", value_type: ValueType::Text, description: "Client User-Agent header", is_uid_component: false },
    ],
    retention: Some("Rotated weekly; configurable"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_nginx_access_log"],
    sources: &[
        "https://www.sans.org/blog/web-server-log-analysis-for-incident-responders/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Web exploitation primary source; attacker may delete or tamper"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_APACHE_ERROR_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apache_error_log",
    name: "Apache HTTP Server Error Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/apache2/error.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Apache error log showing server-side errors, mod_security alerts, and failed request details. Reveals exploitation attempts that generate server-side exceptions — stack traces may expose vulnerable code paths.",
    mitre_techniques: &["T1190"],
    fields: &[FieldSchema { name: "error_message", value_type: ValueType::Text, description: "Error message and stack trace", is_uid_component: true }],
    retention: Some("Rotated weekly"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_apache_access_log"],
    sources: &[
        "https://www.sans.org/blog/web-server-log-analysis-for-incident-responders/",
        "https://httpd.apache.org/docs/current/logs.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Routine application errors generate noise — exploit indicators require pattern matching"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Apache error log rotated by logrotate",
};

pub(crate) static LINUX_NGINX_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_nginx_access_log",
    name: "Nginx Access Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/nginx/access.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Nginx web server access log. Same forensic value as Apache access log; critical for reverse proxy and web application attack investigation. Also covers nginx acting as API gateway or load balancer for containerized apps.",
    mitre_techniques: &["T1190", "T1505.003", "T1071.001"],
    fields: &[
        FieldSchema { name: "client_ip", value_type: ValueType::Text, description: "Client IP address", is_uid_component: true },
        FieldSchema { name: "request", value_type: ValueType::Text, description: "HTTP request line", is_uid_component: false },
        FieldSchema { name: "status_code", value_type: ValueType::UnsignedInt, description: "HTTP response status code", is_uid_component: false },
    ],
    retention: Some("Rotated; configurable"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_apache_access_log"],
    sources: &[
        "https://www.sans.org/blog/web-server-log-analysis-for-incident-responders/",
        "https://nginx.org/en/docs/http/ngx_http_log_module.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Web exploitation primary source; attacker may delete or tamper"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_FAIL2BAN_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_fail2ban_log",
    name: "Fail2Ban Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/fail2ban.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Fail2ban action log recording IP addresses banned for repeated authentication failures. Shows brute-force attack source IPs and ban/unban events — unban events may indicate attacker manipulation of fail2ban rules.",
    mitre_techniques: &["T1110"],
    fields: &[
        FieldSchema { name: "banned_ip", value_type: ValueType::Text, description: "IP address banned", is_uid_component: true },
        FieldSchema { name: "jail", value_type: ValueType::Text, description: "Fail2ban jail that triggered the ban", is_uid_component: false },
    ],
    retention: Some("Rotated"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_auth_log", "linux_secure_log"],
    sources: &[
        "https://www.fail2ban.org/wiki/index.php/Main_Page",
        "https://linux.die.net/man/8/fail2ban",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only present when fail2ban is installed and active"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Fail2ban log rotated by logrotate",
};

pub(crate) static LINUX_DPKG_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dpkg_log",
    name: "DPKG Package Manager Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/log/dpkg.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Debian package manager log recording all install/upgrade/remove/purge operations with precise timestamps. Establishes software installation timeline — reveals attacker-installed tools, backdoored packages, or cleanup attempts.",
    mitre_techniques: &["T1072", "T1195.002"],
    fields: &[
        FieldSchema { name: "package_name", value_type: ValueType::Text, description: "Package name", is_uid_component: true },
        FieldSchema { name: "action", value_type: ValueType::Text, description: "install/upgrade/remove/purge", is_uid_component: false },
        FieldSchema { name: "version", value_type: ValueType::Text, description: "Package version", is_uid_component: false },
    ],
    retention: Some("Rotated monthly; 12 months typically kept"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_apt_hooks"],
    sources: &[
        "https://linux.die.net/man/1/dpkg",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Root attackers can delete or modify entries",
        "Snap/Flatpak/manual installs do not appear here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "DPKG log rotated by logrotate",
};

pub(crate) static LINUX_RPM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rpm_db",
    name: "RPM Package Database",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/lib/rpm/Packages"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Berkeley DB / SQLite database of all installed RPM packages with install timestamps, file checksums, and signatories. Queried with `rpm -qa --last` to reconstruct package installation timeline on RHEL/CentOS systems.",
    mitre_techniques: &["T1072", "T1195.002"],
    fields: &[
        FieldSchema { name: "package_name", value_type: ValueType::Text, description: "RPM package name", is_uid_component: true },
        FieldSchema { name: "install_time", value_type: ValueType::Timestamp, description: "Package installation timestamp", is_uid_component: false },
    ],
    retention: Some("Updated on install/remove; reflects current state"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_messages_log"],
    sources: &[
        "https://linux.die.net/man/8/rpm",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Root attackers can rebuild the database to hide entries",
        "Manual binary installs bypass RPM",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "RPM database persists across reboots; updated on each package operation",
};

pub(crate) static LINUX_SELINUX_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_selinux_config",
    name: "SELinux Configuration",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/selinux/config"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SELinux mode configuration (Enforcing/Permissive/Disabled). An attacker who sets SELINUX=permissive or disabled removes mandatory access control enforcement — this file persists the change across reboots and is a clear indicator of defense evasion.",
    mitre_techniques: &["T1562"],
    fields: &[FieldSchema { name: "selinux_mode", value_type: ValueType::Text, description: "SELinux mode (enforcing/permissive/disabled)", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_auditd_log"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/8/selinux",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Disabled SELinux is itself a strong indicator of attacker activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Config file; persistent until modified",
};

pub(crate) static LINUX_APPARMOR_PROFILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apparmor_profiles",
    name: "AppArmor Profiles",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/apparmor.d/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "AppArmor mandatory access control profiles for confined processes. Attacker modification of profiles can silently grant confined processes expanded file, network, or capability permissions — effective defense evasion on Ubuntu/Debian systems.",
    mitre_techniques: &["T1562"],
    fields: &[FieldSchema { name: "profile_name", value_type: ValueType::Text, description: "AppArmor profile name (usually process path)", is_uid_component: true }],
    retention: Some("Persistent configuration"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_auditd_log"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://gitlab.com/apparmor/apparmor/-/wikis/Documentation",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only meaningful on AppArmor-enabled distributions (Ubuntu, SUSE)"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration files persist until explicit modification",
};

pub(crate) static LINUX_IPTABLES_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_iptables_rules",
    name: "Persisted iptables Rules (IPv4)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/iptables/rules.v4"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Persisted IPv4 iptables ruleset (Debian/Ubuntu). Reveals firewall configuration including port redirections, ACCEPT/DROP rules, and logging targets. Attacker modification can open ports for C2 reverse shells or disable egress filtering.",
    mitre_techniques: &["T1562.004"],
    fields: &[FieldSchema { name: "rule", value_type: ValueType::Text, description: "iptables rule definition", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_nftables_conf"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/8/iptables",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Live ruleset (iptables -L) may differ from persisted file if not saved",
        "Modern systems use nftables instead",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file persists until explicit modification",
};

pub(crate) static LINUX_NFTABLES_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_nftables_conf",
    name: "nftables Firewall Configuration",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/nftables.conf"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "nftables firewall configuration (modern replacement for iptables on RHEL 8+/Debian 10+). Modification reveals firewall tampering for defense evasion or lateral movement facilitation.",
    mitre_techniques: &["T1562.004"],
    fields: &[FieldSchema { name: "rule", value_type: ValueType::Text, description: "nftables rule definition", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_iptables_rules"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://wiki.nftables.org/wiki-nftables/index.php/Main_Page",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Live ruleset may differ from persisted file if not saved"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file persists until explicit modification",
};

pub(crate) static LINUX_HOSTS_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_hosts_file",
    name: "/etc/hosts (static DNS overrides)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/hosts"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Static DNS resolution table. Attacker modification redirects domain lookups (e.g., security update servers) to attacker-controlled IPs, enabling DNS hijacking for credential harvesting, C2, or blocking security tool updates.",
    mitre_techniques: &["T1565.001", "T1584"],
    fields: &[
        FieldSchema { name: "ip_address", value_type: ValueType::Text, description: "IP address", is_uid_component: true },
        FieldSchema { name: "hostname", value_type: ValueType::Text, description: "Hostname(s) mapped to IP", is_uid_component: false },
    ],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_resolv_conf"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/5/hosts",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Some legitimate enterprise environments use hosts entries for internal services"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file persists until explicit modification",
};

pub(crate) static LINUX_RESOLV_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_resolv_conf",
    name: "/etc/resolv.conf (DNS resolver config)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/resolv.conf"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "DNS resolver configuration pointing to nameserver IPs. Modification to point to an attacker-controlled DNS server enables DNS hijacking and traffic interception — all hostname resolution goes through the malicious resolver.",
    mitre_techniques: &["T1565.001"],
    fields: &[FieldSchema { name: "nameserver", value_type: ValueType::Text, description: "DNS server IP address", is_uid_component: true }],
    retention: Some("Persistent; may be overwritten by NetworkManager/dhclient"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_hosts_file"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/5/resolv.conf",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Frequently regenerated by NetworkManager/systemd-resolved — not always persistent",
        "DHCP-pushed nameservers may legitimately point to unfamiliar IPs",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Frequently overwritten by NetworkManager/systemd-resolved on network changes",
};

pub(crate) static LINUX_PROC_MODULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_modules",
    name: "/proc/modules (loaded kernel modules)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/proc/modules"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Live list of loaded kernel modules with addresses and reference counts. Rootkits often load as kernel modules — this file (during live response) reveals loaded modules including those hidden from lsmod via /proc manipulation.",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[
        FieldSchema { name: "module_name", value_type: ValueType::Text, description: "Kernel module name", is_uid_component: true },
        FieldSchema { name: "size", value_type: ValueType::UnsignedInt, description: "Module size in bytes", is_uid_component: false },
    ],
    retention: Some("Live kernel state — volatile"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_modprobe_d", "linux_journal_dir"],
    sources: &[
        // proc_modules(5) — dedicated man page for /proc/modules format and fields
        "https://man7.org/linux/man-pages/man5/proc_modules.5.html",
        // Volatility Phalanx 2 analysis: linux_lsmod vs /proc/modules to detect hidden LKM rootkits
        "https://volatility-labs.blogspot.com/2012/10/phalanx-2-revealed-using-volatility-to.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Live kernel modules; rootkit detection; lost on reboot"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Virtual FS; lost on reboot",
};

pub(crate) static LINUX_MODPROBE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_modprobe_d",
    name: "modprobe.d Configuration (module loading hooks)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/modprobe.d/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Kernel module configuration directory. Persistence via `install` directives causes a malicious binary to execute whenever a legitimate module is loaded — effective module hijacking that survives reboots and appears as normal hardware activity.",
    mitre_techniques: &["T1547.006", "T1574.006"],
    fields: &[FieldSchema { name: "directive", value_type: ValueType::Text, description: "modprobe configuration directive", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_proc_modules", "linux_modules_load_d"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/5/modprobe.d",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Some legitimate hardware vendor packages add modprobe configuration"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration directory persists until explicit modification",
};

pub(crate) static LINUX_DOCKER_CONTAINER_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_container_logs",
    name: "Docker Container Logs and State",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/lib/docker/containers/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Docker container runtime data including per-container JSON log files (`*-json.log`), configuration, network settings, and state. Reveals container activity, volume mounts, environment variables, and exposed ports for containerized malware or compromised workloads.",
    mitre_techniques: &["T1610", "T1611"],
    fields: &[
        FieldSchema { name: "container_id", value_type: ValueType::Text, description: "Container ID (directory name prefix)", is_uid_component: true },
        FieldSchema { name: "image", value_type: ValueType::Text, description: "Container image name and tag", is_uid_component: false },
    ],
    retention: Some("Persists until container and logs are removed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_docker_daemon_json"],
    sources: &[
        "https://www.sans.org/blog/container-forensics/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Container removal deletes associated logs",
        "json-log driver is default but can be overridden to non-persistent backends",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Per-container JSON logs with size-based rotation; deleted on container removal",
};

pub(crate) static LINUX_DOCKER_DAEMON_JSON: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_daemon_json",
    name: "Docker Daemon Configuration",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/docker/daemon.json"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Docker daemon configuration. Modification can enable insecure registries, disable content trust, expose the Docker API socket via TCP (unauthenticated), or configure privileged containers — all high-value attacker persistence and escalation techniques.",
    mitre_techniques: &["T1610", "T1562"],
    fields: &[FieldSchema { name: "config_key", value_type: ValueType::Text, description: "Configuration parameter", is_uid_component: true }],
    retention: Some("Persistent"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_docker_container_logs"],
    sources: &[
        "https://www.sans.org/blog/container-forensics/",
        "https://docs.docker.com/config/daemon/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["File may be absent on default installs (Docker uses defaults)"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file persists until explicit modification",
};

pub(crate) static LINUX_COREDUMP_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_coredump_dir",
    name: "systemd Coredump Storage",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/lib/systemd/coredump/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "systemd coredump storage for crashed processes. Process memory dumps preserved here can contain in-memory secrets (decryption keys, plaintext credentials), decrypted data, and evidence of exploited processes — valuable but often overlooked.",
    mitre_techniques: &["T1005"],
    fields: &[
        FieldSchema { name: "process_name", value_type: ValueType::Text, description: "Crashed process name", is_uid_component: true },
        FieldSchema { name: "signal", value_type: ValueType::UnsignedInt, description: "Signal that caused the crash", is_uid_component: false },
    ],
    retention: Some("Kept up to configured size limit"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_journal_dir"],
    sources: &["https://systemd.io/COREDUMP/"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Coredumps disabled by default on many distributions (kernel.core_pattern, ulimit)",
        "systemd-coredump retention is time- and size-bounded",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "systemd-coredump retention is bounded by time and size",
};

pub(crate) static LINUX_LOGROTATE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_logrotate_d",
    name: "Logrotate Configuration Fragments",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/etc/logrotate.d/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-service log rotation configuration fragments. Attacker modification can reduce retention periods, disable compression, or shred rotated logs — anti-forensic evidence that silently destroys log history.",
    mitre_techniques: &["T1070"],
    fields: &[FieldSchema { name: "config_file", value_type: ValueType::Text, description: "Service-specific logrotate config", is_uid_component: true }],
    retention: Some("Persistent configuration"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_syslog", "linux_auth_log"],
    sources: &[
        "https://www.sans.org/blog/linux-persistence-mechanisms/",
        "https://linux.die.net/man/8/logrotate",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Most fragments are package-installed defaults; tampering must be distinguished"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration directory persists until explicit modification",
};

pub(crate) static LINUX_SNAP_PACKAGES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_snap_packages",
    name: "Installed Snap Packages",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,    file_path: Some("/var/lib/snapd/snaps/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Installed Snap packages (squashfs images). Snap installs bypass traditional package managers and may leave no dpkg/rpm audit trail — reveals snap-installed software including attacker tools that evade package-log-based detection.",
    mitre_techniques: &["T1072"],
    fields: &[FieldSchema { name: "snap_name", value_type: ValueType::Text, description: "Snap package name and revision", is_uid_component: true }],
    retention: Some("Retained until snap is removed"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_dpkg_log"],
    sources: &[
        "https://snapcraft.io/docs/snap-format",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only meaningful on systems with snapd installed",
        "Snap revisions accumulate but are pruned",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Snap package directory persists until explicit removal",
};

// ── Batch I: Linux kernel / live-system artifacts ──────────────────────────

/// Live kernel ring buffer — the in-memory circular buffer read via `dmesg` or `/dev/kmsg`.
///
/// Distinct from `linux_dmesg` (/var/log/dmesg file written at boot): this is the
/// live buffer holding all messages since boot, not yet written to any file. On a
/// running system this contains more recent messages than the file. Lost on reboot.
pub(crate) static LINUX_DMESG_RING_BUFFER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dmesg_ring_buffer",
    name: "Kernel Ring Buffer (live, dmesg command)",
    artifact_type: ArtifactLocation::LiveResponse,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Live kernel ring buffer — all messages since boot, including those not yet \
        written to /var/log/dmesg. Records driver load errors, hardware detection, LKM load \
        events, and module initialization in real time. Richer than the boot-time snapshot \
        in linux_dmesg. In rootkit investigations, compare against /var/log/dmesg to detect \
        messages that appeared after boot (indicating post-boot LKM injection).",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Seconds since boot (monotonic, e.g. [    1.234567])", is_uid_component: false },
        FieldSchema { name: "subsystem", value_type: ValueType::Text, description: "Kernel subsystem prefix", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Kernel ring buffer message text", is_uid_component: false },
    ],
    retention: Some("Lost on reboot; ring buffer wraps when full (default 512KB–16MB depending on kernel config)"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_dmesg", "linux_kern_log", "linux_proc_modules", "linux_chkrootkit_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man1/dmesg.1.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Ring buffer wraps when full; collect early in live response",
        "Root can clear the ring buffer with dmesg --clear (T1070); absence of boot messages is suspicious",
        "See linux_dmesg for the persisted file snapshot written at boot",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "In-memory circular buffer; lost on reboot",
};

pub(crate) static LINUX_KERN_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kern_log",
    name: "Kernel Syslog (Debian/Ubuntu)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/kern.log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "Continuous kernel syslog messages (Debian/Ubuntu). Contains kernel module load/unload events, iptables rule firings, and hardware anomalies. Rootkit-loaded kernel modules appear here as insmod/modprobe events unless the rootkit hides its own load.",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[],
    retention: Some("Rotated by logrotate; typically 4 weeks retained"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_dmesg_ring_buffer", "linux_proc_modules", "linux_syslog"],
    sources: &[
        // syslog(3) — kernel logging facility LOG_KERN feeds kern.log
        "https://man7.org/linux/man-pages/man3/syslog.3.html",
        // Elastic sequel: syslog/kern messages used to detect LKM rootkit persistence events
        "https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Rootkits can suppress their own load events",
        "Easily cleared/modified by root attackers",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Kernel log rotated by logrotate",
};

pub(crate) static LINUX_PROC_KALLSYMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_kallsyms",
    name: "Kernel Symbol Table",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/proc/kallsyms"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Kernel symbol table listing all exported kernel symbols with addresses. Cross-reference with lsmod to find kernel modules that have injected symbols without appearing in the module list — a primary LKM rootkit detection technique. Requires root to see addresses (security.perf_kernel_harden).",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[],
    retention: Some("Live /proc interface; reflects current kernel state"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_proc_modules", "linux_dmesg_ring_buffer"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Requires root; compare against expected module symbols to find injected code"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Reflects live kernel symbol table; changes if modules loaded/unloaded",
};

pub(crate) static LINUX_PROC_NET_TCP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_tcp",
    name: "Kernel IPv4 TCP Socket Table",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/proc/net/tcp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Raw IPv4 TCP socket table in hex format. Cross-reference with 'ss -antp' output: sockets present here but absent from ss indicate a rootkit hiding network connections via syscall hooking or /proc manipulation. Used to detect hidden miner pool connections and C2 channels.",
    mitre_techniques: &["T1014", "T1571", "T1572"],
    fields: &[],
    retention: Some("Live /proc interface; reflects current kernel state"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_ss_output", "linux_proc_net_tcp6", "linux_proc_net_unix"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Live socket table; grab immediately — C2 connections close on detection"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Kernel socket table; entries vanish on connection close",
};

pub(crate) static LINUX_PROC_NET_TCP6: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_tcp6",
    name: "Kernel IPv6 TCP Socket Table",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/proc/net/tcp6"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Raw IPv6 TCP socket table. Complements /proc/net/tcp for IPv6 connections. Rootkits may suppress IPv6 hiding from ss/netstat but leave entries in /proc/net/tcp6 visible to direct file reads.",
    mitre_techniques: &["T1014", "T1571"],
    fields: &[],
    retention: Some("Live /proc interface; reflects current kernel state"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_proc_net_tcp", "linux_ss_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Live snapshot only — historical connections not preserved"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Live kernel snapshot; lost on reboot",
};

pub(crate) static LINUX_PROC_NET_UDP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_udp",
    name: "Kernel IPv4 UDP Socket Table",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/proc/net/udp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Raw IPv4 UDP socket table. DNS-over-UDP port 53 traffic, NTP, and exfiltration via UDP can be detected here. Compare with ss -u output for discrepancies indicating hidden UDP channels.",
    mitre_techniques: &["T1048", "T1071.004"],
    fields: &[],
    retention: Some("Live /proc interface; reflects current kernel state"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_proc_net_tcp", "linux_ss_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["UDP is connectionless — entries reflect bound sockets, not flows"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Live kernel snapshot; lost on reboot",
};

pub(crate) static LINUX_PROC_NET_UNIX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_unix",
    name: "Kernel Unix Domain Socket Table",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/proc/net/unix"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Unix domain socket table. Cryptocurrency miners like XMRig use unix sockets for IPC between the miner process and its controller. Hidden processes with unix socket connections to known miner paths appear here even when the process is hidden from ps.",
    mitre_techniques: &["T1496", "T1014"],
    fields: &[],
    retention: Some("Live /proc interface; reflects current kernel state"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_proc_net_tcp", "linux_ss_output", "linux_lsof_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Only reflects active sockets at acquisition time"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Live kernel snapshot; lost on reboot",
};

pub(crate) static LINUX_LSOF_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_lsof_output",
    name: "lsof Open Files Output",
    artifact_type: ArtifactLocation::LiveResponse,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "lsof (list open files) output from live response collection. Shows all files, sockets, and devices held open by each process including deleted files still referenced by file descriptors. Critical for finding: (1) deleted malware binaries still running via memfd, (2) hidden library injection via LD_PRELOAD, (3) C2 sockets with remote endpoints.",
    mitre_techniques: &["T1014", "T1055", "T1574.006"],
    fields: &[],
    retention: Some("UAC live response collection: live_response/process/lsof*"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_proc_net_unix", "linux_ss_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man8/lsof.8.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Live-response only; deleted files visible only while process holds fd open"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Process state; lost on process exit or system reboot",
};

pub(crate) static LINUX_SS_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ss_output",
    name: "ss Socket Statistics Output",
    artifact_type: ArtifactLocation::LiveResponse,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "ss (socket statistics) output with process information (-antp flags). The authoritative user-space view of network connections. Compare with /proc/net/tcp to detect rootkit-hidden connections: if a socket appears in /proc/net/tcp but not in ss output, a rootkit is filtering the syscall return value.",
    mitre_techniques: &["T1014", "T1571", "T1572"],
    fields: &[],
    retention: Some("UAC live response collection: live_response/network/ss*"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_proc_net_tcp", "linux_lsof_output", "linux_proc_net_unix"],
    sources: &[
        "https://man7.org/linux/man-pages/man8/ss.8.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &["Live-response only; C2 connections disappear on session teardown"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Socket table exists only while connections are active",
};

pub(crate) static LINUX_CHKROOTKIT_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_chkrootkit_output",
    name: "chkrootkit Scan Results",
    artifact_type: ArtifactLocation::LiveResponse,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "chkrootkit scan results from UAC live response. Checks for known rootkit indicators: LD_PRELOAD entries, hidden processes (via /proc vs ps discrepancy), suspicious network connections, trojaned binaries. The 'etc_ld_so_preload' check directly surfaces LD_PRELOAD rootkit persistence.",
    mitre_techniques: &["T1014", "T1574.006"],
    fields: &[],
    retention: Some("UAC live response collection: chkrootkit/"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_lsof_output", "linux_rkhunter_log", "linux_dmesg_ring_buffer"],
    sources: &[
        "https://www.chkrootkit.org/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &["Rootkit may subvert chkrootkit itself; corroborate with memory forensics"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Assessment output; not persisted unless explicitly saved",
};

pub(crate) static LINUX_RKHUNTER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rkhunter_log",
    name: "Rootkit Hunter Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/rkhunter.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Rootkit Hunter scan log. Checks for known rootkit file signatures, hidden files in /dev, suspicious shared libraries, and system command tampering. Complements chkrootkit with SHA256 baseline comparison against known-good system binaries.",
    mitre_techniques: &["T1014", "T1036.005"],
    fields: &[],
    retention: Some("Retained until manually cleared or logrotated"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_chkrootkit_output", "linux_dmesg_ring_buffer"],
    sources: &[
        "https://rkhunter.sourceforge.net/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only present when rkhunter is installed and run",
        "Generates false positives for legitimate system modifications",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Scan log rotated by logrotate",
};

pub(crate) static LINUX_SYSCTL_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sysctl_conf",
    name: "Kernel Parameter Configuration",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/sysctl.conf"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Kernel parameter configuration applied at boot. Attackers modify sysctl parameters for persistence or evasion: disabling core dumps (kernel.core_pattern for malicious handler), enabling IP forwarding for routing attacks (net.ipv4.ip_forward=1), or modifying memory protection (kernel.randomize_va_space=0 to disable ASLR).",
    mitre_techniques: &["T1562.006", "T1547.011"],
    fields: &[],
    retention: Some("Persistent configuration file"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_modules_load_d", "linux_udev_rules_d"],
    sources: &[
        "https://man7.org/linux/man-pages/man8/sysctl.8.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Live sysctl values may differ if changes were made via /proc/sys at runtime"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file persists until explicit modification",
};

// ── Group D: Linux Kernel / Proc (new artifacts only — LINUX_KERN_LOG already defined above) ──

pub(crate) static LINUX_DMESG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dmesg",
    name: "Kernel Ring Buffer Log (dmesg)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/dmesg"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Persisted copy of the kernel ring buffer from the most recent boot. Written by the init system (systemd/SysV) at boot completion. Contains hardware initialization, device driver probe messages, module loading at boot time, and kernel taint information. Forensically distinct from kern.log in that it captures only the boot-time window. Key indicators: LKM load events during boot (rootkit persistence via /etc/modules or initrd), taint flags set during boot, unexpected hardware appearing in lspci/lsusb output but not here (indicates late/live insertion). The live ring buffer is volatile — accessible via 'dmesg' command on running systems.",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[
        FieldSchema { name: "elapsed_seconds", value_type: ValueType::Text, description: "Seconds since boot (kernel monotonic clock, e.g. [    1.234567])", is_uid_component: false },
        FieldSchema { name: "subsystem", value_type: ValueType::Text, description: "Kernel subsystem prefix (usb, pci, net, etc.)", is_uid_component: false },
        FieldSchema { name: "message", value_type: ValueType::Text, description: "Kernel ring buffer message text", is_uid_component: false },
    ],
    retention: Some("Overwritten at each boot; in-memory ring buffer is volatile"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_kern_log", "linux_proc_modules", "linux_dmesg_ring_buffer"],
    sources: &[
        "https://man7.org/linux/man-pages/man1/dmesg.1.html",
        "https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Only captures most-recent boot window; older boots overwritten",
        "Easily cleared/modified by root attackers",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Persisted at boot; overwritten on next boot",
};

pub(crate) static LINUX_BOOT_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_boot_log",
    name: "Boot Log (/var/log/boot.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/boot.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Service start/stop messages captured during system boot by bootlogd or the init system. On systemd systems, equivalent output is in the journal. boot.log records service success/failure status lines (OK/FAILED/SKIPPED) with service names. Forensically valuable as a temporal anchor: comparing boot.log timestamps against MFT/inode change times establishes whether files were modified before or after a known boot event. Unusual FAILED entries may indicate rootkit interference with service initialization.",
    mitre_techniques: &["T1014"],
    fields: &[
        FieldSchema { name: "timestamp", value_type: ValueType::Timestamp, description: "Boot event timestamp", is_uid_component: false },
        FieldSchema { name: "service_name", value_type: ValueType::Text, description: "Service or unit name", is_uid_component: false },
        FieldSchema { name: "status", value_type: ValueType::Text, description: "OK, FAILED, or SKIPPED", is_uid_component: false },
    ],
    retention: Some("Overwritten at each boot on many distributions"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_kern_log", "linux_journal_dir"],
    sources: &[
        "https://man7.org/linux/man-pages/man8/bootlogd.8.html",
        "https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &["systemd systems may have empty boot.log; equivalent data in journald"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Boot log rotated by logrotate",
};

// ── Group E: Linux Auth/Binary Logs ──────────────────────────────────────────

pub(crate) static LINUX_FAILLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_faillog",
    name: "Failed Login Log (/var/log/faillog)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/faillog"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary database of failed login counts indexed by UID. Fixed-size records (struct faillog): fail_cnt (int16, consecutive failure count), fail_max (int16, lockout threshold), fail_time (time_t, last failure time), fail_line (tty string, 12 bytes), fail_locktime (int32, lockout duration in seconds). Read with 'faillog -a' or parse directly at struct offset UID * sizeof(faillog). High fail_cnt values for specific UIDs indicate brute-force targeting. Last failure time provides a timestamp independent of text log rotation. Root UID (0) attacks show at offset 0.",
    mitre_techniques: &["T1110"],
    fields: &[
        FieldSchema { name: "uid", value_type: ValueType::UnsignedInt, description: "User ID (record index; struct offset = uid * record_size)", is_uid_component: true },
        FieldSchema { name: "fail_cnt", value_type: ValueType::UnsignedInt, description: "Number of consecutive login failures for this UID", is_uid_component: false },
        FieldSchema { name: "fail_time", value_type: ValueType::Timestamp, description: "Unix timestamp of most recent failure", is_uid_component: false },
        FieldSchema { name: "fail_line", value_type: ValueType::Text, description: "TTY or PAM service of most recent failure attempt", is_uid_component: false },
    ],
    retention: Some("Persistent binary file; not affected by logrotate unless explicitly configured"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_auth_log", "linux_utmp", "linux_wtmp", "linux_faillock_dir"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/faillog.5.html",
        "https://man7.org/linux/man-pages/man8/faillog.8.html",
        "https://man7.org/linux/man-pages/man8/pam_faillock.8.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Many modern distributions have deprecated faillog in favor of pam_tally2/pam_faillock",
        "Nothing updates faillog unless a PAM tally module is configured, so all-zero counters do NOT mean no failed logins occurred",
        "Modern lockout state lives in /var/run/faillock/ (pam_faillock), not here — check both before reporting a negative",
        "Fixed-size structure overwritten on each failure",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Fixed-size per-UID record overwritten on each failure event",
};

// ── Hak5 LAN Turtle Credential Loot ─────────────────────────────────────────

/// Hak5 LAN Turtle credential loot directory (`/root/loot/`).
///
/// The LAN Turtle is a covert penetration testing device housed in a USB
/// Ethernet adapter case (Realtek RTL8152, VID 0BDA / PID 8152) running
/// OpenWrt Linux. The QuickCreds module runs Responder to capture LLMNR/
/// NBT-NS credentials (typically NTLMv2 hashes) from the host it is plugged
/// into. Captured credentials are saved to numbered subdirectories under
/// `/root/loot/` on the device's 16 MB flash storage.
///
/// Forensic examination of a seized LAN Turtle device involves SSH'ing to
/// 172.16.84.1 (default static IP on the USB Ethernet interface) or imaging
/// the flash storage directly. The loot directory contains Responder output
/// files with victim hostname, domain, username, and NTLMv2 hash.
///
/// On the victim Windows host, the LAN Turtle leaves standard USB device
/// registry artifacts (SYSTEM hive: USB\VID_0BDA&PID_8152) and DHCP event
/// log entries for the new network adapter.
///
/// # Sources
/// - <https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html> —
///   LAN Turtle forensic examination, QuickCreds credential capture, host artifacts
/// - <https://docs.hak5.org/lan-turtle/> — Hak5 LAN Turtle official documentation
// Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
pub(crate) static LAN_TURTLE_LOOT: ArtifactDescriptor = ArtifactDescriptor {
    id: "lan_turtle_loot",
    name: "Hak5 LAN Turtle Credential Loot",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    // Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
    // QuickCreds saves Responder output to numbered dirs in /root/loot/
    file_path: Some("/root/loot/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Hak5 LAN Turtle credential loot directory on the device's OpenWrt Linux \
        filesystem. The QuickCreds module uses Laurent Gaffie's Responder to perform \
        LLMNR/NBT-NS poisoning and capture NTLMv2 credentials from the host machine \
        the Turtle is plugged into. Credentials are stored in numbered subdirectories \
        under /root/loot/. Each capture file contains victim hostname, domain, username, \
        and NTLMv2 hash. The device identifies as a Realtek RTL8152 USB Ethernet \
        adapter (VID 0BDA / PID 8152) and has a static IP of 172.16.84.1 on its USB \
        interface. Credential capture completes in 30 seconds to a few minutes and \
        works whether the victim screen is locked or not (user must be logged in). \
        On the victim Windows host, evidence includes USB device registry entries \
        (SYSTEM hive: USB\\VID_0BDA&PID_8152\\00E04C36150A) and DHCP event log entries \
        for the Realtek USB FE Family Controller network adapter.",
    mitre_techniques: &["T1557.001", "T1200", "T1056"],
    fields: &[
        FieldSchema {
            name: "credential_type",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
            description: "Type of captured credential (e.g. NTLMv2, NTLMv1, HTTP Basic)",
            is_uid_component: false,
        },
        FieldSchema {
            name: "victim_hostname",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
            description: "Hostname of the victim machine that sent the credential",
            is_uid_component: true,
        },
        FieldSchema {
            name: "victim_username",
            value_type: ValueType::Text,
            description: "Username extracted from the credential response",
            is_uid_component: false,
        },
        FieldSchema {
            name: "hash_value",
            value_type: ValueType::Text,
            // Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
            description: "Captured NTLMv2 (or other) hash value; crackable with hashcat/john",
            is_uid_component: false,
        },
    ],
    retention: Some("Persistent on 16 MB flash until manually deleted or reflashed"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &[
        // Source: https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html
        // — LAN Turtle forensic examination walkthrough with QuickCreds and Responder
        "https://cheeky4n6monkey.blogspot.com/2017/01/monkey-plays-lan-turtle.html",
        // Source: https://docs.hak5.org/lan-turtle/ — official Hak5 LAN Turtle docs
        "https://docs.hak5.org/lan-turtle/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_tier: None,
    evidence_caveats: &[
        "Requires physical access to the LAN Turtle device (SSH to 172.16.84.1 or flash imaging)",
        "Loot files can be deleted by the attacker before seizure",
        "Credential type depends on victim OS — NTLMv2 for Windows 7+, may vary for others",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale:
        "Stored on 16 MB flash; persists until manually deleted or device is reflashed",
};

// ── /etc/passwd — local user account database ────────────────────────────────

// Linux `/etc/passwd` — local user account database (world-readable).
// Contains username, UID, GID, GECOS full name, home directory, and login shell.

// ── ESXi vSphere Trust Authority service logs ─────────────────────────────────

/// ESXi `/var/run/log/attestd.log` — vSphere Trust Authority Attestation Service.
///
/// Records attestation events for ESXi Trusted Hosts in a vSphere Trust Authority
/// deployment. Relevant in environments using vTA; anomalies here may indicate
/// tampering with the ESXi TPM attestation chain.
pub(crate) static ESXI_ATTESTD_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_attestd_log",
    name: "ESXi Attestation Service Log (attestd.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/run/log/attestd.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Records attestation events for the ESXi vSphere Trust Authority service. \
        Attestation failures or repeated retries may indicate hypervisor integrity tampering, \
        unauthorized firmware changes, or a host being removed from a trusted cluster. \
        Relevant in vTA deployments; cross-reference with esxtokend.log and kmxa.log for \
        full Trust Authority chain visibility.",
    mitre_techniques: &["T1562"],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped syslog-format log line from the attestation daemon",
        is_uid_component: false,
    }],
    retention: Some("Rotated; check /var/run/log/ for .gz rotations"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["esxi_esxtokend_log", "esxi_kmxa_log"],
    sources: &["https://github.com/forensicartifacts/artifacts"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Only present on ESXi hosts configured as vSphere Trust Authority Trusted Hosts",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "/var/run/log/ on ESXi is RAM-backed (tmpfs); lost on reboot",
};

/// ESXi `/var/run/log/esxtokend.log` — vSphere Trust Authority ESX Token Service.
///
/// Records token issuance events for authenticated workloads in a vTA deployment.
/// Unexpected token requests or failures can indicate credential harvesting against
/// the ESXi token service.
pub(crate) static ESXI_ESXTOKEND_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_esxtokend_log",
    name: "ESXi Token Service Log (esxtokend.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/run/log/esxtokend.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Records token issuance events for the ESXi vSphere Trust Authority Token Service. \
        Unexpected or high-volume token requests, authentication failures, or service restarts \
        may indicate credential harvesting against the ESXi trust chain. \
        Correlate with attestd.log and kmxa.log for full vTA event reconstruction.",
    mitre_techniques: &["T1552", "T1562"],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped syslog-format log line from the token service daemon",
        is_uid_component: false,
    }],
    retention: Some("Rotated; check /var/run/log/ for .gz rotations"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["esxi_attestd_log", "esxi_kmxa_log"],
    sources: &["https://github.com/forensicartifacts/artifacts"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &["Only present on ESXi hosts in a vSphere Trust Authority deployment"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "/var/run/log/ on ESXi is RAM-backed (tmpfs); lost on reboot",
};

/// ESXi `/var/run/log/kmxa.log` — vSphere Trust Authority Key Provider Client Service.
///
/// Records activities of the ESXi Key Management Agent (Client Service) on a
/// Trusted Host. Key provider failures can indicate encryption bypass attempts
/// or infrastructure-level attacks on a vTA cluster.
pub(crate) static ESXI_KMXA_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_kmxa_log",
    name: "ESXi Key Provider Agent Log (kmxa.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/run/log/kmxa.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Records activities of the Key Management Agent (Client Service) on an ESXi \
        Trusted Host in a vSphere Trust Authority deployment. Key provider errors, \
        unexpected key requests, or service restarts may indicate encryption bypass attempts \
        or infrastructure attacks targeting VM encryption keys. \
        Correlate with attestd.log and esxtokend.log.",
    mitre_techniques: &["T1552", "T1486"],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped syslog-format log line from the key management agent",
        is_uid_component: false,
    }],
    retention: Some("Rotated; check /var/run/log/ for .gz rotations"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["esxi_attestd_log", "esxi_esxtokend_log"],
    sources: &["https://github.com/forensicartifacts/artifacts"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: None,
    evidence_caveats: &[
        "Only present on ESXi Trusted Hosts in a vSphere Trust Authority deployment",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "/var/run/log/ on ESXi is RAM-backed (tmpfs); lost on reboot",
};

// ── Assessed artifacts (moved out of descriptors/generated/) ──────────────────
//
// Each of these carries a curated evidence strength and volatility class. No
// upstream corpus supplies that judgement, so it used to be written into the
// generated module by hand after every run — which a full-corpus regeneration
// erased. Here the ingest pipeline sees the id is already catalogued and skips
// its own record, so the judgement survives, and the triage priority is the
// artifact's own rather than the generator's High ceiling.

pub(crate) static VELOCIRAPTOR_FILE_LOG_AUTH_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_log_auth_log",
    name: "Linux.Events.SSHBruteforce",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/auth.log"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "A monitoring artifact which detects a successful SSH login preceded by some
failed attempts within the last hour.

This is particularly important in the case of SSH brute force attacks. If one
of the brute force password attempts succeeded, the password guessing program
will likely report the success and move on. This alert might provide
sufficient time for admins to lock down the account before attackers can
exploit the weak password.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Authentication events; check for brute-force patterns and privilege escalation",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Linux log rotates on size/time schedule",
};

pub(crate) static VELOCIRAPTOR_FILE_SYSLOGTIMESTAMP_TIMESTAMP_SYSLOGFACILITY_S: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_syslogtimestamp_timestamp_syslogfacility_s",
    name: "Linux.Events.SSHBruteforce",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}: %{DATA:event} %{DATA:method} for (invalid user )?%{DATA:user} from %{IPORHOST:ip} port %{NUMBER:port} ssh2(: %{GREEDYDATA:system.auth.ssh.signature})?"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "A monitoring artifact which detects a successful SSH login preceded by some
failed attempts within the last hour.

This is particularly important in the case of SSH brute force attacks. If one
of the brute force password attempts succeeded, the password guessing program
will likely report the success and move on. This alert might provide
sufficient time for admins to lock down the account before attackers can
exploit the weak password.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Authentication events; check for brute-force patterns and privilege escalation"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Linux log rotates on size/time schedule",
};

pub(crate) static VELOCIRAPTOR_FILE_SSH_PEM_ID_RSA_ID_DSA: ArtifactDescriptor =
    ArtifactDescriptor {
        id: "velociraptor_file_ssh_pem_id_rsa_id_dsa",
        name: "Linux.Ssh.PrivateKeys",
        artifact_type: ArtifactLocation::File,
        hive: None,
        key_path: "",
        value_name: None,
        file_path: Some("/home/*/.ssh/{*.pem,id_rsa,id_dsa}"),
        scope: DataScope::Mixed,
        os_scope: OsScope::Win7Plus,
        decoder: Decoder::Identity,
        meaning: "SSH Private keys can be either encrypted or unencrypted. Unencrypted
private keys are more risky because an attacker can use them without
needing to unlock them with a password.

In particular, AWS instances are usually accessed by way of an SSH
key pair generated by the AWS console. This key is not encrypted by
default and it is possible that administrators simply save the key
on their systems without encrypting it.

This artifact searches for private keys in the usual locations and
also records if they are encrypted or not. Not all key types are
supported

NOTE: To encrypt your private key run:

```
ssh-keygen -p -f my_private_key
```

Change the glob to /** if you would like to search the entire filesystem.
Be aware, this is an expensive operation.",
        mitre_techniques: &[],
        fields: &[],
        retention: None,
        triage_priority: TriagePriority::Critical,
        related_artifacts: &[],
        sources: &["https://github.com/Velocidex/velociraptor"],
        evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
        evidence_tier: None,
        evidence_caveats: &["Private key presence proves access capability; verify authorized_keys for lateral movement"],
        volatility: Some(crate::volatility::VolatilityClass::Persistent),
        volatility_rationale: "Private key files persist until explicitly deleted",
    };

pub(crate) static VELOCIRAPTOR_FILE_USR: ArtifactDescriptor = ArtifactDescriptor {
    id: "velociraptor_file_usr",
    name: "Linux.Sys.SUID",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/usr/**"),
    scope: DataScope::Mixed,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Searches for applications that have the `setuid` or `setgid` bits set.

When the `setuid` or `setgid` bits are set on Linux or macOS for an
application, this means that the application will run with the
privileges of the owning user or group respectively. Normally an
application is run in the current user’s context, regardless of
which user or group owns the application. There are instances where
programs need to be executed in an elevated context to function
properly, but the user running them doesn’t need the elevated
privileges. Instead of creating an entry in the `sudoers` file, which
must be done by root, any user can specify the `setuid` or `setgid` flag
to be set for their own applications. These bits are indicated with
an \"s\" instead of an \"x\" when viewing a file's attributes via `ls
-l`. The `chmod` program can set these bits with via bitmasking, `chmod
4777 [file]` or via shorthand naming, `chmod u+s [file]`.

An adversary can take advantage of this to either do a shell escape
or exploit a vulnerability in an application with the setsuid or
setgid bits to get code running in a different user's
context. Additionally, adversaries can use this mechanism on their
own malware to ensure that they're able to execute in elevated
contexts in the future.",
    mitre_techniques: &[],
    fields: &[],
    retention: None,
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[],
    sources: &["https://github.com/Velocidex/velociraptor"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &["Modified timestamps on system binaries indicate trojanized files"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "System binary directory persists until package update",
};

// ── Batch: Linux account & lockout artifacts ─────────────────────────────────

pub(crate) static LINUX_GSHADOW: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gshadow",
    name: "Shadowed Group File (/etc/gshadow)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/gshadow"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Shadowed information for group accounts, colon-separated per line: group name, \
        encrypted group password (crypt(3) format; '!' or '*' means no usable password, a \
        leading '!' before a hash means locked), administrators (comma-separated, may change \
        the password and members), and members (gain group permissions without a password). \
        Completes the account ground truth alongside /etc/passwd, /etc/shadow and /etc/group: \
        an unexpected administrator or member entry here grants group privileges that a review \
        of /etc/group alone will miss, and a set group password lets a non-member enter the \
        group via newgrp(1).",
    mitre_techniques: &["T1003.008"],
    fields: &[
        FieldSchema { name: "group_name", value_type: ValueType::Text, description: "Group name, must exist on the system", is_uid_component: true },
        FieldSchema { name: "encrypted_password", value_type: ValueType::Text, description: "crypt(3) hash, or '!'/'*' when no unix password applies", is_uid_component: false },
        FieldSchema { name: "administrators", value_type: ValueType::Text, description: "Comma-separated users who may change the group password and members", is_uid_component: false },
        FieldSchema { name: "members", value_type: ValueType::Text, description: "Comma-separated users who gain group permissions without a password", is_uid_component: false },
    ],
    retention: Some("Persistent configuration file"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_shadow", "linux_passwd", "linux_etc_group"],
    sources: &["https://man7.org/linux/man-pages/man5/gshadow.5.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Must not be readable by regular users; world-readable permissions are themselves a finding",
        "Group passwords are rarely used in practice, so a populated password field is unusual and worth explaining",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file; persists until edited",
};

pub(crate) static LINUX_PWQUALITY_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_pwquality_conf",
    name: "Password Quality Policy (/etc/security/pwquality.conf)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/security/pwquality.conf"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Default password-quality requirements for system passwords, read by the \
        libpwquality library and the pam_pwquality PAM module: minimum length (minlen), \
        required character classes (minclass, dcredit/ucredit/lcredit/ocredit), and \
        dictionary/similarity checks. Establishes what password policy was actually in force \
        on the box — a weakened or commented-out policy is a finding in its own right, and \
        the policy in force bounds how plausible a brute-force success was.",
    mitre_techniques: &["T1110"],
    fields: &[FieldSchema {
        name: "option",
        value_type: ValueType::Text,
        description: "key = value policy line (minlen, minclass, dcredit, ...)",
        is_uid_component: false,
    }],
    retention: Some("Persistent configuration file"),
    triage_priority: TriagePriority::Low,
    related_artifacts: &["linux_pam_d", "linux_shadow"],
    sources: &["https://linux.die.net/man/5/pwquality.conf"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Only effective where pam_pwquality is wired into the PAM stack (/etc/pam.d); the file's presence alone does not prove enforcement",
        "Drop-in overrides may exist under /etc/security/pwquality.conf.d/ on newer versions",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file; persists until edited",
};

pub(crate) static LINUX_FAILLOCK_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_faillock_dir",
    name: "pam_faillock Tally Directory (/var/run/faillock/)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/run/faillock/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-user tally files written by pam_faillock, the PAM module that locks accounts \
        after consecutive authentication failures (the successor to pam_tally2 on RHEL-family \
        systems). One file per user records the authentication failures counted toward lockout. \
        On a live system, read with 'faillock --user <name>'. This — not /var/log/faillog — is \
        where modern failed-login lockout state lives, so brute-force tallies on a RHEL-family \
        host are answered here.",
    mitre_techniques: &["T1110"],
    fields: &[FieldSchema {
        name: "username",
        value_type: ValueType::Text,
        description: "Tally filename equals the account name being counted",
        is_uid_component: true,
    }],
    retention: Some("Cleared on successful authentication; lost at reboot when /var/run is tmpfs"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_faillog", "linux_auth_log", "linux_btmp"],
    sources: &["https://man7.org/linux/man-pages/man8/pam_faillock.8.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Files disappear after reboot when /var/run/faillock sits on virtual memory (tmpfs); a persistent dir= can be set in /etc/security/faillock.conf",
        "Empty on Debian-family systems unless pam_faillock has been configured into the PAM stack",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Tally files live under /var/run, typically tmpfs; lost at reboot",
};

// ── Batch: journald & syslog facility routing ────────────────────────────────

pub(crate) static LINUX_JOURNALD_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_journald_conf",
    name: "systemd Journal Configuration (/etc/systemd/journald.conf)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/systemd/journald.conf"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Controls where and how long the systemd journal keeps log data. Storage= decides \
        everything an examiner will find: 'persistent' writes below /var/log/journal, \
        'volatile' keeps entries only below /run/log/journal (lost at reboot), 'auto' (the \
        common packaged default) behaves as persistent only if /var/log/journal exists, and \
        'none' drops all stored log data. SystemMaxUse=/RuntimeMaxUse= cap disk usage (default \
        10% of the filesystem, capped at 4G) and so bound retention. Reviewing this file \
        explains why a journal is missing, short, or memory-only — before that absence is \
        misread as tampering.",
    mitre_techniques: &["T1562.001"],
    fields: &[
        FieldSchema { name: "Storage", value_type: ValueType::Text, description: "volatile | persistent | auto | none", is_uid_component: false },
        FieldSchema { name: "SystemMaxUse", value_type: ValueType::Text, description: "Disk-usage cap for /var/log/journal; bounds retention", is_uid_component: false },
    ],
    retention: Some("Persistent configuration file; drop-ins in journald.conf.d/ override it"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_journal_dir", "linux_journal_runtime"],
    sources: &["https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Storage=none silently drops all stored log data while forwarding still works — a deliberate anti-logging setting worth flagging",
        "Drop-in files under /etc/systemd/journald.conf.d/ and /run/systemd/journald.conf.d/ override this file; read all of them",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file; persists until edited",
};

pub(crate) static LINUX_JOURNAL_RUNTIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_journal_runtime",
    name: "Volatile Runtime Journal (/run/log/journal/)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/run/log/journal/"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "The systemd journal's volatile storage: <machine-id>/*.journal files under /run, \
        used when /var/log/journal does not exist or Storage=volatile is set — the default \
        posture on some RHEL-family installs. Everything here is lost at reboot, so on such a \
        host the journal must be collected live (or via journalctl/raw copy) before power-down, \
        and its absence from a dead-box image means the logs were volatile, not wiped. \
        journald also starts here on every boot until systemd-journal-flush.service moves \
        entries to persistent storage.",
    mitre_techniques: &[],
    fields: &[FieldSchema {
        name: "machine_id",
        value_type: ValueType::Text,
        description: "Subdirectory name; matches /etc/machine-id",
        is_uid_component: true,
    }],
    retention: Some("Lost at reboot; size-capped by RuntimeMaxUse= (default 10%/15% of the fs, capped 4G)"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_journal_dir", "linux_journald_conf", "linux_machine_id"],
    sources: &[
        "https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html",
        "https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Which journal a host uses is decided by Storage= and the existence of /var/log/journal — check /etc/systemd/journald.conf before concluding anything from absence",
        "Corrupted or uncleanly-closed files are renamed with a .journal~ suffix and remain readable",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "/run is tmpfs; the runtime journal does not survive a reboot",
};

pub(crate) static LINUX_CRON_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_cron_log",
    name: "Cron Log (/var/log/cron, RHEL family)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/cron"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxRhel,
    decoder: Decoder::Identity,
    meaning: "Scheduled-task execution log on RHEL-family systems: the stock rsyslog \
        configuration routes the cron facility to /var/log/cron ('cron.*'). Records each \
        crontab job launch (user, command), crontab edits, and anacron runs — the primary \
        timeline for cron-based persistence firing, complementing the crontab files that \
        only show what WOULD run.",
    mitre_techniques: &["T1053.003"],
    fields: &[
        FieldSchema { name: "user", value_type: ValueType::Text, description: "Account the job ran as", is_uid_component: true },
        FieldSchema { name: "command", value_type: ValueType::Text, description: "Command line the cron daemon executed (CMD ...)", is_uid_component: false },
    ],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_crontab_system", "linux_user_crontab", "linux_cron_d"],
    sources: &["https://gitlab.com/redhat/centos-stream/rpms/rsyslog/-/raw/c9s/rsyslog.conf"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "RHEL-family rsyslog packaging default; Debian-family ships the cron.* rule commented out, so cron lines land in /var/log/syslog there",
        "Timestamps are in the system's local time zone — normalize before correlating",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

pub(crate) static LINUX_MAIL_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_mail_log",
    name: "Mail Log (/var/log/mail.log, Debian family)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/mail.log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "Mail-facility syslog on Debian-family systems: the stock rsyslog configuration \
        routes 'mail.*' to /var/log/mail.log. Records MTA activity (postfix/exim/sendmail): \
        message accept/relay/delivery, sender and recipient addresses, and connecting hosts — \
        evidence for phishing origin, mail exfiltration, and abuse of a compromised host as \
        a relay.",
    mitre_techniques: &["T1114"],
    fields: &[FieldSchema {
        name: "message",
        value_type: ValueType::Text,
        description: "MTA log line (queue id, from=, to=, relay=, status=)",
        is_uid_component: false,
    }],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_maillog_rhel", "linux_syslog"],
    sources: &["https://sources.debian.org/src/rsyslog/latest/debian/rsyslog.conf/"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Debian-family rsyslog packaging default; RHEL family writes /var/log/maillog instead",
        "Only exists where an MTA actually logs; a minimal server may have neither file",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

pub(crate) static LINUX_MAILLOG_RHEL: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_maillog_rhel",
    name: "Mail Log (/var/log/maillog, RHEL family)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/maillog"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxRhel,
    decoder: Decoder::Identity,
    meaning: "Mail-facility syslog on RHEL-family systems: the stock rsyslog configuration \
        routes 'mail.*' to /var/log/maillog (written with sync on). Same MTA evidence as \
        Debian's /var/log/mail.log — message accept/relay/delivery, sender/recipient, \
        connecting hosts — under the Red Hat naming convention.",
    mitre_techniques: &["T1114"],
    fields: &[FieldSchema {
        name: "message",
        value_type: ValueType::Text,
        description: "MTA log line (queue id, from=, to=, relay=, status=)",
        is_uid_component: false,
    }],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_mail_log", "linux_messages_log"],
    sources: &["https://gitlab.com/redhat/centos-stream/rpms/rsyslog/-/raw/c9s/rsyslog.conf"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "RHEL-family rsyslog packaging default; Debian family writes /var/log/mail.log instead",
        "Only exists where an MTA actually logs; a minimal server may have neither file",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

// ── Batch: service logs (web, firewall, proxy, Sysmon) ──────────────────────

pub(crate) static LINUX_HTTPD_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_httpd_access_log",
    name: "Apache Access Log (/var/log/httpd, RHEL family)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/httpd/access_log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxRhel,
    decoder: Decoder::Identity,
    meaning: "Apache HTTP Server request log under the Red Hat packaging convention: logs live \
        in /var/log/httpd/ (access_log, error_log; per-vhost CustomLog/ErrorLog lines in \
        /etc/httpd/conf/httpd.conf point here too). Same evidence as Debian's \
        /var/log/apache2/access.log — client IP, authenticated user, request line, status, \
        bytes, and in combined format referer and user-agent — for webshell drops, exploit \
        attempts and scanner noise on RHEL-family web servers.",
    mitre_techniques: &["T1190"],
    fields: &[
        FieldSchema { name: "remote_addr", value_type: ValueType::Text, description: "Client IP address", is_uid_component: true },
        FieldSchema { name: "request", value_type: ValueType::Text, description: "Method, URI and protocol of the request", is_uid_component: false },
        FieldSchema { name: "status", value_type: ValueType::UnsignedInt, description: "HTTP response status code", is_uid_component: false },
    ],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_apache_access_log", "linux_apache_error_log"],
    sources: &[
        "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/setting-apache-http-server_deploying-different-types-of-servers",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Red Hat packaging convention; Debian family uses /var/log/apache2/ and openSUSE mixes /etc/apache2/ with the httpd.conf filename",
        "Log location and format are set by CustomLog directives — read the config before trusting the default path",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

pub(crate) static LINUX_APACHE_OTHER_VHOSTS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apache_other_vhosts_log",
    name: "Apache Other-VHosts Access Log (Debian family)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/apache2/other_vhosts_access.log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "Debian/Ubuntu's catch-all access log for VirtualHosts that do not define their \
        own log file: the apache2 package ships conf-available/other-vhosts-access-log.conf \
        with 'CustomLog ${APACHE_LOG_DIR}/other_vhosts_access.log vhost_combined'. The \
        vhost_combined format prepends the serving vhost:port to each combined-format line — \
        so requests to secondary or attacker-added vhosts that never appear in access.log \
        are found here, with the vhost that served them.",
    mitre_techniques: &["T1190"],
    fields: &[
        FieldSchema { name: "vhost", value_type: ValueType::Text, description: "VirtualHost name:port that served the request (vhost_combined prefix)", is_uid_component: true },
        FieldSchema { name: "remote_addr", value_type: ValueType::Text, description: "Client IP address", is_uid_component: false },
        FieldSchema { name: "request", value_type: ValueType::Text, description: "Method, URI and protocol of the request", is_uid_component: false },
    ],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_apache_access_log", "linux_httpd_access_log"],
    sources: &[
        "https://sources.debian.org/src/apache2/latest/debian/config-dir/conf-available/other-vhosts-access-log.conf/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Debian-family packaging; the conf must be enabled (conf-enabled symlink, on by default) and a vhost with its own CustomLog never writes here",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

pub(crate) static LINUX_TOMCAT_CATALINA_OUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_tomcat_catalina_out",
    name: "Apache Tomcat Console Log (catalina.out)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("$CATALINA_BASE/logs/catalina.out"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Tomcat's captured stdout/stderr: console output (System.out/System.err and the \
        default ConsoleHandler) is redirected into catalina.out by the startup scripts, \
        alongside the java.util.logging AsyncFileHandler files (catalina.<date>.log, \
        localhost.<date>.log) and any AccessLogValve access logs in the same logs/ directory. \
        Application exceptions, deployment records and webshell-drop side effects from a \
        compromised Tomcat land here.",
    mitre_techniques: &["T1190", "T1505.003"],
    fields: &[FieldSchema {
        name: "line",
        value_type: ValueType::Text,
        description: "Captured stdout/stderr line (JULI log record or raw application output)",
        is_uid_component: false,
    }],
    retention: Some("Not rotated by Tomcat itself; rotation is deployment-specific"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_apache_access_log", "linux_nginx_access_log"],
    sources: &["https://tomcat.apache.org/tomcat-9.0-doc/logging.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Location is $CATALINA_BASE/logs: /opt/tomcat/logs on common manual installs, /var/log/tomcat<N>/ under distro packaging — resolve CATALINA_BASE before searching",
        "Console output only reaches catalina.out when Tomcat is started via the shipped scripts; systemd units may route it to the journal instead",
    ],
    volatility: Some(crate::volatility::VolatilityClass::ActivityDriven),
    volatility_rationale: "Grows with activity; rotation depends on deployment",
};

pub(crate) static LINUX_SQUID_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_squid_access_log",
    name: "Squid Proxy Access Log",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/squid/access.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "One line per HTTP/ICP transaction through the Squid proxy — timestamp, elapsed \
        time, client IP, cache result/status, bytes, method, URL, and user where \
        authentication is on. On a network egressing through Squid this is the closest thing \
        to a full outbound web history: C2 beacons, exfil uploads and staging downloads all \
        transit it. cache.log in the same directory holds the daemon's own status/debug \
        messages.",
    mitre_techniques: &["T1071.001"],
    fields: &[
        FieldSchema { name: "client_addr", value_type: ValueType::Text, description: "Requesting client IP", is_uid_component: true },
        FieldSchema { name: "url", value_type: ValueType::Text, description: "Requested URL", is_uid_component: false },
        FieldSchema { name: "result_code", value_type: ValueType::Text, description: "Squid cache result and HTTP status (e.g. TCP_MISS/200)", is_uid_component: false },
    ],
    retention: Some("Rotated via 'squid -k rotate', count set by logfile_rotate"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_haproxy_log", "linux_nginx_access_log"],
    sources: &[
        "https://wiki.squid-cache.org/SquidFaq/SquidLogs",
        "http://www.squid-cache.org/Doc/config/access_log/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "/var/log/squid/ is the distro-packaging location; the upstream compiled-in default is /usr/local/squid/var/logs/access.log on source builds — read the access_log directive in squid.conf",
        "access_log none disables it entirely; an absent log on a configured proxy is a finding, not an absence of traffic",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated by squid -k rotate / logrotate",
};

pub(crate) static LINUX_UFW_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ufw_log",
    name: "UFW Firewall Log (/var/log/ufw.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/ufw.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Packet verdicts from the Uncomplicated Firewall: kernel-format lines tagged \
        [UFW BLOCK]/[UFW ALLOW]/[UFW AUDIT] with the netfilter fields (IN=/OUT= interface, \
        SRC=/DST= addresses, SPT=/DPT= ports, PROTO=). ufw logs via the LOG_KERN syslog \
        facility; on rsyslog-configured systems (Ubuntu default) those lines are split into \
        /var/log/ufw.log. Inbound scans, blocked C2 callbacks and allowed sessions through \
        the host firewall are reconstructed from here.",
    mitre_techniques: &["T1562.004"],
    fields: &[
        FieldSchema { name: "action", value_type: ValueType::Text, description: "[UFW BLOCK] / [UFW ALLOW] / [UFW AUDIT] verdict tag", is_uid_component: false },
        FieldSchema { name: "src", value_type: ValueType::Text, description: "Source IP (SRC=)", is_uid_component: true },
        FieldSchema { name: "dpt", value_type: ValueType::UnsignedInt, description: "Destination port (DPT=)", is_uid_component: false },
    ],
    retention: Some("Rotated by logrotate"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_iptables_rules", "linux_kern_log", "linux_firewalld_config"],
    sources: &["https://manpages.debian.org/bookworm/ufw/ufw.8.en.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Only rsyslog-configured systems split ufw lines into this file; otherwise they stay in the kernel-facility log (kern.log/syslog/journal)",
        "Logging is off until 'ufw logging on'; default level 'low' logs blocked packets, not allowed ones — absence of ALLOW lines is a level artifact",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Text log rotated by logrotate",
};

pub(crate) static LINUX_FIREWALLD_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_firewalld_config",
    name: "firewalld System Configuration (/etc/firewalld/)",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/firewalld/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "firewalld's system configuration: XML zone, service and icmptype definitions \
        created by the administrator (or an attacker) that overload the package defaults in \
        /usr/lib/firewalld/. Diffing the two directories isolates every local change to the \
        host firewall — an added zone, a widened service, or a permanent allow rule planted \
        for C2. Runtime-only changes never touch these files, so runtime state must be \
        captured live (firewall-cmd) before shutdown.",
    mitre_techniques: &["T1562.004"],
    fields: &[FieldSchema {
        name: "zone_xml",
        value_type: ValueType::Text,
        description: "Zone/service/icmptype XML definition overriding the defaults",
        is_uid_component: false,
    }],
    retention: Some("Persistent configuration; runtime changes are separate and lost at reload/reboot"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_iptables_rules", "linux_nftables_conf", "linux_ufw_log"],
    sources: &["https://firewalld.org/documentation/man-pages/firewalld.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Default on RHEL-family distros; installable elsewhere — presence of the directory does not prove the service was running",
        "Permanent config only: runtime rules added without --permanent exist solely in the running daemon (inspect via journalctl -u firewalld / firewall-cmd live)",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration directory; persists until edited",
};

pub(crate) static LINUX_HAPROXY_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_haproxy_log",
    name: "HAProxy Log (/var/log/haproxy.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/haproxy.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Load-balancer traffic log: HAProxy emits per-connection/per-request lines \
        (client address, frontend, backend/server chosen, timers, status, bytes) via syslog \
        only — it does not write files itself. Debian's packaging ships an rsyslog rule \
        (programname startswith 'haproxy') that files those lines into /var/log/haproxy.log, \
        rotated daily with 7 kept. On a proxied service this log attributes which backend \
        actually served an attacker's request.",
    mitre_techniques: &["T1071.001"],
    fields: &[
        FieldSchema { name: "client_addr", value_type: ValueType::Text, description: "Client IP:port of the connection", is_uid_component: true },
        FieldSchema { name: "backend_server", value_type: ValueType::Text, description: "backend/server that handled the request", is_uid_component: false },
        FieldSchema { name: "status", value_type: ValueType::UnsignedInt, description: "HTTP status code returned", is_uid_component: false },
    ],
    retention: Some("Debian packaging: rotated daily, 7 rotations kept"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["linux_squid_access_log", "linux_nginx_access_log"],
    sources: &[
        "https://sources.debian.org/src/haproxy/latest/debian/rsyslog.conf/",
        "https://sources.debian.org/src/haproxy/latest/debian/logrotate.conf/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The file path is Debian rsyslog packaging, not an HAProxy default — HAProxy logs only via syslog, so other distros/configs put these lines elsewhere",
        "The log target and verbosity are set by 'log' directives in haproxy.cfg; a chroot'ed HAProxy needs the packaged /var/lib/haproxy/dev/log socket to log at all",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated daily by logrotate (Debian packaging)",
};

pub(crate) static LINUX_SYSMON_EVENTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sysmon_events",
    name: "Sysmon for Linux Events (in syslog)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/syslog"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Microsoft's Sysmon ported to Linux (built on SysinternalsEBPF) writes its events \
        — process creation/termination, network connections, file events, using the same \
        configuration schema as the Windows version — as XML records into the local syslog \
        stream. On Debian-family systems they interleave with normal traffic in \
        /var/log/syslog; the bundled /opt/sysmon/sysmonLogView extracts and renders them. \
        Any syslog acquisition from a Sysmon-instrumented host therefore already contains \
        this high-fidelity telemetry.",
    mitre_techniques: &["T1562.001"],
    fields: &[
        FieldSchema { name: "event_xml", value_type: ValueType::Text, description: "Sysmon event record serialized as XML inside the syslog line", is_uid_component: false },
        FieldSchema { name: "command_line", value_type: ValueType::Text, description: "CommandLine of process-creation events (Event ID 1)", is_uid_component: false },
    ],
    retention: Some("Inherits the host syslog rotation policy"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_syslog", "linux_messages_log", "linux_auditd_log"],
    sources: &["https://github.com/microsoft/SysmonForLinux"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Events land wherever the host's syslog daemon routes them: /var/log/syslog on Debian family, /var/log/messages on RHEL family",
        "Coverage is configuration-dependent — with no config only a subset of event types is collected, and syslog daemons may truncate large (>1-8KB) event records",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Lives inside the rotated syslog stream",
};

// ── Batch: VMware ESXi / vCenter / snapshot memory / WSL ─────────────────────

pub(crate) static ESXI_HOSTD_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_hostd_log",
    name: "ESXi Host Management Log (hostd.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/hostd.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Log of the ESXi host management service (hostd): virtual machine and host tasks \
        and events, communication with the vSphere Client and the vCenter agent (vpxa), and \
        SDK connections. On a ransomware-hit hypervisor this is where VM power-offs, \
        unregistered VMs, datastore browsing and mass snapshot deletions performed through \
        the management plane are recorded.",
    mitre_techniques: &["T1486"],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped hostd log line (task/event/SDK connection)",
        is_uid_component: false,
    }],
    retention: Some("Rotated on the host; older rotations compressed under /var/log/"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["esxi_vpxa_log", "esxi_shell_log", "esxi_auth_log"],
    sources: &["https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "ESXi is VMware's own kernel (VMkernel), not a Linux distribution — the /var/log paths are ESXi-specific",
        "On hosts without persistent scratch storage, /var/log may live on a ramdisk and be lost at reboot",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated log; may sit on a ramdisk on scratchless hosts",
};

pub(crate) static ESXI_VPXA_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_vpxa_log",
    name: "ESXi vCenter Agent Log (vpxa.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/vpxa.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Log of vpxa, the vCenter Server agent on the ESXi host: communication between \
        vCenter and the host's hostd service. Distinguishes actions driven through vCenter \
        from actions taken directly on the host — an operation in hostd.log with no vpxa \
        counterpart was done against the host directly, which matters when vCenter \
        credentials are not the ones compromised.",
    mitre_techniques: &[],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped vpxa log line (vCenter-to-host traffic)",
        is_uid_component: false,
    }],
    retention: Some("Rotated on the host"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["esxi_hostd_log", "vcenter_vpxd_log"],
    sources: &[
        "https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &["Only present when the host is (or was) managed by a vCenter Server"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated log; may sit on a ramdisk on scratchless hosts",
};

pub(crate) static ESXI_SHELL_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_shell_log",
    name: "ESXi Shell Command Log (shell.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/shell.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "ESXi Shell usage log: shell enable/disable events and every command entered in \
        the ESXi Shell. On a compromised hypervisor this answers 'what did they type' \
        directly — ransomware operators' encryption binaries, datastore enumeration and \
        log-clearing attempts all appear as typed commands with timestamps.",
    mitre_techniques: &["T1059.004"],
    fields: &[
        FieldSchema { name: "command", value_type: ValueType::Text, description: "Command line entered in the ESXi Shell", is_uid_component: false },
        FieldSchema { name: "shell_state", value_type: ValueType::Text, description: "Shell enable/disable event", is_uid_component: false },
    ],
    retention: Some("Rotated on the host"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["esxi_auth_log", "esxi_hostd_log"],
    sources: &["https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Only captures the ESXi Shell (local/SSH); API-driven actions never appear here — read hostd.log for those",
        "An attacker with shell access can also clear this log; correlate with remote syslog if configured",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated log; may sit on a ramdisk on scratchless hosts",
};

pub(crate) static ESXI_AUTH_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "esxi_auth_log",
    name: "ESXi Shell Authentication Log (auth.log)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/auth.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "ESXi Shell authentication successes and failures — who reached the hypervisor's \
        shell, from where, and when. Paired with shell.log it gives the who-then-what of a \
        hypervisor intrusion: authenticate here, commands there. Brute-force attempts \
        against SSH on the host also land here.",
    mitre_techniques: &["T1078", "T1110"],
    fields: &[
        FieldSchema { name: "user", value_type: ValueType::Text, description: "Account authenticating to the shell/SSH", is_uid_component: true },
        FieldSchema { name: "outcome", value_type: ValueType::Text, description: "Authentication success or failure", is_uid_component: false },
    ],
    retention: Some("Rotated on the host"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["esxi_shell_log", "esxi_hostd_log"],
    sources: &["https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Same path as the Debian-family Linux auth.log but a different system — do not apply Linux PAM line grammar expectations to it",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated log; may sit on a ramdisk on scratchless hosts",
};

pub(crate) static VCENTER_VPXD_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "vcenter_vpxd_log",
    name: "vCenter Server Main Log (vpxd.log, VCSA)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/vmware/vpxd/vpxd.log"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "The main vCenter Server log on the vCenter Server Appliance: vSphere Client and \
        WebServices connections, internal tasks and events, and communication with the vpxa \
        agent on every managed ESXi host. vCenter logs group under /var/log/vmware/<service>/ \
        on the appliance. Management-plane attacks — mass VM operations, permission changes, \
        host additions — are reconstructed from here across the whole cluster at once.",
    mitre_techniques: &["T1078"],
    fields: &[FieldSchema {
        name: "log_entry",
        value_type: ValueType::Text,
        description: "Timestamped vpxd log line (task/event/connection)",
        is_uid_component: false,
    }],
    retention: Some("Rotated and compressed under /var/log/vmware/vpxd/"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["esxi_vpxa_log", "esxi_hostd_log"],
    sources: &["https://knowledge.broadcom.com/external/article?legacyId=1021804"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "VCSA (Photon OS) path; the deprecated Windows vCenter wrote C:\\ProgramData\\VMware\\vCenterServer\\Logs\\ instead",
        "The path is lowercase /var/log/vmware/ — case matters on the appliance filesystem",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Rotated and compressed by the appliance",
};

pub(crate) static VMWARE_VMEM_SNAPSHOT: ArtifactDescriptor = ArtifactDescriptor {
    id: "vmware_vmem_snapshot",
    name: "VMware Snapshot Memory Pair (.vmem + .vmss/.vmsn)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Guest RAM captured by a VMware snapshot or suspend: the .vmem file holds the \
        memory pages, but it is not self-describing — Volatility 3's VMware layer looks for \
        a same-named .vmss or .vmsn metadata file beside it and warns that one 'may be \
        required to correctly process a VMEM file'. Collect BOTH files from the datastore, \
        from the same snapshot. Snapshotting a running VM with its memory checkbox ticked \
        is a hypervisor-level memory acquisition that needs no agent in the guest.",
    mitre_techniques: &[],
    fields: &[
        FieldSchema { name: "vmem", value_type: ValueType::Bytes, description: "Guest physical memory pages", is_uid_component: false },
        FieldSchema { name: "vmss_vmsn", value_type: ValueType::Bytes, description: "Suspend/snapshot metadata: run groups and memory region offsets", is_uid_component: false },
    ],
    retention: Some("Persists on the datastore until the snapshot is deleted/consolidated"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["esxi_hostd_log"],
    sources: &[
        "https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/layers/vmware.py",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "A snapshot taken WITHOUT the memory option produces no .vmem — verify before relying on it",
        "The metadata file must share the .vmem's base name and directory for tooling to auto-pair them",
        "The same pair appears on Workstation/Fusion host filesystems, not only ESXi datastores",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Datastore files; persist until snapshot deletion/consolidation",
};

pub(crate) static WSL_EXT4_VHDX: ArtifactDescriptor = ArtifactDescriptor {
    id: "wsl_ext4_vhdx",
    name: "WSL2 Distribution Disk (ext4.vhdx)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%LOCALAPPDATA%\\Packages\\<PackageFamilyName>\\LocalState\\ext4.vhdx"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "The entire filesystem of a WSL2 Linux distribution inside one Windows file: a \
        VHDX containing an ext4 volume, one per installed distro, under that distro package's \
        LocalState folder. The authoritative per-distro path is the BasePath value under \
        HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss. Pull this file and every \
        Linux dead-box technique applies to a 'Windows' endpoint — shell history, cron, SSH \
        keys, logs all live inside it at their normal distro-specific locations.",
    mitre_techniques: &["T1564.006"],
    fields: &[FieldSchema {
        name: "vhdx",
        value_type: ValueType::Bytes,
        description: "VHDX-wrapped ext4 filesystem of the distro",
        is_uid_component: false,
    }],
    retention: Some("Persists until the distro is unregistered"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["linux_wsl_conf", "windows_wslconfig", "linux_bash_history"],
    sources: &["https://learn.microsoft.com/en-us/windows/wsl/disk-space"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "WSL2 only; a WSL1 distro stores its files directly on NTFS instead of inside a vhdx",
        "The package folder name varies per distro/vendor — resolve it from the Lxss registry key rather than guessing",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Disk image file; persists until the distro is unregistered",
};

pub(crate) static LINUX_WSL_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_wsl_conf",
    name: "WSL Per-Distribution Config (/etc/wsl.conf)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/wsl.conf"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-distribution WSL settings, stored inside the Linux distro: boot command \
        (boot.command runs at distro start — a persistence spot), automount of Windows \
        drives, networking, Windows-interop enablement, systemd usage, and the default \
        user. In any WSL-focused examination this file says how tightly the Linux \
        environment was coupled to the host and whether anything launches at distro boot.",
    mitre_techniques: &["T1564.006"],
    fields: &[FieldSchema {
        name: "setting",
        value_type: ValueType::Text,
        description: "INI-style key under [automount]/[network]/[interop]/[user]/[boot]",
        is_uid_component: false,
    }],
    retention: Some("Persistent file inside the distro filesystem"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["wsl_ext4_vhdx", "windows_wslconfig"],
    sources: &["https://learn.microsoft.com/en-us/windows/wsl/wsl-config"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Only meaningful inside a WSL distribution; a bare-metal Linux host has no use for it",
        "Not present by default — absence is normal, presence means someone configured the distro",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file inside the distro vhdx",
};

pub(crate) static WINDOWS_WSLCONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_wslconfig",
    name: "WSL Global Config (%UserProfile%\\.wslconfig)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%UserProfile%\\.wslconfig"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Global WSL2 settings on the Windows side of the boundary: VM resources (memory, \
        processors), a custom kernel to boot (kernel= pointing at an attacker-supplied \
        kernel is a hiding/persistence avenue), swap file location, and feature toggles for \
        every WSL2 distro of that user. Lives in the Windows user profile root and applies \
        across all distros, where /etc/wsl.conf is per-distro.",
    mitre_techniques: &["T1564.006"],
    fields: &[FieldSchema {
        name: "setting",
        value_type: ValueType::Text,
        description: "INI-style key under [wsl2] (memory, processors, kernel, swap, ...)",
        is_uid_component: false,
    }],
    retention: Some("Persistent file in the user profile"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["wsl_ext4_vhdx", "linux_wsl_conf"],
    sources: &["https://learn.microsoft.com/en-us/windows/wsl/wsl-config"],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "Not present by default; settings apply to WSL2 distros only",
        "A kernel= line pointing outside the default Microsoft kernel is worth pulling and examining",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Configuration file; persists until edited",
};
