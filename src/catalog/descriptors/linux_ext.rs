//! Extended Linux artifact descriptors.
//!
//! Sources: Velociraptor Linux artifacts, ForensicArtifacts/artifacts (linux.yaml),
//! SANS FOR508, auditd documentation, Docker/container forensics resources.

#![allow(clippy::too_many_lines)]

use super::super::types::{
    ArtifactDescriptor, ArtifactType, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

pub(crate) static LINUX_AUDITD_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_auditd_log",
    name: "Auditd Log",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Kernel-level syscall auditing; attacker must disable auditd to evade"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_AUDIT_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_audit_rules",
    name: "Auditd Rules Configuration",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_SYSLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_syslog",
    name: "Syslog",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_MESSAGES_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_messages_log",
    name: "Messages Log (RHEL/CentOS)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_SECURE_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_secure_log",
    name: "Secure Log (RHEL/CentOS authentication)",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Authentication events; quality depends on PAM configuration"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_APACHE_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apache_access_log",
    name: "Apache HTTP Server Access Log",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Web exploitation primary source; attacker may delete or tamper"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_APACHE_ERROR_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apache_error_log",
    name: "Apache HTTP Server Error Log",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_NGINX_ACCESS_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_nginx_access_log",
    name: "Nginx Access Log",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Web exploitation primary source; attacker may delete or tamper"],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "Log file; rotated by logrotate",
};

pub(crate) static LINUX_FAIL2BAN_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_fail2ban_log",
    name: "Fail2Ban Log",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_DPKG_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dpkg_log",
    name: "DPKG Package Manager Log",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_RPM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rpm_db",
    name: "RPM Package Database",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_SELINUX_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_selinux_config",
    name: "SELinux Configuration",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Disabled SELinux is itself a strong indicator of attacker activity"],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Config file; persistent until modified",
};

pub(crate) static LINUX_APPARMOR_PROFILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_apparmor_profiles",
    name: "AppArmor Profiles",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_IPTABLES_RULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_iptables_rules",
    name: "Persisted iptables Rules (IPv4)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_NFTABLES_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_nftables_conf",
    name: "nftables Firewall Configuration",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_HOSTS_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_hosts_file",
    name: "/etc/hosts (static DNS overrides)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_RESOLV_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_resolv_conf",
    name: "/etc/resolv.conf (DNS resolver config)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_PROC_MODULES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_modules",
    name: "/proc/modules (loaded kernel modules)",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Live kernel modules; rootkit detection; lost on reboot"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Virtual FS; lost on reboot",
};

pub(crate) static LINUX_MODPROBE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_modprobe_d",
    name: "modprobe.d Configuration (module loading hooks)",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_DOCKER_CONTAINER_LOGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_container_logs",
    name: "Docker Container Logs and State",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_DOCKER_DAEMON_JSON: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_daemon_json",
    name: "Docker Daemon Configuration",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_COREDUMP_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_coredump_dir",
    name: "systemd Coredump Storage",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_LOGROTATE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_logrotate_d",
    name: "Logrotate Configuration Fragments",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_SNAP_PACKAGES: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_snap_packages",
    name: "Installed Snap Packages",
    artifact_type: ArtifactType::Directory,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Batch I: Linux kernel / live-system artifacts ──────────────────────────

pub(crate) static LINUX_DMESG_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dmesg_log",
    name: "Kernel Ring Buffer Log",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/dmesg"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Kernel ring buffer dump from boot. Records driver load errors, hardware detection, and module initialization. In the Father rootkit CTF case, boot messages showed 'libymv.so.3 is too short' at 23:16 — 8 minutes before the file's MFT born time — proving the rootkit existed before filesystem timestamps claimed.",
    mitre_techniques: &["T1014", "T1547.006"],
    fields: &[],
    retention: Some("Rotated on next boot; may have .0/.1 rotations"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &["linux_kern_log", "linux_proc_modules", "linux_chkrootkit_output"],
    sources: &[
        "https://man7.org/linux/man-pages/man1/dmesg.1.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_caveats: &["Kernel ring buffer wraps; grab early in live response"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Ring buffer — overwritten as kernel emits new messages",
};

pub(crate) static LINUX_KERN_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kern_log",
    name: "Kernel Syslog (Debian/Ubuntu)",
    artifact_type: ArtifactType::File,
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
    related_artifacts: &["linux_dmesg_log", "linux_proc_modules", "linux_syslog"],
    sources: &[
        // syslog(3) — kernel logging facility LOG_KERN feeds kern.log
        "https://man7.org/linux/man-pages/man3/syslog.3.html",
        // Elastic sequel: syslog/kern messages used to detect LKM rootkit persistence events
        "https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_PROC_KALLSYMS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_kallsyms",
    name: "Kernel Symbol Table",
    artifact_type: ArtifactType::File,
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
    related_artifacts: &["linux_proc_modules", "linux_dmesg_log"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/proc.5.html",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive),
    evidence_caveats: &["Requires root; compare against expected module symbols to find injected code"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Reflects live kernel symbol table; changes if modules loaded/unloaded",
};

pub(crate) static LINUX_PROC_NET_TCP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_tcp",
    name: "Kernel IPv4 TCP Socket Table",
    artifact_type: ArtifactType::File,
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
    evidence_caveats: &["Live socket table; grab immediately — C2 connections close on detection"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Kernel socket table; entries vanish on connection close",
};

pub(crate) static LINUX_PROC_NET_TCP6: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_tcp6",
    name: "Kernel IPv6 TCP Socket Table",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_PROC_NET_UDP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_udp",
    name: "Kernel IPv4 UDP Socket Table",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_PROC_NET_UNIX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_proc_net_unix",
    name: "Kernel Unix Domain Socket Table",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_LSOF_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_lsof_output",
    name: "lsof Open Files Output",
    artifact_type: ArtifactType::LiveResponse,
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
    evidence_caveats: &["Live-response only; deleted files visible only while process holds fd open"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Process state; lost on process exit or system reboot",
};

pub(crate) static LINUX_SS_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ss_output",
    name: "ss Socket Statistics Output",
    artifact_type: ArtifactType::LiveResponse,
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
    evidence_caveats: &["Live-response only; C2 connections disappear on session teardown"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Socket table exists only while connections are active",
};

pub(crate) static LINUX_CHKROOTKIT_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_chkrootkit_output",
    name: "chkrootkit Scan Results",
    artifact_type: ArtifactType::LiveResponse,
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
    related_artifacts: &["linux_lsof_output", "linux_rkhunter_log", "linux_dmesg_log"],
    sources: &[
        "https://www.chkrootkit.org/",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_caveats: &["Rootkit may subvert chkrootkit itself; corroborate with memory forensics"],
    volatility: Some(crate::volatility::VolatilityClass::Volatile),
    volatility_rationale: "Assessment output; not persisted unless explicitly saved",
};

pub(crate) static LINUX_RKHUNTER_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rkhunter_log",
    name: "Rootkit Hunter Log",
    artifact_type: ArtifactType::File,
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
    related_artifacts: &["linux_chkrootkit_output", "linux_dmesg_log"],
    sources: &[
        "https://rkhunter.sourceforge.net/",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_SYSCTL_CONF: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sysctl_conf",
    name: "Kernel Parameter Configuration",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Group D: Linux Kernel / Proc (new artifacts only — LINUX_KERN_LOG already defined above) ──

pub(crate) static LINUX_DMESG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_dmesg",
    name: "Kernel Ring Buffer Log (dmesg)",
    artifact_type: ArtifactType::File,
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
    related_artifacts: &["linux_kern_log", "linux_proc_modules", "linux_dmesg_log"],
    sources: &[
        "https://man7.org/linux/man-pages/man1/dmesg.1.html",
        "https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

pub(crate) static LINUX_BOOT_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_boot_log",
    name: "Boot Log (/var/log/boot.log)",
    artifact_type: ArtifactType::File,
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
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
};

// ── Group E: Linux Auth/Binary Logs ──────────────────────────────────────────

pub(crate) static LINUX_FAILLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_faillog",
    name: "Failed Login Log (/var/log/faillog)",
    artifact_type: ArtifactType::File,
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
    related_artifacts: &["linux_auth_log", "linux_utmp", "linux_wtmp"],
    sources: &[
        "https://man7.org/linux/man-pages/man5/faillog.5.html",
        "https://man7.org/linux/man-pages/man8/faillog.8.html",
    ],
    evidence_strength: None,
    evidence_caveats: &[],
    volatility: None,
    volatility_rationale: "",
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
    artifact_type: ArtifactType::Directory,
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
    evidence_caveats: &[
        "Requires physical access to the LAN Turtle device (SSH to 172.16.84.1 or flash imaging)",
        "Loot files can be deleted by the attacker before seizure",
        "Credential type depends on victim OS — NTLMv2 for Windows 7+, may vary for others",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Stored on 16 MB flash; persists until manually deleted or device is reflashed",
};
