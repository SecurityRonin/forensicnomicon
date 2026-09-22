// ELF capability signals (from memf-linux::elf_analysis)
pub const ELF_HOOKS_PROCESS_HIDING: &str = "elf.hooks.process_hiding";
pub const ELF_HOOKS_FILE_HIDING: &str = "elf.hooks.file_hiding";
pub const ELF_HOOKS_PAM_CREDENTIAL: &str = "elf.hooks.pam_credential_theft";
pub const ELF_HOOKS_NETWORK_HIDING: &str = "elf.hooks.network_hiding";
pub const ELF_HOOKS_UID_SPOOFING: &str = "elf.hooks.uid_spoofing";
pub const ELF_HOOKS_IO_INTERCEPTION: &str = "elf.hooks.io_interception";
pub const ELF_GLOBALLY_LOADED: &str = "elf.globally_loaded";
pub const ELF_NOT_IN_PKG_DB: &str = "elf.not_in_package_db";
pub const ELF_LIBC_SHADOW_EXPORTS: &str = "elf.libc_shadow_exports";
pub const ELF_STRING_FATHER_FORMAT: &str = "elf.string.father_format";
pub const ELF_STRING_STAGING_PATH: &str = "elf.string.staging_path";

// Artifact signals (from issen-parser-uac)
pub const ARTIFACT_PAM_STAGING_STRUCTURAL: &str = "artifact.pam_staging.uid_field_value_format";
pub const ARTIFACT_PAM_STAGING_FATHER: &str = "artifact.pam_staging.father_exact_format";
pub const ARTIFACT_LD_PRELOAD_FOREIGN: &str = "artifact.ld_preload.foreign_library";
pub const ARTIFACT_LD_PRELOAD_IN_HASH_LIST: &str = "artifact.ld_preload.path_in_hash_list";

// Process signals (from issen-parser-uac::parsers::mod, mem_sockstat)
pub const PROCESS_HIDDEN_FROM_PS: &str = "process.hidden_from_ps";
pub const PROCESS_THREAD_MINER_XMRIG: &str = "process.thread.miner.xmrig";
pub const PROCESS_THREAD_MINER_GENERIC: &str = "process.thread.miner.generic";
pub const PROCESS_ANOMALOUS_THREAD_COUNT: &str = "process.anomalous_thread_count";
pub const PROCESS_MASQUERADE: &str = "process.masquerade_as_system_proc";
pub const PROCESS_SHELL_UPGRADE_CHAIN: &str = "process.shell_upgrade_chain";

// Network signals
pub const NETWORK_STRATUM_CONNECTION: &str = "network.stratum_connection";
pub const NETWORK_STRATUM_LISTEN: &str = "network.stratum_listen";
pub const NETWORK_SSH_STRATUM_TUNNEL: &str = "network.ssh_stratum_tunnel";
pub const NETWORK_REVERSE_SHELL: &str = "network.reverse_shell";
pub const NETWORK_MAGIC_PACKET_KNOCK: &str = "network.magic_packet_knock";

// System / OS signals
pub const SYSTEM_KERNEL_TAINT_OOT: &str = "system.kernel_taint.out_of_tree_module";
pub const SYSTEM_KERNEL_TAINT_FORCED: &str = "system.kernel_taint.forced_load";
pub const SYSTEM_CPU_ANOMALY_HIGH: &str = "system.cpu.anomaly_high";
pub const SYSTEM_LD_PRELOAD_SET: &str = "system.ld_preload.set";
pub const SYSTEM_PROC_MODULES_SUSPECT: &str = "system.proc_modules.suspect_entry";

// Temporal / correlation signals (from issen-correlation rules)
pub const TEMPORAL_LDPRELOAD_SSHD_RESTART: &str = "temporal.ld_preload_then_sshd_restart";
pub const TEMPORAL_ACTIVATION_SEQUENCE: &str = "temporal.activation_sequence";

pub struct SignalMeta {
    pub id: &'static str,
    pub description: &'static str,
    pub mitre_technique: Option<&'static str>,
}

pub const SIGNAL_META: &[SignalMeta] = &[
    SignalMeta {
        id: ELF_HOOKS_PROCESS_HIDING,
        description: "ELF exports readdir64/getdents64 — hides PIDs from /proc",
        mitre_technique: Some("T1014"),
    },
    SignalMeta {
        id: ELF_HOOKS_FILE_HIDING,
        description: "ELF exports stat/open/access — hides paths from filesystem calls",
        mitre_technique: Some("T1564.001"),
    },
    SignalMeta {
        id: ELF_HOOKS_PAM_CREDENTIAL,
        description: "ELF exports pam_get_item/pam_authenticate — intercepts credentials",
        mitre_technique: Some("T1556.003"),
    },
    SignalMeta {
        id: ELF_HOOKS_NETWORK_HIDING,
        description: "ELF exports recvmsg/recvfrom — hides network connections",
        mitre_technique: Some("T1014"),
    },
    SignalMeta {
        id: ELF_HOOKS_UID_SPOOFING,
        description: "ELF exports getuid/geteuid — spoofs UID in userspace",
        mitre_technique: Some("T1548"),
    },
    SignalMeta {
        id: ELF_HOOKS_IO_INTERCEPTION,
        description: "ELF exports write — intercepts I/O for keystroke logging",
        mitre_technique: Some("T1056.001"),
    },
    SignalMeta {
        id: ELF_GLOBALLY_LOADED,
        description: "Library loaded in ≥90% of running processes — LD_PRELOAD infection",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: ELF_NOT_IN_PKG_DB,
        description: "ELF path not in dpkg/rpm package database — unknown provenance",
        mitre_technique: None,
    },
    SignalMeta {
        id: ELF_LIBC_SHADOW_EXPORTS,
        description: "ELF exports symbols with same names as libc — function interposition",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: ELF_STRING_FATHER_FORMAT,
        description: "ELF contains 'UID:N:' format string matching Father staging schema",
        mitre_technique: None,
    },
    SignalMeta {
        id: ELF_STRING_STAGING_PATH,
        description: "ELF contains /tmp staging path string",
        mitre_technique: None,
    },
    SignalMeta {
        id: ARTIFACT_PAM_STAGING_STRUCTURAL,
        description: "PAM credential staging file has uid:N:plain format",
        mitre_technique: Some("T1556.003"),
    },
    SignalMeta {
        id: ARTIFACT_PAM_STAGING_FATHER,
        description: "PAM staging file exactly matches Father rootkit format",
        mitre_technique: Some("T1556.003"),
    },
    SignalMeta {
        id: ARTIFACT_LD_PRELOAD_FOREIGN,
        description: "ld.so.preload references a library not in package database",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: ARTIFACT_LD_PRELOAD_IN_HASH_LIST,
        description: "ld.so.preload path matches known-malicious hash list",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: PROCESS_HIDDEN_FROM_PS,
        description: "Process visible in /proc but absent from ps output",
        mitre_technique: Some("T1014"),
    },
    SignalMeta {
        id: PROCESS_THREAD_MINER_XMRIG,
        description: "Thread name matches XMRig libuv worker pattern",
        mitre_technique: Some("T1496"),
    },
    SignalMeta {
        id: PROCESS_THREAD_MINER_GENERIC,
        description: "Thread name matches generic crypto miner pattern",
        mitre_technique: Some("T1496"),
    },
    SignalMeta {
        id: PROCESS_ANOMALOUS_THREAD_COUNT,
        description: "Process has anomalously high thread count for its binary type",
        mitre_technique: None,
    },
    SignalMeta {
        id: PROCESS_MASQUERADE,
        description: "Process name matches a system process but binary path differs",
        mitre_technique: Some("T1036.005"),
    },
    SignalMeta {
        id: PROCESS_SHELL_UPGRADE_CHAIN,
        description: "Process ancestry matches privilege escalation shell upgrade chain",
        mitre_technique: Some("T1059"),
    },
    SignalMeta {
        id: NETWORK_STRATUM_CONNECTION,
        description: "Active connection to Stratum mining pool port",
        mitre_technique: Some("T1496"),
    },
    SignalMeta {
        id: NETWORK_STRATUM_LISTEN,
        description: "Process listening on Stratum protocol port",
        mitre_technique: Some("T1496"),
    },
    SignalMeta {
        id: NETWORK_SSH_STRATUM_TUNNEL,
        description: "SSH port-forward tunnelling Stratum traffic",
        mitre_technique: Some("T1572"),
    },
    SignalMeta {
        id: NETWORK_REVERSE_SHELL,
        description: "Active outbound connection with TTY — reverse shell",
        mitre_technique: Some("T1059"),
    },
    SignalMeta {
        id: NETWORK_MAGIC_PACKET_KNOCK,
        description: "Inbound packet matching magic-packet backdoor trigger pattern",
        mitre_technique: Some("T1205.001"),
    },
    SignalMeta {
        id: SYSTEM_KERNEL_TAINT_OOT,
        description: "Kernel taint flag O set — out-of-tree module loaded",
        mitre_technique: Some("T1547.006"),
    },
    SignalMeta {
        id: SYSTEM_KERNEL_TAINT_FORCED,
        description: "Kernel taint flag F set — module loaded with force flag",
        mitre_technique: Some("T1547.006"),
    },
    SignalMeta {
        id: SYSTEM_CPU_ANOMALY_HIGH,
        description: "System CPU utilisation anomalously high relative to declared workload",
        mitre_technique: Some("T1496"),
    },
    SignalMeta {
        id: SYSTEM_LD_PRELOAD_SET,
        description: "/etc/ld.so.preload or LD_PRELOAD env var is set",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: SYSTEM_PROC_MODULES_SUSPECT,
        description: "/proc/modules contains entry inconsistent with lsmod output",
        mitre_technique: Some("T1014"),
    },
    SignalMeta {
        id: TEMPORAL_LDPRELOAD_SSHD_RESTART,
        description: "ld.so.preload written then sshd restarted within 120 s",
        mitre_technique: Some("T1574.006"),
    },
    SignalMeta {
        id: TEMPORAL_ACTIVATION_SEQUENCE,
        description: "Signal sequence matches known rootkit activation pattern",
        mitre_technique: None,
    },
];
