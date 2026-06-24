//! Indicator index — term-queryable threat-knowledge tables (names + patterns).
//!
//! A single curated mapping of `forensicnomicon` indicator tables to a display
//! label, match kind, and MITRE techniques. Shared by both front-ends: the CLI
//! (`run_query` / `dump`) matches terms against it, and the TUI browses it as a
//! grouped "Threat Indicators" dataset. Keeping it in one place avoids the two
//! surfaces drifting out of sync.

use forensicnomicon::antiforensics::{
    KNOWN_ROOTKIT_NAMES, LOG_WIPE_COMMANDS, SECURE_DELETE_TOOLS, SHADOW_COPY_DELETION_PATTERNS,
    TIMESTOMP_INDICATORS,
};
use forensicnomicon::commands::{
    CREDENTIAL_DUMP_PATTERNS, DEFENSE_EVASION_PATTERNS, DOWNLOAD_TOOL_PATTERNS,
    LATERAL_MOVEMENT_PATTERNS, POWERSHELL_ABUSE_PATTERNS, RECON_PATTERNS, REVERSE_SHELL_PATTERNS,
    WMI_ABUSE_PATTERNS,
};
use forensicnomicon::heuristics::evtx::{
    AMSI_BYPASS_PATTERNS, ARCHIVER_PROCESS_NAMES, BROWSER_PROCESS_NAMES, COMSVCS_MINIDUMP_PATTERNS,
    DEFENDER_TAMPER_PATTERNS, PSEXEC_SERVICE_PATTERNS, VSSADMIN_SHADOW_DELETE_PATTERNS,
    WEBDAV_COMMANDLINE_INDICATORS,
};
use forensicnomicon::heuristics::pe::{CREDENTIAL_PATTERNS, NETWORK_C2_PATTERNS};
use forensicnomicon::heuristics::ransomware::{
    RANSOMWARE_KILL_PROCESSES, RANSOMWARE_STOP_SERVICES, RANSOM_NOTE_FILENAMES,
};
use forensicnomicon::processes::{
    CREDENTIAL_ACCESS_TOOLS, KNOWN_MALWARE_PROCESS_NAMES, LSASS_ACCESS_TOOLS,
    WINDOWS_MASQUERADE_TARGETS,
};
use forensicnomicon::remote_access::KNOWN_RAT_NAMES;
use forensicnomicon::rootkit::KNOWN_LD_PRELOAD_ROOTKITS;
use forensicnomicon::shell_history::{DOWNLOAD_PIPE_TO_SHELL_PATTERNS, HISTORY_CLEARING_PATTERNS};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndicatorKind {
    /// Tool / process / file name — match by basename equality or containment.
    Name,
    /// Command-line / CLI substring — match either direction (fragment of a command).
    Pattern,
}

pub(crate) struct IndicatorSource {
    pub(crate) label: &'static str,
    pub(crate) kind: IndicatorKind,
    pub(crate) mitre: &'static [&'static str],
    pub(crate) table: &'static [&'static str],
}

use IndicatorKind::{Name, Pattern};
pub(crate) const INDICATOR_SOURCES: &[IndicatorSource] = &[
    // ── names ────────────────────────────────────────────────────────────────
    IndicatorSource {
        label: "remote-access trojan (RAT)",
        kind: Name,
        mitre: &["T1219"],
        table: KNOWN_RAT_NAMES,
    },
    IndicatorSource {
        label: "known malware process",
        kind: Name,
        mitre: &[],
        table: KNOWN_MALWARE_PROCESS_NAMES,
    },
    IndicatorSource {
        label: "credential-access tool",
        kind: Name,
        mitre: &["T1003"],
        table: CREDENTIAL_ACCESS_TOOLS,
    },
    IndicatorSource {
        label: "LSASS-access tool",
        kind: Name,
        mitre: &["T1003.001"],
        table: LSASS_ACCESS_TOOLS,
    },
    IndicatorSource {
        label: "common masquerade target",
        kind: Name,
        mitre: &["T1036.005"],
        table: WINDOWS_MASQUERADE_TARGETS,
    },
    IndicatorSource {
        label: "known rootkit",
        kind: Name,
        mitre: &["T1014"],
        table: KNOWN_ROOTKIT_NAMES,
    },
    IndicatorSource {
        label: "LD_PRELOAD rootkit",
        kind: Name,
        mitre: &["T1574.006"],
        table: KNOWN_LD_PRELOAD_ROOTKITS,
    },
    IndicatorSource {
        label: "secure-delete / anti-forensics tool",
        kind: Name,
        mitre: &["T1070.004"],
        table: SECURE_DELETE_TOOLS,
    },
    IndicatorSource {
        label: "ransom-note filename",
        kind: Name,
        mitre: &["T1486"],
        table: RANSOM_NOTE_FILENAMES,
    },
    IndicatorSource {
        label: "process terminated by ransomware",
        kind: Name,
        mitre: &["T1489"],
        table: RANSOMWARE_KILL_PROCESSES,
    },
    IndicatorSource {
        label: "service stopped by ransomware",
        kind: Name,
        mitre: &["T1489"],
        table: RANSOMWARE_STOP_SERVICES,
    },
    IndicatorSource {
        label: "archiver (staging / exfil)",
        kind: Name,
        mitre: &["T1560"],
        table: ARCHIVER_PROCESS_NAMES,
    },
    IndicatorSource {
        label: "browser process",
        kind: Name,
        mitre: &[],
        table: BROWSER_PROCESS_NAMES,
    },
    // ── command-line patterns ─────────────────────────────────────────────────
    IndicatorSource {
        label: "lateral-movement command",
        kind: Pattern,
        mitre: &["T1021"],
        table: LATERAL_MOVEMENT_PATTERNS,
    },
    IndicatorSource {
        label: "discovery / recon command",
        kind: Pattern,
        mitre: &["T1087"],
        table: RECON_PATTERNS,
    },
    IndicatorSource {
        label: "credential-dumping command",
        kind: Pattern,
        mitre: &["T1003"],
        table: CREDENTIAL_DUMP_PATTERNS,
    },
    IndicatorSource {
        label: "defense-evasion command",
        kind: Pattern,
        mitre: &["T1562"],
        table: DEFENSE_EVASION_PATTERNS,
    },
    IndicatorSource {
        label: "reverse-shell command",
        kind: Pattern,
        mitre: &["T1059"],
        table: REVERSE_SHELL_PATTERNS,
    },
    IndicatorSource {
        label: "PowerShell abuse",
        kind: Pattern,
        mitre: &["T1059.001"],
        table: POWERSHELL_ABUSE_PATTERNS,
    },
    IndicatorSource {
        label: "WMI abuse",
        kind: Pattern,
        mitre: &["T1047"],
        table: WMI_ABUSE_PATTERNS,
    },
    IndicatorSource {
        label: "download command",
        kind: Pattern,
        mitre: &["T1105"],
        table: DOWNLOAD_TOOL_PATTERNS,
    },
    IndicatorSource {
        label: "log-wipe command",
        kind: Pattern,
        mitre: &["T1070.001"],
        table: LOG_WIPE_COMMANDS,
    },
    IndicatorSource {
        label: "timestomp indicator",
        kind: Pattern,
        mitre: &["T1070.006"],
        table: TIMESTOMP_INDICATORS,
    },
    IndicatorSource {
        label: "shadow-copy deletion",
        kind: Pattern,
        mitre: &["T1490"],
        table: SHADOW_COPY_DELETION_PATTERNS,
    },
    IndicatorSource {
        label: "vssadmin shadow delete",
        kind: Pattern,
        mitre: &["T1490"],
        table: VSSADMIN_SHADOW_DELETE_PATTERNS,
    },
    IndicatorSource {
        label: "shell-history clearing",
        kind: Pattern,
        mitre: &["T1070.003"],
        table: HISTORY_CLEARING_PATTERNS,
    },
    IndicatorSource {
        label: "download-pipe-to-shell",
        kind: Pattern,
        mitre: &["T1059.004"],
        table: DOWNLOAD_PIPE_TO_SHELL_PATTERNS,
    },
    IndicatorSource {
        label: "AMSI bypass",
        kind: Pattern,
        mitre: &["T1562.001"],
        table: AMSI_BYPASS_PATTERNS,
    },
    IndicatorSource {
        label: "Defender tamper",
        kind: Pattern,
        mitre: &["T1562.001"],
        table: DEFENDER_TAMPER_PATTERNS,
    },
    IndicatorSource {
        label: "PsExec service",
        kind: Pattern,
        mitre: &["T1569.002"],
        table: PSEXEC_SERVICE_PATTERNS,
    },
    IndicatorSource {
        label: "comsvcs LSASS minidump",
        kind: Pattern,
        mitre: &["T1003.001"],
        table: COMSVCS_MINIDUMP_PATTERNS,
    },
    IndicatorSource {
        label: "WebDAV delivery",
        kind: Pattern,
        mitre: &["T1105"],
        table: WEBDAV_COMMANDLINE_INDICATORS,
    },
    IndicatorSource {
        label: "C2 network pattern",
        kind: Pattern,
        mitre: &["T1071"],
        table: NETWORK_C2_PATTERNS,
    },
    IndicatorSource {
        label: "credential string pattern",
        kind: Pattern,
        mitre: &["T1003"],
        table: CREDENTIAL_PATTERNS,
    },
];
