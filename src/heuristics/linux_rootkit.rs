use crate::threat_intel::signals::{
    ELF_HOOKS_FILE_HIDING, ELF_HOOKS_IO_INTERCEPTION, ELF_HOOKS_NETWORK_HIDING,
    ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_UID_SPOOFING,
};

/// A string pattern baked into Father-class rootkit binaries that survives stripping.
pub struct ElfStringPattern {
    /// Literal substring to search in ELF sections (.rodata, .data.rel.ro, etc.).
    pub pattern: &'static str,
    pub description: &'static str,
    /// Relative suspicion weight; sum across matches for a quick pre-score.
    pub weight: u32,
}

/// Strings characteristic of Father-class (and derived) LD_PRELOAD rootkits found
/// in `.rodata` regardless of library name or strip state.
///
/// Sources: Father (github.com/mav8557/Father), Jynx2, Azazel source analysis.
pub const FATHER_CLASS_ELF_PATTERNS: &[ElfStringPattern] = &[
    ElfStringPattern {
        pattern: "UID:%d:",
        description: "Father PAM hook format string — logs credentials as 'UID:N:user:pass'",
        weight: 90,
    },
    ElfStringPattern {
        pattern: "silly.txt",
        description: "Father default credential log filename baked into the binary",
        weight: 85,
    },
    ElfStringPattern {
        pattern: "/tmp/.ICE",
        description: "Father/Jynx staging directory prefix in /tmp",
        weight: 70,
    },
    ElfStringPattern {
        pattern: "libprocesshider",
        description: "Process-hider library self-identifier string",
        weight: 80,
    },
    ElfStringPattern {
        pattern: "MAGIC_GID",
        description: "Jynx2 magic GID constant used to exclude root kit processes from hiding",
        weight: 75,
    },
];

pub struct HookSymbol {
    pub name: &'static str,
    /// Signal ID from `threat_intel/signals.rs` emitted when this symbol is found.
    pub emits_signal: &'static str,
    pub mitre_technique: &'static str,
}

pub const ROOTKIT_HOOK_SYMBOLS: &[HookSymbol] = &[
    HookSymbol {
        name: "readdir",
        emits_signal: ELF_HOOKS_PROCESS_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "readdir64",
        emits_signal: ELF_HOOKS_PROCESS_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "getdents",
        emits_signal: ELF_HOOKS_PROCESS_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "getdents64",
        emits_signal: ELF_HOOKS_PROCESS_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "openat",
        emits_signal: ELF_HOOKS_FILE_HIDING,
        mitre_technique: "T1564.001",
    },
    HookSymbol {
        name: "stat",
        emits_signal: ELF_HOOKS_FILE_HIDING,
        mitre_technique: "T1564.001",
    },
    HookSymbol {
        name: "lstat",
        emits_signal: ELF_HOOKS_FILE_HIDING,
        mitre_technique: "T1564.001",
    },
    HookSymbol {
        name: "access",
        emits_signal: ELF_HOOKS_FILE_HIDING,
        mitre_technique: "T1564.001",
    },
    HookSymbol {
        name: "pam_get_item",
        emits_signal: ELF_HOOKS_PAM_CREDENTIAL,
        mitre_technique: "T1556.003",
    },
    HookSymbol {
        name: "pam_authenticate",
        emits_signal: ELF_HOOKS_PAM_CREDENTIAL,
        mitre_technique: "T1556.003",
    },
    HookSymbol {
        name: "pam_open_session",
        emits_signal: ELF_HOOKS_PAM_CREDENTIAL,
        mitre_technique: "T1556.003",
    },
    HookSymbol {
        name: "recvfrom",
        emits_signal: ELF_HOOKS_NETWORK_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "recvmsg",
        emits_signal: ELF_HOOKS_NETWORK_HIDING,
        mitre_technique: "T1014",
    },
    HookSymbol {
        name: "getuid",
        emits_signal: ELF_HOOKS_UID_SPOOFING,
        mitre_technique: "T1548",
    },
    HookSymbol {
        name: "geteuid",
        emits_signal: ELF_HOOKS_UID_SPOOFING,
        mitre_technique: "T1548",
    },
    HookSymbol {
        name: "getpwuid",
        emits_signal: ELF_HOOKS_UID_SPOOFING,
        mitre_technique: "T1548",
    },
    HookSymbol {
        name: "write",
        emits_signal: ELF_HOOKS_IO_INTERCEPTION,
        mitre_technique: "T1056.001",
    },
];
