use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING, ELF_HOOKS_NETWORK_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING, ELF_NOT_IN_PKG_DB,
    },
};

pub static LIB_PROCESS_HIDER: MalwareProfile = MalwareProfile {
    id: "libprocesshider",
    family: "libprocesshider",
    aliases: &["libshow.so", "libhide", "libproc.a"],
    description: "Minimal LD_PRELOAD rootkit: only hooks readdir/readdir64 to hide \
                  processes by PID prefix. No file hiding, no PAM, no network hiding. \
                  Very small library; commonly used as a base by custom implants.",
    malware_class: MalwareClass::LdPreloadProcessHider,
    mitre_techniques: &["T1574.006", "T1014"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: ELF_NOT_IN_PKG_DB,
            weight: 10,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            penalty: 50,
        },
        WeightedExclusion {
            id: ELF_HOOKS_FILE_HIDING,
            penalty: 30,
        },
        WeightedExclusion {
            id: ELF_HOOKS_NETWORK_HIDING,
            penalty: 40,
        },
    ],
    class_threshold: 30,
    probable_threshold: 45,
    confirmed_threshold: 55,
};
