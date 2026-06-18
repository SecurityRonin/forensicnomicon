use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal},
    signals::{
        PROCESS_HIDDEN_FROM_PS, SYSTEM_KERNEL_TAINT_FORCED, SYSTEM_KERNEL_TAINT_OOT,
        SYSTEM_PROC_MODULES_SUSPECT,
    },
};

pub static LKM_GENERIC: MalwareProfile = MalwareProfile {
    id: "lkm_generic",
    family: "LKM Rootkit",
    aliases: &["diamorphine", "reptile", "suterusu", "knark", "adore"],
    description: "Loadable Kernel Module rootkit. Sets kernel taint bits. May hide \
                  itself from /proc/modules. Includes Diamorphine, Reptile, Suterusu, \
                  and similar kernel-space implants.",
    malware_class: MalwareClass::LkmRootkit,
    mitre_techniques: &["T1215", "T1014"],
    signals: &[
        ProfileSignal {
            id: SYSTEM_KERNEL_TAINT_OOT,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: SYSTEM_PROC_MODULES_SUSPECT,
            weight: 40,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_HIDDEN_FROM_PS,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: SYSTEM_KERNEL_TAINT_FORCED,
            weight: 15,
            required: false,
        },
    ],
    exclusions: &[],
    class_threshold: 30,
    probable_threshold: 55,
    confirmed_threshold: 75,
};
