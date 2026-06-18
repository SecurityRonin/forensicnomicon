use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_PAM_STAGING_FATHER, ELF_GLOBALLY_LOADED, ELF_HOOKS_PAM_CREDENTIAL,
        ELF_HOOKS_PROCESS_HIDING, ELF_NOT_IN_PKG_DB, ELF_STRING_FATHER_FORMAT,
        NETWORK_MAGIC_PACKET_KNOCK,
    },
};

pub static AZAZEL: MalwareProfile = MalwareProfile {
    id: "azazel",
    family: "Azazel",
    aliases: &["azazel-rootkit"],
    description: "LD_PRELOAD rootkit similar to Father: process hiding + PAM credential theft. \
                  Distinguishable from Father by absence of the Father staging format and \
                  presence of magic-packet backdoor activation.",
    malware_class: MalwareClass::LdPreloadPamHooker,
    mitre_techniques: &["T1574.006", "T1014", "T1556.003", "T1205.001"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 20,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: ELF_NOT_IN_PKG_DB,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_MAGIC_PACKET_KNOCK,
            weight: 25,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_FATHER,
            penalty: 20,
        },
        WeightedExclusion {
            id: ELF_STRING_FATHER_FORMAT,
            penalty: 15,
        },
    ],
    class_threshold: 50,
    probable_threshold: 70,
    confirmed_threshold: 85,
};
