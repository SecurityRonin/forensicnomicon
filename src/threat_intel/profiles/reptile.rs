use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING, ELF_HOOKS_NETWORK_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, NETWORK_MAGIC_PACKET_KNOCK, PROCESS_HIDDEN_FROM_PS,
        SYSTEM_KERNEL_TAINT_FORCED, SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT,
        TEMPORAL_ACTIVATION_SEQUENCE,
    },
};

pub static REPTILE: MalwareProfile = MalwareProfile {
    id: "reptile",
    family: "Reptile",
    aliases: &["reptile-rootkit", "reptile_module"],
    description: "Full-featured LKM rootkit with process/file/network hiding, syscall table hooking, \
                  and netfilter magic-packet backdoor (ipt_REPTILE). Operator control via /proc/reptile. \
                  Deployed by Rocke, Andariel, and multiple APT groups.",
    malware_class: MalwareClass::LkmRootkit,
    mitre_techniques: &["T1215", "T1014", "T1205.001", "T1059"],
    signals: &[
        ProfileSignal { id: SYSTEM_KERNEL_TAINT_OOT,       weight: 30, required: true  },
        ProfileSignal { id: SYSTEM_PROC_MODULES_SUSPECT,   weight: 30, required: true  },
        ProfileSignal { id: PROCESS_HIDDEN_FROM_PS,        weight: 30, required: false },
        ProfileSignal { id: ELF_HOOKS_FILE_HIDING,         weight: 20, required: false },
        ProfileSignal { id: ELF_HOOKS_NETWORK_HIDING,      weight: 20, required: false },
        ProfileSignal { id: NETWORK_MAGIC_PACKET_KNOCK,    weight: 35, required: false },
        ProfileSignal { id: SYSTEM_KERNEL_TAINT_FORCED,    weight: 10, required: false },
        ProfileSignal { id: TEMPORAL_ACTIVATION_SEQUENCE,  weight: 15, required: false },
    ],
    exclusions: &[
        WeightedExclusion { id: ELF_GLOBALLY_LOADED,       penalty: 20 },
        WeightedExclusion { id: ELF_HOOKS_PAM_CREDENTIAL,  penalty: 20 },
    ],
    class_threshold:     60,
    probable_threshold:  95,
    confirmed_threshold: 120,
};

#[cfg(test)]
mod tests {
    use super::REPTILE;
    use crate::threat_intel::{
        engine::{score_against_profile, DetectedSignal},
        profile::Classification,
        signals::*,
    };

    fn sigs(ids: &[&'static str]) -> Vec<DetectedSignal> {
        ids.iter()
            .map(|&id| DetectedSignal {
                id,
                confidence: 1.0,
                evidence: String::new(),
            })
            .collect()
    }

    #[test]
    fn reptile_required_signals_reach_class_threshold() {
        let s = sigs(&[SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT]);
        let m = score_against_profile(&s, &REPTILE);
        assert!(
            m.score >= REPTILE.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            REPTILE.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn reptile_with_magic_packet_reaches_probable() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let m = score_against_profile(&s, &REPTILE);
        assert!(
            m.score >= REPTILE.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            REPTILE.probable_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn reptile_full_signals_reach_confirmed() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
            TEMPORAL_ACTIVATION_SEQUENCE,
        ]);
        let m = score_against_profile(&s, &REPTILE);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn reptile_pam_signal_reduces_score() {
        let base = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let with_pam = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
            ELF_HOOKS_PAM_CREDENTIAL,
        ]);
        let m_base = score_against_profile(&base, &REPTILE);
        let m_pam = score_against_profile(&with_pam, &REPTILE);
        assert!(
            m_pam.score < m_base.score,
            "PAM signal should penalise Reptile score"
        );
    }
}
