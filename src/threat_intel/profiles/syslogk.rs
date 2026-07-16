use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, NETWORK_MAGIC_PACKET_KNOCK, PROCESS_HIDDEN_FROM_PS,
        SYSTEM_KERNEL_TAINT_FORCED, SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT,
        TEMPORAL_ACTIVATION_SEQUENCE,
    },
};

pub static SYSLOGK: MalwareProfile = MalwareProfile {
    id: "syslogk",
    family: "SyslogK",
    aliases: &["syslogk-rootkit", "rodduk"],
    description: "LKM rootkit hiding a Rekoobe backdoor (trojanised Open Source Tiny SHell). \
                  Magic-packet activated via TCP port knock. Hides the Rekoobe PID and its port. \
                  Pure kernel-space: no LD_PRELOAD, no PAM hooks. Discovered by Avast 2022.",
    malware_class: MalwareClass::LkmRootkit,
    mitre_techniques: &["T1215", "T1014", "T1205.001", "T1059"],
    signals: &[
        ProfileSignal {
            id: SYSTEM_KERNEL_TAINT_OOT,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: SYSTEM_PROC_MODULES_SUSPECT,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: PROCESS_HIDDEN_FROM_PS,
            weight: 25,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_MAGIC_PACKET_KNOCK,
            weight: 40,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_FILE_HIDING,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: SYSTEM_KERNEL_TAINT_FORCED,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: TEMPORAL_ACTIVATION_SEQUENCE,
            weight: 15,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: ELF_GLOBALLY_LOADED,
            penalty: 25,
        },
        WeightedExclusion {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            penalty: 20,
        },
        WeightedExclusion {
            id: ARTIFACT_LD_PRELOAD_FOREIGN,
            penalty: 30,
        },
    ],
    class_threshold: 60,
    probable_threshold: 100,
    confirmed_threshold: 125,
};

#[cfg(test)]
mod tests {
    use super::SYSLOGK;
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
    fn syslogk_required_signals_reach_class_threshold() {
        let s = sigs(&[SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT]);
        let m = score_against_profile(&s, &SYSLOGK);
        assert!(
            m.score >= SYSLOGK.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            SYSLOGK.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn syslogk_with_magic_packet_reaches_probable() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let m = score_against_profile(&s, &SYSLOGK);
        assert!(
            m.score >= SYSLOGK.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            SYSLOGK.probable_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn syslogk_full_signals_reach_confirmed() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
            NETWORK_MAGIC_PACKET_KNOCK,
            ELF_HOOKS_FILE_HIDING,
            TEMPORAL_ACTIVATION_SEQUENCE,
        ]);
        let m = score_against_profile(&s, &SYSLOGK);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn syslogk_ldpreload_foreign_reduces_score() {
        let base = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let with_preload = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            NETWORK_MAGIC_PACKET_KNOCK,
            ARTIFACT_LD_PRELOAD_FOREIGN,
        ]);
        let m_base = score_against_profile(&base, &SYSLOGK);
        let m_preload = score_against_profile(&with_preload, &SYSLOGK);
        assert!(
            m_preload.score < m_base.score,
            "LD_PRELOAD should penalise SyslogK (pure LKM)"
        );
    }

    #[test]
    fn syslogk_kernel_module_only_no_proc_modules_is_no_match() {
        let s = sigs(&[SYSTEM_KERNEL_TAINT_OOT]);
        let m = score_against_profile(&s, &SYSLOGK);
        assert_eq!(m.classification, Classification::NoMatch);
    }
}
