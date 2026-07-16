use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL, NETWORK_MAGIC_PACKET_KNOCK,
        PROCESS_HIDDEN_FROM_PS, SYSTEM_KERNEL_TAINT_FORCED, SYSTEM_KERNEL_TAINT_OOT,
        SYSTEM_PROC_MODULES_SUSPECT, TEMPORAL_ACTIVATION_SEQUENCE,
    },
};

pub static DIAMORPHINE: MalwareProfile = MalwareProfile {
    id: "diamorphine",
    family: "Diamorphine",
    aliases: &["diamorphine-rootkit"],
    description: "Compact signal-driven LKM rootkit. Signal 31 hides/shows PIDs; signal 63 toggles \
                  module visibility; signal 64 grants root. Files with DIAMORPHINE_SECRET prefix hidden. \
                  No netfilter, no network hiding, no PAM. Widely used by TeamTNT and Rocke.",
    malware_class: MalwareClass::LkmRootkit,
    mitre_techniques: &["T1215", "T1014", "T1548"],
    signals: &[
        ProfileSignal { id: SYSTEM_KERNEL_TAINT_OOT,      weight: 30, required: true  },
        ProfileSignal { id: SYSTEM_PROC_MODULES_SUSPECT,  weight: 30, required: true  },
        ProfileSignal { id: PROCESS_HIDDEN_FROM_PS,       weight: 35, required: false },
        ProfileSignal { id: TEMPORAL_ACTIVATION_SEQUENCE, weight: 25, required: false },
        ProfileSignal { id: SYSTEM_KERNEL_TAINT_FORCED,   weight: 10, required: false },
    ],
    exclusions: &[
        WeightedExclusion { id: NETWORK_MAGIC_PACKET_KNOCK, penalty: 35 },
        WeightedExclusion { id: ELF_HOOKS_PAM_CREDENTIAL,   penalty: 20 },
        WeightedExclusion { id: ELF_HOOKS_NETWORK_HIDING,   penalty: 25 },
    ],
    class_threshold:     60,
    probable_threshold:  85,
    confirmed_threshold: 105,
};

#[cfg(test)]
mod tests {
    use super::DIAMORPHINE;
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
    fn diamorphine_required_signals_reach_class_threshold() {
        let s = sigs(&[SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT]);
        let m = score_against_profile(&s, &DIAMORPHINE);
        assert!(
            m.score >= DIAMORPHINE.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            DIAMORPHINE.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn diamorphine_with_process_hidden_reaches_probable() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
        ]);
        let m = score_against_profile(&s, &DIAMORPHINE);
        assert!(
            m.score >= DIAMORPHINE.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            DIAMORPHINE.probable_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn diamorphine_full_signals_reach_confirmed() {
        let s = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
            TEMPORAL_ACTIVATION_SEQUENCE,
        ]);
        let m = score_against_profile(&s, &DIAMORPHINE);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn diamorphine_magic_packet_reduces_score() {
        let base = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
        ]);
        let with_knock = sigs(&[
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
            PROCESS_HIDDEN_FROM_PS,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let m_base = score_against_profile(&base, &DIAMORPHINE);
        let m_knock = score_against_profile(&with_knock, &DIAMORPHINE);
        assert!(
            m_knock.score < m_base.score,
            "magic packet should penalise Diamorphine (not its style)"
        );
    }
}
