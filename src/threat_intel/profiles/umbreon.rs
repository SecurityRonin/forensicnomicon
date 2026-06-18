use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ARTIFACT_PAM_STAGING_STRUCTURAL, ELF_GLOBALLY_LOADED,
        ELF_HOOKS_FILE_HIDING, ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL,
        ELF_HOOKS_PROCESS_HIDING, ELF_NOT_IN_PKG_DB, PROCESS_THREAD_MINER_XMRIG,
        SYSTEM_KERNEL_TAINT_OOT, SYSTEM_PROC_MODULES_SUSPECT, TEMPORAL_LDPRELOAD_SSHD_RESTART,
    },
};

pub static UMBREON: MalwareProfile = MalwareProfile {
    id: "umbreon",
    family: "Umbreon",
    aliases: &["pokemon-rootkit", "libecat"],
    description: "Dual-layer rootkit: LKM (espeon) + LD_PRELOAD (libecat.so). \
                  PAM backdoor grants root via magic password; creates hidden 'evildoer' user. \
                  VDSO patching for additional evasion.",
    malware_class: MalwareClass::LkmRootkit,
    mitre_techniques: &["T1574.006", "T1014", "T1215", "T1556.003"],
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
            id: SYSTEM_KERNEL_TAINT_OOT,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_FILE_HIDING,
            weight: 25,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_NETWORK_HIDING,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: ELF_NOT_IN_PKG_DB,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: SYSTEM_PROC_MODULES_SUSPECT,
            weight: 30,
            required: false,
        },
        ProfileSignal {
            id: ARTIFACT_LD_PRELOAD_FOREIGN,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: TEMPORAL_LDPRELOAD_SSHD_RESTART,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: ARTIFACT_PAM_STAGING_STRUCTURAL,
            weight: 15,
            required: false,
        },
    ],
    exclusions: &[WeightedExclusion {
        id: PROCESS_THREAD_MINER_XMRIG,
        penalty: 25,
    }],
    class_threshold: 80,
    probable_threshold: 110,
    confirmed_threshold: 140,
};

#[cfg(test)]
mod tests {
    use super::UMBREON;
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
    fn umbreon_required_signals_reach_class_threshold() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let m = score_against_profile(&s, &UMBREON);
        assert!(
            m.score >= UMBREON.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            UMBREON.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn umbreon_with_proc_modules_reaches_probable() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            SYSTEM_KERNEL_TAINT_OOT,
            SYSTEM_PROC_MODULES_SUSPECT,
        ]);
        let m = score_against_profile(&s, &UMBREON);
        assert!(
            m.score >= UMBREON.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            UMBREON.probable_threshold
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn umbreon_full_signals_reach_confirmed() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            SYSTEM_KERNEL_TAINT_OOT,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            ELF_GLOBALLY_LOADED,
            SYSTEM_PROC_MODULES_SUSPECT,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
        ]);
        let m = score_against_profile(&s, &UMBREON);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn umbreon_missing_kernel_taint_is_no_match() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let m = score_against_profile(&s, &UMBREON);
        assert_eq!(m.classification, Classification::NoMatch);
    }

    #[test]
    fn umbreon_miner_signal_reduces_score() {
        let base = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let with_miner = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            SYSTEM_KERNEL_TAINT_OOT,
            PROCESS_THREAD_MINER_XMRIG,
        ]);
        let m_base = score_against_profile(&base, &UMBREON);
        let m_miner = score_against_profile(&with_miner, &UMBREON);
        assert!(
            m_miner.score < m_base.score,
            "miner signal should penalise Umbreon score"
        );
    }
}
