use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_PAM_STAGING_STRUCTURAL, ELF_GLOBALLY_LOADED, ELF_HOOKS_PAM_CREDENTIAL,
        ELF_HOOKS_PROCESS_HIDING, ELF_STRING_STAGING_PATH, NETWORK_STRATUM_CONNECTION,
        PROCESS_HIDDEN_FROM_PS, PROCESS_MASQUERADE, PROCESS_THREAD_MINER_XMRIG,
        SYSTEM_CPU_ANOMALY_HIGH, SYSTEM_KERNEL_TAINT_OOT,
    },
};

pub static NECRO: MalwareProfile = MalwareProfile {
    id: "necro",
    family: "Necro",
    aliases: &["necro-python", "necro-bot"],
    description: "Python-based bot/miner deploying XMRig to /tmp or /dev/shm. Some variants drop \
                  an LD_PRELOAD helper to hide the miner process. C2 for command dispatch. \
                  No LKM, no PAM. Documented by Netlab 360; targets Docker, Redis, Jenkins.",
    malware_class: MalwareClass::CryptoMiner,
    mitre_techniques: &["T1496", "T1036.005", "T1574.006", "T1059"],
    signals: &[
        ProfileSignal {
            id: PROCESS_THREAD_MINER_XMRIG,
            weight: 40,
            required: true,
        },
        ProfileSignal {
            id: ELF_STRING_STAGING_PATH,
            weight: 15,
            required: true,
        },
        ProfileSignal {
            id: SYSTEM_CPU_ANOMALY_HIGH,
            weight: 25,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_HIDDEN_FROM_PS,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_STRATUM_CONNECTION,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_MASQUERADE,
            weight: 10,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: SYSTEM_KERNEL_TAINT_OOT,
            penalty: 30,
        },
        WeightedExclusion {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            penalty: 20,
        },
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_STRUCTURAL,
            penalty: 20,
        },
    ],
    class_threshold: 55,
    probable_threshold: 80,
    confirmed_threshold: 100,
};

#[cfg(test)]
mod tests {
    use super::NECRO;
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
    fn necro_required_signals_reach_class_threshold() {
        let s = sigs(&[PROCESS_THREAD_MINER_XMRIG, ELF_STRING_STAGING_PATH]);
        let m = score_against_profile(&s, &NECRO);
        assert!(
            m.score >= NECRO.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            NECRO.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn necro_with_high_cpu_reaches_probable() {
        let s = sigs(&[
            PROCESS_THREAD_MINER_XMRIG,
            ELF_STRING_STAGING_PATH,
            SYSTEM_CPU_ANOMALY_HIGH,
        ]);
        let m = score_against_profile(&s, &NECRO);
        assert!(
            m.score >= NECRO.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            NECRO.probable_threshold
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn necro_full_signals_reach_confirmed() {
        let s = sigs(&[
            PROCESS_THREAD_MINER_XMRIG,
            ELF_STRING_STAGING_PATH,
            SYSTEM_CPU_ANOMALY_HIGH,
            NETWORK_STRATUM_CONNECTION,
            PROCESS_HIDDEN_FROM_PS,
            PROCESS_MASQUERADE,
        ]);
        let m = score_against_profile(&s, &NECRO);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn necro_kernel_taint_reduces_score() {
        let base = sigs(&[
            PROCESS_THREAD_MINER_XMRIG,
            ELF_STRING_STAGING_PATH,
            SYSTEM_CPU_ANOMALY_HIGH,
        ]);
        let with_lkm = sigs(&[
            PROCESS_THREAD_MINER_XMRIG,
            ELF_STRING_STAGING_PATH,
            SYSTEM_CPU_ANOMALY_HIGH,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let m_base = score_against_profile(&base, &NECRO);
        let m_lkm = score_against_profile(&with_lkm, &NECRO);
        assert!(
            m_lkm.score < m_base.score,
            "kernel taint should penalise Necro (no LKM)"
        );
    }

    #[test]
    fn necro_miner_only_no_staging_is_no_match() {
        let s = sigs(&[PROCESS_THREAD_MINER_XMRIG]);
        let m = score_against_profile(&s, &NECRO);
        assert_eq!(m.classification, Classification::NoMatch);
    }
}
