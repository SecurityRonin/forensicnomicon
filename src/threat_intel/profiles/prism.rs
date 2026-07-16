use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ARTIFACT_PAM_STAGING_STRUCTURAL, ELF_GLOBALLY_LOADED,
        ELF_HOOKS_FILE_HIDING, ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL,
        ELF_HOOKS_PROCESS_HIDING, ELF_LIBC_SHADOW_EXPORTS, ELF_NOT_IN_PKG_DB,
        NETWORK_MAGIC_PACKET_KNOCK, SYSTEM_KERNEL_TAINT_OOT, TEMPORAL_LDPRELOAD_SSHD_RESTART,
    },
};

pub static PRISM: MalwareProfile = MalwareProfile {
    id: "prism",
    family: "Prism",
    aliases: &["prism-backdoor"],
    description:
        "Minimalist LD_PRELOAD backdoor focused on network hiding. Hooks recvmsg/recvfrom \
                  to conceal C2 traffic. No process hiding, no PAM, no file hiding. \
                  Requires a foreign LD_PRELOAD entry. Designed for long-term stealth with \
                  minimal hooking footprint; distinguishable from Medusa by absence of PAM.",
    malware_class: MalwareClass::LdPreloadNetworkHider,
    mitre_techniques: &["T1574.006", "T1014", "T1205.001"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_NETWORK_HIDING,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ARTIFACT_LD_PRELOAD_FOREIGN,
            weight: 15,
            required: true,
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
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_MAGIC_PACKET_KNOCK,
            weight: 25,
            required: false,
        },
        ProfileSignal {
            id: TEMPORAL_LDPRELOAD_SSHD_RESTART,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: ELF_LIBC_SHADOW_EXPORTS,
            weight: 10,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            penalty: 30,
        },
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_STRUCTURAL,
            penalty: 30,
        },
        WeightedExclusion {
            id: SYSTEM_KERNEL_TAINT_OOT,
            penalty: 35,
        },
        WeightedExclusion {
            id: ELF_HOOKS_FILE_HIDING,
            penalty: 15,
        },
    ],
    class_threshold: 45,
    probable_threshold: 75,
    confirmed_threshold: 100,
};

#[cfg(test)]
mod tests {
    use super::PRISM;
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
    fn prism_required_signals_reach_class_threshold() {
        let s = sigs(&[ELF_HOOKS_NETWORK_HIDING, ARTIFACT_LD_PRELOAD_FOREIGN]);
        let m = score_against_profile(&s, &PRISM);
        assert!(
            m.score >= PRISM.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            PRISM.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn prism_with_globally_loaded_reaches_probable() {
        let s = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            ELF_GLOBALLY_LOADED,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let m = score_against_profile(&s, &PRISM);
        assert!(
            m.score >= PRISM.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            PRISM.probable_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn prism_full_signals_reach_confirmed() {
        let s = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            ELF_GLOBALLY_LOADED,
            ELF_NOT_IN_PKG_DB,
            ELF_HOOKS_PROCESS_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
            ELF_LIBC_SHADOW_EXPORTS,
        ]);
        let m = score_against_profile(&s, &PRISM);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn prism_network_hiding_without_foreign_preload_is_no_match() {
        let s = sigs(&[ELF_HOOKS_NETWORK_HIDING]);
        let m = score_against_profile(&s, &PRISM);
        assert_eq!(m.classification, Classification::NoMatch);
    }

    #[test]
    fn prism_pam_credential_reduces_score() {
        let base = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            ELF_GLOBALLY_LOADED,
        ]);
        let with_pam = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            ELF_GLOBALLY_LOADED,
            ELF_HOOKS_PAM_CREDENTIAL,
        ]);
        let m_base = score_against_profile(&base, &PRISM);
        let m_pam = score_against_profile(&with_pam, &PRISM);
        assert!(
            m_pam.score < m_base.score,
            "PAM credential hook should penalise Prism (no PAM)"
        );
    }

    #[test]
    fn prism_kernel_taint_reduces_score() {
        let base = sigs(&[ELF_HOOKS_NETWORK_HIDING, ARTIFACT_LD_PRELOAD_FOREIGN]);
        let with_lkm = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let m_base = score_against_profile(&base, &PRISM);
        let m_lkm = score_against_profile(&with_lkm, &PRISM);
        assert!(
            m_lkm.score < m_base.score,
            "kernel taint should penalise Prism (pure LD_PRELOAD)"
        );
    }
}
