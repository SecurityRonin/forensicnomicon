use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ARTIFACT_PAM_STAGING_FATHER, ELF_GLOBALLY_LOADED,
        ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING,
        ELF_LIBC_SHADOW_EXPORTS, ELF_NOT_IN_PKG_DB, ELF_STRING_FATHER_FORMAT,
        SYSTEM_KERNEL_TAINT_OOT, TEMPORAL_LDPRELOAD_SSHD_RESTART,
    },
};

pub static MEDUSA: MalwareProfile = MalwareProfile {
    id: "medusa",
    family: "Medusa",
    aliases: &["medusa-linux", "libmed"],
    description: "LD_PRELOAD rootkit emphasising network hiding and PAM credential harvesting. \
                  Hooks recvmsg/recvfrom to hide connections, hooks pam_authenticate for credential \
                  theft. Network-heavy hook set distinguishes from Father/Azazel. No LKM component.",
    malware_class: MalwareClass::LdPreloadNetworkHider,
    mitre_techniques: &["T1574.006", "T1014", "T1556.003", "T1205.001"],
    signals: &[
        ProfileSignal { id: ELF_HOOKS_NETWORK_HIDING,        weight: 30, required: true  },
        ProfileSignal { id: ELF_HOOKS_PAM_CREDENTIAL,        weight: 30, required: true  },
        ProfileSignal { id: ELF_HOOKS_PROCESS_HIDING,        weight: 20, required: false },
        ProfileSignal { id: ELF_GLOBALLY_LOADED,             weight: 20, required: false },
        ProfileSignal { id: ELF_NOT_IN_PKG_DB,               weight: 15, required: false },
        ProfileSignal { id: ARTIFACT_LD_PRELOAD_FOREIGN,     weight: 20, required: false },
        ProfileSignal { id: TEMPORAL_LDPRELOAD_SSHD_RESTART, weight: 25, required: false },
        ProfileSignal { id: ELF_LIBC_SHADOW_EXPORTS,         weight: 15, required: false },
    ],
    exclusions: &[
        WeightedExclusion { id: SYSTEM_KERNEL_TAINT_OOT,    penalty: 30 },
        WeightedExclusion { id: ARTIFACT_PAM_STAGING_FATHER, penalty: 20 },
        WeightedExclusion { id: ELF_STRING_FATHER_FORMAT,    penalty: 15 },
    ],
    class_threshold:     60,
    probable_threshold:  95,
    confirmed_threshold: 125,
};

#[cfg(test)]
mod tests {
    use super::MEDUSA;
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
    fn medusa_required_signals_reach_class_threshold() {
        let s = sigs(&[ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let m = score_against_profile(&s, &MEDUSA);
        assert!(
            m.score >= MEDUSA.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            MEDUSA.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn medusa_with_sshd_restart_and_foreign_reaches_probable() {
        let s = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
            ELF_GLOBALLY_LOADED,
        ]);
        let m = score_against_profile(&s, &MEDUSA);
        assert!(
            m.score >= MEDUSA.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            MEDUSA.probable_threshold
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn medusa_full_signals_reach_confirmed() {
        let s = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ELF_HOOKS_PROCESS_HIDING,
            ELF_GLOBALLY_LOADED,
            ELF_NOT_IN_PKG_DB,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
            ELF_LIBC_SHADOW_EXPORTS,
        ]);
        let m = score_against_profile(&s, &MEDUSA);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn medusa_network_hiding_only_is_no_match() {
        let s = sigs(&[ELF_HOOKS_NETWORK_HIDING]);
        let m = score_against_profile(&s, &MEDUSA);
        assert_eq!(m.classification, Classification::NoMatch);
    }

    #[test]
    fn medusa_kernel_taint_reduces_score() {
        let base = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
        ]);
        let with_lkm = sigs(&[
            ELF_HOOKS_NETWORK_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let m_base = score_against_profile(&base, &MEDUSA);
        let m_lkm = score_against_profile(&with_lkm, &MEDUSA);
        assert!(
            m_lkm.score < m_base.score,
            "kernel taint should penalise Medusa (no LKM)"
        );
    }
}
