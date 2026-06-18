use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ARTIFACT_PAM_STAGING_FATHER, ARTIFACT_PAM_STAGING_STRUCTURAL,
        ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING, ELF_HOOKS_NETWORK_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING, ELF_LIBC_SHADOW_EXPORTS,
        ELF_NOT_IN_PKG_DB, ELF_STRING_FATHER_FORMAT, NETWORK_MAGIC_PACKET_KNOCK,
        SYSTEM_KERNEL_TAINT_OOT, TEMPORAL_LDPRELOAD_SSHD_RESTART,
    },
};

pub static BEURK: MalwareProfile = MalwareProfile {
    id: "beurk",
    family: "Beurk",
    aliases: &["beurk-rootkit"],
    description: "Pure LD_PRELOAD rootkit combining process, file, and network hiding via libc \
                  function hooking. Exports fake libc symbols globally. No PAM hooking, no LKM \
                  component. Simple magic-packet backdoor channel. Emphasises broad hook coverage \
                  over specialisation; distinguishable by triple-domain hiding without PAM.",
    malware_class: MalwareClass::LdPreloadFullRootkit,
    mitre_techniques: &["T1574.006", "T1014", "T1205.001"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 25,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_FILE_HIDING,
            weight: 25,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_NETWORK_HIDING,
            weight: 25,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_MAGIC_PACKET_KNOCK,
            weight: 25,
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
            id: ARTIFACT_LD_PRELOAD_FOREIGN,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: ELF_LIBC_SHADOW_EXPORTS,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: TEMPORAL_LDPRELOAD_SSHD_RESTART,
            weight: 10,
            required: false,
        },
    ],
    exclusions: &[
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_STRUCTURAL,
            penalty: 35,
        },
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_FATHER,
            penalty: 40,
        },
        WeightedExclusion {
            id: SYSTEM_KERNEL_TAINT_OOT,
            penalty: 30,
        },
        WeightedExclusion {
            id: ELF_STRING_FATHER_FORMAT,
            penalty: 25,
        },
    ],
    class_threshold: 75,
    probable_threshold: 110,
    confirmed_threshold: 140,
};

#[cfg(test)]
mod tests {
    use super::BEURK;
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
    fn beurk_required_signals_reach_class_threshold() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
        ]);
        let m = score_against_profile(&s, &BEURK);
        assert!(
            m.score >= BEURK.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            BEURK.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn beurk_with_magic_packet_reaches_probable() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
            ELF_GLOBALLY_LOADED,
        ]);
        let m = score_against_profile(&s, &BEURK);
        assert!(
            m.score >= BEURK.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            BEURK.probable_threshold
        );
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn beurk_full_signals_reach_confirmed() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
            ELF_GLOBALLY_LOADED,
            ELF_NOT_IN_PKG_DB,
            ARTIFACT_LD_PRELOAD_FOREIGN,
            ELF_LIBC_SHADOW_EXPORTS,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
        ]);
        let m = score_against_profile(&s, &BEURK);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn beurk_missing_file_hiding_is_no_match() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_NETWORK_HIDING]);
        let m = score_against_profile(&s, &BEURK);
        assert_eq!(m.classification, Classification::NoMatch);
    }

    #[test]
    fn beurk_father_pam_staging_reduces_score() {
        let base = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
        ]);
        let with_father = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            NETWORK_MAGIC_PACKET_KNOCK,
            ARTIFACT_PAM_STAGING_FATHER,
        ]);
        let m_base = score_against_profile(&base, &BEURK);
        let m_father = score_against_profile(&with_father, &BEURK);
        assert!(
            m_father.score < m_base.score,
            "Father PAM staging should penalise Beurk score"
        );
    }

    #[test]
    fn beurk_kernel_taint_reduces_score() {
        let base = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
        ]);
        let with_lkm = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            SYSTEM_KERNEL_TAINT_OOT,
        ]);
        let m_base = score_against_profile(&base, &BEURK);
        let m_lkm = score_against_profile(&with_lkm, &BEURK);
        assert!(
            m_lkm.score < m_base.score,
            "kernel taint should penalise Beurk (pure LD_PRELOAD)"
        );
    }
}
