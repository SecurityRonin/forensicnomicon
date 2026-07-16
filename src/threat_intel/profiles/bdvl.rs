use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_PAM_STAGING_STRUCTURAL, ELF_GLOBALLY_LOADED, ELF_HOOKS_NETWORK_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING, ELF_NOT_IN_PKG_DB,
        NETWORK_MAGIC_PACKET_KNOCK,
    },
};

pub static BDVL: MalwareProfile = MalwareProfile {
    id: "bdvl",
    family: "bdvl",
    aliases: &["bedevil"],
    description: "LD_PRELOAD rootkit specialising in network socket hiding. \
                  Hooks readdir64 (process) and recvmsg/recvfrom (network). \
                  No PAM credential theft. Provides a backdoor shell via magic packet.",
    malware_class: MalwareClass::LdPreloadNetworkHider,
    mitre_techniques: &["T1574.006", "T1014", "T1205.001"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 25,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_NETWORK_HIDING,
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
            id: ELF_HOOKS_PAM_CREDENTIAL,
            penalty: 40,
        },
        WeightedExclusion {
            id: ARTIFACT_PAM_STAGING_STRUCTURAL,
            penalty: 30,
        },
    ],
    class_threshold: 55,
    probable_threshold: 70,
    confirmed_threshold: 85,
};

#[cfg(test)]
mod tests {
    use super::BDVL;
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
    fn bdvl_process_and_network_hiding_reaches_class_threshold() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_NETWORK_HIDING]);
        let m = score_against_profile(&s, &BDVL);
        assert!(
            m.score >= BDVL.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            BDVL.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn bdvl_pam_signal_strongly_excluded() {
        // process (25) + network (30) + PAM penalty (40) → 15 < class_threshold 55
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_NETWORK_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
        ]);
        let m = score_against_profile(&s, &BDVL);
        assert!(
            m.classification < Classification::ClassMatch,
            "PAM should drop BDVL below class threshold, got {:?} (score {})",
            m.classification,
            m.score
        );
    }
}
