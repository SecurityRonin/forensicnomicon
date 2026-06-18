use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::{
        ARTIFACT_PAM_STAGING_STRUCTURAL, ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING,
        ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING, ELF_LIBC_SHADOW_EXPORTS,
        ELF_NOT_IN_PKG_DB,
    },
};

pub static JYNX: MalwareProfile = MalwareProfile {
    id: "jynx",
    family: "Jynx",
    aliases: &["jynx2", "jynxkit"],
    description: "LD_PRELOAD rootkit: process + file hiding. No PAM hooking. \
                  Simpler than Father — only hooks readdir and stat family.",
    malware_class: MalwareClass::LdPreloadProcessHider,
    mitre_techniques: &["T1574.006", "T1014", "T1564.001"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ELF_HOOKS_FILE_HIDING,
            weight: 30,
            required: true,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: ELF_NOT_IN_PKG_DB,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: ELF_LIBC_SHADOW_EXPORTS,
            weight: 5,
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
    class_threshold: 45,
    probable_threshold: 60,
    confirmed_threshold: 75,
};

#[cfg(test)]
mod tests {
    use super::JYNX;
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
    fn jynx_process_and_file_hiding_reaches_class_threshold() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_FILE_HIDING]);
        let m = score_against_profile(&s, &JYNX);
        assert!(
            m.score >= JYNX.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            JYNX.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn jynx_pam_signal_strongly_excluded() {
        // process (30) + file (30) + PAM penalty (40) → 20, below class_threshold 45
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
        ]);
        let m = score_against_profile(&s, &JYNX);
        assert!(
            m.classification < Classification::ClassMatch,
            "PAM should drop below class threshold, got {:?} (score {})",
            m.classification,
            m.score
        );
    }

    #[test]
    fn jynx_without_file_hiding_is_no_match() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING]);
        let m = score_against_profile(&s, &JYNX);
        assert_eq!(m.classification, Classification::NoMatch);
    }
}
