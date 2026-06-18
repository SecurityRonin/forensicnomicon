use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal},
    signals::{
        ARTIFACT_LD_PRELOAD_FOREIGN, ELF_GLOBALLY_LOADED, ELF_HOOKS_FILE_HIDING,
        ELF_HOOKS_NETWORK_HIDING, ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_PROCESS_HIDING,
        ELF_NOT_IN_PKG_DB,
    },
};

/// Catch-all for LD_PRELOAD libraries that don't match any known family.
pub static LD_PRELOAD_GENERIC: MalwareProfile = MalwareProfile {
    id: "ld_preload_generic",
    family: "Unknown LD_PRELOAD Rootkit",
    aliases: &[],
    description: "An LD_PRELOAD library with rootkit-class capability hooks that does \
                  not match any known family profile. Novel or heavily modified variant.",
    malware_class: MalwareClass::GenericLdPreload,
    mitre_techniques: &["T1574.006", "T1014"],
    signals: &[
        ProfileSignal {
            id: ELF_HOOKS_PROCESS_HIDING,
            weight: 30,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_PAM_CREDENTIAL,
            weight: 30,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_NETWORK_HIDING,
            weight: 25,
            required: false,
        },
        ProfileSignal {
            id: ELF_HOOKS_FILE_HIDING,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: ELF_GLOBALLY_LOADED,
            weight: 20,
            required: true,
        },
        ProfileSignal {
            id: ELF_NOT_IN_PKG_DB,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: ARTIFACT_LD_PRELOAD_FOREIGN,
            weight: 15,
            required: false,
        },
    ],
    exclusions: &[],
    class_threshold: 30,
    probable_threshold: 60,
    confirmed_threshold: 80,
};

#[cfg(test)]
mod tests {
    use super::LD_PRELOAD_GENERIC;
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
    fn generic_catches_novel_library_with_unknown_hooks() {
        // Unknown library that is globally loaded — no known hook pattern
        let s = sigs(&[
            ELF_GLOBALLY_LOADED,
            ELF_NOT_IN_PKG_DB,
            ARTIFACT_LD_PRELOAD_FOREIGN,
        ]);
        let m = score_against_profile(&s, &LD_PRELOAD_GENERIC);
        assert!(
            m.score >= LD_PRELOAD_GENERIC.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            LD_PRELOAD_GENERIC.class_threshold
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn generic_requires_globally_loaded_signal() {
        // Has hooks but NOT globally loaded — not LD_PRELOAD infection
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_NOT_IN_PKG_DB]);
        let m = score_against_profile(&s, &LD_PRELOAD_GENERIC);
        assert_eq!(
            m.classification,
            Classification::NoMatch,
            "without ELF_GLOBALLY_LOADED should be NoMatch"
        );
    }
}
