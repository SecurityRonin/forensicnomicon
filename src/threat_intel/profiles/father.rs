use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal, WeightedExclusion},
    signals::*,
};

pub static FATHER: MalwareProfile = MalwareProfile {
    id: "father",
    family: "Father",
    aliases: &["libymv", "father-rootkit"],
    description: "LD_PRELOAD rootkit: process hiding via readdir64 + PAM credential theft. \
                  Writes credentials to a staging file in /tmp (UID:N:password:V format).",
    malware_class: MalwareClass::LdPreloadPamHooker,
    mitre_techniques: &["T1574.006", "T1014", "T1556.003", "T1074"],
    signals: &[
        ProfileSignal { id: ELF_HOOKS_PROCESS_HIDING,         weight: 20, required: true  },
        ProfileSignal { id: ELF_HOOKS_PAM_CREDENTIAL,         weight: 30, required: true  },
        ProfileSignal { id: ARTIFACT_PAM_STAGING_STRUCTURAL,  weight: 25, required: false },
        ProfileSignal { id: ARTIFACT_PAM_STAGING_FATHER,      weight: 15, required: false },
        ProfileSignal { id: ELF_STRING_FATHER_FORMAT,          weight: 10, required: false },
        ProfileSignal { id: ELF_STRING_STAGING_PATH,           weight:  5, required: false },
        ProfileSignal { id: ELF_GLOBALLY_LOADED,               weight: 10, required: false },
        ProfileSignal { id: ELF_NOT_IN_PKG_DB,                 weight: 10, required: false },
        ProfileSignal { id: TEMPORAL_LDPRELOAD_SSHD_RESTART,   weight: 15, required: false },
    ],
    exclusions: &[
        WeightedExclusion { id: ELF_HOOKS_NETWORK_HIDING, penalty: 20 },
    ],
    class_threshold:     50,
    probable_threshold:  75,
    confirmed_threshold: 90,
};

#[cfg(test)]
mod tests {
    use super::FATHER;
    use crate::threat_intel::{
        engine::{score_against_profile, DetectedSignal},
        profile::Classification,
        signals::*,
    };

    fn sigs(ids: &[&'static str]) -> Vec<DetectedSignal> {
        ids.iter().map(|&id| DetectedSignal { id, confidence: 1.0, evidence: String::new() }).collect()
    }

    #[test]
    fn father_process_hiding_plus_pam_reaches_class_threshold() {
        let s = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let m = score_against_profile(&s, &FATHER);
        assert!(m.score >= FATHER.class_threshold,
            "score {} < class_threshold {}", m.score, FATHER.class_threshold);
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn father_with_staging_file_reaches_probable_threshold() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_PAM_STAGING_STRUCTURAL,
        ]);
        let m = score_against_profile(&s, &FATHER);
        assert!(m.score >= FATHER.probable_threshold,
            "score {} < probable_threshold {}", m.score, FATHER.probable_threshold);
        assert!(m.classification >= Classification::Probable);
    }

    #[test]
    fn father_with_all_signals_reaches_confirmed_threshold() {
        let s = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_PAM_STAGING_STRUCTURAL,
            ARTIFACT_PAM_STAGING_FATHER,
            ELF_STRING_FATHER_FORMAT,
            ELF_STRING_STAGING_PATH,
            ELF_GLOBALLY_LOADED,
            ELF_NOT_IN_PKG_DB,
            TEMPORAL_LDPRELOAD_SSHD_RESTART,
        ]);
        let m = score_against_profile(&s, &FATHER);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn father_network_hiding_signal_reduces_score() {
        let base = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let with_network = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_NETWORK_HIDING]);
        let m_base = score_against_profile(&base, &FATHER);
        let m_net  = score_against_profile(&with_network, &FATHER);
        assert!(m_net.score < m_base.score, "network hiding should penalise Father score");
    }

    #[test]
    fn father_requires_both_process_hiding_and_pam() {
        // Process hiding only
        let s1 = sigs(&[ELF_HOOKS_PROCESS_HIDING]);
        let m1 = score_against_profile(&s1, &FATHER);
        assert_eq!(m1.classification, Classification::NoMatch);

        // PAM only
        let s2 = sigs(&[ELF_HOOKS_PAM_CREDENTIAL]);
        let m2 = score_against_profile(&s2, &FATHER);
        assert_eq!(m2.classification, Classification::NoMatch);
    }
}
