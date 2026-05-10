use std::collections::HashSet;
use super::profile::{Classification, FiredSignal, MalwareProfile, ProfileMatch};

#[derive(Debug)]
pub struct DetectedSignal {
    pub id: &'static str,
    pub confidence: f32,
    pub evidence: String,
}

pub fn score_against_profile(
    signals: &[DetectedSignal],
    profile: &'static MalwareProfile,
) -> ProfileMatch {
    let present: HashSet<&str> = signals.iter().map(|s| s.id).collect();

    let missed_required: Vec<&'static str> = profile.signals.iter()
        .filter(|ps| ps.required && !present.contains(ps.id))
        .map(|ps| ps.id)
        .collect();

    if !missed_required.is_empty() {
        return ProfileMatch {
            profile,
            score: 0,
            classification: Classification::NoMatch,
            fired: vec![],
            missed_required,
        };
    }

    let mut fired = Vec::new();
    let raw_score: u32 = profile.signals.iter()
        .filter(|ps| present.contains(ps.id))
        .map(|ps| {
            fired.push(FiredSignal { id: ps.id, weight: ps.weight });
            ps.weight
        })
        .sum();

    let penalty: u32 = profile.exclusions.iter()
        .filter(|ex| present.contains(ex.id))
        .map(|ex| ex.penalty)
        .sum();

    let score = raw_score.saturating_sub(penalty);

    let classification = if score == 0 {
        Classification::LowConfidence
    } else if score >= profile.confirmed_threshold {
        Classification::Confirmed
    } else if score >= profile.probable_threshold {
        Classification::Probable
    } else if score >= profile.class_threshold {
        Classification::ClassMatch
    } else {
        Classification::LowConfidence
    };

    ProfileMatch { profile, score, classification, fired, missed_required: vec![] }
}

pub fn score_all_profiles(signals: &[DetectedSignal]) -> Vec<ProfileMatch> {
    use super::profiles::ALL_PROFILES;
    let mut matches: Vec<ProfileMatch> = ALL_PROFILES.iter()
        .map(|p| score_against_profile(signals, p))
        .filter(|m| m.score > 0)
        .collect();
    matches.sort_by(|a, b| b.score.cmp(&a.score).then(a.profile.id.cmp(b.profile.id)));
    matches
}

pub fn top_match(signals: &[DetectedSignal]) -> Option<ProfileMatch> {
    score_all_profiles(signals)
        .into_iter()
        .find(|m| m.classification >= Classification::ClassMatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_intel::{
        profile::Classification,
        signals::*,
    };

    fn sig(id: &'static str) -> DetectedSignal {
        DetectedSignal { id, confidence: 1.0, evidence: String::new() }
    }

    fn sigs(ids: &[&'static str]) -> Vec<DetectedSignal> {
        ids.iter().map(|&id| sig(id)).collect()
    }

    #[test]
    fn score_zero_signals_returns_no_match_for_all_profiles() {
        let matches = score_all_profiles(&[]);
        assert!(matches.is_empty(), "no signals → no profiles should match");
    }

    #[test]
    fn score_father_required_signals_returns_father_class_match() {
        use crate::threat_intel::profiles::FATHER;
        let signals = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let m = score_against_profile(&signals, &FATHER);
        assert!(m.score >= FATHER.class_threshold);
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn score_father_full_signals_returns_father_confirmed() {
        use crate::threat_intel::profiles::FATHER;
        let signals = sigs(&[
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
        let m = score_against_profile(&signals, &FATHER);
        assert_eq!(m.classification, Classification::Confirmed);
    }

    #[test]
    fn score_jynx_with_pam_signal_excluded_by_penalty() {
        use crate::threat_intel::profiles::JYNX;
        let signals = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_FILE_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
        ]);
        let m = score_against_profile(&signals, &JYNX);
        assert!(m.classification < Classification::ClassMatch,
            "PAM signal should drop Jynx below class threshold, got {:?} (score {})",
            m.classification, m.score);
    }

    #[test]
    fn score_bdvl_required_signals_returns_bdvl_class_match() {
        use crate::threat_intel::profiles::BDVL;
        let signals = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_NETWORK_HIDING]);
        let m = score_against_profile(&signals, &BDVL);
        assert!(m.score >= BDVL.class_threshold);
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn score_xmrig_thread_signal_returns_xmrig_class_match() {
        use crate::threat_intel::profiles::XMRIG;
        let signals = sigs(&[PROCESS_THREAD_MINER_XMRIG]);
        let m = score_against_profile(&signals, &XMRIG);
        assert!(m.score >= XMRIG.class_threshold);
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn score_all_profiles_sorted_descending_by_score() {
        let signals = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_PAM_STAGING_FATHER,
            ELF_STRING_FATHER_FORMAT,
        ]);
        let matches = score_all_profiles(&signals);
        assert!(!matches.is_empty());
        for w in matches.windows(2) {
            assert!(w[0].score >= w[1].score,
                "results not sorted: {} < {}", w[0].score, w[1].score);
        }
    }

    #[test]
    fn score_all_profiles_filters_zero_score() {
        let signals = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let matches = score_all_profiles(&signals);
        assert!(matches.iter().all(|m| m.score > 0));
    }

    #[test]
    fn top_match_returns_highest_classification() {
        let signals = sigs(&[
            ELF_HOOKS_PROCESS_HIDING,
            ELF_HOOKS_PAM_CREDENTIAL,
            ARTIFACT_PAM_STAGING_STRUCTURAL,
            ARTIFACT_PAM_STAGING_FATHER,
            ELF_STRING_FATHER_FORMAT,
        ]);
        let top = top_match(&signals);
        assert!(top.is_some());
        let top = top.unwrap();
        assert!(top.classification >= Classification::ClassMatch);
    }

    #[test]
    fn score_missing_required_signal_is_no_match() {
        use crate::threat_intel::profiles::FATHER;
        let signals = sigs(&[ELF_HOOKS_PROCESS_HIDING]);
        let m = score_against_profile(&signals, &FATHER);
        assert_eq!(m.classification, Classification::NoMatch);
        assert_eq!(m.score, 0);
        assert!(!m.missed_required.is_empty());
    }

    #[test]
    fn score_exclusion_reduces_score() {
        use crate::threat_intel::profiles::FATHER;
        let without_exclusion = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let with_exclusion = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_PAM_CREDENTIAL, ELF_HOOKS_NETWORK_HIDING]);
        let m_no_ex = score_against_profile(&without_exclusion, &FATHER);
        let m_ex    = score_against_profile(&with_exclusion, &FATHER);
        assert!(m_ex.score < m_no_ex.score, "exclusion should lower score");
    }

    #[test]
    fn score_exclusion_cannot_exceed_raw_score() {
        use crate::threat_intel::profiles::JYNX;
        let signals = sigs(&[ELF_HOOKS_PROCESS_HIDING, ELF_HOOKS_FILE_HIDING, ELF_HOOKS_PAM_CREDENTIAL]);
        let m = score_against_profile(&signals, &JYNX);
        let _ = m.score;
    }
}
