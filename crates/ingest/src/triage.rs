//! Triage priority inference for generated artifact records.
//!
//! One ladder, used by every source adapter that has only an artifact *name*
//! and a *description* to go on (fa, kape, regedit, velociraptor).
//!
//! # Why one ladder and not a per-source keyword table
//!
//! The four adapters each grew their own Critical/High/Medium/Low ladder. The
//! keyword sets overlapped heavily and diverged arbitrarily: `lsass` was known
//! to fa and velociraptor but not to kape or regedit; `lateral` only to
//! regedit; `shimcache`/`appcompat`/`amcache` only to velociraptor;
//! `mft`/`lnk`/`shellbag` only to kape. No adapter documented a reason for its
//! own set, and the sets are not partitioned by anything a source *is* — a
//! KAPE target and a Velociraptor artifact describing the same LSASS dump are
//! the same artifact. The differences were accretion, not design, so a
//! per-source table would preserve an accident. Triage depends on the artifact
//! text; the adapter that happened to catalogue it is not evidence.
//!
//! The keyword lists below are the **union** of the four ladders' tiers, so no
//! source loses a signal it previously acted on.
//!
//! # The `High` ceiling
//!
//! Generated records cap at `High`. `Critical` is reserved for handwritten
//! descriptors, which also carry a curated `volatility` and
//! `evidence_strength`; `codegen::generate_static` emits `None` for both, so a
//! generated record can never carry the assessment that justifies `Critical`.
//! fa's ladder documented this rule already — the other three violated it.
//!
//! EVTX channels are triaged by [`crate::sources::evtx`] on the channel name
//! alone (no prose), which is a different input domain and keeps its own
//! mapping.

/// Keywords that place an artifact at `High` — credential access, execution
/// evidence, persistence, and lateral movement. Union of the `Critical` and
/// `High` tiers of the four ladders this replaced.
const HIGH_KEYWORDS: &[&str] = &[
    // credential access (was `Critical` in kape/regedit/velociraptor)
    "credential",
    "password",
    "lsass",
    "sam ",
    "ntds",
    "token",
    "privilege",
    // execution evidence
    "execution",
    "shimcache",
    "appcompat",
    "amcache",
    "prefetch",
    "mft",
    "lnk",
    "shellbag",
    // persistence
    "persistence",
    "run key",
    "startup",
    "service",
    "scheduled task",
    "autorun",
    // lateral movement / remote access
    "lateral",
    "proxy",
    // artifact families a source already treated as high-signal
    "registry",
    "event log",
    "shell",
];

/// Keywords that place an artifact at `Medium` — context-building material.
/// Union of the `Medium` tiers of the four ladders this replaced.
const MEDIUM_KEYWORDS: &[&str] = &[
    "browser", "history", "cookie", "download", "mru", "log", "event", "config", "settings",
];

/// Infer a triage priority from an artifact's name and description.
///
/// Returns a `TriagePriority` variant name. Never returns `"Critical"` — see
/// the module docs for the ceiling.
pub fn infer_triage(name: &str, description: &str) -> &'static str {
    let combined = format!("{name} {description}").to_ascii_lowercase();
    if HIGH_KEYWORDS.iter().any(|k| combined.contains(k)) {
        "High"
    } else if MEDIUM_KEYWORDS.iter().any(|k| combined.contains(k)) {
        "Medium"
    } else {
        "Low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_access_is_high_not_critical() {
        assert_eq!(
            infer_triage("Cached Domain Credentials", "credential material"),
            "High"
        );
        assert_eq!(infer_triage("LSASS", "dumps lsass memory"), "High");
        assert_eq!(
            infer_triage("NTDS", "Active Directory ntds.dit database"),
            "High"
        );
    }

    #[test]
    fn execution_and_persistence_are_high() {
        assert_eq!(
            infer_triage("Shimcache", "AppCompatCache execution evidence"),
            "High"
        );
        assert_eq!(infer_triage("Run", "run key autorun persistence"), "High");
        assert_eq!(infer_triage("Prefetch", ""), "High");
    }

    #[test]
    fn lateral_movement_is_high() {
        assert_eq!(
            infer_triage("PortProxy", "lateral movement indicator"),
            "High"
        );
    }

    #[test]
    fn context_artifacts_are_medium() {
        assert_eq!(infer_triage("Chrome History", "browser history"), "Medium");
        assert_eq!(infer_triage("RecentDocs", "mru list"), "Medium");
    }

    #[test]
    fn unrecognized_text_is_low() {
        assert_eq!(infer_triage("Wallpaper", "desktop background image"), "Low");
        assert_eq!(infer_triage("", ""), "Low");
    }

    #[test]
    fn high_wins_over_medium_when_both_match() {
        // "event log" (High) and "log"/"event" (Medium) both match; the High
        // tier is checked first so the more specific phrase decides.
        assert_eq!(infer_triage("Security", "event log channel"), "High");
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(infer_triage("LSASS PROCESS MEMORY", ""), "High");
        assert_eq!(infer_triage("Browser History", ""), "Medium");
    }

    #[test]
    fn no_keyword_is_listed_in_both_tiers() {
        for high in HIGH_KEYWORDS {
            assert!(
                !MEDIUM_KEYWORDS.contains(high),
                "'{high}' is in both tiers; its tier would depend on list order"
            );
        }
    }

    #[test]
    fn never_returns_critical() {
        // The ceiling holds for every keyword in every tier.
        for kw in HIGH_KEYWORDS.iter().chain(MEDIUM_KEYWORDS) {
            assert_ne!(
                infer_triage(kw, kw),
                "Critical",
                "'{kw}' broke the High ceiling"
            );
        }
    }
}
