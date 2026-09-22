//! Static [`InvestigativeTechnique`] instances and the
//! [`INVESTIGATIVE_TECHNIQUES`] slice.
//!
//! Each entry records an analytic framework as its ORIGINAL publication
//! states it — including the original's own scope and limits, which the
//! popular retellings routinely drop. A framework taught without its boundary
//! conditions becomes folklore: the ordering, the bands, or the axioms get
//! repeated with more confidence than the author ever claimed. The
//! `failure_modes` field is where each framework's own stated limits live,
//! because that is where the schema puts "conditions under which this yields
//! a confident wrong answer".
//!
//! Every entry cites the original published work (author, year in the doc
//! comment; durable link in `sources`) — never a training course or a
//! third-party retelling. `evidence_tier` grades how the entry's description
//! is established, and it is set honestly: a widely-repeated model that was
//! never empirically evaluated is recorded as such, not inflated because the
//! paper is famous.

use super::{InvestigativeTechnique, TechniqueStep};
use forensicnomicon_core::evidence::EvidenceTier;

/// The Pyramid of Pain: David J. Bianco, "The Pyramid of Pain", Enterprise
/// Detection & Response blog, first published 2013-03-01, revised 2014-01-17
/// (the revision added the Hash Values level).
///
/// # What the original actually claims
///
/// A diagram showing "the relationship between the types of indicators you
/// might use to detect an adversary's activities and how much pain it will
/// cause them when you are able to deny those indicators to them". Six
/// indicator types, cheapest-to-deny at the bottom: hash values, IP
/// addresses, domain names, network/host artifacts, tools, TTPs.
///
/// # Evidence status — the distinction retellings drop
///
/// The original presents the ordering as a conceptual model — "To illustrate
/// this concept, I have created what I like to call the Pyramid of Pain" —
/// argued from the author's practice with anecdotal examples (a recon tool's
/// distinctive User-Agent string; detecting pass-the-hash from Windows logs
/// rather than from tool signatures). It offers no measured adversary-cost
/// data for the ordering, and does not claim to. The entry's tier is
/// `SingleSecondary` for exactly that reason: one author's published model,
/// widely repeated, never empirically evaluated in the original.
pub static PYRAMID_OF_PAIN: InvestigativeTechnique = InvestigativeTechnique {
    id: "pyramid_of_pain_indicator_prioritisation",
    name: "Pyramid of Pain indicator prioritisation",
    question: "Which indicator types should detection and response be built on to impose the \
               most cost on this adversary when the indicators are denied to them?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Classify each indicator available for the intrusion set into one of the \
                     six pyramid types: hash values, IP addresses, domain names, network or \
                     host artifacts, tools, TTPs.",
            artifact_id: None,
            yields: "Indicators grouped by the cost the original argues their denial imposes: \
                     hashes trivial to change (any file modification), IPs easy, domains \
                     slightly harder (registration, payment, hosting, propagation delay), \
                     artifacts forcing tool reconfiguration or recompilation, tools forcing \
                     replacement, TTPs forcing the adversary to learn new behaviours.",
        },
        TechniqueStep {
            order: 2,
            action: "Assess, per level, whether current telemetry supports both DETECTING and \
                     RESPONDING there — TTP-level response needs behavioural visibility (the \
                     original's example: spotting pass-the-hash in Windows logs, not tool \
                     signatures), not just an indicator feed.",
            artifact_id: None,
            yields: "The highest pyramid level at which detection and response are feasible \
                     today, and the telemetry gaps blocking the levels above it.",
        },
        TechniqueStep {
            order: 3,
            action: "Build detection and response at the highest feasible level, keeping \
                     lower-level indicators as cheap short-lived coverage rather than the \
                     foundation.",
            artifact_id: None,
            yields: "Monitoring that forces the adversary to change behaviours rather than \
                     rotate infrastructure — per the original, denial across many TTPs leaves \
                     them the options 'give up' or 'reinvent themselves from scratch'.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The ranked quantity is the cost of DENYING an indicator to the adversary; imposing \
         that cost requires the capability to detect AND respond at the chosen level, not \
         merely to name it.",
        "Indicators are attributed to the adversary under investigation — the pain is \
         per-adversary, and denying another group's infrastructure imposes nothing on this \
         one.",
    ],
    failure_modes: &[
        "Treating the ordering as measured adversary-cost data. The original offers no \
         empirical evidence for it and does not claim to: it is an illustration argued from \
         practice. Asserting the ordering as established for every adversary — a \
         well-resourced group rotating custom tooling cheaply, a constrained one finding \
         domain rotation expensive — claims more than the source ever did.",
        "Applying the pyramid to an EVIDENTIAL question. It ranks the cost of denial for \
         detection-and-response prioritisation, not probative weight: a hash sits at the \
         bottom yet identifies a specific file bit-for-bit, which in an examination is \
         stronger identification evidence than a TTP match. Discounting low-level indicators \
         in an identification question misapplies a detection-economics model.",
        "Reading 'trivial to deny' as 'worthless to collect'. The original's own worked \
         example consumes APT1 hashes and IPs; its claim is that low-level indicators are \
         short-lived, not that they detect nothing. Discarding them entirely inverts the \
         model's advice.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &["https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html"],
};

/// Every registered investigative technique. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static INVESTIGATIVE_TECHNIQUES: &[InvestigativeTechnique] = &[PYRAMID_OF_PAIN];
