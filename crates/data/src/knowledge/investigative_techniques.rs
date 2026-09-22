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

/// The Diamond Model: Sergio Caltagirone, Andrew Pendergast, Christopher
/// Betz, "The Diamond Model of Intrusion Analysis", technical report, 2013
/// (DTIC accession ADA586960; author-hosted PDF at activeresponse.org).
///
/// # What the original actually claims — read from the paper
///
/// The atomic element is the EVENT: four edge-connected core features
/// (adversary, capability, infrastructure, victim) plus meta-features —
/// timestamp (start and end), phase, result, direction, methodology,
/// resources. Every feature, core or meta, carries a confidence value the
/// paper leaves "purposefully undefined as each model implementation may
/// understand confidence differently". Events chain into phase-ordered
/// activity threads, and threads coalesce into activity groups.
///
/// # The paper's own axioms and scope — the parts retellings drop
///
/// The model rests on seven explicitly numbered AXIOMS — assumptions stated
/// as such, not findings (Axiom 1: every intrusion event has an adversary
/// using a capability over infrastructure against a victim to produce a
/// result; Axiom 4: every malicious activity has two or more phases; Axiom
/// 6: an adversary-victim relationship always exists; Axiom 7 defines the
/// persistent-adversary sub-set). And the paper bounds itself twice: it
/// "does not present a new ontology, taxonomy, sharing format, or protocol",
/// and it "does not prescribe mitigation strategy or course of action
/// development" — it positions itself as complementary to the Kill Chain,
/// not a replacement for either.
pub static DIAMOND_MODEL: InvestigativeTechnique = InvestigativeTechnique {
    id: "diamond_model_intrusion_analysis",
    name: "Diamond Model of Intrusion Analysis",
    question: "How do I document intrusion events so that what is known, what is inferred, and \
               what is missing stay distinguishable while events are correlated into threads \
               and groups?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Decompose each intrusion event into the four core features — adversary, \
                     capability, infrastructure, victim — and the meta-features (timestamp \
                     start/end, phase, result, direction, methodology, resources), recording a \
                     confidence value on every feature.",
            artifact_id: None,
            yields: "A Diamond event whose empty vertices are explicit gaps rather than \
                     silent omissions.",
        },
        TechniqueStep {
            order: 2,
            action: "Pivot across connected features — from a known victim or capability \
                     toward the unknown infrastructure or adversary vertex — to generate \
                     leads, keeping each pivoted value tagged with its (lower) confidence.",
            artifact_id: None,
            yields: "Hypothesised feature values for the unobserved vertices, distinguishable \
                     from observed ones by their confidence.",
        },
        TechniqueStep {
            order: 3,
            action: "Link causally related events into phase-ordered activity threads (per \
                     Axiom 4, every malicious activity spans two or more phases executed in \
                     succession).",
            artifact_id: None,
            yields: "Activity threads exposing the phases where no event has been observed \
                     yet — the model's gap analysis.",
        },
        TechniqueStep {
            order: 4,
            action: "Coalesce events and threads that share feature values into activity \
                     groups for correlation and attribution.",
            artifact_id: None,
            yields: "Activity groups whose grouping criterion — WHICH shared features drove \
                     the grouping — is recorded and revisitable.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The paper's seven axioms hold for the activity under analysis; they are stated as \
         assumptions, not demonstrated findings, and every downstream construct (threads, \
         groups, gap analysis) inherits them.",
        "A confidence convention exists: the paper leaves the per-feature confidence value \
         'purposefully undefined', so an implementation that never defines one has no way to \
         keep observed and inferred features apart.",
    ],
    failure_modes: &[
        "Attributing from Type 2 infrastructure. The paper itself distinguishes Type 1 \
         (adversary-owned) from Type 2 (controlled by a witting or unwitting intermediary) \
         and warns that Type 2 'serves to obfuscate the origin and attribution of the \
         activity' and that 'the apparent target of activity may not necessarily be the \
         victim'. A pivot from Type 2 infrastructure to an adversary vertex, recorded as if \
         observed, is a confident wrong attribution.",
        "Recording pivoted inferences at observed-fact confidence. The per-feature confidence \
         value is the model's own device for keeping the two apart; retellings that reduce \
         the model to 'four vertices' drop it, and with it the distinction the model exists \
         to preserve.",
        "Treating the model as validated method rather than formalised practice: the paper \
         derives it from analyst experience and states its foundations as axioms. Grouping \
         built over an axiom that fails for the case at hand — e.g. commodity crimeware \
         where the shared 'capability' feature spans unrelated operators — succeeds \
         mechanically and misleads confidently.",
        "Using it for what it says it is not: the paper states it does not provide an \
         ontology, taxonomy or sharing format, and does not prescribe mitigation strategy or \
         courses of action.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &[
        "https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf",
        "https://apps.dtic.mil/sti/citations/ADA586960",
    ],
};

/// Every registered investigative technique. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static INVESTIGATIVE_TECHNIQUES: &[InvestigativeTechnique] = &[PYRAMID_OF_PAIN, DIAMOND_MODEL];
