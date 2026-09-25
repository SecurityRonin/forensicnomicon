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
//!
//! The examination-method batch (signature sweep, controlled negative search,
//! acquisition scope, logical-export selection rule, IP-to-subscriber
//! attribution, roaming IP interpretation, VPN/proxy egress, shared-account
//! hypothesis testing) is different in kind: these are procedures built in
//! casework, where the error each one prevents was first made and then
//! caught. Their mechanisms are cited to standards and measurement papers;
//! the procedures themselves are practice, and the tier says so.

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

/// Estimative probability language: ODNI, Intelligence Community Directive
/// 203, "Analytic Standards", signed January 2, 2015, as amended. The bands
/// below were read from the ODNI-served document itself, not a retelling.
///
/// # The published table, verbatim
///
/// "For expressions of likelihood or probability, an analytic product must
/// use one of the following sets of terms": almost no chance / remote
/// (01-05%), very unlikely / highly improbable (05-20%), unlikely /
/// improbable (improbably) (20-45%), roughly even chance / roughly even odds
/// (45-55%), likely / probable (probably) (55-80%), very likely / highly
/// probable (80-95%), almost certain(ly) / nearly certain (95-99%). As
/// printed, the scale runs 01% to 99% — expressions of certainty sit outside
/// it.
///
/// # The floating band this entry exists to pin down
///
/// The widely-circulated wider band for the middle term is real, and it is
/// Sherman Kent's, not ICD 203's: Kent's "Words of Estimative Probability"
/// (Studies in Intelligence, 1964; CIA Historical Review Program release)
/// charts "chances about even" as 50% give or take about 10% — 40-60% —
/// where the published standard says 45-55%. A reader calibrated to one
/// chart decoding a writer using the other silently shifts the claim, and a
/// band that floats between retellings defeats the one thing the scale is
/// for.
pub static ICD203_ESTIMATIVE_LANGUAGE: InvestigativeTechnique = InvestigativeTechnique {
    id: "icd203_estimative_probability_language",
    name: "ICD 203 estimative probability language",
    question: "How do I express the likelihood of an event so the reader decodes the words back \
               to the probability band I assessed — and no other?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Separate the two dimensions the standard keeps apart: the LIKELIHOOD of \
                     the event or development, and the analyst's CONFIDENCE in the basis for \
                     the judgment (logic, evidentiary base, source quantity and quality).",
            artifact_id: None,
            yields: "Each statement classified as a likelihood expression or a confidence \
                     expression, never a blend.",
        },
        TechniqueStep {
            order: 2,
            action: "Express likelihood using a term from ONE row of the published table: \
                     almost no chance / remote (01-05%), very unlikely / highly improbable \
                     (05-20%), unlikely / improbable (20-45%), roughly even chance / roughly \
                     even odds (45-55%), likely / probable (55-80%), very likely / highly \
                     probable (80-95%), almost certain(ly) / nearly certain (95-99%).",
            artifact_id: None,
            yields: "A verbal expression that carries its published percentage band with it.",
        },
        TechniqueStep {
            order: 3,
            action: "Keep confidence levels and likelihood terms out of the same sentence (the \
                     standard's own prohibition, 'to avoid confusion'), note the causes of \
                     uncertainty, and identify indicators that would alter the level of \
                     uncertainty.",
            artifact_id: None,
            yields: "A judgment a reader can decode back to a band and knows what would move \
                     it.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "Writer and reader are calibrated to the SAME published table. The word-to-band \
         mapping is a convention, not a property of the words: 'likely' carries 55-80% only \
         because ICD 203 says so.",
        "The directive governs analytic products of US Intelligence Community elements; \
         outside that scope the table binds only if adopted explicitly.",
    ],
    failure_modes: &[
        "Decoding against the wrong chart. The published band for 'roughly even chance' is \
         45-55%; the widely-circulated 40-60% is Sherman Kent's 1964 'chances about even' \
         (50% give or take about 10%), from the earlier chart the standard descends from. \
         Both parties are confident, both cite 'the' standard, and the claim silently \
         shifts by up to 5 points at each edge.",
        "Mixing terms from different rows. The standard strongly encourages against it and \
         requires a disclaimer where rows are mixed; unmarked mixing invites the reader to \
         hear a distinction between synonyms ('probable' vs 'likely') that the table says \
         does not exist.",
        "Combining a confidence level and a likelihood in one sentence — prohibited by the \
         standard because 'high confidence that X is likely' reads as a single stronger \
         claim than either dimension supports.",
        "Expressing likelihood in words the table does not contain. The standard's \
         requirement is 'must use one of the following sets of terms'; hedges like \
         'possible', 'may' or 'could' appear in neither row and therefore decode to no band \
         at all.",
    ],
    evidence_tier: EvidenceTier::VendorDocumented,
    mitre_techniques: &[],
    sources: &[
        "https://www.dni.gov/files/documents/ICD/ICD-203.pdf",
        "https://www.cia.gov/resources/csi/static/Words-of-Estimative-Probability.pdf",
    ],
};

/// Beaconing detection by interval regularity, and the discriminator the
/// literature does NOT contain.
///
/// # Sources actually read
///
/// - Hu, Jang, Stoecklin, Wang, Schales, Kirat & Rao, "BAYWATCH: Robust
///   Beaconing Detection to Identify Infected Hosts in Large-Scale
///   Enterprise Networks", IEEE/IFIP DSN 2016 (doi:10.1109/DSN.2016.50).
///   The full text is paywalled; the claims drawn from it here are
///   ABSTRACT-level only, verified on the authors' employer's publication
///   page: beaconing "is also employed by legitimate applications (such as
///   updates checks)", and the method is "an 8-step filtering approach to
///   iteratively refine and eliminate legitimate beaconing traffic".
/// - RITA (Active Countermeasures), read from source: the beacon score in
///   `analysis/beacons.go` is a weighted combination of interval regularity
///   (skew, median absolute deviation), data-size consistency, a 24-hour
///   coverage histogram and duration — every input a property of the
///   connection pair's own regularity, none of intent. The benign/malicious
///   separation lives OUTSIDE the score, in documented modifiers keyed to
///   context: prevalence (how many internal hosts contact the destination)
///   raises or lowers the threat score, and threat-intel hits override the
///   category.
///
/// # The finding the lead asked for
///
/// The literature holds a real tension — regularity is the malice signal in
/// one framing and benign background (update checks, pollers) in the other —
/// and in the treatments verified here, NO published discriminator separates
/// the two cases from the interval statistics alone. Both treatments resolve
/// it exogenously: BAYWATCH by iteratively filtering known-legitimate
/// periodic traffic, RITA by destination prevalence and intel context. That
/// absence is recorded as a failure mode below, because an analyst told "low
/// jitter means malware" has been handed a discriminator that does not
/// exist.
pub static BEACONING_INTERVAL_REGULARITY: InvestigativeTechnique = InvestigativeTechnique {
    id: "beaconing_interval_regularity_triage",
    name: "Beaconing triage by communication-interval regularity",
    question: "Which of this network's regular communicators warrant investigation as possible \
               command-and-control callbacks?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Collect per source-destination pair connection timestamps over a long \
                     window and derive the interval series. Regularity statistics need a \
                     floor of data: RITA's scorer refuses pairs with fewer than 4 timestamps \
                     or fewer than 3 non-zero intervals.",
            artifact_id: None,
            yields: "An interval (and payload-size) distribution per communicating pair.",
        },
        TechniqueStep {
            order: 2,
            action: "Score each pair's REGULARITY: interval dispersion (skew, median absolute \
                     deviation), data-size consistency, temporal coverage across the window \
                     (RITA's timestamp/data-size/histogram/duration subscores; BAYWATCH's \
                     periodicity analysis).",
            artifact_id: None,
            yields: "A ranked list of regular communicators — candidates, in which benign \
                     pollers and C2 callbacks are still mixed.",
        },
        TechniqueStep {
            order: 3,
            action: "Separate benign from suspect candidates using context EXOGENOUS to the \
                     intervals: destination prevalence inside the network, allowlisting or \
                     iterative filtering of known-legitimate periodic services, domain age \
                     and threat intelligence.",
            artifact_id: None,
            yields: "The shortlist an examiner investigates — produced by the context layer, \
                     not by the regularity score.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "A long observation window with enough events per pair to make interval statistics \
         meaningful (BAYWATCH: long-term temporal analysis at several granularities; RITA: \
         at least 4 timestamps and 3 non-zero intervals).",
        "The callback pattern is periodic enough, within the window, to surface — the \
         BAYWATCH abstract itself notes malware authors 'employ various strategies to hide \
         beaconing behavior'.",
    ],
    failure_modes: &[
        "Reading regularity as malice. The BAYWATCH abstract states the opposite in terms — \
         beaconing 'is also employed by legitimate applications (such as updates checks)' — \
         and RITA's score inputs are regularity properties only, so NTP, update pollers and \
         mail checkers score exactly like disciplined C2. The score ranks candidates; it \
         cannot classify intent.",
        "Believing an interval-statistics discriminator exists. In the treatments verified \
         here, none is published: BAYWATCH separates the cases by iteratively eliminating \
         legitimate periodic traffic, RITA by prevalence and threat-intel modifiers applied \
         after the timing score. A confident 'this jitter profile is malicious' asserts a \
         discriminator the sources do not contain.",
        "Reading absence from the candidate list as absence of C2. A callback jittered or \
         slowed past the window's statistics never becomes a candidate; the ranking is over \
         what beaconed detectably, not over what communicated.",
        "Trusting the popularity heuristic structurally. RITA's documented prevalence \
         modifier DECREASES the score of destinations many internal hosts contact — which \
         equally down-scores C2 fronted by a widely-used cloud service. 'Popular therefore \
         benign' is a tuning heuristic in the published config, not a property of the \
         traffic.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[
        "T1071", // Application Layer Protocol (C2 channels this triage surfaces)
    ],
    sources: &[
        "https://doi.org/10.1109/DSN.2016.50",
        "https://research.ibm.com/publications/baywatch-robust-beaconing-detection-to-identify-infected-hosts-in-large-scale-enterprise-networks",
        "https://github.com/activecm/rita/blob/main/analysis/beacons.go",
        "https://github.com/activecm/rita/blob/main/docs/Configuration.md",
    ],
};

/// Wi-Fi BSSID geolocation via a Wi-Fi Positioning System (WPS).
///
/// # Sources actually read
///
/// - iSniff-GPS (hubert3), README and `iSniff_GPS/wloc.py` (code-read): the
///   `QueryBSSID()` function POSTs to `https://gs-loc.apple.com/clls/wloc`
///   and parses the protobuf response, scaling the returned integer
///   latitude/longitude by `pow(10, -8)` (`lat = wifi.location.latitude *
///   pow(10,-8)`), and "will return the coordinates of the MAC queried for
///   and usually an additional 400 nearby BSSIDs and their coordinates". A
///   companion `wigle_api.py` queries wigle.net for an SSID.
/// - Rye & Levin, "Surveilling the Masses with Wi-Fi-Based Positioning
///   Systems", IEEE S&P 2024 (arXiv:2405.14975): Apple's API, queried with a
///   BSSID, returns that BSSID's location PLUS up to several hundred nearby
///   BSSIDs Apple knows about; it returns a sentinel of -180 (an invalid
///   coordinate) for a BSSID it cannot locate; Google's API instead requires
///   at least two BSSIDs and returns only a computed client position.
/// - Google Maps Platform Geolocation API docs: keyed service taking
///   `wifiAccessPoints` (each a `macAddress`) and returning a position.
///
/// # What this establishes, and what it does not
///
/// A WPS turns an access-point BSSID into physical coordinates. The BSSIDs
/// come from the device's own network artifacts — the per-network AP list in
/// `macos_wifi_known_networks` and the `RouterHardwareAddress` in
/// `macos_dhcp_leases`. It locates the ACCESS POINT, not the device: the
/// device may merely have passed near an AP, or have a cloud-synced
/// known-network entry it never joined. Those limits live in the failure
/// modes below, because an analyst told "the BSSID geolocates to X" has been
/// handed the AP's location, not the device's.
pub static WIFI_BSSID_GEOLOCATION: InvestigativeTechnique = InvestigativeTechnique {
    id: "wifi_bssid_geolocation",
    name: "Wi-Fi BSSID geolocation via a positioning system",
    question: "Where is the physical location of a remembered Wi-Fi access point, given its \
               BSSID from a device's network artifacts, using a Wi-Fi Positioning System such as \
               Apple's gs-loc.apple.com service, Google's Geolocation API, or WiGLE?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Extract candidate BSSIDs from the device: the per-network access-point \
                     BSSID list in the remembered-networks store (the LEAKY_AP_BSSID key of \
                     com.apple.wifi.known-networks.plist, and the legacy airport preferences), \
                     and the RouterHardwareAddress recorded in each DHCP lease plist.",
            artifact_id: Some("macos_wifi_known_networks"),
            yields: "A set of access-point MAC addresses (BSSIDs) the device recorded, each a \
                     geolocation handle, with any join/lease timestamps attached.",
        },
        TechniqueStep {
            order: 2,
            action: "Submit each BSSID to a Wi-Fi Positioning System: Apple's \
                     https://gs-loc.apple.com/clls/wloc (unauthenticated; returns the queried \
                     BSSID's latitude/longitude as integers scaled by 10^-8, plus up to several \
                     hundred neighbouring APs), Google's Geolocation API (API key required, \
                     needs at least two BSSIDs and returns only a computed position), or the \
                     WiGLE crowdsourced wardriving database (keyed).",
            artifact_id: None,
            yields: "Coordinates for each BSSID the provider knows, and a sentinel for those it \
                     does not.",
        },
        TechniqueStep {
            order: 3,
            action: "Filter Apple's -180 sentinel (returned for a BSSID it cannot locate), treat \
                     a real returned position as the ACCESS POINT's location, then corroborate \
                     against the join/added timestamps (macos_wifi_known_networks) and the lease \
                     start time (macos_dhcp_leases) to place the device in time.",
            artifact_id: Some("macos_dhcp_leases"),
            yields: "Located access points with a time context, keeping WHERE the device was \
                     distinct from WHERE it merely remembered a network.",
        },
    ],
    artifacts_used: &["macos_wifi_known_networks", "macos_dhcp_leases"],
    preconditions: &[
        "The BSSID is one a WPS has already observed. A never-wardriven access point (a new or \
         private home router unseen by Apple/Google/WiGLE) resolves to nothing, and absence of a \
         hit is not evidence the AP does not exist.",
        "The recorded BSSID is the real access-point hardware address. Client MAC randomization \
         (macOS/iOS 14+) changes the device's own association MAC, not the AP BSSID; but a MAC \
         captured from a device acting as a personal hotspot can be ephemeral and geolocate to \
         wherever that hotspot last was.",
    ],
    failure_modes: &[
        "Reading the AP's location as the device's current position. A WPS places the ACCESS \
         POINT, not the device: the device can remember an AP it merely passed near, and a \
         cloud-synced known-network entry (AddReason \"Cloud Sync\") was never joined on this \
         device at all. The coordinate answers 'where is this network', not 'where was this \
         device'.",
        "Treating -180 as a coordinate. Apple's service returns latitude/longitude of -180 — an \
         invalid value — for a BSSID it has no record of; parsed as a number rather than a \
         sentinel it plots a false point off Antarctica and manufactures a location that was \
         never returned.",
        "Forgetting that the query itself discloses the BSSID to the provider. Submitting a \
         subject's remembered BSSIDs to Apple, Google or WiGLE tells that provider which \
         networks are of interest, and Apple's endpoint returns hundreds of NEARBY APs per query \
         (Rye & Levin), a disclosure with its own privacy and operational-security cost.",
        "Trusting a single crowdsourced or dated hit. WiGLE coverage is uneven and ages; an AP \
         that moved — a replaced router, a mobile hotspot, transit Wi-Fi — resolves to a stale \
         or meaningless location, so a lone hit is a lead to corroborate, not a fix.",
        "Dating an access point from the remembered-network store. A BSSIDList entry holds only \
         LEAKY_AP_BSSID and an opaque LEAKY_AP_LEARNED_DATA blob, with no per-BSSID timestamp or \
         channel (observed on a Big Sur 11.7 image), so the network's timestamps date the SSID, \
         not a particular AP, and a BSSID listed under two SSIDs cannot be dated per SSID. And \
         on a network migrated from the legacy airport store at the Big Sur upgrade, AddedAt can \
         repeat the legacy last-join time rather than record a first join; use ChannelHistory \
         and the legacy .backup record instead.",
        "Assuming the position is contemporary. The service returns a position with no date of \
         observation (iSniff-GPS's wloc.py reads only latitude and longitude), so when the AP \
         was seen there is undisclosed: a router moved to new premises geolocates to where it is \
         now, not to where the device met it.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://github.com/hubert3/iSniff-GPS",
        "https://github.com/hubert3/iSniff-GPS/blob/master/iSniff_GPS/wloc.py",
        "https://arxiv.org/abs/2405.14975",
        "https://developers.google.com/maps/documentation/geolocation/overview",
        "https://api.wigle.net/",
    ],
};

/// Reconstructing a macOS host's network / peer neighbourhood from a dead disk.
///
/// # Sources actually read
///
/// - osxripper `plugins/osx/BluetoothPlist.py` (code-read): parses
///   `/Library/Preferences/com.apple.Bluetooth.plist`, iterating the
///   `PairedDevices` array and the `DeviceCache` dict (keyed by device MAC,
///   each entry carrying a Name and LMP / page-scan attributes).
/// - Kinga Kieczkowska, "AirDrop Forensics 2" (2020): for an AirDropped file
///   the `LSQuarantineEvent` row has `LSQuarantineAgentName = 'sharingd'` and
///   `LSQuarantineSenderName` populated with the sending device's name; the
///   quarantine database outlasts the unified-log AirDrop trail (observed to
///   persist only ~a week).
/// - mac4n6 and Eclectic Light on SharedFileList stores: RecentHosts /
///   RecentServers / FavoriteVolumes under
///   `~/Library/Application Support/com.apple.sharedfilelist/`, NSKeyedArchiver
///   bookmarks, entries undated.
///
/// # What this establishes, and what it does not
///
/// A powered-off Mac's disk retains only the PERSISTED residue of past peer
/// interactions — remembered access points and router, mounted-share and
/// connect-to-server history, Bluetooth pairings and seen devices, and AirDrop
/// sender names. The live layer that a running host would show — the ARP /
/// neighbour table and the mDNS / Bonjour responder cache — is in memory and is
/// lost at power-off. Every recovered identifier is a user-assigned label or a
/// spoofable address, not a verified owner. Those limits live in the failure
/// modes, because an analyst told "these were the Mac's neighbours" has been
/// handed a historical, partial, label-based picture.
pub static NETWORK_NEIGHBOUR_ENUMERATION: InvestigativeTechnique = InvestigativeTechnique {
    id: "network_neighbour_enumeration",
    name: "Network-neighbour / peer-device enumeration from a dead macOS disk",
    question:
        "Which networks, remote shares and peer devices did this Mac interact with, as far as \
               a powered-off disk image can show?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Enumerate the network side: the remembered Wi-Fi access points and their \
                     BSSIDs (macos_wifi_known_networks), and the internal IP / gateway / gateway \
                     MAC / joined SSID from each DHCP lease (macos_dhcp_leases) — placing the Mac \
                     on named networks over time.",
            artifact_id: Some("macos_wifi_known_networks"),
            yields: "The access points and LAN segments the Mac joined, with join / lease times.",
        },
        TechniqueStep {
            order: 2,
            action:
                "Enumerate the remote-share side: the hosts entered into Connect-to-Server and \
                     the favourite network volumes (macos_connect_to_server_history), the servers \
                     actually mounted (macos_sfl2_recent_servers), and the SMB / NetBIOS name the \
                     Mac itself advertised to neighbours (macos_smb_server_identity).",
            artifact_id: Some("macos_connect_to_server_history"),
            yields: "The remote file servers this Mac reached, and the name it presented to peers \
                     — one side keyed to correlate against a peer's own share-access logs.",
        },
        TechniqueStep {
            order: 3,
            action:
                "Enumerate the peer-device side: the bonded and seen Bluetooth devices by name \
                     and MAC (macos_bluetooth_devices), and the AirDrop sender names recorded in \
                     the quarantine database (LSQuarantineSenderName where the agent is sharingd, \
                     macos_bluetooth_devices' AirDrop sibling) alongside the unified-log AirDrop \
                     trail while it survives.",
            artifact_id: Some("macos_bluetooth_devices"),
            yields:
                "Named peripherals and AirDrop peers seen beside the Mac, each a user-assigned \
                     label rather than a verified owner.",
        },
    ],
    artifacts_used: &[
        "macos_bluetooth_devices",
        "macos_smb_server_identity",
        "macos_connect_to_server_history",
        "macos_wifi_known_networks",
        "macos_dhcp_leases",
    ],
    preconditions: &[
        "The examination is of a dead disk image; this technique reconstructs PERSISTED past \
         interactions, not the live network state.",
        "The stores exist and were not cleared: SFL lists are process-gated and undated, the \
         Bluetooth cache is not pruned on unpair, and the quarantine database persists longer than \
         the unified-log AirDrop trail.",
    ],
    failure_modes: &[
        "Reading the reconstruction as the LIVE neighbourhood. A powered-off disk shows only \
         persisted residue; the live ARP / neighbour table and the mDNS / Bonjour responder cache \
         are in-memory and lost at power-off, so present-tense neighbours are simply absent — an \
         absence that is the acquisition method's, not the network's.",
        "Treating a recorded name as a verified owner. Bluetooth DeviceCache Names, the AirDrop \
         LSQuarantineSenderName and Connect-to-Server host labels are user-assigned strings; a MAC \
         or BSSID is spoofable and, under randomization, ephemeral. They identify a label, not a \
         person.",
        "Reading DeviceCache presence as pairing, or a RecentHosts entry as a successful mount. \
         DeviceCache holds devices merely SEEN nearby (the PairedDevices array is the bonded set), \
         and RecentHosts records hosts ENTERED, not necessarily mounted (RecentServers is the \
         mounted record).",
        "Dating the picture from the artifacts. SFL entries are undated (only the file mtime \
         bounds them) and can be extremely old; the quarantine timestamp is a Cocoa epoch needing \
         +978307200. Assigning a time from an undated store manufactures precision the source does \
         not carry.",
        "Dating an access point from BSSIDList. Remembered-network BSSIDList entries hold only \
         LEAKY_AP_BSSID and an opaque LEAKY_AP_LEARNED_DATA blob, with no per-BSSID timestamp or \
         channel (observed on a Big Sur 11.7 image): when a given AP was used, or under which \
         SSID when one BSSID sits under two networks, cannot be read from these stores.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &["T1016"],
    sources: &[
        "https://github.com/bolodev/osxripper/blob/master/plugins/osx/BluetoothPlist.py",
        "https://kieczkowska.wordpress.com/2020/06/29/airdrop-forensics-2/",
        "https://www.mac4n6.com/blog/2017/10/17/script-update-for-macmrupy-v13-new-1013-sfl2-mru-files",
        "https://eclecticlight.co/2017/08/10/recent-items-launch-services-and-sharedfilelists/",
    ],
};

/// Dating when a Mac was on a given Wi-Fi network, and bridging networks
/// through printers reached over mDNS.
///
/// # Sources actually read
///
/// - Apple, "Generating log messages from your code": dynamic strings are
///   redacted by default, which is the general `<private>` behaviour the
///   Broadcom driver entries do not show.
/// - Mandiant macos-UnifiedLogs, `unifiedlog_iterator` (code-read): `Mode`
///   is a clap `ValueEnum` of `Live`, `LogArchive`, `SingleFile`, hence
///   `-m log-archive`.
/// - RFC 6762 section 3 (".local." names are link-local, "meaningful only on
///   the link where they originate"), RFC 8011 section 5.3.7 (job-state 9 is
///   'completed'), RFC 9562 section 5.1 (a UUIDv1 node field is an IEEE 802
///   MAC address).
/// - Apple bootp `IPConfiguration.bproj/ipconfigd.c` (code-read): the
///   `"%@: SSID %@ BSSID %@ Security %s"` log line that names the network
///   the driver's BSSIDs belong to (see `macos_wifi_ssid_unified_log`).
/// - An Apple Community post (Sierra) showing the `RSNSupplicant: Releasing
///   authenticator for` wifi.log line, and a 2016 blog listing daily
///   `wifi.log.N.bz2` archives.
///
/// # Evidence status
///
/// The load-bearing step, the driver entries' plain-text BSSIDs in the
/// unified log, is observed on one Big Sur 11.7 image and no public source
/// was found (see `macos_wifi_driver_log`). One capture is below the two
/// independent captures `SourceOrMultiImpl` requires, so the entry is graded
/// `SingleSecondary`, the weakest load-bearing link, although the mDNS, IPP
/// and UUID facts it rests on are specification-documented.
pub static WIFI_PRESENCE_TIMELINE: InvestigativeTechnique = InvestigativeTechnique {
    id: "wifi_presence_timeline",
    name: "Wi-Fi presence timeline: when was the Mac on network X",
    question: "On which days was this Mac associated with a given Wi-Fi network (and so, with \
               geolocation, where was it), and can networks that cannot be geolocated be tied \
               to ones that can?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Export /private/var/db/diagnostics/ and /private/var/db/uuidtext/ into one \
                     logarchive directory, parse it with Mandiant's unifiedlog_iterator \
                     -m log-archive, and keep process /kernel entries prefixed ARPT: \
                     (SetCryptoKey ea[<BSSID>], 'Roamed or switched channel ... bssid <BSSID>'); \
                     these carry BSSIDs only. Normalise every BSSID octet to two hex digits. Run the control first: the Mac's own Wi-Fi MAC \
                     (macos_network_interfaces) must appear in plain text.",
            artifact_id: Some("macos_wifi_driver_log"),
            yields: "Timestamped BSSIDs from the driver, verified unredacted on this image.",
        },
        TechniqueStep {
            order: 2,
            action: "From the same export, keep the userland entries naming the network: \
                     /usr/libexec/configd subsystem com.apple.IPConfiguration ('<if>: SSID <name> \
                     BSSID <bssid> Security ...', which pairs name and access point), configd \
                     subsystem com.apple.captive, and sharingd/rapportd subsystem \
                     com.apple.CoreUtils ('SysMon: WiFi join started: SSID \"<name>\"'). Check \
                     for <redacted>, which later IPConfiguration writes by default.",
            artifact_id: Some("macos_wifi_ssid_unified_log"),
            yields: "Timestamped network names, and SSID-to-BSSID pairs that name the driver's \
                     access points.",
        },
        TechniqueStep {
            order: 3,
            action: "Aggregate per day: the set of BSSIDs and SSIDs seen each day, with first \
                     and last entry times.",
            artifact_id: None,
            yields: "A day-by-day record of which access points and networks the Mac was \
                     associated with, over the unified log's retention window.",
        },
        TechniqueStep {
            order: 4,
            action: "Add /private/var/log/wifi.log and its wifi.log.N.bz2 archives: \
                     'RSNSupplicant: Releasing authenticator for <BSSID>' lines mark the end of \
                     an association with that AP, and driver (re)initialisation lines \
                     (_bsdDriver_init) mark boots to check against the audit trail \
                     (macos_openbsm_audit). Supply the year and zone, which the lines lack.",
            artifact_id: Some("macos_wifi_log"),
            yields: "Independent per-BSSID dates over wifi.log's own retention, and boot \
                     corroboration.",
        },
        TechniqueStep {
            order: 5,
            action: "Name the networks and extend the window: map BSSIDs to SSIDs through the \
                     remembered-network store (BSSIDList, undated) and DHCP leases, read \
                     ChannelHistory and join times for earlier periods, and geolocate the \
                     BSSIDs (wifi_bssid_geolocation).",
            artifact_id: Some("macos_wifi_known_networks"),
            yields: "Which network each dated BSSID belongs to and, where a positioning system \
                     knows it, where that access point is.",
        },
        TechniqueStep {
            order: 6,
            action: "Bridge networks through printers: read each dnssd://....local./?uuid= \
                     queue in printers.conf, then the spool control files' job-printer-uri, \
                     job-state (9 = completed), time-at-creation and time-at-completed. A \
                     completed job places the printer on the Mac's local network at completion \
                     time; the same printer uuid completed while the Mac was on two different \
                     networks ties the printer, and plausibly the premises, to both.",
            artifact_id: Some("macos_cups_spool_jobs"),
            yields: "Dated LAN co-presence with identified printers, linking a network that \
                     cannot be geolocated to one that can.",
        },
    ],
    artifacts_used: &[
        "macos_wifi_driver_log",
        "macos_wifi_ssid_unified_log",
        "macos_unified_log",
        "fa_file__7",
        "macos_wifi_log",
        "macos_openbsm_audit",
        "macos_network_interfaces",
        "macos_wifi_known_networks",
        "macos_wifi_plist_backup",
        "macos_dhcp_leases",
        "macos_cups_printers_conf",
        "macos_cups_spool_jobs",
    ],
    preconditions: &[
        "The unified log and wifi.log still cover the period in question; both keep only weeks.",
        "The driver entries are unredacted on this image, shown by the control in step 1.",
    ],
    failure_modes: &[
        "Reading the retention edge as the start of presence. The unified log and wifi.log each \
         keep only weeks; before the oldest retained entry there is no record either way.",
        "Skipping the control. The plain-text driver entries were observed on one Big Sur 11.7 \
         image with a Broadcom chip; on another release or Wi-Fi chip they may be redacted or \
         worded differently, and a search that cannot match the Mac's own MAC measures the \
         instrument, not the network history.",
        "Missing a BSSID written unpadded (a:b:...) when searching for the padded form \
         (0a:0b:...), and so reporting a day without association that had one.",
        "Treating the remembered-network store as complete. It keeps only networks not removed \
         by the user; a forgotten network leaves no record there, only in the logs while they \
         last.",
        "Reading AddedAt as a first join. On a network migrated from the legacy airport store at \
         the Big Sur upgrade, AddedAt repeats the legacy last-join time.",
        "Assuming the geolocated position is contemporary. The WPS position date is \
         undisclosed, so an access point that has moved places the Mac at the AP's current \
         home.",
        "Reading a stable network as a stable place. A router and the device can move together \
         (a travel router, a phone hotspot, a household that relocates with its router), so \
         the same BSSID on two dates does not prove the same location.",
        "Treating a printer as a fixed place. A .local. printer can be moved, and an mDNS \
         reflector or Bonjour gateway extends .local. beyond one link; a shared printer uuid \
         links two networks only while the printer stayed put, and a print job identifies \
         reachability, not the operator.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &["T1016"],
    sources: &[
        "https://developer.apple.com/documentation/os/generating-log-messages-from-your-code",
        "https://github.com/mandiant/macos-UnifiedLogs/blob/main/examples/unifiedlog_iterator/src/main.rs",
        "https://github.com/apple-oss-distributions/bootp/blob/bootp-413.80.1/IPConfiguration.bproj/ipconfigd.c",
        "https://discussions.apple.com/thread/7957554",
        "https://blog.frd.mn/disable-wifi-debug-logging/",
        "https://www.rfc-editor.org/rfc/rfc6762#section-3",
        "https://www.rfc-editor.org/rfc/rfc8011#section-5.3.7",
        "https://www.rfc-editor.org/rfc/rfc9562#section-5.1",
    ],
};

/// Whole-volume file-signature sweep as the first step of a device
/// examination, before any record-by-record or checklist pass.
///
/// # Sources actually read
///
/// - NIST SP 800-86 §4.3: "analysts should not assume that file extensions
///   are accurate"; the file header's signature "identifies the type of data
///   that particular file contains" (FF D8 for JPEG in the worked figure).
/// - POSIX `open()`: "If O_NONBLOCK is clear, an open() for reading-only
///   shall block the calling thread until a thread opens the file for
///   writing" - the reason a recursive content read hangs on a FIFO.
///
/// # Basis for the ordering
///
/// Practice, not a standard: the ordering was adopted after a
/// database-by-database examination marked note records "attachment only"
/// and never opened the attachments, which turned out to be the most
/// identity-relevant content on the disk. The sweep is what finds content
/// no parser was pointed at.
pub static WHOLE_VOLUME_SIGNATURE_SWEEP: InvestigativeTechnique = InvestigativeTechnique {
    id: "whole_volume_signature_sweep",
    name: "Whole-volume file-signature sweep before record analysis",
    question: "What user content does this volume actually hold - images, documents, \
               archives - regardless of which application databases reference it or what \
               the files are named?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Walk every regular file on the read-only mounted volume (stat first; \
                     skip FIFOs, sockets and device nodes, and count them) and classify each \
                     by magic bytes, not extension: JPEG, PNG, GIF, HEIC/HEIF (ftyp brand), \
                     TIFF, WebP, PDF, RTF; OLE2 split by stream name; ZIP split by internal \
                     structure (OOXML, ODF, EPUB, iWork, plain zip); package directories as \
                     units. Count unreadable files as their own category.",
            artifact_id: None,
            yields: "A census of every content file by true type, with the unreadable and \
                     special-file counts that bound it.",
        },
        TechniqueStep {
            order: 2,
            action: "Group the census by location to separate software artwork (application \
                     bundles, framework resources, browser and thumbnail caches) from \
                     user-area content, resolving symlinks and de-duplicating by inode so \
                     sandbox containers are not counted twice.",
            artifact_id: None,
            yields: "A short list of user-area content, usually a small fraction of the \
                     total, with its paths.",
        },
        TechniqueStep {
            order: 3,
            action: "Recurse into every container - plain zips included, and images embedded \
                     in documents and PDFs - and filter template decoration by name pattern \
                     rather than by discarding the container.",
            artifact_id: None,
            yields: "Content nested inside archives and documents, listed alongside \
                     top-level files.",
        },
        TechniqueStep {
            order: 4,
            action: "Map application attachments to their parent records, then actually view \
                     the images (contact sheets) and read the document text. Any record \
                     labelled 'attachment only', 'empty', 'encrypted' or 'did not decode' is \
                     an open lead to follow to its payload.",
            artifact_id: None,
            yields: "Findings about content, and a list of leads closed or still open.",
        },
        TechniqueStep {
            order: 5,
            action: "Only then write negatives, scoped to what was swept, viewed and read, \
                     and stating the unreadable and skipped counts.",
            artifact_id: None,
            yields: "Negative findings with a stated scope instead of an implied universal.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The volume is mounted read-only (or read through a parser) with the user-data \
         volume actually mounted: a system-only mount makes the user area look empty.",
        "The classifier recognises the formats in scope. A classifier that knows only \
         office-zip structures and drops everything else silently loses plain zip archives.",
    ],
    failure_modes: &[
        "Record-first examination: a note, message or mail row labelled 'attachment only' or \
         'empty' is written up as having no content, when the attachment file on disk is the \
         evidence. The label is a lead, not a finding.",
        "The walk hangs on a FIFO (a mail-spool or daemon pipe): open() for reading blocks \
         until a writer appears, the sweep stalls with no error, and a partial census gets \
         reported as complete. Guard with stat and S_ISREG before opening.",
        "Encrypted or unparsable files are counted as empty (see the pdftotext behaviour): \
         the documents someone chose to protect fall out of the review.",
        "Counting all image files on the volume as user content: most images on a desktop \
         OS are application artwork and cache entries, and a raw count overstates user \
         activity by orders of magnitude.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &[
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
        "https://pubs.opengroup.org/onlinepubs/9699919799/functions/open.html",
    ],
};

/// A negative search ("X is not in this container") run with positive
/// controls, anchored patterns and every near-miss explained.
///
/// # Sources actually read
///
/// - NIST CFTT Forensic String Searching Tool Requirements Specification
///   (draft 1, 2008): SS-BR-01 "The response returned by a query is equal to
///   the match set for the query"; SS-BR-02 the tool "shall search using one
///   or more specified character representations" - a search is only as
///   complete as the representations and patterns it was given.
/// - NIST SP 800-86 §4.3 on extensions and headers (names do not establish
///   type).
///
/// # Basis
///
/// Practice: each failure mode below was made and caught on a real file
/// listing (a wrong path separator returning zero, a hive-name grep matching
/// thousands of `System32` substrings, app-named files that were phone
/// screenshots).
pub static CONTROLLED_NEGATIVE_SEARCH: InvestigativeTechnique = InvestigativeTechnique {
    id: "controlled_negative_search",
    name: "Controlled negative search with positive control",
    question: "Is artefact X genuinely absent from this listing or container, or did my \
               search fail to find it?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Write the full synonym set for the artefact (for Windows registry \
                     hives: SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat, \
                     RegBack copies, .LOG1/.LOG2 transaction logs) and express each as an \
                     anchored exact-path or exact-name pattern using the listing's own path \
                     separator.",
            artifact_id: None,
            yields: "Patterns that match the artefact and not substrings of other names.",
        },
        TechniqueStep {
            order: 2,
            action: "Run a positive control in the SAME listing with the SAME tool: patterns \
                     for things certain to be present (the parent folders of the target, or \
                     a known sibling file). A zero on the control means the instrument is \
                     broken, not that the listing is empty.",
            artifact_id: None,
            yields: "Proof that the search can return hits on this data.",
        },
        TechniqueStep {
            order: 3,
            action: "Examine every near-miss hit and classify it by path: substring matches, \
                     files named after an application that are not its data (screenshots \
                     named after the foreground app inside a phone backup), and look-alike \
                     assets.",
            artifact_id: None,
            yields: "Each hit explained as the artefact or as a documented false match.",
        },
        TechniqueStep {
            order: 4,
            action: "State the negative scoped to the container searched, naming the \
                     patterns, the control results and what the container could not hold.",
            artifact_id: None,
            yields: "A negative finding bounded by its own search, reproducible by another \
                     examiner.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The listing is complete for the container (files and directories counted \
         separately and reconciled to the container's own totals).",
        "The search runs over the text the listing actually contains: paths decoded in the \
         right character set and extracted without line-wrapping or truncation.",
    ],
    failure_modes: &[
        "Wrong path separator: a pattern written with backslashes against a listing that \
         uses forward slashes returns zero, and the zero is reported as absence.",
        "Unanchored substring patterns: a search for a hive name matches every path \
         containing it as a substring (SYSTEM inside System32), and a count of thousands is \
         reported as presence.",
        "Name is not content: files named after an application are counted as that \
         application's data when they are something else (screenshots, exports, installers) \
         sitting in an unrelated folder.",
        "Scope creep: a negative established over a logical export or a filtered listing is \
         written as a statement about the device.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &[
        "https://www.nist.gov/system/files/documents/2017/05/09/ss-req-sc-draft-v1_0.pdf",
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
    ],
};

/// Establishing what a production actually is - a full physical image, a
/// partial image, or a logical collection - before relying on it.
///
/// # Sources actually read
///
/// - NIST SP 800-86 §4.2.1: a logical backup "copies the directories and
///   files of a logical volume. It does not capture other data that may be
///   present on the media, such as deleted files or residual data stored in
///   slack space"; bit stream imaging "generates a bit-for-bit copy of the
///   original media, including free space and slack space". §4.2 lists
///   the Host Protected Area among places data hides.
/// - NIST SP 800-101r1 §3.1: mobile acquisition levels - logical extraction
///   (level 2) captures "logical storage objects (e.g., directories and
///   files)"; physical methods (levels 3-5) copy the physical store, which is
///   what exposes deleted objects and unallocated space.
/// - libewf EWF format documentation: the EnCase Logical Evidence File
///   (LVF, EWF-L01) is stored in the EWF format but holds selected files,
///   not a media image; the volume section records bytes per sector and the
///   sector count.
pub static ACQUISITION_SCOPE_VERIFICATION: InvestigativeTechnique = InvestigativeTechnique {
    id: "acquisition_scope_verification",
    name: "Acquisition scope verification",
    question: "Is what was produced a complete physical image of the device, or something \
               less - and what can it therefore not contain?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Separate the two questions: container FORMAT (E01/Ex01, AFF4, raw, \
                     L01/Lx01, AD1, a zip of files) and acquisition SCOPE (physical, \
                     partition, logical, targeted). An E01 can hold a physical image; an \
                     L01 in the same EWF family holds selected files only.",
            artifact_id: None,
            yields: "The format and the claimed scope, as two recorded facts.",
        },
        TechniqueStep {
            order: 2,
            action: "Compare the image's sector count x bytes per sector (from the container \
                     header or imaging log) with the device's capacity from its make, model \
                     and label. A shortfall points to an incomplete image, a partition-only \
                     image, or an HPA/DCO region not captured.",
            artifact_id: None,
            yields: "Whether the image geometry matches a whole physical device.",
        },
        TechniqueStep {
            order: 3,
            action: "Record encryption state (full-disk or volume encryption, and whether a \
                     key or decrypted image was supplied) and, for mobile devices, the \
                     extraction type as the tool named it (logical, full file system, \
                     physical) and whether an agent was installed on the device.",
            artifact_id: None,
            yields: "What the image can decrypt and what the extraction method could reach.",
        },
        TechniqueStep {
            order: 4,
            action: "List the artefact classes the scope excludes (unallocated and slack, \
                     deleted records, volume shadow copies and snapshots, file-system \
                     metadata such as $MFT, logs and registry hives if not selected) and \
                     carry that list into every negative finding.",
            artifact_id: None,
            yields: "A scope statement that bounds every later 'not found'.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The device's make, model, serial and capacity are known independently of the \
         imaging log (label, seizure record or photograph).",
    ],
    failure_modes: &[
        "Treating the container format as the scope: 'it is an E01, so it is a full image' \
         when the file is a logical L01/Lx01 or a partition image in the same family.",
        "Trusting a folder or exhibit label ('Full Image') over the container's own \
         structure and sector count.",
        "Treating a mobile 'full file system' extraction as equivalent to a physical image \
         of a computer disk: it excludes unallocated space and many deleted records.",
        "Treating an extraction report's hashes as proof of coverage: a hash over the \
         produced files proves they are unchanged since hashing, not that they are all the \
         device held.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf",
        "https://raw.githubusercontent.com/libyal/libewf/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc",
    ],
};

/// Inferring the rule that selected the files in a logical export (L01,
/// AD1, a zip of collected files) from what it contains.
///
/// # Sources actually read
///
/// - libewf EWF documentation: EWF-L01 (LVF) holds a selection of logical
///   files with their metadata, not the media.
/// - NIST SP 800-86 §4.2.1: a logical copy does not capture deleted files or
///   residual data.
///
/// # Basis
///
/// Practice: the census below distinguished an extension whitelist from a
/// privilege filter on a real production whose folder was labelled as a
/// full image. The method is generic to any logical collection; it is not a
/// statement about any one tool's export options.
pub static LOGICAL_EXPORT_SELECTION_RULE_INFERENCE: InvestigativeTechnique =
    InvestigativeTechnique {
        id: "logical_export_selection_rule_inference",
        name: "Logical export selection-rule inference",
        question: "What rule decided which files went into this logical collection, and \
                   what does that rule guarantee is missing?",
        steps: &[
            TechniqueStep {
                order: 1,
                action: "Enumerate every entry in the container; count files and directories \
                         separately and reconcile both to the container's own totals.",
                artifact_id: None,
                yields: "A complete, reconciled entry list.",
            },
            TechniqueStep {
                order: 2,
                action: "Count files per extension across the whole container and check the \
                         per-extension counts sum to the file total; sum bytes per top-level \
                         folder.",
                artifact_id: None,
                yields: "The extension distribution. A small closed set (documents, images, \
                         archives only) is the signature of an extension whitelist.",
            },
            TechniqueStep {
                order: 3,
                action: "Inspect an operating-system folder inside the export. Under an \
                         extension whitelist it holds only files that happen to match \
                         (icons, logos, document templates) and no binaries, hives or logs; \
                         under a content-based filter (privilege, keyword, custodian) \
                         non-matching system files would remain.",
                artifact_id: None,
                yields: "A test between a type-based and a content-based selection rule.",
            },
            TechniqueStep {
                order: 4,
                action: "State the rule inferred and list the artefact classes it excludes by \
                         construction (event logs, registry hives, file-system metadata, \
                         execution artefacts), leading with the ones the examination \
                         question needs.",
                artifact_id: None,
                yields: "A scope statement explaining which questions the export cannot \
                         answer.",
            },
        ],
        artifacts_used: &[],
        preconditions: &[
            "The container was read completely by a reader that verified it (stored hash \
             checked); a reader that aborts partway yields a partial census.",
        ],
        failure_modes: &[
            "Reading an extension whitelist as a privilege or relevance filter, or the \
             reverse, from the export's label instead of its contents.",
            "Conflating files with entries: directory entries inflate the total and the \
             per-extension counts then fail to reconcile.",
            "Treating absence from the export as absence from the device: a whitelist drops \
             whole application folders that held no whitelisted file type.",
        ],
        evidence_tier: EvidenceTier::SingleSecondary,
        mitre_techniques: &[],
        sources: &[
            "https://raw.githubusercontent.com/libyal/libewf/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc",
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
        ],
    };

/// Tracing a logged public IP address to a subscriber, including behind
/// carrier-grade NAT.
///
/// # Sources actually read
///
/// - RFC 6888 §2 (BCP 127): a CGN is "used to share the same IPv4 address
///   among several subscribers".
/// - RFC 6598: 100.64.0.0/10 is the Shared Address Space for CGN.
/// - RFC 6269 §13.1 (Informational): "IPv4 address X has done something bad
///   at time T0. This is not enough information to uniquely identify the
///   subscriber responsible for the abuse when that IPv4 address is shared by
///   more than one subscriber."
/// - RFC 7620 §10.2 (Informational, Independent Submission; weight it
///   accordingly): cellular operators assign private addresses and NAT them,
///   so "there is no correlation between the internal IP address and the
///   external address:port assigned by the NAT function".
/// - MaxMind geolocation accuracy: GeoIP data "is never precise enough to
///   identify or locate a specific household, individual, or street address".
/// - RIPEstat announced-prefixes: what an AS actually announces, as distinct
///   from what is registered to it.
pub static IP_ADDRESS_SUBSCRIBER_ATTRIBUTION: InvestigativeTechnique = InvestigativeTechnique {
    id: "ip_address_subscriber_attribution",
    name: "IP address to subscriber attribution (including CGN)",
    question: "Which subscriber line held this public IP address when the logged activity \
               happened - and can that be established at all?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "From the service's own logs, establish exactly what was recorded: the \
                     event and what it means (login, upload, page view), the timestamp with \
                     its UTC offset and clock-sync status, the public source IP and SOURCE \
                     PORT, and whether the logged address is the client or a proxy or \
                     load-balancer value (X-Forwarded-For).",
            artifact_id: None,
            yields: "An (IP, port, protocol, UTC instant) tuple and its reliability.",
        },
        TechniqueStep {
            order: 2,
            action: "Identify the holder and routing of the address at that instant: RIR \
                     registration (whois, parsed per object), the prefix actually announced \
                     and by which AS (RIPEstat or BGP archives for historic dates), and \
                     whether the range is CGN or mobile (shared address space, operator \
                     disclosure of port blocks).",
            artifact_id: None,
            yields: "The operator to ask, and whether address-only attribution is even \
                     possible.",
        },
        TechniqueStep {
            order: 3,
            action: "Obtain the operator's records: subscriber assignment at the instant \
                     (lease start and end, static or dynamic), the operator's time zone, and \
                     under CGN the translation log keyed by public IP, public port and time.",
            artifact_id: None,
            yields: "The subscriber account that held the tuple, or a documented reason it \
                     cannot be resolved.",
        },
        TechniqueStep {
            order: 4,
            action: "Corroborate on the device only what the device can show: its private \
                     address, gateway, DHCP lease, known networks, VPN or proxy clients, and \
                     application artefacts matching the logged event. A device image rarely \
                     holds its own public IP.",
            artifact_id: None,
            yields: "Consistency or inconsistency between the subscriber finding and the \
                     device.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The service log, the operator's records and the device evidence are three \
         different custodians' records; each must be obtained, and none substitutes for \
         another.",
        "All timestamps are normalised to UTC with their original offsets recorded; a \
         one-hour zone or DST error can select a different subscriber.",
    ],
    failure_modes: &[
        "Attributing a CGN address from IP and time alone: without the source port (and \
         the operator's translation log) the address was shared by many subscribers at that \
         instant, and naming one of them is a guess.",
        "Treating registration as location or routing: whois says who holds a range; a \
         geolocation database gives a probabilistic area, never a household; and a prefix \
         registered to one operator can be announced by another.",
        "Clock and zone error: an unsynchronised server clock or a mis-read offset moves \
         the instant into another lease and another subscriber.",
        "Ending at a person: the chain terminates at a subscriber account or line, never a \
         person; who used the connection is a separate question the network records do not \
         answer.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://www.rfc-editor.org/rfc/rfc6888.txt",
        "https://www.rfc-editor.org/rfc/rfc6598.txt",
        "https://www.rfc-editor.org/rfc/rfc6269.txt",
        "https://www.rfc-editor.org/rfc/rfc7620.txt",
        "https://support.maxmind.com/hc/en-us/articles/4407630607131-Geolocation-Accuracy",
        "https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes",
    ],
};

/// Interpreting the public IP address of a mobile device that may have been
/// roaming.
///
/// # Sources actually read
///
/// - RFC 7445 §2.1.1: in home-routed mode "the subscriber's UE gets IP
///   addresses from the home network. All traffic belonging to that UE is
///   therefore routed to the home network"; §2.1.2: in local breakout "IP
///   addresses are assigned by the visited network".
/// - 3GPP TS 23.401 (ETSI TS 123 401 v19.6.0) §5.3.1.1: "a) The HPLMN
///   allocates the IP address to the UE when the default bearer is
///   activated ... b) The VPLMN allocates the IP address".
/// - Mandalari et al., "Experience: Implications of Roaming in Europe",
///   MobiCom 2018: names three configurations - home-routed (HR), local
///   breakout (LBO) and IPX hub breakout (IHBO); "HR was used by all 16 MNOs"
///   measured; roaming added "latency penalties of ~60 ms or more, depending
///   on geographical distance". European measurements only.
/// - 3GPP TS 32.298 (ETSI TS 132 298 v18.8.0): charging records carry
///   `servingNodePLMNIdentifier`, `userLocationInformation` and `rATType`,
///   separate from the address the gateway assigned.
pub static MOBILE_ROAMING_IP_INTERPRETATION: InvestigativeTechnique = InvestigativeTechnique {
    id: "mobile_roaming_ip_interpretation",
    name: "Mobile roaming IP interpretation",
    question: "Does a home-country mobile IP address show the device was in its home \
               country, or could it have been roaming abroad?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Identify the roaming mode in force for that SIM, APN/DNN and date. In \
                     home-routed roaming the home network assigns the address and all \
                     traffic exits at the home operator's gateway; in local breakout the \
                     visited network assigns it; in IPX hub breakout traffic exits at an \
                     inter-operator hub that may be in neither country.",
            artifact_id: None,
            yields: "Which network's address space the device would present under each mode.",
        },
        TechniqueStep {
            order: 2,
            action: "Request the operator's charging and session records for the instant: \
                     serving network (servingNodePLMNIdentifier), user location \
                     information, radio access type, APN/DNN, the assigned address, gateway \
                     identity and NAT logs, with the records' time source.",
            artifact_id: None,
            yields: "The serving (location) side and the egress (address) side as separate \
                     facts.",
        },
        TechniqueStep {
            order: 3,
            action: "If latency is argued, compute the penalty as a path difference - \
                     home-routed path minus local-breakout path to the same server - not as \
                     an absolute round-trip time.",
            artifact_id: None,
            yields: "A latency figure tied to the actual endpoints, or a statement that it \
                     cannot discriminate.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The operator's configuration for that subscriber and date is obtainable; \
         prevalence studies establish what is common, not what applied.",
    ],
    failure_modes: &[
        "Reading a home-operator IP as presence in the home country: under home-routed \
         roaming a SIM abroad presents exactly that address.",
        "Assuming a binary: home-routed versus local breakout omits IPX hub breakout, whose \
         exit can be in a third country.",
        "Generalising prevalence: the measurements showing home routing as near-universal \
         are largely European and several share authors; they establish capability and \
         common practice, not the configuration of a given operator.",
        "Treating absolute round-trip time as the roaming penalty, which confounds server \
         distance with the roaming detour.",
        "Treating the records as identifying a user: they identify the SIM and its session.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://www.rfc-editor.org/rfc/rfc7445.txt",
        "https://www.etsi.org/deliver/etsi_ts/123400_123499/123401/19.06.00_60/ts_123401v190600p.pdf",
        "https://vaibhavbajpai.com/documents/papers/proceedings/roaming-mobicom-2018.pdf",
        "https://www.etsi.org/deliver/etsi_ts/132200_132299/132298/18.08.00_60/ts_132298v180800p.pdf",
    ],
};

/// Classifying a logged egress address as a commercial VPN exit, a
/// residential or mobile proxy, or an ordinary subscriber connection.
///
/// # Sources actually read
///
/// - RFC 4301 §5.1.2 (tunnel mode): "The outer IP header Source Address and
///   Destination Address identify the 'endpoints' of the tunnel" - a service
///   behind a VPN logs the exit.
/// - Khan et al., "An Empirical Analysis of the Commercial VPN Ecosystem",
///   IMC 2018: vantage points on "well-known hosting providers like Digital
///   Ocean, LeaseWeb and Softlayer", "easy to blacklist and block".
/// - Mi et al., "Resident Evil: Understanding Residential IP Proxy as a Dark
///   Service", IEEE S&P 2019: 6 million residential proxy IPs across 230+
///   countries and 52K+ ISPs, with only 2.20% found in public blacklists.
/// - MaxMind Anonymous IP database documentation: classifies VPN, hosting and
///   residential-proxy addresses as separate categories.
pub static VPN_AND_RESIDENTIAL_PROXY_EGRESS_CLASSIFICATION: InvestigativeTechnique =
    InvestigativeTechnique {
        id: "vpn_and_residential_proxy_egress_classification",
        name: "VPN and residential-proxy egress classification",
        question: "Does the logged address show a VPN or proxy was - or was not - in use?",
        steps: &[
            TechniqueStep {
                order: 1,
                action: "Classify the address's network at the material date: hosting or \
                         data-centre ASN, fixed-line ISP, or mobile operator, using registry \
                         and routing data plus a dated IP-intelligence classification.",
                artifact_id: None,
                yields: "The network class of the egress address.",
            },
            TechniqueStep {
                order: 2,
                action: "Test the address against the published relay lists of mainstream \
                         VPN providers as at the material date, recording the list, its \
                         retrieval date and its size.",
                artifact_id: None,
                yields: "A positive match, or a bounded non-match against named lists.",
            },
            TechniqueStep {
                order: 3,
                action: "Look for VPN or proxy use on the device and in session evidence \
                         (clients installed, tunnel interfaces, configuration, logs \
                         overlapping the instant), since network-side classification cannot \
                         settle it.",
                artifact_id: None,
                yields: "Device-side evidence for or against tunnelling at the instant.",
            },
        ],
        artifacts_used: &[],
        preconditions: &[
            "Classifications and relay lists are dated to the material time; both change \
             continuously.",
        ],
        failure_modes: &[
            "Concluding 'no VPN or proxy' from a mobile-operator or residential address: \
             residential and mobile proxy networks relay through genuine subscriber \
             addresses, are rarely blacklisted, and cannot be enumerated.",
            "Treating absence from published VPN lists as exclusion: lists are incomplete \
             and change, and self-hosted VPNs terminating on a home or mobile line never \
             appear on them.",
            "Ignoring the ordinary alternatives: the VPN was off, disconnected, or split \
             tunnelling excluded the application whose log is being read.",
            "Treating a hosting-ASN address as proof of a particular person's VPN use: one \
             exit serves many users.",
        ],
        evidence_tier: EvidenceTier::SourceOrMultiImpl,
        mitre_techniques: &["T1090"],
        sources: &[
            "https://www.rfc-editor.org/rfc/rfc4301.txt",
            "https://dspace.networks.imdea.org/bitstream/handle/20.500.12761/619/imc18-final198.pdf",
            "https://conferences.computer.org/sp/pdfs/sp/2019/ResidentEvilUnderstandingResidentialIPProxyasa.pdf",
            "https://dev.maxmind.com/geoip/docs/databases/anonymous-ip/",
        ],
    };

/// Testing one-person, several-account and shared-account hypotheses
/// against a device, instead of asserting exclusive or shared use.
///
/// # Sources actually read
///
/// - ENFSI Guideline for Evaluative Reporting in Forensic Science (2015):
///   "The findings should be evaluated given at least one pair of
///   propositions ... If no alternative can be formulated, the value of the
///   findings cannot be assessed."
/// - Microsoft, "Security identifiers": a SID identifies a "security
///   principal", which "can represent any entity that the operating system
///   can authenticate" - an account, not a human.
///
/// # Basis
///
/// Practice: the three-hypothesis frame and the layer list were built in
/// casework and tested by an adversarial reviewer, which is where the
/// account-is-not-a-person point was independently confirmed. A
/// single-local-account machine later showed several online identities over
/// its lifetime, overturning an early "single user" reading.
pub static SHARED_ACCOUNT_HYPOTHESIS_TESTING: InvestigativeTechnique = InvestigativeTechnique {
    id: "shared_account_hypothesis_testing",
    name: "Shared-account hypothesis testing",
    question: "Was this device or account used by one person exclusively, by several people \
               with separate accounts, or by several people through one account?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Frame at least three hypotheses: H1 one human, one account; H2 several \
                     humans with separate accounts; H3 several humans sharing one account or \
                     session (at once or one after another).",
            artifact_id: None,
            yields: "Competing propositions against which each finding is weighed.",
        },
        TechniqueStep {
            order: 2,
            action: "Examine the layers from determinable to inferential, each with a \
                     current and a historical sub-layer: local accounts; deleted accounts; \
                     several identities inside one account (online accounts, autofill \
                     identities, input languages, paired phones, activity at incompatible \
                     times); remote logons; authenticated remote resources; peripherals and \
                     networks; content and provenance multiplicity; historical states \
                     (snapshots, shadow copies); concealment residue.",
            artifact_id: None,
            yields: "Per layer and per hypothesis: expected, found, absent, unavailable, or \
                     excluded by acquisition scope.",
        },
        TechniqueStep {
            order: 3,
            action: "Weigh concurrency and physical impossibility highest (two activities at \
                     once, activity while a person is shown elsewhere), then identity \
                     multiplicity inside one account, then content multiplicity.",
            artifact_id: None,
            yields: "The hypotheses the evidence supports, weakens or cannot separate.",
        },
        TechniqueStep {
            order: 4,
            action: "Keep association (whose content and accounts the device holds) separate \
                     from attribution (who operated it at a given instant), and word the \
                     conclusion at the level reached, e.g. 'use by X is established; \
                     exclusive use is not'.",
            artifact_id: None,
            yields: "A conclusion that does not promote an account-level finding to a \
                     person-level one.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The acquisition scope is known (see acquisition_scope_verification): a logical \
         export or short-retention source cannot show the layers it excludes, and those \
         cells must be marked excluded by acquisition scope rather than absent.",
    ],
    failure_modes: &[
        "Counting accounts as people: one local account can carry several online identities \
         used by different people, and several accounts can belong to one person.",
        "Reading an artefact as attributing to a human: logons, profiles and SIDs attribute \
         to a security context; who sat at the keyboard is a further inference.",
        "Treating absence of multi-user traces as proof of exclusive use: absence in a \
         filtered, short-retention or logical source says nothing about the device, and \
         even on a full image it shows only that sharing left no trace.",
        "Forcing a binary: testing only 'exclusive' against 'shared' drops H3, the case a \
         single-account machine most often presents.",
        "Treating content multiplicity (other people's documents or photos) as proof of \
         other users: it is consistent with shared use and equally with received or synced \
         content.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &[
        "https://enfsi.eu/wp-content/uploads/2016/09/m1_guideline.pdf",
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers",
    ],
};

// ── Evidence handling (EWF/L01/AD1) and Windows attribution ─────────────────
//
// The techniques below come from one class of problem: evidence arrives as a
// container (E01, L01, AD1), and the question is who used a Windows machine or
// a removable device. Their failure modes are where a container, a hash or an
// artefact is made to carry a claim it cannot support. Where the method rests
// on observation in casework rather than a published source, the tier says so.

/// Establishing who acquired an image, with what, when, and whether it is a
/// whole-device physical image — from the evidence itself.
///
/// The EWF header values (case number, examiner, acquisition and system
/// dates, software version, media type, "is physical", sector geometry,
/// stored hashes) are documented in libewf's EWF specification and printed
/// by ewfinfo; FTK Imager's User Guide documents the Evidence Item
/// Information `.txt` and directory-listing `.csv` it writes beside an image.
pub static ACQUISITION_PROVENANCE_FROM_EVIDENCE: InvestigativeTechnique = InvestigativeTechnique {
    id: "acquisition_provenance_from_evidence",
    name: "Acquisition provenance from the evidence container and its sidecars",
    question:
        "Who acquired this image, with what tool and version, when, and is it a whole-device \
               physical image or a logical export?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Run ewfinfo on the first segment and record the header values: case and \
                     evidence number, examiner, notes, acquisition and system dates, acquiry \
                     software and version, format, media type and 'is physical', bytes per \
                     sector and sector count, and the stored MD5/SHA-1.",
            artifact_id: None,
            yields: "The acquiring tool's own record of the acquisition, including media size \
                     (sector count x bytes per sector).",
        },
        TechniqueStep {
            order: 2,
            action: "Read every sidecar beside the image: FTK Imager's '<image>.E01.txt' or \
                     '<image>.ad1.txt' (examiner, drive model and serial, acquisition start and \
                     finish, computed hashes, and for AD1 the Custom Content Sources lines naming \
                     the source image and partition) and '.csv' listings; search the container \
                     for embedded tool reports and verification logs.",
            artifact_id: None,
            yields: "Operator, device identity (model, hardware serial) and hashes stated \
                     independently of any witness statement, and whether a logical export was \
                     cut from a physical image.",
        },
        TechniqueStep {
            order: 3,
            action: "Compare the media size with the seized device's capacity and the container \
                     dates (segment modification times, acquisition dates) with the imaging \
                     dates in witness statements.",
            artifact_id: None,
            yields: "Whether the image covers the whole device, and which act (imaging, later \
                     export, copying) each date belongs to.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "All segment files of the set are present and readable (see \
         working_copy_integrity_before_findings).",
    ],
    failure_modes: &[
        "Copying a production drive rewrites file modification times, so segment mtimes can \
         reflect the copy rather than the acquisition; corroborate from the header's own dates.",
        "A size mismatch between the image and the device's nominal capacity can reflect an \
         incomplete image, a host-protected area or device configuration overlay, or only the \
         difference between marketed and addressable capacity; do not report it as \
         incompleteness without the sector count of the source.",
        "OCR of a printed log clips build numbers and serials; read the native text file.",
        "Initials or an examiner field can name an operator who has given no statement: record \
         the attribution as coming from the sidecar, and do not extend that operator to other \
         devices without their own records.",
        "Reporting 'no acquisition hash' because a witness statement omits it, when the hash sits \
         in the container header or a sidecar.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://github.com/libyal/libewf/tree/main/documentation",
        "https://github.com/libyal/libewf/blob/main/manuals/ewfinfo.1",
        "https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf",
    ],
};

/// What interval each hash in a custody chain covers.
///
/// NIST SP 800-86 §3.1.2 describes hashing the original media before and
/// after imaging and comparing it with the copy's digest; a hash stored in
/// an EWF container is computed over the acquired data at acquisition
/// (libewf documentation), and FTK Imager's Verify compares a recomputed
/// hash with that stored value (FTK Imager User Guide).
pub static EVIDENCE_HASH_SCOPE: InvestigativeTechnique = InvestigativeTechnique {
    id: "evidence_hash_scope",
    name: "Scope of each hash in the custody chain",
    question: "What interval does each available hash actually cover, and is any part of the \
               chain from seizure to examination unhashed?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "List every hash available: the acquisition hash stored in the container, \
                     any hash of the source device taken at seizure or before imaging, hashes of \
                     files, archives or discs produced later, and tool extraction-list hashes.",
            artifact_id: None,
            yields: "An inventory of hashes with what each was computed over and when.",
        },
        TechniqueStep {
            order: 2,
            action: "Classify each: a stored acquisition hash re-verified (ewfverify, FTK Imager \
                     Verify) proves the image equals itself since acquisition; a source-device \
                     hash taken at seizure bridges seizure to imaging; file or disc hashes prove \
                     the output of a later extraction; an extraction list's hashes prove only \
                     self-consistency.",
            artifact_id: None,
            yields: "The interval each hash bridges.",
        },
        TechniqueStep {
            order: 3,
            action: "Mark any interval no hash covers, typically seizure to imaging, and list \
                     the events recorded inside it (power-on, boot, connection).",
            artifact_id: None,
            yields: "The unhashed intervals, stated as such.",
        },
    ],
    artifacts_used: &[],
    preconditions: &[
        "The container, its sidecars and any embedded tool logs have been searched for hashes \
         before any hash is reported absent.",
    ],
    failure_modes: &[
        "Reading a successful verify as proof the device was unchanged at seizure: it proves the \
         image matches its own acquisition hash, and nothing about the interval between seizure \
         and imaging.",
        "Reporting 'no hash' when one sits in the container header, an embedded report or a \
         sidecar; the absence belongs to the witness statement that omits it, not to the \
         evidence.",
        "Treating a later file or archive hash as an acquisition hash; it covers only what was \
         extracted and when.",
        "Reading a zero-filled stored hash as a mismatch (see \
         ftk_imager_verify_unstored_hash_mismatch).",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &[],
    sources: &[
        "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
        "https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1",
        "https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf",
    ],
};

/// Inferring the rule that selected the files in a logical container.
///
/// Logical containers hold what was selected (FTK Imager User Guide: Custom
/// Content Images built by selection, wildcard search or owner SID). The
/// extension-set inference is a casework method, not a published one; its
/// tier reflects that.
pub static LOGICAL_EXPORT_SELECTION_RULE: InvestigativeTechnique = InvestigativeTechnique {
    id: "logical_export_selection_rule",
    name: "Inferring a logical export's selection rule",
    question: "What rule selected the files in this logical container, and what can it therefore \
               not contain?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Enumerate every entry of an integrity-checked container, counting files and \
                     directories separately.",
            artifact_id: None,
            yields: "A complete listing and its totals.",
        },
        TechniqueStep {
            order: 2,
            action: "Tabulate the distinct file extensions and their counts.",
            artifact_id: None,
            yields: "The extension set.",
        },
        TechniqueStep {
            order: 3,
            action: "Test candidate rules against it: a small closed set of document and media \
                     types indicates a type whitelist; a privilege or relevance filter would keep \
                     unrelated system files of retained types; an owner-SID selection keeps \
                     files of every type under one owner.",
            artifact_id: None,
            yields: "The selection rule most consistent with the listing.",
        },
        TechniqueStep {
            order: 4,
            action: "State what the rule excludes: under a document whitelist, registry hives, \
                     event logs, $MFT and $UsnJrnl, Amcache, SRUM and Prefetch are absent by \
                     construction.",
            artifact_id: None,
            yields: "A scoped list of what the container cannot answer.",
        },
    ],
    artifacts_used: &[],
    preconditions: &["The container's own integrity check (for an L01, the ltree MD5) passed."],
    failure_modes: &[
        "Under an extension whitelist a folder appears only if it held a selected file, so a \
         folder or account (for example a messenger account folder) missing from the export may \
         still exist on the device.",
        "Production labels such as 'Full Image' describe the producer's intent, not the \
         container; read the container.",
        "Stating that only N of something existed when the export reproduces N: the export \
         reproduces N, the device may hold more.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &[
        "https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf",
        "https://github.com/libyal/libewf/tree/main/documentation",
    ],
};

/// Scoped negatives with positive controls, and mapping each finding to the
/// artefact it needs.
///
/// Where the Windows hive files live is documented by Microsoft ("Registry
/// Hives": most supporting files in %SystemRoot%\System32\Config). The
/// method of pairing every negative with a positive control is casework
/// practice; its tier reflects that.
pub static CONTAINER_SCOPE_REPRODUCIBILITY_CHECK: InvestigativeTechnique = InvestigativeTechnique {
    id: "container_scope_reproducibility_check",
    name: "Scoped negatives and finding-to-source reproducibility",
    question: "Does this container hold the artefacts a stated finding depends on, and is a \
               negative search result a fact about the device or only about this container?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "Map each finding to its source artefact: install date to SOFTWARE \
                     InstallDate, last logon and logon count to the SAM F record, the account \
                     table to SAM and ProfileList, logon history to Security.evtx, file history to \
                     $MFT and $UsnJrnl, messenger account counts to the account folders.",
            artifact_id: Some("sam_user_f_record"),
            yields: "The artefact each finding needs.",
        },
        TechniqueStep {
            order: 2,
            action: "Search the container for each artefact by every name it can take (SAM, \
                     SOFTWARE, SYSTEM, SECURITY, NTUSER.DAT, UsrClass.dat, System32\\config, \
                     RegBack, .LOG1/.LOG2, .evtx), and run a positive control in the same query \
                     (paths certain to exist, such as Windows, System32, Users).",
            artifact_id: None,
            yields: "For each artefact: present, or absent with a control proving the search \
                     could have found it.",
        },
        TechniqueStep {
            order: 3,
            action: "Explain every hit that is not the artefact (a file named 'config' that is an \
                     image), then state each negative scoped to the container.",
            artifact_id: None,
            yields: "Negatives worded as 'not in this container', and the findings the container \
                     cannot reproduce.",
        },
    ],
    artifacts_used: &[
        "sam_users",
        "sam_user_f_record",
        "windows_install_date",
        "profile_list_users",
        "evtx_security",
        "mft_file",
        "usnjrnl",
        "wechat_windows_files",
    ],
    preconditions: &["The enumeration of the container is complete and integrity-checked."],
    failure_modes: &[
        "A negative with no positive control measures the search, not the container: a wrong \
         path separator, case or encoding returns zero just as absence does.",
        "Scoping a negative to the device when it holds only for the container: a logical export \
         missing the SAM says nothing about whether the device had one.",
        "Counting a false-positive hit (an unrelated file sharing a hive's name) as the artefact.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &[],
    sources: &["https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives"],
};

/// Verifying every working copy before findings are drawn from it.
///
/// ewfverify recomputes and compares the stored digest; ewfexport's export
/// loop stops with "unexpected end of data" when the segment data ends short
/// of the declared media size (export_handle.c).
pub static WORKING_COPY_INTEGRITY_BEFORE_FINDINGS: InvestigativeTechnique =
    InvestigativeTechnique {
        id: "working_copy_integrity_before_findings",
        name: "Verify working copies before findings, and re-query negatives after repair",
        question:
            "Is the copy I am reading the evidence, and do findings drawn from an earlier copy \
               still hold?",
        steps: &[
            TechniqueStep {
                order: 1,
                action: "Run ewfverify over the full segment set of each working copy and require \
                     the stored and calculated MD5 to match over the whole declared media size.",
                artifact_id: None,
                yields: "A verified copy, or a failed one.",
            },
            TechniqueStep {
                order: 2,
                action: "Check that any raw export's size equals the declared media size.",
                artifact_id: None,
                yields: "Whether the export is complete.",
            },
            TechniqueStep {
                order: 3,
                action: "After any repair or re-copy, re-verify, re-extract, and re-query the \
                     data-bearing artefacts, comparing each value with what was recorded before.",
                artifact_id: None,
                yields: "Findings confirmed on the verified copy, or corrected.",
            },
            TechniqueStep {
                order: 4,
                action: "Re-examine every negative finding drawn from an unverified copy.",
                artifact_id: None,
                yields: "Negatives that hold on the verified copy.",
            },
        ],
        artifacts_used: &[],
        preconditions: &["The original segment set is available to re-copy from."],
        failure_modes: &[
            "Zero-padding a short export to the declared size lets it attach and parse, but the \
         missing region reads as zeros, which looks exactly like absence; padding is not repair.",
            "Trusting a wrapper script's exit status over the inner tool's: a wrapper can report \
         success around a failed export.",
            "Inferring that a value read from an old, unverified copy is correct because the new \
         copy's hash verifies; re-read it from the verified copy.",
            "A short raw export hides any partition that runs past its end.",
        ],
        evidence_tier: EvidenceTier::SourceOrMultiImpl,
        mitre_techniques: &[],
        sources: &[
            "https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1",
            "https://github.com/libyal/libewf/blob/main/manuals/ewfexport.1",
            "https://github.com/libyal/libewf/blob/20231119/ewftools/export_handle.c",
        ],
    };

/// Correlating a seized removable device with host computers by serial.
///
/// The host-side join keys are documented per descriptor; the 1006 event's
/// Vbr0 snapshot and the per-file-system volume-serial offsets are from
/// ElcomSoft (2026) and agree with the exFAT specification's
/// VolumeSerialNumber offset (100).
pub static USB_EXHIBIT_HOST_CORRELATION: InvestigativeTechnique = InvestigativeTechnique {
    id: "usb_exhibit_host_correlation",
    name: "USB exhibit to host correlation",
    question: "Which computers, and under which accounts, did this seized removable device \
               connect to, and when?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "From the device side, take the hardware serial (acquisition sidecar or \
                     device descriptor), the volume serial from the boot sector (fsstat 'Volume \
                     ID') and the volume label.",
            artifact_id: Some("fat_exfat_directory_entry"),
            yields: "The join keys: hardware serial, volume serial, label.",
        },
        TechniqueStep {
            order: 2,
            action: "On each Windows host image, search USBSTOR and USB enumeration, \
                     MountedDevices, setupapi.dev.log, ReadyBoost EMDMgmt (volume serial in \
                     decimal) and Partition/Diagnostic 1006 (hardware serial; volume serial from \
                     Vbr0).",
            artifact_id: Some("usb_stor_enum"),
            yields: "Which hosts saw the device and when.",
        },
        TechniqueStep {
            order: 3,
            action: "Attribute each connection to a profile through MountPoints2 in each \
                     NTUSER.DAT, and look for files opened from the volume in LNK files and jump \
                     lists (volume serial, removable drive type).",
            artifact_id: Some("mountpoints2"),
            yields: "Which profiles mounted it and what they opened from it.",
        },
        TechniqueStep {
            order: 4,
            action: "On macOS hosts, search the unified-log USB mass-storage entries and \
                     FSEvents for the device and volume.",
            artifact_id: Some("macos_usb_mass_storage_log"),
            yields: "Mac connections, with the weaker retention macOS offers.",
        },
        TechniqueStep {
            order: 5,
            action: "Tabulate device x host x profile x time.",
            artifact_id: None,
            yields: "The connection matrix.",
        },
    ],
    artifacts_used: &[
        "usb_stor_enum",
        "usb_enum",
        "mounted_devices",
        "mountpoints2",
        "setupapi_dev_log",
        "emdmgmt_readyboost",
        "evtx_partition_diagnostic_1006",
        "lnk_files",
        "jump_list_auto",
        "fat_exfat_directory_entry",
        "macos_usb_mass_storage_log",
        "macos_fsevents",
    ],
    preconditions: &[
        "Full host images with registry hives, event logs and user profiles; a logical export of \
         documents contains none of the host-side join records.",
    ],
    failure_modes: &[
        "A reformat of the volume changes its volume serial, so a volume-serial miss does not \
         exclude the device; search the hardware serial too.",
        "A hardware serial that is not unique across devices of one model joins the wrong device; \
         confirm the serial is device-specific before relying on it.",
        "MountPoints2 attributes a mount to a profile, not a person; a shared account produces \
         one SID.",
        "A device seized while attached shows one connection at one moment, not its history.",
        "Absence from USBSTOR or 1006 is weak: logs roll over, updates clear channels, and \
         keys can be removed.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &["T1052.001"],
    sources: &[
        "https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/",
        "https://forensics.wiki/usb_history_viewing/",
        "https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification",
    ],
};

/// Which operating system a removable volume was used on, from residue the
/// OS leaves on the volume.
///
/// macOS writes .DS_Store files in folders Finder visits, including on FAT32
/// thumb drives (Poling, ponderthebits 2017), and moves deleted files on
/// non-boot volumes to <volume>/.Trashes/<UID>/ (see macos_trash).
pub static REMOVABLE_VOLUME_HOST_OS_RESIDUE: InvestigativeTechnique = InvestigativeTechnique {
    id: "removable_volume_host_os_residue",
    name: "Host-OS residue on a removable volume",
    question: "Was this removable volume written by a Mac, by Windows, or by both?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "List the volume root and every folder, including hidden and deleted \
                     entries, for .Trashes/<UID>, .fseventsd, .Spotlight-V100, .DS_Store, \
                     AppleDouble ._ files, and System Volume Information.",
            artifact_id: Some("fat_exfat_directory_entry"),
            yields: "The residue present on the volume.",
        },
        TechniqueStep {
            order: 2,
            action: "Read .Trashes/<UID> for the numeric user ID of the macOS account that \
                     deleted files there, and .DS_Store files for names of files once shown.",
            artifact_id: Some("macos_trash"),
            yields: "Evidence of a writable Mac mount and the deleting account's UID.",
        },
        TechniqueStep {
            order: 3,
            action: "Corroborate from the host side by volume serial or label: the Mac's unified \
                     log and FSEvents, and the Windows join records.",
            artifact_id: Some("macos_fsevents"),
            yields: "Which host the residue came from.",
        },
    ],
    artifacts_used: &[
        "fat_exfat_directory_entry",
        "macos_trash",
        "macos_fsevents",
        "macos_spotlight_store",
    ],
    preconditions: &["A physical image of the volume, so hidden and deleted entries are visible."],
    failure_modes: &[
        "Absence of Mac residue is weak: a read-only mount, disabled indexing or a cleaned volume \
         leaves none, and a Mac that only read files may write nothing.",
        "Mac residue shows a writable Mac mount, not which person used the Mac; the Trashes UID \
         names an account on that Mac.",
        "Whether Windows creates System Volume Information on removable FAT volumes was searched \
         for and no primary source was found (searched: Microsoft's Volume Shadow Copy \
         documentation, which covers NTFS system volumes; only third-party claims otherwise). \
         Do not rest a 'used on Windows' finding on its presence or absence.",
    ],
    evidence_tier: EvidenceTier::SingleSecondary,
    mitre_techniques: &["T1052.001"],
    sources: &[
        "https://ponderthebits.com/2017/01/mac-dumpster-diving-identifying-deleted-file-references-in-the-trash-ds_store-files-part-1/",
        "https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf",
        "https://www.mac4n6.com/blog/2016/2/1/the-hitchhikers-guide-to-the-fseventsd",
    ],
};

/// Reconstructing local accounts that existed and were deleted.
///
/// RIDs are never reused on a standalone machine and 4720/4726 record
/// account creation and deletion (Microsoft). The joins across SAM,
/// ProfileList, $SDS and VSS follow from the descriptors cited.
pub static WINDOWS_DELETED_ACCOUNT_RECONSTRUCTION: InvestigativeTechnique = InvestigativeTechnique {
    id: "windows_deleted_account_reconstruction",
    name: "Windows deleted local account reconstruction",
    question: "Did other local accounts exist on this machine and get deleted?",
    steps: &[
        TechniqueStep {
            order: 1,
            action: "List the SIDs the SAM holds now, with RIDs from each F record.",
            artifact_id: Some("sam_user_f_record"),
            yields: "Current accounts and their RIDs.",
        },
        TechniqueStep {
            order: 2,
            action: "Diff them against SIDs found elsewhere: ProfileList subkeys, C:\\Users \
                     folder names, owner SIDs in $SDS, and SID-keyed records such as BAM and \
                     MountPoints2 in hives.",
            artifact_id: Some("profile_list_users"),
            yields: "SIDs that appear on the machine but not in the SAM.",
        },
        TechniqueStep {
            order: 3,
            action: "Search the Security log for 4720 (created), 4726 (deleted) and 4738 \
                     (changed), and for 1102 (log cleared).",
            artifact_id: Some("evtx_security_account_management"),
            yields: "Dated account lifecycle events, where retained.",
        },
        TechniqueStep {
            order: 4,
            action: "Recover earlier SAM and NTUSER.DAT copies from Volume Shadow Copies.",
            artifact_id: Some("vss_snapshot_analysis"),
            yields: "Accounts as they stood at each snapshot.",
        },
    ],
    artifacts_used: &[
        "sam_users",
        "sam_user_f_record",
        "profile_list_users",
        "user_account_sid",
        "evtx_security_account_management",
        "evtx_security",
        "ntfs_secure_sds",
        "vss_snapshot_analysis",
        "bam_user",
        "mountpoints2",
    ],
    preconditions: &["A physical image with the SAM, SOFTWARE and SYSTEM hives and the NTFS metadata."],
    failure_modes: &[
        "Reading a RID gap as deleted people: on OEM installs a sole owner at RID 1002 is ordinary \
         because setup issues and deletes placeholder accounts (see sam_user_f_record).",
        "ProfileList can be cleaned and profile folders deleted, so their absence does not show \
         an account never existed.",
        "Security-log retention is short on a busy machine; absence of 4726 is weak.",
        "An owner SID in $SDS absent from the SAM can belong to another machine's account carried \
         over by a copy that preserved owners.",
        "Using Amcache to find accounts: it is a system-wide inventory of programs and records no \
         user, so it cannot show which accounts existed.",
    ],
    evidence_tier: EvidenceTier::SourceOrMultiImpl,
    mitre_techniques: &["T1531", "T1087.001"],
    sources: &[
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers",
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720",
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726",
    ],
};

/// Every registered investigative technique. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static INVESTIGATIVE_TECHNIQUES: &[InvestigativeTechnique] = &[
    PYRAMID_OF_PAIN,
    DIAMOND_MODEL,
    ICD203_ESTIMATIVE_LANGUAGE,
    BEACONING_INTERVAL_REGULARITY,
    WIFI_BSSID_GEOLOCATION,
    NETWORK_NEIGHBOUR_ENUMERATION,
    WIFI_PRESENCE_TIMELINE,
    WHOLE_VOLUME_SIGNATURE_SWEEP,
    CONTROLLED_NEGATIVE_SEARCH,
    ACQUISITION_SCOPE_VERIFICATION,
    LOGICAL_EXPORT_SELECTION_RULE_INFERENCE,
    IP_ADDRESS_SUBSCRIBER_ATTRIBUTION,
    MOBILE_ROAMING_IP_INTERPRETATION,
    VPN_AND_RESIDENTIAL_PROXY_EGRESS_CLASSIFICATION,
    SHARED_ACCOUNT_HYPOTHESIS_TESTING,
    ACQUISITION_PROVENANCE_FROM_EVIDENCE,
    EVIDENCE_HASH_SCOPE,
    LOGICAL_EXPORT_SELECTION_RULE,
    CONTAINER_SCOPE_REPRODUCIBILITY_CHECK,
    WORKING_COPY_INTEGRITY_BEFORE_FINDINGS,
    USB_EXHIBIT_HOST_CORRELATION,
    REMOVABLE_VOLUME_HOST_OS_RESIDUE,
    WINDOWS_DELETED_ACCOUNT_RECONSTRUCTION,
];
