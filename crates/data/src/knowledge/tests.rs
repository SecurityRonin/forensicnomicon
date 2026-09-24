//! Integrity tests over [`TOOL_BEHAVIOURS`], [`ANTI_FORENSIC_METHODS`],
//! [`INVESTIGATIVE_TECHNIQUES`], the correlation-hint slice, and
//! [`EXAMINATION_PROFILES`].

use forensicnomicon_core::evidence::EvidenceTier;

use crate::catalog::Platform;

use super::*;

/// The exact number of registered tool behaviours — the single place the
/// count is written down. Adding an entry updates this constant and nothing
/// else; every other test asserts presence or invariants, not size.
const EXPECTED_TOOL_BEHAVIOUR_LEN: usize = 11;

#[test]
fn no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for b in TOOL_BEHAVIOURS {
        assert!(seen.insert(b.id), "duplicate tool behaviour id: {}", b.id);
    }
}

#[test]
fn len_matches_expected() {
    assert_eq!(TOOL_BEHAVIOURS.len(), EXPECTED_TOOL_BEHAVIOUR_LEN);
}

/// The memory-forensics absorption batch: the first entries the type ever
/// held, and therefore the pattern every later batch follows.
#[test]
fn memory_forensics_batch_is_present() {
    for id in [
        "vol2_netscan_silent_gaps",
        "vol3_vmware_vmem_missing_metadata",
        "vol3_hollowprocesses_heuristic_coverage",
        "vol3_dumpfiles_zero_fill",
        "memprocfs_findevil_elastic_gate",
        "vol3_malfind_fp_profile",
    ] {
        assert!(
            TOOL_BEHAVIOURS.iter().any(|b| b.id == id),
            "missing tool behaviour: {id}"
        );
    }
}

/// Every entry must be independently verifiable: the load-bearing prose
/// fields are non-empty and every source is a resolvable HTTPS reference.
#[test]
fn every_entry_is_verifiable() {
    for b in TOOL_BEHAVIOURS {
        assert!(!b.tool.is_empty(), "{}: empty tool", b.id);
        assert!(!b.detail.is_empty(), "{}: empty detail", b.id);
        assert!(!b.consequence.is_empty(), "{}: empty consequence", b.id);
        assert!(!b.mitigation.is_empty(), "{}: empty mitigation", b.id);
        assert!(!b.sources.is_empty(), "{}: no sources", b.id);
        for s in b.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                b.id
            );
        }
    }
}

/// Behaviour changes between releases; an undated claim rots. Every entry in
/// this catalog records the version range it was verified against.
#[test]
fn every_entry_records_a_version() {
    for b in TOOL_BEHAVIOURS {
        assert!(
            b.version_range.is_some(),
            "{}: no version range recorded",
            b.id
        );
    }
}

// ── Anti-forensic methods ────────────────────────────────────────────────────

/// The exact number of registered anti-forensic methods — the single place
/// the count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_ANTI_FORENSIC_METHOD_LEN: usize = 2;

#[test]
fn anti_forensic_len_matches_expected() {
    assert_eq!(
        ANTI_FORENSIC_METHODS.len(),
        EXPECTED_ANTI_FORENSIC_METHOD_LEN
    );
}

#[test]
fn anti_forensic_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for m in ANTI_FORENSIC_METHODS {
        assert!(seen.insert(m.id), "duplicate anti-forensic id: {}", m.id);
    }
}

/// The filesystem-timestamp absorption batch: every id absorbed so far.
#[test]
fn timestamp_forgery_batch_is_present() {
    for id in ["ext4_utimensat_timestomp", "ntfs_si_only_timestomp"] {
        assert!(
            ANTI_FORENSIC_METHODS.iter().any(|m| m.id == id),
            "missing anti-forensic method: {id}"
        );
    }
}

/// Every entry must be independently verifiable, and must carry its residue
/// story: `residue` non-empty (or the emptiness deliberate — none absorbed so
/// far are), `detection` non-empty, every source a resolvable HTTPS reference.
#[test]
fn every_anti_forensic_entry_is_verifiable() {
    for m in ANTI_FORENSIC_METHODS {
        assert!(!m.name.is_empty(), "{}: empty name", m.id);
        assert!(!m.method.is_empty(), "{}: empty method", m.id);
        assert!(!m.residue.is_empty(), "{}: empty residue", m.id);
        assert!(!m.detection.is_empty(), "{}: empty detection", m.id);
        assert!(!m.sources.is_empty(), "{}: no sources", m.id);
        for s in m.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                m.id
            );
        }
    }
}

// ── Correlation hints ────────────────────────────────────────────────────────

/// The exact number of registered correlation hints — the single place the
/// count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_CORRELATION_HINT_LEN: usize = 3;

#[test]
fn correlation_len_matches_expected() {
    assert_eq!(CORRELATION_HINTS.len(), EXPECTED_CORRELATION_HINT_LEN);
}

#[test]
fn correlation_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for h in CORRELATION_HINTS {
        assert!(seen.insert(h.id), "duplicate correlation hint id: {}", h.id);
    }
}

/// The volume-provenance absorption batch: every id absorbed so far.
#[test]
fn volume_provenance_batch_is_present() {
    for id in [
        "lnk_tracker_droid_volume_match",
        "prefetch_volume_serial_boot_sector",
    ] {
        assert!(
            CORRELATION_HINTS.iter().any(|h| h.id == id),
            "missing correlation hint: {id}"
        );
    }
}

/// A correlation is a join between at least two artifacts, both sides
/// resolvable in the catalog; and both directions — agreement and
/// divergence — must be stated, since the divergence side is usually the
/// reason the pair is worth pairing.
#[test]
fn every_correlation_entry_is_verifiable() {
    let catalog_has = |id: &str| crate::catalog::CATALOG.by_id(id).is_some();
    for h in CORRELATION_HINTS {
        assert!(!h.name.is_empty(), "{}: empty name", h.id);
        assert!(h.artifacts.len() >= 2, "{}: fewer than two artifacts", h.id);
        for a in h.artifacts {
            assert!(catalog_has(a), "{}: artifact id not in catalog: {a}", h.id);
        }
        assert!(!h.agreement_means.is_empty(), "{}: empty agreement", h.id);
        assert!(!h.divergence_means.is_empty(), "{}: empty divergence", h.id);
        assert!(!h.sources.is_empty(), "{}: no sources", h.id);
        for s in h.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                h.id
            );
        }
    }
}

// ── Investigative techniques ─────────────────────────────────────────────────

/// The exact number of registered investigative techniques — the single place
/// the count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_INVESTIGATIVE_TECHNIQUE_LEN: usize = 15;

#[test]
fn investigative_len_matches_expected() {
    assert_eq!(
        INVESTIGATIVE_TECHNIQUES.len(),
        EXPECTED_INVESTIGATIVE_TECHNIQUE_LEN
    );
}

#[test]
fn investigative_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for t in INVESTIGATIVE_TECHNIQUES {
        assert!(
            seen.insert(t.id),
            "duplicate investigative technique id: {}",
            t.id
        );
    }
}

/// The analytic-frameworks absorption batch: every id absorbed so far.
#[test]
fn analytic_frameworks_batch_is_present() {
    for id in [
        "pyramid_of_pain_indicator_prioritisation",
        "diamond_model_intrusion_analysis",
        "icd203_estimative_probability_language",
        "beaconing_interval_regularity_triage",
    ] {
        assert!(
            INVESTIGATIVE_TECHNIQUES.iter().any(|t| t.id == id),
            "missing investigative technique: {id}"
        );
    }
}

/// The Wi-Fi BSSID geolocation technique must be registered, and it must be
/// wired to the network artifacts it consumes: the remembered-network store
/// whose access-point BSSIDs are the geolocation handle, and the DHCP lease
/// whose RouterHardwareAddress is a second BSSID source. A technique that
/// names no artifact is analytic folklore with no catalog anchor.
#[test]
fn wifi_bssid_geolocation_is_present_and_wired_to_artifacts() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "wifi_bssid_geolocation")
        .expect("wifi_bssid_geolocation technique must be registered");
    assert!(
        t.artifacts_used.contains(&"macos_wifi_known_networks"),
        "must consume the remembered-network store (BSSID source)"
    );
    assert!(
        t.artifacts_used.contains(&"macos_dhcp_leases"),
        "must consume the DHCP lease (RouterHardwareAddress BSSID source)"
    );
    let body = format!("{} {}", t.question, t.failure_modes.join(" "));
    assert!(
        body.contains("gs-loc.apple.com")
            || t.steps
                .iter()
                .any(|s| s.action.contains("gs-loc.apple.com")),
        "must name Apple's WPS endpoint, the unauthenticated BSSID -> location service"
    );
    assert!(
        t.failure_modes.iter().any(|f| f.contains("-180")),
        "must record the -180 sentinel Apple returns for an unknown BSSID"
    );
}

/// The network-neighbour enumeration technique must be registered and wired to
/// the peer-discovery artifacts it consumes: the Bluetooth device store, the
/// SMB identity, the connect-to-server history, the remembered Wi-Fi networks
/// and the DHCP lease. Its critical limit — a dead disk shows only persisted
/// past interactions, while the live ARP/neighbour table and the mDNS/Bonjour
/// responder cache are in-memory and lost at power-off — must be recorded as a
/// failure mode, or the technique over-claims what a static image can prove.
#[test]
fn network_neighbour_enumeration_is_present_and_wired_to_artifacts() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "network_neighbour_enumeration")
        .expect("network_neighbour_enumeration technique must be registered");
    for id in [
        "macos_bluetooth_devices",
        "macos_smb_server_identity",
        "macos_connect_to_server_history",
        "macos_wifi_known_networks",
        "macos_dhcp_leases",
    ] {
        assert!(
            t.artifacts_used.contains(&id),
            "must consume the peer-discovery artifact: {id}"
        );
    }
    let body = t.failure_modes.join(" ");
    assert!(
        body.contains("ARP") && (body.contains("mDNS") || body.contains("Bonjour")),
        "must record that the live ARP/neighbour table and mDNS/Bonjour cache are lost at power-off"
    );
    assert!(
        body.to_lowercase().contains("in-memory") || body.to_lowercase().contains("power-off"),
        "must record that a dead disk shows only persisted past interactions"
    );
}

/// Every entry must be independently verifiable, and must carry its
/// mislead story: `steps` non-empty and 1-based-ordered, `failure_modes`
/// non-empty (a technique with no recorded way to yield a confident wrong
/// answer has not been researched, only transcribed), every source a
/// resolvable HTTPS reference, and any artifact id resolvable in the catalog.
#[test]
fn every_investigative_entry_is_verifiable() {
    let catalog_has = |id: &str| crate::catalog::CATALOG.by_id(id).is_some();
    for t in INVESTIGATIVE_TECHNIQUES {
        assert!(!t.name.is_empty(), "{}: empty name", t.id);
        assert!(!t.question.is_empty(), "{}: empty question", t.id);
        assert!(!t.steps.is_empty(), "{}: no steps", t.id);
        for (i, s) in t.steps.iter().enumerate() {
            assert_eq!(
                usize::from(s.order),
                i + 1,
                "{}: step order not sequential from 1",
                t.id
            );
            assert!(
                !s.action.is_empty(),
                "{}: step {} empty action",
                t.id,
                s.order
            );
            assert!(
                !s.yields.is_empty(),
                "{}: step {} empty yields",
                t.id,
                s.order
            );
            if let Some(a) = s.artifact_id {
                assert!(
                    catalog_has(a),
                    "{}: step artifact not in catalog: {a}",
                    t.id
                );
            }
        }
        for a in t.artifacts_used {
            assert!(catalog_has(a), "{}: artifact id not in catalog: {a}", t.id);
        }
        assert!(!t.failure_modes.is_empty(), "{}: no failure modes", t.id);
        assert!(!t.sources.is_empty(), "{}: no sources", t.id);
        for s in t.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                t.id
            );
        }
    }
}

/// The evidence-handling and Windows attribution batch: eight techniques an
/// examiner needs when the evidence arrives as EWF/L01/AD1 containers and the
/// question is who used a Windows machine or a removable device.
#[test]
fn evidence_handling_and_windows_attribution_techniques_are_present() {
    let t = |id: &str| {
        INVESTIGATIVE_TECHNIQUES
            .iter()
            .find(|t| t.id == id)
            .unwrap_or_else(|| panic!("missing investigative technique: {id}"))
    };
    let fm = |id: &str| t(id).failure_modes.join(" ");

    let prov = t("acquisition_provenance_from_evidence");
    assert!(prov
        .steps
        .iter()
        .any(|s| s.action.contains("ewfinfo") && s.action.contains("sector")));
    assert!(prov.steps.iter().any(|s| s.action.contains(".txt")));

    assert!(fm("evidence_hash_scope").contains("seizure"));
    assert!(t("evidence_hash_scope")
        .sources
        .iter()
        .any(|s| s.contains("800-86")));

    assert!(fm("logical_export_selection_rule").contains("whitelist"));
    let scope = t("container_scope_reproducibility_check");
    assert!(scope
        .steps
        .iter()
        .any(|s| s.action.contains("positive control")));
    for id in [
        "sam_user_f_record",
        "windows_install_date",
        "wechat_windows_files",
    ] {
        assert!(
            scope.artifacts_used.contains(&id),
            "scope check must consume {id}"
        );
    }

    let wc = t("working_copy_integrity_before_findings");
    assert!(wc.steps.iter().any(|s| s.action.contains("ewfverify")));
    assert!(fm("working_copy_integrity_before_findings").contains("padding"));

    let usb = t("usb_exhibit_host_correlation");
    for id in [
        "usb_stor_enum",
        "mountpoints2",
        "evtx_partition_diagnostic_1006",
        "emdmgmt_readyboost",
        "fat_exfat_directory_entry",
        "macos_usb_mass_storage_log",
    ] {
        assert!(
            usb.artifacts_used.contains(&id),
            "USB correlation must consume {id}"
        );
    }
    assert!(fm("usb_exhibit_host_correlation").contains("reformat"));

    let os = t("removable_volume_host_os_residue");
    assert!(os.artifacts_used.contains(&"macos_trash"));
    assert!(
        fm("removable_volume_host_os_residue").contains("System Volume Information")
            && fm("removable_volume_host_os_residue").contains("searched"),
        "SVI on removable FAT must be recorded as searched and unsourced"
    );

    let acct = t("windows_deleted_account_reconstruction");
    for id in [
        "sam_user_f_record",
        "profile_list_users",
        "evtx_security_account_management",
        "ntfs_secure_sds",
        "vss_snapshot_analysis",
    ] {
        assert!(
            acct.artifacts_used.contains(&id),
            "account reconstruction must consume {id}"
        );
    }
    let acct_fm = fm("windows_deleted_account_reconstruction");
    assert!(
        acct_fm.contains("1002"),
        "RID gaps are weak on OEM installs"
    );
    assert!(
        acct_fm.contains("Amcache"),
        "Amcache evidences programs, not accounts"
    );
}

// ── Tool behaviours ──────────────────────────────────────────────────────────

/// A tool that under-reports and a tool that over-reports mislead in opposite
/// directions; the `kind` field must keep them distinguishable. malfind is a
/// false-positive profile, netscan a silent-incompleteness profile.
#[test]
fn kind_distinguishes_fp_profile_from_silent_incompleteness() {
    let by_id = |id: &str| {
        TOOL_BEHAVIOURS
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("missing tool behaviour: {id}"))
    };
    assert_eq!(
        by_id("vol3_malfind_fp_profile").kind,
        ToolBehaviourKind::FalsePositiveProne
    );
    assert_eq!(
        by_id("vol2_netscan_silent_gaps").kind,
        ToolBehaviourKind::SilentlyIncomplete
    );
}

/// A lead that was researched and could NOT be sourced must still be present.
///
/// Four absorption agents each dropped such leads, which is what their briefs
/// asked for and the briefs were wrong: a dropped lead is indistinguishable
/// from one nobody investigated, so the next reader repeats the same failed
/// search. `EvidenceTier::SearchedNotFound` exists to keep the negative
/// result, and the result is only kept if an entry actually carries it.
#[test]
fn researched_but_unsourced_leads_are_recorded_not_dropped() {
    let unsourced: Vec<&str> = CORRELATION_HINTS
        .iter()
        .filter(|h| h.evidence_tier == EvidenceTier::SearchedNotFound)
        .map(|h| h.id)
        .collect();

    assert!(
        unsourced.contains(&"usbstor_wpdbusenum_device_guid"),
        "the USBSTOR/WPDBUSENUM device-GUID join was researched and found \
         unsourceable; it must be RECORDED at SearchedNotFound, not dropped"
    );
}

/// An unsourced entry is only useful if it says where the search already went.
///
/// "Unverified" on its own tells the next reader nothing. Naming the places
/// already exhausted is what turns a dead end into a saved afternoon.
#[test]
fn an_unsourced_entry_records_where_it_was_looked_for() {
    for h in CORRELATION_HINTS
        .iter()
        .filter(|h| h.evidence_tier == EvidenceTier::SearchedNotFound)
    {
        let body = format!("{} {}", h.agreement_means, h.divergence_means);
        assert!(
            body.contains("searched") || body.contains("Searched"),
            "{}: an unsourced entry must record where it was looked for",
            h.id
        );
    }
}

/// Knowledge that was ESTABLISHED and then lost must come back.
///
/// `coreutils_stat_ext4_birth_blank` was fully verified during the
/// anti-forensics absorption - kernel docs, coreutils NEWS, statx(2) and
/// e2fsprogs source all read - and then never landed, because the file it
/// belonged in was locked by a concurrent agent. It was handed over in a
/// report and nobody actioned it.
///
/// That is worse than a dropped lead: a drop reflects a decision, this was
/// forgetting, and the catalog looks identical either way.
#[test]
fn verified_knowledge_lost_to_tooling_is_recovered() {
    assert!(
        TOOL_BEHAVIOURS
            .iter()
            .any(|b| b.id == "coreutils_stat_ext4_birth_blank"),
        "ext4 Birth-time visibility was verified and then lost; it must be recorded"
    );
}

/// An entry recording a blank field must say the ABSENCE is the tool's, not
/// the filesystem's - that inversion is the whole reason it is worth having.
#[test]
fn the_ext4_birth_entry_distinguishes_tool_silence_from_absent_data() {
    let b = TOOL_BEHAVIOURS
        .iter()
        .find(|b| b.id == "coreutils_stat_ext4_birth_blank")
        .expect("entry missing");
    let body = format!("{} {}", b.detail, b.consequence);
    assert!(
        body.contains("debugfs"),
        "must name the tool that CAN read it, or the entry is a dead end"
    );
}

/// Every lead that was researched and came back unsourceable must be present
/// at `SearchedNotFound`, not absent.
///
/// These two were dropped during the memory-forensics absorption. Dropping
/// was a decision, but an invisible one: the catalog reads the same whether a
/// claim was investigated and found wanting or never considered, so the next
/// reader runs the same searches and drops them again.
#[test]
fn unsourceable_memory_forensics_leads_are_recorded() {
    assert!(
        TOOL_BEHAVIOURS
            .iter()
            .any(|b| b.id == "malfind_benign_process_names"),
        "the named-benign-process claim was researched and found unsourceable; \
         record it, do not drop it"
    );

    // The netscan under-reporting was ALSO reported as unsourceable, and that
    // turned out to be wrong: upstream issue 363 documents it. It is folded
    // into vol2_netscan_silent_gaps rather than recorded as a dead end, which
    // is why it is asserted here as a citation and not as an entry.
    let netscan = TOOL_BEHAVIOURS
        .iter()
        .find(|b| b.id == "vol2_netscan_silent_gaps")
        .expect("vol2_netscan_silent_gaps missing");
    assert!(
        netscan.sources.iter().any(|s| s.contains("issues/363")),
        "the observed under-reporting has an upstream report; cite it"
    );
}

/// An unsourced tool behaviour must be unmistakable at the point of use.
///
/// These entries sit in the same slice as verified ones and are read the same
/// way. The tier alone is not enough - a reader scanning `detail` has to see
/// the status without checking a field.
#[test]
fn unsourced_tool_behaviours_announce_themselves_in_the_text() {
    for b in TOOL_BEHAVIOURS
        .iter()
        .filter(|b| b.evidence_tier == EvidenceTier::SearchedNotFound)
    {
        assert!(
            b.detail.contains("UNVERIFIED"),
            "{}: an unsourced entry must say so in its detail text",
            b.id
        );
        assert!(
            b.detail.contains("Searched") || b.detail.contains("searched"),
            "{}: must record where the search already went",
            b.id
        );
    }
}

/// The evidence-container batch: how libewf and FTK Imager present EWF
/// evidence. Each entry must carry the exact message an examiner sees, since
/// the message is the only handle an examiner has to find the entry.
#[test]
fn evidence_container_tool_batch_is_present() {
    let by_id = |id: &str| {
        TOOL_BEHAVIOURS
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("missing tool behaviour: {id}"))
    };

    let lef = by_id("libewf_lef_short_name_open_failure");
    assert_eq!(lef.kind, ToolBehaviourKind::MisreadsStructure);
    assert!(lef
        .detail
        .contains("invalid short name size value out of bounds"));
    assert!(lef.detail.contains("libewf_lef_file_entry.c"));
    assert!(lef
        .sources
        .iter()
        .any(|s| s.contains("20231119/libewf/libewf_lef_file_entry.c")));
    assert!(
        lef.mitigation.contains("ltree"),
        "mitigation must name the independent check: the ltree MD5"
    );

    let seg = by_id("libewf_damaged_segment_error_semantics");
    assert_eq!(seg.kind, ToolBehaviourKind::OutputHidesDetail);
    assert!(seg.detail.contains("unexpected end of data"));
    assert!(seg.detail.contains("unsupported file header signature"));
    assert!(
        seg.consequence.contains("segment"),
        "consequence must say the error does not name the defective segment"
    );

    let ftk = by_id("ftk_imager_verify_unstored_hash_mismatch");
    assert_eq!(ftk.kind, ToolBehaviourKind::FalsePositiveProne);
    assert_eq!(ftk.evidence_tier, EvidenceTier::SearchedNotFound);
    assert!(ftk.detail.contains("Mismatch"));
    assert!(
        ftk.mitigation.contains("zeros") || ftk.mitigation.contains("zero-filled"),
        "mitigation must say to check the stored value for zeros first"
    );
    assert!(
        ftk.consequence.contains("seizure"),
        "a match proves image = itself since acquisition, not = source at seizure"
    );
}

// ── Examination profiles ─────────────────────────────────────────────────────

/// The exact number of registered examination profiles — the single place the
/// count is written down, mirroring [`EXPECTED_TOOL_BEHAVIOUR_LEN`].
const EXPECTED_EXAMINATION_PROFILE_LEN: usize = 4;

#[test]
fn examination_len_matches_expected() {
    assert_eq!(EXAMINATION_PROFILES.len(), EXPECTED_EXAMINATION_PROFILE_LEN);
}

#[test]
fn examination_no_duplicate_ids() {
    let mut seen = std::collections::HashSet::new();
    for p in EXAMINATION_PROFILES {
        assert!(
            seen.insert(p.id),
            "duplicate examination profile id: {}",
            p.id
        );
    }
}

/// The macOS profile batch: the first profiles the type ever held, and their
/// intended shape. A `Full` profile must carry `FullExamination`; a `Focused`
/// profile must carry any focus other than `FullExamination`.
#[test]
fn macos_profiles_present_with_expected_shape() {
    let by_id = |id: &str| {
        EXAMINATION_PROFILES
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("missing examination profile: {id}"))
    };

    let full = by_id("macos_full");
    assert_eq!(full.platform, Platform::MacOS);
    assert_eq!(full.kind, ProfileKind::Full);
    assert_eq!(full.focus, ExaminationFocus::FullExamination);

    let leakage = by_id("macos_data_leakage");
    assert_eq!(leakage.platform, Platform::MacOS);
    assert_eq!(leakage.kind, ProfileKind::Focused);
    assert_eq!(leakage.focus, ExaminationFocus::DataLeakage);

    let malware = by_id("macos_malware");
    assert_eq!(malware.platform, Platform::MacOS);
    assert_eq!(malware.kind, ProfileKind::Focused);
    assert_eq!(malware.focus, ExaminationFocus::Malware);
}

/// The load-bearing correctness property: every member of every profile
/// references a catalog artifact id that actually resolves. A profile pointing
/// at an id no descriptor defines is a dangling checklist entry — an artifact
/// the examiner is told to pull that the catalog cannot describe.
#[test]
fn every_profile_member_resolves_in_catalog() {
    for p in EXAMINATION_PROFILES {
        for m in p.members {
            assert!(
                crate::catalog::CATALOG.by_id(m.artifact_id).is_some(),
                "{}: member artifact id not in catalog: {}",
                p.id,
                m.artifact_id
            );
        }
    }
}

/// Proves the referential-integrity gate can fail: the exact predicate the
/// check above relies on must REJECT a profile whose member points at an id no
/// descriptor defines. A check that has never been shown to fail is not known
/// to work.
#[test]
fn an_unknown_member_id_is_rejected_by_the_integrity_predicate() {
    let bogus = ExaminationProfile {
        id: "test_only_bogus_profile",
        name: "bogus",
        platform: Platform::MacOS,
        kind: ProfileKind::Focused,
        focus: ExaminationFocus::Malware,
        description: "fixture used only to prove the integrity check can fail",
        members: &[ProfileMember {
            artifact_id: "this_artifact_id_is_not_defined_by_any_descriptor",
            category: InvestigativeCategory::Persistence,
            rationale: "fixture",
        }],
        sources: &["https://example.invalid/"],
    };

    let all_resolve = bogus
        .members
        .iter()
        .all(|m| crate::catalog::CATALOG.by_id(m.artifact_id).is_some());
    assert!(
        !all_resolve,
        "the referential-integrity predicate must reject an unknown member id"
    );
}

/// Every profile is well-formed: non-empty prose, at least one member, every
/// member carries a rationale, sources are resolvable HTTPS references, and no
/// artifact id is listed twice within a single profile.
#[test]
fn every_examination_profile_is_well_formed() {
    for p in EXAMINATION_PROFILES {
        assert!(!p.name.is_empty(), "{}: empty name", p.id);
        assert!(!p.description.is_empty(), "{}: empty description", p.id);
        assert!(!p.members.is_empty(), "{}: no members", p.id);
        assert!(!p.sources.is_empty(), "{}: no sources", p.id);
        for s in p.sources {
            assert!(
                s.starts_with("https://"),
                "{}: source is not an https URL: {s}",
                p.id
            );
        }

        // Kind and focus must agree: a Full profile is the comprehensive
        // FullExamination; a Focused profile is anything narrower.
        match p.kind {
            ProfileKind::Full => assert_eq!(
                p.focus,
                ExaminationFocus::FullExamination,
                "{}: a Full profile must have FullExamination focus",
                p.id
            ),
            ProfileKind::Focused => assert_ne!(
                p.focus,
                ExaminationFocus::FullExamination,
                "{}: a Focused profile must not have FullExamination focus",
                p.id
            ),
        }

        let mut seen = std::collections::HashSet::new();
        for m in p.members {
            assert!(
                !m.rationale.is_empty(),
                "{}: member {} has no rationale",
                p.id,
                m.artifact_id
            );
            assert!(
                seen.insert(m.artifact_id),
                "{}: member artifact id listed twice: {}",
                p.id,
                m.artifact_id
            );
        }
    }
}

/// A `Full` profile is comprehensive by construction: it must span several
/// investigative categories and carry more members than any focused profile
/// for the same platform, or "full" is a label with nothing behind it.
#[test]
fn full_profile_is_broader_than_focused_profiles() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");

    let distinct_categories: std::collections::HashSet<_> =
        full.members.iter().map(|m| m.category).collect();
    assert!(
        distinct_categories.len() >= 6,
        "a full examination profile must span many investigative categories, found {}",
        distinct_categories.len()
    );

    for focused in EXAMINATION_PROFILES
        .iter()
        .filter(|p| p.kind == ProfileKind::Focused && p.platform == full.platform)
    {
        assert!(
            full.members.len() > focused.members.len(),
            "full profile ({} members) must be broader than focused {} ({} members)",
            full.members.len(),
            focused.id,
            focused.members.len()
        );
    }
}

/// The curated macOS gap-fill artifacts must now be wired into the full
/// profile: the OpenBSM audit trail and dslocal account store (account use),
/// USB mass-storage and AirDrop history (removable/peer transfer), and the
/// correctly-scoped Safari cookie jar. Before the descriptors existed these
/// areas were excluded from the profile; now that they resolve, the profile
/// must reference them.
#[test]
fn macos_full_references_curated_gap_fill_artifacts() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");
    let has = |id: &str| full.members.iter().any(|m| m.artifact_id == id);
    for id in [
        "macos_openbsm_audit",
        "macos_dslocal_users",
        "macos_usb_mass_storage_log",
        "macos_airdrop_sharingd",
        "macos_safari_cookies",
    ] {
        assert!(
            has(id),
            "macos_full must reference curated descriptor: {id}"
        );
    }
}

/// The data-leakage profile is where removable media, peer transfer and
/// browser state matter most: it must reference USB mass-storage history,
/// AirDrop/sharingd activity, and the Safari cookie jar.
#[test]
fn macos_data_leakage_references_removable_airdrop_and_cookies() {
    let leakage = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_data_leakage")
        .expect("macos_data_leakage missing");
    let has = |id: &str| leakage.members.iter().any(|m| m.artifact_id == id);
    for id in [
        "macos_usb_mass_storage_log",
        "macos_airdrop_sharingd",
        "macos_safari_cookies",
    ] {
        assert!(
            has(id),
            "macos_data_leakage must reference curated descriptor: {id}"
        );
    }
}

/// The full macOS profile must carry the complete network-configuration layer
/// under Connections: the interface hardware map, the service configuration,
/// the DHCP lease, and the remembered Wi-Fi networks. The lease was already a
/// member; the interface map, service configuration and known-networks store
/// are the network descriptors this batch added.
#[test]
fn macos_full_references_network_configuration_layer() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");
    let member = |id: &str| full.members.iter().find(|m| m.artifact_id == id);
    for id in [
        "macos_network_interfaces",
        "macos_network_preferences",
        "macos_dhcp_leases",
        "macos_wifi_known_networks",
    ] {
        let m = member(id)
            .unwrap_or_else(|| panic!("macos_full must reference network descriptor: {id}"));
        assert_eq!(
            m.category,
            InvestigativeCategory::Connections,
            "network descriptor {id} belongs under Connections"
        );
    }
}

/// After the Big Sur migration the legacy known-network records survive only
/// in the airport preferences `.backup`; the full profile must collect it.
#[test]
fn macos_full_references_legacy_wifi_backup() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");
    let m = full
        .members
        .iter()
        .find(|m| m.artifact_id == "macos_wifi_plist_backup")
        .expect("macos_full must reference macos_wifi_plist_backup");
    assert_eq!(m.category, InvestigativeCategory::Connections);
}

/// The remembered-network BSSIDList carries no per-BSSID timestamp, so an
/// access point cannot be dated from it, nor attributed to one SSID when the
/// same BSSID sits under two networks. Both techniques that read BSSIDs from
/// that store must say so.
#[test]
fn bssid_techniques_record_that_bssid_list_is_undated() {
    for id in ["wifi_bssid_geolocation", "network_neighbour_enumeration"] {
        let t = INVESTIGATIVE_TECHNIQUES
            .iter()
            .find(|t| t.id == id)
            .unwrap_or_else(|| panic!("{id} missing"));
        let body = t.failure_modes.join(" ");
        assert!(
            body.contains("BSSIDList") && body.to_lowercase().contains("no per-bssid timestamp"),
            "{id}: must record that BSSIDList entries are undated"
        );
    }
}

/// Step 3 of the geolocation technique corroborates against join/added
/// timestamps; on a migrated network AddedAt is the legacy last-join time,
/// not a first-join date.
#[test]
fn wifi_bssid_geolocation_warns_added_at_is_migrated() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "wifi_bssid_geolocation")
        .expect("wifi_bssid_geolocation missing");
    assert!(t
        .failure_modes
        .iter()
        .any(|f| f.contains("AddedAt") && f.to_lowercase().contains("migrat")));
}

/// A WPS position carries no date: the service does not say when the access
/// point was observed at that position, so a router that has since moved
/// geolocates to its new home.
#[test]
fn wifi_bssid_geolocation_warns_position_date_is_undisclosed() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "wifi_bssid_geolocation")
        .expect("wifi_bssid_geolocation missing");
    assert!(t
        .failure_modes
        .iter()
        .any(|f| f.to_lowercase().contains("undisclosed")));
}

/// The Wi-Fi presence timeline technique dates when the Mac was on a network:
/// it must consume the driver entries, wifi.log, the remembered-network store
/// and the CUPS printer/spool evidence that bridges networks.
#[test]
fn wifi_presence_timeline_is_present_and_wired_to_artifacts() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "wifi_presence_timeline")
        .expect("wifi_presence_timeline technique must be registered");
    for id in [
        "macos_wifi_driver_log",
        "macos_wifi_log",
        "macos_unified_log",
        "macos_wifi_known_networks",
        "macos_cups_printers_conf",
        "macos_cups_spool_jobs",
    ] {
        assert!(t.artifacts_used.contains(&id), "must consume {id}");
    }
    assert!(
        t.steps.iter().any(|s| s.action.contains("log-archive")),
        "must name the unifiedlog_iterator export mode"
    );
}

/// Each way the timeline yields a confident wrong answer must be recorded.
#[test]
fn wifi_presence_timeline_records_its_failure_modes() {
    let t = INVESTIGATIVE_TECHNIQUES
        .iter()
        .find(|t| t.id == "wifi_presence_timeline")
        .expect("wifi_presence_timeline missing");
    let body = t.failure_modes.join(" ").to_lowercase();
    for (needle, why) in [
        ("weeks", "unified log and wifi.log keep only weeks"),
        ("removed", "known-networks keeps only networks not removed"),
        ("addedat", "migrated AddedAt is the legacy last-join time"),
        ("undisclosed", "the WPS position date is undisclosed"),
        ("move together", "router and device may move together"),
        ("printer", "a .local. printer can be moved"),
        (
            "control",
            "the plain-text driver entries need a per-image control",
        ),
    ] {
        assert!(body.contains(needle), "failure modes must record: {why}");
    }
}

/// The full profile must collect the Wi-Fi presence evidence, and the
/// unified log's uuidtext store without which its entries cannot be decoded.
#[test]
fn macos_full_references_wifi_presence_evidence() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");
    for (id, cat) in [
        ("macos_wifi_driver_log", InvestigativeCategory::Connections),
        ("macos_wifi_log", InvestigativeCategory::Connections),
        ("fa_file__7", InvestigativeCategory::ApplicationUse),
    ] {
        let m = full
            .members
            .iter()
            .find(|m| m.artifact_id == id)
            .unwrap_or_else(|| panic!("macos_full must reference {id}"));
        assert_eq!(m.category, cat, "{id}");
    }
}

/// The data-leakage profile places the machine on a named network at a time
/// for egress correlation; the driver entries and wifi.log do that per day.
#[test]
fn macos_data_leakage_references_wifi_presence_evidence() {
    let p = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_data_leakage")
        .expect("macos_data_leakage missing");
    for id in ["macos_wifi_driver_log", "macos_wifi_log"] {
        let m = p
            .members
            .iter()
            .find(|m| m.artifact_id == id)
            .unwrap_or_else(|| panic!("macos_data_leakage must reference {id}"));
        assert_eq!(m.category, InvestigativeCategory::Connections);
    }
}

/// The data-leakage profile is where location exposure and network egress
/// matter: it must reference the DHCP lease (internal IP / gateway / joined
/// Wi-Fi and when) and the remembered Wi-Fi networks (the BSSID location
/// handle), both under Connections.
#[test]
fn macos_data_leakage_references_dhcp_and_known_networks() {
    let leakage = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_data_leakage")
        .expect("macos_data_leakage missing");
    let has = |id: &str| leakage.members.iter().any(|m| m.artifact_id == id);
    for id in ["macos_dhcp_leases", "macos_wifi_known_networks"] {
        assert!(
            has(id),
            "macos_data_leakage must reference network descriptor: {id}"
        );
    }
}

/// The full macOS profile must carry the peer-device / network-neighbour layer
/// under Connections: the Bluetooth device store, the advertised SMB identity,
/// and the connect-to-server host history. These are the persisted traces of
/// the Mac's immediate peer neighbourhood.
#[test]
fn macos_full_references_peer_discovery_layer() {
    let full = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_full")
        .expect("macos_full missing");
    let member = |id: &str| full.members.iter().find(|m| m.artifact_id == id);
    for id in [
        "macos_bluetooth_devices",
        "macos_smb_server_identity",
        "macos_connect_to_server_history",
    ] {
        let m = member(id)
            .unwrap_or_else(|| panic!("macos_full must reference peer-discovery descriptor: {id}"));
        assert_eq!(
            m.category,
            InvestigativeCategory::Connections,
            "peer-discovery descriptor {id} belongs under Connections"
        );
    }
}

/// The data-leakage profile is where remote-share egress matters: it must
/// reference the connect-to-server host history (a common exfiltration
/// destination whose sibling mounted-server list is already carried).
#[test]
fn macos_data_leakage_references_connect_to_server_history() {
    let leakage = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "macos_data_leakage")
        .expect("macos_data_leakage missing");
    assert!(
        leakage
            .members
            .iter()
            .any(|m| m.artifact_id == "macos_connect_to_server_history"),
        "macos_data_leakage must reference macos_connect_to_server_history"
    );
}

/// No profile may reference the mis-scoped generated `browsers_safari_cookies`
/// (OsScope::Win7Plus) now that the correctly macOS-scoped `macos_safari_cookies`
/// exists — the curated descriptor must be used in its place.
#[test]
fn profiles_use_curated_not_mis_scoped_safari_cookies() {
    for p in EXAMINATION_PROFILES {
        assert!(
            p.members
                .iter()
                .all(|m| m.artifact_id != "browsers_safari_cookies"),
            "{}: must reference the curated macos_safari_cookies, not the \
             mis-scoped generated browsers_safari_cookies",
            p.id
        );
    }
    let cookies = crate::catalog::CATALOG
        .by_id("macos_safari_cookies")
        .expect("macos_safari_cookies must exist");
    assert_eq!(
        cookies.os_scope,
        crate::catalog::OsScope::MacOS,
        "the curated Safari cookie descriptor must be macOS-scoped"
    );
}

/// The Windows user-attribution profile: shared versus exclusive use of a
/// Windows computer. Every member must say, in its own rationale, that the
/// artefact attributes to an account, SID, device or system and not to a
/// person, because that is the error this examination most often makes.
#[test]
fn windows_user_attribution_profile_is_present_and_caveated() {
    let p = EXAMINATION_PROFILES
        .iter()
        .find(|p| p.id == "windows_user_attribution")
        .expect("windows_user_attribution profile missing");
    assert_eq!(p.platform, Platform::Windows);
    assert_eq!(p.kind, ProfileKind::Focused);
    assert_eq!(p.focus, ExaminationFocus::UserAttribution);
    assert!(p.description.contains("one SID"));

    for m in p.members {
        assert!(
            m.rationale.contains("not a person") || m.rationale.contains("not the person"),
            "{}: rationale must state the artefact does not identify a person",
            m.artifact_id
        );
    }

    for (id, cat) in [
        ("sam_user_f_record", InvestigativeCategory::AccountUse),
        ("profile_list_users", InvestigativeCategory::AccountUse),
        ("evtx_security", InvestigativeCategory::AccountUse),
        ("bam_user", InvestigativeCategory::ApplicationUse),
        ("amcache_app_file", InvestigativeCategory::ApplicationUse),
        ("prefetch_file", InvestigativeCategory::ApplicationUse),
        ("shellbags_user", InvestigativeCategory::FileActivity),
        ("ntfs_secure_sds", InvestigativeCategory::FileActivity),
        ("mountpoints2", InvestigativeCategory::Connections),
        (
            "evtx_partition_diagnostic_1006",
            InvestigativeCategory::Connections,
        ),
        (
            "wechat_windows_files",
            InvestigativeCategory::Communications,
        ),
        (
            "ooxml_core_properties",
            InvestigativeCategory::DocumentAuthorship,
        ),
        ("chrome_login_data", InvestigativeCategory::WebActivity),
        ("onedrive_metadata", InvestigativeCategory::CloudStorage),
    ] {
        let m = p
            .members
            .iter()
            .find(|m| m.artifact_id == id)
            .unwrap_or_else(|| panic!("windows_user_attribution must include {id}"));
        assert_eq!(m.category, cat, "{id} is in the wrong category");
    }
}
