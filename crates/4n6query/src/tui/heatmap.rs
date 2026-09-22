//! ATT&CK tactic coverage heatmap.
//!
//! Maps MITRE technique IDs (T1059, T1547.001, …) to a tactic mask and
//! renders a braille bar showing coverage across all ATT&CK Enterprise
//! tactics in their canonical order.
//!
//! The width follows [`TACTIC_COUNT`] rather than a literal, so a change in
//! the number of tactics cannot leave the bar disagreeing with the table.
//! Conforms to ATT&CK **v19.2** (15 Enterprise tactics).
//!
//! Built and exercised by tests; not yet wired into the production render loop.

// The whole module is reachable only from tests until the heatmap is wired in.
#![cfg_attr(not(test), allow(dead_code))]

/// The 15 ATT&CK Enterprise tactics in display order.
/// Index 0 = leftmost char in the heatmap bar.
///
/// ATT&CK v19 split the former Defense Evasion: TA0005 kept its ID and was
/// renamed **Stealth** (hiding from defences that remain intact), while
/// behaviours that BREAK defences moved to the new **TA0112 Defense
/// Impairment**. Both names are the current official ones.
pub const TACTICS: &[(&str, &str)] = &[
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"),
    ("TA0112", "Defense Impairment"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
];

pub const TACTIC_COUNT: usize = TACTICS.len(); // 15

/// Filled block for a covered tactic.
pub const BLOCK_HIT: char = '▓';
/// Empty block for an uncovered tactic.
pub const BLOCK_MISS: char = '░';

/// Map a technique ID prefix to the index of its primary tactic in `TACTICS`.
///
/// Uses prefix matching: "T1059" and "T1059.001" both match Execution (TA0002, index 3).
/// Returns `None` if not found.
fn technique_to_tactic_idx(technique: &str) -> Option<usize> {
    // Strip sub-technique suffix for matching
    let base = technique.split('.').next().unwrap_or(technique);

    // Prefix → tactic ID mapping (subset covering common catalog techniques).
    // Carries the tactic ID rather than a slot index so that inserting or
    // reordering a tactic cannot silently misattribute a technique.
    let mapping: &[(&str, &str)] = &[
        // TA0043 Reconnaissance
        ("T1595", "TA0043"),
        ("T1596", "TA0043"),
        ("T1597", "TA0043"),
        ("T1598", "TA0043"),
        ("T1040", "TA0043"),
        // TA0042 Resource Development
        ("T1583", "TA0042"),
        ("T1584", "TA0042"),
        ("T1585", "TA0042"),
        ("T1586", "TA0042"),
        ("T1587", "TA0042"),
        ("T1588", "TA0042"),
        ("T1589", "TA0042"),
        ("T1590", "TA0042"),
        ("T1591", "TA0042"),
        ("T1592", "TA0042"),
        ("T1593", "TA0042"),
        ("T1594", "TA0042"),
        ("T1650", "TA0042"),
        // TA0001 Initial Access
        ("T1078", "TA0001"),
        ("T1091", "TA0001"),
        ("T1133", "TA0001"),
        ("T1189", "TA0001"),
        ("T1190", "TA0001"),
        ("T1195", "TA0001"),
        ("T1199", "TA0001"),
        ("T1200", "TA0001"),
        ("T1566", "TA0001"),
        // TA0002 Execution
        ("T1059", "TA0002"),
        ("T1106", "TA0002"),
        ("T1129", "TA0002"),
        ("T1203", "TA0002"),
        ("T1204", "TA0002"),
        ("T1559", "TA0002"),
        ("T1569", "TA0002"),
        ("T1620", "TA0002"),
        // TA0003 Persistence
        ("T1037", "TA0003"),
        ("T1053", "TA0003"),
        ("T1098", "TA0003"),
        ("T1136", "TA0003"),
        ("T1176", "TA0003"),
        ("T1197", "TA0003"),
        ("T1205", "TA0003"),
        ("T1505", "TA0003"),
        ("T1525", "TA0003"),
        ("T1542", "TA0003"),
        ("T1543", "TA0003"),
        ("T1546", "TA0003"),
        ("T1547", "TA0003"),
        ("T1554", "TA0003"),
        ("T1556", "TA0003"),
        ("T1574", "TA0003"),
        // TA0004 Privilege Escalation
        ("T1134", "TA0004"),
        ("T1484", "TA0004"),
        ("T1548", "TA0004"),
        // TA0005 Stealth
        ("T1006", "TA0005"),
        ("T1014", "TA0005"),
        ("T1027", "TA0005"),
        ("T1036", "TA0005"),
        ("T1055", "TA0005"),
        ("T1070", "TA0005"),
        ("T1112", "TA0005"),
        ("T1127", "TA0005"),
        ("T1140", "TA0005"),
        ("T1202", "TA0005"),
        ("T1207", "TA0005"),
        ("T1211", "TA0005"),
        ("T1216", "TA0005"),
        ("T1218", "TA0005"),
        ("T1220", "TA0005"),
        ("T1221", "TA0005"),
        ("T1222", "TA0005"),
        ("T1497", "TA0005"),
        ("T1553", "TA0005"),
        ("T1564", "TA0005"),
        ("T1599", "TA0005"),
        ("T1600", "TA0005"),
        ("T1601", "TA0005"),
        ("T1647", "TA0005"),
        // TA0112 Defense Impairment — v19: behaviours that BREAK defences,
        // split out of the former Defense Evasion.
        ("T1685", "TA0112"),
        ("T1686", "TA0112"),
        ("T1688", "TA0112"),
        // TA0006 Credential Access
        ("T1003", "TA0006"),
        ("T1056", "TA0006"),
        ("T1110", "TA0006"),
        ("T1111", "TA0006"),
        ("T1187", "TA0006"),
        ("T1212", "TA0006"),
        ("T1528", "TA0006"),
        ("T1539", "TA0006"),
        ("T1552", "TA0006"),
        ("T1555", "TA0006"),
        ("T1557", "TA0006"),
        ("T1558", "TA0006"),
        ("T1606", "TA0006"),
        ("T1621", "TA0006"),
        // TA0007 Discovery
        ("T1007", "TA0007"),
        ("T1010", "TA0007"),
        ("T1012", "TA0007"),
        ("T1016", "TA0007"),
        ("T1018", "TA0007"),
        ("T1033", "TA0007"),
        ("T1046", "TA0007"),
        ("T1049", "TA0007"),
        ("T1057", "TA0007"),
        ("T1069", "TA0007"),
        ("T1082", "TA0007"),
        ("T1083", "TA0007"),
        ("T1087", "TA0007"),
        ("T1120", "TA0007"),
        ("T1124", "TA0007"),
        ("T1135", "TA0007"),
        ("T1201", "TA0007"),
        ("T1217", "TA0007"),
        ("T1482", "TA0007"),
        ("T1518", "TA0007"),
        ("T1526", "TA0007"),
        ("T1538", "TA0007"),
        ("T1580", "TA0007"),
        ("T1613", "TA0007"),
        ("T1614", "TA0007"),
        ("T1615", "TA0007"),
        ("T1619", "TA0007"),
        ("T1652", "TA0007"),
        ("T1654", "TA0007"),
        // TA0008 Lateral Movement
        ("T1021", "TA0008"),
        ("T1080", "TA0008"),
        ("T1210", "TA0008"),
        ("T1534", "TA0008"),
        ("T1550", "TA0008"),
        ("T1563", "TA0008"),
        ("T1570", "TA0008"),
        // TA0009 Collection
        ("T1005", "TA0009"),
        ("T1025", "TA0009"),
        ("T1039", "TA0009"),
        ("T1074", "TA0009"),
        ("T1113", "TA0009"),
        ("T1114", "TA0009"),
        ("T1115", "TA0009"),
        ("T1119", "TA0009"),
        ("T1123", "TA0009"),
        ("T1125", "TA0009"),
        ("T1185", "TA0009"),
        ("T1213", "TA0009"),
        ("T1530", "TA0009"),
        ("T1560", "TA0009"),
        ("T1602", "TA0009"),
        // TA0010 Exfiltration
        ("T1011", "TA0010"),
        ("T1020", "TA0010"),
        ("T1029", "TA0010"),
        ("T1030", "TA0010"),
        ("T1041", "TA0010"),
        ("T1048", "TA0010"),
        ("T1052", "TA0010"),
        ("T1567", "TA0010"),
        // TA0011 Command and Control
        ("T1001", "TA0011"),
        ("T1008", "TA0011"),
        ("T1071", "TA0011"),
        ("T1090", "TA0011"),
        ("T1092", "TA0011"),
        ("T1095", "TA0011"),
        ("T1102", "TA0011"),
        ("T1104", "TA0011"),
        ("T1105", "TA0011"),
        ("T1132", "TA0011"),
        ("T1568", "TA0011"),
        ("T1571", "TA0011"),
        ("T1572", "TA0011"),
        ("T1573", "TA0011"),
        // TA0040 Impact
        ("T1485", "TA0040"),
        ("T1486", "TA0040"),
        ("T1489", "TA0040"),
        ("T1490", "TA0040"),
        ("T1491", "TA0040"),
        ("T1495", "TA0040"),
        ("T1496", "TA0040"),
        ("T1498", "TA0040"),
        ("T1499", "TA0040"),
        ("T1529", "TA0040"),
        ("T1531", "TA0040"),
        ("T1561", "TA0040"),
        ("T1565", "TA0040"),
    ];

    let tactic_id = mapping
        .iter()
        .find(|(prefix, _)| base == *prefix)
        .map(|(_, tactic)| *tactic)?;

    // Resolve the ID to its display slot. Doing this here, rather than storing
    // the slot in the mapping, is what makes the table survive a tactic being
    // inserted or reordered.
    TACTICS.iter().position(|(id, _)| *id == tactic_id)
}

/// Compute a tactic mask from a slice of technique IDs.
///
/// Bit N (counting from LSB) is set if any technique maps to tactic index N.
/// The mask is [`TACTIC_COUNT`] bits wide.
pub fn tactic_mask(techniques: &[&str]) -> u16 {
    let mut mask: u16 = 0;
    for &tech in techniques {
        if let Some(idx) = technique_to_tactic_idx(tech) {
            mask |= 1 << idx;
        }
    }
    mask
}

/// Render a [`TACTIC_COUNT`]-char heatmap bar from a tactic mask.
///
/// Bit 0 → leftmost char (TA0043 Recon).
/// Bit `TACTIC_COUNT - 1` → rightmost char (TA0040 Impact).
pub fn render_bar(mask: u16) -> String {
    (0..TACTIC_COUNT)
        .map(|i| {
            if mask & (1 << i) != 0 {
                BLOCK_HIT
            } else {
                BLOCK_MISS
            }
        })
        .collect()
}

/// Return the tactic IDs that are set in the mask, in display order.
pub fn active_tactic_ids(mask: u16) -> Vec<&'static str> {
    (0..TACTIC_COUNT)
        .filter(|&i| mask & (1 << i) != 0)
        .map(|i| TACTICS[i].0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tactics_has_15_entries() {
        // ATT&CK v19 split Defense Evasion into Stealth (TA0005, same ID) and
        // Defense Impairment (TA0112, new), taking Enterprise from 14 to 15.
        assert_eq!(TACTIC_COUNT, 15);
        assert_eq!(TACTICS.len(), 15);
    }

    #[test]
    fn ta0005_uses_the_v19_name_stealth() {
        let (_, name) = TACTICS
            .iter()
            .find(|(id, _)| *id == "TA0005")
            .expect("TA0005 must still be present — v19 renamed it, it was not retired");
        assert_eq!(
            *name, "Stealth",
            "TA0005 is named Stealth in v19; 'Defense Evasion' is the pre-split name \
             for a broader category that no longer exists"
        );
    }

    #[test]
    fn defense_impairment_tactic_is_present() {
        assert!(
            TACTICS
                .iter()
                .any(|(id, name)| *id == "TA0112" && *name == "Defense Impairment"),
            "v19 added TA0112 Defense Impairment; without it, techniques that \
             moved there render on another tactic's slot"
        );
    }

    #[test]
    fn impairment_techniques_map_to_ta0112_not_ta0005() {
        // These three moved out of the old Defense Evasion in v19. Asserting on
        // tactic IDs rather than bit positions: an index assertion would still
        // pass if the slot ordering silently shifted underneath it.
        for tid in ["T1685", "T1686", "T1688"] {
            let ids = active_tactic_ids(tactic_mask(&[tid]));
            assert_eq!(
                ids,
                vec!["TA0112"],
                "{tid} belongs to Defense Impairment (TA0112) in v19"
            );
        }
    }

    #[test]
    fn stealth_techniques_stay_on_ta0005() {
        // The other half of the split: these did NOT move.
        for tid in ["T1027", "T1036", "T1218", "T1564"] {
            let ids = active_tactic_ids(tactic_mask(&[tid]));
            assert_eq!(ids, vec!["TA0005"], "{tid} remains under TA0005 (Stealth)");
        }
    }

    #[test]
    fn unrelated_tactics_survive_the_insertion() {
        // Inserting a tactic mid-table renumbers every slot after it. These
        // pin a sample on both sides of the insertion point.
        assert_eq!(active_tactic_ids(tactic_mask(&["T1059"])), vec!["TA0002"]);
        assert_eq!(active_tactic_ids(tactic_mask(&["T1003"])), vec!["TA0006"]);
        assert_eq!(active_tactic_ids(tactic_mask(&["T1041"])), vec!["TA0010"]);
    }

    #[test]
    fn tactic_mask_empty_returns_zero() {
        assert_eq!(tactic_mask(&[]), 0);
    }

    #[test]
    fn tactic_mask_t1059_sets_execution_bit() {
        // T1059 → TA0002 Execution → index 3 → bit 3
        let mask = tactic_mask(&["T1059"]);
        assert_eq!(mask, 1 << 3, "T1059 should set bit 3 (Execution)");
    }

    #[test]
    fn tactic_mask_subtechnique_resolves_to_same_tactic() {
        // T1059.001 (PowerShell) → TA0002 Execution → bit 3
        let mask = tactic_mask(&["T1059.001"]);
        assert_eq!(mask, 1 << 3);
    }

    #[test]
    fn tactic_mask_t1547_sets_persistence_bit() {
        // T1547 → TA0003 Persistence → index 4 → bit 4
        let mask = tactic_mask(&["T1547.001"]);
        assert_eq!(mask, 1 << 4);
    }

    #[test]
    fn tactic_mask_t1218_sets_defense_evasion_bit() {
        // T1218 → TA0005 Defense Evasion → index 6 → bit 6
        let mask = tactic_mask(&["T1218"]);
        assert_eq!(mask, 1 << 6);
    }

    #[test]
    fn tactic_mask_multiple_techniques_sets_multiple_bits() {
        let mask = tactic_mask(&["T1059", "T1547.001"]);
        assert!(mask & (1 << 3) != 0, "execution bit");
        assert!(mask & (1 << 4) != 0, "persistence bit");
    }

    #[test]
    fn tactic_mask_unknown_technique_does_not_crash() {
        let mask = tactic_mask(&["T9999"]);
        assert_eq!(mask, 0);
    }

    #[test]
    fn render_bar_all_zeros_is_all_miss() {
        let bar = render_bar(0);
        // Derived from TACTIC_COUNT, not a literal: a hardcoded width is what
        // let the bar silently disagree with the tactic table when ATT&CK
        // changed the number of tactics.
        assert_eq!(bar.chars().count(), TACTIC_COUNT);
        assert!(bar.chars().all(|c| c == BLOCK_MISS));
    }

    #[test]
    fn render_bar_all_ones_is_all_hit() {
        let mask: u16 = (1 << TACTIC_COUNT) - 1;
        let bar = render_bar(mask);
        assert_eq!(bar.chars().count(), TACTIC_COUNT);
        assert!(bar.chars().all(|c| c == BLOCK_HIT));
    }

    #[test]
    fn render_bar_first_bit_fills_first_char() {
        let bar = render_bar(1); // bit 0 = TA0043
        let chars: Vec<char> = bar.chars().collect();
        assert_eq!(chars[0], BLOCK_HIT);
        assert!(chars[1..].iter().all(|&c| c == BLOCK_MISS));
    }

    #[test]
    fn render_bar_length_always_matches_tactic_count() {
        for mask in [0u16, 0xFFFF, 0b0000_1010_0101_0101] {
            assert_eq!(render_bar(mask).chars().count(), TACTIC_COUNT);
        }
    }

    #[test]
    fn active_tactic_ids_empty_mask() {
        assert!(active_tactic_ids(0).is_empty());
    }

    #[test]
    fn active_tactic_ids_execution_bit() {
        let ids = active_tactic_ids(1 << 3);
        assert_eq!(ids, vec!["TA0002"]);
    }

    #[test]
    fn active_tactic_ids_multiple_bits() {
        let mask = tactic_mask(&["T1059", "T1547.001"]);
        let ids = active_tactic_ids(mask);
        assert!(ids.contains(&"TA0002"));
        assert!(ids.contains(&"TA0003"));
    }

    #[test]
    fn full_pipeline_t1059_renders_execution_block() {
        let mask = tactic_mask(&["T1059"]);
        let bar = render_bar(mask);
        let chars: Vec<char> = bar.chars().collect();
        // index 3 = Execution should be filled
        assert_eq!(chars[3], BLOCK_HIT);
        // index 0,1,2 should be empty
        assert_eq!(chars[0], BLOCK_MISS);
        assert_eq!(chars[1], BLOCK_MISS);
        assert_eq!(chars[2], BLOCK_MISS);
    }
}
