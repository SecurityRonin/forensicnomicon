/// ATT&CK tactic coverage heatmap.
///
/// Maps MITRE technique IDs (T1059, T1547.001, …) to a 14-bit tactic mask
/// and renders a braille bar showing coverage across all 14 ATT&CK Enterprise
/// tactics in their canonical order.

/// The 14 ATT&CK Enterprise tactics in display order.
/// Index 0 = leftmost char in the heatmap bar.
pub const TACTICS: &[(&str, &str)] = &[
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
];

pub const TACTIC_COUNT: usize = TACTICS.len(); // 14

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

    // Prefix → tactic index mapping (subset covering common catalog techniques)
    let mapping: &[(&str, usize)] = &[
        // TA0043 Reconnaissance (0)
        ("T1595", 0),
        ("T1596", 0),
        ("T1597", 0),
        ("T1598", 0),
        ("T1040", 0),
        // TA0042 Resource Development (1)
        ("T1583", 1),
        ("T1584", 1),
        ("T1585", 1),
        ("T1586", 1),
        ("T1587", 1),
        ("T1588", 1),
        ("T1589", 1),
        ("T1590", 1),
        ("T1591", 1),
        ("T1592", 1),
        ("T1593", 1),
        ("T1594", 1),
        ("T1650", 1),
        // TA0001 Initial Access (2)
        ("T1078", 2),
        ("T1091", 2),
        ("T1133", 2),
        ("T1189", 2),
        ("T1190", 2),
        ("T1195", 2),
        ("T1199", 2),
        ("T1200", 2),
        ("T1566", 2),
        // TA0002 Execution (3)
        ("T1059", 3),
        ("T1106", 3),
        ("T1129", 3),
        ("T1203", 3),
        ("T1204", 3),
        ("T1559", 3),
        ("T1569", 3),
        ("T1620", 3),
        // TA0003 Persistence (4)
        ("T1037", 4),
        ("T1053", 4),
        ("T1098", 4),
        ("T1136", 4),
        ("T1176", 4),
        ("T1197", 4),
        ("T1205", 4),
        ("T1505", 4),
        ("T1525", 4),
        ("T1542", 4),
        ("T1543", 4),
        ("T1546", 4),
        ("T1547", 4),
        ("T1554", 4),
        ("T1556", 4),
        ("T1574", 4),
        // TA0004 Privilege Escalation (5)
        ("T1134", 5),
        ("T1484", 5),
        ("T1548", 5),
        // TA0005 Defense Evasion (6)
        ("T1006", 6),
        ("T1014", 6),
        ("T1027", 6),
        ("T1036", 6),
        ("T1055", 6),
        ("T1070", 6),
        ("T1112", 6),
        ("T1127", 6),
        ("T1140", 6),
        ("T1202", 6),
        ("T1207", 6),
        ("T1211", 6),
        ("T1216", 6),
        ("T1218", 6),
        ("T1220", 6),
        ("T1221", 6),
        ("T1222", 6),
        ("T1497", 6),
        ("T1553", 6),
        ("T1562", 6),
        ("T1564", 6),
        ("T1599", 6),
        ("T1600", 6),
        ("T1601", 6),
        ("T1647", 6),
        // TA0006 Credential Access (7)
        ("T1003", 7),
        ("T1056", 7),
        ("T1110", 7),
        ("T1111", 7),
        ("T1187", 7),
        ("T1212", 7),
        ("T1528", 7),
        ("T1539", 7),
        ("T1552", 7),
        ("T1555", 7),
        ("T1557", 7),
        ("T1558", 7),
        ("T1606", 7),
        ("T1621", 7),
        // TA0007 Discovery (8)
        ("T1007", 8),
        ("T1010", 8),
        ("T1012", 8),
        ("T1016", 8),
        ("T1018", 8),
        ("T1033", 8),
        ("T1046", 8),
        ("T1049", 8),
        ("T1057", 8),
        ("T1069", 8),
        ("T1082", 8),
        ("T1083", 8),
        ("T1087", 8),
        ("T1120", 8),
        ("T1124", 8),
        ("T1135", 8),
        ("T1201", 8),
        ("T1217", 8),
        ("T1482", 8),
        ("T1518", 8),
        ("T1526", 8),
        ("T1538", 8),
        ("T1580", 8),
        ("T1613", 8),
        ("T1614", 8),
        ("T1615", 8),
        ("T1619", 8),
        ("T1652", 8),
        ("T1654", 8),
        // TA0008 Lateral Movement (9)
        ("T1021", 9),
        ("T1080", 9),
        ("T1210", 9),
        ("T1534", 9),
        ("T1550", 9),
        ("T1563", 9),
        ("T1570", 9),
        // TA0009 Collection (10)
        ("T1005", 10),
        ("T1025", 10),
        ("T1039", 10),
        ("T1074", 10),
        ("T1113", 10),
        ("T1114", 10),
        ("T1115", 10),
        ("T1119", 10),
        ("T1123", 10),
        ("T1125", 10),
        ("T1185", 10),
        ("T1213", 10),
        ("T1530", 10),
        ("T1560", 10),
        ("T1602", 10),
        // TA0010 Exfiltration (11)
        ("T1011", 11),
        ("T1020", 11),
        ("T1029", 11),
        ("T1030", 11),
        ("T1041", 11),
        ("T1048", 11),
        ("T1052", 11),
        ("T1567", 11),
        // TA0011 C2 (12)
        ("T1001", 12),
        ("T1008", 12),
        ("T1071", 12),
        ("T1090", 12),
        ("T1092", 12),
        ("T1095", 12),
        ("T1102", 12),
        ("T1104", 12),
        ("T1105", 12),
        ("T1132", 12),
        ("T1568", 12),
        ("T1571", 12),
        ("T1572", 12),
        ("T1573", 12),
        // TA0040 Impact (13)
        ("T1485", 13),
        ("T1486", 13),
        ("T1487", 13),
        ("T1489", 13),
        ("T1490", 13),
        ("T1491", 13),
        ("T1495", 13),
        ("T1496", 13),
        ("T1498", 13),
        ("T1499", 13),
        ("T1529", 13),
        ("T1531", 13),
        ("T1561", 13),
        ("T1565", 13),
    ];

    mapping
        .iter()
        .find(|(prefix, _)| base == *prefix)
        .map(|(_, idx)| *idx)
}

/// Compute a 14-bit tactic mask from a slice of technique IDs.
///
/// Bit N (counting from LSB) is set if any technique maps to tactic index N.
pub fn tactic_mask(techniques: &[&str]) -> u16 {
    let mut mask: u16 = 0;
    for &tech in techniques {
        if let Some(idx) = technique_to_tactic_idx(tech) {
            mask |= 1 << idx;
        }
    }
    mask
}

/// Render a 14-char heatmap bar from a tactic mask.
///
/// Bit 0 → leftmost char (TA0043 Recon).
/// Bit 13 → rightmost char (TA0040 Impact).
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
    fn tactics_has_14_entries() {
        assert_eq!(TACTIC_COUNT, 14);
        assert_eq!(TACTICS.len(), 14);
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
        assert_eq!(bar.chars().count(), 14);
        assert!(bar.chars().all(|c| c == BLOCK_MISS));
    }

    #[test]
    fn render_bar_all_ones_is_all_hit() {
        let mask: u16 = (1 << 14) - 1;
        let bar = render_bar(mask);
        assert_eq!(bar.chars().count(), 14);
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
    fn render_bar_length_always_14() {
        for mask in [0u16, 0xFFFF, 0b0000_1010_0101_0101] {
            assert_eq!(render_bar(mask).chars().count(), 14);
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
