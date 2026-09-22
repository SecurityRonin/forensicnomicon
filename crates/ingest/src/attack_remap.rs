//! Forward map from revoked MITRE ATT&CK technique IDs to their live
//! successors, applied at codegen emission so a regenerated module never
//! reintroduces a dead ID no matter what the upstream corpus still says.
//!
//! Keys are necessarily the old IDs, so this file is exempted by path in
//! `tests/attack_id_currency.rs` — that guard's deny table is the
//! authority; extend this map when the guard flags regenerated output.
//! Sourced from ATT&CK v19.2 STIX `revoked-by` relationships
//! (<https://github.com/mitre-attack/attack-stix-data>, checked 2026-09-22).

/// Map a possibly-revoked technique ID to its live v19 successor.
/// Unknown and already-live IDs pass through unchanged.
pub(crate) fn live_attack_id(id: &str) -> &str {
    match id {
        "T1562" | "T1562.001" | "T1562.006" => "T1685",
        "T1562.002" => "T1685.001",
        "T1562.003" => "T1690",
        "T1562.004" => "T1686",
        "T1562.007" => "T1686.001",
        "T1562.008" => "T1685.002",
        "T1562.009" => "T1688",
        "T1562.010" => "T1689",
        "T1562.011" => "T1685.003",
        "T1562.012" => "T1685.004",
        "T1562.013" => "T1686.002",
        "T1070.001" => "T1685.005",
        "T1070.002" => "T1685.006",
        "T1053.001" => "T1053.002",
        "T1547.011" => "T1647",
        "T1574.002" => "T1574.001",
        "T1076" => "T1021.001",
        "T1215" => "T1547.006",
        "T1487" => "T1561.002",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::live_attack_id;

    #[test]
    fn revoked_ids_map_to_live_successors() {
        assert_eq!(live_attack_id("T1562.001"), "T1685");
        assert_eq!(live_attack_id("T1562.002"), "T1685.001");
        assert_eq!(live_attack_id("T1070.001"), "T1685.005");
        assert_eq!(live_attack_id("T1574.002"), "T1574.001");
    }

    #[test]
    fn live_ids_pass_through() {
        assert_eq!(live_attack_id("T1547.001"), "T1547.001");
        assert_eq!(live_attack_id("T1685"), "T1685");
    }
}
