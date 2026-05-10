//! SRUM (System Resource Usage Monitor) extension table GUIDs and metadata.
//!
//! Each constant is the ESE table name as it appears in `SRUDB.dat`.
//! GUIDs are verified against
//! `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`
//! and public DFIR research (srum-dump, Mark Baggett's srum-dump, forensic papers).

/// Network Data Usage — bytes sent and received per process per hour.
///
/// Available since Windows 8.1.  Maps to `sr network`.
pub const TABLE_NETWORK_USAGE: &str = "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}";

/// Application Resource Usage — foreground/background CPU cycles per process.
///
/// Available since Windows 8.1.  Maps to `sr apps`.
pub const TABLE_APP_RESOURCE_USAGE: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";

/// Network Connectivity Usage — L2 connection sessions per process.
///
/// Available since Windows 8.1.  Maps to `sr connectivity`.
pub const TABLE_NETWORK_CONNECTIVITY: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";

/// Energy Usage (long-term accumulator) — charge level and energy consumed per process.
///
/// Available since Windows 8.1.  Maps to `sr energy`.
pub const TABLE_ENERGY_USAGE: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}";

/// Push Notifications (WPN provider) — notification type and count per app.
///
/// Available since Windows 8.1.  Maps to `sr notifications`.
pub const TABLE_PUSH_NOTIFICATIONS: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";

/// Application Timeline — in-focus duration and user input time per app.
///
/// Available since Windows 10 Anniversary Update (1607).  Maps to `sr app-timeline`.
pub const TABLE_APP_TIMELINE: &str = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}";

/// Energy Usage Long-Term — same schema as `TABLE_ENERGY_USAGE`, longer accumulation window.
///
/// The ESE table name is the energy GUID with the literal suffix `LT`.
/// Available since Windows 8.1.  Maps to `sr energy-lt`.
pub const TABLE_ENERGY_USAGE_LT: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT";

/// ID map table — integer ID → process path / SID mapping.
///
/// Present on all SRUM-capable Windows versions.  Maps to `sr idmap`.
pub const TABLE_ID_MAP: &str = "SruDbIdMapTable";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_constants_are_nonempty() {
        for guid in [
            TABLE_NETWORK_USAGE,
            TABLE_APP_RESOURCE_USAGE,
            TABLE_NETWORK_CONNECTIVITY,
            TABLE_ENERGY_USAGE,
            TABLE_PUSH_NOTIFICATIONS,
            TABLE_APP_TIMELINE,
            TABLE_ID_MAP,
        ] {
            assert!(!guid.is_empty());
        }
    }

    #[test]
    fn guid_format_starts_with_brace() {
        for guid in [
            TABLE_NETWORK_USAGE,
            TABLE_APP_RESOURCE_USAGE,
            TABLE_NETWORK_CONNECTIVITY,
            TABLE_ENERGY_USAGE,
            TABLE_PUSH_NOTIFICATIONS,
            TABLE_APP_TIMELINE,
        ] {
            assert!(
                guid.starts_with('{') && guid.ends_with('}'),
                "GUID must be wrapped in braces: {guid}"
            );
        }
    }

    #[test]
    fn network_usage_guid_is_correct() {
        assert_eq!(TABLE_NETWORK_USAGE, "{973F5D5C-1D90-4944-BE8E-24B22A728CF2}");
    }

    #[test]
    fn app_resource_usage_guid_is_correct() {
        assert_eq!(TABLE_APP_RESOURCE_USAGE, "{5C8CF1C7-7257-4F13-B223-970EF5939312}");
    }

    #[test]
    fn network_connectivity_guid_is_correct() {
        assert_eq!(TABLE_NETWORK_CONNECTIVITY, "{DD6636C4-8929-4683-974E-22C046A43763}");
    }

    #[test]
    fn id_map_is_not_a_guid() {
        assert!(!TABLE_ID_MAP.starts_with('{'));
    }

    #[test]
    fn energy_usage_lt_guid_is_correct() {
        assert_eq!(
            TABLE_ENERGY_USAGE_LT,
            "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT"
        );
    }
}
