//! SRUM (System Resource Usage Monitor) extension table GUIDs and metadata.
//!
//! Each constant is the ESE table name as it appears in `SRUDB.dat`.
//! GUIDs are verified against
//! `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`
//! and the following authoritative sources:
//!
//! - Mark Baggett's srum-dump (primary GUID reference):
//!   <https://github.com/markbaggett/srum-dump>
//! - SANS ISC diary — SRUM forensic overview:
//!   <https://isc.sans.edu/diary/System+Resource+Utilization+Monitor/21927>
//! - libyal/esedb-kb SRUM table registry:
//!   <https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc>

/// Network Data Usage — bytes sent and received per process per hour.
///
/// Available since Windows 8.1.  Maps to `sr network`.
pub const TABLE_NETWORK_USAGE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";

/// Application Resource Usage — foreground/background CPU cycles per process.
///
/// Available since Windows 8.1.  Maps to `sr apps`.
pub const TABLE_APP_RESOURCE_USAGE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";

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
pub const TABLE_PUSH_NOTIFICATIONS: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}";

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
        assert_eq!(
            TABLE_NETWORK_USAGE,
            "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
        );
    }

    #[test]
    fn app_resource_usage_guid_is_correct() {
        // Application Resource Usage table is {D10CA2FE-...-FA89} (appsruprov.dll).
        // Source: libyal esedb-kb, Velociraptor SRUM artifact.
        assert_eq!(
            TABLE_APP_RESOURCE_USAGE,
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
        );
    }

    #[test]
    fn push_notifications_guid_is_correct() {
        // Push Notifications (WPN, wpnsruprov.dll) is {D10CA2FE-...-FA86} — the FA86
        // suffix is distinct from Application Resource Usage's FA89.
        // Source: libyal esedb-kb, Velociraptor SRUM artifact.
        assert_eq!(
            TABLE_PUSH_NOTIFICATIONS,
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
        );
    }

    #[test]
    fn network_connectivity_guid_is_correct() {
        assert_eq!(
            TABLE_NETWORK_CONNECTIVITY,
            "{DD6636C4-8929-4683-974E-22C046A43763}"
        );
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
