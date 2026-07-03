//! End-of-life (end-of-support) dates for Windows operating systems.
//!
//! A host running an OS past its vendor end-of-support date receives no security
//! updates — a standing triage signal (unpatched, exploitable). This module is
//! the single source of truth for the end-of-support dates; matching a system's
//! product name and comparing against a reference date lives in the caller.
//!
//! Dates are Microsoft's published end-of-support (mainstream+extended, the last
//! date updates shipped without paid ESU). A finding states the OS is past
//! support as of a reference date — an observation, not a verdict on exploitation.
//!
//! Sources:
//! - Microsoft Product Lifecycle: <https://learn.microsoft.com/lifecycle/products/>.
//!   Windows XP 2014-04-08; Vista 2017-04-11; 7 2020-01-14; 8 2016-01-12;
//!   8.1 2023-01-10; 10 (22H2) 2025-10-14; Server 2003 2015-07-14;
//!   Server 2008/2008 R2 2020-01-14; Server 2012/2012 R2 2023-10-10.

/// One end-of-life OS: a display name, a lower-case needle matched (as a
/// substring) against a registry `ProductName`, and its end-of-support date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EolOs {
    /// Display name, e.g. "Windows Server 2008 R2".
    pub name: &'static str,
    /// Lower-case substring matched against a lower-cased product name.
    pub match_substr: &'static str,
    /// End-of-support date, ISO 8601 (`YYYY-MM-DD`).
    pub eol: &'static str,
}

/// Known end-of-life Windows releases, ordered **specific → general** so a
/// substring match resolves to the most precise entry (e.g. "Server 2012 R2"
/// before "Server 2012", "Windows 8.1" before "Windows 8").
pub const EOL_OS: &[EolOs] = &[
    EolOs {
        name: "Windows Server 2012 R2",
        match_substr: "server 2012 r2",
        eol: "2023-10-10",
    },
    EolOs {
        name: "Windows Server 2012",
        match_substr: "server 2012",
        eol: "2023-10-10",
    },
    EolOs {
        name: "Windows Server 2008 R2",
        match_substr: "server 2008 r2",
        eol: "2020-01-14",
    },
    EolOs {
        name: "Windows Server 2008",
        match_substr: "server 2008",
        eol: "2020-01-14",
    },
    EolOs {
        name: "Windows Server 2003",
        match_substr: "server 2003",
        eol: "2015-07-14",
    },
    EolOs {
        name: "Windows XP",
        match_substr: "windows xp",
        eol: "2014-04-08",
    },
    EolOs {
        name: "Windows Vista",
        match_substr: "windows vista",
        eol: "2017-04-11",
    },
    EolOs {
        name: "Windows 7",
        match_substr: "windows 7",
        eol: "2020-01-14",
    },
    EolOs {
        name: "Windows 8.1",
        match_substr: "windows 8.1",
        eol: "2023-01-10",
    },
    EolOs {
        name: "Windows 8",
        match_substr: "windows 8",
        eol: "2016-01-12",
    },
    EolOs {
        name: "Windows 10",
        match_substr: "windows 10",
        eol: "2025-10-14",
    },
];

/// Match a registry `ProductName` to a known end-of-life OS, if any. Case-
/// insensitive substring match against the specific→general table.
#[must_use]
pub fn lookup(product_name: &str) -> Option<&'static EolOs> {
    // RED stub — replaced by the GREEN implementation.
    let _ = product_name;
    None
}

/// Whether `product_name` is a known OS whose end-of-support date is on or before
/// `reference_date` (both ISO `YYYY-MM-DD`; lexical comparison is valid for that
/// format). `reference_date` is the analysis date or the evidence's own date.
#[must_use]
pub fn is_eol_as_of(product_name: &str, reference_date: &str) -> bool {
    lookup(product_name).is_some_and(|e| e.eol <= reference_date)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_windows_7() {
        assert_eq!(
            lookup("Windows 7 Professional").map(|e| e.name),
            Some("Windows 7")
        );
    }

    #[test]
    fn matches_most_specific_server_and_client() {
        assert_eq!(
            lookup("Windows Server 2008 R2 Standard").map(|e| e.name),
            Some("Windows Server 2008 R2")
        );
        // 8.1 must not be swallowed by the "windows 8" entry.
        assert_eq!(
            lookup("Windows 8.1 Enterprise").map(|e| e.name),
            Some("Windows 8.1")
        );
    }

    #[test]
    fn supported_os_is_not_matched() {
        assert!(lookup("Windows 11 Pro").is_none());
        assert!(lookup("Windows Server 2019 Datacenter").is_none());
    }

    #[test]
    fn is_eol_as_of_compares_dates() {
        // Windows 7 EOL 2020-01-14.
        assert!(is_eol_as_of("Windows 7 Professional", "2026-07-02"));
        assert!(!is_eol_as_of("Windows 7 Professional", "2019-01-01"));
        assert!(!is_eol_as_of("Windows 11 Pro", "2026-07-02"));
    }
}
