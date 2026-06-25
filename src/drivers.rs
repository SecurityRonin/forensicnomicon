//! Known-vulnerable / known-malicious **driver denylist** (Bring Your Own
//! Vulnerable Driver — BYOVD) sourced from the [LOLDrivers] project.
//!
//! This is the third service-masquerade vector catalogued in this crate, and the
//! **inverse** of the two service allowlists in [`services`](crate::services):
//!
//! - [`KNOWN_WINDOWS_SERVICE_BINARIES`](crate::services::KNOWN_WINDOWS_SERVICE_BINARIES)
//!   — an *allowlist* of legitimate standalone OwnProcess service `.exe`s; a
//!   System32 service image NOT on it is a lead.
//! - [`KNOWN_WINDOWS_SERVICE_DLLS`](crate::services::KNOWN_WINDOWS_SERVICE_DLLS)
//!   — an *allowlist* of legitimate svchost-hosted `ServiceDll`s; a `ServiceDll`
//!   NOT on it is a lead.
//! - [`KNOWN_VULNERABLE_DRIVERS`] (this module) — a **DENYLIST** of driver
//!   `.sys` basenames; a driver image that IS on it is a lead.
//!
//! ## Why a denylist (not an allowlist) for drivers
//!
//! The allowlist shape works for *services* because the legitimate set is small
//! and enumerable (a few dozen OwnProcess exes, ~100 svchost ServiceDlls). It is
//! the **wrong** shape for drivers: a Windows host loads hundreds of perfectly
//! legitimate third-party kernel drivers — AV/EDR, GPU, VPN, storage, virtual
//! audio, peripheral, and platform-vendor drivers — none of which ship with
//! Windows. An allowlist of "legit drivers" would false-flag essentially every
//! third-party driver on every real machine. The actionable knowledge is instead
//! the *bounded, curated set of drivers known to be vulnerable or malicious* —
//! which is exactly what the LOLDrivers project maintains.
//!
//! ## BYOVD (Bring Your Own Vulnerable Driver)
//!
//! Adversaries install a legitimately-signed but vulnerable kernel driver, then
//! exploit it to gain kernel-mode code execution — disabling EDR, terminating
//! protected processes, or tampering with kernel structures — bypassing Driver
//! Signature Enforcement because the driver is genuinely signed (MITRE ATT&CK
//! [T1543.003 — Create or Modify System Process: Windows Service] for the service
//! registration, and [T1068 — Exploitation for Privilege Escalation] for the
//! kernel exploit). Some entries are outright *malicious* rootkit drivers rather
//! than abused-legitimate ones; LOLDrivers tracks both.
//!
//! ## DENYLIST semantics — presence is the lead
//!
//! Unlike the service allowlists (where *absence* is the lead), here **presence**
//! is the indicator: a loaded/registered driver whose `.sys` basename is in
//! [`KNOWN_VULNERABLE_DRIVERS`] warrants investigation.
//!
//! ## Name-matching is a LEAD, not a verdict — hash-matching is the precise form
//!
//! This denylist matches on **basename only**. That is a deliberately coarse
//! lead: a vulnerable driver can be trivially **renamed** on disk (the kernel
//! does not care what the file is called), so a name match can miss a renamed
//! sample, and — conversely — a *benign, unrelated* file could share a name with
//! a denylisted one. Note in particular that several LOLDrivers basenames
//! collide with the names of legitimate, Microsoft-shipped OS drivers: on a
//! clean domain controller (the DFIRMadness DC01 corpus) the name-only denylist
//! hits exactly `afd.sys` (Winsock Ancillary Function Driver), `monitor.sys`
//! (Monitor Class Function Driver), and `usbxhci.sys` (USB 3.0 xHCI controller)
//! — each a genuine OS driver whose name LOLDrivers also tracks as a
//! vulnerable/malicious sample. A name hit on such an entry is precisely a *lead
//! to corroborate*, not a verdict. The precise form of BYOVD detection is **hash-matching** against
//! the LOLDrivers Authentihash / SHA256 set (a renamed sample still hashes the
//! same, and a benign namesake does not). Embedding the full hash dataset would
//! bloat this zero-dep KNOWLEDGE leaf by megabytes, so it is deliberately **out
//! of scope here** and flagged as a future enhancement; this module ships the
//! lean names-only lead gate. Corroborate a name hit with the on-disk hash, the
//! Authenticode signature, the load path, and the registering service before
//! concluding.
//!
//! ## NON-EXHAUSTIVE
//!
//! LOLDrivers grows continuously (a daily community feed). This embedded snapshot
//! is a point-in-time copy — see the source/date below — and the set varies as
//! new vulnerable drivers are catalogued. Absence from the list does NOT mean a
//! driver is safe; it means "not in this snapshot of the known-bad set". The
//! entries are the de-duplicated `.sys` basenames from the dataset's `Tags`,
//! `KnownVulnerableSamples[].Filename`, and `KnownVulnerableSamples[].OriginalFilename`
//! fields; hash-only placeholder filenames (entries whose stored "name" is itself
//! a hash, useless as a *name* lead) are excluded.
//!
//! # Sources
//!
//! - [LOLDrivers] — "Living Off The Land Drivers", the authoritative BYOVD /
//!   malicious-driver dataset (magicsword-io):
//!   <https://www.loldrivers.io/> · dataset API:
//!   <https://www.loldrivers.io/api/drivers.json>
//! - Generated by `tools/refresh-drivers.py` from the [LOLDrivers] `drivers.json`
//!   export (fetched 2026-06-24) + a hand-curated overlay. The table
//!   ([`BYOVD_DRIVERS`]) carries per-driver GUID, category, CVE, MITRE technique,
//!   representative sample SHA-256, and the HVCI-bypass flag; both
//!   [`KNOWN_VULNERABLE_DRIVERS`] and the EVTX service-name list are co-generated
//!   from it. Refresh = re-run the tool; it never drops an existing basename and
//!   preserves the overlay (service names, EDR-killer flag, GentleKiller/Gentlemen
//!   drop-names per ESET 2026-06).
//! - MITRE ATT&CK T1543.003 / T1068:
//!   <https://attack.mitre.org/techniques/T1543/003/> ·
//!   <https://attack.mitre.org/techniques/T1068/>
//! - Microsoft — "Microsoft recommended driver block rules" (the OS-side
//!   counterpart, HVCI/WDAC blocklist):
//!   <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>
//!
//! [LOLDrivers]: https://www.loldrivers.io/
//! [T1543.003 — Create or Modify System Process: Windows Service]: https://attack.mitre.org/techniques/T1543/003/
//! [T1068 — Exploitation for Privilege Escalation]: https://attack.mitre.org/techniques/T1068/

/// Category of a BYOVD driver in the [LOLDrivers] dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverCategory {
    /// A legitimately-signed driver with an exploitable vulnerability.
    Vulnerable,
    /// An outright-malicious / rootkit driver.
    Malicious,
}

/// A BYOVD driver: its on-disk **file basename** plus enrichment from the
/// [LOLDrivers] dataset (GUID, category, CVE, MITRE technique, representative
/// sample SHA-256, HVCI-bypass) and a hand-curated overlay (service name(s) and
/// the EDR-killer flag).
///
/// **Single source of truth.** [`KNOWN_VULNERABLE_DRIVERS`] (the basename
/// denylist) and [`crate::heuristics::evtx::BYOVD_DRIVER_NAMES`] (the EVTX
/// service-install heuristic's key) are **both co-generated** from
/// [`BYOVD_DRIVERS`] by `tools/refresh-drivers.py`, so the three views cannot
/// drift; a LOLDrivers refresh is one mechanical step.
///
/// [LOLDrivers]: https://www.loldrivers.io/
#[derive(Debug, Clone, Copy)]
pub struct VulnerableDriver {
    /// Lowercase `.sys` file basename.
    pub file_basename: &'static str,
    /// Service name(s) seen in 7045/4697 `ServiceName` fields (curated overlay).
    pub service_names: &'static [&'static str],
    /// Human label / vendor product.
    pub label: &'static str,
    /// LOLDrivers category (vulnerable vs outright-malicious).
    pub category: DriverCategory,
    /// LOLDrivers dataset GUID (empty for entries not in the snapshot).
    pub loldrivers_id: &'static str,
    /// Associated CVE id(s), where one is assigned.
    pub cve: &'static [&'static str],
    /// MITRE ATT&CK technique id(s).
    pub mitre: &'static [&'static str],
    /// Representative known-bad sample SHA-256(s) (capped; use `loldrivers_id`
    /// for the full live sample set).
    pub sha256: &'static [&'static str],
    /// A known sample loads despite HVCI (Vulnerable Driver Blocklist relevance).
    pub loads_despite_hvci: bool,
    /// Documented in public reporting as abused to terminate AV/EDR processes.
    pub edr_killer: bool,
}

#[path = "drivers_data.rs"]
mod drivers_data;
#[doc(inline)]
pub use drivers_data::{BYOVD_DRIVERS, BYOVD_DRIVER_NAMES, KNOWN_VULNERABLE_DRIVERS};

/// Returns `true` if `basename` is a known-vulnerable / known-malicious driver
/// from the [LOLDrivers] dataset (case-insensitive; accepts the name with or
/// without a `.sys` suffix).
///
/// **DENYLIST lead gate, not a verdict**: a `true` result means a driver with
/// this *name* appears in the BYOVD dataset and warrants investigation — it does
/// NOT prove this particular file is the vulnerable driver (a benign namesake can
/// trip it). A `false` result does NOT prove the driver is safe (a renamed
/// vulnerable sample evades a name match, and the snapshot is non-exhaustive).
/// Corroborate with the on-disk hash (the precise form), the Authenticode
/// signature, and the load path. See [`KNOWN_VULNERABLE_DRIVERS`].
///
/// [LOLDrivers]: https://www.loldrivers.io/
#[must_use]
pub fn is_known_vulnerable_driver(basename: &str) -> bool {
    let mut lower = basename.trim().to_ascii_lowercase();
    if !lower.ends_with(".sys") {
        lower.push_str(".sys");
    }
    KNOWN_VULNERABLE_DRIVERS.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_is_non_trivial() {
        assert!(KNOWN_VULNERABLE_DRIVERS.len() >= 500);
    }

    #[test]
    fn all_entries_lowercase_bare_sys() {
        for &d in KNOWN_VULNERABLE_DRIVERS {
            assert_eq!(d, d.to_ascii_lowercase());
            assert!(d.ends_with(".sys"));
            assert!(!d.contains('\\') && !d.contains('/'));
        }
    }

    #[test]
    fn no_duplicate_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for &d in KNOWN_VULNERABLE_DRIVERS {
            assert!(seen.insert(d), "duplicate: {d}");
        }
    }

    #[test]
    fn flags_rtcore64() {
        assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"rtcore64.sys"));
        assert!(is_known_vulnerable_driver("rtcore64.sys"));
        assert!(is_known_vulnerable_driver("rtcore64"));
    }

    #[test]
    fn flags_dbutil_2_3() {
        assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"dbutil_2_3.sys"));
        assert!(is_known_vulnerable_driver("dbutil_2_3.sys"));
    }

    #[test]
    fn byovd_drivers_table_is_enriched() {
        assert!(BYOVD_DRIVERS.len() >= 600);
        // KNOWN_VULNERABLE_DRIVERS is exactly the table's basenames (single source).
        let bn: std::vec::Vec<&str> = BYOVD_DRIVERS.iter().map(|d| d.file_basename).collect();
        assert_eq!(KNOWN_VULNERABLE_DRIVERS, bn.as_slice());
        // rtcore64 is fully enriched (GUID + CVE + MITRE + EDR-killer + category).
        let rt = BYOVD_DRIVERS
            .iter()
            .find(|d| d.file_basename == "rtcore64.sys");
        assert!(rt.is_some_and(|d| {
            !d.loldrivers_id.is_empty()
                && d.cve.contains(&"CVE-2019-16098")
                && d.mitre.contains(&"T1068")
                && d.edr_killer
                && d.category == DriverCategory::Vulnerable
                && d.category != DriverCategory::Malicious
        }));
        // enrichment coverage across the set.
        assert!(BYOVD_DRIVERS.iter().any(|d| d.loads_despite_hvci));
        assert!(BYOVD_DRIVERS
            .iter()
            .any(|d| d.category == DriverCategory::Malicious));
        assert!(BYOVD_DRIVERS.iter().any(|d| !d.sha256.is_empty()));
        assert!(BYOVD_DRIVERS.iter().any(|d| !d.service_names.is_empty()));
        assert!(!format!("{:?}", BYOVD_DRIVERS[0]).is_empty()); // Debug
    }

    #[test]
    fn flags_case_insensitive() {
        assert!(is_known_vulnerable_driver("RTCore64.SYS"));
    }

    #[test]
    fn flags_trimmed() {
        assert!(is_known_vulnerable_driver("  rtcore64.sys  "));
    }

    #[test]
    fn does_not_flag_legit_windows_drivers() {
        assert!(!is_known_vulnerable_driver("ntfs.sys"));
        assert!(!is_known_vulnerable_driver("tcpip.sys"));
        assert!(!is_known_vulnerable_driver("NTFS.SYS"));
    }

    #[test]
    fn does_not_flag_empty_or_random() {
        assert!(!is_known_vulnerable_driver(""));
        assert!(!is_known_vulnerable_driver("totally-not-a-driver.sys"));
    }
}
