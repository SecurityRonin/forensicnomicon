//! Known-good Windows **service-binary** catalog — the baseline a System32
//! service-masquerade detector subtracts legitimate binaries against.
//!
//! A common adversary technique is to register a malicious standalone `.exe` as
//! a Windows service and drop it in `System32` under a plausible name, so it
//! blends in with the dozens of legitimate standalone-OwnProcess service
//! executables that genuinely live there (MITRE ATT&CK
//! [T1036.005 — Masquerading: Match Legitimate Name or Location] and
//! [T1543.003 — Create or Modify System Process: Windows Service]). The DC01
//! `coreupdater.exe` implant in the DFIRMadness "Szechuan Sauce" case is the
//! canonical example: a type-`0x10` (`SERVICE_WIN32_OWN_PROCESS`), auto-start
//! service whose `ImagePath` is `C:\Windows\System32\coreupdater.exe` —
//! structurally indistinguishable from `dns.exe` / `msdtc.exe` / `ismserv.exe`
//! until you have a known-good list to subtract.
//!
//! [`processes`](crate::processes)'s `WINDOWS_MASQUERADE_TARGETS` covers the
//! most-*impersonated* core process names (a deny-style indicator list); this
//! module is the complementary **allow-style** baseline of legitimate *service*
//! executables. Finding a System32-resident OwnProcess service whose basename
//! is NOT in [`KNOWN_WINDOWS_SERVICE_BINARIES`] is a **lead**, not a verdict —
//! it warrants signature / path / hash / ancestry corroboration.
//!
//! ## Scope
//!
//! Entries are lowercase basenames of legitimate **standalone OwnProcess**
//! (`SERVICE_WIN32_OWN_PROCESS`, type `0x10`) service executables that ship in
//! `System32` / `SysWOW64`. The vast majority of Windows services are
//! `svchost.exe`-hosted (`SERVICE_WIN32_SHARE_PROCESS`, type `0x20`) and carry a
//! `ServiceDll` rather than a distinct image; those are out of scope here — see
//! the [`SVCHOST_HOST_BINARY`] note. Kernel/filesystem driver services
//! (types `0x01`/`0x02`, `.sys` images) are likewise out of scope.
//!
//! ## NON-EXHAUSTIVE
//!
//! Windows ships hundreds of services and the set varies by OS version, edition,
//! installed roles, and optional features; third-party software adds its own
//! OwnProcess services. This catalog cannot be complete, and it deliberately
//! gates a *lead*, never a verdict. Absence from the list means "investigate",
//! not "malicious"; presence means "a binary with this name is a documented
//! legitimate Windows service image", not "this particular file is benign"
//! (a masquerade reuses a legit *name*). Corroborate with the on-disk path,
//! a code-signature / hash check, and process ancestry before concluding.
//!
//! # Sources
//!
//! - Microsoft — "Security guidelines for system services in Windows Server"
//!   (per-service catalog: service name, image, startup type):
//!   <https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server>
//! - Microsoft — Windows service architecture / SCM (`OwnProcess` vs
//!   `ShareProcess`, image-path semantics):
//!   <https://learn.microsoft.com/en-us/windows/win32/services/service-programs>
//! - Russinovich, Solomon & Ionescu — *Windows Internals, 7th ed.*, Chapter 9
//!   ("Management mechanisms — Services"): SCM, service types, svchost grouping.
//! - SANS FOR508 — "Advanced Incident Response, Threat Hunting & Digital
//!   Forensics": known-good service-binary baseline methodology.
//! - Elastic Security — "Persistence via a Windows Service" / service-image
//!   anomaly detection rules:
//!   <https://www.elastic.co/guide/en/security/current/persistence-via-a-windows-service.html>
//! - MITRE ATT&CK T1036.005 / T1543.003:
//!   <https://attack.mitre.org/techniques/T1036/005/> ·
//!   <https://attack.mitre.org/techniques/T1543/003/>
//!
//! [T1036.005 — Masquerading: Match Legitimate Name or Location]: https://attack.mitre.org/techniques/T1036/005/
//! [T1543.003 — Create or Modify System Process: Windows Service]: https://attack.mitre.org/techniques/T1543/003/

/// The generic Windows service host binary. Most Windows services are NOT
/// standalone executables — they are DLLs (a `ServiceDll` under the service's
/// `Parameters` key) loaded into a shared `svchost.exe` process group
/// (`SERVICE_WIN32_SHARE_PROCESS`, type `0x20`). For those, the *image* is
/// always `svchost.exe`; the forensically interesting identifier is the
/// `ServiceDll`, which is outside this catalog's basename-of-exe scope.
///
/// Source: Windows Internals 7th ed., ch.9 (svchost service grouping);
/// <https://learn.microsoft.com/en-us/windows/win32/services/service-programs>.
pub const SVCHOST_HOST_BINARY: &str = "svchost.exe";

/// Lowercase basenames of legitimate **standalone OwnProcess** Windows service
/// executables that ship in `System32` / `SysWOW64`.
///
/// **NON-EXHAUSTIVE** — see the module docs. This gates a masquerade *lead*, not
/// a verdict. Each category is sourced in the comment above it.
pub const KNOWN_WINDOWS_SERVICE_BINARIES: &[&str] = &[
    // === Core OS — standalone OwnProcess services in System32 ===
    // Sources: MS "Security guidelines for system services in Windows Server";
    // Windows Internals 7th ed. ch.9 (SCM / service descriptions).
    "services.exe",      // Service Control Manager (SCM) host
    "svchost.exe",       // Generic service host (OwnProcess for some groups)
    "spoolsv.exe",       // Print Spooler
    "lsass.exe",         // Local Security Authority Subsystem (runs services)
    "msdtc.exe",         // Distributed Transaction Coordinator
    "vssvc.exe",         // Volume Shadow Copy
    "wbengine.exe",      // Block Level Backup Engine (Windows Backup)
    "searchindexer.exe", // Windows Search indexer
    "sppsvc.exe",        // Software Protection Platform
    "dllhost.exe",       // COM+ System Application / COM surrogate host
    "msiexec.exe",       // Windows Installer service
    "alg.exe",           // Application Layer Gateway
    "locator.exe",       // Remote Procedure Call (RPC) Locator
    "snmptrap.exe",      // SNMP Trap
    "snmp.exe",          // SNMP Service
    "dashost.exe",       // Device Association Framework host
    "lsm.exe",           // Local Session Manager (older builds)
    "vds.exe",           // Virtual Disk Service
    "sihost.exe",        // Shell Infrastructure Host
    "fontdrvhost.exe",   // Usermode Font Driver Host
    "wlms.exe",          // Windows Licensing Monitoring (older Server)
    "tlntsvr.exe",       // Telnet Server (legacy)
    "ui0detect.exe",     // Interactive Services Detection (legacy)
    "wecsvc.exe",        // Windows Event Collector (also svchost-hosted)
    "sppextcomobj.exe",  // KMS connection broker (SPP external COM object)
    "appvclient.exe",    // Microsoft App-V client
    "wuauclt.exe",       // Windows Update (legacy client)
    "usocoreworker.exe", // Update Session Orchestrator worker
    // === Active Directory Domain Services / Domain-Controller roles ===
    // Sources: MS Windows Server service guidelines (AD DS roles);
    // SANS FOR508 DC baseline. (These are the family the DC01 case lives in.)
    "dns.exe",     // DNS Server
    "dfssvc.exe",  // DFS Namespace
    "dfsrs.exe",   // DFS Replication
    "ismserv.exe", // Intersite Messaging
    "ntfrs.exe",   // File Replication Service (legacy SYSVOL replication)
    "certsrv.exe", // Active Directory Certificate Services
    "wins.exe",    // Windows Internet Name Service
    "dhcp.exe",    // DHCP Server (alt image name on some builds)
    "tssdis.exe",  // RD Connection Broker (Terminal Services Session Directory)
    "tcpsvcs.exe", // Simple TCP/IP + DHCP-related host
    "dnsmgr.exe",  // DNS management helper (role tooling)
    // === Other server roles (IIS, Hyper-V, SQL, Print, WSUS, Exchange) ===
    // Sources: respective product docs; SANS FOR508 role baselines.
    "inetinfo.exe",                 // IIS metabase / legacy IIS host
    "w3wp.exe",                     // IIS worker process (apppool)
    "was.exe",                      // Windows Process Activation Service host (legacy)
    "vmms.exe",                     // Hy-V Virtual Machine Management Service
    "vmcompute.exe",                // Hyper-V Host Compute Service
    "sqlservr.exe",                 // SQL Server database engine
    "sqlwriter.exe",                // SQL Server VSS Writer
    "reportingservicesservice.exe", // SQL Server Reporting Services
    "msmdsrv.exe",                  // SQL Server Analysis Services
    "spoolss.exe",                  // Print subsystem (alt)
    "wsusservice.exe",              // WSUS service
    "wdeploymentserver.exe",        // Windows Deployment Services server
    "wdsserver.exe",                // Windows Deployment Services (alt image)
    // === Common Microsoft platform / security services ===
    // Sources: Microsoft Defender / platform docs; Elastic service rules.
    "msmpeng.exe",               // Microsoft Defender Antivirus engine
    "nissrv.exe",                // Defender Network Inspection Service
    "mssense.exe",               // Microsoft Defender for Endpoint sense
    "securityhealthservice.exe", // Windows Security Health Service
    "wmpnetwk.exe",              // Windows Media Player Network Sharing
    "trustedinstaller.exe",      // Windows Modules Installer (servicing)
    "ngciso.exe",                // NGC Container Isolation (passport)
    "wbiosrvc.exe",              // Windows Biometric Service host (older)
];

/// Returns `true` if `basename` is a known-good standalone Windows service
/// binary (case-insensitive; accepts the name with or without a `.exe` suffix).
///
/// This is an **allow-style lead gate**, not a verdict: a System32 OwnProcess
/// service whose image basename returns `false` warrants investigation, and a
/// `true` result only means the *name* is a documented legitimate service image
/// (a masquerade reuses a legit name — corroborate path / signature / hash).
/// See the module docs (NON-EXHAUSTIVE).
#[must_use]
pub fn is_known_service_binary(basename: &str) -> bool {
    let mut lower = basename.trim().to_ascii_lowercase();
    if !lower.ends_with(".exe") {
        lower.push_str(".exe");
    }
    KNOWN_WINDOWS_SERVICE_BINARIES.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_binary_is_svchost() {
        assert_eq!(SVCHOST_HOST_BINARY, "svchost.exe");
    }

    #[test]
    fn catalog_is_comprehensive() {
        assert!(KNOWN_WINDOWS_SERVICE_BINARIES.len() >= 40);
    }

    #[test]
    fn all_entries_lowercase_bare_exe() {
        for &b in KNOWN_WINDOWS_SERVICE_BINARIES {
            assert_eq!(b, b.to_ascii_lowercase());
            assert!(b.ends_with(".exe"));
            assert!(!b.contains('\\') && !b.contains('/'));
        }
    }

    #[test]
    fn no_duplicate_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for &b in KNOWN_WINDOWS_SERVICE_BINARIES {
            assert!(seen.insert(b), "duplicate: {b}");
        }
    }

    #[test]
    fn legit_dc_six_present() {
        for b in [
            "dfssvc.exe",
            "dfsrs.exe",
            "dns.exe",
            "ismserv.exe",
            "msdtc.exe",
            "sppsvc.exe",
        ] {
            assert!(is_known_service_binary(b), "{b}");
        }
    }

    #[test]
    fn case_insensitive() {
        assert!(is_known_service_binary("MSDTC.EXE"));
        assert!(is_known_service_binary("Dns.Exe"));
    }

    #[test]
    fn accepts_with_or_without_exe() {
        assert!(is_known_service_binary("msdtc"));
        assert!(is_known_service_binary("msdtc.exe"));
    }

    #[test]
    fn implant_is_unknown() {
        assert!(!is_known_service_binary("coreupdater.exe"));
        assert!(!is_known_service_binary("coreupdater"));
    }

    #[test]
    fn empty_and_random_unknown() {
        assert!(!is_known_service_binary(""));
        assert!(!is_known_service_binary("totally-not-a-service"));
    }

    #[test]
    fn whitespace_trimmed() {
        assert!(is_known_service_binary("  dns  "));
    }
}
