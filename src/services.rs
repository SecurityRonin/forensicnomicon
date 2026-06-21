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
//! [`KNOWN_WINDOWS_SERVICE_BINARIES`] entries are lowercase basenames of
//! legitimate **standalone OwnProcess** (`SERVICE_WIN32_OWN_PROCESS`, type
//! `0x10`) service executables that ship in `System32` / `SysWOW64`. The vast
//! majority of Windows services are `svchost.exe`-hosted
//! (`SERVICE_WIN32_SHARE_PROCESS`, type `0x20`) and carry a `ServiceDll` rather
//! than a distinct image; those DLLs are catalogued separately in
//! [`KNOWN_WINDOWS_SERVICE_DLLS`] / [`is_known_service_dll`] — the complement
//! that baselines the svchost implant vector. Kernel/filesystem driver services
//! (types `0x01`/`0x02`, `.sys` images) are out of scope for both.
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
/// `ServiceDll`, baselined separately in [`KNOWN_WINDOWS_SERVICE_DLLS`].
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

/// Lowercase `.dll` basenames of legitimate **svchost-hosted** Windows service
/// DLLs — the `ServiceDll` value under a service's `Parameters` key that a
/// `SERVICE_WIN32_SHARE_PROCESS` (type `0x20`) service loads into a shared
/// `svchost.exe` group.
///
/// This is the **complement** to [`KNOWN_WINDOWS_SERVICE_BINARIES`]: that list
/// baselines standalone OwnProcess service *exes*; this one baselines the *DLLs*
/// that svchost-hosted services load. Because `svchost.exe` is the same image
/// for every hosted service, the forensically interesting identifier is the
/// `ServiceDll`, and a *malicious* ServiceDll — a planted `.dll` registered as
/// the code a legitimate-looking service loads — is the **#1 svchost implant
/// vector** (MITRE ATT&CK
/// [T1543.003 — Create or Modify System Process: Windows Service] and
/// [T1036.005 — Masquerading: Match Legitimate Name or Location]). A
/// svchost-hosted service whose `ServiceDll` basename is NOT in this catalog,
/// or whose ServiceDll resolves outside `System32` (e.g. `\Temp\`, a user
/// profile, `ProgramData`), is a **lead**, not a verdict.
///
/// **NON-EXHAUSTIVE** — Windows ships hundreds of svchost-hosted services and
/// the set varies by OS version, edition, installed roles (a domain controller
/// loads AD-DS DLLs a workstation never has), and optional features; third-party
/// software registers its own ServiceDlls. This catalog cannot be complete and
/// it deliberately gates a *lead*, never a verdict. Absence means "investigate",
/// not "malicious"; presence means "a DLL with this name is a documented
/// legitimate Windows ServiceDll" — a masquerade reuses a legit *name*, so
/// corroborate with the on-disk path (must be `System32`), a code-signature /
/// hash check, and the hosting svchost group before concluding.
///
/// The bulk of this catalog (106 unique basenames) is the exact set of
/// `Parameters\ServiceDll` values observed on the genuine DFIRMadness "Szechuan
/// Sauce" DC01 `SYSTEM` hive (117 ServiceDll rows; several DLLs host multiple
/// services — `rpcss.dll` → `DcomLaunch`+`RpcSs`, `icsvc.dll` → 7 Hyper-V
/// integration services, `wdi.dll` → `WdiServiceHost`+`WdiSystemHost`). See
/// `tests/service_dlls_dc01_baseline.rs` for the baseline-completeness proof.
///
/// # Sources
///
/// - Microsoft — "Security guidelines for system services in Windows Server"
///   (per-service catalog, incl. svchost-hosted services and their DLLs):
///   <https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server>
/// - Russinovich, Solomon & Ionescu — *Windows Internals, 7th ed.*, Chapter 9
///   ("Management mechanisms — Services"): svchost grouping and `ServiceDll`.
/// - SANS FOR508 — "Advanced Incident Response, Threat Hunting & Digital
///   Forensics": svchost / ServiceDll known-good baseline methodology.
/// - Elastic Security — service-DLL anomaly detection rules (svchost loading a
///   ServiceDll from an unexpected path / unknown name):
///   <https://www.elastic.co/guide/en/security/current/persistence-via-a-windows-service.html>
/// - MITRE ATT&CK T1543.003 / T1036.005:
///   <https://attack.mitre.org/techniques/T1543/003/> ·
///   <https://attack.mitre.org/techniques/T1036/005/>
/// - Ground truth: DFIRMadness "Szechuan Sauce" DC01 `SYSTEM` hive (the genuine
///   106-entry ServiceDll set), parsed via `winreg-core` in the validation test.
///
/// [T1543.003 — Create or Modify System Process: Windows Service]: https://attack.mitre.org/techniques/T1543/003/
/// [T1036.005 — Masquerading: Match Legitimate Name or Location]: https://attack.mitre.org/techniques/T1036/005/
pub const KNOWN_WINDOWS_SERVICE_DLLS: &[&str] = &[
    // === Core OS — RPC / COM / base platform svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines; Windows Internals 7th ed.
    // ch.9 (svchost grouping). Set confirmed against the real DC01 SYSTEM hive.
    "rpcss.dll",    // Remote Procedure Call (RpcSs) + DCOM Launch (DcomLaunch)
    "rpcepmap.dll", // RPC Endpoint Mapper (RpcEptMapper)
    "es.dll",       // COM+ Event System (EventSystem)
    "bisrv.dll",    // Background Tasks Infrastructure (BrokerInfrastructure)
    "systemeventsbrokerserver.dll", // System Events Broker (SystemEventsBroker)
    "fntcache.dll", // Windows Font Cache Service (FontCache)
    "fontcache.dll", // Windows Font Cache (alt image name across builds)
    "themeservice.dll", // Themes
    "shsvcs.dll",   // Shell Hardware Detection (ShellHWDetection)
    "profsvc.dll",  // User Profile Service (ProfSvc)
    "gpsvc.dll",    // Group Policy Client (gpsvc)
    "seclogon.dll", // Secondary Logon (seclogon)
    "sens.dll",     // System Event Notification Service (SENS)
    "sessenv.dll",  // Remote Desktop Configuration (SessionEnv)
    "umpo.dll",     // Power (Power)
    "umpnpmgr.dll", // Plug and Play (PlugPlay) + Device Install (DeviceInstall)
    "hidserv.dll",  // Human Interface Device Service (hidserv)
    "wpdbusenum.dll", // Portable Device Enumerator (WPDBusEnum)
    "das.dll",      // Device Association Service (DeviceAssociationService)
    "devicesetupmanager.dll", // Device Setup Manager (DsmSvc)
    "wudfsvc.dll",  // Windows Driver Foundation - user-mode driver framework (wudfsvc)
    "scdeviceenum.dll", // Smart Card Device Enumeration (ScDeviceEnum)
    "scardsvr.dll", // Smart Card (SCardSvr)
    "certprop.dll", // Certificate Propagation (CertPropSvc) + smart-card policy (SCPolicySvc)
    "wcspluginservice.dll", // Windows Color System plug-in (WcsPlugInService)
    "printconfig.dll", // Printer Extensions and Notifications (PrintNotify)
    "pla.dll",      // Performance Logs & Alerts (pla)
    "wdi.dll",      // Diagnostic Service/System Host (WdiServiceHost / WdiSystemHost)
    "dps.dll",      // Diagnostic Policy Service (DPS)
    "fdphost.dll",  // Function Discovery Provider Host (fdPHost)
    "fdrespub.dll", // Function Discovery Resource Publication (FDResPub)
    "mmcss.dll",    // Multimedia Class Scheduler (MMCSS) + Thread Ordering Server (THREADORDER)
    "sysmain.dll",  // SysMain / Superfetch (SysMain)
    "defragsvc.dll", // Optimize drives / Disk Defragmenter (defragsvc)
    "trkwks.dll",   // Distributed Link Tracking Client (TrkWks)
    "appinfo.dll",  // Application Information (Appinfo)
    "appmgmts.dll", // Application Management (AppMgmt)
    "appreadiness.dll", // App Readiness (AppReadiness)
    "appxdeploymentserver.dll", // AppX Deployment Service (AppXSvc)
    "aelupsvc.dll", // Application Experience / Lookup Service (AeLookupSvc)
    "appidsvc.dll", // Application Identity (AppIDSvc)
    "wcmsvc.dll",   // Windows Connection Manager (Wcmsvc)
    "ualsvc.dll",   // User Access Logging Service (UALSVC)
    "smphost.dll",  // Storage Spaces SMP host (smphost)
    "svsvc.dll",    // Spot Verifier (svsvc)
    "wephostsvc.dll", // Windows Encryption Provider Host (WEPHOSTSVC)
    "vaultsvc.dll", // Credential Manager (VaultSvc)
    "keyiso.dll",   // CNG Key Isolation (KeyIso)
    "cryptsvc.dll", // Cryptographic Services (CryptSvc)
    "efssvc.dll",   // Encrypting File System (EFS)
    "wbiosrvc.dll", // Windows Biometric Service (svchost-hosted variant)
    // === Networking svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines; Elastic network-service rules.
    "dnsrslvr.dll",    // DNS Client (Dnscache)
    "dhcpcore.dll",    // DHCP Client (Dhcp)
    "iphlpsvc.dll",    // IP Helper (iphlpsvc)
    "nlasvc.dll",      // Network Location Awareness (NlaSvc)
    "netprofmsvc.dll", // Network List Service (netprofm)
    "ncasvc.dll",      // Network Connectivity Assistant (NcaSvc)
    "netman.dll",      // Network Connections (Netman)
    "nsisvc.dll",      // Network Store Interface Service (nsi)
    "bfe.dll",         // Base Filtering Engine (BFE)
    "mpssvc.dll",      // Windows Firewall / Defender Firewall (MpsSvc)
    "ikeext.dll",      // IKE and AuthIP IPsec Keying Modules (IKEEXT)
    "ipsecsvc.dll",    // IPsec Policy Agent (PolicyAgent)
    "ipnathlp.dll",    // Internet Connection Sharing / NAT (SharedAccess)
    "winhttp.dll",     // WinHTTP Web Proxy Auto-Discovery (WinHttpAutoProxySvc)
    "wkssvc.dll",      // Workstation (LanmanWorkstation)
    "srvsvc.dll",      // Server (LanmanServer)
    "browser.dll",     // Computer Browser (Browser)
    "lmhsvc.dll",      // TCP/IP NetBIOS Helper (lmhosts)
    "ssdpsrv.dll",     // SSDP Discovery (SSDPSRV)
    "upnphost.dll",    // UPnP Device Host (upnphost)
    "lltdsvc.dll",     // Link-Layer Topology Discovery Mapper (lltdsvc)
    "dot3svc.dll",     // Wired AutoConfig (dot3svc)
    "eapsvc.dll",      // Extensible Authentication Protocol (Eaphost)
    "rasauto.dll",     // Remote Access Auto Connection Manager (RasAuto)
    "rasmans.dll",     // Remote Access Connection Manager (RasMan)
    "mprdim.dll",      // Routing and Remote Access (RemoteAccess)
    "sstpsvc.dll",     // Secure Socket Tunneling Protocol Service (SstpSvc)
    "qagentrt.dll",    // Network Access Protection Agent (napagent)
    "tapisrv.dll",     // Telephony (TapiSrv)
    "iscsiexe.dll",    // Microsoft iSCSI Initiator Service (MSiSCSI)
    "w32time.dll",     // Windows Time (W32Time)
    // === Remote management / remote desktop / event-collector svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines; SANS FOR508 lateral-movement baseline.
    "termsrv.dll",  // Remote Desktop Services (TermService)
    "umrdp.dll",    // Remote Desktop Services UserMode Port Redirector (UmRdpService)
    "regsvc.dll",   // Remote Registry (RemoteRegistry)
    "wsmsvc.dll",   // Windows Remote Management / WS-Management (WinRM)
    "wecsvc.dll",   // Windows Event Collector (Wecsvc)
    "wmisvc.dll",   // Windows Management Instrumentation (Winmgmt)
    "schedsvc.dll", // Task Scheduler (Schedule)
    "qmgr.dll",     // Background Intelligent Transfer Service (BITS)
    "wuaueng.dll",  // Windows Update (wuauserv)
    "sacsvr.dll",   // Special Administration Console Helper (sacsvr)
    // === Audio / media / shell user-session svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines.
    "audiosrv.dll",             // Windows Audio (Audiosrv)
    "audioendpointbuilder.dll", // Windows Audio Endpoint Builder (AudioEndpointBuilder)
    "lsm.dll",                  // Local Session Manager (LSM)
    // === Diagnostics / error-reporting svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines.
    "wersvc.dll",        // Windows Error Reporting Service (WerSvc)
    "wercplsupport.dll", // Problem Reports control-panel support (wercplsupport)
    "kmsvc.dll",         // Health Key and Certificate Management (hkmsvc)
    "wsservice.dll",     // Windows Store Service (WSService)
    // === Hyper-V integration / virtualization svchost ServiceDlls ===
    // Sources: MS Hyper-V integration-services docs; Windows Internals 7th ed.
    "icsvc.dll", // Hyper-V integration services (vmicheartbeat / vmicvss / vmicshutdown / vmictimesync / vmickvpexchange / vmicrdv / vmicguestinterface)
    "swprv.dll", // Microsoft Software Shadow Copy Provider (swprv)
    // === Active Directory Domain Services / Domain-Controller-role svchost ServiceDlls ===
    // Sources: MS Windows Server service guidelines (AD DS roles); SANS FOR508
    // DC baseline. These are the family the DC01 case lives in.
    "ntdsa.dll",     // Active Directory Domain Services (NTDS)
    "kdcsvc.dll",    // Kerberos Key Distribution Center (Kdc)
    "kpssvc.dll",    // Microsoft Key Protection Service (KPSSVC)
    "kdssvc.dll",    // Microsoft Key Distribution Service (KdsSvc)
    "dsrolesrv.dll", // DS Role Server (DsRoleSvc)
    "netlogon.dll",  // Netlogon (Netlogon)
    "msdtckrm.dll",  // KtmRm for Distributed Transaction Coordinator (KtmRm)
];

/// Returns `true` if `basename` is a known-good svchost-hosted Windows
/// `ServiceDll` (case-insensitive; accepts the name with or without a `.dll`
/// suffix).
///
/// This is an **allow-style lead gate**, not a verdict: a svchost-hosted service
/// whose `ServiceDll` basename returns `false` — or whose ServiceDll resolves
/// outside `System32` — warrants investigation (T1543.003 / T1036.005), and a
/// `true` result only means the *name* is a documented legitimate ServiceDll
/// (a masquerade reuses a legit name — corroborate path / signature / hash).
/// See [`KNOWN_WINDOWS_SERVICE_DLLS`] (NON-EXHAUSTIVE).
#[must_use]
pub fn is_known_service_dll(basename: &str) -> bool {
    let mut lower = basename.trim().to_ascii_lowercase();
    if !lower.ends_with(".dll") {
        lower.push_str(".dll");
    }
    KNOWN_WINDOWS_SERVICE_DLLS.contains(&lower.as_str())
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

    // --- svchost ServiceDll catalog ---

    #[test]
    fn dll_catalog_covers_real_dc01_baseline() {
        // The genuine DC01 hive has 106 unique ServiceDll basenames; the catalog
        // covers all of them (plus a couple of common cross-build aliases).
        assert!(KNOWN_WINDOWS_SERVICE_DLLS.len() >= 106);
    }

    #[test]
    fn all_dll_entries_lowercase_bare_dll() {
        for &d in KNOWN_WINDOWS_SERVICE_DLLS {
            assert_eq!(d, d.to_ascii_lowercase());
            assert!(d.ends_with(".dll"));
            assert!(!d.contains('\\') && !d.contains('/'));
        }
    }

    #[test]
    fn no_duplicate_dll_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for &d in KNOWN_WINDOWS_SERVICE_DLLS {
            assert!(seen.insert(d), "duplicate: {d}");
        }
    }

    #[test]
    fn known_service_dll_brief_examples() {
        assert!(is_known_service_dll("dnsrslvr.dll"));
        assert!(is_known_service_dll("schedsvc.dll"));
        assert!(is_known_service_dll("qmgr.dll"));
    }

    #[test]
    fn known_service_dll_case_insensitive() {
        assert!(is_known_service_dll("DNSRSLVR.DLL"));
        assert!(is_known_service_dll("SchedSvc.Dll"));
    }

    #[test]
    fn known_service_dll_accepts_with_or_without_dll() {
        assert!(is_known_service_dll("qmgr"));
        assert!(is_known_service_dll("qmgr.dll"));
    }

    #[test]
    fn masquerade_dll_is_unknown() {
        assert!(!is_known_service_dll("evil.dll"));
        assert!(!is_known_service_dll("evil"));
    }

    #[test]
    fn empty_and_random_dll_unknown() {
        assert!(!is_known_service_dll(""));
        assert!(!is_known_service_dll("totally-not-a-service"));
    }

    #[test]
    fn dll_whitespace_trimmed() {
        assert!(is_known_service_dll("  qmgr.dll  "));
    }
}
