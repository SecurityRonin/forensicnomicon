//! Living Off the Land Binaries and Scripts (LOLBAS) + Living Off Foreign Land (LOFL)
//! across Windows, Linux, and macOS — all six upstream datasets in a single module.
//!
//! # Taxonomy
//!
//! **LOL (Living Off the Land):** Abuse of binaries, scripts, and libraries
//! that ship with the OS itself. On Windows these are catalogued by the LOLBAS
//! Project; on Linux by GTFOBins; on macOS by the LOOBins project.
//!
//! **LOFL (Living Off Foreign Land):** Abuse of *third-party* admin tools that
//! are commonly installed on enterprise endpoints — Sysinternals, cloud CLIs,
//! container runtimes, language runtimes, and so on. The LOFL Project catalogues
//! Windows tools; this module adds the first published macOS LOFL catalog
//! (`research/macos-lofl-catalog.yaml`).
//!
//! From a **detection standpoint the distinction is immaterial**: both LOL and
//! LOFL binaries appear identically in process telemetry, Prefetch, AmCache,
//! and EDR telemetry. Unifying them in a single lookup table — as GTFOBins
//! already does for Linux — produces fewer missed detections and eliminates the
//! need for callers to query two separate lists.
//!
//! # The six constants
//!
//! | Constant | Artifact type | Detection source |
//! |----------|---------------|----------------|
//! | [`LOLBAS_WINDOWS`] | Process name (`.exe`), script (`.vbs`/`.cmd`) | Prefetch, Sysmon, EDR process telemetry |
//! | [`LOLBAS_LINUX`] | Process name (no extension) | auditd `execve`, eBPF, EDR |
//! | [`LOLBAS_MACOS`] | Process name (no extension) | macOS ESF / Endpoint Security, audit.log |
//! | [`LOLBAS_WINDOWS_CMDLETS`] | PowerShell cmdlet name or alias | ScriptBlock log (Event 4104), PSReadLine history, AMSI |
//! | [`LOLBAS_WINDOWS_MMC`] | `.msc` filename | LNK files, UserAssist MRU, Jump Lists |
//! | [`LOLBAS_WINDOWS_WMI`] | WMI class name | WMI Activity log (Event 5861), `Get-CimInstance` |
//!
//! # Upstream sources
//!
//! | Upstream | Constant(s) | Source |
//! |----------|-------------|---------|
//! | LOLBAS Project | [`LOLBAS_WINDOWS`] | <https://lolbas-project.github.io/> · GitHub: <https://github.com/LOLBAS-Project/LOLBAS> |
//! | LOFL Project | [`LOLBAS_WINDOWS`] (foreign-land subset), cmdlets, MMC, WMI | <https://lofl-project.github.io/> · GitHub: <https://github.com/lofl-project/lofl-project.github.io> |
//! | LOOBins | [`LOLBAS_MACOS`] (native) | <https://www.loobins.io/> · GitHub: <https://github.com/infosecB/LOOBins> |
//! | macOS LOFL catalog | [`LOLBAS_MACOS`] (foreign-land) | First published — `research/macos-lofl-catalog.yaml` |
//! | GTFOBins | [`LOLBAS_LINUX`] | <https://gtfobins.github.io/> · GitHub: <https://github.com/GTFOBins/GTFOBins.github.io> |
//!
//! # Unified lookup
//!
//! Use [`is_lolbas`] to query all three platform LOLBAS lists at once.
//! Use [`is_lolbas_windows`], [`is_lolbas_linux`], or [`is_lolbas_macos`] for
//! platform-specific lookups. All comparisons are case-insensitive.
//!
//! ```rust
//! use forensicnomicon::lolbins::{is_lolbas, is_lolbas_windows, is_lolbas_macos};
//! use forensicnomicon::lolbins::{is_lolbas_windows_cmdlet, is_lolbas_windows_wmi};
//!
//! assert!(is_lolbas("certutil.exe"));        // Windows LOLBAS
//! assert!(is_lolbas("bash"));                // Linux GTFOBins
//! assert!(is_lolbas("osascript"));           // macOS LOOBins
//! assert!(is_lolbas("kubectl"));             // macOS LOFL (also Linux GTFOBins)
//! assert!(is_lolbas_windows_cmdlet("Invoke-Command")); // PowerShell LOFL
//! assert!(is_lolbas_windows_wmi("Win32_Process"));   // WMI LOLBAS
//! ```
//!
//! # macOS LOFL catalog — first-of-its-kind research
//!
//! The macOS LOFL section of [`LOLBAS_MACOS`] (tools installed via Homebrew,
//! pip, npm, cargo, etc.) is the **first published macOS LOFL catalog anywhere**.
//! It covers 80 tools with 276 documented abuse techniques across 71 ATT&CK IDs.
//! The raw YAML data lives in `research/macos-lofl-catalog.yaml`.

// ── Use-case bitmask constants ────────────────────────────────────────────────

/// Bitmask constants for [`LolbasEntry::use_cases`].
///
/// Multiple flags may be OR-ed together. Mirrors the abuse-tag pattern
/// used in [`crate::abusable_sites::AbusableSite`].
pub const UC_EXECUTE: u16 = 1 << 0; // arbitrary code/binary execution
pub const UC_DOWNLOAD: u16 = 1 << 1; // fetch files from the network
pub const UC_UPLOAD: u16 = 1 << 2; // exfiltrate / send data out
pub const UC_BYPASS: u16 = 1 << 3; // security control bypass (UAC, AMSI, AWL…)
pub const UC_PERSIST: u16 = 1 << 4; // establish persistence
pub const UC_RECON: u16 = 1 << 5; // discovery / enumeration
pub const UC_PROXY: u16 = 1 << 6; // proxy execution of another payload
pub const UC_DECODE: u16 = 1 << 7; // decode / deobfuscate data
pub const UC_ARCHIVE: u16 = 1 << 8; // compress or expand archives
pub const UC_CREDENTIALS: u16 = 1 << 9; // credential access or manipulation
pub const UC_NETWORK: u16 = 1 << 10; // network configuration or lateral movement
pub const UC_DEFENSE_EVASION: u16 = 1 << 11; // log clearing, AV disable, etc.

/// A single entry in a LOL/LOFL binary or cmdlet catalog.
///
/// Every constant (`LOLBAS_WINDOWS`, `LOLBAS_LINUX`, etc.) is a
/// `&[LolbasEntry]`. Use [`lolbas_entry`] for lookups, or iterate
/// directly for richer queries.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LolbasEntry {
    /// Canonical name (case-preserved, e.g. `"certutil.exe"`, `"curl"`, `"iex"`).
    pub name: &'static str,
    /// MITRE ATT&CK technique IDs observed for this entry.
    pub mitre_techniques: &'static [&'static str],
    /// OR-ed [`UC_*`] bitmask describing known abuse use-cases.
    pub use_cases: u16,
    /// Brief one-line description of why this entry is catalogued.
    pub description: &'static str,
}

/// Returns the [`LolbasEntry`] whose `name` matches `name` (case-insensitive),
/// or `None` if not found.
pub fn lolbas_entry<'a>(catalog: &'a [LolbasEntry], name: &str) -> Option<&'a LolbasEntry> {
    let lower = name.to_ascii_lowercase();
    catalog.iter().find(|e| e.name.to_ascii_lowercase() == lower)
}

/// Returns an iterator over just the names in a catalog slice.
/// Useful for building flat name lists or printing catalogs.
pub fn lolbas_names(catalog: &[LolbasEntry]) -> impl Iterator<Item = &'static str> + '_ {
    catalog.iter().map(|e| e.name)
}

// ── Catalogs ─────────────────────────────────────────────────────────────────

/// Windows LOLBAS — unified LOL (native) + LOFL (foreign admin tools).
///
/// Sources:
/// - LOLBAS Project — native Windows binaries, scripts and libraries:
///   <https://lolbas-project.github.io/>
/// - LOFL Project — third-party Windows admin tools common in enterprise:
///   <https://lofl-project.github.io/>
/// - MITRE ATT&CK T1218 — System Binary Proxy Execution:
///   <https://attack.mitre.org/techniques/T1218/>
/// - SANS ISC — Xavier Mertens, "Keep An Eye on LOLBins":
///   <https://isc.sans.edu/diary/Keep+An+Eye+on+LOLBins/26502>
/// - Red Canary — "Misbehaving Binaries: How to Detect LOLbins Abuse in the Wild":
///   <https://redcanary.com/blog/blog/lolbins-abuse/>
///
/// The "foreign land" distinction is academic from a detection standpoint —
/// both native LOLBAS and third-party LOFL binaries appear identically in
/// process telemetry, Prefetch, and AmCache. Unified here as a single lookup
/// table, mirroring how GTFOBins already unifies LOL + LOFL for Linux.
pub const LOLBAS_WINDOWS: &[LolbasEntry] = &[
    // ── T1218 — Signed Binary Proxy Execution <https://attack.mitre.org/techniques/T1218/> ──
    // T1218.001 — InstallUtil <https://attack.mitre.org/techniques/T1218/001/>
    LolbasEntry {
        name: "installutil.exe",
        mitre_techniques: &["T1218.004"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Execute arbitrary .NET assemblies bypassing application allowlisting.",
    },
    // T1218.003 — CMSTP <https://attack.mitre.org/techniques/T1218/003/>
    LolbasEntry {
        name: "cmstp.exe",
        mitre_techniques: &["T1218.003"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Load malicious INF files to execute code and bypass UAC.",
    },
    // T1218.004 — Regasm / Regsvcs <https://attack.mitre.org/techniques/T1218/004/>
    LolbasEntry {
        name: "regasm.exe",
        mitre_techniques: &["T1218.009"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Register .NET COM assemblies; abused to execute arbitrary code.",
    },
    LolbasEntry {
        name: "regsvcs.exe",
        mitre_techniques: &["T1218.009"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Register .NET COM+ component; abused to execute arbitrary code.",
    },
    // T1218.005 — Mshta / WScript / CScript <https://attack.mitre.org/techniques/T1218/005/>
    LolbasEntry {
        name: "mshta.exe",
        mitre_techniques: &["T1218.005"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Execute HTA applications to bypass application allowlisting.",
    },
    LolbasEntry {
        name: "wscript.exe",
        mitre_techniques: &["T1059.005"],
        use_cases: UC_EXECUTE | UC_PROXY,
        description: "Execute VBScript and JScript files via Windows Script Host.",
    },
    LolbasEntry {
        name: "cscript.exe",
        mitre_techniques: &["T1059.005"],
        use_cases: UC_EXECUTE | UC_PROXY,
        description: "Console-mode Windows Script Host for VBScript/JScript execution.",
    },
    // T1218.007 — Msiexec <https://attack.mitre.org/techniques/T1218/007/>
    LolbasEntry {
        name: "msiexec.exe",
        mitre_techniques: &["T1218.007"],
        use_cases: UC_EXECUTE | UC_DOWNLOAD | UC_BYPASS | UC_PROXY,
        description: "Install MSI packages; abused to download and execute remote payloads.",
    },
    // T1218.008 — Odbcconf <https://attack.mitre.org/techniques/T1218/008/>
    LolbasEntry {
        name: "odbcconf.exe",
        mitre_techniques: &["T1218.008"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Configure ODBC; abused to load arbitrary DLLs via REGSVR action.",
    },
    // T1218.010 — Regsvr32 <https://attack.mitre.org/techniques/T1218/010/>
    LolbasEntry {
        name: "regsvr32.exe",
        mitre_techniques: &["T1218.010"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY | UC_DOWNLOAD,
        description: "Register COM DLLs; squiblydoo technique for remote script execution.",
    },
    // T1218.011 — Rundll32 / PresentationHost <https://attack.mitre.org/techniques/T1218/011/>
    LolbasEntry {
        name: "rundll32.exe",
        mitre_techniques: &["T1218.011"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Execute DLL exports; primary Windows LOLBin for signed proxy execution.",
    },
    LolbasEntry {
        name: "presentationhost.exe",
        mitre_techniques: &["T1218.011"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Host XBAP applications; abused to execute arbitrary .NET payloads.",
    },
    LolbasEntry {
        name: "ieexec.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Internet Explorer exec helper; abused to run remote executables.",
    },
    LolbasEntry {
        name: "xwizard.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Extensible wizard host; abused for DLL sideloading and proxy execution.",
    },
    LolbasEntry {
        name: "msdeploy.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Web Deploy tool; abused to execute arbitrary commands via providers.",
    },
    // ── T1105 / T1140 — certutil ──────────────────────────────────────────────
    LolbasEntry {
        name: "certutil.exe",
        mitre_techniques: &["T1218.001", "T1105", "T1140", "T1027"],
        use_cases: UC_DOWNLOAD | UC_DECODE | UC_BYPASS,
        description: "Encode/decode files and download payloads via certificate utility.",
    },
    // ── T1197 — BITS Jobs <https://attack.mitre.org/techniques/T1197/> ──
    LolbasEntry {
        name: "bitsadmin.exe",
        mitre_techniques: &["T1197"],
        use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_PERSIST,
        description: "BITS job manager; abused to stealthily download/upload and persist.",
    },
    // ── T1059.003 — Windows Command Shell ─────────────────────────────────────
    LolbasEntry {
        name: "cmd.exe",
        mitre_techniques: &["T1059.003"],
        use_cases: UC_EXECUTE,
        description: "Windows command interpreter; universal execution and pivot point.",
    },
    LolbasEntry {
        name: "powershell.exe",
        mitre_techniques: &["T1059.001"],
        use_cases: UC_EXECUTE | UC_DOWNLOAD | UC_BYPASS | UC_RECON,
        description: "PowerShell interpreter; the most abused Windows execution LOLBin.",
    },
    LolbasEntry {
        name: "pwsh.exe",
        mitre_techniques: &["T1059.001"],
        use_cases: UC_EXECUTE | UC_DOWNLOAD | UC_BYPASS | UC_RECON,
        description: "PowerShell 7+ cross-platform interpreter; same abuse as powershell.exe.",
    },
    // ── T1047 — WMI ───────────────────────────────────────────────────────────
    LolbasEntry {
        name: "wmic.exe",
        mitre_techniques: &["T1047"],
        use_cases: UC_EXECUTE | UC_RECON | UC_PROXY,
        description: "WMI command-line interface; remote execution and system enumeration.",
    },
    LolbasEntry {
        name: "wbemtest.exe",
        mitre_techniques: &["T1047"],
        use_cases: UC_RECON | UC_EXECUTE,
        description: "WMI testing tool; abused for interactive WMI namespace exploration.",
    },
    // ── T1003 — Credential Dumping ────────────────────────────────────────────
    LolbasEntry {
        name: "ntdsutil.exe",
        mitre_techniques: &["T1003.003"],
        use_cases: UC_CREDENTIALS | UC_EXECUTE,
        description: "NTDS database utility; abused to dump ntds.dit for offline cracking.",
    },
    // ── T1055 — Process Injection ─────────────────────────────────────────────
    LolbasEntry {
        name: "mavinject.exe",
        mitre_techniques: &["T1055.001"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Microsoft App-V injector; abused for DLL injection into processes.",
    },
    // ── T1053.005 — Scheduled Tasks ───────────────────────────────────────────
    LolbasEntry {
        name: "schtasks.exe",
        mitre_techniques: &["T1053.005"],
        use_cases: UC_PERSIST | UC_EXECUTE,
        description: "Scheduled task management; primary persistence mechanism on Windows.",
    },
    LolbasEntry {
        name: "at.exe",
        mitre_techniques: &["T1053.002"],
        use_cases: UC_PERSIST | UC_EXECUTE,
        description: "Legacy AT job scheduler; deprecated but still abused for persistence.",
    },
    // ── T1021 — Remote services ───────────────────────────────────────────────
    LolbasEntry {
        name: "mstsc.exe",
        mitre_techniques: &["T1021.001"],
        use_cases: UC_NETWORK,
        description: "Remote Desktop client; lateral movement via RDP sessions.",
    },
    LolbasEntry {
        name: "net.exe",
        mitre_techniques: &["T1021.002", "T1087.001", "T1069"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "Network and account management; user/share/session enumeration.",
    },
    LolbasEntry {
        name: "net1.exe",
        mitre_techniques: &["T1021.002"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "Alias for net.exe invoked by the net command internally.",
    },
    LolbasEntry {
        name: "ssh.exe",
        mitre_techniques: &["T1021.004"],
        use_cases: UC_NETWORK | UC_EXECUTE,
        description: "Built-in Windows SSH client; lateral movement and tunneling.",
    },
    LolbasEntry {
        name: "scp.exe",
        mitre_techniques: &["T1021.004", "T1105"],
        use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK,
        description: "Secure copy; file transfer over SSH for staging and exfiltration.",
    },
    LolbasEntry {
        name: "sftp.exe",
        mitre_techniques: &["T1021.004"],
        use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK,
        description: "SSH file transfer protocol client for payload delivery.",
    },
    // ── T1548.002 — UAC Bypass ────────────────────────────────────────────────
    LolbasEntry {
        name: "eventvwr.exe",
        mitre_techniques: &["T1548.002"],
        use_cases: UC_BYPASS,
        description: "Event Viewer; classic UAC bypass via registry hijacking.",
    },
    LolbasEntry {
        name: "fodhelper.exe",
        mitre_techniques: &["T1548.002"],
        use_cases: UC_BYPASS,
        description: "Features on Demand helper; UAC bypass via registry key abuse.",
    },
    LolbasEntry {
        name: "sdclt.exe",
        mitre_techniques: &["T1548.002"],
        use_cases: UC_BYPASS,
        description: "Backup and Restore launcher; UAC bypass via DelegateExecute key.",
    },
    LolbasEntry {
        name: "computerdefaults.exe",
        mitre_techniques: &["T1548.002"],
        use_cases: UC_BYPASS,
        description: "Default programs UI; UAC bypass via registry auto-elevate.",
    },
    // ── T1070 — Indicator Removal ─────────────────────────────────────────────
    LolbasEntry {
        name: "wevtutil.exe",
        mitre_techniques: &["T1070.001"],
        use_cases: UC_DEFENSE_EVASION,
        description: "Windows event log utility; abused to clear event logs.",
    },
    LolbasEntry {
        name: "fsutil.exe",
        mitre_techniques: &["T1070.009"],
        use_cases: UC_DEFENSE_EVASION | UC_RECON,
        description: "File system utility; USN journal manipulation and disk info recon.",
    },
    LolbasEntry {
        name: "cipher.exe",
        mitre_techniques: &["T1070.004"],
        use_cases: UC_DEFENSE_EVASION,
        description: "EFS encryption utility; secure delete of free space to hide evidence.",
    },
    // ── T1112 — Modify Registry ────────────────────────────────────────────────
    LolbasEntry {
        name: "reg.exe",
        mitre_techniques: &["T1112", "T1547.001"],
        use_cases: UC_PERSIST | UC_RECON | UC_DEFENSE_EVASION,
        description: "Registry CLI; read/write/export registry for persistence and recon.",
    },
    LolbasEntry {
        name: "regedit.exe",
        mitre_techniques: &["T1112"],
        use_cases: UC_PERSIST | UC_RECON,
        description: "Registry editor GUI; abused to import malicious .reg files.",
    },
    LolbasEntry {
        name: "regini.exe",
        mitre_techniques: &["T1112"],
        use_cases: UC_PERSIST,
        description: "Set registry permissions; abused to modify ACLs for persistence.",
    },
    // ── T1140 — Decode ────────────────────────────────────────────────────────
    LolbasEntry {
        name: "expand.exe",
        mitre_techniques: &["T1140"],
        use_cases: UC_DECODE,
        description: "Cabinet file expander; decode and extract payloads from .cab files.",
    },
    LolbasEntry {
        name: "extrac32.exe",
        mitre_techniques: &["T1140"],
        use_cases: UC_DECODE,
        description: "CAB extraction utility; extract payload from cabinet archives.",
    },
    // ── T1560.001 — Archive ───────────────────────────────────────────────────
    LolbasEntry {
        name: "makecab.exe",
        mitre_techniques: &["T1560.001"],
        use_cases: UC_ARCHIVE,
        description: "Create cabinet archives; stage data for exfiltration.",
    },
    LolbasEntry {
        name: "compact.exe",
        mitre_techniques: &["T1560.001"],
        use_cases: UC_ARCHIVE,
        description: "NTFS compression utility; compress files for staging.",
    },
    LolbasEntry {
        name: "tar.exe",
        mitre_techniques: &["T1560.001"],
        use_cases: UC_ARCHIVE | UC_DOWNLOAD,
        description: "Built-in Windows tar; archive and extract files for payload delivery.",
    },
    // ── T1569.002 — Service Execution ─────────────────────────────────────────
    LolbasEntry {
        name: "sc.exe",
        mitre_techniques: &["T1569.002", "T1543.003"],
        use_cases: UC_EXECUTE | UC_PERSIST,
        description: "Service control manager; create/start services for persistence.",
    },
    // ── T1134 — Token Manipulation ────────────────────────────────────────────
    LolbasEntry {
        name: "runas.exe",
        mitre_techniques: &["T1134"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Run process as another user; privilege escalation and token theft.",
    },
    // ── T1016 — Network Config Discovery ──────────────────────────────────────
    LolbasEntry {
        name: "ipconfig.exe",
        mitre_techniques: &["T1016"],
        use_cases: UC_RECON,
        description: "IP configuration display; network interface and DNS enumeration.",
    },
    LolbasEntry {
        name: "arp.exe",
        mitre_techniques: &["T1016"],
        use_cases: UC_RECON,
        description: "ARP table display; local network host discovery.",
    },
    LolbasEntry {
        name: "netstat.exe",
        mitre_techniques: &["T1049"],
        use_cases: UC_RECON,
        description: "Network connection enumeration; identify listening ports and C2 beacons.",
    },
    LolbasEntry {
        name: "route.exe",
        mitre_techniques: &["T1016"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "Routing table display and modification; network configuration recon.",
    },
    LolbasEntry {
        name: "nslookup.exe",
        mitre_techniques: &["T1018"],
        use_cases: UC_RECON,
        description: "DNS lookup tool; infrastructure mapping and DNS-based C2 testing.",
    },
    LolbasEntry {
        name: "ping.exe",
        mitre_techniques: &["T1018"],
        use_cases: UC_RECON,
        description: "ICMP ping; host discovery and network connectivity checking.",
    },
    LolbasEntry {
        name: "tracert.exe",
        mitre_techniques: &["T1016"],
        use_cases: UC_RECON,
        description: "Traceroute; network topology mapping and path enumeration.",
    },
    // ── T1057 — Process Discovery ─────────────────────────────────────────────
    LolbasEntry {
        name: "tasklist.exe",
        mitre_techniques: &["T1057"],
        use_cases: UC_RECON,
        description: "List running processes; enumerate security tools and targets.",
    },
    LolbasEntry {
        name: "taskkill.exe",
        mitre_techniques: &["T1562.001"],
        use_cases: UC_DEFENSE_EVASION,
        description: "Terminate processes; kill AV/EDR processes for defense evasion.",
    },
    // ── T1082 — System Info Discovery ─────────────────────────────────────────
    LolbasEntry {
        name: "systeminfo.exe",
        mitre_techniques: &["T1082"],
        use_cases: UC_RECON,
        description: "System information display; OS version, hotfixes, hardware fingerprint.",
    },
    LolbasEntry {
        name: "msinfo32.exe",
        mitre_techniques: &["T1082"],
        use_cases: UC_RECON,
        description: "System Information GUI; comprehensive hardware and software inventory.",
    },
    // ── T1083 — File and Directory Discovery ──────────────────────────────────
    LolbasEntry {
        name: "where.exe",
        mitre_techniques: &["T1083"],
        use_cases: UC_RECON,
        description: "Locate executable files in PATH; find security tools and binaries.",
    },
    LolbasEntry {
        name: "attrib.exe",
        mitre_techniques: &["T1083", "T1564.001"],
        use_cases: UC_RECON | UC_DEFENSE_EVASION,
        description: "File attribute manipulation; hide files by setting +H +S flags.",
    },
    LolbasEntry {
        name: "tree.exe",
        mitre_techniques: &["T1083"],
        use_cases: UC_RECON,
        description: "Directory tree display; filesystem structure enumeration.",
    },
    // ── T1124 — System Time Discovery ─────────────────────────────────────────
    LolbasEntry {
        name: "w32tm.exe",
        mitre_techniques: &["T1124"],
        use_cases: UC_RECON,
        description: "Windows Time service tool; NTP enumeration and timestamp manipulation.",
    },
    // ── T1080 — Taint Shared Content ──────────────────────────────────────────
    LolbasEntry {
        name: "xcopy.exe",
        mitre_techniques: &["T1080"],
        use_cases: UC_NETWORK,
        description: "Extended copy; file distribution and lateral movement via shares.",
    },
    LolbasEntry {
        name: "robocopy.exe",
        mitre_techniques: &["T1080", "T1039"],
        use_cases: UC_NETWORK,
        description: "Robust file copy; mass file staging and exfiltration via shares.",
    },
    // ── T1562.001 — Disable Security Tools ────────────────────────────────────
    LolbasEntry {
        name: "netsh.exe",
        mitre_techniques: &["T1562.004", "T1090"],
        use_cases: UC_DEFENSE_EVASION | UC_NETWORK,
        description: "Network shell; firewall rule manipulation and port forwarding.",
    },
    // ── T1127.001 — MSBuild ───────────────────────────────────────────────────
    LolbasEntry {
        name: "msbuild.exe",
        mitre_techniques: &["T1127.001"],
        use_cases: UC_EXECUTE | UC_BYPASS | UC_PROXY,
        description: "Microsoft Build Engine; execute arbitrary C# via inline tasks.",
    },

    // ── LOFL Project — third-party Windows admin tool binaries ────────────────
    // T1569.002 — Service Execution (PsExec) <https://attack.mitre.org/techniques/T1569/002/>
    LolbasEntry {
        name: "psexec.exe",
        mitre_techniques: &["T1569.002", "T1021.002"],
        use_cases: UC_EXECUTE | UC_NETWORK,
        description: "Sysinternals remote executor; lateral movement via SMB exec.",
    },
    // Sysinternals / Microsoft tooling
    LolbasEntry {
        name: "AccessEnum.exe",
        mitre_techniques: &["T1069"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "adexplorer.exe",
        mitre_techniques: &["T1087.002"],
        use_cases: UC_RECON,
        description: "Sysinternals AD Explorer; full Active Directory enumeration.",
    },
    LolbasEntry {
        name: "adrestore.exe",
        mitre_techniques: &["T1087.002"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psfile.exe",
        mitre_techniques: &["T1135"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psgetsid.exe",
        mitre_techniques: &["T1087"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psinfo.exe",
        mitre_techniques: &["T1082"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "pskill.exe",
        mitre_techniques: &["T1562.001"],
        use_cases: UC_DEFENSE_EVASION,
        description: "",
    },
    LolbasEntry {
        name: "pslist.exe",
        mitre_techniques: &["T1057"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psloggedon.exe",
        mitre_techniques: &["T1033"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psloglist.exe",
        mitre_techniques: &["T1654"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "pspasswd.exe",
        mitre_techniques: &["T1098"],
        use_cases: UC_CREDENTIALS,
        description: "",
    },
    LolbasEntry {
        name: "psping.exe",
        mitre_techniques: &["T1018"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "",
    },
    LolbasEntry {
        name: "psservice.exe",
        mitre_techniques: &["T1543.003"],
        use_cases: UC_RECON,
        description: "",
    },
    LolbasEntry {
        name: "psshutdown.exe",
        mitre_techniques: &["T1529"],
        use_cases: UC_EXECUTE,
        description: "",
    },
    LolbasEntry {
        name: "pssuspend.exe",
        mitre_techniques: &["T1562.001"],
        use_cases: UC_DEFENSE_EVASION,
        description: "",
    },
    LolbasEntry {
        name: "sdelete.exe",
        mitre_techniques: &["T1070.004"],
        use_cases: UC_DEFENSE_EVASION,
        description: "Sysinternals secure delete; wipe evidence and anti-forensics.",
    },
    // T1021.001 — RDP remote management
    LolbasEntry {
        name: "RDCMan.exe",
        mitre_techniques: &["T1021.001"],
        use_cases: UC_NETWORK | UC_CREDENTIALS,
        description: "Remote Desktop Connection Manager; credential storage and RDP lateral movement.",
    },
    // Windows built-in admin binaries (not in LOLBAS Project)
    LolbasEntry { name: "csvde.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "cusrmgr.exe", mitre_techniques: &["T1087.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dcdiag.exe", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "devcon.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dfscmd.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dfsdiag.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dfsrdiag.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dfsutil.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "djoin.exe", mitre_techniques: &["T1078.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dnscmd.exe", mitre_techniques: &["T1584.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "driverquery.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsac.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsacls.exe", mitre_techniques: &["T1069.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsadd.exe", mitre_techniques: &["T1136.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsget.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsmgmt.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsmod.exe", mitre_techniques: &["T1098"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsmove.exe", mitre_techniques: &["T1098"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dsquery.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "AD query tool; enumerate users, groups, OUs for lateral movement targeting." },
    LolbasEntry { name: "dsrm.exe", mitre_techniques: &["T1098"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "eventcreate.exe", mitre_techniques: &["T1070.001"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "finger.exe", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "getmac.exe", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "gpfixup.exe", mitre_techniques: &["T1484.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "gpresult.exe", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "Resultant Set of Policy; enumerate effective GPO settings." },
    LolbasEntry { name: "ldifde.exe", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "logman.exe", mitre_techniques: &["T1562.006"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "logoff.exe", mitre_techniques: &["T1529"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "manage-bde.exe", mitre_techniques: &["T1486"], use_cases: UC_EXECUTE, description: "BitLocker management; abused to encrypt drives for ransomware impact." },
    LolbasEntry { name: "mofcomp.exe", mitre_techniques: &["T1047"], use_cases: UC_PERSIST, description: "WMI MOF compiler; establish WMI persistence via MOF file import." },
    LolbasEntry { name: "msg.exe", mitre_techniques: &["T1534"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "msra.exe", mitre_techniques: &["T1021.001"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "ndkping.exe", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "netdom.exe", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "nlb.exe", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "nltest.exe", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "Domain trust enumeration; map forest structure for lateral movement." },
    LolbasEntry { name: "portqry.exe", mitre_techniques: &["T1046"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "printui.exe", mitre_techniques: &["T1218"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "qappsrv.exe", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "qprocess.exe", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "query.exe", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "quser.exe", mitre_techniques: &["T1033"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "qwinsta.exe", mitre_techniques: &["T1033"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "rendom.exe", mitre_techniques: &["T1098"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "repadmin.exe", mitre_techniques: &["T1003.006"], use_cases: UC_CREDENTIALS | UC_RECON, description: "Replication admin; DCSync attack vector for credential harvesting." },
    LolbasEntry { name: "reset.exe", mitre_techniques: &["T1529"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rmtshare.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "rpcdump.exe", mitre_techniques: &["T1046"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "rwinsta.exe", mitre_techniques: &["T1033"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "ServerManager.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "setspn.exe", mitre_techniques: &["T1558.003"], use_cases: UC_CREDENTIALS | UC_RECON, description: "SPN management; Kerberoasting enumeration and SPN manipulation." },
    LolbasEntry { name: "setx.exe", mitre_techniques: &["T1574"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "shadow.exe", mitre_techniques: &["T1021.001"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "shrpubw.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "shutdown.exe", mitre_techniques: &["T1529"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sqlcmd.exe", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "SQL Server CLI; data exfiltration and remote xp_cmdshell execution." },
    LolbasEntry { name: "srvcheck.exe", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "srvinfo.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "takeown.exe", mitre_techniques: &["T1222"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "tsdiscon.exe", mitre_techniques: &["T1021.001"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "tskill.exe", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "typeperf.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "volrest.exe", mitre_techniques: &["T1490"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "waitfor.exe", mitre_techniques: &["T1059.003"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "winrs.exe", mitre_techniques: &["T1021.006"], use_cases: UC_EXECUTE | UC_NETWORK, description: "Windows Remote Shell; remote command execution via WinRM." },
    // LOFL scripts (.vbs/.cmd — appear in Prefetch and Script Block logs)
    LolbasEntry { name: "ospp.vbs", mitre_techniques: &["T1059.005"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pubprn.vbs", mitre_techniques: &["T1216.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Publisher printer script; COM object execution for proxy execution." },
    LolbasEntry { name: "slmgr.vbs", mitre_techniques: &["T1059.005"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "winrm.cmd", mitre_techniques: &["T1021.006"], use_cases: UC_EXECUTE | UC_NETWORK, description: "" },
    // SQL Server / enterprise tools
    LolbasEntry { name: "Microsoft.ConfigurationManagement.exe", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "SmeDesktop.exe", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Ssms.exe", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "TpmVscMgr.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "uptime.exe", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "WinAppDeployCmd.exe", mitre_techniques: &["T1218"], use_cases: UC_EXECUTE | UC_BYPASS, description: "" },
    // ── LOLBAS Project gaps (sourced from lolbas-project.github.io/api/lolbas.json) ──
    // T1218 — Signed Binary Proxy Execution
    LolbasEntry {
        name: "addinutil.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Microsoft .NET Add-In Utility; executes arbitrary .NET add-in manifests to bypass allowlisting.",
    },
    LolbasEntry {
        name: "certoc.exe",
        mitre_techniques: &["T1105", "T1218"],
        use_cases: UC_DOWNLOAD | UC_EXECUTE | UC_BYPASS,
        description: "Certificate Operations; downloads files and loads arbitrary DLLs via certificate management interface.",
    },
    LolbasEntry {
        name: "cmdl32.exe",
        mitre_techniques: &["T1105"],
        use_cases: UC_DOWNLOAD,
        description: "Windows VPN client INF file parser; abused to download arbitrary files via INF ServiceName field.",
    },
    LolbasEntry {
        name: "infdefaultinstall.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Windows Setup API INF installer; executes arbitrary INF scripts to bypass allowlisting.",
    },
    LolbasEntry {
        name: "MpCmdRun.exe",
        mitre_techniques: &["T1218", "T1562.001"],
        use_cases: UC_DOWNLOAD | UC_EXECUTE | UC_BYPASS,
        description: "Windows Defender CLI; downloads payloads via -DownloadFile, executes arbitrary DLLs.",
    },
    LolbasEntry {
        name: "pcwrun.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Program Compatibility Wizard runner; proxy execution of arbitrary binaries via compatibility shim.",
    },
    LolbasEntry {
        name: "rasautou.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Windows Remote Access AutoDial manager; loads arbitrary DLLs via -d and -p arguments.",
    },
    LolbasEntry {
        name: "SyncAppvPublishingServer.exe",
        mitre_techniques: &["T1218"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "App-V publishing server sync; executes arbitrary PowerShell through sync script parameter.",
    },
    LolbasEntry {
        name: "wsreset.exe",
        mitre_techniques: &["T1218", "T1548.002"],
        use_cases: UC_EXECUTE | UC_BYPASS,
        description: "Windows Store cache reset; UAC bypass via COM elevation hijack (auto-elevated, no prompt).",
    },
    // T1003 — OS Credential Dumping / T1490 — Inhibit System Recovery
    LolbasEntry {
        name: "diskshadow.exe",
        mitre_techniques: &["T1003.003", "T1490"],
        use_cases: UC_EXECUTE | UC_CREDENTIALS | UC_DEFENSE_EVASION,
        description: "Windows Server Backup shadow copy utility; extracts NTDS.dit from VSS snapshot; delete shadow copies.",
    },
    LolbasEntry {
        name: "esentutl.exe",
        mitre_techniques: &["T1048", "T1560.001"],
        use_cases: UC_UPLOAD | UC_ARCHIVE | UC_CREDENTIALS,
        description: "Extensible Storage Engine utility; copies locked files including NTDS.dit; file transfer via /cp.",
    }, // Note: UC_UPLOAD used for data staging/transfer (closest to exfil semantics)
    LolbasEntry {
        name: "rdrleakdiag.exe",
        mitre_techniques: &["T1003.001"],
        use_cases: UC_CREDENTIALS,
        description: "RDR Leak Diagnostics; creates full minidumps of LSASS process without SeDebugPrivilege check.",
    },
    LolbasEntry {
        name: "tttracer.exe",
        mitre_techniques: &["T1218", "T1003"],
        use_cases: UC_EXECUTE | UC_CREDENTIALS,
        description: "Time Travel Debugging tracer; dumps process memory and executes with elevated context.",
    },
    // T1105 — Ingress Tool Transfer
    LolbasEntry {
        name: "desktopimgdownldr.exe",
        mitre_techniques: &["T1105"],
        use_cases: UC_DOWNLOAD,
        description: "Desktop Image Downloader (SetupSQM); downloads arbitrary files disguised as desktop wallpaper.",
    },
    // T1040 — Network Sniffing
    LolbasEntry {
        name: "pktmon.exe",
        mitre_techniques: &["T1040"],
        use_cases: UC_NETWORK | UC_RECON,
        description: "Windows Packet Monitor; in-box network packet capture without third-party tools.",
    },
    // T1059.001 — PowerShell / T1072 — Software Deployment Tools
    LolbasEntry {
        name: "wt.exe",
        mitre_techniques: &["T1059.001"],
        use_cases: UC_EXECUTE,
        description: "Windows Terminal; spawns arbitrary shells and profiles; used to obscure parent process chain.",
    },
    LolbasEntry {
        name: "winget.exe",
        mitre_techniques: &["T1072", "T1218"],
        use_cases: UC_EXECUTE | UC_DOWNLOAD | UC_BYPASS,
        description: "Windows Package Manager; installs and executes arbitrary packages from attacker-controlled manifests.",
    },
];

/// Linux LOLBAS — binaries with known GTFOBins escape/bypass techniques.
///
/// Sources:
/// - GTFOBins — curated list of Unix binaries that can bypass local security
///   restrictions; individual pages confirmed at `https://gtfobins.github.io/gtfobins/<binary>/`:
///   <https://gtfobins.github.io/>
/// - MITRE ATT&CK T1059 — Command and Scripting Interpreter:
///   <https://attack.mitre.org/techniques/T1059/>
///
/// All 478 entries sourced directly from the GTFOBins GitHub repository
/// (github.com/GTFOBins/GTFOBins.github.io, `_gtfobins/` directory listing).
///
/// # ATT&CK technique coverage (representative mappings — not exhaustive per entry)
///
/// | Technique | Representative entries |
/// |-----------|---------------------|
/// | T1059.004 Unix Shell | bash, sh, dash, zsh, ksh, fish, python, python3, perl, ruby, lua, awk, gawk |
/// | T1105 Ingress Tool Transfer | curl, wget, nc, netcat, ncat, socat, scp, rsync, tftp, ftp, aria2c |
/// | T1548.001 Setuid/Setgid | find, cp, mv, chmod, chown, tee, dd |
/// | T1218 LOLBin Proxy Exec | env, xargs, find, perl, python3, ruby, awk |
/// | T1055 Process Injection | gdb, strace (ptrace-based) |
/// | T1070 Indicator Removal | shred |
/// | T1003 Credential Dumping | strings, gcore |
/// | T1016 Network Discovery | ip, ifconfig, netstat, ss, arp, nmap |
/// | T1082 System Info | uname, hostname, id, whoami, ps, top, lsof |
/// | T1083 File Discovery | ls, find, locate, tree |
/// | T1560 Archive | tar, zip, gzip, bzip2, xz, 7z |
/// | T1140 Decode | base64, xxd, openssl |
/// | T1046 Network Scan | nmap, masscan, nc, ping |
/// | T1552.004 Private Keys | openssl, ssh-keygen, gpg |
pub const LOLBAS_LINUX: &[LolbasEntry] = &[
    LolbasEntry { name: "7z", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "Archive and extract files; stage data for exfiltration." },
    LolbasEntry { name: "aa-exec", mitre_techniques: &[], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "ab", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "acr", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "agetty", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "alpine", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ansible-playbook", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ansible-test", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "aoss", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "apache2", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "apache2ctl", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "apport-cli", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "apt", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "apt-get", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "aptitude", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ar", mitre_techniques: &[], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "arch-nspawn", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "aria2c", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "Multi-protocol downloader; parallel payload delivery." },
    LolbasEntry { name: "arj", mitre_techniques: &[], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "arp", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "as", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ascii-xfr", mitre_techniques: &[], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "ascii85", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "ash", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "aspell", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "asterisk", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "at", mitre_techniques: &["T1053.003"], use_cases: UC_PERSIST | UC_EXECUTE, description: "" },
    LolbasEntry { name: "atobm", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "autoconf", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "autoheader", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "autoreconf", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "awk", mitre_techniques: &["T1059.004", "T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Text processing language; shell escape and file read/write." },
    LolbasEntry { name: "aws", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "" },
    LolbasEntry { name: "base32", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "base58", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "base64", mitre_techniques: &["T1140", "T1027"], use_cases: UC_DECODE, description: "Encode/decode base64; obfuscate payloads and exfiltrate data." },
    LolbasEntry { name: "basenc", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "basez", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "bash", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Bourne-again shell; execution, SUID abuse, and reverse shells." },
    LolbasEntry { name: "bashbug", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "batcat", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bbot", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "bc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bconsole", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bee", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "borg", mitre_techniques: &["T1560"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "bpftrace", mitre_techniques: &["T1055"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bridge", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "bundle", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bundler", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "busctl", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "busybox", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "Multi-call binary; shell and utility execution in minimal environments." },
    LolbasEntry { name: "byebug", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bzip2", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "c89", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "c99", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cabal", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cancel", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "capsh", mitre_techniques: &["T1548.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Linux capability shell wrapper; capability-based privilege escalation." },
    LolbasEntry { name: "cargo", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cat", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cdist", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "certbot", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "chattr", mitre_techniques: &["T1222"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "check_by_ssh", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "check_cups", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "check_log", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "check_memory", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "check_raid", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "check_ssl_cert", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "check_statusfile", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "chmod", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "File permission modification; set SUID bits for privilege escalation." },
    LolbasEntry { name: "choom", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "chown", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "chroot", mitre_techniques: &["T1548"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Change root directory; container escape and privilege escalation." },
    LolbasEntry { name: "chrt", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "clamscan", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "clisp", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cmake", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cmp", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "cobc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "code", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "codex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "column", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "comm", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "composer", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cowsay", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cowthink", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cp", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "cpan", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cpio", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE | UC_EXECUTE, description: "" },
    LolbasEntry { name: "cpulimit", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "crash", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "crontab", mitre_techniques: &["T1053.003"], use_cases: UC_PERSIST, description: "Cron job management; establish periodic execution persistence." },
    LolbasEntry { name: "csh", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "csplit", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "csvtool", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "ctr", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cupsfilter", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "curl", mitre_techniques: &["T1105", "T1071.001"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "HTTP/HTTPS/FTP client; payload delivery and data exfiltration." },
    LolbasEntry { name: "cut", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "dash", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "date", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "dc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dd", mitre_techniques: &["T1548.001", "T1003"], use_cases: UC_BYPASS | UC_CREDENTIALS, description: "Raw disk read/write; disk image creation and SUID-based file overwrite." },
    LolbasEntry { name: "debugfs", mitre_techniques: &["T1548"], use_cases: UC_EXECUTE | UC_BYPASS, description: "ext2/3/4 debugger; bypass filesystem permissions for privileged access." },
    LolbasEntry { name: "dhclient", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dialog", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "diff", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "dig", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "DNS query tool; infrastructure mapping and C2 DNS beacon testing." },
    LolbasEntry { name: "distcc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dmesg", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dmidecode", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dmsetup", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dnf", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dnsmasq", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "doas", mitre_techniques: &["T1548.003"], use_cases: UC_BYPASS | UC_EXECUTE, description: "" },
    LolbasEntry { name: "docker", mitre_techniques: &["T1610", "T1611"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Container runtime; breakout via privileged containers or socket abuse." },
    LolbasEntry { name: "dos2unix", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "dosbox", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dotnet", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dpkg", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dstat", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "dvips", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "easy_install", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "easyrsa", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "eb", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "ed", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "efax", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "egrep", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "elvish", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "emacs", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "Extensible text editor; shell escape via M-x shell or eval." },
    LolbasEntry { name: "enscript", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "env", mitre_techniques: &["T1218"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Set environment and run command; bypass shebangs and allowlists." },
    LolbasEntry { name: "eqn", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "espeak", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "ex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "exiftool", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "expand", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "expect", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Interactive process automation; abuse interactive prompts and spawn shells." },
    LolbasEntry { name: "facter", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "fail2ban-client", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "fastfetch", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "ffmpeg", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "fgrep", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "file", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "find", mitre_techniques: &["T1083", "T1548.001"], use_cases: UC_RECON | UC_EXECUTE | UC_BYPASS, description: "File discovery with exec; SUID abuse and shell escape via -exec." },
    LolbasEntry { name: "finger", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "firejail", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "fish", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "flock", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "fmt", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "fold", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "forge", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "fping", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "ftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "FTP client; file transfer and interactive shell escape." },
    LolbasEntry { name: "fzf", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "g++", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gawk", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gcc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gcloud", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "" },
    LolbasEntry { name: "gcore", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Generate core dump of process; extract credentials from memory." },
    LolbasEntry { name: "gdb", mitre_techniques: &["T1055"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "GNU debugger; process memory injection and credential extraction via ptrace." },
    LolbasEntry { name: "gem", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "genie", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "genisoimage", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "getent", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "ghc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ghci", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gimp", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ginsh", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "git", mitre_techniques: &["T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Git VCS client; clone payloads and execute hooks for code execution." },
    LolbasEntry { name: "gnuplot", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "go", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "grc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "grep", mitre_techniques: &["T1552.001"], use_cases: UC_RECON, description: "Search files for patterns; credential discovery in config files." },
    LolbasEntry { name: "gtester", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "guile", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gzip", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "hashcat", mitre_techniques: &["T1110.002"], use_cases: UC_CREDENTIALS, description: "GPU password cracker; offline credential recovery." },
    LolbasEntry { name: "hd", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "head", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "hexdump", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "hg", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "highlight", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "hping3", mitre_techniques: &["T1046"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "iconv", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "iftop", mitre_techniques: &["T1040"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "install", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "Install files with permissions; copy files with arbitrary ownership/mode." },
    LolbasEntry { name: "ionice", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ip", mitre_techniques: &["T1016"], use_cases: UC_RECON | UC_NETWORK, description: "IP routing and interface management; network config enumeration." },
    LolbasEntry { name: "iptables-save", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "irb", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ispell", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "java", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "jjs", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "joe", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "join", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "journalctl", mitre_techniques: &["T1654"], use_cases: UC_RECON | UC_EXECUTE, description: "Systemd log viewer; log review and shell escape via pager." },
    LolbasEntry { name: "jq", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "jrunscript", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "jshell", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "jtag", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "julia", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "knife", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ksh", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ksshell", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ksu", mitre_techniques: &["T1548.003"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "kubectl", mitre_techniques: &["T1610"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "Kubernetes CLI; secret extraction, pod exec, RBAC abuse." },
    LolbasEntry { name: "last", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "lastb", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "latex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "latexmk", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ld.so", mitre_techniques: &["T1574.006"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Dynamic linker; preload libraries to hijack function calls." },
    LolbasEntry { name: "ldconfig", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "less", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Pager with shell escape via !command or v in vi mode." },
    LolbasEntry { name: "lftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "" },
    LolbasEntry { name: "links", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "ln", mitre_techniques: &[], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "loginctl", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "logrotate", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "logsave", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "look", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "lp", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ltrace", mitre_techniques: &["T1055"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "lua", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "lualatex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "luatex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "lwp-download", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "lwp-request", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "lxd", mitre_techniques: &["T1611"], use_cases: UC_EXECUTE | UC_BYPASS, description: "LXD container manager; container escape to root via image import." },
    LolbasEntry { name: "m4", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "mail", mitre_techniques: &["T1567"], use_cases: UC_UPLOAD | UC_EXECUTE, description: "" },
    LolbasEntry { name: "make", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Build system; arbitrary command execution via Makefile targets." },
    LolbasEntry { name: "man", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Manual page viewer; shell escape via pager." },
    LolbasEntry { name: "mawk", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "minicom", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "more", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Legacy pager; shell escape via !shell on some implementations." },
    LolbasEntry { name: "mosh-server", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "mosquitto", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "mount", mitre_techniques: &["T1135"], use_cases: UC_EXECUTE | UC_BYPASS, description: "" },
    LolbasEntry { name: "msfconsole", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "msgattrib", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "msgcat", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "msgconv", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "msgfilter", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "msgmerge", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "msguniq", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "mtr", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "multitime", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "mutt", mitre_techniques: &["T1567"], use_cases: UC_UPLOAD | UC_EXECUTE, description: "" },
    LolbasEntry { name: "mv", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "mypy", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "mysql", mitre_techniques: &["T1005"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "MySQL client; data exfiltration and LOAD DATA INFILE abuse." },
    LolbasEntry { name: "nano", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nasm", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nawk", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nc", mitre_techniques: &["T1105", "T1071.001"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "Netcat; reverse shells, file transfer, and port scanning." },
    LolbasEntry { name: "ncdu", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "ncftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "needrestart", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "neofetch", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "nft", mitre_techniques: &["T1562.004"], use_cases: UC_DEFENSE_EVASION | UC_NETWORK, description: "" },
    LolbasEntry { name: "nginx", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nice", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nl", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "nm", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "nmap", mitre_techniques: &["T1046"], use_cases: UC_RECON | UC_NETWORK, description: "Port scanner; network discovery, OS fingerprinting, script execution." },
    LolbasEntry { name: "node", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "Node.js runtime; eval-based code execution, reverse shells." },
    LolbasEntry { name: "nohup", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "npm", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nroff", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "nsenter", mitre_techniques: &["T1611"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Enter Linux namespaces; container escape via host PID namespace." },
    LolbasEntry { name: "ntpdate", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "nvim", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "octave", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "od", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "opencode", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "openssl", mitre_techniques: &["T1552.004", "T1105"], use_cases: UC_CREDENTIALS | UC_DOWNLOAD | UC_DECODE, description: "TLS toolkit; generate self-signed certs, encrypt data, download files." },
    LolbasEntry { name: "openvpn", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "openvt", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "opkg", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pandoc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "passwd", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "paste", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "pax", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "pdb", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pdflatex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pdftex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "perf", mitre_techniques: &["T1055"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "perl", mitre_techniques: &["T1059.006", "T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Perl interpreter; shell exec, network downloads, SUID abuse." },
    LolbasEntry { name: "perlbug", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pexec", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pg", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "php", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "PHP CLI; eval-based code execution and system command invocation." },
    LolbasEntry { name: "pic", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pico", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pidstat", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "pip", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pipx", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pkexec", mitre_techniques: &["T1548.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Polkit exec; CVE-2021-4034 (PwnKit) privilege escalation vector." },
    LolbasEntry { name: "pkg", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "plymouth", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "podman", mitre_techniques: &["T1610"], use_cases: UC_EXECUTE | UC_BYPASS, description: "" },
    LolbasEntry { name: "poetry", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "posh", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pr", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "procmail", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pry", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "psftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "" },
    LolbasEntry { name: "psql", mitre_techniques: &["T1005"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "PostgreSQL client; data exfiltration and pg_read_file abuse." },
    LolbasEntry { name: "ptx", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "puppet", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pwsh", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pygmentize", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pyright", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "python", mitre_techniques: &["T1059.006", "T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Python interpreter; reverse shells, network downloads, SUID abuse." },
    LolbasEntry { name: "qpdf", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "R", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rake", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ranger", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "readelf", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "red", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "redcarpet", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "redis", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "restic", mitre_techniques: &["T1560"], use_cases: UC_ARCHIVE | UC_UPLOAD, description: "Backup tool; encrypted data exfiltration to remote repositories." },
    LolbasEntry { name: "rev", mitre_techniques: &[], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "rlogin", mitre_techniques: &["T1021"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "rlwrap", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rpm", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rpmdb", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "rpmquery", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "rpmverify", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "rsync", mitre_techniques: &["T1105", "T1039"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "File sync; lateral movement data staging and exfiltration." },
    LolbasEntry { name: "rsyslogd", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rtorrent", mitre_techniques: &[], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "ruby", mitre_techniques: &["T1059", "T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Ruby interpreter; shell escape, network requests, file system access." },
    LolbasEntry { name: "run-mailcap", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "run-parts", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "runscript", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rustc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rustdoc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rustfmt", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rustup", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rview", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "rvim", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sash", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "scanmem", mitre_techniques: &[], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "scp", mitre_techniques: &["T1105", "T1021.004"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "Secure copy over SSH; file exfiltration and lateral movement." },
    LolbasEntry { name: "screen", mitre_techniques: &["T1548.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Terminal multiplexer with SUID abuse; persistent session and privilege esc." },
    LolbasEntry { name: "script", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "scrot", mitre_techniques: &["T1113"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sed", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "service", mitre_techniques: &["T1569.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "setarch", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "setcap", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "setfacl", mitre_techniques: &["T1222"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "setlock", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sftp", mitre_techniques: &["T1105", "T1021.004"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "" },
    LolbasEntry { name: "sg", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sh", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "POSIX shell; universal execution and SUID privilege escalation." },
    LolbasEntry { name: "shred", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Secure file deletion; overwrite and delete evidence." },
    LolbasEntry { name: "shuf", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "slsh", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "smbclient", mitre_techniques: &["T1021.002"], use_cases: UC_NETWORK | UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "snap", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "socat", mitre_techniques: &["T1105", "T1071.001"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "Socket relay; reverse shells, port forwarding, C2 channels." },
    LolbasEntry { name: "socket", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "soelim", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "softlimit", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "sort", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "split", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "sqlite3", mitre_techniques: &["T1539", "T1005"], use_cases: UC_CREDENTIALS | UC_RECON, description: "SQLite CLI; extract cookies and credentials from browser/app databases." },
    LolbasEntry { name: "sqlmap", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ss", mitre_techniques: &["T1049"], use_cases: UC_RECON, description: "Socket statistics; enumerate network connections and listening services." },
    LolbasEntry { name: "ssh", mitre_techniques: &["T1021.004"], use_cases: UC_NETWORK | UC_EXECUTE, description: "SSH client; lateral movement, tunneling, and port forwarding." },
    LolbasEntry { name: "ssh-agent", mitre_techniques: &["T1552.004"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "ssh-copy-id", mitre_techniques: &["T1098"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "ssh-keygen", mitre_techniques: &["T1552.004"], use_cases: UC_CREDENTIALS | UC_PERSIST, description: "" },
    LolbasEntry { name: "ssh-keyscan", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "sshfs", mitre_techniques: &["T1021.004"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "sshpass", mitre_techniques: &["T1552"], use_cases: UC_CREDENTIALS | UC_NETWORK, description: "" },
    LolbasEntry { name: "sshuttle", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "start-stop-daemon", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "stdbuf", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "strace", mitre_techniques: &["T1055"], use_cases: UC_CREDENTIALS, description: "System call tracer; intercept credentials from processes via ptrace." },
    LolbasEntry { name: "strings", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Extract printable strings; credential discovery in binary files/dumps." },
    LolbasEntry { name: "su", mitre_techniques: &["T1548.003"], use_cases: UC_BYPASS | UC_EXECUTE, description: "" },
    LolbasEntry { name: "sudo", mitre_techniques: &["T1548.003"], use_cases: UC_BYPASS | UC_EXECUTE, description: "Superuser do; most common Unix privilege escalation mechanism." },
    LolbasEntry { name: "sysctl", mitre_techniques: &["T1082"], use_cases: UC_RECON | UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "systemctl", mitre_techniques: &["T1543.002"], use_cases: UC_PERSIST | UC_EXECUTE, description: "Systemd service manager; create and start services for persistence." },
    LolbasEntry { name: "systemd-resolve", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "systemd-run", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Run commands as systemd transient units; container escape and evasion." },
    LolbasEntry { name: "tac", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "tail", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "tailscale", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "tar", mitre_techniques: &["T1560.001", "T1548.001"], use_cases: UC_ARCHIVE | UC_BYPASS, description: "Archive utility; data staging and SUID-based privilege escalation." },
    LolbasEntry { name: "task", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "taskset", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tasksh", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tbl", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tclsh", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tcpdump", mitre_techniques: &["T1040"], use_cases: UC_CREDENTIALS | UC_RECON, description: "Packet capture; credential harvesting from cleartext protocols." },
    LolbasEntry { name: "tcsh", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tdbtool", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tee", mitre_techniques: &["T1548.001"], use_cases: UC_BYPASS, description: "Write to file with SUID; append to privileged files like /etc/sudoers." },
    LolbasEntry { name: "telnet", mitre_techniques: &["T1021"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "terraform", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "TFTP client; file transfer on port 69, often unmonitored." },
    LolbasEntry { name: "tic", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "time", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "timedatectl", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "timeout", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tmate", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "tmux", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Terminal multiplexer; persistent session and SUID abuse." },
    LolbasEntry { name: "top", mitre_techniques: &["T1057"], use_cases: UC_RECON | UC_EXECUTE, description: "" },
    LolbasEntry { name: "torify", mitre_techniques: &["T1090.003"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "torsocks", mitre_techniques: &["T1090.003"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "troff", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tsc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "tshark", mitre_techniques: &["T1040"], use_cases: UC_CREDENTIALS | UC_RECON, description: "" },
    LolbasEntry { name: "ul", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "unexpand", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "uniq", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "unshare", mitre_techniques: &["T1611"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Create new Linux namespaces; container escape and user NS privilege esc." },
    LolbasEntry { name: "unsquashfs", mitre_techniques: &[], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "unzip", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "update-alternatives", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "urlget", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "uuencode", mitre_techniques: &["T1140"], use_cases: UC_DECODE | UC_UPLOAD, description: "" },
    LolbasEntry { name: "uv", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "vagrant", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "valgrind", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "varnishncsa", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "vi", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Text editor; shell escape via :!shell or :shell command." },
    LolbasEntry { name: "view", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "vigr", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "vim", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Vi improved; shell escape, file read/write, and Python exec." },
    LolbasEntry { name: "vimdiff", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "vipw", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "virsh", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "volatility", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "w3m", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "wall", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "watch", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "wc", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "wg-quick", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "wget", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "HTTP/HTTPS downloader; payload delivery and data staging." },
    LolbasEntry { name: "whiptail", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "whois", mitre_techniques: &["T1590"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "wireshark", mitre_techniques: &["T1040"], use_cases: UC_CREDENTIALS | UC_RECON, description: "" },
    LolbasEntry { name: "wish", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "xargs", mitre_techniques: &["T1218"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Argument builder; execute commands over many arguments, bypass restrictions." },
    LolbasEntry { name: "xdg-user-dir", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "xdotool", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "xelatex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "xetex", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "xmodmap", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "xmore", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "xpad", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "xxd", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "Hex dump and conversion; encode/decode binary payloads." },
    LolbasEntry { name: "xz", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "yarn", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "yash", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "yelp", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "yt-dlp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    LolbasEntry { name: "yum", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "zathura", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "zcat", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "zgrep", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "zic", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "zip", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "" },
    LolbasEntry { name: "zless", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "zsh", mitre_techniques: &["T1059.004"], use_cases: UC_EXECUTE, description: "Z shell; execution, interactive exploitation, and SUID abuse." },
    LolbasEntry { name: "zsoelim", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "zypper", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
];

/// macOS LOLBAS — Living Off the Orchard (LOOBins) binaries.
///
/// LOOBins are macOS native binaries that can be abused by attackers to perform
/// reconnaissance, execution, persistence, credential access, defense evasion,
/// lateral movement, and command-and-control — all without dropping third-party tools.
///
/// The name "Orchard" is a play on Apple's orchard imagery: just as LOLBAS refers to
/// the Windows "land", LOOBins refers to the macOS "orchard" — native Apple-supplied
/// binaries living off Apple's own ecosystem.
///
/// Sources:
/// - LOOBins project — community-maintained macOS LOO binary catalog:
///   <https://loobins.io/>
/// - GitHub repository: <https://github.com/infosecB/LOOBins>
/// - MITRE ATT&CK macOS techniques:
///   <https://attack.mitre.org/matrices/enterprise/macos/>
/// - Objective-See blog — Patrick Wardle, macOS malware analysis series:
///   <https://objective-see.org/blog.html>
/// - SentinelOne — "20 Common Tools & Techniques Used by macOS Threat Actors":
///   <https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/>
///
/// All entries confirmed in the LOOBins dataset (commit verified 2026-05-02).
///
/// # ATT&CK technique coverage (representative mappings)
///
/// | Technique | Representative entries |
/// |-----------|---------------------|
/// | T1059.002 AppleScript | osascript |
/// | T1059.004 Unix Shell | bash, sh, zsh, python3, perl, ruby, awk |
/// | T1105 Ingress Tool Transfer | curl, wget, nc, socat, scp, nscurl, tftp |
/// | T1548.001 Setuid | find, cp, tee, dd |
/// | T1553.001 Code Signing | codesign, spctl |
/// | T1553.004 Trust Bypass | security |
/// | T1562.001 Disable AV | launchctl (unload MRTd), defaults |
/// | T1543.004 Launch Daemon | launchctl, plutil |
/// | T1036 Masquerading | ditto, cp |
/// | T1070 Indicator Removal | rm, diskutil |
/// | T1016 Network Config | networksetup, ifconfig, netstat, ipconfig, arp, nslookup |
/// | T1082 System Info | system_profiler, sysctl, sw_vers, uname, hostname, id, whoami |
/// | T1083 File Discovery | ls, find, mdfind, locate |
/// | T1560 Archive | tar, zip, ditto, hdiutil |
/// | T1003.001 Keychain | security (dump-keychain) |
/// | T1539 Cookie Theft | sqlite3 (browser DBs) |
/// | T1490 Inhibit Recovery | diskutil, hdiutil |
/// | T1078 Valid Accounts | dscl, id, groups, finger |
/// | T1021.004 SSH | ssh, scp |
/// | T1135 Network Shares | mount, df |
/// | T1053.003 Cron | crontab |
/// | T1543.001 Launch Agent | launchctl, plutil, PlistBuddy |
pub const LOLBAS_MACOS: &[LolbasEntry] = &[
    // Execution / scripting
    LolbasEntry { name: "osascript", mitre_techniques: &["T1059.002"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "Execute AppleScript/JXA; credential phishing and lateral movement via RAE." },
    LolbasEntry { name: "osacompile", mitre_techniques: &["T1059.002"], use_cases: UC_EXECUTE | UC_PERSIST, description: "Compile AppleScript to app bundle; create persistence payload." },
    LolbasEntry { name: "swift", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "Swift REPL; direct system API access without shell." },
    LolbasEntry { name: "tclsh", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "Tcl interpreter; execution without shell involvement." },
    // Persistence / launch services
    LolbasEntry { name: "launchctl", mitre_techniques: &["T1543.001", "T1543.004"], use_cases: UC_PERSIST | UC_DEFENSE_EVASION, description: "Load/unload LaunchAgents and Daemons; primary macOS persistence vector." },
    LolbasEntry { name: "lsregister", mitre_techniques: &["T1574"], use_cases: UC_PERSIST, description: "Launch Services DB manipulation; file association hijacking." },
    // Credential access
    LolbasEntry { name: "security", mitre_techniques: &["T1003.002", "T1553.004"], use_cases: UC_CREDENTIALS | UC_BYPASS, description: "Keychain dump, certificate manipulation, and credential extraction." },
    LolbasEntry { name: "dscl", mitre_techniques: &["T1078", "T1087"], use_cases: UC_RECON | UC_CREDENTIALS, description: "Directory Services CLI; user/group enumeration and modification." },
    LolbasEntry { name: "dscacheutil", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "DS cache flushing and user enumeration." },
    LolbasEntry { name: "odutil", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "Open Directory utility; directory service inspection." },
    LolbasEntry { name: "dsconfigad", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "Active Directory binding configuration and inspection." },
    LolbasEntry { name: "dsexport", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "Export directory records; user/group data collection." },
    LolbasEntry { name: "sysadminctl", mitre_techniques: &["T1136.001"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "Create/modify local user accounts; privilege escalation vector." },
    // Discovery / reconnaissance
    LolbasEntry { name: "system_profiler", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Full hardware/software/network inventory." },
    LolbasEntry { name: "networksetup", mitre_techniques: &["T1016", "T1090"], use_cases: UC_RECON | UC_NETWORK, description: "Network interface enumeration and proxy C2 configuration." },
    LolbasEntry { name: "scutil", mitre_techniques: &["T1082", "T1016"], use_cases: UC_RECON, description: "System configuration inspection (hostname, DNS, proxy)." },
    LolbasEntry { name: "sw_vers", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "macOS version fingerprinting." },
    LolbasEntry { name: "sysctl", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Kernel parameter inspection (memory, CPU, network)." },
    LolbasEntry { name: "ioreg", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "IOKit registry; hardware device enumeration." },
    LolbasEntry { name: "kextstat", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "Kernel extension enumeration; security tool detection." },
    LolbasEntry { name: "profiles", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "MDM/configuration profile enumeration." },
    LolbasEntry { name: "last", mitre_techniques: &["T1087"], use_cases: UC_RECON, description: "Login history; user activity reconstruction." },
    LolbasEntry { name: "mdfind", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Spotlight search; locate files without filesystem walk." },
    LolbasEntry { name: "mdls", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Spotlight metadata; file attribute inspection." },
    LolbasEntry { name: "defaults", mitre_techniques: &["T1082", "T1562.001"], use_cases: UC_RECON | UC_DEFENSE_EVASION, description: "Read/write plist preferences; config enumeration and modification." },
    LolbasEntry { name: "plutil", mitre_techniques: &["T1543.001"], use_cases: UC_RECON | UC_PERSIST, description: "Plist manipulation; launch agent config modification." },
    LolbasEntry { name: "sharing", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "File sharing configuration; SMB/AFP exposure enumeration." },
    LolbasEntry { name: "systemsetup", mitre_techniques: &["T1082", "T1021.004"], use_cases: UC_RECON | UC_NETWORK, description: "System preferences modification (remote login, time server)." },
    // Defense evasion / tampering
    LolbasEntry { name: "tccutil", mitre_techniques: &["T1548"], use_cases: UC_BYPASS, description: "TCC database reset; bypass macOS privacy controls." },
    LolbasEntry { name: "csrutil", mitre_techniques: &["T1553"], use_cases: UC_BYPASS | UC_RECON, description: "SIP status check; disable System Integrity Protection." },
    LolbasEntry { name: "spctl", mitre_techniques: &["T1553.001"], use_cases: UC_BYPASS, description: "Gatekeeper bypass assessment; check and modify code signing policy." },
    LolbasEntry { name: "codesign", mitre_techniques: &["T1553.001"], use_cases: UC_BYPASS, description: "Code signature verification and self-signing for trust bypass." },
    LolbasEntry { name: "chflags", mitre_techniques: &["T1564.001"], use_cases: UC_DEFENSE_EVASION, description: "Set immutable/hidden flags on files; tamper with forensic artifacts." },
    LolbasEntry { name: "xattr", mitre_techniques: &["T1553.001"], use_cases: UC_DEFENSE_EVASION, description: "Extended attribute manipulation; quarantine flag removal." },
    LolbasEntry { name: "nvram", mitre_techniques: &["T1542"], use_cases: UC_PERSIST, description: "NVRAM variable read/write; firmware-level persistence." },
    LolbasEntry { name: "sfltool", mitre_techniques: &["T1543.001"], use_cases: UC_PERSIST, description: "SharedFileList manipulation; login item modification." },
    // Exfiltration / file operations
    LolbasEntry { name: "hdiutil", mitre_techniques: &["T1560", "T1490"], use_cases: UC_ARCHIVE | UC_EXECUTE, description: "Disk image creation/mount; data staging and exfiltration." },
    LolbasEntry { name: "ditto", mitre_techniques: &["T1036"], use_cases: UC_EXECUTE, description: "Copy files preserving metadata; stealthy file staging." },
    LolbasEntry { name: "tmutil", mitre_techniques: &["T1490"], use_cases: UC_DEFENSE_EVASION, description: "Time Machine control; backup manipulation or data recovery." },
    LolbasEntry { name: "screencapture", mitre_techniques: &["T1113"], use_cases: UC_RECON, description: "Screen capture; visual data collection." },
    LolbasEntry { name: "pbpaste", mitre_techniques: &["T1115"], use_cases: UC_RECON, description: "Clipboard access; credential and data collection." },
    LolbasEntry { name: "sqlite3", mitre_techniques: &["T1539", "T1005"], use_cases: UC_CREDENTIALS | UC_RECON, description: "SQLite CLI; extract cookies and credentials from browser/app databases." },
    LolbasEntry { name: "textutil", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Document format conversion; data exfiltration staging." },
    LolbasEntry { name: "funzip", mitre_techniques: &["T1140"], use_cases: UC_DECODE, description: "Unzip from stdin; payload unpacking without writing temp files." },
    LolbasEntry { name: "streamzip", mitre_techniques: &["T1560"], use_cases: UC_ARCHIVE, description: "Zip streaming; data archiving without GUI interaction." },
    // Network / C2
    LolbasEntry { name: "nscurl", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "NSURLSession-based curl; TLS downloads bypassing some controls." },
    LolbasEntry { name: "tftp", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "TFTP client; file transfer on port 69, often unmonitored." },
    LolbasEntry { name: "snmptrap", mitre_techniques: &["T1071"], use_cases: UC_NETWORK, description: "SNMP trap sender; covert C2 over SNMP." },
    LolbasEntry { name: "dns-sd", mitre_techniques: &["T1046"], use_cases: UC_RECON | UC_NETWORK, description: "DNS service discovery; network recon and mDNS C2." },
    LolbasEntry { name: "ssh-keygen", mitre_techniques: &["T1552.004"], use_cases: UC_CREDENTIALS | UC_PERSIST, description: "Generate/manage SSH keys; persistence via authorized_keys." },
    // Miscellaneous
    LolbasEntry { name: "open", mitre_techniques: &["T1204.002"], use_cases: UC_EXECUTE, description: "Open URLs/apps; browser redirect and app launch." },
    LolbasEntry { name: "say", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "caffeinate", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Prevent system sleep; keep C2 beacon alive during long operations." },
    LolbasEntry { name: "pkill", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Kill processes by name; disable security tools." },
    LolbasEntry { name: "mktemp", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "notifyutil", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "safaridriver", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "GetFileInfo", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "SetFile", mitre_techniques: &["T1564"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "softwareupdate", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "log", mitre_techniques: &["T1654"], use_cases: UC_RECON, description: "macOS Unified Log streaming; surveillance and anti-forensics awareness." },

    // ── macOS LOFL — foreign tools (Homebrew / pip / npm / cargo / other) ──
    // Cloud CLIs
    LolbasEntry { name: "aws", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "AWS CLI; credential exfil, S3 staging, IAM enumeration." },
    LolbasEntry { name: "az", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "Azure CLI; credential access, storage exfil, AAD recon." },
    LolbasEntry { name: "gcloud", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "Google Cloud CLI; GCS exfil, IAM privilege escalation." },
    LolbasEntry { name: "gh", mitre_techniques: &["T1078"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "GitHub CLI; token access, repo exfil, Actions abuse." },
    LolbasEntry { name: "heroku", mitre_techniques: &["T1078.004"], use_cases: UC_CREDENTIALS | UC_EXECUTE, description: "" },
    LolbasEntry { name: "vault", mitre_techniques: &["T1552"], use_cases: UC_CREDENTIALS, description: "HashiCorp Vault CLI; secret extraction and token abuse." },
    LolbasEntry { name: "consul", mitre_techniques: &["T1046"], use_cases: UC_RECON | UC_NETWORK, description: "" },
    LolbasEntry { name: "step", mitre_techniques: &["T1553.004"], use_cases: UC_BYPASS, description: "" },
    LolbasEntry { name: "teleport", mitre_techniques: &["T1021"], use_cases: UC_NETWORK, description: "" },
    // Container / orchestration
    LolbasEntry { name: "docker", mitre_techniques: &["T1610", "T1611"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Container runtime; breakout via privileged containers or socket abuse." },
    LolbasEntry { name: "kubectl", mitre_techniques: &["T1610"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "Kubernetes CLI; secret extraction, pod exec, RBAC abuse." },
    LolbasEntry { name: "helm", mitre_techniques: &["T1610"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "k9s", mitre_techniques: &["T1610"], use_cases: UC_RECON | UC_EXECUTE, description: "" },
    LolbasEntry { name: "lazydocker", mitre_techniques: &["T1610"], use_cases: UC_RECON | UC_EXECUTE, description: "" },
    LolbasEntry { name: "packer", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    // Language runtimes
    LolbasEntry { name: "python3", mitre_techniques: &["T1059.006", "T1105"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Python REPL; code exec, network downloads, C extension loading." },
    LolbasEntry { name: "node", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "Node.js runtime; eval-based exec and npm script abuse." },
    LolbasEntry { name: "ruby", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "Ruby interpreter; shell escape and Gem abuse." },
    LolbasEntry { name: "go", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "php", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "PHP CLI; eval exec and webshell staging." },
    LolbasEntry { name: "perl", mitre_techniques: &["T1059.006"], use_cases: UC_EXECUTE, description: "Perl interpreter; shell exec and regex-based data extraction." },
    // Package managers
    LolbasEntry { name: "brew", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Homebrew; malicious tap installation and formula abuse." },
    LolbasEntry { name: "pip3", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Python packages; supply chain and code exec via setup.py." },
    LolbasEntry { name: "npm", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Node packages; postinstall scripts and typosquatting attacks." },
    LolbasEntry { name: "yarn", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "cargo", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "pipx", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    // IaC / DevOps
    LolbasEntry { name: "terraform", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "IaC; cloud resource creation and credential leakage via state files." },
    LolbasEntry { name: "ansible", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "Configuration management; mass remote exec via playbooks." },
    LolbasEntry { name: "vagrant", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "act", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    // Database clients
    LolbasEntry { name: "psql", mitre_techniques: &["T1005"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "PostgreSQL client; data exfil and pg_read_file abuse." },
    LolbasEntry { name: "mysql", mitre_techniques: &["T1005"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "MySQL client; data exfil and LOAD DATA INFILE abuse." },
    LolbasEntry { name: "redis-cli", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Redis client; config rewrite and RCE via SLAVEOF." },
    LolbasEntry { name: "mongosh", mitre_techniques: &["T1059"], use_cases: UC_EXECUTE, description: "" },
    // Network tools
    LolbasEntry { name: "nmap", mitre_techniques: &["T1046"], use_cases: UC_RECON | UC_NETWORK, description: "Port scanner; network recon and OS fingerprinting." },
    LolbasEntry { name: "socat", mitre_techniques: &["T1105", "T1071.001"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "Network relay; reverse shells and port forwarding." },
    LolbasEntry { name: "mitmproxy", mitre_techniques: &["T1557"], use_cases: UC_CREDENTIALS | UC_NETWORK, description: "MITM proxy; credential interception and traffic analysis." },
    LolbasEntry { name: "tshark", mitre_techniques: &["T1040"], use_cases: UC_CREDENTIALS | UC_RECON, description: "CLI packet capture; credential harvesting and recon." },
    LolbasEntry { name: "masscan", mitre_techniques: &["T1046"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "dnsmasq", mitre_techniques: &[], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "httpie", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "" },
    // Tunneling / proxy
    LolbasEntry { name: "ngrok", mitre_techniques: &["T1572"], use_cases: UC_NETWORK, description: "Reverse tunnel; C2 over HTTPS/TCP bypassing firewalls." },
    LolbasEntry { name: "cloudflared", mitre_techniques: &["T1572"], use_cases: UC_NETWORK, description: "Cloudflare Tunnel; C2 via trusted CDN infrastructure." },
    LolbasEntry { name: "chisel", mitre_techniques: &["T1572"], use_cases: UC_NETWORK, description: "TCP/UDP tunnel over HTTP; firewall bypass for C2." },
    LolbasEntry { name: "sshuttle", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "VPN over SSH; network pivoting." },
    LolbasEntry { name: "proxychains-ng", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "tailscale", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "WireGuard mesh VPN; covert C2 network." },
    LolbasEntry { name: "wireguard-tools", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    // Security / offensive tools
    LolbasEntry { name: "sqlmap", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "john", mitre_techniques: &["T1110.002"], use_cases: UC_CREDENTIALS, description: "John the Ripper; offline password cracking." },
    LolbasEntry { name: "hashcat", mitre_techniques: &["T1110.002"], use_cases: UC_CREDENTIALS, description: "GPU password cracking; credential recovery." },
    LolbasEntry { name: "frida", mitre_techniques: &["T1055"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Dynamic instrumentation; process injection and hook bypass." },
    LolbasEntry { name: "radare2", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "gdb", mitre_techniques: &["T1055"], use_cases: UC_EXECUTE | UC_CREDENTIALS, description: "GNU debugger; process memory dump and shellcode injection." },
    // Build tools
    LolbasEntry { name: "cmake", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "gradle", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "maven", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "bazel", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    // Credential management
    LolbasEntry { name: "1password-cli", mitre_techniques: &["T1555"], use_cases: UC_CREDENTIALS, description: "1Password CLI; Keychain/vault secret extraction." },
    LolbasEntry { name: "bitwarden-cli", mitre_techniques: &["T1555"], use_cases: UC_CREDENTIALS, description: "Bitwarden CLI; password vault access." },
    // Encryption / signing
    LolbasEntry { name: "openssl", mitre_techniques: &["T1552.004", "T1105"], use_cases: UC_CREDENTIALS | UC_DOWNLOAD | UC_DECODE, description: "TLS toolkit; self-signed C2 certs, data encryption, and file downloads." },
    LolbasEntry { name: "gpg", mitre_techniques: &[], use_cases: UC_DECODE, description: "GnuPG; encrypted C2 and payload concealment." },
    LolbasEntry { name: "age", mitre_techniques: &[], use_cases: UC_DECODE, description: "" },
    LolbasEntry { name: "minisign", mitre_techniques: &["T1553"], use_cases: UC_BYPASS, description: "" },
    // File transfer / sync
    LolbasEntry { name: "rclone", mitre_techniques: &["T1567"], use_cases: UC_UPLOAD, description: "Cloud sync; mass exfiltration to cloud storage." },
    LolbasEntry { name: "rsync", mitre_techniques: &["T1105", "T1039"], use_cases: UC_DOWNLOAD | UC_UPLOAD | UC_NETWORK, description: "File sync; lateral movement data staging." },
    LolbasEntry { name: "wget", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "HTTP downloader; payload delivery." },
    LolbasEntry { name: "aria2c", mitre_techniques: &["T1105"], use_cases: UC_DOWNLOAD, description: "Multi-protocol downloader; parallel payload staging." },
    LolbasEntry { name: "restic", mitre_techniques: &["T1560"], use_cases: UC_ARCHIVE | UC_UPLOAD, description: "Backup tool; encrypted data exfiltration." },
    // Scripting / automation
    LolbasEntry { name: "jq", mitre_techniques: &[], use_cases: UC_RECON, description: "JSON processor; credential extraction from API responses." },
    LolbasEntry { name: "expect", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Automation tool; interactive process exploitation." },
    LolbasEntry { name: "screen", mitre_techniques: &[], use_cases: UC_EXECUTE | UC_PERSIST, description: "Terminal multiplexer; persistent session." },
    LolbasEntry { name: "tmux", mitre_techniques: &[], use_cases: UC_EXECUTE | UC_PERSIST, description: "Terminal multiplexer; session hijacking and persistence." },
    LolbasEntry { name: "imagemagick", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "ffmpeg", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    // macOS-specific utilities
    LolbasEntry { name: "duti", mitre_techniques: &["T1574"], use_cases: UC_PERSIST, description: "File association; handler hijacking for persistence." },
    LolbasEntry { name: "trash", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Move to Trash CLI; evidence staging before deletion." },
];

/// Returns `true` if `name` matches a known Windows LOLBAS binary (case-insensitive).
pub fn is_lolbas_windows(name: &str) -> bool {
    lolbas_entry(LOLBAS_WINDOWS, name).is_some()
}

/// Returns `true` if `name` matches a known Linux LOLBAS binary (case-insensitive).
///
/// The Linux LOLBAS dataset is sourced from GTFOBins — all 478 entries.
pub fn is_lolbas_linux(name: &str) -> bool {
    lolbas_entry(LOLBAS_LINUX, name).is_some()
}

/// Returns `true` if `name` matches a known macOS LOLBAS binary (case-insensitive).
///
/// Matches against the last path component if a full path is given, or the
/// bare binary name. For example, both `"osascript"` and `"/usr/bin/osascript"`
/// return `true`.
pub fn is_lolbas_macos(name: &str) -> bool {
    // Accept either a full path (/usr/bin/osascript) or bare name (osascript)
    let basename = name.rsplit('/').next().unwrap_or(name);
    lolbas_entry(LOLBAS_MACOS, basename).is_some()
}

/// Returns `true` if `name` is a LOLBAS binary on Windows, Linux, or macOS (case-insensitive).
///
/// Convenience wrapper over [`is_lolbas_windows`], [`is_lolbas_linux`], and [`is_lolbas_macos`].
pub fn is_lolbas(name: &str) -> bool {
    is_lolbas_windows(name) || is_lolbas_linux(name) || is_lolbas_macos(name)
}

/// Windows PowerShell indicators — native LOL cmdlets, built-in aliases, and
/// LOFL remote-administration module cmdlets — unified into one catalog.
///
/// ## Why unified?
///
/// From a detection standpoint the distinction between LOL (native PowerShell
/// cmdlets that ship with Windows) and LOFL (third-party admin module cmdlets
/// such as RSAT or Active Directory module) is **academic**: PSReadLine history,
/// PowerShell ScriptBlock logs (Event 4104), AMSI telemetry, and transcription
/// logs capture all forms identically. A SIEM rule scanning PSReadLine for
/// `Invoke-WebRequest` must also catch `iwr` and `wget` (PS 5.x alias).
///
/// ## Coverage
///
/// | Section | Count | Source |
/// |---------|-------|--------|
/// | LOFL admin module cmdlets | 176 | LOFL Project — <https://lofl-project.github.io/> |
/// | Native PS attack cmdlets | ~50 | MITRE ATT&CK T1059.001 — <https://attack.mitre.org/techniques/T1059/001/> |
/// | Built-in PS aliases | ~45 | PowerShell InitialSessionState — <https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/InitialSessionState.cs> |
///
/// ## Artifact types
///
/// - PSReadLine history (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)
/// - PowerShell ScriptBlock log (Event 4104 in Microsoft-Windows-PowerShell/Operational)
/// - PowerShell transcription logs
/// - AMSI provider telemetry
pub const LOLBAS_WINDOWS_CMDLETS: &[LolbasEntry] = &[
    // ── LOFL Project admin module cmdlets ───────────────────────────────────
    // Source: LOFL Project <https://lofl-project.github.io/>
    // Third-party admin tools (RSAT, AD, DNS, BitLocker, etc.) that are
    // universally deployed in enterprise environments, making them indistinguishable
    // from legitimate admin activity — the LOFL evasion mechanism.
    LolbasEntry { name: "Add-ADGroupMember", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Add-DnsClientNrptRule", mitre_techniques: &["T1584.002"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Add-EtwTraceProvider", mitre_techniques: &["T1562.006"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Add-MpPreference", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Add Defender exclusion; bypass AV scanning for payloads." },
    LolbasEntry { name: "Add-NetEventPacketCaptureProvider", mitre_techniques: &["T1040"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Add-NetNatExternalAddress", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Add-NetNatStaticMapping", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Backup-GPO", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Clear-Disk", mitre_techniques: &["T1070"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Clear-DnsClientCache", mitre_techniques: &["T1070"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Clear-Eventlog", mitre_techniques: &["T1070.001"], use_cases: UC_DEFENSE_EVASION, description: "Clear Windows event logs; evidence destruction." },
    LolbasEntry { name: "Close-SmbOpenFile", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Close-SmbSession", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Connect-WSMan", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Copy-Item", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Copy-VMFile", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Disable-ADAccount", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Disable-NetAdapter", mitre_techniques: &["T1562.007"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Disable-NetFirewallRule", mitre_techniques: &["T1562.004"], use_cases: UC_DEFENSE_EVASION, description: "Disable firewall rules; open network for C2." },
    LolbasEntry { name: "Dismount-DiskImage", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Enable-ADAccount", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Enable-NetFirewallRule", mitre_techniques: &["T1562.004"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Enter-PSSession", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK | UC_EXECUTE, description: "Interactive PowerShell remote session; lateral movement." },
    LolbasEntry { name: "Export-VM", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Export-VMSnapshot", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Find-NetRoute", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Format-Volume", mitre_techniques: &["T1070"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Get-ADComputer", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADComputerServiceAccount", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADDomain", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADDomainController", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADForest", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADGroup", mitre_techniques: &["T1069.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADGroupMember", mitre_techniques: &["T1069.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADObject", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADOrganizationalUnit", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADReplicationSubnet", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ADTrust", mitre_techniques: &["T1482"], use_cases: UC_RECON, description: "Enumerate Active Directory trusts; map forest for lateral movement." },
    LolbasEntry { name: "Get-ADUser", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "Enumerate AD users; target selection for credential attacks." },
    LolbasEntry { name: "Get-AppvVirtualProcess", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ChildItem", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "List directory contents; filesystem enumeration." },
    LolbasEntry { name: "Get-CimAssociatedInstance", mitre_techniques: &["T1047"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-CimClass", mitre_techniques: &["T1047"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-CimInstance", mitre_techniques: &["T1047"], use_cases: UC_RECON, description: "Modern WMI queries; system info, process, and network enumeration." },
    LolbasEntry { name: "Get-DfsnFolder", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DfsnFolderTarget", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DfsnRoot", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DfsnRootTarget", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerAuditLog", mitre_techniques: &["T1654"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerDatabase", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerDnsCredential", mitre_techniques: &["T1552"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Get-DhcpServerInDC", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerSetting", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerv4DnsSetting", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerv4Filter", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerv4FilterList", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DhcpServerv4Lease", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-Disk", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DiskImage", mitre_techniques: &[], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsClientCache", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsClientNrptRule", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsClientServerAddress", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsServer", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsServerCache", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-DnsServerForwarder", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-EtwTraceProvider", mitre_techniques: &["T1562.006"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-EtwTraceSession", mitre_techniques: &["T1562.006"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-FileShare", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-GPO", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-GPOReport", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-GPPermission", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-GPResultantSetOfPolicy", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-GPStarterGPO", mitre_techniques: &["T1615"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-HotFix", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-MpComputerStatus", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-MpPreference", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-MpThreat", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-MpThreatCatalog", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-MpThreatDetection", mitre_techniques: &["T1518.001"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetAdapter", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetConnectionProfile", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetEventSession", mitre_techniques: &["T1040"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetFirewallRule", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetIPAddress", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetIPInterface", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNat", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNatExternalAddress", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNatGlobal", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNatSession", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNatStaticMapping", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetNeighbor", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetRoute", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetTCPConnection", mitre_techniques: &["T1049"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NetUDPEndpoint", mitre_techniques: &["T1049"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NfsSession", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-NfsShare", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-OdbcDsn", mitre_techniques: &["T1552"], use_cases: UC_CREDENTIALS | UC_RECON, description: "" },
    LolbasEntry { name: "Get-Partition", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-PhysicalDisk", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-Printer", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-Process", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "Enumerate running processes; identify security tools and targets." },
    LolbasEntry { name: "Get-RemoteAccess", mitre_techniques: &["T1021"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ScheduledTask", mitre_techniques: &["T1053.005"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-ScheduledTaskInfo", mitre_techniques: &["T1053.005"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-Service", mitre_techniques: &["T1007"], use_cases: UC_RECON, description: "Enumerate Windows services; identify security products." },
    LolbasEntry { name: "Get-SmbConnection", mitre_techniques: &["T1021.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-SmbOpenFile", mitre_techniques: &["T1021.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-SmbServerConfiguration", mitre_techniques: &["T1021.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-SmbSession", mitre_techniques: &["T1021.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-SmbShare", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "Enumerate network shares; lateral movement target identification." },
    LolbasEntry { name: "Get-VirtualDisk", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-VM", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-Volume", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-VpnConnection", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-WindowsFeature", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Get-WinEvent", mitre_techniques: &["T1654"], use_cases: UC_RECON, description: "Read Windows event logs; investigation evasion and log inspection." },
    LolbasEntry { name: "Get-WSManInstance", mitre_techniques: &["T1021.006"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Install-WindowsFeature", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Invoke-CimMethod", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "Invoke WMI methods; remote process creation and service manipulation." },
    LolbasEntry { name: "Invoke-Command", mitre_techniques: &["T1021.006"], use_cases: UC_EXECUTE | UC_NETWORK, description: "Execute commands on remote systems via WinRM; lateral movement." },
    LolbasEntry { name: "Invoke-WSManAction", mitre_techniques: &["T1021.006"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Mount-DiskImage", mitre_techniques: &["T1553.005"], use_cases: UC_BYPASS, description: "Mount ISO/VHD to bypass Mark-of-the-Web." },
    LolbasEntry { name: "Move-Item", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "New-ADComputer", mitre_techniques: &["T1136.002"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "New-ADGroup", mitre_techniques: &["T1136.002"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "New-ADObject", mitre_techniques: &["T1136.002"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "New-ADOrganizationalUnit", mitre_techniques: &["T1136.002"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "New-ADServiceAccount", mitre_techniques: &["T1136.002"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "New-ADUser", mitre_techniques: &["T1136.001"], use_cases: UC_CREDENTIALS, description: "Create a new AD user account for persistence." },
    LolbasEntry { name: "New-CimInstance", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "New-CimSession", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "New-EtwTraceSession", mitre_techniques: &["T1562.006"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "New-GPLink", mitre_techniques: &["T1484.001"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "New-GPO", mitre_techniques: &["T1484.001"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "New-NetEventSession", mitre_techniques: &["T1040"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "New-NetFirewallRule", mitre_techniques: &["T1562.004"], use_cases: UC_NETWORK, description: "Create firewall rule; open ports for C2 or lateral movement." },
    LolbasEntry { name: "New-NetNat", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "New-NetRoute", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "New-PSSession", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "Create persistent PS remote session; lateral movement." },
    LolbasEntry { name: "New-ScheduledTask", mitre_techniques: &["T1053.005"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "New-SmbShare", mitre_techniques: &["T1135"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "New-VirtualDisk", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "New-VirtualDiskSnapshot", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "New-WSManInstance", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Out-File", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Publish-DscConfiguration", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Register-CimIndicationEvent", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "Register-ScheduledTask", mitre_techniques: &["T1053.005"], use_cases: UC_PERSIST, description: "Register a scheduled task; persistence via task execution." },
    LolbasEntry { name: "Remove-ADUser", mitre_techniques: &["T1531"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Remove-DhcpServerv4Lease", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-FileShare", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-MpPreference", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Remove Defender settings; weaken AV protection." },
    LolbasEntry { name: "Remove-MpThreat", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Remove-NetEventSession", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-NetNat", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-NetNatExternalAddress", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-NetNatStaticMapping", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-SmbShare", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Remove-VirtualDisk", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Rename-ADObject", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Resolve-DnsName", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "DNS lookups; infrastructure mapping and C2 beacon testing." },
    LolbasEntry { name: "Restart-Computer", mitre_techniques: &["T1529"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Search-ADAccount", mitre_techniques: &["T1087.002"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Set-ADAccountControl", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-ADAccountExpiration", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-ADAccountPassword", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "Set an AD account password; credential manipulation for persistence." },
    LolbasEntry { name: "Set-ADGroup", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-ADObject", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-ADServiceAccount", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-ADUser", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Set-CimInstance", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Set-DhcpServerAuditLog", mitre_techniques: &["T1562.006"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Set-DnsServerSetting", mitre_techniques: &["T1584.002"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Set-MpPreference", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Configure Defender exclusions; bypass AV scanning." },
    LolbasEntry { name: "Set-NetConnectionProfile", mitre_techniques: &["T1016"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Set-NetFirewallProfile", mitre_techniques: &["T1562.004"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Set-NetFirewallRule", mitre_techniques: &["T1562.004"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Set-NetFirewallSetting", mitre_techniques: &["T1562.004"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Set-NetNat", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Set-NetNatGlobal", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Set-NetRoute", mitre_techniques: &["T1090"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Set-ScheduledTask", mitre_techniques: &["T1053.005"], use_cases: UC_PERSIST, description: "" },
    LolbasEntry { name: "Set-WSManInstance", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "" },
    LolbasEntry { name: "Show-DnsServerCache", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Show-EventLog", mitre_techniques: &["T1654"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Show-NetFirewallRule", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Start-DscConfiguration", mitre_techniques: &["T1072"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Start-NetEventSession", mitre_techniques: &["T1040"], use_cases: UC_RECON, description: "" },
    LolbasEntry { name: "Start-ScheduledTask", mitre_techniques: &["T1053.005"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Start-VM", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Stop-Computer", mitre_techniques: &["T1529"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Stop-EtwTraceSession", mitre_techniques: &["T1562.006"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Stop-NetEventSession", mitre_techniques: &[], use_cases: 0, description: "" },
    LolbasEntry { name: "Test-Connection", mitre_techniques: &["T1018"], use_cases: UC_RECON, description: "ICMP ping sweep; host discovery." },
    LolbasEntry { name: "Test-NetConnection", mitre_techniques: &["T1046"], use_cases: UC_RECON, description: "TCP port scan and traceroute; network mapping." },
    LolbasEntry { name: "Uninstall-WindowsFeature", mitre_techniques: &[], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Unlock-ADAccount", mitre_techniques: &["T1098"], use_cases: UC_CREDENTIALS, description: "" },
    LolbasEntry { name: "Unregister-ScheduledTask", mitre_techniques: &["T1070"], use_cases: UC_DEFENSE_EVASION, description: "" },
    LolbasEntry { name: "Write-EventLog", mitre_techniques: &["T1070.001"], use_cases: UC_DEFENSE_EVASION, description: "" },
    // ── Native PowerShell attack cmdlets (LOL) ───────────────────────────────
    // These cmdlets ship with Windows/PowerShell itself (not a third-party module).
    // They appear in every PS installation and are universally abused for
    // download-and-execute, reflective loading, persistence, and credential theft.
    //
    // Sources:
    // - MITRE ATT&CK T1059.001 — PowerShell: <https://attack.mitre.org/techniques/T1059/001/>
    // - Atomic Red Team T1059.001: <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md>
    // - Red Canary Threat Detection Report — "Misbehaving Binaries: LOLbins in the Wild":
    //   <https://redcanary.com/blog/blog/lolbins-abuse/>
    // - MITRE ATT&CK T1620 (Reflective Code Loading): <https://attack.mitre.org/techniques/T1620/>
    // - MITRE ATT&CK T1197 (BITS Jobs): <https://attack.mitre.org/techniques/T1197/>
    // - MITRE ATT&CK T1546 (Event Triggered Execution): <https://attack.mitre.org/techniques/T1546/>
    // - MITRE ATT&CK T1115 (Clipboard Data): <https://attack.mitre.org/techniques/T1115/>
    // - MITRE ATT&CK T1560 (Archive Collected Data): <https://attack.mitre.org/techniques/T1560/>
    //
    // ── Execution ────────────────────────────────────────────────────────────
    LolbasEntry { name: "Invoke-Expression", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Execute arbitrary PowerShell strings; primary AMSI bypass vehicle." },
    LolbasEntry { name: "Invoke-WebRequest", mitre_techniques: &["T1059.001", "T1105"], use_cases: UC_DOWNLOAD | UC_EXECUTE, description: "HTTP/S download cmdlet; payload delivery and C2 communication." },
    LolbasEntry { name: "Invoke-RestMethod", mitre_techniques: &["T1059.001", "T1071.001"], use_cases: UC_DOWNLOAD | UC_EXECUTE, description: "REST API client; C2 over HTTPS and payload retrieval." },
    LolbasEntry { name: "Invoke-Item", mitre_techniques: &["T1204.002"], use_cases: UC_EXECUTE, description: "Execute file via shell association; run payloads without explicit path." },
    LolbasEntry { name: "Start-Process", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Launch process with hidden window; stealthy process execution." },
    LolbasEntry { name: "New-Object", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE | UC_DOWNLOAD, description: "Instantiate Net.WebClient, COM shell, ADODB.Stream for downloads." },
    LolbasEntry { name: "Add-Type", mitre_techniques: &["T1620"], use_cases: UC_EXECUTE, description: "Compile and load C#/VB.NET inline; reflective code loading." },
    LolbasEntry { name: "Start-Job", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Background execution to avoid blocking; evade timeout-based detections." },
    LolbasEntry { name: "Import-Module", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Load PS modules and attack toolkits; import offensive frameworks." },
    LolbasEntry { name: "Install-Module", mitre_techniques: &["T1059.001"], use_cases: UC_DOWNLOAD | UC_EXECUTE, description: "Download modules from PSGallery; supply chain attack vector." },
    //
    // ── Defense evasion ──────────────────────────────────────────────────────
    LolbasEntry { name: "Set-ExecutionPolicy", mitre_techniques: &["T1059.001"], use_cases: UC_BYPASS, description: "Bypass script execution restrictions; enable unsigned script execution." },
    LolbasEntry { name: "Unblock-File", mitre_techniques: &["T1553.005"], use_cases: UC_BYPASS, description: "Remove Zone.Identifier ADS; bypass Mark-of-the-Web." },
    // (Set-MpPreference and Remove-MpPreference already in LOFL section above)
    // (Mount-DiskImage and Dismount-DiskImage already in LOFL section above)
    //
    // ── Persistence ──────────────────────────────────────────────────────────
    LolbasEntry { name: "Register-ObjectEvent", mitre_techniques: &["T1546"], use_cases: UC_PERSIST, description: "Subscribe to .NET events for triggered execution." },
    LolbasEntry { name: "Register-WmiEvent", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST, description: "WMI event subscription persistence; fileless trigger execution." },
    LolbasEntry { name: "Set-ItemProperty", mitre_techniques: &["T1547.001"], use_cases: UC_PERSIST, description: "Write registry keys; Run key persistence." },
    LolbasEntry { name: "New-ItemProperty", mitre_techniques: &["T1547.001"], use_cases: UC_PERSIST, description: "Create new registry values; persistence via Run key." },
    LolbasEntry { name: "New-Service", mitre_techniques: &["T1543.003"], use_cases: UC_PERSIST, description: "Create a Windows service for persistence." },
    LolbasEntry { name: "Set-Service", mitre_techniques: &["T1543.003"], use_cases: UC_PERSIST, description: "Modify existing service config; hijack existing service." },
    LolbasEntry { name: "Enable-PSRemoting", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "Enable WinRM remoting on target; lateral movement enablement." },
    //
    // ── Discovery / reconnaissance ────────────────────────────────────────────
    // (Get-Process, Get-Service, Get-ChildItem, Get-CimInstance, Get-WinEvent, Get-HotFix
    //  Get-NetTCPConnection, Get-NetIPAddress, Get-NetAdapter, Get-SmbShare,
    //  Test-Connection, Test-NetConnection, Resolve-DnsName already in LOFL section above)
    LolbasEntry { name: "Get-ItemProperty", mitre_techniques: &["T1012"], use_cases: UC_RECON, description: "Read registry values; enumerate configuration and credentials." },
    LolbasEntry { name: "Get-WmiObject", mitre_techniques: &["T1047"], use_cases: UC_RECON, description: "WMI queries for system info (PS 5.x); alias gwmi common in telemetry." },
    LolbasEntry { name: "Get-LocalUser", mitre_techniques: &["T1087.001"], use_cases: UC_RECON, description: "Enumerate local user accounts." },
    LolbasEntry { name: "Get-LocalGroup", mitre_techniques: &["T1069.001"], use_cases: UC_RECON, description: "Enumerate local groups." },
    LolbasEntry { name: "Get-LocalGroupMember", mitre_techniques: &["T1069.001"], use_cases: UC_RECON, description: "Enumerate group membership." },
    LolbasEntry { name: "Get-ComputerInfo", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Full system fingerprint; comprehensive hardware and software inventory." },
    LolbasEntry { name: "Test-Path", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Check file/registry existence; probe for security tool installations." },
    //
    // ── Collection ───────────────────────────────────────────────────────────
    LolbasEntry { name: "Get-Clipboard", mitre_techniques: &["T1115"], use_cases: UC_RECON, description: "Steal clipboard contents; capture credentials and sensitive data." },
    LolbasEntry { name: "Set-Clipboard", mitre_techniques: &["T1115"], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Compress-Archive", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "Zip files for staging before exfiltration." },
    LolbasEntry { name: "Expand-Archive", mitre_techniques: &["T1560.001"], use_cases: UC_ARCHIVE, description: "Extract delivered payloads from archives." },
    LolbasEntry { name: "Get-Content", mitre_techniques: &["T1005"], use_cases: UC_RECON, description: "Read file contents; exfiltrate credential files and configs." },
    LolbasEntry { name: "Select-String", mitre_techniques: &["T1552.001"], use_cases: UC_RECON, description: "Regex search in files; grep for passwords in config files." },
    LolbasEntry { name: "Set-Content", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Add-Content", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "" },
    LolbasEntry { name: "Remove-Item", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Delete files; anti-forensics and evidence removal." },
    LolbasEntry { name: "Clear-EventLog", mitre_techniques: &["T1070.001"], use_cases: UC_DEFENSE_EVASION, description: "Wipe Windows event logs; evidence destruction." },
    //
    // ── Credential access ─────────────────────────────────────────────────────
    LolbasEntry { name: "ConvertTo-SecureString", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Handle credential objects; construct credentials from plaintext." },
    LolbasEntry { name: "ConvertFrom-SecureString", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Extract plaintext from secure strings; credential decryption." },
    LolbasEntry { name: "Get-Credential", mitre_techniques: &["T1056.002"], use_cases: UC_CREDENTIALS, description: "Prompt user for credentials; interactive credential capture." },
    LolbasEntry { name: "Export-Clixml", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Serialize credentials to XML; credential theft and portability." },
    LolbasEntry { name: "Import-Clixml", mitre_techniques: &["T1003"], use_cases: UC_CREDENTIALS, description: "Deserialize saved credentials; replay stolen credential objects." },
    //
    // ── Remoting / lateral movement ───────────────────────────────────────────
    // (Enter-PSSession, New-PSSession already in LOFL section above)
    LolbasEntry { name: "Invoke-WmiMethod", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE | UC_NETWORK, description: "Remote WMI method execution; lateral movement via WMI." },
    //
    // ── Network ───────────────────────────────────────────────────────────────
    LolbasEntry { name: "Start-BitsTransfer", mitre_techniques: &["T1197"], use_cases: UC_DOWNLOAD | UC_UPLOAD, description: "BITS job for stealthy download/upload; evade proxy inspection." },
    // (New-NetFirewallRule and Disable-NetFirewallRule already in LOFL section above)
    //
    // ── Built-in PowerShell aliases (LOL) ─────────────────────────────────────
    // Sourced from PowerShell InitialSessionState (canonical):
    // <https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/InitialSessionState.cs>
    // Detection: PSReadLine history and AMSI capture the alias before resolution.
    // ScriptBlock logging (Event 4104) may or may not resolve aliases.
    //
    // Execution
    LolbasEntry { name: "iex", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE | UC_BYPASS, description: "Built-in alias for Invoke-Expression; canonical download-and-execute alias." },
    LolbasEntry { name: "iwr", mitre_techniques: &["T1059.001", "T1105"], use_cases: UC_DOWNLOAD, description: "Invoke-WebRequest alias; payload download shorthand." },
    LolbasEntry { name: "irm", mitre_techniques: &["T1059.001", "T1071.001"], use_cases: UC_DOWNLOAD, description: "Invoke-RestMethod alias; C2 over HTTPS shorthand." },
    LolbasEntry { name: "icm", mitre_techniques: &["T1021.006"], use_cases: UC_EXECUTE | UC_NETWORK, description: "Invoke-Command alias; remote execution shorthand." },
    LolbasEntry { name: "ii", mitre_techniques: &["T1204.002"], use_cases: UC_EXECUTE, description: "Invoke-Item alias." },
    LolbasEntry { name: "saps", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Start-Process alias." },
    LolbasEntry { name: "start", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Start-Process alias; common in one-liner payloads." },
    LolbasEntry { name: "ipmo", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Import-Module alias; load offensive modules." },
    LolbasEntry { name: "sajb", mitre_techniques: &["T1059.001"], use_cases: UC_EXECUTE, description: "Start-Job alias; background execution." },
    // WMI aliases — PS 5.1 only (removed in PS 7)
    LolbasEntry { name: "gwmi", mitre_techniques: &["T1047"], use_cases: UC_RECON, description: "Get-WmiObject alias; extremely common in attack telemetry." },
    LolbasEntry { name: "iwmi", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "Invoke-WmiMethod alias (PS 5.x only)." },
    // Discovery
    LolbasEntry { name: "gci", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Get-ChildItem alias; directory enumeration." },
    LolbasEntry { name: "ls", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Get-ChildItem alias (PS); shadows Unix ls." },
    LolbasEntry { name: "dir", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Get-ChildItem alias; directory listing." },
    LolbasEntry { name: "gps", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "Get-Process alias." },
    LolbasEntry { name: "ps", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "Get-Process alias; shadows Unix ps." },
    LolbasEntry { name: "gsv", mitre_techniques: &["T1007"], use_cases: UC_RECON, description: "Get-Service alias." },
    // Collection
    LolbasEntry { name: "gc", mitre_techniques: &["T1005"], use_cases: UC_RECON, description: "Get-Content alias." },
    LolbasEntry { name: "cat", mitre_techniques: &["T1005"], use_cases: UC_RECON, description: "Get-Content alias; shadows Unix cat." },
    LolbasEntry { name: "type", mitre_techniques: &["T1005"], use_cases: UC_RECON, description: "Get-Content alias." },
    LolbasEntry { name: "sls", mitre_techniques: &["T1552.001"], use_cases: UC_RECON, description: "Select-String alias; credential file grep." },
    LolbasEntry { name: "gp", mitre_techniques: &["T1012"], use_cases: UC_RECON, description: "Get-ItemProperty alias; registry value enumeration." },
    // File manipulation
    LolbasEntry { name: "cp", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "Copy-Item alias; file staging." },
    LolbasEntry { name: "cpi", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "Copy-Item alias." },
    LolbasEntry { name: "copy", mitre_techniques: &["T1074.001"], use_cases: UC_EXECUTE, description: "Copy-Item alias." },
    LolbasEntry { name: "mv", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Move-Item alias." },
    LolbasEntry { name: "mi", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Move-Item alias." },
    LolbasEntry { name: "move", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Move-Item alias." },
    LolbasEntry { name: "rm", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias; file deletion for anti-forensics." },
    LolbasEntry { name: "ri", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias." },
    LolbasEntry { name: "del", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias." },
    LolbasEntry { name: "erase", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias." },
    LolbasEntry { name: "rd", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias; directory removal." },
    LolbasEntry { name: "rmdir", mitre_techniques: &["T1070.004"], use_cases: UC_DEFENSE_EVASION, description: "Remove-Item alias; recursive directory deletion." },
    LolbasEntry { name: "ni", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "New-Item alias." },
    LolbasEntry { name: "ac", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Add-Content alias." },
    LolbasEntry { name: "sc", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Set-Content alias (PS5 only — conflicts with sc.exe Service Control)." },
    LolbasEntry { name: "si", mitre_techniques: &[], use_cases: UC_EXECUTE, description: "Set-Item alias." },
    LolbasEntry { name: "sp", mitre_techniques: &["T1547.001"], use_cases: UC_PERSIST, description: "Set-ItemProperty alias; registry persistence shorthand." },
    // Process/service
    LolbasEntry { name: "spps", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Stop-Process alias; kill security processes." },
    LolbasEntry { name: "kill", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Stop-Process alias; terminate AV/EDR processes." },
    LolbasEntry { name: "sasv", mitre_techniques: &["T1543.003"], use_cases: UC_EXECUTE, description: "Start-Service alias." },
    LolbasEntry { name: "spsv", mitre_techniques: &["T1562.001"], use_cases: UC_DEFENSE_EVASION, description: "Stop-Service alias; disable security services." },
    // Remoting session
    LolbasEntry { name: "etsn", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "Enter-PSSession alias; lateral movement shorthand." },
    LolbasEntry { name: "nsn", mitre_techniques: &["T1021.006"], use_cases: UC_NETWORK, description: "New-PSSession alias." },
    // PS 5.x aliases that shadow Unix commands — evasion via ambiguity
    LolbasEntry { name: "wget", mitre_techniques: &["T1059.001", "T1105"], use_cases: UC_DOWNLOAD, description: "Invoke-WebRequest alias (PS5.x only); shadows /usr/bin/wget." },
    LolbasEntry { name: "curl", mitre_techniques: &["T1059.001", "T1105"], use_cases: UC_DOWNLOAD, description: "Invoke-WebRequest alias (PS5.x only); shadows /usr/bin/curl." },
];

/// Windows LOLBAS MMC snap-ins (`.msc` files).
///
/// MMC snap-ins appear in LNK/shortcut files, UserAssist registry entries,
/// Jump Lists, and Recent file MRUs — not in process telemetry directly.
/// All entries map to T1218.014 — System Binary Proxy Execution: MMC
/// <https://attack.mitre.org/techniques/T1218/014/>
///
/// Sourced from the LOFL Project: <https://lofl-project.github.io/>
pub const LOLBAS_WINDOWS_MMC: &[LolbasEntry] = &[
    // T1218.014 — MMC Signed Binary Proxy Execution <https://attack.mitre.org/techniques/T1218/014/>
    // All .msc files are loaded by mmc.exe; adversaries use them to proxy
    // execution, enumerate sensitive config, and escalate privileges.

    // Security / certificate management
    LolbasEntry { name: "AdRmsAdmin.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Active Directory Rights Management Services." },
    LolbasEntry { name: "azman.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Authorization Manager; RBAC policy inspection." },
    LolbasEntry { name: "certlm.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Local Machine certificate store." },
    LolbasEntry { name: "certmgr.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Personal certificate store." },
    LolbasEntry { name: "certsrv.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Certificate Authority management; PKI recon." },
    LolbasEntry { name: "certtmpl.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON | UC_BYPASS, description: "Certificate Templates; template abuse for privilege escalation." },
    LolbasEntry { name: "ipsecsnp.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "IPsec security policy." },
    LolbasEntry { name: "ipsmsnap.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "IP Security Monitor." },
    LolbasEntry { name: "Microsoft.IdentityServer.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "AD FS Identity Server." },
    LolbasEntry { name: "ocsp.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Online Certificate Status Protocol responder." },
    LolbasEntry { name: "pkiview.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "PKI View; full CA chain enumeration." },
    LolbasEntry { name: "secpol.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON | UC_BYPASS, description: "Local Security Policy; audit policy and user rights assignment." },
    LolbasEntry { name: "tpm.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "TPM Management." },
    LolbasEntry { name: "wsecedit.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Security Configuration Editor." },

    // Active Directory / directory services
    LolbasEntry { name: "adsiedit.msc", mitre_techniques: &["T1218.014", "T1087.002"], use_cases: UC_RECON | UC_CREDENTIALS, description: "ADSI Edit; low-level AD object manipulation and modification." },
    LolbasEntry { name: "domain.msc", mitre_techniques: &["T1218.014", "T1482"], use_cases: UC_RECON, description: "Active Directory Domains and Trusts." },
    LolbasEntry { name: "dsa.msc", mitre_techniques: &["T1218.014", "T1087.002"], use_cases: UC_RECON, description: "Active Directory Users and Computers." },
    LolbasEntry { name: "dssite.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Active Directory Sites and Services." },
    LolbasEntry { name: "schmmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Active Directory Schema; schema enumeration." },

    // Computer / device management
    LolbasEntry { name: "comexp.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Component Services (COM+); COM object registration." },
    LolbasEntry { name: "compmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Computer Management; unified admin console." },
    LolbasEntry { name: "devmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Device Manager; driver enumeration and device info." },
    LolbasEntry { name: "DevModeRunAsUserConfig.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Developer mode user config." },
    LolbasEntry { name: "diskmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Disk Management; partition and volume enumeration." },
    LolbasEntry { name: "lusrmgr.msc", mitre_techniques: &["T1218.014", "T1087.001"], use_cases: UC_RECON, description: "Local Users and Groups; user/group enumeration." },

    // Group Policy
    LolbasEntry { name: "gpedit.msc", mitre_techniques: &["T1218.014", "T1484.001"], use_cases: UC_RECON | UC_BYPASS, description: "Local Group Policy Editor; policy modification." },
    LolbasEntry { name: "gpmc.msc", mitre_techniques: &["T1218.014", "T1484.001"], use_cases: UC_RECON, description: "Group Policy Management Console." },
    LolbasEntry { name: "gpme.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Group Policy Management Editor." },
    LolbasEntry { name: "gptedit.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Group Policy Template Editor." },
    LolbasEntry { name: "rsop.msc", mitre_techniques: &["T1218.014", "T1615"], use_cases: UC_RECON, description: "Resultant Set of Policy; effective policy recon." },

    // Network / infrastructure
    LolbasEntry { name: "CluAdmin.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Failover Cluster Manager." },
    LolbasEntry { name: "dfsmgmt.msc", mitre_techniques: &["T1218.014", "T1135"], use_cases: UC_RECON, description: "DFS Management; share enumeration." },
    LolbasEntry { name: "dhcpmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "DHCP Server Management." },
    LolbasEntry { name: "dnsmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "DNS Server Management." },
    LolbasEntry { name: "nfsmgmt.msc", mitre_techniques: &["T1218.014", "T1135"], use_cases: UC_RECON, description: "NFS Management." },
    LolbasEntry { name: "nps.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Network Policy Server (RADIUS)." },
    LolbasEntry { name: "RAMgmtUI.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Remote Access Management." },
    LolbasEntry { name: "rrasmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Routing and Remote Access." },
    LolbasEntry { name: "tapimgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Telephony (TAPI)." },
    LolbasEntry { name: "winsmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "WINS Server Management." },

    // Storage
    LolbasEntry { name: "fsmgmt.msc", mitre_techniques: &["T1218.014", "T1135"], use_cases: UC_RECON, description: "Shared Folders; network share enumeration." },
    LolbasEntry { name: "fsrm.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "File Server Resource Manager." },
    LolbasEntry { name: "wbadmin.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Windows Server Backup." },
    LolbasEntry { name: "WdsMgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Windows Deployment Services." },

    // Performance / monitoring
    LolbasEntry { name: "lsdiag.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Remote Desktop Licensing Diagnostics." },
    LolbasEntry { name: "perfmon.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Performance Monitor; process/resource telemetry." },

    // IIS / web / print / fax
    LolbasEntry { name: "fxsadmin.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Fax Service Manager." },
    LolbasEntry { name: "iis.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "IIS Manager (IIS 6 compat)." },
    LolbasEntry { name: "iis6.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "IIS 6 Manager." },
    LolbasEntry { name: "printmanagement.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Print Management." },
    LolbasEntry { name: "remoteprograms.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "RemoteApp Programs." },

    // Services / event log / scheduler
    LolbasEntry { name: "eventvwr.msc", mitre_techniques: &["T1218.014", "T1654"], use_cases: UC_RECON, description: "Event Viewer; log inspection and UAC bypass vector." },
    LolbasEntry { name: "services.msc", mitre_techniques: &["T1218.014", "T1543.003"], use_cases: UC_RECON, description: "Services; service enumeration and manipulation." },
    LolbasEntry { name: "taskschd.msc", mitre_techniques: &["T1218.014", "T1053.005"], use_cases: UC_RECON | UC_PERSIST, description: "Task Scheduler; scheduled task persistence." },

    // Virtualization / SQL
    LolbasEntry { name: "virtmgmt.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Hyper-V Manager." },
    LolbasEntry { name: "SQLServerManager15.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "SQL Server 2019 Configuration Manager." },
    LolbasEntry { name: "SQLServerManager16.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "SQL Server 2022 Configuration Manager." },

    // Terminal Services / RDS
    LolbasEntry { name: "tsadmin.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Remote Desktop Services Manager." },
    LolbasEntry { name: "tsconfig.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "RD Session Host Configuration." },
    LolbasEntry { name: "tsgateway.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "RD Gateway Manager." },

    // Firewall / WMI / WSUS
    LolbasEntry { name: "WF.msc", mitre_techniques: &["T1218.014", "T1562.004"], use_cases: UC_RECON | UC_DEFENSE_EVASION, description: "Windows Firewall with Advanced Security." },
    LolbasEntry { name: "WmiMgmt.msc", mitre_techniques: &["T1218.014", "T1047"], use_cases: UC_RECON, description: "WMI Control; WMI namespace permissions." },
    LolbasEntry { name: "wsus.msc", mitre_techniques: &["T1218.014"], use_cases: UC_RECON, description: "Windows Server Update Services." },
];

/// Windows LOLBAS WMI class names — abused in WMI-based attacks.
///
/// These appear as strings inside WMI queries logged in the
/// Microsoft-Windows-WMI-Activity/Operational log (Event 5861) and in
/// PowerShell ScriptBlock logs when accessed via `Get-CimInstance` or
/// `Get-WmiObject`.
///
/// All entries map to T1047 — Windows Management Instrumentation
/// <https://attack.mitre.org/techniques/T1047/>
///
/// Sourced from the LOFL Project: <https://lofl-project.github.io/>
pub const LOLBAS_WINDOWS_WMI: &[LolbasEntry] = &[
    // T1047 — WMI Execution / Process creation
    LolbasEntry { name: "Win32_Process", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "Create/terminate processes; primary WMI remote execution vector." },
    LolbasEntry { name: "Win32_ProcessStartup", mitre_techniques: &["T1047"], use_cases: UC_EXECUTE, description: "Process startup configuration for WMI-launched processes." },

    // T1546.003 — WMI Event Subscription persistence
    LolbasEntry { name: "__EventFilter", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST, description: "WMI event filter; subscribe to system events for triggered execution." },
    LolbasEntry { name: "__EventConsumer", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST, description: "WMI event consumer base class; action taken on matched event." },
    LolbasEntry { name: "__FilterToConsumerBinding", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST, description: "Binds filter to consumer; completes WMI subscription persistence chain." },
    LolbasEntry { name: "ActiveScriptEventConsumer", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST | UC_EXECUTE, description: "Run VBScript/JScript on WMI event; fileless persistence." },
    LolbasEntry { name: "CommandLineEventConsumer", mitre_techniques: &["T1546.003"], use_cases: UC_PERSIST | UC_EXECUTE, description: "Run executable on WMI event; persistence and code execution." },

    // T1082 — System Information Discovery / T1016 — Network Config Discovery
    LolbasEntry { name: "Win32_ComputerSystem", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Hostname, domain, RAM, architecture; system fingerprint." },
    LolbasEntry { name: "Win32_OperatingSystem", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "OS version, install date, last boot; system enumeration." },
    LolbasEntry { name: "Win32_Environment", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Environment variable enumeration." },
    LolbasEntry { name: "Win32_NTLogEvent", mitre_techniques: &["T1654"], use_cases: UC_RECON, description: "Event log query via WMI." },
    LolbasEntry { name: "Win32_QuickFixEngineering", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "Installed hotfix/patch enumeration." },
    LolbasEntry { name: "CIM_DataFile", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "File system query by attribute; file discovery via WMI." },
    LolbasEntry { name: "CIM_Directory", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Directory enumeration via WMI." },
    LolbasEntry { name: "CIM_LogicalFile", mitre_techniques: &["T1083"], use_cases: UC_RECON, description: "Logical file metadata query." },
    LolbasEntry { name: "MSFT_DNSClientCache", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "DNS cache inspection; network reconnaissance." },
    LolbasEntry { name: "MSFT_MTProcess", mitre_techniques: &["T1057"], use_cases: UC_RECON, description: "Modern process telemetry." },
    LolbasEntry { name: "MSFT_NetFirewallRule", mitre_techniques: &["T1016"], use_cases: UC_RECON, description: "Firewall rule enumeration; discover security controls." },
    LolbasEntry { name: "Win32_DfsNode", mitre_techniques: &["T1135"], use_cases: UC_RECON, description: "DFS namespace enumeration; share discovery." },

    // T1543.003 / T1489 — Service manipulation
    LolbasEntry { name: "Win32_Service", mitre_techniques: &["T1543.003", "T1489"], use_cases: UC_RECON | UC_PERSIST, description: "Service enumeration, start/stop, and persistence via WMI." },
    LolbasEntry { name: "Win32_SystemDriver", mitre_techniques: &["T1082"], use_cases: UC_RECON, description: "Kernel driver enumeration; rootkit and AV detection." },

    // T1490 — Inhibit Recovery (VSS deletion)
    LolbasEntry { name: "Win32_ShadowCopy", mitre_techniques: &["T1490"], use_cases: UC_DEFENSE_EVASION, description: "VSS snapshot deletion; inhibit system recovery (ransomware vector)." },

    // T1518 — Software Discovery
    LolbasEntry { name: "Win32_Product", mitre_techniques: &["T1518"], use_cases: UC_RECON, description: "Installed software enumeration." },

    // T1552 — Unsecured Credentials / Registry queries
    LolbasEntry { name: "StdRegProv", mitre_techniques: &["T1552", "T1112"], use_cases: UC_CREDENTIALS | UC_PERSIST, description: "Registry read/write via WMI; credential and config access." },

    // ── WMI expansion — recon + firewall control ──────────────────────────────
    // Source: WMIFilter (github.com/mattifestation/WMIFilter), ATT&CK T1047
    // T1018 — Remote System Discovery
    LolbasEntry {
        name: "Win32_PingStatus",
        mitre_techniques: &["T1018"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "ICMP ping via WMI; remote host discovery without native ping binary.",
    },
    // T1083 — File and Directory Discovery
    LolbasEntry {
        name: "Win32_LogicalDisk",
        mitre_techniques: &["T1083", "T1082"],
        use_cases: UC_RECON,
        description: "Logical drive enumeration; identify data staging candidates.",
    },
    // T1087.001 — Account Discovery: Local Account
    LolbasEntry {
        name: "Win32_UserAccount",
        mitre_techniques: &["T1087.001"],
        use_cases: UC_RECON,
        description: "Local user account enumeration via WMI.",
    },
    // T1016 — System Network Configuration Discovery
    LolbasEntry {
        name: "Win32_NetworkAdapterConfiguration",
        mitre_techniques: &["T1016"],
        use_cases: UC_RECON | UC_NETWORK,
        description: "Network adapter IP/DNS/gateway config; network recon via WMI.",
    },
    // T1518.001 — Security Software Discovery
    LolbasEntry {
        name: "AntiVirusProduct",
        mitre_techniques: &["T1518.001"],
        use_cases: UC_RECON,
        description: "Security product enumeration via SecurityCenter2 namespace; AV detection.",
    },
    // T1562.004 — Impair Defenses: Disable or Modify System Firewall
    LolbasEntry {
        name: "MSFT_NetFirewallProfile",
        mitre_techniques: &["T1562.004"],
        use_cases: UC_RECON | UC_DEFENSE_EVASION,
        description: "Firewall profile enumeration and disable via WMI; impair network defenses.",
    },
];

/// Returns `true` if `name` matches a known Windows PowerShell cmdlet or alias
/// in the unified catalog (native PS attack cmdlets + PS aliases + LOFL admin cmdlets).
/// Case-insensitive. Check against PSReadLine history, AMSI, and Event 4104 logs.
pub fn is_lolbas_windows_cmdlet(name: &str) -> bool {
    lolbas_entry(LOLBAS_WINDOWS_CMDLETS, name).is_some()
}

/// Returns `true` if `name` matches a known Windows LOLBAS MMC snap-in
/// (case-insensitive, `.msc` suffix required). Check against LNK files,
/// UserAssist, and Recent MRUs.
pub fn is_lolbas_windows_mmc(name: &str) -> bool {
    lolbas_entry(LOLBAS_WINDOWS_MMC, name).is_some()
}

/// Returns `true` if `class` matches a known Windows LOLBAS WMI class name
/// (case-insensitive). Check against WMI Activity Event 5861 and
/// PowerShell Get-CimInstance / Get-WmiObject calls.
pub fn is_lolbas_windows_wmi(class: &str) -> bool {
    lolbas_entry(LOLBAS_WINDOWS_WMI, class).is_some()
}


#[cfg(test)]
mod tests {
    use super::*;

    // ── MACOS_LOLBINS RED tests ───────────────────────────────────────────────
    #[test]
    fn macos_lolbins_is_nonempty() {
        assert!(!LOLBAS_MACOS.is_empty());
    }

    #[test]
    fn macos_lolbins_contains_osascript() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "osascript"));
    }

    #[test]
    fn macos_lolbins_contains_launchctl() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "launchctl"));
    }

    #[test]
    fn macos_lolbins_contains_security() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "security"));
    }

    #[test]
    fn macos_lolbins_contains_sqlite3() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "sqlite3"));
    }

    #[test]
    fn macos_lolbins_contains_tccutil() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "tccutil"));
    }

    #[test]
    fn macos_lolbins_contains_networksetup() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "networksetup"));
    }

    #[test]
    fn detects_osascript_exact() {
        assert!(is_lolbas_macos("osascript"));
    }

    #[test]
    fn detects_osascript_uppercase() {
        assert!(is_lolbas_macos("OSASCRIPT"));
    }

    #[test]
    fn detects_security_mixed_case() {
        assert!(is_lolbas_macos("Security"));
    }

    #[test]
    fn does_not_flag_finder() {
        assert!(!is_lolbas_macos("Finder"));
    }

    #[test]
    fn empty_string_not_macos_lolbin() {
        assert!(!is_lolbas_macos(""));
    }

    #[test]
    fn is_lolbas_detects_macos_osascript() {
        assert!(is_lolbas("osascript"));
    }

    #[test]
    fn is_lolbas_detects_macos_launchctl() {
        assert!(is_lolbas("launchctl"));
    }

    #[test]
    fn windows_lolbins_contains_certutil() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "certutil.exe"));
    }

    #[test]
    fn windows_lolbins_contains_mshta() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "mshta.exe"));
    }

    #[test]
    fn windows_lolbins_contains_powershell() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "powershell.exe"));
    }

    #[test]
    fn linux_lolbins_contains_nc() {
        assert!(LOLBAS_LINUX.iter().any(|e| e.name == "nc"));
    }

    #[test]
    fn linux_lolbins_contains_python3() {
        // python3 is not in GTFOBins; python is — test the canonical name
        assert!(LOLBAS_LINUX.iter().any(|e| e.name == "python"));
    }

    #[test]
    fn detects_certutil_exact() {
        assert!(is_lolbas_windows("certutil.exe"));
    }

    #[test]
    fn detects_certutil_uppercase() {
        assert!(is_lolbas_windows("CERTUTIL.EXE"));
    }

    #[test]
    fn detects_mshta_mixed_case() {
        assert!(is_lolbas_windows("Mshta.Exe"));
    }

    #[test]
    fn does_not_flag_notepad() {
        assert!(!is_lolbas_windows("notepad.exe"));
    }

    #[test]
    fn empty_string_not_windows_lolbin() {
        assert!(!is_lolbas_windows(""));
    }

    #[test]
    fn detects_bash() {
        assert!(is_lolbas_linux("bash"));
    }

    #[test]
    fn detects_socat_uppercase() {
        assert!(is_lolbas_linux("SOCAT"));
    }

    #[test]
    fn detects_python3() {
        // python3 is not a GTFOBins entry; python is
        assert!(is_lolbas_linux("python"));
    }

    #[test]
    fn does_not_flag_grep_as_missing() {
        // grep IS in GTFOBins — confirm it's detected
        assert!(is_lolbas_linux("grep"));
    }

    #[test]
    fn empty_string_not_linux_lolbin() {
        assert!(!is_lolbas_linux(""));
    }

    // --- is_lolbas (unified) ---
    #[test]
    fn lolbin_detects_windows_certutil() {
        assert!(is_lolbas("certutil.exe"));
    }
    #[test]
    fn lolbin_detects_linux_nc() {
        assert!(is_lolbas("nc"));
    }
    #[test]
    fn lolbin_detects_powershell() {
        assert!(is_lolbas("powershell.exe"));
    }
    #[test]
    fn lolbin_detects_bash() {
        assert!(is_lolbas("bash"));
    }
    #[test]
    fn lolbin_does_not_flag_notepad() {
        assert!(!is_lolbas("notepad.exe"));
    }
    #[test]
    fn lolbin_case_insensitive_windows() {
        assert!(is_lolbas("MSHTA.EXE"));
    }
    #[test]
    fn lolbin_case_insensitive_linux() {
        assert!(is_lolbas("PYTHON"));
    }
    #[test]
    fn empty_string_not_lolbin() {
        assert!(!is_lolbas(""));
    }

    // ── LOLBAS_MACOS foreign-tool expansion (RED) ────────────────────────────
    #[test]
    fn lolbas_macos_contains_kubectl() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "kubectl"));
    }
    #[test]
    fn lolbas_macos_contains_docker() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "docker"));
    }
    #[test]
    fn lolbas_macos_contains_terraform() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "terraform"));
    }
    #[test]
    fn lolbas_macos_contains_aws() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "aws"));
    }
    #[test]
    fn lolbas_macos_contains_brew() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "brew"));
    }
    #[test]
    fn lolbas_macos_contains_ngrok() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "ngrok"));
    }
    #[test]
    fn lolbas_macos_contains_frida() {
        assert!(LOLBAS_MACOS.iter().any(|e| e.name == "frida"));
    }
    #[test]
    fn is_lolbas_macos_detects_kubectl() {
        assert!(is_lolbas_macos("kubectl"));
    }
    #[test]
    fn is_lolbas_macos_detects_kubectl_uppercase() {
        assert!(is_lolbas_macos("KUBECTL"));
    }
    #[test]
    fn is_lolbas_detects_macos_kubectl() {
        assert!(is_lolbas("kubectl"));
    }

    // ── LOLBAS rename + GTFOBins expansion (RED) ─────────────────────────────
    #[test]
    fn lolbas_windows_constant_exists() {
        assert!(!LOLBAS_WINDOWS.is_empty());
    }
    #[test]
    fn lolbas_linux_constant_exists() {
        assert!(!LOLBAS_LINUX.is_empty());
    }
    #[test]
    fn lolbas_macos_constant_exists() {
        assert!(!LOLBAS_MACOS.is_empty());
    }
    #[test]
    fn is_lolbas_windows_detects_certutil() {
        assert!(is_lolbas_windows("certutil.exe"));
    }
    #[test]
    fn is_lolbas_linux_detects_bash() {
        assert!(is_lolbas_linux("bash"));
    }
    #[test]
    fn is_lolbas_macos_detects_osascript() {
        assert!(is_lolbas_macos("osascript"));
    }
    #[test]
    fn is_lolbas_detects_windows() {
        assert!(is_lolbas("certutil.exe"));
    }
    #[test]
    fn is_lolbas_detects_linux() {
        assert!(is_lolbas("bash"));
    }
    #[test]
    fn is_lolbas_detects_macos() {
        assert!(is_lolbas("osascript"));
    }
    // GTFOBins expansion — entries not in the original 26-entry list
    #[test]
    fn lolbas_linux_contains_7z() {
        assert!(LOLBAS_LINUX.iter().any(|e| e.name == "7z"));
    }
    #[test]
    fn lolbas_linux_contains_docker() {
        assert!(LOLBAS_LINUX.iter().any(|e| e.name == "docker"));
    }
    #[test]
    fn lolbas_linux_contains_sudo() {
        assert!(LOLBAS_LINUX.iter().any(|e| e.name == "sudo"));
    }
    #[test]
    fn is_lolbas_linux_detects_docker() {
        assert!(is_lolbas_linux("docker"));
    }
    #[test]
    fn is_lolbas_linux_detects_pip() {
        assert!(is_lolbas_linux("pip"));
    }
    #[test]
    fn is_lolbas_linux_detects_kubectl() {
        assert!(is_lolbas_linux("kubectl"));
    }
    #[test]
    fn is_lolbas_linux_case_insensitive() {
        assert!(is_lolbas_linux("DOCKER"));
    }
    #[test]
    fn is_lolbas_not_lolbas_grep() {
        // grep is NOT in GTFOBins — it has no known shell escape or bypass
        // (the GTFOBins entry exists but only for data extraction, not privilege esc)
        // Actually grep IS in GTFOBins — adjust this to a truly absent binary
        assert!(!is_lolbas("notepad.exe"));
    }
    #[test]
    fn empty_string_not_lolbas() {
        assert!(!is_lolbas(""));
    }

    // ── LOFL Windows expansion — RED ─────────────────────────────────────────
    // LOFL binaries merged into LOLBAS_WINDOWS
    #[test]
    fn lolbas_windows_contains_psexec() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "psexec.exe"));
    }
    #[test]
    fn lolbas_windows_contains_reg() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "reg.exe"));
    }
    #[test]
    fn lolbas_windows_contains_net() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "net.exe"));
    }
    #[test]
    fn lolbas_windows_contains_wevtutil() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "wevtutil.exe"));
    }
    #[test]
    fn lolbas_windows_contains_nltest() {
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "nltest.exe"));
    }
    #[test]
    fn is_lolbas_windows_detects_psexec() {
        assert!(is_lolbas_windows("psexec.exe"));
    }
    #[test]
    fn is_lolbas_windows_detects_psexec_uppercase() {
        assert!(is_lolbas_windows("PSEXEC.EXE"));
    }
    // LOLBAS_WINDOWS_MMC
    #[test]
    fn lolbas_windows_mmc_exists() {
        assert!(!LOLBAS_WINDOWS_MMC.is_empty());
    }
    #[test]
    fn lolbas_windows_mmc_contains_compmgmt() {
        assert!(LOLBAS_WINDOWS_MMC.iter().any(|e| e.name == "compmgmt.msc"));
    }
    #[test]
    fn lolbas_windows_mmc_contains_eventvwr() {
        assert!(LOLBAS_WINDOWS_MMC.iter().any(|e| e.name == "eventvwr.msc"));
    }
    #[test]
    fn is_lolbas_windows_mmc_detects_compmgmt() {
        assert!(is_lolbas_windows_mmc("compmgmt.msc"));
    }
    #[test]
    fn is_lolbas_windows_mmc_case_insensitive() {
        assert!(is_lolbas_windows_mmc("COMPMGMT.MSC"));
    }
    // LOLBAS_WINDOWS_WMI
    #[test]
    fn lolbas_windows_wmi_exists() {
        assert!(!LOLBAS_WINDOWS_WMI.is_empty());
    }
    #[test]
    fn lolbas_windows_wmi_contains_win32_process() {
        assert!(LOLBAS_WINDOWS_WMI.iter().any(|e| e.name == "Win32_Process"));
    }
    #[test]
    fn lolbas_windows_wmi_contains_win32_shadowcopy() {
        assert!(LOLBAS_WINDOWS_WMI.iter().any(|e| e.name == "Win32_ShadowCopy"));
    }
    #[test]
    fn is_lolbas_windows_wmi_detects_win32_process() {
        assert!(is_lolbas_windows_wmi("Win32_Process"));
    }
    #[test]
    fn is_lolbas_windows_wmi_case_insensitive() {
        assert!(is_lolbas_windows_wmi("win32_process"));
    }

    // LOLBAS_WINDOWS_CMDLETS — unified: native PS cmdlets + PS aliases + LOFL admin cmdlets
    // The distinction (LOL vs LOFL, cmdlet vs alias) is academic from a detection
    // standpoint: PSReadLine history and AMSI capture all forms identically.
    // Just as LOLBAS_WINDOWS merges LOL+LOFL binaries, this merges all PS indicators.
    #[test]
    fn lolbas_windows_cmdlets_exists() {
        assert!(!LOLBAS_WINDOWS_CMDLETS.is_empty());
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_lofl_admin_cmdlet() {
        // LOFL admin module cmdlets are included in the merged constant
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Invoke-Command"));
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Get-ADUser"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_invoke_webrequest() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Invoke-WebRequest"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_invoke_expression() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Invoke-Expression"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_invoke_restmethod() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Invoke-RestMethod"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_start_bitstransfer() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Start-BitsTransfer"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_add_type() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Add-Type"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_new_object() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "New-Object"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_set_executionpolicy() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Set-ExecutionPolicy"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_compress_archive() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Compress-Archive"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_start_process() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Start-Process"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_register_objectevent() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "Register-ObjectEvent"));
    }
    // PS aliases are merged into LOLBAS_WINDOWS_CMDLETS — no separate constant
    #[test]
    fn lolbas_windows_cmdlets_contains_iex_alias() {
        // iex → Invoke-Expression; citation: https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/InitialSessionState.cs
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "iex"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_iwr_alias() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "iwr"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_irm_alias() {
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "irm"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_wget_ps_alias() {
        // wget → Invoke-WebRequest in PS 5.x; removed in PS 7
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "wget"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_curl_ps_alias() {
        // curl → Invoke-WebRequest in PS 5.x; removed in PS 7
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "curl"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_icm_alias() {
        // icm → Invoke-Command
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "icm"));
    }
    #[test]
    fn lolbas_windows_cmdlets_contains_gwmi_alias() {
        // gwmi → Get-WmiObject (PS 5.x); widely seen in attack telemetry
        assert!(LOLBAS_WINDOWS_CMDLETS.iter().any(|e| e.name == "gwmi"));
    }
    #[test]
    fn is_lolbas_windows_cmdlet_detects_iex_alias() {
        assert!(is_lolbas_windows_cmdlet("iex"));
    }
    #[test]
    fn is_lolbas_windows_cmdlet_detects_invoke_webrequest() {
        assert!(is_lolbas_windows_cmdlet("Invoke-WebRequest"));
    }
    #[test]
    fn is_lolbas_windows_cmdlet_case_insensitive_alias() {
        assert!(is_lolbas_windows_cmdlet("IEX"));
        assert!(is_lolbas_windows_cmdlet("IWR"));
    }
    #[test]
    fn is_lolbas_windows_cmdlet_rejects_unknown() {
        assert!(!is_lolbas_windows_cmdlet("NotARealCmdlet-XYZ"));
    }

    // ── LolbasEntry struct — RED tests ────────────────────────────────────────
    // These tests will fail to compile until LolbasEntry, UC_* constants,
    // lolbas_entry(), and lolbas_names() are added.

    #[test]
    fn lolbas_entry_certutil_is_some() {
        assert!(lolbas_entry(LOLBAS_WINDOWS, "certutil.exe").is_some());
    }

    #[test]
    fn lolbas_entry_certutil_has_download_flag() {
        let entry = lolbas_entry(LOLBAS_WINDOWS, "certutil.exe").unwrap();
        assert!(entry.use_cases & UC_DOWNLOAD != 0);
    }

    #[test]
    fn lolbas_entry_certutil_has_mitre_techniques() {
        let entry = lolbas_entry(LOLBAS_WINDOWS, "certutil.exe").unwrap();
        assert!(!entry.mitre_techniques.is_empty());
        assert!(entry.mitre_techniques.contains(&"T1105"));
    }

    #[test]
    fn lolbas_names_windows_contains_certutil() {
        assert!(lolbas_names(LOLBAS_WINDOWS).any(|n| n == "certutil.exe"));
    }

    #[test]
    fn lolbas_entry_linux_curl_is_some() {
        assert!(lolbas_entry(LOLBAS_LINUX, "curl").is_some());
    }

    #[test]
    fn lolbas_entry_macos_osascript_is_some() {
        assert!(lolbas_entry(LOLBAS_MACOS, "osascript").is_some());
    }

    #[test]
    fn lolbas_entry_cmdlet_iex_is_some() {
        assert!(lolbas_entry(LOLBAS_WINDOWS_CMDLETS, "iex").is_some());
    }

    #[test]
    fn lolbas_entry_cmdlet_iex_has_execute_flag() {
        let entry = lolbas_entry(LOLBAS_WINDOWS_CMDLETS, "iex").unwrap();
        assert!(entry.use_cases & UC_EXECUTE != 0);
    }

    #[test]
    fn lolbas_entry_mmc_gpedit_is_some() {
        assert!(lolbas_entry(LOLBAS_WINDOWS_MMC, "gpedit.msc").is_some());
    }

    #[test]
    fn lolbas_entry_wmi_win32_process_is_some() {
        assert!(lolbas_entry(LOLBAS_WINDOWS_WMI, "Win32_Process").is_some());
    }

    // ── LOLBAS_WINDOWS catalog expansion (RED) — LOLBAS Project gaps ─────────
    // Source: https://lolbas-project.github.io/api/lolbas.json
    #[test]
    fn lolbas_windows_contains_diskshadow() {
        // T1003.003/T1490 — VSS shadow copy abuse for NTDS.dit extraction
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "diskshadow.exe"));
    }
    #[test]
    fn lolbas_windows_contains_esentutl() {
        // T1048/T1560 — copy locked files (NTDS.dit), file transfer
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "esentutl.exe"));
    }
    #[test]
    fn lolbas_windows_contains_cmdl32() {
        // T1105 — download via Windows VPN client INF parser
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "cmdl32.exe"));
    }
    #[test]
    fn lolbas_windows_contains_certoc() {
        // T1105/T1218 — certificate operations; download and DLL execution
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "certoc.exe"));
    }
    #[test]
    fn lolbas_windows_contains_addinutil() {
        // T1218 — .NET Add-In utility proxy execution
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "addinutil.exe"));
    }
    #[test]
    fn lolbas_windows_contains_winget() {
        // T1072/T1218 — Windows Package Manager; install/execute arbitrary packages
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "winget.exe"));
    }
    #[test]
    fn lolbas_windows_contains_wt() {
        // T1059.001 — Windows Terminal; spawn arbitrary shells/profiles
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "wt.exe"));
    }
    #[test]
    fn lolbas_windows_contains_pktmon() {
        // T1040 — network packet capture via in-box Windows tool
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "pktmon.exe"));
    }
    #[test]
    fn lolbas_windows_contains_desktopimgdownldr() {
        // T1105 — download arbitrary files via SetupSQM telemetry binary
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "desktopimgdownldr.exe"));
    }
    #[test]
    fn lolbas_windows_contains_rdrleakdiag() {
        // T1003.001 — LSASS memory dump via RDR Leak Diagnostics
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "rdrleakdiag.exe"));
    }
    #[test]
    fn lolbas_windows_contains_wsreset() {
        // T1218/T1548.002 — Windows Store reset; UAC bypass via COM elevation
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "wsreset.exe"));
    }
    #[test]
    fn lolbas_windows_contains_tttracer() {
        // T1218/T1003 — Time Travel Debugging tracer; dumps process memory
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "tttracer.exe"));
    }
    #[test]
    fn lolbas_windows_contains_mpcmdrun() {
        // T1218/T1562.001 — Windows Defender command-line; download + bypass
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "MpCmdRun.exe"));
    }
    #[test]
    fn lolbas_windows_contains_syncappvpublishingserver() {
        // T1218 — App-V publishing server sync; execute arbitrary PowerShell
        assert!(LOLBAS_WINDOWS
            .iter()
            .any(|e| e.name == "SyncAppvPublishingServer.exe"));
    }
    #[test]
    fn lolbas_windows_contains_infdefaultinstall() {
        // T1218 — INF file execution via Setup API; proxy + bypass
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "infdefaultinstall.exe"));
    }
    #[test]
    fn lolbas_windows_contains_rasautou() {
        // T1218 — DLL load via RRAS auto-dial manager; proxy execution
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "rasautou.exe"));
    }
    #[test]
    fn lolbas_windows_contains_pcwrun() {
        // T1218 — Program Compatibility Wizard runner; proxy execution
        assert!(LOLBAS_WINDOWS.iter().any(|e| e.name == "pcwrun.exe"));
    }

    // ── LOLBAS_WINDOWS_WMI expansion (RED) ───────────────────────────────────
    // Source: https://github.com/mattifestation/WMIFilter
    //         https://attack.mitre.org/techniques/T1047/
    #[test]
    fn lolbas_wmi_contains_win32_pingstatus() {
        // T1018 — remote host discovery via ICMP ping
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "Win32_PingStatus"));
    }
    #[test]
    fn lolbas_wmi_contains_win32_logicaldisk() {
        // T1083 — enumerate logical drives for data staging
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "Win32_LogicalDisk"));
    }
    #[test]
    fn lolbas_wmi_contains_win32_useraccount() {
        // T1087.001 — local account enumeration
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "Win32_UserAccount"));
    }
    #[test]
    fn lolbas_wmi_contains_win32_networkadapterconfiguration() {
        // T1016 — network configuration discovery
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "Win32_NetworkAdapterConfiguration"));
    }
    #[test]
    fn lolbas_wmi_contains_antivirus_product() {
        // T1518.001 — security software discovery via SecurityCenter2
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "AntiVirusProduct"));
    }
    #[test]
    fn lolbas_wmi_contains_msft_netfirewallprofile() {
        // T1562.004 — firewall rule enumeration and disable
        assert!(LOLBAS_WINDOWS_WMI
            .iter()
            .any(|e| e.name == "MSFT_NetFirewallProfile"));
    }
}
