/// Windows Living-Off-the-Land binaries (include `.exe` suffix).
///
/// Sources:
/// - LOLBAS Project — community-maintained, individual binary pages confirmed at
///   `https://lolbas-project.github.io/lolbas/Binaries/<Name>/`:
///   <https://lolbas-project.github.io/>
/// - MITRE ATT&CK T1218 — System Binary Proxy Execution (renamed from
///   "Signed Binary Proxy Execution" in April 2025 ATT&CK release):
///   <https://attack.mitre.org/techniques/T1218/>
/// - SANS ISC — Xavier Mertens, "Keep An Eye on LOLBins":
///   <https://isc.sans.edu/diary/Keep+An+Eye+on+LOLBins/26502>
/// - Red Canary — "Misbehaving Binaries: How to Detect LOLbins Abuse in the Wild":
///   <https://redcanary.com/blog/blog/lolbins-abuse/>
///
/// Each binary has a confirmed LOLBAS page (format `…/Binaries/<Name>/`):
/// certutil, mshta, wscript, cscript, regsvr32, rundll32, msiexec, bitsadmin,
/// msbuild, installutil, regasm, regsvcs, cmstp, odbcconf, mavinject, ieexec,
/// xwizard, presentationhost, msdeploy, wmic, powershell.
pub const WINDOWS_LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "odbcconf.exe",
    "mavinject.exe",
    "ieexec.exe",
    "xwizard.exe",
    "presentationhost.exe",
    "msdeploy.exe",
    "wmic.exe",
    "powershell.exe",
    "pwsh.exe",
];

/// Linux Living-Off-the-Land binaries.
///
/// Sources:
/// - GTFOBins — curated list of Unix binaries that can bypass local security
///   restrictions; individual pages confirmed at `https://gtfobins.github.io/gtfobins/<binary>/`:
///   <https://gtfobins.github.io/>
/// - MITRE ATT&CK T1059 — Command and Scripting Interpreter:
///   <https://attack.mitre.org/techniques/T1059/>
///
/// All binaries below have confirmed GTFOBins entries.
pub const LINUX_LOLBINS: &[&str] = &[
    "bash", "sh", "python", "python3", "perl", "ruby", "php", "nc", "ncat", "socat", "tclsh",
    "openssl", "curl", "wget", "lua", "awk", "find", "vim", "less", "git", "env", "node", "dd",
    "strace", "gdb", "nmap",
];

/// Returns `true` if `name` matches a known Windows LOLBin (case-insensitive).
pub fn is_windows_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    WINDOWS_LOLBINS
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known Linux LOLBin (case-insensitive).
pub fn is_linux_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LINUX_LOLBINS
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` is a LOLBin on either Windows or Linux (case-insensitive).
///
/// Convenience wrapper that calls [`is_windows_lolbin`] and [`is_linux_lolbin`].
pub fn is_lolbin(name: &str) -> bool {
    is_windows_lolbin(name) || is_linux_lolbin(name) || is_macos_lolbin(name)
}

/// macOS Living-Off-the-Orchard (LOOBins) binaries.
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
pub const MACOS_LOLBINS: &[&str] = &[
    // Execution / scripting
    "osascript",   // AppleScript + JXA execution, credential phishing, lateral movement via RAE
    "osacompile",  // Compile AppleScript to app bundle — persistence payload creation
    "swift",       // Swift REPL / one-liners for system API access
    "tclsh",       // Tcl interpreter — execution without shell
    // Persistence / launch services
    "launchctl",   // Load/unload LaunchAgents and LaunchDaemons — primary macOS persistence vector
    "lsregister",  // Launch Services database manipulation — file association hijacking
    // Credential access
    "security",    // Keychain dump, certificate manipulation, credential extraction
    "dscl",        // Directory Services CLI — user/group enumeration and modification
    "dscacheutil", // DS cache flushing and user enumeration
    "odutil",      // Open Directory utility — directory service inspection
    "dsconfigad",  // Active Directory binding configuration
    "dsexport",    // Export directory records — user/group data exfiltration
    "sysadminctl", // Create/modify local user accounts (privilege escalation vector)
    // Discovery / reconnaissance
    "system_profiler", // Full hardware/software/network inventory
    "networksetup",    // Network interface enumeration, proxy C2 configuration
    "scutil",          // System configuration inspection (hostname, DNS, proxy)
    "sw_vers",         // macOS version fingerprinting
    "sysctl",          // Kernel parameter inspection (memory, CPU, network)
    "ioreg",           // IOKit registry — hardware device enumeration
    "kextstat",        // Kernel extension enumeration — security tool detection
    "profiles",        // MDM/configuration profile enumeration
    "last",            // Login history — user activity reconstruction
    "mdfind",          // Spotlight search — locate files without filesystem walk
    "mdls",            // Spotlight metadata — file attribute inspection
    "defaults",        // Read/write plist preferences — config modification and enumeration
    "plutil",          // Plist manipulation — config file modification
    "sharing",         // File sharing configuration — SMB/AFP exposure
    "systemsetup",     // System preferences modification (remote login, time server)
    // Defense evasion / tampering
    "tccutil",   // TCC database reset — bypass privacy controls (T1548)
    "csrutil",   // SIP status check / disable attempt
    "spctl",     // Gatekeeper bypass assessment
    "codesign",  // Code signature verification / self-signing
    "chflags",   // Set immutable/hidden flags on files — tamper with forensic artifacts
    "xattr",     // Extended attribute manipulation — quarantine flag removal (T1553.001)
    "nvram",     // NVRAM variable read/write — firmware-level persistence
    "sfltool",   // SharedFileList manipulation — login item modification
    // Exfiltration / file operations
    "hdiutil",      // Disk image creation/mount — data staging and exfiltration
    "ditto",        // Copy files preserving metadata — stealthy file staging
    "tmutil",       // Time Machine control — backup manipulation or data recovery
    "screencapture",// Screen capture — data collection (T1113)
    "pbpaste",      // Clipboard access — credential/data collection (T1115)
    "sqlite3",      // SQLite database access — browser/app data exfiltration
    "textutil",     // Document format conversion — data exfiltration staging
    "funzip",       // Unzip from stdin — payload unpacking
    "streamzip",    // Zip streaming — data archiving without GUI
    // Network / C2
    "nscurl",      // NSURLSession-based curl — TLS downloads bypassing some controls
    "tftp",        // TFTP client — data transfer on port 69 (often unmonitored)
    "snmptrap",    // SNMP trap sender — covert C2 over SNMP
    "dns-sd",      // DNS service discovery — network reconnaissance and mDNS C2
    "ssh-keygen",  // Generate/manage SSH keys — persistence via authorized_keys
    "networksetup", // (also C2) Set proxy for all traffic interception
    // Miscellaneous abuse potential
    "open",          // Open URLs/apps — browser redirect, app launch
    "say",           // Text-to-speech — user notification / social engineering
    "caffeinate",    // Prevent sleep — keep C2 beacon alive
    "pkill",         // Kill processes — disable security tools
    "mktemp",        // Create temp files — payload staging
    "notifyutil",    // macOS notification center abuse
    "safaridriver",  // WebDriver automation — browser-based data access
    "GetFileInfo",   // HFS+ metadata inspection
    "SetFile",       // HFS+ metadata modification
    "softwareupdate",// Trigger software updates / enumerate available updates
    "log",           // macOS Unified Log streaming — surveillance and anti-forensics awareness
];

/// Returns `true` if `name` matches a known macOS LOOBin (case-insensitive).
///
/// Matches against the last path component if a full path is given, or the
/// bare binary name. For example, both `"osascript"` and `"/usr/bin/osascript"`
/// return `true`.
pub fn is_macos_lolbin(name: &str) -> bool {
    // Accept either a full path (/usr/bin/osascript) or bare name (osascript)
    let basename = name.rsplit('/').next().unwrap_or(name);
    let lower = basename.to_ascii_lowercase();
    MACOS_LOLBINS
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MACOS_LOLBINS RED tests ───────────────────────────────────────────────
    #[test]
    fn macos_lolbins_is_nonempty() {
        assert!(!MACOS_LOLBINS.is_empty());
    }

    #[test]
    fn macos_lolbins_contains_osascript() {
        assert!(MACOS_LOLBINS.contains(&"osascript"));
    }

    #[test]
    fn macos_lolbins_contains_launchctl() {
        assert!(MACOS_LOLBINS.contains(&"launchctl"));
    }

    #[test]
    fn macos_lolbins_contains_security() {
        assert!(MACOS_LOLBINS.contains(&"security"));
    }

    #[test]
    fn macos_lolbins_contains_sqlite3() {
        assert!(MACOS_LOLBINS.contains(&"sqlite3"));
    }

    #[test]
    fn macos_lolbins_contains_tccutil() {
        assert!(MACOS_LOLBINS.contains(&"tccutil"));
    }

    #[test]
    fn macos_lolbins_contains_networksetup() {
        assert!(MACOS_LOLBINS.contains(&"networksetup"));
    }

    #[test]
    fn detects_osascript_exact() {
        assert!(is_macos_lolbin("osascript"));
    }

    #[test]
    fn detects_osascript_uppercase() {
        assert!(is_macos_lolbin("OSASCRIPT"));
    }

    #[test]
    fn detects_security_mixed_case() {
        assert!(is_macos_lolbin("Security"));
    }

    #[test]
    fn does_not_flag_finder() {
        assert!(!is_macos_lolbin("Finder"));
    }

    #[test]
    fn empty_string_not_macos_lolbin() {
        assert!(!is_macos_lolbin(""));
    }

    #[test]
    fn is_lolbin_detects_macos_osascript() {
        assert!(is_lolbin("osascript"));
    }

    #[test]
    fn is_lolbin_detects_macos_launchctl() {
        assert!(is_lolbin("launchctl"));
    }

    #[test]
    fn windows_lolbins_contains_certutil() {
        assert!(WINDOWS_LOLBINS.contains(&"certutil.exe"));
    }

    #[test]
    fn windows_lolbins_contains_mshta() {
        assert!(WINDOWS_LOLBINS.contains(&"mshta.exe"));
    }

    #[test]
    fn windows_lolbins_contains_powershell() {
        assert!(WINDOWS_LOLBINS.contains(&"powershell.exe"));
    }

    #[test]
    fn linux_lolbins_contains_nc() {
        assert!(LINUX_LOLBINS.contains(&"nc"));
    }

    #[test]
    fn linux_lolbins_contains_python3() {
        assert!(LINUX_LOLBINS.contains(&"python3"));
    }

    #[test]
    fn detects_certutil_exact() {
        assert!(is_windows_lolbin("certutil.exe"));
    }

    #[test]
    fn detects_certutil_uppercase() {
        assert!(is_windows_lolbin("CERTUTIL.EXE"));
    }

    #[test]
    fn detects_mshta_mixed_case() {
        assert!(is_windows_lolbin("Mshta.Exe"));
    }

    #[test]
    fn does_not_flag_notepad() {
        assert!(!is_windows_lolbin("notepad.exe"));
    }

    #[test]
    fn empty_string_not_windows_lolbin() {
        assert!(!is_windows_lolbin(""));
    }

    #[test]
    fn detects_bash() {
        assert!(is_linux_lolbin("bash"));
    }

    #[test]
    fn detects_socat_uppercase() {
        assert!(is_linux_lolbin("SOCAT"));
    }

    #[test]
    fn detects_python3() {
        assert!(is_linux_lolbin("python3"));
    }

    #[test]
    fn does_not_flag_grep() {
        assert!(!is_linux_lolbin("grep"));
    }

    #[test]
    fn empty_string_not_linux_lolbin() {
        assert!(!is_linux_lolbin(""));
    }

    // --- is_lolbin (unified) ---
    #[test]
    fn lolbin_detects_windows_certutil() {
        assert!(is_lolbin("certutil.exe"));
    }
    #[test]
    fn lolbin_detects_linux_nc() {
        assert!(is_lolbin("nc"));
    }
    #[test]
    fn lolbin_detects_powershell() {
        assert!(is_lolbin("powershell.exe"));
    }
    #[test]
    fn lolbin_detects_bash() {
        assert!(is_lolbin("bash"));
    }
    #[test]
    fn lolbin_does_not_flag_notepad() {
        assert!(!is_lolbin("notepad.exe"));
    }
    #[test]
    fn lolbin_does_not_flag_grep() {
        assert!(!is_lolbin("grep"));
    }
    #[test]
    fn lolbin_case_insensitive_windows() {
        assert!(is_lolbin("MSHTA.EXE"));
    }
    #[test]
    fn lolbin_case_insensitive_linux() {
        assert!(is_lolbin("PYTHON3"));
    }
    #[test]
    fn empty_string_not_lolbin() {
        assert!(!is_lolbin(""));
    }
}
