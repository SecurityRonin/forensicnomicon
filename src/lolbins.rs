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
    is_windows_lolbin(name) || is_linux_lolbin(name)
}

#[cfg(test)]
mod tests {
    use super::*;

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
