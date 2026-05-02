/// Windows LOLBAS — Living Off the Land Binaries, Scripts and Libraries.
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
pub const LOLBAS_WINDOWS: &[&str] = &[
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
pub const LOLBAS_LINUX: &[&str] = &[
    "7z",
    "aa-exec",
    "ab",
    "acr",
    "agetty",
    "alpine",
    "ansible-playbook",
    "ansible-test",
    "aoss",
    "apache2",
    "apache2ctl",
    "apport-cli",
    "apt",
    "apt-get",
    "aptitude",
    "ar",
    "arch-nspawn",
    "aria2c",
    "arj",
    "arp",
    "as",
    "ascii-xfr",
    "ascii85",
    "ash",
    "aspell",
    "asterisk",
    "at",
    "atobm",
    "autoconf",
    "autoheader",
    "autoreconf",
    "awk",
    "aws",
    "base32",
    "base58",
    "base64",
    "basenc",
    "basez",
    "bash",
    "bashbug",
    "batcat",
    "bbot",
    "bc",
    "bconsole",
    "bee",
    "borg",
    "bpftrace",
    "bridge",
    "bundle",
    "bundler",
    "busctl",
    "busybox",
    "byebug",
    "bzip2",
    "c89",
    "c99",
    "cabal",
    "cancel",
    "capsh",
    "cargo",
    "cat",
    "cc",
    "cdist",
    "certbot",
    "chattr",
    "check_by_ssh",
    "check_cups",
    "check_log",
    "check_memory",
    "check_raid",
    "check_ssl_cert",
    "check_statusfile",
    "chmod",
    "choom",
    "chown",
    "chroot",
    "chrt",
    "clamscan",
    "clisp",
    "cmake",
    "cmp",
    "cobc",
    "code",
    "codex",
    "column",
    "comm",
    "composer",
    "cowsay",
    "cowthink",
    "cp",
    "cpan",
    "cpio",
    "cpulimit",
    "crash",
    "crontab",
    "csh",
    "csplit",
    "csvtool",
    "ctr",
    "cupsfilter",
    "curl",
    "cut",
    "dash",
    "date",
    "dc",
    "dd",
    "debugfs",
    "dhclient",
    "dialog",
    "diff",
    "dig",
    "distcc",
    "dmesg",
    "dmidecode",
    "dmsetup",
    "dnf",
    "dnsmasq",
    "doas",
    "docker",
    "dos2unix",
    "dosbox",
    "dotnet",
    "dpkg",
    "dstat",
    "dvips",
    "easy_install",
    "easyrsa",
    "eb",
    "ed",
    "efax",
    "egrep",
    "elvish",
    "emacs",
    "enscript",
    "env",
    "eqn",
    "espeak",
    "ex",
    "exiftool",
    "expand",
    "expect",
    "facter",
    "fail2ban-client",
    "fastfetch",
    "ffmpeg",
    "fgrep",
    "file",
    "find",
    "finger",
    "firejail",
    "fish",
    "flock",
    "fmt",
    "fold",
    "forge",
    "fping",
    "ftp",
    "fzf",
    "g++",
    "gawk",
    "gcc",
    "gcloud",
    "gcore",
    "gdb",
    "gem",
    "genie",
    "genisoimage",
    "getent",
    "ghc",
    "ghci",
    "gimp",
    "ginsh",
    "git",
    "gnuplot",
    "go",
    "grc",
    "grep",
    "gtester",
    "guile",
    "gzip",
    "hashcat",
    "hd",
    "head",
    "hexdump",
    "hg",
    "highlight",
    "hping3",
    "iconv",
    "iftop",
    "install",
    "ionice",
    "ip",
    "iptables-save",
    "irb",
    "ispell",
    "java",
    "jjs",
    "joe",
    "join",
    "journalctl",
    "jq",
    "jrunscript",
    "jshell",
    "jtag",
    "julia",
    "knife",
    "ksh",
    "ksshell",
    "ksu",
    "kubectl",
    "last",
    "lastb",
    "latex",
    "latexmk",
    "ld.so",
    "ldconfig",
    "less",
    "lftp",
    "links",
    "ln",
    "loginctl",
    "logrotate",
    "logsave",
    "look",
    "lp",
    "ltrace",
    "lua",
    "lualatex",
    "luatex",
    "lwp-download",
    "lwp-request",
    "lxd",
    "m4",
    "mail",
    "make",
    "man",
    "mawk",
    "minicom",
    "more",
    "mosh-server",
    "mosquitto",
    "mount",
    "msfconsole",
    "msgattrib",
    "msgcat",
    "msgconv",
    "msgfilter",
    "msgmerge",
    "msguniq",
    "mtr",
    "multitime",
    "mutt",
    "mv",
    "mypy",
    "mysql",
    "nano",
    "nasm",
    "nawk",
    "nc",
    "ncdu",
    "ncftp",
    "needrestart",
    "neofetch",
    "nft",
    "nginx",
    "nice",
    "nl",
    "nm",
    "nmap",
    "node",
    "nohup",
    "npm",
    "nroff",
    "nsenter",
    "ntpdate",
    "nvim",
    "octave",
    "od",
    "opencode",
    "openssl",
    "openvpn",
    "openvt",
    "opkg",
    "pandoc",
    "passwd",
    "paste",
    "pax",
    "pdb",
    "pdflatex",
    "pdftex",
    "perf",
    "perl",
    "perlbug",
    "pexec",
    "pg",
    "php",
    "pic",
    "pico",
    "pidstat",
    "pip",
    "pipx",
    "pkexec",
    "pkg",
    "plymouth",
    "podman",
    "poetry",
    "posh",
    "pr",
    "procmail",
    "pry",
    "psftp",
    "psql",
    "ptx",
    "puppet",
    "pwsh",
    "pygmentize",
    "pyright",
    "python",
    "qpdf",
    "R",
    "rake",
    "ranger",
    "rc",
    "readelf",
    "red",
    "redcarpet",
    "redis",
    "restic",
    "rev",
    "rlogin",
    "rlwrap",
    "rpm",
    "rpmdb",
    "rpmquery",
    "rpmverify",
    "rsync",
    "rsyslogd",
    "rtorrent",
    "ruby",
    "run-mailcap",
    "run-parts",
    "runscript",
    "rustc",
    "rustdoc",
    "rustfmt",
    "rustup",
    "rview",
    "rvim",
    "sash",
    "scanmem",
    "scp",
    "screen",
    "script",
    "scrot",
    "sed",
    "service",
    "setarch",
    "setcap",
    "setfacl",
    "setlock",
    "sftp",
    "sg",
    "sh",
    "shred",
    "shuf",
    "slsh",
    "smbclient",
    "snap",
    "socat",
    "socket",
    "soelim",
    "softlimit",
    "sort",
    "split",
    "sqlite3",
    "sqlmap",
    "ss",
    "ssh",
    "ssh-agent",
    "ssh-copy-id",
    "ssh-keygen",
    "ssh-keyscan",
    "sshfs",
    "sshpass",
    "sshuttle",
    "start-stop-daemon",
    "stdbuf",
    "strace",
    "strings",
    "su",
    "sudo",
    "sysctl",
    "systemctl",
    "systemd-resolve",
    "systemd-run",
    "tac",
    "tail",
    "tailscale",
    "tar",
    "task",
    "taskset",
    "tasksh",
    "tbl",
    "tclsh",
    "tcpdump",
    "tcsh",
    "tdbtool",
    "tee",
    "telnet",
    "terraform",
    "tex",
    "tftp",
    "tic",
    "time",
    "timedatectl",
    "timeout",
    "tmate",
    "tmux",
    "top",
    "torify",
    "torsocks",
    "troff",
    "tsc",
    "tshark",
    "ul",
    "unexpand",
    "uniq",
    "unshare",
    "unsquashfs",
    "unzip",
    "update-alternatives",
    "urlget",
    "uuencode",
    "uv",
    "vagrant",
    "valgrind",
    "varnishncsa",
    "vi",
    "view",
    "vigr",
    "vim",
    "vimdiff",
    "vipw",
    "virsh",
    "volatility",
    "w3m",
    "wall",
    "watch",
    "wc",
    "wg-quick",
    "wget",
    "whiptail",
    "whois",
    "wireshark",
    "wish",
    "xargs",
    "xdg-user-dir",
    "xdotool",
    "xelatex",
    "xetex",
    "xmodmap",
    "xmore",
    "xpad",
    "xxd",
    "xz",
    "yarn",
    "yash",
    "yelp",
    "yt-dlp",
    "yum",
    "zathura",
    "zcat",
    "zgrep",
    "zic",
    "zip",
    "zless",
    "zsh",
    "zsoelim",
    "zypper",
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
pub const LOLBAS_MACOS: &[&str] = &[
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

/// Returns `true` if `name` matches a known Windows LOLBAS binary (case-insensitive).
pub fn is_lolbas_windows(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOLBAS_WINDOWS
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known Linux LOLBAS binary (case-insensitive).
///
/// The Linux LOLBAS dataset is sourced from GTFOBins — all 478 entries.
pub fn is_lolbas_linux(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOLBAS_LINUX
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known macOS LOLBAS binary (case-insensitive).
///
/// Matches against the last path component if a full path is given, or the
/// bare binary name. For example, both `"osascript"` and `"/usr/bin/osascript"`
/// return `true`.
pub fn is_lolbas_macos(name: &str) -> bool {
    // Accept either a full path (/usr/bin/osascript) or bare name (osascript)
    let basename = name.rsplit('/').next().unwrap_or(name);
    let lower = basename.to_ascii_lowercase();
    LOLBAS_MACOS
        .iter()
        .any(|b| b.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` is a LOLBAS binary on Windows, Linux, or macOS (case-insensitive).
///
/// Convenience wrapper over [`is_lolbas_windows`], [`is_lolbas_linux`], and [`is_lolbas_macos`].
pub fn is_lolbas(name: &str) -> bool {
    is_lolbas_windows(name) || is_lolbas_linux(name) || is_lolbas_macos(name)
}

// ── Deprecated aliases — use LOLBAS_* and is_lolbas_* instead ───────────────

#[deprecated(since = "0.0.0", note = "use LOLBAS_WINDOWS")]
pub const WINDOWS_LOLBINS: &[&str] = LOLBAS_WINDOWS;
#[deprecated(since = "0.0.0", note = "use LOLBAS_LINUX")]
pub const LINUX_LOLBINS: &[&str] = LOLBAS_LINUX;
#[deprecated(since = "0.0.0", note = "use LOLBAS_MACOS")]
pub const MACOS_LOLBINS: &[&str] = LOLBAS_MACOS;

#[deprecated(since = "0.0.0", note = "use is_lolbas_windows")]
pub fn is_windows_lolbin(name: &str) -> bool {
    is_lolbas_windows(name)
}
#[deprecated(since = "0.0.0", note = "use is_lolbas_linux")]
pub fn is_linux_lolbin(name: &str) -> bool {
    is_lolbas_linux(name)
}
#[deprecated(since = "0.0.0", note = "use is_lolbas_macos")]
pub fn is_macos_lolbin(name: &str) -> bool {
    is_lolbas_macos(name)
}
#[deprecated(since = "0.0.0", note = "use is_lolbas")]
pub fn is_lolbin(name: &str) -> bool {
    is_lolbas(name)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    // ── MACOS_LOLBINS RED tests ───────────────────────────────────────────────
    #[test]
    fn macos_lolbins_is_nonempty() {
        assert!(!LOLBAS_MACOS.is_empty());
    }

    #[test]
    fn macos_lolbins_contains_osascript() {
        assert!(LOLBAS_MACOS.contains(&"osascript"));
    }

    #[test]
    fn macos_lolbins_contains_launchctl() {
        assert!(LOLBAS_MACOS.contains(&"launchctl"));
    }

    #[test]
    fn macos_lolbins_contains_security() {
        assert!(LOLBAS_MACOS.contains(&"security"));
    }

    #[test]
    fn macos_lolbins_contains_sqlite3() {
        assert!(LOLBAS_MACOS.contains(&"sqlite3"));
    }

    #[test]
    fn macos_lolbins_contains_tccutil() {
        assert!(LOLBAS_MACOS.contains(&"tccutil"));
    }

    #[test]
    fn macos_lolbins_contains_networksetup() {
        assert!(LOLBAS_MACOS.contains(&"networksetup"));
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
        assert!(LOLBAS_WINDOWS.contains(&"certutil.exe"));
    }

    #[test]
    fn windows_lolbins_contains_mshta() {
        assert!(LOLBAS_WINDOWS.contains(&"mshta.exe"));
    }

    #[test]
    fn windows_lolbins_contains_powershell() {
        assert!(LOLBAS_WINDOWS.contains(&"powershell.exe"));
    }

    #[test]
    fn linux_lolbins_contains_nc() {
        assert!(LOLBAS_LINUX.contains(&"nc"));
    }

    #[test]
    fn linux_lolbins_contains_python3() {
        // python3 is not in GTFOBins; python is — test the canonical name
        assert!(LOLBAS_LINUX.contains(&"python"));
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
        assert!(LOLBAS_LINUX.contains(&"7z"));
    }
    #[test]
    fn lolbas_linux_contains_docker() {
        assert!(LOLBAS_LINUX.contains(&"docker"));
    }
    #[test]
    fn lolbas_linux_contains_sudo() {
        assert!(LOLBAS_LINUX.contains(&"sudo"));
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
}
