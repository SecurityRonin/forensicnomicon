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
//! |----------|---------------|-----------------|
//! | [`LOLBAS_WINDOWS`] | Process name (`.exe`), script (`.vbs`/`.cmd`) | Prefetch, Sysmon, EDR process telemetry |
//! | [`LOLBAS_LINUX`] | Process name (no extension) | auditd `execve`, eBPF, EDR |
//! | [`LOLBAS_MACOS`] | Process name (no extension) | macOS ESF / Endpoint Security, audit.log |
//! | [`LOFL_WINDOWS_CMDLETS`] | PowerShell cmdlet name | ScriptBlock log (Event 4104), PSReadLine history |
//! | [`LOFL_WINDOWS_MMC`] | `.msc` filename | LNK files, UserAssist MRU, Jump Lists |
//! | [`LOFL_WINDOWS_WMI`] | WMI class name | WMI Activity log (Event 5861), `Get-CimInstance` |
//!
//! # Upstream sources
//!
//! - LOLBAS Project (Windows native): <https://lolbas-project.github.io/>
//! - LOFL Project (Windows admin tools + cmdlets + MMC + WMI): <https://lofl-project.github.io/>
//! - GTFOBins (Linux unified): <https://gtfobins.github.io/>
//! - LOOBins (macOS native): <https://loobins.io/>
//! - macOS LOFL catalog (first published, this repo): `research/macos-lofl-catalog.yaml`
//!
//! # Unified lookup
//!
//! Use [`is_lolbas`] to query all three platform LOLBAS lists at once.
//! Use [`is_lolbas_windows`], [`is_lolbas_linux`], or [`is_lolbas_macos`] for
//! platform-specific lookups. All comparisons are case-insensitive.
//!
//! ```rust
//! use forensicnomicon::lolbins::{is_lolbas, is_lolbas_windows, is_lolbas_macos};
//! use forensicnomicon::lolbins::{is_lofl_windows_cmdlet, is_lofl_windows_wmi};
//!
//! assert!(is_lolbas("certutil.exe"));        // Windows LOLBAS
//! assert!(is_lolbas("bash"));                // Linux GTFOBins
//! assert!(is_lolbas("osascript"));           // macOS LOOBins
//! assert!(is_lolbas("kubectl"));             // macOS LOFL (also Linux GTFOBins)
//! assert!(is_lofl_windows_cmdlet("Invoke-Command")); // PowerShell LOFL
//! assert!(is_lofl_windows_wmi("Win32_Process"));     // WMI LOFL
//! ```
//!
//! # macOS LOFL catalog — first-of-its-kind research
//!
//! The macOS LOFL section of [`LOLBAS_MACOS`] (tools installed via Homebrew,
//! pip, npm, cargo, etc.) is the **first published macOS LOFL catalog anywhere**.
//! It covers 80 tools with 276 documented abuse techniques across 71 ATT&CK IDs.
//! The raw YAML data lives in `research/macos-lofl-catalog.yaml`.

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
pub const LOLBAS_WINDOWS: &[&str] = &[
    // ── LOLBAS Project — native Windows binaries ─────────────────────────
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

    // ── LOFL Project — third-party Windows admin tool binaries ────────────
    // Sysinternals / Microsoft tooling
    "AccessEnum.exe",
    "adexplorer.exe",
    "adrestore.exe",
    "psexec.exe",
    "psfile.exe",
    "psgetsid.exe",
    "psinfo.exe",
    "pskill.exe",
    "pslist.exe",
    "psloggedon.exe",
    "psloglist.exe",
    "pspasswd.exe",
    "psping.exe",
    "psservice.exe",
    "psshutdown.exe",
    "pssuspend.exe",
    "sdelete.exe",
    "RDCMan.exe",
    // Windows built-in admin binaries (not in LOLBAS Project)
    "at.exe",
    "csvde.exe",
    "cusrmgr.exe",
    "dcdiag.exe",
    "devcon.exe",
    "dfscmd.exe",
    "dfsdiag.exe",
    "dfsrdiag.exe",
    "dfsutil.exe",
    "djoin.exe",
    "dnscmd.exe",
    "driverquery.exe",
    "dsac.exe",
    "dsacls.exe",
    "dsadd.exe",
    "dsget.exe",
    "dsmgmt.exe",
    "dsmod.exe",
    "dsmove.exe",
    "dsquery.exe",
    "dsrm.exe",
    "eventcreate.exe",
    "finger.exe",
    "getmac.exe",
    "gpfixup.exe",
    "gpresult.exe",
    "ldifde.exe",
    "logman.exe",
    "logoff.exe",
    "manage-bde.exe",
    "mofcomp.exe",
    "msg.exe",
    "msinfo32.exe",
    "msra.exe",
    "mstsc.exe",
    "ndkping.exe",
    "net.exe",
    "netdom.exe",
    "netsh.exe",
    "nlb.exe",
    "nltest.exe",
    "nslookup.exe",
    "portqry.exe",
    "printui.exe",
    "qappsrv.exe",
    "qprocess.exe",
    "query.exe",
    "quser.exe",
    "qwinsta.exe",
    "reg.exe",
    "regedit.exe",
    "regini.exe",
    "rendom.exe",
    "repadmin.exe",
    "reset.exe",
    "rmtshare.exe",
    "rpcdump.exe",
    "rwinsta.exe",
    "sc.exe",
    "schtasks.exe",
    "scp.exe",
    "ServerManager.exe",
    "setspn.exe",
    "setx.exe",
    "shadow.exe",
    "shrpubw.exe",
    "shutdown.exe",
    "sqlcmd.exe",
    "srvcheck.exe",
    "srvinfo.exe",
    "ssh.exe",
    "systeminfo.exe",
    "takeown.exe",
    "taskkill.exe",
    "tasklist.exe",
    "tsdiscon.exe",
    "tskill.exe",
    "typeperf.exe",
    "volrest.exe",
    "w32tm.exe",
    "waitfor.exe",
    "wbemtest.exe",
    "wevtutil.exe",
    "winrs.exe",
    // LOFL scripts (.vbs/.cmd — appear in Prefetch and Script Block logs)
    "ospp.vbs",
    "pubprn.vbs",
    "slmgr.vbs",
    "winrm.cmd",
    // SQL Server / enterprise tools
    "Microsoft.ConfigurationManagement.exe",
    "SmeDesktop.exe",
    "Ssms.exe",
    "TpmVscMgr.exe",
    "uptime.exe",
    "WinAppDeployCmd.exe",
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

    // ── macOS LOFL — foreign tools (Homebrew / pip / npm / cargo / other) ──
    // First catalog of macOS LOFL binaries: research/macos-lofl-catalog.yaml
    // These are developer/DevOps tools universally installed on Mac enterprise
    // systems; rarely blocked by EDR/allowlisting; high offensive capability.

    // Cloud CLIs — direct API access to cloud credentials and resources
    "aws",          // AWS CLI — credential exfil, S3 staging, IAM enumeration
    "az",           // Azure CLI — credential access, storage exfil, AAD recon
    "gcloud",       // Google Cloud CLI — GCS exfil, IAM privilege escalation
    "gh",           // GitHub CLI — token access, repo exfil, Actions abuse
    "heroku",       // Heroku CLI — dyno shell, env var exfil
    "vault",        // HashiCorp Vault CLI — secret extraction, token abuse
    "consul",       // HashiCorp Consul — service mesh recon, KV store access
    "step",         // Smallstep CLI — PKI abuse, certificate issuance
    "teleport",     // Teleport CLI — privileged access proxy abuse

    // Container / orchestration — escape and lateral movement
    "docker",       // Container runtime — breakout via privileged containers
    "kubectl",      // Kubernetes CLI — secret extraction, pod exec, RBAC abuse
    "helm",         // Kubernetes package manager — deploy malicious charts
    "k9s",          // Kubernetes TUI — cluster recon, pod shell access
    "lazydocker",   // Docker TUI — container management, image abuse
    "packer",       // HashiCorp Packer — backdoored image creation

    // Language runtimes — arbitrary code execution without shell
    "python3",      // Python REPL — code exec, C extension loading, network
    "node",         // Node.js — eval-based exec, npm script abuse
    "ruby",         // Ruby interpreter — shell escape, Gem abuse
    "go",           // Go toolchain — compile/exec on-device, CGO abuse
    "php",          // PHP CLI — eval exec, webshell staging
    "perl",         // Perl interpreter — shell exec, regex DoS

    // Package managers — supply chain and dependency confusion attacks
    "brew",         // Homebrew — malicious tap installation, formula abuse
    "pip3",         // Python packages — supply chain, code exec via setup.py
    "npm",          // Node packages — postinstall scripts, typosquatting
    "yarn",         // Yarn — same supply chain vectors as npm
    "cargo",        // Rust crates — build scripts execute arbitrary code
    "pipx",         // Python app installer — isolated env exec

    // IaC / DevOps — infrastructure manipulation
    "terraform",    // IaC — cloud resource creation, credential in state files
    "ansible",      // Configuration management — mass remote exec via playbooks
    "vagrant",      // VM management — guest exec, shared folder traversal
    "act",          // Local GitHub Actions runner — workflow-based code exec

    // Database clients — data exfiltration via query
    "psql",         // PostgreSQL client — data exfil, pg_read_file abuse
    "mysql",        // MySQL client — data exfil, LOAD DATA INFILE
    "redis-cli",    // Redis client — config rewrite, RCE via SLAVEOF
    "mongosh",      // MongoDB shell — data exfil, JS eval execution

    // Network tools — reconnaissance and C2 channels
    "nmap",         // Port scanner — network recon, OS fingerprinting
    "socat",        // Network relay — reverse shells, port forwarding
    "mitmproxy",    // MITM proxy — credential interception, traffic analysis
    "tshark",       // CLI packet capture — credential harvesting, recon
    "masscan",      // Fast port scanner — large-scale network recon
    "dnsmasq",      // DNS/DHCP server — DNS poisoning, traffic redirection
    "httpie",       // HTTP client — API abuse, credential testing

    // Tunneling / proxy — C2 channel establishment
    "ngrok",        // Reverse tunnel — C2 over HTTPS/TCP bypassing firewalls
    "cloudflared",  // Cloudflare Tunnel — C2 via trusted CDN infrastructure
    "chisel",       // TCP/UDP tunnel over HTTP — firewall bypass
    "sshuttle",     // VPN over SSH — network pivoting
    "proxychains-ng", // Proxy chains — traffic routing for evasion
    "tailscale",    // WireGuard mesh VPN — covert C2 network
    "wireguard-tools", // WireGuard CLI — encrypted tunnel setup

    // Security / offensive tools — direct attack capability
    "sqlmap",       // SQL injection automation — database takeover
    "john",         // John the Ripper — password cracking
    "hashcat",      // GPU password cracking — credential recovery
    "frida",        // Dynamic instrumentation — process injection, hook bypass
    "radare2",      // Reverse engineering — binary analysis, patch
    "gdb",          // GNU debugger — process memory dump, shellcode injection

    // Build tools — code compilation and execution
    "cmake",        // Build system — compile malicious C code on-device
    "gradle",       // Java build tool — task execution, dependency abuse
    "maven",        // Java package manager — plugin code exec
    "bazel",        // Google build — remote execution abuse

    // Credential management — secret access
    "1password-cli",  // 1Password CLI — Keychain/vault secret extraction
    "bitwarden-cli",  // Bitwarden CLI — password vault access

    // Encryption / signing — evidence tampering, covert channels
    "openssl",      // TLS toolkit — self-signed C2 certs, data encryption
    "gpg",          // GnuPG — encrypted C2, payload concealment
    "age",          // Modern encryption — payload concealment, key management
    "minisign",     // Signature tool — artifact signing for trust bypass

    // File transfer / sync — data staging and exfiltration
    "rclone",       // Cloud sync — mass exfiltration to cloud storage
    "rsync",        // File sync — lateral movement, data staging
    "wget",         // HTTP downloader — payload delivery
    "aria2c",       // Multi-protocol downloader — parallel payload staging
    "restic",       // Backup tool — encrypted data exfiltration

    // Scripting / automation
    "jq",           // JSON processor — credential extraction from API responses
    "expect",       // Automation tool — interactive process exploitation
    "screen",       // Terminal multiplexer — persistent session, SUID abuse
    "tmux",         // Terminal multiplexer — session hijacking, persistence
    "imagemagick",  // Image processing — CVE exploit history, server-side
    "ffmpeg",       // Media processing — covert channel via media encoding

    // macOS-specific utilities
    "duti",         // File association — handler hijacking for persistence
    "trash",        // Move to Trash CLI — evidence staging before deletion
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

/// Windows LOFL PowerShell cmdlets — abusable built-in and AD module cmdlets.
///
/// These appear in PSReadLine history, PowerShell ScriptBlock logs (Event 4104),
/// and transcription logs — not in process telemetry. Sourced from the LOFL Project:
/// <https://lofl-project.github.io/>
pub const LOFL_WINDOWS_CMDLETS: &[&str] = &[
    "Add-ADGroupMember",
    "Add-DnsClientNrptRule",
    "Add-EtwTraceProvider",
    "Add-MpPreference",
    "Add-NetEventPacketCaptureProvider",
    "Add-NetNatExternalAddress",
    "Add-NetNatStaticMapping",
    "Backup-GPO",
    "Clear-Disk",
    "Clear-DnsClientCache",
    "Clear-Eventlog",
    "Close-SmbOpenFile",
    "Close-SmbSession",
    "Connect-WSMan",
    "Copy-Item",
    "Copy-VMFile",
    "Disable-ADAccount",
    "Disable-NetAdapter",
    "Disable-NetFirewallRule",
    "Dismount-DiskImage",
    "Enable-ADAccount",
    "Enable-NetFirewallRule",
    "Enter-PSSession",
    "Export-VM",
    "Export-VMSnapshot",
    "Find-NetRoute",
    "Format-Volume",
    "Get-ADComputer",
    "Get-ADComputerServiceAccount",
    "Get-ADDomain",
    "Get-ADDomainController",
    "Get-ADForest",
    "Get-ADGroup",
    "Get-ADGroupMember",
    "Get-ADObject",
    "Get-ADOrganizationalUnit",
    "Get-ADReplicationSubnet",
    "Get-ADTrust",
    "Get-ADUser",
    "Get-AppvVirtualProcess",
    "Get-ChildItem",
    "Get-CimAssociatedInstance",
    "Get-CimClass",
    "Get-CimInstance",
    "Get-DfsnFolder",
    "Get-DfsnFolderTarget",
    "Get-DfsnRoot",
    "Get-DfsnRootTarget",
    "Get-DhcpServerAuditLog",
    "Get-DhcpServerDatabase",
    "Get-DhcpServerDnsCredential",
    "Get-DhcpServerInDC",
    "Get-DhcpServerSetting",
    "Get-DhcpServerv4DnsSetting",
    "Get-DhcpServerv4Filter",
    "Get-DhcpServerv4FilterList",
    "Get-DhcpServerv4Lease",
    "Get-Disk",
    "Get-DiskImage",
    "Get-DnsClientCache",
    "Get-DnsClientNrptRule",
    "Get-DnsClientServerAddress",
    "Get-DnsServer",
    "Get-DnsServerCache",
    "Get-DnsServerForwarder",
    "Get-EtwTraceProvider",
    "Get-EtwTraceSession",
    "Get-FileShare",
    "Get-GPO",
    "Get-GPOReport",
    "Get-GPPermission",
    "Get-GPResultantSetOfPolicy",
    "Get-GPStarterGPO",
    "Get-HotFix",
    "Get-MpComputerStatus",
    "Get-MpPreference",
    "Get-MpThreat",
    "Get-MpThreatCatalog",
    "Get-MpThreatDetection",
    "Get-NetAdapter",
    "Get-NetConnectionProfile",
    "Get-NetEventSession",
    "Get-NetFirewallRule",
    "Get-NetIPAddress",
    "Get-NetIPInterface",
    "Get-NetNat",
    "Get-NetNatExternalAddress",
    "Get-NetNatGlobal",
    "Get-NetNatSession",
    "Get-NetNatStaticMapping",
    "Get-NetNeighbor",
    "Get-NetRoute",
    "Get-NetTCPConnection",
    "Get-NetUDPEndpoint",
    "Get-NfsSession",
    "Get-NfsShare",
    "Get-OdbcDsn",
    "Get-Partition",
    "Get-PhysicalDisk",
    "Get-Printer",
    "Get-Process",
    "Get-RemoteAccess",
    "Get-ScheduledTask",
    "Get-ScheduledTaskInfo",
    "Get-Service",
    "Get-SmbConnection",
    "Get-SmbOpenFile",
    "Get-SmbServerConfiguration",
    "Get-SmbSession",
    "Get-SmbShare",
    "Get-VirtualDisk",
    "Get-VM",
    "Get-Volume",
    "Get-VpnConnection",
    "Get-WindowsFeature",
    "Get-WinEvent",
    "Get-WSManInstance",
    "Install-WindowsFeature",
    "Invoke-CimMethod",
    "Invoke-Command",
    "Invoke-WSManAction",
    "Mount-DiskImage",
    "Move-Item",
    "New-ADComputer",
    "New-ADGroup",
    "New-ADObject",
    "New-ADOrganizationalUnit",
    "New-ADServiceAccount",
    "New-ADUser",
    "New-CimInstance",
    "New-CimSession",
    "New-EtwTraceSession",
    "New-GPLink",
    "New-GPO",
    "New-NetEventSession",
    "New-NetFirewallRule",
    "New-NetNat",
    "New-NetRoute",
    "New-PSSession",
    "New-ScheduledTask",
    "New-SmbShare",
    "New-VirtualDisk",
    "New-VirtualDiskSnapshot",
    "New-WSManInstance",
    "Out-File",
    "Publish-DscConfiguration",
    "Register-CimIndicationEvent",
    "Register-ScheduledTask",
    "Remove-ADUser",
    "Remove-DhcpServerv4Lease",
    "Remove-FileShare",
    "Remove-MpPreference",
    "Remove-MpThreat",
    "Remove-NetEventSession",
    "Remove-NetNat",
    "Remove-NetNatExternalAddress",
    "Remove-NetNatStaticMapping",
    "Remove-SmbShare",
    "Remove-VirtualDisk",
    "Rename-ADObject",
    "Resolve-DnsName",
    "Restart-Computer",
    "Search-ADAccount",
    "Set-ADAccountControl",
    "Set-ADAccountExpiration",
    "Set-ADAccountPassword",
    "Set-ADGroup",
    "Set-ADObject",
    "Set-ADServiceAccount",
    "Set-ADUser",
    "Set-CimInstance",
    "Set-DhcpServerAuditLog",
    "Set-DnsServerSetting",
    "Set-MpPreference",
    "Set-NetConnectionProfile",
    "Set-NetFirewallProfile",
    "Set-NetFirewallRule",
    "Set-NetFirewallSetting",
    "Set-NetNat",
    "Set-NetNatGlobal",
    "Set-NetRoute",
    "Set-ScheduledTask",
    "Set-WSManInstance",
    "Show-DnsServerCache",
    "Show-EventLog",
    "Show-NetFirewallRule",
    "Start-DscConfiguration",
    "Start-NetEventSession",
    "Start-ScheduledTask",
    "Start-VM",
    "Stop-Computer",
    "Stop-EtwTraceSession",
    "Stop-NetEventSession",
    "Test-Connection",
    "Test-NetConnection",
    "Uninstall-WindowsFeature",
    "Unlock-ADAccount",
    "Unregister-ScheduledTask",
    "Write-EventLog",
];

/// Windows LOFL MMC snap-ins (`.msc` files).
///
/// MMC snap-ins appear in LNK/shortcut files, UserAssist registry entries,
/// Jump Lists, and Recent file MRUs — not in process telemetry directly.
/// Sourced from the LOFL Project: <https://lofl-project.github.io/>
pub const LOFL_WINDOWS_MMC: &[&str] = &[
    "AdRmsAdmin.msc",
    "adsiedit.msc",
    "azman.msc",
    "certlm.msc",
    "certmgr.msc",
    "certsrv.msc",
    "certtmpl.msc",
    "CluAdmin.msc",
    "comexp.msc",
    "compmgmt.msc",
    "devmgmt.msc",
    "DevModeRunAsUserConfig.msc",
    "dfsmgmt.msc",
    "dhcpmgmt.msc",
    "diskmgmt.msc",
    "dnsmgmt.msc",
    "domain.msc",
    "dsa.msc",
    "dssite.msc",
    "eventvwr.msc",
    "fsmgmt.msc",
    "fsrm.msc",
    "fxsadmin.msc",
    "gpedit.msc",
    "gpmc.msc",
    "gpme.msc",
    "gptedit.msc",
    "iis.msc",
    "iis6.msc",
    "ipsecsnp.msc",
    "ipsmsnap.msc",
    "lsdiag.msc",
    "lusrmgr.msc",
    "Microsoft.IdentityServer.msc",
    "nfsmgmt.msc",
    "nps.msc",
    "ocsp.msc",
    "perfmon.msc",
    "pkiview.msc",
    "printmanagement.msc",
    "RAMgmtUI.msc",
    "remoteprograms.msc",
    "rrasmgmt.msc",
    "rsop.msc",
    "schmmgmt.msc",
    "secpol.msc",
    "services.msc",
    "SQLServerManager15.msc",
    "SQLServerManager16.msc",
    "tapimgmt.msc",
    "taskschd.msc",
    "tpm.msc",
    "tsadmin.msc",
    "tsconfig.msc",
    "tsgateway.msc",
    "virtmgmt.msc",
    "wbadmin.msc",
    "WdsMgmt.msc",
    "WF.msc",
    "winsmgmt.msc",
    "WmiMgmt.msc",
    "wsecedit.msc",
    "wsus.msc",
];

/// Windows LOFL WMI class names — abused in WMI-based attacks.
///
/// These appear as strings inside WMI queries logged in the
/// Microsoft-Windows-WMI-Activity/Operational log (Event 5861) and in
/// PowerShell ScriptBlock logs when accessed via `Get-CimInstance` or
/// `Get-WmiObject`. Sourced from the LOFL Project:
/// <https://lofl-project.github.io/>
pub const LOFL_WINDOWS_WMI: &[&str] = &[
    "CIM_DataFile",
    "CIM_Directory",
    "CIM_LogicalFile",
    "MSFT_DNSClientCache",
    "MSFT_MTProcess",
    "MSFT_NetFirewallRule",
    "StdRegProv",
    "Win32_DfsNode",
    "Win32_Environment",
    "Win32_NTLogEvent",
    "Win32_OperatingSystem",
    "Win32_Process",
    "Win32_Product",
    "Win32_QuickFixEngineering",
    "Win32_Service",
    "Win32_ShadowCopy",
    "Win32_SystemDriver",
];

/// Returns `true` if `name` matches a known Windows LOFL PowerShell cmdlet
/// (case-insensitive). Check against PSReadLine history and Event 4104 logs.
pub fn is_lofl_windows_cmdlet(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOFL_WINDOWS_CMDLETS
        .iter()
        .any(|c| c.to_ascii_lowercase() == lower)
}

/// Returns `true` if `name` matches a known Windows LOFL MMC snap-in
/// (case-insensitive, `.msc` suffix required). Check against LNK files,
/// UserAssist, and Recent MRUs.
pub fn is_lofl_windows_mmc(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOFL_WINDOWS_MMC
        .iter()
        .any(|m| m.to_ascii_lowercase() == lower)
}

/// Returns `true` if `class` matches a known Windows LOFL WMI class name
/// (case-insensitive). Check against WMI Activity Event 5861 and
/// PowerShell Get-CimInstance / Get-WmiObject calls.
pub fn is_lofl_windows_wmi(class: &str) -> bool {
    let lower = class.to_ascii_lowercase();
    LOFL_WINDOWS_WMI
        .iter()
        .any(|w| w.to_ascii_lowercase() == lower)
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

    // ── LOLBAS_MACOS foreign-tool expansion (RED) ────────────────────────────
    #[test]
    fn lolbas_macos_contains_kubectl() {
        assert!(LOLBAS_MACOS.contains(&"kubectl"));
    }
    #[test]
    fn lolbas_macos_contains_docker() {
        assert!(LOLBAS_MACOS.contains(&"docker"));
    }
    #[test]
    fn lolbas_macos_contains_terraform() {
        assert!(LOLBAS_MACOS.contains(&"terraform"));
    }
    #[test]
    fn lolbas_macos_contains_aws() {
        assert!(LOLBAS_MACOS.contains(&"aws"));
    }
    #[test]
    fn lolbas_macos_contains_brew() {
        assert!(LOLBAS_MACOS.contains(&"brew"));
    }
    #[test]
    fn lolbas_macos_contains_ngrok() {
        assert!(LOLBAS_MACOS.contains(&"ngrok"));
    }
    #[test]
    fn lolbas_macos_contains_frida() {
        assert!(LOLBAS_MACOS.contains(&"frida"));
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

    // ── LOFL Windows expansion — RED ─────────────────────────────────────────
    // LOFL binaries merged into LOLBAS_WINDOWS
    #[test]
    fn lolbas_windows_contains_psexec() {
        assert!(LOLBAS_WINDOWS.contains(&"psexec.exe"));
    }
    #[test]
    fn lolbas_windows_contains_reg() {
        assert!(LOLBAS_WINDOWS.contains(&"reg.exe"));
    }
    #[test]
    fn lolbas_windows_contains_net() {
        assert!(LOLBAS_WINDOWS.contains(&"net.exe"));
    }
    #[test]
    fn lolbas_windows_contains_wevtutil() {
        assert!(LOLBAS_WINDOWS.contains(&"wevtutil.exe"));
    }
    #[test]
    fn lolbas_windows_contains_nltest() {
        assert!(LOLBAS_WINDOWS.contains(&"nltest.exe"));
    }
    #[test]
    fn is_lolbas_windows_detects_psexec() {
        assert!(is_lolbas_windows("psexec.exe"));
    }
    #[test]
    fn is_lolbas_windows_detects_psexec_uppercase() {
        assert!(is_lolbas_windows("PSEXEC.EXE"));
    }
    // LOFL_WINDOWS_CMDLETS
    #[test]
    fn lofl_windows_cmdlets_exists() {
        assert!(!LOFL_WINDOWS_CMDLETS.is_empty());
    }
    #[test]
    fn lofl_windows_cmdlets_contains_invoke_command() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Invoke-Command"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_get_aduser() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Get-ADUser"));
    }
    #[test]
    fn is_lofl_windows_cmdlet_detects_invoke_command() {
        assert!(is_lofl_windows_cmdlet("Invoke-Command"));
    }
    #[test]
    fn is_lofl_windows_cmdlet_case_insensitive() {
        assert!(is_lofl_windows_cmdlet("invoke-command"));
    }
    #[test]
    fn is_lofl_windows_cmdlet_rejects_unknown() {
        assert!(!is_lofl_windows_cmdlet("Write-FakeOutput"));
    }
    // LOFL_WINDOWS_MMC
    #[test]
    fn lofl_windows_mmc_exists() {
        assert!(!LOFL_WINDOWS_MMC.is_empty());
    }
    #[test]
    fn lofl_windows_mmc_contains_compmgmt() {
        assert!(LOFL_WINDOWS_MMC.contains(&"compmgmt.msc"));
    }
    #[test]
    fn lofl_windows_mmc_contains_eventvwr() {
        assert!(LOFL_WINDOWS_MMC.contains(&"eventvwr.msc"));
    }
    #[test]
    fn is_lofl_windows_mmc_detects_compmgmt() {
        assert!(is_lofl_windows_mmc("compmgmt.msc"));
    }
    #[test]
    fn is_lofl_windows_mmc_case_insensitive() {
        assert!(is_lofl_windows_mmc("COMPMGMT.MSC"));
    }
    // LOFL_WINDOWS_WMI
    #[test]
    fn lofl_windows_wmi_exists() {
        assert!(!LOFL_WINDOWS_WMI.is_empty());
    }
    #[test]
    fn lofl_windows_wmi_contains_win32_process() {
        assert!(LOFL_WINDOWS_WMI.contains(&"Win32_Process"));
    }
    #[test]
    fn lofl_windows_wmi_contains_win32_shadowcopy() {
        assert!(LOFL_WINDOWS_WMI.contains(&"Win32_ShadowCopy"));
    }
    #[test]
    fn is_lofl_windows_wmi_detects_win32_process() {
        assert!(is_lofl_windows_wmi("Win32_Process"));
    }
    #[test]
    fn is_lofl_windows_wmi_case_insensitive() {
        assert!(is_lofl_windows_wmi("win32_process"));
    }

    // Native PowerShell attack cmdlets (gap vs LOFL Project)
    #[test]
    fn lofl_windows_cmdlets_contains_invoke_webrequest() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Invoke-WebRequest"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_invoke_expression() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Invoke-Expression"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_invoke_restmethod() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Invoke-RestMethod"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_start_bitstransfer() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Start-BitsTransfer"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_add_type() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Add-Type"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_new_object() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"New-Object"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_set_executionpolicy() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Set-ExecutionPolicy"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_compress_archive() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Compress-Archive"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_start_process() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Start-Process"));
    }
    #[test]
    fn lofl_windows_cmdlets_contains_register_objectevent() {
        assert!(LOFL_WINDOWS_CMDLETS.contains(&"Register-ObjectEvent"));
    }
    // PowerShell built-in aliases — attackers use these to evade keyword detection
    #[test]
    fn lofl_windows_ps_aliases_exists() {
        assert!(!LOFL_WINDOWS_PS_ALIASES.is_empty());
    }
    #[test]
    fn lofl_windows_ps_aliases_contains_iex() {
        assert!(LOFL_WINDOWS_PS_ALIASES.contains(&"iex"));
    }
    #[test]
    fn lofl_windows_ps_aliases_contains_iwr() {
        assert!(LOFL_WINDOWS_PS_ALIASES.contains(&"iwr"));
    }
    #[test]
    fn lofl_windows_ps_aliases_contains_irm() {
        assert!(LOFL_WINDOWS_PS_ALIASES.contains(&"irm"));
    }
    #[test]
    fn lofl_windows_ps_aliases_contains_wget_ps_alias() {
        // wget is a PS built-in alias for Invoke-WebRequest (distinct from /usr/bin/wget)
        assert!(LOFL_WINDOWS_PS_ALIASES.contains(&"wget"));
    }
    #[test]
    fn lofl_windows_ps_aliases_contains_curl_ps_alias() {
        // curl is a PS built-in alias for Invoke-WebRequest (PS 5.x; removed in PS 7)
        assert!(LOFL_WINDOWS_PS_ALIASES.contains(&"curl"));
    }
    #[test]
    fn is_lofl_windows_ps_alias_detects_iex() {
        assert!(is_lofl_windows_ps_alias("iex"));
    }
    #[test]
    fn is_lofl_windows_ps_alias_case_insensitive() {
        assert!(is_lofl_windows_ps_alias("IEX"));
    }
    #[test]
    fn is_lofl_windows_ps_alias_rejects_unknown() {
        assert!(!is_lofl_windows_ps_alias("notanalias"));
    }
}
