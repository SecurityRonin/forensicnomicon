//! PE (Portable Executable) format constants for forensic heuristics.
//!
//! Zero-dependency compile-time constants for detecting suspicious PE characteristics:
//! process-injection APIs, packed executables, AV exclusion path patterns.

// ── Magic bytes ──────────────────────────────────────────────────────────────

/// DOS stub magic bytes at offset 0 of every valid PE file.
pub const MZ_MAGIC: [u8; 2] = *b"MZ";

/// PE signature at offset pointed to by e_lfanew.
pub const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

// ── Machine types ─────────────────────────────────────────────────────────────

/// AMD64 / x86-64 machine type.
pub const MACHINE_AMD64: u16 = 0x8664;
/// x86 (32-bit) machine type.
pub const MACHINE_I386: u16 = 0x014C;
/// AArch64 (ARM64) machine type.
pub const MACHINE_ARM64: u16 = 0xAA64;

// ── Suspicious import names ───────────────────────────────────────────────────

/// Windows API names commonly imported by malware for process injection,
/// privilege escalation, anti-debugging, encryption, and C2.
///
/// Presence alone is not conclusive — many are used by legitimate software too.
/// Combine with section entropy, compile timestamp, and import count.
pub const SUSPICIOUS_IMPORT_NAMES: &[&str] = &[
    // Process injection / code execution
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "SetThreadContext",
    "GetThreadContext",
    "SuspendThread",
    "ResumeThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    // Handle/privilege acquisition
    "OpenProcess",
    "NtOpenProcess",
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "DuplicateTokenEx",
    // Dynamic code loading
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    // Anti-debugging
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    // Crypto (ransomware / C2)
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenKey",
    "CryptImportKey",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenerateSymmetricKey",
    // File operations (mass encryption / deletion)
    "FindFirstFileA",
    "FindFirstFileW",
    "FindFirstFileExA",
    "FindFirstFileExW",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileExA",
    "MoveFileExW",
    // Execution
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
    // Registry persistence
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    // Network / C2
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WSAStartup",
    "WSAConnect",
    "WSASend",
    "WSARecv",
    "connect",
    "send",
    "recv",
];

// ── Packed / protected section names ─────────────────────────────────────────

/// PE section names associated with known packers and protectors.
///
/// A match indicates the binary was processed by a packer, which is a strong
/// signal combined with high section entropy (> 6.8).
pub const PACKED_SECTION_NAMES: &[&str] = &[
    "UPX0", "UPX1", "UPX2",
    ".upx0", ".upx1",
    ".aspack", ".adata",
    ".packed", ".shrink",
    "MPRESS1", "MPRESS2",
    ".petite",
    ".nsp0", ".nsp1", ".nsp2",  // NsPack
    ".themida", ".winlicen",
    "PESHiELD",
    "_winzip_",
    "ASProtect",
    ".enigma1", ".enigma2",
    ".vmp0", ".vmp1",           // VMProtect
    ".obsidium",
    "Exe32Pack",
];

// ── AV exclusion path / registry fragments ───────────────────────────────────

/// Path and registry key fragments appearing in PE string tables of binaries
/// that manipulate AV exclusion lists (T1562.001).
///
/// Match these against ASCII/UTF-16 strings extracted from PE .data/.rdata sections.
pub const AV_EXCLUSION_PATH_FRAGMENTS: &[&str] = &[
    // Windows Defender exclusion registry keys
    "Exclusions\\Paths",
    "Exclusions\\Extensions",
    "Exclusions\\Processes",
    "Exclusions\\IpAddresses",
    "Windows Defender\\Exclusions",
    "Microsoft\\Windows Defender",
    // Kaspersky
    "Kaspersky Lab\\AVP",
    "KasperskyLab",
    // Symantec / SEP
    "Symantec\\Symantec Endpoint Protection",
    "Norton AntiVirus",
    // McAfee
    "McAfee\\DesktopProtection",
    "McAfee\\Endpoint Security",
    // Trend Micro
    "TrendMicro",
    "OfficeScanNT",
    // Sophos
    "SophosSAV",
    "Sophos\\Sophos Anti-Virus",
    // ESET
    "ESET\\ESET Security",
    // Bitdefender
    "Bitdefender",
    "bd_ie",
    // Malwarebytes
    "Malwarebytes",
    // VIPRE Security
    "VIPRE",
    // SentinelOne
    "SentinelOne",
    // API / command patterns
    "AddDynamicSignature",
    "RemoveDynamicSignature",
    "DisableRealtimeMonitoring",
    "SubmitSamplesConsent",
    "MpCmdRun",
    "ExcludeFromScan",
    "ExclusionPath",
    "SecurityCenter",
    "AntiVirusOverride",
    "FirewallDisableNotify",
];

// ── QWCrypt / RedCurl PE IOCs ─────────────────────────────────────────────────

/// Strings found in QWCrypt/RedCurl PE data sections that confirm attribution.
pub const QWCRYPT_PE_STRING_IOCS: &[&str] = &[
    ".qwCrypt",
    "rbcw",
    "ADNotificationManager",
    "excludeVM",        // QWCrypt --excludeVM CLI flag
    "HyperV",
    "ZAM64",            // Zemana anti-malware driver
    "zamguard",
    // Cloudflare Workers C2 patterns
    "workers.dev",
    "cloudflare",
];

// ── Anti-debugging imports ────────────────────────────────────────────────────

/// Windows API names whose primary purpose in malware is debugger/analysis detection.
///
/// These narrow the general [`SUSPICIOUS_IMPORT_NAMES`] set to functions that,
/// when present together, form a strong signal for debugger evasion (T1622).
/// Individual hits are low confidence; clusters of 3+ are high confidence.
pub const ANTI_DEBUG_IMPORT_NAMES: &[&str] = &[
    // Explicit debugger presence queries
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",    // class 7 = ProcessDebugPort
    "ZwQueryInformationProcess",
    // Thread hiding from debugger (SysInternals / anti-attach technique)
    "NtSetInformationThread",       // ThreadHideFromDebugger = 17
    "ZwSetInformationThread",
    // Exception-based debugger probing
    "SetUnhandledExceptionFilter",
    "UnhandledExceptionFilter",
    "RaiseException",
    // Timing attacks (debugger slows execution)
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "timeGetTime",
    // CloseHandle on invalid handle raises exception only under debugger
    "CloseHandle",
    // Debug output as presence probe
    "OutputDebugStringA",
    "OutputDebugStringW",
    // Process enumeration for analysis tool detection
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "Module32First",
    "Module32Next",
    // Window title scanning (OllyDbg, x64dbg, IDA, etc.)
    "FindWindowA",
    "FindWindowW",
    "FindWindowExA",
    "FindWindowExW",
    "EnumWindows",
    // Input blocking — sandbox / automated analysis detection
    "BlockInput",
];

// ── Process hollowing API cluster ─────────────────────────────────────────────

/// Windows API imports associated with process hollowing (T1055.012).
///
/// No single API is conclusive; malware scoring requires at least 3 of these
/// together. Legitimate process creation does NOT combine `NtUnmapViewOfSection`
/// with `WriteProcessMemory` + `SetThreadContext`.
pub const PROCESS_HOLLOWING_APIS: &[&str] = &[
    // Hollow the target — unmap legitimate image
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    // Map attacker image into vacated space
    "NtMapViewOfSection",
    "ZwMapViewOfSection",
    "NtCreateSection",
    "ZwCreateSection",
    // Write payload and redirect execution
    "VirtualAllocEx",
    "WriteProcessMemory",
    "SetThreadContext",
    "GetThreadContext",
    // Resume target process
    "ResumeThread",
    "NtResumeThread",
    "ZwResumeThread",
];

// ── Ransomware string patterns ────────────────────────────────────────────────

/// String fragments found in PE data sections of ransomware payloads (T1486).
///
/// Covers encrypted file extension markers, ransom note keywords,
/// cryptocurrency payment instructions, and Tor/dark-web patterns.
/// High confidence when any of these appear in .data / .rdata strings.
pub const RANSOMWARE_STRING_PATTERNS: &[&str] = &[
    // Common encrypted-file extension suffixes
    ".encrypted",
    ".locked",
    ".enc",
    ".crypt",
    ".crypted",
    ".locky",
    ".zepto",
    ".cerber",
    ".wncry",           // WannaCry
    ".wnry",
    ".ryuk",
    ".conti",
    ".hive",
    ".lockbit",
    ".qwCrypt",             // QWCrypt / RedCurl ransomware
    // Ransom note filenames / embedded content
    "HOW_TO_DECRYPT",
    "DECRYPT_FILES",
    "RECOVER_FILES",
    "README_DECRYPT",
    "YOUR_FILES_ARE_ENCRYPTED",
    "IMPORTANT_README",
    "restore_files",
    "How to Decrypt Files",
    "All your files",
    "Your personal ID",
    "unique identifier",
    // Cryptocurrency payment instructions
    "bitcoin",
    "Bitcoin",
    "monero",
    "Monero",
    " BTC",
    " XMR",
    "wallet address",
    "Bitcoin address",
    "send payment",
    // Tor / dark-web contact patterns
    ".onion",
    "tor2web",
    "torproject.org",
    // Generic ransomware vocabulary
    "ransom",
    "decrypt",
    "decryption key",
    "decryptor",
    "pay within",
    "deadline",
];

// ── Persistence string patterns ───────────────────────────────────────────────

/// Registry key paths and system locations embedded in PE data sections that
/// indicate a binary installs persistence (T1547.001 / T1543.003 / T1546).
pub const PERSISTENCE_STRING_PATTERNS: &[&str] = &[
    // Registry autorun keys (T1547.001)
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "CurrentVersion\\RunServices",
    "CurrentVersion\\RunServicesOnce",
    // Winlogon hijack (T1547.004)
    "Winlogon\\Userinit",
    "Winlogon\\Shell",
    // Windows service registry (T1543.003)
    "CurrentControlSet\\Services",
    // Scheduled tasks (T1053.005)
    "schtasks /create",
    "schtasks.exe",
    "Task Scheduler",
    "\\Microsoft\\Windows\\TaskScheduler",
    // Startup folders (T1547.001)
    "\\Start Menu\\Programs\\Startup",
    "\\Roaming\\Microsoft\\Windows\\Start Menu",
    // WMI persistence (T1546.003)
    "__EventFilter",
    "__EventConsumer",
    "CommandLineEventConsumer",
    "ROOT\\subscription",
    // COM hijacking (T1546.015)
    "InprocServer32",
    "LocalServer32",
    // AppInit DLLs (T1546.010)
    "AppInit_DLLs",
    // Image File Execution Options debugger key (T1546.012)
    "Image File Execution Options",
    // Security Support Provider (T1547.005)
    "Security Packages",
    "Authentication Packages",
    // Logon scripts (T1037.001)
    "UserInitMprLogonScript",
    // Boot / pre-OS via driver (T1547.006)
    "BootExecute",
];

// ── Network / C2 communication patterns ──────────────────────────────────────

/// String fragments in PE data sections indicating network communication,
/// C2 beaconing, or data exfiltration (T1071.001 / T1095 / T1132).
///
/// Match against the full string table — C2 URLs, HTTP headers, and path
/// templates are often stored as literals in `.data` / `.rdata`.
pub const NETWORK_C2_PATTERNS: &[&str] = &[
    // Protocol schemes (non-browser binaries rarely have these)
    "http://",
    "https://",
    "ftp://",
    // Anonymisation infrastructure
    ".onion",
    "tor2web",
    // Embedded HTTP request templates
    "User-Agent:",
    "Content-Type: application/",
    "Authorization: Bearer",
    "Authorization: Basic",
    "X-Forwarded-For:",
    // Common C2 verb/path patterns
    "POST /",
    "/beacon",
    "/checkin",
    "/gate.php",
    "/config.php",
    "/panel/",
    "/upload",
    "/download",
    "/command",
    "/tasks",
    "/results",
    "/implant",
    "/stager",
    // Cloudflare Workers abuse (RedCurl/QWCrypt C2 infrastructure)
    "workers.dev",
    // DNS-over-HTTPS / DNS resolver abuse (T1071.004)
    "dns.google",
    "cloudflare-dns.com",
    "doh.pub",
    // Encoded payload delivery indicators
    "powershell -enc",
    "powershell -e ",
    "powershell -EncodedCommand",
    "cmd.exe /c ",
    // Known C2 framework indicators
    "meterpreter",
    "reverse_tcp",
    "reverse_https",
    "shellcode",
    "payload.dll",
];

// ── Hardcoded credential patterns ────────────────────────────────────────────

/// String patterns indicating hardcoded credentials, API keys, or secret
/// material embedded in PE data sections (T1552.001).
///
/// These should never appear in deployed binaries; any match warrants
/// immediate investigation of the credential's validity and rotation.
pub const CREDENTIAL_PATTERNS: &[&str] = &[
    // Generic password assignment patterns
    "password=",
    "Password=",
    "passwd=",
    "pass=",
    "pwd=",
    "secret=",
    // API key patterns
    "api_key=",
    "apikey=",
    "api-key=",
    "API_KEY=",
    // Token patterns
    "token=",
    "access_token",
    "refresh_token",
    "auth_token",
    // HTTP auth headers (hardcoded in request templates)
    "Authorization: Basic",
    "Authorization: Bearer",
    // Cloud provider key prefixes
    "AKIA",                         // AWS access key ID prefix
    "aws_secret_access_key",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "client_secret",
    "client_id",
    // Database connection string fragments
    "Data Source=",
    "User ID=",
    "Password;",
    "Integrated Security=False",
    // PEM-encoded key material markers
    "-----BEGIN",
    "BEGIN RSA PRIVATE",
    "BEGIN PRIVATE KEY",
    "BEGIN CERTIFICATE",
    // SSH patterns
    "ssh-rsa ",
    "id_rsa",
    // JWT / Bearer token structure
    "eyJhbGciOi",                    // base64-encoded {"alg"
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anti_debug_import_names_not_empty() {
        assert!(!ANTI_DEBUG_IMPORT_NAMES.is_empty());
    }

    #[test]
    fn anti_debug_contains_core_apis() {
        assert!(ANTI_DEBUG_IMPORT_NAMES.contains(&"IsDebuggerPresent"));
        assert!(ANTI_DEBUG_IMPORT_NAMES.contains(&"CheckRemoteDebuggerPresent"));
        assert!(ANTI_DEBUG_IMPORT_NAMES.contains(&"NtQueryInformationProcess"));
        assert!(ANTI_DEBUG_IMPORT_NAMES.contains(&"QueryPerformanceCounter"));
    }

    #[test]
    fn anti_debug_no_duplicates() {
        let mut sorted = ANTI_DEBUG_IMPORT_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ANTI_DEBUG_IMPORT_NAMES.len(), "no duplicates");
    }

    #[test]
    fn process_hollowing_apis_not_empty() {
        assert!(!PROCESS_HOLLOWING_APIS.is_empty());
    }

    #[test]
    fn process_hollowing_contains_unmap_and_resume() {
        assert!(PROCESS_HOLLOWING_APIS.contains(&"NtUnmapViewOfSection"));
        assert!(PROCESS_HOLLOWING_APIS.contains(&"WriteProcessMemory"));
        assert!(PROCESS_HOLLOWING_APIS.contains(&"SetThreadContext"));
        assert!(PROCESS_HOLLOWING_APIS.contains(&"ResumeThread"));
    }

    #[test]
    fn ransomware_patterns_not_empty() {
        assert!(!RANSOMWARE_STRING_PATTERNS.is_empty());
    }

    #[test]
    fn ransomware_patterns_cover_extensions_and_payment() {
        assert!(RANSOMWARE_STRING_PATTERNS.contains(&".encrypted"));
        assert!(RANSOMWARE_STRING_PATTERNS.contains(&".wncry"));
        assert!(RANSOMWARE_STRING_PATTERNS.contains(&"bitcoin"));
        assert!(RANSOMWARE_STRING_PATTERNS.contains(&".onion"));
        assert!(RANSOMWARE_STRING_PATTERNS.contains(&"HOW_TO_DECRYPT"));
    }

    #[test]
    fn persistence_patterns_not_empty() {
        assert!(!PERSISTENCE_STRING_PATTERNS.is_empty());
    }

    #[test]
    fn persistence_patterns_cover_key_techniques() {
        assert!(PERSISTENCE_STRING_PATTERNS.contains(&"CurrentVersion\\Run"));
        assert!(PERSISTENCE_STRING_PATTERNS.contains(&"CurrentControlSet\\Services"));
        assert!(PERSISTENCE_STRING_PATTERNS.contains(&"AppInit_DLLs"));
        assert!(PERSISTENCE_STRING_PATTERNS.contains(&"__EventFilter"));
    }

    #[test]
    fn network_c2_patterns_not_empty() {
        assert!(!NETWORK_C2_PATTERNS.is_empty());
    }

    #[test]
    fn network_c2_patterns_cover_http_and_c2() {
        assert!(NETWORK_C2_PATTERNS.contains(&"http://"));
        assert!(NETWORK_C2_PATTERNS.contains(&"https://"));
        assert!(NETWORK_C2_PATTERNS.contains(&".onion"));
        assert!(NETWORK_C2_PATTERNS.contains(&"User-Agent:"));
        assert!(NETWORK_C2_PATTERNS.contains(&"meterpreter"));
    }

    // ── RED: QWCrypt gap tests ─────────────────────────────────────────────────

    #[test]
    fn av_exclusion_covers_malwarebytes() {
        assert!(
            AV_EXCLUSION_PATH_FRAGMENTS.contains(&"Malwarebytes"),
            "QWCrypt explicitly excludes Malwarebytes from its AV kill list"
        );
    }

    #[test]
    fn av_exclusion_covers_vipre() {
        assert!(
            AV_EXCLUSION_PATH_FRAGMENTS.contains(&"VIPRE"),
            "QWCrypt explicitly excludes VIPRE Security"
        );
    }

    #[test]
    fn av_exclusion_covers_sentinelone() {
        assert!(
            AV_EXCLUSION_PATH_FRAGMENTS.contains(&"SentinelOne"),
            "QWCrypt explicitly excludes SentinelOne endpoint protection"
        );
    }

    #[test]
    fn network_c2_patterns_cover_cloudflare_workers() {
        assert!(
            NETWORK_C2_PATTERNS.contains(&"workers.dev"),
            "workers.dev is the Cloudflare Workers C2 infrastructure abused by RedCurl/QWCrypt"
        );
    }

    #[test]
    fn ransomware_patterns_cover_qwcrypt_extension() {
        assert!(
            RANSOMWARE_STRING_PATTERNS.contains(&".qwCrypt"),
            ".qwCrypt is the file extension appended by QWCrypt ransomware"
        );
    }

    #[test]
    fn credential_patterns_not_empty() {
        assert!(!CREDENTIAL_PATTERNS.is_empty());
    }

    #[test]
    fn credential_patterns_cover_passwords_tokens_and_pem() {
        assert!(CREDENTIAL_PATTERNS.contains(&"password="));
        assert!(CREDENTIAL_PATTERNS.contains(&"api_key="));
        assert!(CREDENTIAL_PATTERNS.contains(&"AKIA"));
        assert!(CREDENTIAL_PATTERNS.contains(&"-----BEGIN"));
    }
}
