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
