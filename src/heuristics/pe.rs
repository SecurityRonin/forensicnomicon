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
    "UPX0",
    "UPX1",
    "UPX2",
    ".upx0",
    ".upx1",
    ".aspack",
    ".adata",
    ".packed",
    ".shrink",
    "MPRESS1",
    "MPRESS2",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".nsp2", // NsPack
    ".themida",
    ".winlicen",
    "PESHiELD",
    "_winzip_",
    "ASProtect",
    ".enigma1",
    ".enigma2",
    ".vmp0",
    ".vmp1", // VMProtect
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
    "excludeVM", // QWCrypt --excludeVM CLI flag
    "HyperV",
    "ZAM64", // Zemana anti-malware driver
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
    "NtQueryInformationProcess", // class 7 = ProcessDebugPort
    "ZwQueryInformationProcess",
    // Thread hiding from debugger (SysInternals / anti-attach technique)
    "NtSetInformationThread", // ThreadHideFromDebugger = 17
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
    ".wncry", // WannaCry
    ".wnry",
    ".ryuk",
    ".conti",
    ".hive",
    ".lockbit",
    ".qwCrypt", // QWCrypt / RedCurl ransomware
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
    "AKIA", // AWS access key ID prefix
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
    "eyJhbGciOi", // base64-encoded {"alg"
];

// ── Pure PE-header offset decoders ────────────────────────────────────────────
//
// Zero-I/O decoders over caller-fetched header bytes. Each is bounds-checked,
// panic-free (no `unwrap`/`expect`/index-panic), and returns `Option` so a
// truncated or malformed buffer degrades to `None` rather than crashing.
//
// Offsets follow the Microsoft PE/COFF specification:
// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>.

/// Offset of the `e_lfanew` field (u32, LE) within the DOS header.
const DOS_E_LFANEW_OFFSET: usize = 0x3C;

/// Offset of `NumberOfSections` (u16, LE) within the COFF file header.
const COFF_NUMBER_OF_SECTIONS_OFFSET: usize = 6;

/// Offset of `SizeOfOptionalHeader` (u16, LE) within the COFF file header.
const COFF_SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 0x14;

/// Optional-header `Magic` value identifying a 32-bit (PE32) image.
const OPT_MAGIC_PE32: u16 = 0x010B;

/// Optional-header `Magic` value identifying a 64-bit (PE32+) image.
const OPT_MAGIC_PE32PLUS: u16 = 0x020B;

/// Data-directory array base, as an offset from the start of a PE32
/// optional header. (`NumberOfRvaAndSizes` @92, directories begin @96.)
const PE32_DATA_DIR_OFFSET: usize = 96;

/// Data-directory array base, as an offset from the start of a PE32+
/// optional header.
const PE32PLUS_DATA_DIR_OFFSET: usize = 112;

/// Each PE section-table entry is 40 bytes.
const SECTION_ENTRY_SIZE: usize = 40;

/// Parsed fields of the COFF file header relevant to locating the section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    /// `NumberOfSections` — count of entries in the section table.
    pub number_of_sections: u16,
    /// `SizeOfOptionalHeader` — bytes of optional header following the COFF header.
    pub size_of_optional_header: u16,
}

/// Optional-header `Magic`, distinguishing 32-bit (PE32) from 64-bit (PE32+) images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalHeaderMagic {
    /// PE32 — 32-bit image (`Magic` == 0x010B).
    Pe32,
    /// PE32+ — 64-bit image (`Magic` == 0x020B).
    Pe32Plus,
}

impl OptionalHeaderMagic {
    /// Offset of the data-directory array from the start of the optional header.
    ///
    /// PE32 and PE32+ place the directory array at different offsets because the
    /// PE32+ header widens several fields to 64 bits.
    #[must_use]
    pub fn data_directory_offset(self) -> usize {
        match self {
            OptionalHeaderMagic::Pe32 => PE32_DATA_DIR_OFFSET,
            OptionalHeaderMagic::Pe32Plus => PE32PLUS_DATA_DIR_OFFSET,
        }
    }
}

/// Reads a little-endian `u16` at `offset`, or `None` if out of bounds.
fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

/// Reads a little-endian `u32` at `offset`, or `None` if out of bounds.
fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

/// Parsed fields of a single 40-byte PE section-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    /// Section name (`Name[8]`), trailing NUL padding stripped.
    pub name: Vec<u8>,
    /// `VirtualSize` — size of the section when loaded into memory.
    pub virtual_size: u32,
    /// `VirtualAddress` — RVA of the section relative to the image base.
    pub virtual_address: u32,
}

/// Reads `e_lfanew` (offset of the PE header) from a DOS header.
///
/// Validates the `MZ` magic and returns `None` if the buffer is too short or
/// the magic is absent.
#[must_use]
pub fn parse_dos_header(bytes: &[u8]) -> Option<u32> {
    if bytes.get(..2)? != MZ_MAGIC {
        return None;
    }
    read_u32_le(bytes, DOS_E_LFANEW_OFFSET)
}

/// Parses the COFF file header from a slice positioned at the PE signature.
///
/// Validates the `PE\0\0` signature and returns `None` on a short or malformed
/// buffer.
#[must_use]
pub fn parse_coff_header(bytes: &[u8]) -> Option<CoffHeader> {
    if bytes.get(..4)? != PE_SIGNATURE {
        return None;
    }
    Some(CoffHeader {
        number_of_sections: read_u16_le(bytes, COFF_NUMBER_OF_SECTIONS_OFFSET)?,
        size_of_optional_header: read_u16_le(bytes, COFF_SIZE_OF_OPTIONAL_HEADER_OFFSET)?,
    })
}

/// Classifies an optional header by its `Magic` field.
///
/// `bytes` must be positioned at the start of the optional header. Returns
/// `None` for a short buffer or an unrecognized magic value.
#[must_use]
pub fn parse_optional_header_magic(bytes: &[u8]) -> Option<OptionalHeaderMagic> {
    match read_u16_le(bytes, 0)? {
        OPT_MAGIC_PE32 => Some(OptionalHeaderMagic::Pe32),
        OPT_MAGIC_PE32PLUS => Some(OptionalHeaderMagic::Pe32Plus),
        _ => None,
    }
}

/// Parses a single 40-byte section-table entry.
///
/// Returns `None` if fewer than 40 bytes are supplied.
#[must_use]
pub fn parse_section_entry(bytes: &[u8]) -> Option<SectionEntry> {
    let entry = bytes.get(..SECTION_ENTRY_SIZE)?;
    let raw_name = entry.get(..8)?;
    let name_len = raw_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_name.len());
    Some(SectionEntry {
        name: raw_name.get(..name_len)?.to_vec(),
        virtual_size: read_u32_le(entry, 8)?,
        virtual_address: read_u32_le(entry, 0xC)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects the `///` doc comment immediately above `pub const <name>` in
    /// `source`, so a documented relationship can be checked against the data.
    fn doc_comment_above(source: &str, const_name: &str) -> String {
        let needle = format!("pub const {const_name}:");
        let (head, _) = source
            .split_once(needle.as_str())
            .unwrap_or_else(|| panic!("{const_name} not found in source"));
        let mut lines: Vec<&str> = head
            .lines()
            .rev()
            .skip_while(|line| line.trim().is_empty())
            .take_while(|line| line.trim_start().starts_with("///"))
            .collect();
        lines.reverse();
        lines.join("\n")
    }

    struct SubsetClaim {
        source: &'static str,
        child_name: &'static str,
        child: &'static [&'static str],
        parent_name: &'static str,
        parent: &'static [&'static str],
    }

    /// Doc-claim guard (repo Accuracy Standards): a constant table's doc comment
    /// may state that it is a subset of — or narrows — another table only when
    /// the data satisfies `child ⊆ parent`. A false relationship claim makes an
    /// analyst reason wrongly about coverage, and nothing else in the build
    /// checks prose against data.
    ///
    /// The guard is generic over the claim rather than over one table: any table
    /// that grows such a phrase in future is checked the same way.
    #[test]
    fn subset_doc_claims_hold_in_the_data() {
        const CLAIM_PHRASES: &[&str] = &["subset of", "narrow the general", "narrows the general"];

        let claims = [
            SubsetClaim {
                source: include_str!("pe.rs"),
                child_name: "ANTI_DEBUG_IMPORT_NAMES",
                child: ANTI_DEBUG_IMPORT_NAMES,
                parent_name: "SUSPICIOUS_IMPORT_NAMES",
                parent: SUSPICIOUS_IMPORT_NAMES,
            },
            SubsetClaim {
                source: include_str!("pe.rs"),
                child_name: "PROCESS_HOLLOWING_APIS",
                child: PROCESS_HOLLOWING_APIS,
                parent_name: "SUSPICIOUS_IMPORT_NAMES",
                parent: SUSPICIOUS_IMPORT_NAMES,
            },
            SubsetClaim {
                source: include_str!("../processes.rs"),
                child_name: "WINDOWS_SYSTEM32_BINARIES",
                child: crate::processes::WINDOWS_SYSTEM32_BINARIES,
                parent_name: "WINDOWS_MASQUERADE_TARGETS",
                parent: crate::processes::WINDOWS_MASQUERADE_TARGETS,
            },
        ];

        let mut violations = Vec::new();
        for claim in &claims {
            let doc = doc_comment_above(claim.source, claim.child_name);
            if !doc.contains(claim.parent_name) {
                continue;
            }
            let Some(phrase) = CLAIM_PHRASES.iter().find(|p| doc.contains(**p)) else {
                continue;
            };
            let missing: Vec<&str> = claim
                .child
                .iter()
                .copied()
                .filter(|name| !claim.parent.contains(name))
                .collect();
            if !missing.is_empty() {
                violations.push(format!(
                    "{} doc claims \"{phrase}\" against {}, but {} of its {} members are \
                     absent from {}: {missing:?}",
                    claim.child_name,
                    claim.parent_name,
                    missing.len(),
                    claim.child.len(),
                    claim.parent_name,
                ));
            }
        }
        assert!(
            violations.is_empty(),
            "false subset claim(s) in doc comments:\n{}",
            violations.join("\n")
        );
    }

    /// The anti-debug table is curated independently of the general suspicious
    /// import list, and its doc comment names the exact overlap. Pin that overlap
    /// so an edit to either table cannot silently make the doc false.
    #[test]
    fn anti_debug_overlap_with_suspicious_imports_is_the_documented_five() {
        let shared: Vec<&str> = ANTI_DEBUG_IMPORT_NAMES
            .iter()
            .copied()
            .filter(|name| SUSPICIOUS_IMPORT_NAMES.contains(name))
            .collect();
        assert_eq!(
            shared,
            [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "OutputDebugStringA",
                "OutputDebugStringW",
            ],
            "overlap with SUSPICIOUS_IMPORT_NAMES changed — update the \
             ANTI_DEBUG_IMPORT_NAMES doc comment to match"
        );
        assert_eq!(
            ANTI_DEBUG_IMPORT_NAMES.len() - shared.len(),
            22,
            "count of anti-debug names unique to this table changed — update its doc comment"
        );
    }

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

    // ── PE-header offset decoders ──────────────────────────────────────────────

    /// Builds a 64-byte DOS header with the `MZ` magic and a given `e_lfanew`.
    fn dos_header(e_lfanew: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x40];
        buf[0..2].copy_from_slice(&MZ_MAGIC);
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        buf
    }

    /// Builds a COFF header slice starting at the `PE\0\0` signature.
    ///
    /// Offsets are relative to the signature: `NumberOfSections` @ +6,
    /// `SizeOfOptionalHeader` @ +0x14 (signature 4 bytes + COFF field @ +16).
    fn coff_header(number_of_sections: u16, size_of_optional_header: u16) -> Vec<u8> {
        // 4-byte signature + 20-byte COFF file header = 24 bytes.
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&PE_SIGNATURE);
        buf[6..8].copy_from_slice(&number_of_sections.to_le_bytes());
        buf[0x14..0x16].copy_from_slice(&size_of_optional_header.to_le_bytes());
        buf
    }

    #[test]
    fn dos_header_returns_e_lfanew() {
        assert_eq!(parse_dos_header(&dos_header(0x80)), Some(0x80));
        assert_eq!(parse_dos_header(&dos_header(0xF0)), Some(0xF0));
    }

    #[test]
    fn dos_header_rejects_missing_mz_magic() {
        let mut buf = dos_header(0x80);
        buf[0] = b'X';
        assert_eq!(parse_dos_header(&buf), None);
    }

    #[test]
    fn dos_header_rejects_short_buffer() {
        // Too short to hold e_lfanew @ 0x3C..0x40.
        assert_eq!(parse_dos_header(b"MZ"), None);
        assert_eq!(parse_dos_header(&[0u8; 0x3F]), None);
        assert_eq!(parse_dos_header(&[]), None);
    }

    #[test]
    fn coff_header_parses_section_count_and_opt_size() {
        let parsed = parse_coff_header(&coff_header(7, 0xF0)).expect("valid COFF");
        assert_eq!(parsed.number_of_sections, 7);
        assert_eq!(parsed.size_of_optional_header, 0xF0);
    }

    #[test]
    fn coff_header_rejects_bad_signature() {
        let mut buf = coff_header(2, 0xF0);
        buf[1] = b'X'; // corrupt "PE\0\0"
        assert_eq!(parse_coff_header(&buf), None);
    }

    #[test]
    fn coff_header_rejects_short_buffer() {
        assert_eq!(parse_coff_header(&PE_SIGNATURE), None);
        assert_eq!(parse_coff_header(&[]), None);
    }

    #[test]
    fn optional_header_magic_classifies_pe32_and_pe32plus() {
        let pe32 = 0x010Bu16.to_le_bytes();
        let pe32plus = 0x020Bu16.to_le_bytes();
        assert_eq!(
            parse_optional_header_magic(&pe32),
            Some(OptionalHeaderMagic::Pe32)
        );
        assert_eq!(
            parse_optional_header_magic(&pe32plus),
            Some(OptionalHeaderMagic::Pe32Plus)
        );
    }

    #[test]
    fn optional_header_magic_rejects_unknown_and_short() {
        assert_eq!(parse_optional_header_magic(&0x0000u16.to_le_bytes()), None);
        assert_eq!(parse_optional_header_magic(&[0x0B]), None);
        assert_eq!(parse_optional_header_magic(&[]), None);
    }

    #[test]
    fn data_directory_offset_matches_spec() {
        // PE32: NumberOfRvaAndSizes @92, directories @96.
        assert_eq!(OptionalHeaderMagic::Pe32.data_directory_offset(), 96);
        // PE32+: directories @112.
        assert_eq!(OptionalHeaderMagic::Pe32Plus.data_directory_offset(), 112);
    }

    #[test]
    fn section_entry_parses_name_vsize_and_vaddr() {
        let mut buf = vec![0u8; 40];
        buf[0..5].copy_from_slice(b".text");
        buf[8..12].copy_from_slice(&0x1234u32.to_le_bytes()); // VirtualSize @8
        buf[0xC..0x10].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress @0xC
        let entry = parse_section_entry(&buf).expect("valid entry");
        assert_eq!(entry.name, b".text");
        assert_eq!(entry.virtual_size, 0x1234);
        assert_eq!(entry.virtual_address, 0x1000);
    }

    #[test]
    fn section_entry_strips_nul_padding_only() {
        // A full 8-byte name has no NUL terminator and must survive intact.
        let mut buf = vec![0u8; 40];
        buf[0..8].copy_from_slice(b".rdata12");
        let entry = parse_section_entry(&buf).expect("valid entry");
        assert_eq!(entry.name, b".rdata12");
    }

    #[test]
    fn section_entry_rejects_short_buffer() {
        assert_eq!(parse_section_entry(&[0u8; 39]), None);
        assert_eq!(parse_section_entry(&[]), None);
    }
}
