//! All public enums and structs for the forensic artifact catalog.
// ── Core enums ───────────────────────────────────────────────────────────────

/// The kind of forensic artifact location.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    /// A registry key (container of values).
    RegistryKey,
    /// A specific registry value.
    RegistryValue,
    /// A file on disk.
    File,
    /// A directory on disk.
    Directory,
    /// A Windows Event Log channel.
    EventLog,
    /// A region of process/physical memory.
    MemoryRegion,
    /// Output collected during live response from a running system (lsof, ss, chkrootkit, etc.).
    LiveResponse,
    /// A structured database file (ESE/SQLite/etc.).
    DatabaseEntry,
}

/// Which Windows registry hive an artifact lives in.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiveTarget {
    HklmSystem,
    HklmSoftware,
    HklmSam,
    HklmSecurity,
    NtUser,
    UsrClass,
    Amcache,
    Bcd,
    /// Non-registry artifacts (files, event logs, memory).
    None,
}

/// Whether the artifact is per-user, system-wide, or mixed.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataScope {
    User,
    System,
    Network,
    Mixed,
}

/// Minimum OS version / platform required for the artifact to exist.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsScope {
    // ── Windows ──────────────────────────────────────────────────────────
    All,
    Win7Plus,
    Win8Plus,
    Win10Plus,
    Win11Plus,
    Win11_22H2,
    // ── Linux ────────────────────────────────────────────────────────────
    /// All Linux distributions (kernel + standard POSIX userland).
    Linux,
    /// systemd-based distros (Ubuntu 16.04+, Fedora 15+, Debian 8+, Arch).
    LinuxSystemd,
    /// Debian / Ubuntu specific paths or tools.
    LinuxDebian,
    /// Red Hat / CentOS / Fedora specific paths.
    LinuxRhel,
    // ── macOS ────────────────────────────────────────────────────────────
    /// All macOS versions (10.x+).
    MacOS,
    /// macOS 12 Monterey and later.
    MacOS12Plus,
    /// macOS 13 Ventura and later.
    MacOS13Plus,
    /// macOS 14 Sonoma and later.
    MacOS14Plus,
}

// ── Binary field layout ──────────────────────────────────────────────────────

/// Primitive type of a field inside a fixed-layout binary record.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFieldType {
    U16Le,
    U32Le,
    U64Le,
    I32Le,
    I64Le,
    FiletimeLe,
    Bytes { len: usize },
}

/// One field inside a fixed-layout binary record (e.g. the 72-byte UserAssist
/// value). Fully `const`-constructible.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryField {
    pub name: &'static str,
    pub offset: usize,
    pub field_type: BinaryFieldType,
    pub description: &'static str,
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Describes how to decode raw bytes (and/or a registry value name) into
/// structured fields.
///
/// This enum is intentionally **flat** -- no recursive `&'static Decoder` --
/// so every variant is usable in `const`/`static` context.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoder {
    /// Pass-through: interpret raw bytes as UTF-8 text. Single field "value".
    Identity,
    /// ROT13-decode the *name* parameter. Single field "program".
    Rot13Name,
    /// Read an 8-byte little-endian FILETIME at the given byte offset.
    FiletimeAt { offset: usize },
    /// Interpret raw bytes as UTF-16LE text.
    Utf16Le,
    /// Split the *name* (or raw as UTF-8) on `|` and zip with field names.
    PipeDelimited { fields: &'static [&'static str] },
    /// Read a little-endian u32 from raw bytes.
    DwordLe,
    /// REG_MULTI_SZ: NUL-separated UTF-16LE strings terminated by double NUL.
    MultiSz,
    /// MRUListEx: u32-LE index list terminated by 0xFFFFFFFF.
    MruListEx,
    /// Parse a fixed-layout binary record using the given field descriptors.
    BinaryRecord(&'static [BinaryField]),
    /// ROT13-decode the *name*, then parse the binary *value* using field
    /// descriptors. Combined output has "program" plus all binary fields.
    Rot13NameWithBinaryValue(&'static [BinaryField]),
    /// Extensible Storage Engine (ESE/JET Blue) database format.
    EseDatabase,
}

// ── Field schema (describes output fields) ───────────────────────────────────

/// The semantic type of a decoded output field value.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    Text,
    Integer,
    UnsignedInt,
    Timestamp,
    Bytes,
    Bool,
    List,
}

/// Describes one field in a decoded artifact record -- purely metadata, no data.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: &'static str,
    pub value_type: ValueType,
    pub description: &'static str,
    /// If `true`, this field participates in the record's unique identifier.
    pub is_uid_component: bool,
}

/// Triage collection priority for this artifact during live incident response.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TriagePriority {
    /// Must collect immediately — volatile, high forensic value, or credential exposure.
    Critical = 3,
    /// Collect in first pass — strong execution/persistence evidence.
    High = 2,
    /// Collect when time permits — useful but less time-sensitive.
    Medium = 1,
    /// Collect last — low volatility, supporting evidence only.
    Low = 0,
}

// ── ArtifactDescriptor (the catalog entry) ───────────────────────────────────

/// A single entry in the forensic artifact catalog. Fully `const`-constructible
/// so it can live in a `static`.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    /// Short machine-readable identifier, e.g. `"userassist"`.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// What kind of artifact location this is.
    pub artifact_type: ArtifactType,
    /// Which registry hive, or `None` for non-registry artifacts.
    pub hive: Option<HiveTarget>,
    /// Registry key path relative to the hive root (empty for non-registry).
    pub key_path: &'static str,
    /// Specific registry value name, if targeting a single value.
    pub value_name: Option<&'static str>,
    /// Filesystem path, for file/directory artifacts.
    pub file_path: Option<&'static str>,
    /// User vs System vs Mixed scope.
    pub scope: DataScope,
    /// Minimum OS version required.
    pub os_scope: OsScope,
    /// How to decode the raw data.
    pub decoder: Decoder,
    /// Forensic meaning / significance of this artifact.
    pub meaning: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: &'static [&'static str],
    /// Schema of the decoded output fields.
    pub fields: &'static [FieldSchema],
    /// How long this artifact typically persists before being overwritten or rotated.
    /// `None` means indefinite (registry keys, most files until explicitly deleted).
    pub retention: Option<&'static str>,
    /// Live triage collection priority.
    pub triage_priority: TriagePriority,
    /// IDs of related catalog descriptors useful for cross-correlation.
    pub related_artifacts: &'static [&'static str],
    /// Authoritative external references for this artifact (SANS, Harlan Carvey,
    /// Brian Carrier, Red Canary, Microsoft docs, MITRE ATT&CK, etc.).
    /// Every production entry should have at least one URL.
    pub sources: &'static [&'static str],
}

/// How to acquire and enumerate the outer container that holds one or more
/// forensic artifacts.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerProfile {
    /// Machine-readable identifier, e.g. `windows_registry_hive`.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// Summary of what the container represents.
    pub summary: &'static str,
    /// High-signal acquisition and enumeration guidance.
    pub parser_hints: &'static [&'static str],
    /// Authoritative references that justify the container guidance.
    pub sources: &'static [&'static str],
}

/// How to recognize or carve a container format from raw bytes.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerSignature {
    /// Container id this signature belongs to.
    pub container_id: &'static str,
    /// Human-readable name for the signature.
    pub name: &'static str,
    /// Expected magic or marker bytes near the start of the structure.
    pub header_magic: &'static [u8],
    /// Optional footer or trailer bytes when the format has a stable trailer.
    pub footer_magic: &'static [u8],
    /// Byte offset where `header_magic` is expected.
    pub header_offset: usize,
    /// Minimum plausible container size.
    pub min_size: Option<usize>,
    /// Expected alignment or page/chunk size when applicable.
    pub alignment: Option<usize>,
    /// Structural validation rules beyond simple magic bytes.
    pub invariants: &'static [&'static str],
    /// Authoritative references for the signature or structure rules.
    pub sources: &'static [&'static str],
}

/// Parsing guidance for artifacts whose interpretation requires more than a
/// flat decoder or field schema.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactParsingProfile {
    /// Catalog artifact id this guidance applies to.
    pub artifact_id: &'static str,
    /// Storage or serialization format analysts should expect.
    pub format: &'static str,
    /// Short summary of the parsing model.
    pub summary: &'static str,
    /// High-signal parser notes and workflow guidance.
    pub parser_hints: &'static [&'static str],
    /// Semantically important fields or entities to extract.
    pub extracted_fields: &'static [&'static str],
    /// Authoritative references that justify the parsing guidance.
    pub sources: &'static [&'static str],
}

/// How to recognize or validate individual records or payloads inside a
/// container, including carved fragments.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSignature {
    /// Machine-readable record identifier.
    pub id: &'static str,
    /// Parent container id.
    pub container_id: &'static str,
    /// Optional artifact id this signature is directly associated with.
    pub artifact_id: Option<&'static str>,
    /// Human-readable display name.
    pub name: &'static str,
    /// Expected magic or marker bytes near the start of the record.
    pub header_magic: &'static [u8],
    /// Optional footer or trailer bytes when present and stable.
    pub footer_magic: &'static [u8],
    /// Byte offset where `header_magic` is expected.
    pub header_offset: usize,
    /// Minimum plausible record size.
    pub min_size: Option<usize>,
    /// Expected alignment or chunking rule.
    pub alignment: Option<usize>,
    /// Structural validation rules beyond simple magic bytes.
    pub invariants: &'static [&'static str],
    /// Authoritative references for the record structure.
    pub sources: &'static [&'static str],
}

// ── ArtifactValue (universal decoded value) ──────────────────────────────────

/// A decoded value produced by the catalog's decode logic. Uses only `std` types.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactValue {
    Text(String),
    Integer(i64),
    UnsignedInt(u64),
    Timestamp(String),
    Bytes(Vec<u8>),
    Bool(bool),
    List(Vec<ArtifactValue>),
    Map(Vec<(String, ArtifactValue)>),
    Null,
}

// ── ArtifactRecord (universal decoded output) ────────────────────────────────

/// A fully decoded forensic artifact record. This is the universal output type
/// that all consumers receive -- no raw bytes, no hardcoded field names.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactRecord {
    /// Globally unique URI, e.g. `winreg://HKCU/Software/.../value_name` or
    /// `file:///path/to/file#line`.
    pub uid: String,
    /// The catalog entry id that produced this record.
    pub artifact_id: &'static str,
    /// Human-readable artifact name.
    pub artifact_name: &'static str,
    /// Data scope (User/System/...).
    pub scope: DataScope,
    /// OS scope.
    pub os_scope: OsScope,
    /// Primary timestamp in ISO 8601 UTC, if the artifact has one.
    pub timestamp: Option<String>,
    /// Ordered decoded field name-value pairs.
    pub fields: Vec<(&'static str, ArtifactValue)>,
    /// Human-readable meaning, possibly with interpolated field values.
    pub meaning: String,
    /// MITRE ATT&CK technique IDs applicable to this record.
    pub mitre_techniques: Vec<&'static str>,
    /// Confidence score 0.0-1.0, set by the decoder or classifier.
    pub confidence: f32,
}

// ── ArtifactQuery (filter parameters) ────────────────────────────────────────

/// Filter parameters for querying the catalog. All fields are optional --
/// `None` means "match any".
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Default)]
pub struct ArtifactQuery {
    pub scope: Option<DataScope>,
    pub os_scope: Option<OsScope>,
    pub artifact_type: Option<ArtifactType>,
    pub hive: Option<HiveTarget>,
    pub mitre_technique: Option<&'static str>,
    pub id: Option<&'static str>,
}

// ── DecodeError ──────────────────────────────────────────────────────────────

/// Errors that can occur during artifact decoding.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The raw data buffer is too short for the decoder to operate.
    BufferTooShort { expected: usize, actual: usize },
    /// The raw data is not valid UTF-8 where UTF-8 was expected.
    InvalidUtf8,
    /// The raw data is not valid UTF-16LE.
    InvalidUtf16,
    /// A binary field offset+size exceeds the buffer length.
    FieldOutOfBounds {
        field: &'static str,
        offset: usize,
        size: usize,
        buf_len: usize,
    },
    /// The decoder variant does not apply to this data shape.
    UnsupportedDecoder(&'static str),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: need {expected} bytes, got {actual}")
            }
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in raw data"),
            Self::InvalidUtf16 => write!(f, "invalid UTF-16LE in raw data"),
            Self::FieldOutOfBounds {
                field,
                offset,
                size,
                buf_len,
            } => write!(
                f,
                "field '{field}' at offset {offset} size {size} exceeds buffer length {buf_len}"
            ),
            Self::UnsupportedDecoder(msg) => write!(f, "unsupported decoder: {msg}"),
        }
    }
}

impl std::error::Error for DecodeError {}
// ── ForensicCatalog ──────────────────────────────────────────────────────────

/// A queryable collection of [`ArtifactDescriptor`]s with built-in decode logic.
pub struct ForensicCatalog {
    entries: &'static [ArtifactDescriptor],
}

impl ForensicCatalog {
    /// Create a new catalog from a static slice of descriptors.
    pub const fn new(entries: &'static [ArtifactDescriptor]) -> Self {
        Self { entries }
    }

    /// Return all descriptors in the catalog.
    pub fn list(&self) -> &[ArtifactDescriptor] {
        self.entries
    }

    /// Look up a descriptor by its `id` field.
    pub fn by_id(&self, id: &str) -> Option<&ArtifactDescriptor> {
        self.entries.iter().find(|d| d.id == id)
    }

    /// Return all descriptors matching the given query. Every `Some` field in
    /// the query must match; `None` fields are wildcards.
    pub fn filter(&self, query: &ArtifactQuery) -> Vec<&ArtifactDescriptor> {
        self.entries
            .iter()
            .filter(|d| {
                if let Some(scope) = query.scope {
                    if d.scope != scope {
                        return false;
                    }
                }
                if let Some(os) = query.os_scope {
                    if d.os_scope != os {
                        return false;
                    }
                }
                if let Some(at) = query.artifact_type {
                    if d.artifact_type != at {
                        return false;
                    }
                }
                if let Some(hive) = query.hive {
                    if d.hive != Some(hive) {
                        return false;
                    }
                }
                if let Some(tech) = query.mitre_technique {
                    if !d.mitre_techniques.contains(&tech) {
                        return false;
                    }
                }
                if let Some(id) = query.id {
                    if d.id != id {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Return all descriptors associated with the given MITRE ATT&CK technique ID.
    pub fn by_mitre(&self, technique: &str) -> Vec<&ArtifactDescriptor> {
        self.entries
            .iter()
            .filter(|d| d.mitre_techniques.contains(&technique))
            .collect()
    }

    /// Return all descriptors sorted by triage priority descending (Critical first).
    /// Within the same priority, original catalog order is preserved.
    pub fn for_triage(&self) -> Vec<&ArtifactDescriptor> {
        let mut v: Vec<&ArtifactDescriptor> = self.entries.iter().collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.triage_priority));
        v
    }

    /// Return all descriptors whose `meaning` or `name` contains `keyword`
    /// (case-insensitive).
    pub fn filter_by_keyword(&self, keyword: &str) -> Vec<&ArtifactDescriptor> {
        let kw = keyword.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|d| {
                d.meaning.to_ascii_lowercase().contains(&kw)
                    || d.name.to_ascii_lowercase().contains(&kw)
            })
            .collect()
    }
}
