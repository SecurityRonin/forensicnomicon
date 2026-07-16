//! Container profiles, container signatures, artifact-container bindings,
//! record signatures, parsing profiles, and the infer_container_profile helper.

use super::types::{
    ArtifactDescriptor, ArtifactLocation, ArtifactParsingProfile, ContainerProfile,
    ContainerSignature, RecordSignature,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ArtifactContainerBinding {
    pub(super) artifact_id: &'static str,
    pub(super) container_id: &'static str,
}

const WINDOWS_REGISTRY_HIVE_HINTS: &[&str] = &[
    "Open the hive as an offline Registry container and enumerate keys, values, and raw value bytes.",
    "Replay transaction logs when available before trusting key/value state from a copied hive.",
    "Preserve the original value name and raw bytes so artifact-specific decoders can interpret them correctly.",
];

const REGISTRY_HIVE_INVARIANTS: &[&str] = &[
    "Header begins with the ASCII signature 'regf' at offset 0.",
    "Primary hive bins normally begin with 'hbin' on 0x1000 boundaries after the 4 KB hive header.",
    "Cell records use signed size fields; negative values indicate allocated cells.",
];

const SQLITE_DATABASE_INVARIANTS: &[&str] = &[
    "Header begins with 'SQLite format 3\\0' at offset 0.",
    "Database page size is stored in the header and should be a power of two between 512 and 65536.",
];

const ESE_DATABASE_INVARIANTS: &[&str] = &[
    "Header begins with the ESE/Jet signature at offset 4.",
    "Page-based structure should remain consistent with the recorded page size and checksum rules.",
];

const OLE_COMPOUND_FILE_INVARIANTS: &[&str] = &[
    "Header begins with the OLE compound file signature at offset 0.",
    "Sector size and FAT/DIFAT fields must be internally consistent before trusting carved data.",
];

const EVTX_INVARIANTS: &[&str] = &[
    "File header begins with 'ElfFile\\0' and chunks begin with 'ElfChnk\\0'.",
    "Chunk headers and record offsets must be internally consistent before trusting carved events.",
];

const USERASSIST_RECORD_INVARIANTS: &[&str] = &[
    "Value name is ROT13-encoded and must be decoded before path interpretation.",
    "Win7+ Count payload is 72 bytes with last_run FILETIME at offset 60.",
];

const REGISTRY_NK_INVARIANTS: &[&str] = &[
    "Record begins with the 'nk' key-cell signature.",
    "Cell size and subkey/value offsets must remain within the parent hive bin.",
];

const REGISTRY_VK_INVARIANTS: &[&str] = &[
    "Record begins with the 'vk' value-cell signature.",
    "Name length, data length, and data offset must remain within the parent hive bin or data cell.",
];

const SQLITE_PAGE_INVARIANTS: &[&str] =
    &["B-tree page header and cell pointers must remain within the declared page size."];

const OLE_DIR_STREAM_INVARIANTS: &[&str] = &[
    "Directory entries are 128-byte records whose sibling/child references must remain internally consistent.",
];

const EVTX_CHUNK_INVARIANTS: &[&str] =
    &["Chunk begins with 'ElfChnk\\0' and normally spans 64 KB."];

const EVTX_RECORD_INVARIANTS: &[&str] = &[
    "EVTX records begin with the 0x2a 0x2a 0x00 0x00 signature and end with their declared size.",
];

const MEMORY_FRAGMENT_INVARIANTS: &[&str] = &[
    "Memory-bearing sources rarely have a stable footer; validate carved fragments by internal structure and cross-artifact corroboration.",
];

const SQLITE_DATABASE_HINTS: &[&str] = &[
    "Open the file as a SQLite database and enumerate schema, tables, and rows before applying artifact-specific queries.",
    "Preserve raw cell values and timestamps so higher-level artifact logic can normalize them safely.",
];

const ESE_DATABASE_HINTS: &[&str] = &[
    "Treat the file as an Extensible Storage Engine database and enumerate tables, columns, and records.",
    "Be prepared for dirty-state handling and page-level recovery when working from copied live systems.",
];

const OLE_COMPOUND_FILE_HINTS: &[&str] = &[
    "Open the file as an OLE compound file and enumerate storages and streams before interpreting embedded records.",
    "Preserve stream names and raw stream bytes so artifact-specific parsers can resolve AppIDs, LNK blocks, or other structured payloads.",
];

const EVTX_HINTS: &[&str] = &[
    "Open the file or channel as an EVTX container and enumerate records with their event IDs, providers, timestamps, and XML payloads.",
    "Keep both rendered and raw event data available so artifact-specific logic can cross-check field extraction.",
];

const MEMORY_IMAGE_HINTS: &[&str] = &[
    "Treat the source as a memory-bearing container whose pages must be reconstructed before higher-level artifact interpretation.",
    "Preserve page-level provenance so extracted processes, sockets, strings, and handles can be tied back to the source image.",
];

const FLAT_FILE_HINTS: &[&str] = &[
    "Treat the source as a flat file or directory artifact and preserve raw bytes, filenames, and timestamps before any higher-level interpretation.",
];

const VMWARE_VMDK_HINTS: &[&str] = &[
    "Read the embedded or sidecar text descriptor first: its createType selects the layout (monolithicSparse, twoGbMaxExtent*, vmfsSparse, seSparse, streamOptimized, flat, or device-map) and its extent lines name the companion files to collect.",
    "For sparse layouts, resolve the virtual disk through the two-level grain directory / grain table: a grain-table entry of 0 is sparse and 1 is an explicitly zeroed grain (header version 2+).",
    "For streamOptimized, allocated grains are zlib (RFC 1950) compressed behind a 12-byte GrainMarker; a primary gdOffset of 0xFFFFFFFFFFFFFFFF means the real grain directory is in the footer header at file_end-1024.",
    "Collect every companion extent (and, for delta disks, the parent chain via parentFileNameHint) before treating the virtual disk as complete.",
];

const VMDK_INVARIANTS: &[&str] = &[
    "VMDK4 sparse extents begin with the little-endian magic 'KDMV' (0x564D444B) at offset 0; the 512-byte header carries capacity, grainSize, gdOffset, and compressAlgorithm.",
    "ESXi COWD (vmfsSparse/vmfsThin) extents begin with the big-endian magic 'COWD' at offset 0, use 32-bit fields, and place the grain directory at sector 4 with 4096 entries per grain table.",
    "seSparse (VMFS6) extents begin with the u64 constant-header magic 0x00000000CAFEBABE at offset 0 and a volatile header (0x00000000CAFECAFE) at sector 1; grain size is fixed at 8 sectors and grain entries are nibble-typed with a bit-rotated grain index.",
    "A text descriptor (createType=...) may stand alone and reference one or more extent files; flat/VMFS/ZERO extents hold raw data while SPARSE/VMFSSPARSE/SESPARSE extents are binary with their own headers.",
];

const VHDX_HINTS: &[&str] = &[
    "Validate against both header copies (offset 0x10000 and 0x20000) and use the one with the highest SequenceNumber whose CRC-32C checks out.",
    "Resolve the Block Allocation Table via the Metadata and BAT regions named by the region table; a BAT entry state of 6 = fully present, 0 = not present.",
    "Replay the log before trusting BAT/metadata state on a dirty image.",
];
const VHDX_INVARIANTS: &[&str] = &[
    "Begins with the 8-byte file identifier 'vhdxfile' at offset 0.",
    "Two 'head'-signed header copies live at 64 KiB and 128 KiB; two 'regi'-signed region tables at 192 KiB and 256 KiB; all checksums are CRC-32C (poly 0x82F63B78).",
];

const VHD_HINTS: &[&str] = &[
    "Read the 512-byte 'conectix' footer at end-of-file for diskType, currentSize, and (for dynamic/differencing) the dataOffset of the 'cxsparse' header.",
    "A fixed VHD has dataOffset = 0xFFFFFFFFFFFFFFFF and is raw data plus the footer; dynamic/differencing VHDs use a Block Allocation Table reached from the dynamic header.",
];
const VHD_INVARIANTS: &[&str] = &[
    "Ends with a 512-byte footer whose cookie is 'conectix'; dynamic/differencing disks repeat the footer at offset 0 and add a 'cxsparse' 1024-byte dynamic header.",
    "diskType is 2 (fixed), 3 (dynamic), or 4 (differencing); the footer checksum is the one's-complement of the footer with the checksum field zeroed.",
];

const QCOW2_HINTS: &[&str] = &[
    "Parse the big-endian header for cluster_bits, virtual size, and the L1 table offset, then walk L1 -> L2 -> cluster to resolve guest offsets.",
    "Refuse the image if any incompatible_features bit you do not understand is set; bit 0 (dirty) and bit 1 (corrupt) indicate the image needs repair.",
    "L2 entries with bit 62 set point to a zlib (or zstd) compressed cluster; a backing_file_offset names a parent image that must also be collected.",
];
const QCOW2_INVARIANTS: &[&str] = &[
    "Begins with the big-endian magic 'QFI\\xfb' (0x514649FB) at offset 0; version is 2 or 3.",
    "cluster_bits is in 9..=21 (512 B .. 2 MiB clusters); v3 adds the 64-bit incompatible/compatible/autoclear feature words at offset 0x48.",
];

const EWF_HINTS: &[&str] = &[
    "Identify the variant by the 8-byte signature: 'EVF\\x09\\x0d\\x0a\\xff\\x00' = EWF1 (.E01), 'EVF2..' = Ex01, 'LEF2..' = Lx01 logical evidence.",
    "Walk the section chain (header, volume/disk, table/sectors, ... done) and collect every segment file (.E01, .E02, ...) — the acquisition spans all of them.",
    "Verify the stored MD5/SHA-1 hash and per-chunk Adler-32 to confirm integrity before relying on the evidence.",
];
const EWF_INVARIANTS: &[&str] = &[
    "Begins with one of the 8-byte EVF/EVF2/LEF2 signatures at offset 0.",
    "Data is stored as compressed or raw chunks indexed by 'table' sections; the high bit of each EWF1 table offset flags a compressed chunk.",
];

const AFF4_HINTS: &[&str] = &[
    "Open the file as a ZIP container and read 'information.turtle' (RDF) to discover the aff4:ImageStream or aff4:Map that backs the disk image.",
    "For ImageStreams, reassemble data from chunked bevy segments (default 32 KiB chunks, 2048 chunks per bevy); for Map-backed images, follow the map ranges to ImageStream / Zero / SymbolicStream targets.",
];
const AFF4_INVARIANTS: &[&str] = &[
    "Is a ZIP container: offset 0 is the local-file-header magic 'PK\\x03\\x04'; metadata lives in the 'information.turtle' segment.",
    "Object identifiers use the aff4:// URI scheme and the http://aff4.org/Schema# RDF namespace.",
];

const DMG_HINTS: &[&str] = &[
    "Read the 512-byte 'koly' trailer at end-of-file for the XML property-list offset/length and the total sector count; there is no header magic.",
    "Parse the plist's blkx entries (each a 'mish' block table) and decode chunks by type: 0 zero-fill, 1 raw, 0x80000005 zlib, 0x80000006 bzip2, 0x80000007 LZFSE.",
];
const DMG_INVARIANTS: &[&str] = &[
    "Ends with a 512-byte big-endian 'koly' (0x6B6F6C79) trailer; the decode tables are 'mish' (0x6D697368) BLKX block tables referenced from the XML plist.",
    "Chunk entry type 0xFFFFFFFF terminates a block table and 0x7FFFFFFE is a comment.",
];

static CONTAINER_PROFILES: &[ContainerProfile] = &[
    ContainerProfile {
        id: "windows_registry_hive",
        name: "Windows Registry Hive",
        summary: "Offline Windows Registry hive containing keys, values, value names, and raw value bytes.",
        parser_hints: WINDOWS_REGISTRY_HIVE_HINTS,
        sources: &[
            "https://github.com/mkorman90/regipy",
            "https://github.com/EricZimmerman/Registry",
            "https://github.com/EricZimmerman/RECmd",
        ],
    },
    ContainerProfile {
        id: "sqlite_database",
        name: "SQLite Database",
        summary: "SQLite database used by browser, timeline, and other application artifacts.",
        parser_hints: SQLITE_DATABASE_HINTS,
        sources: &[
            "https://github.com/EricZimmerman/SQLECmd",
            "https://github.com/EricZimmerman/WxTCmd",
            "https://github.com/EricZimmerman/DFIR-SQL-Query-Repo",
        ],
    },
    ContainerProfile {
        id: "ese_database",
        name: "ESE Database",
        summary: "Extensible Storage Engine database used by Windows Search and related Windows subsystems.",
        parser_hints: ESE_DATABASE_HINTS,
        sources: &[
            "https://github.com/EricZimmerman/WinSearchDBAnalyzer",
            "https://www.sans.org/blog/windows-search-index-forensics/",
        ],
    },
    ContainerProfile {
        id: "ole_compound_file",
        name: "OLE Compound File",
        summary: "Compound file binary format used by Jump Lists and other multi-stream Windows artifacts.",
        parser_hints: OLE_COMPOUND_FILE_HINTS,
        sources: &[
            "https://github.com/EricZimmerman/OleCf",
            "https://github.com/EricZimmerman/JLECmd",
            "https://github.com/EricZimmerman/LECmd",
        ],
    },
    ContainerProfile {
        id: "windows_evtx",
        name: "Windows EVTX",
        summary: "Windows Event Log file or channel containing structured event records.",
        parser_hints: EVTX_HINTS,
        sources: &[
            "https://github.com/EricZimmerman/evtx",
            "https://attack.mitre.org/techniques/T1070/001/",
        ],
    },
    ContainerProfile {
        id: "memory_image",
        name: "Memory Image",
        summary: "Memory-bearing container such as hiberfil.sys or a paging artifact.",
        parser_hints: MEMORY_IMAGE_HINTS,
        sources: &[
            "https://forensics.wiki/hiberfil.sys/",
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options",
        ],
    },
    ContainerProfile {
        id: "flat_file",
        name: "Flat File",
        summary: "Standalone file or directory artifact without a richer outer container model.",
        parser_hints: FLAT_FILE_HINTS,
        sources: &[
            "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file",
        ],
    },
    ContainerProfile {
        id: "vmware_vmdk",
        name: "VMware VMDK Disk Image",
        summary: "VMware virtual disk container (monolithicSparse, streamOptimized, twoGbMaxExtent*, vmfsSparse/vmfsThin COWD, seSparse, flat, or device-map) holding a guest virtual disk whose sectors must be reconstructed before filesystem analysis.",
        parser_hints: VMWARE_VMDK_HINTS,
        sources: &[
            "https://github.com/libyal/libvmdk/blob/main/documentation/VMware%20Virtual%20Disk%20Format%20(VMDK).asciidoc",
            "https://github.com/qemu/qemu/blob/master/block/vmdk.c",
        ],
    },
    ContainerProfile {
        id: "microsoft_vhdx",
        name: "Microsoft VHDX Disk Image",
        summary: "Hyper-V / Windows 8+ / WSL2 / Azure virtual disk with dual headers, a region table, a Block Allocation Table, and a log for crash consistency.",
        parser_hints: VHDX_HINTS,
        sources: &[
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/",
        ],
    },
    ContainerProfile {
        id: "microsoft_vhd",
        name: "Microsoft VHD Disk Image (legacy)",
        summary: "Legacy Virtual PC / Hyper-V Gen-1 virtual disk: fixed, dynamic, or differencing, identified by a 'conectix' footer at end-of-file.",
        parser_hints: VHD_HINTS,
        sources: &[
            "https://www.microsoft.com/en-us/download/details.aspx?id=23850",
        ],
    },
    ContainerProfile {
        id: "qemu_qcow2",
        name: "QEMU QCOW2 Disk Image",
        summary: "QEMU / KVM / libvirt copy-on-write virtual disk (v2/v3) with two-level L1/L2 cluster mapping, optional compression, encryption, and backing files.",
        parser_hints: QCOW2_HINTS,
        sources: &[
            "https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt",
        ],
    },
    ContainerProfile {
        id: "ewf_image",
        name: "Expert Witness Format (E01/Ex01/L01)",
        summary: "Dominant professional forensic acquisition container: chunked, compressed, hashed evidence segments (EWF1 .E01, EWF2 Ex01, logical Lx01).",
        parser_hints: EWF_HINTS,
        sources: &[
            "https://github.com/libyal/libewf/tree/main/documentation",
        ],
    },
    ContainerProfile {
        id: "aff4_image",
        name: "AFF4 Forensic Image",
        summary: "ZIP-based Advanced Forensic Format 4 container with RDF/Turtle metadata; disk images are aff4:ImageStream bevies or aff4:Map-backed streams.",
        parser_hints: AFF4_HINTS,
        sources: &[
            "https://github.com/aff4/Standard",
        ],
    },
    ContainerProfile {
        id: "apple_dmg",
        name: "Apple DMG / UDIF Disk Image",
        summary: "macOS disk image with a 512-byte 'koly' trailer, an XML property list, and 'mish' BLKX block tables whose chunks are raw, zero, or zlib/bzip2/LZFSE compressed.",
        parser_hints: DMG_HINTS,
        sources: &[
            "http://newosxbook.com/DMG.html",
        ],
    },
];

static REGF_MAGIC: &[u8] = b"regf";
static VMDK4_MAGIC_BYTES: &[u8] = b"KDMV"; // little-endian 0x564D444B
static COWD_MAGIC_BYTES: &[u8] = b"COWD"; // big-endian, ESXi vmfsSparse/vmfsThin
static SESPARSE_MAGIC_BYTES: &[u8] = &[0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00]; // u64 LE 0xCAFEBABE
static VHDX_MAGIC_BYTES: &[u8] = b"vhdxfile";
static VHD_FOOTER_COOKIE: &[u8] = b"conectix";
static QCOW2_MAGIC_BYTES: &[u8] = &[0x51, 0x46, 0x49, 0xFB]; // big-endian "QFI\xfb"
static EVF1_MAGIC_BYTES: &[u8] = &[0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00]; // EWF1 .E01
static AFF4_ZIP_MAGIC_BYTES: &[u8] = b"PK\x03\x04"; // ZIP local file header
static DMG_KOLY_COOKIE: &[u8] = b"koly"; // 512-byte trailer at end-of-file
static SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
static ESE_MAGIC: &[u8] = &[0xef, 0xcd, 0xab, 0x89];
static OLE_MAGIC: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
static EVTX_FILE_MAGIC: &[u8] = b"ElfFile\0";
static MEMORY_MAGIC: &[u8] = &[];
static NK_MAGIC: &[u8] = b"nk";
static VK_MAGIC: &[u8] = b"vk";
static EVTX_CHUNK_MAGIC: &[u8] = b"ElfChnk\0";
static EVTX_RECORD_MAGIC: &[u8] = &[0x2a, 0x2a, 0x00, 0x00];

static CONTAINER_SIGNATURES: &[ContainerSignature] = &[
    ContainerSignature {
        container_id: "windows_registry_hive",
        name: "Windows Registry Hive Signature",
        header_magic: REGF_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(4096),
        alignment: Some(4096),
        invariants: REGISTRY_HIVE_INVARIANTS,
        sources: &[
            "https://github.com/mkorman90/regipy",
            "https://github.com/EricZimmerman/Registry",
        ],
    },
    ContainerSignature {
        container_id: "sqlite_database",
        name: "SQLite Database Header",
        header_magic: SQLITE_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(100),
        alignment: None,
        invariants: SQLITE_DATABASE_INVARIANTS,
        sources: &[
            "https://github.com/EricZimmerman/SQLECmd",
            "https://github.com/EricZimmerman/DFIR-SQL-Query-Repo",
        ],
    },
    ContainerSignature {
        container_id: "ese_database",
        name: "ESE Database Header",
        header_magic: ESE_MAGIC,
        footer_magic: &[],
        header_offset: 4,
        min_size: Some(4096),
        alignment: Some(4096),
        invariants: ESE_DATABASE_INVARIANTS,
        sources: &[
            "https://github.com/EricZimmerman/WinSearchDBAnalyzer",
        ],
    },
    ContainerSignature {
        container_id: "ole_compound_file",
        name: "OLE Compound File Header",
        header_magic: OLE_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(512),
        alignment: Some(512),
        invariants: OLE_COMPOUND_FILE_INVARIANTS,
        sources: &[
            "https://github.com/EricZimmerman/OleCf",
        ],
    },
    ContainerSignature {
        container_id: "windows_evtx",
        name: "Windows EVTX File Header",
        header_magic: EVTX_FILE_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(4096),
        alignment: Some(4096),
        invariants: EVTX_INVARIANTS,
        sources: &[
            "https://github.com/EricZimmerman/evtx",
        ],
    },
    ContainerSignature {
        container_id: "memory_image",
        name: "Memory-Bearing Container Signature",
        header_magic: MEMORY_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: None,
        alignment: Some(4096),
        invariants: MEMORY_FRAGMENT_INVARIANTS,
        sources: &[
            "https://forensics.wiki/hiberfil.sys/",
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options",
        ],
    },
    ContainerSignature {
        container_id: "vmware_vmdk",
        name: "VMDK Sparse Extent Header (KDMV)",
        header_magic: VMDK4_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(512),
        alignment: Some(512),
        invariants: VMDK_INVARIANTS,
        sources: &[
            "https://github.com/libyal/libvmdk/blob/main/documentation/VMware%20Virtual%20Disk%20Format%20(VMDK).asciidoc",
        ],
    },
    ContainerSignature {
        container_id: "vmware_vmdk",
        name: "VMDK COWD Sparse Extent Header (vmfsSparse/vmfsThin)",
        header_magic: COWD_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(2048),
        alignment: Some(512),
        invariants: VMDK_INVARIANTS,
        sources: &[
            "https://github.com/qemu/qemu/blob/master/block/vmdk.c",
        ],
    },
    ContainerSignature {
        container_id: "vmware_vmdk",
        name: "VMDK seSparse Constant Header (0xCAFEBABE)",
        header_magic: SESPARSE_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(512),
        alignment: Some(512),
        invariants: VMDK_INVARIANTS,
        sources: &[
            "https://github.com/qemu/qemu/blob/master/block/vmdk.c",
        ],
    },
    ContainerSignature {
        container_id: "microsoft_vhdx",
        name: "VHDX File Identifier",
        header_magic: VHDX_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(0x10_0000),
        alignment: Some(0x1_0000),
        invariants: VHDX_INVARIANTS,
        sources: &["https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/"],
    },
    ContainerSignature {
        container_id: "microsoft_vhd",
        name: "VHD conectix Footer",
        header_magic: &[],
        footer_magic: VHD_FOOTER_COOKIE,
        header_offset: 0,
        min_size: Some(512),
        alignment: Some(512),
        invariants: VHD_INVARIANTS,
        sources: &["https://www.microsoft.com/en-us/download/details.aspx?id=23850"],
    },
    ContainerSignature {
        container_id: "qemu_qcow2",
        name: "QCOW2 Header Magic",
        header_magic: QCOW2_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(72),
        alignment: None,
        invariants: QCOW2_INVARIANTS,
        sources: &["https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt"],
    },
    ContainerSignature {
        container_id: "ewf_image",
        name: "EWF1 EVF Signature",
        header_magic: EVF1_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(13),
        alignment: None,
        invariants: EWF_INVARIANTS,
        sources: &["https://github.com/libyal/libewf/tree/main/documentation"],
    },
    ContainerSignature {
        container_id: "aff4_image",
        name: "AFF4 ZIP Local File Header",
        header_magic: AFF4_ZIP_MAGIC_BYTES,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(22),
        alignment: None,
        invariants: AFF4_INVARIANTS,
        sources: &["https://github.com/aff4/Standard"],
    },
    ContainerSignature {
        container_id: "apple_dmg",
        name: "DMG koly Trailer",
        header_magic: &[],
        footer_magic: DMG_KOLY_COOKIE,
        header_offset: 0,
        min_size: Some(512),
        alignment: None,
        invariants: DMG_INVARIANTS,
        sources: &["http://newosxbook.com/DMG.html"],
    },
];

static ARTIFACT_CONTAINER_BINDINGS: &[ArtifactContainerBinding] = &[
    ArtifactContainerBinding {
        artifact_id: "windows_timeline",
        container_id: "sqlite_database",
    },
    ArtifactContainerBinding {
        artifact_id: "chrome_login_data",
        container_id: "sqlite_database",
    },
    ArtifactContainerBinding {
        artifact_id: "chrome_cookies",
        container_id: "sqlite_database",
    },
    ArtifactContainerBinding {
        artifact_id: "search_db_user",
        container_id: "ese_database",
    },
    ArtifactContainerBinding {
        artifact_id: "jump_list_auto",
        container_id: "ole_compound_file",
    },
    ArtifactContainerBinding {
        artifact_id: "jump_list_custom",
        container_id: "ole_compound_file",
    },
    ArtifactContainerBinding {
        artifact_id: "jump_list_system",
        container_id: "ole_compound_file",
    },
    ArtifactContainerBinding {
        artifact_id: "hiberfil_sys",
        container_id: "memory_image",
    },
    ArtifactContainerBinding {
        artifact_id: "pagefile_sys",
        container_id: "memory_image",
    },
];

static RECORD_SIGNATURES: &[RecordSignature] = &[
    RecordSignature {
        id: "registry_nk_cell",
        container_id: "windows_registry_hive",
        artifact_id: None,
        name: "Registry Key Cell (nk)",
        header_magic: NK_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(0x4c),
        alignment: None,
        invariants: REGISTRY_NK_INVARIANTS,
        sources: &[
            "https://github.com/mkorman90/regipy",
            "https://github.com/EricZimmerman/Registry",
        ],
    },
    RecordSignature {
        id: "registry_vk_cell",
        container_id: "windows_registry_hive",
        artifact_id: None,
        name: "Registry Value Cell (vk)",
        header_magic: VK_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(0x18),
        alignment: None,
        invariants: REGISTRY_VK_INVARIANTS,
        sources: &[
            "https://github.com/mkorman90/regipy",
            "https://github.com/EricZimmerman/Registry",
        ],
    },
    RecordSignature {
        id: "userassist_count_payload",
        container_id: "windows_registry_hive",
        artifact_id: Some("userassist_exe"),
        name: "UserAssist Count Payload",
        header_magic: &[],
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(72),
        alignment: None,
        invariants: USERASSIST_RECORD_INVARIANTS,
        sources: &[
            "http://windowsir.blogspot.com/2013/05/userassist-redux.html",
            "https://github.com/EricZimmerman/RegistryPlugins",
        ],
    },
    RecordSignature {
        id: "sqlite_btree_page",
        container_id: "sqlite_database",
        artifact_id: None,
        name: "SQLite B-tree Page",
        header_magic: &[],
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(512),
        alignment: Some(512),
        invariants: SQLITE_PAGE_INVARIANTS,
        sources: &["https://github.com/EricZimmerman/SQLECmd"],
    },
    RecordSignature {
        id: "ole_directory_entry",
        container_id: "ole_compound_file",
        artifact_id: None,
        name: "OLE Directory Entry",
        header_magic: &[],
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(128),
        alignment: Some(128),
        invariants: OLE_DIR_STREAM_INVARIANTS,
        sources: &["https://github.com/EricZimmerman/OleCf"],
    },
    RecordSignature {
        id: "evtx_chunk",
        container_id: "windows_evtx",
        artifact_id: None,
        name: "EVTX Chunk",
        header_magic: EVTX_CHUNK_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(65536),
        alignment: Some(65536),
        invariants: EVTX_CHUNK_INVARIANTS,
        sources: &["https://github.com/EricZimmerman/evtx"],
    },
    RecordSignature {
        id: "evtx_record",
        container_id: "windows_evtx",
        artifact_id: None,
        name: "EVTX Record",
        header_magic: EVTX_RECORD_MAGIC,
        footer_magic: &[],
        header_offset: 0,
        min_size: Some(24),
        alignment: None,
        invariants: EVTX_RECORD_INVARIANTS,
        sources: &["https://github.com/EricZimmerman/evtx"],
    },
];

fn infer_container_profile(descriptor: &ArtifactDescriptor) -> Option<&'static ContainerProfile> {
    if descriptor.hive.is_some() {
        return container_profile("windows_registry_hive");
    }

    match descriptor.artifact_type {
        ArtifactLocation::EventLog => container_profile("windows_evtx"),
        ArtifactLocation::File | ArtifactLocation::Directory => container_profile("flat_file"),
        _ => None,
    }
}

/// Public-to-parent wrapper so `catalog/mod.rs` can call `infer_container_profile`
/// without exposing it to external crate users.
pub(super) fn infer_container_profile_pub(
    descriptor: &ArtifactDescriptor,
) -> Option<&'static ContainerProfile> {
    infer_container_profile(descriptor)
}

const USERASSIST_PARSER_HINTS: &[&str] = &[
    "Decode the registry value name with ROT13 before treating it as a program or folder path.",
    "For Win7+ Count values, parse the binary payload as a fixed 72-byte structure rather than plain text.",
    "Use offset 4 for run_count, 8 for focus_count, 12 for focus_duration_ms, and 60 for the last_run FILETIME.",
    "Promote the decoded last_run FILETIME to the record timestamp and keep a null when the FILETIME is zeroed.",
];

const USERASSIST_EXTRACTED_FIELDS: &[&str] = &[
    "program",
    "run_count",
    "focus_count",
    "focus_duration_ms",
    "last_run",
];

const HIBERFIL_PARSER_HINTS: &[&str] = &[
    "Treat hiberfil.sys as a compressed hibernation snapshot, not as a generic flat file.",
    "Use a hibernation-aware parser to reconstruct memory pages before extracting processes, sockets, handles, or strings.",
    "Prioritize command lines, network connections, loaded modules, clipboard fragments, and credential-bearing memory regions.",
    "Correlate recovered memory state with pagefile.sys and nearby event-log activity to bound execution time.",
];

const MEMORY_IMAGE_FIELDS: &[&str] = &[
    "processes",
    "command_lines",
    "sockets",
    "loaded_modules",
    "clipboard_data",
    "interesting_strings",
];

const PAGEFILE_PARSER_HINTS: &[&str] = &[
    "Treat pagefile.sys as paged-out memory fragments rather than a structured file format with stable records.",
    "Search for strings, command fragments, URLs, registry paths, and credential residue, then re-anchor those hits to other artifacts.",
    "Use pagefile hits as corroborating evidence unless you can tie them back to a process, socket, or on-disk artifact.",
];

const BITS_PARSER_HINTS: &[&str] = &[
    "Enumerate qmgr*.dat job-store files under the Downloader directory and preserve originals before parsing.",
    "Parse each job as a durable transfer record with job GUID, owner SID/account, source URL, destination path, and state.",
    "Extract notify command or callback metadata when present; command-to-notify is the highest-signal execution pivot.",
    "Correlate parsed jobs with downloaded files, Prefetch, PowerShell, and BITS-related event logs or cmdlet usage.",
];

const BITS_EXTRACTED_FIELDS: &[&str] = &[
    "job_id",
    "owner_sid",
    "display_name",
    "source_url",
    "destination_path",
    "job_state",
    "created_time",
    "modified_time",
    "notify_command",
];

const WMI_REPOSITORY_PARSER_HINTS: &[&str] = &[
    "Treat the repository as a graph of permanent-consumer objects, not a simple directory listing.",
    "Reconstruct triads of __EventFilter, consumer instance, and __FilterToConsumerBinding for each subscription.",
    "Normalize standard consumer classes such as CommandLineEventConsumer, ActiveScriptEventConsumer, and NTEventLogEventConsumer.",
    "Extract WQL query text, consumer payload, referenced namespace, and creator SID to distinguish benign admin automation from persistence.",
];

const WMI_REPOSITORY_FIELDS: &[&str] = &[
    "filter_name",
    "filter_query",
    "consumer_class",
    "consumer_payload",
    "binding_consumer",
    "binding_filter",
    "creator_sid",
    "namespace",
];

const WMI_REGISTRY_PARSER_HINTS: &[&str] = &[
    "Treat the registry-side subscription view as a pivot artifact, not the authoritative source of full WMI subscription semantics.",
    "Use names and paths recovered here to resolve the underlying repository objects in root\\subscription.",
    "Validate the complete chain by linking EventFilter, consumer object, and FilterToConsumerBinding rather than alerting on a single fragment.",
];

const WMI_REGISTRY_FIELDS: &[&str] = &["filter_name", "consumer_type", "consumer_value", "query"];

static PARSING_PROFILES: &[ArtifactParsingProfile] = &[
    ArtifactParsingProfile {
        artifact_id: "userassist_exe",
        format: "NTUSER.DAT UserAssist Count binary value",
        summary: "ROT13-decode the value name, then parse the fixed-layout Count payload.",
        parser_hints: USERASSIST_PARSER_HINTS,
        extracted_fields: USERASSIST_EXTRACTED_FIELDS,
        sources: &[
            "http://windowsir.blogspot.com/2013/05/userassist-redux.html",
            "https://github.com/EricZimmerman/RegistryPlugins",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "userassist_folder",
        format: "NTUSER.DAT UserAssist Count binary value",
        summary: "Folder GUID entries use the same ROT13 name decoding and 72-byte Count layout as EXE entries.",
        parser_hints: USERASSIST_PARSER_HINTS,
        extracted_fields: USERASSIST_EXTRACTED_FIELDS,
        sources: &[
            "http://windowsir.blogspot.com/2013/05/userassist-redux.html",
            "https://github.com/EricZimmerman/RegistryPlugins",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "pagefile_sys",
        format: "Windows paging file containing paged-out virtual memory",
        summary: "Pagefile evidence is memory residue that should be searched and correlated, not row-oriented parsed.",
        parser_hints: PAGEFILE_PARSER_HINTS,
        extracted_fields: MEMORY_IMAGE_FIELDS,
        sources: &[
            "https://raw.githubusercontent.com/bitbug0x55AA/Blue_Team_Hunting_Field_Notes/main/06_Tool_Command_Vault/6.02_Windows_DFIR_Master_Notes.md",
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "hiberfil_sys",
        format: "Compressed Windows hibernation memory image",
        summary: "Reconstruct the memory image before extracting forensic entities from the snapshot.",
        parser_hints: HIBERFIL_PARSER_HINTS,
        extracted_fields: MEMORY_IMAGE_FIELDS,
        sources: &[
            "https://forensics.wiki/hiberfil.sys/",
            "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/storport/nf-storport-storportmarkdumpmemory",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "bits_db",
        format: "BITS qmgr job database",
        summary: "Parse qmgr*.dat as persisted transfer jobs and pull out transfer metadata plus notify-execution pivots.",
        parser_hints: BITS_PARSER_HINTS,
        extracted_fields: BITS_EXTRACTED_FIELDS,
        sources: &[
            "https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal",
            "https://www.sans.org/white-papers/39195",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "wmi_mof_dir",
        format: "WMI repository containing permanent consumer objects",
        summary: "Rebuild permanent-event-consumer relationships from repository objects, not just filenames.",
        parser_hints: WMI_REPOSITORY_PARSER_HINTS,
        extracted_fields: WMI_REPOSITORY_FIELDS,
        sources: &[
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event",
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-and-responding-to-events-with-standard-consumers",
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer",
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding",
        ],
    },
    ArtifactParsingProfile {
        artifact_id: "wmi_subscriptions",
        format: "Registry-side WMI subscription index",
        summary: "Use registry-side subscription data as a pivot into the authoritative WMI repository objects.",
        parser_hints: WMI_REGISTRY_PARSER_HINTS,
        extracted_fields: WMI_REGISTRY_FIELDS,
        sources: &[
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event",
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-and-responding-to-events-with-standard-consumers",
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/--filtertoconsumerbinding",
        ],
    },
];

// ── Free functions ────────────────────────────────────────────────────────────

/// Returns all container-layer parsing profiles maintained by the catalog.
pub fn all_container_profiles() -> &'static [ContainerProfile] {
    CONTAINER_PROFILES
}

/// Returns the container profile by id.
pub fn container_profile(id: &str) -> Option<&'static ContainerProfile> {
    CONTAINER_PROFILES
        .iter()
        .find(|profile| profile.id.eq_ignore_ascii_case(id))
}

/// Returns all container carving/signature profiles maintained by the catalog.
pub fn all_container_signatures() -> &'static [ContainerSignature] {
    CONTAINER_SIGNATURES
}

/// Returns the container signature by container id.
pub fn container_signature(id: &str) -> Option<&'static ContainerSignature> {
    CONTAINER_SIGNATURES
        .iter()
        .find(|sig| sig.container_id.eq_ignore_ascii_case(id))
}

/// Returns all parser knowledge profiles maintained by the catalog.
pub fn all_parsing_profiles() -> &'static [ArtifactParsingProfile] {
    PARSING_PROFILES
}

/// Returns parsing guidance for a catalog artifact id.
pub fn parsing_profile(id: &str) -> Option<&'static ArtifactParsingProfile> {
    PARSING_PROFILES
        .iter()
        .find(|profile| profile.artifact_id.eq_ignore_ascii_case(id))
}

/// Returns all record signatures maintained by the catalog.
pub fn all_record_signatures() -> &'static [RecordSignature] {
    RECORD_SIGNATURES
}

/// Returns record signatures associated with a container id.
pub fn record_signatures_for_container(id: &str) -> Vec<&'static RecordSignature> {
    RECORD_SIGNATURES
        .iter()
        .filter(|sig| sig.container_id.eq_ignore_ascii_case(id))
        .collect()
}

/// Returns the artifact-container bindings slice (for use by catalog/mod.rs).
pub(super) fn artifact_container_bindings() -> &'static [ArtifactContainerBinding] {
    ARTIFACT_CONTAINER_BINDINGS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::catalog::types::{DataScope, Decoder, HiveTarget, OsScope, TriagePriority};

    fn desc(artifact_type: ArtifactLocation, hive: Option<HiveTarget>) -> ArtifactDescriptor {
        ArtifactDescriptor {
            id: "x",
            name: "n",
            artifact_type,
            hive,
            key_path: "",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::Identity,
            meaning: "m",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Medium,
            related_artifacts: &[],
            sources: &[],
            evidence_strength: None,
            evidence_caveats: &[],
            volatility: None,
            volatility_rationale: "",
        }
    }

    #[test]
    fn infer_container_profile_covers_every_arm() {
        // hive present -> registry hive (regardless of artifact_type).
        assert_eq!(
            infer_container_profile(&desc(
                ArtifactLocation::RegistryValue,
                Some(HiveTarget::NtUser)
            ))
            .unwrap()
            .id,
            "windows_registry_hive"
        );
        // EventLog -> windows_evtx.
        assert_eq!(
            infer_container_profile(&desc(ArtifactLocation::EventLog, None))
                .unwrap()
                .id,
            "windows_evtx"
        );
        // File / Directory -> flat_file.
        for at in [ArtifactLocation::File, ArtifactLocation::Directory] {
            assert_eq!(
                infer_container_profile(&desc(at, None)).unwrap().id,
                "flat_file"
            );
        }
        // Anything else with no hive -> None.
        assert!(infer_container_profile(&desc(ArtifactLocation::MemoryRegion, None)).is_none());

        // Public wrapper delegates identically.
        assert_eq!(
            infer_container_profile_pub(&desc(ArtifactLocation::EventLog, None))
                .unwrap()
                .id,
            "windows_evtx"
        );
    }

    #[test]
    fn free_lookup_functions() {
        assert!(!all_container_profiles().is_empty());
        assert!(!all_container_signatures().is_empty());
        assert!(!all_parsing_profiles().is_empty());
        assert!(!all_record_signatures().is_empty());
        assert!(!artifact_container_bindings().is_empty());

        // Case-insensitive id lookups.
        assert!(container_profile("SQLITE_DATABASE").is_some());
        assert!(container_profile("does_not_exist").is_none());
        assert!(container_signature("windows_registry_hive").is_some());
        assert!(container_signature("does_not_exist").is_none());
        assert_eq!(
            parsing_profile("USERASSIST_EXE").unwrap().artifact_id,
            "userassist_exe"
        );
        assert!(parsing_profile("nope").is_none());

        let regsigs = record_signatures_for_container("windows_registry_hive");
        assert!(regsigs.iter().any(|s| s.id == "registry_nk_cell"));
        assert!(record_signatures_for_container("no_such_container").is_empty());
    }
}
