//! Super-timeline construction methodology.
//!
//! Covers three primary Windows timelining tools:
//!
//! - **The Sleuth Kit (TSK)** — `fls` + `mactime`: file-system-only timelines from disk
//!   images; outputs and consumes the bodyfile format.
//! - **Plaso / log2timeline** — multi-source "super timelines" correlating event logs,
//!   registry, browser history, execution artifacts, and filesystem timestamps into a
//!   single unified `.plaso` store.
//! - **MFTECmd** — `--body` flag exports `$MFT` in bodyfile format, compatible with
//!   `mactime` and importable into Plaso via the `mft` parser.
//!
//! # Quick reference
//!
//! ```text
//! File-system timeline only (fast):
//!   fls -r -m / image.raw > body.txt
//!   mactime -b body.txt -d > timeline.csv
//!
//! Super timeline (comprehensive):
//!   log2timeline.py evidence.plaso image.raw
//!   psort.py -o l2tcsv evidence.plaso > supertimeline.csv
//!
//! $MFT bodyfile via MFTECmd (Windows host):
//!   MFTECmd.exe -f \\.\C: --body out\ --bdl c --bodyf mft.body --blf
//!   mactime -b out\mft.body -d > mft_timeline.csv
//! ```
//!
//! # Analyst notes (from Richard Davis — 13Cubed IWE Q&A)
//!
//! - `fls` produces **file-system-only** timelines; Plaso/log2timeline is required
//!   for "super timelines" that also include Event Logs, Prefetch, registry, etc.
//! - When `log2timeline` completes in < 7 min with a 316 KB output and 1 KB CSV,
//!   the image failed to open — verify the path uses `/mnt/...` WSL notation, not
//!   a Windows-style path. Use `pinfo` to inspect warnings.
//! - To recover a longer `$UsnJrnl` window, parse Volume Shadow Copies alongside
//!   the live volume: Plaso's `vss_stores` option includes all VSS snapshots.
//! - When `$MFT` path contains `$`, escape with a backtick in PowerShell:
//!   `` MFTECmd.exe -f C:\...\`$MFT ``
//!
//! Sources:
//! - Brian Carrier — "File System Forensic Analysis" (2005), bodyfile format and
//!   mactime methodology: <https://www.sleuthkit.org>
//! - Kristinn Gudjonsson — Plaso/log2timeline documentation:
//!   <https://plaso.readthedocs.io>
//! - Eric Zimmerman — MFTECmd documentation and bodyfile export:
//!   <https://ericzimmerman.github.io/#!index.md>
//! - SANS FOR508 — "Advanced Incident Response, Threat Hunting, and Digital
//!   Forensics", super-timeline methodology:
//!   <https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/>
//! - Andrea Fortuna — "USN Journal" (2025):
//!   <https://andreafortuna.org/2025/09/06/usn-journal>
//! - Richard Davis (13Cubed) — "Investigating Windows Endpoints" IWE course Q&A,
//!   timelining module (2024): <https://training.13cubed.com>

// ── Bodyfile format ───────────────────────────────────────────────────────────

/// One field in the TSK bodyfile pipe-delimited format.
///
/// The bodyfile format is the interchange format between `fls`/`MFTECmd` (producers)
/// and `mactime` (consumer). It encodes MACB timestamps and file metadata as a
/// plain-text, pipe-separated row.
///
/// Sources:
/// - TSK bodyfile specification: <https://wiki.sleuthkit.org/index.php?title=Body_file>
/// - Brian Carrier — "File System Forensic Analysis" (2005), §§ on timeline analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BodyfileField {
    /// 0-based column index in the pipe-delimited row.
    pub index: u8,
    /// Field name as used in TSK documentation.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
}

/// All 11 fields of the TSK bodyfile format, in column order.
///
/// Format: `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
///
/// All timestamps are Unix epoch seconds (UTC). A value of `0` means unknown.
pub const BODYFILE_FIELDS: &[BodyfileField] = &[
    BodyfileField {
        index: 0,
        name: "MD5",
        description: "MD5 hash of file content, or 0 if unavailable",
    },
    BodyfileField {
        index: 1,
        name: "name",
        description: "Full file path; deleted files prefixed with (deleted)",
    },
    BodyfileField {
        index: 2,
        name: "inode",
        description: "MFT record number (or inode number on non-NTFS)",
    },
    BodyfileField {
        index: 3,
        name: "mode_as_string",
        description: "File type and permission string (e.g., r/rrwxrwxrwx)",
    },
    BodyfileField {
        index: 4,
        name: "UID",
        description: "User ID (Windows: 0)",
    },
    BodyfileField {
        index: 5,
        name: "GID",
        description: "Group ID (Windows: 0)",
    },
    BodyfileField {
        index: 6,
        name: "size",
        description: "File size in bytes",
    },
    BodyfileField {
        index: 7,
        name: "atime",
        description: "Last accessed (A) — Unix epoch seconds",
    },
    BodyfileField {
        index: 8,
        name: "mtime",
        description: "Last modified (M) — Unix epoch seconds",
    },
    BodyfileField {
        index: 9,
        name: "ctime",
        description: "MFT record changed (C) — Unix epoch seconds",
    },
    BodyfileField {
        index: 10,
        name: "crtime",
        description: "Created / birth (B) — Unix epoch seconds",
    },
];

// ── Timeline tools ────────────────────────────────────────────────────────────

/// Output format produced by a timeline tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TimelineOutputFormat {
    /// Pipe-delimited bodyfile (MD5|name|inode|…|crtime).
    Bodyfile,
    /// Plaso binary store (`.plaso`); post-process with `psort.py`.
    PlasoStore,
    /// L2T CSV — legacy/deprecated in Plaso (second-only timestamps, fixed 17 fields);
    /// superseded by the 'dynamic' module. Readable by Timeline Explorer.
    L2tCsv,
    /// CSV output from `mactime`.
    MacTimeCsv,
    /// Plaso "dynamic" CSV — the psort/psteal default module, with customizable
    /// columns (written directly by `psteal.py -o dynamic -w timeline.csv`).
    DynamicCsv,
    /// Textual metadata report about a `.plaso` store (event counts, time range,
    /// parsers, warnings) written to stdout by `pinfo.py`; not a timeline.
    StoreReport,
    /// Files carved out of a storage-media image to an output directory by
    /// `image_export.py` (with a `hashes.json` manifest); targeted collection, not a timeline.
    ExtractedFiles,
}

/// A timelining tool with its scope and canonical command template.
///
/// `{IMAGE}` and `{OUTPUT}` are placeholder tokens for the image path and
/// output file/directory in the command templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TimelineTool {
    /// Short identifier (lowercase, no spaces).
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// What source types this tool covers.
    pub covers: &'static str,
    /// Canonical command to produce a timeline; `{IMAGE}` and `{OUTPUT}` are placeholders.
    pub command: &'static str,
    /// Output format produced.
    pub output_format: TimelineOutputFormat,
    /// Key analyst caveats specific to this tool.
    pub caveats: &'static [&'static str],
}

/// All timelining tools documented in forensicnomicon.
///
/// Sources:
/// - TSK documentation: <https://www.sleuthkit.org/sleuthkit/docs.php>
/// - Plaso documentation: <https://plaso.readthedocs.io/en/latest/>
/// - Eric Zimmerman — MFTECmd: <https://ericzimmerman.github.io/#!index.md>
pub static TIMELINE_TOOLS: &[TimelineTool] = &[
    TimelineTool {
        id: "fls",
        name: "The Sleuth Kit — fls",
        covers: "NTFS/FAT filesystem timestamps ($MFT $STANDARD_INFORMATION); file and directory metadata only",
        command: "fls -r -m / {IMAGE} > body.txt",
        output_format: TimelineOutputFormat::Bodyfile,
        caveats: &[
            "File-system only — does not include Event Logs, registry, or execution artifacts",
            "Whole-disk (multi-partition) image fails with 'Cannot determine file system type', and forcing a type with -f (e.g. -f ntfs/-f fat) does NOT fix it — fls then reads sector 0 (the partition table) where no filesystem boot sector exists. Run mmls first to get the partition's Start sector, then pass -o <start-sector> (offset in SECTORS); e.g. fls -r -m / -o 2048 image.raw. It is a partition-offset problem, not a filesystem-type one, so the same -o fix applies to every fs type",
            "Timestamps come from $STANDARD_INFORMATION only; add -f ntfs for $FILE_NAME column",
            "Run inside WSL on Windows; use /mnt/... paths, not C:\\ style paths",
            "Deleted files appear with (deleted) prefix and may have partial metadata",
        ],
    },
    TimelineTool {
        id: "mactime",
        name: "The Sleuth Kit — mactime",
        covers: "Bodyfile consumer; sorts and filters MACB entries from fls/MFTECmd output",
        command: "mactime -b body.txt -d > timeline.csv",
        output_format: TimelineOutputFormat::MacTimeCsv,
        caveats: &[
            "Input is a bodyfile; mactime itself performs no parsing — it only sorts and formats",
            "-d flag outputs CSV; omit for human-readable table format",
            "-z flag specifies timezone (default UTC); always use -z UTC for forensic outputs",
            "The MACB column is a fixed 4-character M-A-C-B field: a letter appears when that \
             timestamp equals the row's time and a dot (.) when it does not; the order is always \
             M,A,C,B regardless of which times are set",
            "When all four timestamps coincide, mactime collapses them into a single 'macb' row. \
             This is produced BOTH by timestomping tools AND by ordinary file creation (which sets \
             M=A=C=B), so an all-macb row is NOT by itself indicative of tampering",
        ],
    },
    TimelineTool {
        id: "log2timeline",
        name: "Plaso — log2timeline.py",
        covers: "Super timeline: filesystem, Event Logs, registry, Prefetch, browser history, \
                 LNK files, Jump Lists, SRUM, AmCache, ActivitiesCache, Recycle Bin, and more",
        command: "log2timeline.py {OUTPUT}.plaso {IMAGE}",
        output_format: TimelineOutputFormat::PlasoStore,
        caveats: &[
            "Processing a full disk image can take 30–90+ minutes depending on image size",
            "If processing completes in < 7 min with a 316 KB .plaso and 1 KB CSV, the image \
             failed to open; use pinfo to inspect warnings — verify path uses /mnt/... notation in WSL",
            "LinuxHostnameFile error on start means plaso-tools install is broken; \
             run: sudo apt purge plaso-tools && sudo apt autoremove && sudo apt install plaso-tools",
            "Pass --vss_stores all to include Volume Shadow Copies, extending the $UsnJrnl window",
            "Output is a binary .plaso store; post-process with psort.py to get human-readable CSV",
            "--artifact-filters takes a comma-separated list of ForensicArtifacts definition names \
             (e.g. WindowsEventLogSystem, WindowsEventLogs) for targeted collection — only files \
             matched by those definitions are parsed; --artifact_filters_file reads one definition \
             name per line from a file (note the underscore before 'file'). The two are mutually \
             exclusive, and filtering is applied at the source level, not inside archives",
            "--custom_artifact_definitions supplies a custom artifacts YAML when a needed definition \
             is not in the bundled ForensicArtifacts set",
        ],
    },
    TimelineTool {
        id: "psort",
        name: "Plaso — psort.py",
        covers: "Post-processes a .plaso store into filtered, sorted, human-readable output",
        command: "psort.py -o l2tcsv {OUTPUT}.plaso > supertimeline.csv",
        output_format: TimelineOutputFormat::L2tCsv,
        caveats: &[
            "-o l2tcsv is DEPRECATED in Plaso (member of _DEPRECATED_OUTPUT_FORMATS); psort/psteal print a user-warning that it has 'significant limitations such as second-only date and time values and/or a limited predefined set of output fields' and recommend 'dynamic'. It emits a fixed 17-field row (date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra) at second-only resolution — so sub-second ordering of near-simultaneous events is LOST. Prefer -o dynamic; l2tcsv only when a tool requires the legacy Timeline Explorer 17-field layout",
            "Apply --slice and --slice_size to focus on a time window and reduce noise",
            "Use pinfo.py first to inspect the .plaso store for parser warnings and event counts",
        ],
    },
    TimelineTool {
        id: "mftecmd_body",
        name: "MFTECmd — bodyfile export",
        covers: "$MFT entries (MACB timestamps, filename, size, MFT record number, allocated/deleted flag)",
        command: r"MFTECmd.exe -f \\.\C: --body out\ --bdl c --bodyf mft.body --blf",
        output_format: TimelineOutputFormat::Bodyfile,
        caveats: &[
            "--bdl <letter> (body drive letter) is REQUIRED whenever --body is used; MFTECmd exits with '--bdl is required when using --body. Exiting' otherwise. The check fires before any source-specific handling, so it applies even to a raw volume",
            "Escape $ in PowerShell: MFTECmd.exe -f C:\\...\\`$MFT",
            "--blf includes both $STANDARD_INFORMATION and $FILE_NAME timestamps (two rows per file)",
            "Pass -m flag when processing $UsnJrnl to resolve parent paths from $MFT",
            "MFTECmd does not yet parse $LogFile; use for $MFT, $UsnJrnl, $I30 only",
        ],
    },
    TimelineTool {
        id: "psteal",
        name: "Plaso — psteal.py",
        covers: "One-step super timeline: fuses log2timeline (extraction) and psort \
                 (post-processing) in a single pass over a disk image, same source \
                 coverage as log2timeline",
        command: "psteal.py --source {IMAGE} -o dynamic -w supertimeline.csv",
        output_format: TimelineOutputFormat::DynamicCsv,
        caveats: &[
            "Fuses log2timeline + psort in one pass; output is equivalent to running the \
             two-step log2timeline.py then psort.py pipeline",
            "Writes a timeline directly (no reusable intermediate .plaso store is kept) — \
             use the explicit log2timeline.py + psort.py pipeline when you need to re-sort, \
             re-filter, or inspect the store with pinfo.py without reprocessing the image",
            "-o dynamic is the default customizable-column module; pass -o l2tcsv for the \
             legacy fixed 17-field format Timeline Explorer expects",
            "-o list enumerates the available output modules (same set as psort.py)",
            "Same WSL path caveats as log2timeline: use /mnt/... notation, not C:\\ paths",
        ],
    },
    TimelineTool {
        id: "pinfo",
        name: "Plaso — pinfo.py",
        covers: "Inspection: reports .plaso store metadata — how it was collected, total \
                 event count, earliest/latest event timestamps, the parsers/data-source \
                 types that ran, and processing warnings/errors",
        command: "pinfo.py {OUTPUT}.plaso",
        output_format: TimelineOutputFormat::StoreReport,
        caveats: &[
            "Sanity check before psort: a 0-event count, a wrong time range, or parser \
             warnings reveal a failed or partial extraction before you build a timeline",
            "--compare old.plaso new.plaso diffs two stores (versions, counters) — useful \
             to confirm two runs over the same source agree",
            "--output_format json emits a machine-readable report; --sections limits output",
            "Inspection only — it reads a store and never modifies it or produces a timeline",
        ],
    },
    TimelineTool {
        id: "image_export",
        name: "Plaso — image_export.py",
        covers: "Targeted collection: exports files from a storage-media image (RAW or \
                 inside VSS) by filter — extension (-x), filename (--names), file-format \
                 signature (--signatures), path (-f), or creation date range (--date-filter) \
                 — to isolate evidence from a large dataset; not timelining",
        command: "image_export.py -w output_dir --signatures esedb,lnk {IMAGE}",
        output_format: TimelineOutputFormat::ExtractedFiles,
        caveats: &[
            "Extraction, not timelining — use it to pull files of interest, then process \
             those with log2timeline/other tools",
            "By default a SHA-256 is computed per file and duplicates are skipped; a \
             hashes.json manifest is written unless --no_hashes, and --include_duplicates keeps dupes",
            "--signatures list shows supported file-format signatures; --enable_artifacts_map \
             writes a JSON map of extracted files to artifact definitions",
            "Filter paths use the same targeted-filter syntax as a plaso collection filter; \
             --partitions / --vss_stores select where to look",
        ],
    },
];

// ── Plaso parsers ─────────────────────────────────────────────────────────────

/// A Plaso parser with its associated forensicnomicon artifact IDs.
///
/// The `artifact_ids` field lists catalog IDs from [`crate::catalog::CATALOG`] that
/// this parser covers. Use [`parsers_for_artifact`] for reverse lookups.
///
/// Sources:
/// - Plaso parser list: <https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html>
/// - Kristinn Gudjonsson — "Plaso Architecture" (2016):
///   <https://osdfir.blogspot.com/2016/02/plaso-20160202.html>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PlasoParser {
    /// Plaso parser name as passed to `--parsers`.
    pub name: &'static str,
    /// What this parser extracts.
    pub description: &'static str,
    /// Catalog artifact IDs covered by this parser.
    pub artifact_ids: &'static [&'static str],
}

/// Plaso parsers relevant to Windows endpoint forensics.
///
/// Sources:
/// - Plaso documentation: <https://plaso.readthedocs.io>
pub static PLASO_PARSERS: &[PlasoParser] = &[
    PlasoParser {
        name: "winevtx",
        description: "Windows XML Event Log (.evtx) files",
        artifact_ids: &["evtx_security", "evtx_system", "evtx_powershell"],
    },
    PlasoParser {
        name: "winreg",
        description: "Windows Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, etc.)",
        artifact_ids: &[
            "userassist_exe",
            "shimcache",
            "amcache_app_file",
            "bam_user",
            "muicache",
            "run_key_hklm",
            "run_key_hkcu",
        ],
    },
    PlasoParser {
        name: "prefetch",
        description: "Windows Prefetch files (.pf) — execution timestamps and referenced DLLs",
        artifact_ids: &["prefetch_file", "prefetch_dir"],
    },
    PlasoParser {
        name: "lnk",
        description: "LNK / Shell Link shortcut files — accessed file paths and timestamps",
        artifact_ids: &["lnk_files"],
    },
    PlasoParser {
        name: "custom_destinations",
        description:
            "Jump Lists (custom destinations) — pinned and recently accessed files per app",
        artifact_ids: &["jump_list_custom"],
    },
    PlasoParser {
        name: "automatic_destinations",
        description: "Jump Lists (automatic destinations) — recently accessed files per app",
        artifact_ids: &["jump_list_auto"],
    },
    PlasoParser {
        name: "mft",
        description: "$MFT entries — MACB timestamps for every file on the volume",
        artifact_ids: &["mft_file"],
    },
    PlasoParser {
        name: "usnjrnl",
        description: "$UsnJrnl/$J — file creation, modification, rename, and deletion events",
        artifact_ids: &["usnjrnl_file"],
    },
    PlasoParser {
        name: "recycle_bin",
        description: "Recycle Bin $I metadata files — deleted file paths and deletion timestamps",
        artifact_ids: &["recycle_bin"],
    },
    PlasoParser {
        name: "srum",
        description: "System Resource Usage Monitor (SRUDB.dat) — per-app CPU and network usage",
        artifact_ids: &["srum_db", "srum_app_resource", "srum_network_data"],
    },
    PlasoParser {
        name: "windows_timeline",
        description: "ActivitiesCache.db (Windows Timeline) — user activity across devices",
        artifact_ids: &["activities_cache"],
    },
    PlasoParser {
        name: "chrome_history",
        description: "Google Chrome / Chromium browser history, downloads, and search terms",
        artifact_ids: &["chrome_history"],
    },
    PlasoParser {
        name: "firefox_history",
        description: "Mozilla Firefox browser history, downloads, and cookies",
        artifact_ids: &["firefox_history"],
    },
    PlasoParser {
        name: "filestat",
        description: "Generic file system stat metadata — MACB timestamps for files on disk",
        artifact_ids: &["mft_file"],
    },
];

// ── Query functions ───────────────────────────────────────────────────────────

/// Return all Plaso parsers that cover `artifact_id`.
///
/// ```
/// use forensicnomicon::timelining::parsers_for_artifact;
/// let parsers = parsers_for_artifact("prefetch_file");
/// assert!(parsers.iter().any(|p| p.name == "prefetch"));
/// ```
pub fn parsers_for_artifact(artifact_id: &str) -> Vec<&'static PlasoParser> {
    PLASO_PARSERS
        .iter()
        .filter(|p| p.artifact_ids.contains(&artifact_id))
        .collect()
}

/// Return a Plaso parser by exact name.
///
/// ```
/// use forensicnomicon::timelining::plaso_parser_by_name;
/// assert!(plaso_parser_by_name("winevtx").is_some());
/// assert!(plaso_parser_by_name("nonexistent").is_none());
/// ```
pub fn plaso_parser_by_name(name: &str) -> Option<&'static PlasoParser> {
    PLASO_PARSERS.iter().find(|p| p.name == name)
}

/// Return a timeline tool by ID.
///
/// ```
/// use forensicnomicon::timelining::tool_by_id;
/// assert!(tool_by_id("log2timeline").is_some());
/// ```
pub fn tool_by_id(id: &str) -> Option<&'static TimelineTool> {
    TIMELINE_TOOLS.iter().find(|t| t.id == id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Bodyfile ─────────────────────────────────────────────────────────────

    #[test]
    fn bodyfile_has_eleven_fields() {
        assert_eq!(BODYFILE_FIELDS.len(), 11);
    }

    #[test]
    fn bodyfile_field_indices_are_sequential() {
        for (i, f) in BODYFILE_FIELDS.iter().enumerate() {
            assert_eq!(f.index as usize, i, "field '{}' has wrong index", f.name);
        }
    }

    #[test]
    fn bodyfile_macb_fields_present() {
        let names: Vec<&str> = BODYFILE_FIELDS.iter().map(|f| f.name).collect();
        assert!(names.contains(&"atime"), "missing atime (A)");
        assert!(names.contains(&"mtime"), "missing mtime (M)");
        assert!(names.contains(&"ctime"), "missing ctime (C)");
        assert!(names.contains(&"crtime"), "missing crtime (B)");
    }

    // ── Timeline tools ────────────────────────────────────────────────────────

    #[test]
    fn all_four_tools_present() {
        let ids: Vec<&str> = TIMELINE_TOOLS.iter().map(|t| t.id).collect();
        assert!(ids.contains(&"fls"), "missing fls");
        assert!(ids.contains(&"mactime"), "missing mactime");
        assert!(ids.contains(&"log2timeline"), "missing log2timeline");
        assert!(ids.contains(&"psort"), "missing psort");
        assert!(ids.contains(&"mftecmd_body"), "missing mftecmd_body");
        assert!(ids.contains(&"psteal"), "missing psteal");
        assert!(ids.contains(&"pinfo"), "missing pinfo");
        assert!(ids.contains(&"image_export"), "missing image_export");
    }

    #[test]
    fn tool_by_id_log2timeline() {
        let t = tool_by_id("log2timeline").expect("log2timeline must exist");
        assert_eq!(t.output_format, TimelineOutputFormat::PlasoStore);
        assert!(!t.caveats.is_empty());
    }

    #[test]
    fn tool_by_id_unknown_returns_none() {
        assert!(tool_by_id("nonexistent").is_none());
    }

    /// psteal fuses log2timeline + psort in a single pass, writing a timeline directly
    /// (no intermediate .plaso store), so it deserves its own entry alongside the
    /// two-step tools. Source: plaso.readthedocs.io (psteal).
    #[test]
    fn tool_by_id_psteal() {
        let t = tool_by_id("psteal").expect("psteal (one-step log2timeline+psort) must exist");
        assert!(t.command.contains("psteal"), "command must invoke psteal");
        let ctx = format!("{} {}", t.covers, t.caveats.join(" ")).to_lowercase();
        assert!(
            ctx.contains("log2timeline") && ctx.contains("psort"),
            "psteal must be described as fusing log2timeline + psort in one pass"
        );
        assert_ne!(
            t.output_format,
            TimelineOutputFormat::PlasoStore,
            "psteal writes a timeline directly, not an intermediate .plaso store"
        );
    }

    /// pinfo inspects a .plaso store (event counts, time range, parsers, warnings) and
    /// image_export extracts files from an image by filter. Both are plaso toolchain
    /// members that do not emit a timeline, so they round out the plaso tool set.
    /// Source: plaso.readthedocs.io (Using-pinfo, Using-image_export).
    #[test]
    fn tool_by_id_pinfo_and_image_export() {
        let pinfo = tool_by_id("pinfo").expect("pinfo (.plaso store inspection) must exist");
        assert!(pinfo.command.contains("pinfo"), "command must invoke pinfo");
        assert!(
            pinfo.covers.to_lowercase().contains("metadata")
                || pinfo.covers.to_lowercase().contains("inspect"),
            "pinfo must describe store inspection / metadata"
        );
        assert_ne!(
            pinfo.output_format,
            TimelineOutputFormat::PlasoStore,
            "pinfo reads a .plaso store; it does not produce one"
        );

        let ie =
            tool_by_id("image_export").expect("image_export (targeted file extraction) must exist");
        assert!(
            ie.command.contains("image_export"),
            "command must invoke image_export"
        );
        assert!(
            ie.covers.to_lowercase().contains("extract")
                || ie.covers.to_lowercase().contains("collect"),
            "image_export must describe targeted file extraction/collection"
        );
    }

    #[test]
    fn fls_output_is_bodyfile() {
        let fls = tool_by_id("fls").unwrap();
        assert_eq!(fls.output_format, TimelineOutputFormat::Bodyfile);
    }

    /// A whole-disk image fails fls auto-detect ("Cannot determine file system type")
    /// and -f does not fix it (fls still reads sector 0); the fix is spatial — mmls
    /// then -o <start-sector>. The caveat must carry this so an analyst is not misled
    /// into forcing -f. Source: TSK fls/mmls usage.
    #[test]
    fn fls_caveat_covers_whole_disk_offset() {
        let t = tool_by_id("fls").unwrap();
        let all = t.caveats.join(" ");
        assert!(
            all.contains("mmls") && all.contains("-o"),
            "fls caveats must document the whole-disk mmls + -o <sector> offset fix"
        );
    }

    /// l2tcsv is deprecated in Plaso (second-only timestamps), so a forensic timeline
    /// loses sub-second ordering of near-simultaneous events. psort's caveats must warn
    /// of this. Source: Plaso tool_options.py _DEPRECATED_OUTPUT_FORMATS + l2t_csv.py.
    #[test]
    fn psort_caveat_flags_l2tcsv_deprecation() {
        let t = tool_by_id("psort").unwrap();
        let all = t.caveats.join(" ");
        assert!(
            all.contains("DEPRECATED") && all.contains("second-only"),
            "psort caveats must flag l2tcsv as deprecated with second-only resolution"
        );
    }

    /// mactime renders a fixed M-A-C-B column (letter=equals row time, dot=not); an
    /// all-macb row is produced by ordinary file creation too, so it is NOT by itself
    /// indicative of timestomping. Source: TSK mactime.base.
    #[test]
    fn mactime_documents_macb_rendering_without_overstatement() {
        let t = tool_by_id("mactime").unwrap();
        let all = t.caveats.join(" ");
        assert!(
            all.contains("M-A-C-B"),
            "must document the fixed M-A-C-B column rendering"
        );
        assert!(
            all.contains("not by itself") || all.contains("NOT by itself"),
            "must avoid overstating an all-macb row as a timestomping indicator"
        );
    }

    /// The MFTECmd --body command requires --bdl <letter>; without it MFTECmd exits.
    /// The command in both the descriptor and the module doc must include it. Source:
    /// MFTECmd Program.cs.
    #[test]
    fn mftecmd_body_command_includes_bdl() {
        let t = tool_by_id("mftecmd_body").unwrap();
        assert!(
            t.command.contains("--bdl"),
            "mftecmd_body command must include --bdl <letter> (required with --body)"
        );
    }

    /// log2timeline targeted-collection filters cut timeline noise; the filter-file flag
    /// is --artifact_filters_file (underscore before 'file'). Source: plaso
    /// artifact_filters.py.
    #[test]
    fn log2timeline_documents_artifact_filters() {
        let t = tool_by_id("log2timeline").unwrap();
        let all = t.caveats.join(" ");
        assert!(
            all.contains("--artifact-filters") && all.contains("--artifact_filters_file"),
            "must document --artifact-filters and the correctly-spelled --artifact_filters_file"
        );
    }

    #[test]
    fn log2timeline_caveat_mentions_wsl_path() {
        let t = tool_by_id("log2timeline").unwrap();
        let all_caveats = t.caveats.join(" ");
        assert!(
            all_caveats.contains("/mnt/"),
            "log2timeline caveats should mention WSL /mnt/ path requirement"
        );
    }

    // ── Plaso parsers ─────────────────────────────────────────────────────────

    #[test]
    fn plaso_parsers_nonempty() {
        assert!(!PLASO_PARSERS.is_empty());
    }

    #[test]
    fn winevtx_parser_covers_security_evtx() {
        let parsers = parsers_for_artifact("evtx_security");
        assert!(
            parsers.iter().any(|p| p.name == "winevtx"),
            "winevtx should cover evtx_security"
        );
    }

    #[test]
    fn prefetch_parser_covers_prefetch_file() {
        let parsers = parsers_for_artifact("prefetch_file");
        assert!(
            parsers.iter().any(|p| p.name == "prefetch"),
            "prefetch parser should cover prefetch_file"
        );
    }

    #[test]
    fn mft_parser_covers_mft_file() {
        let parsers = parsers_for_artifact("mft_file");
        assert!(
            parsers
                .iter()
                .any(|p| p.name == "mft" || p.name == "filestat"),
            "mft or filestat parser should cover mft_file"
        );
    }

    #[test]
    fn plaso_parser_by_name_winevtx() {
        let p = plaso_parser_by_name("winevtx").expect("winevtx must exist");
        assert!(!p.artifact_ids.is_empty());
    }

    #[test]
    fn plaso_parser_by_name_unknown_returns_none() {
        assert!(plaso_parser_by_name("nosuchparser").is_none());
    }

    #[test]
    fn all_parser_names_are_unique() {
        let mut names: Vec<&str> = PLASO_PARSERS.iter().map(|p| p.name).collect();
        let orig_len = names.len();
        names.dedup();
        assert_eq!(names.len(), orig_len, "duplicate parser names found");
    }

    #[test]
    fn unknown_artifact_returns_empty_parser_list() {
        assert!(parsers_for_artifact("no_such_artifact").is_empty());
    }
}
