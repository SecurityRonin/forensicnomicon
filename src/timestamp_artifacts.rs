//! Which timestamp encoding each well-known forensic artifact stores — the
//! artifact→format knowledge a timestamp engine needs to resolve an "artifact
//! hint" (e.g. `"chrome history"`) to the right decode. The `format` field is a
//! [timeglyph](https://github.com/SecurityRonin/timeglyph) registry id, the
//! fleet's timestamp engine; this table is the knowledge, timeglyph the decoder.
//!
//! `no_std`-safe: only `&'static` data, no allocation.
//!
//! Sources are cited per entry; general references:
//! - SANS DFIR / Sarah Edwards (mac4n6) for Apple Cocoa/NSDate epochs
//! - Brian Carrier, *File System Forensic Analysis* for NTFS/FAT
//! - Microsoft [MS-DTYP] for FILETIME; Chromium source for WebKit time

/// One artifact's timestamp field and the format it is encoded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactTimestamp {
    /// Lower-case artifact hint (e.g. `"chrome history"`, `"imessage"`).
    pub artifact: &'static str,
    /// Where the timestamp lives (table.column / structure field).
    pub location: &'static str,
    /// timeglyph registry format id (e.g. `"webkit"`, `"filetime"`, `"iostime"`).
    pub format: &'static str,
    /// Authoritative reference for the artifact↔format fact.
    pub source: &'static str,
}

/// Artifact→timestamp-format knowledge, indexed by artifact hint.
pub const ARTIFACT_TIMESTAMPS: &[ArtifactTimestamp] = &[
    ArtifactTimestamp {
        artifact: "chrome history",
        location: "History.urls.last_visit_time",
        format: "webkit",
        source: "Chromium source (base/time/time.h: microseconds since 1601-01-01 UTC)",
    },
    ArtifactTimestamp {
        artifact: "edge history",
        location: "History.urls.last_visit_time",
        format: "webkit",
        source: "Chromium-based Edge; same WebKit/Chrome time as Chrome",
    },
    ArtifactTimestamp {
        artifact: "firefox history",
        location: "places.sqlite moz_places.last_visit_date",
        format: "prtime",
        source: "Mozilla PRTime (microseconds since 1970-01-01 UTC)",
    },
    ArtifactTimestamp {
        artifact: "safari history",
        location: "History.db history_visits.visit_time",
        format: "cocoa",
        source: "Apple CFAbsoluteTime (seconds since 2001-01-01 UTC); mac4n6 (S. Edwards)",
    },
    ArtifactTimestamp {
        artifact: "imessage",
        location: "chat.db message.date",
        format: "iostime",
        source: "Apple NSDate nanoseconds since 2001 (iOS 11+/High Sierra+); mac4n6 (S. Edwards)",
    },
    ArtifactTimestamp {
        artifact: "whatsapp",
        location: "msgstore.db message.timestamp",
        format: "unix_ms",
        source: "WhatsApp Android msgstore: Unix milliseconds",
    },
    ArtifactTimestamp {
        artifact: "ntfs mft",
        location: "$MFT $STANDARD_INFORMATION / $FILE_NAME",
        format: "filetime",
        source: "Microsoft [MS-DTYP] FILETIME (100 ns since 1601-01-01 UTC); Carrier, FSFA",
    },
    ArtifactTimestamp {
        artifact: "windows registry",
        location: "key LastWrite time",
        format: "filetime",
        source: "Microsoft [MS-DTYP] FILETIME; registry key LastWrite is a FILETIME",
    },
    ArtifactTimestamp {
        artifact: "prefetch",
        location: ".pf last run times",
        format: "filetime",
        source: "Windows Prefetch (.pf) stores FILETIME last-run times; libscca",
    },
    ArtifactTimestamp {
        artifact: "evtx",
        location: "EventRecord SystemTime",
        format: "filetime",
        source: "Windows Event Log (EVTX) TimeCreated SystemTime is a FILETIME",
    },
    ArtifactTimestamp {
        artifact: "fat",
        location: "directory entry create/modify",
        format: "fat",
        source: "Microsoft FAT spec (packed 2-second-resolution local time); Carrier, FSFA",
    },
    ArtifactTimestamp {
        artifact: "ext4",
        location: "inode i_[cma]time",
        format: "unix_ns",
        source: "Linux kernel ext4 inode timestamps (Unix seconds + nanoseconds)",
    },
];

/// The timestamp-format knowledge for an artifact hint (case-insensitive exact
/// match), or `None` if the artifact is not catalogued.
#[must_use]
pub fn timestamp_format_for(artifact: &str) -> Option<&'static ArtifactTimestamp> {
    ARTIFACT_TIMESTAMPS
        .iter()
        .find(|a| a.artifact.eq_ignore_ascii_case(artifact.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_artifacts_map_to_their_format() {
        assert_eq!(
            timestamp_format_for("chrome history").unwrap().format,
            "webkit"
        );
        assert_eq!(timestamp_format_for("iMessage").unwrap().format, "iostime");
        assert_eq!(
            timestamp_format_for("  ntfs mft  ").unwrap().format,
            "filetime"
        );
        assert_eq!(
            timestamp_format_for("firefox history").unwrap().format,
            "prtime"
        );
    }

    #[test]
    fn unknown_artifact_is_none() {
        assert!(timestamp_format_for("not a real artifact").is_none());
    }

    #[test]
    fn every_entry_is_cited_and_nonempty() {
        for a in ARTIFACT_TIMESTAMPS {
            assert!(
                !a.artifact.is_empty() && !a.format.is_empty() && a.source.len() > 10,
                "{a:?}"
            );
            assert_eq!(
                a.artifact,
                a.artifact.to_ascii_lowercase(),
                "hint must be lower-case: {a:?}"
            );
        }
    }
}
