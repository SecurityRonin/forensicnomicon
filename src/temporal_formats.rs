//! The authoritative catalog of timestamp *encodings* — epochs, tick units, and
//! packed bit-field layouts — for every well-known forensic timestamp format.
//!
//! This is the *knowledge* half of the timeglyph knowledge/engine split: it is
//! pure `&'static` data (no calendar math, no I/O, no allocation), so it lives in
//! forensicnomicon, the zero-dependency DFIR knowledge leaf. The
//! [timeglyph](https://github.com/SecurityRonin/timeglyph) engine is the decoder
//! that consumes this table — it maps a stored value to an instant, encodes an
//! instant back, and auto-detects an unknown value's format, all driven by the
//! [`Encoding`] each [`TimeFormat`] declares here.
//!
//! `no_std`-safe: only compile-time constant tables and `const fn` arithmetic.
//!
//! Every `epoch_ns` constant is a clean-room fact from a primary spec (cited per
//! entry). The engine cross-validates each against the MIT `time-decode` oracle
//! and the spec's worked example; NEVER sourced from decompiling a proprietary
//! tool.

// ---------------------------------------------------------------------------
// Tick unit
// ---------------------------------------------------------------------------

/// The tick unit a linear/embedded format counts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Unit {
    /// Whole seconds.
    Seconds,
    /// Milliseconds (Java/JS).
    Millis,
    /// Centiseconds — 10-millisecond units (Sonyflake's embedded time field).
    CentiSecond,
    /// Microseconds (Chrome/WebKit, PostgreSQL).
    Micros,
    /// 100-nanosecond intervals (FILETIME, .NET ticks).
    HundredNanos,
    /// Nanoseconds (APFS, Unix-ns).
    Nanos,
    /// Whole days (OLE Automation / Excel serial — usually fractional).
    Days,
}

impl Unit {
    /// Nanoseconds per tick of this unit.
    #[must_use]
    pub const fn nanos(self) -> i128 {
        match self {
            Self::Seconds => 1_000_000_000,
            Self::Millis => 1_000_000,
            Self::CentiSecond => 10_000_000,
            Self::Micros => 1_000,
            Self::HundredNanos => 100,
            Self::Nanos => 1,
            Self::Days => 86_400 * 1_000_000_000,
        }
    }

    /// Decimal digits of *sub-second* resolution this unit can express
    /// (seconds/days → 0, millis → 3, micros → 6, 100-nanos → 7, nanos → 9).
    /// Drives the engine's auto-detect granularity scoring: a whole-second raw
    /// value is a poor fit for a finer unit, so it is penalised, never hidden.
    #[must_use]
    pub const fn sub_second_digits(self) -> u32 {
        match self {
            Self::Seconds | Self::Days => 0,
            Self::CentiSecond => 2,
            Self::Millis => 3,
            Self::Micros => 6,
            Self::HundredNanos => 7,
            Self::Nanos => 9,
        }
    }
}

// ---------------------------------------------------------------------------
// Timezone / leap-second semantics
// ---------------------------------------------------------------------------

/// Timezone semantics of a format's stored value — NOT garnish: FAT stores local
/// time, EXIF often lacks an offset, Event Logs store UTC but display local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TzSemantics {
    /// The value denotes UTC (POSIX, leap-ignoring).
    Utc,
    /// The value denotes naive *local* time with no recorded offset (FAT/DOS).
    LocalNaive,
    /// The value carries its own offset (exFAT tz field, EXIF with offset).
    OffsetEmbedded,
}

/// Leap-second semantics. Most forensic epochs are POSIX (leap-ignoring); only
/// the GPS/TAI/NTP family needs true leap math (handled by the engine's separate
/// leap-aware instant type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum LeapSemantics {
    /// UTC-labelled but leap-ignoring (pure constant offset to Unix). The norm.
    PosixIgnored,
    /// True leap-aware scale (GPS/TAI/NTP) — handled by a separate instant type.
    LeapAware,
}

// ---------------------------------------------------------------------------
// Packed bit-field layout tags
// ---------------------------------------------------------------------------

/// Identifies which packed bit-field layout an [`Encoding::Packed`] format uses.
/// A packed timestamp is not a linear offset but calendar fields squeezed into an
/// integer, so decoding it needs a dedicated unpacker. The knowledge table names
/// the layout here; the *engine* (timeglyph) dispatches this tag to the unpacker
/// that does the (calendar-aware) math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum PackedLayout {
    /// FAT/DOS 32-bit packed date+time (2-second resolution), LOCAL time.
    FatDos,
    /// exFAT 32-bit packed timestamp, LOCAL time.
    ExFat,
    /// Microsoft DTTM 32-bit packed date (no seconds), LOCAL time.
    Dttm,
    /// Samsung/LG BitDate (byte-reversed 32-bit packed), LOCAL time.
    BitDate,
    /// Bitwise Decimal packed date, LOCAL time.
    BitDec,
    /// Binary-Coded-Decimal `YYMMDDHHMMSS` digit pairs, LOCAL time.
    Bcd,
    /// Motorola 6-byte timestamp (one byte per field, year + 1970), UTC.
    Moto,
    /// Symantec AV 6-byte timestamp (like Motorola, month + 1), UTC.
    Symantec,
    /// DVR (WFS/DHFS) 32-bit packed timestamp (year since 2000), LOCAL time.
    Dvr,
    /// Nokia S40 7-byte timestamp (big-endian year u16), UTC.
    Ns40,
    /// Nokia S40 7-byte timestamp (little-endian year u16), UTC.
    Ns40Le,
    /// JET LogTime 8-byte timestamp (reversed field bytes, year + 1900), UTC.
    LogTime,
    /// Semi-octet decimal (nibble-swapped digit pairs, `YY` + 2000), LOCAL time.
    SemiOctet,
    /// GSM 7-byte semi-octet timestamp (per-byte nibble swap + tz byte), UTC.
    Gsm,
    /// Nokia time LE (byte-reversed two's-complement seconds before 2050), UTC.
    NokiaLe,
    /// SQL Server `datetime` (int32 days since 1900 + uint32 1/300-second ticks).
    SqlServer,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// How a stored value maps to an instant. The engine reads this to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Encoding {
    /// `value` (integer ticks) × `unit` + `epoch_ns` = nanoseconds since Unix.
    LinearInt {
        /// The format's epoch as nanoseconds relative to the Unix epoch.
        epoch_ns: i128,
        /// The tick unit.
        unit: Unit,
    },
    /// `value` (floating ticks, e.g. OLE days as `f64`) × `unit` + `epoch_ns`.
    /// Lossy by nature; the engine flags the precision caveat.
    LinearFloat {
        /// The format's epoch as nanoseconds relative to the Unix epoch.
        epoch_ns: i128,
        /// The tick unit.
        unit: Unit,
    },
    /// An ID with an embedded timestamp in its high bits: the low `shift_bits`
    /// bits are worker/sequence/random, so `value >> shift_bits` is a count of
    /// `unit` ticks since `epoch_ns`. Most snowflake-class IDs count milliseconds
    /// (Twitter/Discord/Mastodon/LinkedIn), but the unit is part of the scheme
    /// (TikTok counts whole seconds), so it is carried explicitly.
    Embedded {
        /// The scheme's epoch as nanoseconds relative to the Unix epoch.
        epoch_ns: i128,
        /// Number of low bits to discard before reading the timestamp.
        shift_bits: u32,
        /// The tick unit of the embedded timestamp.
        unit: Unit,
    },
    /// A bit-packed civil datetime (FAT/DOS, exFAT, …): the integer is packed
    /// calendar fields, not a linear offset, so decoding needs the layout-specific
    /// unpacker the engine selects from this [`PackedLayout`] tag. Timezone
    /// semantics (e.g. FAT's LOCAL naive time) are carried on the [`TimeFormat`].
    Packed(PackedLayout),
}

// ---------------------------------------------------------------------------
// One format
// ---------------------------------------------------------------------------

/// One forensic timestamp format: evidence metadata, not just a converter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TimeFormat {
    /// Stable id (e.g. `"filetime"`).
    pub id: &'static str,
    /// Human label (e.g. `"Windows FILETIME"`).
    pub label: &'static str,
    /// Where it's found / who writes it.
    pub family: &'static str,
    /// Authoritative spec citation (clean-room provenance).
    pub citation: &'static str,
    /// Timezone semantics.
    pub tz: TzSemantics,
    /// Leap-second semantics.
    pub leap: LeapSemantics,
    /// Observed forensic plausibility window `[from, to)` in nanoseconds since the
    /// Unix epoch — the engine uses it to rank auto-detect candidates (NOT to
    /// assert a single answer).
    pub plausible: (i128, i128),
    /// How the stored value maps to an instant.
    pub encoding: Encoding,
}

// ---------------------------------------------------------------------------
// Epoch offsets (nanoseconds relative to the Unix epoch, 1970-01-01)
// ---------------------------------------------------------------------------

const NS: i128 = 1_000_000_000;
const MS: i128 = 1_000_000;

/// FILETIME epoch: 1601-01-01 UTC, in ns relative to the Unix epoch. [MS-DTYP]
pub const FILETIME_EPOCH_NS: i128 = -11_644_473_600 * NS;
/// Cocoa / CFAbsoluteTime epoch: 2001-01-01 UTC.
pub const COCOA_EPOCH_NS: i128 = 978_307_200 * NS;
/// Apple HFS/HFS+ epoch: 1904-01-01 (HFS+ TN1150).
pub const HFS_EPOCH_NS: i128 = -2_082_844_800 * NS;
/// .NET `DateTime.Ticks` epoch: 0001-01-01.
pub const DOTNET_EPOCH_NS: i128 = -62_135_596_800 * NS;
/// OLE Automation date epoch: 1899-12-30.
pub const OLE_EPOCH_NS: i128 = -2_209_161_600 * NS;
/// PostgreSQL / DHCPv6 DUID-LLT epoch: 2000-01-01.
pub const POSTGRES_EPOCH_NS: i128 = 946_684_800 * NS;
/// Julian Day 0 = noon, 24 Nov 4714 BC (proleptic Gregorian). `unix_seconds(JD 0)`
/// = `(0 - 2440587.5) × 86400`, since JD 2440587.5 is the Unix epoch (SQLite docs).
pub const JULIAN_EPOCH_NS: i128 = -210_866_760_000 * NS;
/// Modified Julian Day 0 = 1858-11-17 00:00 UTC (JD − 2400000.5). MJD 40587 =
/// 1970-01-01, so MJD day 0 is 40587 days before the Unix epoch.
pub const MJD_EPOCH_NS: i128 = -3_506_716_800 * NS;
/// SQL Server `datetime` epoch: 1900-01-01. Referenced by the engine's packed
/// SQL Server decoder (the days-since-1900 base).
pub const SQLSERVER_EPOCH_NS: i128 = -2_208_988_800 * NS;
/// Twitter/X Snowflake epoch: 2010-11-04 (published in ms).
pub const TWITTER_EPOCH_NS: i128 = 1_288_834_974_657 * MS;
/// Discord Snowflake epoch: 2015-01-01 (published in ms).
pub const DISCORD_EPOCH_NS: i128 = 1_420_070_400_000 * MS;
/// Sonyflake epoch: 2014-09-01 (10 ms units).
pub const SONY_EPOCH_NS: i128 = 1_409_529_600 * NS;
/// KSUID epoch: Unix second 1_400_000_000 = 2014-05-13T16:53:20Z (Segment KSUID).
pub const KSUID_EPOCH_NS: i128 = 1_400_000_000 * NS;

// Plausibility window for the engine's auto-detect ranking: 1990-01-01 .. 2040-01-01.
// NOT a filter on truth — only a prior on which readings to surface first.
const W_FROM: i128 = 631_152_000 * NS; // 1990-01-01
const W_TO: i128 = 2_208_988_800 * NS; // 2040-01-01
const W: (i128, i128) = (W_FROM, W_TO);

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------

/// Every catalogued timestamp format. Ordered stably (linear → float → embedded →
/// packed families interleaved as historically registered); the order is part of
/// the engine's provenance digest, so entries are appended, never reordered.
pub static TIME_FORMATS: &[TimeFormat] = &[
    TimeFormat {
        id: "unix",
        label: "Unix time (seconds)",
        family: "POSIX / Linux / web",
        citation: "POSIX.1-2017 §4.16",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: 0,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "unix_ms",
        label: "Unix time (milliseconds, Java/JS)",
        family: "Java, JavaScript Date",
        citation: "ECMA-262 (Date)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: 0,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        id: "unix_us",
        label: "Unix time (microseconds)",
        family: "various (sqlite, syslog)",
        citation: "derived (Unix epoch, µs)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: 0,
            unit: Unit::Micros,
        },
    },
    TimeFormat {
        id: "filetime",
        label: "Windows FILETIME (100ns since 1601)",
        family: "NTFS, Registry, Event Log, AD",
        citation: "[MS-DTYP] §2.3.3 FILETIME",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: FILETIME_EPOCH_NS,
            unit: Unit::HundredNanos,
        },
    },
    TimeFormat {
        id: "webkit",
        label: "Chrome / WebKit (µs since 1601)",
        family: "Chromium history/cookies",
        citation: "Chromium base::Time (Windows epoch, µs)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: FILETIME_EPOCH_NS,
            unit: Unit::Micros,
        },
    },
    TimeFormat {
        id: "cocoa",
        label: "Cocoa / CFAbsoluteTime (s since 2001)",
        family: "macOS/iOS, NSDate, Core Data",
        citation: "Apple Foundation NSDate (CFAbsoluteTime)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: COCOA_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "hfsplus",
        label: "Apple HFS+ (s since 1904)",
        family: "HFS+ filesystem",
        citation: "Apple TN1150 (HFS Plus)",
        tz: TzSemantics::Utc, // NB: classic-Mac HFS stored LOCAL; HFS+ is UTC.
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: HFS_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        // Classic Mac HFS: same 1904 epoch + seconds unit as HFS+, but the stored
        // value is LOCAL wall-clock (TN1150) — a distinct forensic reading of the
        // same bits, surfaced alongside `hfsplus` rather than instead of it.
        id: "hfs",
        label: "Apple HFS (local, s since 1904)",
        family: "HFS filesystem (classic Mac OS)",
        citation: "Apple TN1150 (HFS)",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: HFS_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "dotnet_ticks",
        label: ".NET DateTime.Ticks (100ns since 0001)",
        family: ".NET / SQL Server datetime2",
        citation: "ECMA-335 / .NET DateTime.Ticks",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: DOTNET_EPOCH_NS,
            unit: Unit::HundredNanos,
        },
    },
    TimeFormat {
        id: "ole",
        label: "OLE Automation date (days since 1899-12-30)",
        family: "Excel, COM, VARIANT DATE",
        citation: "MS OLE Automation (DATE / VT_DATE)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: OLE_EPOCH_NS,
            unit: Unit::Days,
        },
    },
    TimeFormat {
        id: "unix_ns",
        label: "Unix time (nanoseconds)",
        family: "Go time.UnixNano, APFS on-disk",
        citation: "derived (Unix epoch, ns); Apple APFS reference",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: 0,
            unit: Unit::Nanos,
        },
    },
    TimeFormat {
        id: "dhcp6",
        label: "DHCPv6 DUID-LLT (s since 2000)",
        family: "DHCPv6 DUID-LLT (RFC 3315)",
        citation: "RFC 3315 §9.2 (DUID-LLT)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            // 2000-01-01 UTC — the same epoch as PostgreSQL (µs); DUID-LLT counts
            // whole seconds. Reused DRY; the literal lives in one place.
            epoch_ns: POSTGRES_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "postgres",
        label: "PostgreSQL timestamp (µs since 2000)",
        family: "PostgreSQL (64-bit integer datetimes)",
        citation: "PostgreSQL src timestamp.h (POSTGRES_EPOCH_JDATE)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: POSTGRES_EPOCH_NS,
            unit: Unit::Micros,
        },
    },
    TimeFormat {
        id: "cocoa_float",
        label: "Cocoa CFAbsoluteTime (signed double, s since 2001)",
        family: "macOS/iOS plists, NSKeyedArchiver, Core Data",
        citation: "Apple CoreFoundation CFAbsoluteTime (CFDateGetAbsoluteTime)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: COCOA_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        // Unix seconds carried as an IEEE-754 double — the integer part is the
        // time_t, the fraction is sub-second. The float twin of `unix`, mirroring
        // the cocoa/cocoa_float pair; a float input never matched the LinearInt
        // `unix` before this. Ubiquitous in log pipelines.
        id: "unix_float",
        label: "Unix time (seconds, double)",
        family: "Slack ts, Zeek/Squid, Splunk _time, log pipelines",
        citation: "POSIX time_t (IEEE-754 double; fractional seconds)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: 0,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "sqlite_julian",
        label: "SQLite Julian day (float days)",
        family: "SQLite julianday() / REAL date storage",
        citation: "SQLite date-and-time functions (Julian day number)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: JULIAN_EPOCH_NS,
            unit: Unit::Days,
        },
    },
    TimeFormat {
        id: "snowflake",
        label: "Twitter/X Snowflake ID (ms since 2010, <<22)",
        family: "Twitter/X object IDs",
        citation: "Twitter Snowflake (epoch 1288834974657 ms, 22-bit shift)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: TWITTER_EPOCH_NS,
            shift_bits: 22,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        // GMail Message ID: the top 44 bits of the 64-bit id are Unix
        // milliseconds — i.e. `id >> 20`. The low 20 bits are a per-message
        // counter. Email-forensics dating (the id appears in headers / Takeout).
        id: "gmsgid",
        label: "GMail Message ID (ms since 1970, >>20)",
        family: "GMail message identifiers",
        citation: "GMail Message ID (top 44 bits = Unix ms; 20-bit shift)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: 0,
            shift_bits: 20,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        id: "discord",
        label: "Discord Snowflake ID (ms since 2015, <<22)",
        family: "Discord object IDs",
        citation: "Discord developer docs (epoch 1420070400000 ms, 22-bit shift)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: DISCORD_EPOCH_NS,
            shift_bits: 22,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        id: "fat",
        label: "FAT/DOS packed date+time (LOCAL time)",
        family: "FAT/exFAT, ZIP, DOS",
        citation: "Microsoft FAT spec / ECMA-107 (DOS date/time fields)",
        // FAT stores wall-clock LOCAL time with NO offset — the rendered instant
        // is naive and must not be assumed UTC.
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::FatDos),
    },
    TimeFormat {
        id: "active",
        label: "Active Directory / LDAP (100ns since 1601)",
        family: "Active Directory, LDAP (lastLogon, pwdLastSet)",
        citation: "[MS-DTYP] §2.3.3 FILETIME (AD Integer8 date attributes)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: FILETIME_EPOCH_NS,
            unit: Unit::HundredNanos,
        },
    },
    TimeFormat {
        id: "prtime",
        label: "Mozilla PRTime (µs since 1970)",
        family: "Firefox places.sqlite, Mozilla NSPR",
        citation: "Mozilla NSPR PRTime (microseconds since the Unix epoch)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: 0,
            unit: Unit::Micros,
        },
    },
    TimeFormat {
        id: "iostime",
        label: "Apple NSDate iOS 11+ (ns since 2001)",
        family: "iOS 11+ Cocoa nanosecond NSDate",
        citation: "Apple Foundation NSDate (CFAbsoluteTime), nanosecond form",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: COCOA_EPOCH_NS,
            unit: Unit::Nanos,
        },
    },
    TimeFormat {
        id: "ksuid",
        label: "KSUID timestamp (s since 2014-05-13)",
        family: "Segment KSUID (k-sortable unique IDs)",
        citation: "Segment KSUID (epoch 1_400_000_000 = 2014-05-13T16:53:20Z)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearInt {
            epoch_ns: KSUID_EPOCH_NS,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "excel1904",
        label: "Microsoft Excel 1904 date (float days since 1904-01-01)",
        family: "Excel (legacy Mac 1904 date system)",
        citation: "Microsoft Excel 1904 date system (serial day 0 = 1904-01-01)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: HFS_EPOCH_NS,
            unit: Unit::Days,
        },
    },
    TimeFormat {
        id: "mastodon",
        label: "Mastodon Snowflake ID (ms since 1970, <<16)",
        family: "Mastodon status / object IDs",
        citation: "Mastodon Snowflake (Unix-ms epoch, 16-bit shift); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: 0,
            shift_bits: 16,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        id: "linkedin",
        label: "LinkedIn activity ID (ms since 1970, <<22)",
        family: "LinkedIn activity / URN IDs",
        citation: "LinkedIn activity timestamp (Unix-ms epoch, 22-bit shift); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: 0,
            shift_bits: 22,
            unit: Unit::Millis,
        },
    },
    TimeFormat {
        id: "tiktok",
        label: "TikTok Snowflake ID (s since 1970, <<32)",
        family: "TikTok object IDs",
        citation: "TikTok ID (Unix-seconds epoch, 32-bit shift); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: 0,
            shift_bits: 32,
            unit: Unit::Seconds,
        },
    },
    TimeFormat {
        id: "exfat",
        label: "exFAT packed timestamp (LOCAL time)",
        family: "exFAT filesystem",
        citation: "Microsoft exFAT spec (32-bit packed timestamp); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::ExFat),
    },
    TimeFormat {
        id: "dttm",
        label: "Microsoft DTTM packed date (LOCAL time)",
        family: "Microsoft Compound File / Office DTTM",
        citation: "Microsoft DTTM packed date (year since 1900); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Dttm),
    },
    TimeFormat {
        id: "bitdate",
        label: "Samsung/LG BitDate (byte-reversed packed, LOCAL time)",
        family: "Samsung / LG device timestamps",
        citation: "Samsung/LG BitDate (byte-reversed 32-bit packed); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::BitDate),
    },
    TimeFormat {
        id: "bitdec",
        label: "Bitwise Decimal packed date (LOCAL time)",
        family: "Bitwise Decimal packed timestamps",
        citation: "Bitwise Decimal (decimal bit-packed date); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::BitDec),
    },
    TimeFormat {
        id: "bcd",
        label: "Binary-Coded-Decimal YYMMDDHHMMSS (LOCAL time)",
        family: "BCD digit-pair timestamps",
        citation: "Binary-Coded-Decimal (YY+2000 MM DD HH MM SS pairs); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Bcd),
    },
    TimeFormat {
        id: "moto",
        label: "Motorola 6-byte timestamp",
        family: "Motorola device timestamps",
        citation: "Motorola 6-byte (one byte per field, year+1970); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Moto),
    },
    TimeFormat {
        id: "symantec",
        label: "Symantec AV 6-byte timestamp",
        family: "Symantec antivirus logs",
        citation: "Symantec AV 6-byte (year+1970, month+1); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Symantec),
    },
    TimeFormat {
        id: "dvr",
        label: "DVR (WFS/DHFS) packed timestamp (LOCAL time)",
        family: "DVR WFS / DHFS filesystems",
        citation: "DVR WFS/DHFS 32-bit packed (year since 2000); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Dvr),
    },
    TimeFormat {
        id: "sony",
        label: "Sonyflake ID (10ms units since 2014-09-01, <<24)",
        family: "Sonyflake distributed IDs",
        citation: "Sonyflake (id>>24 in 10ms units, 2014-09-01 epoch); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Embedded {
            epoch_ns: SONY_EPOCH_NS,
            shift_bits: 24,
            unit: Unit::CentiSecond,
        },
    },
    TimeFormat {
        id: "ns40",
        label: "Nokia S40 7-byte timestamp",
        family: "Nokia S40 devices",
        citation: "Nokia S40 7-byte (year BE u16 + field bytes); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Ns40),
    },
    TimeFormat {
        id: "ns40le",
        label: "Nokia S40 7-byte timestamp (LE year)",
        family: "Nokia S40 devices",
        citation: "Nokia S40 7-byte, little-endian year u16; vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Ns40Le),
    },
    TimeFormat {
        id: "logtime",
        label: "JET LogTime 8-byte timestamp",
        family: "Microsoft JET / ESE database logs",
        citation: "JET LogTime (reversed field bytes, year+1900); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::LogTime),
    },
    TimeFormat {
        id: "semioctet",
        label: "Semi-Octet decimal (LOCAL time)",
        family: "Semi-octet (nibble-swapped) timestamps",
        citation: "Semi-Octet decimal (nibble-swapped pairs, YY+2000); vs time-decode",
        tz: TzSemantics::LocalNaive,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::SemiOctet),
    },
    TimeFormat {
        id: "gsm",
        label: "GSM 7-byte semi-octet timestamp",
        family: "GSM mobile timestamps",
        citation: "GSM semi-octet (per-byte nibble swap + tz byte); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::Gsm),
    },
    TimeFormat {
        id: "nokiale",
        label: "Nokia time LE (seconds before 2050)",
        family: "Nokia devices",
        citation: "Nokia LE (byte-reversed two's-complement seconds before 2050); vs time-decode",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::NokiaLe),
    },
    TimeFormat {
        id: "mjd",
        label: "Modified Julian Day (float days since 1858-11-17)",
        family: "astronomy / VMS / scientific timestamps",
        citation: "Modified Julian Day (JD − 2400000.5; day 0 = 1858-11-17)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::LinearFloat {
            epoch_ns: MJD_EPOCH_NS,
            unit: Unit::Days,
        },
    },
    TimeFormat {
        id: "sqlserver",
        label: "SQL Server datetime (days since 1900 + 1/300s ticks)",
        family: "Microsoft SQL Server datetime",
        citation: "SQL Server datetime (int32 days since 1900-01-01 + uint32 1/300s ticks)",
        tz: TzSemantics::Utc,
        leap: LeapSemantics::PosixIgnored,
        plausible: W,
        encoding: Encoding::Packed(PackedLayout::SqlServer),
    },
];

/// The catalogued format with this stable id, or `None` if not catalogued.
#[must_use]
pub fn time_format(id: &str) -> Option<&'static TimeFormat> {
    TIME_FORMATS.iter().find(|f| f.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_is_45() {
        assert_eq!(TIME_FORMATS.len(), 45);
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = TIME_FORMATS.iter().map(|f| f.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total);
    }

    #[test]
    fn lookup_hits_and_misses() {
        assert!(time_format("filetime").is_some());
        assert!(time_format("not-a-format").is_none());
    }

    #[test]
    fn filetime_epoch_is_1601() {
        assert_eq!(FILETIME_EPOCH_NS, -11_644_473_600 * 1_000_000_000);
    }
}
