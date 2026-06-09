//! Clock provenance for `[H]` temporal states — four orthogonal trust axes.

use std::time::Duration;

/// What produced the timestamp associated with a temporal state.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockSource {
    /// BIOS/UEFI real-time clock.
    RealTimeClock,
    /// File system metadata (mtime, ctime, atime).
    FileMetadata,
    /// Record field inside a structured log (EVTX TimeCreated, journald __REALTIME_TIMESTAMP).
    LogRecord,
    /// Network protocol timestamp (HTTP Last-Modified, S3 object last-modified, SMTP Date:).
    NetworkProtocol,
    /// Application-embedded timestamp (WhatsApp message row, browser history visit_time).
    ApplicationEmbedded,
    /// Cryptographic transparency log (Sigstore Rekor, RFC3161 TSA).
    TransparencyLog,
    /// TPM measured-boot event log (temporally chained PCR events).
    TpmEventLog,
    /// Sequence / LSN only — no absolute wall time (SQLite WAL frame, NTFS $LogFile LSN).
    SequenceOnly,
    /// Analyst reconstruction from bracketing events.
    Reconstructed,
    Unknown,
}

/// How much to trust the absolute time value of a temporal state.
///
/// Independent of `TamperResistance`: a local VSS timestamp (`LocalSubsystem`) has
/// `AdminWritable` tamper resistance; an iOS APFS snapshot (`LocallyAttested`) has
/// `SignedImmutable` tamper resistance — same format, different trust.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustGrade {
    /// RFC3161 TSA, Sigstore, server-side WhatsApp timestamp, TPM measured boot.
    ExternallyAttested,
    /// systemd-journald FSS, iOS APFS via Secure Enclave.
    LocallyAttested,
    /// Google Drive version time, cloud object timestamp (no cryptographic proof).
    CustodialThirdParty,
    /// VSS timestamp, journald wall-clock without FSS — same host as evidence.
    LocalSubsystem,
    /// Browser cookie expiry, file mtime set by writing program.
    LocalApplication,
    /// LSN, git parent links, USN seqnum — ordering only, no absolute time.
    OrderingOnly,
    /// Inferred by analyst from bracketing events.
    Reconstructed,
    Unknown,
}

/// How hard it is for an adversary to retroactively forge the timestamp.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TamperResistance {
    /// Cryptographically chained, externally audited (transparency log, TPM event log).
    AppendOnlyAttested,
    /// Append-only by local subsystem with no external proof (journald FSS sealed).
    AppendOnlyLocal,
    /// Signed by a trusted key at creation time (RFC3161 token, signed APFS snapshot).
    SignedImmutable,
    /// Can be overwritten by a local administrator (VSS shadow copy, journald without FSS).
    AdminWritable,
    /// Can be overwritten by the user (mtime, ctime via `touch`).
    UserWritable,
    /// Trivially forgeable by any process (embedded date string in file content).
    Trivial,
}

/// External authentication mechanism providing additional timestamp assurance.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMechanism {
    /// IETF RFC3161 time-stamp token.
    Rfc3161,
    /// Sigstore Rekor transparency log entry.
    Sigstore,
    /// TPM platform configuration register (PCR) measurement.
    TpmPcr,
    /// Apple Secure Enclave–signed APFS snapshot metadata.
    ApfsSecureEnclave,
    /// systemd Forward Secure Sealing (journald FSS).
    JournaldFss,
    Other(String),
}

/// Full provenance record for the clock associated with a `TemporalState`.
///
/// Four orthogonal axes rather than a flat trust level: it is possible for a source to
/// have `LocalSubsystem` trust but `SignedImmutable` tamper resistance (iOS APFS), or
/// `ExternallyAttested` trust with `AppendOnlyAttested` tamper resistance (Sigstore).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockProvenance {
    /// What mechanism produced the timestamp value.
    pub source: ClockSource,
    /// How trustworthy the absolute time value is.
    pub trust_grade: TrustGrade,
    /// How difficult it is to retroactively forge the timestamp.
    pub tamper_resistance: TamperResistance,
    /// If `true`, this epoch has no absolute wall time — only a relative ordering key
    /// (LSN, seqnum, git parent link). `wall_time` on the `TemporalState` will be `None`.
    pub ordering_only: bool,
    /// Known clock skew relative to UTC, if measurable.
    pub skew_known: Option<Duration>,
    /// Cryptographic authentication mechanism, if any.
    pub authenticated: Option<AuthMechanism>,
}
