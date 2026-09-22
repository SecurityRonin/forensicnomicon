//! Static [`AntiForensicMethod`] instances and the [`ANTI_FORENSIC_METHODS`]
//! slice.
//!
//! Each entry records a technique that destroys, forges or hides evidence —
//! together with its residue, because what the technique FAILS to erase is
//! what makes it detectable. Every entry was verified against an independent
//! primary source (a kernel or vendor document, a man page, or a maintained
//! open-source implementation's on-disk-layout source), cited in `sources`.
//!
//! Where the residue is ABSENT under some condition, the entry says so
//! explicitly: an examiner who believes a residue is universal will read its
//! absence as "no tampering", which is the same manufactured negative this
//! catalog exists to prevent.

use super::AntiForensicMethod;
use forensicnomicon_core::evidence::EvidenceTier;

/// `touch -t` / `utimensat(2)` timestomping on ext4: atime and mtime are the
/// entire writable surface; ctime and crtime are out of reach from user space.
///
/// # Verification
///
/// - `utimensat(2)` (man7.org): `times[0]` sets atime, `times[1]` sets mtime,
///   to arbitrary nanosecond values — those two are the whole interface. And:
///   "The status change time (ctime) will be set to the current time, even if
///   the other time stamps don't actually change" — the stomp itself
///   refreshes ctime.
/// - GNU coreutils manual, `touch` invocation: "The `touch` command cannot
///   set a file's status change timestamp to a user-specified value, and
///   cannot change the file's birth time (if supported) at all." `-t` takes
///   `[[cc]yy]mmddhhmm[.ss]` — whole seconds, no sub-second field.
/// - Kernel ext4 documentation (inodes): `i_crtime` ("File creation time")
///   with `i_crtime_extra` sub-second bits lives at 0x90/0x94 in the inode —
///   in the extra space beyond the original 128 bytes, so it exists only on
///   filesystems with larger inodes (256 bytes is the mkfs default).
///
/// # A lead this research REFUTED
///
/// "mtime earlier than crtime is impossible in normal operation" is FALSE:
/// every mtime-preserving copy (`cp -p`, `rsync -a`, `tar -x`, unzip) writes
/// the archived mtime into a freshly created inode, producing mtime < crtime
/// with no forgery anywhere. The anomaly is a lead requiring corroboration,
/// never proof — the entry records it that way.
pub static EXT4_UTIMENSAT_TIMESTOMP: AntiForensicMethod = AntiForensicMethod {
    id: "ext4_utimensat_timestomp",
    name: "touch -t / utimensat() timestomping on ext4",
    suppresses: &[],
    method: "utimensat(2)/futimens(2) — the syscall behind touch, cp -p, rsync and every \
             portable timestamp setter — accepts exactly two timestamps: times[0] (atime) and \
             times[1] (mtime), each settable to an arbitrary nanosecond value. That is the \
             entire user-space surface: no argument reaches ctime (inode change time) or the \
             ext4 creation time (i_crtime), and the GNU coreutils manual states both limits for \
             touch outright. touch -t takes [[cc]yy]mmddhhmm[.ss] — whole seconds — so a -t \
             stomp writes zero nanosecond fractions.",
    residue: &[
        "ctime is REFRESHED by the stomp itself: utimensat(2) sets the status change time to \
         the current time 'even if the other time stamps don't actually change'. A file whose \
         atime/mtime say one epoch while ctime says another, with no chmod/chown/rename to \
         explain the ctime, is consistent with a timestamp write.",
        "crtime (i_crtime, on ext4 filesystems with >128-byte inodes; 256 is the mkfs.ext4 \
         default) is untouched: mtime earlier than crtime survives the stomp. CAUTION — \
         mtime-preserving copies (cp -p, rsync -a, tar/zip extraction) legitimately produce \
         mtime < crtime on a freshly created inode, so this residue is a lead to corroborate, \
         never proof.",
        "touch -t writes whole seconds, so atime and mtime carry a .000000000 fraction while \
         kernel-stamped timestamps (and the stomp-refreshed ctime) carry nanosecond noise. \
         Second-granularity archive restores (classic tar, zip) share this signature — \
         corroborate before concluding forgery.",
    ],
    detection: "Read all four timestamps — statx(2) for btime, or debugfs -R 'stat <file>' on \
                the unmounted image — and cross-view them: mtime < crtime, zeroed fractions on \
                atime/mtime beside a nanosecond-bearing ctime, and a ctime far later than mtime \
                with no metadata operation to explain it are each consistent with stomping; \
                corroborate against copy/extract explanations before concluding. RESIDUE ABSENT: \
                a clock-rollback stomp (set the system clock back, then write/create) forges \
                ctime and crtime too, and is caught only by external records (auth/audit logs, \
                journald entries around date/timedatectl, NTP step logs); on 128-byte-inode \
                filesystems there is no crtime and no sub-second field, so both on-disk residues \
                vanish.",
    evidence_tier: EvidenceTier::VendorDocumented,
    mitre_techniques: &[
        "T1070.006", // Indicator Removal: Timestomp
        "T1070",     // Indicator Removal on Host
    ],
    sources: &[
        "https://man7.org/linux/man-pages/man2/utimensat.2.html",
        "https://www.gnu.org/software/coreutils/manual/html_node/touch-invocation.html",
        "https://docs.kernel.org/filesystems/ext4/inodes.html",
    ],
};

/// Every registered anti-forensic method. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static ANTI_FORENSIC_METHODS: &[AntiForensicMethod] = &[EXT4_UTIMENSAT_TIMESTOMP];
