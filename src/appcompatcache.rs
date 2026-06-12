//! AppCompatCache (ShimCache) on-disk format constants, by Windows build.
//!
//! The Application Compatibility Cache — "ShimCache" — lives in the `SYSTEM`
//! hive at `…\Control\Session Manager\AppCompatCache` (value `AppCompatCache`,
//! `REG_BINARY`). Presence of a path in the cache proves the binary *existed*
//! on disk and was seen by the application-compatibility subsystem; it is NOT
//! proof of execution. The per-entry timestamp is the binary's `$STANDARD_INFO`
//! last-modified time (FILETIME), not an execution time.
//!
//! The on-disk layout is undocumented by Microsoft but thoroughly
//! reverse-engineered. This module is the fleet's single source of truth for
//! the header signatures, entry markers, and entry-body field offsets — facts
//! only; the decoding algorithm lives in the consuming reader
//! (`winreg-artifacts::shimcache`), per forensicnomicon's knowledge-only charter.
//!
//! # Authoritative sources
//!
//! - Andrew Davis (Mandiant/FireEye), *Leveraging the Application Compatibility
//!   Cache in Forensic Investigations* — the original whitepaper that
//!   reverse-engineered the XP→Windows 7 layouts and the ShimCacheParser tool:
//!   <https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf>
//! - Eric Zimmerman, `AppCompatCacheParser` — the canonical, maintained
//!   implementation; format dispatch and per-build entry walks:
//!   <https://github.com/EricZimmerman/AppCompatCacheParser>
//!   (`AppCompatCache/AppCompatCache.cs` — version detection by the marker at
//!   offset 128; `AppCompatCache/Windows8x.cs` — the 8.0/8.1 entry body;
//!   `AppCompatCache/Windows10.cs` — the 1507/1607+ entry body).
//! - libyal `winreg-kb`, *Application compatibility cache key*:
//!   <https://github.com/libyal/winreg-kb/blob/main/docs/sources/system-keys/Application-compatibility-cache.md>
//! - Mandiant ShimCacheParser (Python reference for the legacy headers):
//!   <https://github.com/mandiant/ShimCacheParser>
//!
//! # Format families (header signature → build)
//!
//! | First dword / marker            | Windows build                         | Entry body |
//! |---------------------------------|---------------------------------------|------------|
//! | `0xDEADBEEF` (400-byte header)  | XP 32-bit                             | XP         |
//! | `0xBADC0FFE`                    | Server 2003 / Vista / Server 2008     | NT5.2/6.0  |
//! | `0xBADC0FEE` (128-byte header)  | Windows 7 / Server 2008 R2            | Win7       |
//! | `"00ts"` marker at offset 128   | Windows 8.0 / Server 2012             | Win8.x     |
//! | `"10ts"` marker at offset 128   | Windows 8.1 / Server 2012 R2          | Win8.x     |
//! | first dword `0x30` (header len) | Windows 10 1507                       | Win10      |
//! | first dword `0x34` (header len) | Windows 10 1607+ / Windows 11         | Win10      |
//!
//! The reliable discriminant between the Win8.x and Win10 families is the
//! **ASCII marker at byte offset 128**, exactly as Zimmerman's parser tests it
//! (`"00ts"`/`"10ts"` ⇒ Win8.x; otherwise the first dword is the Win10
//! entry-array offset). The Win8.x header's first dword is documented as `0x80`
//! by libyal but has been observed as `0x00000000` in the wild (Case-001 DC01,
//! a Server 2012 R2 domain controller), so the marker — not the first dword —
//! must gate the format.

/// Windows XP AppCompatCache header magic (first dword, LE), 400-byte header.
pub const SIG_WINXP: u32 = 0xDEAD_BEEF;

/// Server 2003 / Vista / Server 2008 header magic (first dword, LE).
pub const SIG_WIN2003_VISTA: u32 = 0xBADC_0FFE;

/// Windows 7 / Server 2008 R2 header magic (first dword, LE), 128-byte header.
pub const SIG_WIN7: u32 = 0xBADC_0FEE;

/// Windows 10 1507 header: the first dword is the header **length** `0x30`,
/// immediately followed by the `"10ts"` entry array.
pub const WIN10_1507_HEADER_LEN: u32 = 0x30;

/// Windows 10 1607+ / Windows 11 header: the first dword is the header
/// **length** `0x34`, immediately followed by the `"10ts"` entry array.
pub const WIN10_1607_HEADER_LEN: u32 = 0x34;

/// Cache-entry marker for Windows 8.0 / Server 2012 (`"00ts"`).
pub const ENTRY_MARKER_WIN80: [u8; 4] = *b"00ts";

/// Cache-entry marker for Windows 8.1 / Server 2012 R2 **and** all Windows 10
/// builds (`"10ts"`). The same four bytes (`0x73743031` LE) tag every entry in
/// the 8.1 and 10 streams; the surrounding header/body differ, not the marker.
pub const ENTRY_MARKER_WIN81_WIN10: [u8; 4] = *b"10ts";

/// `"10ts"` as a little-endian `u32` (`0x73743031`) — convenience for callers
/// that compare the first dword of a header-less entry stream.
pub const ENTRY_MARKER_WIN81_WIN10_U32: u32 = 0x7374_3031;

/// Byte offset at which the Win8.0/8.1 (and Server 2012/2012 R2) entry stream
/// begins — i.e. the fixed header length for those families. The `"00ts"` /
/// `"10ts"` marker sits here.
pub const WIN8X_ENTRY_STREAM_OFFSET: usize = 128;

/// Length of the per-entry framing that precedes every entry body, shared by
/// the Win8.x and Win10 families: `signature(4) | unknown(4) | ce_data_size(4)`.
/// `ce_data_size` is the length of the body that follows these 12 bytes.
pub const ENTRY_FRAMING_LEN: usize = 12;

/// Win8.x entry body: bytes between the end of the variable-length path and the
/// FILETIME — `package_len(2) | package[package_len] | insertion_flags(4) |
/// shim_flags(4)`. The FILETIME therefore sits at
/// `path_end + 2 + package_len + WIN8X_PATH_TO_FILETIME_FIXED`.
///
/// (`insertion_flags` bit `0x2` = "Executed"; `shim_flags` follow. Source:
/// Zimmerman `Windows8x.cs`; libyal winreg-kb "Windows 8.1 application compat
/// cache entry". libyal orders the trailing 10 bytes as
/// `insertion(4) | shim(4) | unknown(2)`; Zimmerman as `pkg_len(2) | pkg |
/// ins(4) | shim(4)` — the two are indistinguishable when `package_len == 0`,
/// which holds for every non-Store entry. The fleet follows Zimmerman, the
/// maintained reference.)
pub const WIN8X_PATH_TO_FILETIME_FIXED: usize = 8;

/// Win10 entry body: the FILETIME immediately follows the variable-length path
/// (`path_size(2) | path | FILETIME(8) | data_size(4) | data`), i.e. at
/// `path_end + WIN10_PATH_TO_FILETIME` with no intervening flags.
pub const WIN10_PATH_TO_FILETIME: usize = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_are_distinct_and_ascii() {
        assert_eq!(&ENTRY_MARKER_WIN80, b"00ts");
        assert_eq!(&ENTRY_MARKER_WIN81_WIN10, b"10ts");
        assert_ne!(ENTRY_MARKER_WIN80, ENTRY_MARKER_WIN81_WIN10);
    }

    #[test]
    fn win10_marker_u32_matches_bytes() {
        assert_eq!(
            ENTRY_MARKER_WIN81_WIN10_U32.to_le_bytes(),
            ENTRY_MARKER_WIN81_WIN10
        );
    }

    #[test]
    fn header_magics_distinct() {
        let magics = [SIG_WINXP, SIG_WIN2003_VISTA, SIG_WIN7];
        for (i, a) in magics.iter().enumerate() {
            for b in &magics[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
