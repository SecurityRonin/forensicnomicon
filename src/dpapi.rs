//! DPAPI (Data Protection API) blob format knowledge — algorithm IDs, the
//! provider GUID, Chrome cookie prefixes, and the hash/cipher parameter tables.
//!
//! Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`) wraps secrets in a
//! `DPAPI_BLOB` whose header names a hash algorithm (`algId`) and a cipher
//! algorithm (`algIdEncrypt`) by their Wincrypt `CALG_*` constants. The session
//! key is derived as `HMAC_H(SHA1(masterKey), salt[||entropy])` and the cipher
//! key by impacket's `deriveKey`; both depend on the algorithm-specific block
//! sizes captured here.
//!
//! This module is the fleet's single source of truth for those **constants** —
//! the magic numbers only. The parsing and the RustCrypto-backed key derivation
//! / decryption live in the consuming reader (`dpapi-core`), per
//! forensicnomicon's knowledge-only charter (no I/O, no crypto here).
//!
//! # Authoritative sources
//!
//! - impacket `DPAPI` structures and `ALGORITHMS_DATA` — the reverse-engineered
//!   reference the DFIR community has settled on:
//!   <https://github.com/fortra/impacket/blob/master/impacket/dpapi.py>
//!   (`ALGORITHMS_DATA` maps each `CALG_*` to its digest / block / key / IV
//!   lengths; `DPAPI_BLOB.decrypt` / `.deriveKey` consume them.)
//! - Wincrypt `CALG_*` algorithm identifiers (`wincrypt.h`, `[MS-…]`):
//!   <https://learn.microsoft.com/windows/win32/seccrypto/alg-id>
//! - The DPAPI provider GUID `{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}` — the
//!   well-known Microsoft Base Cryptographic Provider GUID written into every
//!   `DPAPI_BLOB` header.
//! - Chromium `os_crypt` — the `v10`/`v20` AES-256-GCM cookie/value prefixes:
//!   <https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/sync/os_crypt_win.cc>

// ---------------------------------------------------------------------------
// Hash algorithm IDs (the blob's `algId`)
// ---------------------------------------------------------------------------

/// `CALG_SHA1` — SHA-1 hash (20-byte digest, 64-byte block). Wincrypt `0x8004`.
pub const CALG_SHA1: u32 = 0x8004;

/// `CALG_HMAC` — keyed-hash MAC. In a DPAPI blob this selects the **SHA-512**
/// hash module with a **64-byte** `deriveKey` salt/block field (impacket
/// `ALGORITHMS_DATA[0x8009][4] == 64`). Wincrypt `0x8009`.
pub const CALG_HMAC: u32 = 0x8009;

/// `CALG_SHA_512` — SHA-512 hash (64-byte digest, 128-byte block) with a
/// **128-byte** `deriveKey` salt/block field. Wincrypt `0x800e`.
pub const CALG_SHA_512: u32 = 0x800e;

// ---------------------------------------------------------------------------
// Cipher algorithm IDs (the blob's `algIdEncrypt`)
// ---------------------------------------------------------------------------

/// `CALG_AES_256` — AES-256 (32-byte key, 16-byte IV/block). Wincrypt `0x6610`.
pub const CALG_AES_256: u32 = 0x6610;

/// `CALG_3DES` — triple DES (24-byte key, 8-byte IV/block). Wincrypt `0x6603`.
pub const CALG_3DES: u32 = 0x6603;

// ---------------------------------------------------------------------------
// Provider GUID
// ---------------------------------------------------------------------------

/// The DPAPI provider GUID `{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}` as the 16
/// raw bytes that appear in a `DPAPI_BLOB` header.
///
/// A GUID is serialised mixed-endian: the first three components
/// (`Data1`/`Data2`/`Data3`) are little-endian, the last two (`Data4`) are
/// big-endian. So `{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}` is written on the
/// wire as `d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb`. A reader compares
/// the 16 bytes following the 4-byte version field against this const.
pub const PROVIDER_GUID_BYTES: [u8; 16] = [
    0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
];

// ---------------------------------------------------------------------------
// Chrome / Chromium cookie & value prefixes
// ---------------------------------------------------------------------------

/// Chrome/Chromium `v10` AES-256-GCM prefix — classic App-Bound encryption.
pub const CHROME_COOKIE_V10: &[u8] = b"v10";

/// Chrome/Chromium `v20` AES-256-GCM prefix (Chrome 127+ App-Bound encryption);
/// same wire layout as `v10` (`prefix | 12-byte nonce | ciphertext | 16-byte tag`).
pub const CHROME_COOKIE_V20: &[u8] = b"v20";

// ---------------------------------------------------------------------------
// Hash algorithm descriptor
// ---------------------------------------------------------------------------

/// Parameters of a DPAPI hash algorithm, mirroring impacket's `ALGORITHMS_DATA`.
///
/// Two distinct block sizes are in play and must not be conflated:
/// * `derive_block_len` is the salt/block field used by `deriveKey` (impacket
///   index `[4]`): 64 for SHA-1 and `CALG_HMAC`, 128 for `CALG_SHA_512`.
/// * `hash_block_len` is the underlying hash module's block size used by the
///   integrity check (SHA-1 = 64, SHA-512 = 128).
///
/// For `CALG_HMAC` (`0x8009`) these differ (64 vs 128), so both are tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashAlgInfo {
    /// SHA-512 hash module if `true`, SHA-1 if `false`.
    pub is_sha512: bool,
    /// Output digest length in bytes (20 for SHA-1, 64 for SHA-512).
    pub digest_len: usize,
    /// `deriveKey` salt/block field (impacket `ALGORITHMS_DATA[..][4]`).
    pub derive_block_len: usize,
    /// Underlying hash module block size (used by the integrity HMAC).
    pub hash_block_len: usize,
}

/// Resolve a DPAPI hash `algId` to its parameters, or `None` if unrecognised.
///
/// Recognises [`CALG_SHA1`] (`0x8004` → SHA-1), [`CALG_HMAC`] (`0x8009` →
/// SHA-512 module, 64-byte derive block) and [`CALG_SHA_512`] (`0x800e` →
/// SHA-512, 128-byte derive block). A caller may treat `None` as the historical
/// SHA-1 default, but the unrecognised `algId` is surfaced rather than hidden.
#[must_use]
pub const fn hash_alg_info(alg_id: u32) -> Option<HashAlgInfo> {
    match alg_id {
        CALG_SHA1 => Some(HashAlgInfo {
            is_sha512: false,
            digest_len: 20,
            derive_block_len: 64,
            hash_block_len: 64,
        }),
        CALG_HMAC => Some(HashAlgInfo {
            is_sha512: true,
            digest_len: 64,
            derive_block_len: 64,
            hash_block_len: 128,
        }),
        CALG_SHA_512 => Some(HashAlgInfo {
            is_sha512: true,
            digest_len: 64,
            derive_block_len: 128,
            hash_block_len: 128,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cipher algorithm descriptor
// ---------------------------------------------------------------------------

/// Parameters of a DPAPI cipher algorithm, mirroring impacket's `ALGORITHMS_DATA`.
///
/// The DPAPI IV is always zero-filled to `iv_len` (impacket: `iv=b'\x00'*IVLen`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherAlgInfo {
    /// Cipher key length in bytes (32 for AES-256, 24 for 3DES).
    pub key_len: usize,
    /// Cipher IV / block length in bytes (16 for AES-256, 8 for 3DES).
    pub iv_len: usize,
}

/// Resolve a DPAPI cipher `algIdEncrypt` to its parameters, or `None` if
/// unrecognised.
///
/// Recognises [`CALG_AES_256`] (`0x6610`) and [`CALG_3DES`] (`0x6603`).
#[must_use]
pub const fn cipher_alg_info(alg_id: u32) -> Option<CipherAlgInfo> {
    match alg_id {
        CALG_AES_256 => Some(CipherAlgInfo {
            key_len: 32,
            iv_len: 16,
        }),
        CALG_3DES => Some(CipherAlgInfo {
            key_len: 24,
            iv_len: 8,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calg_ids_match_wincrypt() {
        assert_eq!(CALG_SHA1, 0x8004);
        assert_eq!(CALG_HMAC, 0x8009);
        assert_eq!(CALG_SHA_512, 0x800e);
        assert_eq!(CALG_AES_256, 0x6610);
        assert_eq!(CALG_3DES, 0x6603);
    }

    #[test]
    fn provider_guid_is_well_known_dpapi_provider() {
        // {df9d8cd0-1501-11d1-8c7a-00c04fc297eb} mixed-endian on the wire.
        assert_eq!(
            PROVIDER_GUID_BYTES,
            [
                0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2,
                0x97, 0xeb,
            ]
        );
    }

    #[test]
    fn chrome_prefixes_are_three_byte_ascii() {
        assert_eq!(CHROME_COOKIE_V10, b"v10");
        assert_eq!(CHROME_COOKIE_V20, b"v20");
        assert_eq!(CHROME_COOKIE_V10.len(), 3);
        assert_eq!(CHROME_COOKIE_V20.len(), 3);
    }

    #[test]
    fn hash_alg_sha1_params() {
        let info = hash_alg_info(CALG_SHA1).expect("sha1 known");
        assert!(!info.is_sha512);
        assert_eq!(info.digest_len, 20);
        assert_eq!(info.derive_block_len, 64);
        assert_eq!(info.hash_block_len, 64);
    }

    #[test]
    fn hash_alg_hmac_uses_sha512_with_64_byte_derive_block() {
        let info = hash_alg_info(CALG_HMAC).expect("hmac known");
        assert!(info.is_sha512);
        assert_eq!(info.digest_len, 64);
        assert_eq!(info.derive_block_len, 64);
        assert_eq!(info.hash_block_len, 128);
    }

    #[test]
    fn hash_alg_sha512_uses_128_byte_derive_block() {
        let info = hash_alg_info(CALG_SHA_512).expect("sha512 known");
        assert!(info.is_sha512);
        assert_eq!(info.digest_len, 64);
        assert_eq!(info.derive_block_len, 128);
        assert_eq!(info.hash_block_len, 128);
    }

    #[test]
    fn hash_alg_unknown_is_none() {
        assert!(hash_alg_info(0x0000).is_none());
        assert!(hash_alg_info(0x8003).is_none());
    }

    #[test]
    fn cipher_alg_aes256_params() {
        let info = cipher_alg_info(CALG_AES_256).expect("aes256 known");
        assert_eq!(info.key_len, 32);
        assert_eq!(info.iv_len, 16);
    }

    #[test]
    fn cipher_alg_3des_params() {
        let info = cipher_alg_info(CALG_3DES).expect("3des known");
        assert_eq!(info.key_len, 24);
        assert_eq!(info.iv_len, 8);
    }

    #[test]
    fn cipher_alg_unknown_is_none() {
        assert!(cipher_alg_info(0x0000).is_none());
        assert!(cipher_alg_info(0x6611).is_none());
    }
}
