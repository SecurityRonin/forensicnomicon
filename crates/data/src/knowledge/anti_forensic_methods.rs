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

/// Every registered anti-forensic method. Lookup and iteration read this
/// slice; a static not referenced here is invisible to every consumer.
pub static ANTI_FORENSIC_METHODS: &[AntiForensicMethod] = &[];
