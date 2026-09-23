//! Static [`ExaminationProfile`] instances and the [`EXAMINATION_PROFILES`]
//! slice.
//!
//! A profile is a reusable examination checklist over the artifact catalog:
//! the artifacts to pull for a stated examination goal on one platform, each
//! member referencing an [`crate::catalog::ArtifactDescriptor`] by id and
//! carrying its own rationale. The core crate owns the schema; this module
//! owns the entries, the same core/data split as `catalog` and the other
//! knowledge types.
//!
//! Every member id MUST resolve to a real descriptor in [`crate::catalog::CATALOG`];
//! that referential integrity is the load-bearing correctness property and is
//! enforced in `tests.rs`. Where an examination area has no catalog descriptor
//! yet, the gap is recorded in the review notes rather than papered over with an
//! invented id.

// GREEN implementation follows in the next commit; the empty slice here lets the
// referential-integrity and presence tests compile and fail for the right reason
// (the profiles are absent), which is the RED state.
use super::ExaminationProfile;

/// Every registered examination profile. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static EXAMINATION_PROFILES: &[ExaminationProfile] = &[];
