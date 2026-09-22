//! Static [`CorrelationHint`] instances and the [`CORRELATION_HINTS`] slice.
//!
//! Each entry names an OBSERVABLE join between artifacts — a value that can
//! be read from both sides and compared — and states what agreement and
//! disagreement each support. A hint is never a conclusion: "the same volume
//! identifier appears in both" is observable; who created either file is not.
//! Every entry was verified against an independent primary source (a
//! normative specification or a maintained open-source implementation's
//! format documentation), cited in `sources`.

use super::CorrelationHint;

/// Every registered correlation hint. Lookup and iteration read this slice;
/// a static not referenced here is invisible to every consumer.
pub static CORRELATION_HINTS: &[CorrelationHint] = &[];
