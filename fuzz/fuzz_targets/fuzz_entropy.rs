//! Fuzz target: arbitrary bytes through the entropy + confidence-scoring math.
//! Invariant: `byte_entropy`, `is_high_entropy`, and `combine_all_confidence` never
//! panic on any input (including empty) — no division by zero, no NaN-driven panic,
//! no out-of-range index.
#![no_main]
use forensicnomicon::heuristics::{entropy, scoring};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = entropy::byte_entropy(data);
    let _ = entropy::is_high_entropy(data);
    let _ = scoring::combine_all_confidence(data);
});
