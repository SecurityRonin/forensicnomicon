//! Fuzz target: arbitrary bytes as a PCA (Program Compatibility Assistant) UTF-16LE
//! record blob. Invariant: `decode_pca_utf16le` never panics on a truncated record,
//! an odd byte count, or an unterminated string — it returns whatever pairs it could
//! decode, never an index/slice panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = forensicnomicon::pca::decode_pca_utf16le(data);
});
