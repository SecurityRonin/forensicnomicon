//! Fuzz target: arbitrary bytes through the single-byte-XOR deobfuscation helpers.
//! The first fuzz byte is the XOR key; the rest is the obfuscated payload. Invariant:
//! `deobf` and `starts_with_obf` never panic on any key/payload — decoding is a pure
//! byte map, never an index panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (key, obf) = match data.split_first() {
        Some((k, rest)) => (*k, rest),
        None => (0u8, &[][..]),
    };
    let _ = forensicnomicon::obf::deobf(obf, key);
    // A separate haystack derived from the same bytes exercises the prefix check.
    let haystack = String::from_utf8_lossy(obf);
    let _ = forensicnomicon::obf::starts_with_obf(&haystack, obf, key);
});
