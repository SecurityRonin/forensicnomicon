//! Fuzz target: arbitrary bytes into the fixed 32-byte history constructors.
//! Invariant: `EpochTag::from_bytes` and `CohortKey::new` never panic on any 32-byte
//! block — the fuzz input is (zero-)padded/truncated to exactly 32 bytes, so length is
//! never the variable; this exercises the value-derivation logic on every bit pattern.
#![no_main]
use forensicnomicon::history::{epoch::EpochTag, identity::CohortKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut block = [0u8; 32];
    let n = data.len().min(32);
    block[..n].copy_from_slice(&data[..n]);
    let _ = EpochTag::from_bytes(block);
    let _ = CohortKey::new(block);
});
