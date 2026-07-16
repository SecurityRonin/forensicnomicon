//! Fuzz target: arbitrary bytes as boot code, through both boot-code scanners.
//! Invariant: `identify_loader` and `bootkit::scan` never panic on a short or
//! non-boot buffer — signature matching is bounded, never an out-of-bounds read.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = forensicnomicon::boot_signatures::identify_loader(data);
    let _ = forensicnomicon::bootkit::scan(data);
});
