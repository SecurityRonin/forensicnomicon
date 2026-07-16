//! Fuzz target: arbitrary bytes through every PE-header parser.
//! Invariant: none of the DOS / COFF / optional-header / section parsers panic —
//! a truncated or lying header yields `None`, never an out-of-bounds index or
//! arithmetic overflow.
#![no_main]
use forensicnomicon::heuristics::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe::parse_dos_header(data);
    let _ = pe::parse_coff_header(data);
    let _ = pe::parse_optional_header_magic(data);
    let _ = pe::parse_section_entry(data);
});
