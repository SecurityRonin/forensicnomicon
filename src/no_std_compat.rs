//! Validation tests for `no_std`-compatible APIs.
//!
//! # `no_std` boundary
//!
//! This crate is designed so that its static indicator tables and core catalog
//! data are accessible in `#![no_std]` environments (embedded systems, UEFI
//! bootloaders, custom OS kernels) when the `std` feature is disabled.
//!
//! ## Modules that work without `std`
//!
//! The following modules depend only on `core` (primitive types, `&'static`
//! slices, scalar math) and are therefore fully available without the `std`
//! feature:
//!
//! | Module | Public surface |
//! |---|---|
//! | [`crate::ports`] | `SUSPICIOUS_PORTS`, `is_suspicious_port` |
//! | [`crate::lolbins`] | `LOLBAS_WINDOWS`, `LOLBAS_LINUX`, `LOLBAS_MACOS`, `is_lolbas_windows`, `is_lolbas_linux`, `is_lolbas_macos`, `is_lolbas` |
//! | [`crate::persistence`] | `WINDOWS_RUN_KEYS`, `LINUX_PERSISTENCE_PATHS`, `is_persistence_key` |
//! | [`crate::antiforensics`] | `ANTIFORENSICS_TOOLS`, `is_antiforensics_tool` |
//! | [`crate::paths`] | `WINDOWS_ARTIFACT_PATHS`, `LINUX_ARTIFACT_PATHS` |
//! | [`crate::processes`] | `SUSPICIOUS_PROCESSES`, `is_suspicious_process` |
//! | [`crate::commands`] | `SUSPICIOUS_COMMANDS`, `is_suspicious_command` |
//! | [`crate::encryption`] | `ENCRYPTION_TOOLS`, `is_encryption_tool` |
//! | [`crate::remote_access`] | `REMOTE_ACCESS_TOOLS`, `is_remote_access_tool` |
//! | [`crate::catalog`] | `CATALOG.list()`, `CATALOG.by_id()` (slice/Option — no allocation) |
//!
//! All `const`/`static` tables in these modules are constructible at compile
//! time from `core`-only types and work in any Rust target profile.
//!
//! ## Modules that require `std`
//!
//! The following modules allocate (`Vec`, `HashMap`, `String`) or otherwise
//! depend on `std` and are only compiled when the `std` feature is active
//! (the default):
//!
//! - `catalog::filter`, `catalog::record_signatures_for_artifact` (return `Vec`)
//! - `navigator` — `HashMap`-based ATT&CK navigator layer builder
//! - `yara` — `String`-based YARA rule generator
//! - `sigma` — `String`-based Sigma rule generator
//! - `temporal`, `evidence`, `references`, `playbooks` — owned `String`/`Vec` APIs
//! - `stix`, `forensicartifacts`, `chainsaw`, `toolchain`, `plugin` — JSON/output builders
//!
//! ## How to enable `no_std` mode
//!
//! In your `Cargo.toml` dependency entry, disable the default `std` feature:
//!
//! ```toml
//! [dependencies]
//! forensicnomicon = { version = "...", default-features = false }
//! ```
//!
//! You will still have access to all the modules listed in the first table above.
//! The `serde` feature can be combined with `no_std` when a suitable allocator is
//! available (e.g. `extern crate alloc`), but requires the consuming crate to
//! provide `serde` with `no_std`+`alloc` support independently.

#[cfg(test)]
mod tests {
    /// `is_suspicious_port` uses only `SUSPICIOUS_PORTS: &[u16]` and the
    /// primitive `u16::contains` — no allocation, works in `no_std`.
    #[test]
    fn ports_has_no_std_compatible_api() {
        assert!(
            crate::ports::is_suspicious_port(4444),
            "4444 (Metasploit default) must be flagged"
        );
        assert!(
            !crate::ports::is_suspicious_port(80),
            "port 80 (HTTP) must not be flagged"
        );
    }

    /// `is_lolbas_windows` / `is_lolbas_linux` use only `&[&'static str]` and
    /// `str::to_ascii_lowercase` — both are `core` operations.
    #[test]
    fn lolbins_has_no_std_compatible_api() {
        assert!(
            crate::lolbins::is_lolbas_windows("certutil.exe"),
            "certutil.exe must be a Windows LOLBAS binary"
        );
        assert!(
            crate::lolbins::is_lolbas_linux("bash"),
            "bash must be a Linux LOLBAS binary"
        );
        assert!(
            !crate::lolbins::is_lolbas_windows("notepad.exe"),
            "notepad.exe must not be a LOLBAS binary"
        );
    }

    /// Persistence key tables are `&[&'static str]` — zero allocation.
    #[test]
    #[allow(clippy::const_is_empty)]
    fn persistence_keys_are_static() {
        assert!(
            !crate::persistence::WINDOWS_RUN_KEYS.is_empty(),
            "WINDOWS_RUN_KEYS must be non-empty"
        );
        assert!(
            !crate::persistence::LINUX_PERSISTENCE_PATHS.is_empty(),
            "LINUX_PERSISTENCE_PATHS must be non-empty"
        );
    }

    /// `CATALOG.list()` returns `&[ArtifactDescriptor]` — a borrowed slice, no
    /// allocation.  `by_id` returns `Option<&ArtifactDescriptor>` — also
    /// allocation-free.  Both are usable in `no_std` environments.
    #[test]
    fn catalog_static_access_is_allocation_free() {
        use crate::catalog::CATALOG;

        let entries = CATALOG.list();
        assert!(
            entries.len() > 100,
            "CATALOG should contain >100 entries, got {}",
            entries.len()
        );

        // by_id is a slice scan — core-only, no allocation
        let found = CATALOG.by_id("userassist_exe");
        assert!(
            found.is_some(),
            "CATALOG.by_id(\"userassist_exe\") must find an entry"
        );
    }
}
