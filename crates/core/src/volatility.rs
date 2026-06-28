//! Artifact volatility model — RFC 3227 Order of Volatility encoded as data.
//!
//! [`VolatilityClass`] is the rating type stored on
//! [`crate::catalog::ArtifactDescriptor::volatility`]. The catalog-querying helpers
//! (`volatility_for`, `acquisition_order`) live in the umbrella `forensicnomicon`
//! crate, where the assembled global catalog is wired.

/// Acquisition urgency for a forensic artifact under RFC 3227 Order of Volatility.
///
/// Values run from 0 (lowest urgency / most stable) to 4 (highest urgency / most
/// ephemeral). `acquisition_order` (umbrella crate) returns artifacts sorted 4→0
/// (most ephemeral first), matching live-response triage practice.
///
/// ## Choosing the right class
///
/// | Class | Collect when | Rationale |
/// |---|---|---|
/// | `Volatile` | Immediately — before reboot | Only in RAM |
/// | `RotatingBuffer` | Before buffer fills | Fixed-size circular store |
/// | `ActivityDriven` | Before more user activity | Overwritten by normal use |
/// | `Persistent` | Standard scheduled collection | Present until explicit deletion |
/// | `Residual` | Last — always present on a live volume | Storage-level structure |
///
/// ## What `Residual` means — and what it does NOT mean
///
/// `Residual` is the **lowest acquisition urgency** class. Use it only for artifacts
/// that are **structurally present on any live mounted volume** and cannot be
/// destroyed by normal system operation (only by reformatting, physical destruction,
/// or deliberate forensic manipulation). The canonical example is `$MFT` — any
/// mounted NTFS volume always has an MFT; it is the last artifact you need to rush
/// to collect.
///
/// **`Residual` does NOT mean "recoverable via .LOG1/.LOG2, VSS, or $UsnJrnl after
/// deletion."** That property applies to virtually every NTFS artifact and provides
/// no discrimination between classes. A registry key that *could* be recovered from
/// a transaction log after deletion is `Persistent` while it exists — use `Persistent`
/// for all live registry keys and files regardless of post-deletion recoverability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VolatilityClass {
    /// Storage-level artifact inherently present on any live mounted volume — cannot
    /// be destroyed by normal system operation. Lowest acquisition urgency: collect
    /// last. Example: `$MFT` (always present on NTFS), Volume Boot Record.
    ///
    /// **Not** a synonym for "recoverable via VSS/.LOG1/.LOG2 after deletion" — that
    /// applies to virtually all NTFS artifacts and is not discriminating.
    Residual = 0,
    /// Present in its primary location until explicitly deleted. Default class for
    /// registry keys, configuration files, and most forensic artifacts on a live
    /// system. Examples: Run keys, NTDS.dit, event log files (the file itself, not
    /// its contents — for contents see `RotatingBuffer`).
    Persistent = 1,
    /// Overwritten by ordinary user activity; degrades with normal system use.
    /// Examples: MRU lists, Recent Documents, browser history, typed URL cache.
    ActivityDriven = 2,
    /// Overwritten when a fixed-size circular buffer fills; oldest entries lost.
    /// Examples: Windows Event Log records (when log reaches max size), Prefetch
    /// files (128-entry limit), $UsnJrnl (wraps based on configured max size).
    RotatingBuffer = 3,
    /// Lost on reboot or process termination; exists only in volatile memory.
    /// Collect immediately in a live response before system shutdown.
    /// Examples: RAM contents, process handles, network connections, open file
    /// handles, the in-memory ShimCache state not yet flushed to registry.
    Volatile = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatility_ordering_is_consistent() {
        assert!(VolatilityClass::Volatile > VolatilityClass::RotatingBuffer);
        assert!(VolatilityClass::RotatingBuffer > VolatilityClass::ActivityDriven);
        assert!(VolatilityClass::ActivityDriven > VolatilityClass::Persistent);
        assert!(VolatilityClass::Persistent > VolatilityClass::Residual);
    }
}
