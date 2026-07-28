//! Common USB vendor IDs → vendor name.
//!
//! A curated table of the USB vendors seen most in casework (storage controllers,
//! phone OEMs, PC OEMs). These are individual `VID → name` **facts** — not the
//! copyrightable linux-usb.org `usb.ids` compilation, which readers load at runtime
//! for full coverage. This is the zero-config KNOWLEDGE leaf a USB parser consults.
//!
//! Values verified against the linux-usb.org `usb.ids` database (© Stephen J. Gowdy).

/// A USB vendor id and its human-readable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UsbVendor {
    /// The 16-bit USB vendor id (`VID`).
    pub vid: u16,
    /// Human-readable vendor name.
    pub name: &'static str,
}

/// Curated common USB vendors. Facts sourced from linux-usb.org `usb.ids`.
pub const COMMON_USB_VENDORS: &[UsbVendor] = &[]; // RED — filled in GREEN

/// Resolve a common USB vendor id to its name, if present in [`COMMON_USB_VENDORS`].
#[must_use]
pub fn vendor_name(_vid: u16) -> Option<&'static str> {
    None // RED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_known_vendor() {
        assert_eq!(vendor_name(0x0781), Some("SanDisk Corp."));
    }

    #[test]
    fn resolves_a_phone_oem() {
        assert_eq!(vendor_name(0x05ac), Some("Apple, Inc."));
    }

    #[test]
    fn unknown_vendor_is_none() {
        assert_eq!(vendor_name(0xFFFF), None);
    }

    #[test]
    fn table_is_a_curated_subset_not_a_dump() {
        // Enough to be useful, deliberately far short of usb.ids' thousands.
        assert!(COMMON_USB_VENDORS.len() >= 40);
        assert!(COMMON_USB_VENDORS.len() < 200);
    }

    #[test]
    fn no_duplicate_vids() {
        let mut vids: Vec<u16> = COMMON_USB_VENDORS.iter().map(|v| v.vid).collect();
        vids.sort_unstable();
        let before = vids.len();
        vids.dedup();
        assert_eq!(before, vids.len(), "duplicate VID in the table");
    }
}
