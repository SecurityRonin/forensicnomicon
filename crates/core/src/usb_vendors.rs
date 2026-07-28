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
pub const COMMON_USB_VENDORS: &[UsbVendor] = &[
    // ── Flash / storage controllers & media ──────────────────────────────
    UsbVendor {
        vid: 0x0781,
        name: "SanDisk Corp.",
    },
    UsbVendor {
        vid: 0x0951,
        name: "Kingston Technology",
    },
    UsbVendor {
        vid: 0x090c,
        name: "Silicon Motion, Inc. - Taiwan (formerly Feiya Technology Corp.)",
    },
    UsbVendor {
        vid: 0x04e8,
        name: "Samsung Electronics Co., Ltd",
    },
    UsbVendor {
        vid: 0x0930,
        name: "Toshiba Corp.",
    },
    UsbVendor {
        vid: 0x0480,
        name: "Toshiba America Inc",
    },
    UsbVendor {
        vid: 0x13fe,
        name: "Phison Electronics Corp.",
    },
    UsbVendor {
        vid: 0x154b,
        name: "PNY",
    },
    UsbVendor {
        vid: 0x18a5,
        name: "Verbatim, Ltd",
    },
    UsbVendor {
        vid: 0x8564,
        name: "Transcend Information, Inc.",
    },
    UsbVendor {
        vid: 0x1307,
        name: "Transcend Information, Inc.",
    },
    UsbVendor {
        vid: 0x058f,
        name: "Alcor Micro Corp.",
    },
    UsbVendor {
        vid: 0x1b1c,
        name: "Corsair",
    },
    UsbVendor {
        vid: 0x1f75,
        name: "Innostor Technology Corporation",
    },
    UsbVendor {
        vid: 0x1516,
        name: "CompUSA",
    },
    UsbVendor {
        vid: 0x048d,
        name: "Integrated Technology Express, Inc.",
    },
    UsbVendor {
        vid: 0x174c,
        name: "ASMedia Technology Inc.",
    },
    UsbVendor {
        vid: 0x152d,
        name: "JMicron Technology Corp. / JMicron USA Technology Corp.",
    },
    UsbVendor {
        vid: 0x14cd,
        name: "Super Top",
    },
    UsbVendor {
        vid: 0x0bda,
        name: "Realtek Semiconductor Corp.",
    },
    UsbVendor {
        vid: 0x05dc,
        name: "Lexar Media, Inc.",
    },
    UsbVendor {
        vid: 0x1058,
        name: "Western Digital Technologies, Inc.",
    },
    UsbVendor {
        vid: 0x059f,
        name: "LaCie, Ltd",
    },
    UsbVendor {
        vid: 0x125f,
        name: "A-DATA Technology Co., Ltd.",
    },
    UsbVendor {
        vid: 0x1a86,
        name: "QinHeng Electronics",
    },
    UsbVendor {
        vid: 0x10d6,
        name: "Actions Semiconductor Co., Ltd",
    },
    // ── Silicon / controller / bridge vendors ────────────────────────────
    UsbVendor {
        vid: 0x0483,
        name: "STMicroelectronics",
    },
    UsbVendor {
        vid: 0x0409,
        name: "NEC Corp.",
    },
    UsbVendor {
        vid: 0x04b4,
        name: "Cypress Semiconductor Corp.",
    },
    UsbVendor {
        vid: 0x067b,
        name: "Prolific Technology, Inc.",
    },
    UsbVendor {
        vid: 0x0b95,
        name: "ASIX Electronics Corp.",
    },
    UsbVendor {
        vid: 0x8087,
        name: "Intel Corp.",
    },
    UsbVendor {
        vid: 0x04ca,
        name: "Lite-On Technology Corp.",
    },
    // ── Phone / device OEMs (frequent MTP/USB attach) ────────────────────
    UsbVendor {
        vid: 0x05ac,
        name: "Apple, Inc.",
    },
    UsbVendor {
        vid: 0x18d1,
        name: "Google Inc.",
    },
    UsbVendor {
        vid: 0x22b8,
        name: "Motorola PCS",
    },
    UsbVendor {
        vid: 0x12d1,
        name: "Huawei Technologies Co., Ltd.",
    },
    UsbVendor {
        vid: 0x2717,
        name: "Xiaomi Inc.",
    },
    UsbVendor {
        vid: 0x1004,
        name: "LG Electronics, Inc.",
    },
    UsbVendor {
        vid: 0x0fce,
        name: "Sony Ericsson Mobile Communications AB",
    },
    UsbVendor {
        vid: 0x19d2,
        name: "ZTE WCDMA Technologies MSM",
    },
    UsbVendor {
        vid: 0x1e0e,
        name: "Qualcomm / Option",
    },
    // ── PC OEMs ──────────────────────────────────────────────────────────
    UsbVendor {
        vid: 0x413c,
        name: "Dell Computer Corp.",
    },
    UsbVendor {
        vid: 0x03f0,
        name: "HP, Inc",
    },
];

/// Resolve a common USB vendor id to its name, if present in [`COMMON_USB_VENDORS`].
#[must_use]
pub fn vendor_name(vid: u16) -> Option<&'static str> {
    COMMON_USB_VENDORS
        .iter()
        .find(|v| v.vid == vid)
        .map(|v| v.name)
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
