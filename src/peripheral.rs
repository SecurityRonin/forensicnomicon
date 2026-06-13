//! Peripheral (external-device) connection forensic knowledge.
//!
//! Constants and classification tables for reasoning about devices that attach
//! to a host over a physical or logical **bus** — USB mass storage, MTP phones,
//! FireWire/Thunderbolt DMA hardware, SD cards, etc. The taxonomy drives two
//! threat lenses:
//!
//! - **DMA capability** ([`is_dma_capable`]) — a bus-mastering transport
//!   (FireWire, Thunderbolt, PCIe, ExpressCard) can read/write host RAM
//!   directly, the DMA-attack surface (MITRE T1200).
//! - **Mass-storage class** ([`is_mass_storage`]) — a removable storage
//!   transport (USB, eSATA, SD/MMC, SCSI/SAS, NVMe) is an exfiltration and
//!   autorun-replication surface (MITRE T1052.001 / T1091).
//!
//! This module is knowledge only — the [`Bus`] enum, the
//! enumerator→bus classifier, the DMA/mass-storage predicates, the per-class
//! MITRE references, and the Windows device-property keys. Parsing
//! `setupapi.dev.log` / registry `Enum` keys into device records lives in the
//! consuming reader (`peripheral-core`), per forensicnomicon's knowledge-only
//! charter.
//!
//! # Authoritative sources
//!
//! - Microsoft — *Device Instance IDs* and *Standard USB Identifiers*: the
//!   enumerator (leading token of a device instance id, e.g. `USBSTOR`, `USB`,
//!   `1394`, `PCI`, `SCSI`, `SD`, `WpdBusEnumRoot`) names the bus driver:
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-instance-ids>
//! - libyal `winreg-kb`, *USB & USB storage device keys* — the
//!   `SYSTEM\CurrentControlSet\Enum\` enumerator layout and the device-property
//!   `{83da6326-97a6-4088-9453-a1923f573b29}` Install/First-Install timestamps:
//!   <https://github.com/libyal/winreg-kb/blob/main/documentation/USB%20storage%20device%20keys.asciidoc>
//! - Yogesh Khatri (swiftforensics) — "USB device tracking: Last-Insertion /
//!   Last-Removal times" — establishes the `0066` Last-Arrival and `0067`
//!   Last-Removal device-property `FILETIME`s, which Microsoft does NOT
//!   document (treat as inferred, not authoritative):
//!   <https://www.swiftforensics.com/2017/05/usb-device-tracking-last-insertion.html>
//! - MITRE ATT&CK — T1200 Hardware Additions, T1052.001 Exfiltration over USB,
//!   T1091 Replication Through Removable Media:
//!   <https://attack.mitre.org/techniques/T1200/> ·
//!   <https://attack.mitre.org/techniques/T1052/001/> ·
//!   <https://attack.mitre.org/techniques/T1091/>

/// The physical/logical bus a peripheral attached through.
///
/// The variant drives the DMA-capability ([`is_dma_capable`]) and
/// storage-class ([`is_mass_storage`]) threat lenses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bus {
    /// USB (host-controller mediated; not directly DMA-capable as mass storage).
    Usb,
    /// Media Transfer Protocol (phones/cameras) — surfaced via `WpdBusEnumRoot`.
    Mtp,
    /// IEEE 1394 FireWire — bus-mastering DMA.
    FireWire,
    /// Thunderbolt — PCIe-tunnelled, bus-mastering DMA.
    Thunderbolt,
    /// PCI Express — bus-mastering DMA.
    Pcie,
    /// External SATA — SATA/storage transport, explicitly NOT DMA.
    Esata,
    /// SD/MMC card.
    SdMmc,
    /// Bluetooth (typically HID/wireless).
    Bluetooth,
    /// ExpressCard — PCIe-backed, bus-mastering DMA.
    ExpressCard,
    /// SCSI / SAS storage transport.
    ScsiSas,
    /// NVMe storage.
    Nvme,
    /// Bus could not be determined from the enumerator.
    Unknown,
}

/// MITRE techniques a **DMA-capable** bus is consistent with (Hardware
/// Additions). HID/keystroke-injection hardware (BadUSB) maps here too.
pub const MITRE_DMA: &[&str] = &["T1200"];

/// MITRE techniques a **removable mass-storage** bus is consistent with
/// (Exfiltration over USB / Replication Through Removable Media).
pub const MITRE_MASS_STORAGE: &[&str] = &["T1052.001", "T1091"];

/// MITRE techniques a **HID / Bluetooth** input device is consistent with
/// (Hardware Additions — keystroke injection / rogue input).
pub const MITRE_HID: &[&str] = &["T1200"];

/// The Windows device-property category GUID under which a device-instance key
/// stores its connection timestamps:
/// `…\Enum\<id>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<key>`.
pub const DEVICE_PROPERTIES_GUID: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";

/// Device-property key `0064` — **InstallDate** (`FILETIME`). Documented by
/// Microsoft (`DEVPKEY_Device_InstallDate`).
pub const PROPERTY_INSTALL_DATE: u16 = 0x0064;

/// Device-property key `0065` — **FirstInstallDate** (`FILETIME`). Documented
/// by Microsoft (`DEVPKEY_Device_FirstInstallDate`).
pub const PROPERTY_FIRST_INSTALL_DATE: u16 = 0x0065;

/// Device-property key `0066` — **LastArrivalDate** (last connect, `FILETIME`).
///
/// UNDOCUMENTED by Microsoft: the Last-Arrival meaning is the
/// reverse-engineered forensic consensus (swiftforensics), not a published
/// `DEVPKEY`. Treat values read from it as *inferred*, not authoritative.
pub const PROPERTY_LAST_ARRIVAL_DATE: u16 = 0x0066;

/// Device-property key `0067` — **LastRemovalDate** (last disconnect,
/// `FILETIME`).
///
/// UNDOCUMENTED by Microsoft (see [`PROPERTY_LAST_ARRIVAL_DATE`]): treat as
/// *inferred*, not authoritative.
pub const PROPERTY_LAST_REMOVAL_DATE: u16 = 0x0067;

/// Classify a bus from a device-instance **enumerator** prefix — the leading
/// token of a device instance id (`USBSTOR`, `USB`, `1394`, `PCI`, `SCSI`,
/// `SD`, `WpdBusEnumRoot`, …), matched case-insensitively after trimming.
///
/// Returns [`Bus::Unknown`] for an unrecognized or empty enumerator.
#[must_use]
pub fn bus_from_enumerator(enumerator: &str) -> Bus {
    match enumerator.trim().to_ascii_uppercase().as_str() {
        "USBSTOR" | "USB" => Bus::Usb,
        "1394" => Bus::FireWire,
        "THUNDERBOLT" => Bus::Thunderbolt,
        "PCI" | "PCIE" => Bus::Pcie,
        "SCSI" | "SAS" => Bus::ScsiSas,
        "NVME" => Bus::Nvme,
        "SD" | "MMC" | "SDBUS" => Bus::SdMmc,
        "ESATA" => Bus::Esata,
        "BTHENUM" | "BTHLE" | "BLUETOOTH" => Bus::Bluetooth,
        "EXPRESSCARD" => Bus::ExpressCard,
        "WPDBUSENUMROOT" | "MTP" => Bus::Mtp,
        _ => Bus::Unknown,
    }
}

/// Whether this bus can perform **bus-mastering DMA**, the property that makes
/// a device a direct-memory-access attack surface (MITRE T1200).
///
/// DMA-capable: FireWire, Thunderbolt, PCIe, ExpressCard. Storage-class
/// transports (USB, eSATA, SD/MMC, SCSI/SAS, NVMe) and HID/wireless transports
/// (USB-HID, Bluetooth) are NOT DMA in this model.
///
/// Caveat: SD-Express tunnels PCIe and *can* be DMA-capable; this classifier
/// treats bare `SD` as the legacy non-DMA SD/MMC bus (the common case).
/// Distinguishing SD-Express needs the device-capability bits a richer source
/// carries.
#[must_use]
pub fn is_dma_capable(bus: Bus) -> bool {
    matches!(
        bus,
        Bus::FireWire | Bus::Thunderbolt | Bus::Pcie | Bus::ExpressCard
    )
}

/// Whether this bus is a removable **mass-storage** transport (the
/// data-exfiltration / autorun lens, MITRE T1052.001 / T1091).
#[must_use]
pub fn is_mass_storage(bus: Bus) -> bool {
    matches!(
        bus,
        Bus::Usb | Bus::Esata | Bus::SdMmc | Bus::ScsiSas | Bus::Nvme
    )
}

/// The MITRE ATT&CK techniques a connection over `bus` is *consistent with*
/// (never a verdict): DMA buses → [`MITRE_DMA`], mass-storage buses →
/// [`MITRE_MASS_STORAGE`], Bluetooth (HID) → [`MITRE_HID`]; otherwise empty.
#[must_use]
pub fn mitre_for(bus: Bus) -> &'static [&'static str] {
    if is_dma_capable(bus) {
        MITRE_DMA
    } else if is_mass_storage(bus) {
        MITRE_MASS_STORAGE
    } else if matches!(bus, Bus::Bluetooth) {
        MITRE_HID
    } else {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_enumerators_classify_as_usb() {
        assert_eq!(bus_from_enumerator("USBSTOR"), Bus::Usb);
        assert_eq!(bus_from_enumerator("USB"), Bus::Usb);
        assert_eq!(bus_from_enumerator("usbstor"), Bus::Usb);
    }

    #[test]
    fn firewire_scsi_pci_sd_classify() {
        assert_eq!(bus_from_enumerator("1394"), Bus::FireWire);
        assert_eq!(bus_from_enumerator("SCSI"), Bus::ScsiSas);
        assert_eq!(bus_from_enumerator("SAS"), Bus::ScsiSas);
        assert_eq!(bus_from_enumerator("PCI"), Bus::Pcie);
        assert_eq!(bus_from_enumerator("PCIE"), Bus::Pcie);
        assert_eq!(bus_from_enumerator("SD"), Bus::SdMmc);
        assert_eq!(bus_from_enumerator("MMC"), Bus::SdMmc);
        assert_eq!(bus_from_enumerator("SDBUS"), Bus::SdMmc);
    }

    #[test]
    fn mtp_thunderbolt_esata_expresscard_bluetooth_nvme_classify() {
        assert_eq!(bus_from_enumerator("WpdBusEnumRoot"), Bus::Mtp);
        assert_eq!(bus_from_enumerator("MTP"), Bus::Mtp);
        assert_eq!(bus_from_enumerator("THUNDERBOLT"), Bus::Thunderbolt);
        assert_eq!(bus_from_enumerator("ESATA"), Bus::Esata);
        assert_eq!(bus_from_enumerator("EXPRESSCARD"), Bus::ExpressCard);
        assert_eq!(bus_from_enumerator("BTHENUM"), Bus::Bluetooth);
        assert_eq!(bus_from_enumerator("BTHLE"), Bus::Bluetooth);
        assert_eq!(bus_from_enumerator("BLUETOOTH"), Bus::Bluetooth);
        assert_eq!(bus_from_enumerator("NVME"), Bus::Nvme);
    }

    #[test]
    fn unknown_and_empty_fall_back() {
        assert_eq!(bus_from_enumerator("WIBBLE"), Bus::Unknown);
        assert_eq!(bus_from_enumerator(""), Bus::Unknown);
        assert_eq!(bus_from_enumerator("  "), Bus::Unknown);
    }

    #[test]
    fn dma_capable_only_bus_mastering_transports() {
        for b in [Bus::FireWire, Bus::Thunderbolt, Bus::Pcie, Bus::ExpressCard] {
            assert!(is_dma_capable(b), "{b:?} should be DMA-capable");
        }
        for b in [
            Bus::Usb,
            Bus::Esata,
            Bus::SdMmc,
            Bus::ScsiSas,
            Bus::Nvme,
            Bus::Bluetooth,
            Bus::Mtp,
            Bus::Unknown,
        ] {
            assert!(!is_dma_capable(b), "{b:?} should NOT be DMA-capable");
        }
    }

    #[test]
    fn mass_storage_transports() {
        for b in [Bus::Usb, Bus::Esata, Bus::SdMmc, Bus::ScsiSas, Bus::Nvme] {
            assert!(is_mass_storage(b), "{b:?} should be mass-storage");
        }
        for b in [
            Bus::FireWire,
            Bus::Thunderbolt,
            Bus::Pcie,
            Bus::ExpressCard,
            Bus::Bluetooth,
            Bus::Mtp,
            Bus::Unknown,
        ] {
            assert!(!is_mass_storage(b), "{b:?} should NOT be mass-storage");
        }
    }

    #[test]
    fn mitre_for_dma_buses_is_t1200() {
        for b in [Bus::FireWire, Bus::Thunderbolt, Bus::Pcie, Bus::ExpressCard] {
            assert_eq!(mitre_for(b), &["T1200"]);
        }
        assert_eq!(mitre_for(Bus::Bluetooth), &["T1200"]);
    }

    #[test]
    fn mitre_for_mass_storage_is_exfil_and_replication() {
        for b in [Bus::Usb, Bus::Esata, Bus::SdMmc, Bus::ScsiSas, Bus::Nvme] {
            assert_eq!(mitre_for(b), &["T1052.001", "T1091"]);
        }
    }

    #[test]
    fn mitre_for_mtp_and_unknown_is_empty() {
        assert!(mitre_for(Bus::Mtp).is_empty());
        assert!(mitre_for(Bus::Unknown).is_empty());
    }

    #[test]
    fn mitre_threat_class_constants() {
        assert_eq!(MITRE_DMA, &["T1200"]);
        assert_eq!(MITRE_MASS_STORAGE, &["T1052.001", "T1091"]);
        assert_eq!(MITRE_HID, &["T1200"]);
    }

    #[test]
    fn device_property_guid_and_install_timestamp_keys() {
        assert_eq!(
            DEVICE_PROPERTIES_GUID,
            "{83da6326-97a6-4088-9453-a1923f573b29}"
        );
        assert_eq!(PROPERTY_INSTALL_DATE, 0x0064);
        assert_eq!(PROPERTY_FIRST_INSTALL_DATE, 0x0065);
        assert_eq!(PROPERTY_LAST_ARRIVAL_DATE, 0x0066);
        assert_eq!(PROPERTY_LAST_REMOVAL_DATE, 0x0067);
    }
}
