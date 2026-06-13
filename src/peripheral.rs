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
