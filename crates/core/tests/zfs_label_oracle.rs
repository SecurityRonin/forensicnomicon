//! Tier-2 real-artifact cross-check for the structural ZFS detector.
//!
//! Validates [`forensicnomicon_core::filesystems::detect_zfs`] against a genuine
//! OpenZFS vdev label, not a fixture we authored. The label is the L0 vdev
//! label (device offset 0, 256 KiB) minted by OpenZFS `zol-0.6.1`; its uberblock
//! ring holds the `0x00bab10c` magic 32× starting at `0x21000` (the ring start
//! `0x20000` is zeros), which is precisely the data-dependent layout the
//! fixed-offset signature table cannot represent.
//!
//! Provenance: the file lives in the sibling `zfs-forensic` repo at
//! `tests/data/zfs_zol061_vdev0_label0.bin` (md5 `5351411f80df20ddea67629b1fca14d5`,
//! 262144 bytes), not committed here. Env-gated: point `ZFS_LABEL_FIXTURE` at it
//! to run; the test skips cleanly when the var is unset (fleet oracle-test idiom).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon_core::filesystems::{detect_name, detect_zfs};

#[test]
fn detect_zfs_on_real_openzfs_label() {
    let Ok(path) = std::env::var("ZFS_LABEL_FIXTURE") else {
        eprintln!("skipping: set ZFS_LABEL_FIXTURE to the real OpenZFS vdev label to run");
        return;
    };
    let bytes = std::fs::read(&path).expect("read ZFS_LABEL_FIXTURE");
    assert!(
        detect_zfs(&bytes),
        "real OpenZFS zol-0.6.1 label must be detected by detect_zfs"
    );
    assert_eq!(detect_name(&bytes), Some("ZFS"));
}
