# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.0.0...forensicnomicon-data-v1.1.0) - 2026-07-10

### Added

- convert regedit_system_select from generated stub to manual descriptor
- enrich evtx_security with DC-side + SMB lateral-movement events
- enrich ntds_dit with the ntdsutil IFM extraction footprint
- add kansa_collection_output (PowerShell-remoting IR framework) descriptor
- add ie_recovery_session (IE crash-recovery store) descriptor
- add mem_access_tokens (Primary vs Impersonation) descriptor
- add srum_app_timeline + fix the mislabeled AppTimelineProvider GUID
- add mem_extracted_pe_images (PE recovery from RAM) descriptor
- add NTFS Object ID index ($Extend\$ObjId:$O) descriptor
- enrich mem_network_connections with the full netscan column set
- add file_carving (signature-based recovery) descriptor
- enrich evtx_rdp_client with EID 1029 username-hash source pivot
- enrich RecentFileCache.bcf (Win7 execution-inventory predecessor)
- enrich evtx_system with DCOM activation events (lateral movement)
- enrich windows_timeline with Win11 degradation story
- enrich edge_webcache with container map + file:// local-access
- enrich usb_stor_enum with per-device connection FILETIMEs
- enrich pca_general_db with the full 8-field record + AmCache join
- enrich thumbcache with version-dependent size buckets + empty-tell
- enrich mounted_devices with the two attribution joins
- enrich wordwheel_query with derived-timestamp rule + LNK correlation
- enrich windows_search_db_win11 with the three co-resident files
- enrich evtx_ntlm with forced-auth coercion/relay context
- enrich shimcache with timestomp-exposure + rename/move inferences
- enrich mountpoints2 with UNC-share + per-subkey LastWrite semantics
- enrich muicache with renamed-binary detection + honest tiering
- enrich run_mru with decode-gotcha caveats
- add MemProcFS FindEvil anomaly detections (mem_findevil) descriptor
- add NTFS MACB update-rule baseline (ntfs_macb_rules) descriptor
- add PCA PcaGeneralDb1.txt (rotating secondary) descriptor
- add WZCSVC wireless connection history (XP) descriptor
- add PhotoRec carving-output (photorec_recup_dir) descriptor
- add NTFS reparse points (ntfs_reparse_point) descriptor
- add generic NTFS Alternate Data Stream (ntfs_ads) descriptor
- add EMDMgmt/ReadyBoost external-device volume cache descriptor
- add Task-Manager LSASS dump (lsass.DMP) descriptor
- add Amcache InventoryApplication (installed programs) descriptor
- add PSEXESVC.exe dropped-binary (PsExec target) descriptor
- add NTFS directory-index ($I30) slack descriptor
- add CDP Global Device Identifier (GDID / MSA Device PUID) descriptor
- add Thumbs.db (per-folder thumbnail cache) descriptor
- add Zone.Identifier / Mark-of-the-Web (MOTW) descriptor

### Fixed

- SRUM table GUIDs — app-resource FA89, push FA86, network descriptor
- ComDlg32 MRU keys — Win7+ PIDL variants (OpenSavePidlMRU/LastVisitedPidlMRU)
- pca_applaunch_dic — filename is PcaAppLaunchDic.txt, not AppLaunch.dic
- edge_webcache — point at WebCacheV01.dat ESE DB, type File not Directory

## [1.0.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v0.1.0...forensicnomicon-data-v1.0.0) - 2026-06-29

### Changed

- Stabilize the detection-knowledge API at 1.0 atop `forensicnomicon-core` 1.0. No
  functional changes from 0.1.0; catalog content continues to evolve additively.

## [0.1.0](https://github.com/SecurityRonin/forensicnomicon/releases/tag/forensicnomicon-data-v0.1.0) - 2026-06-28

### Other

- *(data)* fix broken intra-doc link surfaced by the public-api audit
- *(data)* split forensicnomicon-data out of the umbrella (3-crate layout)
