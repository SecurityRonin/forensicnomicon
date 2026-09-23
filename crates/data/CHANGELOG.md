# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.4.0...forensicnomicon-data-v1.5.0) - 2026-09-23

### Added

- *(catalog)* GREEN - iCloud Drive app container list
- *(catalog)* GREEN - OOXML and OLE2 document authorship metadata
- *(catalog)* GREEN - iWork document package format
- *(catalog)* GREEN - Calendar event store and .icbu archives
- *(catalog)* GREEN - CUPS spool jobs, printers.conf and logs
- *(catalog)* GREEN - Relocated Items folders as OS install markers
- *(catalog)* GREEN - sandboxed Safari WebKitCache and tab snapshots
- *(catalog)* GREEN - screenshot provenance xattrs
- *(catalog)* GREEN - locked Apple Notes and their encrypted attachments
- *(catalog)* GREEN - Notes attachment originals and derived renders
- *(knowledge)* GREEN - memory acquisition sources, dnf log, and the Cilium lead kept
- *(catalog)* GREEN - virtualization & WSL Linux artifacts
- *(knowledge)* GREEN - service logs: web, firewall, proxy, and Sysmon for Linux
- *(knowledge)* GREEN - journald storage semantics and distro-specific syslog routing
- *(knowledge)* GREEN - Linux account & lockout artifacts, sourced from man pages
- *(catalog)* GREEN - macOS persistence + Finder descriptors, independently sourced
- *(catalog)* GREEN - macOS usage-telemetry descriptors, independently sourced
- *(catalog)* GREEN - macOS download-provenance descriptors, independently sourced
- *(knowledge)* recover two dropped leads - one sourceable after all
- *(knowledge)* GREEN - recover the ext4 Birth-time entry that was lost
- *(knowledge)* GREEN - keep the USBSTOR/WPDBUSENUM lead as SearchedNotFound
- *(knowledge)* absorb beaconing triage and the discriminator that is absent (GREEN)
- *(knowledge)* absorb ICD 203 estimative language with its verbatim bands (GREEN)
- *(knowledge)* absorb the Diamond Model with its own axioms and scope (GREEN)
- *(knowledge)* absorb the Pyramid of Pain as published, not as retold (GREEN)
- *(knowledge)* GREEN — Prefetch volume serial vs the volume's boot record
- *(knowledge)* GREEN — LNK tracker droid-volume join, stated as observable
- *(knowledge)* GREEN — NTFS $SI-only timestomp, with the $FN residue
- *(knowledge)* the blank-Birth instrument caveat, inside the ext4 stomp entry
- *(knowledge)* GREEN — ext4 utimensat/touch -t timestomp, with its residue
- *(knowledge)* populate ToolBehaviour with six verified memory-forensics entries (GREEN)
- *(knowledge)* add EvidenceTier and four non-artifact knowledge types
- *(catalog)* add two memory descriptors, deepen 29 more, record source-count provenance
- *(catalog)* backfill 49 artifact descriptors from a coverage audit

### Documentation

- *(knowledge)* pin the vmware-vmem behaviour to its commit and region table

### Fixed

- *(catalog)* GREEN - Photos library path globs the localised bundle name
- *(catalog)* GREEN - macos_notes_db points at NoteStore.sqlite; attachments are files
- remap revoked MITRE ATT&CK IDs to their v19 successors, workspace-wide
- *(docs)* wrap Archive-<Log> in code spans so rustdoc stops parsing it as HTML
- *(knowledge)* source vol2_netscan_silent_gaps to the public issue tracker
- *(catalog)* land six researched findings, correcting three wrong statements

## [1.4.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.3.3...forensicnomicon-data-v1.4.0) - 2026-08-04

### Added

- *(catalog)* regenerate with source-merging dedup

### Fixed

- *(catalog)* GREEN — correct evtx_bits_client event-ID mapping
- *(catalog)* GREEN — wire the 52 orphaned fa descriptors, drop the dead_code mask
- *(catalog)* GREEN — one EXPECTED_CATALOG_LEN, 17 count tests become presence tests

### Other

- *(catalog)* move assessed descriptors to hand-written homes

## [1.3.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.2.1...forensicnomicon-data-v1.3.0) - 2026-07-16

### Added

- *(catalog)* Linux machine-id (/etc/machine-id) identifier descriptor
- *(catalog)* Apple hardware UUID / DSID / IDFA identifier descriptors

## [1.2.1](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.2.0...forensicnomicon-data-v1.2.1) - 2026-07-12

### Fixed

- *(ci)* fmt generated descriptors + eventids doc-lazy-continuation (rust 1.96)

## [1.2.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-data-v1.1.0...forensicnomicon-data-v1.2.0) - 2026-07-12

### Added

- *(catalog)* GREEN — dfir-scripts registry ingest source (+404 descriptors)

### Fixed

- *(catalog)* count 7103 after merging apple-atx + gcfa descriptors

### Other

- Merge branch 'gcfa-disk-descriptors' into worktree-merge-feature-branches
- Merge branch 'feat/apple-atx-knowledge' into worktree-merge-feature-branches

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
