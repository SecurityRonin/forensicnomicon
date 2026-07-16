# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.6.0...forensicnomicon-v1.7.0) - 2026-07-16

### Added

- *(filesystems)* GREEN — FsKind open string-backed FS-identity registry
- *(paths)* GREEN — is_executable_image + retire srum EXEC_EXTENSIONS dup

### Documentation

- reverse-engineer PRD + ADRs from the codebase

## [1.5.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.4.0...forensicnomicon-v1.5.0) - 2026-07-12

### Added

- *(browser_profiles)* GREEN — profile shapes + embedded-Chromium catalog

### Fixed

- *(ci)* fmt generated descriptors + eventids doc-lazy-continuation (rust 1.96)

## [1.4.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.3.0...forensicnomicon-v1.4.0) - 2026-07-12

### Added

- *(eventids)* GREEN — Defender/Operational + System channel event enrichment
- *(eventids)* GREEN — add Sysmon 1-20, 23-29 event-ID enrichment

## [1.3.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.2.0...forensicnomicon-v1.3.0) - 2026-07-10

### Added

- *(temporal-formats)* GREEN — authoritative timestamp-format catalog
- convert regedit_system_select from generated stub to manual descriptor
- add EventIdEntry.caveats seam + populate 4688 GPO-toggle caveats
- complete the SECURITY_LOGON_TYPE map (add 0/7/11/12/13)
- refine 104/1102 log-clearing + 4104 PowerShell scriptblock semantics
- refine ESENT 216/325 + ntdsutil for location-based ntds.dit-dump detection
- add kansa_collection_output (PowerShell-remoting IR framework) descriptor
- add ie_recovery_session (IE crash-recovery store) descriptor
- add mem_access_tokens (Primary vs Impersonation) descriptor
- add srum_app_timeline + fix the mislabeled AppTimelineProvider GUID
- add mem_extracted_pe_images (PE recovery from RAM) descriptor
- enrich shlink with ShellLinkHeader target MAC-time fields + doc
- enrich mactime/mftecmd_body/log2timeline timeline tools
- enrich psort/L2tCsv with l2tcsv deprecation + second-only caveat
- enrich fls with whole-disk offset (-o) caveat
- add MemProcFS FindEvil anomaly detections (mem_findevil) descriptor
- add NTFS MACB update-rule baseline (ntfs_macb_rules) descriptor
- add PCA PcaGeneralDb1.txt (rotating secondary) descriptor
- add WZCSVC wireless connection history (XP) descriptor
- add PhotoRec carving-output (photorec_recup_dir) descriptor
- add pinfo and image_export plaso tools
- add psteal one-step timeline tool
- add 8 Security event IDs (5140/5145/4798/4799/4778/4779/4697/5156)

### Documentation

- *(research)* mark 4624 logon-type map shipped (48 corpus items); 2 structural defers remain
- *(research)* mark 104/1102/4104 shipped (47 corpus items)
- *(research)* mark evtx_security x3 shipped (45 corpus items)
- *(research)* mark ntds_dit shipped (42 corpus items)
- *(research)* mark ESENT/ntdsutil refinement shipped (41 corpus items)
- *(research)* mark srum_app_timeline shipped (37 total, GUID bug fixed)
- *(research)* mark ntfs_objid shipped (35 corpus items, 2/7 needs-fix new)
- *(research)* mark mem_network_connections + file_carving shipped (34 total)
- *(research)* mark RecentFileCache.bcf + evtx_rdp_client shipped (24/43)
- *(research)* mark evtx_system shipped (22/43)
- *(research)* mark shlink enrichments complete (21/43)
- *(shlink)* add Win10/11 create-on-save LNK interpretation caveat
- *(research)* mark 2 shlink timestamp enrichments shipped (20/43)
- *(research)* mark mactime/mftecmd_body/log2timeline shipped (18/43)
- *(research)* mark windows_timeline shipped (15/43)
- *(research)* mark edge_webcache shipped (14/43)
- *(research)* mark usb_stor_enum shipped (13/43) + note assert-message gotcha
- *(research)* mark pca_general_db enrichment shipped (12/43)
- *(research)* defer regedit_system_select (needs generated->manual conversion)
- *(research)* mark thumbcache enrichment shipped (11/43)
- *(research)* mark 10 enrichments shipped (wordwheel_query, mounted_devices)
- *(research)* mark windows_search_db_win11 enrichment shipped
- *(research)* mark 7 enrichments shipped (mountpoints2, shimcache, evtx_ntlm)
- *(research)* mark muicache shipped, enumerate remaining enrichments
- *(research)* mark run_mru enrichment shipped
- *(research)* mark fls+psort enrichments shipped
- *(research)* add precise resume plan to ingestion corpus
- *(research)* mark ntfs_reparse_point shipped in progress tracker
- *(research)* add application-progress tracker to ingestion corpus
- *(research)* source-verified IWE+GCFA ingestion corpus + worklists
- l2tcsv caveat — legacy 17-field format, not 'industry-standard'

### Fixed

- SRUM table GUIDs — app-resource FA89, push FA86, network descriptor
- EID 1029 — Base64(SHA-256) on RDPClient/Operational, not SHA1 on RdpCoreTS

## [1.2.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.1.0...forensicnomicon-v1.2.0) - 2026-07-09

### Added

- artifact timestamp-format knowledge (timestamp_artifacts)

## [1.0.1](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v1.0.0...forensicnomicon-v1.0.1) - 2026-06-29

### Documentation

- *(readme)* bump install snippet forensicnomicon 0.12 -> 1

## [1.0.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v0.12.0...forensicnomicon-v1.0.0) - 2026-06-29

### Changed

- Stabilize the public API at 1.0. The `forensicnomicon` facade re-exports
  `forensicnomicon-core` 1.0 (report model, lookup engine, structural constants)
  and `forensicnomicon-data` 1.0 (artifact catalog, IOC, MITRE knowledge) under a
  semver-stable contract. No functional changes from 0.12.0.

## [0.12.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-v0.11.0...forensicnomicon-v0.12.0) - 2026-06-28

### Fixed

- *(release-plz)* set publish=false for ingest to match its Cargo.toml
- *(gitignore)* un-ignore the committed .claude command (unblock release-plz)

### Other

- *(release-plz)* pin release-plz/action to a digest SHA (supply-chain)
- *(public-api)* add cargo-public-api baseline gate for the published libs
- *(release-plz)* use RELEASE_PLZ_TOKEN (fallback to GITHUB_TOKEN) for the release PR
- *(release-plz)* wire fully-automated library publishing; release.yml = binaries only
- *(release)* publish all 3 library crates in dependency order; renovate range-bump
- *(data)* split forensicnomicon-data out of the umbrella (3-crate layout)
- *(core)* move catalog engine + types + rating enums into forensicnomicon-core
- *(core)* extract forensicnomicon-core with report model + structural constants
