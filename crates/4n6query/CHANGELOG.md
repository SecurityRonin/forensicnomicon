# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-cli-v0.1.1...forensicnomicon-cli-v0.1.2) - 2026-06-28

### Documentation

- *(readme)* update for the 3-crate split

## [0.1.1](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-cli-v0.1.0...forensicnomicon-cli-v0.1.1) - 2026-06-28

### Added

- *(4n6query-cli)* GREEN — event ids, sigma, flows, profiles in dump + query
- *(4n6query-tui)* GREEN — browse BYOVD drivers + threat indicators
- *(4n6query)* wire BYOVD drivers + threat-indicator index into the CLI

### Fixed

- *(ci)* anchor WixUILicenseRtf to repo root (LGHT0103)
- *(ci)* fix WiX comment CNDL0104 and use --no-build for deb (bin!=pkg name)
- *(ci)* align deb job with sqlite-forensic proven pattern; surface WiX candle error
- *(ci)* repair deb asset path and WiX Source paths for 4n6query binaries
- *(lints)* GREEN — remediate Paranoid Gatekeeper violations to clippy-clean

### Other

- *(4n6query-cli)* RED — event ids, sigma, flows, profiles via dump + query
- *(4n6query-tui)* RED — BYOVD drivers + threat-indicators panes
- *(4n6query)* extract indicator index into shared indicators.rs
- *(readme)* officially position forensicnomicon as DFIR Knowledge-as-Code (KaC)
- *(lints)* RED — enable Paranoid Gatekeeper lint set
