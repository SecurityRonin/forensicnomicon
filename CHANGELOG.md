# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
