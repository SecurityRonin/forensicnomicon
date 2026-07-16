# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-core-v1.1.0...forensicnomicon-core-v1.2.0) - 2026-07-16

### Added

- *(filesystems)* GREEN — FsKind open string-backed FS-identity registry

## [1.0.0](https://github.com/SecurityRonin/forensicnomicon/compare/forensicnomicon-core-v0.1.0...forensicnomicon-core-v1.0.0) - 2026-06-29

### Changed

- Stabilize the engine API at 1.0: the `Finding` / `Severity` / `Observation`
  report model, the `ForensicCatalog` lookup engine, the rating enums, and the
  structural-constant modules are now under a semver-stable contract. No functional
  changes from 0.1.0.
