# forensicnomicon Enhancement Roadmap

> Produced 2026-04-19 after full codebase analysis of v0.1.0.
> Each item respects the zero-mandatory-dep / no-I/O / const-static / MSRV 1.75 constraints unless explicitly noted as feature-gated.

---

## Table of Contents

1. [Tier 1 — High-Impact, Near-Term](#tier-1--high-impact-near-term)
2. [Tier 2 — Medium-Impact, Medium-Effort](#tier-2--medium-impact-medium-effort)
3. [Tier 3 — Strategic, High-Effort](#tier-3--strategic-high-effort)
4. [Tier 4 — Visionary / Ecosystem Play](#tier-4--visionary--ecosystem-play)
5. [Cross-Cutting Concerns](#cross-cutting-concerns)
6. [Anti-Goals (Explicit Non-Targets)](#anti-goals-explicit-non-targets)

---

## Tier 1 — High-Impact, Near-Term

### 1.1 `serde` Feature Flag for Serialization

**Problem:** Consumers building DFIR pipelines, web UIs, or Sigma-to-forensicnomicon bridges need JSON/YAML/CBOR output. Today they must hand-roll serialization for every struct.

**Shape:**
```toml
[features]
serde = ["dep:serde"]

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```
- Derive `Serialize`/`Deserialize` behind `#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]` on all public types.
- `ArtifactValue` maps cleanly to serde's data model.
- Zero impact on zero-dep default. Additive only.

**Priority:** Critical. This is the number-one adoption blocker for pipeline integration.

**Effort:** Low (mechanical derive additions).

**Risk:** `serde` is the most audited crate in the Rust ecosystem. License (MIT/Apache-2.0) is compatible.

---

### 1.2 macOS Artifact Coverage

**Problem:** The crate has ~60+ Linux artifacts, ~90+ Windows artifacts, but zero macOS-specific descriptors. macOS is a first-class incident response target (corporate fleets, developer workstations, nation-state targeting).

**Artifacts to add (starter set):**
| ID | Path / Location | ATT&CK |
|----|----------------|--------|
| `macos_unified_log` | `/var/db/diagnostics/` + `log show` | T1070.001 |
| `macos_launch_agents_user` | `~/Library/LaunchAgents/*.plist` | T1543.001 |
| `macos_launch_agents_system` | `/Library/LaunchAgents/*.plist` | T1543.001 |
| `macos_launch_daemons` | `/Library/LaunchDaemons/*.plist` | T1543.004 |
| `macos_login_items` | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm` | T1547.015 |
| `macos_tcc_db` | `~/Library/Application Support/com.apple.TCC/TCC.db` | T1548 |
| `macos_kext_dir` | `/Library/Extensions/*.kext` | T1547.006 |
| `macos_spotlight_store` | `~/.Spotlight-V100/` | T1083 |
| `macos_fseventsd` | `/.fseventsd/` | T1083 |
| `macos_quarantine_events` | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | T1204.002 |
| `macos_keychain_user` | `~/Library/Keychains/login.keychain-db` | T1555.001 |
| `macos_keychain_system` | `/Library/Keychains/System.keychain` | T1555.001 |
| `macos_install_history` | `/var/log/install.log` | T1204 |
| `macos_safari_history` | `~/Library/Safari/History.db` | T1217 |
| `macos_safari_downloads` | `~/Library/Safari/Downloads.plist` | T1217 |
| `macos_knowledgeC` | `~/Library/Application Support/Knowledge/knowledgeC.db` | T1083 |
| `macos_coreanalytics` | `/Library/Logs/DiagnosticReports/*.core_analytics` | T1059 |
| `macos_sudo_log` | `/var/log/system.log` (sudo entries) | T1548.003 |
| `macos_autoruns_loginwindow` | `/etc/ttys`, login hooks | T1037.004 |
| `macos_periodic_scripts` | `/etc/periodic/daily|weekly|monthly` | T1053.003 |
| `macos_emond` | `/etc/emond.d/rules/*.plist` | T1546 |
| `macos_profiles` | `profiles show -all`, `/var/db/ConfigurationProfiles/` | T1176 |
| `macos_xprotect` | `/Library/Apple/System/Library/CoreServices/XProtect.bundle` | T1562.001 |
| `macos_gatekeeper` | `spctl --status`, related plists | T1553.001 |
| `macos_bash_sessions` | `~/.bash_sessions/` | T1059.004 |

**Shape:**
- Add `OsScope::MacOS`, `OsScope::MacOS12Plus`, `OsScope::MacOS13Plus`, `OsScope::MacOS14Plus` variants.
- Add `macos_persistence.rs` indicator table (paralleling `persistence.rs` which already has `MACOS_PERSISTENCE_PATHS`).
- ContainerProfiles for plist (binary/XML), SQLite, and Apple Unified Log.

**Priority:** Critical for enterprise adoption. Every SOC handles Macs now.

**Effort:** Medium (research-heavy but structurally identical to existing patterns).

---

### 1.3 Investigation Playbook Engine

**Problem:** The `related_artifacts` field provides basic cross-referencing, but real investigations follow directed paths: "if you found X, check Y and Z next, because adversaries who use technique A typically also leave traces at B and C."

**Shape:**
```rust
/// A directed investigation path starting from a trigger artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvestigationPath {
    /// What triggered this path (artifact ID or MITRE technique).
    pub trigger: &'static str,
    /// Human-readable scenario name.
    pub name: &'static str,
    /// Ordered sequence of artifact IDs to check.
    pub steps: &'static [InvestigationStep],
    /// ATT&CK tactics this path covers.
    pub tactics_covered: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvestigationStep {
    pub artifact_id: &'static str,
    /// Why this step matters in the context of the investigation.
    pub rationale: &'static str,
    /// What to look for specifically.
    pub look_for: &'static str,
    /// If this yields results, which follow-on steps become relevant.
    pub unlocks: &'static [&'static str],
}
```

Example playbooks:
- **Lateral Movement via RDP:** `rdp_client_servers` → `networklist_profiles` → `evtx_security` (4624 type 10) → `prefetch_file` (mstsc.exe) → `jump_list_auto` → `bam_user`
- **Credential Harvesting:** `lsa_secrets` → `dpapi_masterkey_user` → `dpapi_cred_user` → `dcc2_cache` → `ntds_dit` → `evtx_security` (4672/4768)
- **Persistence Hunt:** `run_key_hklm` → `run_key_hkcu` → `active_setup_hklm` → `winlogon_shell` → `boot_execute` → `appinit_dlls` → `ifeo_debugger` → `com_hijack_clsid_hkcu`
- **Data Exfiltration:** `chrome_cookies` → `browser_helper_objects` → `network_drives` → `portable_devices` → `usb_enum` → `recycle_bin`

**Priority:** High. This is what separates a lookup table from an expert system. No other artifact catalog offers this.

**Effort:** Medium (struct design is trivial; curating good playbooks requires DFIR expertise).

---

### 1.4 Artifact Volatility Model

**Problem:** `retention` is a free-form string. Investigators need machine-comparable volatility ordering to prioritize acquisition during live response.

**Shape:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VolatilityClass {
    /// Lost on reboot (RAM, page file contents, process handles).
    Volatile = 4,
    /// Overwritten on rotation (event logs, prefetch, circular buffers).
    RotatingBuffer = 3,
    /// Overwritten by user activity (MRU, recent docs, browser history).
    ActivityDriven = 2,
    /// Persistent until explicit deletion (registry keys, files).
    Persistent = 1,
    /// Survives deletion attempts (journal, shadow copies, slack space).
    Residual = 0,
}
```
- Add `pub volatility: VolatilityClass` to `ArtifactDescriptor`.
- Add `CATALOG.by_volatility()` returning artifacts sorted most-volatile-first.
- Add `CATALOG.acquisition_order()` that combines `triage_priority` and `volatility` into a recommended collection sequence.

**Priority:** High. RFC 3227 (Order of Volatility) is the foundation of forensic acquisition, and encoding it makes the catalog actionable for triage tooling.

**Effort:** Low-medium.

---

### 1.5 Split artifact.rs into Sub-Modules

**Problem:** `artifact.rs` is 9,864 lines. This is painful for contributors, IDE indexing, and code review. The file contains struct definitions, static data, decode logic, container profiles, parsing profiles, record signatures, and tests all interleaved.

**Shape:**
```
src/
  catalog/
    mod.rs              # re-exports, ForensicCatalog impl
    types.rs            # ArtifactDescriptor, enums, ArtifactQuery, ArtifactRecord, etc.
    decode.rs           # Decoder logic, rot13, filetime, binary field parsing
    descriptors/
      mod.rs            # CATALOG static, aggregation
      execution.rs      # userassist, prefetch, amcache, bam, shimcache
      persistence.rs    # run keys, services, scheduled tasks, COM hijack
      credential.rs     # DPAPI, LSA, DCC2, NTDS, vault, certificates
      filesystem.rs     # MFT, USN, recycle bin, LNK, jump lists
      network.rs        # network profiles, RDP, VPN, WiFi
      browser.rs        # Chrome, Firefox, Edge
      eventlog.rs       # EVTX descriptors
      linux.rs          # All Linux descriptors
      macos.rs          # (future) All macOS descriptors
    containers.rs       # ContainerProfile, ContainerSignature statics
    parsing.rs          # ArtifactParsingProfile, RecordSignature statics
    tests/
      mod.rs
      decode_tests.rs
      query_tests.rs
      descriptor_tests.rs
```
- `pub use catalog as artifact` preserves backward compat.
- Each descriptor file exports a `const` slice; `mod.rs` concatenates them (or uses `const` array concatenation when stabilized, or a build script).

**Priority:** High for maintainability. Blocking for community contributions.

**Effort:** Medium (purely mechanical refactor, but must not break public API).

---

### 1.6 Compile-Time Integrity Checks

**Problem:** With 150+ descriptors, it's easy to introduce duplicates, dangling `related_artifacts` references, missing `sources`, or MITRE IDs that don't match the ATT&CK schema.

**Shape:**
```rust
#[cfg(test)]
mod catalog_integrity {
    #[test]
    fn no_duplicate_ids() { /* ... */ }

    #[test]
    fn all_related_artifacts_exist() { /* ... */ }

    #[test]
    fn all_mitre_ids_match_pattern() {
        // T\d{4}(\.\d{3})?
    }

    #[test]
    fn all_entries_have_sources() { /* ... */ }

    #[test]
    fn no_empty_meanings() { /* ... */ }

    #[test]
    fn investigation_paths_reference_valid_artifacts() { /* ... */ }

    #[test]
    fn container_profiles_referenced_by_descriptors_exist() { /* ... */ }

    #[test]
    fn all_field_schemas_have_descriptions() { /* ... */ }

    #[test]
    fn no_orphaned_container_profiles() { /* ... */ }
}
```

**Priority:** High. Prevents knowledge rot as the catalog scales.

**Effort:** Low.

---

## Tier 2 — Medium-Impact, Medium-Effort

### 2.1 Sigma Rule Cross-Reference Table

**Problem:** Sigma is the lingua franca for detection rules. Analysts want to go from artifact → "what Sigma rules would detect activity in this artifact?" and vice versa.

**Shape:**
```rust
/// A cross-reference between a forensic artifact and Sigma detection rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigmaMapping {
    /// Artifact ID from the catalog.
    pub artifact_id: &'static str,
    /// Sigma logsource category (e.g., "process_creation", "registry_set").
    pub logsource_category: &'static str,
    /// Sigma logsource product (e.g., "windows", "linux").
    pub logsource_product: &'static str,
    /// Sigma logsource service (e.g., "sysmon", "security").
    pub logsource_service: Option<&'static str>,
    /// Representative Sigma rule IDs (from SigmaHQ) that target this artifact.
    pub sigma_rule_ids: &'static [&'static str],
    /// Human summary of what Sigma detections exist for this artifact.
    pub detection_summary: &'static str,
}
```

- New module: `src/sigma.rs`.
- `pub fn sigma_mappings_for(artifact_id: &str) -> &[SigmaMapping]`
- `pub fn artifacts_for_sigma_category(category: &str) -> Vec<&'static str>`

**Priority:** High for SOC integration. Sigma is the bridge between detection engineering and forensic analysis.

**Effort:** Medium (Sigma logsource taxonomy is well-documented; mapping to artifacts is manual but finite).

---

### 2.2 KAPE Target/Module Mapping

**Problem:** KAPE is the most widely used forensic collection tool. Analysts need to map forensicnomicon artifact IDs to KAPE target names and module names so they can programmatically build collection configs.

**Shape:**
```rust
pub struct KapeMapping {
    pub artifact_id: &'static str,
    /// KAPE target name(s) that collect this artifact.
    pub kape_targets: &'static [&'static str],
    /// KAPE module name(s) that process this artifact.
    pub kape_modules: &'static [&'static str],
    /// Velociraptor artifact name(s) equivalent.
    pub velociraptor_artifacts: &'static [&'static str],
}
```

New module: `src/toolchain.rs` — maps forensicnomicon IDs to KAPE, Velociraptor, Plaso/log2timeline parser names, and Autopsy module names.

**Priority:** High. Makes the catalog the Rosetta Stone between DFIR tools.

**Effort:** Medium.

---

### 2.3 Temporal Correlation Hints

**Problem:** Forensic analysis is fundamentally about timelines. Today, artifacts are isolated entries. Investigators need to know which artifacts produce timestamps that can be correlated.

**Shape:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalHint {
    /// Artifact ID.
    pub artifact_id: &'static str,
    /// Which decoded field contains the primary timestamp.
    pub timestamp_field: &'static str,
    /// What the timestamp represents.
    pub timestamp_semantics: TimestampSemantics,
    /// Precision of the timestamp.
    pub precision: TimestampPrecision,
    /// Clock source (helps assess reliability and skew).
    pub clock_source: ClockSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSemantics {
    /// When the event actually occurred.
    EventTime,
    /// When the record was created/written.
    WriteTime,
    /// Last modification time.
    ModifiedTime,
    /// Last access time (unreliable on modern Windows).
    AccessTime,
    /// Scheduled/future time.
    ScheduledTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPrecision {
    HundredNanoseconds, // FILETIME
    Milliseconds,       // Java epoch
    Seconds,            // Unix epoch
    Minutes,            // Some logs
    Days,               // Date-only fields
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSource {
    SystemClock,    // Affected by NTP, manual changes, timestomping
    MonotonicTick,  // e.g., uptime-based counters
    SequenceNumber, // Not a clock, but ordering
    External,       // Received from network (DNS, Kerberos)
}
```

- `pub fn timeline_sources() -> Vec<&'static TemporalHint>` — all artifacts that produce timestamps.
- `pub fn correlatable_artifacts(artifact_id: &str) -> Vec<(&'static str, &'static str)>` — other artifacts whose timestamps can be meaningfully correlated.

**Priority:** Medium-high. Timeline analysis is the core of forensic casework.

**Effort:** Medium.

---

### 2.4 Anti-Forensics Awareness Layer

**Problem:** `antiforensics.rs` lists indicators, but artifacts themselves don't know whether they are susceptible to tampering, timestomping, or deletion. An analyst looking at a Prefetch entry doesn't know "this can be trivially deleted by a local admin, and attackers commonly do so."

**Shape:**
Add to `ArtifactDescriptor`:
```rust
/// Known anti-forensic techniques that can affect this artifact.
pub anti_forensics: &'static [AntiForensicRisk],
```

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiForensicRisk {
    pub technique: AntiForensicTechnique,
    pub description: &'static str,
    /// What to look for to detect the anti-forensic action.
    pub detection_hint: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiForensicTechnique {
    Timestomping,
    LogClearing,
    FileDeletion,
    RegistryDeletion,
    Encryption,
    Steganography,
    ProcessHollowing,
    DllSideloading,
    SecureOverwrite,
    VolumeSnapshotDeletion,
}
```

**Priority:** Medium-high. Knowing what can be tampered with is as valuable as knowing what to collect.

**Effort:** Low-medium.

---

### 2.5 Evidence Grading / Confidence Model

**Problem:** Not all artifacts are equally reliable. A Prefetch file proves execution with high confidence. A registry MRU entry might have been auto-populated by the OS. A timestamp might be subject to clock skew.

**Shape:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceStrength {
    /// Definitive proof (e.g., Prefetch = execution happened).
    Definitive = 4,
    /// Strong evidence, but could have edge-case explanations.
    Strong = 3,
    /// Corroborative — useful with other evidence, not standalone.
    Corroborative = 2,
    /// Circumstantial — suggestive but easily explained away.
    Circumstantial = 1,
    /// Unreliable — known false-positive generator.
    Unreliable = 0,
}
```

Add `pub evidence_strength: EvidenceStrength` to `ArtifactDescriptor`, plus a `pub evidence_caveats: &'static [&'static str]` for known gotchas.

**Priority:** Medium. Crucial for court-admissible reporting and analyst training.

**Effort:** Low (struct change is trivial; calibrating values requires DFIR judgment).

---

### 2.6 Event Log Specific Enrichment

**Problem:** The catalog has `evtx_security`, `evtx_sysmon`, `evtx_system`, `evtx_powershell`, but forensic investigators work at the Event ID level. "Event ID 4688 in Security = process creation" is the kind of knowledge that should be queryable.

**Shape:**
```rust
pub struct EventLogEntry {
    pub log_channel: &'static str,      // "Security", "Microsoft-Windows-Sysmon/Operational"
    pub event_id: u32,
    pub name: &'static str,             // "Process Creation"
    pub description: &'static str,
    pub mitre_techniques: &'static [&'static str],
    pub key_fields: &'static [&'static str],  // ["NewProcessName", "ParentProcessName", "CommandLine"]
    pub triage_value: TriagePriority,
    /// Sigma logsource fields for cross-reference.
    pub sigma_category: Option<&'static str>,
    /// Whether Sysmon or audit policy must be enabled for this to appear.
    pub requires_configuration: Option<&'static str>,
}
```

New module: `src/eventids.rs`.

Starter coverage:
- Security: 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4771, 4776, 5140, 5145, 5156, 5158
- Sysmon: 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25, 26
- PowerShell: 4103, 4104, 4105, 4106
- System: 7034, 7035, 7036, 7040, 7045
- TaskScheduler: 106, 141, 200, 201
- WMI: 5857, 5858, 5859, 5860, 5861
- Windows Defender: 1006, 1007, 1008, 1009, 1010, 1116, 1117

**Priority:** Medium-high. Event IDs are the bread and butter of Windows forensics.

**Effort:** Medium (well-documented domain, but many entries).

---

### 2.7 `no_std` Compatibility

**Problem:** Embedded forensic tools (firmware extraction, hardware forensic devices, UEFI pre-boot analyzers) could use the catalog but can't pull in `std`.

**Shape:**
- Most of the crate is already `no_std`-compatible (const statics, no heap in lookups).
- `decode()` uses `String` and `Vec` (alloc, not std).
- Split: `#![no_std]` at crate root, `extern crate alloc` for decode functionality, gate I/O-adjacent features.
- The indicator table modules (ports, lolbins, etc.) are trivially `no_std`.

```toml
[features]
default = ["alloc"]
alloc = []  # Enables decode() and anything that allocates
std = ["alloc"]  # Future: enables error types that impl std::error::Error
```

**Priority:** Medium. Niche but high-signal for the embedded forensics community.

**Effort:** Medium (audit every use of String/Vec/format!, gate behind alloc).

---

### 2.8 YARA Rule Templates

**Problem:** Analysts often need to write YARA rules to scan for artifacts in disk images or memory dumps. The catalog knows the magic bytes (ContainerSignature), file paths, and registry key patterns — it could emit YARA rule skeletons.

**Shape:**
```rust
/// Generate a YARA rule skeleton for detecting this artifact's container on disk or in memory.
pub fn yara_rule_template(artifact_id: &str) -> Option<String>
```

Output example:
```
rule PrefetchFile {
    meta:
        description = "Windows Prefetch file (forensicnomicon: prefetch_file)"
        mitre = "T1059"
        reference = "https://..."
    strings:
        $magic = { 4D 41 4D 04 }  // from ContainerSignature
    condition:
        $magic at 0
}
```

**Priority:** Medium. Nice-to-have that showcases the catalog's depth.

**Effort:** Low (template generation from existing ContainerSignature data).

**Feature gate:** `yara-templates` (requires alloc for String building).

---

## Tier 3 — Strategic, High-Effort

### 3.1 ForensicArtifacts.com (GRR) YAML Interop

**Problem:** The [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) project (used by GRR, Plaso, dfTimewolf) is the closest thing to a standard artifact definition format. Bidirectional interop would make forensicnomicon the canonical Rust representation.

**Shape:**
- Feature-gated `forensicartifacts` module.
- `pub fn to_forensic_artifact_yaml(id: &str) -> String` — emit ForensicArtifacts YAML for any descriptor.
- `pub fn from_forensic_artifact_yaml(yaml: &str) -> Result<ArtifactDescriptor, ParseError>` — parse YAML into a descriptor (requires `serde` + `serde_yaml` as optional deps).
- CI job that diffs the catalog against the upstream ForensicArtifacts repo and reports coverage gaps.

**Priority:** Medium-high. Positions forensicnomicon as the superset, not a competitor.

**Effort:** Medium-high.

---

### 3.2 STIX 2.1 Observable Mapping

**Problem:** Threat intelligence platforms speak STIX. If forensicnomicon can emit STIX 2.1 Observed Data objects and Indicator patterns, it becomes usable in CTI workflows.

**Shape:**
```rust
/// STIX 2.1 Cyber Observable type that this artifact produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StixObservableType {
    File,
    WindowsRegistryKey,
    Process,
    NetworkTraffic,
    UserAccount,
    Directory,
    Software,
    X509Certificate,
}
```

- Add `pub stix_type: Option<StixObservableType>` to `ArtifactDescriptor`.
- Feature-gated `stix` module that can emit STIX JSON bundles.

**Priority:** Medium. Important for TIP integration but niche.

**Effort:** Medium.

---

### 3.3 Cloud Artifact Coverage

**Problem:** Modern IR increasingly involves cloud providers. AWS CloudTrail, Azure Activity Logs, GCP Audit Logs, M365 Unified Audit Log, Entra ID sign-in logs are all "forensic artifacts" in the same sense as registry keys.

**Shape:**
```rust
pub enum ArtifactType {
    // ... existing ...
    /// A cloud service log or configuration.
    CloudLog,
    /// A cloud storage object.
    CloudObject,
    /// A cloud API endpoint / configuration.
    CloudConfig,
}

pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    M365,
    Okta,
    GitHub,
}
```

Starter artifacts:
| ID | Provider | Source | ATT&CK |
|----|----------|--------|--------|
| `aws_cloudtrail` | AWS | CloudTrail logs | T1078.004 |
| `aws_guardduty` | AWS | GuardDuty findings | T1078.004 |
| `aws_s3_access_logs` | AWS | S3 access logs | T1530 |
| `aws_vpc_flow_logs` | AWS | VPC Flow Logs | T1049 |
| `azure_activity_log` | Azure | Activity Log | T1078.004 |
| `azure_signin_log` | Azure | Entra ID Sign-in | T1078.004 |
| `azure_audit_log` | Azure | Entra ID Audit | T1098 |
| `gcp_audit_log` | GCP | Cloud Audit Logs | T1078.004 |
| `m365_unified_audit` | M365 | Unified Audit Log | T1114 |
| `m365_mailbox_audit` | M365 | Mailbox Audit Log | T1114.002 |
| `okta_system_log` | Okta | System Log | T1078 |
| `github_audit_log` | GitHub | Audit Log | T1078 |

**Priority:** Medium. Cloud IR is the fastest-growing segment but strays from the crate's disk-forensics roots.

**Effort:** High (each provider has its own schema, retention model, and access pattern).

**Risk:** Scope creep. Consider a separate `forensicnomicon-cloud` crate.

---

### 3.4 Artifact Dependency Graph

**Problem:** Artifacts have implicit structural dependencies. You can't interpret a registry value without knowing its hive file. You can't parse an EVTX record without the chunk header. You can't decode a UserAssist entry without understanding the NTUSER.DAT container.

**Shape:**
```rust
pub struct ArtifactDependency {
    pub artifact_id: &'static str,
    pub depends_on: &'static str,
    pub relationship: DependencyKind,
}

pub enum DependencyKind {
    /// Must parse the container to access this artifact.
    ContainedIn,
    /// Needs context from another artifact to interpret.
    ContextFrom,
    /// Timestamps should be correlated with this artifact.
    TemporalCorrelation,
    /// This artifact is an alternative source for the same evidence.
    AlternativeSource,
}
```

- `pub fn dependency_graph() -> &'static [ArtifactDependency]`
- `pub fn prerequisites(artifact_id: &str) -> Vec<&'static str>`
- `pub fn full_collection_set(artifact_ids: &[&str]) -> Vec<&'static str>` — given a set of target artifacts, compute the minimal collection set including all dependencies.

**Priority:** Medium. Extremely useful for automated collection tool generation.

**Effort:** Medium.

---

### 3.5 Decoder Plugin Architecture

**Problem:** The `Decoder` enum is closed. Third-party crates that want to add custom decoders (e.g., for Shimcache, Amcache AppFile, WMI event subscriptions) can't extend it without forking.

**Shape:**
```rust
/// Trait for custom decoders that can be registered at runtime.
pub trait CustomDecoder: Send + Sync {
    fn id(&self) -> &str;
    fn decode(&self, raw: &[u8], name: &str) -> Result<Vec<(&str, ArtifactValue)>, DecodeError>;
}

/// Extended catalog that supports runtime-registered decoders.
pub struct ExtendedCatalog {
    base: &'static ForensicCatalog,
    custom_decoders: Vec<Box<dyn CustomDecoder>>,
    custom_descriptors: Vec<ArtifactDescriptor>,
}
```

This preserves the zero-alloc const core while allowing runtime extension.

**Priority:** Medium. Important for ecosystem growth.

**Effort:** Medium.

**Risk:** Feature-gate behind `alloc` or `std`. Must not affect the core zero-dep story.

---

### 3.6 Build-Time Code Generation from External Sources

**Problem:** Manually maintaining 150+ descriptors is error-prone. Some data sources are machine-readable (ForensicArtifacts YAML, MITRE ATT&CK STIX, SigmaHQ rules).

**Shape:**
- `build.rs` or `xtask` that:
  1. Downloads ForensicArtifacts YAML → generates `const ArtifactDescriptor` entries for coverage gaps.
  2. Downloads MITRE ATT&CK Enterprise JSON → validates all technique IDs in the catalog.
  3. Downloads SigmaHQ rules → generates `SigmaMapping` entries.
- Generated code goes into `src/generated/` and is committed (not generated at consumer build time — that would require network access).

**Priority:** Medium. Reduces maintenance burden as the catalog grows.

**Effort:** High (xtask design, schema mapping, CI integration).

---

## Tier 4 — Visionary / Ecosystem Play

### 4.1 `forensicnomicon-ffi` — C/Python/Go FFI Layer

**Problem:** The DFIR tooling ecosystem is predominantly Python (Volatility, Plaso, dfTimewolf), Go (Velociraptor), and C (Sleuth Kit). If forensicnomicon is Rust-only, it's a silo.

**Shape:**
- Companion crate `forensicnomicon-ffi` with `cbindgen`-generated C headers.
- Python bindings via `pyo3`/`maturin` → `pip install forensicnomicon`.
- Go bindings via CGo or a gRPC interface.
- WASM target for browser-based forensic dashboards.

**API surface for FFI:**
```c
// C API
const ForensicCatalog* fc_catalog_global(void);
size_t fc_catalog_count(const ForensicCatalog* c);
const ArtifactDescriptor* fc_catalog_by_id(const ForensicCatalog* c, const char* id);
const char* fc_artifact_name(const ArtifactDescriptor* d);
const char* fc_artifact_meaning(const ArtifactDescriptor* d);
// ... etc
```

```python
# Python API
from forensicnomicon import CATALOG

for art in CATALOG.by_mitre("T1547.001"):
    print(f"{art.name}: {art.meaning}")
    for step in art.investigation_path:
        print(f"  -> check {step.artifact_id}: {step.rationale}")
```

**Priority:** Medium-long term. Massive ecosystem impact if executed well.

**Effort:** High (FFI design, packaging, CI for manylinux/macOS/Windows wheels).

---

### 4.2 Interactive TUI Explorer

**Problem:** Analysts exploring the catalog need something better than grep. A TUI that lets you browse artifacts, filter by MITRE technique, see related artifacts, and follow investigation paths would be a killer demo and daily-use tool.

**Shape:**
- Companion binary crate `forensicnomicon-tui` using `ratatui` (the `tui-rs` successor).
- Panels: artifact list (filterable), detail view, investigation path viewer, MITRE heatmap.
- Vim-style keybindings.
- Export selected artifacts to JSON, KAPE targets, or Velociraptor artifact YAML.

**Priority:** Low-medium (great for adoption and demos, but not a library concern).

**Effort:** Medium.

---

### 4.3 MITRE ATT&CK Coverage Heatmap Generator

**Problem:** Security teams need to understand their detection coverage gaps. If forensicnomicon can generate an ATT&CK Navigator layer JSON showing which techniques have artifact coverage, it becomes a coverage assessment tool.

**Shape:**
```rust
/// Generate a MITRE ATT&CK Navigator layer JSON showing artifact coverage.
/// Feature-gated behind `serde` + `attck-navigator`.
pub fn generate_navigator_layer(
    artifacts: &[&ArtifactDescriptor],
    layer_name: &str,
) -> String
```

Output is a JSON file directly importable into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

**Priority:** Medium. High-visibility deliverable for security leadership.

**Effort:** Low (Navigator layer JSON schema is simple).

---

### 4.4 Forensic Artifact Changelog / Version Tracking

**Problem:** Windows artifacts change across OS versions. Prefetch format changed between Win7/Win8/Win10. UserAssist GUIDs changed. Amcache moved from RecentFileCache.bcf to Amcache.hve. The catalog should model this evolution.

**Shape:**
```rust
pub struct ArtifactVersionHistory {
    pub artifact_id: &'static str,
    pub changes: &'static [VersionChange],
}

pub struct VersionChange {
    pub os_version: OsScope,
    pub change_type: ChangeType,
    pub description: &'static str,
    pub reference: &'static str,
}

pub enum ChangeType {
    Introduced,
    FormatChanged,
    LocationMoved,
    Deprecated,
    Removed,
    BehaviorChanged,
}
```

**Priority:** Medium. Deep expertise differentiator.

**Effort:** High (requires detailed version-by-version research).

---

### 4.5 Automated Triage Collection Manifest

**Problem:** Given a set of hypotheses (e.g., "suspected lateral movement via RDP and credential theft"), generate a minimal collection manifest — which files, registry hives, and event log channels to acquire, in what order, with estimated data sizes.

**Shape:**
```rust
pub struct CollectionManifest {
    pub hypotheses: Vec<&'static str>,
    pub phases: Vec<CollectionPhase>,
    pub estimated_total_bytes: Option<u64>,
}

pub struct CollectionPhase {
    pub name: &'static str,
    pub artifacts: Vec<&'static ArtifactDescriptor>,
    pub rationale: &'static str,
    pub estimated_bytes: Option<u64>,
}
```

- `pub fn collection_manifest(hypotheses: &[&str]) -> CollectionManifest`
- Can also emit KAPE target lists or Velociraptor artifact YAML for the collection.

**Priority:** Low-medium. High value for automated IR platforms.

**Effort:** Medium.

---

### 4.6 Differential Artifact Analysis

**Problem:** Given two snapshots of a system (e.g., before and after suspected compromise), which artifacts changed? The catalog knows which artifacts to compare and what changes are significant.

**Shape:**
```rust
pub struct DiffProfile {
    pub artifact_id: &'static str,
    /// Fields that are significant for change detection.
    pub diff_fields: &'static [&'static str],
    /// What a change in this artifact typically indicates.
    pub change_significance: &'static str,
    /// Fields to ignore in diff (e.g., last-access times on modern Windows).
    pub ignore_fields: &'static [&'static str],
}
```

**Priority:** Low. Niche but powerful for baseline-comparison workflows.

**Effort:** Low-medium.

---

### 4.7 Localization / Internationalization of Meanings

**Problem:** DFIR is global. Japanese, Korean, German, and Spanish-speaking analysts would benefit from localized artifact descriptions and investigation guidance.

**Shape:**
- Feature-gated `i18n` module.
- `pub fn meaning_localized(artifact_id: &str, lang: &str) -> Option<&'static str>`
- Start with English (default) and one additional language as proof of concept.
- Translations live in `const` static tables, not resource files (preserving no-I/O).

**Priority:** Low. Nice for global adoption but heavy maintenance burden.

**Effort:** High (translation quality matters enormously in forensics).

---

### 4.8 Chainsaw / Hayabusa Rule Mapping

**Problem:** [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and [Hayabusa](https://github.com/Yamato-Security/hayabusa) are Rust-native EVTX analysis tools. Mapping forensicnomicon event log artifacts to their rule formats creates a Rust-native DFIR stack.

**Shape:**
```rust
pub struct ChainsawMapping {
    pub artifact_id: &'static str,
    pub chainsaw_rule_group: &'static str,
    pub hayabusa_rule_category: Option<&'static str>,
}
```

**Priority:** Low-medium. Rust ecosystem synergy.

**Effort:** Low.

---

### 4.9 Memory Forensics Artifact Layer

**Problem:** The catalog has `memory_image` as a ContainerProfile but no descriptors for in-memory artifacts: process VAD entries, loaded driver lists, SSDT hooks, callback registrations, injected threads, named pipes, etc.

**Shape:**
```rust
pub enum ArtifactType {
    // ... existing ...
    /// A structure or region within a memory image.
    MemoryStructure,
}
```

Starter artifacts:
| ID | Structure | ATT&CK |
|----|-----------|--------|
| `mem_eprocess` | _EPROCESS linked list | T1055 |
| `mem_loaded_drivers` | PsLoadedModuleList | T1014 |
| `mem_ssdt` | KeServiceDescriptorTable | T1014 |
| `mem_idt` | Interrupt Descriptor Table | T1014 |
| `mem_callbacks` | PspNotifyRoutines, CmCallbackListHead | T1014 |
| `mem_vad_tree` | Virtual Address Descriptor tree | T1055.001 |
| `mem_network_connections` | _TCPT_OBJECT / _TCP_ENDPOINT | T1049 |
| `mem_registry_hive_list` | CmHive linked list | T1012 |
| `mem_injected_code` | VADs with PAGE_EXECUTE_READWRITE | T1055.001 |
| `mem_named_pipes` | Named pipe objects | T1570 |
| `mem_malfind` | Executable non-image-backed pages | T1055 |

**Priority:** Medium. Memory forensics is a distinct discipline but shares the knowledge-as-code philosophy.

**Effort:** High (requires deep Windows internals knowledge per OS version).

**Risk:** Memory structure layouts change across OS versions and require version-specific offsets. Better suited for a companion crate.

---

### 4.10 Artifact Simulation / Synthetic Data Generator

**Problem:** DFIR training, tool testing, and CI pipelines need realistic forensic data. The catalog knows the exact binary layouts (BinaryField), encoding rules, and valid value ranges for artifacts.

**Shape:**
```rust
/// Feature-gated behind `simulate`.
pub fn generate_sample(artifact_id: &str, scenario: SimulationScenario) -> Vec<u8>

pub enum SimulationScenario {
    /// Normal user activity.
    Benign,
    /// Artifact showing signs of malicious activity.
    Malicious { technique: &'static str },
    /// Artifact that has been tampered with (timestomped, cleared, etc.).
    AntiForensic,
    /// Corrupted/partial artifact for parser robustness testing.
    Corrupted,
}
```

**Priority:** Low. High value for training platforms and tool CI.

**Effort:** High.

---

## Cross-Cutting Concerns

### C.1 Testing Strategy

- **Property-based testing** (via `proptest`, feature-gated): Every decoder should roundtrip — encode random data, decode, verify fields match.
- **Fuzz targets** (via `cargo-fuzz`): Every decoder path should have a fuzz target. Binary parsers are the #1 source of panics.
- **Snapshot tests**: `ArtifactDescriptor` serialization (with serde) should have insta snapshots to catch accidental regressions.
- **Coverage target**: 90%+ line coverage on decode logic; catalog lookup logic should be exhaustively tested.

### C.2 Documentation Strategy

- **Handbook expansion**: The `handbook.rs` module should become a comprehensive analyst guide, organized by investigation scenario rather than module name.
- **Worked examples**: Each artifact family should have a "how to investigate X" walkthrough in rustdoc.
- **Architecture Decision Records**: Document key design decisions (why `const`, why no I/O, why flat Decoder enum) in `docs/adr/`.

### C.3 Release Strategy

- **Semantic versioning discipline**: Adding artifacts is semver-minor. Adding struct fields is semver-major (unless `#[non_exhaustive]`).
- **Add `#[non_exhaustive]`** to all public enums and structs now (before 1.0) to preserve future extensibility without breaking changes.
- **Changelog automation**: Generate changelogs from conventional commits, grouped by artifact additions, API changes, and decoder improvements.

### C.4 Community Strategy

- **Contribution guide**: Template for adding new artifacts (fill in this struct, add these tests, cite these sources).
- **Artifact request issue template**: Structured form for requesting new artifact coverage.
- **DFIR advisory board**: Recruit 3-5 known DFIR practitioners (Harlan Carvey, Eric Zimmerman, Andrew Rathbun, etc.) as reviewers for artifact accuracy.
- **Conference talks**: SANS DFIR Summit, OSDFCon, BSides — "DFIR Knowledge as Code" is a compelling talk topic.

### C.5 Performance Considerations

- **Indexing**: The current linear scan in `by_id()`, `filter()`, and `by_mitre()` is fine for 150 entries. At 1000+ entries, consider compile-time perfect hashing (via `phf` crate, feature-gated) or sorted-slice binary search.
- **Binary size**: Monitor binary size impact. At 150 descriptors with all the static strings, the catalog adds ~200KB to the binary. Profile this and document it.
- **Compile time**: A 10,000-line single file hurts incremental compilation. The module split (1.5) is a prerequisite for scaling.

---

## Anti-Goals (Explicit Non-Targets)

These are things the crate should **not** do, to maintain focus:

1. **Full file format parsers** — No EVTX parser, no Registry hive parser, no MFT parser. Those are separate crates. This crate tells you *what* to parse and *where* to find it, not *how* to parse it byte-by-byte.

2. **Network I/O** — No fetching MITRE ATT&CK data, no downloading Sigma rules, no HTTP clients. The crate is a pure knowledge library.

3. **Platform-specific system calls** — No Windows API calls to read the live registry, no `/proc` reading. Callers provide raw bytes.

4. **GUI** — The TUI (4.2) is a companion binary, not part of the library crate.

5. **Threat intelligence feed consumption** — The crate is a reference library, not a real-time feed consumer. The `feed-watch` CI job maintains source freshness, but the crate itself is a point-in-time snapshot.

6. **Replacing existing tools** — forensicnomicon is the *knowledge layer* that existing tools can embed. It doesn't replace KAPE, Velociraptor, or Plaso — it makes them better by giving them a shared vocabulary.

---

## Priority Summary Matrix

| # | Enhancement | Impact | Effort | Priority |
|---|------------|--------|--------|----------|
| 1.1 | serde feature flag | Critical | Low | **P0** |
| 1.2 | macOS artifacts | Critical | Medium | **P0** |
| 1.3 | Investigation playbooks | High | Medium | **P1** |
| 1.4 | Volatility model | High | Low | **P1** |
| 1.5 | Split artifact.rs | High | Medium | **P1** |
| 1.6 | Compile-time integrity | High | Low | **P1** |
| 2.1 | Sigma cross-reference | High | Medium | **P1** |
| 2.2 | KAPE/Velociraptor mapping | High | Medium | **P1** |
| 2.3 | Temporal correlation | Medium-high | Medium | **P2** |
| 2.4 | Anti-forensics awareness | Medium-high | Low-medium | **P2** |
| 2.5 | Evidence grading | Medium | Low | **P2** |
| 2.6 | Event ID enrichment | Medium-high | Medium | **P2** |
| 2.7 | no_std support | Medium | Medium | **P2** |
| 2.8 | YARA templates | Medium | Low | **P2** |
| 3.1 | ForensicArtifacts interop | Medium-high | Medium-high | **P2** |
| 3.2 | STIX 2.1 mapping | Medium | Medium | **P3** |
| 3.3 | Cloud artifacts | Medium | High | **P3** |
| 3.4 | Dependency graph | Medium | Medium | **P2** |
| 3.5 | Decoder plugins | Medium | Medium | **P3** |
| 3.6 | Build-time codegen | Medium | High | **P3** |
| 4.1 | FFI layer | High (ecosystem) | High | **P3** |
| 4.2 | TUI explorer | Medium | Medium | **P3** |
| 4.3 | ATT&CK heatmap | Medium | Low | **P2** |
| 4.4 | Version tracking | Medium | High | **P3** |
| 4.5 | Collection manifest | Low-medium | Medium | **P3** |
| 4.6 | Differential analysis | Low | Low-medium | **P4** |
| 4.7 | i18n | Low | High | **P4** |
| 4.8 | Chainsaw/Hayabusa mapping | Low-medium | Low | **P3** |
| 4.9 | Memory forensics | Medium | High | **P3** |
| 4.10 | Synthetic data gen | Low | High | **P4** |

---

## Suggested Execution Order (v0.2 → v1.0)

### v0.2 — Foundation
1. Add `#[non_exhaustive]` to all public enums/structs
2. `serde` feature flag (1.1)
3. Compile-time integrity tests (1.6)
4. Volatility model (1.4)
5. Evidence grading (2.5)

### v0.3 — Platform Parity
1. Split artifact.rs (1.5)
2. macOS artifact coverage (1.2)
3. OsScope variants for macOS

### v0.4 — Intelligence Layer
1. Investigation playbooks (1.3)
2. Event ID enrichment (2.6)
3. Anti-forensics awareness (2.4)

### v0.5 — Ecosystem Bridges
1. Sigma cross-reference (2.1)
2. KAPE/Velociraptor mapping (2.2)
3. ATT&CK Navigator layer (4.3)
4. Temporal correlation (2.3)

### v0.6 — Advanced
1. Artifact dependency graph (3.4)
2. YARA templates (2.8)
3. ForensicArtifacts interop (3.1)
4. no_std support (2.7)

### v1.0 — Stable API
1. API review and stabilization
2. `#[non_exhaustive]` audit
3. Full documentation pass
4. Comprehensive property-based and fuzz testing
5. Community contribution guide

### Post-1.0
- FFI layer (4.1)
- Cloud artifacts (3.3)
- Memory forensics (4.9)
- TUI explorer (4.2)
- Decoder plugins (3.5)
