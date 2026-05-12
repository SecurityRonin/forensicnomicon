<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/forensicnomicon-banner-dark.png" />
    <img src="assets/forensicnomicon-transparent.png" alt="Forensicnomicon" width="520" />
  </picture>
</p>

[![crates.io](https://img.shields.io/crates/v/forensicnomicon?style=for-the-badge&logo=rust)](https://crates.io/crates/forensicnomicon)
[![docs.rs](https://img.shields.io/docsrs/forensicnomicon?style=for-the-badge)](https://docs.rs/forensicnomicon)
[![CI](https://img.shields.io/github/actions/workflow/status/SecurityRonin/forensicnomicon/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/SecurityRonin/forensicnomicon/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/forensicnomicon?style=for-the-badge)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.75+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Sponsor](https://img.shields.io/github/sponsors/h4x0r?style=for-the-badge&logo=github&label=Sponsor&color=ea4aaa)](https://github.com/sponsors/h4x0r)

**6,554 forensic artifacts. Every one enriched.**

You're in an active IR. You need to know if a binary is abusable, right now, offline, without opening a browser.

```bash
brew install SecurityRonin/tap/4n6query
# or: cargo install forensicnomicon-cli

4n6query certutil.exe          # LOLBin lookup, ATT&CK techniques, use cases
4n6query userassist            # 5 artifact variants, decoded field schemas, triage priority
4n6query T1547.001             # all artifacts mapped to this technique
4n6query --triage              # Critical artifacts to collect first, RFC 3227 order
```

Building DFIR tools in Rust? The same data is a zero-dependency library:

```toml
[dependencies]
forensicnomicon = "0.1"
```

---

## What makes it different

MITRE ATT&CK and lolbas-project.github.io are browser references. This is a binary.

- **Offline.** All 6,554 artifacts compile into the binary. Zero I/O at runtime, zero network calls.
- **Enriched.** Not just where an artifact lives — how to decode it, how strong the evidence is, what to collect alongside it, which KAPE targets and Velociraptor artifacts collect it.
- **All six LOL/LOFL datasets unified.** LOLBAS, GTFOBins, LOOBins, LOFL cmdlets, LOFL MMC snap-ins, LOFL WMI classes. One lookup, one API.

---

## LOL + LOFL — six datasets, one lookup

LOL (Living Off the Land) is abuse of OS-shipped binaries. LOFL (Living Off Foreign Land) is abuse of third-party admin tools common on enterprise endpoints: cloud CLIs, container runtimes, Sysinternals, language runtimes. Both appear identically in process telemetry and EDR alerts. Unifying them in one lookup produces fewer missed detections.

| Constant | Entries | Source |
|----------|---------|--------|
| `LOLBAS_WINDOWS` | 187 | [LOLBAS Project](https://lolbas-project.github.io/) + [LOFL Project](https://lofl-project.github.io/) |
| `LOLBAS_MACOS` | 139 | [LOOBins](https://loobins.io/) (~61 native) + [macOS LOFL catalog](https://github.com/SecurityRonin/forensicnomicon/blob/main/research/macos-lofl-catalog.yaml) (~78, first catalog of its kind) |
| `LOLBAS_LINUX` | 479 | [GTFOBins](https://gtfobins.github.io/) |
| `LOLBAS_WINDOWS_CMDLETS` | 289 | [LOFL Project](https://lofl-project.github.io/) + native PS attack cmdlets + PS aliases (Event 4104/PSReadLine) |
| `LOLBAS_WINDOWS_MMC` | 63 | [LOFL Project](https://lofl-project.github.io/) MMC snap-ins (.msc, LNK/UserAssist) |
| `LOLBAS_WINDOWS_WMI` | 30 | [LOFL Project](https://lofl-project.github.io/) WMI classes (Event 5861) |

Each constant is a `&[LolbasEntry]`. Every entry carries a name, MITRE technique IDs, a `use_cases` bitmask, and a description.

<details>
<summary>LOLBin lookup API</summary>

| Constant | Detection source |
|----------|----------------|
| `LOLBAS_WINDOWS` / `LOLBAS_LINUX` / `LOLBAS_MACOS` | Process telemetry, Prefetch, AmCache, EDR |
| `LOLBAS_WINDOWS_CMDLETS` | PowerShell ScriptBlock log (Event 4104), PSReadLine history, AMSI |
| `LOLBAS_WINDOWS_MMC` | LNK files, UserAssist MRU, Jump Lists |
| `LOLBAS_WINDOWS_WMI` | WMI Activity log (Event 5861), `Get-CimInstance` calls |

```rust
use forensicnomicon::lolbins::{
    is_lolbas, lolbas_entry,
    LOLBAS_WINDOWS, LOLBAS_LINUX, LOLBAS_MACOS,
    LOLBAS_WINDOWS_CMDLETS, LOLBAS_WINDOWS_MMC, LOLBAS_WINDOWS_WMI,
    UC_EXECUTE, UC_DOWNLOAD, UC_BYPASS,
};

// Cross-platform check
assert!(is_lolbas("certutil.exe"));
assert!(is_lolbas("bash"));
assert!(is_lolbas("osascript"));

// Rich struct lookup
let entry = lolbas_entry(LOLBAS_WINDOWS, "certutil.exe").unwrap();
assert!(entry.use_cases & UC_DOWNLOAD != 0);
println!("{}", entry.description);

// Non-binary LOFL types
assert!(is_lolbas_windows_cmdlet("Invoke-Command"));
assert!(is_lolbas_windows_mmc("compmgmt.msc"));
assert!(is_lolbas_windows_wmi("Win32_Process"));
```

</details>

---

## Artifact catalog

The catalog covers 6,554 artifacts across Windows, Linux, macOS, and cloud environments. Hundreds of entries are fully hand-curated with decoded field schemas, analyst-written meanings, triage priorities, evidence strength ratings, and detection pivots. The rest are generated from seven authoritative DFIR source corpora.

Take UserAssist. Every artifact registry gives you the key path. This catalog gives you:

| Field | Value |
|---|---|
| Decode | Value names are ROT13. Payload is a 72-byte struct: run count at offset 4, last execution FILETIME at offset 60 |
| Meaning | Proves a specific user account interactively launched a program |
| Reliability | `Strong`, but the key can be cleared. Absence does not prove non-execution. |
| Triage priority | `Critical` |
| Volatility | `Persistent` (on-disk registry). Grab RAM first per RFC 3227. |
| Detection pivots | T1204.002, 3 Sigma rules, YARA template |

<details>
<summary>What's in the catalog</summary>

**Execution evidence:** UserAssist, Prefetch, Shimcache/AppCompatCache, Amcache, BAM/DAM, MUICache, SRUM, AppShim, Windows Timeline, Background Activity Moderator

**Persistence:** Run/RunOnce keys (HKLM + HKCU), Scheduled tasks, Startup folders, Active Setup, IFEO debugger hijacking, AppInit DLLs, WMI subscriptions, Services ImagePath, Boot Execute, Print monitors, LSA packages, COM hijacking, Winlogon, Screensaver executable, Netsh helpers, Password filter DLLs

**Registry MRU and shell history:** ShellBags, Jump Lists, LNK files, OpenSave MRU, LastVisited MRU, Run MRU, TypedURLs, TypedPaths, WordWheelQuery, Recent Documents

**File system:** $MFT, USN Journal, Recycle Bin, Thumbcache, Windows Search database

**Windows Event Logs:** Security, System, PowerShell/ScriptBlock (4104), Sysmon, and 22 additional named channels including RDP, WinRM, WMI, Defender, BITS, AppLocker, Firewall, NTLM, SMB, Task Scheduler

**Credential artifacts:** SAM hive, LSA secrets, DPAPI master keys, Windows Credential Manager, Windows Hello/NGC keys, certificate stores, DCC2/MSCachev2

**Network and remote access:** RDP bitmap cache, RDP client server history, VPN/RAS phonebook, WinSCP, PuTTY, WiFi profiles, NetworkList, MountPoints2, portable devices

**Cloud, browser, and third-party:** Chrome, Edge, Firefox credential stores; TeamViewer, AnyDesk, ScreenConnect, RustDesk; OneDrive, Dropbox, Google Drive FS, MEGAsync; Teams, Slack, Discord, Signal; WinRAR history

**Active Directory:** NTDS.dit, SYSTEM boot key, DPAPI SYSTEM master key

**macOS:** LaunchAgents, LaunchDaemons, emond, Unified Log, CoreAnalytics, KnowledgeC, Keychain, TCC database, Quarantine Events, Safari, Gatekeeper, bash/zsh sessions

**Linux:** bash/zsh history, cron, systemd units, XDG autostart, SSH keys, sudoers, /etc/passwd, auth.log, systemd journal, wtmp/btmp/utmp, ld.so.preload, PAM, udev rules, cloud credentials (AWS, Azure, GCP, Kubernetes), Docker config, git credentials

**Generated entries by source:**

| Source | Entries |
|--------|---------|
| KAPE targets (EricZimmerman/KapeFiles) | 2,422 |
| ForensicArtifacts YAML | 2,545 |
| EVTX/ETW channels | 995 |
| Velociraptor artifacts | 122 |
| RECmd batch files | 44 |
| Browser artifacts (20 browsers) | 37 |
| NirSoft tools | 28 |

</details>

<details>
<summary>Catalog API: query, decode, evidence, volatility</summary>

```rust
use forensicnomicon::catalog::{CATALOG, TriagePriority};
use forensicnomicon::volatility::acquisition_order;

// RFC 3227 acquisition order: RAM first
let order = acquisition_order();

// Triage-ordered list, Critical first
let critical: Vec<_> = CATALOG
    .for_triage()
    .into_iter()
    .filter(|d| d.triage_priority == TriagePriority::Critical)
    .collect();

// Keyword search
let hits = CATALOG.filter_by_keyword("prefetch");

// MITRE technique lookup
let hits = CATALOG.by_mitre("T1547.001");

// Decode a raw artifact
let d = CATALOG.by_id("userassist_exe").unwrap();
let record = CATALOG.decode(d, value_name, raw_bytes)?;
// record.fields     — Vec<(&str, ArtifactValue)>: typed field pairs
// record.timestamp  — Option<String>: ISO 8601 UTC when present
```

Built-in decoders: `Rot13Name` (UserAssist), `FiletimeAt` (FILETIME to ISO 8601), `BinaryRecord`, `MruListEx`, `MultiSz`, `Utf16Le`.

```rust
use forensicnomicon::evidence::{evidence_for, EvidenceStrength};
use forensicnomicon::volatility::{volatility_for, acquisition_order};

let e = evidence_for("prefetch_dir").unwrap();
// e.evidence_strength — EvidenceStrength::Strong
// e.evidence_caveats  — &["Disabled by default on Server SKUs", ...]

let order = acquisition_order();
// order[0] → mem_running_processes (Volatile)
// order[n] → mft_file (Persistent)
```

</details>

---

## Abusable sites

The `abusable_sites` module maps domains attackers use for C2, phishing, payload delivery, and exfiltration. These are trusted domains that enterprises cannot block.

`BlockingRisk` encodes the key tradeoff. GitHub and AWS carry `BlockingRisk::Critical` because blocking them breaks your own CI/CD and cloud workloads. Use this field to choose between blocking (low risk) and detect-and-alert (high or critical risk).

Data from the [LOTS Project](https://lots-project.com/) and [URLhaus](https://urlhaus.abuse.ch/).

<details>
<summary>Abusable sites API</summary>

```rust
use forensicnomicon::abusable_sites::{
    is_abusable_site, abusable_site_info, sites_with_tag, sites_above_risk,
    BlockingRisk, TAG_C2,
};

assert!(is_abusable_site("raw.githubusercontent.com"));

let site = abusable_site_info("api.telegram.org").unwrap();
// site.blocking_risk        → BlockingRisk::Medium
// site.abuse_tags & TAG_C2  → true

// C2-capable domains you cannot block
let critical_c2: Vec<_> = sites_with_tag(TAG_C2)
    .filter(|s| s.blocking_risk >= BlockingRisk::Critical)
    .collect();
```

</details>

---

## `4n6query` CLI

Look up any binary, domain, or artifact from the terminal. All queries are offline.

```
$ 4n6query certutil.exe                    # LOLBin lookup, all platforms
$ 4n6query certutil.exe --platform windows # restrict to one platform
$ 4n6query curl --platform linux
$ 4n6query raw.githubusercontent.com       # abusable domain lookup
$ 4n6query userassist                      # artifact search, all variants
$ 4n6query T1547.001                       # technique lookup

$ 4n6query --triage                        # Critical artifacts first (RFC 3227 order)
$ 4n6query --triage --scenario ransomware  # filter by incident type
$ 4n6query --triage --type lateral-movement

$ 4n6query dump --format json              # full dataset for SIEM/SOAR integration
$ 4n6query dump --format yaml --dataset lolbas
$ 4n6query dump --format json --dataset catalog
$ 4n6query certutil.exe --format json      # JSON output for any query
```

`--scenario` options: `ransomware`, `data-breach`, `bec`, `insider`, `supply-chain`

`--type` options: `execution`, `persistence`, `lateral-movement`, `credential-access`, `defense-evasion`, `discovery`, `collection`, `exfiltration`, `command-and-control`, `privilege-escalation`

---

<details>
<summary>Indicator table modules</summary>

| Module | Covers | Key API |
|---|---|---|
| `ports` | C2, Cobalt Strike, Tor, WinRM, RAT defaults | `is_suspicious_port(u16)` |
| `lolbins` | All six LOL/LOFL datasets | `is_lolbas(&str)`, `lolbas_entry(catalog, name)` |
| `abusable_sites` | LOTS Project + URLhaus | `is_abusable_site(&str)`, `sites_above_risk(BlockingRisk)` |
| `processes` | Malware and masquerade process names | `is_masquerade_target(&str)` |
| `commands` | Reverse shells, download cradles, WMI abuse | `is_reverse_shell_pattern(&str)` |
| `paths` | Suspicious staging and hijack paths | path slices |
| `persistence` | Run keys, cron, LaunchAgents, IFEO, AppInit | `WINDOWS_RUN_KEYS`, `LINUX_PERSISTENCE_PATHS` |
| `antiforensics` | Log-wipe, timestomping, rootkit indicators | indicator slices |
| `remote_access` | LOLRMM/RMM tool indicators | `is_lolrmm_path(&str)` |
| `third_party` | PuTTY, WinSCP, OneDrive, Chrome, Dropbox | `identify_application(&str)` |

</details>

<details>
<summary>Enrichment modules</summary>

| Module | Key API |
|---|---|
| `attack_flow` | `flow_by_id(&str)`, `flows_for_artifact(&str)` |
| `chainsaw` | `hunt_rules_for(&str)` |
| `dependencies` | `dependencies_of(&str)`, `full_collection_set(&[&str])` |
| `eventids` | `event_entry(u32)`, `events_for_artifact(&str)` |
| `navigator` | `generate_navigator_layer(&str)`, `covered_techniques()` |
| `playbooks` | `playbook_by_id(&str)`, `playbooks_for_artifact(&str)` |
| `sigma` | `sigma_refs_for(&str)` |
| `stix` | `stix_mapping_for(&str)` |
| `temporal` | `temporal_hints_for(&str)` |
| `toolchain` | `kape_mapping_for(&str)`, `kape_target_set(&[&str])`, `velociraptor_artifact_set(&[&str])` |
| `volatility` | `acquisition_order()`, `volatility_for(&str)` |
| `yara` | `yara_rule_template(&str)` |

</details>

<details>
<summary>ArtifactDescriptor field reference</summary>

| Field | Type | Description |
|---|---|---|
| `id` | `&'static str` | Machine-readable identifier, e.g. `"userassist_exe"` |
| `name` | `&'static str` | Human-readable display name |
| `artifact_type` | `ArtifactType` | `RegistryKey`, `RegistryValue`, `File`, `Directory`, `EventLog`, `MemoryRegion` |
| `hive` | `Option<HiveTarget>` | Registry hive, or `None` for file/memory artifacts |
| `key_path` | `&'static str` | Path relative to hive root |
| `file_path` | `Option<&'static str>` | Absolute file path where applicable |
| `scope` | `DataScope` | `User`, `System`, `Network`, `Mixed` |
| `os_scope` | `OsScope` | `Win10Plus`, `Linux`, `LinuxSystemd`, `MacOS`, `MacOS12Plus` |
| `meaning` | `&'static str` | Forensic significance |
| `mitre_techniques` | `&'static [&'static str]` | ATT&CK technique IDs |
| `fields` | `&'static [FieldSchema]` | Decoded output field schema |
| `triage_priority` | `TriagePriority` | `Critical` / `High` / `Medium` / `Low` |
| `related_artifacts` | `&'static [&'static str]` | Cross-correlation artifact IDs |
| `sources` | `&'static [&'static str]` | Authoritative source URLs |

</details>

---

## Docs

| | |
|---|---|
| [API Reference](https://docs.rs/forensicnomicon) | Full rustdoc for all modules |
| [Architecture](ARCHITECTURE.md) | Data-flow: raw bytes to ArtifactRecord |

---

## Used by

- [`RapidTriage`](https://github.com/SecurityRonin/RapidTriage) — live incident response triage tool
- [`blazehash`](https://github.com/SecurityRonin/blazehash) — high-speed forensic hash verification

---

## Acknowledgments

- [**Andrew Case**](https://www.linkedin.com/in/andrewcase) — core Volatility developer; memory forensics research that underpins the artifact volatility ordering and acquisition sequence in this library
- [**Brendan Dolan-Gavitt**](https://www.cs.columbia.edu/~brendan/) — memory forensics researcher; foundational work on virtual machine introspection and memory structure analysis
- [**Volatility Foundation**](https://volatilityfoundation.org/) — the open-source memory forensics framework whose artifact taxonomy and plugin architecture shaped how this library models `MemoryRegion` artifacts
- [**Ulf Frisk / MemProcFS**](https://github.com/ufrisk/MemProcFS) — pioneered the filesystem-as-memory-interface model; MemProcFS's forensic mode and `MemoryRegion`-centric artifact layout informed this library's `MemoryRegion` artifact type and acquisition ordering
- [**jam1garner**](https://github.com/jam1garner) — creator of [`binrw`](https://github.com/jam1garner/binrw), the declarative binary parsing crate used for structured artifact decoding
