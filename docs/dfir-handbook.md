# DFIR Handbook

This handbook is the analyst-facing entry point for `forensicnomicon`.

## What this crate does

Most artifact registries tell you *where* an artifact lives. forensicnomicon
tells you what it **means** — and gives your tool the structured knowledge to
act on that meaning automatically.

Every artifact entry carries a set of **enrichments**:

| Enrichment | What it answers |
|---|---|
| **Decode** | How to turn raw bytes into structured fields (ROT13, FILETIME, MRU order, binary layout) |
| **Meaning** | What the artifact proves forensically and how it differs from similar artifacts |
| **Reliability** | Evidence strength (`Unreliable` → `Definitive`) and analyst caveats |
| **Triage priority** | `Critical` / `High` / `Medium` / `Low` — what to look at first in a constrained window |
| **Volatility** | RFC 3227 class (`Volatile` → `Residual`) — acquisition order for live response |
| **Dependencies** | What else you need to collect or decrypt this artifact |
| **Detection pivots** | MITRE ATT&CK techniques, Sigma rules, YARA templates, Chainsaw rules |

The catalog holds **6,548 artifacts** total. 361 are fully curated with all
enrichments above. The remaining 6,187 are generated from seven authoritative
corpora (KAPE targets, ForensicArtifacts YAML, EVTX/ETW channels, Velociraptor,
RECmd batch files, browser paths, NirSoft paths) and carry location, OS scope,
decoder, and source citation.

Use this handbook when you need to answer questions like:

- what artifacts matter first during triage?
- where should I look for execution, persistence, or credential evidence?
- how does this crate model parsing and carving knowledge?
- which source material justifies a given artifact or module?

The crate is a knowledge and enrichment model, not a full parser suite. Use it
to identify, prioritize, and interpret artifacts; pair it with collection and
parsing tools for the rest.

## Reading Order

1. Start with [`crate::catalog::CATALOG`] — query by triage priority, MITRE technique, or keyword.
2. Use [`crate::volatility::acquisition_order`] to determine what to collect first on a live machine.
3. Use [`crate::evidence::evidence_for`] to understand how reliable each artifact is as evidence.
4. Use [`crate::dependencies::full_collection_set`] to compute the transitive artifact set for an investigation.
5. Use [`crate::playbooks`] for directed investigation paths from a trigger artifact.
6. Use [`crate::references`] for module-level provenance.
7. Use container, parsing, and signature profiles when you need acquisition, decoding, or carving boundaries.

## Core Knowledge Layers

The crate keeps DFIR knowledge in explicit layers:

- `ModuleReference`
  Broad provenance for small indicator modules and the artifact catalog as a whole.
- `ArtifactDescriptor`
  The answer to “where does this artifact live, and why does it matter?”
- `ContainerProfile`
  How to open the outer container, such as a Registry hive, SQLite database, EVTX log, OLE compound file, or memory-bearing source.
- `ContainerSignature`
  How to recognize or carve that outer container from raw bytes.
- `ArtifactParsingProfile`
  Artifact-specific semantics above the container layer, such as `UserAssist` ROT13 or WMI subscription relationships.
- `RecordSignature`
  How to recognize or validate individual records or payload fragments inside a container.
- `Decoder`
  Compact, stable transforms implemented directly in the crate.

## High-Value Artifact Families

### Execution

Focus here when you need evidence that something ran:

- `userassist_exe`
- `prefetch_dir`
- `prefetch_file`
- `amcache_app_file`
- `shimcache`
- `bam_user`
- `dam_user`
- `powershell_history`
- `windows_timeline`
- `srum_app_resource`

Cross-correlation pattern:

- `UserAssist` and `Prefetch` strengthen interactive execution
- `Amcache` and `ShimCache` strengthen file-presence and execution-history claims
- `BAM` and `DAM` help with last execution timing
- `PowerShell history` adds command-level context

### Persistence

Focus here when you need autoruns or durable footholds:

- `run_key_hkcu`
- `run_key_hklm_run`
- `run_key_hkcu_runonce`
- `run_key_hklm_runonce`
- `scheduled_tasks_dir`
- `startup_folder_user`
- `startup_folder_system`
- `services_imagepath`
- `wmi_mof_dir`
- `wmi_subscriptions`
- `logon_scripts`

Cross-correlation pattern:

- Registry autoruns explain launch intent
- Startup folders and scheduled tasks explain user or boot-triggered launch
- WMI artifacts explain stealthier persistence that may not appear in common autorun-only tooling

### Credential Access

Focus here when you need local secret material or browser credential evidence:

- `dpapi_masterkey_user`
- `dpapi_cred_user`
- `dpapi_cred_roaming`
- `windows_vault_user`
- `windows_vault_system`
- `chrome_login_data`
- `firefox_logins`
- `vpn_ras_phonebook`

Cross-correlation pattern:

- DPAPI master keys enable follow-on decryption
- Vault and browser stores show what secrets were locally available
- Pair these with execution artifacts to understand how secrets may have been accessed

### File System and Timeline Reconstruction

Focus here when you need existence, deletion, rename, or broad timeline evidence:

- `mft_file`
- `usn_journal`
- `recycle_bin`
- `lnk_files`
- `jump_list_auto`
- `jump_list_custom`
- `jump_list_system`
- `thumbcache`
- `search_db_user`

Cross-correlation pattern:

- `$MFT` and `$UsnJrnl` provide strong file-system timeline evidence
- `Recycle Bin` adds deletion context
- `LNK` and `Jump Lists` add user-access context
- `Search DB` and `Thumbcache` retain evidence even after original content is gone

### Memory-Adjacent Evidence

Focus here when you do not have a full RAM capture but still need memory-derived context:

- `pagefile_sys`
- `hiberfil_sys`

Interpretation boundary:

- treat these as memory-bearing sources
- use the container and parsing profiles to understand how to reconstruct them
- do not treat them as simple flat files with row-oriented records

## Carving Guidance

When analyzing unallocated space or fragmented memory, use the signature layers:

- `ContainerSignature` answers “does this byte range look like a Registry hive, SQLite DB, EVTX file, or OLE compound file?”
- `RecordSignature` answers “does this fragment look like a Registry cell, EVTX record, or artifact-specific payload?”

Important rule:

- signatures are not only magic bytes
- strong carving also depends on structural invariants, alignment, size rules, and internal consistency

Registry is the canonical example:

- hive-level: `regf` plus `hbin`/cell structure
- record-level: `nk` and `vk` cells
- artifact-level: `UserAssist` Count payload semantics

## Investigation Paths

### Suspected Malware Execution

1. Start with `prefetch_file`, `amcache_app_file`, `shimcache`, `bam_user`, and `powershell_history`
2. Pivot into `evtx_security`, `evtx_sysmon`, and `evtx_powershell`
3. Use `mft_file`, `usn_journal`, and `recycle_bin` for file-system reconstruction

### Suspected Persistence

1. Start with `run_key_hkcu`, `run_key_hklm_run`, `scheduled_tasks_dir`, and `services_imagepath`
2. Check `wmi_mof_dir` and `wmi_subscriptions`
3. Correlate with `prefetch_file`, `powershell_history`, and `evtx_system`

### Suspected Credential Theft

1. Start with `dpapi_masterkey_user`, `windows_vault_user`, `chrome_login_data`, and `firefox_logins`
2. Correlate with execution artifacts such as `powershell_history`, `prefetch_file`, and `amcache_app_file`
3. Use provenance and parsing profiles to decide whether decryption or deeper parser tooling is needed

## Provenance and Trust

Use provenance at two levels:

- [`crate::references`]
  Broad module-level justification
- [`crate::catalog::ArtifactDescriptor::sources`]
  Artifact-level justification

Use the curated source corpus for discovery, but do not treat corpus membership as a substitute for artifact-specific citations.

## Scope Boundary

This handbook describes a forensic catalog and knowledge architecture.

It is not a claim that the crate fully parses every supported format. The
intended boundary is:

- keep compact, stable decode logic in-core
- keep parsing and carving knowledge explicit and queryable
- keep large evolving parser implementations outside the core catalog unless
  they are small, stable, and intrinsic to the artifact model
