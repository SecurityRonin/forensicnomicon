# 13Cubed "Investigating Windows Endpoints" (IWE) — forensicnomicon Coverage Audit

Audit of every forensic artifact, Event ID, registry key, NTFS structure, and
timelining fact taught in the 13Cubed IWE course against what `forensicnomicon`
already encodes. Source material: the IWE chapter markdown (`00`…`11`) plus
`IWE-Exam-Cram.md`. Classification per item: **PRESENT** (already encoded),
**PARTIAL** (some facet encoded, gap remains), **MISSING** (absent).

This audit is the deliverable even where the gap was deliberately *not*
backfilled — see the "Deliberately not backfilled" section at the end for the
rationale (decoder logic vs. data table).

Confidence markers: ✓ = course-confirmed verbatim; ~ = inferred mapping
(e.g. the MITRE technique attached to an Event ID is a defensible standard
mapping, not a string the course printed).

---

## Scorecard (counts by chapter)

| Chapter | PRESENT | PARTIAL | MISSING (backfilled) | MISSING (out of scope) |
|---|---|---|---|---|
| 02 — Windows Event Logs | 14 EIDs | — | 26 EIDs (→ `eventids`) | 1 (EID 1102 RDP-client collision) |
| 03 — The Registry | 27 reg artifacts | — | 0 | 0 |
| 04 — Evidence of Execution | Prefetch, Shimcache, Amcache, UserAssist, SRUM, MUICache, BAM/DAM | PCA | 0 (catalog descriptors present) | — |
| 05 — Persistence / PrivEsc / LatMov | Services, TaskCache, NTDS, WDigest, MountPoints2 | — | service+task+RDP+WMI EIDs (counted in ch02 row) | — |
| 06 — Anatomy of NTFS | $MFT/$SI/$FN/$I30/$LogFile/$UsnJrnl/ADS | — | 0 | — |
| 07 — Deletion & Recovery | $Recycle.Bin $I/$R, $I30 slack carving | — | 0 | — |
| 08 — LNK & Jump Lists | LNK, AutomaticDestinations, CustomDestinations, AppID/DestList | — | 0 | — |
| 09 — Timelining | FILETIME, MACB, SI-vs-FN, $J, Plaso/fls | — | 0 | — |
| 10 — Additional Content | Thumbcache, ActivitiesCache.db, Search index, browser | — | 0 | — |

Backfilled this pass: **26 Event IDs** added to `src/eventids.rs::EVENT_ID_TABLE`.
No registry/execution catalog descriptors were genuinely absent.

---

## Chapter 02 — Windows Event Logs

`eventids::EVENT_ID_TABLE` is the structured home. Before this pass the table held
16 entries (14 of them course-taught). The course teaches the following Event IDs.

### PRESENT (already in `EVENT_ID_TABLE`)

| EID | Channel | forensicnomicon location | Note |
|---|---|---|---|
| 104 | System | `eventids` ✓ | Log cleared |
| 1102 | Security | `eventids` ✓ | Audit log cleared |
| 4624 | Security | `eventids` ✓ | Successful logon |
| 4625 | Security | `eventids` ✓ | Failed logon |
| 4648 | Security | `eventids` ✓ | Explicit-cred logon |
| 4663 | Security | `eventids` ✓ | Object access (not course-headline but present) |
| 4688 | Security | `eventids` ✓ | Process creation |
| 4698 | Security | `eventids` ✓ | Scheduled task created |
| 4702 | Security | `eventids` ✓ | Scheduled task updated |
| 4720 | Security | `eventids` ✓ | User account created |
| 4732 | Security | `eventids` ✓ | Member added to local group |
| 4768 | Security | `eventids` ✓ | Kerberos TGT |
| 4769 | Security | `eventids` ✓ | Kerberos service ticket |
| 4771 | Security | `eventids` ✓ | Kerberos pre-auth fail |
| 4776 | Security | `eventids` ✓ | NTLM auth |
| 7045 | System | `eventids` ✓ | Service installed |

### MISSING → backfilled into `EVENT_ID_TABLE` this pass

| EID | Channel | Meaning (course-verbatim) | MITRE (~) |
|---|---|---|---|
| 4634 | Security | Logoff (system-generated) | — |
| 4647 | Security | User-initiated logoff | — |
| 4672 | Security | Special privileges assigned to new logon (admin) | T1078 |
| 4722 | Security | User account enabled | T1098 |
| 21 | TerminalServices-LocalSessionManager/Op | RDP session logon succeeded | T1021.001 |
| 22 | TerminalServices-LocalSessionManager/Op | RDP shell start | T1021.001 |
| 1149 | TerminalServices-RemoteConnectionManager/Op | Network connect (misleading "auth succeeded") | T1021.001 |
| 1029 | RDPCoreTS | SHA1 hash of connecting username | T1021.001 |
| 106 | TaskScheduler/Op | Task registered (created) | T1053.005 |
| 140 | TaskScheduler/Op | Task updated | T1053.005 |
| 141 | TaskScheduler/Op | Task deleted | T1053.005 |
| 200 | TaskScheduler/Op | Task action started | T1053.005 |
| 201 | TaskScheduler/Op | Task action completed | T1053.005 |
| 4103 | PowerShell/Op | Module logging | T1059.001 |
| 4104 | PowerShell/Op | Script block logging (decoded content) | T1059.001 |
| 400 | Windows PowerShell (classic) | Engine/session start | T1059.001 |
| 600 | Windows PowerShell (classic) | Provider start/stop | T1059.001 |
| 7034 | System | Service crashed unexpectedly | T1543.003 |
| 7036 | System | Service started/stopped | T1543.003 |
| 1116 | Defender/Op | Malware detected | T1059 |
| 1117 | Defender/Op | Action taken (remediation) | — |
| 216 | Application (ESENT) | Database location change detected | T1003.003 |
| 325 | Application (ESENT) | Database engine created a new database | T1003.003 |
| 326 | Application (ESENT) | Database attached | T1003.003 |
| 327 | Application (ESENT) | Database detached | T1003.003 |

> Logon-type codes (2/3/4/5/7/8/9/10/11) and the RDP corroboration caveat are
> *decode/heuristic* knowledge, not a flat EID table — they belong in the
> consuming analyzer (issen-evtx logon handler), not the enrichment table.

---

## Chapter 03 — The Registry — PRESENT (no backfill)

A prior audit confirmed all 27 13Cubed registry artifacts are catalogued; this
pass re-verified by keyword grep against `src/catalog/`. All present:
TypedPaths, BagMRU/ShellBags, MuiCache, MountPoints2, RunMRU, UserAssist,
TaskCache, Portable Devices, WDigest, AppCompatCache/Shimcache, USBSTOR,
USB Enum, MountedDevices, TypedURLs, LastVisited/OpenSavePidlMRU, RecentDocs,
WordWheelQuery, Run/RunOnce, Services, Amcache, BAM, ComputerName, TimeZone,
InstallDate. **Classification: PRESENT.** No descriptors added.

---

## Chapter 04 — Evidence of Execution — PRESENT / PARTIAL

| Artifact | Location | Status |
|---|---|---|
| Prefetch | `catalog` (`*.pf`) | PRESENT |
| Shimcache (AppCompatCache) | `catalog` registry descriptor | PRESENT |
| Amcache | `catalog` (`Amcache.hve`) | PRESENT |
| UserAssist | `catalog` (`UserAssist\{GUID}\Count`) | PRESENT |
| SRUM | `catalog` + `srum` module (`SRUDB.dat`) | PRESENT |
| MUICache | `catalog` | PRESENT |
| BAM/DAM | `catalog` | PRESENT |
| PCA (`PcaAppLaunchDic.txt`) | `catalog` | PARTIAL — present as a path artifact; ROT13/decode rules are decoder logic, not a data table |

---

## Chapter 06–10 — NTFS / Deletion / LNK / Timelining / Additional — PRESENT

`ntfs` module encodes $MFT (1024-byte record), $SI/$FN MACE, $I30 (INDEX_ROOT/
ALLOCATION/BITMAP B-tree + slack), $LogFile, $UsnJrnl/$J (sparse, filename-not-path),
ADS/Zone.Identifier, $Recycle.Bin $I/$R. LNK + AutomaticDestinations/
CustomDestinations + AppID/DestList covered by `catalog` LNK/JumpList descriptors.
Timelining facts (FILETIME, MACB, SI-vs-FN tunnelling, epoch zoo) live in
`timelining`. All **PRESENT** as knowledge; no flat-table gaps.

---

## Deliberately NOT backfilled (and why)

- **EID 1102 on the RDP-Client (`...RDPClient/Operational`) channel** — "client
  connected to remote host". `EVENT_ID_TABLE` is keyed by numeric `event_id`
  alone and `event_entry()` returns the first match, so a second `1102` would
  collide with the already-present Security "audit log cleared". Encoding both
  requires a channel-keyed lookup — a structural API change outside this task.
  Recorded here so it is not lost.
- **Logon Type codes / RDP "1149 alone ≠ auth" corroboration rule** — these are
  decode + heuristic correlation, the consuming analyzer's job (issen-evtx),
  not a flat enrichment row.
- **PCA ROT13 / SRUM ESE decode / UserAssist ROT13 / DestList parsing** —
  decoder algorithms, which is `winreg-forensic` / parser-crate territory, not
  a `forensicnomicon` data table.
- **Registry descriptors** — none missing; the 27 IWE registry artifacts are
  already catalogued.
