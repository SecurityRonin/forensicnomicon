# IWE Facts -> forensicnomicon Reconciliation Worklist

**What this is.** The 2,369 IWE knowledge facts (`research/iwe-knowledge-inventory.md`)
diffed against what `forensicnomicon` descriptors and `src/*.rs` modules **actually
encode** (main tree, not `.claude/worktrees/`). Each fact was classified ENCODED
(already captured), ENRICHMENT (a present descriptor is missing a specific detail),
or NEW (no descriptor exists). Only ENRICHMENT and NEW are listed.

**Discipline.** Every item names a **target** (descriptor id / EVENT_ID_TABLE row /
`src` module) and a **primary source to cite** (Microsoft docs, libyal, Eric Zimmerman
tool docs, Carrier FSFA, vendor DFIR writeups). **13cubed is never cited** — it was the
pointer to the fact, not the authority for it. Verify each against its primary source
before editing a descriptor.

**Totals:** 116 enrichments · 47 new-descriptor gaps · across 9 chapters.

---

## A. Corrections (ship first — these are factual errors, not gaps)

The pass surfaced descriptor content that is **wrong or stale**, which matters more than
any missing enrichment because a wrong descriptor misleads an examiner. Verify each
against the cited source, then fix.

| # | Descriptor | Current (wrong/stale) | Correct | Source to confirm |
|---|---|---|---|---|
| 1 | `EVENT_ID_TABLE` EID **1029** | "SHA1 of username" | **Base64(SHA-256(username))**, case-sensitive, channel TerminalServices-RDPClient/Operational, provider ClientActiveXCore | MS RDP client logging docs / ANSSI DFIR-ORC notes |
| 2 | `edge_webcache` | path = `…\INetCache\` (content folder) | `…\WebCache\WebCacheV01.dat` (ESE DB); also add the `file:///` local-file-access container thread | libyal libesedb; MS WebCache/ESE docs |
| 3 | `pca_applaunch_dic` | `file_path = AppLaunch.dic` | real file is **`PcaAppLaunchDic.txt`** (a collector keyed on the wrong name misses it) | AboutDFIR PCA writeup; MS appcompat |
| 4 | `opensave_mru` / `lastvisited_mru` | XP-era keys `OpenSaveMRU` / `LastVisitedMRU` | Win7+ = **`OpenSavePidlMRU` / `LastVisitedPidlMRU`** (per-extension + `*` subkeys) | MS comdlg32 docs; EZ Registry Explorer |
| 5 | timelining `l2tcsv` output | labelled "industry-standard" | modern Plaso **deprecates l2tcsv**, recommends `dynamic` | plaso.readthedocs.io |
| 6 | SRUM table GUIDs (VERIFY) | descriptor vs `src/srum.rs` disagree on network-usage & push-notification GUIDs; push GUID appears to collide with app-resource | reconcile to the canonical GUIDs | Baggett SRUM-DUMP; libyal esedb-kb |
| 7 | `psort` caveat (VERIFY) | `--slice_size` (underscore) | likely `--slice-size` (hyphen) | plaso.readthedocs.io |

## B. New descriptors worth building (ranked)

High-value artifacts with **no descriptor at all**:

1. **File carving / PhotoRec** [High] — no carving descriptor exists (concept: header/footer
   signature recovery from unallocated; limitation: no filename/metadata, fragmentation).
   _Cite:_ Carrier FSFA; PhotoRec (cgsecurity) docs; DFRWS carving refs. *(ch07)*
2. **`$I30` index-slack deleted-filename recovery** [High] — INDX exists as a bare constant
   only; no From-Slack name+size+MACB recovery descriptor. _Cite:_ libyal libfsntfs; Carrier FSFA. *(ch06)*
3. **Zone.Identifier / Mark-of-the-Web** [High] — no descriptor; ZoneId 0-4 enum + HostUrl/ReferrerUrl
   attribution. _Cite:_ MS-FSCC named streams; MOTW writeups. *(ch06)*
4. **Thumbs.db** [High] — distinct from Thumbcache; still written on modern Win11 for UNC/network
   paths and via the `\\localhost\C$` loopback trigger. _Cite:_ libyal dtformats; Thumbs Viewer. *(ch10)*
5. **SRUM `AppTimelineProvider`** [High] — GUID const in `src/srum.rs` but no `ArtifactDescriptor`;
   uniquely carries Exe-Timestamp ~= PE compile time. _Cite:_ Baggett SRUM-DUMP; libyal esedb. *(ch04)*
6. **AmCache `InventoryApplication`** [Med] — installed-apps subkey + Program ID join key (only
   File/Driver/Shortcut are encoded). _Cite:_ libyal Amcache dtformats; ANSSI. *(ch04)*
7. **Plaso `psteal` / `pinfo` / `image_export`** [Med] — three tools, no descriptors. _Cite:_ plaso docs. *(ch09)*
8. **New Event IDs for `EVENT_ID_TABLE`** [High/Med] — 5140/5145 (share object access),
   4798/4799 (group-membership enumeration), 4778/4779 (RDP reconnect — in code, not the table),
   4697 (service install, Security log), 5156 (WFP), 7009, 100/102, 40, 1000/1002. _Cite:_ MS auditing docs; UWS encyclopedia. *(ch02, ch05)*
9. **`PSEXESVC.exe` dropped-binary artifact** [Med] — on-disk PsExec-target file in `%SystemRoot%`
   (currently only the 7045 event is modelled). _Cite:_ MS Sysinternals; MITRE ATT&CK. *(ch05)*
10. **EMDMgmt / ReadyBoost** [Med] — `SOFTWARE\...\EMDMgmt` USB volume-serial source (non-SSD).
    _Cite:_ MS docs; USB-forensics writeups. *(ch03)*

## C. Cleanup (duplication / thin descriptors)

- **`usn_journal`** (mod.rs) reuses `DIR_ENTRY_FIELDS` and lacks the reason-code bitmask that its
  sibling **`usnjrnl`** already carries — reconcile to one. *(ch06)*
- **`logfile_ntfs`** is thin; the deep `$LogFile` redo/undo op-code coverage already lives in
  **`ntfs_logfile_records`** — point one at the other or merge. *(ch06)*
- **Branch note:** `windows_ntfs_ext.rs` currently lives only on the `gcfa-disk-descriptors` working
  branch, not `main`; several ch06 targets assume it. Confirm merge state before editing.

---

# Per-chapter detail


## Chapter 02

### IWE Ch02 (Windows Event Logs) — recon vs forensicnomicon (MAIN tree)

Scope note: forensicnomicon is an artifact/Event-ID catalog, not a tool-usage manual. IWE
tool/UI/workflow facts (EvtxECmd flags `-f/-d/--csv/--csvf/--sync/--vss`, Timeline Explorer
grid/grouping/shortcuts, Event Viewer nav, `Get-WinEvent`/`Get-EventLog`, Arsenal Image Mounter,
`vssadmin`, Windows Sandbox, Get-ZimmermanTools/Maps layout) and format-history facts (XP=3 logs,
`.evt` legacy/libevt, EVTX=binary XML, `%4`=`/`, winevt\Logs path, locked/dirty files, log counts
102/373, registry-relocatable path, WEF/SIEM, log-clearing anti-forensics, VSS recovery) are
**out of scope** for the catalog — counted ENCODED/OOS below, not listed as candidates.

## Counts
- **ENCODED (or out-of-scope for catalog): ~155** — includes all tool/UI/format-history facts, plus
  event IDs already in `EVENT_ID_TABLE` (104, 1102, 4624/4625/4648/4663/4688/4698/4702/4720/4732/
  4768/4769/4771/4776, 4634/4647/4672/4722, 7045/7034/7036, 21/22, 1149, 106/140/141/200/201,
  400/600/4103/4104, 1116/1117, 216/325/326/327) and the RDP/PowerShell/Defender/SMB/Sysmon channel
  descriptors, Sysmon event catalog (1/3/7/8/10/11/22), 5140/5145 (heuristics), ntdsutil lolbin,
  1149 misleading-label caveat, SYSTEM-hive-decrypts-NTDS, unsalted-MD4 NT hash concept.
- **ENRICHMENT: 9**
- **NEW: 8**

## Enrichments (ranked)
- **1029 (RDP outgoing username hash)** [High] — `EVENT_ID_TABLE` row is factually wrong: says "SHA1 hash" on channel `...RemoteDesktopServices-RdpCoreTS/Operational`. Correct = **Base64(SHA-256(username))**, case-sensitive, on `Microsoft-Windows-TerminalServices-RDPClient/Operational`, provider **ClientActiveXCore** (RdpCoreTS is server/inbound side). Also add the decode step and correlation to target-side 21/22. `evtx_rdp_client` descriptor does not mention 1029 at all. _Target:_ `EVENT_ID_TABLE` eid 1029 + descriptor `evtx_rdp_client`. _Cite:_ https://nullsec.us/windows-rdp-related-event-logs-the-client-side-story/ ; https://learn.microsoft.com/en-us/windows/win32/termserv/ (RDPClient channel).
- **4624 logon-type code map** [High] — table row is just "Successful logon"; no decode of Logon Type. Add the 2=Interactive/Console, 3=Network(SMB), 4=Batch(sched task), 5=Service, 7=Unlock, 8=NetworkCleartext (red flag), 9=NewCredentials (correlates 4648), 10=RemoteInteractive(RDP), 11=CachedInteractive, 12=CachedRemoteInteractive, 13=CachedUnlock map. Currently only ad-hoc mentions in `playbooks.rs`; no central mapping. _Target:_ `EVENT_ID_TABLE` eid 4624 (add field/decode) or a new `logon_type` map in `src/evtx.rs`. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 (SECURITY_LOGON_TYPE).
- **216 / 325 (ESENT NTDS.dit) location decode** [High] — table flags "NTDS.dit move ⇒ red flag" generically. Missing the benign-vs-malicious discriminator: benign 216 = `.dit` snapshotted into a **VSS path**; malicious = `.dit` written to `C:\Users\Public`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\Temp`, or PerfLogs. Also missing the 216+325(+326/327) = `ntdsutil` IFM fingerprint and its on-disk structure (an `Active Directory` dir with the `.dit` + a `registry` dir holding SYSTEM **and** SECURITY hives). _Target:_ `EVENT_ID_TABLE` eids 216/325 + `ntdsutil` lolbin note. _Cite:_ https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ntdsutil-create-ifm-media (IFM structure) ; https://github.com/nasbench/EVTX-ETW-Resources (ESENT provider IDs).
- **104 cross-log clearing semantics** [Med] — table 104 = "System log cleared" only. Missing that System-104 records clearing of **other** channels too (clearing Application writes a 104 into System — Application does NOT self-log its clear), whereas Security uniquely self-logs via 1102. _Target:_ `EVENT_ID_TABLE` eids 104 & 1102 descriptions. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102 ; https://github.com/nasbench/EVTX-ETW-Resources.
- **4776 single-ID success+failure** [Med] — table 4776 = "NTLM authentication"; missing that 4776 uses **one** Event ID for both success and failure (distinguished by the Error Code field), unlike the 4624/4625 split. Add the note + error-code hint. _Target:_ `EVENT_ID_TABLE` eid 4776. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776.
- **4688 dual-toggle + core-process exception** [Med] — table 4688 = "Process creation"; missing that (a) process-creation auditing is OFF by default, (b) full command-line capture is a **second** independent GPO toggle, and (c) some core system processes still emit 4688 on unaudited hosts. Determines whether the goldmine exists. _Target:_ `EVENT_ID_TABLE` eid 4688 caveats. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing.
- **RDP reconnect/logoff correlation chains** [Med] — `evtx.rs` has an `RdpReconnect` from 4778/4779 but no explicit chain. Add: reconnect = 1149 → 4624 **type 7** (not 10) → LSM 25 + event 40 + Security 4778; logoff = LSM 23 → Security 4634(type 10/7) + 4647(user-initiated). Distinguishes reconnect from fresh logon and disconnect from logoff. _Target:_ `src/evtx.rs` RDP correlation / `EVENT_ID_TABLE`. _Cite:_ https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/.
- **4104 PS v5+ auto-warning** [Med] — table 4104 = "script block logging — full content"; missing that PowerShell v5+ auto-logs blocks it deems suspicious as **Warning-level 4104 even without Script Block Logging configured** (free evidence on unconfigured hosts). _Target:_ `EVENT_ID_TABLE` eid 4104 / `evtx_powershell` caveats. _Cite:_ https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ (automatic suspicious script-block logging).
- **LSM 23/24/25 in EVENT_ID_TABLE** [Low] — `evtx_rdp_session`/`evtx_terminal_services` descriptors cover 21/23/24/25, but `EVENT_ID_TABLE` only has 21 and 22. Add 23 (logoff), 24 (disconnect — session persists), 25 (reconnect) rows so ID lookups resolve. _Target:_ `EVENT_ID_TABLE`. _Cite:_ https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/.

## New (ranked)
- **4798 (Security)** [High] — a user's local group membership was enumerated. No entry anywhere. Recon / discovery indicator (T1069.001). _Target:_ `EVENT_ID_TABLE` new row, channel Security. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798.
- **4799 (Security)** [Med-High] — a security-enabled local group membership was enumerated. No entry. Complements 4798 for network-resource group recon (T1069). _Target:_ `EVENT_ID_TABLE` new row, Security. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799.
- **4778 / 4779 (Security)** [Med] — session reconnected / disconnected (RDP + fast-user-switch). Referenced in `src/evtx.rs` correlation but absent from `EVENT_ID_TABLE`. _Target:_ `EVENT_ID_TABLE` new rows, Security. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778 ; .../event-4779.
- **7009 (System)** [Med] — service-start timeout. Table has 7034/7036 but not 7009. Correlate with 7034 for oddly-named services in the incident window (outlier-service scoping). _Target:_ `EVENT_ID_TABLE` new row, System. _Cite:_ https://learn.microsoft.com/en-us/windows-server/troubleshoot/event-id-7009-7011 (Service Control Manager).
- **100 / 102 (Microsoft-Windows-TaskScheduler/Operational)** [Med] — task started (100) / task completed (102). Distinct from the 200/201 (action started/completed) already in the table; IWE cites 100/102 explicitly. _Target:_ `EVENT_ID_TABLE` new rows, TaskScheduler/Operational. _Cite:_ https://github.com/nasbench/EVTX-ETW-Resources (Microsoft-Windows-TaskScheduler provider).
- **40 (Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational)** [Low-Med] — RDP disconnect-reason / appears in reconnect flow. No entry. Supplemental RDP session-state correlation. _Target:_ `EVENT_ID_TABLE` new row. _Cite:_ https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/.
- **1000 / 1002 (Application)** [Low-Med] — application error (1000) / application hang (1002). No entry. Malware execution often triggers these inside the actor's active window — timeline corroboration (Windows Error Reporting provider). _Target:_ `EVENT_ID_TABLE` new rows, Application. _Cite:_ https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting (Application Error / Windows Error Reporting events).
- **5140 / 5145 in EVENT_ID_TABLE** [Low] — network share accessed (5140) / detailed share-object access check (5145). Present as consts in `src/heuristics/evtx.rs` and in playbooks, but not as `EVENT_ID_TABLE` rows, so a direct ID lookup misses them. _Target:_ `EVENT_ID_TABLE` new rows, Security. _Cite:_ https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140 ; .../event-5145.

## Chapter 03

### IWE Chapter 03 (The Registry) — Reconciliation vs forensicnomicon

Scope: MAIN tree only (`.claude/worktrees/` and `target/` ignored). Descriptors read from
`crates/data/src/catalog/descriptors/{mod.rs, windows_registry_ext.rs, ext2, ext3, generated/*}`
and `src/shellbags.rs`. Every enrichment/new row was checked against the descriptor's `meaning`,
`decoder`, and `fields` before being called missing.

## Counts

- **ENCODED ≈ 112** — the bulk of ch03. All five fundamentals/tooling files (hive layout, root keys,
  System32\config set, Regedit/Registry Explorer/RECmd/RegRipper/RLA/ShellBags Explorer tooling,
  ROT13-concept, transaction-log/dirty-hive/RegBack theory, deleted-record/slack recovery) are either
  domain narration with no descriptor surface, or map to an artifact already present. Present artifact
  descriptors that fully cover their IWE fact: `userassist_exe`/`userassist_folder`
  (ROT13 decoder `Rot13NameWithBinaryValue` + GUI-only caveat), `shellbags_user` + `src/shellbags.rs`
  (BagMRU/Bags paths for NTUSER **and** UsrClass, shell-item class bytes, BEEF0004/BEEF0026 timestamp
  blocks, zip=compressed-folder 0x50, network 0xC3), `muicache` (Utf16Le), `amcache_app_file`, `bam_user`,
  `networklist_profiles`, `mountpoints2`, `mounted_devices`, `run_mru`, `typed_paths`, `mru_recent_docs`,
  `wordwheel_query`, `opensave_mru`, `lastvisited_mru`, `usb_enum`/`usb_stor_enum`, `portable_devices`,
  `setupapi_dev_log`, `system_timezone`, `computer_name`, `network_shares_server` (LanmanServer Shares),
  `dhcp_ipv4_interface` (= the Tcpip per-interface IP/subnet/gateway/DNS artifact),
  `prefetch_status` (already notes server-off nuance), `enable_periodic_backup` (RegBack/RegIdleBackup/v1803),
  `run_key_hklm`/`run_key_hkcu` + `run_services_*` (Run/RunOnce ASEPs), `regedit_control_session_manager_appcompatcache` + `src/appcompatcache.rs` (Shimcache), `windows_install_date`.
- **ENRICHMENT = 14** — present descriptor missing a decode-step / key-path nuance / MRU rule / timestamp
  semantics / gotcha (listed below).
- **NEW = 2** — no descriptor for the key at all (EMDMgmt, WZCSVC).

## Enrichments (ranked)

- **USBSTOR Properties connect/disconnect timestamps** [High] — `usb_stor_enum`/`usb_enum` meaning cites
  "first/last connection via setupapi correlation" but does not encode the registry `Properties\{devnode
  GUID}\0064` (first connected), `0066` (last connected), `0067` (last removed) subkeys, nor the
  three-source last-connect corroboration (0066 value vs USBSTOR serial-key LastWrite vs MountPoints2
  LastWrite). These Properties keys are RegEdit-unreadable live and are the canonical USB timeline.
  _Target:_ `usb_stor_enum` (windows_registry_ext.rs) / `usb_enum` (mod.rs).
  _Cite:_ Nicole Ibrahim "USB Registry Artifacts" + SANS "Profiling USB thumbdrives"; Microsoft DEVPKEY device-property GUIDs.
- **RunMRU decode gotchas** [High] — `run_mru` meaning notes MRU ordering but omits three rules: it records
  **only successfully-executed** commands (absence ⇒ command failed/never ran); the trailing `\1` is a
  storage artifact, not user-typed text; single-letter value names (a,b,c…) + `MRUList` whose first char =
  most-recent. _Target:_ `run_mru` (mod.rs). _Cite:_ forensics.wiki "RunMRU"; SANS DFIR registry cheat sheet.
- **ComDlg32 modern PIDL key names** [High] — `opensave_mru`/`lastvisited_mru` `key_path` values point at the
  XP-era `ComDlg32\OpenSaveMRU` / `LastVisitedMRU`; Vista/Win7+ store these as `OpenSavePidlMRU` /
  `LastVisitedPidlMRU` (binary PIDLs) with per-extension subkeys plus the wildcard `*` subkey. Current
  key_path will miss on modern hives. _Target:_ `opensave_mru`, `lastvisited_mru` (mod.rs).
  _Cite:_ forensics.wiki "OpenSaveMRU and LastVisitedMRU"; libyal winreg-kb.
- **MountedDevices→MountPoints2 attribution join** [Med] — `mounted_devices` describes drive-letter/volume
  mappings but not the two joins that matter: device serial → assigned drive letter, and serial → Volume
  GUID, where the Volume GUID matched against each user's MountPoints2 identifies *which user* mounted a
  device. _Target:_ `mounted_devices` (+ cross-ref note on `mountpoints2`).
  _Cite:_ SANS "Profiling USB thumbdrives"; Harlan Carvey, *Windows Registry Forensics*.
- **ShellBags: feature-update clobbering + Explorer-only + NodeSlot** [Med] — `src/shellbags.rs` /
  `shellbags_user` cover paths, class bytes and MAC-time extension blocks but omit: (a) Win10/11 feature
  updates reset ShellBag last-write/timestamps (reliability caveat — correlate against last feature-update
  date); (b) ShellBags are populated **only** by Explorer (CMD/PowerShell/WSL traversal creates none);
  (c) the `NodeSlot` value that joins a BagMRU structural entry to its Bags view-settings entry.
  _Target:_ `src/shellbags.rs` / `shellbags_user`. _Cite:_ Eric Zimmerman ShellBags Explorer docs; libyal dtformats "Windows Shellbags".
- **WordWheelQuery MRU-position-0 dating** [Med] — `wordwheel_query` (MruListEx) omits the derived-timestamp
  rule: the subkey LastWrite dates only the MRU-position-0 term; older terms are datable only as "sometime
  before". Also distinguish from the Start-menu/taskbar search (a separate ESE/Windows Search DB).
  _Target:_ `wordwheel_query` (mod.rs). _Cite:_ forensics.wiki "WordWheelQuery".
- **TypedPaths url1..urlN ordering** [Med] — `typed_paths` omits the ordering encoding: no MRUList value;
  order is carried by value names `url1`(most recent)…`urlN`, shifting down by one on each new entry.
  _Target:_ `typed_paths` (mod.rs). _Cite:_ forensics.wiki "TypedPaths".
- **Control set Select\Current resolution** [Med] — `regedit_system_select` `meaning` is a stub ("Current
  Control Set Name"); missing the `Select\Current` value → `ControlSet00x` resolution and the gotcha that
  `CurrentControlSet` is a live-only symlink (dead-box images carry only numbered sets; data may be
  duplicated/triplicated across sets). _Target:_ `regedit_system_select` (generated/regedit_generated.rs).
  _Cite:_ Microsoft "ControlSet / LastKnownGood"; Carvey, *Windows Registry Forensics*.
- **USB VID/PID ampersand pseudo-serial rule** [Med] — the `Enum\USB` VID/PID descriptor
  (`nirsoft` generated) omits the rule that a serial-subkey whose **second character is `&`** is an
  OS-assigned pseudo-serial, NOT a globally-unique hardware serial. _Target:_ `usb_enum` / nirsoft `Enum\USB`.
  _Cite:_ Nicole Ibrahim USB artifacts; SANS "Profiling USB thumbdrives".
- **MountPoints2 LastWrite + UNC shares** [Med] — `mountpoints2` omits: subkey LastWrite dates the mount
  event, and MountPoints2 also records mapped/UNC network shares (with `#`-encoded subkey names), not only
  removable media. _Target:_ `mountpoints2` (mod.rs). _Cite:_ forensics.wiki "MountPoints2"; Carvey.
- **RecentDocs per-extension LastWrite** [Low] — `mru_recent_docs` omits that each per-extension subkey
  (`.docx`, `.csv`, `.ai`, …) carries its own LastWrite (datable per file-type), while the individual
  filename values do not. _Target:_ `mru_recent_docs` (mod.rs). _Cite:_ forensics.wiki "RecentDocs".
- **NetworkList gateway-MAC fingerprint** [Low] — `networklist_profiles` records profile name/category and
  created/last-connected dates but omits `DefaultGatewayMac` (uniquely fingerprints a physical network even
  when the SSID is common) and `DnsSuffix` / wireless-vs-wired flag. _Target:_ `networklist_profiles`
  (mod.rs). _Cite:_ forensics.wiki "NetworkList".
- **LanmanServer Shares default-admin exclusion** [Low] — `network_shares_server` omits the triage gotcha:
  built-in admin shares (`C$`, `ADMIN$`, `IPC$`) are not listed, so an empty key = defaults only and any
  entry is a deliberately created share. _Target:_ `network_shares_server` (windows_registry_ext2.rs).
  _Cite:_ Microsoft LanmanServer\Shares documentation.
- **Portable Devices volume label + timestamp** [Low] — `portable_devices` maps device identity to
  drive/name but could add the user-assigned volume **label** recovery (e.g. "Sticky") and the
  Registry-Explorer-surfaced timestamp. _Target:_ `portable_devices` (mod.rs).
  _Cite:_ SANS "Profiling USB thumbdrives".

## New (ranked)

- **EMDMgmt / ReadyBoost registry key** [Med] — `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`
  yields a USB device's **volume serial number** (another device-instance identifier); present only when
  the system/boot drive is a spinning HDD (absent on SSD systems — not tampering). Only EVTX ReadyBoost
  channels and a passing caveat mention exist; no registry descriptor. _Target:_ new descriptor in
  windows_registry_ext.rs (HKLM SOFTWARE). _Cite:_ Nicole Ibrahim "EMDMgmt / ReadyBoost" USB writeup; SANS
  "Profiling USB thumbdrives".
- **WZCSVC (Windows XP wireless history)** [Low] — `SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces\<GUID>`
  (Wireless Zero Configuration, XP-only): interface-GUID key LastWrite = last network connect; embedded hex
  classifies wired / broadband / wireless. Legacy analog to NetworkList still seen on XP-era images.
  _Target:_ new descriptor in windows_registry_ext.rs (OsScope XP). _Cite:_ forensics.wiki / Carvey XP
  wireless-network registry analysis.

## Chapter 04

### IWE ch04 (Evidence of Execution) — Reconciliation vs forensicnomicon (MAIN tree)

Scope: 7 IWE lessons (ShimCache, AmCache, Prefetch, UserAssist, SRUM, MUICache, PCA) reconciled
against the descriptors in `crates/data/src/catalog/descriptors/*.rs` (+ `src/srum.rs`). Worktrees / target ignored.

**Counts (high-value interpretive nuances, not every atomic tooling fact):**
- **ENCODED (count only): ~42.** Core semantics already present — ShimCache presence-not-execution +
  write-on-clean-shutdown + `shimcache_memory` + "responder-creates-entries" exposure caveat; AmCache
  presence-not-execution + LastWrite≠first-exec (Compatibility Appraiser) + 0000-prefixed SHA-1 + driver
  tracking (`amcache_driver`); Prefetch 8-run-timestamps/run-count/referenced-files/prefetch-hash/volume-serial +
  server-disabled + `prefetch_status` (EnablePrefetcher=0) + SDelete self-incrimination; UserAssist ROT13 +
  two GUIDs (CEB exe / F4E lnk) + Focus-Time-vs-Run-Count; SRUM 5 tables + L2ProfileId(SSID)/bytes/CPU-cycles/
  interface-type; BAM/DAM; MUICache path→display-name; PCA Win11-22H2 + pipe-delimited + exit-code + Db0/Db1 pivot note.
- **ENRICHMENT (present descriptor missing a nuance): 14** (below).
- **NEW (no descriptor at all): 4** (below).

## Enrichments (ranked)

- **ShimCache** [High] — no encoding of the **2023 four-byte execution indicator**: the trailing 4 bytes of each entry == 1 ⇒ the binary executed, **for non-native (third-party) binaries only** (cmd.exe/powershell.exe not determinable). Descriptor `shimcache` states only "presence ≠ execution" and has no `Executed` (Yes/No/NA) field or flag. This is the single highest-value miss. _Target:_ shimcache. _Cite:_ EZ AppCompatCacheParser docs / Mandiant AppCompatCache.
- **PCA** [High] — primary-file **filename is wrong**: descriptor `file_path` = `C:\Windows\appcompat\pca\AppLaunch.dic`, but the real Win11 22H2 artifact is `PcaAppLaunchDic.txt`. A collector keying on `AppLaunch.dic` misses the file. _Target:_ pca_applaunch_dic. _Cite:_ AboutDFIR PCA / Sygnia PCA.
- **MUICache** [High] — **masquerade-detection value not encoded**: the two values `ApplicationCompany` (vendor) + `FriendlyAppName` are read from the PE **VersionInfo** resource and are independent of the on-disk filename, so a renamed binary retains its original identity. Descriptor `muicache` has one field (`display_name`), no `evidence_strength`, no caveats. _Target:_ muicache. _Cite:_ Hexacorn / SANS MUICache writeup.
- **PCA** [Med] — `PcaGeneralDb0.txt` schema missing the **AmCache Program ID** field (the PCA↔AmCache join key that enriches a record with SHA-1/PE detail) plus run-status, file-description, software-vendor, file-version fields. Descriptor `pca_general_db` has only exe_path/exit_code/timestamp. _Target:_ pca_general_db. _Cite:_ AboutDFIR PCA / Sygnia / Carvey PCAParse.
- **ShimCache** [Med] — **timestamp semantics + timestomping detection** not encoded: the entry timestamp is the file's **M (modification)** time (= Explorer "Modified"), NOT execution/shim time; comparing ShimCache-M vs live-filesystem-M exposes timestomping, and an identical 64-bit timestamp across two paths identifies a rename/move. Schema is a single opaque `raw` blob. _Target:_ shimcache. _Cite:_ Mandiant AppCompatCache.
- **AmCache** [Med] — `InventoryApplicationFile` fields limited to file_id + sha1; missing the rich metadata IWE stresses: **PE compile time ("link date")**, file size, publisher, product name/version, binary type / PE flag, OS-component flag. _Target:_ amcache_app_file. _Cite:_ libyal Amcache format docs / Lagny "Analysis of the AmCache".
- **AmCache** [Med] — SHA-1 **hash cap figure is wrong/ambiguous**: `sha1` field says "first 31.25 MB"; primaries put the cap at exactly **30 MiB = 31,457,280 bytes**. Correct the figure (files > cap won't match a full-file SHA-1). _Target:_ amcache_app_file. _Cite:_ libyal Amcache / Lagny "Analysis of the AmCache".
- **MUICache** [Med] — **no-timing caveat** absent: MUICache has no per-execution timestamp (registry values carry none); only the key LastWrite exists and cannot be attributed to a specific value, and there is no MRU — proves a GUI program ran but not *when*. _Target:_ muicache. _Cite:_ Hexacorn / SANS MUICache.
- **UserAssist** [Med] — **1601-01-01 00:00:00 FILETIME-epoch sentinel** not documented: a null/bogus last-exec produced when a program starts in the user context without a click (service, scheduled task, startup/Start-menu autostart); pairs with the "zero run count + valid timestamp is contradictory" anomaly. Existing caveats cover "Open file location" but not the epoch sentinel. _Target:_ userassist_exe. _Cite:_ Didier Stevens / imphash "UserAssist with a Pinch of Salt".
- **Prefetch** [Med] — **filesystem-timestamp derivation** not encoded: first-run ≈ .pf **Birth** − monitoring delta, last-run ≈ .pf **Modified** − delta; the delta **varies per binary (~0–10 s, not a fixed 10 s)** and is recoverable by comparing .pf Modified against the stored last-run time. `prefetch_file` exposes only the internal SCCA run times. _Target:_ prefetch_file. _Cite:_ EZ PECmd docs / libyal SCCA.
- **Prefetch** [Med] — the **four parameter-hashing binaries** (`svchost.exe`, `dllhost.exe`, `rundll32.exe`, `mmc.exe`) fold command-line args into the path hash, legitimately yielding multiple same-name `.pf`; otherwise a duplicate-name `.pf` means execution from a **different path**. Not captured against `prefetch_hash`. _Target:_ prefetch_file. _Cite:_ Hexacorn prefetch-hash articles / libyal SCCA.
- **ShimCache** [Med] — **Explorer-viewport population** refinement: only files actually rendered in the Explorer window get shimmed (resizing to reveal more adds them on next flush); a console `dir` does not. Sharpens the existing "shell exposure" caveat into the specific viewport behaviour. _Target:_ shimcache. _Cite:_ Mandiant AppCompatCache / EZ AppCompatCacheParser.
- **ShimCache** [Low] — **entry caps** absent (XP 96, Server 2003 512, Vista/2008+/Win8+ 1024) and per-control-set copies (parse **all** control sets → up to 2×1024). No retention/cap on `shimcache`. _Target:_ shimcache. _Cite:_ Mandiant AppCompatCache / EZ AppCompatCacheParser.
- **ShimCache** [Low] — **Cache Entry Position** (MRU, 0 = most-recently-shimmed) + the identical-timestamp/position-gap rename heuristic; execution does not reshim or move position. _Target:_ shimcache. _Cite:_ Mandiant AppCompatCache / EZ AppCompatCacheParser.

## New (ranked)

- **SRUM AppTimelineProvider** [High] — ESE table `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` (const `TABLE_APP_TIMELINE` already in `src/srum.rs`, but **no `ArtifactDescriptor`**). One of IWE's four highest-value SRUM CSVs; carries executable info, DB-write `Timestamp`, and a distinct **`Exe Timestamp` ≈ PE compile time** — an independent execution-corroboration + timestomp-flag source the current 5 SRUM descriptors don't cover. _Target:_ new `srum_app_timeline`. _Cite:_ Baggett SRUM-DUMP / EZ SrumECmd docs.
- **AmCache InventoryApplication (installed apps)** [Med] — no descriptor for the installed-application-package subkey (Add/Remove Programs / MSI): timestamp, name, version, publisher, source, root-dir path, uninstall string, and the **Program ID** that joins to `InventoryApplicationFile`. Only File/Driver/Shortcut subkeys are encoded. _Target:_ new `amcache_app_install`. _Cite:_ libyal Amcache / Lagny "Analysis of the AmCache".
- **PCA PcaGeneralDb1.txt** [Low] — sibling file (often 0 bytes, sometimes populated) has no descriptor; should be collected/checked alongside Db0. _Target:_ new `pca_general_db1`. _Cite:_ Carvey PCAParse / AboutDFIR.
- **AmCache RecentFileCache.bcf** [Low] — Win7 predecessor execution-profiling artifact; may appear on legacy/unpatched Win7. No descriptor. _Target:_ new `recentfilecache_bcf`. _Cite:_ libyal / Lagny (ANSSI).

---
_Out-of-IWE-scope data-quality flags noticed during recon (not counted above):_
- `srum_network_usage` descriptor GUID `{973F5D5C-1D90-11D3-AE08-00A0C90F57DA}` disagrees with `src/srum.rs` `TABLE_NETWORK_USAGE` `{973F5D5C-1D90-4944-BE8E-24B94231A174}`.
- `srum_push_notification` descriptor GUID `{D10CA2FE-...FA86}` vs `src/srum.rs` `TABLE_PUSH_NOTIFICATIONS` `{D10CA2FE-...FA89}` (the FA89 GUID is also used by `srum_app_resource`). Table GUIDs need reconciling against Baggett SRUM-DUMP / libyal esedb-kb.

## Chapter 05

### IWE ch05 Reconciliation — Credential-theft & lateral-movement detection artifacts

Scope: reconcile distilled ch05 DFIR facts (LSASS/NTDS/WDigest, Services/Scheduled-Tasks, SMB/RDP/WMI/PsExec/UAL) against forensicnomicon MAIN tree (`crates/data/src/catalog/descriptors/*.rs`, `src/eventids.rs`, `src/processes.rs`, `src/commands.rs`, `src/attack_flow.rs`, `src/dpapi.rs`). Framed as *evidence an examiner inspects*.

## Counts
- **ENCODED ≈ 26** detection-artifact classes already recorded (see note below).
- **ENRICHMENT = 10** (present descriptor/event missing a detection detail).
- **NEW = 5** (no descriptor records the artifact at all).

ENCODED (count-only, not listed individually): LSASS credential store (`mem_user_credentials`) + single-instance/parent-of-wininit baseline (`processes::WINDOWS_SINGLETON_PROCESSES`, `WINDOWS_PARENT_RULES`) + LSASS-access/cred-dump tool lists (`processes::LSASS_ACCESS_TOOLS`, `CREDENTIAL_ACCESS_TOOLS`); Defender LSASS-dump alert (evt 1116/1117); WDigest `UseLogonCredential=1` (`wdigest_caching`); NTDS.dit DB (`ntds_dit`); SAM + LSA secrets (`sam_users`, `lsa_secrets`, `lsa_auth_pkgs`, `lsa_security_pkgs`); ESENT 216/325/326/327; Pass-the-Hash trio 4648+4624+4672 (each event present); Kerberos 4768/4769; log-clear 1102/104; service-install 7045; Task-Scheduler 106/140/141/200/201 + 4698/4702 + `scheduled_tasks_dir`/`taskcache_tasks_path`; services (`services_imagepath`, `services_hklm`); RDP TS logs 21/22/1149/1029 (`evtx_rdp_session`/`_inbound`/`_client`, `evtx_terminal_services`) + RDP client MRU/bitmap cache; WMI-Activity 5857-5861 (`evtx_wmi_activity`, `wmi_mof_dir`, `wmi_subscriptions`); WMIC remote-exec patterns (`commands::WMI_ABUSE_PATTERNS`); WinRM operational (`evtx_winrm`) + PowerShell 4103/4104/400/600; UAL/SUM (`sum_db`); ShimCache tracks Modified-time (`shimcache`); NTLM 4776/`evtx_ntlm`; Impacket exec-tool command names (`commands.rs`); SMB-client 31001 (`evtx_smb_client`).

---

## Enrichments (ranked)

- **7045 service-install → PSEXESVC / BTOBTO service-name signature** [High] — the 7045 entry is a generic "Service installed"; it does not record that a service named **PSEXESVC** (Sysinternals PsExec) or **BTOBTO** (Impacket `smbexec.py` default) with start type "demand start" running as LocalSystem is the target-side signature proving the host was the *destination* of a remote-exec session. _Target:_ EVENT_ID_TABLE 7045 (and/or `services_imagepath`/`services_hklm` meaning). _Cite:_ [MITRE T1569.002](https://attack.mitre.org/techniques/T1569/002/), Impacket `smbexec.py` source (default service `BTOBTO`), Mandiant lateral-movement writeups.
- **4624 Logon Type 3 = inbound network/SMB logon** [High] — the 4624 entry ("Successful logon") omits logon-type semantics; **Type 3** isolates inbound SMB/network logons for a lateral-movement timeline (vs Type 10 RDP, Type 2 interactive). Without it an examiner can't separate SMB access from console logon. _Target:_ EVENT_ID_TABLE 4624 (add logon-type note/field). _Cite:_ [MS 4624 docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/).
- **`ntds_dit` — Ntdsutil IFM dump filesystem signature** [High] — descriptor points only at `C:\Windows\NTDS\NTDS.dit`; it does not record the attacker-dump trace: an `ntdsutil "ac i ntds" ifm "create full <path>"` leaves sibling **`Active Directory\`** (holds `NTDS.dit` + a `.jfm` flush-map) and **`registry\`** (SYSTEM + SECURITY hives) subdirs under an ad-hoc path (commonly `C:\ProgramData\...`); even now-empty dirs are indicators, and the write is corroborated by **ESENT 325** naming `ntds.dit` outside its normal path. _Target:_ `ntds_dit` (meaning + related_artifacts to evt 325). _Cite:_ [MS ntdsutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ntdsutil), [MITRE T1003.003 detection](https://attack.mitre.org/techniques/T1003/003/).
- **1102 & 104 — suppressible by Mimikatz event-log patching** [Med] — both log-clearing events are encoded, but neither notes that Mimikatz `event::drop` patches the running EventLog service to clear logs *without* emitting 1102/104, so their **absence does not prove logs were untouched**. High-value caveat for any anti-forensics assessment. _Target:_ EVENT_ID_TABLE 104 and 1102 (description caveat). _Cite:_ [MITRE T1070.001](https://attack.mitre.org/techniques/T1070/001/), Mandiant "Mimikatz Overview, Defenses and Detection".
- **`evtx_wmi_activity` — WMI remote-exec (not just persistence subscriptions)** [Med] — meaning frames 5857-5861 around persistence subscriptions (5861); it does not record WMI as a *lateral-movement/remote-exec* vector: `wmic /node:<ip> process call create` leaves an operation record (5857/5858) and spawns a child parented by **wmiprvse.exe** — the target-side trace of `wmiexec.py`/WMIC. _Target:_ `evtx_wmi_activity` meaning (+ relate to `processes` ancestry). _Cite:_ [Mandiant WMI offense/defense/forensics](https://cloud.google.com/blog/topics/threat-intelligence/windows-management-instrumentation-wmi-offense-defense-forensics), [MITRE T1047](https://attack.mitre.org/techniques/T1047/).
- **`shellbags_user` — captures UNC/network-share paths** [Med] — meaning says folder browsing only; it does not record that shellbags also persist **network/UNC locations** (e.g. `\\host\financialdata\payroll`), exposing the SMB destinations an interactive actor browsed to — a lateral-movement mapping source. _Target:_ `shellbags_user` meaning. _Cite:_ [SANS ShellBags forensics](https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags/), Magnet Forensics ShellBags.
- **ShimCache PsExec timing exception + 7045 correlation** [Med] — `shimcache` correctly notes it stores the **Modified** time, not execution time; it does not record the PsExec exception: a freshly-dropped `PSEXESVC.exe` has M = creation (new-file MACB equal), so its ShimCache timestamp approximates *execution time* when corroborated by a matching 7045. _Target:_ `shimcache` meaning/related_artifacts. _Cite:_ [Mandiant ShimCache](https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-val), [MS NTFS timestamp behaviour](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times).
- **`regedit_currentversion_explorer_runmru` — admin/hidden-share (`\\host\d$`) evidence** [Med] — generated meaning is only "RunMRU(Start>Run)"; it does not record that RunMRU captures **typed network paths including `$`-suffixed admin shares** (`C$`/`D$`/`ADMIN$`), proving a user reached a hidden SMB share — a classic lateral-movement tell. _Target:_ `regedit_currentversion_explorer_runmru` meaning. _Cite:_ [MS admin shares](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/administrative-shares-cannot-be-deleted), forensafe RunMRU.
- **`wdigest_caching` — value-absent-by-default + offline ControlSet00x path** [Med] — descriptor gives the live `CurrentControlSet` path and the `=1` meaning, but not that **`UseLogonCredential` does not exist by default** (its mere creation is the artifact) and that on a dead/offline hive there is no `CurrentControlSet`, so the examiner must check `ControlSet001`/`ControlSet002`. _Target:_ `wdigest_caching` meaning/caveats. _Cite:_ [MS KB2871997](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649), [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/).
- **`sum_db` — dirty-ESE database requires `esentutl /p` before parsing** [Low] — the SUM/UAL descriptor is thorough, but does not record the acquisition caveat: a live-collected `Current.mdb`/`{GUID}.mdb`/`SystemIdentity.mdb` is locked and errors "not shut down cleanly" in SumECmd; repair with built-in **`esentutl /p`** (which discards unreplayed transaction logs — an evidentiary note). Methodology, not new evidence. _Target:_ `sum_db` caveats. _Cite:_ [MS esentutl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/esentutl), EricZimmerman SumECmd.

## New (ranked)

- **Event ID 5145 / 5140 — network share object access (SMB)** [High] — no EVENT_ID_TABLE entry; **5145** (detailed file-share access) records the exact share + relative target path an account touched, **5140** the share connect — the primary evidence, beyond 4624, tying an identity to a specific share during SMB lateral movement. _Target:_ EVENT_ID_TABLE (new 5140, 5145). _Cite:_ [MS 5145](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145), [MS 5140](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140), [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/).
- **`PSEXESVC.exe` dropped binary in `%SystemRoot%` (on-disk PsExec-target artifact)** [High] — no file descriptor for the service binary PsExec writes to `C:\Windows\PSEXESVC.exe` on *every* run; its presence and MFT birth (B) timestamp prove the host was the **TARGET** of PsExec and date the execution (recreated fresh each run). Distinct from the generic 7045 event. _Target:_ new descriptor in `windows_files_ext.rs`, related to evt 7045. _Cite:_ [MITRE T1569.002](https://attack.mitre.org/techniques/T1569/002/), [Sysinternals PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec), Mandiant.
- **Event ID 4697 — service installed (Security log)** [Med] — table has 7045 (System) but not **4697** (Security), the corroborating service-install record when "Audit Security System Extension" is enabled; confirms PsExec/service persistence independently of the System log. _Target:_ EVENT_ID_TABLE (new 4697). _Cite:_ [MS 4697](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697), [MITRE T1543.003](https://attack.mitre.org/techniques/T1543/003/).
- **Task-Manager LSASS dump file `lsass.DMP` in `%LocalAppData%\Temp`** [Med] — `mem_user_credentials` covers *live* LSASS creds and `windows_minidump` covers *crash* dumps, but no artifact records the specific attacker-produced LSASS process dump written by the Task Manager "Create Dump File" action to `C:\Users\<user>\AppData\Local\Temp\lsass.DMP` — a high-fidelity, hunt-by-name on-disk credential-dump artifact. _Target:_ new descriptor (`windows_files_ext.rs`), related to `mem_user_credentials` / evt 1116. _Cite:_ [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/), [Elastic "LSASS memory dump" rule](https://www.elastic.co/guide/en/security/current/lsass-memory-dump-creation.html).
- **Event ID 5156 — Windows Filtering Platform allowed a connection** [Med] — absent; ties a connection to concrete source/destination **IP + port**, giving SMB (or any) connectivity evidence when share-access auditing is off. (The ch05 fact flags it as missing even from the referenced cheat-sheet.) _Target:_ EVENT_ID_TABLE (new 5156). _Cite:_ [MS 5156](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156).

## Chapter 06

### IWE ch06 (Anatomy of NTFS) — Reconciliation vs forensicnomicon

Scope: 4 IWE fact files (I30, MACB, Metafiles/MFT/Journaling/ADS, Parsing MFT/USN).
Reconciled against MAIN checkout: `src/ntfs.rs` (constants/layout only) + descriptors
`ntfs_timestomping_si_fn`, `ntfs_logfile_records` (windows_ntfs_ext.rs), and `mft`,
`mft_file`, `usnjrnl`, `usn_journal`, `logfile_ntfs`, `ntfs_last_access_status`,
`shellbags_user` (mod.rs / windows_registry_ext2.rs).

## Counts

- **ENCODED: ~40 substantive facts.** Signatures FILE/BAAD/INDX (`src/ntfs.rs` SIGNATURE_*);
  attr type codes $SI 0x10 / $FN 0x30 / $DATA 0x80 / $INDEX_ROOT 0x90 / $INDEX_ALLOCATION 0xA0
  / $BITMAP 0xB0 / $REPARSE 0xC0 / $EA 0xE0; well-known metafiles $MFT/$MFTMirr/$LogFile/$Volume/
  $Bitmap/$Boot/$Secure/$Extend (mft_records); $Boot→MFT_LCN; record size 1024/4096; entry+seq=
  file-reference; In-Use flag + deleted-record/undelete; dual $SI/$FN MACB (8 timestamps, offsets);
  C hidden from API; $SI-settable/$FN-kernel; **$SI<$FN tell** + **nanosecond-zero tell** (2 of 3);
  USN reason codes with hex bitmask (FILE_CREATE 0x100 / FILE_DELETE 0x200 / RENAME_OLD 0x1000 /
  RENAME_NEW 0x2000 / DATA_OVERWRITE 0x1 / CLOSE 0x80000000), $J-ADS/sparse/$Extend path, $Max
  metadata, USN→MFT correlation, rename-chain, rolling window; **$LogFile op codes**
  (InitializeFileRecordSegment / Add+DeleteIndexEntryAllocation, redo/undo) fully in
  `ntfs_logfile_records`; deletion-has-no-MACB→journal; NtfsDisableLastAccessUpdate + 0x80000001
  (`ntfs_last_access_status`); sparse flag; reparse point; filename namespaces + 8.3; hard-link/ref count.
- **ENRICHMENT: ~14 facts → 9 gaps** in existing descriptors (below).
- **NEW: ~18 facts → 3 descriptors** absent (below).
- **Out of scope (~30 facts):** pure tooling/workflow — MFTECmd `-f/--csv/--csvf/--dr`, FTK Imager
  export, CAPE collector, Timeline Explorer, VSC processing, row counts, red-X overlay, `dir /r`,
  `more <`, `copy con`. Not descriptor material; neither gap nor coverage.

## Enrichments (ranked)

- **Per-operation MACB rule matrix** [High] — no descriptor encodes the legitimate baseline of which of M/A/C/B move per operation (CREATE→all four = create time; ACCESS→A only; MODIFY→M+A, B untouched; RENAME→C only, API-invisible; COPY→B+A=copy time, M inherited from source; local MOVE→B+M preserved, C conditional, A anomalous; DELETE→none, in neither $SI nor $FN). This is the interpretive baseline that tells legitimate-from-forged; without it the timestomping flags have no reference frame. Add as an interpretive note/field-set. _Target:_ ntfs_timestomping_si_fn (meaning/caveats) or new `ntfs_macb_rules`. _Cite:_ Carrier FSFA ch11–13 (timestamp update rules; note Carrier predates modern OS-version drift).
- **COPY tell (M earlier than B / modified-before-created)** [High] — the 3rd timestomping/copy heuristic the task names is absent; `ntfs_timestomping_si_fn` has only `si_before_fn` + `si_subsecond_zeroed` (2 of 3). A copied file inherits source M while getting a fresh B, so `si_modified < si_created` flags a copy. Add a derived `modified_before_created` flag. _Target:_ ntfs_timestomping_si_fn (NTFS_TIMESTOMPING_SI_FN_FIELDS). _Cite:_ Carrier FSFA (MACB update semantics on copy).
- **Resident-data flag + ~600-byte threshold** [Med] — MFT_FIELDS has `file_size` but no `is_resident`/`has_ads` residency indicator, and no note that $DATA content ≤~600 B lives in-record (fully recoverable from $MFT alone, MFTECmd `--dr`). _Target:_ MFT_FIELDS (mft / mft_file). _Cite:_ Carrier FSFA (resident vs non-resident $DATA).
- **ADS has_ads / is_ads columns** [Med] — MFT_FIELDS exposes no alternate-data-stream flags although the MFT record carries them and MFTECmd surfaces them; needed to flag $J, Zone.Identifier, and hidden streams per record. _Target:_ MFT_FIELDS (mft / mft_file). _Cite:_ libyal libfsntfs (named $DATA streams) / MS-FSCC §2.4.4.
- **$I30 as third timestamp source** [Med] — no descriptor records that folder/dir listings pull $FN-derived timestamps from the $I30 index (not $SI), that $I30 holds its own MACB set (usually = $SI), and the single-file(=$SI)-vs-folder-view(=$I30) source rule. Interpretive, ties to the NEW $I30 descriptor. _Target:_ new `ntfs_i30_index` meaning / mft. _Cite:_ Carrier FSFA ch13 (NTFS directory indexes).
- **$MFTMirr is a partial mirror (records 0–3 only)** [Low] — `src/ntfs.rs` mft_records::MFTMIRR gives the record number but no note it duplicates only the first four MFT records for single-sector-failure recovery, not the whole table. _Target:_ src/ntfs.rs (MFT_RECORD_NAMES comment) / mft. _Cite:_ Carrier FSFA / libyal libfsntfs ($MFTMirr).
- **Zone ID content + reparse-target columns on the MFT record** [Low] — MFTECmd surfaces a Zone-ID-contents and reparse-target column per record; MFT_FIELDS has neither (reference-count = existing `hard_link_count`). Ties to the Zone.Identifier NEW descriptor. _Target:_ MFT_FIELDS. _Cite:_ MS-FSCC (reparse points §2.1.2) / libyal libfsntfs.
- **`usn_journal` is a shallow duplicate of `usnjrnl`** [Low] — the `usn_journal` descriptor (id `usn_journal`, mod.rs:5222) borrows `DIR_ENTRY_FIELDS` and lacks the USN reason-code bitmask that `usnjrnl` (USNJRNL_FIELDS) already encodes. Point it at USNJRNL_FIELDS to avoid a thin, reason-code-less second copy. _Target:_ usn_journal (mod.rs). _Cite:_ libyal USN dtformats (USN_RECORD_V2 reason flags).
- **A-timestamp ≤128 GB conditional re-enable nuance** [Low] — `ntfs_last_access_status` captures the registry toggle + 0x80000001 well but not the Win10-build history (Vista off → re-enabled on ≤128 GB boot drives → fully re-enabled through Win11). Mostly context, minor caveat value. _Target:_ ntfs_last_access_status (evidence_caveats). _Cite:_ MS-FSCC / Microsoft fsutil behavior docs.

## New (ranked)

- **$I30 directory-index slack (deleted-filename recovery)** [High] — INDX signature exists as a bare constant in `src/ntfs.rs` (SIGNATURE_INDX) but there is NO artifact descriptor. Missing: the $I30 = virtual view of $INDEX_ROOT (0x90) + $INDEX_ALLOCATION (0xA0) + $BITMAP (0xB0); B-tree rebalancing creates slack distinct from file slack; slack retains a removed file's **name, size, and full MACB set** (≈$SI values) — often the only proof a file existed; survives Shift+Delete; MFTECmd "From Slack"=True boolean; physical-vs-logical size + cluster arithmetic. _Target:_ new descriptor `ntfs_i30_index`. _Cite:_ Carrier FSFA ch13 (NTFS indexes/B-trees/INDX) + libyal libfsntfs (index entry / $INDEX_ALLOCATION).
- **Zone.Identifier / Mark-of-the-Web** [High] — no descriptor. Missing: OS-created ADS `filename:Zone.Identifier` on internet-downloaded files, embeds HostUrl (source URL), and the **ZoneId enum 0=Local Computer / 1=Local Intranet / 2=Trusted Site / 3=Internet / 4=Restricted Site** (3 is the download-provenance value). High attribution value; download-origin evidence. _Target:_ new descriptor `zone_identifier`. _Cite:_ MS-FSCC §2.4.4 (named data streams) for the ADS mechanism; ZoneId enum per Microsoft URL security zones (record in prose, not 13cubed).
- **Alternate Data Streams (generic)** [Med] — no dedicated ADS descriptor (only per-record flags, see enrichment). Missing: `filename:streamname` colon syntax, ADS is an extra $DATA stream in the MFT record, invisible to size/`dir`/Explorer-properties, legitimate ($J, Zone.Identifier) vs abuse (hidden malware/contraband), HFS resource-fork origin. Could fold into the Zone.Identifier/MFT-flag work rather than stand alone. _Target:_ new `ntfs_ads` or merge into `zone_identifier` + MFT_FIELDS flags. _Cite:_ MS-FSCC §2.4.4 (named streams) / Carrier FSFA (NTFS $DATA attributes).

## Chapter 07

### IWE ch07 (File Deletion & Recovery) vs forensicnomicon — Reconciliation

Scope: MAIN tree only. Descriptors read: `recycle_bin` (+ `RECYCLE_BIN_FIELDS`) in
`crates/data/src/catalog/descriptors/mod.rs`; generated `fa_file_recycle_bin`,
`fa_file_recycler`, `fa_file_info2`, `kape_file_recycle_info2`; deletion mechanics in
`src/ntfs.rs` and `src/antiforensics.rs`. RBCmd is already cited as a `recycle_bin` source
(`github.com/EricZimmerman/RBCmd`) and in `src/references.rs`.

## Counts

- **ENCODED (count only): ~24** — the whole Vista+ $I model is well-covered by the `recycle_bin`
  descriptor: two-file $I/$R model + shared-suffix pairing (`i_filename` field), $I=metadata /
  $R=content, `version` (v1 path@24 / v2 path@28), `original_size`, `deletion_time` (FILETIME,
  **explicitly** "moment moved to Recycle.Bin — not secure-delete time" → move-time semantics
  ENCODED), `original_path`, `sid` + SAM pivot, `r_file_exists` ($R-absent still recoverable from
  $I), `mft_addr`. Pre-Vista generations exist as separate descriptors (`fa_file_info2`,
  `fa_file_recycler`). Permanent-deletion mechanics: resident vs non-resident (`ntfs.rs`
  `mft_offsets::NON_RESIDENT`), MFT `IN_USE` flag + "unallocated entries = recently deleted, persist
  until overwritten" (`mft_file` descriptor, mod.rs ~2561), secure-delete tool names + Shift+Delete
  bypass mention (`antiforensics.rs`). Undelete-via-inactive-MFT concept ridable on `mft_file`.
- **ENRICHMENT: ~8** (below).
- **NEW: ~7** — the entire file-carving / PhotoRec fact set has **no descriptor** in the tree
  (grep for `photorec` / `file_carv` / carving-id returns only author names and prose asides).

## Enrichments (ranked)

- **Recycle Bin — RBCmd usage & output fields** [Med] — RBCmd is cited only as a URL; the descriptor
  encodes none of its behaviour: output fields ("Found one File" count, format-version 2 = Win10/11,
  size in bytes **and** KB, original path, "Deleted On" = recycled-on), CLI flags (`-f` single file,
  `-d` recursive dir, `--csv <dir>`, `--csvf <name>`, stdout-by-default, Tab auto-completes to the $I
  member not $R), and that RBCmd parses **both** INFO2 and $I. _Target:_ `recycle_bin`. _Cite:_ EZ RBCmd docs (github.com/EricZimmerman/RBCmd).
- **Recycle Bin — filename anatomy (six random chars + preserved original extension)** [Med] — `i_filename`
  says only "$I{hex} … random but consistent within the pair". Missing: the token is **six** characters
  (and "hex" is imprecise), and the recycle-bin name **ends with the original file extension**, identical
  on both $I and $R (e.g. `$IXXXXXX.png` ↔ `$RXXXXXX.png`) — the extension hints at type without parsing $I.
  _Target:_ `recycle_bin` (`RECYCLE_BIN_FIELDS.i_filename`). _Cite:_ $I file-format writeup (github.com/akhil-dara/RecycleBin-Forensic-Explorer).
- **Recycle Bin — hidden-directory triage gotcha** [Med] — both `$Recycle.Bin` and its per-SID
  subdirectories are hidden; a non-hidden-aware listing yields a false negative. Not in `evidence_caveats`.
  _Target:_ `recycle_bin` (`evidence_caveats`). _Cite:_ EZ RBCmd docs / Carrier FSFA (Recycle Bin).
- **Recycle Bin — bypass leaves no $I/$R caveat** [Med] — empty-bin / Shift+Delete / cmd / PowerShell
  create no $I/$R pair, so absence of the artifact ≠ file never deleted (recovery falls to carving /
  journal). The descriptor states $I *survival* but not this *absence* caveat. _Target:_ `recycle_bin`
  (`evidence_caveats`). _Cite:_ Carrier, *File System Forensic Analysis* (deletion & Recycle Bin).
- **Permanent deletion — undelete gated by cluster non-reuse** [Med] — metadata-based undelete succeeds
  only if the file's clusters have not been reused; a recovered record pointing at overwritten clusters
  yields garbage. `mft_file` encodes "unallocated entries persist until overwritten" but not this
  recovery-viability rule. _Target:_ `mft_file` descriptor (mod.rs ~2561) / `src/ntfs.rs`. _Cite:_ Carrier FSFA (NTFS analysis / recovery).
- **Permanent deletion — $Bitmap cluster-free mechanic** [Low] — on delete the file's clusters are marked
  free in `$Bitmap` (record 6, already named in `ntfs.rs` `MFT_RECORD_NAMES`) and the MFT `IN_USE` flag is
  cleared; the free-cluster half of the mechanic isn't spelled out. _Target:_ `src/ntfs.rs`. _Cite:_ Carrier FSFA (NTFS $Bitmap).
- **Permanent deletion — trigger equivalence** [Low] — Shift+Delete, empty-from-bin, and cmd/PowerShell
  `del` all drive the identical NTFS change sequence (same recovery workflow). Encoded only as scattered
  tool/bypass strings in `antiforensics.rs`. _Target:_ `src/antiforensics.rs`. _Cite:_ Carrier FSFA (deletion).
- **Recycle Bin — pre-Vista OS→dir-name mapping** [Low] — descriptors exist for INFO2/Recycler, but the
  OS mapping (95/98/ME = `Recycled`, NT/2000/XP = `Recycler`, single consolidated `INFO2` for 95–XP with
  path/size/date-sent fields) is not captured in their prose. _Target:_ `fa_file_info2` / `fa_file_recycler`.
  _Cite:_ Carrier FSFA (FAT/NTFS Recycle Bin) / EZ RBCmd docs.

## New (ranked)

- **File carving (content/signature-based recovery)** [High] — no carving descriptor exists. Core model:
  recovers files by recognising built-in header/format **signatures** in unallocated space, independent of
  filesystem metadata — the recovery path when no MFT record survives. _Target:_ new `file_carving`
  descriptor (or `src/` carving module). _Cite:_ Carrier, *File System Forensic Analysis* (data recovery / carving); PhotoRec docs (cgsecurity.org).
- **Carving limitations** [High] — carving cannot recover **fragmented** files (assumes contiguous
  clusters) and recovers **no original filename, path, or MAC timestamps** — only content; recovered-file
  timestamps reflect the carve, not the original. Critical epistemic caveat for any carving finding.
  _Target:_ new `file_carving` descriptor (`evidence_caveats`). _Cite:_ Carrier FSFA (carving limitations); PhotoRec docs.
- **PhotoRec tool identity** [Med] — PhotoRec ships inside the **TestDisk** bundle; two Windows binaries
  `photorec_win.exe` (TUI) / `qphotorec_win.exe` (GUI) perform the identical carve. _Target:_ new
  `photorec` descriptor. _Cite:_ PhotoRec/TestDisk docs (cgsecurity.org).
- **PhotoRec output layout & naming** [Med] — writes to sequential `recup_dir.N` folders with files named
  `f<number>.<ext>`, optionally metadata-renamed from embedded content (e.g. EXIF). Lets an examiner
  recognise/parse a PhotoRec output tree. _Target:_ new `photorec` descriptor. _Cite:_ PhotoRec docs (cgsecurity.org).
- **PhotoRec signature selection / custom signatures** [Med] — large built-in signature library (UI shows a
  subset); "File Formats" (GUI) / "File Options" (TUI, space toggles) restrict the target set to speed the
  carve; user-defined custom signatures for formats not in the library. _Target:_ new `photorec` descriptor.
  _Cite:_ PhotoRec docs (cgsecurity.org).
- **Free-space vs whole-partition scan mode** [Low] — PhotoRec can scan only unallocated (free) space or the
  whole partition; the choice trades completeness for runtime. _Target:_ new `photorec` descriptor. _Cite:_ PhotoRec docs (cgsecurity.org).
- **Filesystem-type selection hint** [Low] — carve target selection distinguishes ext2/3/4 vs "other"
  (NTFS/FAT/exFAT) for free-space location; minor operational option. _Target:_ new `photorec` descriptor. _Cite:_ PhotoRec docs (cgsecurity.org).

## Chapter 08

### IWE Ch08 (LNK Files & Jump Lists) — reconciliation vs forensicnomicon

Scope: `src/shlink.rs` (`[MS-SHLLINK]` constants — HeaderSize, LinkCLSID, all
LinkFlags, FileAttributesFlags, ExtraData block signatures) and `src/jumplist.rs`
(DestList header/entry offsets v1+v2, CustomDestinations format/footer/category
types, AppID CRC-64 + `appid_name` + `WELL_KNOWN_APPIDS`). Both are **knowledge-only**
modules (constants/doc), registered in `src/lib.rs`; the parser lives in `lnk-core`.
No separate id-string descriptor registry exists — these two modules *are* the
descriptors for ids `lnk`/`shlink`, `jumplist`, `automaticdestinations`,
`customdestinations`, `destlist`.

**Counts (per-bullet, 120 total): ENCODED 45 · ENRICHMENT 31 · NEW 44.**

Classification note: `shlink.rs` already encodes the *presence flags* (LinkFlags),
the target *attributes* enum (FileAttributesFlags), the ExtraData signatures incl.
`TrackerDataBlock`, and — at doc level — target path / volume serial / machine
NetBIOS name / droid GUID. It does **not** model the `ShellLinkHeader` fixed fields
(three target FILETIMEs, FileSize, IconIndex) or the `LinkInfo` VolumeID fields
(label, drive type). `jumplist.rs` encodes one entry FILETIME (last-access),
hostname, pin status, access count, droid GUIDs — but not MRU ordering, a second
per-entry timestamp, or MAC-from-droid derivation.

## Enrichments (ranked)

- **Embedded target B/A/M timestamps (ShellLinkHeader)** [High] — `shlink` encodes `HEADER_SIZE` but not the header's three fixed FILETIME fields (CreationTime/AccessTime/WriteTime of the *target*), the field an examiner recovers for a deleted file. Add header field-offset constants / doc. _Target:_ `src/shlink.rs`. _Cite:_ [MS-SHLLINK] §2.1 ShellLinkHeader; liblnk *LNK format* §3 Data.
- **Two-timestamp-set distinction (LNK host $SI vs embedded target)** [High] — the module doc says "MAC timestamps" without separating the LNK file's own host timestamps from the embedded target timestamps; this is the highest-value examiner gotcha. Document the split. _Target:_ `src/shlink.rs` (doc). _Cite:_ [MS-SHLLINK] §2.1; liblnk *LNK format* §3.
- **Win10/11 create-on-file-creation behaviour change** [High] — legacy Windows created the LNK on *open*; Win10/11 create it on target *creation*, so LNK existence no longer proves the target was opened. Neither module notes this inference-changing behaviour. _Target:_ `src/shlink.rs` (doc). _Cite:_ EZ LECmd docs; liblnk *LNK format* (creation semantics).
- **LinkInfo VolumeID fields — volume label + drive type** [Med] — `shlink` models neither the `LinkInfo` structure nor its `VolumeID` (VolumeLabelOffset, DriveType incl. removable/fixed); volume serial and local base path are only mentioned in the doc. _Target:_ `src/shlink.rs`. _Cite:_ [MS-SHLLINK] §2.3 LinkInfo / §2.3.1 VolumeID; liblnk §4.
- **Target file size (ShellLinkHeader.FileSize)** [Med] — the header FileSize field (size of a now-deleted target, recoverable from the LNK) is not encoded. _Target:_ `src/shlink.rs`. _Cite:_ [MS-SHLLINK] §2.1.
- **MAC address derived from droid/birth GUID node bytes** [Med] — both modules encode the droid/BirthDroid GUIDs but not that the NIC MAC is the v1-UUID node field of those GUIDs (the "MAC address" JLECmd/LECmd surface). Note the derivation. _Target:_ `src/shlink.rs` (TrackerDataBlock) + `src/jumplist.rs` (DestList droid GUIDs). _Cite:_ liblnk *LNK format* TrackerDataBlock; dtformats *Jump lists* DestList (droid identifiers).
- **DestList MRU ordering vs EntryNumber distinction** [Med] — `jumplist` encodes `EntryNumber` and the last-access FILETIME but not the MRU-position concept (MRU 0 = most recent), which is distinct from the storage EntryNumber. _Target:_ `src/jumplist.rs`. _Cite:_ dtformats *Jump lists* §2.1.2; kacos2000 Jumplist-Browser DestList notes.
- **DestList per-entry creation vs last-modified timestamps** [Med] — the module encodes a single last-access FILETIME (offset 100); IWE distinguishes a per-entry creation and a last-modified time (JLECmd surfaces both, partly from the embedded LNK). Document which timestamp is which. _Target:_ `src/jumplist.rs`. _Cite:_ dtformats *Jump lists* DestList entry; EZ JLECmd docs.
- **AppID map gaps — Adobe Illustrator; VS Code AppID variance** [Med] — Illustrator (`163AA…`) is absent from `WELL_KNOWN_APPIDS` (reported "unknown"); IWE's VS Code AppID (`1CED…`) differs from the map's `e36b6e3a…` entry (path/version-dependent). Extend the curated map. _Target:_ `src/jumplist.rs` `WELL_KNOWN_APPIDS`. _Cite:_ kacos2000 Jumplist-Browser `AppIdlist.csv`.
- **LNK host mtime = last target-access semantics** [Low] — the LNK's own modification time advances on any open (even open-and-close with no edit); useful as a "last accessed" proxy. Not documented. _Target:_ `src/shlink.rs` (doc). _Cite:_ EZ LECmd docs; liblnk *LNK format*.
- **Standalone-LNK Recent folder location** [Low] — `jumplist` doc gives the Recent path; `shlink` gives no on-disk location for standalone `.lnk` (`%AppData%\Roaming\Microsoft\Windows\Recent`). _Target:_ `src/shlink.rs` (doc). _Cite:_ liblnk *LNK format*; EZ LECmd docs.
- **Target 8.3 short name (LinkInfo)** [Low] — the short-name field (equal to long name when ≤8 chars) is not modeled. _Target:_ `src/shlink.rs`. _Cite:_ [MS-SHLLINK] §2.3 LinkInfo / §2.1.1 LinkTargetIDList.
- **ShellLinkHeader IconIndex** [Low] — attributes are encoded (FileAttributesFlags) but the header IconIndex field is not. _Target:_ `src/shlink.rs`. _Cite:_ [MS-SHLLINK] §2.1.
- **Manual/user-vs-OS LNK creation** [Low] — that most LNKs are OS-generated (New→Shortcut is the rare manual case) frames why they are evidentiary. _Target:_ `src/shlink.rs` (doc). _Cite:_ liblnk *LNK format*; EZ LECmd docs.
- **Browser jump lists carry non-file categories** [Low] — Chrome's jump list holds "most visited"/"recently closed tabs" (custom-destination tasks), not recent files. _Target:_ `src/jumplist.rs` (doc). _Cite:_ dtformats *Jump lists* §3 (custom categories); kacos2000 Jumplist-Browser.
- **Same AppID across automatic + custom** [Low] — an app uses one AppID (from its exe path) for both container types, enabling correlation. _Target:_ `src/jumplist.rs` (doc). _Cite:_ Hexacorn *Jump to Jump to Jump* (AppID derivation).
- **Pinned-item location nuance** [Low] — IWE says pinned items live in custom destinations; the module also encodes a `PinStatus` in the *automatic* DestList entry. Note both surfaces of "pinned". _Target:_ `src/jumplist.rs` (doc). _Cite:_ dtformats *Jump lists* DestList (pin status); EZ JLECmd docs.
- **Custom-destinations low-value gotcha** [Low] — custom destinations frequently parse to null/empty fields; developer-defined, so no universal schema — pivot to the automatic file for the same AppID. _Target:_ `src/jumplist.rs` (doc). _Cite:_ dtformats *Jump lists* §3; EZ JLECmd docs.
- **DestList expected-vs-actual entry-count mismatch** [Low] — the header `NumberOfEntries` is encoded; a mismatch against actual walked entries flags truncation/deletion. Note as a parser sanity check. _Target:_ `src/jumplist.rs` (doc). _Cite:_ dtformats *Jump lists* §2.1.1; EZ JLECmd docs.
- **Removable-media drive-type tracking** [Low] — LNKs/jump lists still record files on USB/external drives; distinguishable via LinkInfo DriveType = removable. _Target:_ `src/shlink.rs` (LinkInfo DriveType). _Cite:_ [MS-SHLLINK] §2.3.1 VolumeID DriveType.

## New (ranked)

- **Tool: JLECmd usage & switches** [Med] — `-f`/`-d`, CSV output dir, `--appIds` mapping file (extends AppID resolution — which `appid_name` already implements as a curated map), `--dumpTo` LNK extraction, built-in mappings, full-Recent-path invocation. No tool/CLI descriptor in a knowledge-only crate. _Target:_ n/a (out of format scope; parser/tooling concern). _Cite:_ EZ JLECmd docs.
- **Tool: LECmd usage & switches** [Med] — `-f` single file, directory/recursive, CSV columns, mounted-image path, removable-only filter, admin-not-required, source-vs-target output sections. _Target:_ n/a (tooling concern). _Cite:_ EZ LECmd docs.
- **Hidden `.lnk` extension / double extension on disk** [Low] — Windows hides `.lnk` even with extensions shown (`HELLO-DEMO.txt.lnk` displays as `HELLO-DEMO.txt`); true name revealed via CLI `dir`. OS display behaviour, not a format field. _Target:_ n/a. _Cite:_ EZ LECmd docs (artifact naming).
- **Custom-destinations null-field / "both worth parsing" guidance** [Low] — a randomly chosen custom file can parse to all-null; still always parse both types. Workflow guidance. _Target:_ n/a. _Cite:_ EZ JLECmd docs; dtformats *Jump lists* §3.
- **Operational path helpers** [Low] — `%appdata%` in Run opens Roaming; "Recent Items" is a display alias for on-disk `Recent`; per-user path substitution; `dir /tc` reads LNK creation time; folder holds many shortcuts. Live-triage operational trivia. _Target:_ n/a. _Cite:_ EZ LECmd docs.
- **Tool: ExifTool as improper LNK parser** [Low] — ExifTool reads substantial LNK metadata (local-time + UTC offset display; top block = LNK's own M/A/C, "Inode change" = C timestamp) but is not the correct parser. Illustrative only. _Target:_ n/a. _Cite:_ liblnk *LNK format* (for the underlying fields ExifTool surfaces).
- **Manual AppID confirmation via live UI** [Low] — an unknown AppID can be confirmed by matching a live pinned-app jump list against parsed entries. Operational cross-check. _Target:_ n/a. _Cite:_ EZ JLECmd docs.
- **Cross-artifact USN.csv recovery example** [Low] — a deleted `USN.csv` desktop file's surviving LNK recovered its B/A/M + size; concrete illustration of persistence (already covered structurally). _Target:_ n/a (example). _Cite:_ liblnk *LNK format*.
- **Live-UI ↔ MRU correlation examples** [Low] — top non-pinned = MRU 0, UI order = MRU descending; end-to-end validation examples. _Target:_ n/a (validation). _Cite:_ dtformats *Jump lists* DestList (MRU).

## Chapter 09

### CHAPTER 09 (Timelining) — IWE ↔ forensicnomicon reconciliation

Reconciled against MAIN tree only: `src/timelining.rs` (5 `TimelineTool` descriptors — `fls`,
`mactime`, `log2timeline`, `psort`, `mftecmd_body`; 11-field `BODYFILE_FIELDS`; 14 `PLASO_PARSERS`).
Timestomping $SI-vs-$FN divergence is already encoded outside this module in `src/antiforensics_aware.rs`
(`Timestomping`, mft_file detection_hint) and `src/temporal.rs` (SI-vs-FN discrepancy hints), so
$FN-birth / $SI-mod facts are treated as ENCODED.

**Counts (approximate, fact-level across the 3 IWE files ~155 atomic facts):**
ENCODED ≈ 67 · ENRICHMENT ≈ 63 · NEW ≈ 13 (remainder = demo-specific skips: record counts, file sizes, runtimes, FTK-Imager acquisition, `ll` alias, `wc -l` check).

---

## Enrichments (ranked)

- **fls `-o` partition offset + "Cannot determine file system type" fix** [High] — descriptor command is `fls -r -m / {IMAGE}` with no `-o`; caveats never mention the multi-partition failure. IWE: on a whole-disk image with >1 partition fls cannot find a FS at offset 0; forcing `-f ntfs` does NOT fix it; the fix is `-o <start-sector>`. The single most important missing gotcha. _Target:_ `fls` descriptor / `src/timelining.rs`. _Cite:_ Sleuth Kit `fls` man page (`-o imgoffset`); Carrier FSFA.
- **l2tcsv deprecated → `dynamic` output format** [High] — encoded canonical uses `psort.py -o l2tcsv` and the caveat calls l2tcsv "industry-standard". Modern Plaso *warns against* l2tcsv (second-only resolution, fixed 17-field set) and recommends `dynamic` as default. Encoded canonical is stale. _Target:_ `psort` + `log2timeline` descriptors / `TimelineOutputFormat` / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (output modules).
- **MACB dot-notation decode** [High] — `BODYFILE_FIELDS` encodes the four MACB columns but nothing decodes mactime's `M.C.`/`.A..`/`M..B` collapsing: a dot = that timestamp type does not apply to this row; a letter = it does; identical times collapse into one row flagged by letters. _Target:_ `BODYFILE_FIELDS` / `mactime` / `src/timelining.rs`. _Cite:_ Sleuth Kit bodyfile spec (wiki.sleuthkit.org/Body_file); Carrier FSFA.
- **MFTECmd `--bdl` drive letter (required for a standalone $MFT bodyfile)** [High] — `mftecmd_body` command uses `-f \\.\C:` (a live volume, so drive letter is implicit) and omits `--bdl`. For an *extracted* `$MFT` file the standalone MFT carries no mount drive letter, so `--bdl <letter>` is required and is prepended to every path; any letter is accepted (tool does not validate), so it must be set to the real source drive. _Target:_ `mftecmd_body` descriptor / `src/timelining.rs`. _Cite:_ EZ MFTECmd docs (ericzimmerman.github.io).
- **log2timeline collection filters: `--artifact-filters` and `--file-filter`** [High] — no caveat covers collection-stage (into-.plaso) filtering. `--artifact-filters` takes ForensicArtifacts definition names (e.g. `WindowsEventLogSystem`); `--file-filter` takes a YAML include/exclude filter file. This is the super-timeline filter rule at the collection point. _Target:_ `log2timeline` descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (Collection filters); ForensicArtifacts repo.
- **mactime `-y` (ISO 8601 + UTC) and `-y`/`-z` mutual exclusivity** [Med] — descriptor command is `mactime -b body.txt -d`; caveat mentions `-z UTC` only. `-y` yields ISO 8601 output *and* normalises to UTC in one flag and is the preferred forensic option; `-z` (custom zone) should be avoided; the two cannot be combined. _Target:_ `mactime` descriptor / `src/timelining.rs`. _Cite:_ Sleuth Kit `mactime` man page.
- **MFTECmd CSV mode `--csv` (directory) + `--csvf` (filename) → Timeline Explorer** [Med] — only the bodyfile half of MFTECmd is encoded. The second capability: `--csv <dir>` sets the output *folder*, `--csvf <file>` the filename; the resulting CSV opened in Timeline Explorer *is* the file-system timeline (no bodyfile/mactime step). `--body`/`--bodyf` mirror this pairing. _Target:_ `mftecmd_body` descriptor / `src/timelining.rs`. _Cite:_ EZ MFTECmd docs.
- **psort `-w <file>` output flag + `.plaso` as positional arg** [Med] — encoded command redirects (`> supertimeline.csv`). Modern psort takes the `.plaso` store as a positional argument and writes with `-w`, e.g. `psort.py -o dynamic -w timeline.csv timeline.plaso`. _Target:_ `psort` descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io.
- **log2timeline `--storage-file` flag** [Med] — encoded command is positional `log2timeline.py {OUTPUT}.plaso {IMAGE}`; modern syntax names the store with `--storage-file <name> <image>`. _Target:_ `log2timeline` descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io.
- **psort `--slice` specifics + date-range filter** [Med] — caveat names `--slice`/`--slice_size` but omits: default slice window is 5 min before/after; the `--slice` time must be ISO 8601 *with timezone offset*; and psort supports a date-range filter (events after/before boundaries). Also verify flag spelling — IWE has `--slice-size` (hyphen) vs the caveat's `--slice_size` (underscore). _Target:_ `psort` descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (Event filters).
- **YAML `--file-filter` field schema** [Med] — no encoding of the filter-file structure: `type` (required, `include`|`exclude`), inclusion applied before exclusion, directory paths recurse the whole subtree, `paths` are regexes, `path_separator` defaults to `/` and must be set to `\` for Windows paths, optional `description`. _Target:_ `log2timeline` descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (Collection filters); ForensicArtifacts repo.
- **mactime date-range filter `YYYY-MM-DD..YYYY-MM-DD`** [Med] — no mactime output-window filter encoded; two-dot range (e.g. `2024-01-01..2024-01-31`) scopes the timeline. _Target:_ `mactime` descriptor / `src/timelining.rs`. _Cite:_ Sleuth Kit `mactime` man page.
- **Offset discovery: `fdisk -l` (Start sector) / `mmls`** [Med] — pairs with the `-o` fix but has no home. `fdisk -l <image>` lists partitions with Start/End/Sectors; the target partition's Start sector is the `-o` value; the Windows data partition is the largest (typically the "Microsoft basic data" of the EFI / MSR / MSData / Recovery layout). TSK's own `mmls` does the same. _Target:_ `fls` descriptor / `src/timelining.rs`. _Cite:_ Sleuth Kit `mmls` man page; Carrier FSFA (partition layout).
- **fls `-p` full-path flag** [Med] — encoded command uses `-r -m /` without `-p`; the IWE canonical is `fls -r -p -m "/"`. Without `-p` the bodyfile/timeline lacks full per-entry paths. _Target:_ `fls` descriptor / `src/timelining.rs`. _Cite:_ Sleuth Kit `fls` man page.
- **mactime CSV output column schema** [Med] — `BODYFILE_FIELDS` encodes the *input* bodyfile only; the mactime *output* CSV schema (Timestamp, MACB, meta, filename/full-path, size, UID, GID, permissions) is not encoded, nor the note that UID/GID/permissions are Unix-only and ignorable on NTFS, nor default oldest→newest sort. _Target:_ `src/timelining.rs` (new output-schema const) / `mactime`. _Cite:_ Sleuth Kit `mactime` man page.
- **Placeholder/bogus timestamp gotcha** [Med] — no caveat warns that files lacking a valid extractable timestamp show `1980-01-01` / `2001-01-01` sentinel dates (not tool errors) and, because of oldest-first sort, cluster at the top of the timeline. _Target:_ `mactime`/`fls` caveats / `src/timelining.rs`. _Cite:_ Sleuth Kit docs; Carrier FSFA (NTFS default timestamps).
- **Plaso install ordering gotcha** [Low] — `log2timeline` has a "broken install → purge/reinstall plaso-tools" caveat but not the setup: add `universe` repo, add the Plaso PPA, then run `sudo apt update` *before* `apt install plaso-tools` — skipping the update makes the install fail (stale index). _Target:_ `log2timeline` caveats / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (Ubuntu packaged-release install).
- **TSK install + fdisk prerequisite** [Low] — `sudo apt install sleuthkit`; `fdisk` is not preinstalled on a fresh Ubuntu (`sudo apt install fdisk`), needed to read the partition table for the `-o` offset. _Target:_ `fls` caveats / `src/timelining.rs`. _Cite:_ Sleuth Kit install docs.
- **fls silent-run + runtime expectation** [Low] — no caveat that fls prints nothing (bare cursor) while working — a normal working state, not a hang — and a full-volume enumeration can take minutes to 30 min+. _Target:_ `fls` caveats / `src/timelining.rs`. _Cite:_ Sleuth Kit `fls` docs.
- **.plaso store is SQLite** [Low] — the store is a SQLite DB (`file` reports SQLite), so it is directly inspectable/queryable with `sqlite3`. _Target:_ `log2timeline`/`PlasoStore` / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (storage format).
- **Plaso interactive partition prompt / `all`** [Low] — `log2timeline`/`psteal` prompt for a partition (`p3` = Windows in the ACME layout, the largest); typing `all` processes every partition. Distinct from TSK's explicit `-o`. _Target:_ `log2timeline` caveats / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io.
- **fls `-d` (deleted-only), `-f list`, MFTECmd auto-detect / cosmetic extension** [Low] — minor flags/behaviours: `-d` restricts to deleted entries; `-f list` prints supported FS types; MFTECmd auto-detects input type by signature (a renamed `$MFT`→`MFT` still parses) and the `.body`/`.csv` extension is cosmetic (format is set by the flag). _Target:_ `fls` / `mftecmd_body` / `src/timelining.rs`. _Cite:_ Sleuth Kit `fls` man page; EZ MFTECmd docs.

---

## New (ranked)

- **psteal (`psteal.py`)** [High] — no descriptor. One-step tool that fuses `log2timeline` + `psort` in a single pass: `psteal.py --source <image> -o dynamic -w timeline.csv`; `-o list` enumerates formats (same set as psort); output is byte-for-byte equivalent to the two-step pipeline. Deserves its own `TimelineTool` entry. _Target:_ new descriptor in `TIMELINE_TOOLS` / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (psteal).
- **pinfo (`pinfo.py`)** [Med] — named only inside `log2timeline`/`psort` caveats, no descriptor. Reports `.plaso` store metadata: total event count, earliest/latest timestamps, processed data-source types, and processing warnings/errors — the scope/sanity check before psort. _Target:_ new descriptor in `TIMELINE_TOOLS` / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (pinfo).
- **image_export (`image_export.py`)** [Low] — no descriptor. Extracts files of interest from a disk image by filter (filename, file type, location) to isolate evidence from large datasets — targeted collection rather than timelining. _Target:_ new descriptor / `src/timelining.rs`. _Cite:_ plaso.readthedocs.io (image_export).

## Chapter 10

### IWE Ch10 (Additional Content) → forensicnomicon reconciliation

Scope: four IWE lessons — Thumbcache, Web Browser Forensics, Windows Activity Timeline,
Windows Search Index. Compared against MAIN-tree descriptors only
(`crates/data/src/catalog/descriptors/`), worktrees and `target/` ignored.

**Counts:** ENCODED ≈ 4 artifact families already present and substantially covered
(the large majority of the ~200 atomic IWE facts map here) · ENRICHMENT = 10 rows ·
NEW = 4 rows.

Descriptors that already carry the core of each lesson:
- **Thumbcache** → `thumbcache` (mod.rs:3240) — path, per-user, deleted-file survival, Thumbcache Viewer cited.
- **Windows Timeline** → `windows_timeline` (mod.rs:2939) + `windows_timeline_devicecache` — path, SQLite, CopyPaste=Activity_Type 16, ~30d retention, GUID→device resolution, db-wal carving.
- **Windows Search** → `windows_search_edb` (windows_files_ext.rs:977) + `windows_search_db_win11` (mod.rs:3030) + `search_db_user` (mod.rs:3274) — ESE↔SQLite split, path change, gather_time independent of NTFS, AON write-up cited.
- **Browsers** → `edge_chromium_history`/`_login_data`, `chrome_*` (browser_ext.rs + mod.rs), `firefox_places`/`_session_restore`/`_form_history`/`_logins`, `browser_safari_history`, `edge_webcache`, generated `browsers_ie_webcache_db`. Chromium WebKit-µs and Firefox Unix-µs epochs already noted; `Network\Cookies` path already noted for Chrome.

## Enrichments (ranked)

- **WebCacheV01.dat (IE/legacy-Edge ESE)** [High] — `edge_webcache` points at `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` (the content-cache folder), not the ESE DB `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`; and the meaning omits the standout modern-Win11 value: `file:///<drive>:\path` **local file-access** entries (OS-tracked file opens, not browser visits — TA-tracking gold), plus the container map (History→history, Content→cache, Cookies→metadata-only, IEDownload→downloads). _Target:_ `edge_webcache`. _Cite:_ libesedb (libyal) + forensicswiki "WebCache" / MS docs.
- **Windows Search — Win11 three-database set** [High] — `windows_search_db_win11` lists only `windows.db`; missing the co-resident `Windows-gather.db` (holds the Gthr/gather tables) and `Windows-usn.db` (least relevant) in the same `...\Applications\Windows\` dir. All three must be collected. _Target:_ `windows_search_db_win11`. _Cite:_ SIDR docs (github.com/strozfriedberg/sidr) + AON Cyber Solutions Windows-Search write-up.
- **Thumbcache size-bucket table** [High] — descriptor omits the `thumbcache_<N>.db` resolution mapping (1280→1280×720, 1920→1920×1080, 2560→2560×1440, and up) and the triage tell that an empty bucket is ~24 bytes vs a populated bucket in the tens of MB. _Target:_ `thumbcache`. _Cite:_ Thumbcache Viewer docs / libyal dtformats / forensics.wiki "windows_thumbcache".
- **ActivitiesCache Win11-reduced caveat** [High] — `windows_timeline` (os_scope Win10Plus) does not record the OS-version degradation: UI removed in Win11 but local collection persists **through 22H2**; on **23H2** the DB exists but most useful data is gone, leaving mainly clipboard — and clipboard only when both "Clipboard history" and "Sync across devices" are enabled. Absence on 23H2 is not exculpatory. _Target:_ `windows_timeline`. _Cite:_ kacos2000 WindowsTimeline (Costas K.) + MS support "activity history".
- **Windows Search key tables + columns** [Med] — `windows_search_edb` cites only `SystemIndex_0A`; IWE's schema is `SystemIndex_Gthr` / `SystemIndex_GthrPth` / `SystemIndex_PropertyStore`, with the Win11 rename to `SystemIndex_1_PropertyStore` (+ `SystemIndex_1_PropertyStore_Metadata` for property-ID→name resolution). Column set also missing owner and full MACB (`System_DateCreated`/`_DateAccessed`). _Target:_ `windows_search_edb` / `windows_search_db_win11`. _Cite:_ SIDR docs + AON Cyber.
- **ActivitiesCache subfolder naming + activity/timestamp semantics** [Med] — path uses a bare `*`; missing that the `ConnectedDevicesPlatform\<sub>` name encodes account type (`L.<profile>` local vs `AAD.<GUID>` Entra/Azure AD). Also missing ExecuteOpen (Start=launch, often no End/Duration) vs InFocus (Start+End+Duration) semantics, Expiration = Start+30d, and Last-Modified / Last-Modified-On-Client anchors. _Target:_ `windows_timeline`. _Cite:_ kacos2000 WindowsTimeline + EricZimmerman/WxTCmd docs.
- **SIDR parser (both formats)** [Med] — no descriptor cites SIDR ("cider"), the purpose-built parser that reads both the Win10 ESE and Win11 SQLite indexes and emits File / Internet-History / Activity-History reports (Activity-History ~0 bytes on Win11 — known GitHub issue; populated on Win10). Useful as tool + independent oracle. _Target:_ `windows_search_edb`. _Cite:_ SIDR docs (github.com/strozfriedberg/sidr).
- **Thumbcache → path reconstruction cross-ref** [Med] — `thumbcache.related_artifacts` is empty; Thumbcache IDs/hashes map back to source paths "in some cases" via the Windows Search ESE DB (Thumbcache Viewer "Map File Paths" → Load ESE database). Wire a cross-ref to `windows_search_edb`/`search_db_user`. _Target:_ `thumbcache`. _Cite:_ Thumbcache Viewer docs (thumbcacheviewer.github.io).
- **Windows Search — Auto Summary partial content** [Med] — descriptor notes indexed metadata/timestamps but not Auto Summary, which caches portions of file content recoverable after move/delete (noisy but occasionally high-value). _Target:_ `windows_search_edb`. _Cite:_ AON Cyber Solutions write-up.
- **Windows Search — Server caveat + default scope** [Low] — missing that the indexer is on by default on client Windows but off by default on Server (explains artifact absence), and default scope indexes `C:\Users\*` **excluding AppData** plus the global `...\Start Menu\Programs` (per-user pinned/Startup not indexed). _Target:_ `windows_search_edb`. _Cite:_ MS docs "Windows Search" (learn.microsoft.com).

## New (ranked)

- **Thumbs.db (per-folder thumbnail cache)** [High] — a distinct artifact from Thumbcache with no descriptor: hidden per-folder DB (source path is implicit = its containing folder), still written on **modern Win11 22H2** for UNC/network paths, created only in an icon/thumbnail view, and reproducible locally via the loopback UNC share `\\localhost\C$` (direct `C:\` browsing does not create it). Survives file deletion/wiping. _Target:_ new descriptor `thumbs_db`. _Cite:_ libyal dtformats (Thumbs.db format) + Thumbs Viewer docs.
- **Edge (Chromium) cookies / cache / sessions** [Low] — only `edge_chromium_history` and `_login_data` are hand-authored; Chrome has the full set via `browser_ext.rs` but Edge lacks cookies (`Network\Cookies`), `Cache\`, and `Sessions\` descriptors despite identical Chromium layout. _Target:_ new `edge_chromium_cookies` / `_cache` / `_session`. _Cite:_ Chromium user-data-dir docs / SANS Edge forensics.
- **IE on-disk cookies + IE session Recovery** [Low] — actual IE cookie files at `%APPDATA%\Microsoft\Windows\Cookies` (and `...\Cookies\Low`) and session-restore `.dat` at `%LOCALAPPDATA%\Microsoft\Internet Explorer\Recovery` are unencoded (WebCacheV01.dat holds only cookie **metadata**). _Target:_ new `ie_cookies_ondisk` / `ie_recovery_session`. _Cite:_ MS docs / forensicswiki "Internet Explorer".
- **Firefox cache (cache2, Local exception)** [Low] — no Firefox cache descriptor; unlike other Firefox artifacts (Roaming), cache sits under `%LOCALAPPDATA%\...\<profile>.default-release\cache2\`. _Target:_ new `firefox_cache`. _Cite:_ Mozilla source / forensicswiki "Mozilla Firefox".
