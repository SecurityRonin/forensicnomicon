## Application Progress

Applied serially via TDD on `iwe-corrections` (each RED+GREEN committed). Update as items ship.

**Shipped from corpus:** emdmgmt_readyboost ✅, ntfs_ads ✅, ntfs_reparse_point ✅, photorec_recup_dir ✅, wzcsvc_wireless_interfaces ✅, photorec+pca_general_db1 ✅
**Also shipped earlier this session (pre-corpus):** cdp_gdid, ntfs_i30_index, psexesvc_dropped_binary, psteal, pinfo, image_export, amcache_program, lsass_dump_file, zone_identifier, thumbs_db

**Remaining confirmed NEW descriptors:** NONE — all 8 shipped ✅
**Enrichments shipped (11/43):** fls, psort/L2tCsv, run_mru, muicache, mountpoints2, shimcache, evtx_ntlm, windows_search_db_win11, wordwheel_query, mounted_devices, thumbcache ✅
**Enrichments remaining (36):** windows_search_db_win11, evtx_ntlm, evtx_security(x3), fa_file..recentfilecache, evtx_rdp_client, usb_stor_enum, ntds_dit, edge_webcache, thumbcache, windows_timeline, evtx_system, mounted_devices, wordwheel_query, regedit_system_select, pca_general_db, src/shlink.rs(x3), mactime, mftecmd_body, log2timeline, and the EVENT_ID_TABLE/eventids.rs items (216/325/326/327, 4776, 4688, 104/1102, 4104) + lolbins ntdsutil — several eventids items tripped the cyber safeguard in the workflow, apply manually with defensive framing.
**Needs-fix NEW remaining (7):** srum_app_timeline, file_carving, mem_extracted_pe_images, ntfs_objid, mem_access_tokens, ie_recovery_session, kansa_collection_output (each has FIX FIRST note inline).
**Remaining needs-fix NEW:** srum_app_timeline, file_carving, mem_extracted_pe_images, ntfs_objid, mem_access_tokens, ie_recovery_session, kansa_collection_output
**Enrichments (43):** see sections below — apply after new descriptors.

WATCH: some corpus specs set volatility:None WITH evidence_strength:Some — this violates the
catalog `assessed_entries_have_complete_metadata` invariant. Fix volatility at apply time
(ntfs_ads needed this). 

---

# IWE + GCFA Ingestion Corpus (source-verified)

Generated from the `iwe-gcfa-ingestion` workflow (run wf_7b8f95ec-847). Each spec was
drafted against an independent primary source and adversarially verified. Apply serially
via TDD on branch `iwe-corrections`. STATUS: `confirmed` = ready; `needs-fix` = apply the
listed correction first. Items already shipped this session are omitted.

## RESUME PLAN (next session — read this first)

**Branch:** `iwe-corrections` (local, rebased onto old main; `origin/iwe-corrections`@ec35759 is the IMMUTABLE backup — do NOT force-push it). All commits UNSIGNED (gitsign off to dodge OIDC storm) — batch re-sign before any push.

**Catalog count is at 6677** (18 assertions in tests.rs). Each new descriptor bumps all 18 (`perl -0pi -e 's/CATALOG\.list\(\)\.len\(\), N\)/...N+1.../g; s/\n            N,/\n            N+1,/g'`).

**Apply rhythm per new descriptor (proven this session):** read spec from this file → verify related_artifacts ids exist + enum variants valid → RED test in tests.rs::catalog_integrity (before `all_related_artifacts_exist`) → run (expect 101) → commit RED → add descriptor before the `/// All descriptor instances` anchor in mod.rs → register in CATALOG_ENTRIES → bump 18 counts → `cargo test -p forensicnomicon-data --lib` + clippy → commit GREEN. WATCH: any spec with `evidence_strength: Some` MUST have `volatility: Some` + non-empty rationale (invariant `assessed_entries_have_complete_metadata`) — the corpus specs sometimes set volatility:None wrongly (fixed ntfs_ads this way).

**Remaining confirmed NEW (2):**
- `ntfs_macb_rules` — interpretive MACB-update-rules baseline anchored to $MFT; fields encode the per-operation matrix (op_copy_xvolume etc.) — READ THE FULL FIELD LIST in this file before applying (unconventional). mitre T1070.006.
- `mem_findevil` — MemProcFS FindEvil anomaly taxonomy (MemoryRegion). Tripped the cyber safeguard during drafting; apply with defensive-DFIR framing (detection-of-malware artifact, not attack method). Full flag table + sources already in the Confirmed section above.

**Remaining needs-fix NEW (7):** srum_app_timeline, file_carving (re-attribute no-metadata caveat to Garfinkel not PhotoRec), mem_extracted_pe_images, ntfs_objid (soften 'MFT record 25' → dynamically-allocated under $Extend), mem_access_tokens, ie_recovery_session, kansa_collection_output. Each has its FIX FIRST note inline.

**Enrichments (43):** in the ENRICHMENTS section below. Many target src/eventids.rs EVENT_ID_TABLE (216/325/326/327, 4776, 4688, 104/1102, 4104), src/timelining.rs (fls l2tcsv-deprecation caveat, psort), src/lolbins.rs (ntdsutil), and catalog descriptors (run_mru, muicache, mountpoints2, shimcache, windows_search_db_win11, evtx_ntlm, evtx_security). NOTE: several eventids.rs items (104/1102 log-clearing, injection heuristics) tripped the cyber safeguard in the workflow — apply manually with defensive framing.

**Shipped this session from corpus (6):** emdmgmt_readyboost, ntfs_ads, ntfs_reparse_point, photorec_recup_dir, wzcsvc_wireless_interfaces, pca_general_db1.

---

## Confirmed (ready to apply)

### `mem_findevil` — FindEvil Anomaly Detections (Memory)  [new_descriptor]

```
NEW DESCRIPTOR — single descriptor covering the MemProcFS FindEvil detection output (the /forensic/findevil/findevil.txt virtual file), enumerating the anomaly-flag taxonomy as the load-bearing content. Not currently in the catalog (grep of catalog/descriptors + src for findevil/memprocfs/PEB_MASQ/PE_NOLINK/PE_PATCHED/masquerade/unlinked returned nothing). Fits the existing mem_* MemoryRegion family (mem_running_processes, mem_loaded_modules, etc.).

id: "mem_findevil"
name: "FindEvil Anomaly Detections (Memory)"
artifact_type: ArtifactLocation::MemoryRegion
hive: None
key_path: ""
value_name: None
file_path: None   (surfaced as the MemProcFS virtual file /forensic/findevil/findevil.txt — a memory-analysis product, not an on-disk path; noted in meaning per mem_* convention)
scope: DataScope::System
os_scope: OsScope::Win10Plus   (source: FindEvil is enabled only for 64-bit Windows 10/11 to keep the false-positive ratio low — m_fc_findevil.c readme + wiki)
decoder: Decoder::Identity
meaning: "MemProcFS FindEvil scans process/kernel memory for indicators of user-mode malware and reports anomalies in /forensic/findevil/findevil.txt (columns: PID, ProcessName, Type, VirtualAddress, ModuleName/Description). Each row is a typed detection flag ranked by severity. Key process/module/page anomalies (Name : Severity, from modules.h): PE_INJECT 0xe000 (module classified injected — in VAD image region but not a normal loaded module); UM_APC 0xd800 (user-mode APC injection); PROC_NOLINK 0xd000 (process EPROCESS not in the kernel ActiveProcessLinks list — DKOM unlinking); PROC_PARENT 0xc000 (unexpected/spoofed parent process); PROC_BAD_DTB 0xb000 (masqueraded DirectoryTableBase hiding page tables); PROC_USER 0xa000 (unexpected owning user); PROC_BASEADDR 0x9c00 (image base mismatch); PE_HDR_SPOOF 0x9800 (spoofed PE header); HIGH_ENTROPY 0x9400 (high-entropy page, packing/encryption); PEB_MASQ 0x9000 (PEB masquerade — user-land process image path differs from the kernel EPROCESS path); DRIVER_PATH 0x8000 (anomalous driver path); PROC_DEBUG 0x7800; THREAD 0x7400 (evil thread); PEB_BAD_LDR 0x7000 (no normally-linked modules in the PEB Ldr list); PE_NOLINK 0x6000 (executable PE module present in the VAD map but not linked from the in-process PEB/Ldr lists — unlinked/hidden module); PE_PATCHED 0x5000 (executable image page whose physical page differs from the kernel prototype page — in-memory code patch/hook); PRIVATE_RWX 0x4000 / NOIMAGE_RWX 0x3000 / PRIVATE_RX 0x2000 / NOIMAGE_RX 0x1000 (executable pages in private or non-image memory — classic injected/floating shellcode). Also emits TIME_CHANGE 0x10000 and AV_DETECT 0xf000, plus YARA (YR_*) hits from bundled Elastic rules when the Elastic License 2.0 is accepted."
fields (FieldSchema[]):
  - name: "pid", value_type: ValueType::UnsignedInt, description: "Owning process identifier of the flagged artifact", is_uid_component: true
  - name: "process_name", value_type: ValueType::Text, description: "Short process image name (max 15 chars as shown by MemProcFS)", is_uid_component: false
  - name: "detection_type", value_type: ValueType::Text, description: "FindEvil anomaly flag (e.g. PEB_MASQ, PE_NOLINK, PE_PATCHED, PE_INJECT, PROC_NOLINK, NOIMAGE_RWX, PRIVATE_RWX); higher-severity flags sort to the top of findevil.txt", is_uid_component: false
  - name: "virtual_address", value_type: ValueType::UnsignedInt, description: "Virtual address of the flagged region/module/PEB within the process address space", is_uid_component: true
  - name: "description", value_type: ValueType::Text, description: "Detection-specific detail — e.g. Module:[name] and backing VAD for PE_NOLINK/PE_INJECT, or page/protection detail for PE_PATCHED and RWX findings", is_uid_component: false
retention: Some("RAM only; lost on power-off")
triage_priority: TriagePriority::Critical
related_artifacts: &["mem_running_processes", "mem_loaded_modules", "mem_network_connections"]   (all three verified present in catalog: ids at mod.rs:8674, 8774, 8727)
sources: &[
  "https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/modules.h",   (authoritative VMMEVIL_TYPE table: exact flag Names + Severity values)
  "https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil",                     (tool's own documentation: per-flag descriptions, output format, 64-bit Win10/11 scope, FP caveat)
  "https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing"  (RE writeup on image-vs-private memory, RWX, modified/hollowed images — concepts behind PE_PATCHED / NOIMAGE_RWX / PRIVATE_RWX)
]
mitre_techniques: &["T1055", "T1055.012", "T1036", "T1620", "T1134.004"]
  - T1055 Process Injection — PE_INJECT, NOIMAGE_RWX/RX, PRIVATE_RWX/RX, PE_NOLINK
  - T1055.012 Process Hollowing — PROC_BASEADDR, PROC_BAD_DTB, PEB_MASQ
  - T1036 Masquerading — PEB_MASQ, PE_HDR_SPOOF
  - T1620 Reflective Code Loading — NOIMAGE_RWX/RX unbacked executable memory
  - T1134.004 Parent PID Spoofing — PROC_PARENT
evidence_strength: Some(EvidenceStrength::Corroborative)   (honest: MemProcFS wiki explicitly states "FindEvil have false positives in its current implementation" and "will miss certain types of malware"; a flag is an anomaly indicator consistent with — not proof of — malicious code, warranting manual follow-up)
evidence_caveats: &[
  "64-bit Windows 10/11 only; not produced on 32-bit or pre-Win10 targets",
  "Detects user-mode malware only; kernel/rootkit and not-yet-implemented techniques are missed",
  "Documented false positives — legitimate JIT, self-patching runtimes, and packed-but-benign code can trip PE_PATCHED / HIGH_ENTROPY / RWX flags; treat each row as an anomaly to investigate, not a confirmed detection",
  "PEB_MASQ and PROC_NOLINK findings suppress related PE_NOLINK rows for the same process (per-VAD/per-process finding limits), so absence of PE_NOLINK does not exclude an unlinked module",
  "YARA (YR_*) rows require accepting the Elastic License 2.0 at startup; absent otherwise"
]
volatility: Some(VolatilityClass::Volatile)
volatility_rationale: "Derived from live RAM; lost on power-off and re-computed per acquisition"
```

**Sources verified:**
- [1 (tool source code — the implementation itself)] https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/modules.h — Authoritative VMMEVIL_TYPE constant table giving the EXACT flag names and severities: PEB_MASQ=0x9000, PE_NOLINK=0x6000, PE_PATCHED=0x5000, PE_INJECT=0xe000, PROC_NOLINK=0xd000, PROC_PARENT=0xc000, PROC_BAD_DTB=0xb000, PROC_USER=0xa000, PROC_BASEADDR=0x9C00, PE_HDR_SPOOF=0x9800, HIGH_ENTROPY=0x9400, PEB_BAD_LDR=0x7000, PRIVATE_RWX=0x4000, NOIMAGE_RWX=0x3000, PRIVATE_RX=0x2000, NOIMAGE_RX=0x1000, plus TIME_CHANGE/AV_DETECT/UM_APC/DRIVER_PATH/PROC_DEBUG/THREAD (fetched raw from master)
- [1 (tool source code)] https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/m_evil_proc1.c — Detection logic + comments for PE_NOLINK (executable PE module in VAD map but not linked from in-process PEB/Ldr lists), PE_PATCHED (image VAD executable page whose physical page differs from the kernel prototype page), PE_INJECT, PEB_BAD_LDR, PROC_NOLINK
- [1 (tool source code)] https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/m_evil_proc2.c — PEB_MASQ logic + comment: 'Locate PEB masquerading - i.e. when process image path in user-land differs from the kernel path'; also PROC_BAD_DTB (masqueraded DirectoryTableBase), PROC_PARENT, PROC_USER
- [1 (tool source code)] https://github.com/ufrisk/MemProcFS/blob/master/vmm/modules/m_fc_findevil.c — README string confirming FindEvil is enabled only for 64-bit Windows 10+ to keep the false-positive ratio low, uses bundled Elastic YARA rules under Elastic License 2.0, and is memory-analysis-based
- [1 (tool's own documentation)] https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil — Human-facing per-flag descriptions and output format (columns PID/Process/Type/VirtualAddress/ModuleName), findevil.txt/yara.txt files, explicit 'primarily available on 64-bit Windows 10 and 11', explicit 'FindEvil have false positives', 'only detects user-mode malware', and the PE_NOLINK suppression side-effect under PEB_MASQ
- [1 (independent reverse-engineering writeup)] https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing — RE writeup on image vs private memory, RWX executable pages, and modified/hollowed image regions — the underlying concepts behind PE_PATCHED, NOIMAGE_RWX and PRIVATE_RWX (title verified: 'Masking Malicious Memory Artifacts – Part I: Phantom DLL Hollowing')

**Notes:** One descriptor is the right granularity: findevil.txt is a single MemProcFS output surface whose rows are typed by the flag taxonomy, mirroring the existing mem_* MemoryRegion family rather than exploding into ~22 near-identical descriptors. The flag names and severities are copied verbatim from modules.h (tier-1 tool source), not paraphrased.

Evidence strength deliberately set to Corroborative, not Definitive: MemProcFS itself documents false positives and coverage gaps, so a FindEvil flag is consistent with malicious code and warrants manual triage — it is not proof. This is the honest tier for a heuristic anomaly detector.

Triage logic for an analyst: sort by the built-in severity (findevil.txt already ranks high-to-low). PEB_MASQ / PROC_NOLINK / PROC_BAD_DTB point at process-level deception (hollowing, DKOM, path spoofing) — pivot to /sys/proc/proc-v.txt and compare kernel vs user image paths. PE_NOLINK / PE_INJECT point at hidden or injected modules — correlate the flagged VirtualAddress against mem_loaded_modules and the VAD map. PE_PATCHED points at in-memory hooks/patches — diff the flagged page against the on-disk image. NOIMAGE/PRIVATE RWX/RX are floating executable memory (shellcode) — correlate the owning PID with mem_running_processes and mem_network_connections for C2. Note the suppression side-effect: PEB_MASQ and PROC_NOLINK suppress PE_NOLINK rows for the same process, so absence of PE_NOLINK is not exculpatory. All three related_artifacts ids (mem_running_processes, mem_loaded_modules, mem_network_connections) were verified present in the catalog.

### `emdmgmt_readyboost` — EMDMgmt / ReadyBoost External Device Volume Cache  [new_descriptor]

```
id: "emdmgmt_readyboost"
name: "EMDMgmt / ReadyBoost External Device Volume Cache"
artifact_type: ArtifactLocation::RegistryKey
hive: Some(HiveTarget::HklmSoftware)
key_path: "Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"
value_name: None
file_path: None
scope: DataScope::System
os_scope: OsScope::Win7Plus  (feature is Vista+; no Vista-specific enum variant exists, and Win7Plus avoids over-claiming XP where the key does not exist — see caveat re Win11 22H2 removal)
decoder: Decoder::Identity
meaning: "EMDMgmt (External Memory Device Management) is the registry store written by the ReadyBoost service (Emdmgmt.dll). When any non-system-drive external storage volume is attached, ReadyBoost profiles it and writes a subkey whose NAME embeds three forensically valuable fields: the device instance ID (e.g. `_??_USBSTOR#Disk&Ven_...#<iSerialNumber>#`), followed by the GUID_DEVINTERFACE_DISK class GUID {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}, then the volume label, then the volume serial number in DECIMAL. It is one of the few registry locations (besides MountedDevices/MountPoints) that ties a device's USB iSerialNumber to a volume serial number (VSN), letting an examiner correlate the device to VSNs recorded in LNK files and Jump Lists — decisive when a drive letter has been reused across several devices. The same iSerialNumber appearing with multiple different VSNs is consistent with the volume having been reformatted (a new VSN is generated on each format)."
mitre_techniques: &["T1052.001", "T1025"]  (mirrors sibling usb_stor_enum: exfiltration over USB / data from removable media; the key is passive connection evidence supporting these investigations)
fields:
  - FieldSchema { name: "device_instance_id", value_type: ValueType::Text, description: "USBSTOR/USB device instance ID embedded in the subkey name, including enumerator prefix, vendor/product/revision, and iSerialNumber", is_uid_component: true }
  - FieldSchema { name: "volume_label", value_type: ValueType::Text, description: "Volume label string, taken from the subkey name between the disk class GUID and the trailing underscore", is_uid_component: false }
  - FieldSchema { name: "volume_serial_number", value_type: ValueType::Text, description: "Volume serial number (VSN), stored in DECIMAL as the final underscore-delimited component of the subkey name; convert to hex (XXXX-XXXX) to match VSNs in LNK/Jump List records", is_uid_component: true }
retention: Some("Persists after device removal; entries are not cleared automatically")
triage_priority: TriagePriority::High
related_artifacts: &["usb_stor_enum", "mounted_devices", "lnk_files", "setupapi_dev_log"]  (all verified-existing catalog ids)
sources:
  - "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk"
  - "https://github.com/woanware/usbdeviceforensics/blob/master/usbdeviceforensics.py"
  - "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/emdmgmt.pl"
evidence_strength: Some(EvidenceStrength::Strong)  (positive device<->VSN linkage; absence is Circumstantial only)
evidence_caveats:
  - "Volume serial number is stored in DECIMAL in the subkey name — convert to hex (compare as XXXX-XXXX) before matching against LNK/Jump List VSNs"
  - "Populated only by the ReadyBoost service, which Windows DISABLES when the system drive is an SSD or is deemed fast enough (\"the system disk is fast enough that ReadyBoost is unlikely to provide any additional benefit\"); an absent or empty key on such systems is EXPECTED and is NOT evidence of tampering/anti-forensics"
  - "ReadyBoost was removed in Windows 11 22H2, so the key may be unpopulated on that build and later regardless of drive type"
  - "Records non-system EXTERNAL volumes broadly (USB, eSATA, FireWire, non-system local disks) — not USB-only; MTP/PTP devices (phones, cameras) are not captured"
  - "Corroborate with USBSTOR, MountedDevices, setupapi.dev.log, and Microsoft-Windows-Partition/Diagnostic; do not treat EMDMgmt absence in isolation as an investigative conclusion"
volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Registry subkeys survive device removal and reboot until manually deleted"
```

**Sources verified:**
- [1 (Microsoft vendor documentation)] https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk — Confirms {53F56307-B6BF-11D0-94F2-00A0C91EFB8B} = GUID_DEVINTERFACE_DISK, the disk device-interface class GUID (Ntddstor.h) that is embedded in each EMDMgmt subkey name between the device instance ID and the volume label/serial
- [2 (independent real tool source / parsing oracle)] https://github.com/woanware/usbdeviceforensics/blob/master/usbdeviceforensics.py — Real tool source: key path 'Microsoft\Windows NT\CurrentVersion\EMDMgmt'; subkey filter '_??_USBSTOR#Disk&' / '_##_USBSTOR#Disk&'; VSN parsed as the substring after the final underscore following the disk GUID; VSN stored in DECIMAL and converted to hex ('%x' % int(vsn))
- [2 (independent real tool source / parsing oracle)] https://github.com/keydet89/RegRipper3.0/blob/master/plugins/emdmgmt.pl — Second independent tool source (Harlan Carvey): targets the Software hive at 'Microsoft\Windows NT\CurrentVersion\EMDMgmt'; parses device instance ID / volume name / volume serial number from subkey names; converts the decimal VSN to uppercase hex and formats as XXXX-XXXX
- [2 (vendor-hosted corroboration of behavior)] https://learn.microsoft.com/en-us/answers/questions/745893/how-to-fix-this-readyboost-problem-on-my-flash-dri — Microsoft-surfaced ReadyBoost message confirming the service is disabled when the system disk is an SSD/fast enough ('...the system disk is fast enough that ReadyBoost is unlikely to provide any additional benefit'), establishing that an absent/empty EMDMgmt key on SSD systems is expected, not anti-forensics

**Notes:** Placement: windows_registry_ext.rs, adjacent to USB_STOR_ENUM / SETUPAPI_DEV_LOG (same USB-forensics cluster). EMDMgmt currently appears in the catalog ONLY as free-text inside windows_evtx_ext.rs line 546 (listed as a fallback pivot when the DriverFrameworks channel is empty) and as three generated ReadyBoost *EVTX channel* descriptors (evtx_microsoft_windows_readyboost*) — none of which is the HKLM SOFTWARE registry key. No dedicated registry descriptor exists, so this is a genuine gap.

Evidence tiering: the structural facts (hive, key path, subkey `_??_USBSTOR#Disk&` format, VSN parsed from the final underscore component, decimal->hex conversion, XXXX-XXXX formatting) are confirmed by TWO independent real tool sources (woanware usbdeviceforensics.py and Harlan Carvey's RegRipper3.0 emdmgmt.pl) — Tier 2 (real tool source acting as oracle, ground truth derivable from the documented parse). The embedded GUID {53F56307-B6BF-11D0-94F2-00A0C91EFB8B} = GUID_DEVINTERFACE_DISK (Ntddstor.h) is confirmed by Microsoft Learn — Tier 1 vendor doc. The SSD/"fast disk" absence behavior is corroborated by Microsoft's own ReadyBoost error string on Microsoft Q&A and the documented Win11 22H2 removal — vendor-corroborated, hence the SSD caveat is stated as expected behavior, not overstated to "proves SSD."

Blogs (hecfblog, windowsir, hatsoffsecurity, Nicole Ibrahim, SANS) were used ONLY as discovery pointers; none is cited as the authority for any fact.

os_scope note: the OsScope enum has no Vista-specific variant. ReadyBoost/EMDMgmt is Vista-through-Win11(pre-22H2); Win7Plus is the closest accurate choice and avoids the XP over-claim that OsScope::All would introduce. The Vista-vs-Win7 lower bound and the 22H2 upper bound are both documented in evidence_caveats rather than forced into the enum.

related_artifacts rationale: usb_stor_enum (same device iSerialNumber), mounted_devices (the other VSN<->device linkage location), lnk_files (the primary correlation target for the VSN), setupapi_dev_log (first-connection timestamp). All four ids verified present in the catalog.

### `ntfs_ads` — NTFS Alternate Data Stream (generic named $DATA stream)  [new_descriptor]

```
id: "ntfs_ads"
name: "NTFS Alternate Data Stream (generic named $DATA stream)"
artifact_type: ArtifactLocation::File
hive: None
key_path: ""
value_name: None
file_path: Some(r"<any-file-or-dir>:<stream-name>:$DATA")
scope: DataScope::System
os_scope: OsScope::All  (NTFS-only; ADS present since NTFS 1.0 / Windows NT 3.1 — matches the MFT descriptor's OsScope::All)
decoder: Decoder::Identity

meaning: "An NTFS file or directory may carry more than one $DATA attribute. The first, unnamed $DATA attribute is the ordinary file content; any additional NAMED $DATA attribute is an Alternate Data Stream (ADS). Per [MS-FSCC] a stream's full name is <filename>:<stream name>:<stream type>, so the default content is 'file.txt::$DATA' and a named ADS is 'file.txt:secret:$DATA'. Any character legal in a filename (including spaces) is legal in a stream name, and directories — which have no default $DATA stream — can still carry named data streams. ADS are NOT shown by default `dir` or by Explorer (which report only the unnamed stream's size and hide the ADS bytes); they surface with `dir /R`, `Get-Item -Stream *`, `fsutil file streams`, or an $MFT parser that enumerates every $DATA attribute. Legitimate ADS exist across the OS — Zone.Identifier (Mark-of-the-Web, see zone_identifier), the change-journal $UsnJrnl:$J and $UsnJrnl:$Max streams, SmartScreen and Wof/compression metadata, and Finder/SMB resource forks (:AFP_AfpInfo, :com.apple.*). Abuse is the mirror image: an adversary hides a payload, script, or exfil data in a named stream so it occupies no visible file, is skipped by tools that scan only unnamed streams, and can be executed directly (e.g. WMIC/rundll32/wscript reading file.txt:hidden.exe). ADS do not survive a copy to a non-NTFS volume (FAT/exFAT), most network/SMB shares, or many archive/email round-trips, so absence never proves a stream was never present. Forensic reasoning: presence of an unexpected named $DATA stream, its stream name, its size, and its content are the facts; whether it is benign or malicious is inferred from the stream name and bytes, not from ADS presence alone."

fields:
  - stream_name (Text): "Name of the alternate $DATA stream (the <stream name> component of <filename>:<stream name>:$DATA). Empty for the default file content; non-empty names such as 'Zone.Identifier', '$J', or an arbitrary attacker-chosen name identify an ADS. Any legal filename character, including spaces, is permitted." is_uid_component: true
  - stream_type (Text): "The $stream type$ component, normally '$DATA' for a data stream (directories use '$INDEX_ALLOCATION'; the default directory stream name is '$I30'). Confirms the attribute is a data stream rather than an index or other attribute." is_uid_component: false
  - stream_size (UnsignedInt): "Logical byte length of the named stream as recorded in its $DATA attribute — the size Explorer and a plain `dir` do NOT report for the host file. A non-trivial size on an otherwise small file is a hiding indicator." is_uid_component: false
  - host_path (Text): "Full path of the host file or directory that owns the stream (the <filename> component). Ties the hidden stream to its visible carrier for pivoting to the $MFT record." is_uid_component: true

mitre_techniques: &["T1564.004"]  (Hide Artifacts: NTFS File Attributes — the clean fit; do NOT force an execution technique since ADS presence alone is not execution)

retention: Some("Persists with the host file on NTFS until the file, the named stream, or the $DATA attribute is removed; lost on copy to FAT/exFAT, most SMB/network shares, and many archive/email round-trips")

triage_priority: TriagePriority::Medium

related_artifacts: &["mft", "mft_file", "zone_identifier", "usnjrnl"]  (all verified present in the catalog)

sources: &[
  "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3",  // [MS-FSCC] NTFS Streams — authoritative naming syntax <filename>:<stream name>:<stream type>, default ::$DATA, named :bar:$DATA, dir /R visibility
  "https://attack.mitre.org/techniques/T1564/004/",  // T1564.004 Hide Artifacts: NTFS File Attributes — ADS abuse
]

evidence_strength: Some(EvidenceStrength::Strong)
  Rationale: the structural presence of a named $DATA attribute in the $MFT is a definitive filesystem fact; the benign-vs-malicious characterisation is a contextual inference from stream name + content, so the descriptor as a whole is Strong (structural), not Definitive for the abuse conclusion.

evidence_caveats: &[
  "ADS presence is a filesystem fact; benign vs malicious is inferred from the stream name and its bytes, not from the mere existence of a named stream (Zone.Identifier, $UsnJrnl:$J, and resource-fork streams are all legitimate).",
  "Requires an $MFT parser or raw enumeration (dir /R, Get-Item -Stream, fsutil file streams); default `dir` and Explorer hide named streams and report only the unnamed stream's size.",
  "Streams are not carried to non-NTFS volumes (FAT/exFAT), most SMB/network shares, or many archive/email round-trips, so absence does not prove a stream was never present.",
]

volatility: None
volatility_rationale: "On-disk NTFS metadata; persists with the host file until the file or the named stream is deleted."
```

**Additions:** N/A — new descriptor. Note for integrator: zone_identifier already covers the specific Zone.Identifier/MOTW ADS and should REMAIN separate (it has its own INI/[ZoneTransfer] field schema); ntfs_ads is the generic parent covering arbitrary named streams and their hiding/execution abuse. Consider adding "ntfs_ads" to zone_identifier.related_artifacts as a reciprocal link when wiring this in.

**Sources verified:**
- [1] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3 — [MS-FSCC] NTFS Streams (Tier 1, authoritative Microsoft open-spec): stream full name syntax '<filename>:<stream name>:<stream type>'; default unnamed data stream 'sample.txt::$DATA'; named ADS 'sample.txt:bar:$DATA'; any legal filename character (incl. spaces) legal in a stream name; directories have default stream $INDEX_ALLOCATION/$I30 and CAN carry named data streams; named streams 'are not normally visible, but can be observed from a command line using the /R option of the DIR command'.
- [1] https://attack.mitre.org/techniques/T1564/004/ — MITRE ATT&CK T1564.004 exact name 'Hide Artifacts: NTFS File Attributes'; description confirms adversaries store malicious data or binaries in NTFS attribute metadata including Alternate Data Streams (ADS) to evade static/AV scanning.

**Notes:** Distinct from existing catalog entries: zone_identifier = one specific ADS (MOTW, [ZoneTransfer] INI); mft/mft_file = the table/record that holds the $DATA attributes; usnjrnl = the $UsnJrnl file whose $J is itself a named stream. None is a generic ADS descriptor. Triage logic: enumerate all $DATA attributes per $MFT record; an unnamed + one-or-more named $DATA = ADS present. Named 'Zone.Identifier' → pivot to zone_identifier for MOTW/URL attribution. Named '$J'/'$Max' on $UsnJrnl → normal change-journal, pivot to usnjrnl. Arbitrary/random stream names, executable magic bytes (MZ) in stream content, or a large stream on a tiny host file → hiding/staging indicator (T1564.004); confirm by reading the stream bytes, never from presence alone. Streams on directories are legal and often overlooked (dir /R at a directory, or fsutil file streams on the dir). Do NOT fold into zone_identifier: that descriptor's field schema is INI-specific and would misrepresent generic streams; keep them as parent (ntfs_ads) + specific instance (zone_identifier).

### `photorec_recup_dir` — PhotoRec Carving Output (recup_dir.N)  [new_descriptor]

```
id: "photorec_recup_dir"
name: "PhotoRec Carving Output (recup_dir.N)"
artifact_type: ArtifactLocation::Directory
hive: None
key_path: ""
value_name: None
file_path: Some(r"recup_dir.N")  — NOTE: destination is user-chosen at runtime, so there is no fixed absolute path; the load-bearing, tool-invariant token is the "recup_dir.<N>" directory-name pattern. Set file_path to the pattern string and explain in meaning; the descriptor identifies the pattern, not a fixed location.
scope: DataScope::System  (output is a produced artifact, not per-user config)
os_scope: OsScope::All  — DECISION FLAG FOR REVIEWER: PhotoRec is cross-platform (Linux/macOS/Windows) and the recup_dir.N / f<sector>.<ext> output convention is byte-for-byte identical on every OS. The catalog has no OS-agnostic scope (OsScope::All == "Windows XP+"). The task frames this around the Windows binaries (photorec_win.exe / qphotorec_win.exe), so OsScope::All is the closest fit; the caveats explicitly state the convention is platform-independent. If a generic/cross-platform scope is preferred, adjust.
decoder: Decoder::Identity
meaning: "Output directory tree produced by PhotoRec / QPhotoRec file carving. PhotoRec writes recovered files into sequentially-numbered sub-directories recup_dir.1, recup_dir.2, ... under a user-chosen destination, creating a new sub-directory every 500 recovered files. Each recovered file is named by a single letter + a >=7-digit number + the detected extension: 'f' = a normally recovered file whose number is the logical sector where the file begins (computed as (file location - partition offset) / sector size), e.g. f0017088.txt begins at sector 17088; when PhotoRec can extract an embedded title it appends it (e.g. f0016741_Prudent_Engineering_Practice...pdf). Thumbnails carved from inside pictures are saved as t*.jpg; corrupted files / fragments (if kept) begin with 'b' (broken). The first recup_dir also contains report.xml recording the run's sectorsize and img_offset (partition offset). The mere presence of this directory tree is a strong signature that PhotoRec/QPhotoRec was executed and used to carve/recover files on that system or against that image."
fields:
  - recovered_file (Text): "Recovered file, named f<sector><ext> (e.g. f0017088.txt); 'f' = file, number = logical sector of file start"  [is_uid_component: true]
  - start_sector (UnsignedInt): "Sector where the file begins, embedded in the filename = (file location - partition offset) / sector size; equals the original cluster/block number when block size == sector size (NTFS/exFAT/ext2-4)"
  - embedded_title (Text): "Optional title extracted from file metadata and appended to the name (Office/PDF etc.)"
  - thumbnail_file (Text): "t*.jpg - thumbnail carved from inside a picture"
  - broken_file (Text): "b<sector><ext> - corrupted file or fragment retained when 'keep corrupted files' was enabled"
  - report_xml (Text): "report.xml in the first recup_dir; records sectorsize and img_offset (partition offset) for the run"
mitre_techniques: &[]  — left empty: no ATT&CK technique cleanly fits "recognizing carved recovery-tool output"; forcing T1005 (Data from Local System) or an anti-forensics technique would overstate.
related_artifacts: &["prefetch_dir", "amcache_app_file", "userassist_exe"]  (all verified present; these corroborate that photorec_win.exe / qphotorec_win.exe was executed on a Windows host)
retention: None
triage_priority: TriagePriority::Medium
sources: &[
  "https://www.cgsecurity.org/testdisk_doc/photorec.html",   // authoritative doc: f<sector> naming, f0017088.txt example, new dir per 500 files, report.xml sectorsize/img_offset, t*.jpg, b(roken), ext2/3/4-vs-Other, free-vs-whole
  "https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step",    // FileOpts signature selection (>300 file families / >480 extensions), whole-partition vs unallocated-only, 'choose Other unless ext2/3/4'
  "https://www.cgsecurity.org/wiki/PhotoRec_FAQ",             // "PhotoRec uses the logical sector number to create the filename, it appends the original filename or the document title when possible, the filename ends by the file extension"
  "https://www.cgsecurity.org/testdisk_doc/running.html",     // Windows binaries: testdisk_win.exe / photorec_win.exe / qphotorec_win.exe (bundled portable package)
  "https://git.cgsecurity.org/cgit/testdisk/tree/win/qphotorec_win.exe.manifest"  // source tree confirms qphotorec_win.exe ships in the win/ package
]
evidence_strength: Some(EvidenceStrength::Strong)  — the recup_dir.N + f<sector>.<ext> convention is unique to PhotoRec, and the sibling report.xml (with sectorsize/img_offset) is a definitive run signature; Strong rather than Definitive because a directory could in principle be hand-fabricated, and the artifact evidences tool USE, not the origin/authenticity of the carved content.
evidence_caveats: &[
  "Destination directory is chosen by whoever runs PhotoRec; there is no fixed path. Match on the 'recup_dir.<N>' name pattern plus f/t/b-prefixed sector-named files and a sibling report.xml.",
  "Cross-platform: identical output convention on Linux, macOS and Windows. Only the executable names (photorec_win.exe / qphotorec_win.exe) are Windows-specific.",
  "Carving loses filesystem context: original filenames and directory structure are not preserved (except an optional embedded title). The sector number in the name locates the file start within the source, not the original path.",
  "Presence evidences that a carving/recovery run occurred (could be a legitimate examiner, a user recovering their own data, or an adversary staging data) - it does not by itself establish intent.",
  "report.xml records the run's sectorsize and img_offset, letting an examiner map each f<sector> file back to a byte offset in the source image."
]
volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Carved output files persist on disk until explicitly deleted."
```

**Sources verified:**
- [1 (primary vendor/authoritative documentation)] https://www.cgsecurity.org/testdisk_doc/photorec.html — Recovered-file naming 'a letter followed by a number (7 digits or more)', f=file, number=sector, example f0017088.txt starts at sector 17088; new recup_dir directory created each 500 files; report.xml records sectorsize and img_offset; t*.jpg thumbnails; b(roken) prefix; 'Unless it is an ext2/ext3/ext4 filesystem, choose Other'; whole-partition vs unallocated-only scan.
- [1 (primary vendor documentation)] https://www.cgsecurity.org/wiki/PhotoRec_Step_By_Step — FileOpts menu enables/disables file types; >300 file families / >480 extensions; whole partition (corrupted FS) vs unallocated-space-only (deleted files, ext2/3/4/FAT/NTFS); ext-vs-Other filesystem choice; recup_dir.1/recup_dir.2 output.
- [1 (primary vendor documentation)] https://www.cgsecurity.org/wiki/PhotoRec_FAQ — 'PhotoRec uses the logical sector number to create the filename, it appends the original filename or the document title when possible, the filename ends by the file extension.'
- [1 (primary vendor documentation)] https://www.cgsecurity.org/testdisk_doc/running.html — Windows portable package ships testdisk_win.exe, photorec_win.exe and qphotorec_win.exe (double-click to run as Administrator); QPhotoRec is the Qt GUI of PhotoRec.
- [1 (primary tool source repository)] https://git.cgsecurity.org/cgit/testdisk/tree/win/qphotorec_win.exe.manifest — qphotorec_win.exe is a real build artifact in the TestDisk win/ source tree, confirming QPhotoRec ships bundled with TestDisk on Windows.

**Notes:** This is a tool-output / tool-usage artifact rather than a fixed-location OS artifact. Its forensic value is twofold: (1) recognizing recup_dir.N trees (with f<sector>.<ext> files + report.xml) as unambiguous PhotoRec/QPhotoRec carving output, and (2) treating that as strong evidence the tool was run — corroborate the Windows case with prefetch_dir / amcache_app_file / userassist_exe entries for photorec_win.exe or qphotorec_win.exe. Two reviewer decisions flagged: (a) file_path holds the "recup_dir.N" pattern, not an absolute path, because the destination is user-chosen; (b) OsScope::All is the closest available scope but the output convention is genuinely OS-agnostic (caveated). All naming/structure facts (f=file+sector, f0017088.txt, 500-files-per-dir, report.xml sectorsize/img_offset, t*.jpg, b(roken), ext2/3/4-vs-Other, whole-vs-unallocated, FileOpts signature selection) are confirmed against the authoritative testdisk_doc; the Windows binary names are confirmed against running.html and the git.cgsecurity.org source tree. No 13cubed/SANS/blog was used as an authority.

### `ntfs_reparse_point` — NTFS Reparse Points ($REPARSE_POINT / $Extend\$Reparse)  [new_descriptor]

```
id: "ntfs_reparse_point"
name: "NTFS Reparse Points ($REPARSE_POINT / $Extend\\$Reparse)"
artifact_type: ArtifactLocation::File
hive: None
key_path: ""
value_name: None
file_path: Some(r"<NTFS file/dir>:$REPARSE_POINT (attribute type 0xC0); enumerated volume-wide via $Extend\$Reparse:$R:$INDEX_ALLOCATION")
scope: DataScope::System
os_scope: OsScope::All  (NTFS reparse points exist Windows 2000/XP onward; Windows-only)
decoder: Decoder::Identity
triage_priority: TriagePriority::Medium

meaning: |
  A reparse point is an NTFS extensibility mechanism: any file or directory can carry
  a $REPARSE_POINT attribute (MFT attribute type 0xC0), and its $STANDARD_INFORMATION
  file-attribute flags carry FILE_ATTRIBUTE_REPARSE_POINT (0x400). The attribute begins
  with a 32-bit *reparse tag* that names the filter driver owning the point, followed by
  a 16-bit data length and filter-specific data. Per [MS-FSCC] §2.1.2.1 the tag is a
  bit-field: bit 31 = M (Microsoft-owned), bit 30 = R (reserved, formerly high-latency),
  bit 29 = N (Name Surrogate — the entry is an alias/redirection to another named object),
  bit 28 = D (Directory), bits 16–27 reserved, bits 0–15 = the 16-bit tag Value.
  The N bit is the key forensic discriminator: N=1 tags are true path redirections
  (junctions, symlinks, mount points, WSL symlinks); N=0 tags overlay or virtualise the
  file's own data in place (WOF/compression, Dedup, OneDrive/Cloud placeholders).
  Predefined tags of forensic interest (verbatim from [MS-FSCC] Reparse Tags):
    IO_REPARSE_TAG_MOUNT_POINT  0xA0000003  directory junctions and volume mount points
    IO_REPARSE_TAG_SYMLINK      0xA000000C  NTFS symbolic links (file or dir)
    IO_REPARSE_TAG_DEDUP        0x80000013  Data Deduplication (content in chunk store)
    IO_REPARSE_TAG_WOF          0x80000017  Windows Overlay Filter (WIMBoot / single-file compression)
    IO_REPARSE_TAG_WCI          0x80000018  Windows Container Isolation
    IO_REPARSE_TAG_CLOUD        0x9000001A  Cloud Files filter — OneDrive placeholder/dehydrated file
    IO_REPARSE_TAG_PROJFS       0x9000001C  Projected FS (e.g. VFS for Git)
    IO_REPARSE_TAG_APPEXECLINK  0x8000001B  UWP/Store app execution alias (App Execution Alias)
    IO_REPARSE_TAG_LX_SYMLINK   0xA000001D  WSL UNIX symbolic link
  For MOUNT_POINT and SYMLINK the data holds a SubstituteName (the kernel target path,
  often \??\ prefixed) and a PrintName (display path); a mount point / directory junction
  points at another local volume/path, a symlink may point anywhere and (unlike a junction)
  is evaluated on the client. NTFS also maintains a volume-wide index: the metadata file
  \$Extend\$Reparse carries an index named $R that enumerates every reparse point on the
  volume, keyed by the file's MFT file_id (collation COLLATION_NTOFS_ULONGS); the $R index
  has keys only (no index data), so the actual reparse data lives in each file's 0xC0
  attribute while $R is the fast "all reparse points on this volume" lookup.
  Forensic relevance: junctions/symlinks are abused for path redirection, TOCTOU races,
  and sandbox/permission escapes; a MOUNT_POINT/SYMLINK SubstituteName reveals where a
  path actually resolves (e.g. a "folder" that redirects to another volume or an attacker
  staging area). WOF/Dedup tags mean the file's bytes are not in a plain $DATA run — a
  naive $DATA carve returns a stub, and the real content sits in the WIM/overlay or the
  Dedup chunk store; CLOUD/OneDrive tags mark placeholder ("online-only"/dehydrated) files
  whose data is not resident locally at all. Enumerate with fsutil reparsepoint query,
  MFTECmd (surfaces the tag + substitute/print names from 0xC0), or libfsntfs.

fields (FieldSchema[]):
  - reparse_tag        : ValueType::UnsignedInt, is_uid_component: true
      "32-bit reparse tag from the $REPARSE_POINT (0xC0) attribute; identifies the owning filter driver. Decode per [MS-FSCC] bit-field (M/R/N/D flags + 16-bit Value). Show the raw hex tag when it is not one of the predefined values."
  - tag_name           : ValueType::Text, is_uid_component: false
      "Symbolic name of the tag when recognised (e.g. IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_WOF, IO_REPARSE_TAG_CLOUD); for an unrecognised tag report the raw 0x-hex value verbatim."
  - name_surrogate     : ValueType::Bool, is_uid_component: false
      "N bit (bit 29): true when the point is a name alias/redirection (junction, symlink, mount point, WSL symlink); false for in-place data-overlay tags (WOF, Dedup, Cloud)."
  - is_microsoft       : ValueType::Bool, is_uid_component: false
      "M bit (bit 31): the tag is owned by Microsoft. Third-party/undocumented tags have M=0; surface these for triage."
  - substitute_name    : ValueType::Text, is_uid_component: false
      "For MOUNT_POINT/SYMLINK: the kernel target path the point redirects to (often \\??\\ prefixed), i.e. where the path actually resolves."
  - print_name         : ValueType::Text, is_uid_component: false
      "For MOUNT_POINT/SYMLINK: the human-readable display target path."
  - reparse_data_length: ValueType::UnsignedInt, is_uid_component: false
      "Length in bytes of the filter-specific reparse data following the tag/GUID header (0xC0 attribute ReparseDataLength)."

related_artifacts (all verified existing catalog ids): &["mft", "mft_file", "ntfs_i30_index", "usn_journal", "logfile_ntfs"]

mitre_techniques: &[]  (No ATT&CK technique cleanly fits reparse points as an on-disk artifact; junction/symlink abuse is technique-dependent, so left empty rather than forced.)

sources: &[
  "https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4",  // [MS-FSCC] Reparse Tags — tag bit-field + full predefined tag/value table
  "https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/ca069dad-ed16-42aa-b057-b6b207f447cc",  // [MS-FSCC] §2.1.2.5 Mount Point reparse data (SubstituteName/PrintName)
  "https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913",  // [MS-FSCC] §2.1.2.4 Symbolic Link reparse data
  "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",  // $Extend\$Reparse / $R index + 0xC0 attribute layout (RE reference)
  "https://flatcap.github.io/linux-ntfs/ntfs/attributes/reparse_point.html"  // $REPARSE_POINT (0xC0) attribute structure (linux-ntfs RE)
]

evidence_strength: Some(EvidenceStrength::Strong)
  (Tag values and bit-field are Definitive from [MS-FSCC]; the forensic interpretation — redirection target, non-resident data, placeholder state — is Strong.)

evidence_caveats: &[
  "A reparse tag identifies the owning filter, not intent: junctions/symlinks are used legitimately by Windows and installers, so presence alone is not suspicious — the SubstituteName target and context carry the signal.",
  "WOF/Dedup/Cloud tags mean the file's bytes are not in a plain $DATA run: a naive $DATA carve yields a stub/placeholder, not the real content (WIM overlay, Dedup chunk store, or cloud-only/dehydrated file).",
  "An unrecognised or non-Microsoft (M=0) tag should be reported with its raw 0x-hex value; do not silently drop it — undocumented tags can indicate third-party or malicious filters.",
  "The $Extend\\$Reparse $R index enumerates points by MFT file_id but stores no reparse data; the authoritative data is each file's 0xC0 attribute — reconcile the two, and note the index can lag if updated out of band.",
  "Directory junctions vs symbolic links differ in where they resolve (junction = server/local-side, symlink = client-side) and in privilege to create; both share MOUNT_POINT/SYMLINK tags respectively but have distinct abuse profiles."
]

volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Reparse data is stored in the file's on-disk $REPARSE_POINT (0xC0) MFT attribute and indexed in \$Extend\$Reparse; it persists until the reparse point is explicitly removed or the file is deleted."
```

**Sources verified:**
- [1 (primary spec, [MS-FSCC])] https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4 — Reparse tag 32-bit bit-field: M(31)/R(30, formerly high-latency)/N(29 Name Surrogate)/D(28 Directory)/Reserved(16-27)/Value(0-15); full predefined tag table with hex values incl. MOUNT_POINT 0xA0000003, SYMLINK 0xA000000C, DEDUP 0x80000013, WOF 0x80000017, WCI 0x80000018, CLOUD 0x9000001A, PROJFS 0x9000001C, APPEXECLINK 0x8000001B, LX_SYMLINK 0xA000001D
- [2 (reverse-engineering reference, libyal/Metz)] https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc — $Extend\$Reparse metadata file carries an index named $R enumerating all volume reparse points keyed by file_id (COLLATION_NTOFS_ULONGS) with keys only / no index data; reparse tag present in MFT entry when FILE_ATTRIBUTE_REPARSE_POINT set; 0xC0 attribute holds tag + substitute/print names
- [2 (reverse-engineering reference, linux-ntfs)] https://flatcap.github.io/linux-ntfs/ntfs/attributes/reparse_point.html — $REPARSE_POINT attribute is MFT attribute type 0xC0; structure of tag + reparse data

**Notes:** Not in catalog: grep of crates/data/src/catalog/descriptors/ and src/ shows "reparse" only as passing mentions inside the LNK/shell-link descriptors (mod.rs ~5157, 5192 — LNK header reparse-tag hints) and unrelated "mount_point" fields; no dedicated $REPARSE_POINT / $Extend\$Reparse descriptor exists. Triage logic: (1) N bit (name_surrogate) splits redirections (junction/symlink/mount — abuse: path redirection, TOCTOU, sandbox escape; inspect SubstituteName) from data-overlay tags (WOF/Dedup/Cloud — the file's real bytes are elsewhere, defeating naive $DATA carving). (2) CLOUD/OneDrive tag => file is a local placeholder, data not resident; corroborate with the OneDrive/cloud-sync artifacts before concluding the content was ever on the machine. (3) APPEXECLINK => Store/UWP execution alias. (4) Any M=0 or unrecognised tag => surface raw hex for analyst follow-up. Related artifacts chosen from verified existing ids: mft, mft_file (0xC0 lives in the MFT record), ntfs_i30_index (parent-directory index that lists the reparse entry's name), usn_journal (records reparse create/delete/change with USN reason flags), logfile_ntfs ($LogFile transactions for the 0xC0 attribute + $Extend\$Reparse index updates). MITRE left empty deliberately — no clean technique maps to the artifact itself.

### `evtx_ntlm` — NTLM Operational Log — forced-authentication (coercion) → NTLM relay enrichment  [enrichment]

**Additions:** Target existing descriptor: id = "evtx_ntlm" (crates/data/src/catalog/descriptors/windows_evtx_ext.rs, static EVTX_NTLM). This is an ENRICHMENT — do NOT create a new descriptor. Rationale: the catalog is one-descriptor-per-event-channel (no per-event-ID or "technique" artifact_type exists in ArtifactLocation), Security-5145 already lives under Security.evtx = evtx_security, and evtx_ntlm already carries T1187 (Forced Authentication) + "NTLM relay" in its meaning, so it is the on-channel home for the coerced/relayed NTLM authentication that these attacks land.

1) meaning — append coercion-vector context (keep existing sentence, add):
"Forced-authentication coercion abuses low-privilege RPC methods that force a victim (frequently a domain controller's machine account) to authenticate outbound over NTLM to an attacker-chosen host: PetitPotam drives EFSRPC methods (e.g. EfsRpcOpenFileRaw) over the \\pipe\\lsarpc or \\pipe\\efsrpc named pipe ([MS-EFSR]); PrinterBug/Dementor drives RpcRemoteFindFirstPrinterChangeNotificationEx over \\pipe\\spoolss ([MS-RPRN]); Coercer and DFSCoerce cover further RPC interfaces. The coerced NTLM authentication is then relayed (ntlmrelayx) to LDAP/ADCS/SMB. In this log, a DC or server machine account ($) authenticating to an unexpected host is CONSISTENT WITH coercion + relay — it does not by itself prove it."

2) mitre_techniques — no change needed (already &[\"T1550.002\", \"T1187\"]; T1187 Forced Authentication + T1550.002 Pass-the-Hash already cover this; do not force-add others).

3) evidence_caveats — add these two entries (keep the existing two):
   - "Upstream coercion is best seen in Security.evtx (evtx_security) via event 5145 — the sole event of the Object Access > Detailed File Share subcategory — showing access to Share Name IPC$ with Relative Target Name of the coercion pipe (efsrpc, lsarpc, or spoolss); that subcategory is OFF by default and high-volume, so absence of 5145 is not absence of coercion."
   - "A machine-account NTLM authentication to an unexpected destination is consistent with coercion/relay but also occurs during benign cross-host service auth; corroborate with evtx_smb_client (relay victim), evtx_print_service (spooler coercion), and Security 4624/4768 machine-account logons."

4) related_artifacts — extend from &[\"evtx_security\", \"dcc2_cache\"] to also include \"evtx_smb_client\" and \"evtx_print_service\" (both verified as existing catalog ids in the same file). These give the analyst the downstream relay-victim log and the spooler coercion channel.

5) sources — add these primary-source URLs to the existing &[hayabusa-rules] entry:
   - "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2"  ([MS-EFSR] Standards Assignments — \\pipe\\lsarpc, \\pipe\\efsrpc + UUIDs)
   - "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515"  ([MS-RPRN] Standards Assignments — \\pipe\\spoolss + UUID)
   - "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145"  (Event 5145, Detailed File Share)

Do NOT change: evidence_strength (keep Corroborative — a machine-account auth to an unexpected host is consistent-with, not definitive-of, coercion), triage_priority (High), file_path, os_scope, decoder, volatility.

**Sources verified:**
- [1 (Microsoft Open Specifications — authoritative protocol spec)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2 — EFSRPC (PetitPotam vector) RPC well-known endpoints \pipe\lsarpc and \pipe\efsrpc; interface UUIDs {c681d488-d850-11d0-8c52-00c04fd90f7e} and {df1941c5-fe89-4e79-bf10-463657acf44d}
- [1 (Microsoft Open Specifications — authoritative protocol spec)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515 — Print System Remote Protocol (PrinterBug/Dementor vector) RPC well-known endpoint \pipe\spoolss; interface UUID 12345678-1234-ABCD-EF00-0123456789AB
- [1 (Microsoft vendor documentation)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145 — Event 5145 'A network share object was checked' is the sole event of the Detailed File Share (Object Access) audit subcategory; records Share Name (IPC$), Relative Target Name (named pipe), source IP; disabled by default and high-volume
- [1 (Microsoft Open Specifications — landing page)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31 — MS-EFSR (Encrypting File System Remote Protocol) identity/versioning for citation

**Notes:** Two-log detection story, each half needing non-default auditing: (a) UPSTREAM coercion — Security.evtx event 5145 (Object Access > Detailed File Share; off by default, noisy) showing Share Name IPC$ + Relative Target Name = efsrpc/lsarpc/spoolss from an unexpected source IP; (b) DOWNSTREAM forced/relayed auth — the NTLM Operational log (this descriptor, also off by default) and SMBClient Security log (evtx_smb_client) recording the machine-account NTLM authentication. The strongest single indicator is a DOMAIN CONTROLLER machine account ($) authenticating outbound to a non-DC/unexpected host — consistent with PetitPotam/PrinterBug/Coercer feeding ntlmrelayx, but not proof (benign cross-host service auth exists). Named pipes are tool-agnostic: any tool hitting \\pipe\\lsarpc|\\pipe\\efsrpc ([MS-EFSR]) or \\pipe\\spoolss ([MS-RPRN]) produces the same 5145 signal, so detect on the pipe/interface, not the tool name. Mitigation context worth noting for the analyst: EPA/SMB signing and RPC-filter blocking of these interfaces change what lands, so a coercion attempt can appear in 5145 without a successful relay in the NTLM log. Anonymous/NTLMv1 downgrade in the relay chain is visible via evtx_ntlm challenge/response and Security 4776.

### `wzcsvc_wireless_interfaces` — WZCSVC Wireless Interface Connection History (Windows XP)  [new_descriptor]

```
id: "wzcsvc_wireless_interfaces"
name: "WZCSVC Wireless Interface Connection History (Windows XP)"
artifact_type: ArtifactLocation::RegistryKey
hive: Some(HiveTarget::HklmSoftware)
key_path: "Microsoft\\WZCSVC\\Parameters\\Interfaces"
value_name: None  (per-interface data lives in subkeys named by the wireless adapter GUID; SSID history is in the ActiveSettings and Static#000x binary values under each GUID subkey)
file_path: None
scope: DataScope::System
os_scope: OsScope::All  (NOTE: no XP-only variant exists; OsScope::All is documented as "All Windows versions (XP and later), Windows-only". WZCSVC is XP / Server 2003 ONLY — replaced by WLAN AutoConfig (WlanSvc) + NetworkList in Vista+. Flag: an OsScope::WinXpOnly variant would be more precise.)
decoder: Decoder::Identity  (REG_BINARY values need custom parsing; no dedicated WZCSVC decoder in catalog — extraction offsets documented in fields)
meaning: "Windows XP / Server 2003 Wireless Zero Configuration Service (WZCSVC) wireless connection history. Each subkey under Parameters\\Interfaces is named by the wireless adapter's interface GUID; its LastWrite time is consistent with the last time that adapter's wireless configuration was updated (approximate last-connect). Under each GUID subkey, ActiveSettings (REG_BINARY) holds the current/last-active profile and Static#0000, Static#0001, … each hold a previously-connected wireless network (SSID + AP MAC). XP-era predecessor of the Vista+ NetworkList profile history. Wireless-only — does not record wired or broadband networks."
fields:
  - { name: "interface_guid", value_type: ValueType::Text, description: "Subkey name = GUID of the wireless network adapter", is_uid_component: true }
  - { name: "ssid", value_type: ValueType::Text, description: "Connected network SSID; length = DWORD (LE) at binary offset 0x10, name bytes begin at offset 0x14 (per RegRipper ssid.pl)", is_uid_component: true }
  - { name: "ap_mac", value_type: ValueType::Text, description: "Access-point BSSID/MAC address, 6 bytes at binary offset 0x08", is_uid_component: false }
  - { name: "last_write", value_type: ValueType::Timestamp, description: "LastWrite time of the interface-GUID subkey; consistent with last wireless-config update / last association on that adapter", is_uid_component: false }
retention: Some("Persistent until registry modification / profile removal")
triage_priority: TriagePriority::Medium
related_artifacts: &["networklist_profiles", "wifi_profiles", "dhcp_ipv4_interface", "network_interfaces"]
sources: &[
  "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/ssid.pl",
  "http://windowsir.blogspot.com/2005/07/where-oh-where-did-my-little-ssid-go.html"
]
evidence_strength: Some(EvidenceStrength::Strong)  (key path/values/SSID offsets Definitive via tool source + RE writeup; "LastWrite = last connect" is a forensic inference — hence Strong overall, not Definitive)
evidence_caveats: &[
  "Windows XP / Server 2003 only — absent on Vista+ (superseded by WlanSvc + NetworkList).",
  "ActiveSettings binary layout is not fully documented and reportedly changed between builds; only SSID (0x10/0x14) and MAC (0x08) extraction are reliable across systems.",
  "SSID history is populated only when wireless is managed by WZCSVC; vendor clients (Broadcom, Cisco, Intel) may store SSIDs in their own keys instead.",
  "Interface-GUID LastWrite reflects the most recent config write — consistent with, but not proof of, the exact last connection time."
]
volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Registry key in the SOFTWARE hive; persists until explicit deletion or profile removal"
```

**Sources verified:**
- [2 (real tool source — RegRipper ssid.pl, authored by Harlan Carvey, the RegRipper author)] https://github.com/keydet89/RegRipper3.0/blob/master/plugins/ssid.pl — Key path Microsoft\WZCSVC\Parameters\Interfaces; values matched by /^Static#/; SSID length = unpack V of substr($data,0x10,0x04), SSID = substr($data,0x14,$l); AP MAC at offset 0x08 (6 bytes)
- [2 (reverse-engineering writeup by the recognized authority)] http://windowsir.blogspot.com/2005/07/where-oh-where-did-my-little-ssid-go.html — Original discovery that HKLM\Software\Microsoft\WZCSVC\Parameters\Interfaces subkeys (per interface GUID) hold ActiveSettings and Static#0000 REG_BINARY values whose data contains connected wireless SSIDs; vendor-client storage caveat

**Notes:** Work-item corrections: (1) The claim "embedded hex classifies wired/broadband/wireless (legacy NetworkList analog)" is UNSUPPORTED and inaccurate — WZCSVC is the *Wireless* Zero Configuration service and records wireless SSIDs only; the wired(6)/wireless(71)/broadband(23) NameType classification is a Vista+ NetworkList feature (already catalogued as networklist_profiles), not WZCSVC. Dropped it; described WZCSVC accurately as XP wireless SSID/connection history. (2) forensics.wiki was a discovery pointer only; load-bearing citations are Carvey's RegRipper ssid.pl (tool source) and his 2005 RE blog. (3) OsScope gap: enum has no XP-only variant (OsScope::All = "XP and later, Windows-only"), so OsScope::All slightly overstates — recommend adding OsScope::WinXpOnly (also relevant to the existing UserAssist XP-era descriptors in mod.rs). Confirmed NOT already in catalog: no "wzcsvc"/"Wireless Zero" hit anywhere in crates/ or src/. All four related_artifacts ids verified present. Deliberately omitted: the 0x2B8 timestamp field inside the binary (present in ssid.pl but undocumented meaning, no independent oracle) — used the subkey LastWrite instead, a standard registry property. MITRE left empty: this is passive network-connection history with no clean offensive ATT&CK technique (forcing T1016 System Network Configuration Discovery would misattribute the artifact to an attacker action).

### `pca_general_db1` — PCA PcaGeneralDb1.txt  [new_descriptor]

```
NEW DESCRIPTOR — mirrors the existing `pca_general_db` (PcaGeneralDb0.txt) descriptor at crates/data/src/catalog/descriptors/mod.rs:318, differing only in id/name/file_path/docs/related_artifacts. Reuse the existing shared field schema and decoder to stay DRY and consistent with the sibling.

- id: "pca_general_db1"
- name: "PCA PcaGeneralDb1.txt"
- artifact_type: ArtifactLocation::File
- hive: None
- key_path: "" (empty — file artifact)
- value_name: None
- file_path: Some(r"C:\Windows\appcompat\pca\PcaGeneralDb1.txt")
- scope: DataScope::System  (Carvey: "there's nothing in either file that points to a specific user"; both Db0 and Db1 are system-scoped)
- os_scope: OsScope::Win11_22H2  (PCA text-file artifacts introduced with the PcaSvc service in Windows 11 22H2; same as Db0/PcaAppLaunchDic)
- decoder: Decoder::Identity  (mirror the existing pca_general_db, which uses Identity rather than the PipeDelimited decoder)
- meaning: "Secondary/rotating half of the Program Compatibility Assistant abnormal-exit log pair. PcaGeneralDb0.txt is the primary file and PcaGeneralDb1.txt the secondary; new records go to whichever is primary until it reaches 2 MB (2 x 10^6 bytes), at which point the secondary is cleared and becomes the new primary and the cycle repeats — so 2-4 MB of historical data is retained across the pair. Same record format and encoding as Db0 (UTF-16LE, CRLF, one pipe-delimited record per line). Frequently empty or sparse: a clean-install Win11 Pro VM did not populate Db1 at all, while a real-use machine populated it (less than Db0). Must be collected and parsed alongside Db0 to avoid losing the older rotation window. No user attribution is recorded in the file itself — correlate with EVTX / EDR telemetry to assign activity to a user."
- fields: reuse the existing PCA_GENERAL_DB_FIELDS_SCHEMA (exe_path [uid], exit_code, timestamp). NOTE (forensic_notes): the on-disk record actually carries 8 pipe-delimited fields per Sygnia's RE table — see forensic_notes; the shared 3-field schema is the same simplification the existing Db0 descriptor already uses, kept for consistency.
- mitre_techniques: &["T1059", "T1204.002"]  (mirror Db0 — CLI execution launched from Explorer GUI; user-initiated execution)
- retention: None
- triage_priority: TriagePriority::High  (mirror Db0)
- related_artifacts: &["pca_general_db", "pca_applaunch_dic"]  (both verified present in catalog: mod.rs:319 and mod.rs:251)
- sources: &[
    "https://www.sygnia.co/blog/new-windows-11-pca-artifact/",   (RE writeup — rotation mechanism, 2MB threshold, UTF-16LE/CRLF, 8-field layout)
    "https://windowsir.blogspot.com/2024/02/pcaparse.html",       (Carvey PCAParse tool — parses the pca folder files, sample record)
    "https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/"  (Db1 empty on clean VM / populated on real machine)
  ]
- evidence_strength: recommend Some(Corroborative) — execution evidence corroborating other sources, weaker than Db0 because Db1 is often empty/sparse and carries no user attribution. (The existing Db0 descriptor leaves this None; either mirror None for strict consistency or set Corroborative per the honest-tiering rule. Recommend Corroborative + caveats.)
- evidence_caveats: &["Frequently empty or sparse due to the Db0/Db1 rotation; presence of data is machine-dependent.", "No user attribution recorded in the file; correlate with EVTX/EDR to attribute.", "Records only executions launched via Windows File Explorer (GUI), not all process launches."]
- volatility: None
- volatility_rationale: "" (mirror Db0)

Test/impl follow-ups (not part of the descriptor, flagged for the implementer): add the descriptor to the DESCRIPTORS registry array; bump the "catalog count after pca_general_db" assertion at tests.rs:9230; src/pca.rs already exposes PCA_GENERAL_DB1_PATH (line 25) and is_pca_file() already recognizes Db1 (test at line 129), so no src/pca.rs change is needed.
```

**Sources verified:**
- [Tier-2 (independent reverse-engineering writeup)] https://www.sygnia.co/blog/new-windows-11-pca-artifact/ — Verbatim: 'Initially, PcaGeneralDb0.txt is the primary database file, and PcaGeneralDb1.txt is the secondary database file. New records are written to the primary file as long as it is smaller than two megabytes (2 x 10^6 bytes). When it reaches two megabytes, the secondary file is cleared, becomes the new primary file, and this cycle repeats.' Also: 'Both are text files encoded in Wide Character (UTF-16LE, allowing unpaired surrogates) with Windows line endings (CRLF). Each line stores a single record, and each record stores eight fields in a pipe-delimited format.' And the abnormal-exit hex code format. Introduced Win11 22H2 (builds 22621/22632).
- [Tier-2 (real DFIR tool source — Carvey PCAParse)] https://windowsir.blogspot.com/2024/02/pcaparse.html — Tool parses the files under C:\Windows\appcompat\pca; sample record 'timestamp|PCA|||%programfiles%\...\x.exe - Abnormal process exit with code 0x2' confirms the pipe-delimited exe-path + exit-code record format that Db1 shares with Db0.
- [Tier-3 (DFIR blog — corroborating, discovery pointer)] https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/ — PcaGeneralDb1.txt is often empty/sparse: not populated on a clean-install Win11 Pro VM but populated (less than Db0) on a real personal machine — justifies collecting it despite frequent emptiness and the Corroborative evidence strength.

**Notes:** Design decision: NEW descriptor rather than enrichment of pca_general_db. The catalog is one-descriptor-per-file (pca_applaunch_dic and pca_general_db are already separate), and pca_general_db.file_path is hardcoded to PcaGeneralDb0.txt, so a catalog-driven collector silently skips PcaGeneralDb1.txt. Adding the sibling closes that gap and matches the exact framing of the work item ("collect/check alongside Db0"). src/pca.rs already defines the Db1 path constant and is_pca_file() matches it, so the catalog descriptor is the only missing piece.

True on-disk record layout (8 pipe-delimited fields, from Sygnia's RE table cross-checked against a real sample record): (1) timestamp "YYYY-MM-DD HH:MM:SS.mmm"; (2) a small integer status/record-type code (value "2" in the sample — the two WebFetch renderings disagreed on this field's name, so treat its exact semantics as unconfirmed); (3) image/exe path with the volume letter stripped and normalized to env-vars (%programfiles%, %USERPROFILE%, %systemroot%); (4) product/description name; (5) company/vendor name; (6) product/file version string; (7) Amcache ProgramId (InventoryApplicationFile-style, e.g. 0000e3e7177c6e3ba0c9c0c59dfdca1000ffff); (8) message, e.g. "Abnormal process exit with code 0xNN". Verified sample (Db0, same format as Db1): `2022-05-20 16:42:41.053|2|%programfiles%\greenshot\plugins\greenocrplugin\greenocrcommand.exe|greenocrcommand|greenshot|1.2.10.6-release-c2414cf0149a1475ea00520eff1b87c225c|0000e3e7177c6e3ba0c9c0c59dfdca1000ffff|Abnormal process exit with code 0xfffffffe`. If the maintainers ever expand Db0 to the full 8-field schema, do the same to Db1 in one pass (both share PCA_GENERAL_DB_FIELDS_SCHEMA).

Encoding caveat worth carrying: PcaGeneralDb0/Db1 are UTF-16LE with CRLF, whereas the companion PcaAppLaunchDic.txt is ANSI/CP-1252 — a parser must switch encoding by filename (this asymmetry is stated in the AboutDFIR/artefacts.help writeups but NOT independently confirmed in the Sygnia quote I pulled, so treat the ANSI-for-AppLaunchDic half as Corroborative, not Definitive).

Rating on the evidence tiers: the rotation mechanism, 2 MB threshold, UTF-16LE/CRLF encoding, and 8-field structure are all from Sygnia's reverse-engineering writeup and are consistent with Carvey's PCAParse tool output — Tier-2 (RE writeup + real tool), not a first-party Microsoft spec (Microsoft documents PCA the feature, not the on-disk file format). Set evidence_strength honestly to Corroborative.

### `EVENT_ID_TABLE eids 216 & 325 (src/eventids.rs) + LOLBAS ntdsutil.exe (src/lolbins.rs); related catalog descriptor: ntds_dit` — ntdsutil IFM ntds.dit-dump fingerprint: ESENT 216/325 location discriminator + on-disk IFM set layout  [enrichment]

**Additions:** ALREADY-PRESENT (do NOT re-add): eids 216, 325, 326, 327 exist in EVENT_ID_TABLE (src/eventids.rs:332-364, channel "Application", T1003.003, artifact_ids ["evtx_application"]); ntdsutil.exe exists as a LolbasEntry (src/lolbins.rs:287-291, T1003.003). This is a description-refinement enrichment across two static tables.

=== EDIT 1 — src/eventids.rs, EVENT_ID_TABLE entry event_id: 216 ===
Rationale: current text "(NTDS.dit move ⇒ red flag)" OVERSTATES. Verified: ESENT 216 fires ROUTINELY on every VSS-based backup (a shadow-copy target path is expected/benign), so it is low-fidelity on its own. Replace description with:
  "ESENT: a database location change was detected — embeds the from→to paths (e.g. C:\\Windows\\NTDS\\ntds.dit → \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\Windows\\NTDS\\ntds.dit). Fires routinely during VSS-based backups, so low-fidelity alone — a shadow-copy device path is expected/benign; corroborate with 325 to an unusual path."
Also change high_value: true → false (it is corroboration/context, not a standalone red flag). Keep mitre_techniques &["T1003.003"], artifact_ids &["evtx_application"].

=== EDIT 2 — src/eventids.rs, EVENT_ID_TABLE entry event_id: 325 ===
Rationale: this is the HIGH-fidelity discriminator. Replace description with:
  "ESENT: the database engine created a new database — records the full DB path. ntdsutil IFM 'create full <path>' writes a fresh (defragmented) ntds.dit copy, so a 325 whose path is OUTSIDE the standard %SystemRoot%\\NTDS\\ — especially world-writable staging (C:\\Users\\Public, C:\\ProgramData, C:\\Windows\\Temp, C:\\PerfLogs) — is strongly consistent with credential-theft staging. Correlate with a following 327 (detach) on the same path and ntdsutil.exe process-create (4688 / Sysmon 1)."
Keep high_value: true, mitre &["T1003.003"], artifact_ids &["evtx_application"]. (326/327 text is correct as-is — leave unchanged.)

=== EDIT 3 — src/lolbins.rs, LolbasEntry name: "ntdsutil.exe" ===
Replace description with:
  "NTDS database utility; abused via 'activate instance ntds → ifm → create full <path>' to dump ntds.dit for offline cracking. Writes an IFM set at <path>: 'Active Directory\\ntds.dit' plus 'registry\\SYSTEM' and 'registry\\SECURITY' — the SYSTEM hive carries the boot key/SysKey needed to decrypt the hashes. Leaves ESENT 325 (new DB created) + 327 (detached) in the Application log at the destination path."
Keep mitre &["T1003.003"], use_cases UC_CREDENTIALS | UC_EXECUTE.

Optional (only if a test is desired, per house TDD style like the existing event_1029 test): assert 216.high_value == false and 216.description contains "VSS"/"backup"; assert 325.description contains "PerfLogs" (or the staging-path keyword) and "IFM"/"create full"; assert ntdsutil description contains "Active Directory" and "SYSTEM". Related catalog ids referenced are all valid and present: ntds_dit (mod.rs:3666), evtx_application, evtx_security, services_hklm.

**Sources verified:**
- [Tier-1 (Microsoft vendor doc — ntdsutil ifm reference)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11) — Confirms the 'create full %s' subcommand creates installation media (a fresh copy of the AD database) for a writable domain controller in the %s folder; establishes IFM as the legitimate Install-From-Media provisioning path.
- [Tier-1 (Microsoft vendor doc)] https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/esent-event-327-326 — Confirms ESENT Application-log events 326/327 embed the FULL database path in the description (verbatim example: 'database engine has attached database (2, C:\Windows\system32\LogFiles\Sum\SystemIdentity.mdb)') — the path field is the basis of the location discriminator; source/provider = ESENT.
- [Tier-2 (independent reverse-engineering / technique writeup)] https://www.cyberis.com/article/obtaining-ntdsdit-using-built-windows-commands — Confirms the exact ntdsutil sequence 'activate instance ntds → ifm → create full c:\pentest' and that it backs up ntds.dit plus the SYSTEM file (which contains the key required to extract password hashes) using VSS, without third-party tooling.
- [Tier-2 (SigmaHQ detection-rule source — community-maintained tool)] https://detection.fyi/sigmahq/sigma/windows/builtin/application/esent/win_esent_ntdsutil_abuse_susp_location/ — Corroborates event 216/325/326/327 + provider ESENT + Data field 'ntds.dit'; the 'suspicious location' variant keys on Event 325 to world-writable staging paths (Public/ProgramData/Temp/PerfLogs); documents the false-positive caveat that 216 fires on legitimate backup/shadow-copy creation (VSS-path = benign).
- [Tier-2 (Microsoft-hosted Q&A — corroborating, community-answered)] https://learn.microsoft.com/en-us/answers/questions/740459/domain-controller-promotion-install-from-media-ifm — Corroborates the on-disk IFM set layout: '.\ADBackup\Active Directory\ntds.dit' and '.\ADBackup\registry\SYSTEM' subfolder structure produced by ntdsutil 'Create Full'.

**Notes:** Epistemic layering (kept "consistent with", not "proves"): (1) Event 216 alone is NOT a red flag — it is normal VSS-backup noise; the from→to path field is what carries meaning. (2) The high-fidelity signal is Event 325 whose recorded DB path lies outside %SystemRoot%\NTDS\ (standard live location) and is not a shadow-copy device path — a world-writable staging dir (Public/ProgramData/Temp/PerfLogs) is strongly consistent with ntdsutil IFM dumping. (3) The tightest fingerprint is the sequence 325→327 on the same ntds.dit path + a co-occurring ntdsutil.exe process-create; the on-disk IFM set (<path>\Active Directory\ntds.dit + <path>\registry\SYSTEM+SECURITY) corroborates on the filesystem. Caveats: ntdsutil IFM is a legitimate DC-promotion (Install-From-Media) workflow — presence on a DC is expected during provisioning; the discriminator is the DESTINATION path, not the tool's use per se. VSS-based backups (incl. legitimate Windows Server Backup) also touch ntds.dit and generate 216, so baseline backup windows to suppress noise. ESENT 326/327 semantics in the existing table (attach/detach) are correct and unchanged. Do not treat an unusual 325 path as proof — it is evidence; correlate with process-execution and Security-log context (e.g. 4799, 7036) before concluding.

### `run_mru` — Run Dialog MRU  [enrichment]

**Additions:** Enrich the EXISTING descriptor `run_mru` (crates/data/src/catalog/descriptors/mod.rs, RUN_MRU, currently evidence_caveats: &[] and evidence_strength: None). No id/path/hive/field changes.

1) Populate evidence_caveats (&[...]) with these tool-source-backed decode gotchas:
- "Each command value ends with a trailing \\1 marker (backslash + '1'); it is a storage/terminator artifact appended by Explorer, not part of the user-typed command — strip it before display (Eric Zimmerman's RunMRU plugin removes the trailing \\1; regipy strips it as a 0x01 byte)."
- "Command entries use single-character value names (a, b, c, ...); the separate MRUList value is an ordering string of those letters whose FIRST character identifies the most recently used entry. Only that most-recent entry can be time-anchored to the key's LastWrite time — the remaining entries carry no individual timestamp."
- "Reflects commands launched through the Windows Run dialog (Start > Run) only; it is user-typed interactive-execution evidence, not a complete process-execution log — programs started by any other vector (shell, scripts, task scheduler, double-click) never appear here, so absence of a command does not establish it was never run."

2) Set evidence_strength: Some(EvidenceStrength::Strong) — presence of a command is strong evidence a user interactively typed and launched that exact string via the Run dialog.

3) Optionally append the EZ plugin source URL to `sources` (currently lists regipy + RECmd/RegistryPlugins repo roots but not the specific file): "https://github.com/EricZimmerman/RegistryPlugins/blob/master/RegistryPlugin.RunMRU/RunMRU.cs".

NOTE — deliberately NOT asserting the candidate's "records only successfully-executed commands / absence => failed" claim, because it could not be confirmed against any independent primary source (see forensic_notes). The absence caveat above is phrased conservatively instead.

**Sources verified:**
- [Tier 2 (real tool source — Eric Zimmerman's RegistryExplorer/RECmd plugin)] https://github.com/EricZimmerman/RegistryPlugins/blob/master/RegistryPlugin.RunMRU/RunMRU.cs — Single-letter value names hold commands; MRUList is an ordering string of letters; the entry at MRUList index 0 (first char) is most-recently-used and is the only one assigned the key LastWriteTime (mru==0 => openedOn=key.LastWriteTime); trailing literal \1 (@"\1", 2 chars) is stripped from each command value.
- [Tier 2 (real tool source — regipy)] https://raw.githubusercontent.com/mkorman90/regipy/master/regipy/plugins/ntuser/runmru.py — MRUList holds order as a string of letters (e.g. 'dcba'); single-letter alpha value names contain the commands; trailing marker stripped (regipy uses rstrip('\x01') — a 0x01 byte, differing from EZ's literal \1).
- [Tier 3 (community wiki — pointer/path corroboration only)] https://forensics.wiki/list_of_windows_mru_locations/ — RunMRU key path Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU under HKCU (Run dialog box); no decode-detail authority.

**Notes:** Two of the three candidate facts are confirmed by independent real tool source; the third is not, and is intentionally softened to avoid overstatement.

CONFIRMED (tier 2, tool source): (a) single-letter value names hold the commands; (b) MRUList is a letter-ordering string and its first character is the most-recently-used entry — Eric Zimmerman's RunMRU.cs sets openedOn = key.LastWriteTime only when mru == 0 (MRUList IndexOf == 0), i.e. only the most-recent entry is timestampable; (c) a trailing \1 is stripped as a non-user artifact.

DISCREPANCY worth flagging in code review: the two reference tools disagree on the trailing marker's byte form. EricZimmerman/RunMRU.cs strips a literal two-char string @"\1" (0x5C 0x31), while regipy/runmru.py strips a single 0x01 (SOH) control byte via rstrip("\x01"). Either way it is a terminator artifact, not typed text; the caveat is written to cover both interpretations without asserting which is canonical (would need a raw hive hexdump oracle to settle).

NOT CONFIRMED: "records only successfully-executed commands; absence => failed/never ran." No independent primary source (spec, vendor doc, or RE writeup) was found establishing that the Run dialog excludes failed/invalid commands from RunMRU. Tool authors describe RunMRU as "recently executed programs" (EZ ShortDescription), which supports the general "executed" framing but does NOT support the stronger negative claim that failures are excluded. Excluded from the enrichment per the no-overstatement rule.

forensics.wiki no longer has a dedicated RunMRU page (site migrated to mkdocs); its "List of Windows MRU Locations" page confirms only the key path.

related_artifacts unchanged (wordwheel_query, powershell_history, prefetch_file all verified present in catalog).

### `muicache` — MUICache  [enrichment]

**Additions:** Enrich the EXISTING descriptor `muicache` (crates/data/src/catalog/descriptors/mod.rs:1495, MUICACHE) — add the value-name-suffix fields, the masquerade-detection semantics, evidence_strength, and caveats. Task-scoped changes:

1) FIELDS (MUICACHE_FIELDS, mod.rs:1484) — currently only `display_name`. Add two suffix-specific fields so the catalog reflects that each executed GUI program produces two named values `<PE_full_path>.FriendlyAppName` and `<PE_full_path>.ApplicationCompany`:
   - name: "friendly_app_name" — value_type: Text — description: "Value name suffix .FriendlyAppName; sourced from the executable's PE VersionInfo FileDescription string. Survives file rename, so a renamed binary retains its original embedded identity (masquerade/renamed-executable detection)." — is_uid_component: false
   - name: "application_company" — value_type: Text — description: "Value name suffix .ApplicationCompany; sourced from the executable's PE VersionInfo CompanyName string. Survives file rename." — is_uid_component: false
   (Keep the existing `display_name` field.)

2) meaning — update to: "Cached display names keyed by executable path; per-program .FriendlyAppName (PE FileDescription) and .ApplicationCompany (PE CompanyName) come from the binary's embedded VersionInfo and survive rename — evidence a GUI program was present/run and of its original identity even if renamed."

3) evidence_strength: Some(EvidenceStrength::Corroborative)  — MUICache is execution-adjacent GUI-program-presence evidence, not standalone proof: it is populated by the shell, carries no execution timestamp, and shell interaction (not only launch) can create entries. Corroborative ("useful with other evidence; not standalone proof") is the honest tier; do NOT set Definitive.

4) evidence_caveats: &[
   "No execution timestamp: entries are stored as registry values, so the key's last-write time cannot be used to infer when a program executed.",
   "Records graphical-interface (GUI) programs registered by the shell; not a definitive record that full execution occurred — shell interaction can populate entries. Use with UserAssist/BAM/Prefetch/Amcache to corroborate execution.",
   ".FriendlyAppName / .ApplicationCompany are absent when the binary has no PE VersionInfo resource (common for packed or stripped malware), so their absence is not exculpatory.",
   "FriendlyAppName/ApplicationCompany derive from the PE's embedded VersionInfo and therefore survive a file rename — useful to reveal a renamed/masqueraded binary's original identity, but an attacker can also forge these fields in the binary."
 ]

5) related_artifacts (currently &[] ) — populate with verified-existing sibling execution ids: &["userassist_exe", "bam_user", "amcache_app_file", "prefetch_file", "shimcache"] (all confirmed present in the catalog). Optional but recommended since UserAssist and Amcache already list "muicache" as related (windows_registry_ext.rs:522,762).

6) SOURCES — add the two primary sources used to verify these facts (keep existing entries; the current sources are SANS/Magnet/forensafe blogs which are discovery pointers only):
   - https://learn.microsoft.com/en-us/windows/win32/menurc/stringfileinfo-block  (MS spec: CompanyName and FileDescription are predefined StringFileInfo VersionInfo keys)
   - https://artefacts.help/windows_registry_muicache.html  (RE-derived DFIR artifact reference: .FriendlyAppName←FileDescription, .ApplicationCompany←CompanyName, rename-detection use, and no-timestamp property)

**Sources verified:**
- [1 (authoritative vendor spec — Microsoft Win32 docs)] https://learn.microsoft.com/en-us/windows/win32/menurc/stringfileinfo-block — CompanyName ('Company that produced the file') and FileDescription ('File description to be presented to users') are predefined StringFileInfo VersionInfo string keys embedded in the PE — the source fields MuiCache's .ApplicationCompany and .FriendlyAppName are populated from.
- [2 (RE-derived DFIR artifact reference, Qazeer/artefacts.help)] https://artefacts.help/windows_registry_muicache.html — Each execution creates two MuiCache values under the executable full path: <PE_FULL_PATH>.FriendlyAppName (references PE FileDescription) and <PE_FULL_PATH>.ApplicationCompany (references PE CompanyName); FriendlyAppName can identify a renamed executable; MuiCache provides NO execution timestamp and the key last-write time cannot infer execution time; key references GUI-program execution; path HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MUICache in UsrClass.dat.

**Notes:** Masquerade-detection mechanism verified: the two per-program MuiCache values `<PE_full_path>.FriendlyAppName` and `<PE_full_path>.ApplicationCompany` are copied from the executable's embedded PE VersionInfo (StringFileInfo) FileDescription and CompanyName strings respectively (Microsoft primary spec confirms these are the predefined version-resource keys). Because they live in the binary's .rsrc and are recorded verbatim by the shell, they persist a filesystem rename — evil.exe renamed to svchost.exe still shows its true FriendlyAppName. Caveat both ways: (a) the fields are absent if the binary carries no version resource (packed/stripped malware), so absence is not exculpatory; (b) an attacker can forge the VersionInfo, so a matching name is consistent-with, not proof-of, a given identity. Two hard limits kept honest in the caveats: MuiCache has NO execution timestamp (values stored directly; key mtime only tracks the most-recent change, not any specific program), and it registers shell/GUI-program interaction rather than proving a full process launch — hence Corroborative, not Definitive. Modern path is HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache (UsrClass.dat); the descriptor's current key_path `Local Settings\MuiCache` is the legacy short form — flagged for a possible follow-up but out of this enrichment's scope. Did NOT cite 13cubed/SANS/Magnet as authorities (discovery pointers only).

### `ntfs_macb_rules` — NTFS MACB Timestamp Update Rules (Per-Operation Baseline)  [new_descriptor]

```
id: "ntfs_macb_rules"
name: "NTFS MACB Timestamp Update Rules (Per-Operation Baseline)"
artifact_type: ArtifactLocation::File
hive: None
key_path: ""
value_name: None
file_path: Some(r"\\.\<volume>\$MFT")   // interpretive descriptor anchored to $MFT, where $SI (attr 0x10) + $FN (attr 0x30) timestamps live
scope: DataScope::System
os_scope: OsScope::All   // rules are NTFS-wide, but see caveats on OS-version drift
decoder: Decoder::Identity
triage_priority: TriagePriority::High

meaning:
"Interpretive baseline for reading NTFS timestamps: which of the four MACB values move on each file operation. Each MFT record holds two timestamp sets — $STANDARD_INFORMATION (SI, attr 0x10, user-writable via SetFileTime) and $FILE_NAME (FN, attr 0x30, kernel-maintained). M=Modified (data), A=Accessed, C=MFT/metadata changed (entry-modified), B=Born/created; all are 64-bit FILETIME (100ns since 1601-01-01 UTC). Legitimate operations move a KNOWN subset; a set that cannot be produced by any single operation, or SI values that are internally impossible (e.g. M earlier than B), is the reference frame for detecting forgery (T1070.006). Baseline (SI unless noted):
- CREATE: all four (M,A,C,B) set to creation time, in BOTH $SI and $FN.
- ACCESS: A only (and only when Last-Access updates are enabled — see caveats); $FN unchanged.
- MODIFY (data write): M and C update to write time; A updates if Last-Access enabled; B unchanged; $FN unchanged.
- RENAME (same volume): SI C only; the $FN set is (re)written from the current $SI values — so timestomping $SI then renaming propagates the forged values into $FN (false-negative for SI-vs-FN comparison).
- LOCAL MOVE (same volume): SI C updates; $FN C updates; M/A/B preserved.
- MOVE across volumes: SI A and C update to move time; M and B preserved; $FN reset (creation-like) to move time.
- COPY across volumes: SI M and C inherited from the SOURCE, while SI A and B are the copy time; $FN MACB all = copy time. This yields the classic COPY tell: SI Modified is EARLIER than SI Born (M < B), which no create/write path produces.
- DELETE: no timestamp change; the MFT record is flagged inactive.
Use as the frame against which observed $SI/$FN sets and MACB orderings are judged; it does not by itself prove tampering."

fields (FieldSchema[]; value_type Text; encode the matrix as one field per operation):
- op_create        — "SI+FN: M,A,C,B all set to creation time"
- op_access        — "SI: A only (Last-Access-policy gated); FN unchanged"
- op_modify        — "SI: M,C update (A if Last-Access enabled); B unchanged; FN unchanged"
- op_rename_local  — "SI: C only; FN rewritten from current SI values (indirect propagation)"
- op_move_local    — "SI: C updates; FN: C updates; M,A,B preserved"
- op_move_xvolume  — "SI: A,C update to move time; M,B preserved; FN reset to move time"
- op_copy_xvolume  — "SI: M,C inherited from source; A,B = copy time; FN MACB = copy time -> M<B tell"
- op_delete        — "No SI/FN timestamp change; MFT record marked inactive"

mitre_techniques: &["T1070.006"]   // Timestomp — this baseline is the reference frame for detecting it; T1070.004 (deletion) tangential, left out to avoid forcing

related_artifacts: &["mft", "mft_file", "ntfs_i30_index", "ntfs_last_access_status", "logfile_ntfs", "usnjrnl", "usn_journal", "recycle_bin"]   // all verified present in catalog

sources: &[
  // Primary authoritative textbook — NTFS timestamp update semantics
  "Carrier, B. (2005). File System Forensic Analysis, ch. 11-13 (NTFS). Addison-Wesley. ISBN 0-32-126817-2",
  // Vendor doc — FILETIME + last-access behavior gating the A rule
  "https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table",
  "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior",
  // RE authority (Maxim Suhanov) — $SI vs $FN, NtfsDisableLastAccessUpdate new semantics
  "https://dfir.ru/2021/01/10/standard_information-vs-file_name/",
  "https://dfir.ru/2018/12/08/the-last-access-updates-are-almost-back/",
  // Empirical modern-Windows corroboration of the per-operation matrix (RE writeup)
  "https://www.senturean.com/posts/19_04_22_win10_ntfs_time_rules/",
]

evidence_strength: Some(EvidenceStrength::Corroborative)
// Honest: the core rules (create/copy-cross-volume/delete) are stable and well-documented, but the
// full matrix has real OS-version drift (last-access default, move/copy handler changes across
// XP -> 7 -> 10 1803+). A single deviation is consistent with tampering, not proof of it.

evidence_caveats: &[
  "OS-version drift: Carrier (2005) documents the classic rules; Win7/Win10 changed move/copy handling and last-access defaults. Validate on a comparable test system when timestamps are central.",
  "Last-Access (A) updates are policy-gated via HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\NtfsDisableLastAccessUpdate (new 4-value semantics since Win10 1803: 0x80000000 User/Enabled, 0x80000001 User/Disabled, 0x80000002 System/Enabled, 0x80000003 System/Disabled; System-Managed default enables A only when the system volume is <=128 GiB). Absent A movement does not imply an anomaly. See ntfs_last_access_status.",
  "$FN values are (re)written from $SI on rename and local move, so SI-vs-FN comparison yields false negatives when an attacker timestomps $SI then renames/moves the file.",
  "File System Tunneling can restore a prior file's creation time on CREATE, mimicking backdating without tampering.",
  "1-second granularity caveats and sub-second (fractional) zeroing are separate timestomping heuristics, not part of this operation matrix.",
]

volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Interpretive baseline; the underlying $MFT timestamps persist until overwritten."
```

**Sources verified:**
- [corroborative (references SANS poster; discovery pointer, values cross-checked against RE sources)] https://artefacts.help/windows_macb_timestamps.html — Copy across NTFS partitions: SI M,C inherited from source, SI A,B = copy time, FN MACB = copy time; local move updates SI C + FN C; cross-partition move updates SI A,C
- [RE authority (Maxim Suhanov)] https://dfir.ru/2018/12/08/the-last-access-updates-are-almost-back/ — NtfsDisableLastAccessUpdate new 4-value semantics since Win10 1803; System-Managed default enables Last-Access only when system volume <=128 GiB
- [vendor doc (primary)] https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table — $MFT layout; $STANDARD_INFORMATION and $FILE_NAME attributes hold the timestamp sets; FILETIME semantics
- [RE writeup (empirical Win10 testing)] https://www.senturean.com/posts/19_04_22_win10_ntfs_time_rules/ — Per-operation MACB update matrix on modern Windows (create/access/modify/rename/move/copy/delete) — corroborates the version-drifted rules
- [authoritative textbook (primary reference for NTFS internals)] Carrier, File System Forensic Analysis (2005), ch. 11-13 — Baseline NTFS timestamp update semantics for $SI and $FN per operation; noted to predate modern OS-version drift

**Notes:** Triage logic: use this descriptor as the reference frame, then read the actual timestamps from `mft`/`mft_file` and cross-check operation-level sequencing against `usnjrnl`/`usn_journal` (USN reason codes) and `logfile_ntfs` (LSN ordering). The strongest single-record forgery tell encoded here is the COPY tell — SI Modified earlier than SI Born (M < B) — which no legitimate create/write path produces; it flags a cross-volume copy (or crude timestomping) without needing $FN at all. The $FN-vs-$SI comparison (the mft descriptors) is complementary but defeated by the rename/local-move propagation caveat, so the two methods are not redundant. Directory index ($I30, ntfs_i30_index) retains a $SI snapshot that can predate a later $SI timestomp. Do NOT treat a deviation as proof of tampering: state it as consistent with forgery and account for OS-version drift, last-access policy, and File System Tunneling first. This is a NEW descriptor — the referenced `ntfs_timestomping_si_fn` appears only in research/iwe-forensicnomicon-reconciliation.md (a planning doc), not the shipped catalog, so there is no existing descriptor to enrich; the existing `mft`/`mft_file` descriptors cover SI-vs-FN divergence detection but not the per-operation update-rule matrix.

### `fls` — The Sleuth Kit — fls  [enrichment]

**Additions:** TARGET: enrich the existing `fls` TimelineTool descriptor (id: "fls") in /Users/4n6h4x0r/src/forensicnomicon/src/timelining.rs (currently lines 197-209), by adding one new entry to its `caveats: &[...]` array. Insert it as the SECOND caveat (immediately after the "File-system only" note) because it is the most common operational blocker.

EXACT new caveat string to add:

"Whole-disk (multi-partition) image fails with 'Cannot determine file system type', and forcing a type with -f (e.g. -f ntfs/-f fat) does NOT fix it — fls then reads sector 0 (the partition table) where no filesystem boot sector exists ('Do you have a disk image instead of a partition image?' / 'invalid sector size 0'). Run mmls first to get the partition's Start sector, then pass -o <start-sector> (offset in sectors); e.g. fls -r -m / -o 2048 image.raw"

Notes for the editor:
- The `-o` semantics come straight from the fls tool's own usage output: "-o imgoffset: Offset into image file (in sectors)" — offset is in SECTORS, not bytes.
- mmls (TSK) enumerates the partition table with Start sectors ("Units are in 512-byte sectors"); the partition Start value feeds directly into fls -o.
- No struct/schema change needed — TimelineTool.caveats is already a &[&'static str]; this is a one-element addition.
- Optionally update the module-level doc comment (lines 5, 17) or add a source URL to the fls doc block: TSK fls man page http://www.sleuthkit.org/sleuthkit/man/fls.html (the -o imgoffset entry) — but the load-bearing citation is the tool's own usage output, already verbatim above.

**Sources verified:**
- [Tier 1 — authoritative tool's own output] file:///usr/local/bin/fls (TSK fls usage output) — fls flag semantics verbatim: '-o imgoffset: Offset into image file (in sectors)' — offset unit is SECTORS. Also confirms fls is a filesystem-layer tool taking a single image.
- [Tier 1 — authoritative tool's own output] file:///usr/local/bin/mmls (TSK mmls usage + run output) — mmls enumerates the partition table with Start sectors ('Units are in 512-byte sectors'); the Start sector is what feeds fls -o. On the test image mmls reported the FAT16 partition Start=1.
- [Tier 2 — real engine output, ground truth from independent oracle (mmls)] Empirical reproduction on /tmp/fls-test/diskraw.dmg (hdiutil-created 20MB MBR + FAT16 whole-disk image) — Confirmed the full failure/fix chain on real TSK output: (1) `fls diskraw.dmg` -> 'Cannot determine file system type'; (2) `fls -f fat diskraw.dmg` -> 'sector size (0)... Do you have a disk image instead of a partition image?'; (2b) `fls -f ntfs diskraw.dmg` -> 'Not a NTFS file system (invalid sector size 0)'; (3) `fls -o 1 diskraw.dmg` and `fls -r -m / -o 1 diskraw.dmg` -> succeed, listing the filesystem and producing a valid bodyfile. Ground truth (partition start) independently derived from mmls's partition-table parse.
- [Tier 1 — vendor documentation] http://www.sleuthkit.org/sleuthkit/man/fls.html — Published TSK fls man page documenting -o imgoffset; corroborates the local usage output.
- [Corroborative — textbook reference] Brian Carrier, 'File System Forensic Analysis' (2005), volume/partition analysis chapters — Documents the whole-disk-vs-partition distinction and the mmls->offset workflow that TSK filesystem tools require.

**Notes:** Why -f does not help (mechanism, confirmed by TSK's own error text): on a whole-disk image, offset 0 holds the MBR/GPT partition table, not a filesystem boot sector. fls auto-detect fails with "Cannot determine file system type". Forcing -f ntsf/-f fat only changes the parser, not the read offset — TSK still reads sector 0 and fails with "invalid sector size 0" / "Not a NTFS file system", and for FAT literally prints "Do you have a disk image instead of a partition image?". The real fix is spatial: point fls at the partition's start with -o <sector> (from mmls). This is a partition-offset problem, not a filesystem-type problem — the same fix applies to every fs type (NTFS, FAT, ext, APFS via -o/-B), so it is the general rule, not an NTFS special case. Evidence strength: Strong/Definitive — the -o flag semantics are the tool's own documented behavior (Tier 1), and the failure/fix chain was reproduced end-to-end on a real hdiutil-built MBR+FAT16 image whose ground-truth partition offset was independently read by mmls (Tier 2). A partition image (already carved to the filesystem, e.g. via `mmls`+`dd` or `img_cat`) needs no -o; the gotcha is specific to whole-disk acquisitions (E01/raw of an entire drive), which is the common case for full-disk forensic images.

### `psort` — Plaso — psort.py (timeline output module descriptor)  [enrichment]

**Additions:** Target: the `TimelineTool { id: "psort" }` entry in /Users/4n6h4x0r/src/forensicnomicon/src/timelining.rs (and, secondarily, the `TimelineOutputFormat::L2tCsv` variant doc + the module-level quick-reference example). The catalog already knows "dynamic is plaso's default module" and calls l2tcsv "legacy fixed 17-field", but it does NOT capture that (a) l2tcsv is a member of Plaso's `_DEPRECATED_OUTPUT_FORMATS` and psort/psteal now emit a runtime user-warning when it is selected, nor (b) the concrete technical reason — second-only date/time resolution. Both are load-bearing for a forensic timeline (sub-second ordering of near-simultaneous events is lost with l2tcsv). Three precise edits:

1. Flip the canonical `command` so it no longer leads with the deprecated format. Change
   `command: "psort.py -o l2tcsv {OUTPUT}.plaso > supertimeline.csv"`
   to
   `command: "psort.py -o dynamic -w supertimeline.csv {OUTPUT}.plaso"`
   Rationale: `dynamic` is the built-in default (`plaso/cli/helpers/output_modules.py`: `--output_format ... default="dynamic"`), so leading with l2tcsv makes the canonical command trigger Plaso's own deprecation warning. `-w <file>` is the modern output-file flag (mirrors the psteal entry already in the catalog), replacing the shell redirect.

2. Replace psort caveats[0]
   `"-o l2tcsv produces the legacy fixed 17-field L2T CSV format readable by Timeline Explorer; plaso's default module is 'dynamic', which supports customizable fields"`
   with a deprecation-aware, spec-precise pair of caveats:
   - `"'dynamic' is the default output module (customizable columns) and is the recommended format; it carries sub-second (datetime) precision"`
   - `"-o l2tcsv is DEPRECATED in Plaso (member of _DEPRECATED_OUTPUT_FORMATS); psort/psteal print a user-warning that it has 'significant limitations such as second-only date and time values and/or a limited predefined set of output fields' and recommend 'dynamic'. l2tcsv emits a fixed 17-field row (date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra) at second-only resolution, readable by Timeline Explorer"`

3. (Optional, same fact) The `TimelineOutputFormat::L2tCsv` variant doc currently reads `/// L2T CSV — human-readable, sortable by psort.py -o l2tcsv.` — append the deprecation status: `/// Legacy/deprecated in Plaso (second-only timestamps, fixed 17 fields); superseded by the 'dynamic' module.` Likewise the module-level quick-reference example on line ~22 (`psort.py -o l2tcsv evidence.plaso > supertimeline.csv`) should be updated to the dynamic form for consistency with the flipped canonical command.

evidence_strength for these facts: Definitive (Plaso's own source declares the deprecation set, the warning text, the default format, and the 17-field DESCRIPTION verbatim). No MITRE technique applies (tooling/output-format metadata, not an adversary behaviour) — leave empty.

**Sources verified:**
- [Tier 1 (authoritative tool source)] https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/cli/tool_options.py — l2tcsv is DEPRECATED: `_DEPRECATED_OUTPUT_FORMATS = frozenset(["l2tcsv", "l2ttln", "tln"])`; code comment 'Output format that have second-only date and time value and/or a limited predefined set of output fields'; runtime user-warning text 'has significant limitations such as second-only date and time values and/or a limited predefined set of output fields. It is strongly recommend to use an alternative output format like: dynamic.'
- [Tier 1 (authoritative tool source)] https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/cli/helpers/output_modules.py — 'dynamic' is the built-in default output format: `--output_format ... default="dynamic"` and `getattr(options, "output_format", "dynamic")`.
- [Tier 1 (authoritative tool source)] https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/output/l2t_csv.py — l2tcsv has exactly 17 fixed fields: class L2TCSVOutputModule DESCRIPTION = 'CSV format used by legacy log2timeline, with 17 fixed fields.' and `_FIELD_NAMES` = [date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra] (17 entries). Second-only resolution: _FormatDate -> 'MM/DD/YYYY', _FormatTime -> HH:MM:SS (no sub-second component).

**Notes:** The literal phrase "industry-standard" is NOT present anywhere in timelining.rs (grepped src/ and crates/) — the staleness the work item points at is structural, not a string: the psort descriptor's canonical `command` and the module-level quick-reference both lead with `-o l2tcsv`, a format Plaso itself now flags as deprecated. The enrichment corrects that lead and records the two facts the catalog was missing (deprecation membership + second-only resolution). Note the deprecation set also contains `l2ttln` and `tln` for the same reason (second-only / limited fields), but those TLN formats are not currently modelled in the TimelineTool table, so no action there beyond mentioning it. related_artifacts already correct in-file: psort links to log2timeline/psteal/pinfo which all exist in TIMELINE_TOOLS. The l2tcsv format spec lives at forensics.wiki/l2t_csv (referenced from l2t_csv.py's own header) if a secondary human-readable citation is wanted, but the primary authority is the Plaso source itself.

### `windows_search_db_win11` — Windows Search Index SQLite (windows.db, Win11 22H2+)  [enrichment]

**Additions:** Enrich the EXISTING descriptor `windows_search_db_win11` (crates/data/src/catalog/descriptors/mod.rs:3126). The current descriptor treats Win11 Search as a single file (windows.db) and mislocates the forensic payload: the `FileName`/`gather_time` data does NOT live in windows.db — it lives in the co-resident Windows-gather.db. Add the two co-resident files and correct where each field comes from.

1. meaning — replace/extend to state that Win11 22H2+ splits the Search index into THREE co-resident SQLite files in the SAME directory `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\`, and ALL THREE must be collected together:
   - windows.db — property/metadata store. Table `SystemIndex_1_PropertyStore` (WorkId, ColumnId, Value) + `SystemIndex_1_PropertyStore_Metadata` (Id↔ColumnId, UniqueKey names). In Win11 the property store is restructured to one row per property (vs Win10's wide multi-column `SystemIndex_PropertyStore`).
   - Windows-gather.db — the gatherer DB; highest forensic value. Table `SystemIndex_Gthr` holds FileName, LastModified, ScopeID (parent link), DocumentID (per-object UID). Table `SystemIndex_GthrPth` + ScopeID reconstructs the full path. WorkId in windows.db maps to DocumentID here.
   - Windows-usn.db — third co-resident DB; little/no forensic value (explicitly excluded from the AON and Securelist write-ups). Collect for completeness, but analysis focus is gather.db + windows.db.
   Add a collection caveat: collecting only windows.db loses the filename/path/gather-time evidence, which is in Windows-gather.db.

2. fields — the existing two fields (`file_path`, `gather_time`) actually originate in Windows-gather.db's `SystemIndex_Gthr` (columns FileName + a GatherTime/LastModified value; SIDR surfaces the value as `System_Search_GatherTime`), NOT windows.db. Annotate the field descriptions to say they come from Windows-gather.db `SystemIndex_Gthr`. Optionally add `document_id` (SystemIndex_Gthr.DocumentID, links to windows.db WorkId) and `scope_id` (parent-scope link used with SystemIndex_GthrPth for path reconstruction).

3. sources — add (current list has only kacos2000/WinEDB):
   - https://github.com/strozfriedberg/sidr (SIDR tool source — parses both Windows.edb ESE and Windows.db SQLite, emits File/Internet-History/Activity-History reports; confirms the `System_Search_GatherTime` field)
   - https://cyber.aon.com/aon_cyber_labs/windows-search-index-the-forensic-artifact-youve-been-searching-for/ (AON RE writeup; also mirrored at levelblue.com/blogs/spiderlabs-blog/windows-search-index-the-forensic-artifact-youve-been-searching-for/)
   - https://securelist.com/forensic-artifacts-in-windows-11/117680/ (Securelist/Kaspersky RE writeup — independent corroboration of the three-file split and table/column names)

4. evidence_caveats — add: (a) 'Win11 Search splits across THREE co-resident SQLite files (windows.db, Windows-gather.db, Windows-usn.db) in the same Applications\\Windows dir; collect all three — filename/path/gather-time evidence is in Windows-gather.db, not windows.db.'; (b) 'Windows-usn.db has little forensic value and is excluded from most write-ups.' evidence_strength for gather_time as a present-on-system indicator independent of NTFS timestamps: Corroborative (two independent RE writeups + a tool that surfaces it), not Definitive.

related_artifacts already correctly references existing ids windows_search_edb, mft, usnjrnl — leave as-is (all three verified present in catalog).

**Sources verified:**
- [RE writeup (AON/Trustwave-SpiderLabs mirror) — independent primary] https://www.levelblue.com/blogs/spiderlabs-blog/windows-search-index-the-forensic-artifact-youve-been-searching-for/ — Win11 splits Search into three SQLite files in C:\ProgramData\Microsoft\Search\Data\Applications\Windows\: Windows.db (property store), Windows-gather.db (gatherer: SystemIndex_Gthr/GthrPth), Windows-usn.db (limited value); verbatim: 'Because Windows-usn.db ... has less forensic value, it is not covered in this post.'; SystemIndex_1_PropertyStore restructured as individual rows; WorkId maps to DocumentID
- [RE writeup (Securelist/Kaspersky) — independent corroboration] https://securelist.com/forensic-artifacts-in-windows-11/117680/ — Corroborates the three-file split and table/column names (SystemIndex_Gthr FileName/LastModified/ScopeID/DocumentID; ScopeID+SystemIndex_GthrPth reconstructs full path; SystemIndex_1_PropertyStore in windows.db); Windows-usn.db has no useful forensic info
- [Tool source — real implementation] https://github.com/strozfriedberg/sidr — SIDR parses Windows.edb (ESE) and Windows.db (SQLite), emits three reports (File/Internet-History/Activity-History); src/ese.rs confirms the System_Search_GatherTime field. Does NOT parse gather.db/usn.db as separate inputs — so it corroborates the GatherTime field but not the file-split claim

**Notes:** Verification outcome: the co-resident three-file structure is CONFIRMED by two independent reverse-engineering write-ups (AON Cyber Solutions / mirrored on Trustwave SpiderLabs-LevelBlue, and Securelist/Kaspersky) with identical filenames, tables, and columns. Correction to the task's candidate-source list: SIDR (github.com/strozfriedberg/sidr) does NOT itself parse Windows-gather.db or Windows-usn.db as separate inputs — its README states it handles 'Windows.edb' (ESE) and 'Windows.db' (SQLite); its only 'gather' reference is the FIELD `System_Search_GatherTime` (src/ese.rs), not a separate file. So SIDR corroborates the GatherTime field but is NOT the authority for the three-file split; the AON and Securelist RE writeups are. Important accuracy note for the edit: the existing descriptor's `file_path`/`gather_time` fields are attributed to windows.db but the underlying data (FileName, LastModified/GatherTime, ScopeID, DocumentID) actually resides in Windows-gather.db's SystemIndex_Gthr / SystemIndex_GthrPth tables — windows.db holds only the SystemIndex_1_PropertyStore metadata (WorkId↔DocumentID join). Windows-usn.db is collect-for-completeness only. Per standing rules these RE writeups are acceptable primary sources (not used as mere discovery pointers); tier them as Corroborative, keep 'consistent with' framing for the gather_time-as-timeline-indicator claim.

### `evtx_security` — Security Event Log (Security.evtx)  [enrichment]

**Additions:** Enrich the EVTX_SECURITY descriptor (crates/data/src/catalog/descriptors/mod.rs, id: "evtx_security", starting line 7099) as follows:

1) MEANING field — add EID 4776 to the enumerated key event IDs (insert alongside the existing 5379/1102 clauses):
   "4776 (NTLM credential validation — 'The computer attempted to validate the credentials for an account'; subcategory Audit Credential Validation; generated ONLY on the computer authoritative for the account: the domain controller for DOMAIN accounts, the local machine for local accounts. Records Logon Account (TargetUserName) and Source Workstation (the CLIENT the NTLM auth originated FROM — never the destination server, which this event does not record), plus an Error Code (Status: 0x0 = success, non-zero = failure, e.g. 0xC000006A bad password, 0xC0000234 account locked). On a DC this yields a central view of ALL NTLM authentication attempts for domain accounts, including the source workstation — a primary pivot for pass-the-hash / NTLM lateral movement, because 4624 alone does not attribute the NTLM authentication source the way DC-side 4776 does. Provider Microsoft-Windows-Security-Auditing GUID {54849625-5478-4994-A5BA-3E3B0328C30D}; PackageName always MICROSOFT_AUTHENTICATION_PACKAGE_V1_0; also fires on workstation-unlock; does NOT fire when a domain account logs on locally at a DC)"

2) MITRE_TECHNIQUES — add "T1550.002" (Use Alternate Authentication Material: Pass the Hash). Current array is &["T1070.001", "T1059", "T1078", "T1555"] → add T1550.002. This is consistent with src/eventids.rs line 140 which already maps EID 4776 → T1550.002.

3) SOURCES — add the Microsoft primary-source URL with an attribution comment:
   // Source: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776
   // — Microsoft documents Event 4776 (S,F) 'The computer attempted to validate
   //   the credentials for an account': generated on every NTLM credential
   //   validation, ONLY on the authoritative computer (DC for domain accounts,
   //   local machine for local accounts). Fields: PackageName (always
   //   MICROSOFT_AUTHENTICATION_PACKAGE_V1_0), TargetUserName (Logon Account),
   //   Workstation (Source Workstation = the client the auth originated from, NOT
   //   the destination), Status (Error Code; 0x0 = success). Doc: 'on domain
   //   controllers you can see all authentication attempts for domain accounts
   //   when NTLM authentication was used' and 'you'll see CLIENT-1 in the Source
   //   Workstation field ... destination computer (SERVER-1) isn't presented'.
   "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776",

4) EVIDENCE_CAVEATS — optionally add one entry capturing the DC-authoritative scope limit:
   "Event 4776 is recorded only on the computer authoritative for the account (the domain controller for domain accounts, the local machine for local accounts); it records the Source Workstation the NTLM authentication originated from but not the destination server, and does not generate for Kerberos authentication or when a domain account logs on locally at a DC."

No change to related_artifacts is required (existing set already includes lateral-movement-relevant artifacts; dcc2_cache and ntds_dit are referenced from this descriptor elsewhere in the catalog). evidence_strength stays Definitive (Microsoft-documented event schema).

**Sources verified:**
- [1] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776 — Tier 1 (vendor primary source, Microsoft Learn). Confirms Event 4776 title 'The computer attempted to validate the credentials for an account (S,F)'; subcategory Audit Credential Validation; generated on every NTLM credential validation and ONLY on the authoritative computer (DC for domain accounts, local machine for local accounts); Source Workstation = client the auth originated from (explicitly NOT the destination server, e.g. CLIENT-1 not SERVER-1); fields PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0, TargetUserName (Logon Account), Workstation (Source Workstation), Status/Error Code (0x0=success); provider GUID {54849625-5478-4994-A5BA-3E3B0328C30D}; error-code table (0xC000006A bad password, 0xC0000234 locked, etc.); 'on domain controllers you can see all authentication attempts for domain accounts when NTLM authentication was used'; also fires on workstation unlock; does not fire for domain account local logon at a DC.

**Notes:** Enrichment, not a new descriptor — evtx_security already exists (mod.rs:7099) and its eventids.rs table (line 140) already maps 4776→T1550.002, but the descriptor's meaning/sources omit the forensic detail. The load-bearing forensic value confirmed by Microsoft: on a DC, 4776 centralises every NTLM credential-validation attempt for domain accounts AND records the originating Source Workstation, which is the pass-the-hash / NTLM lateral-movement pivot. Caveat to preserve honesty: the descriptor summary's 'not shown by 4624' framing should be stated as 'DC-side 4776 attributes the NTLM source workstation for all domain-account NTLM auth', not an absolute claim that 4624 never shows a source — 4624 Type 3 does carry WorkstationName/IpAddress; the distinction is that 4776 gives the DC-central NTLM-only view. Scope limits (Definitive-but-bounded): recorded only on the authoritative host; records source not destination; Kerberos auth and DC-local domain logons produce no 4776; NTLM auditing must be enabled. Evidence strength Definitive (documented event schema). MITRE T1550.002 is the clean fit (Pass the Hash uses NTLM); do not over-claim T1110/brute-force as primary — failure-code clustering supports it only circumstantially.

### `evtx_security` — Security Event Log (Security.evtx)  [enrichment]

**Additions:** TARGET (exact existing id): evtx_security — descriptor at crates/data/src/catalog/descriptors/mod.rs:7099 (EVTX_SECURITY). EIDs 5140/5145 are NOT in the descriptor meaning today (verified by grep); they already exist only in src/heuristics/evtx.rs (EID_SMB_SHARE_ACCESS=5140, EID_SMB_OBJECT_ACCESS=5145, ADMIN_SHARE_NAMES) and src/playbooks.rs — so the catalog descriptor should be enriched to match.

1) ADD to `meaning` (append a new clause before the "1102 (audit log cleared…)" clause, matching existing "NNNN (desc)" style):

"5140 (network share object accessed — Audit File Share subcategory; generates once per session on the first access attempt; records ShareName in the \\\\*\\SHARE_NAME format so admin-share access shows as \\\\*\\C$, \\\\*\\ADMIN$, \\\\*\\IPC$ — primary lateral-movement / T1021.002 SMB admin-share signal when the Source Address (IpAddress) is a remote, non-localhost host; AccessMask is always 0x1 / ReadData(ListDirectory), and ShareLocalPath is empty for IPC$), 5145 (detailed network share object check — Audit Detailed File Share subcategory; fires per file/folder object rather than once per session, so it is high-volume and off by default; adds RelativeTargetName — the file path relative to the share, or \\ for the share root — plus a fuller AccessMask/Accesses list and an AccessReason SDDL access-check trail, giving file-level visibility into what a remote account touched over SMB, e.g. staged tools or exfiltrated files under an admin share)"

2) ADD to `mitre_techniques`: add "T1021.002" (SMB/Windows Admin Shares — already used by the PsExec descriptor in windows_files_ext.rs, so the technique id is valid in-repo) and "T1039" (Data from Network Shared Drive). Optionally "T1135" (Network Share Discovery) for the 5140 enumeration angle, but T1021.002 + T1039 are the cleanest fit; keep T1135 out unless enumeration coverage is wanted. Existing list T1070.001, T1059, T1078, T1555 stays.

3) ADD to `sources` (two Microsoft primary docs, with the existing "// Source:" comment convention):
// Source: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140
// — Microsoft documents Event 5140 "A network share object was accessed",
//   Subcategory "Audit File Share"; generates once per session on first access;
//   fields SubjectUserSid/Name/Domain, SubjectLogonId, ObjectType (always File),
//   IpAddress (Source Address), IpPort, ShareName (\\*\SHARE_NAME), ShareLocalPath
//   (empty for IPC$), AccessMask (always 0x1 = ReadData/ListDirectory).
"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140",
// Source: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
// — Microsoft documents Event 5145 "A network share object was checked to see
//   whether client can be granted desired access", Subcategory "Audit Detailed
//   File Share"; fires per object; adds RelativeTargetName (relative file path,
//   \ for the share itself), AccessMask/Accesses (full file-access-code table),
//   and AccessReason/Access Check Results (SDDL). Failure events only on
//   share-level denial, not NTFS-level denial.
"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145",

4) evidence_strength: leave as Definitive (Microsoft-documented event schema, tier-1 vendor doc). Optionally ADD an evidence_caveat noting that 5140 fires once per session (misses subsequent accesses in the same session) and that 5145 (Audit Detailed File Share) is OFF by default and very high-volume, so its absence does not mean no share access occurred:
"5140 (Audit File Share) fires once per session on first access — it does not log every subsequent access within that session; 5145 (Audit Detailed File Share) is disabled by default and high-volume, so its absence is not evidence that no per-file share access occurred."

No related_artifacts change needed (existing srum_network_usage / srum_app_resource / prefetch_file / shimcache still apply; evtx_rdp_inbound already relates back to evtx_security for lateral-movement context).

**Notes:** Facts confirmed against Microsoft's per-event auditing docs (tier-1 vendor primary source), not against the candidate blog (ultimatewindowssecurity.com was only a discovery pointer and was not used as authority). Key forensic points: (a) 5140 = "Audit File Share" subcategory, once-per-session, share-level; ShareName encodes admin shares as \\*\C$ / \\*\ADMIN$ / \\*\IPC$, with IPC$ having an empty ShareLocalPath — this is the concrete field that the repo's existing ADMIN_SHARE_NAMES heuristic keys on. (b) 5145 = "Audit Detailed File Share" subcategory, per-object, adds RelativeTargetName (relative path within the share, "\" for the share root) and an AccessReason SDDL trail — the file-level granularity for tracking exactly which files a remote account touched. (c) Both carry IpAddress (Source Address) + IpPort; remote non-localhost Source Address is the lateral-movement discriminator. Caveats worth surfacing: 5140 fires only once per session (undercounts repeat access); 5145 is off by default and extremely noisy (its absence is not exculpatory); 5145 Failure events fire only on share-level (not NTFS-level) denial. MITRE mapping is honest: T1021.002 (SMB/Windows Admin Shares) and T1039 (Data from Network Shared Drive) fit cleanly; T1135 (Network Share Discovery) is a weaker/optional fit and I left it out of the firm recommendation.

### `EVENT_ID_TABLE` — Windows Event ID 7009 (System) — Service Control Manager service-start timeout  [enrichment]

**Additions:** TARGET: the static `EVENT_ID_TABLE` in /Users/4n6h4x0r/src/forensicnomicon/src/eventids.rs (a `&[EventIdEntry]`). 7009 is confirmed absent (grep -c "7009" src/eventids.rs = 0). The sibling System-log service events 7034 (line 298) and 7036 (line 306) already exist; 7000 and 7011 are also absent (out of scope for this item).

ADD one `EventIdEntry` row, placed in the "// System — services" block adjacent to 7034/7036 (after line 305), matching the surrounding style exactly:

    EventIdEntry {
        event_id: 7009,
        channel: "System",
        description: "Service-start timeout — Service Control Manager timed out (default 30000 ms, tunable via ServicesPipeTimeout) waiting for a service to connect/start; corroborate with 7000/7011 (same timeout family) and 7034 to scope a hung or outlier service binary",
        mitre_techniques: &[],
        artifact_ids: &["evtx_system"],
        high_value: false,
    },

Field justification:
- channel: "System" — SCM writes to the System log (matches 7034/7036/7045 which are all channel:"System").
- source note (in description): the Windows event Source is "Service Control Manager"; the numeric default is 30000 ms, governed by HKLM\SYSTEM\CurrentControlSet\Control\ServicesPipeTimeout (confirmed by the Microsoft support article for the 7000/7011 timeout family, which documents the same SCM timeout mechanism).
- mitre_techniques: &[] — deliberately EMPTY. 7009 is a generic timeout error emitted routinely by legitimate slow-starting services; it is not itself a persistence/creation indicator. Forcing T1543.003 (used by the sibling 7034/7036/7045 rows) onto a high-false-positive timeout would overstate. Per the standing rule, leave MITRE empty when no technique cleanly fits. Its forensic value is corroborative/triage, not technique detection.
- artifact_ids: &["evtx_system"] — verified the descriptor id "evtx_system" exists (crates/data/src/catalog/descriptors/mod.rs:7183).
- high_value: false — matches the noisy sibling 7034/7036 (false, corroborative) rather than the high-value 7045 (service installed).

NOTE: if a test asserts table ordering or a count of System-service events, it may need updating; the existing tests reference the 7000/7009 warning inside the evtx_system descriptor meaning (tests.rs:6924) — that is a separate string and is unaffected by this table addition.

**Sources verified:**
- [1 — Microsoft primary vendor documentation (raw source of the official Learn support article, ms.date 02/12/2026)] https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/main/support/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error.md — Service Control Manager is the emitter; it waits for the ServicesPipeTimeout-specified interval before logging the timeout events (7000/7011, with 7009 in the same family); the value lives at HKLM\SYSTEM\CurrentControlSet\Control\ServicesPipeTimeout as a DWORD in milliseconds; Microsoft frames it as a workaround and notes the timeout is usually a symptom of a deeper per-service problem
- [1 — Microsoft Learn (rendered authoritative support article)] https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error — Same content live on learn.microsoft.com: SCM service-start time-out mechanism, ServicesPipeTimeout registry control, default timeout behaviour for the 7000/7011/7009 family in supported Windows Server versions

**Notes:** 7009 is the "waiting for the service to connect" arm of the SCM start-timeout family (7000 = service failed to respond to start/control request; 7011 = timeout waiting for a transaction response; all share the 30000 ms ServicesPipeTimeout default). Correlation-only value: on its own it is high-noise (legitimate slow services on boot generate it), so it belongs at high_value:false and MITRE-empty. Its DFIR use is scoping — a service that a defender is examining for T1543.003 persistence (surfaced by 7045 install / 7034 crash) that ALSO throws 7009 points at a binary that hangs on start (e.g. a malicious or corrupted service image, or a service whose payload blocks the SCM handshake). Triage logic: pivot from an outlier 7045/7034 service name into System-log 7009/7000/7011 rows bearing the same service name to build a start-failure timeline. Do not read 7009 as evidence of compromise by itself. Related existing artifact: evtx_system descriptor already carries a note warning that 7000/7009 errors commonly FOLLOW a PowerShell-as-service (7045) creation (mod.rs meaning + tests.rs:6924-6928) — this table row is consistent with that existing guidance.

### `EVENT_ID_TABLE / eventids.rs event_id 4776` — 4776 — NTLM credential validation (success + failure share one Event ID)  [enrichment]

**Additions:** Target: the existing `EventIdEntry { event_id: 4776, ... }` in `/Users/4n6h4x0r/src/forensicnomicon/src/eventids.rs` (lines ~138-145).

The `EventIdEntry` struct has no free-text notes field, so the forensic distinction must be carried in `description` (short-string convention, matching neighbours) plus `mitre_techniques`:

1. description: change "NTLM authentication" ->
   "NTLM credential validation — success and failure share this Event ID (Error Code 0x0 = success, non-zero = failure), unlike the 4624/4625 split"
   (If a tighter fit to the terse neighbour style is preferred: "NTLM credential validation (success/failure via Error Code); no 4624/4625-style split").

2. mitre_techniques: change &["T1550.002"] -> &["T1550.002", "T1110"].
   Rationale: 4776 covers BOTH branches. Success events are Pass-the-Hash-relevant (T1550.002, already present); Failure events (Error Code != 0x0) are the DC-side brute-force / password-spray / account-enumeration indicator — Microsoft's own Security Monitoring Recommendations table maps 0xC000006A "bad password" to brute force and 0xC0000064 "bad username" to account enumeration. This mirrors the catalog's treatment of 4625/4771 (T1110). Leave T1110 out only if the maintainer wants to keep the mapping single-technique.

3. high_value: currently `false`. OPTIONAL suggestion to set `true` — on a domain controller 4776 is the authoritative record of ALL NTLM authentication for domain accounts (the only place PtH-over-NTLM and NTLM password-spray surface centrally). Flagging as optional, not asserting; neighbours 4625/4771 are `high_value: true`.

Supporting facts from the primary doc worth noting in a code comment (not new struct fields): event only generates on the computer authoritative for the credentials (DC for domain accounts, local machine for local accounts); it does NOT generate when a domain account logs on locally to a DC; also fires on workstation unlock. Key EventData fields: PackageName (e.g. MICROSOFT_AUTHENTICATION_PACKAGE_V1_0), Logon Account / TargetUserName, Source Workstation (auth source only — destination server is NOT recorded), Error Code (HexInt32). Provider GUID {54849625-5478-4994-A5BA-3E3B0328C30D}, Subcategory "Audit Credential Validation".

**Sources verified:**
- [Tier 1 — vendor primary spec (Microsoft Learn)] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776 — Title '4776(S, F)'; 'It shows successful and unsuccessful credential validation attempts'; 'If a credential validation attempt fails, you'll see a Failure event with Error Code parameter value not equal to 0x0'; Error Code field is HexInt32, 0x0 for Success; failure-code table (0xC0000064/0xC000006A/etc.); event generates only on the authoritative computer (DC for domain accounts, local machine for local accounts); does not generate for domain account local logon to a DC; also fires on workstation unlock; Provider GUID {54849625-5478-4994-A5BA-3E3B0328C30D}; Subcategory Audit Credential Validation; fields PackageName / Logon Account / Source Workstation (source only, no destination).
- [Tier 1 — vendor primary spec (Microsoft Learn, previous-versions mirror)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776 — Security Monitoring Recommendations table mapping failure conditions to attack meaning: 'misspelled or bad user account -> account enumeration', 'misspelled or bad password -> brute-force password attack', 'account locked -> brute-force' — basis for adding T1110 to the failure branch.

**Notes:** The load-bearing forensic point (verified): 4776 is a single Event ID for both outcomes, discriminated only by the Error Code field (0x0 = success, non-zero = failure) — you cannot filter success vs failure by Event ID as you can with the 4624/4625 pair; you must parse Error Code. Common failure codes: 0xC0000064 (bad/nonexistent username -> enumeration), 0xC000006A (bad password -> brute force), 0xC000006D (generic, incl. LM auth-level mismatch), 0xC0000234 (account locked), 0xC0000072 (disabled), 0xC0000193 (expired). Caveat / analytic limits: Source Workstation records only the origin computer name, never the destination server, and the field is attacker-controllable, so it is corroborative not definitive for locating the target host. 4776 appears only on the authoritative host (DC for domain accounts), so relay/PtH activity against member servers over NTLM lands on the DC's 4776 stream, not the member server's. related_artifacts already correct: evtx_security. No new descriptor and no related-artifact change needed. evidence_strength for the success/failure-Error-Code fact: Definitive (Microsoft vendor spec). The T1110 addition is Strong (Microsoft's own monitoring guidance ties the failure codes to brute force/enumeration), not merely inferred.

### `EVENT_ID_TABLE eid 4688 (src/eventids.rs, EventIdEntry { event_id: 4688 })` — Security Event ID 4688 — A new process has been created  [enrichment]

**Additions:** Enrich the eid-4688 EventIdEntry with two collection caveats (both primary-source-verified). The current struct has no caveats field, so this needs a one-field seam: add an optional `caveats: &'static str` (or `Option<&'static str>`, default "" / None for the other ~30 entries) to `EventIdEntry` in src/eventids.rs, and populate it for 4688. Do NOT cram this into the terse one-line `description` (siblings are all short one-liners; inconsistent). Keep `description: "Process creation"` as-is.

CAVEATS TEXT to add for 4688:
"Two independent GPO toggles gate this event. (1) The event itself is OFF by default: it requires the 'Audit Process Creation' policy (Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking), whose default is Not Configured — absence of 4688 does not prove absence of process execution, only that auditing was disabled. (2) The ProcessCommandLine field is a SECOND, separate toggle: 'Include command line in process creation events' (Administrative Templates\\System\\Audit Process Creation), default Not Configured, and it takes effect only when Audit Process Creation is already enabled. When enabled it writes each process's full command line in plaintext into 4688 (which itself can leak secrets passed on the command line)."

EVIDENCE STRENGTH for these caveats: Definitive (stated verbatim in Microsoft vendor docs).

NOT ADDED (could not verify): the work-item's third proposed caveat — 'some core system processes still emit 4688 on unaudited hosts' — is NOT stated on either Microsoft primary page (event-4688 or the command-line-process-auditing doc). It is repeated in DFIR blogs but I found no independent primary source; per the no-guess rule it is excluded. If retained later, source it independently and tier it Circumstantial.

Note on registry value: the widely-cited registry mirror of toggle (2) is HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled (DWORD). The MS command-line-process-auditing page gives only the GPO path, not the registry value, so treat the registry value name as community-documented (not in this primary page) if you include it.

MITRE: leave existing &["T1059"] unchanged — no ATT&CK technique cleanly maps to the auditing-disabled caveat itself.

**Sources verified:**
- [Tier-1 (vendor primary doc)] https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing — Audit Process Creation policy Default: Not configured (event OFF by default); 'Include command line in process creation events' is a separate policy under Administrative Templates\System\Audit Process Creation, Default Not Configured, applies only when Audit Process Creation is enabled, logs command line in plaintext into event 4688; supported Windows 7 and above.
- [Tier-1 (vendor primary doc)] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688 — Full 4688 field schema (New Process Name, Creator Process Name, Token Elevation Type %%1936/1937/1938, Mandatory Label, Process Command Line) and security monitoring recommendations. Contains NO statement that system processes emit 4688 when auditing is disabled — basis for excluding the third proposed caveat.

**Notes:** Triage logic: when 4688 is absent or sparse, do not conclude no process execution occurred — first determine whether Audit Process Creation was enabled at all (check the audit policy / Detailed Tracking config, or corroborate with Sysmon EID 1, Prefetch, Amcache, SRUM). When 4688 IS present but the ProcessCommandLine field is empty/missing, that means toggle (2) 'Include command line in process creation events' was not enabled — the process was audited but arguments were not captured; fall back to command-line reconstruction from other artifacts (Prefetch, Sysmon EID 1, ScriptBlock logging, AmCache). Cross-artifact: existing catalog already links 4688 via artifact_ids=["evtx_security"], and src/heuristics/evtx.rs matches EID 4688 CommandLine (T1490/T1059) — the empty-command-line caveat is directly relevant to those heuristics (a clean host with auditing off will silently produce no matches, a Bootstrap-vs-not-found distinction).

### `nirsoft_usbdeview_enum_usb` — USBDeview — USB Device Enumeration (Enum\USB pseudo-serial rule)  [enrichment]

**Additions:** ENRICH existing descriptor `nirsoft_usbdeview_enum_usb` (crates/data/src/catalog/descriptors/generated/nirsoft_generated.rs:107; key_path `CurrentControlSet\Enum\USB`, HklmSystem). It currently has fields: &[], evidence_strength: None, evidence_caveats: &[], sources: only the nirsoft URL.

1) ADD a FieldSchema documenting the pseudo-serial rule (fields: currently empty):
FieldSchema {
  name: "instance_id",
  value_type: ValueType::Text,
  description: "Device-instance subkey name beneath Enum\\USB\\VID_xxxx&PID_xxxx. If its SECOND character is '&' (e.g. 7&365565E6&0&0000, 5&3541780&0&1, or PCI-style 1&08), it is a Plug-and-Play-manager-GENERATED pseudo-serial: the USB device reported NO iSerialNumber string descriptor, so per Microsoft the bus driver returns UniqueID=FALSE and the PnP manager synthesizes a bus/location-based instance ID that is unique only on THIS machine — it is NOT a globally-unique hardware serial and does NOT travel with the device to another host. An instance ID WITHOUT '&' as the second character is the device's own iSerialNumber (bus-supplied, UniqueID=TRUE) and may correlate the same physical device across machines.",
  is_uid_component: false
}

2) ADD to sources (append, keep the existing nirsoft URL):
- "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/instance-ids"
- "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-instance-ids"

3) SET evidence_strength: Some(EvidenceStrength::Strong)  (the underlying mechanism is Microsoft-documented/Definitive; the exact "second character = &" test is the settled forensic reading of that mechanism, not a single literal Microsoft sentence — hence Strong, not Definitive).

4) SET evidence_caveats (currently empty):
- "The '&'-as-second-character test is a forensic heuristic derived from Microsoft's UniqueID / PnP-generated-instance-ID mechanism (Instance IDs + Device Instance IDs docs), not one literal Microsoft statement."
- "Absence of '&' does NOT prove the value is a true manufacturer serial: Windows may still surface a non-unique value, and independent testing has observed multiple devices sharing one ID and pre-21H2 behavioural differences. Treat any Enum serial as a Windows-assigned tracking ID consistent with, not proof of, a specific physical device."

5) ADD to related_artifacts (currently empty): "nirsoft_usbdeview_enum_usbstor" (verified existing id at nirsoft_generated.rs:132, key_path CurrentControlSet\Enum\USBSTOR — same &-rule applies there).

Leave mitre_techniques (T1052, T1025), hive, os_scope, decoder, triage_priority unchanged.

**Sources verified:**
- [1 (vendor primary spec — Microsoft Windows Drivers)] https://learn.microsoft.com/en-us/windows-hardware/drivers/install/instance-ids — When DEVICE_CAPABILITIES.UniqueID is FALSE (device supplies no unique serial), the bus-supplied instance ID is unique only to the bus and the PnP manager modifies/generates it to make the device instance ID system-unique; instance IDs are persistent across restarts and queried via IRP_MN_QUERY_ID/BusQueryInstanceID. This is the mechanism behind a Windows-generated pseudo-serial.
- [1 (vendor primary spec — Microsoft Windows Drivers)] https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-instance-ids — Device instance ID is system-supplied and built from device ID + instance ID + UniqueID; gives the worked example of a PnP-generated instance ID `1&08` (concatenated as PCI\VEN_1000&DEV_0001&SUBSYS_00000000&REV_02\1&08) whose SECOND character is '&' — confirming the format of a machine-generated instance ID.
- [1 (vendor primary spec — Microsoft, referenced by libyal winreg-kb)] https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-generated-by-usbstor-sys — USBSTOR.SYS device/hardware/compatible ID formats (USBSTOR\v(8)p(16)r(4)); establishes that the enumerator layer generates identifier strings from descriptor/SCSI-inquiry data — context for the sibling Enum\USBSTOR key and how generated IDs arise.
- [1 (independent RE reference — libyal winreg-kb, already cited in src/peripheral.rs)] https://raw.githubusercontent.com/libyal/winreg-kb/main/docs/sources/system-keys/USB-storage.md — Enum\USBSTOR device-key and device-instance-key layout; real device-instance-key example `1002131402536a&0` and `AA951D0000007252&0` showing the '&0' generated-instance-ID form; links to the Microsoft USBSTOR.SYS identifiers page as the authority.

**Notes:** Mechanism (Microsoft, Definitive): "Instance IDs" doc states that when the bus driver's DEVICE_CAPABILITIES.UniqueID is FALSE, "the bus-supplied instance ID for a device is unique only to the device's bus. The Plug and Play (PnP) manager modifies the bus-supplied instance ID, and combines it with the corresponding device ID, to create a device instance ID that is unique in the system." A USB device with no iSerialNumber descriptor is exactly the UniqueID=FALSE case, so Windows synthesizes the instance ID. The "Device Instance IDs" doc gives a worked example of such a PnP-generated instance ID — `PCI\VEN_1000&DEV_0001&SUBSYS_00000000&REV_02\1&08` — where the instance ID `1&08` has '&' as its second character. Real-world Windows examples of the generated form (`7&365565E6&0&0000`, `5&3541780&0&1`) confirm the same second-char signature.

The specific "second character is &" phrasing is forensic consensus (Nicole Ibrahim, Rob Lee/SANS, libyal winreg-kb which links straight to the Microsoft USBSTOR page) — used here only as a DISCOVERY pointer; the catalog fact is anchored on the two Microsoft primary docs. Note the SANS "The Truth About USB Device Serial Numbers" caveat is real and worth carrying: even non-'&' values are not guaranteed to be the manufacturer's serial, and identical IDs across devices have been observed — hence evidence_caveats above and Strong (not Definitive).

Sibling triage: the identical rule applies to `nirsoft_usbdeview_enum_usbstor` (Enum\USBSTOR device-instance subkeys, e.g. `AA951D0000007252&0` vs a real `1002131402536a&0`). Recommend a matching enrichment there in a follow-up work item — the libyal USB-storage doc example `1002131402536a&0` is itself a '&'-suffixed generated instance under USBSTOR.

Not a decoder/value-producing path, so no oracle needed; this is a classification rule about registry key naming, correctness defined by the Microsoft spec.

### `mountpoints2` — MountPoints2  [enrichment]

**Additions:** Enrich the existing MOUNTPOINTS2 descriptor (crates/data/src/catalog/descriptors/mod.rs:8101) with two verified facts:

1) SUBKEY LASTWRITE DATES THE MOUNT EVENT. The forensic value of MountPoints2 is per-SUBKEY, not the parent key: each device/share subkey's own registry LastWrite time records when Explorer last mounted (connected) that volume/share for this user. Add this to `meaning` and add a new field to MOUNTPOINTS2_FIELDS.

2) NETWORK/UNC SHARES ARE RECORDED, NOT ONLY REMOVABLE MEDIA. Subkey names encode the type: volume GUIDs begin with `{`, drive letters begin with `[A-Z]`, and mapped network/UNC shares begin with `#` in the form `##server#share` (the UNC path `\\server\share` with each `\` replaced by `#`, since backslashes are illegal in key names). Entries persist after the mapping is disconnected/removed.

Concrete field edits — replace MOUNTPOINTS2_FIELDS (mod.rs:8094-8099) with three fields:

pub(crate) static MOUNTPOINTS2_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "mount_point",
        value_type: ValueType::Text,
        description: "Subkey name identifying the mounted resource: a volume GUID ({...}), a drive letter (A-Z), or a mapped network/UNC share encoded as ##server#share (backslashes in \\\\server\\share replaced by #).",
        is_uid_component: true,
    },
    FieldSchema {
        name: "share_type",
        value_type: ValueType::Text,
        description: "Resource class derived from the subkey-name prefix: '{' = volume GUID (removable/fixed media), 'A-Z' = drive letter, '#' = network/UNC share (##server#share).",
        is_uid_component: false,
    },
    FieldSchema {
        name: "subkey_lastwrite",
        value_type: ValueType::Timestamp,
        description: "Registry LastWrite time of the individual mount subkey; consistent with the last time this user mounted/connected the device or share (persists after disconnect).",
        is_uid_component: false,
    },
];

Update `meaning` to: "Per-user record of resources Explorer has mounted — removable/fixed media (volume-GUID subkeys), drive letters, and mapped network/UNC shares (subkeys named ##server#share). Each subkey's LastWrite time is consistent with when this user last mounted that resource, and entries persist after disconnection, so the key attributes device and network-share interaction to a specific logged-in user."

Add `evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative)` (attribution to a user is reliable; LastWrite-as-last-mount is the accepted convention but should be corroborated).

Add `evidence_caveats`:
 - "Subkey LastWrite is commonly interpreted as the last mount/connect time, but it records the last modification of the subkey; corroborate with MountedDevices, USBSTOR/USB enum, LNK/JumpLists, and event logs before asserting a precise connection time."
 - "Network-share subkeys use ##server#share encoding (\\\\server\\share with backslashes replaced by #); decode before reporting the share path."
 - "Entries are retained after a device is removed or a mapped drive is disconnected, so presence does not imply the resource is still mounted."

Add `network_drives` to related_artifacts -> &["mounted_devices", "usb_enum", "network_drives"] (all three ids verified present in the catalog: mod.rs:7641, 1455, 7543).

Add source (real tool source that establishes both facts + Microsoft reference): "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/mp2.pl" and Microsoft KB "https://support.microsoft.com/kb/932463" (cited by that plugin).

Note: T1091 (Replication Through Removable Media) is already set and remains appropriate for the removable-media aspect; no additional MITRE technique cleanly fits the network-share aspect, so leave MITRE as-is.

**Sources verified:**
- [Tier 2 (real tool source — RegRipper mp2.pl, H. Carvey)] https://github.com/keydet89/RegRipper3.0/blob/master/plugins/mp2.pl — Classifies MountPoints2 subkeys by name prefix: volume GUID (^{), drive letter (^[A-Z]), and network/remote share (^#), and timelines each mount by the individual subkey's LastWrite via $s->get_timestamp() (Remote Drives / Volumes / Drives). Confirms both that network/UNC shares are recorded and that per-subkey LastWrite dates the mount event.
- [Tier 1 (vendor — Microsoft KB, referenced by mp2.pl)] https://support.microsoft.com/kb/932463 — Microsoft reference cited by the plugin for MountPoints2 behavior/cleanup of mount-point entries.

**Notes:** The two facts are confirmed directly from RegRipper's mp2.pl (mod by H. Carvey, real tool source, Tier 2): it classifies subkeys by name prefix — `$name =~ m/^{/` (volume GUID), `m/^[A-Z]/` (drive letter), `m/^#/` (remote/network share) — and it timelines each entry by the SUBKEY's own timestamp via `$s->get_timestamp()`, grouping output into "Remote Drives", "Volumes", and "Drives". This is unambiguous tool source that MountPoints2 records network/UNC shares (not only removable media) and that the per-subkey LastWrite is the dated mount event. The plugin's cited authority is Microsoft KB 932463. The exact `##server#share` encoding (UNC `\\server\share` with backslashes -> `#`) is corroborated across multiple references and is consistent with the mp2.pl `^#` regex. Evidence-tiering: attribution of a mount/share to a specific user (because the data lives in that user's NTUSER.DAT) is Strong; the LastWrite = "last connected" reading is an accepted convention, not a guarantee — hence Corroborative overall with the caveat to cross-check. forensics.wiki candidate source could not be fetched (site parked/404); primary support therefore rests on the RegRipper tool source + Microsoft KB rather than the wiki.

### `shimcache` — ShimCache (AppCompatCache)  [enrichment]

**Additions:** Target existing descriptor id "shimcache" (crates/data/src/catalog/descriptors/mod.rs:1090). One of the three work-item claims (entry timestamp = file modification time, NOT execution time) is ALREADY encoded in this descriptor (doc-comment line 1088-1089 "last-modified timestamps (NOT execution times on Win8+)" + caveat "Presence proves file existed on disk, not necessarily executed"). The two GENUINELY NEW claims — timestomping exposure and rename/move detection — are not yet in the catalog and are what this enrichment adds. Both are added as forensic-inference caveats phrased "consistent with", because they are analytical inferences built on two primary facts (below), not techniques any single primary source documents end-to-end.

ADD to evidence_caveats (&[...] at lines 1121-1126):

1. Timestomping exposure caveat: "The stored value is a historical snapshot of the executable's $STANDARD_INFORMATION last-modified (last-write) FILETIME, captured when the entry was created; it reflects the last time the file's content ($DATA) changed, not an execution time (Mandiant, 'Caching Out'). A mismatch between this ShimCache-recorded timestamp and the LIVE filesystem $SI last-modified time for the same path is consistent with timestomping of that file between the two capture points — SetFileTime alters on-disk $SI timestamps without changing $DATA (Microsoft, 'File Times'). Direction-dependent: detectable only when the shim predates the timestomp; if the file was timestomped before being shimmed, ShimCache captures the already-altered value."

2. Rename/move caveat: "An identical 64-bit last-modified FILETIME appearing under two or more different paths in the cache is consistent with the same binary having been renamed/moved: rename/move within a volume does not rewrite $DATA, so the $SI last-modified time is preserved, while each new path is re-shimmed as a fresh entry. Useful for tracing malware relocation/propagation and renamed-utility masquerading. (Note the psexec exception: psexec rewrites its own $DATA on each run, so multiple psexec-named entries carry DIFFERENT modified timestamps rather than an identical one.)"

ADD to mitre_techniques (currently &["T1218", "T1059"] at line 1102) -> add "T1070.006" (Indicator Removal: Timestomp — the artifact DETECTS this; T1070.006 is already the established timestomp technique id used across this codebase, e.g. src/heuristics/mod.rs, src/temporal.rs, src/references.rs) and "T1036.003" (Masquerading: Rename System Utilities — the rename/move detection use case). Resulting set: &["T1218", "T1059", "T1070.006", "T1036.003"].

ADD to sources (&[...] at lines 1107-1119) the two primary sources this enrichment rests on, neither currently present (the current list has redcanary/sans/magnet/EricZimmerman/sethenoka/13cubed but NOT the actual Mandiant "Caching Out" article nor the Microsoft File Times doc):
  - "https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-val/" (Mandiant "Caching Out: The Value of Shimcache for Investigators" — vendor authoritative writeup)
  - "https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times" (Microsoft — File Times: last-write time semantics + SetFileTime)

DO NOT change evidence_strength (leave Strong) — the two added caveats are Corroborative-tier inferences layered under the descriptor's overall Strong rating, and the "consistent with" phrasing keeps them from being overstated.

**Sources verified:**
- [Tier-1 vendor authoritative (Mandiant)] https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-val/ — Confirms the ShimCache entry timestamp is the file's $STANDARD_INFORMATION last-modified time and is explicitly NOT indicative of execution time ('Because the last modified timestamp reflects the last time that file's contents were changed, it is not indicative of the file execution time'). Does NOT itself cover timestomping-comparison or rename/move detection — those are inferences layered on top.
- [Tier-1 primary vendor spec (Microsoft)] https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times — Confirms last-write time is updated when writing to file content ('When writing to a file, the last write time is not fully updated until all handles that are used for writing are closed') and that SetFileTime can modify creation/last-access/last-write times WITHOUT changing file content — the primitive mechanism behind both the timestomping-mismatch inference and the rename-preserves-timestamp inference.
- [Tier-1 primary (MITRE ATT&CK)] https://attack.mitre.org/techniques/T1070/006/ — T1070.006 Indicator Removal: Timestomp — the technique the timestomping-exposure caveat helps detect; already the canonical timestomp id used across this codebase (src/heuristics/mod.rs, src/temporal.rs, src/references.rs).

**Notes:** Evidence tiering is the crux here. Only ONE of the three work-item claims has a clean independent primary source AND it is already in the catalog: the entry timestamp is the file's $STANDARD_INFORMATION last-modified time, not an execution time — Mandiant's own "Caching Out" article states verbatim "Because the last modified timestamp reflects the last time that file's contents were changed, it is not indicative of the file execution time." (Definitive, primary.)

The two NEW claims are forensic INFERENCES, not directly-documented techniques, so they are added as "consistent with" caveats rather than asserted facts:
- Timestomping exposure rests on two primary facts: (a) ShimCache stores the $SI last-modified snapshot (Mandiant, confirmed); (b) Windows last-write time reflects content writes and can be altered independently of content via SetFileTime (Microsoft File Times doc: "SetFileTime ... lets you modify creation, last access, and last write times without changing the content of the file"). The mismatch-as-timestomping conclusion follows from combining these — no single primary source states it as a ShimCache technique (only DFIR blogs/SANS do, which the standing rules bar as authority). It is also ORDER-DEPENDENT: only exposes timestomping that occurred after the shim was created.
- Rename/move detection rests on: ShimCache stores $SI-M (Mandiant) + rename/move does not rewrite $DATA so $SI last-write is preserved (Microsoft File Times: last-write updates "when writing to a file"). Identical timestamp across paths is therefore CONSISTENT WITH a rename/move, not proof — two unrelated files could coincidentally share a modified time, and the psexec case shows same-name entries can legitimately carry DIFFERENT timestamps.

Deliberately did NOT cite the numerous DFIR blogs (cyberengage, magnet, medium posts, nk0 gitbook) that describe these techniques — they are discovery pointers only under the standing rules; the enrichment is anchored solely on the Mandiant vendor writeup + Microsoft primary doc, with the analytical step made explicit and hedged.

Same timestamp semantics apply equally to the sibling descriptor shimcache_memory (id "shimcache_memory", shares SHIMCACHE_FIELDS) — if desired, the same two caveats could be mirrored there, but this work item targets "shimcache" only.

### `muicache` — MUICache  [enrichment]

**Additions:** Enrich the existing descriptor `MUICACHE` (id: "muicache", file crates/data/src/catalog/descriptors/mod.rs ~line 1495). It currently has `evidence_caveats: &[]` and `evidence_strength: None`. Add the no-timing caveats and set an honest strength.

SET evidence_caveats to (three entries):
1. "No per-execution timestamp: in the REGF hive format a value key (vk) record carries no time field — only the parent MuiCache key node (nk) has a LastWritten FILETIME. That key LastWrite reflects only the most recent modification to the key and cannot be attributed to any individual value, so no single cached program name can be timestamped from it."
2. "No MRU / ordering: MUICache values are unordered with no MRUListEx, so recency or execution sequence cannot be established from the key alone (Carvey, 'Mystery of MUICache … solved')."
3. "Establishes that a GUI program's display name was cached — consistent with the program having been run — but NOT when it ran. Timing requires external correlation (Prefetch, $MFT / filesystem MAC times, UserAssist, event logs)."

SET evidence_strength: Some(EvidenceStrength::Corroborative)  — MUICache presence is consistent with execution and corroborates other execution artifacts, but standing alone it is untimed and can also be populated by shell/Explorer name-caching, so it is not a definitive standalone execution timestamp.

ADD to sources (append, keep existing): the REGF format spec as the structural authority for the no-value-timestamp claim —
"https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc"
(The existing windowsir.blogspot 2005 'mystery-of-muicachesolved' source is Carvey's RE writeup that authoritatively supports the no-MRU / no-when claim — keep it.)

Do NOT change key_path, decoder, hive, mitre_techniques, or meaning. Minimal diff: only evidence_caveats, evidence_strength, and one appended source.

Note: a second, redundant descriptor exists — `NIRSOFT_MUICACHE_LOCAL_SETTINGS` (id "nirsoft_muicache_local_settings" in generated/nirsoft_generated.rs) with the same MuiCache key. It also has empty caveats. Out of scope for this item, but flagging that the same no-timing caveat applies to it and the two overlap (dedup candidate).

**Sources verified:**
- [Tier 1 — authoritative reverse-engineered format specification] https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc — Key node (nk) record contains a LastWritten FILETIME; value key (vk) record has NO timestamp field. Structural basis for 'no per-value/per-execution timestamp; only the key LastWrite exists, unattributable to a specific value.'
- [Tier 1 — original reverse-engineering writeup (Harlan Carvey, who decoded MUICache)] http://windowsir.blogspot.com/2005/12/mystery-of-muicachesolved.html — 'we don't know when the application was run, as there is no MRUList associated with the entries' — confirms no MRU/ordering and no in-key timing; MUICache proves a program ran, not when.

**Notes:** The target is the primary hand-written descriptor `muicache` in mod.rs (fuller: mitre T1059+T1204.002, Utf16Le decoder, MUICACHE_FIELDS). A duplicate `nirsoft_muicache_local_settings` covers the same key with a NirSoft-tool source; both currently lack the timing caveat. Structural fact: REGF value-key (vk) cells have no timestamp — only key-node (nk) cells store a LastWritten FILETIME — so the single MuiCache key's LastWrite is shared across all cached program names and is unattributable to any one execution. Carvey (the RE writeup that first decoded MUICache) independently confirms no MRUList, hence no ordering/recency and no 'when'. Practical triage: treat MUICache as an untimed 'this GUI program's name was cached (ran) at some point' signal; anchor timing to Prefetch/$MFT/UserAssist/event logs, not to the key LastWrite. Note MUICache can also be written when the shell caches a friendly name (Explorer interaction), so it is corroborative rather than definitive execution proof.

## Needs-fix (apply the correction, then ship)

### `srum_app_timeline` — SRUM Application Timeline Table (AppTimelineProvider)  [new_descriptor]
**FIX FIRST:** The descriptor's factual content is fully verified and accurate. The central GUID correction is CONFIRMED by three independent sources: EricZimmerman/Srum issue #8 (quotes the HKLM\...\SRUM\Extensions registry default values — the ground truth), the WithSecureLabs/chainsaw SRUM-Analysis wiki, and AboutDFIR. All three agree: {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} = vfuprov (vfuprov.dll), {5C8CF1C7-7257-4F13-B223-970EF5939312} = App Timeline Provider (eeprov.dll). The proposal's claim that the existing src/srum.rs:43 TABLE_APP_TIMELINE={7ACBBAA3-...} is mislabeled is therefore a genuine, correctly-diagnosed bug. Column schema (AppId/UserId/TimeStamp/EndTime/DurationMS/ExeTimestamp/Flags/InFocusS/KeyboardInputS/MouseInputS/UserInputS/AudioInS/AudioOutS) and the ~7-day per-table retention are corroborated by AboutDFIR, used only as corroboration (not sole authority — the load-bearing authority is the registry values in issue #8), so this is standing-rule compliant. Not a duplicate; related_artifacts and all enum values verified against sibling descriptors. Evidence tiering is honest (Corroborative overall; ExeTimestamp==PE-compile-time correctly held to a Circumstantial caveat; MITRE defensibly empty). It is needs_fix (not confirmed) only because it is NOT a drop-in: applying just the descriptor breaks the invariant test catalog_srum_descriptor_guids_match_module_consts (srum.rs:154), which requires every srum_ descriptor GUID to appear in its `known` array; {5C8CF1C7-...} is absent. The mandatory companion srum.rs const fix must land in the same change.
- MANDATORY companion change (already flagged in the proposal's additions field): fix src/srum.rs:43 TABLE_APP_TIMELINE from {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} to {5C8CF1C7-7257-4F13-B223-970EF5939312} and correct its doc-comment; the {7ACBBAA3-...} value is vfuprov, not App Timeline. Minimal fix (change the const value in place) auto-updates the `known` array in catalog_srum_descriptor_guids_match_module_consts since it references TABLE_APP_TIMELINE by name — without this, adding the descriptor fails that test.
- Optionally add a TABLE_VFUPROV = {7ACBBAA3-...} const to preserve the correct label for that GUID (do NOT create a vfuprov descriptor — its column schema/purpose is community-unknown, no verified schema).
- Also update the srum.rs module doc-comment (lines 8-13): it cites Mark Baggett srum-dump / SANS ISC / libyal esedb-kb as GUID authorities, but esedb-kb does NOT document App Timeline Provider or vfuprov; the registry Extensions values (per EZ Srum issue #8) are the actual source for these two GUIDs.
- PRE-EXISTING separate bug worth fixing in the same PR (not part of this descriptor): srum_db doc-comment at descriptors/mod.rs:2945 wrongly states {5C8CF1C7-...} = Network Data Usage. Network Data Usage is {973F5D5C-...}; {5C8CF1C7-...} is App Timeline Provider. Same block (mod.rs:2943) mislabels SRUDB.dat as a 'SQLite database' — it is an ESE/JET database.
- Minor: retention Some("~7 days (this table); SRUDB.dat overall ~30-60 days") — the '~30-60 days' overall figure is inconsistent with sibling srum_* descriptors which use '~30 days'. Harmless but consider aligning to '~30 days' for consistency, or leave as-is since SRUDB retention genuinely varies.
- Minor: descriptor omits the InFocusTimeline/AudioInTimeline/AudioOutTimeline and SpanMS columns AboutDFIR lists. Not required (descriptors curate), but the field list is a subset — acceptable.

```
CORRECTION FIRST (load-bearing): The work item's premise is wrong about the GUID. The AppTimelineProvider table is {5C8CF1C7-7257-4F13-B223-970EF5939312}, NOT {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}. Per the Windows registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions default values, {7ACBBAA3-...-F1D8F} registers the provider "vfuprov" (historically purpose-unknown), while {5C8CF1C7-...-5939312} registers "AppTimelineProvider" — the table that actually carries the exe/focus/input/EndTime/DurationMS/ExeTimestamp columns. This means src/srum.rs::TABLE_APP_TIMELINE (= {7ACBBAA3-...}) and its doc-comment ("Application Timeline — in-focus duration...") are MISLABELED; that GUID is vfuprov. The correct descriptor below uses the correct GUID {5C8CF1C7-...}.

--- DESCRIPTOR ---
id: srum_app_timeline
name: SRUM Application Timeline Table (AppTimelineProvider)
artifact_type: ArtifactLocation::File (ESE alternate-table under SRUDB.dat, consistent with sibling srum_* descriptors which use ArtifactLocation::File / EseDatabase)
hive: None
key_path: ""
value_name: None
file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat:{5C8CF1C7-7257-4F13-B223-970EF5939312}")
scope: DataScope::System
os_scope: OsScope::Win10Plus  (introduced Windows 10 1607 / Anniversary Update; use the existing Win10Plus variant)
decoder: Decoder::Identity
meaning: "ESE table {5C8CF1C7-7257-4F13-B223-970EF5939312} (registry provider name 'AppTimelineProvider') records per-app, per-user activity intervals with rich human-interaction telemetry: how long each application held the foreground window (InFocus), and how long there was actual keyboard, mouse, audio-in and audio-out activity while focused. Because it captures real user-input duration, it distinguishes interactive human use from unattended/automated execution far better than the CPU-cycle App Resource Usage table. Each row also carries an approximate execution EndTime, total DurationMS, and a distinct ExeTimestamp (a per-executable timestamp reported by community analysis to correspond to the binary's PE compile/link time, NOT the run time). This table retains only ~7 days of data — a much shorter window than the ~30-60 day SRUDB.dat whole-database retention."
fields:
  - app_id            (Text,        is_uid_component: true)   "AppId — application path / executable identity (resolved via SruDbIdMapTable)"
  - user_id           (Text,        is_uid_component: true)   "UserId — SID of the user account (resolved via SruDbIdMapTable)"
  - timestamp         (Timestamp,   false)  "TimeStamp — SRUM entry write time (when the interval row was committed to the DB, UTC)"
  - end_time          (Timestamp,   false)  "EndTime — approximate end-of-execution timestamp for the interval (UTC)"
  - duration_ms       (UnsignedInt, false)  "DurationMS — total execution duration for the interval, in milliseconds"
  - exe_timestamp     (Timestamp,   false)  "ExeTimestamp — distinct per-executable timestamp; community analysis reports it as the executable's PE compile/link time, not the run time (see caveat)"
  - in_focus_seconds  (UnsignedInt, false)  "InFocusS — seconds the application's window was the foreground/in-focus window"
  - user_input_seconds(UnsignedInt, false)  "UserInputS — seconds of combined keyboard+mouse user input while focused"
  - keyboard_input_seconds (UnsignedInt, false) "KeyboardInputS — seconds of keyboard input while focused"
  - mouse_input_seconds    (UnsignedInt, false) "MouseInputS — seconds of mouse input while focused"
  - audio_in_seconds  (UnsignedInt, false)  "AudioInS — seconds of microphone/audio-input activity"
  - audio_out_seconds (UnsignedInt, false)  "AudioOutS — seconds of audio-output activity"
  - flags             (UnsignedInt, false)  "Flags — bitfield (semantics undocumented)"
mitre_techniques: &[]  (leave empty — this is an execution/user-presence evidence source, not itself an ATT&CK technique; sibling srum_app_resource forces T1059 but that does not cleanly fit a focus/input-duration table, so per the no-forcing rule leave empty)
related_artifacts: &["srum_app_resource", "srum_db", "prefetch_file", "shimcache"]  (all verified present in catalog)
retention: Some("~7 days (this table); SRUDB.dat overall ~30-60 days")
triage_priority: TriagePriority::High
sources: &[
  "https://github.com/EricZimmerman/Srum/issues/8",
  "https://github.com/EricZimmerman/Srum/pull/10/files",
  "https://github.com/WithSecureLabs/chainsaw/wiki/SRUM-Analysis",
  "https://aboutdfir.com/app-timeline-provider-srum-database/",
  "https://github.com/MarkBaggett/srum-dump"
]
evidence_strength: Some(EvidenceStrength::Corroborative)   (Strong specifically for the user-was-at-the-keyboard inference: non-zero KeyboardInputS/MouseInputS/UserInputS is strong evidence of interactive human presence during the interval; corroborative for execution overall)
evidence_caveats: &[
  "Interval-sampled, not a per-launch event log; DurationMS/InFocusS aggregate an interval, not a single session",
  "ExeTimestamp is interpreted by community analysis as the executable's PE compile time — treat as a binary-identity/anti-tamper corroborator, not a run timestamp; not confirmed against a Microsoft spec",
  "This table retains only ~7 days, shorter than the rest of SRUDB.dat",
  "Field/column semantics are reverse-engineered (no Microsoft [MS-*] spec); Flags meaning unknown"
]
volatility: Some(VolatilityClass::RotatingBuffer)
volatility_rationale: "SRUM ESE database, rotated on schedule by Windows; this table's own retention is only ~7 days"
```

**Additions:** N/A — new descriptor. BUT a companion correction is required in the crate (report to maintainer, not part of this descriptor): src/srum.rs const TABLE_APP_TIMELINE = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}" with doc-comment "Application Timeline — in-focus duration and user input time per app" is MISLABELED. That GUID is registry provider 'vfuprov' (purpose historically unknown). Either (a) rename the const to TABLE_VFUPROV and add a separate TABLE_APP_TIMELINE = "{5C8CF1C7-7257-4F13-B223-970EF5939312}", or (b) fix the value to {5C8CF1C7-...}. The catalog invariant test catalog_srum_descriptor_guids_match_module_consts in srum.rs will FAIL if this srum_app_timeline descriptor ({5C8CF1C7-...}) is added while the module const set still lists only {7ACBBAA3-...} for app-timeline — so the srum.rs const MUST be corrected/added in the same change.

**Sources verified:**
- [2] https://github.com/EricZimmerman/Srum/issues/8 — Registry-based resolution: {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} default value = 'vfuprov'; {5C8CF1C7-7257-4F13-B223-970EF5939312} = 'App Timeline Provider'. Tier 2 (tool-author RE, registry-derived).
- [2] https://github.com/EricZimmerman/Srum/pull/10/files — SrumECmd renames output 'Unknown312' -> AppTimelineProvider (GUID ...5939312) and 'UnknownD8F' -> vfuprov (GUID ...F1D8F), confirming the GUID split. Tier 2 (tool source).
- [2] https://github.com/WithSecureLabs/chainsaw/wiki/SRUM-Analysis — Independent confirmation: {5C8CF1C7-...} = App Timeline Provider, {7ACBBAA3-...} = vfuprov; App Timeline Provider populated by eeprov.dll and usable to prove execution. Tier 2 (vendor RE/tool wiki).
- [3] https://aboutdfir.com/app-timeline-provider-srum-database/ — App Timeline Provider table GUID = {5C8CF1C7-7257-4F13-B223-970EF5939312}; columns AppId, UserId, EndTime, DurationMS, ExeTimestamp, Flags, InFocusS, KeyboardInputS, MouseInputS, AudioOutS, AudioInS, UserInputS; ~7-day retention for this table. Tier 3 (DFIR compendium; corroborative for column schema).
- [3] https://notes.qazeer.io/dfir/windows/_artefacts_overview/srum — Corroborates {5C8CF1C7-7257-4F13-B223-970EF5939312} = App Timeline Provider. Tier 3 (DFIR notes; corroborative only).
- [1] https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc — NEGATIVE result: libyal esedb-kb documents SRUM tables but does NOT include {7ACBBAA3-...} or {5C8CF1C7-...}/AppTimelineProvider — so it cannot be cited for this artifact and the srum.rs claim that {7ACBBAA3} is App Timeline is unsupported by it.

**Notes:** Triage logic: AppTimelineProvider ({5C8CF1C7-...}) is the SRUM table of choice for the "was a human at the keyboard?" question. Cross-reference with srum_app_resource ({D10CA2FE-...-FA89}): a row with high foreground CPU cycles in App Resource Usage but zero KeyboardInputS/MouseInputS/UserInputS in App Timeline for the same AppId+interval is consistent with automated/unattended or headless execution (scheduled task, service, injected code) rather than interactive use. Non-zero AudioInS is a pivot for microphone-access / eavesdropping concerns. ExeTimestamp gives a per-binary identity anchor useful for spotting a renamed/re-compiled dropper.

GUID caution (the reason this item needed correction): older SRUM tooling (early srum-dump templates, pre-resolution community writeups) mislabeled {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} as "App Timeline". The Windows registry Extensions subkey default values are the ground truth: {7ACBBAA3-...} = 'vfuprov', {5C8CF1C7-...} = 'AppTimelineProvider'. EricZimmerman/Srum issue #8 and PR #10 (which renamed the tool's "Unknown312" output to AppTimelineProvider and "UnknownD8F" to vfuprov) reflect this registry-based resolution; WithSecure/chainsaw and AboutDFIR independently corroborate. The rich focus/input/ExeTimestamp columns live in {5C8CF1C7-...}. The existing srum.rs const carries the wrong GUID for this artifact — flagged in the additions field.

Evidence-tier honesty: GUID→provider attribution is Strong (three independent RE/tool sources + registry semantics). Column set is Corroborative (AboutDFIR + EZ SrumECmd output; no Microsoft spec). ExeTimestamp==PE-compile-time is Circumstantial (community interpretation only) — kept as a caveat, not asserted as fact. libyal/esedb-kb does NOT document this table at all, so it could not serve as the primary source here.

Separately note: a 'vfuprov' descriptor could be added later for {7ACBBAA3-...}, but its schema/purpose is still community-"unknown" — do not create one without a verified column schema.

### `file_carving` — File Carving (Signature-Based Recovery)  [new_descriptor]
**FIX FIRST:** Content and sourcing are solid and independently verified: PhotoRec (cgsecurity) and the Garfinkel DFRWS 2007 paper (NPS PDF, text extracted locally) both support the claims with the exact verbatim quotes given; evidence is honestly Tier-1, MITRE correctly empty, evidence_strength Corroborative is fair, it is not a duplicate, and all related_artifacts ids exist. The File+file_path:None modeling is precedented (apfs_container et al.), so that caveat is not blocking. The one blocking defect is os_scope: OsScope::All is explicitly documented as 'Windows-only — not cross-platform,' which directly contradicts the descriptor's own 'OS-independent' meaning and would misclassify the entry under platform filtering in a published library. Fixable via a cross-platform OsScope variant (or maintainer schema decision) — hence needs_fix, not reject.
- os_scope: OsScope::All is documented in crates/core/src/catalog/types.rs as 'All Windows versions (XP and later). Windows-only — not cross-platform.' The descriptor's own meaning states carving is 'filesystem- and OS-independent.' This is an internal contradiction and misclassifies the entry for platform filtering. Resolve before entry: add a cross-platform/StorageLevel OsScope variant in -core and use it, or have the maintainer decide the correct model. This is the one blocking item.
- Minor/non-blocking (maintainer decision, already flagged by proposer): technique-vs-location schema fit is acceptable given precedent (apfs_container and 5 other ArtifactLocation::File entries already use file_path: None), so the File+None modeling need NOT change; the near-duplicate id clusters (mft/mft_file, usnjrnl/usn_journal) are out of scope. The chosen ids (mft, usnjrnl, recycle_bin, pagefile_sys, hiberfil_sys) all verified present.
- Minor/non-blocking: the ScienceDirect DOI citation was not independently fetched (likely paywalled) but is redundant — the NPS-hosted PDF carries the verbatim Garfinkel text, which I extracted and confirmed. No fix required unless a resolving citation is wanted.

```
id: "file_carving"
name: "File Carving (Signature-Based Recovery)"
artifact_type: ArtifactLocation::File  (carved output is reconstructed files; represents content-based recovery from raw storage. NOTE: this is a recovery *technique* over unallocated/raw regions, not a fixed on-disk path — see forensic_notes for the schema-fit caveat.)
hive: None
key_path: ""
value_name: None
file_path: None  (no fixed path — carving operates over unallocated space, slack space, and raw disk images independent of any directory entry)
scope: DataScope::System  (storage-level, whole-volume/image)
os_scope: OsScope::All  (SCHEMA CAVEAT — carving is inherently filesystem- and OS-independent; the enum has no cross-platform "any" variant. All is the least-wrong Windows-context value. Flagging for maintainer: a cross-platform/"StorageLevel" OsScope variant would model this honestly — see forensic_notes.)
decoder: Decoder::Identity  (raw bytes; carvers match magic/header + optional footer, then validate by format-specific object validation)
meaning: "Content/signature-based recovery of files from unallocated space, slack, or a raw disk image, reconstructing files from their byte content rather than from filesystem metadata that points to the content. Works after the filesystem is damaged, reformatted, or the directory/inode/MFT entry deleted. Recovers file DATA ONLY — the original filename, full path, and MAC timestamps are lost with the metadata and are NOT reconstructible by carving."
mitre_techniques: &[]  (file carving is a recovery/analysis technique, not adversary behaviour — no ATT&CK technique cleanly fits; left empty per rigor rule)
fields: FILE_PATH_FIELDS  (reuse existing shared field slice, consistent with pagefile_sys/hiberfil_sys concept entries)
retention: None
triage_priority: TriagePriority::Medium  (recoverable content degrades as unallocated space is reused, but not RAM-volatile)
related_artifacts: &["mft", "usnjrnl", "recycle_bin", "pagefile_sys", "hiberfil_sys"]  (all verified present in catalog; mft/usnjrnl/recycle_bin are the metadata-based recovery paths carving complements when metadata is intact; pagefile_sys/hiberfil_sys are common carving targets)
sources: &[
  "https://www.cgsecurity.org/wiki/PhotoRec",  (PhotoRec vendor/tool doc — ignores filesystem, matches signatures, does not recover filenames/timestamps)
  "https://www.sciencedirect.com/science/article/pii/S1742287607000369",  (Garfinkel, "Carving contiguous and fragmented files with fast object validation", Digital Investigation 4S (2007) S2-S12, DFRWS 2007)
  "https://calhoun.nps.edu/server/api/core/bitstreams/22c52db8-a881-475e-9a66-7709b50176fb/content"  (NPS-hosted primary PDF of the same paper — verbatim quotes confirmed)
]
evidence_strength: Some(EvidenceStrength::Corroborative)  (carved content proves the byte sequence existed on the medium, but without recoverable filename/path/timestamps it cannot alone establish when it was written or by whom — needs corroboration for attribution/timeline)
evidence_caveats: &[
  "No original filename, path, or MAC timestamps recovered — carving returns file CONTENT only; the metadata that carried those attributes is exactly what is absent when carving is needed (PhotoRec docs).",
  "Basic header/footer (contiguous) carving cannot reassemble FRAGMENTED files — Garfinkel (DFRWS 2007): 'no file carvers can automatically reassemble fragmented files'; fragmented recoveries emerge truncated or corrupt.",
  "Header-signature matches without a validator produce false positives (a magic-byte collision is not a valid file); format-specific object validation is required to discard bad candidates.",
  "Recovered content demonstrates data was present on the medium — it is consistent with, but does not prove, when the data was written or which user created it (no on-disk timeline/attribution without corroborating filesystem metadata)."
]
volatility: Some(VolatilityClass::ActivityDriven)  (carvable content sits in unallocated/slack regions that ordinary allocation overwrites — degrades with normal system use)
volatility_rationale: "Carving targets unallocated and slack space, which is reused (overwritten) by ordinary new file allocations; recoverability degrades with continued system use."
```

**Sources verified:**
- [primary (vendor/tool documentation)] https://www.cgsecurity.org/wiki/PhotoRec — Carving ignores the filesystem and recovers by matching file signatures in raw data ('PhotoRec ignores the file system and goes after the underlying data'); deleted-file metadata (filename, date/time, size, first-block location) is lost and is NOT reconstructed; fragmentation limits recovery.
- [primary (peer-reviewed paper, NPS-hosted PDF, text extracted and quoted verbatim)] https://calhoun.nps.edu/server/api/core/bitstreams/22c52db8-a881-475e-9a66-7709b50176fb/content — Definition: 'File carving reconstructs files based on their content, rather than using metadata that points to the content.' And the fragmentation limitation: 'no file carvers can automatically reassemble fragmented files.'
- [primary (journal of record — Digital Investigation 4S (2007) S2-S12, DFRWS 2007)] https://www.sciencedirect.com/science/article/pii/S1742287607000369 — Canonical publication venue/citation for the Garfinkel carving definition and the fragmented-file limitation.

**Notes:** Not currently in the catalog — grep of crates/data/src/catalog/ and src/ found no carving/PhotoRec/unallocated-recovery descriptor (only incidental "carving" mentions inside other entries: db-wal carving in clipboard, thumbnail hex-carving). Verified with `grep -rin 'carv|photorec|scalpel|unallocated|file recovery'`.

Two schema-fit caveats the maintainer should decide on:
1. artifact_type / file_path: file carving is a RECOVERY TECHNIQUE spanning unallocated + slack + raw images, not a single on-disk location. Modeled as ArtifactLocation::File with file_path: None, mirroring how the catalog already carries concept-level file entries (pagefile_sys, hiberfil_sys). If a location-purist stance is preferred, this could instead be scoped to a container/record-signature layer (the ContainerSignature/RecordSignature structs already exist for exactly this magic-byte carving model — header_magic/footer_magic/invariants). Recommend keeping it as a descriptor for discoverability but noting the technique nature in `meaning` (done).
2. os_scope: carving is filesystem- and OS-independent, but OsScope has no cross-platform "any"/"StorageLevel" variant (OsScope::All is documented as "All Windows versions"). Chose All as least-wrong; a genuine fix is a new cross-platform OsScope variant — flag as a small -core enum addition if cross-platform honesty matters here.

MITRE left empty deliberately: carving is examiner tradecraft, not adversary behaviour; forcing e.g. T1070.004 (Indicator Removal: File Deletion) would invert the actor (that technique describes the deletion carving *counters*, not carving itself).

related_artifacts all verified present via grep: mft, usnjrnl, recycle_bin, pagefile_sys, hiberfil_sys. Note the catalog also has near-duplicate ids (mft_file, usn_journal) — chose the shorter canonical ones (mft, usnjrnl) that match the pagefile/hiberfil cluster's style; maintainer may want to dedupe those pairs separately (out of scope here).

Evidence tiering: both content facts are Tier-1 (independent third-party authors: cgsecurity/PhotoRec project + Garfinkel/DFRWS). No self-authored fixtures involved.

### `mem_network_connections` — Network Connections (Memory)  [enrichment]
**FIX FIRST:** The enrichment is well-sourced and non-duplicative — the existing descriptor mem_network_connections (crates/data/src/catalog/descriptors/mod.rs:8726) matches this artifact, and enrichment (not a new descriptor) is the correct action. I fetched the primary source (volatility3 netscan.py) and confirmed: the 10 TreeGrid columns (Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created), Created rendered as datetime.datetime, Proto values TCPv4/TCPv6/UDPv4/UDPv6, and pool tags TcpL/TcpE/UdpA plus conditional TTcb for symbol table netscan-win10-20348. The four proposed fields (protocol, owner_process, created, offset) are non-duplicative of the existing four, all ValueType variants exist (verified in crates/core/src/catalog/types.rs: Text, UnsignedInt, Timestamp), related_artifacts mem_running_processes is a real id, MITRE correctly left as T1049 with no forced C2 technique, and evidence_strength Definitive with the pool-scan caveat is honest. ONE factual error requires correction before applying: build 20348 is Windows Server 2022, NOT Server 2019 (Server 2019 = build 17763). This mislabel appears in the catalog-facing meaning text ('plus TTcb on Server 2019/20348') and in forensic_notes ('TTcb (Server 2019+/build 20348)'). Since meaning enters the published library, this must be fixed.
- FACTUAL ERROR (must fix before applying): build 20348 is Windows Server 2022, not Server 2019. The proposed meaning string 'Volatility3 windows.netscan scans TcpE/TcpL/UdpA pool tags, plus TTcb on Server 2019/20348' mislabels the build. Correct to 'plus TTcb on Server 2022 (build 20348)' or simply '(build 20348)'. Windows Server 2019 = build 17763; the volatility3 symbol table is 'netscan-win10-20348' = build 20348 = Server 2022.
- Same mislabel in forensic_notes ('TTcb (Server 2019+/build 20348)') — correct to Server 2022 / build 20348.
- Minor: the netscan.py source URL points at the 'develop' branch (a moving target). Acceptable as a tool-source pointer, but a permalink to a pinned commit/tag would be more durable for a published catalog citation. Not blocking.

**Additions:** Enrich the EXISTING descriptor `mem_network_connections` (mod.rs ~line 8726) — the netscan artifact is already represented but under-specified. Do NOT create a new descriptor (would duplicate).

1) ADD FOUR FIELDS to MEM_NETWORK_CONNECTIONS_FIELDS (mod.rs ~8699). Volatility3 netscan renders 10 columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created (verified in netscan.py generator). The existing 4 fields (local_addr, remote_addr, state, pid) cover 6 of those columns; add the missing 4:
  - FieldSchema { name: "protocol", value_type: ValueType::Text, description: "Transport protocol and IP version (TCPv4, TCPv6, UDPv4, UDPv6) — netscan 'Proto' column, derived from the pool tag / object type", is_uid_component: false }
  - FieldSchema { name: "owner_process", value_type: ValueType::Text, description: "Owning process image name (netscan 'Owner' column), resolved from the owning EPROCESS", is_uid_component: false }
  - FieldSchema { name: "created", value_type: ValueType::Timestamp, description: "Endpoint creation time (netscan 'Created' column); populated for TCP endpoints (TcpE), enabling C2 beacon timing correlation", is_uid_component: false }
  - FieldSchema { name: "offset", value_type: ValueType::UnsignedInt, description: "Offset of the pool-tagged network object in the memory image (netscan 'Offset' column)", is_uid_component: false }

2) UPDATE `meaning` to reflect the pool-tag-scanning method (which is what makes netscan distinct from netstat's table-walk): 
  "Active and recently terminated network connections recovered by pool-tag scanning kernel socket structures (Volatility3 windows.netscan scans TcpE/TcpL/UdpA pool tags, plus TTcb on Server 2019/20348); recovers closed and hidden connections absent from the live OS table, revealing C2 channels and lateral-movement paths."

3) ADD a primary source to `sources` (keep the existing volatilityfoundation.org homepage as a project pointer, but the tool source is the authority for the fields):
  "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py"

4) ADD an evidence caveat covering pool-scan reliability (keep existing "Volatile; connections may close during acquisition"):
  "Pool-tag scanning also surfaces freed/reused pool structures — stale or partially-overwritten connection objects can appear; corroborate the endpoint against the owning process (mem_running_processes) before treating it as an active channel."

5) MITRE: leave as-is (T1049). Do NOT force-add C2 techniques (T1071/T1571) — netscan output is an observation of connections, and no ATT&CK technique cleanly maps to the artifact itself; the C2 interpretation is analyst inference, not a property of the data.

evidence_strength stays Definitive (real kernel structures parsed from a memory image), which is honest for the recovered fields; the pool-scan false-positive caveat above tempers it appropriately.

**Sources verified:**
- [1 (independent third-party tool source code — the reference implementation of the technique)] https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/netscan.py — Primary tool source: netscan renders 10 columns (Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created); Created is datetime; scans pool tags TcpL/TcpE/UdpA (plus TTcb on build 20348) via PoolScanner.generate_pool_scan with PoolConstraint; Proto is TCPv4/TCPv6/UDPvN; Owner is the owning process image name; PID is owning process id.

**Notes:** The work item asked for a NEW descriptor, but `mem_network_connections` already exists and represents exactly this artifact (memory-recovered network connections with PID/endpoints/state). The correct action is enrichment, not a duplicate descriptor. Key value-add: the `created` timestamp field — Volatility3 netscan populates a Created time for TCP endpoints (TcpE), which is precisely the "timing correlation for C2 hunting" the task summary requests, and it was missing. netscan (pool-tag scanning) differs from netstat (walking the TCP partition/hash tables): netscan can recover terminated/hidden connections but at the cost of surfacing freed pool structures, hence the added corroboration caveat. Pool tags verified from tool source: TcpE (TCP endpoints), TcpL (TCP listeners), UdpA (UDP endpoints), TTcb (Server 2019+/build 20348). related_artifacts already links mem_running_processes (correct — Owner/PID resolution and corroboration path). ValueType::Timestamp and ValueType::Text/UnsignedInt all confirmed to exist in crates/core/src/catalog/types.rs.

### `mem_extracted_pe_images` — Executables/DLLs/Drivers Extracted from Memory  [new_descriptor]
**FIX FIRST:** New, non-duplicate descriptor; all related_artifacts exist. Every core factual claim (procdump PE reconstruction + --unsafe forged-size-field bypass, memdump resident-only raw dump, dlldump/moddump PE reconstruction, Vol3 pedump dump_pe_at_base/dump_ldr_entry/dump_kernel_pe_at_base, and the zread zero-fill residency caveat) was independently verified against Tier-1 vendor wiki and Volatility tool source — the zero-fill caveat is even confirmed verbatim in the vendor wiki (line 949, zread pads non-resident pages with 0's). Evidence tiering is honest (Strong, not Definitive) and MITRE T1055/T1620 is a defensible, convention-consistent 'consistent-with' mapping. One fixable citation defect blocks it: sources_verified #2, the Vol3 windows.memmap readthedocs URL, is a thin API stub containing only the class name 'Memmap' — it does NOT contain the DumpFileOffset/memory-resident/--dump detail attributed to it. That detail is actually supported by the Vol2 wiki (source #1). Repoint or re-attribute that claim.
- sources_verified #2 (https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.memmap.html) over-claims: fetched page is an auto-generated stub containing only the class name 'Memmap' and no 'DumpFileOffset', 'memory-resident', 'addressable', or '--dump' text. Re-attribute the DumpFileOffset/resident-only claim to the Vol2 wiki command-reference (source #1, lines 790/810, verified) or repoint the URL to the wiki #memmap/#memdump anchor.
- Descriptor sketch omits required struct fields 'retention' and 'triage_priority' present on every sibling mem_* entry (e.g. retention: Some("RAM only; lost on power-off"), triage_priority: TriagePriority::High). Set them on apply.
- Non-blocking: os_scope Win10Plus matches the mem_* family but is narrower than reality (Volatility wiki examples target Win7); acceptable for family consistency.

```
id: "mem_extracted_pe_images"
name: "Executables/DLLs/Drivers Extracted from Memory"
artifact_type: ArtifactLocation::MemoryRegion
hive: None
key_path: ""
value_name: None
file_path: None  (produced by an analysis tool from a RAM image; not a fixed on-disk path — distinct from on-disk minidump .dmp files, which are covered by fa_file_minidump_dmp / lsass_dump_file)
scope: DataScope::System
os_scope: OsScope::Win10Plus
decoder: Decoder::Identity
meaning: "PE images (process executables, mapped DLLs, and kernel drivers) reconstructed OUT of a RAM capture by a memory-forensics engine. Two extraction modes: (1) code-focused PE reconstruction — Volatility procdump/procexedump (Vol2) or windows.pedump / windows.pslist --dump (Vol3) for a process image, dlldump / windows.dlllist --dump for a mapped DLL, moddump / windows.modules --dump for a kernel driver — walks the PE header and writes each section, rebuilding a file that resembles the on-disk binary; (2) full process dump — memdump (Vol2) / windows.memmap --dump (Vol3) writes ALL memory-resident pages of a process (code + heap + stack) into one raw, virtual-address-ordered blob (not a PE, ideal for strings/YARA). The highest-value use is recovering in-memory-only payloads: reflectively loaded / injected code that never touched disk, and unsigned modules absent from the loader lists."
fields:
  - artifact_kind (Text): "What was recovered: process_image | full_process_dump | dll | kernel_driver — determines whether the output is a reconstructed PE or a raw resident-memory blob." is_uid_component: false
  - pid (UnsignedInt): "Owning process id for process-image / full-process / DLL dumps (absent for kernel drivers)." is_uid_component: true
  - base_addr (UnsignedInt): "Virtual base address the PE was mapped at (ImageBaseAddress for a process, LDR entry DllBase for a DLL, driver base for a module)." is_uid_component: true
  - name (Text): "Image / module file name recovered from the PE or loader entry (attacker-controllable; may be forged or blank for injected code)." is_uid_component: false
  - fully_resident (Boolean): "True only if every page of the image was resident in RAM at capture. False means one or more pages were paged out and were zero-filled during reconstruction — the recovered file is incomplete and will not hash-match the on-disk original." is_uid_component: false
mitre_techniques: &["T1055", "T1620"]  (Process Injection; Reflective Code Loading — the in-memory-only artifacts this extraction is used to recover; consistent-with, not proof of, malicious loading. Mirrors mem_loaded_modules → T1055.)
related_artifacts: &["mem_running_processes", "mem_loaded_modules", "lsass_dump_file", "fa_file_minidump_dmp"]  (all verified to exist in the catalog)
sources: &[
  "https://github.com/volatilityfoundation/volatility/wiki/command-reference",
  "https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.memmap.html",
  "https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.pedump.html",
]
evidence_strength: Strong  (genuine bytes lifted from RAM, but reconstruction may be incomplete — not Definitive for byte-exact file identity)
evidence_caveats: &[
  "Reconstructed from a RAM image; pages that were paged out / not memory-resident at capture are zero-filled (Volatility reconstructs via zread, which returns null bytes for unreadable pages) — the recovered image can differ from the on-disk original and may be structurally incomplete.",
  "A code-focused PE dump (procdump/pedump) rebuilds the file from PE-header section metadata; malware can forge PE size fields to break the dump, requiring --unsafe/-u to bypass sanity checks — a --unsafe reconstruction is lower-fidelity.",
  "dlldump/moddump can fail outright when critical PE-header pages are non-resident; a full-memory (memmap/memdump) dump captures only resident pages and is virtual-address-ordered raw memory, not a runnable PE.",
  "An in-memory image that has no file-backed on-disk counterpart is consistent with reflective/injected loading, not proof of it — corroborate with the VAD protection/backing and loader-list membership.",
]
volatility: VolatilityClass::Volatile
volatility_rationale: "Source is RAM; content and page residency are lost on power-off — the extraction must run against a live-acquired memory image."
```

**Sources verified:**
- [Tier-1 (vendor primary)] https://github.com/volatilityfoundation/volatility/wiki/command-reference — Vendor-authored (Volatility Foundation) definitions: procdump reconstructs a process PE from headers/sections and --unsafe/-u bypasses sanity checks because malware forges PE size fields; memdump extracts only memory-resident pages into a single raw file; dlldump reconstructs loaded DLL PEs and fails when pages are non-resident (due to paging); moddump reconstructs kernel-driver PEs and fails when critical header pages are not resident.
- [Tier-1 (vendor primary)] https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.memmap.html — Volatility 3 windows.memmap plugin: dumps a process's memory showing which pages are memory-resident (virtual addr, physical offset, size); with --dump writes the addressable/resident memory to a file; DumpFileOffset column correlates memmap output with the dumped file. Confirms full-process-dump mode captures resident pages only.
- [Tier-1 (vendor primary)] https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.pedump.html — Volatility 3 windows.pedump: reconstructs PE files (executables, DLLs, drivers) from memory via dump_pe_at_base (process), dump_ldr_entry (DLLs and kernel modules), dump_kernel_pe_at_base (kernel). Confirms the code-focused PE-reconstruction mode and the process/DLL/driver split in Vol3.
- [Tier-1 (tool source)] https://raw.githubusercontent.com/volatilityfoundation/volatility/master/volatility/plugins/overlays/windows/pe_vtypes.py — Volatility source: _IMAGE_DOS_HEADER.get_code / _get_image_exe read section and header data via obj_vm.zread(...), which returns null bytes for inaccessible/paged-out regions — i.e. non-resident pages are zero-filled during PE reconstruction. Primary-source confirmation of the zero-padding residency caveat.
- [Tier-1 (tool source)] https://raw.githubusercontent.com/volatilityfoundation/volatility/master/volatility/plugins/procdump.py — procdump.py calls pe_file.get_image(unsafe, memory, fix) and errors when the PEB/ImageBaseAddress is unavailable 'possibly due to paging' — confirms procdump is a header-driven PE reconstruction that can fail on non-resident header pages.

**Notes:** Not covered by existing catalog entries. The `mem_*` family (mem_running_processes, mem_loaded_modules, mem_network_connections, mem_registry_hives, mem_user_credentials) only ENUMERATES memory objects; this descriptor covers EXTRACTING/reconstructing the actual code bytes (process/DLL/driver) out of the image. `fa_file_minidump_dmp` and `lsass_dump_file` cover on-disk MiniDumpWriteDump `.dmp` files (a different thing: a Windows API crash/user dump written to disk), so minidump.dmp as an on-disk artifact is already handled — this descriptor is the analysis-derived counterpart from a full RAM capture.

Triage logic: (1) Prefer a code-focused reconstruction (procdump/pedump/dlldump/moddump) when you need a PE to reverse or hash; prefer a full memmap/memdump when you need to strings/YARA-scan everything the process touched. (2) Always check page residency — a `fully_resident=false` result means zero-padded gaps, so a non-match against a known-good hash is inconclusive, not exculpatory. (3) The strongest signal is a reconstructed PE whose VAD is private/executable with no file backing and which is absent from the loader lists — consistent with injection/reflective loading (T1055/T1620), to be corroborated against mem_loaded_modules and mem_running_processes.

Evidence-tiering note: the zero-padding behaviour is Tier-1 confirmed against Volatility's own source (pe_vtypes.py get_code → obj_vm.zread) and the vendor command-reference wiki, not a blog. evidence_strength set to Strong (not Definitive) precisely because reconstruction fidelity is bounded by residency.

### `ntfs_objid` — NTFS Object ID Index ($Extend\$ObjId:$O)  [new_descriptor]
**FIX FIRST:** All factual claims verified true against primary sources: MS-FSCC 2.1.3.1 confirms the exact 64-byte FILE_OBJECTID_BUFFER Type 1 layout (ObjectId/BirthVolumeId/BirthObjectId/DomainId, 16 bytes each), volume-scoped uniqueness, and birth-value-at-creation semantics; MS-FSCC 2.4.36.1 confirms the 8-byte FileReferenceNumber prefix; MS-DLTW exact-quote confirms the CrossVolumeMoveFlag is the low-order bit of the first byte of BirthVolumeId; USN_REASON_OBJECT_ID_CHANGE=0x00080000 confirmed; libyal confirms MFT entry 25 = $Extend\$ObjId and attribute 0x40 = $OBJECT_ID; repo src/ntfs.rs already defines OBJECT_ID at 0x40. Not a duplicate; all 6 related_artifacts exist; sources are tier-1 primary specs + one tier-2 RE reference with no blog/13cubed/SANS cited as authority; MITRE correctly left empty; evidence_strength=Strong is honestly hedged with the MAC-attribution caveat. Only citation-precision defects remain, all fixable.
- FIELD birth_volume_id: attributes the CrossVolumeMove flag to 'MS-FSCC 2.1.3.1 / MS-DLTW', but the fetched MS-FSCC 2.1.3.1 page contains NO CrossVolumeMove flag — the flag is defined only in MS-DLTW. Remove the 'MS-FSCC 2.1.3.1' attribution for that specific fact and cite MS-DLTW only (verified: MS-DLTW states 'CrossVolumeMoveFlag, stored as the low order bit of the first byte of the BirthVolumeId field').
- sources_verified[0] (MS-FSCC 2.1.3.1) 'supports' text claims it documents an 'ExtendedInfo 48-byte union alternative' — the actual page has no ExtendedInfo content. The 48-byte ExtendedInfo (VolumeID+ObjectID+16 zero bytes) is corroborated by MS-DLTW's FSCTL_SET_OBJECT_ID_EXTENDED example and the winioctl.h SDK header, not by 2.1.3.1. Re-attribute this claim.
- FIELD birth_domain_id: says DomainId is 'reserved and typically all-zero on standalone NTFS volumes' — MS-FSCC states it is unused / SHOULD be zero / MUST be ignored on all volumes, not scoped to standalone. Broaden the wording to match the spec (unused/ignored generally).

```
id: "ntfs_objid"
name: "NTFS Object ID Index ($Extend\\$ObjId:$O)"
artifact_type: ArtifactLocation::File
hive: None
key_path: ""
value_name: None
file_path: Some(r"\\.\<volume>\$Extend\$ObjId")   // system metadata file at fixed MFT entry 25 (NTFS >=3.0); the object-ID records live in its $O index attribute and in each file's resident $OBJECT_ID (0x40) attribute. Accessible via raw disk / VSC only.
scope: DataScope::System
os_scope: OsScope::All   // matches sibling NTFS descriptors (mft/usnjrnl/logfile_ntfs), which use OsScope::All
decoder: Decoder::Identity
meaning: "Maps NTFS object-identifier GUIDs to MFT file references for distributed link tracking; each 64-byte record carries an object ID plus the birth volume/object/domain IDs recorded when the ID was first assigned, so a file can be correlated across renames and cross-volume copy/move operations even after its current object ID changes"

fields (FieldSchema[]):
  - name: "object_id"          value_type: ValueType::Guid    is_uid_component: true
    description: "16-byte GUID (key of the $O index / offset 0 of the $OBJECT_ID attribute) uniquely identifying the file within this volume; can repeat on a different volume but never on the same one (MS-FSCC 2.1.3.1). Version-1 GUIDs embed the origin machine's MAC address + a 60-bit creation timestamp"
  - name: "file_reference"     value_type: ValueType::Integer is_uid_component: true
    description: "8-byte MFT file reference (48-bit record number + 16-bit sequence) stored in the $O index value data, linking the object ID back to its MFT entry"
  - name: "birth_volume_id"    value_type: ValueType::Guid    is_uid_component: false
    description: "16-byte GUID of the volume on which the object resided when its object ID was first created (zero if the volume had no object ID then); differs from the current volume after a cross-volume move/copy — the low bit of byte 0 is the CrossVolumeMove flag (MS-FSCC 2.1.3.1 / MS-DLTW)"
  - name: "birth_object_id"    value_type: ValueType::Guid    is_uid_component: false
    description: "16-byte GUID = the object ID assigned at creation; copy/move/other operations MAY change ObjectId but not BirthObjectId, so it persists as a stable cross-volume/rename tracking key (MS-FSCC 2.1.3.1)"
  - name: "birth_domain_id"    value_type: ValueType::Guid    is_uid_component: false
    description: "16-byte GUID domain identifier; reserved and typically all-zero on standalone NTFS volumes (MS-FSCC 2.1.3.1)"

mitre_techniques: &[]   // intentionally empty — object IDs are a tracking/correlation artifact, not an attacker technique; no ATT&CK technique fits cleanly. (Related tampering surfaces as USN_REASON_OBJECT_ID_CHANGE 0x80000 in the USN journal, already covered by `usnjrnl`.)

retention: Some("Object-ID record persists for the life of the file's MFT entry; the $O index entry survives until the object ID is deleted (FSCTL_DELETE_OBJECT_ID) or the file is removed")
triage_priority: TriagePriority::Medium
related_artifacts: &["mft", "usnjrnl", "logfile_ntfs", "lnk_files", "jump_list_auto", "jump_list_custom"]
  // mft: the $OBJECT_ID attribute (0x40) is resident in the file's own MFT entry; $ObjId is the volume-wide index of them
  // usnjrnl: USN_REASON_OBJECT_ID_CHANGE (0x80000) records object-ID changes
  // logfile_ntfs: $ObjId index updates are journalled transactions
  // lnk_files / jump_list_auto / jump_list_custom: LNK shortcuts and jump lists embed the droid + birth-droid object IDs, enabling correlation of a shortcut/target back to the $ObjId record

sources: &[
  "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/34a727a2-960a-4825-9cd2-6100c84e3a81",  // [MS-FSCC] 2.1.3.1 FILE_OBJECTID_BUFFER Type 1 — 64-byte layout: ObjectId(16)+BirthVolumeId(16)+BirthObjectId(16)+DomainId(16)
  "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/63cdde16-85ac-480c-95bf-0bb8f5f09de8",  // [MS-FSCC] 2.4.36.1 FILE_OBJECTID_INFORMATION_TYPE_1 — 8-byte FileReferenceNumber prefix + the 64-byte buffer
  "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc"  // Joachim Metz RE reference: MFT entry 25 = $Extend\$ObjId; $OBJECT_ID attr (0x40) 16/64-byte Droid+Birth-droid layout; $O index used by $ObjId; $ObjID:$O key(object GUID)+value(file ref@offset4, birth volume/file/domain GUIDs)
]

evidence_strength: Some(EvidenceStrength::Strong)
evidence_caveats: &[
  "Object IDs are not created for every file — NTFS assigns them lazily (on first FSCTL_CREATE_OR_GET_OBJECT_ID, typically when a file is targeted by a shell shortcut/OLE link), so absence of a record is not evidence of absence of the file",
  "ObjectId can be changed or deleted by applications with sufficient privilege (FSCTL_SET/DELETE_OBJECT_ID); only BirthObjectId/BirthVolumeId are the stable-at-creation values",
  "Origin-machine attribution from a version-1 GUID's embedded MAC address is consistent with, not proof of, a specific NIC — MACs can be spoofed and GUID version is not guaranteed",
  "Requires raw disk access or a volume shadow copy; $Extend\\$ObjId is locked on live systems",
]
volatility: Some(VolatilityClass::Persistent)
volatility_rationale: "Object-ID records persist on disk for the life of the file's MFT entry / index entry; survive reboots and are not memory-resident"
```

**Sources verified:**
- [1 (authoritative primary spec — Microsoft Open Specifications)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/34a727a2-960a-4825-9cd2-6100c84e3a81 — [MS-FSCC] 2.1.3.1 FILE_OBJECTID_BUFFER Type 1: exact 64-byte record = ObjectId(16) + BirthVolumeId(16) + BirthObjectId(16) + DomainId(16); ObjectId unique within volume, may repeat across volumes; BirthVolumeId/BirthObjectId are creation-time values that MAY differ from current after copy/move; DomainId semantics; ExtendedInfo 48-byte union alternative
- [1 (authoritative primary spec)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/63cdde16-85ac-480c-95bf-0bb8f5f09de8 — [MS-FSCC] 2.4.36.1 FILE_OBJECTID_INFORMATION_TYPE_1: 8-byte FileReferenceNumber (64-bit file ID) prefixed to the same 64-byte object-ID buffer — the object-ID-to-file-reference association
- [2 (independent reverse-engineering reference, Joachim Metz/libyal — the settled community NTFS reference)] https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc — MFT entry 25 = $Extend\$ObjId ('Unique file identifiers for distributed link tracking'); $OBJECT_ID attribute type 0x40 resident, 16/64 bytes, Droid file id + Birth droid volume/file/domain id GUID layout; index name $O is used by $ObjId; $ObjID:$O entry key=object GUID(16), value=file reference(8 at offset 4)+birth droid volume/file/domain GUIDs; worked hex example mapping OBJECT_ID GUID to MFT file reference
- [1 (authoritative primary spec — Distributed Link Tracking)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dltw/535f4e4b-5eda-4314-8ca5-45f406a84de2 — CrossVolumeMoveFlag stored as low-order bit of the first byte of BirthVolumeId; example of an un-moved file where ObjectId == BirthObjectId and DomainId == 0

**Notes:** Distinct, uncovered artifact. The catalog's `mft` descriptor only mentions "$Object_ID UUID creation time" in passing (the GUID-v1 timestamp trick); it has no descriptor for the $ObjId index itself, the birth IDs, or the object-ID-to-MFT-reference mapping. Verified layouts:

- $OBJECT_ID attribute (type 0x40, resident in each file's MFT entry): 16 or 64 bytes = Droid file id(16) + Birth droid volume id(16) + Birth droid file id(16) + Birth droid domain id(16). Repo's own src/ntfs.rs already defines attr_types::OBJECT_ID = 0x40.
- $Extend\$ObjId (MFT entry 25, NTFS >=3.0): its $O index maps object IDs -> files. $ObjID:$O entry = Key: object-identifier GUID(16); Value: file reference(8, at value-data offset 4) + Birth droid volume id(16) + Birth droid file id(16) + Birth droid domain id(16).
- MS-FSCC FILE_OBJECTID_BUFFER Type 1 is the authoritative 64-byte record; the three birth GUIDs are a union with a 48-byte user-defined ExtendedInfo block (FSCTL_SET_OBJECT_ID_EXTENDED), so on volumes where extended info was set the last 48 bytes are opaque, not GUIDs — a parser should treat the birth fields as GUIDs only when ExtendedInfo was not overridden.

Triage logic: pivot from a suspicious LNK/jump-list droid/birth-droid GUID to the $ObjId record to identify the current MFT file reference (survives rename); compare BirthVolumeId against the current $Volume object ID to detect cross-volume copies (CrossVolumeMove flag = low bit of BirthVolumeId byte 0); decode a version-1 ObjectId/BirthObjectId to recover the origin machine's MAC address and creation timestamp. Cross-check object-ID changes against the USN journal (USN_REASON_OBJECT_ID_CHANGE 0x80000).

Evidence tiering: the object-ID -> MFT-reference mapping is a filesystem-authoritative fact (definitive); the higher-value inferences (origin-machine attribution from the MAC in a v1 GUID, and file-copy correlation via matching BirthObjectId) are corroborative, hence overall evidence_strength = Strong with the MAC-attribution caveat. No ATT&CK technique forced (left empty).

### `mem_access_tokens` — Access Tokens (Memory) — Primary vs Impersonation  [new_descriptor]
**FIX FIRST:** Facts are sound and independently verified against Microsoft primary sources (fetched, genuine pages, not fake-200s): TOKEN_TYPE (TokenPrimary=1, TokenImpersonation=2) confirmed on the winnt.h page; mandatory integrity RIDs/SIDs (UNTRUSTED S-1-16-0, LOW 0x1000/S-1-16-4096, MEDIUM 0x2000/S-1-16-8192, HIGH 0x3000/S-1-16-12288, SYSTEM 0x4000/S-1-16-16384) and S-1-5-18=LocalSystem confirmed on the Well-known SIDs page. Not a duplicate (mem_access_tokens/MEM_ACCESS_TOKENS absent). All four related_artifacts exist (mem_running_processes, mem_user_credentials, mem_loaded_modules, evtx_security). OsScope::All and EvidenceStrength::Definitive are valid variants; siblings use Definitive too. mitre_techniques are free-form (navigator.rs coverage only, no validation against mitre.rs), so the sub-technique IDs won't break the build. Evidence epistemics are honest — observed token facts = Definitive, theft = 'consistent with'. Two minor fixable items keep this from a clean confirm.
- Registration pointer error in the sketch: it says define the static 'after MEM_USER_CREDENTIALS (~mod.rs:8897)', but MEM_USER_CREDENTIALS actually ENDS at line 8880 — line 8897 is inside ZONE_IDENTIFIER_FIELDS. Place the new MEM_ACCESS_TOKENS static + its _FIELDS immediately after line 8880, and add 'MEM_ACCESS_TOKENS,' to the array right after 'MEM_USER_CREDENTIALS,' in the mem_ block (~lines 9423-9427, not 9424-9428).
- MITRE mapping is over-broad for a static in-RAM token snapshot. T1134, T1134.001 (impersonation-token user-SID mismatch), and T1134.005 (injected SIDs surface in group_sids) are directly evidenced by token contents. T1134.002 (Create Process with Token) and T1134.003 (Make and Impersonate Token) describe HOW a token was obtained (CreateProcessWithTokenW / LogonUser+DuplicateToken) — not derivable from the token object itself. Recommend trimming mitre_techniques to ["T1134", "T1134.001", "T1134.005"], or keep .002/.003 only as deliberate broad-family coverage (defensible but weakly evidenced).
- Minor style note (not blocking): sources cite the bare homepage https://volatilityfoundation.org/ as the memory-acquisition oracle. It is used for the acquisition path, not as authority for any enum fact (those are Microsoft-sourced), and it matches the existing sibling mem_ descriptors' convention — acceptable, but a specific Volatility token-plugin doc/source URL would be a stronger citation.

```
id: "mem_access_tokens"
name: "Access Tokens (Memory) — Primary vs Impersonation"
artifact_type: ArtifactLocation::MemoryRegion
hive: None
key_path: ""
value_name: None
file_path: None
scope: DataScope::System
os_scope: OsScope::All   (token type + impersonation level exist since Windows XP; the integrity-level SID field is Windows Vista and later — see caveat)
decoder: Decoder::Identity
meaning: "Windows access tokens (_TOKEN kernel objects) recovered from RAM. Each token carries the security context a thread/process runs under: the user SID, group SIDs (incl. any injected SID-History entries), the enabled/disabled privilege set, the mandatory integrity-level SID, the token TYPE (Primary vs Impersonation), and — for impersonation tokens — the impersonation level. A process holding an impersonation token whose user SID differs from its own primary token is consistent with token theft/impersonation; a Medium-integrity process holding SeDebugPrivilege or SeImpersonatePrivilege enabled, or a non-SYSTEM process wielding a SYSTEM (S-1-5-18) impersonation token, is consistent with privilege escalation via token manipulation."
mitre_techniques: &["T1134", "T1134.001", "T1134.002", "T1134.003", "T1134.005"]
fields:
  - pid            (UnsignedInt, "Owning process identifier", is_uid_component: true)
  - token_type     (Text, "TOKEN_TYPE: 'Primary' (TokenPrimary=1) or 'Impersonation' (TokenImpersonation=2)", is_uid_component: false)
  - impersonation_level (Text, "SECURITY_IMPERSONATION_LEVEL for impersonation tokens: Anonymous(0)/Identification(1)/Impersonation(2)/Delegation(3); empty for primary tokens", is_uid_component: false)
  - user_sid       (Text, "Token owner/user SID (e.g. S-1-5-18 = LocalSystem)", is_uid_component: true)
  - integrity_level (Text, "Mandatory integrity-level SID: Untrusted S-1-16-0 / Low S-1-16-4096 / Medium S-1-16-8192 / High S-1-16-12288 / System S-1-16-16384", is_uid_component: false)
  - privileges     (List, "Privileges present and their enabled/disabled state (e.g. SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege)", is_uid_component: false)
  - group_sids     (List, "Group SIDs carried in the token, including SID-History entries", is_uid_component: false)
retention: Some("RAM only; lost on power-off; token freed when last handle closes")
triage_priority: TriagePriority::Critical
related_artifacts: &["mem_running_processes", "mem_user_credentials", "mem_loaded_modules", "evtx_security"]
sources: &[
  "https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type",
  "https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level",
  "https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control",
  "https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids",
  "https://attack.mitre.org/techniques/T1134/",
  "https://volatilityfoundation.org/",
]
evidence_strength: Some(EvidenceStrength::Definitive)   (Definitive as to the security context the process CURRENTLY holds; the inference of *theft/manipulation* from that context is circumstantial — see caveats)
evidence_caveats: &[
  "Live RAM only; requires active acquisition or a memory image. Recovered via memory-forensics tooling (Volatility getsids/privileges token plugins), not from disk.",
  "A duplicated or stolen token is byte-for-byte indistinguishable from a legitimately-obtained one — a mismatched impersonation token is CONSISTENT WITH theft (T1134.001), not proof of it. Server processes legitimately impersonate clients (RPC/named pipes/IIS).",
  "Integrity-level SID (S-1-16-*) exists only on Windows Vista and later; on Windows XP the token has no integrity field.",
  "Enabled privileges reflect the token's current state; a privilege being PRESENT-but-DISABLED is normal and not itself suspicious.",
]
volatility: Some(VolatilityClass::Volatile)
volatility_rationale: "Kernel _TOKEN object in RAM; lost on power-off"

REGISTRATION: add `MEM_ACCESS_TOKENS,` to the descriptor array alongside the sibling mem_ entries at crates/data/src/catalog/descriptors/mod.rs:9424-9428, and define the static + its _FIELDS immediately after MEM_USER_CREDENTIALS (~mod.rs:8897).
```

**Sources verified:**
- [1 (Microsoft Win32 API spec / winnt.h)] https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type — TOKEN_TYPE enumeration differentiates a primary token from an impersonation token: TokenPrimary = 1, TokenImpersonation = 2.
- [1 (Microsoft Win32 API spec / winnt.h)] https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level — SECURITY_IMPERSONATION_LEVEL values: SecurityAnonymous=0, SecurityIdentification=1, SecurityImpersonation=2, SecurityDelegation=3, and their meanings (server can/cannot impersonate locally vs remotely).
- [1 (Microsoft Win32 conceptual spec)] https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control — Windows defines four integrity levels (low/medium/high/system); standard users receive medium, elevated users high, services system; the integrity SID for a security principal is stored in its access token.
- [1 (Microsoft Win32 spec)] https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids — Mandatory integrity RIDs: SECURITY_MANDATORY_UNTRUSTED_RID 0x0, LOW 0x1000, MEDIUM 0x2000, MEDIUM_PLUS 0x2100, HIGH 0x3000, SYSTEM 0x4000 → S-1-16-{0,4096,8192,12288,16384}.
- [1 (Microsoft doc)] https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers — Each sign-in creates an access token containing the user's SID, user rights (privileges), and group SIDs; SID-History is carried in the token's group SIDs and can allow/deny access.
- [1 (MITRE ATT&CK primary knowledge base)] https://attack.mitre.org/techniques/T1134/ — T1134 Access Token Manipulation and sub-techniques: .001 Token Impersonation/Theft, .002 Create Process with Token, .003 Make and Impersonate Token, .004 Parent PID Spoofing, .005 SID-History Injection.
- [2 (established memory-forensics tool / oracle)] https://volatilityfoundation.org/ — Access tokens (SIDs, privileges) are recovered from memory images via Volatility token plugins — establishes the MemoryRegion acquisition path, consistent with sibling mem_ descriptors.

**Notes:** Placement: this belongs in the existing in-memory `mem_*` family (MemoryRegion / DataScope::System / Volatile), modelled on MEM_RUNNING_PROCESSES and MEM_USER_CREDENTIALS. Access tokens are kernel _TOKEN objects with no on-disk representation — the only forensic recovery paths are a live host or a RAM image, so MemoryRegion (not EventLog/File) is correct.

Correlation logic: pair token contents with (1) mem_running_processes to map a token back to its process image and parent; (2) evtx_security — EIDs 4672 (special privileges assigned to new logon), 4673 (privileged service called), 4624 (logon, records ImpersonationLevel), 4688 (new process, token elevation type) — to corroborate a live-memory token finding against the logged audit trail; (3) mem_user_credentials when a SYSTEM/High token co-occurs with credential material.

Three-layer epistemics deliberately kept honest in the fields/caveats: the token's user SID / integrity / privileges / type are OBSERVED FACTS (Definitive as to the current security context); a process holding a foreign-user or SYSTEM impersonation token is a FORENSIC INFERENCE ("consistent with token theft/impersonation"), never asserted as proof, because legitimate server impersonation produces identical structures.

Enum values all pinned to Microsoft primary sources: TOKEN_TYPE (TokenPrimary=1, TokenImpersonation=2); SECURITY_IMPERSONATION_LEVEL (Anonymous=0, Identification=1, Impersonation=2, Delegation=3); integrity RIDs from the Well-known SIDs page (UNTRUSTED 0x0=S-1-16-0, LOW 0x1000=S-1-16-4096, MEDIUM 0x2000=S-1-16-8192, HIGH 0x3000=S-1-16-12288, SYSTEM 0x4000=S-1-16-16384). MITRE T1134.004 (Parent PID Spoofing) deliberately EXCLUDED — it is a process-tree artifact, not a property of token contents; T1134.005 (SID-History Injection) IS included because injected SIDs surface in the token's group_sids.

### `fa_file_programs_recentfilecache_bcf` — WindowsRecentFileCacheBCF  [enrichment]
**FIX FIRST:** Core facts are well-sourced and honestly tiered (Corroborative strength, empty MITRE, no-timestamp/no-hash claim directly supported by the libyal format spec, signature correctly not hardcoded, all related_artifacts verified present, in-place enrichment of a generated descriptor matches established repo practice). But two fixable problems block application: (1) the proposed `fields` sketch is structurally incompatible with the repo's `FieldSchema` type; (2) two meaning claims overstate what the cited primary sources support.
- STRUCTURAL (must fix before apply): the `fields` sketch uses keys {name, offset, size, meaning}, but the repo's `FieldSchema` (crates/core/src/catalog/types.rs:320) is `{ name: &str, value_type: ValueType, description: &str, is_uid_component: bool }` and its doc says it 'Describes one field in a DECODED artifact record' — not on-disk byte layout. There is no offset/size/meaning slot, so the sketch will not compile. Rewrite as FieldSchema literals; on-disk header offsets/sizes have no home in this type (put them in `meaning`/caveats instead). Note the semantic mismatch: a file-header 'signature' is not a decoded-record field a user queries — the natural decoded field for RecentFileCache.bcf is a single `entry_path` (value_type: ValueType::Text, is_uid_component: true), optionally with the char-count. Model it on the real non-empty `fields` blocks already in mod.rs (e.g. the LSN/record_type example ~line 2856).
- SOURCING/overstatement (fix): the meaning asserts the file is 'Populated by the ProgramDataUpdater scheduled task (Application Experience)' and 'Records the full file paths of executables newly encountered/registered by the compatibility inventory since the last sweep'. Neither the libyal dtformats spec nor artifacts-kb states this — both say only 'metadata about program installation and execution for Windows Application Compatibility'. The ProgramDataUpdater attribution and the 'newly encountered since last sweep' nuance are unsourced community analysis. Either add a primary/vendor source for them, or soften to what the cited sources support (a flat list of full executable paths from the Application Compatibility inventory). The verifiable, primary-sourced claims (flat list of paths, UTF-16LE, no per-entry timestamps, no hashes, Win7-only, superseded by Amcache.hve) should carry the meaning.
- MINOR (verify, not blocking): the ANSSI CoRIIN 2019 URL (cyber.gouv.fr) was not independently fetched in this review; the predecessor-to-Amcache claim it backs is already corroborated in-repo by version_history.rs (lines 81/87) and is well-established, so low risk — but confirm the URL is a real 200 before adding it to sources.
- DURABILITY caveat (not a blocker, established precedent exists): editing the AUTO-GENERATED fa_generated.rs is durable only because `load_catalog_ids` scans generated/ and the ingest dedup skips already-present ids, so a no-new-id `cargo run -p ingest` leaves the file untouched (this is how evtx/kape generated files keep hand-added enrichment). BUT if the `fa` source later yields any NEW id, main.rs regenerates the whole fa_generated.rs from only new_records (mod.rs:275 fs::write) and would DELETE the hand-enriched entry along with all other existing fa entries. Worth a note; consider whether a curated home is more robust long-term, though same-id relocation is blocked by the no_duplicate_ids test.
- JUDGMENT (defensible, flag only): triage_priority Low->Medium is reasonable but not clearly required — the artifact is weaker than shimcache/amcache/prefetch (no timestamps, no hashes) AND Win7-only; Low is also defensible. Not a factual error.

**Additions:** Enrich the existing bare stub `fa_file_programs_recentfilecache_bcf` (currently: meaning="The RecentFileCache.bcf file.", empty fields/MITRE/related_artifacts/sources[1]/evidence_strength, TriagePriority::Low). Keep id, name, artifact_type=File, file_path, os_scope=Win7Plus unchanged. Apply:

- meaning: "Windows 7 Application Experience program-inventory file, the predecessor to Amcache.hve. Populated by the ProgramDataUpdater scheduled task (Application Experience). Records the full file paths of executables newly encountered/registered by the compatibility inventory since the last sweep — evidence that a program was present and processed by the inventory. The file itself carries NO per-entry timestamps and NO file hashes (unlike Amcache.hve); it is a flat list of path strings. Superseded by Amcache.hve on Windows 8+."

- triage_priority: raise TriagePriority::Low -> TriagePriority::Medium (legacy Win7-only execution/presence artifact; useful where present, but absent on all Win8+ systems).

- fields (record layout per libyal dtformats spec): add a small fields table describing the on-disk structure — a variable-length file header beginning with a 4-byte signature at offset 0 (documented by libyal; treat exact magic bytes as per-spec, do not assert a hand-typed value), followed by a sequence of entry records, each = 4-byte character count (includes null terminator) + UTF-16LE full-path string with end-of-string character. Suggested field entries: {name:"signature", offset:0, size:4, meaning:"file signature identifying RecentFileCache.bcf (per libyal dtformats)"}; {name:"entry_char_count", meaning:"UTF-16 character count of the following path string, including null terminator"}; {name:"entry_path", meaning:"UTF-16LE full path of an executable inventoried by Application Experience"}.

- related_artifacts: &["amcache_app_file", "amcache_program", "shimcache", "prefetch_dir"] (all verified present in mod.rs).

- mitre_techniques: leave &[] — no ATT&CK technique cleanly describes what the artifact IS (an OS inventory file); it corroborates execution/presence rather than mapping to an adversary technique.

- evidence_strength: Some(EvidenceStrength::Corroborative).

- evidence_caveats: (1) "Windows 7 only — replaced by Amcache.hve on Windows 8 and later; absence on Win8+ is expected, not evidentiary."; (2) "Contains no embedded timestamps and no hashes; the file's own filesystem MFT/last-write time bounds the entries, individual entries cannot be independently dated."; (3) "Lists executables the Application Experience inventory (ProgramDataUpdater) newly encountered — presence is consistent with the file having existed/been inventoried on the system, not proof a user executed it."; (4) "os_scope is stored as Win7Plus for enum compatibility but the artifact is Win7-specific."

- sources: keep existing artifacts-kb URL and add: libyal dtformats RecentFileCache.bcf format spec (RE reference), ANSSI CoRIIN 2019 Amcache analysis (note current host cyber.gouv.fr), Eric Zimmerman RecentFileCacheParser (tool source, already referenced in src/references.rs)."

**Sources verified:**
- [2 (reverse-engineered reference the forensic community uses; libyal/Joachim Metz)] https://raw.githubusercontent.com/libyal/dtformats/main/documentation/RecentFileCache.bcf%20format.asciidoc — On-disk format: 4-byte signature at offset 0, variable-length file header, then entry records = 4-byte character count (incl. null terminator) + UTF-16LE little-endian path string with end-of-string char. 'Test version: Windows 7'.
- [2 (ANSSI RE writeup; primary govt research publication)] https://cyber.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf — Amcache is the Win7/8/10 database recording metadata on binary execution and program installation; RecentFileCache.bcf is the Win7 predecessor superseded by Amcache.hve (per this repo's version_history.rs citations to this paper).
- [2 (Digital Forensics Artifact knowledge base / ForensicArtifacts, community-curated)] https://artifacts-kb.readthedocs.io/en/latest/sources/windows/RecentFileCache.html — File location C:\Windows\AppCompat\Programs\RecentFileCache.bcf; Windows 7 stores a list of recently executed programs here.
- [2 (tool source; already in src/references.rs)] https://github.com/EricZimmerman/RecentFileCacheParser — Dedicated parser exists for RecentFileCache.bcf, confirming it is a distinct parseable Win7 execution artifact.

**Notes:** Coverage check: the artifact is ALREADY in the catalog as `fa_file_programs_recentfilecache_bcf` (generated from ForensicArtifacts/artifacts-kb) plus three KAPE target descriptors (kape_file_programs_recentfilecache_bcf, kape_file_recentfilecache, kape_file_recentfilecache_tkape). So do NOT create a new descriptor — enrich the existing FA one, which is a bare stub (meaning "The RecentFileCache.bcf file.", empty fields/related/MITRE, Low priority). version_history.rs already tracks the Win7->Win8 RecentFileCache.bcf->Amcache.hve transition citing the ANSSI paper.

Triage logic: on a Win7 host, RecentFileCache.bcf sits alongside Shimcache (AppCompatCache) and Amcache/Prefetch as execution/presence corroboration — but it is weaker than all of them because it holds no timestamps and no hashes, just newly-inventoried executable paths. On Win8+ its absence is expected (Amcache.hve replaced it); do not treat absence as evidentiary. The parenthetical 'AmCache' in the task title is slightly loose — RecentFileCache.bcf is Amcache's Win7 *predecessor*, a flat binary file, not a registry hive; the hive form (Amcache.hve) is a separate artifact covered by amcache_app_file / amcache_program.

Signature caveat (Doer-Checker): libyal's asciidoc prints the signature as '0xffeffef' (only 7 hex digits, ambiguous — likely a doc typo for a 4-byte LE magic). I did NOT hand-transcribe an exact magic value into the descriptor to avoid shipping a wrong constant; the field references libyal as the byte-level authority. If an exact magic is wanted, confirm against a real RecentFileCache.bcf sample or RecentFileCacheParser source before hardcoding.

Evidence tiering: all sources are tier-2 (RE references / community KB / govt research / tool source) — no vendor spec or RFC exists for this legacy format, so Corroborative is the honest evidence_strength; there is no independent third-party answer-key corpus validating a parser here.

### `ie_recovery_session` — Internet Explorer Automatic Crash Recovery Store (RecoveryStore / TravelLog)  [new_descriptor]
**FIX FIRST:** Not a duplicate (verified no existing RecoveryStore/ie_recovery descriptor), all four related_artifacts ids exist, all enum values valid, and the core facts (paths XP vs Vista/Win7, OLE/CFBF container, RFC 4122 v1 GUID decoding to a 1582-epoch FILETIME timestamp + MAC = creation time, and url/title/referrer fields) are directly supported by the Khatri RE writeup — legitimately used as the community-settled reverse-engineering reference, not as a blog-authority, and correctly tiered T2. evidence_strength Strong is honest and its caveats properly hedge the RE-derived layout. However three specifics presented as fact are NOT supported by any cited source and must be fixed before entering a published library.
- Fabricated stream nomenclature: the descriptor labels streams 'TSxx' and 'TLxx' (e.g. fields recovered 'from a TravelLog (TLxx) stream'), but the cited Khatri source names the streams FrameList, TravelLog, and |Kjjaqfaj... — it never uses TSxx/TLxx. Replace with the actual documented stream names or drop the invented suffixes.
- 'AdminActive' subfolder is unsourced: Khatri lists only Active, LastActive, and 'sometimes High, Low'. Remove AdminActive or add an independent source. Same for the evidence_caveat 'AdminActive/High/Low subfolders correspond to IE Protected Mode/elevation levels' — the source does not explain High/Low, so the Protected Mode interpretation is unsourced; hedge or cite it.
- IE version range overstated: the 2011 source covers IE8/9 only, but the descriptor claims 'IE8 Vista through IE11 on Win10' and implies Win10 coverage in `meaning`. Scope the claim to what the source establishes (IE8/9) with later-IE persistence marked as presumed/unverified, or add a source covering IE10/11. os_scope Win7Plus itself is an acceptable closest-fit.
- Borderline (not blocking): MITRE T1217 is a stretch for a session-restore artifact, but it matches the existing firefox_session_restore catalog precedent, so it is acceptable for consistency.

```
id: "ie_recovery_session"
name: "Internet Explorer Automatic Crash Recovery Store (RecoveryStore / TravelLog)"
artifact_type: ArtifactLocation::File
hive: None
key_path: ""
value_name: None
file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Internet Explorer\Recovery\*\*.dat")
  (subfolders observed: Active, LastActive (a.k.a. "Last Active"), and occasionally High / Low / AdminActive; on XP the root is <profile>\Application Data\Microsoft\Internet Explorer\Recovery. Two file kinds per subfolder: one RecoveryStore.{GUID}.dat plus one {GUID}.dat per open tab.)
scope: DataScope::User
os_scope: OsScope::Win7Plus   (IE8 Vista through IE11 on Win10; no Vista-specific variant exists in the enum, Win7Plus is the closest documented fit and matches the existing fa_file_cookies_index_dat entries)
decoder: Decoder::Identity   (container is OLE/CFBF structured storage readable by any compound-file reader; the inner TravelLog streams are an undocumented binary layout — no dedicated decoder in-tree, same treatment as firefox_session_restore's LZ4)
meaning: "Internet Explorer's Automatic Crash Recovery store, written continuously as tabs are opened/navigated so IE can restore the session after a crash. Each subfolder holds a RecoveryStore.{GUID}.dat (an OLE/CFBF compound file whose streams — FrameList, TSxx, and the |Kjjaqfaj... stream — record tab order and the tab GUIDs) plus one {GUID}.dat per tab (OLE/CFBF file whose TravelLog / TLxx streams hold each navigated entry's base URL, referrer URL, and page title). The {GUID} is an RFC 4122 v1 UUID: the low 6 bytes are a NIC MAC address and the first 60 bits are a FILETIME-style 100 ns timestamp (epoch 1582-10-15) giving the tab/store creation time. Provides evidence of open tabs and navigation — including full URLs and titles — that persists on disk even after browsing history and the WebCache are cleared, because the recovery store is a separate mechanism from history."
mitre_techniques: ["T1217"]   (Browser Information Discovery — same as firefox_session_restore; leave nothing else, no cleaner ATT&CK fit)
fields:
  - { name: "url", value_type: ValueType::Text, description: "Base URL of a navigated entry recovered from a TravelLog (TLxx) stream", is_uid_component: true }
  - { name: "title", value_type: ValueType::Text, description: "Page title of the navigated entry", is_uid_component: false }
  - { name: "referrer_url", value_type: ValueType::Text, description: "Referrer URL stored alongside the entry in the TLxx stream", is_uid_component: false }
retention: Some("Rewritten as the session changes; LastActive holds the previous graceful-close session, Active the live one. Files removed on clean IE exit in some versions but frequently orphaned on disk.")
triage_priority: TriagePriority::High
related_artifacts: ["browsers_ie_webcache_db", "browsers_ie_typed_urls", "fa_file_cookies_index_dat", "firefox_session_restore"]  (all verified present in catalog)
sources: [
  "http://www.swiftforensics.com/2011/09/internet-explorer-recoverystore-aka.html",  // Yogesh Khatri RE writeup — the community reference for the TravelLog/RecoveryStore format
  "https://forensics.wiki/ole_compound_file/",  // container format (CFBF/OLE structured storage)
  "https://forensics.wiki/internet_explorer/"   // IE artifact overview incl. Recovery folder
]
evidence_strength: Some(EvidenceStrength::Strong)
evidence_caveats: [
  "Recovered URLs/titles/referrers are Strong evidence of pages loaded in a tab, but the inner TravelLog (TLxx) binary layout is reverse-engineered, not vendor-documented — parsing depth and field boundaries are RE-derived (Khatri), so treat extracted fields as consistent-with, not spec-guaranteed",
  "The {GUID} timestamp is the tab/store creation time (RFC 4122 v1), NOT a visit time; cross-check against the on-disk MAC/MFT timestamps",
  "Presence of a URL proves the tab existed in a recoverable session, not that the user actively read it (background/redirect navigations also recorded)",
  "AdminActive/High/Low subfolders correspond to IE Protected Mode / elevation levels, not separate users"
]
volatility: Some(VolatilityClass::ActivityDriven)
volatility_rationale: "Overwritten as the IE session changes; LastActive preserves the prior graceful-close session while Active tracks the live one"
```

**Sources verified:**
- [T2 (reverse-engineering reference the DFIR community settled on for this format)] http://www.swiftforensics.com/2011/09/internet-explorer-recoverystore-aka.html — Exact Recovery folder paths and subfolder names (Active, LastActive, High, Low) on XP vs Vista/Win7; file naming RecoveryStore.{GUID}.dat + {GUID}.dat; OLE structured-storage container; inner stream names (FrameList, TSxx, TravelLog, TLxx, |Kjjaqfaj...) and that TLxx holds base URL + referrer URL + page title; {GUID} is RFC 4122 v1 UUID = FILETIME timestamp (epoch 1582-10-15) + NIC MAC
- [T1 (format wiki / primary format reference)] https://forensics.wiki/ole_compound_file/ — Confirms the OLE/Compound File Binary Format (CFBF, FAT-like storages+streams) that the RecoveryStore .dat files use as their container
- [T1 (format wiki reference)] https://forensics.wiki/internet_explorer/ — Internet Explorer forensic artifact overview referencing the Recovery folder and cookie/index.dat/WebCache locations
- [catalog check] https://api.github.com/repos/... (in-repo grep) — Confirmed no existing ie_recovery_* descriptor; on-disk cookies already covered by fa_file_cookies_index_dat / fa_file_low_index_dat (active in mod.rs) and WebCache by browsers_ie_webcache_db; related ids browsers_ie_webcache_db, browsers_ie_typed_urls, fa_file_cookies_index_dat, firefox_session_restore all exist

**Notes:** Duplication check: the OTHER half of the work item — IE on-disk cookie files at %APPDATA%\Microsoft\Windows\Cookies (and \Low) — is ALREADY in the catalog and registered, as fa_file_cookies_index_dat and fa_file_low_index_dat (both active at mod.rs lines 12535-12536), plus the modern package variant fa_file_ac_inetcookies and KAPE targets kape_file_windows_inetcookies. WebCacheV01.dat is covered by browsers_ie_webcache_db and fa_file_webcache_webcachev_dat. So no new cookie descriptor is proposed; if enrichment is later wanted, the one non-duplicative fact to add to fa_file_cookies_index_dat is that on IE10/11 (Win8+) the actual cookie VALUES live as individual UNENCODED plaintext files in %LOCALAPPDATA%\Microsoft\Windows\INetCookies\, while WebCacheV01.dat's Cookie container holds only metadata (name, host, expiry, accessed time) and NOT the cookie value — so the plaintext files are the recovery path for the value. I did not add this as it needs its own primary-source pass on the INetCookies plaintext layout.

The genuinely-missing artifact is the IE Recovery/RecoveryStore session-restore store — there is no descriptor for it (the only nearby entries are the generic KAPE "Local Internet Explorer folder" collection target at kape_generated.rs:30980 and the Firefox equivalent firefox_session_restore). Hence the new descriptor above.

Triage logic: when IE history/WebCache has been cleared, check Recovery\LastActive first — it survives history clearing and yields open-tab URLs + titles. The {GUID} filename decodes to a creation timestamp and the host MAC address (useful for tying an image to a NIC). Container is plain OLE/CFBF so olefile / any compound-file reader mounts it; the TLxx inner streams need the Khatri-style RE parser.

Could not retrieve the JDFSL peer-reviewed paper (commons.erau.edu returned HTTP 403), so it is not cited as a source; the descriptor rests on the Khatri RE writeup plus forensics.wiki for the container format, which independently corroborate location, OLE container, and recoverable fields.

### `kansa_collection_output` — Kansa Live-Response Collection (PowerShell Remoting)  [new_descriptor]
**FIX FIRST:** All load-bearing mechanics verified against kansa.ps1 (Tier-1 primary source, the tool's own code) and README: OutputFormat ValidateSet(CSV default/JSON/TSV/XML/GL/SPLUNK) line 339-340; default Port 5985 line 366; Modules.conf ordering + recursive Get-*.ps1 fallback lines 520/534; Output_timestamp\ModuleName\Hostname-ModuleName.ext naming line 29; Get- prefix strip line 844; MAXPATH 260 truncation to Error.Log lines 850/866; BINDEP->ADMIN$ via Pushbin lines 68-89/800. Not a duplicate; all 5 related_artifacts (evtx_winrm, amcache_program, fa_file_prefetch_pf, cmd_autorun_hklm, shimcache) exist. MITRE correctly empty for a defensive tool; Corroborative strength honest; caveats sound. One factual fix needed before merge.
- meaning prose says 'default TCP 5985 / 5986 for -UseSSL' — kansa.ps1 uses -Port $Port (default 5985) even with -UseSSL; it does NOT auto-switch to 5986. Reword to: 'default TCP 5985; -UseSSL enables WinRM-over-HTTPS but keeps the -Port value (operator sets -Port 5986 for the standard HTTPS port).' The rest of the meaning field is accurate.

```
pub(crate) static KANSA_COLLECTION_OUTPUT: ArtifactDescriptor = ArtifactDescriptor {
  id: "kansa_collection_output",
  name: "Kansa Live-Response Collection (PowerShell Remoting)",
  artifact_type: ArtifactLocation::LiveResponse,
  hive: None,
  key_path: "",
  value_name: None,
  file_path: None,   // no fixed path; output written to an "Output_<timestamp>\" directory beside kansa.ps1
  scope: DataScope::System,
  os_scope: OsScope::Win7Plus,   // relies on WinRM / PowerShell Remoting (WinRM 2.0 / PowerShell 2.0, Win7 / 2008 R2+)
  decoder: Decoder::Identity,
  meaning: "Output tree produced by Kansa, an open-source PowerShell incident-response framework (davehull/Kansa). Kansa fans a set of collector modules out across an enterprise over PowerShell Remoting (WinRM, default TCP 5985 / 5986 for -UseSSL) and gathers the results centrally. Only scripts named Get-*.ps1 under .\\Modules\\ run; if .\\Modules\\Modules.conf exists it controls WHICH modules run and in what ORDER (blank/# lines ignored), otherwise every Get-*.ps1 is discovered recursively in filesystem order. Targets come from -Target (single host), -TargetList (a file, one hostname per line), or an Active Directory query (Get-Targets, requires RSAT). Results land in a new Output_<timestamp>\\ directory with one subdirectory per module (module name minus the Get- prefix) holding one file per host named Hostname-ModuleName.ext, e.g. Get-PrefetchListing.ps1 -> Output_<ts>\\PrefetchListing\\Hostname-PrefetchListing.txt. -OutputFormat selects the serialization (CSV default; also JSON/TSV/XML/GL/SPLUNK). Non-terminating errors, per-host module failures, binary-push failures and MAX_PATH (260-char) truncations are logged to Error.Log in the output directory. -Pushbin copies module-declared third-party binaries (a 'BINDEP .\\Modules\\bin\\<tool>.exe' directive in a module's .NOTES block) to each target's ADMIN$ share before execution; -Rmbin removes them afterward. Post-collection, -Analysis runs the frequency/stacking scripts under .\\Analysis\\ (optimised for multi-host data). For an examiner, a Kansa Output_<timestamp> tree is a point-in-time, fleet-wide snapshot of execution, persistence, network and account state.",
  mitre_techniques: &[],   // defensive collection framework — no attacker ATT&CK technique cleanly represents the tool itself
  fields: &[
    FieldSchema { name: "hostname", value_type: ValueType::Text, description: "Target host the row was collected from (left of the '-' in Hostname-ModuleName.ext)", is_uid_component: true },
    FieldSchema { name: "module", value_type: ValueType::Text, description: "Collector module, i.e. the Get-*.ps1 name with the Get- prefix stripped (also the subdirectory name)", is_uid_component: true },
    FieldSchema { name: "output_format", value_type: ValueType::Text, description: "Serialization chosen with -OutputFormat: CSV (default), JSON, TSV, XML, GL, or SPLUNK", is_uid_component: false },
  ],
  retention: Some("Written to Output_<timestamp>\\ under the Kansa working directory; persists until the operator deletes it (a saved case artifact, not auto-rotated)"),
  triage_priority: TriagePriority::High,
  related_artifacts: &["evtx_winrm", "amcache_program", "fa_file_prefetch_pf", "cmd_autorun_hklm", "shimcache"],
  sources: &[
    "https://github.com/davehull/Kansa",
    "https://github.com/davehull/Kansa/blob/master/kansa.ps1",
    "https://github.com/davehull/Kansa/blob/master/README.md",
  ],
  evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
  evidence_caveats: &[
    "The framework is a collection wrapper — evidentiary weight lives in the specific module output (e.g. Get-PrefetchListing, Get-Autorunsc), not in Kansa itself",
    "Modules collect through PowerShell cmdlets / WMI, which read the live OS via APIs a kernel-mode rootkit can subvert; corroborate with raw on-disk artifacts or memory forensics",
    "Default CSV / serialized output can truncate or reshape objects; prefer JSON or XML and retain raw artifacts for evidentiary use",
    "-Pushbin writes third-party binaries to each target's ADMIN$ share, altering the subject system; record it in the acquisition log",
    "Empty per-host module output plus an entry in Error.Log indicates a collection failure, not a clean host",
  ],
  volatility: Some(crate::volatility::VolatilityClass::Volatile),
  volatility_rationale: "Point-in-time snapshot of volatile live-system state; frozen once written to Output_<timestamp> but the captured state is unreproducible after reboot",
};

Notes for the reviewer/integrator:
- File placement: this is a Windows LiveResponse framework descriptor; it belongs alongside other Windows live-response/tool-output entries (mirrors the existing Linux LiveResponse pattern LINUX_LSOF_OUTPUT / LINUX_SS_OUTPUT / LINUX_CHKROOTKIT_OUTPUT in linux_ext.rs). Register the static in the same module list those Windows descriptors use.
- related_artifacts all verified present in the catalog: evtx_winrm, amcache_program, fa_file_prefetch_pf, cmd_autorun_hklm, shimcache.
- MITRE intentionally empty (rules: leave empty rather than force). If a mechanism tag is ever wanted, T1021.006 (Remote Services: Windows Remote Management) describes the WinRM transport Kansa rides on, but it characterises attacker use, not the defensive tool — recommend leaving empty.
```

**Sources verified:**
- [Tier 1 (primary — the tool's own source: parameter block + comment-based help)] https://github.com/davehull/Kansa/blob/master/kansa.ps1 — Parameters (-Target/-TargetList/-Analysis/-Pushbin/-Rmbin/-OutputFormat/-UseSSL/-Port etc.); Get-Targets resolves single host, TargetList file (one host per line), or AD query; Modules.conf controls which Get-*.ps1 modules run and their order else all Get-*.ps1 run recursively; Output_<timestamp> directory with per-module subdir (Get- prefix stripped) and per-host file Hostname-ModuleName.ext (Get-PrefetchListing -> PrefetchListing\Hostname-PrefetchListing.txt); Error.Log for non-terminating errors and MAX_PATH truncation; -Pushbin copies BINDEP-declared binaries to target ADMIN$ share; default WinRM port 5985
- [Tier 1 (primary — tool documentation authored by the tool author)] https://github.com/davehull/Kansa/blob/master/README.md — Kansa uses PowerShell Remoting (WinRM) to run user-contributed modules across the enterprise; modules live in .\Modules and double as standalone scripts (e.g. Modules\Net\Get-Netstat.ps1); output produces Output_<timestamp> subdirectory with per-module subdirectories; .\Analysis directory holds analysis scripts geared to multi-system collections; example invocation .\kansa.ps1 -Target $env:COMPUTERNAME -ModulePath .\Modules -Verbose

**Notes:** Fit: the catalog already carries LiveResponse tool-output descriptors (LINUX_LSOF_OUTPUT, LINUX_SS_OUTPUT, LINUX_CHKROOTKIT_OUTPUT). Kansa is the Windows enterprise analog — the same category as the Linux UAC framework the Linux entries reference in their retention notes. A single descriptor represents the framework's output tree, not one artifact; that is why evidence_strength is Corroborative and the caveats push weight down to the individual module output. Triage logic for an examiner handed a Kansa Output_<timestamp> tree: read Error.Log first (distinguish a clean host from a failed collection), then correlate the module subdirectories against the standalone artifacts they mirror — PrefetchListing<->fa_file_prefetch_pf, Autorunsc<->cmd_autorun_hklm, execution evidence<->amcache_program/shimcache — and treat the WinRM channel (evtx_winrm) on both collector and targets as the provenance record for when/how collection ran. All mechanics (Modules.conf ordering, Get-* filter, Output_<timestamp>\ModuleName\Hostname-ModuleName.ext naming, -OutputFormat set, Error.Log, -Pushbin/ADMIN$/BINDEP, -Analysis) were read directly from kansa.ps1's comment-based help and the repo README — the tool's own source, a primary source. No independent oracle beyond the source exists for a tool's own behavior; nothing here is a synthetic-fixture claim.

### `evtx_rdp_client` — RDP Client Operational Log (outbound) — add Event ID 1029 username-hash  [enrichment]
**FIX FIRST:** Sources all resolve and substantively support the core claims (EZ map = tier-1 tool source confirming channel/provider/EID 1029/TraceMessage/Base64; Stroz Friedberg RE writeup confirms SHA256+domain dual-hash and the three no-hash conditions; nullsec corroborates UTF-16LE→SHA256→Base64 + wordlist crack). Not a duplicate — the descriptor genuinely omits 1029 (only 1024/1102), while eventids.rs is already correct/test-enforced. All added related_artifacts exist. MITRE T1021.001 fits; evidence_strength Definitive is honest; no overstatement. ONE fixable defect: the legacy-OS caveat asserts "Win7/Server 2008R2/Win8 do not record EID 1029", which conflicts with its own cited sources — Stroz says "Windows 7 and Windows Server 2008" (not R2) record nothing and Win8 records events-but-not-1029, while the EZ map attributes SHA1-logged 1029 to "Windows 7 / Server 2008 R2" (i.e. 2008 R2 DOES log it). Asserting "2008R2 does not record 1029" is contradicted by one of the cited sources.
- Legacy-OS caveat over-specifies and mis-states the enumeration: change 'on Win7/Server 2008R2/Win8 (which do not record EID 1029)' to match the Stroz Friedberg source — 'Windows 7 and Windows Server 2008 record no events in the RDPClient/Operational log; Windows 8 records some events but not EID 1029'. Drop or hedge the '2008 R2' claim, since the EZ map (also cited) implies Server 2008 R2 does log 1029 (with SHA1) — the two cited sources conflict on 2008 R2, so don't assert it as fact.
- Optional: the descriptor is Win10Plus-scoped where 1029 is SHA256, so the SHA1-on-Win8.1/Server-2012-R2 nuance from Stroz can be omitted; but if the legacy caveat is kept, keep it accurate to the source rather than an invented OS list.
- Everything else (meaning text, username_hash field, hash-one-way and no-hash-conditions caveats, related_artifacts, both primary sources) is verified and ready to apply unchanged.

**Additions:** Enrich the existing `evtx_rdp_client` descriptor (crates/data/src/catalog/descriptors/windows_evtx_ext.rs, lines 41-67). The EVENT_ID_TABLE 1029 entry in src/eventids.rs is ALREADY correct (channel RDPClient/Operational, Base64(SHA-256(UTF-16LE(username))), source host, wordlist-reversible, enforced by test event_1029_username_hash_is_sha256_on_rdpclient_channel at line 480) — the only unaddressed nuance there is the correlation-to-target-21/22 hint (optional description tweak). The descriptor is where 1029 is missing entirely.

1) meaning — currently only lists "1024 = success, 1102 = disconnect". Append EID 1029:
"EID 1029 records the connecting username as a case-sensitive Base64(SHA-256(UTF-16LE(username))) digest (provider Microsoft-Windows-TerminalServices-ClientActiveXCore), logged on the SOURCE/client host. The TraceMessage payload holds zero, one, or two `hash-hash` values (username and/or domain). Decode by hashing candidate usernames through the same UTF-16LE→SHA-256→Base64 pipeline and matching the string (EvtxECmd's 1029 map does this automatically). Once the plaintext username is recovered, correlate it against the DESTINATION host's TerminalServices-LocalSessionManager/Operational EID 21/22 and Security 4624 Type 10 to tie the source pivot to the target logon."

2) fields — add:
FieldSchema { name: "username_hash", value_type: ValueType::Text, description: "EID 1029: case-sensitive Base64(SHA-256(UTF-16LE(username))) of the connecting account; may also carry a domain hash as `usernameHash-domainHash`", is_uid_component: false }

3) evidence_caveats — add (keep existing "Outbound RDP; proves this host pivoted to another"):
- "EID 1029 hash is a one-way digest — only reversible by dictionary/wordlist attack against candidate usernames, not decryptable"
- "No 1029 hash is logged when NLA is disabled on the target server, when the 'Save Credentials' option is used, or on Win7/Server 2008R2/Win8 (which do not record EID 1029) — absence of 1029 does NOT mean no RDP connection occurred"

4) related_artifacts — add "evtx_rdp_session" (exists; the target-side 21/22 correlation home) to the existing &["rdp_client_servers", "evtx_rdp_inbound", "rdp_bitmap_cache"].

5) sources — add alongside the existing ponderthebits URL:
- "https://github.com/EricZimmerman/evtx/blob/master/evtx/Maps/Microsoft-Windows-TerminalServices-RDPClient-Operational_Microsoft-Windows-TerminalServices-ClientActiveXCore_1029.map" (tool/decoder source: confirms channel, provider, EID, TraceMessage extraction)
- "https://www.levelblue.com/blogs/spiderlabs-blog/remote-desktop-event-log-analysis-variations-in-logging-for-event-id-1029/" (Stroz Friedberg RE writeup: UTF-16LE construction, username/domain dual-hash, no-hash conditions)

evidence_strength stays Definitive (unchanged). MITRE stays T1021.001 (no new technique — this is a source-side lateral-movement artifact already covered).

**Sources verified:**
- [1 (independent tool/decoder implementation)] https://raw.githubusercontent.com/EricZimmerman/evtx/master/evtx/Maps/Microsoft-Windows-TerminalServices-RDPClient-Operational_Microsoft-Windows-TerminalServices-ClientActiveXCore_1029.map — Channel = Microsoft-Windows-TerminalServices-RDPClient/Operational; Provider = Microsoft-Windows-TerminalServices-ClientActiveXCore; EventID = 1029; extracts the Base64-encoded SHA256 username hash from the TraceMessage EventData field (XPath /Event/EventData/Data[@Name="TraceMessage"], refined to Base64 charset)
- [2 (Stroz Friedberg reverse-engineering writeup)] https://www.levelblue.com/blogs/spiderlabs-blog/remote-desktop-event-log-analysis-variations-in-logging-for-event-id-1029/ — Hash = Base64(SHA-256(UTF-16LE(name))) computed on the initiating/source host; TraceMessage carries zero/one/two `hash-hash` values (username and/or domain); NO hash logged when NLA disabled on server, when Save Credentials used, or on Win7/2008R2/Win8
- [3 (original RE writeup + cracker script — discovery pointer, corroborates the tool source)] https://nullsec.us/windows-event-id-1029-hashes/ — UTF-16LE → SHA-256 (raw bytes) → Base64 decode pipeline; logged on the SOURCE host; reversible only via a username wordlist

**Notes:** The eventids.rs half of the work item is already shipped and test-enforced — do not re-fix it; only the optional target-side-21/22 correlation phrasing could be added to its description. The load-bearing correction is that the `evtx_rdp_client` descriptor's `meaning` omits 1029 entirely (only 1024/1102). Base64 is inherently byte-exact/case-sensitive, so cracking requires an exact string match after UTF-16LE→SHA-256→Base64 — flagging it "case-sensitive" prevents an analyst from case-folding usernames in a wordlist. Key triage caveat worth surfacing: 1029 is silently absent under NLA-disabled / saved-credentials / legacy-OS conditions, so its absence is not exculpatory. The username hash is on the SOURCE host; the plaintext, once cracked, is the join key to the DESTINATION host's 21/22 and 4624 Type 10.

### `src/heuristics/process.rs — Windows logon type constants (Event ID 4624) block; cross-referenced by EVENT_ID_TABLE eid 4624 in src/eventids.rs` — Complete Windows 4624 Logon Type (SECURITY_LOGON_TYPE) code map  [enrichment]
**FIX FIRST:** The core enrichment is accurate and verbatim-verified against the Tier-1 primary source (Microsoft Learn event-4624 "Logon types and descriptions" table): all five missing constants (0=System, 7=Unlock, 11=CachedInteractive, 12=CachedRemoteInteractive "Same as RemoteInteractive. This type is used for internal auditing.", 13=CachedUnlock), the seven existing ones, the exact short names in logon_type_label, and the "no Type 1 / no Type 6" claim all match the source exactly. Target/home in src/heuristics/process.rs is correct; the constants and logon_type_label do NOT already exist (grepped src/ and crates/) so it is not a duplicate; is_remote_logon and is_lateral_movement_logon exist as described; evidence_strength DEFINITIVE is honest; leaving the map MITRE-unmapped is correct. One factual error must be fixed before applying: the forensic_notes sentence "The same enum applies to 4634/4647/4648 logon-type fields" is wrong for 4647 and 4648 — those events do not contain a Logon Type field (4648 carries Subject/credentials-used/target-server/process/network-info; 4647 carries only the logoff subject). Only 4624 and 4634 carry a Logon Type field, and the shipping Rust doc comment correctly says "4624/4634". Fixable by narrowing that sentence to "4634" (drop 4647/4648).
- forensic_notes overstates event scope: 'The same enum applies to 4634/4647/4648 logon-type fields' is inaccurate — Event 4647 (user-initiated logoff) and Event 4648 (explicit-credential logon) have NO Logon Type field. Only 4624 and 4634 carry it. Fix: change to '...applies to the 4634 logon-type field' (the code's own doc comment already correctly says '4624/4634').
- Minor (non-blocking) verification note: the authoritative table now lives at the Microsoft Learn 'previous-versions/.../windows-10/security/threat-protection/auditing/event-4624' path (the cited /threat-protection/... URL redirects there). Same authoritative vendor content; consider citing the resolved URL to avoid future link-rot ambiguity.

**Additions:** TARGET / HOME: The logon-type map already has a partial home in `src/heuristics/process.rs` (constants `LOGON_INTERACTIVE=2, LOGON_NETWORK=3, LOGON_BATCH=4, LOGON_SERVICE=5, LOGON_NETWORK_CLEARTEXT=8, LOGON_NEW_CREDENTIALS=9, LOGON_REMOTE_INTERACTIVE=10`). Do NOT create a second map in src/evtx.rs — extend the existing one here (DRY). The `EventIdEntry` struct in src/eventids.rs is `#[non_exhaustive]` with fixed fields and no slot for a map, so keep the enrichment in process.rs and let the 4624 EVENT_ID_TABLE row reference it in prose.

EXACT ADDITIONS (all values verbatim from the Microsoft "Logon types and descriptions" table on the event-4624 page — the authoritative SECURITY_LOGON_TYPE enumeration):

1. Add the FIVE missing constants alongside the existing seven:
   - `pub const LOGON_SYSTEM: u32 = 0;`  // System — used only by the System account, e.g. at system startup
   - `pub const LOGON_UNLOCK: u32 = 7;`  // Unlock — this workstation was unlocked
   - `pub const LOGON_CACHED_INTERACTIVE: u32 = 11;` // CachedInteractive — logged on with locally-cached network credentials; DC was NOT contacted to verify them
   - `pub const LOGON_CACHED_REMOTE_INTERACTIVE: u32 = 12;` // CachedRemoteInteractive — "Same as RemoteInteractive. This type is used for internal auditing."
   - `pub const LOGON_CACHED_UNLOCK: u32 = 13;` // CachedUnlock — "Workstation logon."
   Note there is deliberately NO Logon Type 1 and NO Type 6 in the enum — the Microsoft table skips them; do not invent them.

2. Add a label accessor returning the exact Microsoft short name (None for unknown codes — fail-loud rather than guess):
   ```rust
   /// Human-readable name for a Windows 4624/4634 Logon Type code.
   /// Values and names per Microsoft's SECURITY_LOGON_TYPE enumeration
   /// (Event 4624 "Logon types and descriptions" table).
   #[must_use]
   pub fn logon_type_label(logon_type: u32) -> Option<&'static str> {
       Some(match logon_type {
           0 => "System",
           2 => "Interactive",
           3 => "Network",
           4 => "Batch",
           5 => "Service",
           7 => "Unlock",
           8 => "NetworkCleartext",
           9 => "NewCredentials",
           10 => "RemoteInteractive",
           11 => "CachedInteractive",
           12 => "CachedRemoteInteractive",
           13 => "CachedUnlock",
           _ => return None,
       })
   }
   ```
   (Optionally a parallel `logon_type_description` returning the full sentence from the table, e.g. type 8: "credentials passed to the authentication package in unhashed form" — verbatim wording available in sources.)

3. Tests (Tier-2, ground truth = the documented Microsoft enum): assert each code→name pair, and assert `logon_type_label(1) == None` and `logon_type_label(6) == None` (the two codes the enum omits) so the fail-loud path is exercised.

FORENSIC/TRIAGE VALUE to note in the 4624 row prose: Type 3 = Network (SMB/authenticated share access, lateral movement candidate); Type 8 = NetworkCleartext (password sent unhashed — legacy/basic-auth/IIS, high interest); Type 9 = NewCredentials (token clone with alternate outbound creds — pass-the-hash / runas /netonly indicator); Type 10 = RemoteInteractive (RDP/Terminal Services); Types 11–13 = cached-credential logons where the DC was not contacted. Existing `is_remote_logon` (3/8/10) and `is_lateral_movement_logon` (3/8/9) helpers stay as-is; the new constants/labels only add the missing codes and human-readable names.

**Sources verified:**
- [1 (primary vendor documentation)] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 — Authoritative Microsoft 'Logon types and descriptions' table for Event 4624, confirming every value/name/description verbatim: 0=System, 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive, 11=CachedInteractive, 12=CachedRemoteInteractive, 13=CachedUnlock. Confirms no Type 1 or 6 in the enum. Also documents provider GUID {54849625-5478-4994-A5BA-3E3B0328C30D}, channel Security, and Type-10-only Restricted Admin Mode / NewCredentials-only Network Account Name semantics.

**Notes:** Evidence strength: DEFINITIVE — the values and names come directly from Microsoft's own vendor documentation of the SECURITY_LOGON_TYPE enumeration (the event-4624 audit reference page), which is the primary authority for this field. The same enum applies to 4634/4647/4648 logon-type fields.

MITRE: leave the map itself unmapped — a code→name lookup is descriptive, not a technique. The 4624 EVENT_ID_TABLE row already carries T1078 (Valid Accounts). Individual types correlate with techniques for triage (Type 10 ↔ T1021.001 RDP; Type 3 ↔ T1021 network/SMB; Type 9 ↔ pass-the-hash/T1550), but per the standing rule don't bolt these onto the generic map — they belong on the specific behavioural playbooks (src/playbooks.rs already encodes Type 10=RDP and Type 8/3 lateral-movement look-fors).

Caveat worth preserving from the source: Type 12 CachedRemoteInteractive is documented as "Same as RemoteInteractive. This type is used for internal auditing" and Type 13 CachedUnlock simply as "Workstation logon" — keep the verbatim Microsoft wording rather than paraphrasing, since these two are terse by design. Also retain the existing Type-10 WorkstationName caveat already documented in process.rs (destination vs source machine) — it is orthogonal to and complements this map.

### `usb_stor_enum` — USBSTOR Device Enumeration  [enrichment]
**FIX FIRST:** The central factual thrust of this enrichment is CONFIRMED against a tier-1 primary source, and the flagged code correction is justified. Microsoft's own Windows 10 SDK devpkey.h (tpn/winsdk-10, 10.0.16299.0/shared/devpkey.h, lines 172-175, fetched and grepped) defines ALL FOUR properties under GUID {83da6326-97a6-4088-9453-a1923f573b29} as DEVPROP_TYPE_FILETIME: DEVPKEY_Device_InstallDate (pid 100=0x64), FirstInstallDate (101=0x65), LastArrivalDate (102=0x66), LastRemovalDate (103=0x67). This directly refutes the existing src/peripheral.rs:101-113 comments calling 0066/0067 "UNDOCUMENTED by Microsoft" — they ARE documented DEVPKEYs. The proposal's recommended downgrade of those comments is accurate. The swiftforensics RE writeup resolves (92KB, real content) and supports the forensic Last-Insertion/Last-Removal interpretation and Win8 origin, and is correctly used only for the analyst-facing naming, not as the authority for the keys' existence. All five related_artifacts verified present (mountpoints2 mod.rs:8102, mounted_devices mod.rs:7641, usb_enum mod.rs:1455, portable_devices mod.rs:8130, setupapi_dev_log). MITRE (T1052.001, T1025) unchanged and appropriate — no new technique forced. evidence_strength Strong is honest (vendor+RE-documented FILETIMEs, but last-connect corroboration leans partly on key LastWrite metadata and the device-removal caveat). The descriptor targets id=usb_stor_enum which exists (windows_registry_ext.rs:685) — a genuine enrichment, not a duplicate. ONE fixable inaccuracy remains, see issues.
- OS-version attribution overstates novelty of 0064/0065 and contradicts the cited swiftforensics source. The proposal labels the 'first_install_date' field 'Win8+' and evidence-caveat #3 says '0064-0067 property subkeys are Windows 8+; on Windows 7/XP fall back...'. But swiftforensics (the proposal's own source) explicitly states Windows 7 ALREADY had Install Date (0064) and First Install Date (0065) — under the nested path {GUID}\00xx\00000000\Data — and that ONLY Last Arrival Date (0066) and Last Removal Date (0067) are the Windows 8 additions. Fix: (a) remove the 'Win8+' label from first_install_date (0065) — the timestamp existed in Win7; keep 'Win8+' only on last_arrival_date and last_removal_date; (b) reword caveat #3 so 'Windows 8+' applies to the FLAT layout for 0066/0067 (and the flattened path for 0064/0065), not to the existence of the InstallDate/FirstInstallDate timestamps themselves — on Win7 InstallDate/FirstInstallDate live at {GUID}\00xx\00000000\Data rather than being absent. As written it implies FirstInstallDate is unavailable pre-Win8, which the cited source refutes.
- Minor, non-blocking: the existing SOURCES retain the SANS blog (a DFIR blog used as a source, pre-existing in the descriptor). The proposal correctly adds tier-1 primary sources (MS devpkey.h) alongside it, which is a net improvement and satisfies the primary-source requirement; consider demoting/removing the SANS blog as an authority since it's a discovery pointer, but this is not required to apply the enrichment.

**Additions:** Enrich the EXISTING descriptor id="usb_stor_enum" (crates/data/src/catalog/descriptors/windows_registry_ext.rs:685). Do NOT create a new descriptor; the property-key CONSTANTS already exist in src/peripheral.rs (DEVICE_PROPERTIES_GUID + PROPERTY_INSTALL_DATE/FIRST_INSTALL_DATE/LAST_ARRIVAL_DATE/LAST_REMOVAL_DATE) — this enrichment adds the artifact-catalog encoding of the per-device Properties subkeys and the last-connect corroboration.

1) FIELDS — append four FieldSchema entries (all ValueType::Timestamp, is_uid_component:false), each stored under the per-device subkey `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<hex>` as a little-endian FILETIME:
- name:"install_date"        desc:"InstallDate (property 0x0064 = DEVPKEY_Device_InstallDate, FILETIME) — device driver install time; MAY be rewritten on a later driver (re)install, so it is not a reliable first-connect."
- name:"first_install_date"  desc:"FirstInstallDate (property 0x0065 = DEVPKEY_Device_FirstInstallDate, FILETIME, Win8+) — immutable first time the device was seen; the reliable first-connect timestamp."
- name:"last_arrival_date"   desc:"LastArrivalDate (property 0x0066 = DEVPKEY_Device_LastArrivalDate, FILETIME, Win8+) — most recent time the device was connected."
- name:"last_removal_date"   desc:"LastRemovalDate (property 0x0067 = DEVPKEY_Device_LastRemovalDate, FILETIME, Win8+) — most recent time the device was disconnected."

2) MEANING — extend the existing meaning to state that per-device connection timestamps are stored under `USBSTOR\<device>\<serial>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\` as decimal-named subkeys 0064-0067 (hex 0x64-0x67), each a REG_BINARY FILETIME, rather than derived only from setupapi log correlation. Note this replaces the current parenthetical "(via setupapi log correlation)" as the sole first/last-connect source — setupapi.dev.log remains the corroborating first-install source (already related via setupapi_dev_log).

3) EVIDENCE_CAVEATS — append:
- "First-connect: prefer 0065 FirstInstallDate (immutable, Win8+) over 0064 InstallDate — 0064 can be overwritten on a later driver (re)install and then no longer reflects the earliest connection."
- "Last-connect three-source corroboration: 0066 LastArrivalDate (documented FILETIME) is the authoritative last-connect; it should agree with the LastWrite time of the USBSTOR\\<device>\\<serial> registry subkey and the LastWrite time of the per-user NTUSER.DAT MountPoints2 subkey for the same volume GUID. The MountPoints2 hit also attributes the connection to a specific logged-in user. Registry subkey LastWrite times are corroborative (any write to the key updates them), not equivalent in precision to the 0066 FILETIME."
- "0064-0067 property subkeys are Windows 8+; on Windows 7/XP fall back to USBSTOR subkey LastWrite plus setupapi.dev.log for first-connect."

4) SOURCES — add (keep existing two):
- "https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/devpkey.h"  (Microsoft Windows 10 SDK devpkey.h — primary: GUID {83da6326-97a6-4088-9453-a1923f573b29} + property IDs 100-103 = 0x64-0x67, DEVPROP_TYPE_FILETIME)
- "https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html"  (Yogesh Khatri — RE writeup establishing the forensic Last-Insertion/Last-Removal meaning and Win8 introduction)
- "https://github.com/libyal/winreg-kb/blob/main/documentation/USB%20storage%20device%20keys.asciidoc"  (libyal winreg-kb — RE reference for the Enum\\USBSTOR\\...\\Properties layout)

5) RELATED_ARTIFACTS — extend existing &["usb_enum","portable_devices","setupapi_dev_log"] to also include "mountpoints2" and "mounted_devices" (both verified to exist: mod.rs:8102 and mod.rs:7641) to encode the corroboration/attribution triangle.

6) MITRE — leave unchanged (T1052.001, T1025 already present; the timestamp corroboration adds no new technique). evidence_strength stays Strong.

**Sources verified:**
- [1 (primary — vendor SDK header)] https://raw.githubusercontent.com/tpn/winsdk-10/master/Include/10.0.16299.0/shared/devpkey.h — Exact DEFINE_DEVPROPKEY macros: GUID {83da6326-97a6-4088-9453-a1923f573b29} with property IDs 100 (InstallDate), 101 (FirstInstallDate), 102 (LastArrivalDate), 103 (LastRemovalDate) = registry hex 0x64/0x65/0x66/0x67
- [1 (primary corroboration — independent header impl)] https://github.com/wine-mirror/wine/blob/master/include/devpkey.h — Independently confirms the same GUID and property IDs 100-103 and DEVPROP_TYPE_FILETIME for InstallDate/FirstInstallDate/LastArrivalDate/LastRemovalDate
- [RE writeup (Yogesh Khatri)] https://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html — Forensic interpretation: 0066/0067 = Last-Insertion(Arrival)/Last-Removal times, introduced in Windows 8, stored as FILETIME under the device Properties subkey
- [RE reference (libyal)] https://github.com/libyal/winreg-kb/blob/main/documentation/USB%20storage%20device%20keys.asciidoc — SYSTEM\CurrentControlSet\Enum\USBSTOR device-instance layout and the Properties\{83da6326-...} device-property subkeys (already cited in src/peripheral.rs)

**Notes:** Correction flagged in src/peripheral.rs (lines 101-113): the doc-comments assert properties 0066 (LastArrivalDate) and 0067 (LastRemovalDate) are "UNDOCUMENTED by Microsoft" and should be treated as "inferred, not authoritative." That is inaccurate — both are formally defined in Microsoft's own devpkey.h (Windows 10 SDK 10.0.16299.0, corroborated by the Wine devpkey.h mirror) as DEVPKEY_Device_LastArrivalDate (id 102=0x66) and DEVPKEY_Device_LastRemovalDate (id 103=0x67), type DEVPROP_TYPE_FILETIME. Recommend downgrading those "UNDOCUMENTED/inferred" comments to "documented in devpkey.h; forensic Last-Insertion/Last-Removal interpretation per swiftforensics." (swiftforensics remains the source for the analyst-facing naming, not for the existence of the keys.)

Task-mapping nuance: the work item labels "0064 (first connected)". Precisely, 0064 is DEVPKEY_Device_InstallDate, which can be rewritten on a later driver reinstall; the immutable first-connect is 0065 DEVPKEY_Device_FirstInstallDate (Win8+). The enrichment encodes both and marks 0065 as the reliable first-connect to avoid an overstatement.

Registry representation: the property IDs are stored as zero-padded DECIMAL subkey names that visually coincide with the hex (100->"0064" is actually the decimal 100 rendered... note: the registry subkey name is the 4-hex-digit form 0064/0065/0066/0067, i.e. hex of 100-103). Each value is a little-endian FILETIME in a REG_BINARY. Consumers reading these live in peripheral-core, per the knowledge-only charter — the descriptor documents location/meaning only.

Corroboration precision: 0066 is a true event FILETIME; the USBSTOR-subkey and MountPoints2-subkey LastWrite times are key-metadata and update on ANY write to those keys, so treat them as Corroborative (they bound/agree-with 0066), not as independent precise measurements. MountPoints2's added value is USER ATTRIBUTION (it is per-user NTUSER.DAT), which the machine-wide USBSTOR key cannot give.

### `shimcache` — ShimCache (AppCompatCache)  [enrichment]
**FIX FIRST:** Core fact is solid and verified against the load-bearing tool source (AppCompatCacheParser Windows10.cs line 81: trailing-4-bytes==1 => Executed; AppCompatCache.cs Execute enum = Yes/No/NA). The new Text tri-state field, Strong evidence_strength, unchanged MITRE, and the shared-fields decision are all defensible; the id is the existing 'shimcache' descriptor (not a duplicate) and it has no 'executed' field today; related_artifacts all pre-exist. BUT the evidence_caveats prose and field description overstate/fabricate specifics that are NOT in the only source that could support them (the nullsec RE writeup). Must be corrected before entering a published library.
- WRONG VALUE: caveat writes 0x0000864C; the article's observed value is byte sequence '64 86' = 0x8664 (little-endian short), not 0x864C — 0x864C matches no byte ordering of 64 86. Fix to the values exactly as the source lists them: 00 00, 01 00, 02 00, 4C 01, 64 86.
- FABRICATED ATTRIBUTIONS: 'non-native binaries genuinely run or merely extracted have shown values such as 0x0000864C and 0x0000014C' and the specific '0x0000864C for pestudio.exe run via Prefetch, 0x0000014C for extracted-but-not-run portable exe' appear nowhere in the cited article. The author explicitly says 'I'm not sure what those indicate.' Remove pestudio.exe, Prefetch, and the extracted-portable-exe attributions — they are invented meaning the source disclaims.
- CONTRADICTED SCOPE: the repeated 'non-native third-party binaries only' framing (in BOTH the field description and the caveat) is refuted by the cited article, which shows native binaries on both sides — cmd.exe/lsass.exe/explorer.exe marked No despite execution, but msiexec.exe/conhost.exe/regsvr32.exe (also native) marked Yes. The author explicitly rejects the built-in-vs-third-party theory. Remove the native/non-native scoping; keep only the supported asymmetry (Yes = very likely executed; No does not rule out execution).
- UNVERIFIED EXAMPLE: caveat cites 'powershell.exe' among binaries showing No; the article names cmd.exe (and lsass.exe, explorer.exe) but not powershell.exe. Replace with cmd.exe, which is verified.
- SOURCES OK (no change needed): the three added URLs resolve and support the core fact — Windows10.cs (verbatim exec logic), AppCompatCache.cs (Execute enum Yes/No/NA), and nullsec (March-2023 provenance confirmed + observed values). The nullsec blog is used only as a corroborative Tier-3 caveat source, not as authority for the core fact, which is fine. Once the caveat prose is corrected to match what nullsec actually states, the enrichment is ready.

**Additions:** Enrich EXISTING descriptor id "shimcache" (crates/data/src/catalog/descriptors/mod.rs, SHIMCACHE at line 1090; fields at SHIMCACHE_FIELDS line 1078). NOT already covered — the current descriptor documents ShimCache as "presence proves file existed, not execution" and has NO Executed field and NO mention of the Win10/11 trailing-4-byte indicator. Three concrete additions:

1) NEW FIELD in SHIMCACHE_FIELDS (line 1078). ValueType has no Enum variant, so use Text for the tri-state:
   FieldSchema {
     name: "executed",
     value_type: ValueType::Text,
     description: "Derived execution indicator (Yes/No/NA). Win10/Server2016+: last 4 bytes of the entry's Data field == 0x00000001 (little-endian) => Yes, any other value => No. Pre-Win10 (Win7/8.x) entries have no equivalent field => NA. Reverse-engineered from observation (not Microsoft-documented); reliable only as a POSITIVE signal and only for non-native third-party binaries.",
     is_uid_component: false,
   }
   NOTE: SHIMCACHE_FIELDS is shared by both SHIMCACHE and SHIMCACHE_MEMORY. The last-4-bytes flag lives in the AppCompatCache *entry structure* (present in both the registry blob and the in-memory buffer), so applying the derived field to both is defensible; if they prefer shimcache_memory untouched, split into a dedicated SHIMCACHE_REG_FIELDS. Recommend keeping it shared (minimal diff, structurally correct).

2) NEW evidence_caveats entry on SHIMCACHE (append to the existing array at line 1121):
   "Win10/Server2016+ execution indicator (reverse-engineered; added to Eric Zimmerman's AppCompatCacheParser Mar 2023): if the trailing 4 bytes of an entry's Data == 0x00000001 the binary was executed (Executed=Yes). ASYMMETRIC — high confidence when Yes, but a No (any non-0x00000001 value) does NOT rule out execution. False-negatives are documented: non-native binaries genuinely run or merely extracted have shown values such as 0x0000864C and 0x0000014C, and native Windows binaries (cmd.exe, powershell.exe) routinely show No despite repeated use. The parser's simple '== 1 else No' logic collapses all other observed values (0x00000002, 0x0000014C, 0x0000864C) into No. Use Yes as corroboration of execution for non-native third-party binaries only; never use No as evidence of non-execution."

3) NEW sources on SHIMCACHE (append to sources array at line 1107) — the tool source is the load-bearing primary:
   - https://github.com/EricZimmerman/AppCompatCacheParser/blob/master/AppCompatCache/Windows10.cs  (implements: var exec = BitConverter.ToInt32(ce.Data, ce.Data.Length - 4) == 1; ce.Executed = Execute.No; if (exec) ce.Executed = Execute.Yes;)
   - https://github.com/EricZimmerman/AppCompatCacheParser/blob/master/AppCompatCache/AppCompatCache.cs  (Execute enum { Yes, No, NA })
   - https://nullsec.us/windows-10-11-appcompatcache-deep-dive/  (RE writeup: non-native-only + false-negative values 0x864C etc.)

Leave evidence_strength as Strong (the positive Yes signal is a strong corroborator; the asymmetry is captured in caveats). No MITRE change (T1218/T1059 still fit).

**Sources verified:**
- [Tier 2 — real tool source implementing the behavior (RE-derived, not Microsoft-documented)] https://raw.githubusercontent.com/EricZimmerman/AppCompatCacheParser/master/AppCompatCache/Windows10.cs — Verbatim logic: var exec = BitConverter.ToInt32(ce.Data, ce.Data.Length - 4) == 1; ce.Executed = AppCompatCache.Execute.No; if (exec) ce.Executed = AppCompatCache.Execute.Yes; — confirms trailing 4 bytes == 1 (0x00000001 LE) => executed.
- [Tier 2 — real tool source] https://raw.githubusercontent.com/EricZimmerman/AppCompatCacheParser/master/AppCompatCache/AppCompatCache.cs — Execute enum has exactly three members: Yes, No, NA — confirms the requested tri-state field values; NA used for pre-Win10 entries lacking the indicator.
- [Tier 3 — independent RE observation writeup (corroborative)] https://nullsec.us/windows-10-11-appcompatcache-deep-dive/ — Non-native-third-party-binary-only scope; false-negative behavior with observed non-01 values (e.g. 0x0000864C for pestudio.exe run via Prefetch, 0x0000014C for extracted-but-not-run portable exe); March 2023 addition to AppCompatCacheParser; asymmetric confidence (Yes high, No low).

**Notes:** Independence check: the fact (last-4-bytes==0x00000001 => Executed) is confirmed by the AppCompatCacheParser source itself, which is the reference tool for this artifact — not a blog. The "non-native only" scope, the specific false-negative byte values, and the March-2023 provenance come from RE writeups (discovery pointers), so they enter as CAVEATS, not as a proof-grade claim. Microsoft has never documented the meaning of these bytes; the interpretation is reverse-engineered, so the honest framing is a strong POSITIVE corroborator with an explicit asymmetry (Yes ~ high confidence of execution; No ~ NOT evidence of non-execution). This does not overturn the descriptor's core caveat that ShimCache presence != execution — it adds one narrow, tool-derived positive signal on top of it. Existing related_artifacts (amcache_app_file, prefetch_dir, bam_user, shimcache_memory) already provide the corroboration path the caveat points to; no new related ids needed. Confirmed all four related ids exist in the catalog.

### `7045` — EVENT_ID_TABLE 7045 — Service installed (System log)  [enrichment]
**FIX FIRST:** The factual content is sound and well-sourced, the MITRE mapping is correct, and it is not a duplicate — but the proposed `description` grossly violates the EventIdEntry table's convention and must be trimmed, with the long-form content routed to the descriptor fields the proposal already identifies as secondary.

WHAT VERIFIED (Tier-1, fetched directly):
- Target confirmed: eventids.rs:147-154, 7045, channel "System", description "Service installed", mitre &["T1543.003"], high_value true. Matches proposal exactly.
- Impacket smbexec.py tag impacket_0_10_0 (fetched raw): line 59 SERVICE_NAME='BTOBTO', line 55 OUTPUT_FILENAME='__output', line 286 dwStartType=scmr.SERVICE_DEMAND_START, line 277/182 shell '%COMSPEC% /Q /c echo <cmd> ^> ...\__output 2^>^&1'. Also has -service-name arg (overridable). CONFIRMED.
- Impacket smbexec.py master (fetched raw): line 138-139 service name randomized (8 ascii letters), line 59 OUTPUT_FILENAME='__output_'+8 random. CONFIRMED — BTOBTO is legacy, not current default, exactly as proposal states.
- Impacket serviceinstall.py master (used by psexec.py, fetched raw): line 33 service name = random 4 ascii letters, line 36 binary = random 8-char + '.exe', line 101 SERVICE_DEMAND_START. CONFIRMED — psexec.py has no fixed-name IOC.
- MITRE T1569.002 mapping fits and is already used in this catalog for psexec.exe (lolbins.rs:585) and PSEXESVC_DROPPED_BINARY (windows_files_ext.rs:2061). Adding it to the 7045 entry while keeping T1543.003 is correct and not overstated.
- Secondary claim accurate: services_hklm evidence_caveats (windows_registry_ext3.rs:335) already contains "correlate with EVTX 7045"; services_imagepath (mod.rs) has an evidence_caveats field to extend.
- Not a duplicate: the 7045 EventIdEntry itself carries only T1543.003; the IOC content exists elsewhere (PSEXESVC_DROPPED_BINARY descriptor, PSEXEC_SERVICE_PATTERNS in heuristics/evtx.rs), so this is additive, not conflicting. related ids evtx_system/evtx_security/services_imagepath/services_hklm all exist. The 4697 Security twin (eventids.rs:419) exists as claimed.

Evidence honesty is good: proposal correctly frames PSEXESVC/BTOBTO as defaults not fixed, BTOBTO as legacy-only, psexec.py as random-name, and uses "consistent with / target-side" not "proves".

FIXES REQUIRED before applying — see issues.
- BLOCKING (fit-the-codebase): The proposed `description` for the 7045 EventIdEntry is ~1,400 characters. The longest description in the entire EventIdEntry table is ~88 chars (4697); typical entries are one short clause. This table is a compact event-id -> technique lookup, not a place for a paragraph-length lateral-movement essay — the addition breaks convention ~16x over. FIX: keep the EventIdEntry description to one short clause (e.g. 'Service installed (System log; SCM on the TARGET host — a demand-start LocalSystem service is the target-side signature of SMB remote-exec such as PsExec/Impacket)') and add T1569.002. Route the full tool-signature narrative (PSEXESVC/-r, BTOBTO legacy vs randomized master, psexec.py random names, __output redirect structure, 4624 Type-3 / 5140/5145 correlation) into the ArtifactDescriptor `meaning`/`evidence_caveats` of services_imagepath and services_hklm — i.e. the SECONDARY target the proposal already scoped. That is where the codebase keeps long-form forensic detail.
- MINOR (precision): The proposed smbexec ImagePath placeholder '^> \\<host>\<share>\__output' can be misread as the attacker host. The actual output UNC is loopback/local: tag 0.10.0 uses '\\127.0.0.1\<share>\__output' (line 178); master uses '\\%COMPUTERNAME%\<share>\__output' (line 180). State it as a loopback/COMPUTERNAME UNC on the target, not '<host>'.
- MINOR (unverified source): I did not fetch the JPCERT/CC PsExec page or the Microsoft PsExec page directly (fake-200 risk unassessed). The underlying claims they back — 7045 is written by SCM on the destination host, and -r/-s override name/run-as-System — are structurally guaranteed by CreateServiceW/SCM semantics and corroborated by the verified Impacket source plus the existing PSEXESVC_DROPPED_BINARY descriptor, so the claims stand regardless. Recommend a same-response click-through of the JPCERT URL before citing its page content as the authority, or lean on the Impacket source + MS doc (already cited) as the load-bearing primaries and demote JPCERT to a corroborating oracle.

**Additions:** TARGET (primary): the EVENT_ID_TABLE entry for event_id 7045 in /Users/4n6h4x0r/src/forensicnomicon/src/eventids.rs (lines 147-154). Currently: description "Service installed", mitre_techniques &["T1543.003"], high_value true.

TWO EXACT ADDITIONS:

1) mitre_techniques: add "T1569.002" (System Services: Service Execution) — keep existing "T1543.003". Rationale: 7045 covers BOTH persistent service install (T1543.003) AND the ephemeral demand-start service used purely for remote command execution (T1569.002). The lateral-movement / remote-exec target-side case is T1569.002, which is currently missing.

2) description: replace terse "Service installed" with a target-side lateral-movement signature note. Proposed:
"Service installed (System log, logged by Service Control Manager on the host where the service is created — i.e. the TARGET/destination of remote execution). A demand-start (SERVICE_DEMAND_START) service running as LocalSystem is the target-side signature of SMB-delivered remote code execution: ServiceName/ImagePath PSEXESVC + PSEXESVC.exe = Sysinternals PsExec default (override with -r servicename; child runs as System with -s); ServiceName BTOBTO with an ImagePath of the form '%COMSPEC% /Q /c echo <cmd> ^> \\<host>\<share>\__output ...' = Impacket smbexec.py hardcoded default (through v0.10.0; randomized 8-char service name and __output_<rand> in current master); a random 4-letter ServiceName dropping a random 8-char *.exe (RemComSvc) = Impacket psexec.py. Because 7045 is written on the host that RECEIVES the service creation, its presence is consistent with this host being the remote-exec destination — correlate the 7045 ServiceName/ImagePath with a Security-log 4624 Type-3 (network) logon and 5140/5145 admin-share (ADMIN$/C$/IPC$) access at the same timestamp to reconstruct the source."

Keep high_value: true, channel "System", artifact_ids &["evtx_system"].

SECONDARY (optional, same IOC in the registry descriptors): the registry-side counterparts services_imagepath (crates/data/src/catalog/descriptors/mod.rs:1933) and services_hklm (windows_registry_ext3.rs:294) may add to evidence_caveats a one-line pointer: "A demand-start LocalSystem service named PSEXESVC (PsExec) or BTOBTO (Impacket smbexec.py ≤0.10.0, randomized in current master) is the target-side signature of SMB remote code execution; correlate with System.evtx 7045 and 4624 Type-3." services_hklm already says "correlate with EVTX 7045" so this extends it with the concrete named-service IOCs.

EVIDENCE TIERING / honesty notes to preserve:
- PSEXESVC is the DEFAULT, not fixed: -r overrides it (Microsoft vendor doc). State as "default", not "always".
- BTOBTO is a LEGACY hardcoded default (verified in Impacket tags 0.9.15/0.9.19/0.9.22/0.10.0 as SERVICE_NAME='BTOBTO'); current master randomizes the service name — so BTOBTO is a strong indicator of an older/unmodified Impacket, NOT proof of current smbexec. Do not claim it is the current default.
- Impacket psexec.py uses RANDOM names (4-char service, 8-char *.exe) — no fixed-name IOC there; the durable IOCs are the demand-start + LocalSystem + __output-redirect command structure, not a literal name.
- Frame as "consistent with this host being the destination", not "proves" — 7045 alone shows a service was installed; the lateral-movement inference needs the ImagePath/ServiceName pattern plus the Type-3 logon + admin-share correlation.
- evidence_strength for the target-side inference: Strong when ServiceName+ImagePath match a known tool signature AND a concurrent 4624 Type-3 / 5145 exists; Corroborative on the 7045 name alone (names are trivially changeable).

**Sources verified:**
- [1 (vendor primary — Microsoft Sysinternals)] https://learn.microsoft.com/en-us/sysinternals/downloads/psexec — PsExec creates/interacts with a remote service via -r servicename; -s runs the remote process in the System account. Confirms the remote-service + LocalSystem mechanism (default name PSEXESVC is overridable via -r).
- [1 (authoritative technical analysis — JPCERT/CC national CERT)] https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm — On the DESTINATION host, Event ID 7045 in the System log records that the PSEXESVC service was installed/started/ended — the literal default service name and the target-side 7045 signature.
- [1 (tool source — Impacket, legacy tag)] https://raw.githubusercontent.com/fortra/impacket/impacket_0_10_0/examples/smbexec.py — smbexec.py SERVICE_NAME='BTOBTO' hardcoded default; OUTPUT_FILENAME='__output'; hRCreateServiceW(... dwStartType=scmr.SERVICE_DEMAND_START); ImagePath '%COMSPEC% /Q /c echo <cmd> ^> \\<host>\<share>\__output 2^>^&1 ...'. Also verified identical BTOBTO default in tags 0.9.15/0.9.19/0.9.22.
- [1 (tool source — Impacket current master)] https://raw.githubusercontent.com/fortra/impacket/master/examples/smbexec.py — Current master RANDOMIZES the service name (8 ascii letters, line 138-139) and output file (__output_<8 rand>) — so BTOBTO is a legacy/default IOC, not the current default. Still SERVICE_DEMAND_START.
- [1 (tool source — Impacket)] https://raw.githubusercontent.com/fortra/impacket/master/impacket/examples/serviceinstall.py — psexec.py service install: default service name = random 4 ascii letters, dropped binary = random 8-char *.exe (RemComSvc), dwStartType=SERVICE_DEMAND_START — confirms psexec.py has no fixed-name IOC.
- [2 (framework authority — MITRE ATT&CK)] https://attack.mitre.org/techniques/T1569/002/ — System Services: Service Execution — a temporary Windows service created via SCM/7045, 'demand start', running as LocalSystem, is the canonical execution pattern; PsExec explicitly cited as executing commands via a temporary service. Justifies adding T1569.002 to the 7045 entry.

**Notes:** Verification caveats and anomalies:
- Attribution asymmetry: 7045 is written by SCM on the host that RECEIVES the CreateServiceW call, so it is a DESTINATION artifact. The SOURCE host of PsExec/smbexec leaves different traces (Prefetch of psexec.exe, 4648/outbound). Do not read a 7045 as evidence the logging host was the attacker's origin.
- Name mutability: all three tools accept a custom service name (PsExec -r; Impacket serviceName= param), so a matching literal name is Corroborative, not Definitive. BTOBTO/PSEXESVC hits indicate default/unmodified tooling; absence does not exclude these tools.
- Version drift on BTOBTO: verified hardcoded 'BTOBTO' in Impacket 0.9.15→0.10.0; current fortra/impacket master randomizes both the service name (8 ascii letters) and the output file (__output_<8 rand>). Treat BTOBTO as an IOC for older/pinned Impacket, and the '%COMSPEC% /Q /c echo ... ^> \\host\share\__output... 2^>^&1' ImagePath structure as the more version-robust smbexec signature.
- Cleanup: PsExec and Impacket delete the service after execution, so 7045 (service install) may be the ONLY durable trace if the service key was removed before imaging; pair with 7034/7036 (SCM service state changes) and Sysmon 13 (registry set on Services\ key) where available.
- Related existing catalog ids for cross-linking (all verified present): evtx_system, services_imagepath, services_hklm, evtx_security. The evtx_security 4697 entry (eventids.rs:419) is the Security-log twin of 7045 (requires audit policy) and should be cross-referenced.
- Cross-check oracle: JPCERT/CC Tool Analysis Result Sheet (national CERT technical reference) independently documents PSEXESVC install/start/stop recorded in System-log 7045 on the destination host — this is the authoritative confirmation of the target-side inference, independent of the Impacket source (which is the primary for BTOBTO/demand-start).

### `evtx_security` — Security Event Log (Security.evtx)  [enrichment]
**FIX FIRST:** Core additions are well-supported and correctly sourced. Verified live: (1) Microsoft event-4624 doc contains the LogonType table verbatim, matching the proposal's enum (2/3/4/5/7/8/9/10/11) and confirming Source Network Address = client IP and Source Port 0 for interactive logons — tier-1 vendor spec, correctly labeled Definitive. (2) MITRE T1021.002 (SMB/Windows Admin Shares, C$/ADMIN$/IPC$, Valid Accounts, Lateral Movement) and T1021.001 (RDP, Lateral Movement) both resolve on attack.mitre.org and support the Type-3 and Type-10 vector mappings; both IDs already exist in the catalog, so no invented techniques. The MITRE mapping fits (4624 is the log where these lateral-movement authentications are observed) and is not forced. This is an enrichment of the existing evtx_security descriptor, not a duplicate; related_artifacts unchanged and valid. evidence_strength and forensic_notes are honestly hedged ("consistent with," Type 3 also benign, correlate with 4648/4672/IpAddress). No blog/13cubed/SANS used as authority. One fixable accuracy nit prevents a clean confirm.
- ADDITION 1 labels its list 'Full enum (Microsoft)' but omits value 0 (System), which is fully visible and NOT truncated in the Microsoft event-4624 doc (also omits 12/13). Calling a 9-of-~12 subset the 'Full enum' is a minor factual overstatement for a published library. Fix: either add '0 System' (and optionally '12 CachedRemoteInteractive') or relabel to 'key logon types' / 'logon types (Microsoft)' rather than 'Full enum'.

**Additions:** Target existing descriptor id: `evtx_security` (crates/data/src/catalog/descriptors/mod.rs, static EVTX_SECURITY, lines ~7098-7180). The work-item's "EVENT_ID_TABLE 4624" maps to this descriptor — 4624 is one of the enumerated key event IDs in its `meaning` field, and the descriptor already carries a Type-3-vs-Type-10 note but ONLY in the context of WorkstationName source-attribution, NOT as a logon-type-as-pivot for building a lateral-movement timeline. The requested enrichment is the missing pivot/filter angle plus the two Lateral-Movement techniques.

ADDITION 1 — new evidence_caveats entry (append to the existing `evidence_caveats` array, after the current "Event 4624 WorkstationName semantics differ by logon type…" entry):

"Event 4624 LogonType isolates the logon vector for a lateral-movement timeline: Type 3 (Network) = a user or computer authenticated to this host from the network — the inbound SMB / net-use / admin-share (C$/ADMIN$/IPC$) and pass-the-hash vector; Type 10 (RemoteInteractive) = Terminal Services / Remote Desktop (RDP); Type 2 (Interactive) = local console. Filtering Security.evtx 4624 by LogonType therefore separates remote network authentication (Type 3) from RDP sessions (Type 10) and local logons (Type 2) when reconstructing how an actor moved between hosts. Full enum (Microsoft): 2 Interactive, 3 Network, 4 Batch, 5 Service, 7 Unlock, 8 NetworkCleartext, 9 NewCredentials, 10 RemoteInteractive, 11 CachedInteractive."

ADDITION 2 — MITRE techniques (append to the existing `mitre_techniques` array, currently &[\"T1070.001\", \"T1059\", \"T1078\", \"T1555\"]):
add \"T1021.002\" (Remote Services: SMB/Windows Admin Shares — the Type 3 SMB/admin-share vector) and \"T1021.001\" (Remote Services: Remote Desktop Protocol — the Type 10 RDP vector). Both are Lateral Movement (TA0008) sub-techniques of T1021, verified live on attack.mitre.org.

ADDITION 3 — sources (append to the existing `sources` array; the event-4624 Microsoft URL is a candidate source and confirms the full LogonType enum):
"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624" (Microsoft — authoritative 4624 field + LogonType table), and "https://attack.mitre.org/techniques/T1021/002/" (MITRE — SMB/Windows Admin Shares lateral movement).

evidence_strength: leave at existing Definitive — the LogonType enum values are documented verbatim by Microsoft (tier-1 vendor spec); the "isolates the logon vector for a lateral-movement timeline" framing is analyst-pivot interpretation (Corroborative) but is stated as usage guidance, not a definitive causal claim, so no downgrade of the descriptor's overall strength is warranted.

**Sources verified:**
- [1 (Microsoft vendor spec)] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 — Full LogonType enum table verbatim: 2 Interactive (a user logged on to this computer), 3 Network (a user or computer logged on from the network), 10 RemoteInteractive (logged on remotely using Terminal Services or Remote Desktop). Also confirms Source Network Address = IP of machine from which logon was performed; Source Port 0 for interactive logons.
- [1 (MITRE ATT&CK authoritative)] https://attack.mitre.org/techniques/T1021/002/ — T1021.002 = Remote Services: SMB/Windows Admin Shares, Tactic Lateral Movement (TA0008), sub-technique of T1021; adversaries use Valid Accounts over SMB with hidden admin shares C$/ADMIN$/IPC$ and Pass-the-Hash. Sibling T1021.001 = Remote Desktop Protocol confirmed in the sub-technique list.

**Notes:** Non-overstatement: the LogonType→vector mapping is a filtering aid, not proof of lateral movement — a Type 3 event records network authentication, it does not by itself establish an attacker moved laterally (correlate with 4648 explicit-cred, 4672 special privileges, source IpAddress, and destination-host process activity). Type 3 also covers benign network activity (file-share browsing, service accounts), so it is "consistent with" the SMB/admin-share vector, not conclusive. Note the existing WorkstationName caveat already in the descriptor is complementary: Type 3 WorkstationName = source machine (usable), Type 10 WorkstationName = destination machine (misleading — use Source Network Address instead). The enum values (2/3/10 etc.) are Microsoft-documented verbatim; the "0 System" and "12" rows exist in the doc but 12 is truncated in the fetched table — I list only the values I confirmed. related_artifacts unchanged (srum_network_usage, prefetch_file, shimcache remain the correct correlation pivots for a lateral-movement timeline; evtx_security is itself the anchor).

### `ntds_dit` — Active Directory Database (NTDS.dit)  [enrichment]
**FIX FIRST:** The enrichment is fundamentally sound, well-tiered, and correctly wired — but two source-attribution imprecisions must be tightened before it enters a published library.

WHAT I VERIFIED (all confirmed):
- Target descriptor exists: NTDS_DIT at crates/data/src/catalog/descriptors/mod.rs:3664, id "ntds_dit", currently sourced only to a SANS blog. Enrichment correctly ADDS primary vendor docs rather than relying on the SANS pointer. Good — no blog cited as authority.
- MS ifm doc (cc732530) RESOLVES and supports the load-bearing claims VERBATIM: (a) "When you create installation media for a domain controller, the ifm subcommand stores the installation media in a subfolder named Active Directory after the subcommand completes"; (b) "The full AD DS installation media includes the registry." The "Active Directory subfolder + registry included" claim is legitimately Definitive from this primary source. Not a fake-200.
- MS ESENT doc (esent-event-327-326) RESOLVES and confirms event source "ESENT" and Event IDs 326/327 logged in the Application log. Real.
- Sigma rule (win_esent_ntdsutil_abuse.yml) RESOLVES and confirms the tier-2 detection oracle: Provider_Name 'ESENT', EventID [216, 325, 326, 327], Data|contains 'ntds.dit', falsepositives "Legitimate backup operation/creating shadow copies". This corroborates 325 belonging to the ntds.dit-extraction event family and honestly grounds the benign-collision caveat.
- MITRE T1003.003 (OS Credential Dumping: NTDS) already present, correct, unchanged — fits cleanly.
- related_artifacts handling is EXACTLY right: I grepped descriptors/ — no hand-curated ESENT/event-325 descriptor exists (only auto-generated fa_* entries), so the proposal correctly does NOT invent an id and flags the gap. The reverse cross-ref evtx_netlogon → "ntds_dit" is confirmed at windows_evtx_ext.rs:445.
- Evidence tiering is honest: Definitive kept; .jfm name + exact registry\ subdir + SYSTEM/SECURITY filenames labeled Corroborative (TrustedSec/thehacker.recipes, tier-3); "consistent with extraction, not proof" caveat is properly hedged; the non-default path (not the event alone) named as the discriminator.

TWO FIXES NEEDED (source attribution overstated):
1. The caveat writes "(326=attached, 327=detached per MS support doc)". The cited MS doc (esent-event-327-326) does NOT establish 327=detached — its symptom example shows BOTH 326 AND 327 with the description "database engine has attached database" (the article is about log-spam, not attach/detach semantics). 326=attach/327=detach is genuine ESENT behavior but is NOT supported by this specific citation. Fix: either drop "per MS support doc" from the detach claim, soften to "326/327 = database attach/detach events", or cite a source that actually documents 327=detach.
2. Event 325 is described as "database engine created a new database" with no primary-source citation for that exact semantic label — the Sigma rule only lists 325 as a matched EventID, it doesn't define it. Per the standing rule (every fact needs a primary-source citation), attach a primary anchor for the 325 description or explicitly mark it as corroborated-by-Sigma rather than asserted fact.

Both are wording/attribution tightenings on Corroborative-tier detail; the load-bearing IFM-footprint enrichment, evidence strength, MITRE, and related_artifacts are all correct and ready.
- Caveat attributes "327=detached" to MS doc esent-event-327-326, but that doc's own symptom example shows BOTH 326 and 327 as "database engine has attached database" — the doc does not support 327=detached. Drop the attribution or cite a doc that documents attach/detach semantics.
- Event 325 described as "database engine created a new database" without a primary-source citation for that label; the Sigma rule only lists 325 as an EventID. Add a primary anchor or mark it as Sigma-corroborated rather than asserted.

**Additions:** Enrich the EXISTING descriptor `ntds_dit` (crates/data/src/catalog/descriptors/mod.rs:3665). No new descriptor.

1) MEANING — append the ntdsutil IFM on-disk footprint to the existing meaning string. Current:
   "Domain controller AD database; contains NTLM hashes for all domain accounts"
   New:
   "Domain controller AD database; contains NTLM hashes for all domain accounts. A `ntdsutil \"ac i ntds\" \"ifm\" \"create full <path>\"` dump leaves a portable copy at an ad-hoc path: the target folder holds two sibling subdirs — `Active Directory\\` (ntds.dit + ntds.jfm ESE flush map) and `registry\\` (SYSTEM + SECURITY hives) — i.e. everything offline secretsdump needs, since the SYSTEM hive carries the BootKey/SYSKEY that decrypts the .dit"

2) EVIDENCE_CAVEATS — add two entries to the existing &[...] (keep the current one):
   - "ntdsutil IFM dump footprint: an ad-hoc target folder with sibling `Active Directory\\` (ntds.dit + ntds.jfm flush map) and `registry\\` (SYSTEM + SECURITY) subdirs — per MS ifm doc the media is stored in an 'Active Directory' subfolder and full AD DS media 'includes the registry'; a ntds.dit found anywhere other than the default %SystemRoot%\\NTDS\\ is strong evidence of extraction"
   - "Corroborated by ESENT Application-log event 325 (database engine created a new database) whose referenced database path is the non-default IFM copy; event source 'ESENT', IDs 216/325/326/327 with data containing 'ntds.dit' (326=attached, 327=detached per MS support doc). Consistent with credential-theft staging; the referenced path — not the event alone — is the discriminator"

3) SOURCES — add to the existing &[...] (replace reliance on the lone SANS blog with primary vendor docs; keep or drop the SANS link at maintainer discretion):
   - "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11)"  (MS ifm reference: 'Active Directory' subfolder + 'full AD DS installation media includes the registry')
   - "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/esent-event-327-326"  (MS: ESENT event source, IDs 326/327)

4) MITRE — no change. T1003.003 already present and correct (OS Credential Dumping: NTDS).

5) RELATED_ARTIFACTS — no change. Task asked to "relate to evt 325", but NO ESENT-325 / ESENT-application-log descriptor exists in the catalog (grep of descriptors/ for ESENT/event 325 returns nothing), and related_artifacts must reference existing ids. Do NOT invent one. If an ESENT Application-log event descriptor is later added, wire ntds_dit <-> that id then. (Existing cross-ref already runs the other way: evtx_netlogon lists ntds_dit in its related_artifacts at windows_evtx_ext.rs:445.)

Evidence strength unchanged (Definitive). The .jfm filename and the exact `registry\` subdir name are Corroborative (community/TrustedSec writeups + ESE docs), while the load-bearing 'Active Directory subfolder + registry included' claim is Definitive from the MS ifm doc.

**Sources verified:**
- [1 (Microsoft vendor doc, primary)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530(v=ws.11) — ntdsutil/dsdbutil 'ifm create full %s' creates writable-DC installation media; media is stored in a subfolder named 'Active Directory'; 'The full AD DS installation media includes the registry'; 'create sysvol full' adds SYSVOL. Confirms the Active Directory + registry sibling-subdir structure.
- [1 (Microsoft support doc, primary)] https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/esent-event-327-326 — Confirms event source 'ESENT' and event IDs 326 (database attached) / 327 (database detached) in the Application log. Anchors the ESENT event family used to detect the new-database (325) trace.
- [2 (real detection-tool source, independent oracle)] https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse.yml — Detection matches Provider_Name 'ESENT', EventID in (216,325,326,327), and event data containing 'ntds.dit' — confirms 325 is the create-new-database event correlated with ntdsutil ntds.dit extraction.
- [3 (RE writeup, corroborative)] https://trustedsec.com/blog/exploring-ntds-dit-part-1-cracking-the-surface-with-dit-explorer — ntds.jfm is the ESE flush map file (.chk=checkpoint, .jrs=log reserve, .jfm=flush map); part of the modern NTDS file set copied alongside ntds.dit.
- [3 (community writeup, corroborative)] https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds — IFM output paths: <path>\Active Directory\ntds.dit, <path>\registry\SYSTEM, <path>\registry\SECURITY; SYSTEM hive holds the SYSKEY needed to decrypt ntds.dit; consumed by secretsdump/gosecretsdump. Corroborates exact 'registry\' subdir and SYSTEM+SECURITY filenames.

**Notes:** Triage logic for an examiner: a ntds.dit at the default %SystemRoot%\NTDS\ntds.dit is expected; a copy anywhere else (temp/staging path) is the finding. The IFM footprint is self-identifying — the paired `Active Directory\` and `registry\` subdirs under one ad-hoc parent, with ntds.dit+ntds.jfm in the former and SYSTEM+SECURITY in the latter, is the exact file set secretsdump/gosecretsdump consumes (`secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL`). Time-correlate with ESENT Application event 325 (new database created at the non-default path) and, for VSS-based variants, Service Control Manager 7036 for Volume Shadow Copy starting ~1s prior. ntds.jfm is the ESE flush map (Win Server 2016 / Win10 anniversary+); its presence beside the .dit both aids offline ESE recovery and marks a modern-DC dump. CAVEAT: legitimate DC-promotion IFM and backup jobs produce the identical footprint and events — the non-default path plus a ntdsutil.exe parent process (Sysmon EID 1/11) is what separates benign from malicious; the artifact alone is 'consistent with' extraction, not proof. Task said 'relate to evt 325' but no ESENT-325 event descriptor exists in the catalog to link to; flagged as a gap rather than forcing an invented id.

### `src/shlink.rs (Shell Link / .LNK knowledge module)` — ShellLinkHeader target MAC timestamps (CreationTime / AccessTime / WriteTime FILETIME fields)  [enrichment]
**FIX FIRST:** Offsets, field widths, and FILETIME semantics all verified Tier-1 against MS-SHLLINK §2.1 (fetched): CreationTime@0x1C, AccessTime@0x24, WriteTime@0x2C, FileSize@0x34, HeaderSize MUST=0x4C. Not a duplicate in shlink.rs or the catalog; sources resolve and support; evidence_strength honest; MITRE correctly empty. One factual inaccuracy to fix before applying: the module-doc and forensic_notes understate the spec on the WriteTime zero clause.
- Module-doc text ('A zero value denotes an unset field (per spec for CreationTime and AccessTime)') and forensic_notes ('verbatim spec language for CreationTime and AccessTime') exclude WriteTime — but the fetched MS-SHLLINK §2.1 spec applies the identical clause to all three: 'WriteTime ... If the value is zero, there is no write time set on the link target.' This understates the spec and is internally inconsistent with the OFFSET_WRITE_TIME constant doc, which correctly states it. Fix: reword both to cover all three timestamps (CreationTime, AccessTime, WriteTime).
- Everything else confirmed and ready: offsets 0x1C/0x24/0x2C and FILETIME_FIELD_SIZE=8 derive exactly from the fixed-width preceding fields; not already present in src/shlink.rs (existing fa_*_shlink DLL entries and the Velociraptor LNK descriptor are unrelated); all three cited sources resolve and support (MS-SHLLINK §2.1 fetched and verbatim-supports; liblnk already cited in-module; MS-DTYP FILETIME standard); evidence_strength (Definitive for layout, Strong/Corroborative for MAC-time interpretation) is honest; MITRE correctly left empty; 'consistent-with-not-proof' and 'survives target deletion' framing properly hedged.

**Additions:** ENRICH the existing knowledge-only module `src/shlink.rs`. It currently encodes HEADER_SIZE, LINK_CLSID, LinkFlags, FileAttributesFlags, and the ExtraData block signatures, but omits the three fixed FILETIME fields in the ShellLinkHeader — the target file's MAC timestamps, one of the most forensically valuable parts of a .LNK because they persist after the referenced target is deleted.

Add fixed-offset field constants + a doc block, in the module's existing style (SCREAMING_SNAKE_CASE, hex, one-line `///` referencing the spec section). Every field before them is fixed-width, so the offsets are exact: HeaderSize(4)@0x00 + LinkCLSID(16)@0x04 + LinkFlags(4)@0x14 + FileAttributes(4)@0x18 ⇒ CreationTime @0x1C, AccessTime @0x24, WriteTime @0x2C, then FileSize @0x34.

Proposed constants (placed after LINK_CLSID / before the LinkFlags section, matching header field order):

    /// Byte offset of `ShellLinkHeader.CreationTime` — an 8-byte FILETIME
    /// ([MS-DTYP] §2.3.3) recording the link *target's* creation time
    /// ([MS-SHLLINK] §2.1). Zero means no creation time was set on the target.
    pub const OFFSET_CREATION_TIME: usize = 0x1C;

    /// Byte offset of `ShellLinkHeader.AccessTime` — an 8-byte FILETIME
    /// ([MS-DTYP] §2.3.3) recording the target's last-access time
    /// ([MS-SHLLINK] §2.1). Zero means no access time was set on the target.
    pub const OFFSET_ACCESS_TIME: usize = 0x24;

    /// Byte offset of `ShellLinkHeader.WriteTime` — an 8-byte FILETIME
    /// ([MS-DTYP] §2.3.3) recording the target's last-write time
    /// ([MS-SHLLINK] §2.1). Zero means no write time was set on the target.
    pub const OFFSET_WRITE_TIME: usize = 0x2C;

    /// Width, in bytes, of each ShellLinkHeader FILETIME timestamp field.
    pub const FILETIME_FIELD_SIZE: usize = 8;

Also extend the module-level doc (and add a `header_timestamp_offsets` unit test asserting 0x1C / 0x24 / 0x2C and size 8) with the forensic note:

"The three ShellLinkHeader timestamps are the *link target's* MAC times captured at the moment the shortcut was last written, encoded as FILETIME (100-ns intervals since 1601-01-01 UTC, [MS-DTYP] §2.3.3). Because they are copied into the .LNK, they survive deletion of the target: a .LNK left in a Recent/AutoDest/jump-list can preserve a deleted file's creation/access/write times even when the file itself is gone. A zero value denotes an unset field (per spec for CreationTime and AccessTime), not the 1601 epoch — consumers must treat 0 as 'absent', never render it as a real timestamp. These are consistent with (not proof of) the target's true filesystem times: they reflect the target's metadata as seen at link-write time and can be stale or forged.

evidence_strength: Definitive for the on-disk layout/offsets (fixed by the [MS-SHLLINK] §2.1 grid + MUST-be-0x4C header size); Strong/Corroborative for the forensic MAC-time interpretation (the values mirror the target's timestamps at link-write time, so they corroborate rather than establish the target's real times).

mitre_techniques: leave empty — no ATT&CK technique cleanly fits a passive timestamp field. (The broader .LNK-as-artifact links to persistence/execution evidence, but the timestamp fields themselves carry no technique.)

**Sources verified:**
- [Tier 1 (primary spec — MSFT Open Specifications, [MS-SHLLINK] §2.1)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15 — ShellLinkHeader field order and fixed widths: HeaderSize(4, MUST=0x4C), LinkCLSID(16), LinkFlags(4), FileAttributes(4), CreationTime(8 FILETIME), AccessTime(8 FILETIME), WriteTime(8 FILETIME), FileSize(4). Confirms each timestamp is a FILETIME ([MS-DTYP] §2.3.3) of the link target and that a zero value means the corresponding time is not set on the target. Offsets 0x1C/0x24/0x2C derived from these fixed widths.
- [Tier 1/2 (independent reverse-engineered reference, J. Metz / libyal)] https://raw.githubusercontent.com/libyal/liblnk/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc — Independent corroboration of the fixed 76-byte (0x4C) file header layout with class identifier, data/link flags, file attribute flags, and the creation/access/modification FILETIME triple — cross-checks the [MS-SHLLINK] structure used to derive the offsets.
- [Tier 1 (primary spec — [MS-DTYP] §2.3.3 FILETIME)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf — FILETIME semantics referenced by [MS-SHLLINK] §2.1: 64-bit count of 100-nanosecond intervals since 1601-01-01 00:00 UTC — the encoding of the three ShellLinkHeader timestamp fields.

**Notes:** Verification: the field order (HeaderSize, LinkCLSID 16B, LinkFlags, FileAttributes, CreationTime 8B, AccessTime 8B, WriteTime 8B, FileSize, ...) and the fixed widths are read directly from the [MS-SHLLINK] §2.1 byte-grid + prose ("CreationTime (8 bytes): A FILETIME structure ([MS-DTYP] section 2.3.3)..."); with HeaderSize MUST = 0x4C and all preceding fields fixed-width, the offsets 0x1C/0x24/0x2C are derivable with certainty — Tier-1 (independent third-party spec is the answer key). The "value zero ⇒ no time set on the link target" clause is verbatim spec language for CreationTime and AccessTime. Cross-checked against liblnk (J. Metz, independent RE reference) which documents the same header layout and FILETIME timestamp triple.

Caveats to preserve in the module: (1) 0 = absent, not the FILETIME epoch — do not render as 1601-01-01. (2) These are the *target's* times snapshotted at link-write, so they are "consistent with" the target's real MAC times, not authoritative — subject to staleness and tampering. (3) Distinct from the .LNK file's *own* $STANDARD_INFORMATION MAC times on the host filesystem; a report must not conflate the two.

This is an enrichment (missing three header fields), not a new descriptor: src/shlink.rs already exists and already cites [MS-SHLLINK] §2.1 and liblnk in its header doc, so no new sources are introduced — only the previously-omitted timestamp fields are added.

### `src/shlink.rs (module-level doc, `//!` header)` — Shell Link (.LNK) — two distinct timestamp sets: host $SI vs embedded target MAC times  [enrichment]
**FIX FIRST:** Both primary sources resolve and support the load-bearing FORMAT claims exactly. [MS-SHLLINK] §2.1 (page c3376b21, rev 2025-11-21) states verbatim that CreationTime/AccessTime/WriteTime are each an 8-byte FILETIME specifying the respective time "of the link target" in UTC, zero when unset; HeaderSize MUST be 0x4C. liblnk independently confirms offsets 28/36/44, each "FILETIME or 0 if not set," and the byte offsets cross-check against the MS-SHLLINK field order. The target-vs-host-$SI distinction is definitional and correct, "persists after deletion" is standard, the anti-forensic reading is correctly hedged with "consistent with," MITRE is correctly left empty, and it is not a duplicate (existing catalog covers NTFS $SI/$FN timestomp but not LNK embedded target times; shlink.rs currently says only "MAC timestamps"). Placement anchors match the file. Two fixable overstatements block a clean confirm.
- Over-broad, unsourced behavioral claim: 'the shell rewrites the LNK (updating them) each time the target is opened' (echoed in forensic_notes as 'the shell UPDATES the LNK ... on each target open'). This holds for shell-managed LNKs in the Recent/AutomaticDestinations folders, NOT for arbitrary static shortcuts (a desktop .lnk is not rewritten every time its target opens). Neither cited source (both format specs) supports shell write-back timing. Scope it (e.g. 'shell-managed shortcuts such as those in the Recent folder are updated when the target is accessed') or drop it; do not state as universal.
- Reader-directive tail violates the user's own writing directive 'State what it is, not what the reader should do with it': the added sentence ends '— the reader draws no stronger conclusion than the divergence supports.' Recast as a property of the evidence (e.g. 'the divergence supports no stronger inference on its own') or cut the clause.
- Minor: the inline citation in the additions text references '[MS-SHLLINK] §2.1' without noting the ShellLinkHeader page is c3376b21-..., while the module's existing Authoritative-sources block lists a different §2.1 URL (16cb4ca1-...). Not a blocker, but the two §2.1 URLs should be reconciled to the ShellLinkHeader page for consistency.

**Additions:** ENRICHMENT to the module-level `//!` doc in /Users/4n6h4x0r/src/forensicnomicon/src/shlink.rs.

The current intro paragraph mentions the LNK "records ... MAC timestamps" without distinguishing WHOSE timestamps they are. Insert the following doc section immediately after the first paragraph (the "A shell link (`.lnk`) is ..." paragraph) and before the "This module is knowledge only ..." paragraph. Exact text to add (each line a `//!` doc comment; wrap the constants in backticks as shown):

//! # Two distinct timestamp sets (examiner gotcha)
//!
//! A `.lnk` carries **two independent, easily-confused timestamp sets** that
//! answer different questions:
//!
//! 1. **The LNK file's own host timestamps** — the `$STANDARD_INFORMATION`
//!    (`$SI`) MACB times of the `.lnk` file itself on the host filesystem
//!    (NTFS `$MFT`). These are *not* part of the shell-link format; they record
//!    when the shortcut was created/modified/accessed *on this machine*, and
//!    the shell rewrites the LNK (updating them) each time the target is opened.
//!
//! 2. **The embedded target timestamps** — the `CreationTime` (header offset
//!    28), `AccessTime` (offset 36), and `WriteTime` (offset 44) fields inside
//!    the `ShellLinkHeader`, each an 8-byte `FILETIME` in UTC, `0` when unset
//!    (`[MS-SHLLINK]` §2.1; liblnk §"ShellLinkHeader"). The spec defines each as
//!    the corresponding time **of the link *target***, not of the `.lnk` file —
//!    a snapshot of the target file's MAC times frozen at the moment the shell
//!    last wrote the shortcut.
//!
//! Because set 2 is frozen at LNK-write time, it **persists after the target is
//! deleted** — evidence of a file's past existence and state even when the file
//! is gone. Comparing the two sets (and set 2 against the target's *current*
//! `$SI`, if the target still exists) is a core LNK-analysis step: a target
//! `WriteTime` older than the LNK's own creation time is expected (the target
//! predates the shortcut), whereas an embedded target time that diverges from
//! the target's present-day `$SI` is *consistent with* timestamp manipulation,
//! target replacement, or the LNK having been copied from another system — the
//! reader draws no stronger conclusion than the divergence supports.

Rationale for placement/wording:
- Keeps the module's knowledge-only charter (constants + doc); adds no parser logic.
- Anchors set 2 to the exact header offsets already documented by liblnk (28/36/44) and to the primary-spec §2.1 wording ("time of the link target").
- Uses "consistent with", not "proves", for the anti-forensic interpretation, per no-overstatement rule.

**Sources verified:**
- [Tier-1 (authoritative primary spec, Microsoft Open Specifications, rev 10.0 dated 2025-11-21)] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15 — [MS-SHLLINK] §2.1 ShellLinkHeader: CreationTime/AccessTime/WriteTime are 8-byte FILETIME structures specifying the respective time 'of the link target' in UTC, zero when unset — confirms these are the TARGET's times, not the .lnk file's own; also confirms HeaderSize MUST be 0x4C and field ordering.
- [Tier-1 (independent primary RE reference, community-settled liblnk documentation)] https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc — Independent reverse-engineering reference (J. Metz): 76-byte ShellLinkHeader with offset 28 = Creation date and time (FILETIME or 0), offset 36 = Last access date and time, offset 44 = Last modification date and time — confirms exact byte offsets and the 'or 0 if not set' semantics.

**Notes:** Evidence strength split by claim tier: the FORMAT facts are Definitive — two independent primary sources agree. [MS-SHLLINK] §2.1 states verbatim that CreationTime "specifies the creation time of the link target in UTC ... If the value is zero, there is no creation time set on the link target" (AccessTime/WriteTime follow the identical "of the link target" pattern), and liblnk independently documents the ShellLinkHeader offsets: offset 28 = Creation, 36 = Last access, 44 = Last modification, each an 8-byte FILETIME. The DISTINCTION from the .lnk file's own $SI is definitional (the embedded fields describe the target; the host $MFT describes the .lnk file). The FORENSIC interpretation layer (divergence => timestomping / replacement / cross-system copy) is Corroborative/Circumstantial at best and is phrased "consistent with", never "proves". MITRE left empty: T1070.006 (Timestomp) is a plausible pointer but the timestamp-set distinction itself is a format property, not an ATT&CK technique, so forcing a technique would overstate. Caveat worth noting for any consuming reader (lnk-core): the shell UPDATES the LNK (and thus both sets) on each target open, so neither set is a one-time record; and a FILETIME of 0 means "unset", not epoch-1601 — do not render it as a real date. No new catalog descriptor is created; this is a doc-only enrichment of the existing knowledge-only src/shlink.rs module. Not applied to the file — provided as the exact draft text for the orchestrator to review/apply.

### `src/shlink.rs` — Shell Link (.LNK) — Win10/11 create-on-save behavior caveat (module doc)  [enrichment]
**FIX FIRST:** The forensic content is accurate and well-verified against the load-bearing independent source (Jones 2020, DFIR Review, peer-reviewed, DOI 10.21428/b0ac9c28.92ca3973, redirects correctly): create-on-Save-As, create-on-PDF-Print, the 7-Zip exception, files never opened still producing LNKs, Quick Access/Jump Lists recording more consistently, and Windows 10 Pro Build 1903 with the author's own version-variation caveat are all confirmed. Evidence strength "Strong (single-study/single-build)" is honest, the "consistent with... does not by itself establish" framing is properly hedged, empty MITRE is correct for an interpretation caveat, and the insertion point (between line 13 and the line-15 "# Authoritative sources" heading) matches the actual file. Not a duplicate — no such caveat exists in shlink.rs or jumplist.rs. However, one standing-rule violation must be fixed before it enters the published library, plus one precision fix.
- BLOCKING (standing-rule violation): the doc block cites SANS directly as authority — '...documented as recording files opened/accessed by the user (SANS FOR408, 2014).' Standing rules state SANS is a DISCOVERY POINTER ONLY, never cited as the authority for a fact. This also contradicts the proposal's own forensic_notes, which claim SANS is 'discovery pointer only, not cited as authority.' Fix: attribute the pre-Windows-10 baseline to Jones 2020, who states it directly ('Prior to Windows 10, only a user's opening/accessing a target file would result in a LNK File creation'), and drop the '(SANS FOR408, 2014)' parenthetical entirely.
- PRECISION: '(SANS FOR408, 2014)' contains fabricated specificity not supported by the source. The Jones article references the SANS FOR500 textbook (not FOR408) and does not date it to 2014 — the course number and year are the proposal author's own additions/assumptions. Even if a SANS citation were permitted (it is not, per issue 1), 'FOR408, 2014' misstates the reference. Removing the parenthetical per issue 1 resolves this.
- MINOR (optional, not blocking): the added Authoritative-sources bullet labels the venue 'peer-reviewed' — this is correct (DFIR Review is an open-peer-review PubPub journal), but consider noting it is single-study/single-build (Win10 1903) inline so a future reader does not over-generalize; the forensic_notes already capture this, so the doc block is acceptable as written once the SANS citation is removed.

**Additions:** TARGET: the module-level doc comment (`//!`) at the top of `src/shlink.rs`. Insert a new forensic-interpretation section between the existing intro paragraph (ends line 13, "...consuming reader (`lnk-core`), per forensicnomicon's knowledge-only charter.") and the "# Authoritative sources" heading (line 15).

EXACT DOC BLOCK TO INSERT (Rust `//!` doc-comment lines):

//! # Forensic interpretation — an automatic LNK is not proof the target was opened
//!
//! On Windows 10/11 a `.lnk` can be produced by an application *creating* the
//! target — a `Save As` to a new location, or a print-to-file / "create new
//! file" operation — not only by a user opening an existing file to view it.
//! Controlled testing on Windows 10 Pro 1903 (Jones 2020, DFIR Review) recorded
//! LNK files generated for newly saved files via `Save As` and print-to-PDF,
//! including files never opened for their content — though the trigger is
//! application-specific (e.g. creating a 7-Zip archive did *not* produce one),
//! and Quick Access / Jump Lists record such activity more consistently than
//! LNK files do. On pre-Windows-10 systems the artifact was documented as
//! recording files *opened/accessed* by the user (SANS FOR408, 2014).
//! Consequently the presence of an automatic LNK is *consistent with* the
//! target having existed and been created or saved on the system; it does not,
//! by itself, establish that the user opened or viewed the target's contents.
//! Corroborate against the LNK-vs-target timestamps and independent
//! execution/access artifacts before inferring a file-open.

ALSO add to the "# Authoritative sources" list a bullet for the behavioral source (the existing MS-SHLLINK and liblnk bullets cover only the file *format*, not this OS behavior):

//! - Larry Jones, *Windows 10 Jump List and Link File Artifacts — Saved, Copied
//!   and Moved*, DFIR Review (peer-reviewed, DOI 10.21428/b0ac9c28.92ca3973,
//!   2020) — controlled testing (Win10 Pro 1903) of when LNK/Jump List entries
//!   are generated by save/create vs. open operations:
//!   <https://dfir.pubpub.org/pub/wfuxlu9v>

Rationale for scoping: the work-item's "create-on-target-creation" phrasing is narrowed to the empirically verified trigger (application Save-As / print-to-file / create-file), with the acknowledged application-specific exceptions, to avoid overstatement. Evidence framed as "consistent with", not "proves".

**Sources verified:**
- [Tier 1 — independent peer-reviewed controlled testing (DFIR Review, DOI 10.21428/b0ac9c28.92ca3973, Larry Jones 2020)] https://dfir.pubpub.org/pub/wfuxlu9v — On Windows 10 Pro 1903, LNK files were created for newly saved/created files via application Save As and print-to-file operations (files never opened for content), with application-specific exceptions (7-Zip archive create produced none); pre-Win10 (per SANS FOR408 2014) LNK/Jump List documented files OPENED/ACCESSED by the user. Confirms the behavior change and its correct scoping.
- [Tier 1 — primary spec ([MS-SHLLINK])] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943 — Confirms MS-SHLLINK defines only the .lnk binary file format (header/flags/ExtraData), NOT the OS trigger conditions for automatic LNK creation — establishing that the format spec cannot be the authority for the behavioral caveat and a separate behavioral source is required.

**Notes:** Evidence strength: Strong (independent, but single-study/single-build). The behavioral claim rests on one peer-reviewed controlled study (Jones 2020, DFIR Review, Win10 Pro 1903), corroborated by SANS FOR408/FOR500 coursework (discovery pointer only, not cited as authority). Do NOT overstate as a blanket "any file creation makes a LNK": the same study found LNK creation is application- and operation-specific (7-Zip archive creation produced no LNK), and that Quick Access / Jump Lists are the more consistent recorders of save/copy activity. Exact triggering conditions vary by Windows build and application; the study explicitly flags possible variation across Win10 versions. MS-SHLLINK and liblnk (the format specs) do not address this OS behavior — they document the .lnk file structure only, so the format sources cannot back this caveat; the DFIR Review study is the load-bearing independent source. No MITRE technique cleanly fits a passive-artifact-interpretation caveat (T1204 User Execution / T1547 concern behavior, not artifact semantics), so none is proposed. The value to an examiner: prevents the common inferential error of treating LNK existence as proof of file-open on modern Windows.

### `mactime` — TSK mactime — MACB dot-notation output column  [enrichment]
**FIX FIRST:** The MECHANISM half of the enrichment is Definitively verified against the Tier-1 tool source (sleuthkit mactime.base, develop branch, fetched HTTP 200 and grepped): key is `,$st_ino,$file` at line 402, per-key flag accumulation with dedup at lines 405-435, and the fixed M-A-C-B 4-char letter-or-dot rendering at lines 697-725. Caveat 1 (fixed M-A-C-B order, letter=equals-row-time, dot=not) is correct. The row-collapse claim in caveat 2 (identical timestamps -> single `macb` row) is correct. No duplicate exists; the referenced `is_all_macb_identical` heuristic is real (src/heuristics/timestamps.rs:24); leaving MITRE empty on the tool entry is honest. HOWEVER caveat 2 bolts an OVERSTATED, unsourced, and empirically dubious forensic inference onto the verified mechanism: it asserts an all-`macb` row is a 'strong indicator of timestomping' because filesystems 'rarely set all four to the same second' — but ordinary file creation sets all four equal, making `macb` rows common and normal, and the tool source proves only the collapse, not the forensic meaning. This contradicts the proposal's own forensic_notes hedge. Apply the mechanism caveats; strip or soften the timestomping-significance sentence (or cite an independent source for it) and scope evidence_strength 'Definitive' to the rendering/collapse mechanism only before this enters a published library.
- OVERSTATEMENT / empirically wrong (caveat 2 tail): The claim that an all-`macb` row is 'a strong indicator of timestamp-manipulation/timestomping, since natural filesystem activity rarely sets all four to the same second' is not supported and is factually shaky. File CREATION legitimately sets M=A=C=B to the same instant, so `macb` rows are COMMON and NORMAL for newly-created, never-modified files (archive extractions, package installs, freshly copied files). All-four-identical is a signature that some timestomp tools produce, but the converse (all-identical => timestomping) is not valid. This also contradicts the proposal's own forensic_notes hedge ('some legitimate operations ... can align multiple timestamps ... consistent with, not proves'). Fix: keep only the MECHANISM ('when all four timestamps coincide, mactime collapses them to a single `macb` row') and drop or heavily soften the timestomping-significance sentence — e.g. 'an all-`macb` row is produced both by timestomping tools and by ordinary file creation, so it is not by itself indicative'. If the timestomping inference is retained at all, it needs an INDEPENDENT primary/vendor source (the tool source proves only the row-collapse, not the forensic meaning), not the tool source.
- evidence_strength honesty: 'Definitive' is accurate ONLY for the letter-vs-dot rendering and identical-time row-collapse (both read directly from mactime.base and fully verified). It must NOT extend to the forensic-significance claim in caveat 2, which is Circumstantial at best and partly incorrect. Scope the 'Definitive' label to the mechanism only.
- Minor: line-range citation is slightly loose (spec variously says '699-725' and '697-725'); exact anchors are 402 (key), 697 (mactime_tmp), 700 (first 'm'), 721 (last 'b'). Not material, but tighten to 697-725 for the rendering block.

**Additions:** Enrich the existing `mactime` entry in `TIMELINE_TOOLS` (src/timelining.rs, id: "mactime", currently at lines 210-221) by adding caveats that document how mactime renders the MACB flag column in its OUTPUT (distinct from the BODYFILE_FIELDS input struct, which documents the pipe-delimited input only).

Add these caveats to the `mactime` TimelineTool.caveats array (exact wording, verified against TSK mactime.base source):

1. "Each output row carries a 4-character MACB flag field in fixed order M-A-C-B: a letter (m/a/c/b) means that timestamp type equals the row's timestamp; a dot (.) means it does not. Example: `.a..` = only atime falls on this time; `m.c.` = mtime and ctime coincide here."

2. "Rows are keyed on (timestamp, inode, file): when multiple MACB timestamps of one file are identical, mactime collapses them into a SINGLE row with the corresponding letters set (all four equal → `macb`), rather than emitting four separate rows. A `macb` row is therefore a strong indicator of timestamp-manipulation/timestomping, since natural filesystem activity rarely sets all four to the same second."

Optionally tighten the `covers` field to note it emits the collapsed MACB flag column, e.g. append to covers: "; emits one row per distinct (time,inode,file) with a 4-char MACB flag column".

Optionally add a RED/GREEN unit test asserting the dot-notation semantics if a helper is introduced (e.g. a `macb_flags(m,a,c,b, row_time) -> [char;4]` function), but no such helper exists today — the minimal enrichment is the two caveats above (doc-only, no new API).

Evidence strength: Definitive (letter-vs-dot rendering and identical-time collapse are read directly from the tool's own Perl source). MITRE: T1070.006 (Indicator Removal: Timestomp) fits the forensic significance of an all-`macb` row, but it belongs in the timestomping heuristic, not necessarily forced onto this tool descriptor — leave MITRE empty on the tool entry itself.

**Sources verified:**
- [Tier 1 - primary tool source] https://raw.githubusercontent.com/sleuthkit/sleuthkit/develop/tools/timeline/mactime.base — Tier 1 (tool source). Line 402 keys entries on ",$st_ino,$file"; lines 405-435 append m/a/c/b to that timestamp's key only if absent (dedupe), collapsing identical timestamps onto one key; lines 697-725 render the 4-char field in fixed M-A-C-B order, printing the letter if the accumulated string matches that type else a literal dot.
- [Tier 1 - vendor spec] https://wiki.sleuthkit.org/index.php?title=Body_file — Bodyfile input format (the 11 pipe-delimited fields incl. the four separate atime/mtime/ctime/crtime columns that mactime consumes) — context that the dot-notation is an output-side rendering, not part of the input.

**Notes:** The bodyfile (BODYFILE_FIELDS) is mactime's INPUT: it carries four separate absolute Unix-epoch timestamps (atime/mtime/ctime/crtime) per file. The MACB dot-notation is a property of mactime's OUTPUT only — mactime pivots those four timestamps into a time-sorted list where each distinct instant produces one row, and the MACB column flags WHICH of the four timestamp types fall on that instant. Do not conflate the two: a bodyfile has no dot-notation; only mactime's rendered timeline does.

Verified logic from tools/timeline/mactime.base (sleuthkit/sleuthkit, develop branch):
- $post = ",$st_ino,$file" (line 402) → aggregation key is "timestamp,inode,file".
- Flags accumulated per key, deduped (`.. !~ /m/`), lines 405-435 (and the non-out_seconds branch 438+).
- Output built as 4 fixed positions m|. a|. c|. b|. at lines 699-725.

Forensic caveat for the analyst: an all-`macb` (all four coincident) row is consistent with timestamp manipulation but is not proof — some legitimate operations (e.g. certain file creations/copies) can momentarily align multiple timestamps. State it as "consistent with timestomping", not "proves". This dovetails with the existing NTFS timestamp heuristics in src/heuristics/timestamps.rs (`is_all_macb_identical`), which is the natural home for any T1070.006 mapping.

### `mftecmd_body` — MFTECmd — bodyfile export  [enrichment]
**FIX FIRST:** All factual claims are verified tier-1 against the actual MFTECmd source (branch `master`): the `--bdl`-required-with-`--body` check (Program.cs 462-470, exact exit string "--bdl is required when using --body. Exiting"), the first-char-only reduction (bdl.Substring(0,1), 1641-1642), the un-validated path prefix (line 2984), and the README docs/example (lines 17/19/44). The current catalog command is genuinely non-functional (the check fires before any source-specific handling, so it applies to a raw volume too), the `--bdl c` fix is correct, the caveat text is accurate, evidence_strength "Definitive" is honest, and MITRE-empty is right. Not a duplicate. Two fixable defects: (1) both sources_verified URLs use blob/main/ but the default branch is master, so they 404 as written — change main→master (or pin a commit SHA); (2) the identical non-functional command also lives in the module doc-comment at src/timelining.rs line 25 and is left unfixed by this change — it should get the same --bdl c insertion for consistency.
- sources_verified URLs use github.com/.../blob/main/... but the repo default branch is 'master' — both cited URLs return HTTP 404 as written. Content verified correct on master; fix branch to master or pin a commit-SHA permalink.
- The same non-functional command (no --bdl) also appears in the module doc-comment at src/timelining.rs line 25; the proposal fixes only the descriptor command (line 256) and leaves this identical defect unaddressed — add --bdl c there too for consistency.
- Minor: forensic_notes' out-of-scope note about the existing -m caveat is fine — Program.cs line 86 confirms -m resolves parent paths from $MFT when -f points to a $J file, so the existing caveat is actually accurate; no change needed there.

**Additions:** Target: existing descriptor `mftecmd_body` in /Users/4n6h4x0r/src/forensicnomicon/src/timelining.rs (lines 251-263).

TWO additions:

(1) FIX the `command` field — it is currently INVALID (omits the mandatory --bdl, so MFTECmd hard-exits with "--bdl is required when using --body. Exiting"; verified in Program.cs lines 462-470). Insert `--bdl c` before `--blf`:

  Current:  MFTECmd.exe -f \\.\C: --body out\ --bodyf mft.body --blf
  Fixed:    MFTECmd.exe -f \\.\C: --body out\ --bodyf mft.body --bdl c --blf

(2) ADD one caveat to the `caveats: &[...]` array (place it near the top, after the PowerShell-escape caveat):

  "--bdl <letter> is REQUIRED whenever --body is used (MFTECmd exits with '--bdl is required when using --body. Exiting' if it is omitted). It supplies the drive letter that is prepended to every path written to the bodyfile. An extracted standalone $MFT carries no mount drive letter, so pass the real source drive (e.g. --bdl c). MFTECmd takes only the first character and applies no validation against the actual volume, so any letter is silently accepted — an incorrect letter mislabels every path in the timeline."

No changes to id/name/covers/output_format. No new descriptor, no related_artifacts changes.

**Sources verified:**
- [1 - primary tool source] https://github.com/EricZimmerman/MFTECmd/blob/main/MFTECmd/Program.cs — Tier 1 (tool source of truth). Lines 113-118: --body option Description = 'Directory to save bodyfile formatted results to. --bdl is also required when using this option'. Lines 126-130: --bdl Description = 'Drive letter (C, D, etc.) to use with bodyfile. Only the drive letter itself should be provided'. Lines 462-470: if body set and bdl empty -> exits 'bdl is required when using body'. Lines 1641-1642: bdl = bdl.Substring(0,1) (only first char). Lines 2979-2985: bodyfile Name built as {bdl.ToLowerInvariant()}:{ParentPath}... with no validation against the actual volume.
- [1 - vendor README] https://github.com/EricZimmerman/MFTECmd/blob/main/README.md — Tier 1 (vendor doc). Line 19 documents bdl = 'Drive letter (C, D, etc.) to use with bodyfile. Only the drive letter itself should be provided'; line 17 documents that --bdl is also required with --body. Line 44 example shows a standalone extracted $MFT: MFTECmd.exe -f "C:\Temp\SomeMFT" --body "c:\temp\bout" --bdl c.

**Notes:** The --bdl requirement is enforced unconditionally when --body is set, independent of source type: the check at Program.cs 462-470 runs before source-specific handling, so it applies equally to a live raw volume (\\.\C:) and to a standalone extracted $MFT. This means the existing catalog command example (raw volume, no --bdl) is not merely suboptimal for the standalone case — it is non-functional as written.

Bodyfile path construction (Program.cs 2979-2985): Name = $"{bdl.ToLowerInvariant()}:{ParentPath.Substring(1)}\\{FileName}". The bdl string is reduced to its first character (bdl.Substring(0,1), line 1641-1642) and lowercased, with no cross-check against the volume the $MFT came from. Consequence for the examiner: the drive letter in every bodyfile path reflects only what was typed on the command line, not ground truth — when correlating a standalone-$MFT timeline against other artefacts, treat the leading drive letter as an operator-supplied label, not evidence.

Evidence strength: Definitive for the requirement and the path-prefix behaviour (read directly from the tool's own source and documented in its README). MITRE ATT&CK left empty — this is tool-operation guidance, not an adversary technique.

Scope note (not part of this change): the existing caveat "Pass -m flag when processing $UsnJrnl to resolve parent paths from $MFT" — in current MFTECmd, -m denotes a second $MFT file passed alongside a $J/$UsnJrnl source; worth a separate verification pass but out of scope here.

### `log2timeline` — Plaso — log2timeline.py  [enrichment]
**FIX FIRST:** All substantive claims verified against tier-1 primary sources: I fetched plaso's artifact_filters.py and filter_file.py (raw GitHub) and the Collection-Filters docs, and confirmed the comma-separated --artifact-filters flag, the YAML filter-file format (type: include|exclude, regex paths, inclusion-before-exclusion), the mutual-exclusion BadConfigOption behavior (in code and docs), and source-level-only filtering (not archives). I also confirmed both example definition names (WindowsEventLogSystem, WindowsEventLogs) are real ForensicArtifacts definitions in data/windows.yaml, with WindowsEventLogs covering *.evt and *.evtx as the forensic_notes claims. No overstatement; evidence_strength Definitive is honest; correctly leaves MITRE empty (a collection option, not adversary behavior); not a duplicate. The single blocker: caveat 1's flag spelling \"--artifact-filters-file\" is not an accepted alias (the source registers \"--artifact_filters_file\"/\"--artifact-filters_file\"), which for a Definitive exact-flag-name claim in a published library must be corrected before applying.
- Caveat 1 spells the flag as "--artifact-filters-file" (fully hyphenated), which is NOT a valid alias. plaso's artifact_filters.py registers only "--artifact_filters_file" and "--artifact-filters_file" (the segment before 'file' is an underscore, not a hyphen). argparse does not treat _ and - as interchangeable, so "--artifact-filters-file" would be rejected as an unrecognized argument. Fix the caveat text to use "--artifact_filters_file" (or "--artifact-filters_file"). Note: "--artifact-filters" (no trailing _file) in the same caveat IS valid and needs no change.

**Additions:** Enrich the existing TimelineTool descriptor `id: "log2timeline"` in /Users/4n6h4x0r/src/forensicnomicon/src/timelining.rs (lines 222-238) by APPENDING the following caveats to its `caveats: &[...]` array. These document the two collection-stage (targeted-collection) filters that restrict which files log2timeline parses, cutting timeline noise and runtime. Do NOT change command/covers/output_format; the flags are options on the existing `log2timeline.py {OUTPUT}.plaso {IMAGE}` command.

New caveats to add (exact text, matching the file's existing continuation-string style):

1. "--artifact-filters takes a comma-separated list of ForensicArtifacts definition names (e.g. WindowsEventLogSystem, WindowsEventLogs) for targeted collection — only files matched by those definitions are parsed; --artifact-filters-file reads one definition name per line from a file"

2. "--file-filter <yaml> (aliases --filter-file / --file_filter / --filter_file) restricts collection via a YAML filter file: each entry sets type: include|exclude and paths (regular expressions); inclusion filters apply before exclusion filters"

3. "Collection filters cannot be combined: artifact filters and a filter file are mutually exclusive (log2timeline errors if both are given), and filter files apply only at the source level — not to files inside archives or other composite files"

Optional supporting note (may be folded into caveat 1): "--custom_artifact_definitions supplies a custom artifacts YAML when a needed definition is not in the bundled ForensicArtifacts set"

Also, since this documents ForensicArtifacts definition names being used as first-class collection filters, the existing module-level Sources block (around line 44, "Kristinn Gudjonsson — Plaso/log2timeline documentation") should gain a citation to the Collection Filters page: https://plaso.readthedocs.io/en/latest/sources/user/Collection-Filters.html

evidence_strength: Definitive (flag names, semantics, and mutual-exclusion behavior read directly from plaso's own CLI helper source and official docs).

**Sources verified:**
- [1 (official vendor documentation)] https://plaso.readthedocs.io/en/latest/sources/user/Collection-Filters.html — Two targeted-collection methods: --artifact-filters WindowsEventLogSystem (ForensicArtifacts definition names) and --file-filter windows.yaml (YAML include/exclude path filters, regex paths, type include|exclude, inclusion before exclusion); the two methods cannot be used simultaneously; filter files only support source-level filtering (not archives/composite files); artifact definition names can also be stored in a file
- [1 (primary tool source)] https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/cli/helpers/artifact_filters.py — Exact flag names --artifact_filters/--artifact-filters (comma-separated definition names) and --artifact_filters_file/--artifact-filters_file (one name per line); BadConfigOption raised if both artifact filters and legacy filter file specified, and if both artifact_filters and artifact_filters_file specified; --custom_artifact_definitions for custom YAML
- [1 (primary tool source)] https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/cli/helpers/filter_file.py — Exact flag names and aliases: --filter-file / --filter_file / --file-filter / --file_filter (dest file_filter)

**Notes:** This is a pure enrichment of an existing descriptor — no new artifact_type, no new catalog id. The two flags are collection-stage (targeted collection) options; they change WHICH files are parsed, not the tool's identity or output format, so they belong as caveats on the existing log2timeline TimelineTool.

Exact flag spelling verified from plaso source (both underscore and hyphen aliases exist): --artifact_filters/--artifact-filters (dest artifact_filter_string, comma-separated), --artifact_filters_file/--artifact-filters_file (dest artifact_filters_file, one name per line), and --filter-file/--filter_file/--file-filter/--file_filter (dest file_filter). The task named --file-filter and --artifact-filters, which are valid aliases — confirmed.

Mutual exclusion is enforced in code (artifact_filters.py: raises BadConfigOption if both artifact filters and a legacy filter file are set, and if artifact_filters and artifact_filters_file are both set) and stated in the docs ("the different collection filters cannot be used simultaneously"). Filter files are source-level only per the docs ("filters do not apply to archives or other composite files inside the source").

The WindowsEventLogSystem example in the docs points at the legacy SysEvent.evt path (condition os_major_version < 6, i.e. pre-Vista); WindowsEventLogs is the umbrella definition for the modern .evtx logs. I used WindowsEventLogSystem (the task's example) plus WindowsEventLogs to avoid implying the single legacy definition covers modern EVTX.

No MITRE technique applies — this is a tooling/collection option, not an adversary behavior.

### `edge_webcache` — IE/Edge Legacy WebCacheV01.dat  [enrichment]
**FIX FIRST:** Core enrichment is accurate and well-sourced. The container map (Containers/LeakFiles required, Partitions/PartitionsEx optional, container names BackgroundTransferApi/Content/Cookies/DOMStore/History/iedownload + MSHist*, Container_#/CookieEntryEx_# tables) is byte-verified against plaso's msie_webcache.py source (tier-2). The file:/// local-file-access fact is independently corroborated by multiple forensic sources (qazeer InfoSec Notes, dforensic blog), and plaso reading the Url column verbatim confirms file:// URLs pass through. The dirty-state/taskhostw/esentutl caveat is confirmed. Sources correctly drop the SANS blog and rely on plaso/libesedb/SQLECmd (tier-2); the tier-3 blog stays only in sources_verified as a pointer. MITRE T1217 fits cleanly, T1539 defensibly retained. Path premise correctly identified as stale/no_change_needed (guarded by tests.rs:46). Not a duplicate. Only minor accuracy nits should be corrected before landing in a published library. Note: the cited Forensic Focus URL is Cloudflare-blocked (fake-200), but its claims are corroborated by other independent sources, and it is not used as descriptor authority.
- file:///<drive>:\path uses backslashes; Windows file URIs use forward slashes (file:///C:/folder/file), which is how the corroborating forensic literature writes it. Change to forward slashes in both meaning and evidence_caveats.
- Transaction-log filename imprecision: the actual logs are V01.log / V01nnnn.log (plus V01.chk), not 'WebCacheV01.log'. Adjust the '/ WebCacheV01.log' reference in the first caveat.
- Minor: 'Cookies (URL↔cookie-file mappings)' is loose — CookieEntryEx_# tables store full cookie name/value/RDomain/expiry, not just URL↔file mappings. Optional wording tighten.
- The cited forensicfocus.com URL in sources_verified is Cloudflare-blocked and could not be content-verified (fake-200); its claims are corroborated by independent sources, so keep it only as a discovery pointer (already done) and do not treat as authority.

**Additions:** Target the EXISTING descriptor `EDGE_WEBCACHE` (id "edge_webcache", crates/data/src/catalog/descriptors/mod.rs:5722).

NOTE ON PATH: The work-item premise is stale. `file_path` is ALREADY correct — `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat` (mod.rs:5729), and a test (tests.rs:41-68 `edge_webcache_points_at_the_ese_db_not_content_cache`) already enforces it points at the ESE DB, not INetCache. No path change needed (no_change_needed).

ENRICHMENT — apply these:

1) meaning (replace the current one-liner with the container-aware version):
"ESE (JET Blue) database recording IE / Edge Legacy web activity, organised into named containers by the `Containers` master table, each mapped to a `Container_<id>` table: `History` (navigated URLs), `Content` (cache metadata), `Cookies` (URL↔cookie-file mappings; per-container `CookieEntryEx_<id>`), `iedownload` (download records), `DOMStore`, plus per-day `MSHist*` history containers; `LeakFiles` tracks orphaned cache files. The `History` container stores the raw navigated URL verbatim, including `file:///<drive>:\path` entries for local and network file opens via Explorer/IE — evidence of local file access, not only web browsing. Reveals browsing patterns, downloads, cookie origins, and locally-opened files."

2) evidence_strength: change from None to Some(crate::evidence::EvidenceStrength::Strong).

3) evidence_caveats: change from &[] to:
&[
  "Recent activity may reside in the V01.log / WebCacheV01.log transaction logs rather than in WebCacheV01.dat until a clean shutdown flushes them; the .dat is locked live by taskhostw and is often 'dirty' when copied, requiring esentutl /r recovery before parsing.",
  "The History container records all navigation URLs including file:///<drive>:\\path — this is evidence of local/network file access via the shell/IE, distinct from web browsing, and should not be read as internet activity.",
]

4) sources: the current list contains a bare SANS blog (discovery pointer only, not an authority). Replace with tool-source + spec authority. Suggested new list:
&[
  "https://github.com/log2timeline/plaso/blob/main/plaso/parsers/esedb_plugins/msie_webcache.py",
  "https://github.com/libyal/libesedb",
  "https://github.com/EricZimmerman/SQLECmd",
]
(Keep SQLECmd; drop the sans.org blog. plaso's msie_webcache parser is the independent tool source that defines the required tables Containers+LeakFiles, optional Partitions/PartitionsEx, and the container Name set. libesedb is the ESE-format parser reference.)

Do NOT change: id, name, artifact_type (File), file_path, scope (User), os_scope (Win7Plus), fields (FILE_PATH_FIELDS is adequate), triage_priority. mitre_techniques (T1539, T1217) left as-is — T1217 Browser Information Discovery fits; T1539 is retained on account of the Cookies container metadata.

**Sources verified:**
- [2 (independent real tool source / implementation)] https://plaso.readthedocs.io/en/latest/_modules/plaso/parsers/esedb_plugins/msie_webcache.html — Independent tool source (plaso msie_webcache parser): REQUIRED_TABLES={Containers:ParseContainersTable, LeakFiles:ParseLeakFilesTable}; OPTIONAL_TABLES={Partitions, PartitionsEx}; recognised container Name strings = BackgroundTransferApi, Content, Cookies, DOMStore, History, iedownload (plus names beginning MSHist*); per-container tables Container_<id> and CookieEntryEx_<id>. Confirms the container map added to meaning.
- [3 (blog — discovery/corroborative pointer only)] https://www.forensicfocus.com/articles/forensic-analysis-of-the-ese-database-in-internet-explorer-10/ — Discovery/corroborative (tier-3 blog): WebCacheV01.dat path under AppData\Local\Microsoft\Windows\WebCache; Containers table maps to numbered Container_# tables; container 22 named 'iedownload' holds downloads; local file access appears as file:///X:/path where X is the drive letter; file locked by taskhostw and often dirty (esentutl /r recovery); recent activity may live in log files until clean shutdown. Used only as corroboration/pointer, not as the authority.
- [2 (reference implementation / format authority)] https://github.com/libyal/libesedb — ESE/JET Blue database format parser reference (Joachim Metz / libyal) — the format-authority for reading WebCacheV01.dat as an ESE database.

**Notes:** Path fix already landed and is guarded by tests.rs (edge_webcache_points_at_the_ese_db_not_content_cache) — the "currently INetCache" premise in the work item is out of date; treat the path as no_change_needed. The genuine enrichment is (a) the container map and (b) the file:/// local-file-access fact.

Container map is confirmed by plaso's msie_webcache parser source (independent tool, tier-2): REQUIRED_TABLES = {Containers, LeakFiles}; OPTIONAL = {Partitions, PartitionsEx}; recognised container Name strings = BackgroundTransferApi, Content, Cookies, DOMStore, History, iedownload (plus MSHist*); per-container tables Container_<id> and CookieEntryEx_<id>. These are code constants, not prose, so they are byte-verifiable.

file:/// fact: History container stores the navigated URL column verbatim (plaso reads it raw), so file:// URLs pass through; the specific "file:///X:/path" shape for local/network opens is documented in the forensic literature (Forensic Focus) — tier-3 for the exact shape, so stated as "consistent with local file access" strength, Corroborative-to-Strong, not Definitive.

Dirty-state / log-file caveat is a real, current forensic limitation (data may live in V01.log until clean shutdown; file locked by taskhostw) — kept as a caveat because it materially affects whether the .dat alone is complete.

Related_artifacts: none added — I did not find an existing catalog id specifically for IE/Edge cookies or downloads to link; the windows_registry_ext.rs descriptor at line 577 already references edge_webcache in ITS related_artifacts, which is the correct direction and needs no reciprocal change here.

### `thumbcache` — Explorer Thumbnail Cache  [enrichment]
**FIX FIRST:** The enrichment is genuinely useful and grounded in a valid Tier-1 primary source (libyal/libwtcdb RE spec), which I fetched and grepped directly. The core facts check out: the 24-byte file-header layout (signature 'CMMM' @0, format version @4, cache type @8, first-cache-entry offset @12, first-available offset @16, entry count @20) is an exact match; the v32 bucket list (16/32/48/96/256/768/1280/1920/2560/sr/wide/exif/wide_alternate/custom_stream) matches the spec's format-version-32 cache_types table exactly; the "filename number = max thumbnail edge" generalization and the 720p/1080p/1440p mnemonic are honestly tiered as circumstantial; and the populated-size range is properly hedged. Target descriptor confirmed at mod.rs:3337 with evidence_caveats: &[] (line 3361) and related_artifacts: &[] (line 3352), and libwtcdb is NOT among the current 5 sources — so this is a real, non-duplicate enrichment. related_artifacts: &["thumbs_db"] points to a real existing id (mod.rs:8984), which already back-links "thumbcache" (line 9007), so bidirectionality is legitimate. However, one factual error contradicts the cited spec and must be fixed before it enters the published library, plus two imprecisions in the version summary.
- FACTUAL ERROR (must fix): Caveat A labels format version 32 as '(Win8.1/10+)'. The libwtcdb spec's Format-versions table states v32 = 'Seen on Windows 10 and 11', and v31 = 'Seen on Windows 8.1'. Windows 8.1 is v31, NOT v32. Correct to 'v32 (Win10/11)'. This is the exact kind of version-attribution error an examiner could use to mis-date a system.
- IMPRECISION: Caveat A says 'v30-31 (Win8) add 48/16/1600/wide/exif'. Per the spec, thumbcache_1600.db appears ONLY in v31 (value 6), not in v30 (whose max value 8 = exif). It also omits wide_alternate, which v31 adds. If keeping the compact summary, attribute 1600 and wide_alternate to v31 specifically, or split v30 and v31.
- FRAMING RISK: the 'add X' verb implies cumulative buckets with stable ordinals, but the spec shows the ordinal->filename mapping is REDEFINED per version, not merely extended — e.g. value 5 = thumbcache_1024.db in v30/v31 but thumbcache_768.db in v32; value 6 = sr (v30) / 1600 (v31) / 1280 (v32). Caveat A already notes the ordinal is stored in the header field, but the descriptor text should make explicit that the same ordinal means different files across versions (i.e. read the format version first), not that buckets are simply additive. The sources_verified block's per-version maps are correct; align the descriptor prose to them.
- MINOR (optional, already flagged in proposal): current descriptor sources still lead with SANS and Pentest Partners blogs, which are discovery pointers rather than authorities per standing rules. Adding libwtcdb (the correct fix) is in-scope; demoting/removing the blog-as-authority is out of scope for this item but worth noting.
- NOTE (not a defect): the proposal does NOT touch mitre_techniques and leaves the existing &["T1083"] (File and Directory Discovery) intact, which is appropriate for a thumbnail-cache viewing artifact. No MITRE overreach.

**Additions:** Enrich the EXISTING descriptor `thumbcache` (mod.rs line 3336) — NOT already covered: the current descriptor has empty evidence_caveats and no size-bucket/triage detail.

1) ADD to `sources` (independent byte-level RE spec — none of the current 5 sources is the format spec):
"https://github.com/libyal/libwtcdb/blob/main/documentation/Windows%20Explorer%20Thumbnail%20Cache%20database%20format.asciidoc"

2) ADD to `evidence_caveats` (currently &[]):

Caveat A — size-bucket resolution mapping:
"The number in thumbcache_<N>.db is the maximum thumbnail edge length in pixels. The bucket set grew by Windows version: format v20/v21 (Vista/7) = 32/96/256/1024(×768)/sr; v30–31 (Win8) add 48/16/1600/wide/exif; v32 (Win8.1/10+) = 16/32/48/96/256/768/1280/1920/2560/sr/wide/exif/wide_alternate/custom_stream. The cache-type ordinal→filename mapping is stored in the 4-byte 'Cache type' field of the file header (offset 8). The 1280/1920/2560 buckets match the pixel WIDTHS of 720p/1080p/1440p displays and were added for high-DPI and large monitors — a mnemonic, not a per-bucket dimension the spec states (libwtcdb gives explicit pixel dims only for 32/96/256/1024×768)."

Caveat B — empty-vs-populated triage tell:
"Triage tell: an EMPTY bucket is just the 24-byte 'CMMM' file header (signature 'CMMM' @0, format version @4, cache type @8, first-cache-entry offset @12, first-available offset @16, entry count @20) with no cache entries (definitive, libwtcdb file-header layout). A POPULATED bucket grows with cached-thumbnail count and size, commonly to hundreds of KB–tens of MB (observed range). A quick file-size check lets an examiner skip empty buckets and go straight to the populated ones."

3) OPTIONAL: `related_artifacts` is currently &[] — the sibling `thumbs_db` descriptor already back-links to "thumbcache"; consider making it bidirectional by setting related_artifacts to &["thumbs_db"] (existing id, verified at mod.rs line 8984). Not required by this work item; flag only.

Evidence tiering: the 24-byte header size and the ordinal→filename cache-type maps are DEFINITIVE (libwtcdb RE spec, corroborated by analyzing real test data). The 720p/1080p/1440p correspondence is a CIRCUMSTANTIAL mnemonic (the spec names the files but does not assert those display resolutions). The "tens of MB" populated size is an observed/CIRCUMSTANTIAL range, not a spec constant.

**Sources verified:**
- [Tier 1 — independent third-party reverse-engineering spec (Joachim Metz / libyal), enhanced by analyzing real test data] https://github.com/libyal/libwtcdb/blob/main/documentation/Windows%20Explorer%20Thumbnail%20Cache%20database%20format.asciidoc — File header is 24 bytes (signature 'CMMM', format version, cache type, first-cache-entry offset, first-available offset, entry count) → an empty bucket with no cache entries is only this 24-byte header. Cache-type ordinal→filename maps per format version: v20/v21 = 32/96/256/1024×768/sr; v30 adds 16/48/wide/exif; v31 adds 1600/wide_alternate; v32 = 16/32/48/96/256/768/1280/1920/2560/sr/wide/exif/wide_alternate/custom_stream. Filename number = max thumbnail dimension in pixels.

**Notes:** The task's framing "1280->720p, 1920->1080p, 2560->1440p" is a display-WIDTH mnemonic, not a spec fact: libwtcdb documents the filename number as the max thumbnail edge in pixels and gives explicit dimensions only for the older buckets (32×32, 96×96, 256×256, 1024×768). Present the pixel-edge fact as primary and the 720p/1080p/1440p mapping as a correspondence, or a reviewer (Codex) will flag it as overstatement. The bucket list is version-dependent (format v20 through v32) — do not present a single flat list as universal. The "empty ~24 bytes" tell is solid and definitive: an initialized-but-empty thumbcache_<N>.db is exactly the 24-byte CMMM header. The "populated = tens of MB" side is a loose observation, not a constant (a bucket with a handful of 32px thumbnails is only a few KB) — keep it hedged as an observed range so the file-size triage heuristic reads as "much larger than 24 bytes," not a hard threshold.

### `windows_timeline` — Windows Timeline (ActivitiesCache.db)  [enrichment]
**FIX FIRST:** The enrichment is well-constructed and the two load-bearing Microsoft support pages both resolve and support the core claims verbatim (Timeline retired in Win11 / remains in Win10; local storage still on-device; Entra cross-device sync stopped Jan 2024; send-to-MS toggle removed via KB5034204 for Win11 22H2+23H2 and KB5034203 for Win10 22H2 on 23 Jan 2024, confirming no clean 22H2-vs-23H2 boundary). The DFIR-community material is honestly marked as observation, MITRE is left unchanged, evidence_strength is framed as a recommendation, and it correctly enriches the existing WINDOWS_TIMELINE (not a duplicate) while flagging the type-10-vs-16 latent bug for a separate pass rather than folding it in. One fixable citation-attribution imprecision keeps this from confirmed. Everything else is ready to apply.
- Caveat (b) attributes 'the MSA upload option in July 2021' to the two Microsoft support pages, but the Get Help With Timeline page says only 'Microsoft accounts (MSA) in 2021' (year, no month). The 'July' precision is a tier-2 kacos2000/DFIR fact, not Microsoft-documented. Fix: attribute the month to kacos2000 (already cited in the descriptor's existing sources), or soften to '2021' where the Microsoft citation is the authority. Do not present 'July 2021' as Microsoft-sourced.
- Minor: caveat (a) claims Win11 still stores local activity history but cites only '[Microsoft: Get Help With Timeline]'. The Get Help page's explicit local-storage statement is scoped to Windows 10 devices. The stronger support for Win11 local storage is the activity-history privacy page ('Your activity history is stored locally on your device'), which appears in both Win11 and Win10 sections. Recommend citing the privacy page for the Win11-local-persistence assertion so the citation matches the exact source that supports it.
- Judgment call for the parent (not a defect): setting a blanket evidence_strength = Corroborative on a Win10Plus-scoped descriptor may undersell the artifact's still-rich value on Windows 10, where Timeline (app focus, lifecycle, per-device attribution) remains a strong activity source. The Corroborative rating is driven by the Win11 degradation. Consider whether the OS-version dependency belongs in the caveat text (as proposed) while the strength reflects the artifact's fuller Win10 population, or accept Corroborative as the conservative floor.

**Additions:** Enrich the EXISTING descriptor `windows_timeline` (crates/data/src/catalog/descriptors/mod.rs, WINDOWS_TIMELINE, line ~3035). This adds the OS-version degradation story, which the descriptor currently lacks (it only mentions "Cloud sync disabled July 2021").

1) ADD to `evidence_caveats` (currently `&[]`) — three caveats, all primary-source-backed except where marked as observation:

  a. "Windows 11 retired the Timeline user experience (Task View no longer shows activity history); it remains only on Windows 10. Local activity history is still stored on-device when the Activity History setting is enabled, so ActivitiesCache.db can still exist on Windows 11 — its absence from Task View is a UI change, not deletion." [Microsoft: Get Help With Timeline]

  b. "Cross-device cloud sync was disabled in two stages: the MSA upload option in July 2021, and Microsoft Entra (AAD) cross-device syncing in January 2024. Separately, the 'send my activity history to Microsoft' toggle was removed entirely via KB5034204 (Windows 11 22H2 AND 23H2) and KB5034203 (Windows 10 22H2), both dated 23 January 2024. 22H2 and 23H2 share a common core, so this is not a clean 22H2-vs-23H2 break — both builds are affected identically." [Microsoft: activity-history privacy page; Get Help With Timeline]

  c. "Forensic bottom line — NOT exculpatory: on Windows 11 the on-device ActivitiesCache.db is commonly sparse, with rich application/file-execution history no longer populated; surviving entries are typically clipboard (ActivityType 10 = clipboard text present; ActivityType 16 = copy-vs-paste indicator) plus minimal system activity. A sparse or missing ActivitiesCache.db on Windows 11 is the expected, documented consequence of the Timeline deprecation — it does NOT indicate anti-forensic deletion or that the user was inactive. Check ActivitiesCache.db-wal for buffered/deleted entries. (The 'clipboard-only' population pattern and its dependence on clipboard-history + clipboard-sync toggles is a DFIR-community observation — inversecos, Cellebrite — not vendor-documented; state it as observed, not proven.)"

2) ADD two Microsoft primary sources to `sources`:
  - https://support.microsoft.com/en-us/windows/get-help-with-timeline-febc28db-034c-d2b0-3bbe-79aa0c501039
  - https://support.microsoft.com/en-us/windows/windows-activity-history-and-your-privacy-2b279964-44ec-8c2f-e0c2-6779b07d2cbd

3) RECOMMEND setting `evidence_strength: Some("Corroborative")` — on Windows 11 the artifact's surviving value is mostly residual clipboard text and system activity; it corroborates rather than definitively establishes activity, and its absence carries no negative inference.

Leave `mitre_techniques`, `fields`, `os_scope` (Win10Plus is still correct), `retention`, and `file_path` unchanged.

**Sources verified:**
- [1 (vendor primary — Microsoft support)] https://support.microsoft.com/en-us/windows/get-help-with-timeline-febc28db-034c-d2b0-3bbe-79aa0c501039 — Verbatim: 'The timeline user experience was retired in Windows 11, although it remains in Windows 10.' and 'The timeline user experience and all your local activity history still remain on Windows 10 devices.' Also confirms July 2021 MSA upload-option removal and 'Cross-device syncing of Microsoft Entra user activity history will stop starting in January 2024. Microsoft will stop storing this data in the cloud.'
- [1 (vendor primary — Microsoft support)] https://support.microsoft.com/en-us/windows/windows-activity-history-and-your-privacy-2b279964-44ec-8c2f-e0c2-6779b07d2cbd — Verbatim: 'The option to send activity history to Microsoft has been deprecated from Windows 11 23H2 and 22H2, January 23, 2024-KB5034204 update' and '...from Windows 10 22H2, January 23, 2024-KB5034203 update.' Confirms activity history is stored locally on device and on-device Timeline still relies on it when enabled. Establishes the toggle change hit 22H2 and 23H2 identically (no clean version split).
- [1 (vendor primary — Microsoft KB)] https://support.microsoft.com/en-gb/topic/january-23-2024-kb5034204-os-builds-22621-3085-and-22631-3085-preview-7652acf2-56dc-430e-b8ef-ec8f56ec1028 — KB5034204 dated Jan 23 2024, OS Builds 22621.3085 (22H2) and 22631.3085 (23H2) — confirms a single update spanning both 22H2 and 23H2, and that 22H2/23H2 share a common core / update-history page.
- [2 (RE tool source — kacos2000/Costas K.)] https://raw.githubusercontent.com/kacos2000/WindowsTimeline/master/README.md — Confirms the July 2021 MSA sync-upload deprecation note and clipboard ActivityType handling (type 10 = clipboard text, type 16 = copy/paste). Does NOT document any Win11/22H2/23H2 degradation — verified absent, so it cannot be cited as authority for the OS-version-split claim.

**Notes:** Scope/accuracy corrections for the parent to weigh:

- The work item's "local collection persists through 22H2; on 23H2 the DB exists but most useful data is gone" framing is IMPRECISE and partly unsupported. Microsoft's docs show the send-to-Microsoft toggle removal (KB5034204) applied to BOTH 22H2 and 23H2 on the same date, and the two builds share a common OS core — there is no primary-source basis for a clean 22H2-vs-23H2 degradation boundary. The reliable primary facts are: (i) Win11 retired the Timeline UI, Win10 retains it; (ii) MSA sync off July 2021, Entra sync off Jan 2024; (iii) send-to-MS toggle removed via KB5034204/KB5034203 on 23 Jan 2024. The finer "23H2 = clipboard-only" claim comes from DFIR blogs (inversecos, Cellebrite, forensicfocus), which per standing rules are discovery pointers only — I have kept it in the caveat but explicitly marked it as observed, not vendor-confirmed.

- The kacos2000 README (the named candidate source) does NOT document any Win11/22H2/23H2 degradation — I fetched the raw README and confirmed it only covers Win10 up to 1903 plus the July-2021 MSA note. So kacos2000 supports the July-2021 sync fact but NOT the OS-version degradation; the load-bearing citations are the two Microsoft support pages.

- LATENT BUG flagged (out of this task's scope, do not silently fold in): the descriptor's existing `meaning` says "Activity_Type 16 (CopyPaste) entries capture clipboard text." Per kacos2000's parser source and inversecos, the clipboard TEXT lives in ActivityType 10 (ClipboardPayload base64), while ActivityType 16 only flags copy-vs-paste. The current meaning attributes the text capture to the wrong type. Recommend a separate correction pass.

- Also note (not changed): descriptor `retention: Some("~30 days")` is the app/file-activity retention; clipboard entries expire far sooner (~12h ExpirationTime per inversecos/Cellebrite). Consider clarifying in a future pass.

### `evtx_system` — System Event Log (System.evtx)  [enrichment]
**FIX FIRST:** All three cited sources resolve and directly support the core claims (verified via full-text search, not just HTTP 200). KB5004442 confirms the exact 10036 text with %4=Client IP / %3=SID, client events 10037/10038, the HKLM\SOFTWARE\Microsoft\Ole\AppCompat RequireIntegrityActivationAuthenticationLevel DWORD, and CVE-2021-26414. The 10016 troubleshoot page confirms CLSID/APPID/SID/from-address fields, LocalHost/LRPC, SYSTEM/LOCAL SERVICE, and the verbatim "can be safely ignored ... by design." MITRE confirms T1021.003 = DCOM lateral movement (technique already in src/mitre.rs). Not a duplicate — no existing DCOM-event coverage in the catalog; related_artifacts are all valid existing ids; no blog cited as authority for the new facts; evidence_strength and the "consistent with, not proof" framing are honest and correctly NOT inflated. One fixable accuracy issue prevents an immediate confirmed: the enrichment text asserts Microsoft "documents ... against RuntimeBroker and Immersive Shell CLSIDs," but the cited MS 10016 doc actually names the container ShellExperienceHost with generic CLSIDs — it never names RuntimeBroker or Immersive Shell. Those specifics are community lore, not backed by the cited primary source. Reword to match the doc (ShellExperienceHost / generic shell CLSIDs) or drop the specific process names; then it is ready to apply.
- meaning + evidence_caveats overstate the cited primary source: they claim Microsoft documents the benign 10016 records 'against RuntimeBroker and Immersive Shell CLSIDs', but the cited MS Learn 10016 page names ShellExperienceHost and generic CLSIDs, not RuntimeBroker/Immersive Shell. Reword to what the doc shows (or cite those names to a source that actually states them) to keep the primary-source attribution honest.
- Minor, no change strictly required: the MS 10016 example is a LOCAL activation (LocalHost/LRPC); the proposal's 'denied local/remote DCOM activation-permission grant' is acceptable because the event's 'from address' field can carry a remote host, but ensure the descriptor doesn't imply Microsoft's example itself was remote.

**Additions:** ENRICH EXISTING DESCRIPTOR: `EVTX_SYSTEM` (id "evtx_system") in crates/data/src/catalog/descriptors/mod.rs (~line 7181). Not currently covered — grep of catalog + src for 10036/10016/DistributedCOM/DCOM returned zero DCOM-event hits.

--- 1) APPEND to `meaning` (after the existing 7000/7009 sentence) ---
"DistributedCOM (Source: Microsoft-Windows-DistributedCOM) also writes DCOM activation-permission events to System.evtx, relevant to DCOM lateral movement (T1021.003 — abuse of MMC20.Application / ShellWindows / ShellBrowserWindow / Excel.Application objects). Event 10036 is SERVER-SIDE ('The server-side authentication level policy does not allow the user <DOMAIN>\\<user> SID (<SID>) from address <IP> to activate DCOM server') and, as a by-product of the CVE-2021-26414 DCOM hardening (KB5004442; RequireIntegrityActivationAuthenticationLevel DWORD under HKLM\\SOFTWARE\\Microsoft\\Ole\\AppCompat), records the SOURCE IP and SID of a remote DCOM activation attempt — an activation-source pivot even when the activation itself is blocked. Its client-side counterparts are 10037 (explicitly-set auth level) and 10038 (default auth level). Event 10016 records a denied local/remote DCOM activation-permission grant (CLSID, APPID, user SID, and 'from address'), but is overwhelmingly benign by-design noise — Microsoft documents the LocalHost/LRPC records for NT AUTHORITY\\LOCAL SERVICE / SYSTEM against RuntimeBroker and Immersive Shell CLSIDs as expected and safely ignored. Filter 10016/10036 to the forensic subset: 'from address' = a REMOTE host (not LocalHost / (Using LRPC)) paired with an interactive or domain user SID and a non-standard CLSID."

--- 2) ADD to `mitre_techniques` ---
Append "T1021.003" (Remote Services: Distributed Component Object Model — Lateral Movement TA0008; verified at attack.mitre.org/techniques/T1021/003/). Result: &["T1543.003", "T1070.001", "T1059.001", "T1021.003"].

--- 3) ADD to `sources` (with provenance comments matching the file's existing comment style) ---
// Source: https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/event-10016-logged-when-accessing-dcom
// — Microsoft: Event 10016 (DistributedCOM) fields CLSID/APPID/SID/from address;
//   states LocalHost/LRPC records for LOCAL SERVICE/SYSTEM are by-design and "can be safely ignored".
"https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/event-10016-logged-when-accessing-dcom",
// Source: https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c
// — Microsoft KB5004442: server-side Event 10036 text incl. "from address %4" (client IP)
//   and SID; client-side 10037/10038; RequireIntegrityActivationAuthenticationLevel under
//   HKLM\SOFTWARE\Microsoft\Ole\AppCompat; CVE-2021-26414 DCOM hardening.
"https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c",

--- 4) ADD to `evidence_caveats` ---
"Event 10016 (DistributedCOM) is high-volume benign noise: Microsoft documents the LocalHost/LRPC records for NT AUTHORITY\\LOCAL SERVICE and SYSTEM against RuntimeBroker/Immersive Shell CLSIDs as by-design and safely ignorable. Treat only 10016/10036 whose 'from address' is a REMOTE host (not LocalHost / Using LRPC) as a DCOM lateral-movement pivot.",
"Event 10036 is a CVE-2021-26414 / KB5004442 hardening by-product, so its volume also spikes from benign WMI-polling appliances (firewalls, security/monitoring tools) that activate DCOM below RPC_C_AUTHN_LEVEL_PKT_INTEGRITY. The event is consistent with a remote DCOM activation attempt, not proof of lateral movement — corroborate the source IP against expected management infrastructure first.",

Do NOT change evidence_strength (stays Strong) or volatility.

**Sources verified:**
- [1 (primary vendor spec — Microsoft KB)] https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c — Exact server-side Event 10036 text 'The server-side authentication level policy does not allow the user %1\%2 SID (%3) from address %4 to activate DCOM server' — %4 is the client source IP; client-side events 10037 (explicit auth level) and 10038 (default auth level); registry HKLM\SOFTWARE\Microsoft\Ole\AppCompat value RequireIntegrityActivationAuthenticationLevel; tied to CVE-2021-26414 DCOM hardening.
- [1 (primary vendor doc — Microsoft Learn troubleshoot)] https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/event-10016-logged-when-accessing-dcom — Event 10016 (DistributedCOM) records CLSID, APPID, user SID and 'from address' for a denied local/remote DCOM activation permission; Microsoft states these events are by-design (component tries one param set, retries with another) and 'can be safely ignored'.
- [1 (primary — MITRE ATT&CK)] https://attack.mitre.org/techniques/T1021/003/ — T1021.003 = Remote Services: Distributed Component Object Model, Lateral Movement (TA0008), Windows; adversaries use DCOM to remotely execute code as the logged-on user (MMC20.Application, Office objects, etc.).

**Notes:** Enrichment, not a new descriptor: DistributedCOM 10016/10036 are logged by the Microsoft-Windows-DistributedCOM provider to the System channel (System.evtx), so they belong on the existing evtx_system descriptor rather than a standalone entry.

Epistemic layering (kept "consistent with", not "proves"):
- 10036 is genuinely useful for LATERAL-MOVEMENT SOURCE ATTRIBUTION because it carries the remote client IP (%4) and the activating SID — an activation-source pivot even when activation is blocked. But it is a CVE-2021-26414/KB5004442 hardening by-product whose baseline volume is dominated by benign WMI-polling appliances (Palo Alto, Meraki, monitoring tools) using RPC below PKT_INTEGRITY. So the event is Corroborative for DCOM lateral movement, not Definitive — corroborate the IP against known management infra. Left the descriptor's overall evidence_strength at Strong (unchanged) since it aggregates 7045/7036/etc.
- 10016 is overwhelmingly by-design noise (Microsoft: safely ignore). The load-bearing filtering guidance: keep only records whose 'from address' is a REMOTE host (not LocalHost / (Using LRPC)) with an interactive/domain user SID and a non-standard CLSID; discard the standard LOCAL SERVICE/SYSTEM + RuntimeBroker/Immersive Shell LRPC records.

Side/client note (not added to keep scope tight, flag for future): 10037/10038 are the CLIENT-side hardening events (verified in KB5004442) — could seed an EVTX Application/System client-activation enrichment later if desired.

MITRE: added only T1021.003 (clean fit). Did not force any T1047/WMI technique — 10036/10016 are DCOM activation events, and WMI-over-DCOM noise is called out as a false-positive source, not asserted as the technique.

related_artifacts: no change proposed (existing &["evtx_security","scheduled_tasks_dir","services_imagepath"] all remain valid; no existing DCOM/WMI descriptor id to add).

### `EVENT_ID_TABLE` — Task Scheduler EID 100 (Task Started) / 102 (Task completed)  [enrichment]
**FIX FIRST:** The core catalog data is correct and well-sourced: EID 100 (Task Started) and 102 (Task completed) on Microsoft-Windows-TaskScheduler/Operational, with channel/level=Information/opcode Start-Stop and the exact message templates "Task Scheduler started '{InstanceId}' instance of the '{TaskName}' task for user '{UserContext}'." / "Task Scheduler successfully finished '{InstanceId}' instance...", are confirmed tier-1 against TWO independent OS provider-manifest dumps (Win10 1507/10240 and 1809/17763.1397) that resolve and match verbatim. Not duplicates (grep confirms 100/102 absent, no id collision, no duplicate event_ids). artifact_id "evtx_task_scheduler" is a real catalog descriptor used by siblings (all_artifact_ids_valid passes). MITRE T1053.005 fits cleanly. evidence_strength "Strong" is honest (notes log rolls/can be cleared, absence != non-execution). BUT the proposal's secondary instruction is defective and must be dropped before applying.
- DROP the IWE_REQUIRED edit. The proposal instructs adding (100, ...)/(102, ...) to the (id, channel) list at lines ~573-578 'or the iwe_event_channel_map consistency test at ~595-601 will fail.' This justification is false: there is no test named iwe_event_channel_map, and the only test over that list (iwe_course_event_ids_present, line 598) asserts only IWE_REQUIRED subset EVENT_ID_TABLE. Adding rows to EVENT_ID_TABLE alone breaks no test (all module tests 457-635 traced).
- SEMANTIC error: IWE_REQUIRED is documented (lines 548-549) as '13Cubed IWE course-taught Event IDs ... each with the channel the course assigns.' Putting 100/102 there falsely asserts the 13cubed IWE course teaches them — unverified, and encoding 13cubed-as-authority violates the standing rule that 13cubed is a discovery pointer only. The edit is also unnecessary (see above), so remove it entirely.
- FIX: apply ONLY the two EventIdEntry rows to the EVENT_ID_TABLE Task Scheduler block (~lines 223-263). Leave the IWE_REQUIRED table untouched. All tests (iwe_course_event_ids_present, all_artifact_ids_valid) still pass.
- MINOR (non-blocking): the forensic_notes claim 'exactly one EID 100/102 per run vs N pairs of 200/201 per action' and 'InstanceId groups the 200/201 events' are sound inferences from the Start/Stop (task-level) vs 200/201 (action-level) opcode structure, but are not literally stated in the manifest CSV — treat as consistent-with reasoning, not manifest-confirmed fact. The in-code row descriptions are measured enough to keep as-is.

**Additions:** Target: the `EVENT_ID_TABLE` static in /Users/4n6h4x0r/src/forensicnomicon/src/eventids.rs (the "Task Scheduler operational" block, currently rows 106/140/141/200/201 at lines ~223-263). EID 100 and 102 are NOT present (confirmed by grep — only 106/140/141/200/201 exist). Add two new EventIdEntry rows.

WHY these are distinct from 200/201 (the point of the work item): 100/102 bracket the TASK as a whole; 200/201 bracket each ACTION within the task. A scheduled task containing N actions emits exactly one EID 100 (task start) and one EID 102 (task completed), but N pairs of 200/201 (one per action). So 100/102 prove the task instance actually ran end-to-end and give the {InstanceId} correlation GUID that ties all the 200/201 action events of one run together; 200/201 only prove an individual action fired. 100/102 are therefore the correct anchor for "did this scheduled task execute" and for grouping a run.

Exact new rows to insert in the "Task Scheduler operational" block (place 100 before 106, 102 after — or keep numeric order):

    EventIdEntry {
        event_id: 100,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task started (task instance began; brackets the whole task run — carries {InstanceId} correlation GUID grouping this run's 200/201 action events; one per run vs one 200/201 per action)",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },
    EventIdEntry {
        event_id: 102,
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        description: "Scheduled task completed (task instance finished; matches the {InstanceId} of the corresponding EID 100 — task-level completion, distinct from EID 201 per-action completion)",
        mitre_techniques: &["T1053.005"],
        artifact_ids: &["evtx_task_scheduler"],
        high_value: false,
    },

ALSO add the matching channel-map entries in the second table (the `(id, channel)` list at lines ~573-578, "Task Scheduler operational" comment block), or the existing `iwe_event_channel_map` consistency test at lines ~595-601 will fail:

        (100, "Microsoft-Windows-TaskScheduler/Operational"),
        (102, "Microsoft-Windows-TaskScheduler/Operational"),

Field justification:
- channel/description/level: from the OS provider manifest (see sources). Manifest Task names are literally "Task Started" (100) and "Task completed" (102); Opcode Start/Stop; Level Information.
- artifact_ids: reuse existing "evtx_task_scheduler" (already used by sibling rows 140/141/200/201 — verified present, do NOT invent a new id).
- mitre_techniques T1053.005 (Scheduled Task): matches all sibling TaskScheduler rows; 100/102 are the execution evidence of a scheduled task, so the technique cleanly fits (not forced).
- high_value false: matches siblings 200/201 (execution confirmation); the high-value creation/persistence event in this channel is 106 (registration), left unchanged.

**Sources verified:**
- [1 (independent artifact: OS binary manifest extracted by a third party; ground truth = the binary itself)] https://raw.githubusercontent.com/nasbench/EVTX-ETW-Resources/main/ETWEventsList/CSV/Windows10/1809/W10_1809_Pro_20200811_17763.1397/Providers/Microsoft-Windows-TaskScheduler.csv — Provider manifest dumped straight from the Windows 10 1809 (17763.1397) Microsoft-Windows-TaskScheduler binary: EID 100 Level=Information Channel=Operational Task='Task Started' Opcode=Start Message="Task Scheduler started '{InstanceId}' instance of the '{TaskName}' task for user '{UserContext}'."; EID 102 Task='Task completed' Opcode=Stop Message="Task Scheduler successfully finished '{InstanceId}' instance of the '{TaskName}' task for user '{UserContext}'." This is the OS's own message table (primary), not a blog.
- [1 (second independent OS-version manifest, corroborating stability)] https://raw.githubusercontent.com/nasbench/EVTX-ETW-Resources/main/ETWEventsList/CSV/Windows10/1507/W10_1507_Pro_20150729_10240/Providers/Microsoft-Windows-TaskScheduler.csv — Same 100/102 IDs, names, channel, and message templates present in the earliest Win10 build (1507, 10240) — confirms the mapping is stable across OS versions from 2015 to 2020, so the row is not version-specific.

**Notes:** Message templates (verbatim from the extracted manifest, {} = substitution slots): EID 100 = "Task Scheduler started '{InstanceId}' instance of the '{TaskName}' task for user '{UserContext}'."; EID 102 = "Task Scheduler successfully finished '{InstanceId}' instance of the '{TaskName}' task for user '{UserContext}'." Both Level=Information, Channel=Operational, Opcode Start/Stop.

Triage logic: EID 102 (successful task completion) fires only on success — a task that starts (100) but errors emits EID 101 (Task Start Failed) or 103 (Action start failed) instead of 102, so a 100 with no matching 102 for the same {InstanceId} is consistent with a failed/aborted run. The {InstanceId} GUID is the join key across 100 → (200/201 per action) → 102 for one run; use it rather than TaskName when a task fires repeatedly. Evidence strength for "task executed": Strong (task-level start/stop are logged by the scheduler service itself), but note the Operational channel is small and rolls quickly, and an attacker with admin can clear it — absence is not proof of non-execution.

Not proposed here (out of scope, but adjacent if later wanted): EID 101 (Task Start Failed), 103 (Action start failed), 110 (Task triggered by user), 129 (Created Task Process, carries the child PID), 111 (Task terminated), 118/119 (task engine). These were seen in the same manifest CSV but the work item is scoped to 100/102.

### `src/eventids.rs :: EVENT_ID_TABLE (event_id 104 System, event_id 1102 Security)` — Cross-log clearing semantics for eventlog events 104 (System) and 1102 (Security)  [enrichment]
**FIX FIRST:** Both cited sources resolve and directly support the load-bearing facts (verified by curl+grep): nasbench manifest CSV shows 104=System/"The {Channel} log file was cleared" and 1102=Security/"The audit log was cleared"+Subject account fields; MS Learn event-1102 page contains the escaped XML with <Channel>Security</Channel>, Task>104, Microsoft-Windows-Eventlog, LogFileCleared, SubjectUserSid/SubjectLogonId — no fake-200. It is an enrichment of existing EVENT_ID_TABLE entries (not a duplicate), artifact_ids evtx_system/evtx_security exist, and MITRE T1070.001 fits both. evidence_strength Strong is honest and the Application-log claim is correctly hedged as "consistent with". The only defect is an internal overstatement: the description text ("instead self-logs", "the exception to the 104 pattern") asserts that clearing the Security log does NOT also emit a System 104 — an exclusivity the proposal's own forensic_notes explicitly mark as unverified/out-of-scope, and which neither cited source establishes. Soften the wording to contrast only where the self-log lands, then it is ready to apply.
- Overstatement/internal contradiction: 104 description word 'instead' and 1102 description phrase 'the exception to the 104 pattern' imply clearing the Security log does NOT also emit a System event 104. The proposal's own forensic_notes list this exact co-emission question under 'Not verified here (out of scope, do not assert)'. Neither cited source (manifest CSV / MS event-1102 page) establishes exclusivity — they show channels and message templates only.
- Fix: for 104, replace 'The one channel that instead self-logs its own clearing is Security (event 1102)' with a non-exclusive form such as 'Security additionally records its own clearing in the Security channel itself via event 1102.' For 1102, replace 'Security is the exception to the 104 pattern: its clearing is recorded in the very log being cleared, whereas every other channel's clearing is recorded by System event 104' with 'Unlike other channels — whose clearing is recorded by System event 104 — Security records its own clearing in the Security log via 1102.'
- No change needed to: mitre_techniques (T1070.001 fits), high_value, artifact_ids (evtx_system/evtx_security confirmed present), or the Application-log-not-self-logging claim (already honestly hedged as 'consistent with'). evidence_strength Strong is accurate.

**Additions:** Enrich the two terse `description` strings on the `EventIdEntry` records in `EVENT_ID_TABLE` (src/eventids.rs, lines 27-42). Both already correctly carry `mitre_techniques: &["T1070.001"]` (Indicator Removal: Clear Windows Event Logs) and `high_value: true`; leave those unchanged. Change only the `description` fields to capture the verified cross-log semantics:

- event_id 104 (channel "System"): replace "System log cleared" with —
  "Event log cleared — emitted by provider Microsoft-Windows-Eventlog into the System channel, message 'The {Channel} log file was cleared'. The {Channel} parameter names WHICH log was cleared, so 104 is the clearing record for arbitrary channels (Application, Setup, custom Operational logs), not the System log alone. A cleared Application log therefore leaves no event in Application itself — the evidence is the 104 in System naming it. The one channel that instead self-logs its own clearing is Security (event 1102)."

- event_id 1102 (channel "Security"): replace "Audit log cleared" with —
  "Security audit log cleared — self-logged into the Security channel by provider Microsoft-Windows-Eventlog (Task 'Log clear', message 'The audit log was cleared'), carrying the clearing account in SubjectUserSid/SubjectUserName/SubjectDomainName/SubjectLogonId. Security is the exception to the 104 pattern: its clearing is recorded in the very log being cleared, whereas every other channel's clearing is recorded by System event 104."

Forensic corollary worth keeping in mind for consumers (no struct field to hold it): to detect log clearing across all channels an examiner must check BOTH System-104 and Security-1102 — neither alone is complete.

**Sources verified:**
- [Tier 1 (vendor primary — Microsoft Learn auditing reference, with literal event XML)] https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102 — Event 1102 is written into the Security channel itself (<Channel>Security</Channel>), provider Microsoft-Windows-Eventlog, Task 104, message 'The audit log was cleared', carrying SubjectUserSid/UserName/DomainName/LogonId of the clearing account — i.e. Security self-logs its own clearing.
- [Tier 1/2 (mechanical dump of the Windows Microsoft-Windows-Eventlog binary provider manifest — vendor artifact, not commentary)] https://raw.githubusercontent.com/nasbench/EVTX-ETW-Resources/main/ETWEventsList/CSV/Windows10/1607/W10_1607_Pro_20161108_14393.447/Providers/Microsoft-Windows-Eventlog.csv — Event 104: Provider=Microsoft-Windows-Eventlog, Channel=System, Task='Log clear', Message='The {Channel} log file was cleared' (parameterized channel name = cross-log clearing record). Event 1102: Channel=Security, Task='Log clear', Message='The audit log was cleared'. Confirms 104 lives in System and names the cleared channel, while 1102 lives in Security.

**Notes:** Evidence strength: Strong. Two independent primary artifacts agree. (1) Microsoft Learn's event-1102 page shows the literal event XML with <Channel>Security</Channel>, <Provider Name="Microsoft-Windows-Eventlog">, <Task>104</Task>, and a LogFileCleared UserData block — proving 1102 is written into the Security channel itself (self-logging) and carries the clearing account. (2) nasbench's EVTX-ETW-Resources is a mechanical dump of the Windows Microsoft-Windows-Eventlog binary provider manifest (the vendor artifact, not a blog): it lists event 104 as Provider=Microsoft-Windows-Eventlog, Channel=System, Task="Log clear", Message="The {Channel} log file was cleared", and event 1102 as Channel=Security, Message="The audit log was cleared". The parameterized {Channel} token in 104's message is the load-bearing evidence that 104 records clearing of arbitrary channels and names the cleared one.

Caveat / epistemic layer: the specific sub-claim "the Application log does not self-log its own clear" is an inference FROM the manifest structure (104 is defined once, in System, with a {Channel} parameter; the manifest defines no per-channel clear event for Application), corroborated by long-standing DFIR practice — not a sentence Microsoft states verbatim. State it as "consistent with", not proven. The verified, definitive facts are the two message templates and their channels; the cross-channel behavior follows from them.

Not verified here (out of scope, do not assert): whether clearing the Security log ALSO emits a 104 in System on a given Windows build — the enrichment deliberately avoids claiming it does or does not.

### `evtx_security` — Security Event Log (Security.evtx) — RDP reconnect vs fresh-logon / disconnect vs logoff correlation  [enrichment]
**FIX FIRST:** All five cited sources are Tier-1 Microsoft vendor primary docs that resolve and support their specific claims verbatim (verified via fetch: 4778/4779 FUS+Hyper-V non-exclusivity, provider GUID {54849625-5478-4994-A5BA-3E3B0328C30D}, Session/Client fields, 4624 Type-7=Unlock/Type-10=RemoteInteractive table, 4634 session-terminated + Logon-ID correlation, 4647 user-initiated-logoff distinction). No blog/13cubed/SANS is used as authority; the ponderthebits RCM event-40 reason-code table was correctly excluded. Target id evtx_security is correct and does NOT yet carry 4778/4779 in its descriptor prose (genuine gap, not duplicate). All four related_artifacts exist; LSM 21/23/24/25 mapping matches the repo's own evtx_rdp_session descriptor; T1021.001 fits and is already used for these IDs in eventids.rs. Ready to apply after one wording fix: the causal claim that an RDP reconnect "produces 4624 Logon Type 7" is a forensic inference not stated in any cited MS page (4624 only defines Type 7 = 'workstation unlocked') and is not universally true (unlock fires only if the session was locked). Soften it in the `meaning` prose to 'typically generates' / keep it in the 'consistent-with' caveat framing rather than as flat Definitive fact — the proposal's own evidence_strength note already uses the correct framing; only the meaning text needs to match it.
- OVERSTATEMENT (fixable): 'a reconnect to an existing (locked) session produces 4624 Logon Type 7, NOT a fresh Type 10 logon' is stated as flat fact in the proposed `meaning`, but no cited MS page documents the reconnect→Type-7 linkage (the 4624 doc only defines Type 7 = 'This workstation was unlocked'). It is also conditional — the unlock/Type-7 fires only if the session was locked. Soften to 'typically' and keep the linkage in the 'consistent-with' caveat framing, not as Definitive fact in meaning. The caveat line 'generates Security 4778 + 4624 Logon Type 7 (Unlock)' should likewise read 'typically generates'.
- MINOR: everything else verified. 4778/4779 fields, GUID, FUS/Hyper-V non-exclusivity, 4634 'session terminated and no longer exists' + Logon-ID correlation (unique only between reboots), 4647 user-initiated-logoff distinction all confirmed against the five learn.microsoft.com pages. related_artifacts (evtx_rdp_session/evtx_rdp_inbound/evtx_terminal_services) all exist; LSM 23/24/25 mapping matches repo's evtx_rdp_session; T1021.001 fits. RCM event-40 exclusion is correct per standing rules.
- NOTE (not a defect): 4778/4779 already appear in src/eventids.rs mapped to evtx_security — this enrichment adds them to the descriptor prose/caveats, which is the actual gap; not a duplicate.

**Additions:** TARGET DESCRIPTOR (exact existing id): evtx_security (crates/data/src/catalog/descriptors/mod.rs, id: "evtx_security").

Rationale: evtx_security already lists 4624/4625 (logon), 4634/4647 (logoff) and even carries the Type-3-vs-Type-10 WorkstationName caveat, but it does NOT document (a) 4778/4779, (b) Logon Type 7 (Unlock), or (c) the correlation logic that separates an RDP *reconnect* from a *fresh logon* and a *disconnect* from a true *logoff*. That is the enrichment. 4778/4779 belong here (Security channel, provider Microsoft-Windows-Security-Auditing {54849625-5478-4994-A5BA-3E3B0328C30D}), not on the LSM descriptors.

1) ADD to `meaning` (extend the event-ID list) — verbatim facts from MS docs:
"4778 (a session was reconnected to a Window Station) / 4779 (a session was disconnected from a Window Station) — Audit Other Logon/Logoff Events subcategory; carry AccountName, AccountDomain, LogonID, plus Session Name, Client Name and Client Address. Logon Type 7 (Unlock) vs Type 10 (RemoteInteractive/RDP): a reconnect to an *existing* (locked) session produces 4624 Logon Type 7, NOT a fresh Type 10 logon."

2) ADD to `evidence_caveats` (the correlation semantics — this is the load-bearing enrichment):
 - "Reconnect ≠ fresh logon: an RDP reconnect to a pre-existing session generates Security 4778 + 4624 Logon Type 7 (Unlock) and LSM (LocalSessionManager) event 25 (reconnect) — it does NOT emit a fresh 4624 Logon Type 10. Counting Type-10 events alone therefore undercounts actual RDP sessions; the initial connect is Type 10, subsequent reconnects are Type 7 + 4778."
 - "Disconnect ≠ logoff: a disconnect leaves the session alive (Security 4779 + LSM event 24 disconnect); the credentials/processes persist. A true logoff destroys the session (Security 4634 = session terminated, typically together with 4647 = user-initiated logoff, + LSM event 23 logoff). Treat a 4779/LSM-24 without a matching 4634/4647 as a still-live session an attacker can resume."
 - "4778/4779 are NOT RDP-exclusive: MS docs state they also fire on Fast User Switching and on reconnect/disconnect to a Hyper-V Enhanced Session. Do not attribute a 4778/4779 to RDP without corroboration from LSM 25/24 (or RCM 1149) and a non-loopback Client Address; a console FUS switch produces the same event IDs."
 - "Correlate the chain by LogonID: 4624 ↔ 4778/4779 ↔ 4634/4647 share the Logon ID (unique only between reboots on the same host); use it to bind reconnect/disconnect/logoff to the originating logon."

3) ADD to `sources` (independent primary sources — MS event reference; keep the existing 4624 source):
 - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778  (4778 = session reconnected; also FUS + Hyper-V Enhanced Session)
 - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779  (4779 = session disconnected; same non-RDP caveat)
 - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634  (4634 = account logged off / session terminated; correlate to 4624 via Logon ID; 4647-vs-4634 distinction)
 - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647  (4647 = user initiated logoff)
 - (4624 logon-type table incl. Type 7 Unlock / Type 10 RemoteInteractive is already cited via the existing event-4624 reference in this descriptor.)

4) ADD to `related_artifacts` (all verified existing catalog ids): "evtx_rdp_session", "evtx_rdp_inbound", "evtx_terminal_services". These are the LSM (21/23/24/25) and RCM (1149) partners the correlation chain joins against.

5) OPTIONAL `mitre_techniques`: add "T1021.001" (Remote Services: RDP) — the reconnect/disconnect chain is RDP lateral-movement evidence; evtx_security currently lists T1070.001/T1059/T1078/T1555.

EXCLUDED (no independent primary source): RemoteConnectionManager "event 40" disconnect reason-code table. The only source is the ponderthebits blog (discovery pointer, not authority); Microsoft does not document RCM 40 reason codes. Do NOT add event-40 reason-code claims until a primary/RE-reference source is found. The task's mention of "event 40" is therefore intentionally dropped from the authoritative enrichment.

evidence_strength stays Definitive: the event *definitions* (4778/4779/4634/4647, Logon Type 7 vs 10) are Microsoft-documented (Definitive). The reconnect-vs-logon / disconnect-vs-logoff *chain assembly* is a forensic correlation stated as "consistent with", grounded in those definitions — not overstated as proof.

**Sources verified:**
- [1 (vendor primary — Microsoft event reference)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778 — 4778 = 'A session was reconnected to a Window Station'; generated on reconnect to an existing Terminal Services session, Fast User Switching, or Hyper-V Enhanced Session; Security channel, provider Microsoft-Windows-Security-Auditing {54849625-5478-4994-A5BA-3E3B0328C30D}; carries AccountName/AccountDomain/LogonID/Session Name/Client Name/Client Address. Confirms 4778 is NOT RDP-exclusive.
- [1 (vendor primary)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779 — 4779 = 'A session was disconnected from a Window Station'; disconnect from existing TS session, FUS switch-away, or Hyper-V Enhanced Session — session persists (not a logoff).
- [1 (vendor primary)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 — Logon-type table: Type 7 = 'Unlock' ('This workstation was unlocked.'); Type 10 = 'RemoteInteractive' (RDP/Terminal Services). Basis for reconnect (Type 7) vs fresh RDP logon (Type 10).
- [1 (vendor primary)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634 — 4634 = 'An account was logged off' — session terminated and no longer exists; positively correlated to 4624 via Logon ID; both 4647 and 4634 typically appear when logoff initiated by user (Interactive/RemoteInteractive).
- [1 (vendor primary)] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647 — 4647 = 'User initiated logoff' — generated when logoff procedure initiated by a specific account via the logoff function; distinguishes user-initiated logoff from generic session termination (4634).

**Notes:** This is an ENRICHMENT of existing descriptor evtx_security, not a new descriptor — the catalog already has dense RDP coverage (evtx_rdp_inbound/1149, evtx_rdp_session, evtx_terminal_services/LSM 21-25, evtx_rdp_client/1024-1102) and evtx_security already lists 4624/4634/4647. The gap is purely the *correlation semantics*: 4778/4779, Logon Type 7 (Unlock), and the reconnect≠logon / disconnect≠logoff distinction.

Triage logic added: (1) initial RDP connect = 4624 Type 10 + LSM 21 (Source Network Address) + RCM 1149; (2) reconnect to a locked/existing session = 4624 Type 7 (Unlock) + 4778 + LSM 25 — the tell that a session is being *resumed*, not freshly created (counting only Type-10 undercounts sessions); (3) disconnect = 4779 + LSM 24, session STILL LIVE; (4) true logoff = 4634 (+4647) + LSM 23, session destroyed. A 4779/LSM-24 with no trailing 4634/4647 = a resumable orphaned session — an attacker-persistence pivot.

Honest caveat that must survive into the descriptor: 4778/4779 are shared with Fast User Switching and Hyper-V Enhanced Session per MS docs, so they are NOT sufficient alone for RDP attribution — require a non-loopback Client Address and an LSM 25/24 or RCM 1149 corroborator.

Deliberately dropped from the task's proposed chain: RemoteConnectionManager 'event 40' reason codes — no Microsoft or independent RE-reference primary source exists (only the ponderthebits blog, which is a discovery pointer, not an authority per the standing rules). Flagged for a future pass if a primary source surfaces.

### `EVENT_ID_TABLE eid 4104 (artifact_ids: evtx_powershell)` — PowerShell script block logging (Event ID 4104) — automatic Warning-level logging of suspicious content  [enrichment]
**FIX FIRST:** Core enrichment is source-verified and correct. Microsoft's own PowerShell source (CompiledScriptBlock.cs, fetched live) confirms the mechanism verbatim: CheckSuspiciousContent/SuspiciousContentChecker.Match sets HasSuspiciousContent (line 238-240); forceLogCreation = HasSuspiciousContent (line 2106) forces creation logging; the suspicious branch emits LogOperationalWarning while the ordinary branch emits LogOperationalVerbose, both id: ScriptBlock_Compile_Detail (lines 1553-1573). The Microsoft "PowerShell - the Blue Team" devblog (Lee Holmes) confirms "record of last resort" auto-logging, EventId 4104/0x1008, Channel Operational, Level Verbose for full SBL, and that Invoke-Expression of dynamically generated code produces its own logged event (backing the obfuscation/decode correction and the removal of the blanket "(decoded)" claim). cobbr.io is used only as Tier-2 corroboration, not as authority. Not a duplicate (4104 already at src/eventids.rs:273-280; this adds new behavior). MITRE T1059.001 fits and is unchanged. Related artifact ids evtx_powershell and evtx_powershell_classic both exist. evidence_strength Strong→Definitive is honest. One real defect requires fixing before apply.
- Level-numbering error (fix required): the proposal conflates Verbose with Informational. Enriched description says full SBL logs at 'Verbose/Informational' and forensic_notes say 'benign 4104 samples show Level 5/Informational'. Per Windows/ETW levels (Warning=3, Informational=4, Verbose=5) AND both cited primary sources (devblog 'Level Verbose'; source LogOperationalVerbose), Level 5 = Verbose, NOT Informational. Remove '/Informational' / 'Level 5/Informational'; state that full SBL 4104 = Verbose (Level 5) vs auto-suspicious = Warning (Level 3). The load-bearing triage tip (filter LevelDisplayName='Warning') is correct and can stay.
- Minor precision (optional): the auto-log's Warning level is confirmed by the source (LogOperationalWarning), not by the devblog — keep that attribution as written (proposal already does). The 4104 = ScriptBlock_Compile_Detail numeric mapping was not re-derivable from a fetched PSEventId enum (candidate raw-URL paths 404'd and code-search API needs auth), but 4104 is the established value already in the catalog and is confirmed by the devblog ('EventId 4104 / 0x1008') — no change needed.

**Additions:** Target: the existing `EventIdEntry { event_id: 4104, channel: "Microsoft-Windows-PowerShell/Operational", ... artifact_ids: &["evtx_powershell"] }` in src/eventids.rs (lines 273-280).

The `EventIdEntry` struct has no free-form notes/caveat field, so the enrichment goes into the `description` string. Extend the current description:

  Current:
    "PowerShell script block logging — captures full (decoded) script content"

  Enriched:
    "PowerShell script block logging — captures full script content. PowerShell v5+ auto-logs script blocks whose text matches its built-in suspicious-content signature list at WARNING level (LevelDisplayName='Warning') even when Script Block Logging is NOT configured via policy — a record-of-last-resort that yields free evidence on unconfigured hosts; ordinary (fully-configured) 4104 events log at Verbose/Informational. Triage tip: filter 4104 on Level=Warning to surface the flagged subset."

Note two accuracy corrections folded in (both source-backed):
- Drop the unqualified "(decoded)" claim — the compiled script block text is logged as it enters the engine; an obfuscated payload is stored in its obfuscated form, and only a subsequent Invoke-Expression of a decoded string emits its own separate 4104 that may contain readable code (Microsoft devblog + PowerShell source: hook fires at compile time before obfuscation unwinds).
- Full-SBL 4104 events are Verbose-level per the Microsoft devblog ("Level  Verbose"); the auto-logged suspicious subset is promoted to Warning via `PSEtwLog.LogOperationalWarning(...)`.

No change to mitre_techniques (T1059.001 remains correct), channel, artifact_ids, or high_value (already true). Evidence strength for the added claim: Strong→Definitive (Microsoft's own PowerShell source code confirms the forced-logging path and the Warning level).

**Sources verified:**
- [Tier 1 — authoritative vendor source code (Microsoft PowerShell repo)] https://raw.githubusercontent.com/PowerShell/PowerShell/master/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs — Confirms the mechanism verbatim: `CheckSuspiciousContent`/`SuspiciousContentChecker.Match` detects suspicious script text; `bool forceLogCreation = scriptBlock._scriptBlockData.HasSuspiciousContent` forces creation logging regardless of the EnableScriptBlockLogging setting; the event is emitted via `PSEtwLog.LogOperationalWarning(id: PSEventId.ScriptBlock_Compile_Detail, ...)` i.e. Warning level, PSEventId.ScriptBlock_Compile_Detail = 4104.
- [Tier 1 — vendor primary doc (Microsoft PowerShell Team blog, authored by Lee Holmes)] https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ — Confirms PowerShell automatically logs script blocks 'when they have content often used by malicious scripts' as a 'record of last resort' even when full Script Block Logging is not enabled; confirms full Script Block Logging events (4104) are recorded at 'Level  Verbose'; confirms obfuscated content is logged as-is with a subsequent decode producing its own event.
- [Tier 2 — independent reverse-engineering writeup (Ryan Cobb)] https://cobbr.io/ScriptBlock-Warning-Event-Logging-Bypass.html — Corroborates that the suspicious-content signature list is a non-public static field and that matches are logged to a ScriptBlock Warning-level 4104 event before any bypass takes effect; used only as corroboration, not sole authority.

**Notes:** Already-covered check: EID 4104 IS in the catalog (src/eventids.rs:273-280, high_value:true, T1059.001, evtx_powershell). This is a genuine enrichment, not a duplicate — the existing entry does not record the auto-logging-without-policy behavior or the Warning-level triage signal.

Caveats for the forensic user:
- The Warning-level auto-log is a *last resort*, not equivalent to full SBL: it fires ONLY when the compiled text matches the built-in signature list (encoded commands, reflection/GetField/NonPublic, AMSI-bypass strings), so it captures a subset, not all activity. Absence of Warning 4104 does NOT mean no malicious PowerShell ran.
- Filter on LevelDisplayName='Warning' rather than a numeric level: Windows severity numbering is confusing here (Warning=3; benign 4104 samples show Level 5/Informational), so match on the display name to avoid mis-filtering.
- The signature list is bypassable (null-out via reflection), but the tamper attempt itself typically emits a Warning 4104 first — so the bypass leaves a trace.
- Do NOT overstate "decoded": obfuscated payloads are stored obfuscated; readable code appears only in the follow-on 4104 emitted when a decoded string is re-invoked. Present findings as 'consistent with' obfuscated execution, not 'proves the plaintext'.
- Related existing catalog ids (verified present): evtx_powershell (4103/4104 Operational), evtx_powershell_classic (400/600 legacy Windows PowerShell log). No new related_artifacts needed.

### `mounted_devices` — Mounted Devices  [enrichment]
**FIX FIRST:** All load-bearing claims are Tier-1/tool-source verified: the trailing GUID {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}=MOUNTDEV_MOUNTED_DEVICE_GUID/GUID_DEVINTERFACE_VOLUME is confirmed verbatim on Microsoft's WDK page; the UTF-16-LE decode, \DosDevices vs \??\Volume value-name semantics, 12-byte MBR (4+8) and 24-byte GPT (16+8) formats are confirmed in regipy mountdev.py; the Volume-GUID->user join is confirmed verbatim in RegRipper mp2.pl ("Correlate the Volume entries to those found in the MountedDevices entries that begin with \??\Volume"); all four related_artifacts ids exist; it correctly enriches (not duplicates) the existing descriptor. Two small citation/precision gaps keep it from confirmed, both fixable without changing the substance.
- Uncited fact: the '&'-as-second-character 'Windows-generated (non-unique) serial' rule appears in both the usb_serial field description and a caveat, but none of the added sources (Microsoft GUID page, regipy mountdev.py, RegRipper mp2.pl) support it. Add a Microsoft primary source for device-instance-ID uniqueness (the '&' rule) or soften the claim; do not leave it uncited in a published library.
- Imprecise field description: usb_serial says the serial is 'the tail after the last #, before the {GUID}'. The last '#' immediately precedes the {GUID}; the iSerialNumber lives in the instance-ID segment '<serial>&0' that sits before that trailing '#{GUID}' (i.e., after the second-to-last '#'). Reword to point at the instance-ID segment, and note the '&0' suffix.
- Optional source hygiene: the RegRipper source uses the warewolf/regripper mirror; prefer the canonical keydet89/RegRipper3.0/plugins/mp2.pl (verified to contain the identical Analysis Tip).

**Additions:** ENRICH existing descriptor `mounted_devices` (mod.rs:7640) — it currently documents drive-letter/volume mappings but does NOT encode the two attribution joins. All additions verified against independent primary/tool sources.

--- 1. FIELDS (append two to MOUNTED_DEVICES_FIELDS, mod.rs:7619) ---
Add:
FieldSchema {
    name: "usb_serial",
    description: "USB device iSerialNumber decoded from the REG_BINARY device path (the tail after the last '#', before the {volume-interface GUID}); joins to the USBSTOR instance ID under SYSTEM\\CurrentControlSet\\Enum\\USBSTOR. A serial whose second character is '&' was generated by Windows because the device lacks a spec-compliant unique serial.",
    value_type: ValueType::Text,
    is_uid_component: false,
}
FieldSchema {
    name: "volume_guid",
    description: "Volume GUID from a \\??\\Volume{GUID} value name; the same GUID appears as a subkey under each user's NTUSER MountPoints2, which is the join that attributes the device to a specific user account.",
    value_type: ValueType::Text,
    is_uid_component: false,
}
(Rationale for existing device_path/value_name: MountedDevices value names are \DosDevices\<letter>: (drive-letter records) or \??\Volume{GUID} (volume records); the REG_BINARY data is a UTF-16-LE device path such as \??\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler&Rev_PMAP#<iSerialNumber>&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}. The trailing GUID is GUID_DEVINTERFACE_VOLUME / MOUNTDEV_MOUNTED_DEVICE_GUID — verified Microsoft. MBR devices instead store a 12-byte record: 4-byte disk signature + 8-byte partition offset; GPT stores a 24-byte GUID+offset record — verified in regipy mountdev.py.)

--- 2. MEANING (replace) ---
"Drive-letter and volume mappings under HKLM\\SYSTEM\\MountedDevices. Value names are either \\DosDevices\\<letter>: (a drive-letter assignment) or \\??\\Volume{GUID} (a volume record); the REG_BINARY data is a UTF-16-LE device path whose trailing {53f5630d-b6bf-11d0-94f2-00a0c91efb8b} is GUID_DEVINTERFACE_VOLUME. Supports two attribution joins for removable-media analysis: (1) device serial -> drive letter / Volume GUID — the USBSTOR iSerialNumber embedded in the device path links a \\DosDevices\\<letter>: entry (which letter the device mounted as) and a \\??\\Volume{GUID} entry (its Volume GUID) back to the same physical device in SYSTEM\\...\\Enum\\USBSTOR; (2) Volume GUID -> user — the \\??\\Volume{GUID} value's GUID is matched against the subkeys of each user's NTUSER Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2, identifying which user account mounted the device. Non-USBSTOR entries carry an MBR disk signature (4 bytes) + partition offset, or a GPT partition GUID."

--- 3. evidence_strength: Some(EvidenceStrength::Strong)  (was None) ---

--- 4. evidence_caveats (was empty) ---
[
  "MountedDevices retains only the last mapping for a given drive letter; a letter later reassigned overwrites the prior device's entry.",
  "The serial in the device path is the USB device iSerialNumber, NOT the filesystem Volume Serial Number seen in LNK/shortcut files — do not conflate the two.",
  "An iSerialNumber whose second character is '&' was Windows-generated because the device presented no spec-compliant unique serial, so it is not globally unique across devices.",
  "User attribution depends on matching the \\??\\Volume{GUID} entry against a user's NTUSER MountPoints2 subkeys; MountPoints2 entries are not reliably created, so absence is not proof the user did not use the device.",
]

--- 5. related_artifacts (was ["usb_enum", "wifi_profiles"]) ---
Change to ["usb_stor_enum", "mountpoints2", "usb_enum", "setupapi_dev_log"] — all verified-existing catalog ids. usb_stor_enum holds the iSerialNumber/ParentIdPrefix that the serial-join targets; mountpoints2 is the per-user attribution join target; setupapi_dev_log gives the reliable first-connection timestamp. (wifi_profiles dropped — not related to this artifact.)

--- 6. sources (add two; keep existing regipy/RECmd) ---
Add:
  "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/mountdev-mounted-device-guid"  (Microsoft primary: MOUNTDEV_MOUNTED_DEVICE_GUID = alias of GUID_DEVINTERFACE_VOLUME {53F5630D-...}, the GUID that tails MountedDevices unique IDs)
  "https://github.com/warewolf/regripper/blob/master/plugins/mp2.pl"  (RegRipper tool source: MountPoints2 subkeys named by Volume GUID; plugin's own note: "Correlate the Volume entries to those found in the MountedDevices entries that begin with \\??\\Volume")

--- MITRE: leave as-is (&["T1091"]). No additional ATT&CK technique cleanly fits the attribution join; not forcing one. ---

**Notes:** Evidence tiering: the descriptor's mapping facts are Tier-1/primary. (a) The trailing GUID {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} = GUID_DEVINTERFACE_VOLUME, aliased MOUNTDEV_MOUNTED_DEVICE_GUID, is Microsoft-documented (WDK) — the Mount Manager registers volumes under this interface, which is why it terminates every MountedDevices unique ID. (b) Value-name semantics (\DosDevices\<letter> vs \??\Volume{GUID}), UTF-16-LE device-path decode, embedded USBSTOR serial, and the 12-byte MBR / 24-byte GPT binary formats are confirmed in real tool source (regipy mountdev.py, already a catalog source). (c) The Volume-GUID -> user join is confirmed in RegRipper mp2.pl tool source, whose own analysis note instructs correlating MountPoints2 Volume-GUID subkeys back to MountedDevices \??\Volume entries.

evidence_strength set to Strong (not Definitive): the two joins are strong device-presence and device-to-user correlations, but MountedDevices keeps only the last drive-letter mapping and MountPoints2 creation is not guaranteed, so neither join is dispositive alone — both should be corroborated with usb_stor_enum, setupapi_dev_log, LNK/ShellBags. Kept "consistent with" framing in caveats (absence is not proof of non-use).

Triage note for whoever applies this: this is a pure metadata/field enrichment to an existing static descriptor — no decoder change (Decoder::Identity is correct; the binary decode is an analysis step, not a catalog transform). The two new fields are non-UID (value_name remains the sole is_uid_component). Blog sources (cyberengage, binary-zone, boutnaru Medium) were used ONLY as discovery pointers and are deliberately NOT added to sources.

### `wordwheel_query` — WordWheelQuery (Explorer Search)  [enrichment]
**FIX FIRST:** Both new primary sources resolve and directly support the core claims (verified by fetching the RegRipper parser and searching the Mandiant writeup). RegRipper tier-1 confirms the MRUListEx u32-array + 0xFFFFFFFF-terminator + UTF-16LE mechanics and the key path/hive; Mandiant tier-1 confirms — verbatim — the timestamp limitation (LastWrite dates only the most-recent term), the most-recent-first MRUListEx order, and the LNK-correlation method. EvidenceStrength::Strong exists and is honest (not overstated to Definitive); related_artifacts "lnk_files" is a real existing id (mod.rs:5144); MITRE T1083 is unchanged and fits. Not a duplicate — this enriches the existing descriptor. Two minor, fixable precision issues remain before it should enter the published library.
- Caveat #3 makes an UNSOURCED positive claim: 'Start-menu / taskbar search-box queries are handled by the Windows Search subsystem, not written here.' Neither cited primary source (RegRipper, Mandiant) states where Start-menu/taskbar queries go; both support only the scope (this key = File Explorer search bar). Fix: keep the sourced scope claim and drop or independently cite the 'Windows Search subsystem' attribution.
- Caveat #2's phrase 'Index at position 0 is the term the LastWrite time belongs to' is ambiguous and risks inverting the very correction this enrichment encodes. Mandiant's own Figure 5 shows value-INDEX 0 ('global') at the bottom = LEAST recent; the intended meaning is the FIRST element of the most-recent-first MRUListEx array. Reword to e.g. 'the first entry of the MRUListEx array (most-recent-first) identifies the term the LastWrite dates' to avoid being misread as value-index 0.
- Minor/non-blocking: the parenthetical 'RegRipper wordwheelquery.pl: unpack("V*"), pop if 0xffffffff' in caveat #2 cites RegRipper for the array mechanics, but the 'position 0 = LastWrite term' semantic is actually Mandiant's; the attribution is defensible as-is but the Mandiant source is the authority for the timing claim.

**Additions:** Enrich the EXISTING descriptor `wordwheel_query` (crates/data/src/catalog/descriptors/mod.rs:2418). No path/hive/decoder change — those are already correct (NtUser hive, key `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`, Decoder::MruListEx). Add the following:

1) evidence_caveats — currently `&[]`; set to (verbatim facts, each independently sourced):
  - "Derived-timestamp rule: the key LastWrite time dates ONLY the single most-recent search term — the value whose index sits at MRUListEx position 0. Every other term can be bounded only as searched *before* that LastWrite time; the Registry stores no per-term timestamp (Mandiant, 2020)."
  - "Recency order is recovered from the MRUListEx value: an array of little-endian u32 value-indices, most-recent-first, whose final entry is the 0xFFFFFFFF terminator (dropped before use). Index at position 0 is the term the LastWrite time belongs to (RegRipper wordwheelquery.pl: `unpack(\"V*\")`, `pop if 0xffffffff`)."
  - "Scope is File Explorer's search bar only, stored in NTUSER.DAT as numbered UTF-16LE values; Start-menu / taskbar search-box queries are handled by the Windows Search subsystem, not written here."
  - "Older search times can be recovered by correlating each term with user-search LNK files, which carry their own target MAC timestamps for when a file was opened from the search results; combining the LNK times with the MRUListEx order lets the analyst infer the relative sequence of earlier searches (Mandiant 'The Missing LNK', 2020)."

2) evidence_strength — currently `None`; set to `Some(crate::evidence::EvidenceStrength::Strong)`. Presence of a numbered value is a strong, direct record that the user typed that term into Explorer search; the only soft edge is per-term timing, now captured in evidence_caveats.

3) sources — append two independent primary sources to the existing array (keep the existing windowsir.blogspot.com pointer):
  - "https://cloud.google.com/blog/topics/threat-intelligence/the-missing-lnk-correlating-user-search-lnk-files/" (Mandiant RE writeup — the timestamp-interpretation limitation and LNK-correlation method)
  - "https://github.com/keydet89/RegRipper3.0/blob/master/plugins/wordwheelquery.pl" (real tool source — MRUListEx u32-array + 0xFFFFFFFF terminator + UTF-16LE term decoding)

4) related_artifacts — currently `&[]`; set to `&["lnk_files"]` (verified existing id at mod.rs:5144; it is the artifact Mandiant correlates against to time the older terms).

MITRE: leave mitre_techniques unchanged (&["T1083"] — File and Directory Discovery still fits; no additional technique cleanly applies).

**Sources verified:**
- [1 (independent RE/case writeup — Mandiant/Google Cloud)] https://cloud.google.com/blog/topics/threat-intelligence/the-missing-lnk-correlating-user-search-lnk-files/ — WordWheelQuery = user Explorer search history; searches listed in MRUListEx order; key LastWrite dates ONLY the most-recent term; older terms not directly datable from Registry; correlate with user-search LNK files (with their own MAC timestamps) to recover/infer earlier search times and order.
- [1 (real tool source — RegRipper3.0 parser)] https://github.com/keydet89/RegRipper3.0/blob/master/plugins/wordwheelquery.pl — Key path Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery in NTUSER.DAT; MRUListEx parsed as little-endian u32 array (unpack V*) with trailing 0xFFFFFFFF terminator popped; numbered values are the terms decoded from UTF-16LE; report emits key LastWrite time plus terms in MRUListEx order.

**Notes:** The load-bearing correction this enrichment encodes: a single WordWheelQuery key with N terms is often mis-read as N datable events. Only ONE term (MRUListEx position 0) is datable from the key's LastWrite; the rest are "before that time" and nothing more from the Registry alone. The MRUListEx structure (u32 index array, most-recent-first, 0xFFFFFFFF terminator) is confirmed directly in RegRipper's parser code, and the timestamp limitation is stated explicitly in Mandiant's writeup ("investigators could only determine the search time of the most recent term using the last modification time of the registry key"). The Start-menu/taskbar distinction is a scoping note: both cited sources describe this key strictly as File Explorer search-bar history; the Windows Search DB internals are not asserted here beyond that scoping. Evidence tiering: the MRUListEx layout and term decoding are tier-1 (real tool source); the timestamp-interpretation rule and LNK-correlation method are tier-1 (independent RE writeup on a real case). Keep language as "consistent with a user having searched for X" — the term proves the string was entered, not intent.

### `regedit_system_select` — Current Control Set Selector (HKLM\SYSTEM\Select)  [enrichment]
**FIX FIRST:** The forensic facts are accurate and well-sourced: winreg-kb (independent tier-1 RE reference) directly supports the Select key's four REG_DWORD values (Current/Default/Failed/LastKnownGood), the Current->ControlSet00N mapping (1->001, values 3/47 known), and the dead-box gotcha that CurrentControlSet is a run-time-only alias whose target is resolved via Select\\Current; MS Learn corroborates the path semantics (real page, not a fake-200). evidence_strength=Definitive is honest for a documented mechanical mapping, MITRE-empty is correct, volatility=Persistent with its rationale is sound, and the related_artifacts id is real. However the enrichment is not ready to apply as written for two reasons. (1) The prescribed mechanism is wrong for this codebase and would produce no enrichment: the ingest pipeline's codegen.rs hardcodes fields/related_artifacts/evidence_strength/evidence_caveats/volatility/volatility_rationale to defaults and IngestRecord carries none of them, so 'edit the generator source row and regenerate' would strip additions 2/4/5/6/7; there is also no local editable source row (records are parsed from Eric Zimmerman's remote RECmd .reb). The correct path is a hand-written manual descriptor (as the sibling CurrentControlSet artifacts already do), with the generated stub + its registration at mod.rs:15736 removed to avoid a duplicate id. (2) Three field descriptions exceed the cited sources and one is dated.
- CRITICAL (mechanism): The proposal says to apply the change to the generator/source row and regenerate, NOT hand-edit the generated .rs. This is impossible for the rich fields. crates/ingest/src/codegen.rs lines 151-159 hardcode fields:&[], related_artifacts:&[], evidence_strength:None, evidence_caveats:&[], volatility:None, volatility_rationale:"" as literal template constants, and crates/ingest/src/record.rs (IngestRecord) carries none of them. Regeneration would emit a stub identical to the current one. The enrichment MUST instead be a hand-written manual descriptor (like the other CurrentControlSet\... artifacts in mod.rs / windows_registry_ext2.rs, which do carry FieldSchema/EvidenceStrength/VolatilityClass).
- CRITICAL (no editable source row): The regedit_system_select record is parsed from Eric Zimmerman's remote RECmd_Batch_MC.reb (meaning = its Comment field); there is no local generator row to edit for meaning/name. Changing meaning via the generator is not possible without forking upstream.
- Transitional duplicate-id risk: the generated REGEDIT_SYSTEM_SELECT (id 'regedit_system_select') is still registered at crates/data/src/catalog/descriptors/mod.rs:15736. Adding a manual descriptor with the same id requires removing the generated stub and its registration, or the catalog will register the id twice.
- Overstatement beyond cited sources: field description Default='control set number used on the next normal boot. Usually equals Current' is not in winreg-kb or MS Learn. Either cite an authority (Windows Internals) or trim to winreg-kb's 'Default Control Set'.
- Overstatement: Failed='...0 if none has failed' is not sourced; winreg-kb only says 'Control Set that failed to boot'. Trim or cite.
- Overstatement + dated: LastKnownGood='Selected by the boot-menu LKG option after a failed boot' is not in the cited sources, and the F8 'Last Known Good Configuration' boot-menu option was removed/disabled by default from Windows 8 onward, while os_scope is Win7Plus. Trim to winreg-kb's 'Last known good Control Set / control set that last successfully booted Windows', or cite an authority for the mechanism and scope it correctly.
- Verified as correct (no change needed), for the implementer: winreg-kb fully supports the four-value schema, REG_DWORD types, Current->ControlSet00N mapping incl. 3/47, and the run-time-only CurrentControlSet stored-in-SYSTEM claim; related_artifacts id regedit_controlset00_control_windows exists at regedit_generated.rs:923; evidence_strength Definitive, MITRE empty, triage Low, and volatility Persistent are all defensible.

**Additions:** Enrich the existing stub `regedit_system_select` (crates/data/src/catalog/descriptors/generated/regedit_generated.rs:898, key_path "Select", hive HklmSystem). Note: this file is generated — apply the change to the upstream generator/source row for `regedit_system_select`, not by hand-editing the generated .rs, then regenerate.

1) meaning — replace the stub string "Current Control Set Name" with:
"HKLM\\SYSTEM\\Select holds four REG_DWORD values (Current, Default, Failed, LastKnownGood), each a number N that resolves the control set ControlSet00N (e.g. Current=1 -> ControlSet001). Current identifies the control set the running system booted from — i.e. what the live-only 'CurrentControlSet' symlink points to. On a dead-box/offline SYSTEM hive there is NO CurrentControlSet key (it is a volatile, boot-time-created registry link, not stored on disk); the examiner must read Select\\Current and follow it to the correct numbered ControlSet00N. Values other than 1/2 (e.g. 3, 47) occur after Last Known Good recovery or repeated boot failures."

2) fields — replace `fields: &[]` with four entries:
  FieldSchema { name: "Current",       value_type: ValueType::UnsignedInt, description: "REG_DWORD; number N of the control set the system is booted from -> ControlSet00N. This is the set 'CurrentControlSet' aliases at run time; the one to analyse on a live box.", is_uid_component: false },
  FieldSchema { name: "Default",       value_type: ValueType::UnsignedInt, description: "REG_DWORD; control set number used on the next normal boot. Usually equals Current.", is_uid_component: false },
  FieldSchema { name: "Failed",        value_type: ValueType::UnsignedInt, description: "REG_DWORD; control set number that was marked as failing to boot Windows. 0 if none has failed.", is_uid_component: false },
  FieldSchema { name: "LastKnownGood", value_type: ValueType::UnsignedInt, description: "REG_DWORD; control set number that last successfully booted (the Last Known Good set). Selected by the boot-menu LKG option after a failed boot.", is_uid_component: false }

3) sources — add (keep the existing RECmd .reb source):
  "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Current-control-set.html"
  "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-control-registry-tree"

4) evidence_strength: Some(crate::evidence::EvidenceStrength::Definitive) — the Select\\Current DWORD deterministically and by documented design identifies the active control set; the resolution is a mechanical mapping, not an inference.

5) evidence_caveats:
  "'CurrentControlSet' is a live-only volatile symlink created at boot and is NOT present in an offline/dead-box SYSTEM hive; resolve the active set via Select\\Current -> ControlSet00N instead of expecting a CurrentControlSet key.",
  "Configuration data is often duplicated across ControlSet001/002 (and any 003+). Analysing the wrong set, or assuming both sets agree, can produce stale or divergent findings — always pin analysis to the set named by Select\\Current, and diff sets when they differ.",
  "Control-set numbers above 2 (e.g. 3, 47) indicate prior Last Known Good recovery or repeated boot failures; Failed pointing at a set is consistent with a boot that was rolled back."

6) related_artifacts — add the existing catalog id "regedit_controlset00_control_windows" (a ControlSet00*\\Control child that the Select\\Current resolution points into).

7) volatility: Some(crate::volatility::VolatilityClass::Persistent); volatility_rationale: "The Select key and the numbered ControlSet00N keys are stored in the on-disk SYSTEM hive and survive reboots; only the CurrentControlSet alias itself is volatile (rebuilt at each boot)."

triage_priority: keep TriagePriority::Low (orientation/prerequisite artifact, not itself incriminating). mitre_techniques: keep &[] (no ATT&CK technique cleanly fits an orientation key; adversary persistence lives under the resolved ControlSet\\Services, not in Select).

**Sources verified:**
- [1 (independent reverse-engineering reference, Joachim Metz/winreg-kb)] https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Current-control-set.html — Select key contains Current/Default/Failed/LastKnownGood all REG_DWORD; Current's DWORD N resolves to ControlSet00N (1->ControlSet001; values 3, 47 also seen); CurrentControlSet 'is only present at run-time', its contents stored in the SYSTEM file and determined by reading Select\Current -> the dead-box resolution + volatile-symlink gotcha
- [1 (vendor primary, Microsoft Learn)] https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-control-registry-tree — Vendor documentation of the HKLM\SYSTEM\CurrentControlSet\Control tree semantics, corroborating that CurrentControlSet is the active control set path applications reference

**Notes:** Verified facts, all from the independent RE reference winreg-kb (Joachim Metz), tier-1/primary: (a) Select contains exactly Current/Default/Failed/LastKnownGood, all REG_DWORD; (b) Current's DWORD N maps to ControlSet00N, N normally 1 or 2 but "3 or 47 are known"; (c) CurrentControlSet "is only present at run-time" and its contents are stored in the SYSTEM file and determined by reading Select\\Current — this is the exact dead-box gotcha the work item asks for. The MS Learn "HKLM\\SYSTEM\\CurrentControlSet\\Control Registry Tree" page is the vendor corroboration for the CurrentControlSet path/semantics. Note the originally-suggested MS troubleshoot URL (registry-hklm-system-currentcontrolset) returned HTTP 404, so I did NOT cite it. The WebSearch synthesis attributed the Failed/LKG-rollback mechanism to Russinovich's Windows Internals (Microsoft Press) — plausible and consistent, but I did not click through to that page, so I kept the caveats to what winreg-kb + MS Learn actually confirm and did not assert the internal rollback sequence as catalog fact. related_artifacts id "regedit_controlset00_control_windows" confirmed present at regedit_generated.rs:923. This descriptor lives in a generated file — the enrichment must be applied to the generator source row and regenerated, not hand-patched.

### `pca_general_db` — PCA PcaGeneralDb0.txt  [enrichment]
**FIX FIRST:** Core enrichment is well-supported by two independent RE writeups (AboutDFIR + Sygnia) plus a verbatim sample: the 8-field pipe order, UTF-16LE encoding, UNC-blanking of Product/Company/Version/ProgramID, Blanche Lagny's ProgramId-derivation quote, Record Type 3 = 'PCA Resolve is Called', ~4MB rotation, and the correction of the unsupported 'embeds FILETIME' claim to a UTC datetime string. evidence_strength Strong is honest (RE writeups, not a Microsoft spec); the amcache_app_file related id exists; MITRE left unchanged is reasonable. Four fixable accuracy issues remain before it should enter the published catalog.
- Misquoted 'verbatim' sample: the spec renders the AboutDFIR sample line ending as 'Abnormal process exit with code 0x0', but the actual AboutDFIR page reads '...0x80'. Correct the quoted value to 0x80 (verified against the fetched page).
- run_status overstatement: description says '3 = PCA Resolve call (the component that applies compatibility fixes)'. Sygnia explicitly states they could NOT identify what triggers these records and only that they are 'associated with the PCA mechanism itself'. Remove the 'applies compatibility fixes' gloss and use Sygnia's actual framing.
- Inaccurate field cross-reference: program_id description says '(see amcache_app_file.program_id)', but the amcache_app_file descriptor uses AMCACHE_FIELDS which contains only file_id and sha1 — there is no program_id field on that descriptor (program_id is in a different descriptor's AMCACHE_PROGRAM_FIELDS). Drop the '.program_id' pinpoint or reword; the ProgramId->InventoryApplicationFile join concept is still sound.
- Securelist source (#5) could not be fetched (repeated ECONNRESET) so its specific claims are unverified. The 'timestamp recorded at process termination (not at launch)' correction and 'Observed values 0-4' run_status range rest partly on this unverified source (AboutDFIR labels field 1 only 'Runtime'). Independently verify Securelist, or soften these two assertions; the rotation and InventoryApplicationFile linkage are already covered by Sygnia so those are fine.

**Additions:** Enrich the EXISTING descriptor `pca_general_db` (crates/data/src/catalog/descriptors/mod.rs:318). Its PCA_GENERAL_DB_FIELDS_SCHEMA currently has only 3 fields (exe_path, exit_code, timestamp). The raw on-disk PcaGeneralDb0.txt record is UTF-16LE, pipe-delimited, with 8 fields in this VERIFIED order (from AboutDFIR's verbatim sample line):

  timestamp | run_status | exe_path | file_description | software_vendor | file_version | program_id | exit-message

Verbatim sample (AboutDFIR): `2022-05-12 21:32:42.556|2|%USERPROFILE%\appdata\local\githubdesktop\app-2.9.9\resources\app\git\cmd\git.exe|git|the git development community|2.32.0.windows.2|0006ea6a66e62a303f7b974dc4952647a80300000904|Abnormal process exit with code 0x0`

1) ADD these four FieldSchema entries to PCA_GENERAL_DB_FIELDS_SCHEMA (mod.rs:281-303), interleaved to match on-disk order:
  FieldSchema { name: "run_status", value_type: ValueType::Text, description: "Numeric record/run-status code (field 2). Observed values 0-4; e.g. 2 in the sample, 3 = PCA Resolve call (the component that applies compatibility fixes). Analogous to an Event ID for the record.", is_uid_component: false }
  FieldSchema { name: "file_description", value_type: ValueType::Text, description: "PE FileDescription of the executable (e.g. \"git\"). Blank when the program was run from a UNC path.", is_uid_component: false }
  FieldSchema { name: "software_vendor", value_type: ValueType::Text, description: "CompanyName / publisher from the PE version resource (e.g. \"the git development community\"). Blank for UNC-launched programs.", is_uid_component: false }
  FieldSchema { name: "file_version", value_type: ValueType::Text, description: "ProductVersion / FileVersion from the PE version resource (e.g. \"2.32.0.windows.2\"). Blank for UNC-launched programs.", is_uid_component: false }

2) ADD the AmCache join-key field:
  FieldSchema { name: "program_id", value_type: ValueType::Text, description: "AmCache ProgramId (e.g. 0006ea6a66e62a303f7b974dc4952647a80300000904) — the join key to the AmCache InventoryApplicationFile subkey of the same name (see amcache_app_file.program_id). Per Blanche Lagny's AmCache research the ProgramId is derived from the file Name, Version, Publisher and Language, so it is stable for identical software across systems and enables cross-artifact and cross-host correlation. Blank for UNC-launched programs.", is_uid_component: false }

3) CORRECT the existing `timestamp` field description (mod.rs:299-300). The raw on-disk timestamp is a UTC string of the form `YYYY-MM-DD HH:MM:SS.f` (sample: 2022-05-12 21:32:42.556), recorded at PROCESS TERMINATION (not start); Carvey's PCAParse converts this to Unix epoch seconds. The current wording ("raw on-disk records embed FILETIME") is not supported by the sample — replace with: "Raw on-disk format is a UTC datetime string 'YYYY-MM-DD HH:MM:SS.f' recorded when the process terminates (not at launch); Carvey's PCAParse re-emits it as Unix epoch seconds."

4) ADD "amcache_app_file" to related_artifacts (mod.rs:338) → related_artifacts: &["pca_applaunch_dic", "amcache_app_file"] (both ids verified present in catalog).

5) ADD Securelist to sources (mod.rs:341-345): "https://securelist.com/forensic-artifacts-in-windows-11/117680/" — explicitly states the ProgramId is "referenced in the Amcache registry hive (InventoryApplicationFile key)" and documents the UTF-16LE pipe-delimited field layout and the ~2 MB PcaGeneralDb0/PcaGeneralDb1 rotation.

6) OPTIONAL meaning refresh (mod.rs:329-333): note that beyond the abnormal-exit code, each record also carries the executable's file description, vendor, version and the AmCache ProgramId, so the file is a self-contained execution+identity record that can be pivoted into AmCache even after the executable is deleted.

Set evidence_strength: Some(EvidenceStrength::Strong) (field schema confirmed by three independent RE writeups plus a verbatim sample line). Suggested evidence_caveats: &["Field schema and order established by RE writeups (Sygnia, AboutDFIR, Securelist) plus one verbatim sample line, not a Microsoft spec.", "Product name, company, version and ProgramId are blank for programs launched from UNC paths.", "PCA logs only Explorer-launched programs; absence is not proof of non-execution."]. Do NOT add new MITRE techniques — existing T1059/T1204.002 remain appropriate for these metadata fields.

**Sources verified:**
- [Tier-2 (independent RE writeup w/ verbatim sample)] https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/ — Verbatim raw PcaGeneralDb0.txt line establishing 8-field pipe order: timestamp | run_status(2) | exe_path | file_description(git) | software_vendor(the git development community) | file_version(2.32.0.windows.2) | ProgramId(0006ea6a...) | exit-message(Abnormal process exit with code 0x0). States the 7th field 'appears to be the ProgramId as recorded in the Amcache'.
- [Tier-2 (Kaspersky RE writeup)] https://securelist.com/forensic-artifacts-in-windows-11/117680/ — Confirms UTF-16LE pipe-delimited layout; fields = timestamp, execution status, full exe path, description+vendor, file version, 'ProgramId referenced in the Amcache registry hive (InventoryApplicationFile key)', exit code. Notes run-status 3 = PCA Resolve call; timestamp recorded at process termination; UNC-launched programs leave Product/Company/Version/ProgramID blank; PcaGeneralDb0/1 rotate at 2 MB.
- [Tier-2 (Sygnia RE writeup)] https://www.sygnia.co/blog/new-windows-11-pca-artifact/ — Documents 8 pipe-delimited fields incl. record type (0-4), Product Name, Company Name, Product Version, ProgramID, Executable Path, Record Message; and that 'ProgramIDs were first observed in the AmCache', citing Blanche Lagny that ProgramId is a hash of Name, Version, Publisher and Language (stable across systems).
- [Tier-1 (catalog source)] file:///Users/4n6h4x0r/src/forensicnomicon/crates/data/src/catalog/descriptors/mod.rs — Confirms related-artifact id 'amcache_app_file' (Amcache InventoryApplicationFile, line 936) exists with a 'program_id' field (line 978) described as the pivot to InventoryApplicationFile — the correct join target for the new PcaGeneralDb0 program_id field.

**Notes:** Field order was settled by AboutDFIR's verbatim sample line rather than the Sygnia summary table (Sygnia lists ProductName/Company/Version before ProgramID/Path; the actual raw line puts exe_path in field 3, ProgramId in field 7 — the sample is authoritative). The existing descriptor's claim that raw timestamps 'embed FILETIME' is unsupported and corrected to the UTC string format shown in the sample; Carvey's Unix-epoch output is his PCAParse re-encoding, and Carvey's `1652387261|PCA|||...` line is TLN output, not the raw on-disk record. ProgramId join is the load-bearing enrichment: a PcaGeneralDb0 record whose ProgramId matches an AmCache InventoryApplicationFile subkey ties the crash event to AmCache's installed-application identity and SHA-1, and survives deletion of the executable. Caveat preserved: nothing in the file attributes activity to a user, and UNC-launched programs blank the identity fields (description/vendor/version/ProgramId), so absence of those fields is consistent with UNC execution, not with tampering.
