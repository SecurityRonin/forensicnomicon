# 13cubed "Investigating Windows Endpoints" (IWE) — Exhaustive Knowledge Inventory

**Status:** Private gap-analysis worklist. This is knowledge (forensic facts,
artifact behaviours, techniques — uncopyrightable), fully reworded in our own
words from the IWE course transcripts; **not for publication**. Every item is
**UNVERIFIED** and must receive an independent primary-source citation (Microsoft
docs, libyal, Eric Zimmerman tool docs, Volatility source, Brian Carrier FSFA,
established DFIR write-ups) before it enters `forensicnomicon`. Descriptors cite
those primary sources, **never 13cubed**. The course transcripts stay in the
user's Sync library; only reworded facts appear here.

**Method:** Per-lesson distillation of all 34 content lessons of the IWE course
(one agent per `.srt` transcript, "tables/steps/commands are facts, extract
everything"). This is the depth-parity companion to the earlier
`docs/13cubed-iwe-coverage-audit.md`: the audit answered *which artifacts are
present/missing in forensicnomicon* (and backfilled 26 Event IDs); this inventory
captures the *interpretive knowledge* (how to read each artifact, the analytic
nuances and gotchas) the audit did not extract.

## Summary

- **Knowledge facts:** 2,369 (from 2,369 raw bullets, minus 0 byte-identical duplicates)
- **Lessons distilled:** 34 / 34 content lessons (setup/intro lessons excluded)
- **Average:** 69 facts per lesson

### Lesson index

| Chapter | Lesson | Facts |
|---|---|---:|
| 02 | Fundamentals | 42 |
| 02 | In depth Analysis | 143 |
| 02 | Tools and Best Practices | 91 |
| 03 | Fundamentals | 57 |
| 03 | NTUSERDAT | 73 |
| 03 | Scalable Analysis | 70 |
| 03 | USB Forensics Networks | 70 |
| 03 | UsrClass ShellBags | 80 |
| 04 | AmCache | 75 |
| 04 | MUICache | 39 |
| 04 | PCA | 34 |
| 04 | Prefetch | 104 |
| 04 | SRUM | 68 |
| 04 | ShimCache | 97 |
| 04 | UserAssist | 42 |
| 05 | LSASS NTDS WDigest | 66 |
| 05 | SMB RDP WMI PsExec UAL | 94 |
| 05 | Services Scheduled Tasks | 87 |
| 06 | I30 Index Attributes | 35 |
| 06 | MACB Timestamps | 84 |
| 06 | Metafiles MFT Journaling ADS | 116 |
| 06 | Parsing MFT USN | 71 |
| 07 | Permanent Deletion | 21 |
| 07 | PhotoRec Carving | 67 |
| 07 | Recycle Bin | 45 |
| 08 | Jump Lists | 65 |
| 08 | LNK Files | 55 |
| 09 | MFTECmd | 37 |
| 09 | Plaso Log2Timeline | 94 |
| 09 | TSK fls mactime | 75 |
| 10 | Thumbcache | 49 |
| 10 | Web Browser Forensics | 68 |
| 10 | Windows Activity Timeline | 63 |
| 10 | Windows Search Index | 92 |

## Reconciliation with the coverage audit

Cross-reference this inventory against `docs/13cubed-iwe-coverage-audit.md`:
the audit's PRESENT/PARTIAL/MISSING rows say *whether* forensicnomicon encodes an
artifact; the facts here say *what the analyst needs to know* about it. Where a
fact here adds a decode step, a timestamp-semantics nuance, or a gotcha not in a
PRESENT descriptor, that is a candidate enrichment (cite the primary source, not
13cubed). Notable high-value nuances captured here that a coverage checklist
misses: the ShimCache execution-vs-presence myth (+ the 2023 four-byte finding
and write-only-on-shutdown behaviour), Amcache presence-not-execution, UserAssist
1601-epoch sentinels from service-launched processes, and the full per-operation
MACB rule matrix.

---

# Knowledge Inventory (by course chapter)


## Chapter 02 · Fundamentals

### Log format history and evolution

- **Windows XP event log count** — Windows XP shipped with only three event logs: Application, System, and Security. _Why:_ Sets the baseline showing how limited pre-Vista telemetry was, so an XP-era case has far fewer log sources to mine. _[IWE ch02 · Event Logs / Fundamentals]_
- **.EVT format** — The XP-era event logs used the legacy EVT format with a `.evt` file extension. _Why:_ Tells the examiner which parser (e.g. libevt) is required for pre-Vista artefacts. _[IWE ch02 · Event Logs / Fundamentals]_
- **EVT is proprietary binary** — The `.evt` format is a proprietary binary format, not text/XML. _Why:_ Cannot be read with a text editor; needs a format-aware tool. _[IWE ch02 · Event Logs / Fundamentals]_
- **EVT compute cost** — The legacy EVT format was CPU-expensive to write to and to parse. _Why:_ Explains why so few logs existed under XP — performance limited how much logging was practical. _[IWE ch02 · Event Logs / Fundamentals]_
- **Vista as the security demarcation** — Windows Vista and later operating systems mark a distinct improvement in security-relevant logging compared to earlier Windows. _Why:_ A modern Windows target yields materially richer forensic evidence than a pre-Vista one. _[IWE ch02 · Event Logs / Fundamentals]_
- **EVTX introduced in Vista** — Windows Vista introduced the EVTX log format, which remains in use in current Windows. _Why:_ One parser (EVTX-aware) covers Vista through the latest Windows. _[IWE ch02 · Event Logs / Fundamentals]_
- **EVTX is binary XML** — EVTX is a binary XML format. _Why:_ Records are structured XML under the hood, so parsers can render field-labelled XML for each event. _[IWE ch02 · Event Logs / Fundamentals]_
- **EVTX efficiency** — EVTX is far more efficient (lower compute cost to write and parse) than its EVT predecessor. _Why:_ Efficiency gain is what enabled Windows to expand from 3 logs to hundreds. _[IWE ch02 · Event Logs / Fundamentals]_
- **More logs enabled by EVTX + security focus** — The combination of EVTX efficiency and Vista's increased security focus is why modern Windows exposes far more event logs than the original three. _Why:_ Causal link explaining the artefact abundance the examiner now benefits from. _[IWE ch02 · Event Logs / Fundamentals]_

### Log location and counts

- **Default log directory** — By default, EVTX logs live at `%SystemRoot%\System32\winevt\Logs` (i.e. `Windows\System32\winevt\Logs`). _Why:_ First place to collect from on a live or imaged system. _[IWE ch02 · Event Logs / Fundamentals]_
- **Log location is registry-configurable** — The event-log storage location can be changed via the registry, though it is rarely relocated in practice. _Why:_ If logs are absent from the default path, check the registry for a redirected location before concluding they were deleted. _[IWE ch02 · Event Logs / Fundamentals]_
- **Log count on a heavily-featured host** — A system with many extra Windows features and third-party software installed showed 373 log files in the winevt\Logs folder. _Why:_ Log count scales with installed roles/software; more features means more potential evidence sources. _[IWE ch02 · Event Logs / Fundamentals]_
- **Log count on a clean Windows 11 install** — A plain, freshly-installed Windows 11 system carried 102 event logs in winevt\Logs. _Why:_ Baseline expectation for a vanilla host — roughly 100 logs even before any customisation. _[IWE ch02 · Event Logs / Fundamentals]_
- **Classic three persist** — Application, System, and Security still exist as distinct logs on modern Windows alongside all the newer logs. _Why:_ The legacy triad remains a starting point even though it is no longer the whole picture. _[IWE ch02 · Event Logs / Fundamentals]_
- **Microsoft-Windows-* naming convention** — Many modern logs follow a `Microsoft-Windows-<Component>/<Channel>` naming pattern. _Why:_ The name itself identifies the originating component, guiding which log to open for a given activity. _[IWE ch02 · Event Logs / Fundamentals]_

### The Security log specifics

- **Security log as first pivot** — The Security log is the typical first log to examine when investigating a suspected Windows compromise. _Why:_ It concentrates authentication/logon and policy events central to intrusion triage. _[IWE ch02 · Event Logs / Fundamentals]_
- **Only LSASS writes the Security log** — The only process that should legitimately write to and update the Security log is LSASS (Local Security Authority Subsystem Service). _Why:_ Any other writer to that log is anomalous and worth flagging. _[IWE ch02 · Event Logs / Fundamentals]_
- **LSASS role** — LSASS is responsible for essentially all authentication and security functions on a Windows system, making it one of the most important processes. _Why:_ Explains why LSASS is both the Security-log author and a prime credential-theft target. _[IWE ch02 · Event Logs / Fundamentals]_
- **Single LSASS instance** — Exactly one `lsass.exe` process should be running at any time; more than one instance indicates a problem (e.g. masquerading malware). _Why:_ A quick live-triage integrity check — duplicate LSASS is a red flag. _[IWE ch02 · Event Logs / Fundamentals]_
- **Security log churn / small event horizon** — The Security log is very busy, so at default size it covers only a short time window (small "event horizon"), especially on a domain controller. _Why:_ Sets expectations that Security-log history may be too short to reach the incident date; corroborate elsewhere. _[IWE ch02 · Event Logs / Fundamentals]_
- **Default Security log size** — On the demonstrated system the Security log's default maximum size was 20 MB. _Why:_ A small cap means fast rollover; older events may already be overwritten by collection time. _[IWE ch02 · Event Logs / Fundamentals]_
- **Log size is increaseable and should be** — The maximum size of Windows event logs can and should be raised (e.g. to 200 MB or more) given cheap disk. _Why:_ Larger caps preserve a longer event horizon, improving retrospective investigations. _[IWE ch02 · Event Logs / Fundamentals]_
- **Churn persists even when enlarged** — Even after increasing the maximum size, the Security log still experiences significant churn. _Why:_ Bigger logs help but do not eliminate the need for centralised collection. _[IWE ch02 · Event Logs / Fundamentals]_

### Centralised collection

- **Centralised log collection is critical** — Because of Security-log churn, centrally collecting event logs off-host is important for forensic readiness. _Why:_ Central copies survive local rollover and tampering, extending the recoverable timeline. _[IWE ch02 · Event Logs / Fundamentals]_
- **Windows Event Forwarding (WEF)** — Windows includes built-in Windows Event Forwarding, available free since Windows Vista, for centralising logs. _Why:_ A no-cost native option; check whether the environment used it for a forwarded log source. _[IWE ch02 · Event Logs / Fundamentals]_
- **SIEM as alternative** — A full SIEM (e.g. Splunk) is an alternative centralised collection mechanism to native WEF. _Why:_ A SIEM may hold event history the local host has already overwritten. _[IWE ch02 · Event Logs / Fundamentals]_

### Anti-forensics and log clearing

- **Threat actors clear logs as anti-forensics** — Attackers commonly clear event logs to cover their tracks. _Why:_ Missing or truncated logs can themselves be evidence of anti-forensic activity, not innocent absence. _[IWE ch02 · Event Logs / Fundamentals]_
- **Security log is the top clearing target** — When clearing logs, adversaries prioritise the Security log first. _Why:_ Focus corroboration efforts elsewhere when the Security log has been wiped. _[IWE ch02 · Event Logs / Fundamentals]_
- **Secondary clearing targets** — After Security, attackers often also clear System, sometimes Application, and a few select other logs. _Why:_ Predicts which logs are likely damaged and which ancillary ones may survive. _[IWE ch02 · Event Logs / Fundamentals]_
- **Ancillary logs likely survive clearing** — Because there are so many logs, the odds are high that attackers miss some, leaving recoverable evidence in overlooked logs. _Why:_ Justifies parsing the full log corpus rather than only the classic three. _[IWE ch02 · Event Logs / Fundamentals]_

### Event log timeline technique

- **Event log timeline** — An "event log timeline" is built by parsing every event log and ordering all records chronologically. _Why:_ Cross-log temporal view surfaces context around a suspected event that a single log would miss. _[IWE ch02 · Event Logs / Fundamentals]_
- **EvtxECmd for bulk parsing** — Eric Zimmerman's EvtxECmd can parse through all event logs on a system and place records in temporal order. _Why:_ The named tool to produce the combined cross-log timeline. _[IWE ch02 · Event Logs / Fundamentals]_
- **Pivot around a suspected time** — With a combined timeline you pivot on the time a suspicious event is believed to have occurred and read the surrounding events across other logs. _Why:_ Temporal proximity across logs reconstructs what happened before/during/after an incident. _[IWE ch02 · Event Logs / Fundamentals]_
- **Discovering unfamiliar logs** — A combined timeline can surface an obscure/unfamiliar EVTX log recording something important, which can then be researched to determine what that log captures. _Why:_ Encourages investigating unknown logs rather than ignoring them — they sometimes answer the case. _[IWE ch02 · Event Logs / Fundamentals]_

### Investigative significance

- **Logs can solve a case alone** — With a complete set of event logs spanning the threat-actor activity window, a case can sometimes be resolved on event logs alone. _Why:_ Justifies prioritising event-log analysis early in an investigation. _[IWE ch02 · Event Logs / Fundamentals]_
- **Do not limit to the classic three** — Restricting analysis to Application/System/Security misses the many additional logs that also carry evidence. _Why:_ Methodological warning against tunnel vision on the legacy triad. _[IWE ch02 · Event Logs / Fundamentals]_

### Terminal Services / lateral movement

- **Terminal Services logs profile RDP** — The Terminal Services event logs record Remote Desktop (RDP) activity. _Why:_ Primary source for reconstructing remote-desktop sessions. _[IWE ch02 · Event Logs / Fundamentals]_
- **Terminal Services logs reveal lateral movement** — RDP activity captured in Terminal Services logs can expose lateral movement across an environment. _Why:_ Maps how an attacker pivoted host-to-host. _[IWE ch02 · Event Logs / Fundamentals]_

### Tools and workflow

- **Event IDs as pivot values** — Specific numeric Event IDs within logs are the values to search/pivot on to answer investigative questions. _Why:_ Filtering by Event ID is the core query technique for event-log analysis. _[IWE ch02 · Event Logs / Fundamentals]_
- **Event Viewer** — Windows ships with Event Viewer, a built-in GUI to open logs, filter, and search event records. _Why:_ Native tool available on any Windows host for ad-hoc review without extra software. _[IWE ch02 · Event Logs / Fundamentals]_
- **EvtxECmd for full-system parsing** — EvtxECmd is used to parse all event logs on a given system (beyond ad-hoc Event Viewer inspection). _Why:_ Scales analysis to the whole log corpus and feeds timelining/CSV output. _[IWE ch02 · Event Logs / Fundamentals]_
- **Windows Sandbox for clean testing** — Windows Sandbox provides a disposable, plain Windows 11 environment (used here to count default logs). _Why:_ A safe throwaway VM for validating baseline artefact state or detonating samples. _[IWE ch02 · Event Logs / Fundamentals]_

## Chapter 02 · In depth Analysis

### Event Viewer & terminology

- **Event Viewer** — a built-in Windows application providing basic interaction with the Windows event logs; less capable than dedicated parsing utilities for searching/filtering. _Why:_ baseline triage tool always present on the box, but not the analytical workhorse. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Event Viewer access path 1** — reachable through the Computer Management snap-in (searchable from Start), which also exposes Task Scheduler, Shared Folders, Local Users and Groups, Performance, and Device Manager. _Why:_ one of two standard ways to open it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Event Viewer access path 2** — typing "event" into Start surfaces an Event Viewer match to launch directly. _Why:_ fastest launch route. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Windows Logs node** — under "Windows Logs" there are five standard entries: Application, Security, Setup, System, and Forwarded Events. _Why:_ the core log set to know by default. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Channel** — a "channel" is essentially the log name itself. _Why:_ correct terminology for where events live; a channel maps to a physical .evtx log. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Provider** — a specific program, service, or driver that writes events into a channel. _Why:_ an event is identified by its channel AND its provider, not just the log name. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Applications and Services Logs node** — a separate tree containing channels created for individual applications and components (beyond the five core Windows Logs). _Why:_ where most non-core/ancillary logs (Task Scheduler, PowerShell Operational, Terminal Services, Defender) live. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Event Viewer layout** — the top pane lists the log's events; the bottom (or detail) pane shows the selected event's Event ID, general/plain-English description, source, and log name. _Why:_ orients the analyst to where each field is read. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Filter Current Log** — right-side action that narrows the current channel to specified Event IDs (and other criteria). _Why:_ primary in-GUI triage filter. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **GUI filtering keywords** — the filter dialog can also constrain by a specific user or a specific computer, in addition to Event ID. _Why:_ limited extra pivots, but far less flexible than CSV parsing. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Event ID reuse across logs** — the same numeric Event ID can mean entirely different things in different channels; an ID's meaning is only defined together with its log/provider. _Why:_ prevents cross-log misinterpretation (e.g. 106 in Task Scheduler ≠ 106 elsewhere). _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Log volume baseline** — a plain vanilla Windows system exposes 100+ event logs; a heavily used/instrumented system can exceed 300 logs. _Why:_ sets scope; no cheat sheet can enumerate every log/ID, so prioritisation matters. _[IWE ch02 · Event Logs / In-depth Analysis]_

### ESE / ESENT concept

- **ESE / ESENT** — the Extensible Storage Engine (also called JET Blue), a database format used within Windows. _Why:_ underpins several high-value artifacts and its provider writes forensically relevant events. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ESE usage** — ESE backs the Windows Search database, Microsoft Exchange, and `ntds.dit` (the Active Directory database). _Why:_ explains why ESENT events matter across endpoint and DC investigations. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ntds.dit contents** — stores cryptographic representations (hashes) of credentials for all users in the Active Directory environment plus other AD security data. _Why:_ prime threat-actor target; drives the "profile ESENT activity" rationale. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ESENT is not its own log** — ESENT events are found in the Application channel with the provider "ESENT," not in a separate `esent.evtx` file. _Why:_ you look in Application filtered by provider, correcting the intuition to seek a dedicated log. _[IWE ch02 · Event Logs / In-depth Analysis]_

### 4624 successful logon (Security)

- **4624 (Security)** — a successful account logon; one of the most ubiquitous Windows Event IDs. _Why:_ core account-activity artifact; memorise it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4624 fields** — records Subject (Security ID, Account Name, Account Domain, Logon ID), Logon Type, and for remote events the source network address and source port. _Why:_ enables who/where/how reconstruction of a logon. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Computer-account trailing `$`** — an account name ending in `$` denotes a machine/computer account rather than a human user. _Why:_ distinguishes machine logons from interactive user activity. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **WORKGROUP domain field** — a logon showing domain "WORKGROUP" indicates the host is not domain-joined. _Why:_ quick read of standalone vs domain context. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4624 source address = origin** — in a network 4624, the recorded source/workstation address is the computer from which the connection originated. _Why:_ pivots to the attacking/originating host. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4624 source provider** — the source shown is "Microsoft Windows security auditing." _Why:_ confirms the auditing subsystem authored the event. _[IWE ch02 · Event Logs / In-depth Analysis]_

### 4688 process creation (Security)

- **4688 (Security)** — a process execution / process auditing event indicating a process was run on the system. _Why:_ direct evidence of program execution when enabled. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4688 not on by default** — process auditing must be explicitly enabled (e.g. via Group Policy). _Why:_ absence of 4688s does not mean nothing executed. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4688 command-line capture is a second setting** — logging the full process command line requires an additional configuration beyond enabling process creation auditing. _Why:_ two independent toggles; full command line is a bonus only when both are on. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4688 core-process exception** — some core Windows system processes may still generate 4688s even when process tracking is not enabled. _Why:_ explains stray 4688s on unaudited systems. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4688 command-line value** — when full command line is captured, the event shows the executable and its arguments (e.g. `mmc.exe eventvwr.msc` reveals which snap-in MMC loaded). _Why:_ command line is the richest forensic detail in a 4688. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **MMC / snap-in mechanics** — `mmc.exe` (Microsoft Management Console) renders snap-ins; Event Viewer itself runs as MMC loading `eventvwr.msc`. _Why:_ context for reading MMC 4688 command lines. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Security log properties & 1102 log clear

- **Security log volatility** — the Security log's default size is very small and rolls (overwrites) quickly, especially on domain controllers. _Why:_ short event horizon; central collection is often needed to retain history. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Central log collection value** — forwarding Security events to a SIEM (e.g. Splunk) preserves them even if a threat actor clears the local log. _Why:_ defeats anti-forensic log clearing; the cleared local log becomes a minor inconvenience. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1102 (Security)** — records that the Security/audit log was cleared, including the account responsible and the host. _Why:_ high-signal anti-forensic indicator; names who cleared it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1102 self-logging** — when the Security log is cleared, the very first entry written to the (now empty) log is the 1102 clear event itself. _Why:_ clearing cannot hide the fact of clearing within Security. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Security is the "special snowflake"** — Security is unique in having its own dedicated clear-log Event ID (1102), unlike other logs. _Why:_ contrasts with the System-log 104 model below. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **LSASS writes Security** — only LSASS is able to write to the Security log. _Why:_ integrity property of the Security channel (as stated in the lesson). _[IWE ch02 · Event Logs / In-depth Analysis]_

### Security log — cheat-sheet Event IDs

- **4625 (Security)** — a failed logon. _Why:_ pairs with 4624; brute-force / failed-access detection. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4634 (Security)** — a logoff; typically seen for network-type sessions on disconnect (e.g. after a `\\host\share` network path access ends). _Why:_ session-end tracking for non-interactive sessions. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4647 (Security)** — a user-initiated logoff, used in place of 4634 for interactive sessions (hands-on-keyboard or remote desktop logins). _Why:_ distinguishes interactive session termination from network disconnect. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4648 (Security)** — logon attempted using explicit / alternate credentials (e.g. right-click "run as a different user"). _Why:_ flags credential switching, a common lateral-movement / privilege pattern. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4672 (Security)** — logged whenever a login is granted administrative (special) privileges. _Why:_ a 4672 following a 4624 for an account flags that account as privileged/admin. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4776 (Security)** — an NTLM authentication event, typically on a domain controller where Kerberos would normally be used. _Why:_ NTLM in an AD environment can indicate pass-the-hash-style attacks. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Kerberos vs NTLM** — Kerberos is the protocol typically used for authentication within Active Directory; NTLM appearing (4776) is comparatively anomalous. _Why:_ protocol context for spotting suspicious auth. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4776 single-ID success/failure** — 4776 uses one Event ID for both success and failure, distinguished by how the log entry is recorded, unlike 4624/4625 which are separate IDs. _Why:_ don't assume separate success/failure IDs for every auth event. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4768 / 4769 / 4771 (Security)** — Kerberos-related authentication events to profile in an Active Directory environment. _Why:_ ticket-request/auth telemetry on domain controllers. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4720 / 4722 (Security)** — relate to new user accounts being created or enabled. _Why:_ account-creation persistence / backdoor account detection. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4698 (Security)** — if audited, records the creation of a scheduled task. _Why:_ scheduled-task persistence visible in Security (in addition to the separate Task Scheduler operational log). _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4798 (Security)** — relates to a user's group membership enumeration. _Why:_ reconnaissance / enumeration indicator. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4799 (Security)** — group-membership related event associated with network-accessed resources. _Why:_ complements 4798 for group/network activity. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **5140 (Security)** — a network share object was accessed. _Why:_ SMB share access tracking within Security. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **5145 (Security)** — detailed network share access (checks whether access to a shared object was granted). _Why:_ finer-grained SMB access telemetry than 5140. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **SMB definition** — SMB (Server Message Block) is the protocol used for Windows file sharing. _Why:_ context for 5140/5145 and share-access analysis. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **SMB-specific logs exist** — beyond 5140/5145 in Security, dedicated SMB channels track additional SMB-related data. _Why:_ deeper share/lateral-movement evidence when Security is thin. _[IWE ch02 · Event Logs / In-depth Analysis]_

### 4624 logon type codes

- **Logon type 2 — Console** — a hands-on-keyboard interactive logon (user physically at the machine). _Why:_ distinguishes local physical presence. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 3 — Network** — a network logon such as an SMB connection to a file server / shared resource. _Why:_ remote resource access without interactive session. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 4 — Batch** — used for scheduled tasks. _Why:_ ties a logon to scheduled-task execution. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 5 — Service** — a Windows service authenticating under its service account (rather than a human). _Why:_ a 4624 type 5 = service start, not user activity. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Service accounts** — services have associated accounts granting the permissions the service needs; when a service logs on it produces a type-5 logon. _Why:_ explains service-account logon semantics. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 7 — Unlock** — a workstation screen unlock. _Why:_ tracks return-to-session events; also appears in RDP reconnect flows. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 8 — NetworkCleartext** — a network logon where credentials are passed in the clear. _Why:_ security-relevant; cleartext credential transmission is a red flag. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 9 — NewCredentials** — run-as with alternate credentials specified (correlates with 4648). _Why:_ credential-switching detection. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 10 — RemoteInteractive** — a remote desktop (RDP) logon. _Why:_ primary Security-log indicator of RDP access. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 11 — CachedInteractive** — logon using cached domain credentials (e.g. a domain laptop off-network logging in via cached creds). _Why:_ explains off-domain interactive logons. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Cached credentials mechanism** — a domain-joined machine can authenticate a domain user while disconnected from the corporate network because credentials are cached locally. _Why:_ underpins type-11 semantics. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 12 — CachedRemoteInteractive** — a cached RDP-type logon, analogous to type 10 but using cached credentials. _Why:_ distinguishes cached RDP reconnections. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Logon type 13 — CachedUnlock** — a cached unlock, analogous to type 7. _Why:_ cached-credential unlock variant. _[IWE ch02 · Event Logs / In-depth Analysis]_

### System log

- **7045 (System)** — a new service was installed on the system. _Why:_ service-install persistence / lateral-movement indicator. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Service definition** — a service is a background program in Windows, usually launched at system startup. _Why:_ context for why service events matter. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **7045 fields** — records service name, service file name (full path to the binary), service type (e.g. user-mode service), start type (e.g. auto-start = starts with the system), and the service account (e.g. LocalSystem). _Why:_ full profile of an installed service. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Impacket installs services** — several Impacket utilities install services on the remote/target system as part of execution; these surface as 7045s to profile. _Why:_ ties a common attacker toolkit to a concrete artifact. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **7034 (System)** — a service terminated/quit unexpectedly, and the event also logs how many times it has done so. _Why:_ crashing services can betray a threat actor's failed service-instantiation / lateral-movement attempts. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **7009 (System)** — a service timeout event. _Why:_ like 7034, useful to spot outlier/odd-named services during a suspect timeframe. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Outlier-service analysis** — correlate 7034/7009 for oddly named services against the threat actor's active timeframe and the machines they touched. _Why:_ turns benign-looking crash events into scoping evidence. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **104 (System)** — an event log was cleared; the event names the responsible user, task category, timestamp, and computer. _Why:_ anti-forensic indicator in System. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **104 cross-log clearing** — 104 in the System log records the clearing of OTHER logs too (e.g. clearing the Application log writes a 104 into System), not just clearing of System itself. _Why:_ the Application log does NOT self-log its own clearing; look in System for it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **104 vs 1102 distinction** — most logs' clearing is recorded via 104 in System, whereas Security uniquely records its own clearing via 1102. _Why:_ know which log to check for a given cleared channel. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Application log

- **1000 (Application)** — an application error. _Why:_ malware execution often triggers app errors within the attacker's active window. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1002 (Application)** — an application hang. _Why:_ same rationale as 1000; correlate with the incident timeframe. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Application log third-party writers** — third-party software (e.g. antivirus) can write into the Application log, not just Windows components. _Why:_ non-Windows sources may hold key evidence there. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **216 (Application / ESENT)** — an ESE database location change was detected; on a DC it references `ntds.dit` and its path. _Why:_ core indicator for AD database staging/theft. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **216 benign case** — a normal 216 shows `ntds.dit` being snapshotted into a Volume Shadow Copy path (organic system behavior). _Why:_ baseline to distinguish from malicious staging. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **216 malicious case** — a 216 showing `ntds.dit` created/placed outside its normal path (e.g. `C:\Users\Public`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\Temp`, PerfLogs) can indicate staging for exfiltration. _Why:_ location anomaly is the tell for AD database theft. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **325 / 326 / 327 (Application / ESENT)** — creation of a new database, attachment of a database, and detachment of a database, respectively. _Why:_ combinations of 216 + 325/326/327 fingerprint `ntdsutil` dumping. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ntdsutil** — a built-in Windows utility (found on domain controllers) that threat actors abuse to snapshot/copy `ntds.dit`. _Why:_ living-off-the-land AD-dump technique. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ntdsutil output structure** — an `ntdsutil` IFM-style dump creates, under the specified path, an "Active Directory" directory (containing the `.dit`) and a "registry" directory (containing the SYSTEM and SECURITY hives). _Why:_ telltale on-disk structure to confirm the technique. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **ntdsutil exports SECURITY too** — technically only the SYSTEM hive is needed to decrypt the hashes, but `ntdsutil` also exports the SECURITY hive. _Why:_ presence of both hives alongside a `.dit` supports the ntdsutil attribution. _[IWE ch02 · Event Logs / In-depth Analysis]_

### ntds.dit / hash cracking

- **ntds.dit meaning** — "NT Directory Services . Directory Information Tree"; the primary Active Directory database. _Why:_ correct expansion and role. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Full domain compromise pairing** — stealing `ntds.dit` together with the SYSTEM registry hive can compromise the entire domain. _Why:_ explains why both are collected together. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **SYSTEM hive holds the decryption key** — the SYSTEM registry hive contains (in reassemblable form) the key used to decrypt the encrypted hashes stored in `ntds.dit`. _Why:_ the `.dit` alone is not immediately useful without it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **AD hash format** — after decryption the NT hashes are unsalted MD4 over UTF-16 little-endian Unicode of the password. _Why:_ unsalted MD4 is comparatively feasible to attack (dictionary/precomputed). _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Hashcat cracking workflow** — compute hashes of candidate passwords (e.g. from breach corpora) and compare against the decrypted `ntds.dit` hashes; a match reveals the plaintext password. _Why:_ describes the offline credential-recovery threat. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Hash one-wayness** — a hash is a one-way cryptographic representation; you cannot reverse it, only test candidate inputs for a matching hash. _Why:_ correct mental model for "cracking." _[IWE ch02 · Event Logs / In-depth Analysis]_

### PowerShell logs

- **Two PowerShell logs** — Windows PowerShell has more than one log: the "Windows PowerShell" (classic) log and the "Microsoft-Windows-PowerShell/Operational" log. _Why:_ different Event IDs live in each. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **400 / 600 (Windows PowerShell)** — indicate the PowerShell engine starting up. _Why:_ profiling engine starts can reveal abnormal PowerShell usage. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4104 (PowerShell/Operational)** — Script Block Logging, capturing the text of executed PowerShell script blocks. _Why:_ often the richest record of malicious PowerShell. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4104 auto-logging (PS v5+)** — from PowerShell v5 onward, script blocks the system deems potentially malicious are logged via 4104 (as a Warning) even without explicit Script Block Logging configuration. _Why:_ you may get PowerShell evidence for free on unconfigured hosts. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Script block definition** — a block of text constituting a PowerShell script that the system may evaluate as potentially malicious. _Why:_ context for 4104. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Malicious PowerShell examples** — downloading and executing a threat-actor-controlled binary, exfiltrating data, or invoking Mimikatz (a credential-theft tool). _Why:_ the behavior classes 4104 tends to catch. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Task Scheduler / Operational

- **Scheduled tasks as persistence** — threat actors create/modify scheduled tasks for persistence (e.g. periodic beaconing to attacker infrastructure) to retain environment access. _Why:_ scheduled tasks should be profiled in nearly every incident. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **106 (Task Scheduler/Operational)** — registration/creation of a new scheduled task; the key Event ID in this log. _Why:_ primary scheduled-task persistence indicator. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **100 (Task Scheduler/Operational)** — a task started. _Why:_ execution timing of a task. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **102 (Task Scheduler/Operational)** — a task completed successfully. _Why:_ confirms task execution finished. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **141 (Task Scheduler/Operational)** — deletion of a task. _Why:_ anti-forensic / cleanup indicator for scheduled-task persistence. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Two places for scheduled tasks** — scheduled-task activity appears both in Security (4698) and in the separate ancillary Task Scheduler operational log. _Why:_ cross-check both; the operational log persists longer than Security. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **`Get-WinEvent -ListProvider` for available IDs** — `(Get-WinEvent -ListProvider "Microsoft-Windows-TaskScheduler").Events | Format-Table Id, Description` enumerates every Event ID a provider can emit. _Why:_ discover the full ID set for any log without a cheat sheet. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Windows Defender / Operational

- **Defender is built in & always-on-capable** — Windows Defender ships free with modern Windows and may keep running/logging in the background even when a third-party AV is installed. _Why:_ Defender logs may exist even where another AV is primary. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1116 (Defender/Operational)** — Defender detected malware/potentially unwanted item ("found something bad"). _Why:_ detection evidence and timeline anchor. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1117 (Defender/Operational)** — Defender took action on a detection (quarantine, delete, etc.). _Why:_ shows the response/remediation the AV performed. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Opening saved logs & on-disk log files

- **Log file location** — the .evtx files live at `C:\Windows\System32\winevt\logs`. _Why:_ path to acquire/parse raw logs offline. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Core channel = file mapping** — the five Windows Logs channels map to physical files (`Application.evtx`, `Security.evtx`, etc.). _Why:_ channel names correspond to filenames on disk. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Open Saved Log** — Event Viewer's "Open Saved Log" action loads any .evtx (including the many ancillary logs not shown in the default tree) under a "Saved Logs" node. _Why:_ how to view/parse arbitrary channels in the GUI. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **`%4` in log filenames** — in .evtx filenames, `%4` is URL-style encoding for a forward slash (`/`), used because `/` is illegal in a filename (e.g. `...LocalSessionManager%4Operational.evtx`). _Why:_ lets you map an on-disk filename back to its channel path. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Terminal Services / RDP logs

- **Ancillary logs roll slower** — non-core logs (Terminal Services, etc.) generally roll far more slowly than Security/System, giving a much larger event horizon. _Why:_ RDP evidence may survive in these logs long after Security has rolled. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **LocalSessionManager/Operational IDs are on the target** — Event IDs 21–25 in the Terminal Services LocalSessionManager operational log describe RDP session activity on the system that was connected TO. _Why:_ these are target-side RDP artifacts. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **21 (LocalSessionManager/Operational)** — a successful RDP session logon; records user, session ID, and the source network address of the connecting host. _Why:_ primary target-side proof an RDP logon succeeded, with attacker IP. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **21↔22 pairing** — where a 21 exists a 22 typically accompanies it, so profiling 21 alone usually suffices. _Why:_ efficient triage; 22 is the shell-start companion to 21. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **23 (LocalSessionManager/Operational)** — an RDP session logoff (the user actually signed out / properly terminated the session). _Why:_ true session end, distinct from a mere disconnect. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **24 (LocalSessionManager/Operational)** — an RDP session was disconnected (e.g. closing the RDP window while leaving the session running). _Why:_ disconnect ≠ logoff; the session persists. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **25 (LocalSessionManager/Operational)** — an RDP session reconnection succeeded (reattaching to a previously disconnected session); the opposite of 24. _Why:_ tracks return to an existing session. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Disconnect vs logoff distinction** — closing the RDP window disconnects (session stays up, still consuming an RDP license) whereas Start → Sign out logs off; they generate different events. _Why:_ interpret session lifecycle correctly. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Local logons in LSM log** — sometimes purely local (non-RDP) console logons are still recorded by the Terminal Services LocalSessionManager as if RDP events (a 21 for a local login); the exact triggering circumstances were not fully characterised in the lesson. _Why:_ a 21 does not by itself prove a remote connection; corroborate with source address / Security type 10. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1149 (RemoteConnectionManager/Operational)** — labelled "User authentication succeeded," but it actually reflects the network connection reaching the RDP service, occurring BEFORE actual user authentication. _Why:_ misleading name; a 1149 does NOT prove the user authenticated. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1149 needs 21/22 corroboration** — to prove a successful RDP logon you need a 21/22, not merely an 1149. _Why:_ prevents overstating RDP success from 1149 alone. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1149 records fields** — captures the user, domain, and source network address of the connection attempt. _Why:_ still useful for connection-attempt pivoting despite the misleading label. _[IWE ch02 · Event Logs / In-depth Analysis]_

### RDP client (source-side) — 1029

- **RDPClient/Operational is source-side** — the Terminal Services RDPClient operational log records RDP activity on the system connected FROM (the initiating host). _Why:_ complements target-side 21–25 for outbound RDP attribution. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1029 (RDPClient/Operational)** — logs a Base64 encoding of the SHA-256 hash of the username used for an outbound RDP connection. _Why:_ proves an outbound RDP connection originated from this box and, once decoded, which account initiated it. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **1029 is case-sensitive** — the username hash differs for different letter casing (e.g. `Administrator` vs `administrator` produce different hashes). _Why:_ you must test exact casing when matching a candidate username. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Matching 1029 to a username** — you cannot reverse the hash; instead hash candidate usernames (Base64(SHA-256(username))) and compare, e.g. via a CyberChef recipe from 13cubed's "RDP hashes" research (based on a nullsec.us article). _Why:_ practical method to attribute the 1029 hash to a known account. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Cross-correlation of RDP sides** — a source-side 1029 can be married with the target-side 21/22 to reconstruct both ends of an RDP session. _Why:_ full connection attribution when both hosts' logs are available. _[IWE ch02 · Event Logs / In-depth Analysis]_

### RDP flowchart correlations (cross-channel)

- **Successful RDP logon flow** — 1149 (RemoteConnectionManager), then 4624 type 10 (Security), then 21/22 (LocalSessionManager). _Why:_ multi-log signature confirming a real RDP logon. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Unsuccessful RDP logon flow** — 1149 still appears (still says "authentication succeeded"), followed by 4625 (Security) "account failed to log on" with logon type 10 (or 7 for a reconnect attempt). _Why:_ 4625 is the discriminator that authentication actually failed despite 1149. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **RDP reconnect flow** — 1149, then 4624 type 7 (reconnect, not type 10), then 25 (session reconnection) plus a 40, and a 4778 (Security). _Why:_ reconnects use type 7 and add 25/40/4778, distinct from a fresh logon. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4778 (Security)** — associated with RDP session reconnection. _Why:_ Security-side reconnect indicator complementing LSM 25. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4779 (Security)** — an obscure RDP-related event surfaced in the RDP flowchart (session disconnect side), not on the main cheat sheet. _Why:_ additional disconnect correlation for deep RDP profiling. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Event ID 40 (RDP)** — appears in reconnect/disconnect flows and also correlates to reconnections (flagged with an asterisk). _Why:_ supplemental RDP session-state event. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **RDP logoff flow** — 23 (LocalSessionManager), plus 4634 (type 10 or 7) and 4647 in Security, with 4647 being the user-initiated logoff; a further obscure System-log event may also be written. _Why:_ two Security logoff IDs plus the LSM 23 all mark a proper RDP sign-out. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Disconnect granularity** — closing the RDP window versus choosing Start → Disconnect produce different event flows. _Why:_ event set can even distinguish the manner of disconnection. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **RDP flowchart provenance** — the RDP event correlations are based on Jonathan Poling's "Ponder the Bits" writeup combined with the instructor's own testing. _Why:_ primary-source lead for independent verification of RDP event semantics. _[IWE ch02 · Event Logs / In-depth Analysis]_

### PowerShell cmdlets & tooling for event logs

- **Get-WinEvent** — a PowerShell cmdlet to query Windows event logs (e.g. `Get-WinEvent -LogName Security`), analogous to the Event Viewer GUI but scriptable/exportable. _Why:_ built-in programmatic access with filtering and export. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Security log needs admin** — reading the Security log (e.g. via Get-WinEvent) requires administrative context; without it the call fails with "attempted to perform an unauthorized operation." _Why:_ elevation prerequisite for Security-log access. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Get-EventLog is deprecated** — `Get-EventLog` still works (as of recording) but is the older, largely superseded cmdlet replaced by `Get-WinEvent`. _Why:_ prefer Get-WinEvent; recognise Get-EventLog as legacy. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **EvtxECmd (Eric Zimmerman)** — the recommended tool to parse all event logs and export to CSV for far more flexible slicing/filtering than Event Viewer. _Why:_ analytical workhorse for bulk event-log analysis. _[IWE ch02 · Event Logs / In-depth Analysis]_

### Priorities & ideal auditing

- **Security is the go-to starting log** — the Security event log is generally the first place to start an investigation. _Why:_ concentrates logon, privilege, and audit-clearing evidence. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **4688 is critical but conditional** — 4688 with full command line is extremely valuable, but only if process auditing is enabled, command-line auditing is enabled, and the short-lived Security log's data survived (ideally via central collection). _Why:_ the "stack of ifs" that determines whether this goldmine exists. _[IWE ch02 · Event Logs / In-depth Analysis]_
- **Ideal auditing baseline** — the module's final part covers baseline auditing: what forensic investigators would hope a well-configured environment has enabled. _Why:_ pointer that recommended audit configuration is treated separately. _[IWE ch02 · Event Logs / In-depth Analysis]_

## Chapter 02 · Tools and Best Practices

### EVTX file location & live-system handling

- **Live EVTX path** — On a running Windows system the event log files live at `C:\Windows\System32\winevt\Logs`. _Why:_ Canonical collection target for both live triage and mounted-image parsing. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Locked-file gotcha** — Parsing EVTX directly from the live `winevt\Logs` path fails because the files are in use and locked by the running OS; the parser will report the logs as in-use/locked. _Why:_ You cannot point a parser at the live path; you must work from a copy or a mounted image. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Workaround for demo/live collection** — Copy the EVTX files out to a separate working folder (e.g. a `logs` folder) and parse that copy instead of the locked live directory. _Why:_ Avoids the in-use lock and lets the tool read the files. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Real-world image workflow** — In casework you typically mount a forensic image with Arsenal Image Mounter, note the assigned mount drive letter (e.g. `F:`), then point the parser at `F:\Windows\System32\winevt\Logs` (the same relative path, under the mount point). _Why:_ Standard image-based collection path; everything else in the workflow is identical to live minus the mounting step. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Running the tools — privileges

- **Run as administrator** — It is generally preferred to run the forensic tools from an elevated (administrator) terminal because some of them require administrative privileges to run. _Why:_ Avoids privilege-related failures when a tool needs elevation. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Elevation indicator** — An elevated Windows Terminal / Command Prompt is identifiable by the UAC shield icon and the word "Administrator" in the prompt title. _Why:_ Quick visual confirmation the session is elevated. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Eric Zimmerman tools — acquisition & layout

- **Get-ZimmermanTools.ps1** — Eric Zimmerman's tools are installed/updated via the PowerShell script `Get-ZimmermanTools` (a `.ps1`). _Why:_ Standard, repeatable way to fetch/update the EZ toolset. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`net6` output directory** — `Get-ZimmermanTools` pulls the tools into a `net6` subdirectory (the .NET 6 build). _Why:_ Tells you where the downloaded binaries land after running the installer script. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Directory layout** — Within the `net6` folder some tools sit in the root and others (e.g. Registry Explorer, EvtxECmd) have their own dedicated subdirectory. _Why:_ You must `cd` into a tool's subdirectory to find its executable and support files. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### EvtxECmd — Maps feature

- **Maps subdirectory** — EvtxECmd's own folder contains a `Maps` subdirectory holding map definition files. _Why:_ Maps are the data files that drive EvtxECmd's normalized descriptions. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **What Maps do** — A Map takes one or a series of Windows events and provides a normalized, standard, human-readable description of what the event is. _Why:_ Converts cryptic event IDs into plain-English meaning during parsing. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Community-authored maps** — Maps are not limited to those shipped with the tool; users and community members can author their own and contribute them to the tool's GitHub repository. _Why:_ Coverage grows over time and you can extend it for custom event sources. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Maps beyond native Windows events** — Maps exist for many non-Windows-event-log sources too, including Carbon Black Defense, Sophos, and Cisco AnyConnect, plus extensive coverage of Terminal Services logs. _Why:_ EvtxECmd/Maps can normalize third-party product logs, not just built-in channels. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Map file structure (example: Event ID 1029)

- **1029 context** — Terminal Services Event ID 1029 is recorded on the source system (the machine from which the RDP connection originated) and stores the username as a hash. _Why:_ Explains why a map + hash-computation step is needed to identify the user of an outgoing RDP connection. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Map metadata block** — A map file opens with metadata: author, a description (for 1029: "RDP (outgoing connection)"), and the target Event ID. _Why:_ Identifies what the map produces and who authored it. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Channel field** — The map specifies the `Channel`, which is the event log file itself the event comes from. _Why:_ Ties the mapped description to the specific EVTX channel. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Provider field** — The map specifies the `Provider` within that channel; for 1029 the provider is `ClientActiveXCore`. _Why:_ Provider + channel + event ID uniquely scope which events the map matches. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Property/value extraction logic** — The map defines property, property-value, and value entries containing the logic to pull the relevant data fields out of the event. _Why:_ This is the mechanism that extracts structured fields from the raw event payload. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Embedded documentation** — Map files can include documentation: reference links (e.g. the nullsec article the technique is based on) and example event data. _Why:_ Lets an analyst verify what payload the map expects and cross-reference the source research. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Embedded CyberChef recipe** — The 1029 map file contains a CyberChef recipe that computes the username hash so it can be compared against a candidate plaintext username. _Why:_ Provides the reproducible decode step for resolving the hashed username in outgoing-RDP events. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Example event data in maps** — Map files typically include example event data showing what the actual event payload looks like. _Why:_ Lets you preview exactly what fields the map will parse before running it. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### EvtxECmd — key flags

- **`--sync`** — `EvtxECmd --sync` downloads/updates the latest maps from the GitHub repository to the local system; if none are newer it reports that no new maps are available. _Why:_ Maps are constantly added and tweaked; sync keeps normalization coverage current. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`-f` (file)** — `-f` specifies a single event log (EVTX) file to process. _Why:_ One of the two primary input modes; `-f` or `-d` is required. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`-d` (directory)** — `-d` specifies an entire directory of files to process (parses every EVTX in the folder). _Why:_ Bulk-parse a whole `winevt\Logs` collection in one run; the required alternative to `-f`. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`-f`/`-d` are required** — Exactly one of `-f` or `-d` must be supplied; they are the most important parameters. _Why:_ The tool needs an input source; nothing runs without one. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`--csv`** — `--csv` specifies the directory into which the CSV output should be written. _Why:_ Selects the output-format (CSV) and its destination folder. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`--csvf`** — `--csvf` is optional and sets the explicit CSV output file name. _Why:_ Lets you name the timeline file; without it a name is generated. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Default CSV filename** — If `--csvf` is omitted, EvtxECmd generates a default output filename based on a timestamp. _Why:_ Output is still produced (and uniquely named) even without specifying a name. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **JSON output** — EvtxECmd supports JSON output options in addition to CSV. _Why:_ Alternative structured format for ingestion into other tools/pipelines. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **XML output** — EvtxECmd supports XML output options. _Why:_ Another structured export format available. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Custom date/time format** — EvtxECmd allows specifying a custom date-time format for output. _Why:_ Normalizes timestamp rendering to the analyst's/consumer's preference. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Include-event-ID list** — EvtxECmd can be given an explicit allow-list of event IDs (e.g. 4624, 4625, 4688) so it includes only those and ignores everything else. _Why:_ Focuses output on events of interest and shrinks the resulting timeline. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Exclude-event-ID list** — Conversely, EvtxECmd can be given a deny-list of event IDs to skip while grabbing everything else. _Why:_ Removes noisy event IDs while keeping the rest. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Start/end date bounding** — EvtxECmd accepts a start date and an end date to restrict parsing to events within a time range. _Why:_ Time-bounds the timeline to the incident window, reducing volume. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`--vss`** — `--vss` tells EvtxECmd to crawl any available Volume Shadow Copies, pull out the event logs present in them, deduplicate them, and add them into the resulting event-log timeline. _Why:_ Can recover event logs a threat actor cleared/deleted from the live volume if older shadows still hold them. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **`--vss` is common across EZ tools** — The `--vss` option (crawl shadows → extract → deduplicate → merge into results) is available on numerous other Eric Zimmerman tools, not only EvtxECmd. _Why:_ The same shadow-recovery technique generalizes across the EZ toolset. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Volume Shadow Copies — forensic significance

- **Definition** — A Volume Shadow Copy is a point-in-time snapshot taken by the Windows OS; by default the OS periodically creates them automatically, and they can also be created manually. _Why:_ Provides a "time machine" view of the system's earlier state. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **List shadows** — `vssadmin list shadows` enumerates the Volume Shadow Copies present, including each shadow's creation timestamp. _Why:_ Lets you confirm shadows exist and check whether any predate anti-forensic activity. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Anti-forensics recovery principle** — Deleting or even securely deleting data on the live volume does not alter what a previously-taken Volume Shadow Copy already captured; as long as a shadow predating the deletion is still on disk, the earlier data can be recovered from it. _Why:_ Cleared event logs may survive in older shadows — a key recovery avenue after log tampering. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Shadow deletion caveat** — A threat actor can delete the Volume Shadow Copies themselves, which is a common anti-forensics technique; if they do, the shadow-based recovery avenue is gone. _Why:_ Shadow recovery is opportunistic — check whether shadows survived, don't assume they did. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### EvtxECmd — run behaviour & dirty files

- **Progress reporting** — During a run EvtxECmd prints statistical/progress information at the top, including percent complete. _Why:_ Lets you gauge remaining time on large collections. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Ordered crawl + map enrichment** — EvtxECmd crawls every event log in order, parses each, and applies the maps to pull out additional/normalized information as it goes. _Why:_ Explains what produces the enriched columns (e.g. Map Description) in the output. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Completion summary** — On finishing, EvtxECmd reports the number of files processed and the elapsed seconds, and notes any files that had errors. _Why:_ Baseline QA metrics for a parsing run. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **"Is dirty" on live-collected logs** — EVTX files copied from a live/running system are commonly flagged "is dirty" and produce parsing errors, because they were open/in-use when copied. _Why:_ Distinguishes collection-method artifacts from genuine corruption; expected when grabbing logs live. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Clean-image expectation** — Parsing EVTX from a full disk image of a properly powered-off system that was correctly imaged yields far fewer errors/dirty-file warnings than parsing files pulled off a live system. _Why:_ Sets expectations: many errors on live-copied logs are normal; a clean image should be tidy. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Errors are not uncommon** — Some files reporting errors during a run is not unusual and does not necessarily mean the output is unusable. _Why:_ Don't treat every error line as a failed collection. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Opening the results — Timeline Explorer

- **Do not open the CSV in Excel** — Do not open the resulting event-log CSV in Microsoft Excel. _Why:_ Excel can alter/mangle the data and is unsuitable for large forensic CSVs. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Use Timeline Explorer** — Eric Zimmerman's Timeline Explorer is the recommended viewer for the CSV output. _Why:_ Purpose-built for large forensic timelines and preserves data integrity. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Read-only by design** — Timeline Explorer is purpose-built as a read-only viewer; you cannot change/edit the underlying data with it. _Why:_ Protects evidence integrity — no accidental modification of the timeline. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Opens CSV and Excel files** — Timeline Explorer can open CSV files and also Excel (`.xls/.xlsx`) files. _Why:_ Single viewer for multiple tabular evidence formats. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Works with any CSV** — Timeline Explorer works with any CSV, not only output from Eric Zimmerman tools. _Why:_ General-purpose timeline/triage viewer across data sources. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Timeline Explorer — line counts & filtering

- **Total vs Visible lines** — The bottom-right shows "total lines" and "visible lines"; when they match exactly, zero rows are filtered and you are seeing all data. _Why:_ Quick integrity check that no hidden filter is suppressing evidence. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Mismatch = active filter** — If total lines and visible lines differ, a filter is applied and you are not viewing the full dataset. _Why:_ Prevents drawing conclusions from an unknowingly filtered view. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Column-header filter panel (bottom-left)** — An applied column filter (e.g. `Event ID = 1029`) is shown in the bottom-left; you can toggle it via its checkbox (temporarily on/off) or press the `X` to remove it entirely. _Why:_ Lets you see, disable, or clear filters that are hiding rows. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Timeline Explorer — columns

- **Column set** — Timeline Explorer surfaces columns including: line number; a check/tag column; record number / event record ID; timestamp (Time Created); Event ID; logging Level; Provider; Channel; Process ID; Computer; User ID; Map Description; Username; Remote Host; Payload Data 1–6; Executable Info; Source File; and the full Payload. _Why:_ Reference for where each field lives when triaging. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Event Record ID** — The record number / event record ID column reflects the record ID stored inside the event log. _Why:_ Ties each row to its native EVTX record identifier. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **User ID is a SID** — The "User ID" column holds the numeric SID (Security Identifier) representation of the account. _Why:_ You must translate SIDs to names; well-known SIDs (e.g. the SYSTEM account) map to known principals. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Map Description column** — The Map Description column is populated from the map files and gives the plain-English description of the event. _Why:_ Turns raw event IDs into readable meaning directly in the grid (e.g. 1029 → "RDP (outgoing connection)"). _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Payload Data 1** — "Payload Data 1" typically holds most of the substantive event-log data. _Why:_ First place to look for the meaningful extracted fields. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Source File column** — The Source File column shows the specific EVTX file each row was obtained from. _Why:_ Provenance — traces every entry back to its origin channel/file. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Full Payload + Format** — The full raw event payload sits at the end column; double-clicking shows it as a jumbled string, and clicking the "Format" button renders it into a readable structured layout. _Why:_ Lets you inspect the complete underlying event XML/payload cleanly. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Resizable columns** — Any column in Timeline Explorer can be resized. _Why:_ UI ergonomics for wide payload fields. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Timeline Explorer — filtering, searching, grouping

- **Per-column filter by typing** — Typing a value into a column's filter (e.g. `1029` in Event ID) restricts the grid to matching rows and registers as an active filter. _Why:_ Fast way to isolate a specific event ID. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Top-right search box** — The top-right search block filters/searches results across the data; enter a term (e.g. a username) and click Find to pull rows containing it. _Why:_ Free-text search across all event lines, complementary to column filters. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Search history dropdown** — The search box dropdown keeps a history of prior search terms/finds. _Why:_ Re-run earlier queries quickly. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Quick Help for search options** — Timeline Explorer's Help → Quick Help documents the additional search syntax/options available. _Why:_ Where to learn advanced search operators. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Group by drag-to-header** — Dragging a column header (e.g. Map Description) into the grouping area groups all rows by that column's value. _Why:_ Collapses the timeline into readable categories of what happened. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Hierarchical multi-column grouping** — You can drag a second (and further) column into the grouping area to create nested/hierarchical grouping (e.g. Map Description → Username, or Username → Event ID). _Why:_ Answers questions like "what did this user do on this box" by drilling from category to sub-category. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Grouping + search combine** — An active grouping and a search term can be applied together, so results are grouped and the matching term is highlighted within the groups. _Why:_ Combines slicing (grouping) and finding (search) in one view. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Ungroup by dragging out** — Dragging a grouped column back out of the grouping area removes that grouping level (and can return the grid to its default ungrouped state). _Why:_ Restores the flat view or steps back through grouping levels. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Timeline Explorer — keyboard shortcuts & sorting

- **Ctrl+R resets columns** — `Control + R` resets the columns to their default state (undoing resizing/rearranging). _Why:_ Recover a sane layout after fiddling with columns. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Ctrl+Home** — `Control + Home` jumps back to the top (line 1) of the grid. _Why:_ Fast navigation to the start of the timeline. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sort by Time Created → event horizon** — Sorting by the Time Created column reveals the full time span ("event horizon") covered by the parsed logs, from earliest to latest event. _Why:_ Establishes the temporal coverage of your evidence set at a glance. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Event IDs referenced

- **4648** — Event ID 4648 = "a logon was attempted using explicit credentials" (e.g. RunAs, where one account supplies a different set of credentials to execute something). _Why:_ Indicates credential-specified execution / lateral-movement-adjacent behaviour. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **1029 (recap)** — Event ID 1029 maps to "RDP (outgoing connection)" and, in the grouped/enriched view, exposes the associated hashes where available. _Why:_ Ties the earlier map/hash discussion to what you actually see in Timeline Explorer. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **21** — Event ID 21 = Terminal Services successful (RDP) connection. _Why:_ Confirms a successful interactive/remote session — core RDP session evidence. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Cheat sheet reliance** — The class provides an event-log cheat sheet of event IDs; the guidance is to keep it at hand and reference it rather than memorize the IDs. _Why:_ Practical workflow — event IDs recur across later modules. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Baseline logging & Sysmon

- **nullsec baseline-logging repo** — nullsec.us publishes a GitHub repository (a work-in-progress) that automates a Windows baseline-logging configuration, applying the recommended settings described in the associated article. _Why:_ A ready-made way to bring a host to a forensically ideal logging posture. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Baseline repo pulls Sysmon** — The baseline-logging automation, when run, also pulls down and configures Sysmon as part of the ideal logging setup. _Why:_ Sysmon is part of the recommended baseline, not an optional afterthought. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon = Sysinternals** — Sysmon (System Monitor) is part of the Microsoft Sysinternals Suite; searching "Sysmon" surfaces the Sysinternals page as the top result. _Why:_ Authoritative source/download for Sysmon. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon definition** — Sysmon is a Windows service and device driver that, once installed, remains resident across system reboots and monitors/logs system activity to the Windows event log. _Why:_ Persistent, kernel-assisted telemetry source that survives restarts. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon = greatly amplified logging** — Sysmon generates a large amount of additional detail that augments the existing native Windows event logs. _Why:_ Fills visibility gaps the default logging leaves. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon → SIEM/WEF** — Sysmon output can be fed into a centralized Windows Event Collection (WEF) setup or into a SIEM for aggregation. _Why:_ Integrates host telemetry into central detection/investigation. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon Event ID 1 = Process Creation** — Sysmon Event ID 1 is a process-creation event — Sysmon's richer counterpart to native Event ID 4688. _Why:_ Provides more detail on process creation than the built-in 4688. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon overlap vs unique events** — Some Sysmon events overlap with existing native Windows events (but add more data), while others log activity not captured by default at all. _Why:_ Sysmon both enriches and extends native coverage. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon can log DNS queries** — Sysmon can log DNS queries among many other event types. _Why:_ Network/name-resolution telemetry not present in default logging. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon event catalog** — Sysmon event types include: process creation (ID 1); process changed a file creation time; network connection; Sysmon service state changed; process terminated; driver loaded; image loaded; CreateRemoteThread; file creation; registry events; FileCreateStreamHash; and PipeEvent. _Why:_ Reference for the breadth of Sysmon telemetry available to an investigation. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon built into Windows (early 2026)** — As of early 2026 Microsoft began shipping Sysmon as a built-in feature of Windows 11 and Windows Server 2025; it is disabled by default, but instead of downloading/installing it separately you can enable the feature and configure a ruleset. _Why:_ Lowers the barrier to having Sysmon telemetry available on modern endpoints. _[IWE ch02 · Event Logs / Tools & Best Practices]_

### Investigative best-practice takeaways

- **Sysmon availability is the exception, not the rule** — In real casework only a small percentage of engagements have full Sysmon/rich logging available; you generally cannot count on it. _Why:_ Sets realistic expectations — treat Sysmon data as a bonus, not a given. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Event logs can close a case alone** — With the right event logs covering the threat-actor activity window, a case can sometimes be solved on event logs alone, without needing other artifacts. _Why:_ Emphasizes the primacy of event-log analysis when coverage is good. _[IWE ch02 · Event Logs / Tools & Best Practices]_
- **Sysmon extends event logs** — Sysmon is an extension of Windows event logging (its data lands in the Windows event log), so the same analysis workflow applies. _Why:_ You analyze Sysmon data with the same tools/approach as native EVTX. _[IWE ch02 · Event Logs / Tools & Best Practices]_

## Chapter 03 · Fundamentals

### What the Registry Is

- **Registry (definition)** — The Windows Registry is a configuration database maintained by the operating system that stores hardware and software configuration settings. _Why:_ Establishes the Registry as the central OS-managed configuration store, the root of a large family of forensic artifacts. _[IWE ch03 · Registry / Fundamentals]_
- **Registry scope** — It holds configuration for the OS itself and for applications that opt to use it. _Why:_ Defines the two broad categories of data an investigator can expect to find. _[IWE ch03 · Registry / Fundamentals]_
- **Application opt-in** — Not every program running on Windows uses the Registry; whether to do so is a developer choice. _Why:_ Absence of an app's keys does not prove the app never ran; some apps store config elsewhere. _[IWE ch03 · Registry / Fundamentals]_
- **Practical dependence** — Most mainstream applications (e.g. Microsoft Word, Adobe Photoshop) depend heavily on the Registry to function because much of their configuration lives there. _Why:_ Common apps leave rich configuration evidence in the Registry. _[IWE ch03 · Registry / Fundamentals]_
- **Design rationale** — The Registry was introduced to replace scattered `.ini` and other configuration files spread across the file system with a single centralized store. _Why:_ Explains why config that predates the Registry may still appear in loose `.ini` files. _[IWE ch03 · Registry / Fundamentals]_
- **Structure** — The Registry is a centralized, hierarchical database allowing structured storage and retrieval of configuration data. _Why:_ The hierarchical key/subkey model underlies all Registry navigation and tooling. _[IWE ch03 · Registry / Fundamentals]_
- **Historical origin** — Registry functionality dates back to Windows 3.1, though the modern Registry as recognized today effectively took shape in Windows 95. _Why:_ Corrects the common misconception that the Registry began with Windows 95. _[IWE ch03 · Registry / Fundamentals]_
- **Etymology of "hive"** — The term "hive" reportedly originated as an inside joke by an early Windows NT developer whose colleague feared bees, naming the backing files "registry hives." _Why:_ Trivia only; explains terminology, no forensic weight. _[IWE ch03 · Registry / Fundamentals]_

### Registry Is Not a Single File

- **No monolithic file** — There is no single file that constitutes "the Registry"; there is no `C:\the Registry`. _Why:_ Investigators must collect multiple hive files, not one object. _[IWE ch03 · Registry / Fundamentals]_
- **Composite of components** — The Registry is assembled from multiple components: some memory-resident only, others backed by files on disk. _Why:_ A disk-only acquisition misses volatile portions that exist only in RAM. _[IWE ch03 · Registry / Fundamentals]_
- **In-memory-only portions** — Some Registry components have no file on disk; they are created and maintained purely in memory by the OS kernel while the system runs. _Why:_ Certain keys can only be recovered from a live system or memory image. _[IWE ch03 · Registry / Fundamentals]_
- **Disk-backed portions** — Other Registry components are backed by on-disk files called registry hives. _Why:_ These hive files are the primary dead-box acquisition targets. _[IWE ch03 · Registry / Fundamentals]_
- **Composite whole** — The on-disk hive files together with the kernel-managed in-memory components form what is collectively called the Windows Registry. _Why:_ Frames the complete evidence set an examiner should account for. _[IWE ch03 · Registry / Fundamentals]_

### Primary Hive Location (System32\config)

- **Main hive path** — Most of the core registry hives reside under `%SystemRoot%\System32\config`, typically resolving to `C:\Windows\System32\config`. _Why:_ First place to collect machine-level hives during acquisition. _[IWE ch03 · Registry / Fundamentals]_
- **`%SystemRoot%` variable** — `%SystemRoot%` is used instead of a hardcoded `C:\Windows` because Windows need not be installed to `C:\Windows`. _Why:_ Prevents wrong-path assumptions on non-default installs; parse the variable's real value per system. _[IWE ch03 · Registry / Fundamentals]_
- **Config hive set** — The hive files found in `System32\config` include DEFAULT, SAM, SECURITY, SOFTWARE, and SYSTEM. _Why:_ Names the machine-scope hive files to acquire. _[IWE ch03 · Registry / Fundamentals]_
- **Not all hives here** — `System32\config` holds a large chunk of the hives but not all of them (user hives and Amcache live elsewhere). _Why:_ Acquisition must also cover per-user and appcompat locations. _[IWE ch03 · Registry / Fundamentals]_

### Per-User Hives

- **Two user hives each** — Every user account has two user-specific registry hives: `NTUSER.DAT` and `UsrClass.dat`. _Why:_ Per-user analysis requires both files, once per profile. _[IWE ch03 · Registry / Fundamentals]_
- **NTUSER.DAT location** — `NTUSER.DAT` sits in the root of each user's profile directory (e.g. `C:\Users\<user>\`). _Why:_ Locates the primary per-user hive for collection. _[IWE ch03 · Registry / Fundamentals]_
- **NTUSER.DAT hidden** — `NTUSER.DAT` is a hidden file, not shown by a plain `dir`; it appears with `dir /a`. _Why:_ Default directory listings hide it; collectors must include hidden files. _[IWE ch03 · Registry / Fundamentals]_
- **UsrClass.dat location** — `UsrClass.dat` is located under `AppData\Local\Microsoft\Windows` within each user's profile. _Why:_ The second per-user hive lives in a separate, deeper path than NTUSER.DAT. _[IWE ch03 · Registry / Fundamentals]_
- **Per-user, per-profile** — Because these hives are per user, a multi-user system has one NTUSER.DAT and one UsrClass.dat per profile. _Why:_ Scope collection to every relevant user account. _[IWE ch03 · Registry / Fundamentals]_
- **Pronunciation note** — "user class" is used interchangeably with `UsrClass`. _Why:_ Terminology clarity when reading documentation or narration. _[IWE ch03 · Registry / Fundamentals]_

### Amcache Hive

- **Amcache as a hive** — Amcache is stored as a registry hive in a `.hve` file named `Amcache.hve`. _Why:_ Amcache is parsed with Registry tooling despite being an execution artifact. _[IWE ch03 · Registry / Fundamentals]_
- **Amcache location** — `Amcache.hve` is located at `%SystemRoot%\appcompat\Programs` (typically `C:\Windows\appcompat\Programs`). _Why:_ Distinct path from the config and per-user hives; must be collected separately. _[IWE ch03 · Registry / Fundamentals]_
- **Amcache purpose** — Amcache is a backwards-compatibility (application compatibility) mechanism built into Windows that forensic analysts repurpose as evidence. _Why:_ Explains why it exists and why it records program metadata. _[IWE ch03 · Registry / Fundamentals]_
- **Amcache as execution evidence** — Amcache is one of the main evidence-of-execution artifacts, covered in depth in the evidence-of-execution material. _Why:_ Flags Amcache's forensic value for proving program execution. _[IWE ch03 · Registry / Fundamentals]_

### Registry Editor (Regedit) and Root Keys

- **Regedit tool** — Registry Editor (Regedit) is the built-in Windows GUI for viewing/editing the Registry. _Why:_ Baseline native tool; contrasted later with forensic tooling. _[IWE ch03 · Registry / Fundamentals]_
- **Root keys are top-level** — The top-level folder-like items shown in Regedit are the root registry keys; everything beneath a root key is, by definition, a subkey. _Why:_ Defines the key/subkey hierarchy for path notation. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_CLASSES_ROOT** — HKEY_CLASSES_ROOT primarily holds file-extension association information — which program opens a given extension (e.g. `.txt`, `.jpg`, `.png`, `.pdf`). _Why:_ Reveals configured default-application associations. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_CURRENT_USER** — HKEY_CURRENT_USER (HKCU) is the Registry view for the currently logged-in user. _Why:_ Scopes user-specific analysis to the active account. _[IWE ch03 · Registry / Fundamentals]_
- **HKCU composition** — HKCU is a virtual representation populated from the logged-in user's on-disk `NTUSER.DAT` and part of `UsrClass.dat`. _Why:_ Mapping HKCU back to the source hive files lets you analyze the same data offline. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_LOCAL_MACHINE** — HKEY_LOCAL_MACHINE (HKLM) contains the machine-level hives collected from `Windows\System32\config`. _Why:_ Links the HKLM tree directly to the DEFAULT/SAM/SECURITY/SOFTWARE/SYSTEM files on disk. _[IWE ch03 · Registry / Fundamentals]_
- **HKLM subkey mapping** — Under HKLM you find SAM, SECURITY, SOFTWARE, and SYSTEM, corresponding to four of the `System32\config` hive files. _Why:_ Direct file-to-key correspondence for offline analysis. _[IWE ch03 · Registry / Fundamentals]_
- **HKLM\HARDWARE is volatile** — HKLM contains a HARDWARE subkey that has no hive file; it is generated at boot, stored in memory, and managed by the Windows kernel. _Why:_ HARDWARE data is recoverable only from a live/memory image, never from disk hives. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_USERS** — HKEY_USERS holds configuration for all active users on the system, not just the current one. _Why:_ Multi-user analysis without switching accounts. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_USERS\.DEFAULT mapping** — Under HKEY_USERS, the `default` entry maps to (is populated from) the DEFAULT hive file in `Windows\System32\config`. _Why:_ Ties the DEFAULT hive to its live-Registry representation. _[IWE ch03 · Registry / Fundamentals]_
- **HKEY_CURRENT_CONFIG** — HKEY_CURRENT_CONFIG holds the current hardware profile of the computer and local system; it is stored in memory and rendered at boot. _Why:_ Another volatile, boot-generated tree with no persistent hive file. _[IWE ch03 · Registry / Fundamentals]_
- **Five root keys** — The five root registry keys are HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, and HKEY_CURRENT_CONFIG. _Why:_ Complete enumeration of top-level entry points. _[IWE ch03 · Registry / Fundamentals]_
- **Investigative focus** — HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE are the two root keys of greatest forensic focus. _Why:_ Prioritizes where the highest-value user and machine artifacts live. _[IWE ch03 · Registry / Fundamentals]_
- **Standard shorthand** — HKEY_CURRENT_USER abbreviates to HKCU and HKEY_LOCAL_MACHINE to HKLM. _Why:_ These abbreviations appear throughout tooling, cheat sheets, and documentation. _[IWE ch03 · Registry / Fundamentals]_

### Live vs. Disk Mapping

- **Live view is populated from hives** — What Regedit displays is populated at runtime from the on-disk hive files (plus in-memory components). _Why:_ Explains why offline hive parsing reproduces the same data an examiner sees live. _[IWE ch03 · Registry / Fundamentals]_

### Transaction Logs & Dirty Hives

- **RegBack directory** — `System32\config` contains a `RegBack` subdirectory intended as a backup of the main registry hives. _Why:_ Historically an alternate source for clean hive copies. _[IWE ch03 · Registry / Fundamentals]_
- **RegIdleBackup task** — Registry backups to `RegBack` were produced by a scheduled task named `RegIdleBackup`. _Why:_ Identifies the mechanism that once populated RegBack. _[IWE ch03 · Registry / Fundamentals]_
- **RegBack disabled** — As of a certain Windows 10 build, `RegIdleBackup` was disabled, so `RegBack` is typically empty on modern systems (a `dir RegBack` shows nothing). _Why:_ Do not rely on RegBack as a backup source on current Windows 10+ systems. _[IWE ch03 · Registry / Fundamentals]_
- **`.LOG1` / `.LOG2` files** — Each hive has associated `.LOG1` and `.LOG2` transaction-log-journal files (e.g. `SAM.LOG1`, `SAM.LOG2`, and likewise for SECURITY, SOFTWARE, SYSTEM, DEFAULT, NTUSER.DAT, UsrClass.dat, Amcache.hve). _Why:_ These logs must be collected alongside each hive to reconstruct complete state. _[IWE ch03 · Registry / Fundamentals]_
- **Log files are hidden** — The `.LOG1`/`.LOG2` and related files are hidden; a plain `dir` does not show them, but `dir /a` does. _Why:_ Collectors must enumerate hidden files or they will silently miss the logs. _[IWE ch03 · Registry / Fundamentals]_
- **`.regtrans-ms` files** — Additional transaction files named `*.regtrans-ms` (with long hex-style names) accompany the hives and carry transactional information. _Why:_ Part of the in-flight-transaction data set that completes a hive. _[IWE ch03 · Registry / Fundamentals]_
- **Logs = transaction journals** — The `.LOG1`, `.LOG2`, and `.regtrans-ms` files are transaction log journals for the registry hives. _Why:_ Frames the Registry as a transactional database whose recent writes may live only in the logs. _[IWE ch03 · Registry / Fundamentals]_
- **In-flight writes** — At any moment, Registry keys and values may be in flight — not yet committed to the hive file itself. _Why:_ The hive on disk can lag behind actual live state. _[IWE ch03 · Registry / Fundamentals]_
- **Dirty hive risk** — A hive collected alone (without its logs) is likely in a "dirty," incomplete state, missing uncommitted changes. _Why:_ Grabbing only the hive can yield stale or partial data — a real acquisition pitfall. _[IWE ch03 · Registry / Fundamentals]_
- **Database analogy** — Like any live database, some Registry operations are uncommitted at collection time; the log journals hold that pending data. _Why:_ Reinforces why logs are mandatory for a faithful reconstruction. _[IWE ch03 · Registry / Fundamentals]_
- **Log replay to clean a hive** — An Eric Zimmerman tool can replay the transaction-log data into a dirty hive to bring it fully up to date. _Why:_ The remediation for dirty hives — replay logs before analysis for accuracy. _[IWE ch03 · Registry / Fundamentals]_
- **Amcache log presence** — `Amcache.hve` has `.LOG1` and `.LOG2` files but does not show the `.regtrans-ms` files seen with other hives. _Why:_ Log-file footprint varies by hive; still collect the LOG files for Amcache. _[IWE ch03 · Registry / Fundamentals]_

### Forensic Tooling & Access

- **Admin rights required** — Traversing to the hive locations (e.g. via an elevated terminal) requires running as administrator; the elevation shield in Windows Terminal indicates admin context. _Why:_ Live collection of protected hive paths needs elevation. _[IWE ch03 · Registry / Fundamentals]_
- **`dir /a` for hidden files** — Use `dir /a` at the command prompt to reveal the hidden hive, log, and transaction files that a normal `dir` omits. _Why:_ Practical command to enumerate the full hive file set during live collection. _[IWE ch03 · Registry / Fundamentals]_
- **Registry Explorer** — Eric Zimmerman's Registry Explorer is a forensic-purpose alternative to Regedit — similar interface but more capable, designed for forensic analysis. _Why:_ Preferred tool for offline hive analysis over the native editor. _[IWE ch03 · Registry / Fundamentals]_

## Chapter 03 · NTUSERDAT

### Tooling and general method

- **Registry Explorer (Eric Zimmerman)** — the tool used to browse most of these registry destinations; it has a plugin system that automatically decodes/translates encoded or binary values into human-readable form. _Why:_ Turns raw binary/encoded registry data into interpretable forensic evidence without manual decoding. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Regedit (Registry Editor, built-in Windows)** — still worth using alongside Registry Explorer because it shows the data in its original, pre-decoded (binary/encoded) state, whereas Registry Explorer's plugins have already transformed it. _Why:_ Seeing the raw original state builds understanding of what the tool transformed and lets an examiner validate the decode. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — live registry access requires admin** — launched without administrator context, the File menu's "Live System" option is greyed out and unselectable because the process lacks permission to interrogate the live registry. _Why:_ Reading live hives needs elevation; an examiner who forgets to elevate will wrongly think the feature is missing. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — offline hive loading needs no admin** — File → Load Hive can open offline hives extracted from a full disk image, a KAPE acquisition, or another triage tool without elevated privileges. _Why:_ Standard dead-box workflow: examiners work on extracted hive copies, not the live system. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — Live System lists Amcache, SAM, SECURITY, SOFTWARE, SYSTEM** — when elevated, the Live System menu exposes Amcache plus the four core hives. _Why:_ Confirms which system hives are directly reachable live. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — Live System lists NTUSER.DAT and UsrClass.dat per user** — under Users it shows both user hives for every profile, including Default and Public (present on any system) plus explicitly created accounts. _Why:_ Distinguishes real user accounts from built-in profiles when scoping per-user artifacts. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — "Collapse all hives" button** (bottom-right) resets an expanded tree back to the default closed state. _Why:_ Navigation convenience; not evidentiary. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — Alt+Down expands a key** in the tree, unlike Regedit where the right arrow expands. _Why:_ Tool-specific navigation. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — F5 opens a Technical Details pane, it does NOT refresh** — pressing F5 shows advanced metadata (relative offset, absolute offset, flags, etc.), whereas F5 in Regedit refreshes the live view. _Why:_ An examiner expecting a refresh will misread the tool; the offsets/flags are advanced-forensics detail beyond intermediate scope. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer — no live-registry refresh** — once it reads the live registry it holds a snapshot in time from the moment of open; there is no way to re-read live changes (unlike Regedit's F5), so recent live edits made after opening will be absent. _Why:_ Explains why a value entered after Registry Explorer opened does not appear — it is a stale snapshot, not missing evidence. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Regedit F5 refreshes the live registry** and updates values in real time as the system changes. _Why:_ Lets an examiner watch keys mutate live for validation/testing. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Regedit navigation shortcut** — typing the first letters of a subkey name jumps to it; arrow keys expand. _Why:_ Navigation convenience. _[IWE ch03 · Registry / NTUSER.DAT]_
- **13cubed Windows Registry cheat sheet** exists (downloads section of the source site) laying out forensically significant registry paths across four pages. _Why:_ Context only; the cheat-sheet paths are the artifacts enumerated in this chapter. _[IWE ch03 · Registry / NTUSER.DAT]_

### HKCU composition and hive mapping

- **HKCU = HKEY_CURRENT_USER** and represents the currently logged-on user. _Why:_ Foundational to reading any per-user artifact path. _[IWE ch03 · Registry / NTUSER.DAT]_
- **HKCU is composed of two user hives** — the logged-on user's NTUSER.DAT plus their UsrClass.dat; together these two user-specific hives form HKEY_CURRENT_USER for that user. _Why:_ Tells the examiner which on-disk hive file backs any given HKCU subtree. _[IWE ch03 · Registry / NTUSER.DAT]_
- **NTUSER.DAT and UsrClass.dat are the two user-specific registry hives.** _Why:_ Defines the per-user evidence sources distinct from the machine hives. _[IWE ch03 · Registry / NTUSER.DAT]_
- **The Explorer per-user artifacts in this chapter live in NTUSER.DAT** (HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer subtree), not UsrClass.dat. _Why:_ Directs the examiner to the correct hive file for these keys. _[IWE ch03 · Registry / NTUSER.DAT]_
- **UsrClass.dat plugs into HKCU under Software\Classes** — the mechanism by which the second user hive attaches to the HKCU tree is via the Classes subtree (covered when reaching software classes). _Why:_ Explains where UsrClass.dat-backed data (e.g. shellbags) surfaces within HKCU. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Core machine hives location** — SAM, SECURITY, SOFTWARE, SYSTEM live in `%SystemRoot%\System32\config` (typically `C:\Windows\System32\config`). _Why:_ Where to pull machine hives from an image. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Base Explorer path** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer` is the parent key holding most of the forensically valuable per-user Explorer subkeys; it contains many more subkeys than the cheat sheet lists, but the cheat-sheet ones are the most forensically impactful. _Why:_ One path to memorize that anchors RunMRU, TypedPaths, RecentDocs, ComDlg32, MountPoints2, UserAssist, WordWheelQuery. _[IWE ch03 · Registry / NTUSER.DAT]_

### Registry timestamp semantics

- **Only keys and subkeys carry LastWrite timestamps; values do NOT.** _Why:_ The single most important registry-forensics rule for dating activity — you can only date the containing key, never an individual value directly. _[IWE ch03 · Registry / NTUSER.DAT]_
- **A subkey's LastWrite time means "some value in this subkey was last updated at this time"** — it does not tell you which value changed. _Why:_ Bounds what you can honestly claim: the container changed, not necessarily a specific value. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Deriving a value's time via an MRU list** — when a subkey has an MRU ordering, the item at MRU position 0 (most recent) can be inferred to have been written in conjunction with the subkey's LastWrite timestamp. _Why:_ Legitimate inference chain to date the single most-recent action; anything older than position 0 cannot be dated. _[IWE ch03 · Registry / NTUSER.DAT]_
- **LastWrite captures only the most recent write, not a full history** — you get the last write time, not every write time, so older entries' individual times are unrecoverable. _Why:_ Sets the epistemic ceiling: for non-position-0 MRU items you can only say "sometime before" the LastWrite. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer's per-value LastWrite times are DERIVED, not native** — when it shows a timestamp next to a value (e.g. in WordWheelQuery) it is intelligently inferring it from the MRU list + the subkey LastWrite, because values have no real timestamp. _Why:_ Examiner must know these are inferred so as not to overstate them as recorded facts. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer displays the selected value's hive and LastWrite time in the bottom-left status area**, matching the column value; double-clicking that field copies "last write time to clipboard" for reports. _Why:_ Reporting convenience and cross-check. _[IWE ch03 · Registry / NTUSER.DAT]_

### MRU (most recently used) concept

- **MRU = Most Recently Used** whenever seen in a registry context. _Why:_ Decodes the ubiquitous naming convention. _[IWE ch03 · Registry / NTUSER.DAT]_
- **MRUListEx / MRU list encodes ordering** — a value (often named "MRUListEx" or "MRUList") holds a sequence referencing other value names, giving the order from most-recently-used down to least-recently-used. _Why:_ The ordering, not the timestamps, is how you reconstruct sequence for most MRU artifacts. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Some artifacts have no MRU list and no order-revealing numbering** — in that case the population order of the values cannot be determined. _Why:_ Cautions against assuming sequence where none is recorded. _[IWE ch03 · Registry / NTUSER.DAT]_

### ComDlg32 — Common Dialog MRUs

- **ComDlg32 = the Windows common dialog** (the shared File → Open and File → Save As window used across Windows applications). _Why:_ Explains why unrelated apps all write here and why it is a rich source of file-interaction evidence. _[IWE ch03 · Registry / NTUSER.DAT]_
- **The common dialog remembers the last-used save/open location** and stores those settings in the registry, which is why apps reopen at your previous path. _Why:_ Root cause of the artifact — user file navigation is persisted. _[IWE ch03 · Registry / NTUSER.DAT]_
- **ComDlg32 subkeys of interest: LastVisitedPidlMRU and OpenSavePidlMRU** (PIDL, spoken "piddle"). _Why:_ The two subkeys carrying the evidentiary content. _[IWE ch03 · Registry / NTUSER.DAT]_
- **LastVisitedPidlMRU tracks the applications/programs** used to open and save files (e.g. Notepad.exe, Chrome.exe). _Why:_ Reveals which executable performed the file interaction. _[IWE ch03 · Registry / NTUSER.DAT]_
- **OpenSavePidlMRU tracks the actual files** opened or saved by those applications. _Why:_ Reveals which specific documents/files a user touched via the dialog. _[IWE ch03 · Registry / NTUSER.DAT]_
- **LastVisited + OpenSave pair up** — LastVisited = the app, OpenSave = the file that app used. _Why:_ Correlating the two links a program to the documents it handled. _[IWE ch03 · Registry / NTUSER.DAT]_
- **ComDlg32 data is stored as binary (hex) blobs** in value data; Regedit shows the raw binary and its partial ASCII rendering. _Why:_ Requires decoding; explains the "gibberish" appearance in Regedit. _[IWE ch03 · Registry / NTUSER.DAT]_
- **App/file strings are UTF-16 (double-wide), so every other byte is null** — in Regedit's ASCII pane you see "C·H·R·..." (C null, H null) for "Chrome". _Why:_ Explains the spaced-out characters and confirms the encoding when manually reading raw bytes. _[IWE ch03 · Registry / NTUSER.DAT]_
- **OpenSavePidlMRU is organized by file extension subkeys** (e.g. `mp4`, `docx`, `ai`) plus a wildcard `*` subkey for most-recently-used files of any extension. _Why:_ Lets an examiner target a specific file type or the global recent list. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer decodes ComDlg32 into MRU position + readable app/file names**, sortable by MRU position from most- to least-recently-used. _Why:_ Turns binary PIDLs into a usable timeline of program/file activity. _[IWE ch03 · Registry / NTUSER.DAT]_
- **ComDlg32 records full paths including drive letters and UNC** — example showed Adobe Premiere Pro opening a path on `D:`. _Why:_ Path detail can place a file on removable/networked storage. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Forensic value of ComDlg32** — can reveal software a threat actor used and which documents/files that software interacted with. _Why:_ Ties a tool to the data it touched during an intrusion. _[IWE ch03 · Registry / NTUSER.DAT]_

### MountPoints2

- **MountPoints2** (same Explorer subtree) tracks removable drives a user mounted — USB flash drives, USB external hard drives, and also mapped/UNC network paths. _Why:_ Ties external and network storage to a specific user profile. _[IWE ch03 · Registry / NTUSER.DAT]_
- **MountPoints2 stores UNC paths** — example showed `\\x-.13cubed.home\13cubed` style NAS paths (with `#` separators in the stored subkey names) that the Davis RG user had mounted/traversed. _Why:_ Reveals network shares the user accessed. _[IWE ch03 · Registry / NTUSER.DAT]_
- **MountPoints2 is per-user** (in NTUSER.DAT), so entries reflect drives/paths that particular user interacted with. _Why:_ Attributes device/share usage to a named account. _[IWE ch03 · Registry / NTUSER.DAT]_
- **MountPoints2 subkey LastWrite dates the mount** — example LastWrite `2022-10-07 16:56:02 UTC` for a path. _Why:_ Provides a timestamp for when that mount/path was last written. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Some MountPoints2 info is readable directly in Regedit** (subkey names contain the path/share text) before any tool decoding. _Why:_ Fast triage without a decoder. _[IWE ch03 · Registry / NTUSER.DAT]_

### RecentDocs

- **RecentDocs** (Explorer subtree) records the recent documents a user has interacted with. _Why:_ High-value, frequently used in investigations to show file access. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RecentDocs root holds a mixed list plus per-extension subkeys** — extension subkeys like `.csv`, `.ai`, `.docx` group entries by file type. _Why:_ Lets an examiner filter recent files by type. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RecentDocs value data is binary in Regedit** requiring double-click/decoding to read the filename (e.g. `MFT_before.csv`). _Why:_ Explains the need for Registry Explorer's decode. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer renders RecentDocs target names in a readable list** at the root, with each extension subkey showing its filenames. _Why:_ Produces a clean list of accessed documents. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Each RecentDocs extension subkey carries its own LastWrite timestamp** (e.g. the `.docx` subkey), but the individual filename values within do not. _Why:_ You can date the last activity for a file type, not each specific file. _[IWE ch03 · Registry / NTUSER.DAT]_

### RunMRU

- **RunMRU** tracks entries typed into the Run dialog (Win+R). _Why:_ Shows commands/programs a user explicitly launched via Run. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RunMRU is human-readable in Regedit without decoding** — value data is plain text (e.g. `regedit\1`). _Why:_ Fast to triage directly. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RunMRU uses single-letter value names (a, b, c, …) plus an MRUList value** — the MRUList string (e.g. "gutsbafrdnq…") lists those letters in order, first character = most recently used. _Why:_ The MRUList ordering reconstructs the exact sequence of Run entries. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RunMRU entries have a trailing `\1`** appended by storage convention — it is an artifact of how the data is stored, NOT part of what the user typed. _Why:_ Prevents mis-reporting the literal command string. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RunMRU updates live in real time** — running a new Run command (e.g. `calc`) reorders the MRUList (new letter jumps to front) on F5 refresh in Regedit. _Why:_ Demonstrates ordering behavior and live-registry mutability. _[IWE ch03 · Registry / NTUSER.DAT]_
- **RunMRU only records SUCCESSFULLY executed commands** — typing a non-existent command (e.g. `Richard`) that returns "Windows cannot find…" does NOT populate the key. _Why:_ Critical, rarely-mentioned gotcha: absence from RunMRU means the command failed/never ran, and every RunMRU entry is a confirmed successful launch. _[IWE ch03 · Registry / NTUSER.DAT]_

### TypedPaths

- **TypedPaths** records paths a user typed directly into the Windows Explorer address bar (file-navigation address bar, e.g. `C:\Windows\System32\winevt\Logs`). _Why:_ Shows deliberate navigation to specific locations by that user. _[IWE ch03 · Registry / NTUSER.DAT]_
- **TypedPaths is distinct from the Run dialog** — it is Explorer's address bar, not Win+R; note you can also type `cmd` into the Explorer address bar to launch a command prompt at the current location. _Why:_ Avoids conflating two different launch surfaces; `cmd`-in-address-bar is a real technique. _[IWE ch03 · Registry / NTUSER.DAT]_
- **TypedPaths has no explicit MRU list, but the value names encode order** — values are named `url1`, `url2`, `url3`, … where `url1` is the most recent; on a new entry everything shifts down one (old url1 → url2). _Why:_ Ordering is recoverable from the numbering despite no MRUList value. _[IWE ch03 · Registry / NTUSER.DAT]_
- **TypedPaths is readable in Regedit without decoding** (plain-text path values). _Why:_ Fast triage. _[IWE ch03 · Registry / NTUSER.DAT]_

### UserAssist

- **UserAssist** is a per-user evidence-of-execution artifact (lives in each user's NTUSER.DAT). _Why:_ Attributes program execution to a specific account. _[IWE ch03 · Registry / NTUSER.DAT]_
- **UserAssist records GUI-launched programs only** — programs started from the GUI (e.g. Calculator, Notepad), NOT programs launched from the command line/command prompt; GUI launch is the prerequisite. _Why:_ Bounds coverage — absence does not prove non-execution if the program ran from CLI. _[IWE ch03 · Registry / NTUSER.DAT]_
- **UserAssist has GUID subkeys, each containing a `Count` subkey** that holds the tracked entries. _Why:_ Structure to navigate; different GUIDs categorize entry types (detailed in the evidence-of-execution module). _[IWE ch03 · Registry / NTUSER.DAT]_
- **UserAssist value names are ROT13-encoded** — a simple substitution cipher rotating the alphabet 13 places; raw names look like "NOTRABQ.RKR…" gibberish in Regedit. _Why:_ Must ROT13-decode to read program names; explains the alien-looking value names. _[IWE ch03 · Registry / NTUSER.DAT]_
- **ROT13 is not a security mechanism** — trivially reversible (CyberChef, or any "rot13 decode" utility); double-ROT13 = ROT26 = the original plaintext (the classic joke). _Why:_ Frames the encoding as obfuscation only; no cryptographic meaning. _[IWE ch03 · Registry / NTUSER.DAT]_
- **Registry Explorer auto-ROT13-decodes UserAssist** at the root key, showing readable program names (e.g. Microsoft Edge, File Explorer, Visual Studio Code) with a run count. _Why:_ Removes the manual decode step and surfaces execution counts. _[IWE ch03 · Registry / NTUSER.DAT]_
- **UserAssist tracks a run count per program.** _Why:_ Indicates how many times a program was executed by that user (fuller detail in the evidence-of-execution module). _[IWE ch03 · Registry / NTUSER.DAT]_

### WordWheelQuery

- **WordWheelQuery** records searches typed into Windows Explorer's built-in search box (top-right of an Explorer window). _Why:_ Reveals what a user searched their file system for. _[IWE ch03 · Registry / NTUSER.DAT]_
- **WordWheelQuery is NOT the Start-menu / taskbar "Type here to search"** — that Start-menu search is a separate Windows Search database stored in a JET Blue / ESE (Extensible Storage Engine) database, a different artifact entirely. _Why:_ Common beginner confusion; the two searches produce different artifacts and sources. _[IWE ch03 · Registry / NTUSER.DAT]_
- **WordWheelQuery has an MRU list plus numbered values (0, 1, …)** — MRU position 0 is the most recent search term (e.g. "testing 123"), position 1 the next (e.g. "secret chicken recipe"). _Why:_ Reconstructs search sequence. _[IWE ch03 · Registry / NTUSER.DAT]_
- **WordWheelQuery value data is binary in Regedit but still partly readable**; Registry Explorer decodes it to MRU position + search string. _Why:_ Explains raw vs decoded presentation. _[IWE ch03 · Registry / NTUSER.DAT]_
- **WordWheelQuery LastWrite dates only the MRU-position-0 search** — example LastWrite `2023-01-29 05:12:55 UTC`; because the position-0 term ("testing 123") was written with that LastWrite, you can state with confidence it was searched at that time, while the position-1 term ("secret chicken recipe") can only be dated "sometime before" it. _Why:_ Canonical worked example of the derive-from-MRU inference and its limit. _[IWE ch03 · Registry / NTUSER.DAT]_

## Chapter 03 · Scalable Analysis

### RECmd — identity and location

- **RECmd** — RECmd is the command-line counterpart of the GUI tool Registry Explorer, part of Eric Zimmerman's tool suite. _Why:_ enables scriptable, non-interactive registry parsing for scalable/enterprise work. _[IWE ch03 · Registry / Scalable Analysis]_
- **RECmd folder** — Within the root of the net6 folder where the Zimmerman tools reside, RECmd sits in its own `RECmd` subfolder. _Why:_ locating the executable and its supporting files. _[IWE ch03 · Registry / Scalable Analysis]_
- **RECmd contents** — The RECmd folder holds the `RECmd.exe` executable plus a `BatchExamples` subfolder containing sample batch files. _Why:_ the batch examples are the key to scalable parsing. _[IWE ch03 · Registry / Scalable Analysis]_
- **Zimmerman-tool syntax consistency** — RECmd's option syntax follows the same conventions as other Eric Zimmerman tools, so prior familiarity with any one tool transfers. _Why:_ reduces learning curve across the suite. _[IWE ch03 · Registry / Scalable Analysis]_
- **Running with no options** — Invoking `RECmd.exe` with no arguments prints the full list of available options/help. _Why:_ standard discovery of flags. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd — input selection flags

- **`-f` flag** — `-f` specifies a single registry hive file to process. _Why:_ targeted single-hive parsing. _[IWE ch03 · Registry / Scalable Analysis]_
- **`-d` flag** — `-d` specifies an entire directory containing multiple hives to process in one run. _Why:_ this is the scalable path — point it at a folder of collected hives and parse all at once. _[IWE ch03 · Registry / Scalable Analysis]_
- **Recommended scalable workflow** — The ideal enterprise/scale approach is to create a directory, dump all collected hives into it, and run RECmd with `-d` against the whole directory rather than feeding one hive at a time. _Why:_ single command parses everything, then analyst searches the combined output. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd — search and display capabilities

- **Key/value display** — RECmd can display details for a specified key name or a specified value. _Why:_ pinpoint lookup of known artifacts. _[IWE ch03 · Registry / Scalable Analysis]_
- **String search across components** — RECmd can search for a specific string across keys, values, data, and slack. _Why:_ broad hunting when you don't know the exact key path. _[IWE ch03 · Registry / Scalable Analysis]_
- **Searchable components** — RECmd's search can target values, records, key names, value names, value data, and value slack. _Why:_ granular control over what part of the hive is matched. _[IWE ch03 · Registry / Scalable Analysis]_
- **Regex support** — RECmd search supports regular expressions. _Why:_ pattern-based hunting (e.g., matching families of value names). _[IWE ch03 · Registry / Scalable Analysis]_
- **Slack** — RECmd exposes "slack" as a searchable region; slack refers to residual/leftover space associated with registry values (analogous to file slack), potentially holding recoverable remnants. _Why:_ residual data in slack can contain forensically relevant leftovers. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd — Volume Shadow Copy support

- **`--vss` option** — RECmd's VSS option makes it crawl all available Volume Shadow Copies present on the drive. _Why:_ pulls historical registry state, not just the live hive. _[IWE ch03 · Registry / Scalable Analysis]_
- **Historical snapshots via VSS** — Using the VSS option, RECmd grabs historical registry snapshots from each Volume Shadow Copy. _Why:_ VSS entries are point-in-time snapshots that can extend the visible timeline. _[IWE ch03 · Registry / Scalable Analysis]_
- **Extended event horizon** — Parsing registry data from Volume Shadow Copies can extend the investigative "event horizon," revealing state from earlier points in time than the current live hive shows. _Why:_ recovers evidence that has since changed or been removed on the live system. _[IWE ch03 · Registry / Scalable Analysis]_
- **Shared VSS switch across tools** — The same VSS switch concept was demonstrated on EvtxECmd; RECmd offers the equivalent capability to parse any of the volume shadows. _Why:_ consistent VSS handling across the Zimmerman suite. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd — output formats

- **Output formats** — RECmd can write results as CSV or JSON. _Why:_ downstream tooling / spreadsheet review flexibility. _[IWE ch03 · Registry / Scalable Analysis]_
- **`--csv` flag** — `--csv` specifies the directory/location where RECmd writes the CSV output. _Why:_ controls where results land. _[IWE ch03 · Registry / Scalable Analysis]_
- **`--csvf` (CSV filename)** — RECmd optionally lets you supply the CSV output filename (in the demo `recmd.csv`); if omitted a default name is used. _Why:_ naming control for the master CSV. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd batch files (.reb)

- **Batch processing concept** — RECmd supports a "batch processing file" that defines a large set of registry keys/values to enumerate in one run. _Why:_ turns registry parsing into a repeatable, comprehensive sweep. _[IWE ch03 · Registry / Scalable Analysis]_
- **`.reb` file extension** — RECmd batch files use the `.reb` extension; the `.reb` is the file actually consumed by RECmd. _Why:_ this is the machine-readable batch definition. _[IWE ch03 · Registry / Scalable Analysis]_
- **`.md` companion is documentation only** — Each batch example ships with a paired `.md` file that is purely a textual description of the batch's contents, NOT an input to RECmd. _Why:_ gotcha — do not point `--bn` at the `.md`; use the `.reb`. _[IWE ch03 · Registry / Scalable Analysis]_
- **Kroll_Batch.reb** — `Kroll_Batch.reb` is the flagship example batch file in the BatchExamples folder; it is large and enumerates a wide range of registry keys. _Why:_ ready-made comprehensive collection template. _[IWE ch03 · Registry / Scalable Analysis]_
- **Kroll_Batch coverage** — Kroll_Batch.reb pulls a wealth of information from many registry locations, starting with basic system information and continuing through a long list of artifacts. _Why:_ one batch file covers most of the registry cheat-sheet artifacts and more. _[IWE ch03 · Registry / Scalable Analysis]_
- **Batch supersets the cheat sheet** — Kroll_Batch.reb covers essentially everything on the Windows Registry cheat sheet plus additional artifacts beyond it. _Why:_ using the batch means you won't miss standard artifacts. _[IWE ch03 · Registry / Scalable Analysis]_
- **`--bn` flag** — `--bn` tells RECmd to use the settings from a supplied batch file to find keys and values (per its own help text pointing to the included sample). _Why:_ this is the flag that activates batch-mode parsing. _[IWE ch03 · Registry / Scalable Analysis]_
- **Key-path visibility in batch entries** — Entries in the batch file include the source key path from which each artifact is pulled. _Why:_ transparency/auditability of where each parsed value originates. _[IWE ch03 · Registry / Scalable Analysis]_

### Artifacts referenced as covered by the batch

- **OpenSavePidlMRU** — The batch file includes OpenSave PidlMRU (an MRU of open/save dialog activity). _Why:_ tracks files interacted with via common open/save dialogs. _[IWE ch03 · Registry / Scalable Analysis]_
- **LastVisitedPidlMRU** — The batch file includes LastVisited PidlMRU. _Why:_ tracks applications and last-visited paths from open/save dialogs. _[IWE ch03 · Registry / Scalable Analysis]_
- **RunMRU** — The batch includes RunMRU, which records entries typed into the Run box (Windows Key + R, the dialog in the bottom-left). _Why:_ shows commands the user manually launched via Run. _[IWE ch03 · Registry / Scalable Analysis]_
- **AppCompatCache** — The batch includes AppCompatCache (Shimcache). _Why:_ evidence-of-execution / presence artifact. _[IWE ch03 · Registry / Scalable Analysis]_
- **RecentDocs** — A per-artifact CSV for RecentDocs is produced. _Why:_ recently opened documents. _[IWE ch03 · Registry / Scalable Analysis]_
- **UserAssist** — A per-artifact CSV for UserAssist is produced; UserAssist is a per-user, GUI-based evidence-of-execution artifact. _Why:_ shows GUI program execution per user. _[IWE ch03 · Registry / Scalable Analysis]_
- **WordWheelQuery** — A per-artifact CSV for WordWheelQuery is produced; it holds terms typed into Windows Explorer search (demo values: "testing123", "secret chicken recipe"). _Why:_ reveals what a user searched for in Explorer. _[IWE ch03 · Registry / Scalable Analysis]_
- **TypedPaths** — TypedPaths captures explicit paths typed into the Windows Explorer address bar. _Why:_ shows navigation the user manually entered. _[IWE ch03 · Registry / Scalable Analysis]_
- **MountPoints2** — MountPoints2 records mounted volumes / network shares (demo showed a share path referencing 13Cubed and an `/archive` path). _Why:_ evidence of removable media and network share access per user. _[IWE ch03 · Registry / Scalable Analysis]_
- **RunMRU typed-command example** — In the demo RunMRU output the typed commands included `mstsc`, `regedit`, and `windows\system32\config`. _Why:_ concrete example of reconstructing user Run-box activity. _[IWE ch03 · Registry / Scalable Analysis]_

### RECmd — invocation example and output behavior

- **Full example command** — A working invocation combines `--bn BatchExamples\Kroll_Batch.reb`, `-f <NTUSER.DAT>`, `--csv <output dir>`, and a CSV filename such as `recmd.csv`. _Why:_ concrete syntax template. _[IWE ch03 · Registry / Scalable Analysis]_
- **Live-registry parsing** — RECmd can be pointed at the live registry of the running machine (e.g., the current user's NTUSER.DAT). _Why:_ live triage without prior extraction. _[IWE ch03 · Registry / Scalable Analysis]_
- **Single-hive limitation** — Feeding a batch file only one hive (e.g., NTUSER.DAT) yields only the subset of batch entries sourced from that hive; keys targeting SYSTEM, SOFTWARE, or other hives are simply not produced. _Why:_ gotcha — a single hive gives an incomplete picture of what the batch can do; supply all hives for full coverage. _[IWE ch03 · Registry / Scalable Analysis]_
- **Batch spans multiple hives** — Kroll_Batch.reb draws from SYSTEM, SOFTWARE, and other hives in addition to NTUSER.DAT. _Why:_ explains why a directory of all hives (`-d`) is preferred. _[IWE ch03 · Registry / Scalable Analysis]_
- **Speed** — In the demo RECmd parsed NTUSER.DAT via the batch file in just under two seconds. _Why:_ RECmd is extremely fast at parsing. _[IWE ch03 · Registry / Scalable Analysis]_
- **Master CSV output** — RECmd writes the named master CSV (e.g., recmd.csv) containing all parsed tidbits in one file. _Why:_ single consolidated result set. _[IWE ch03 · Registry / Scalable Analysis]_
- **Per-artifact CSV subfolder** — Alongside the master CSV, RECmd also creates a timestamp-named folder containing individual CSV files, one per extracted artifact (e.g., separate CSVs for RunMRU, RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, UserAssist, WordWheelQuery). _Why:_ lets analysts open just the artifact they care about. _[IWE ch03 · Registry / Scalable Analysis]_
- **Master CSV columns** — The master CSV columns include Path, Type, Description, Category, (key) Path, ValueName, ValueType, and ValueData. _Why:_ knowing the schema aids filtering/sorting. _[IWE ch03 · Registry / Scalable Analysis]_
- **Group-by-Description tip** — Moving/sorting the master CSV by the Description column groups all rows of the same artifact together for easier review. _Why:_ practical triage technique on the consolidated CSV. _[IWE ch03 · Registry / Scalable Analysis]_

### RLA — replaying transaction logs

- **rla.exe** — `rla.exe` (referred to as RLA; the transcript's on-screen "rlx" is the transaction-log replay utility) is an Eric Zimmerman tool located in the root of the net6 folder. _Why:_ needed to clean/complete dirty hives before analysis. _[IWE ch03 · Registry / Scalable Analysis]_
- **Purpose of RLA** — RLA replays registry transaction logs against a dirty hive, folding the in-flight changes recorded in the logs back into the hive and outputting a clean, updated hive. _Why:_ recovers the most recent registry changes not yet committed to the hive. _[IWE ch03 · Registry / Scalable Analysis]_
- **Dirty-hive concept** — A hive in a "dirty" state has pending changes still held in its transaction logs rather than merged into the hive itself. _Why:_ analyzing a dirty hive without replay misses recent data. _[IWE ch03 · Registry / Scalable Analysis]_
- **RLA output directory** — RLA lets you specify the directory to save the updated (replayed) hives to. _Why:_ preserves the original and writes a separate clean copy. _[IWE ch03 · Registry / Scalable Analysis]_
- **`.LOG1` / `.LOG2` files** — The transaction logs RLA replays are the `.LOG1` and `.LOG2` files that accompany each hive. _Why:_ these journals hold the in-flight changes to roll in. _[IWE ch03 · Registry / Scalable Analysis]_
- **TXR / CLFS logs (distinct type)** — A separate kind of registry transaction log exists: transactional registry logs (TXR files), stored in Common Log File System (CLFS) format, whose filenames end with `.regtrans-ms`. _Why:_ do not confuse these with the `.LOG1/.LOG2` journals — RLA's replay in this context targets the `.LOG1/.LOG2` files. _[IWE ch03 · Registry / Scalable Analysis]_

### RegRipper

- **RegRipper** — RegRipper is another registry-parsing tool (mentioned in the setup video as available but not the module's primary tool) that parses artifacts out of the various hives. _Why:_ alternative/second tool for the same job. _[IWE ch03 · Registry / Scalable Analysis]_
- **RegRipper plugins** — RegRipper uses a plugin architecture and knows how to read the different hive types. _Why:_ each plugin targets a specific artifact. _[IWE ch03 · Registry / Scalable Analysis]_
- **`rip` command** — RegRipper's command-line driver is `rip`. _Why:_ the executable to invoke for scripted runs. _[IWE ch03 · Registry / Scalable Analysis]_
- **`rip -r` flag** — `-r` specifies the registry hive file to parse (demo used NTUSER.DAT). _Why:_ input-hive selection. _[IWE ch03 · Registry / Scalable Analysis]_
- **`rip -p` flag** — `-p` specifies which plugin to run (demo used the `userassist` plugin). _Why:_ selects the artifact-specific parser. _[IWE ch03 · Registry / Scalable Analysis]_
- **Example RegRipper run** — `rip -r <NTUSER.DAT> -p userassist` extracts UserAssist evidence-of-execution data from NTUSER.DAT in a single command. _Why:_ concrete syntax; comparable functionality to RECmd. _[IWE ch03 · Registry / Scalable Analysis]_
- **Multiple tools are fine** — Having more than one registry tool (RECmd and RegRipper) is a legitimate choice; they provide overlapping functionality. _Why:_ tool redundancy/cross-validation. _[IWE ch03 · Registry / Scalable Analysis]_

### Registry Explorer bookmarks (GUI, referenced)

- **Bookmarks** — Registry Explorer (GUI) ships with predetermined bookmarks pointing to specific forensic artifacts (e.g., ComDlg32, MountPoints2, RunMRU). _Why:_ one-click navigation to known-relevant keys/subkeys/values. _[IWE ch03 · Registry / Scalable Analysis]_
- **101 bookmarks with three hives** — With NTUSER.DAT, SOFTWARE, and SYSTEM loaded, 101 bookmarks were available. _Why:_ concrete count of built-in coverage. _[IWE ch03 · Registry / Scalable Analysis]_
- **Cheat-sheet parity** — Every artifact on the Windows Registry cheat sheet has a corresponding bookmark, plus many more beyond the cheat sheet. _Why:_ bookmarks are a superset of the standard artifact list. _[IWE ch03 · Registry / Scalable Analysis]_
- **Sysinternals-usage bookmark** — A bookmark exists to enumerate Sysinternals usage, based on the registry record created when a user accepts a Sysinternals tool's EULA. _Why:_ proves a given user actually ran a given Sysinternals tool. _[IWE ch03 · Registry / Scalable Analysis]_

### Registry as an allocated file-system-like structure

- **Registry is allocated structure** — The registry is an allocated structure analogous to a file system, with the concepts of allocated and unallocated space/records. _Why:_ deletion mechanics mirror those of files on disk. _[IWE ch03 · Registry / Scalable Analysis]_
- **Deleted-record recovery** — Deleted registry data can be recovered from unallocated space until it is overwritten, just as deleted files can be recovered from disk. _Why:_ deleted keys/values are a live source of evidence. _[IWE ch03 · Registry / Scalable Analysis]_
- **Registry Explorer deleted-record display** — Registry Explorer surfaces deleted records in red within the hive view, distinguishing "associated deleted records" from "unassociated deleted records." _Why:_ built-in carving/recovery of deleted registry entries. _[IWE ch03 · Registry / Scalable Analysis]_
- **Associated vs unassociated deleted records** — "Associated" deleted records retain a known parent/context link, whereas "unassociated" deleted records have lost that linkage. _Why:_ affects how much context a recovered record carries. _[IWE ch03 · Registry / Scalable Analysis]_
- **Recovery caveat** — Recovery of deleted registry records is only possible up to the point the underlying space is overwritten. _Why:_ time-sensitivity of recoverable deleted registry data. _[IWE ch03 · Registry / Scalable Analysis]_
- **Cross-module pointer** — File-system deletion mechanics underlying registry recovery are covered in depth in the MFT/NTFS module; UserAssist evidence-of-execution is covered in the evidence-of-execution module. _Why:_ locates the fuller treatment of these topics. _[IWE ch03 · Registry / Scalable Analysis]_

## Chapter 03 · USB Forensics Networks

### Run / RunOnce keys (ASEPs)

- **ASEP definition** — An AutoStart Extensibility Point (ASEP) is any location in Windows configured to launch a program automatically on a trigger such as boot, logon, or another condition. _Why:_ ASEPs are the primary hunting ground for persistence mechanisms. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Run/RunOnce trigger scope** — The Run and RunOnce keys fire on *user logon*, not on system startup. _Why:_ Distinguishes logon-persistence from boot/service persistence when timing execution. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Run vs RunOnce behavior** — Entries under a Run key execute at every logon of the applicable user; entries under RunOnce execute only once, at the next logon, and are then removed. _Why:_ RunOnce presence indicates a one-shot action (e.g. a post-update cleanup) rather than durable persistence. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **HKCU Run path source** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and `\RunOnce`) is read from the individual user's `NTUSER.DAT` hive and affects only that current user. _Why:_ Scopes autostart entries to a single user account; per-user hive location for dead-box analysis. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **HKLM Run path source** — `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (and `\RunOnce`) is read from the `SOFTWARE` hive and applies to all users on the system. _Why:_ Machine-wide autostart; affects every account that logs on. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Run key content is directly readable** — Run/RunOnce values can be inspected in plain RegEdit without Registry Explorer; each value's data holds the full binary path plus any command-line parameters. _Why:_ Full path + args reveal what actually launches and how. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **RunOnce Edge cleanup example** — An HKLM RunOnce entry resembling an MS Edge cleanup script with a `--delete-old-versions` parameter is typically a benign Edge-update artifact scheduled to run once at the next start. _Why:_ Baseline for distinguishing normal update residue from malicious one-shot entries. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Run keys remain a top persistence choice** — Run keys are among the most ubiquitous autostart locations in Windows and are still heavily used by threat actors despite being well known, because they work and are simple. _Why:_ Do not deprioritize checking Run keys just because they are obvious. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Scale of ASEPs** — Windows exposes well over 100 distinct autostart extensibility points capable of launching something at startup or logon. _Why:_ Run keys are one of many; comprehensive persistence hunting must consider the broader ASEP surface. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Control sets (SYSTEM hive)

- **Control set definition** — A control set is a stored set of hardware/configuration data the operating system uses. _Why:_ Frames why USB/device data lives under a ControlSet tree. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **CurrentControlSet is live-only** — `CurrentControlSet` is a runtime symlink present only on a live running system; a dead-box image will not contain `CurrentControlSet`, only numbered `ControlSet00x` keys. _Why:_ On offline images you must resolve which numbered control set to read. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Numbered control sets** — A system may contain `ControlSet001`, `ControlSet002`, etc.; multiple sets can exist. _Why:_ Duplicate/triplicate device data across sets must be reconciled. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Select\Current resolves active set** — `SYSTEM\Select`, value `Current`, holds a number identifying which control set was last in use (e.g. `1` → `ControlSet001`). _Why:_ Tells the analyst which ControlSet00x to trust on an offline image. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **"Last Known Good" implies extra control set** — A boot-time "Reverting to last known good configuration" message implies an additional control set exists and the OS switched to that set's hardware configuration. _Why:_ Explains why multiple control sets and divergent data appear. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Data duplication across control set trees** — The same data may be duplicated (or triplicated) across the different ControlSet trees depending on how many sets exist. _Why:_ Analyst must pick the correct set via Select\Current to avoid reading stale config. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### USB device history — USB key

- **USB enumeration path** — USB device subkeys live under `SYSTEM\CurrentControlSet\Enum\USB`. _Why:_ Primary root for enumerating connected USB devices. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **VID/PID subkey naming** — Under `Enum\USB`, subkeys are named with a VID (Vendor ID) and PID (Product ID). _Why:_ VID/PID uniquely identify the hardware make/model class. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **VID/PID lookup** — A device's VID and PID can be searched against public USB ID databases to resolve the manufacturer and model (e.g. a Kingston, SanDisk Ultra, or SanDisk Cruzer flash drive). _Why:_ Turns opaque IDs into identifiable device make/model for profiling. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **VID/PID worked example** — VID `0781` with PID `559C` corresponds to a SanDisk Ultra-class USB flash drive. _Why:_ Concrete mapping example for the SanDisk device used throughout the lesson. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Serial-number subkeys** — Beneath each VID/PID key are subkeys that in many cases represent the device's serial number. _Why:_ Serial ties a specific physical device (not just a model) to the system. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Ampersand rule for serials** — If the second character of the subkey identifier is an ampersand (`&`), the value is NOT a genuine globally-unique serial number; absent that early ampersand, it should be a real globally-unique device serial. _Why:_ Distinguishes an OS-assigned pseudo-serial from a true hardware serial when attributing a physical device. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### USB device history — USBSTOR key

- **USBSTOR path** — USB mass-storage devices are enumerated under `SYSTEM\CurrentControlSet\Enum\USBSTOR`. _Why:_ Storage-specific device history, distinct from the general USB key. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **USBSTOR subkey naming** — USBSTOR subkey names embed descriptive fields such as `Ven` (vendor), `Prod` (product), and version, e.g. a name reading like "Disk&Ven_SanDisk&Prod_Ultra_USB_3.0". _Why:_ Human-readable device identity without external VID/PID lookup. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **USBSTOR yields class ID + serial** — USBSTOR exposes the device class ID and, in the subkey beneath the device name, the device serial number. _Why:_ Confirms the specific device instance for correlation with other keys. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **USBSTOR device values** — The USBSTOR device subkey carries additional values describing the device (friendly name, disk ID, etc.). _Why:_ Extra descriptive metadata for device profiling. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### USB timestamps — Properties subkeys

- **Properties key unreadable in live RegEdit** — Under a USBSTOR device serial subkey there is a `Properties` subkey that RegEdit cannot open on a live system ("Error Opening Key: Properties cannot be opened"); this error is expected and not a sign of corruption. _Why:_ Explains why the richest USB timestamps are invisible in live RegEdit and need offline/parsed access. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Numeric property subkeys** — Beneath `Properties` are numerically-named subkeys such as `0064`, `0066`, `0067` that hold device connect/disconnect timestamps. _Why:_ These are the canonical first/last/removed connect times for the device. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **0064 = first connected** — The `0064` property subkey yields the first time the USB device was connected to the system. _Why:_ Establishes earliest possible presence of a device (e.g. earliest exfiltration window). _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **0066 = last connected** — The `0066` property subkey yields the last time the USB device was connected/used. _Why:_ Bounds the most recent use of the device. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **0067 = last removed** — The `0067` property subkey yields the last time the device was removed (ejected) from the system. _Why:_ Distinguishes an eject event from a connect event on the timeline. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Three ways to get last-connect** — The last connection time of a USB device can be derived three ways: (1) the `0066` property value, (2) the last-write time of the USB/USBSTOR serial-number key, and (3) the last-write time of the user's MountPoints2 key. _Why:_ Provides corroboration/cross-checking of a single last-connect claim. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Last-write times require Registry Explorer** — Registry key last-write timestamps are visible in Registry Explorer but are NOT shown by RegEdit. _Why:_ Tool choice determines whether the timestamp-derivation methods above are even available. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### MountedDevices, drive letters, Volume GUID

- **MountedDevices path** — `SYSTEM\MountedDevices` (SYSTEM hive, not under a control set) records devices that were mounted on the system. _Why:_ Bridges a device serial to its assigned drive letter and Volume GUID. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Serial → drive letter** — Using a device's serial number, MountedDevices lets you determine the drive letter that the USB device was assigned when connected. _Why:_ Answers "what drive letter was the SanDisk stick" for correlating file/shellbag activity. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Serial → Volume GUID** — MountedDevices also maps the device to its Volume GUID, an alternative unique identifier for the device on that system. _Why:_ The Volume GUID is the join key to user-level MountPoints2 attribution. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Windows Portable Devices — volume label

- **Windows Portable Devices path** — `SOFTWARE\Microsoft\Windows Portable Devices\Devices` (SOFTWARE hive) holds portable-device subkeys. _Why:_ Recovers the human-assigned volume label of a USB device. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Volume name / label recovery** — The Windows Portable Devices\Devices subkey reveals the volume name (label) the user gave the USB flash drive (worked example: a stick labeled "Sticky"). _Why:_ A user-chosen label can identify a specific physical device across systems or match witness descriptions. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Portable Devices carries a timestamp** — Registry Explorer surfaces a timestamp alongside the portable-device friendly name/label. _Why:_ Adds a temporal anchor to the labeled device. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### EMDMgmt / ReadyBoost

- **EMDMgmt path** — `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` (SOFTWARE hive) is the ReadyBoost management key. _Why:_ A secondary source of USB volume identity, conditional on drive type. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **EMDMgmt only when system drive is not SSD** — The EMDMgmt key is present only when the system/boot drive is a traditional spinning hard drive, not an SSD. _Why:_ Its absence is expected on modern SSD systems and is not evidence of tampering. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **ReadyBoost background** — ReadyBoost, introduced in Windows Vista, let an SD card or USB flash drive act as a cache to speed up the OS; EMDMgmt existed to track ReadyBoost. _Why:_ Explains why this key ever recorded USB device data. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **EMDMgmt → volume serial number** — The device serial in EMDMgmt can be used to recover the volume serial number of the USB device. _Why:_ Volume serial is another device-instance identifier for correlation. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Volume serial number nature** — A volume serial number is assigned when a volume is formatted, is (per system) unique, and is visible via `dir` at a command prompt. _Why:_ Clarifies what the recovered value represents and how to independently verify it. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### User attribution — MountPoints2

- **MountPoints2 path** — MountPoints2 lives at `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` inside each user's `NTUSER.DAT`. _Why:_ Per-user record of what that user mounted — the attribution layer. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **MountPoints2 is per-user** — Because it resides in NTUSER.DAT, every user on the system has their own MountPoints2 subtree. _Why:_ Enables "which of the N users plugged in the device" analysis. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Volume GUID → mounting user** — Taking the Volume GUID from `SYSTEM\MountedDevices` and matching it against each user's MountPoints2 identifies which specific user mounted a given USB device. _Why:_ Attributes a device connection to an individual account on a multi-user host. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **MountPoints2 also records network shares** — MountPoints2 entries include not only removable devices but also mounted network shares. _Why:_ Same key evidences mapped-drive / remote-share access per user. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### setupapi.dev.log — USB first-connect

- **setupapi.dev.log path** — On Windows Vista and later, USB first-time device-connection events are logged (outside the registry) at `Windows\inf\setupapi.dev.log`. _Why:_ Independent, non-registry corroboration of a device's first-connect time. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **setupapi is a first-connect source** — The first-connect timestamp that the registry Properties key (`0064`) provides should also be recoverable from setupapi.dev.log. _Why:_ Cross-source validation of the earliest device-presence claim. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Registry Explorer workflow (Eric Zimmerman)

- **Loading live hives** — In Registry Explorer, `File → Live system` loads a live hive (e.g. SOFTWARE, then SYSTEM); multiple hives can be open simultaneously. _Why:_ Cross-hive USB correlation (SYSTEM + SOFTWARE + NTUSER.DAT) in one workspace. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Bookmarks feature** — Registry Explorer ships curated "bookmarks" — pre-built pointers to forensically-significant keys — whose available count grows as more hives are loaded (e.g. ~66 with SOFTWARE+SYSTEM, ~101 after also loading an NTUSER.DAT). _Why:_ Bookmarks jump straight to artifacts and auto-parse them, removing manual traversal. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Bookmarks auto-parse USB properties** — The USBSTOR bookmark surfaces serial number, device name, disk ID, and the installed/first-installed/last-connected (and last-removed) timestamps — i.e. it decodes the Properties subkeys RegEdit could not open. _Why:_ One click yields the connect/disconnect timeline that is otherwise hard to reach. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Empty last-removed is normal** — A "last removed" timestamp field may be unpopulated if no eject event was recorded for the device. _Why:_ Absence of a removal time is not necessarily suspicious. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Bookmarks organized by hive** — Available bookmarks group under the hive they belong to (SYSTEM, SOFTWARE, NTUSER.DAT); MountPoints2 appears under the NTUSER.DAT group. _Why:_ Confirms which hive each artifact is sourced from during analysis. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### System profiling keys (SYSTEM hive)

- **TimeZoneInformation path** — `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, value `TimeZoneKeyName`, records the configured time zone (worked example: "Eastern Standard Time"). _Why:_ Essential for correct timeline normalization of all other timestamps. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **ComputerName key** — A ComputerName key (SYSTEM hive) records the machine's hostname (worked example: "DFIRBOX"). _Why:_ Attributes an image/artifacts to a named host. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Shares key** — A `Shares` key (SYSTEM hive) enumerates file shares explicitly configured on the system. _Why:_ Reveals intentionally shared folders (potential lateral-movement/exfil paths). _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Default shares excluded** — The Shares key does not list the built-in default administrative shares (`C$`, `ADMIN$`, `IPC$`); an empty Shares key means only defaults exist. _Why:_ Any entry present indicates a deliberately created share worth scrutiny. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Network interfaces (SYSTEM hive)

- **Interfaces artifact** — The SYSTEM hive `Interfaces` data records each network interface's IP address, subnet mask, and DHCP configuration/state. _Why:_ Establishes the host's network identity and addressing at the interface level. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Per-interface detail** — Expanding an individual interface reveals IP address, subnet, default gateway, domain (worked example: "13cubed.home"), and DNS server (worked example: 172.16.10.40). _Why:_ Full per-interface network config for host attribution and network reconstruction. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Network history — NetworkList (SOFTWARE hive)

- **NetworkList path** — `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList` records networks the system has connected to. _Why:_ Primary source of network-connection history including wireless SSIDs. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **NetworkList names + type** — NetworkList exposes the names of connected networks — including wireless SSIDs (worked examples: "Wolf359", "Luyten726") and wired connections — and flags whether each was a wireless connection. _Why:_ Places a device on named/physical networks (e.g. a specific office or home Wi-Fi). _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **NetworkList first/last connect** — NetworkList records first-connection and last-connection timestamps for each profiled network. _Why:_ Bounds when the host was on a given network. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **NetworkList additional fields** — NetworkList also yields DNS suffixes and gateway MAC addresses (the DefaultGatewayMac / DnsSuffix profiling data) per network. _Why:_ Gateway MAC can uniquely fingerprint a specific physical network even if the SSID name is common. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Legacy network history — Windows XP (WZCSVC)

- **WZCSVC path (XP only)** — On Windows XP, `SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces\<GUID>` (Wireless Zero Configuration Service) records interface data; this key exists only on XP. _Why:_ Legacy analog to NetworkList for XP-era systems still encountered in the field. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **WZCSVC last-write = last network connect** — The last-write time of the XP WZCSVC interface GUID key indicates the last time a network was connected to. _Why:_ Derives most-recent network use on XP. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **WZCSVC hex → connection type** — Hex values within the XP WZCSVC key indicate whether the network was wired, broadband/cellular-modem, or wireless. _Why:_ Classifies the connection medium on XP hosts. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

### Evidence-of-execution keys (previewed here, detailed elsewhere)

- **AppCompatCache = Shimcache** — `AppCompatCache` (a.k.a. "Shimcache"), stored in the SYSTEM hive, is an application-compatibility (backwards-compatibility) feature that can sometimes serve as an evidence-of-execution artifact. _Why:_ Candidate program-execution source, with the caveat that its presence does not always prove execution. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Prefetch config key location** — A SYSTEM-hive key and its associated values determine whether Prefetch is enabled/disabled and can be used to change that configuration. _Why:_ Confirms whether Prefetch evidence should be expected on the host. _[IWE ch03 · Registry / USB Forensics, Networks & More]_
- **Prefetch reliability + default state** — Prefetch is a highly reliable program-execution artifact, but it is enabled by default only on Windows *desktop* editions; Windows Server does not enable it by default (though it can be turned on explicitly via the Prefetch config key). _Why:_ Absence of Prefetch on a server is expected, not evidence of anti-forensics; a running Prefetch on a server means it was deliberately enabled. _[IWE ch03 · Registry / USB Forensics, Networks & More]_

## Chapter 03 · UsrClass ShellBags

### UsrClass.dat — Identity & Mounting

- **UsrClass.dat role** — UsrClass.dat is one of the two user-specific registry hives (the other being NTUSER.dat). _Why:_ Establishes which per-user hives an examiner must collect to reconstruct a user's activity. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **UsrClass.dat mount point** — The contents of UsrClass.dat are mounted into the live registry under the path HKEY_CURRENT_USER\Software\Classes. _Why:_ Tells the examiner where UsrClass data surfaces in a live/loaded registry view. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **HKCU composition** — HKEY_CURRENT_USER is assembled from two hives together: everything under Software\Classes comes from UsrClass.dat, and everything else in HKCU comes from NTUSER.dat. _Why:_ Explains the provenance split so an examiner knows which offline hive to parse for a given HKCU key. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Delineation boundary** — Every key from HKCU\Software\Classes downward (the entire subtree beneath that subkey) originates in UsrClass.dat. _Why:_ Precise boundary for attributing a live-registry key back to its source hive on disk. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **HKCU\Software\Classes abbreviation** — The path is commonly written HKCU\Software\Classes (HKCU = HKEY_CURRENT_USER). _Why:_ Notation examiners will see in tools and documentation. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### UsrClass.dat — Artifacts of Interest

- **Two principal artifacts** — Within UsrClass.dat, the two main forensic artifacts of interest are MUICache and ShellBags. _Why:_ Focuses collection/analysis on the highest-value keys in this hive. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache expansion** — MUICache stands for Multilingual User Interface Cache. _Why:_ Clarifies the acronym for reporting and cross-referencing. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache classification** — MUICache is an Evidence-of-Execution artifact, usable to determine that a program executed. _Why:_ Places MUICache in the execution-evidence category alongside artifacts like Prefetch/ShimCache. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache location** — The main MUICache key sits under HKCU\Software\Classes at Local Settings\Software\Microsoft\Windows\Shell\MUICache. _Why:_ Exact key path for locating the artifact in the hive. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Secondary MUICache location** — A second location containing MUICache-related data exists in a similar path, but the Shell\MUICache key above is the primary location of interest. _Why:_ Warns the examiner not to stop at one key; corroborating data may live elsewhere. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache readability** — MUICache data is stored in plainly readable form; no special plugin (e.g., Registry Explorer plugins) is required to interpret it. _Why:_ An examiner can read it directly in raw registry views without a decoder. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache value contents** — For each executable, MUICache records the full path to the executable plus two values: the application company and the friendly application name. _Why:_ Identifies what evidentiary detail MUICache yields per program. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MUICache value count** — Two values (application company and friendly app name) exist for each recorded executable. _Why:_ Sets the expected structure so missing/extra values stand out. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — Location & Storage

- **ShellBags source hives** — ShellBags data is stored across two registry hives: most ShellBags live in UsrClass.dat, while ShellBags for the desktop and for network locations live in NTUSER.dat. _Why:_ Both hives must be parsed or an examiner misses desktop/network-path evidence. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Network-location example** — Network-location ShellBags include UNC paths such as \\COMPUTERNAME\c$, and these are stored in NTUSER.dat. _Why:_ Shows the specific kind of path that lives in the NTUSER-side ShellBags. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **UsrClass ShellBags key path** — In UsrClass.dat, ShellBags reside under HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell, where the two subkeys BagMRU and Bags are found. _Why:_ Exact key path to locate ShellBags in the live/loaded hive. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **BagMRU and Bags adjacency** — The BagMRU and Bags subkeys sit directly above the MUICache key within the Shell key. _Why:_ Navigational cue — an examiner at MUICache is one level away from ShellBags. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Two ShellBags subkeys** — ShellBags is composed of two cooperating subkeys: BagMRU (the numeric folder hierarchy / structure) and Bags (the stored view settings). _Why:_ Reconstructing ShellBags requires correlating both subkeys. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — What They Are & Prove

- **Purpose** — ShellBags stores the Windows Explorer window/view settings a user configured for a folder (e.g., sort order, view mode, window size and position), and Explorer restores them on revisit. _Why:_ Explains the benign OS function that incidentally produces forensic evidence. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Persistence of preferences** — Because Explorer remembers per-folder settings across sessions (e.g., a folder set to "Sort by Type" and "Extra Large Icons" reopens that way), those remembered settings are exactly what ShellBags stores. _Why:_ Ties the observable Explorer behavior to the underlying artifact. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Population trigger** — A ShellBag is created only the first time a user traverses to a given path within Windows Explorer; paths are not pre-populated. _Why:_ Presence of a ShellBag is affirmative evidence the user actually visited that path. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **"GPS for the file system"** — ShellBags can be used (framing attributed to Eric Zimmerman) as a GPS for the file system, revealing the Explorer paths a given user has traversed. _Why:_ Concise mental model of the artifact's investigative value. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Proves traversal / interest** — A ShellBag entry demonstrates the user was at least ostensibly interested in a path because they navigated to it; it does not by itself prove downstream actions (e.g., staging or exfiltration). _Why:_ Sets the correct evidentiary weight — traversal, not intent-to-exfiltrate. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Threat-actor use case** — For a compromised account, examining that account's ShellBags can reveal sensitive paths the actor navigated to (e.g., a payroll/financial-data directory), indicating interest in that data. _Why:_ Concrete IR scenario for applying the artifact. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Knowledge/intent use case** — A ShellBag for a folder (e.g., under a user's Downloads) is evidence the user explicitly traversed to that location and thus had foreknowledge of it; the folder name alone can rebut a claim of ignorance, because the ShellBag would not exist had the user not gone there. _Why:_ Explains how ShellBags counter "I never went there / didn't know" defenses. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Folder-name value** — The folder's name recorded in a ShellBag can itself be probative (e.g., a descriptively named folder), independent of the folder's contents. _Why:_ Even absent surviving files, the name in the ShellBag carries evidentiary meaning. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — Scope & Coverage Rules

- **Folders only** — ShellBags tracks folders, not files. _Why:_ Prevents over-claiming — an examiner cannot infer file-level access from ShellBags. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Zip-file exception** — The sole file exception is zip files: because Windows treats an opened zip archive as if it were a folder (it can be double-clicked and browsed/traversed in a folder view), zip archives get logged in ShellBags. _Why:_ Explains the one file type that appears and why. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Why zips are tracked** — When a user changes view settings (icon size, sort type, etc.) inside an opened zip, that per-"folder" information must be stored somewhere, and that place is ShellBags — hence zips are treated as folders and logged. _Why:_ Root-cause rationale for the zip exception. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Explorer-only artifact** — ShellBags is populated only by Windows Explorer; traversing the same paths via Command Prompt, PowerShell, or WSL does not create ShellBags entries. _Why:_ Absence of a ShellBag does not prove absence of access via non-Explorer tools. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Drives beyond C:** — ShellBags records paths on drives other than C: (e.g., D:, F:), including local and removable volumes. _Why:_ Evidence of activity on secondary/removable media, not just the system drive. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Mapped network drives** — Mapped network drives (e.g., an X: or Z: drive backed by a share) appear in ShellBags. _Why:_ Reveals user access to remote/mapped storage. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **UNC network locations** — UNC/network locations are tracked, e.g., \\host.domain\share and \\<IP address>\d$. _Why:_ Documents lateral/remote browsing to network shares. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **WSL$ paths** — WSL$ locations (part of the Windows Subsystem for Linux, browsed through Explorer) show up in ShellBags. _Why:_ Explorer-mediated access to the WSL filesystem is captured. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### BagMRU / Bags — Structure & Decoding

- **Numeric hierarchy** — Under BagMRU, folders are represented as a nested hierarchy of numeric subkeys (0, 1, 2, 3, 4, ...) that mirrors the directory tree the user traversed. _Why:_ The numbering is the on-disk encoding an examiner must decode to rebuild paths. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Live build-out** — New BagMRU numeric entries are created in real time as a user visits new locations in Explorer (visiting Users, then PerfLogs, then EFI, then Program Files sequentially creates successive numbered entries). _Why:_ Demonstrates that each number corresponds to a discrete first-visit event. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Sibling numbering order** — Sibling folders under a parent are numbered in the order first visited (e.g., 0=Windows, 1=Users, 2=PerfLogs, 3=EFI, 4=Program Files (x86)). _Why:_ The number order itself encodes visit sequence among siblings. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Nested subfolders** — A numeric entry can contain further numeric subkeys representing its child folders, producing a deep nested structure. _Why:_ Depth of nesting mirrors depth of the traversed path. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Folder name in binary value** — Double-clicking a BagMRU numeric value exposes the folder name embedded within the raw binary shell-item data (e.g., the value under 0 decodes to "Windows"). _Why:_ Shows where the human-readable name is recovered from within the shell item. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MRUListEx presence** — Each BagMRU key contains an MRU list value tracking most-recently-used ordering of its child entries. _Why:_ Provides recency ordering of sibling folders for timeline reasoning. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **NodeSlot linkage** — Each BagMRU entry carries a NodeSlot value that links the folder's structural entry in BagMRU to its corresponding view-settings entry in the Bags subkey. _Why:_ NodeSlot is the join key between path structure (BagMRU) and stored settings (Bags). _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Bags settings contents** — Drilling into the Bags subkey reveals stored view settings such as Icon Size, Logical View Mode, and Sort. _Why:_ Confirms Bags holds the actual per-folder display configuration. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Manual decode is tedious** — ShellBags can be decoded by hand (writing out the numeric hierarchy and mapping each number to a folder), but this is impractical at scale, motivating tool use. _Why:_ Justifies why examiners use a parser rather than raw regedit. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Sparse on fresh systems** — On a brand-new/clean system, BagMRU and Bags are sparse (few entries) because little browsing has occurred. _Why:_ Baseline expectation — volume of ShellBags scales with system age and usage. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — Timestamps & Metadata

- **Three tracked interaction facts** — Beyond the path, ShellBags tracks the first time and last time the user interacted with a path in Explorer, and can also record the creation date of the directories. _Why:_ Enumerates the temporal data points available for a visited folder. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Timestamp column set** — ShellBags Explorer surfaces Created/Modified/Accessed timestamps (embedded MAC times) plus First Interacted and Last Interacted timestamps. _Why:_ Distinguishes filesystem MAC times captured in the shell item from Explorer-interaction times. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **First/Last Interacted meaning** — First Interacted = when the user first interacted with the folder; Last Interacted = when the user last interacted with it. _Why:_ Defines the two most load-bearing ShellBags timestamps for activity timelining. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Equal first/last** — First and Last Interacted timestamps can be identical (a folder visited only once). _Why:_ Equal values indicate a single interaction, not missing data. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — Longevity, Deletion & Anti-Tamper Behavior

- **No expiry / no cap** — ShellBags do not expire and have no fixed maximum count (there is no rollover at, e.g., 1,024 entries). _Why:_ Entries can persist indefinitely, so old activity remains recoverable. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Historical reach** — Because they do not expire, ShellBags can reach far back in history, limited chiefly by the age of the operating system install. _Why:_ Sets expectations for how far back ShellBags evidence may extend. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Survives path deletion** — Deleting a path in Windows Explorer does not delete its ShellBag; the ShellBag persists after the folder is removed. _Why:_ ShellBags can prove a now-deleted folder once existed and was visited. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Survives secure wipe** — Even securely wiping/deleting the underlying path does not affect the ShellBags data. _Why:_ Anti-forensic wiping of files leaves the ShellBags evidence intact. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Evidence of vanished paths** — ShellBags therefore commonly contains entries for paths that no longer exist on disk, letting an examiner see traversals to media/folders no longer present. _Why:_ A primary reason ShellBags is prized in investigations. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags — Feature-Update Caveat (Reliability)

- **Feature-update clobbering** — Windows 10/11 feature updates (released roughly twice a year) can and have clobbered some ShellBags timestamps, because a feature update behaves like installing a new operating system. _Why:_ Major reliability caveat — timestamps may be reset by an OS event unrelated to user activity. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **What gets reset** — Reported effects include last-write times being clobbered and other data being reset around a feature update. _Why:_ Tells the examiner which fields to distrust after an update. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Correlation remedy** — When ShellBags timestamps do not add up, correlate them against the date of the last feature-update install to check whether the update clobbered them. _Why:_ Practical validation step to explain anomalous timestamps. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### ShellBags Explorer (GUI Tool)

- **Tool identity** — ShellBags Explorer is Eric Zimmerman's dedicated ShellBags parser, similar in spirit to Registry Explorer but a distinct tool. _Why:_ Names the standard tool and its author for method documentation. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Run as Administrator for live** — To parse the live running system's ShellBags, ShellBagsExplorer.exe must be launched via right-click "Run as Administrator"; the live-registry option is only available when run elevated (mirrors Registry Explorer's requirement). _Why:_ Explains why elevation is needed for live acquisition. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **First-run email prompt** — On first launch, the tool prompts to populate an email address in Options, used for error submissions. _Why:_ Expected setup step, not an error. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Default timezone UTC** — The default timezone option is UTC and should be left as UTC. _Why:_ Consistent UTC handling prevents conversion errors. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Always use UTC** — Forensic best practice is to use UTC for everything and avoid converting between time zones, because manual conversion risks a critical mistake. _Why:_ General timestamp-handling discipline that protects the timeline's integrity. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Two load options** — The File menu offers "Load Active Registry" and "Load Offline Hive". _Why:_ Defines the two acquisition modes the tool supports. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Load Active Registry scope** — "Load Active Registry" parses both NTUSER.dat and UsrClass.dat of the current user. _Why:_ Confirms the live mode covers both ShellBags source hives automatically. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Real-world offline workflow** — Typical casework: receive an image, mount it (e.g., with Arsenal Image Mounter), extract NTUSER.dat and UsrClass.dat for the users of interest, then use "Load Offline Hive" to parse them. _Why:_ Documents the defensible, non-live examination procedure. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Both hives needed offline** — For complete ShellBags coverage on an offline exam, load both NTUSER.dat and UsrClass.dat (desktop/network ShellBags live in NTUSER.dat). _Why:_ Loading only UsrClass.dat misses desktop and network-location entries. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Parsing-complete summary** — After parsing, the tool reports a total ShellBags count and a breakdown by bag type (example figures: 607 total; network location = 5; directory = 550; etc.). _Why:_ Provides a quick census of the artifact set and its composition. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Unmapped GUID warnings** — Parsing may raise warning messages about an unmapped GUID (a shell item whose GUID the tool could not resolve); these can generally be noted and set aside. _Why:_ Distinguishes benign parse warnings from substantive errors. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Two-pane layout** — The GUI presents a logically laid-out tree structure on the left (like Windows Explorer) and the data columns on the right. _Why:_ Orients the examiner to the tool's presentation. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Column set** — Right-pane columns include Value, Icon, Shell Type, MRU position (most-recently-used position), Created/Modified/Accessed timestamps, and First/Last Interacted timestamps. _Why:_ Enumerates the fields available for analysis and reporting. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Shell Type icon** — The Icon/Shell Type column indicates the item type (e.g., a directory shell type). _Why:_ Lets the examiner distinguish directories from other shell-item types at a glance. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **MRU position semantics** — The most-recently-used position column orders sibling items by recency (position 0 = most recently used, then next, etc.). _Why:_ Enables recency ranking of folders visited under a common parent. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Per-user analysis** — ShellBags Explorer results are scoped to a specific user account (e.g., user "davisrg"), showing when that user interacted with each path. _Why:_ Attributes traversals to a named user for accountability. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Bottom metadata pane** — Selecting an entry shows a metadata pane at the bottom, including the absolute (full) path of the item and its First/Last Interacted timestamps. _Why:_ Where the examiner reads the resolved full path and key times per selection. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Has Explored caveat** — The "Has Explored" column is a ShellBags Explorer convenience field, NOT a value coming from the underlying ShellBags structure; its population method is undocumented/unclear (even in the tool's docs at time of recording), so it is prudent to ignore it and rely on the timestamps instead. _Why:_ Prevents an examiner from treating a tool-derived heuristic as native artifact data. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Expand Tree Nodes** — Tools > "Expand Tree Nodes" (keyboard shortcut Alt+Down) expands the entire tree to reveal all entries at once. _Why:_ Efficient way to survey the full ShellBags set. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **No file contents** — Because ShellBags tracks folders only, the tool cannot show the contents of a folder (e.g., what files were inside an "Xbox Games" folder); it shows the folder's existence/traversal, not its files. _Why:_ Bounds what conclusions the tool output supports. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Export formats** — File > Export can output the parsed data to CSV, Excel, or JSON for further slicing and analysis. _Why:_ Enables downstream processing and integration with timelines. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

### SBECmd (Command-Line Tool)

- **CLI counterpart** — SBECmd (SBECmd.exe) is the command-line version of ShellBags Explorer, located one directory up in the Net 6 tools folder. _Why:_ Identifies the scriptable variant for automation. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **CLI usage** — SBECmd is driven by a few options plus a CSV output target and writes all ShellBags data to a CSV file. _Why:_ Basic invocation model for batch/automated parsing. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_
- **Equivalent output** — SBECmd produces output equivalent to the GUI's Export; the presenter nonetheless prefers the GUI for ShellBags because its Explorer-like presentation is more intuitive (a stated personal preference / "your mileage may vary"). _Why:_ Tool-choice guidance; both are valid, GUI favored for interpretability. _[IWE ch03 · Registry / UsrClass.dat & ShellBags]_

## Chapter 04 · AmCache

### Reference Documentation

- **Primary reference document** — The most complete public reference on AmCache is a ~66-page PDF titled "Analysis of the AmCache" authored by Blanche Lagny. _Why:_ Names the authoritative deep-dive source an analyst should consult beyond introductory coverage. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Finding the reference** — The Lagny document is readily located by a web search along the lines of "analysis AmCache" and typically appears as the top result. _Why:_ Points to where the authoritative writeup can be retrieved. _[IWE ch04 · Evidence of Execution / AmCache]_

### Origin & History

- **Predecessor artifact** — AmCache is the successor to an older Windows 7 artifact named `RecentFileCache.bcf`. _Why:_ Frames AmCache lineage; analysts on legacy systems may still encounter the predecessor. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Predecessor purpose** — `RecentFileCache.bcf` on Windows 7 could help profile program execution on Windows 7 systems. _Why:_ Establishes the historical execution-profiling role AmCache inherited. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Introduction version** — AmCache replaced `RecentFileCache.bcf` beginning with Windows 8. _Why:_ Sets the OS baseline at which the modern artifact appears. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Backport to Windows 7** — AmCache was backported to fully patched Windows 7 systems near the end of that OS's service life, so it can exist on fully patched Windows 7 as well. _Why:_ An analyst should not assume AmCache is absent on Windows 7 machines. _[IWE ch04 · Evidence of Execution / AmCache]_

### File Location & Structure

- **Artifact is a registry hive** — AmCache is stored as a standalone Windows registry hive, not a flat file. _Why:_ Determines the tooling (registry parsers) needed to read it. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Hive filename** — The hive file is named `Amcache.hve`. _Why:_ Exact filename needed to locate/extract the artifact. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Hive path** — The hive resides at `%SystemRoot%\AppCompat\Programs\` (i.e. `Windows\AppCompat\Programs\Amcache.hve`). _Why:_ Precise on-disk location for collection. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Accessing the directory** — Browsing to the `AppCompat\Programs` location on a live system may require an elevated (administrative) command prompt. _Why:_ Explains why a normal shell may fail to reach the hive. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Transaction logs present** — Alongside the hive are its registry transaction log files `Amcache.hve.LOG1` and `Amcache.hve.LOG2`. _Why:_ These logs may hold unflushed data and should be collected with the hive for complete/consistent parsing. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Logs are hidden** — The `.LOG1` and `.LOG2` transaction log files are marked hidden and do not appear in a default file listing. _Why:_ Analyst must reveal hidden files (or use a forensic imager) to collect them. _[IWE ch04 · Evidence of Execution / AmCache]_

### What AmCache Tracks

- **Installed applications** — AmCache tracks installed application packages, e.g. software deployed via an MSI installer. _Why:_ One of the three primary evidence categories in the hive. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Loose executables** — AmCache also tracks loose/standalone executables (individual `.exe` files not tied to an installed package). _Why:_ Captures ad-hoc/dropped binaries that installed-application tracking would miss. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Drivers tracked** — Unlike Prefetch, AmCache tracks drivers. _Why:_ Distinctive capability; supports investigation of malicious/rogue kernel drivers. _[IWE ch04 · Evidence of Execution / AmCache]_

### Presence vs. Execution (CRUCIAL nuance)

- **Not evidence of execution (modern)** — In modern AmCache, presence of an entry does NOT prove the file executed; AmCache can no longer be used as an evidence-of-execution artifact. _Why:_ Central caveat; misreading it as execution proof is a defensible-analysis failure. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Historical execution role** — AmCache was, at some point in the past and in some circumstances, usable to indicate that something had executed; this is why it is still taught under the "Evidence of Execution" heading. _Why:_ Explains categorization while flagging the capability is deprecated. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Correct modern interpretation** — Modern AmCache should be interpreted as evidence of file presence/existence on the system, the same interpretive stance now applied to modern Shimcache (AppCompatCache). _Why:_ Tells the analyst the correct claim to make in a report. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Automated-entry contamination** — Entries can be written to AmCache by automated system actions, so an entry does not always indicate that a user or process ran the file. _Why:_ Root reason presence ≠ execution; guards against false positives. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Explicit prohibition** — AmCache cannot be used to prove execution. _Why:_ Stated flatly; the load-bearing report-language constraint. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Presence persists after deletion** — Deleting a file does not remove its AmCache entry, so historical entries can remain for files that no longer exist on disk. _Why:_ Enables proving a file "once existed" even after removal — behaves like Shimcache in this respect. _[IWE ch04 · Evidence of Execution / AmCache]_

### Tracked Fields / Metadata

- **Full file path** — AmCache records the full file path of the executable. _Why:_ Locates where the binary lived on disk. _[IWE ch04 · Evidence of Execution / AmCache]_
- **File size** — AmCache records the file size of the tracked binary. _Why:_ Supports identity correlation and matching against known samples. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Compilation time** — AmCache stores the PE compilation time (a.k.a. link date) — the time the PE32 binary/program was compiled. _Why:_ A pivot for timelining and detecting freshly built/backdated malware. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Compilation-time = link date terminology** — In AmcacheParser output and the registry, the compilation time appears under the label "link date." _Why:_ Same value, two names; avoids confusion when reading fields. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Additional metadata** — AmCache stores further metadata beyond path/size/compile time (name, publisher, version, product name, product version, binary type / PE flag, OS-component flag, file extension, etc.). _Why:_ Rich attribution context for each binary. _[IWE ch04 · Evidence of Execution / AmCache]_

### SHA-1 Hash Storage

- **SHA-1 stored** — AmCache stores the SHA-1 hash of the tracked executable — a capability unique to AmCache versus Prefetch or essentially any other Windows artifact. _Why:_ Enables hash-based identification/threat-intel lookup even when the file is gone. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Hash lives in "File ID"** — The SHA-1 hash is held in a value/field named "File ID." _Why:_ Tells the analyst which raw registry value carries the hash. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Driver hash in "Driver ID"** — For drivers, the SHA-1 hash is held in the "Driver ID" value. _Why:_ The driver-side equivalent of File ID. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Leading-zeros prefix** — The raw File ID / Driver ID value is prefixed with four leading zeros ("0000") that are NOT part of the actual SHA-1; they must be truncated to recover the true hash. _Why:_ Failing to strip them yields a wrong hash and failed comparisons. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Tool auto-truncation** — Registry Explorer's top-level summary and AmcacheParser output already strip the four leading zeros, presenting the value in a dedicated column labeled "SHA-1." _Why:_ Explains why tool output differs from the raw subkey value. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Hash size cap** — AmCache hashes only the first 30 MB of a given executable. _Why:_ Files larger than 30 MB will not match a full-file hash — a comparison gotcha. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Exact cap in bytes** — The 30 MB cap is exactly 31,457,280 bytes, the maximum number of bytes AmCache will hash. _Why:_ Precise threshold for reasoning about large-file mismatches. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Derivation of 30 MB** — 31,457,280 ÷ 1,048,576 (bytes per MB) = 30, confirming the cap is exactly 30 MB. _Why:_ Shows the arithmetic behind the figure. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Large-file mismatch mechanism** — For a file over 30 MB (e.g. a 100 MB executable), AmCache hashes only the first 30 MB, so its stored SHA-1 will not equal a SHA-1 computed over the whole file. _Why:_ Explains an otherwise puzzling non-match during hash verification. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Cap rarely matters in practice** — The vast majority of executables encountered are well under 30 MB, so the hash cap seldom causes a real-world problem. _Why:_ Contextualizes the gotcha's practical impact. _[IWE ch04 · Evidence of Execution / AmCache]_

### Timestamp Semantics

- **Subkey LastWrite times exist** — Each program-tracking subkey carries a registry LastWrite timestamp. _Why:_ These are the timestamps analysts must interpret carefully. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Old interpretation (deprecated)** — In older AmCache versions, the subkey LastWrite time was used as a rough approximation of the first time of execution. _Why:_ Historical context; explains legacy writeups that equate LastWrite with first-run. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Modern interpretation** — In modern AmCache, the LastWrite time does NOT indicate an execution time; it generally reflects when the populating scheduled task ran. _Why:_ Prevents misdating "execution" from a scan artifact — the key timestamp caveat. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Populating scheduled task** — AmCache data is populated by a scheduled task called the Microsoft Compatibility Appraiser. _Why:_ Identifies the mechanism whose run time drives the LastWrite values. _[IWE ch04 · Evidence of Execution / AmCache]_
- **LastWrite ≈ Appraiser run** — The subkey LastWrite time is usually commensurate with a run of the Microsoft Compatibility Appraiser scheduled task, not with user activity. _Why:_ Tells the analyst what the timestamp actually measures. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Distinct stored timestamps** — Beyond registry LastWrite, entries carry their own stored timestamps (e.g. a per-entry "timestamp" value, link/compile date, and — for drivers — separate driver timestamps and driver last-write times). _Why:_ Multiple time fields must not be conflated; each has different meaning. _[IWE ch04 · Evidence of Execution / AmCache]_

### Key Registry Subkeys

- **InventoryApplication** — The `InventoryApplication` subkey tracks installed application packages (software that would appear in Add/Remove Programs, e.g. MSI installs). _Why:_ First of the three primary subkeys; where installed-software evidence lives. _[IWE ch04 · Evidence of Execution / AmCache]_
- **InventoryApplication fields** — Selecting the `InventoryApplication` root shows columns including timestamp, name, version, publisher, source, root directory path, and uninstall string. _Why:_ Enumerates the attribution fields available for installed apps. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Program ID linkage** — Each `InventoryApplication` child subkey is keyed by a Program ID that matches the value shown in its detail view. _Why:_ The Program ID is the join key between installed-app and file records. _[IWE ch04 · Evidence of Execution / AmCache]_
- **InventoryApplicationFile** — The `InventoryApplicationFile` subkey tracks loose/standalone executables (individual files, not installed packages). _Why:_ Second primary subkey; where dropped/standalone binary evidence lives. _[IWE ch04 · Evidence of Execution / AmCache]_
- **InventoryApplicationFile fields** — `InventoryApplicationFile` records include timestamp, path, name, product name, publisher, version, and the SHA-1 (File ID). _Why:_ Enumerates the loose-executable attribution fields, including the hash. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Subkeys named after executables** — `InventoryApplicationFile` child subkeys are named after the actual executable filenames (e.g. a 7-Zip binary). _Why:_ Lets an analyst spot a target binary by name directly in the key tree. _[IWE ch04 · Evidence of Execution / AmCache]_
- **File→App correlation** — A loose executable in `InventoryApplicationFile` that belongs to an installed package carries a Program ID that can be matched back to the corresponding `InventoryApplication` entry for fuller context. _Why:_ Enables pivoting from a single binary to its parent application record. _[IWE ch04 · Evidence of Execution / AmCache]_
- **InventoryDriverBinary** — The `InventoryDriverBinary` subkey tracks drivers. _Why:_ Third primary subkey; the driver-evidence source unique to AmCache. _[IWE ch04 · Evidence of Execution / AmCache]_
- **InventoryDriverBinary fields** — Driver records include timestamp, driver LastWrite time, company, product, product version, driver name, driver version, path, and SHA-1 (Driver ID). _Why:_ Enumerates driver attribution fields for rogue-driver hunting. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Driver example** — `ACPI.sys` is a concrete example of a driver whose Driver ID (SHA-1, minus the leading zeros) is recoverable from `InventoryDriverBinary`. _Why:_ Illustrates driver-hash extraction on a real system driver. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Three key subkeys summary** — The three most important AmCache subkeys are `InventoryApplication` (installed apps), `InventoryApplicationFile` (loose executables), and `InventoryDriverBinary` (drivers). _Why:_ The prioritized triage set for AmCache analysis. _[IWE ch04 · Evidence of Execution / AmCache]_

### Tooling — Registry Explorer

- **Opens in Registry Explorer** — `Amcache.hve` can be opened directly in Eric Zimmerman's Registry Explorer for manual browsing. _Why:_ Baseline tool for interactive inspection of the hive. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Live-system loading** — Run Registry Explorer as administrator and use File → Live System to load `Amcache.hve` from the running machine without manual extraction. _Why:_ A fast way to inspect AmCache on a live host. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Root-key summary view** — Clicking a top-level subkey in Registry Explorer renders all of its child entries in a consolidated table on the right, versus drilling into each child individually. _Why:_ Efficient triage view of an entire category at once. _[IWE ch04 · Evidence of Execution / AmCache]_

### Tooling — AmcacheParser

- **Purpose-built parser** — Eric Zimmerman provides a dedicated tool, AmcacheParser (`AmcacheParser.exe`), that parses the hive into multiple CSV outputs. _Why:_ The go-to bulk-extraction tool for AmCache. _[IWE ch04 · Evidence of Execution / AmCache]_
- **`-f` required** — AmcacheParser requires the `-f` flag pointing to the hive file; unlike AppCompatCacheParser, it cannot parse the live system directly. _Why:_ Dictates that the hive must be extracted first. _[IWE ch04 · Evidence of Execution / AmCache]_
- **`--csv` required** — AmcacheParser also requires a `--csv` argument specifying the output directory for the multiple CSVs it produces. _Why:_ Mandatory output flag; run fails without it. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Optional output name** — AmcacheParser optionally accepts a name prefix for the generated CSV files; omitting it uses the default naming. _Why:_ Documents an optional flag for output organization. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Fast runtime** — Parsing completes very quickly (sub-second in the demonstrated run). _Why:_ Sets expectation that AmCache parsing is cheap. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Run summary output** — On completion AmcacheParser prints a breakdown of what it found (file entries, shortcuts, driver binaries, etc.). _Why:_ Confirms categories parsed and rough counts. _[IWE ch04 · Evidence of Execution / AmCache]_

### AmcacheParser CSV Outputs

- **UnassociatedFileEntries CSV** — The "UnassociatedFileEntries" CSV corresponds to the `InventoryApplicationFile` subkey — the loose executables. _Why:_ Maps the primary loose-file registry source to its CSV; a top go-to output. _[IWE ch04 · Evidence of Execution / AmCache]_
- **UnassociatedFileEntries columns** — This CSV includes Program ID, File Key, LastWrite timestamp, SHA-1, OS-component flag, full path, name, file extension, link date, product name, size, version, product version, binary type, and PE flag. _Why:_ Enumerates the loose-file analysis columns available in one place. _[IWE ch04 · Evidence of Execution / AmCache]_
- **DriveBinaries CSV** — The "DriveBinaries" CSV corresponds to the `InventoryDriverBinary` subkey — the drivers. _Why:_ Maps the driver registry source to its CSV; the second top go-to output. _[IWE ch04 · Evidence of Execution / AmCache]_
- **DriveBinaries columns** — This CSV includes the key name (full driver path), LastWrite timestamps, driver timestamps, driver LastWrite times, driver names, checksums, companies, driver ID, type, version, and size. _Why:_ Enumerates driver-analysis columns for the CSV workflow. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Two most useful CSVs** — UnassociatedFileEntries and DriveBinaries are considered the two most important/primary AmcacheParser outputs. _Why:_ Prioritizes analyst attention among many CSVs. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Shortcuts CSV** — A "Shortcuts" CSV tracks LNK (link) files on the system, listing the LNK files, their full paths, and associated key LastWrite timestamps. _Why:_ A secondary but usable output for shortcut/LNK evidence. _[IWE ch04 · Evidence of Execution / AmCache]_
- **DeviceContainers CSV** — AmcacheParser also emits a "DeviceContainers" CSV, generally regarded as less useful. _Why:_ Notes an additional output an analyst can usually deprioritize. _[IWE ch04 · Evidence of Execution / AmCache]_
- **DriverPackages CSV** — AmcacheParser also emits a "DriverPackages" CSV among its outputs. _Why:_ Completes the enumeration of produced CSV categories. _[IWE ch04 · Evidence of Execution / AmCache]_

### Collection Workflow

- **Extraction required before parsing** — Because AmcacheParser cannot read a live system, the hive (and ideally its transaction logs) must be extracted from the running/imaged system first. _Why:_ Defines the mandatory pre-parse step. _[IWE ch04 · Evidence of Execution / AmCache]_
- **FTK Imager extraction** — FTK Imager can extract AmCache: add the physical OS drive as an evidence item, drill into the Windows partition → `Windows\AppCompat\Programs`, and export `Amcache.hve` plus its `.LOG1`/`.LOG2` logs. _Why:_ A concrete, forensically sound extraction path from a live or imaged disk. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Real-case workflow** — In a real investigation against a supplied drive image, extracting and parsing `InventoryApplicationFile` (loose executables) and `InventoryDriverBinary` (drivers) are among the primary AmCache steps. _Why:_ States the practitioner's default triage focus. _[IWE ch04 · Evidence of Execution / AmCache]_

### Evidentiary Value Summary

- **Fewer caveats than Shimcache** — AmCache is comparatively easier to understand and carries fewer caveats than Shimcache (AppCompatCache). _Why:_ Sets relative difficulty/expectations between the two presence artifacts. _[IWE ch04 · Evidence of Execution / AmCache]_
- **Net investigative value** — AmCache's value is proving file presence (that a file once existed, even if deleted) plus a wealth of tracked metadata — most notably the SHA-1 hash — not proving execution. _Why:_ The correct one-line summary of what AmCache delivers in a report. _[IWE ch04 · Evidence of Execution / AmCache]_

## Chapter 04 · MUICache

### What MUICache is

- **MUICache — name/expansion** — "MUICache" abbreviates Multilingual User Interface Cache. _Why:_ orients the analyst to the artifact's original OS purpose, distinct from its forensic use. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — original purpose** — It was created to support language localization, letting one binary present its UI in several languages. _Why:_ explains why the data (company/app names) exists at all; execution evidence is a side effect, not the design goal. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — localization example** — A single executable authored in English can carry localized strings for Spanish, German, and other languages so users in different regions run the same binary. _Why:_ clarifies the localization mechanism that seeds the cached metadata. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — introduced in Windows 2000** — The feature dates back to Windows 2000. _Why:_ establishes broad availability across Windows versions the examiner is likely to encounter. _[IWE ch04 · Evidence of Execution / MUICache]_

### Forensic value and scope

- **MUICache — execution-evidence class** — For DFIR it serves as an artifact of program execution. _Why:_ places MUICache in the "evidence of execution" category alongside artifacts like Prefetch, Shimcache, etc. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — per-user artifact** — It is a per-user artifact because it lives inside each user's own registry hive. _Why:_ execution recorded here is attributable to a specific user profile, not the machine as a whole. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — GUI programs only** — It records execution of GUI-based applications only, not command-line programs. _Why:_ absence of a CLI tool in MUICache is not proof it never ran; the analyst must not treat MUICache as a complete execution list. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — populated on first run** — The two values for an executable are written the first time that executable runs. _Why:_ presence indicates the program executed at least once under that user. _[IWE ch04 · Evidence of Execution / MUICache]_

### Storage location (hive and key path)

- **MUICache — stored in UsrClass.dat** — MUICache resides in each user's UsrClass.dat hive (also spelled UserClass.dat). _Why:_ tells the examiner which hive file to extract from a disk image for offline parsing. _[IWE ch04 · Evidence of Execution / MUICache]_
- **User registry hives — the two per-user hives** — The two user-specific registry hives are UsrClass.dat and NTUSER.DAT. _Why:_ context for where per-user artifacts live; MUICache is in the former, not NTUSER.DAT. _[IWE ch04 · Evidence of Execution / MUICache]_
- **UsrClass.dat — live mount point** — On a live system UsrClass.dat mounts under HKEY_CURRENT_USER\Software\Classes. _Why:_ tells the analyst where regedit exposes the hive when examining a running machine. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — full key path** — The main key is UsrClass.dat → Local Settings → Software → Microsoft → Windows → Shell → MUICache (i.e. Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MUICache). _Why:_ the exact path an analyst navigates to or targets with a parser. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — adjacent to Shellbags** — The MUICache key sits under the same Shell key that holds Shellbags data. _Why:_ analysts already handling Shellbags can locate MUICache nearby in the same hive branch. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — secondary system-wide subkey** — A separate MUICache-related subkey under Local Settings holds entries for system-wide binaries; this is not the primary location of investigative interest. _Why:_ prevents the analyst from mistaking the system-wide subkey for the main per-application MUICache key. _[IWE ch04 · Evidence of Execution / MUICache]_

### What each entry records

- **MUICache — two values per executable** — Each executable produces two registry values. _Why:_ the analyst knows to expect and pair them per program. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — ApplicationCompany value** — One value is "ApplicationCompany", carrying the vendor/company name. _Why:_ identifies who authored the binary, useful for spotting mismatches. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — FriendlyAppName value** — The other value is "FriendlyAppName", carrying the human-readable application name. _Why:_ reveals what the program claims to be regardless of its filename. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — value-name format** — Each value name is the full path to the executable, followed by a period, followed by either "ApplicationCompany" or "FriendlyAppName" (e.g. C:\...\Steam.exe.ApplicationCompany). _Why:_ shows the analyst how to read the value naming and extract both the path and the metadata field. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — full executable path recorded** — The value name embeds the complete filesystem path to the executable that ran. _Why:_ gives the location from which the program was launched, not just its name. _[IWE ch04 · Evidence of Execution / MUICache]_

### Metadata source (PE version info)

- **MUICache — source of company/app strings** — ApplicationCompany and FriendlyAppName are pulled from the Portable Executable (PE) binary itself, not from the filename or user input. _Why:_ the values describe the true binary, enabling detection of renamed/disguised executables. _[IWE ch04 · Evidence of Execution / MUICache]_
- **PE — resource sections** — A PE file contains resource sections embedded in the binary. _Why:_ background for where the metadata originates. _[IWE ch04 · Evidence of Execution / MUICache]_
- **PE — VersionInfo resource** — One resource section is the "version info" resource, holding executable metadata. _Why:_ names the specific PE structure MUICache reads. _[IWE ch04 · Evidence of Execution / MUICache]_
- **PE VersionInfo — fields present** — VersionInfo includes company name, version, copyright information, and more. _Why:_ the analyst can corroborate MUICache values directly against the PE by inspecting the same resource. _[IWE ch04 · Evidence of Execution / MUICache]_

### Detecting renamed / masqueraded binaries

- **MUICache — rename creates a new entry** — Renaming Steam.exe to notSteam.exe and running it produces a fresh MUICache entry. _Why:_ each distinct path (including renamed copies) is tracked separately. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — path changes, metadata does not** — On a renamed binary, only the path portion of the value name changes; ApplicationCompany still reads "Valve Corporation" and FriendlyAppName still reads "Steam", not the new filename. _Why:_ the metadata is bound to the binary's embedded strings, so a renamed malware still shows its original identity. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — metadata independent of filename** — The recorded company/app values have no relationship to the on-disk filename. _Why:_ foundational for the masquerade-detection use case. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — masquerade detection** — When a threat actor renames a utility (e.g. to A.exe or an unrelated name) to hide it, MUICache still surfaces the binary's genuine metadata, letting the analyst see it is not what its filename claims. _Why:_ direct investigative payoff — spotting disguised tools by comparing filename against embedded identity. _[IWE ch04 · Evidence of Execution / MUICache]_

### Timestamp caveats

- **MUICache — no per-execution timestamp** — There is no timestamp tied to the execution recorded in MUICache. _Why:_ MUICache proves that a program ran but cannot establish when. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — no time information derivable** — No time of execution can be derived for any entry. _Why:_ stops the analyst from inferring timing from MUICache alone; pair with a time-bearing artifact. _[IWE ch04 · Evidence of Execution / MUICache]_
- **Registry — values have no timestamps** — Registry values carry no individual timestamps; only keys do. _Why:_ general registry principle explaining why per-entry timing is impossible here. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — key last-write time exists** — The MUICache key itself has a registry last-write time. _Why:_ gives one coarse timestamp — when the key was last modified. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — no MRU list** — MUICache maintains no Most Recently Used (MRU) list ordering its entries. _Why:_ without an MRU there is no ordering or per-entry recency signal. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — last-write cannot be attributed to a specific entry** — The key's last-write time reveals only that MUICache was updated at that moment, not which of its value sets was the one updated. _Why:_ prevents overclaiming that a particular program ran at the key's last-write time. _[IWE ch04 · Evidence of Execution / MUICache]_

### Coverage across drives / execution locations

- **MUICache — non-C: drives tracked** — Entries are not limited to C:; other volumes such as a second hard drive (e.g. D:) also appear. _Why:_ analyst must review all drive letters, not just the system drive. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — mapped network drives tracked** — A mapped network drive letter (e.g. Z:) can appear in MUICache. _Why:_ evidences execution of GUI apps from network locations. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — removable/USB media tracked** — USB flash drives and other locations are recorded, provided the GUI application was actually executed from that location. _Why:_ ties execution to external media, useful for data-exfil or rogue-tool scenarios. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — execution location determines entry** — An entry is populated for a location only when a GUI app was executed from that location. _Why:_ presence of a drive/path implies actual launch from there, not mere connection. _[IWE ch04 · Evidence of Execution / MUICache]_

### Tooling / parsing

- **MUICache — no special parser required** — MUICache needs no specialized tool to read; it is a straightforward registry key. _Why:_ lowers the barrier — any registry viewer or hive parser suffices. _[IWE ch04 · Evidence of Execution / MUICache]_
- **MUICache — regedit inspection (live)** — On a live system it can be viewed directly with regedit under the HKCU mount. _Why:_ fast triage path on a running host. _[IWE ch04 · Evidence of Execution / MUICache]_

## Chapter 04 · PCA

### Origin & Versioning

- **PCA execution artifact** — The PCA-based evidence-of-execution artifact is new to Windows and first appeared in Windows 11, version 22H2. _Why:_ Establishes the earliest OS build on which the artifact can exist; absence on pre-22H2 systems is expected, not a collection failure. _[IWE ch04 · Evidence of Execution / PCA]_
- **PCA update lineage** — The artifact was introduced as part of an update to the Program Compatibility Assistant (PCA) subsystem, not as a wholly separate mechanism. _Why:_ Frames the artifact's purpose (compatibility tracking) and why it captures GUI-launched programs. _[IWE ch04 · Evidence of Execution / PCA]_
- **Longevity uncertainty** — Because the artifact is recent, its continued existence or evolution in later Windows 11 builds (or Windows 12) is not guaranteed. _Why:_ Analysts should confirm the artifact is still produced on the specific OS build under examination rather than assume persistence. _[IWE ch04 · Evidence of Execution / PCA]_
- **Reliability observation** — In testing to date the artifact has proven reliable (recorded execution times matched actual launches). _Why:_ Supports treating recovered timestamps as trustworthy pending independent validation. _[IWE ch04 · Evidence of Execution / PCA]_

### Scope of What PCA Records

- **GUI program coverage** — The PCA artifact records execution of GUI ("Gooey")-based programs. _Why:_ Defines the population of programs the artifact can evidence; command-line-only server activity may not appear. _[IWE ch04 · Evidence of Execution / PCA]_
- **CLI-from-GUI coverage** — It also records CLI programs when they are launched from the GUI. _Why:_ Extends coverage to console tools started interactively, distinguishing them from programs launched by other CLI-only mechanisms. _[IWE ch04 · Evidence of Execution / PCA]_

### Locations & Files

- **PCA directory path** — The artifact lives under `%SystemRoot%\appcompat\pca\`, where `%SystemRoot%` is typically `C:\Windows`. _Why:_ Exact collection path; sits under the same `appcompat` parent as AmCache. _[IWE ch04 · Evidence of Execution / PCA]_
- **Sibling to AmCache location** — The PCA folder shares the `appcompat` parent directory with AmCache, but AmCache is under `appcompat\programs\` while PCA is under `appcompat\pca\`. _Why:_ Helps analysts locate both related artifacts and avoid confusing the two subfolders. _[IWE ch04 · Evidence of Execution / PCA]_
- **Three text files** — The `pca` directory contains three plain-text files. _Why:_ Sets collection expectation; all three should be preserved. _[IWE ch04 · Evidence of Execution / PCA]_
- **Plain-text format** — The PCA artifacts are human-readable text files (not a registry hive or SQLite/ESE database), pipe-delimited. _Why:_ Can be reviewed directly without specialized parsers, simplifying rapid triage. _[IWE ch04 · Evidence of Execution / PCA]_

### PcaAppLaunchDic.txt (primary file)

- **Primary file of interest** — `PcaAppLaunchDic.txt` is the most important and primary file of interest among the three. _Why:_ Directs triage priority to the file with the cleanest path-plus-timestamp mapping. _[IWE ch04 · Evidence of Execution / PCA]_
- **Records full binary path** — Each entry stores the full path of the executed binary. _Why:_ Gives the on-disk location of what ran, aiding correlation with other artifacts. _[IWE ch04 · Evidence of Execution / PCA]_
- **Records last execution time** — Each entry stores the last execution time of that binary, expressed in UTC. _Why:_ Provides a directly usable execution timestamp already normalized to UTC. _[IWE ch04 · Evidence of Execution / PCA]_
- **Last-execution semantics** — The timestamp is the *last* time the binary executed, not a first-run or per-run history. _Why:_ Prevents over-reading the value as a complete run count; only the most recent launch is captured for that path. _[IWE ch04 · Evidence of Execution / PCA]_
- **Pipe delimiter** — Within each line the full path and the UTC execution time are separated by a pipe (`|`) character. _Why:_ Defines the parse rule (split on `|`) for scripted extraction. _[IWE ch04 · Evidence of Execution / PCA]_
- **Newest entries at bottom** — Recently added/most recent entries appear at the bottom of the file (example showed the latest launch as the last line). _Why:_ Tells the analyst where to look for the freshest activity when scanning the file. _[IWE ch04 · Evidence of Execution / PCA]_
- **Validated example** — In the demonstrated case an `install backblaze.exe` full path with its UTC time matched a launch the examiner had performed within the previous hour. _Why:_ Concrete evidence the recorded time reflects actual execution, reinforcing reliability. _[IWE ch04 · Evidence of Execution / PCA]_

### PcaGeneralDb0.txt / PcaGeneralDb1.txt (secondary files)

- **Two general DB files** — Two additional files, `PcaGeneralDb0.txt` and `PcaGeneralDb1.txt`, accompany the primary file. _Why:_ Completes the inventory of the three PCA files. _[IWE ch04 · Evidence of Execution / PCA]_
- **Db1 often empty** — In the examiner's testing `PcaGeneralDb1.txt` was always zero bytes. _Why:_ An empty Db1 is common and not necessarily a sign of tampering or wiping. _[IWE ch04 · Evidence of Execution / PCA]_
- **Db1 can be populated** — Others have reported finding `PcaGeneralDb1.txt` populated, so its emptiness is system-dependent. _Why:_ Analysts should still collect and check Db1 rather than assume it is always empty. _[IWE ch04 · Evidence of Execution / PCA]_
- **Db0 typically holds data** — In the demonstrated system `PcaGeneralDb0.txt` was the populated file carrying the richer records. _Why:_ Points triage to Db0 for the multi-field execution records. _[IWE ch04 · Evidence of Execution / PCA]_
- **Pipe-delimited records** — Entries in `PcaGeneralDb0.txt` contain multiple values delimited by pipe (`|`) characters. _Why:_ Same parse rule as the primary file; split on `|` to recover fields. _[IWE ch04 · Evidence of Execution / PCA]_

### PcaGeneralDb0.txt field content

- **Field: execution time (UTC)** — One field is the execution time in UTC. _Why:_ Provides the run timestamp for the record. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: run status** — One field is a "run status" value. _Why:_ Additional state metadata about the execution recorded by PCA. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: full binary path** — One field is the full path to the executed binary. _Why:_ Identifies what ran, matching the primary file's path data. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: file description** — A field may carry the binary's file description (can be empty). _Why:_ Human-readable program identification pulled from PE metadata. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: software vendor** — A field may carry the software vendor (can be empty). _Why:_ Attribution metadata for the program's publisher. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: file version** — A field may carry the file version (can be empty). _Why:_ Version identification useful for correlating specific builds. _[IWE ch04 · Evidence of Execution / PCA]_
- **Empty metadata fields** — The description/vendor/version fields can be blank, appearing as empty segments between pipe delimiters. _Why:_ Empty fields are normal; parsers must tolerate blank values without misaligning columns. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: AmCache program ID** — A field contains the AmCache program ID for the binary. _Why:_ This is the key that links a PCA record to its AmCache entry. _[IWE ch04 · Evidence of Execution / PCA]_
- **Field: exit code** — A field records the process exit code; the demonstrated example read "abnormal process exit with code x1." _Why:_ Indicates how the process terminated (e.g., abnormal exit), adding behavioral context to the execution. _[IWE ch04 · Evidence of Execution / PCA]_

### AmCache Tie-In

- **PCA↔AmCache linkage** — The AmCache program ID embedded in `PcaGeneralDb0.txt` lets an analyst join a PCA record to the corresponding AmCache entry. _Why:_ Correlation yields additional metadata (SHA-1 hash, PE details, etc.) beyond what PCA alone stores. _[IWE ch04 · Evidence of Execution / PCA]_
- **Enrichment via correlation** — Marrying PCA to AmCache through the program ID produces "even more information" than either artifact standalone. _Why:_ Justifies always pairing PCA analysis with AmCache lookup for fuller execution evidence. _[IWE ch04 · Evidence of Execution / PCA]_

### Analysis Guidance

- **Prioritize the launch-dictionary file** — For most investigations, focus first on `PcaAppLaunchDic.txt` (clean path + last-run UTC), then consult `PcaGeneralDb0.txt` for the richer multi-field records and the AmCache pivot. _Why:_ Efficient triage order: fastest answer first, deeper context second. _[IWE ch04 · Evidence of Execution / PCA]_

## Chapter 04 · Prefetch

### Nature and Purpose of Prefetch

- **Artifact origin** — Most Windows "forensic artifacts" were never designed as forensic evidence; they exist for other reasons and are repurposed by examiners. _Why:_ Frames why artifact behaviour is quirky and undocumented for forensic use. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Two artifact buckets** — Repurposed Windows artifacts generally fall into one of two categories: features added to improve user experience, or mechanisms added for backwards compatibility with older software. _Why:_ Mental model for predicting artifact behaviour and reliability. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Prefetch category** — Prefetch belongs to the user-experience-improvement bucket. _Why:_ Explains its design intent and why it exists on interactive systems. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Core purpose** — Prefetch's entire purpose is to speed up subsequent launches of applications on a Windows system. _Why:_ Its side-effects (timestamps, run counts, referenced files) are what make it forensically valuable. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Speed-up example** — A first launch that takes ~20 seconds can drop to ~5 seconds on a later launch partly because of prefetch (prefetch is one contributing factor, not the sole reason). _Why:_ Clarifies prefetch is a partial performance contributor, not the only caching mechanism. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Persistence across reboot** — The speed-up benefit persists even after the computer has been restarted. _Why:_ Confirms prefetch data is on-disk, not merely in-memory cache. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Background monitoring process** — Prefetch runs a background monitoring process for approximately 10 seconds when a program launches. _Why:_ This ~10s window is the "delta" needed to back-calculate true execution time from file-system timestamps. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **What monitoring captures** — During the monitoring window prefetch observes which files and resources the program interacts with, in order to pre-cache that data for faster future starts. _Why:_ This is the mechanism behind the "files referenced" list that reveals a binary's interactions. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **GUI and CLI coverage** — Prefetch operates on both GUI and command-line programs. _Why:_ Console tools and LOLBins run from a shell are also captured, not just windowed applications. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Storage Location

- **Not in registry** — Prefetch data itself is not stored in the registry. _Why:_ Directs the examiner to the file system, not hive parsing, for the data. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Registry holds config only** — The registry setting that enables or disables prefetch does live in the registry (covered in the registry module cheat sheet), but the artifact data does not. _Why:_ Distinguishes the on/off control point from the evidence store. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **File-system path** — Prefetch is stored on the file system under `%SystemRoot%`, which is almost always `C:\Windows\Prefetch`. _Why:_ Primary collection location for the artifact. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **File extension** — The relevant files carry a `.pf` extension. _Why:_ Filter target when triaging the Prefetch directory. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Other files present** — The Prefetch folder also contains non-`.pf` files, but the `.pf` files are the ones of interest for execution evidence. _Why:_ Avoids confusion when the examiner sees layout/DB files alongside `.pf`. _[IWE ch04 · Evidence of Execution / Prefetch]_

### File Naming and the Hash

- **Name structure** — A `.pf` file name begins with the executable's name in capital letters (e.g., `CMD.EXE`), followed by a hyphen, followed by eight hexadecimal characters. _Why:_ Lets an examiner read the source executable and detect duplicate/anomalous entries at a glance. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Hex suffix is a hash** — The eight hex characters after the hyphen are not random; they are a hash value. _Why:_ The hash encodes path/parameter provenance, so duplicates are meaningful. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Proprietary algorithm** — The hash is not MD5, SHA-1, or SHA-256; it is a proprietary hashing algorithm used specifically by the prefetching process. _Why:_ Prevents the examiner from trying to reproduce it with standard crypto hashes. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Hash input: full path** — The hash primarily incorporates the full path from which the executable was launched (e.g., `C:\temp\evil.exe`). _Why:_ Same binary run from two paths yields two different `.pf` files. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Hash input: parameters (some binaries)** — For certain executables the hash also incorporates the command-line parameters/flags used (e.g., `/flag` or `-flag`). _Why:_ Explains why some binaries produce many `.pf` files for one path. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Hexacorn reference** — Detailed write-ups of how the prefetch hash algorithm works are published by Hexacorn (multiple articles). _Why:_ Primary-source pointer for verifying/implementing the hash. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Interpreting Multiple / Duplicate Entries

- **Different hash = different origin** — Two `.pf` files for the same executable name but with different hashes indicate the executable ran from two different locations (or, for special binaries, with different parameters). _Why:_ A second `CMD.EXE-xxxx` can flag execution from an unexpected path. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Created on first launch** — `.pf` files do not pre-exist for all installed software; each is created upon the first launch of its application. _Why:_ The mere existence of a `.pf` file is evidence the program executed. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Existence proves execution** — Because a `.pf` is created on first run, its presence establishes that the named program ran on the system. _Why:_ Foundational evidence-of-execution inference. _[IWE ch04 · Evidence of Execution / Prefetch]_

### File-System Timestamps of the .pf File

- **Explorer default column** — Windows Explorer shows the Date Modified column by default; a `DIR` listing also shows the modification time by default. _Why:_ The examiner sees modification time first and must add creation time deliberately. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **MACB definition** — MACB timestamps are Modification, Access, MFT-record Change (metadata change), and Birth (creation); the C means MFT record/metadata change, not "creation." _Why:_ Prevents the common misread of C as creation. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Two timestamps used** — For prefetch analysis the examiner primarily uses the M (modification) and B (creation/birth) timestamps of the `.pf` file. _Why:_ These two map to last and first execution respectively. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Creation = first run** — The `.pf` file's creation timestamp corresponds to the first time the program was executed (it was created on that first launch), minus the monitoring delta. _Why:_ Yields first-execution time. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Modification = last run** — The `.pf` file's modification timestamp corresponds to the last execution, because each run both reads and updates the `.pf` file, minus the monitoring delta. _Why:_ Yields most-recent-execution time. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Read-and-update on run** — Every time a program runs, prefetch reads its `.pf` (to speed launch) and updates/rewrites it (bumping the modification time). _Why:_ Explains why modification time tracks the latest run. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Second precision via Properties** — The file Properties dialog shows timestamps to second precision, versus Explorer's minute-level display. _Why:_ Needed for accurate timelining and delta subtraction. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Timestamps are local** — Timestamps displayed by Explorer/Properties are in the machine's local time zone; convert to UTC for forensic reports and timelines. _Why:_ Avoids time-zone errors in cross-system correlation. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Monitoring delta rule of thumb** — Subtract a delta (rule of thumb ~10 seconds) from the creation and modification timestamps to approximate first and last execution. _Why:_ Corrects for the monitoring window built into the timestamps. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Delta is not fixed** — Some documentation claims the delta is always 10 seconds; that is not true. The actual monitoring duration varies. _Why:_ Blindly subtracting 10s introduces error; treat it as approximate. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Delta varies by complexity** — A complex program (e.g., Photoshop) may use the full ~10s of monitoring, while a simple one (e.g., cmd.exe) may finish in sub-second to one or two seconds. _Why:_ Delta must be inferred per-binary, ideally from the pf's own last-run timestamp. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Ran at least twice** — When the creation and modification timestamps differ, the program ran at least twice. _Why:_ Quick lower-bound on execution count from file-system metadata alone. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Count not derivable from timestamps** — File-system timestamps alone cannot give the total run count; that value lives inside the `.pf` file. _Why:_ Directs the examiner to parse the pf for a precise count. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Maximum File Counts and OS Scope

- **XP–Windows 7 cap** — Windows XP through Windows 7 allow a maximum of 128 `.pf` files. _Why:_ Bounds how far back execution history can reach on legacy systems. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Windows 8+ cap** — Windows 8 and later raise the cap to 1024 `.pf` files, deleting the oldest first; on the 1025th, the oldest ages out. This holds through current Windows. _Why:_ Larger history window on modern systems; also explains gaps for very old activity. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Desktop-only by default** — Prefetch is enabled by default only on Windows desktop operating systems. _Why:_ Sets expectation for where the artifact will and won't exist. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Server folder empty** — On a Windows Server OS the Prefetch folder is empty by default because prefetch is not enabled there. _Why:_ Absence of prefetch on a server is normal, not evidence of wiping. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Rationale for server default** — Disabling on servers makes sense because servers are not expected to be used interactively for daily apps (Photoshop, Word, browsers). _Why:_ Contextualises the default and its exceptions. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Registry can flip default** — A registry setting can disable prefetch on a desktop OS or enable it on a server OS. _Why:_ Examiner should not assume default state; check the config value. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Overrides rare in practice** — In real-world casework, neither override (disabling on desktop or enabling on server) is commonly seen. _Why:_ Baseline expectation, with the config still worth verifying. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Data Stored Inside the .pf File

- **Total run count** — The `.pf` file records the total number of times the executable has run. _Why:_ Exact execution frequency, not just first/last. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Last eight run times (Win8+)** — Starting with Windows 8, the `.pf` file stores the last eight execution times. _Why:_ Provides multiple recent run timestamps for timelining. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Nine total timestamps** — Combining the creation timestamp (first run, minus delta) with the eight stored run times yields up to nine known execution times. _Why:_ Defines the full set of execution moments an examiner can recover. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Middle runs unknowable** — For a program run many times (e.g., 100), only the first and the last eight runs are recoverable; an arbitrary middle run (e.g., the 56th, 22nd, 15th) cannot be determined. _Why:_ Sets the limits of execution-history reconstruction. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Referenced files tracked** — The files a binary interacts with are recorded in its `.pf` file (because prefetch monitored them to cache them). _Why:_ Turns prefetch into an interaction/data-touch artifact, not just execution proof. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Compression-utility example** — Parsing the `.pf` for a compression tool (e.g., WinRAR / `rar.exe`) may reveal the actual files that were zipped/compressed, because those files were interacted with during the monitored run. _Why:_ Can show what data an actor staged or exfiltrated. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Directories plus files** — A parsed `.pf` lists both directories interacted with and individual files referenced. _Why:_ Reveals working locations and specific data touched. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Parameters in the Hash — Special Binaries

- **svchost many entries** — `svchost.exe` produces many `.pf` files because its command-line parameters are folded into the hash. _Why:_ Explains a normally-large svchost `.pf` population so it isn't misread as anomalous. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **svchost ubiquity** — `svchost.exe` is one of the most ubiquitous processes in Windows. _Why:_ Context for both its many pf files and its abuse by malware. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **svchost impersonation** — Malware frequently disguises itself as `svchost.exe` because the name is so common and ubiquitous. _Why:_ Prompts the examiner to verify the true path of any svchost pf. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **svchost -k flag** — Every legitimate `svchost.exe` runs with a `-k` flag plus a following parameter, and that parameter is included in the hash calculation. _Why:_ Explains the mechanism behind multiple distinct svchost pf files. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Four parameter-hashing binaries** — `svchost.exe`, `dllhost.exe`, `rundll32.exe`, and `mmc.exe` all include their command-line parameters (not just the path) in the hash calculation. _Why:_ These four legitimately yield multiple pf files per path. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Possibly more binaries** — Other executables may also fold parameters into the hash beyond the four named. _Why:_ The list is not necessarily exhaustive; treat it as known-examples. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **cmd param demo (negative)** — Running `cmd /c calc.exe` did not create a new `cmd.exe` `.pf`; the existing one was merely updated, confirming `cmd.exe` does not fold parameters into its hash. _Why:_ Demonstrates the parameter-hashing behaviour is binary-specific. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **mmc param demo (positive)** — Running `mmc.exe /hello...` (a bogus, invalid parameter) created a new (fourth) `mmc.exe` `.pf`, proving parameters drive mmc's hash. _Why:_ Confirms even an invalid parameter yields a distinct pf. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Single-run identical timestamps** — The freshly-created mmc `.pf` had identical creation and modification timestamps because it had run exactly once with that parameter. _Why:_ Equal M and B timestamps indicate a single execution. _[IWE ch04 · Evidence of Execution / Prefetch]_

### 32-bit vs 64-bit and SysWOW64

- **System32 holds 64-bit** — On a 64-bit Windows system, 64-bit binaries reside in `%SystemRoot%\System32` (counterintuitively named). _Why:_ Path in a pf tells you the binary's bitness/origin. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SysWOW64 holds 32-bit** — The `SysWOW64` directory stores the 32-bit binaries on a 64-bit system. _Why:_ Execution out of SysWOW64 can indicate 32-bit (often malicious) code. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Malware bitness trend** — Most in-the-wild malware is still written as 32-bit. _Why:_ Raises baseline suspicion for SysWOW64 execution. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Compatibility asymmetry** — 32-bit code runs fine on 64-bit systems, but 64-bit code does not run on 32-bit systems. _Why:_ Explains why attackers choose 32-bit for maximum reach. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Malware-author incentive** — To maximise the number of endpoints their code runs on, malware authors compile as 32-bit. _Why:_ Justifies watching SysWOW64 activity. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Cross-bitness call rule** — A 32-bit binary cannot call a 64-bit binary; it can only call another 32-bit binary. _Why:_ 32-bit malware pulls in 32-bit SysWOW64 LOLBins, which then surface in prefetch. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **LOLBin definition** — Living-off-the-land binaries are pre-existing legitimate binaries on the system that threat actors leverage for malicious purposes. _Why:_ Names the category of abuse prefetch can help detect. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SysWOW64 cmd demo** — Launching the SysWOW64 (32-bit) `cmd.exe` created a second `cmd.exe` `.pf` with a different hash, because it ran from a different path. _Why:_ Live proof that path drives the hash and produces duplicate-name pf files. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **32-bit cmd is suspicious** — Explicit execution of the 32-bit `cmd.exe` from SysWOW64 does not normally happen organically and may indicate a 32-bit malware invoked it. _Why:_ Investigative lead worth pivoting on. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Parse to confirm path** — To determine which path a duplicate-name `.pf` truly points to, parse the file. _Why:_ The 8-hex hash alone doesn't reveal the path; parsing does. _[IWE ch04 · Evidence of Execution / Prefetch]_

### PECmd Tool (Eric Zimmerman)

- **Tool and location** — `PECmd.exe` is Eric Zimmerman's prefetch parser (found in the net6 build of his tools). _Why:_ Standard tooling for pf analysis. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **`-f` single file** — The `-f` flag processes a single prefetch file. _Why:_ Targeted analysis of one pf. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **`-d` directory** — The `-d` flag processes an entire directory of prefetch files. _Why:_ Bulk parsing of the whole Prefetch folder. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Output formats** — PECmd can write output to CSV, JSON, and HTML. _Why:_ Feeds timelines/review pipelines in the analyst's preferred format. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **VSS flag** — A `--vss` (volume shadow copy) flag makes PECmd also traverse Volume Shadow Copies and extract prefetch from them. _Why:_ Recovers historical/deleted prefetch and extends the visible event horizon. _[IWE ch04 · Evidence of Execution / Prefetch]_

### PECmd Output Fields

- **Keyword color-coding** — PECmd color-codes "keywords" in its output to make notable strings stand out. _Why:_ Speeds visual triage of parsed output. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **TMP/TEMP highlighted** — References to `TMP`/`TEMP` locations are color-coded because temp paths are often of interest. _Why:_ Draws attention to execution/data staging from temp directories. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Custom keyword list** — The keyword highlight list is customizable; the examiner can add their own terms to color-code. _Why:_ Tailor output to case-specific indicators. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **File-system timestamps shown** — Output includes the `.pf` file's own creation, modification, and last-access timestamps from the file system. _Why:_ Basis for first/last execution derivation. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Executable name field** — Output shows the executable name. _Why:_ Confirms which binary the pf represents. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Hash field** — Output shows the prefetch hash value. _Why:_ Correlates with the pf file name and path derivation. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Original file size** — Output shows the original file size of the monitored executable. _Why:_ Useful identifying metadata, especially when the binary is gone. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **pf survives binary deletion** — Deleting or even securely wiping a binary does not automatically delete its `.pf`; prefetch can persist for executables no longer on the system, retaining the file-system timestamps and original file size. _Why:_ Recovers evidence of programs an actor removed. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Prefetch version field** — Output reports the prefetch format version in use (e.g., the Windows 10/11 version). _Why:_ Confirms OS-era and correct parsing assumptions. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Run count field** — Output shows the total run count (e.g., 31 times in the demo). _Why:_ Precise execution frequency. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Last run time field** — Output shows the last run time. _Why:_ Most-recent execution moment from inside the pf. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Delta cross-check demo** — In the demo, modification time 16:20:19 vs. last runtime 16:20:18 gives a 1-second delta, so monitoring of `cmd.exe` took ~1 second (not the full 10). _Why:_ Shows deriving the true per-binary delta by comparing modification time to the stored last-run time. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Eight run times listed** — Output lists the eight stored run times (the single last run plus the other seven). _Why:_ Provides the recoverable recent execution history. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Approximated first run** — First execution is approximated as the creation timestamp minus the (per-binary inferred) delta. _Why:_ Gives a defensible first-run estimate. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Volume information / serial** — Output includes volume information including the volume serial number. _Why:_ Ties execution to a specific volume, useful for multi-volume/removable-media correlation. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Directories referenced** — Output lists the directories referenced by the binary. _Why:_ Reveals working/interaction locations. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Files referenced** — Output lists the files referenced, including the executable itself (flagged with an "executable true" marker) plus the DLLs and files the program needs to function. _Why:_ Full interaction inventory; the executable's own full path confirms its origin. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Compressed files may appear** — For a compression utility, the "files referenced" section may contain the actual files that were compressed/zipped. _Why:_ Directly evidences data an actor archived. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SysWOW64 pf parse** — Parsing the 32-bit `cmd.exe` pf showed run count 1, directories/executable path under SysWOW64, and a ~4-second delta (11 vs 15) for that first run's monitoring. _Why:_ Confirms path-in-pf reveals bitness and that delta differs per run. _[IWE ch04 · Evidence of Execution / Prefetch]_

### Deletion, Anti-Forensics, and SDelete

- **Deletion does not break OS** — Deleting `.pf` files does not crash the operating system; affected programs still run, only slightly slower on the next launch. _Why:_ Explains why deletion is a low-risk anti-forensic move for an actor. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **pf recreated on next run** — After a `.pf` is deleted, the program simply recreates it on the next execution. _Why:_ A "new" pf may mask prior history. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Misleading first-run after deletion** — A recreated `.pf` shows a creation timestamp reflecting the first run since deletion, which can be misread as the program's true first-ever execution. _Why:_ Guards against over-claiming "first executed on" from a possibly-recreated pf. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Deletion is common anti-forensics** — Deleting prefetch files is a common anti-forensics technique that can undermine execution conclusions. _Why:_ Prompts corroboration from other execution artifacts. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Prefetch Deep Dive reference** — A ~45-minute "Prefetch Deep Dive" episode covers prefetch in greater depth, including memory forensics aspects of prefetch. _Why:_ Pointer to deeper coverage (incl. in-memory prefetch structures). _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SDelete definition** — SDelete is a Sysinternals secure file-wiping tool that renders files unrecoverable. _Why:_ Names the specific anti-forensic tool in the demo. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Mass wipe survives** — Securely wiping every prefetch file (e.g., ~400) with SDelete does not crash the system. _Why:_ Confirms bulk destruction is operationally safe for an actor. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SDelete self-incrimination** — Running SDelete itself creates a `.pf` for SDelete. _Why:_ The anti-forensic act leaves its own execution artifact. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **SDelete pf is parsable** — SDelete's `.pf` is a normal, parsable prefetch file. _Why:_ Recoverable evidence about the wiping run. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Wiped files listed in SDelete pf** — SDelete's "files referenced" list contains the very prefetch files it just deleted (e.g., calc, Chrome, cmd), because SDelete interacted with them during the monitored run. _Why:_ Prefetch can recover the names of files an anti-forensic tool destroyed. _[IWE ch04 · Evidence of Execution / Prefetch]_
- **Referenced-files power** — This shows prefetch's value extends beyond evidence of execution to a record of files a binary referenced/touched. _Why:_ Reframes prefetch as an interaction artifact, not merely an execution flag. _[IWE ch04 · Evidence of Execution / Prefetch]_

## Chapter 04 · SRUM

### Identity and scope

- **SRUM acronym** — "SRUM" expands to System Resource Utilization Monitor and is pronounced/abbreviated S-R-U-M. _Why:_ Correctly naming the artifact anchors documentation and tool searches. _[IWE ch04 · Evidence of Execution / SRUM]_
- **SRUM as more than execution evidence** — SRUM records extend well past mere program-execution evidence; it belongs to the execution-evidence category only by convenience of grouping. _Why:_ Sets expectations that the artifact answers network- and resource-usage questions, not just "did it run." _[IWE ch04 · Evidence of Execution / SRUM]_
- **Categories tracked** — SRUM tracks energy usage, network-related connectivity, push-notification data, and detailed application usage. _Why:_ Defines the four evidentiary domains an examiner can query from a single artifact. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Retention window** — SRUM data typically covers a rolling period of roughly 30 to 60 days. _Why:_ Bounds how far back the artifact can answer questions; older activity has aged out. _[IWE ch04 · Evidence of Execution / SRUM]_

### User-facing surface

- **Task Manager App History is SRUM** — The "App History" tab in Windows Task Manager (opened via Ctrl+Shift+Escape) is populated directly from SRUM data. _Why:_ Confirms the artifact's fidelity — the same data an examiner parses is what Windows shows the user. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Task Manager shortcut** — Task Manager opens with the keyboard shortcut Ctrl+Shift+Escape. _Why:_ Fast live-triage path to preview SRUM-derived app history. _[IWE ch04 · Evidence of Execution / SRUM]_

### Storage format and on-disk location

- **Backend is a database** — Behind the Task Manager view, SRUM information is stored in a database file, not flat logs. _Why:_ Dictates that parsing requires an ESE-capable tool, not text tooling. _[IWE ch04 · Evidence of Execution / SRUM]_
- **ESE / JET Blue format** — The SRUM database uses the ESE (Extensible Storage Engine) format, also historically called JET Blue. _Why:_ Determines which parser/library (ESEDB-aware) is needed and that transaction-log semantics apply. _[IWE ch04 · Evidence of Execution / SRUM]_
- **ESE is reused across Windows artifacts** — The ESE/JET Blue format underlies numerous other Windows forensic artifacts, not just SRUM. _Why:_ Skills and tooling for one ESE artifact transfer to others (e.g., Windows Search, WebCacheV01). _[IWE ch04 · Evidence of Execution / SRUM]_
- **Database directory** — The SRUM database lives under %SystemRoot%\System32\sru (with %SystemRoot% normally resolving to C:\Windows). _Why:_ Exact acquisition path for the artifact. _[IWE ch04 · Evidence of Execution / SRUM]_
- **%SystemRoot% resolution** — %SystemRoot% typically resolves to C:\Windows. _Why:_ Lets an examiner translate the environment-variable path to a literal path on an imaged drive. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Main database filename** — The database file itself is named SRUDB.dat inside the sru folder. _Why:_ The single primary file to target for parsing. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Supporting files in the sru folder** — Alongside SRUDB.dat, the sru directory contains transaction logs and other supporting files. _Why:_ These logs may hold un-committed records; collecting them enables proper replay before parsing. _[IWE ch04 · Evidence of Execution / SRUM]_

### Acquisition

- **File is locked on a live system** — On a running system SRUDB.dat is locked and in use, so a naive copy captures it in a dirty (inconsistent, un-replayed) state. _Why:_ Explains why plain file copy is unreliable and why alternate acquisition methods are needed. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Dirty-state risk** — Copying the in-use database yields data in a dirty state because outstanding transactions have not been flushed/replayed into it. _Why:_ Motivates using VSS, forensic imagers, or replaying logs to obtain a clean database. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Acquisition option — Volume Shadow Copy** — A Volume Shadow Copy can serve as a source from which to extract the SRUM database. _Why:_ Provides a consistent, non-locked copy and potentially historical versions of the database. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Enumerating shadows** — `vssadmin list shadows` lists available Volume Shadow Copies to check whether any exist to pull the database from. _Why:_ First step to determine if a shadow-based acquisition is viable. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Acquisition option — KAPE** — KAPE has a dedicated target that easily collects the SRUM artifact. _Why:_ Automates correct, complete collection (database plus supporting files) at triage speed. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Acquisition option — FTK Imager** — FTK Imager can export the SRUM files off a mounted physical drive. _Why:_ A common forensic imager path when working from a live disk or attached evidence drive. _[IWE ch04 · Evidence of Execution / SRUM]_
- **FTK Imager workflow** — In FTK Imager, add the OS physical drive as an evidence item (File → Add Evidence Item → Physical Drive), then drill down root → Windows → System32 → sru. _Why:_ Reproducible manual export path for the SRUM directory. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Export the whole sru folder** — Rather than exporting individual files, export the entire sru folder (right-click sru → Export Files) so SRUDB.dat and its transaction logs travel together. _Why:_ Keeping logs with the database allows a clean replay/parse and avoids missing uncommitted records. _[IWE ch04 · Evidence of Execution / SRUM]_

### SOFTWARE hive dependency

- **Also collect the SOFTWARE registry hive** — In addition to the sru folder, acquire the SOFTWARE registry hive to enrich SRUM parsing. _Why:_ The parser uses it to add context the database alone lacks. _[IWE ch04 · Evidence of Execution / SRUM]_
- **SOFTWARE hive location** — The SOFTWARE hive resides under System32\config. _Why:_ Exact path to collect the hive during the same acquisition pass. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Collect the hive's transaction logs too** — When exporting the SOFTWARE hive, also grab its transaction log files (the three files together). _Why:_ Log replay ensures the hive is current before name resolution. _[IWE ch04 · Evidence of Execution / SRUM]_
- **What the SOFTWARE hive resolves** — The SOFTWARE hive lets the parser resolve network profile names within the network information SRUM records. _Why:_ Turns opaque network identifiers into human-meaningful network names. _[IWE ch04 · Evidence of Execution / SRUM]_
- **SSID recovery** — Via the SOFTWARE hive, SRUM network data can be enriched with the SSID (the wireless network name) the computer connected to. _Why:_ Places the machine on specific named Wi-Fi networks — strong location/attribution evidence. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Co-locate hive with sru export** — Place the exported SOFTWARE hive (and its logs) into the same sru folder as the database so a directory-mode parse finds everything. _Why:_ Enables the single-directory (-d) parsing convenience below. _[IWE ch04 · Evidence of Execution / SRUM]_

### Parsing with SrumECmd

- **Parser tool — SrumECmd** — SrumECmd (Eric Zimmerman tool, .NET) parses the SRUM database into CSV output. _Why:_ The recommended, fast parser for this artifact in the EZ toolset. _[IWE ch04 · Evidence of Execution / SRUM]_
- **-f flag (single file)** — `-f` points SrumECmd at a single loose SRUDB.dat file. _Why:_ Use when you have only the database file and no surrounding folder. _[IWE ch04 · Evidence of Execution / SRUM]_
- **-d flag (directory)** — `-d` points SrumECmd at a directory; in this mode it automatically looks for both SRUDB.dat and the SOFTWARE hive within that directory. _Why:_ One-shot parse that auto-enriches with network profile names when the hive is co-located. _[IWE ch04 · Evidence of Execution / SRUM]_
- **-d was built for KAPE** — The directory (-d) auto-discovery behavior was primarily added to support KAPE acquisitions, but works for any correctly assembled directory. _Why:_ Explains why placing the hive beside the database "just works" and can be leveraged outside KAPE. _[IWE ch04 · Evidence of Execution / SRUM]_
- **--csv flag** — `--csv` specifies the output directory into which SrumECmd writes the CSV files. _Why:_ Directs output to a known location for review. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Multiple CSV outputs** — A single SrumECmd run emits multiple CSV files, one per SRUM data table. _Why:_ Each table (app resource, app timeline, network usage, network connectivity, energy, push notifications) becomes its own CSV. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Run confirms inputs found** — On execution SrumECmd reports that it located the SRUM database file and the SOFTWARE hive. _Why:_ A quick sanity check that enrichment will occur; absence of the hive line signals missing network-name resolution. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Run prints a per-category count** — SrumECmd prints a count summary of what it found per category (e.g., Energy Usage, Push Notifications, Network). _Why:_ Lets the examiner gauge data volume and spot empty tables before opening CSVs. _[IWE ch04 · Evidence of Execution / SRUM]_

### Output tables / CSV files

- **CSV: AppResourceUseInfo** — One output CSV is AppResourceUseInfo, holding detailed per-application resource-usage records. _Why:_ Primary source for how long/how intensively an app ran and foreground/background state. _[IWE ch04 · Evidence of Execution / SRUM]_
- **CSV: AppTimelineProvider** — Another output CSV is AppTimelineProvider, an application-timeline table. _Why:_ Corroborates that specific executables ran, with an executable-metadata timestamp. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Two network CSVs** — SRUM output includes two network-related CSVs: one for network connectivity (which interface was connected when) and one for network usage (bytes per app). _Why:_ Together they answer "which network, when" and "how much data, by which app." _[IWE ch04 · Evidence of Execution / SRUM]_
- **Four highest-value CSVs** — In Davis's assessment the four most useful CSVs are the two App-related files (AppResourceUseInfo, AppTimelineProvider) and the two Network files (connectivity, usage). _Why:_ Prioritizes review effort on the tables that most often carry investigative value. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Energy and Push Notification tables are lower yield** — Additional tables such as Energy Usage and Push Notifications exist but are generally less investigatively useful than the app/network tables. _Why:_ Sets triage priority; don't over-invest in the energy/notification CSVs. _[IWE ch04 · Evidence of Execution / SRUM]_

### AppResourceUseInfo fields and semantics

- **Timestamp — when logged** — AppResourceUseInfo carries a timestamp marking when the record was logged to the database. _Why:_ Anchors resource-usage samples to wall-clock time. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Hourly write cadence** — SRUM resource-usage records are typically written about once per hour, depending on when the computer was actually active. _Why:_ Timing granularity is ~1 hour, so SRUM shows activity within an hour window, not to the second — and idle periods produce no rows. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Field — Executable Info** — Each record identifies the executable (application) involved. _Why:_ Attributes resource usage to a specific program. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Field — User Name** — Records include the associated user name. _Why:_ Attributes activity to a specific account. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Fields — SID and SID Type** — Records include the SID and a SID Type field. _Why:_ Precisely identifies the security principal (and distinguishes user vs. service/well-known SIDs). _[IWE ch04 · Evidence of Execution / SRUM]_
- **Fields — Background bytes read/written** — Records capture background bytes read and written by the application. _Why:_ Quantifies disk/IO activity attributable to background operation. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Fields — Context Switches and Cycle Times** — Records include context-switch counts and CPU cycle-time metrics. _Why:_ Low-level evidence of how much processing the app performed. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Foreground vs. background flag** — Records indicate whether the application was in the foreground or background. _Why:_ Distinguishes active user interaction from background execution. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Active-window / focus duration** — From these records an examiner can infer how long a user actually had an application up and running as the active (topmost, in-focus) window. _Why:_ Directly evidences deliberate user interaction time with a specific app. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Per-profile usage** — The resource records tie usage to profile/account, giving profile-level usage information per application. _Why:_ Supports multi-user attribution on shared machines. _[IWE ch04 · Evidence of Execution / SRUM]_

### AppTimelineProvider fields and semantics

- **Contains Executable Info** — AppTimelineProvider records identify the executable that ran. _Why:_ Independent corroboration that a given program executed. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Timestamp — DB write time** — Its Timestamp field reflects when the entry was actually written/populated into the database. _Why:_ Provides a database-side time for when the activity was recorded. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Exe Timestamp field** — AppTimelineProvider also has an "Exe Timestamp" pulled from metadata inside the executable itself. _Why:_ A second, program-intrinsic time distinct from the logging time. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Exe Timestamp ≈ compilation time** — In Davis's testing the Exe Timestamp generally aligns with the executable's compilation time embedded in the binary (PE header). _Why:_ Lets an examiner reason about the build age of the program that ran, and flag time-stomped or oddly-dated binaries. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Two distinct timestamps must not be conflated** — The record's write Timestamp (when logged to the DB) and the Exe Timestamp (binary metadata/compile time) mean different things and should be interpreted separately. _Why:_ Prevents misdating execution by confusing compile time with run/log time. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Evidence of execution** — Because AppTimelineProvider lists programs that ran, finding a specific executable there establishes that it executed on the system. _Why:_ Serves as a corroborating execution-evidence source. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Self-referential example** — Timeline Explorer (the review tool) itself appears in AppTimelineProvider, illustrating that recently used programs are captured. _Why:_ Demonstrates SRUM's coverage of ordinary interactive-app usage. _[IWE ch04 · Evidence of Execution / SRUM]_

### Network connectivity table

- **Records active interface over time** — The network connectivity table records which network interface was active and connected at any given time, with an interface ID. _Why:_ Reconstructs when the machine was network-connected and via which adapter. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Interface ID field** — Connectivity records include an interface ID identifying the specific adapter. _Why:_ Correlates connectivity to a particular NIC/interface. _[IWE ch04 · Evidence of Execution / SRUM]_

### Network usage table

- **Per-executable network usage** — The network usage table breaks data down to a specific executable, letting you find network activity by a named application. _Why:_ Attributes byte transfer to the exact program responsible. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Username association** — Network usage records include the username associated with the activity. _Why:_ Attributes network transfer to a specific account. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Bytes Sent and Bytes Received** — Records report Bytes Sent and Bytes Received per application. _Why:_ Quantifies data volume — key for detecting exfiltration or heavy transfers by a given app. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Interface and Interface Type** — Records include the Interface and Interface Type fields for each usage entry. _Why:_ Distinguishes wired vs. wireless vs. other transports carrying the traffic. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Example apps observed** — Real records showed third-party apps such as Backblaze (backup software) and PowerToys, each tied to a user with byte counts and interface data. _Why:_ Illustrates that SRUM captures ordinary background/utility software's network behavior at per-app granularity. _[IWE ch04 · Evidence of Execution / SRUM]_

### Investigative value and review tooling

- **Combined investigative reach** — From SRUM an examiner can determine which applications were active and when, how long they were active, how long they were in focus as the topmost window, and how much data each transferred. _Why:_ A single artifact answers execution, user-interaction, and data-transfer questions together. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Network connectivity is high value** — Davis rates the network-connectivity data as especially valuable in past investigations. _Why:_ Placing a machine on specific networks at specific times supports timeline and location analysis. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Review in Timeline Explorer** — The CSV outputs are reviewed in Eric Zimmerman's Timeline Explorer. _Why:_ Standard EZ-tool viewer for sorting/filtering the multi-column CSVs. _[IWE ch04 · Evidence of Execution / SRUM]_
- **Launch Timeline Explorer first for tabbed view** — Launching Timeline Explorer first, then File → Open and selecting all four CSVs, opens them as tabs in one window; double-clicking the CSVs individually instead opens four separate windows. _Why:_ Practical gotcha for keeping related SRUM tables together during review. _[IWE ch04 · Evidence of Execution / SRUM]_

## Chapter 04 · ShimCache

### Naming and Purpose

- **ShimCache identity** — ShimCache, AppCompatCache, and Application Compatibility Cache are three names for the same single artifact. _Why:_ Reports and tools use the terms interchangeably; recognising the equivalence avoids treating them as separate evidence sources. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Artifact category** — ShimCache exists to provide backwards compatibility for older software, not to improve user experience (the category Prefetch falls into). _Why:_ Understanding the design intent explains why it is being repurposed forensically and why its data is quirky. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Design goal** — ShimCache was created so older software could still run on newer versions of Windows. _Why:_ Frames the artifact's original engineering purpose. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Mechanism** — It works by building and maintaining what amounts to a database of executables from across the system. _Why:_ Establishes that it is a system-wide inventory of binaries. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Tracks regardless of shimming** — On modern Windows, the database tracks executables whether or not they ultimately needed to be shimmed. _Why:_ Presence in ShimCache does NOT mean a shim was applied; the cache is an inventory, not a shim-applied list. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Windows XP contrast** — On Windows XP this was NOT the case (it did not track everything regardless of shimming); the track-everything behaviour is a modern-ShimCache trait. _Why:_ Behaviour is version-dependent; XP-era assumptions do not transfer to modern systems. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Definition of a shim** — A "shim" means extra properties or settings are applied to an executable so it runs on a newer OS than it was designed for. _Why:_ Clarifies the compatibility-layer concept underlying the artifact. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Storage Location

- **Not a conventional database** — The ShimCache "database" is not SQLite, not ESE, and not a traditional database file; it lives entirely in the Windows Registry. _Why:_ Directs the examiner to the registry, not a standalone DB file. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Hive** — The data is stored in the SYSTEM registry hive. _Why:_ Identifies which hive to acquire/parse. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **On-disk hive path** — The SYSTEM hive on disk is at %SystemRoot%\System32\config\SYSTEM. _Why:_ The physical file to pull for dead-box parsing. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Live registry path root** — In regedit on a live system the hive appears under HKEY_LOCAL_MACHINE (HKLM) > SYSTEM. _Why:_ Maps the live-system view to the on-disk hive. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Full live key path** — The artifact is at HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache. _Why:_ The exact key to navigate on a live/running system. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Subkey and value both named AppCompatCache** — Under Session Manager there is a subkey named AppCompatCache, and inside it a value ALSO named AppCompatCache. _Why:_ The nested identical naming is where the actual cache bytes reside; the value (not the subkey alone) holds the data. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Data source for parsers** — The AppCompatCache value is the location from which every parsing tool pulls the actual ShimCache entries. _Why:_ Confirms the single authoritative data blob tools decode. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Control Sets

- **CurrentControlSet is live-only** — CurrentControlSet appears only on a live and running system; it is a runtime pointer, not a stored key. _Why:_ Explains why dead-box images lack it. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Dead-box shows ControlSet00N** — On a disk image / dead-box registry you see ControlSet001 (and possibly ControlSet002, ControlSet003, etc.) instead of CurrentControlSet. _Why:_ Sets expectations for offline analysis. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Dead-box is the usual case** — Dead-box forensics (parsing from a disk image) is almost always the situation, versus live parsing. _Why:_ Frames the common workflow. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Parse all control sets** — Best practice is to parse ShimCache from every available control set, and most tools default to this. _Why:_ Each control set carries its own copy, so parsing all maximises recovered entries. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Do not assume 001 is current** — You cannot assume ControlSet001 is the most recent control set in use when more than one exists. _Why:_ Prevents a wrong "current" attribution. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Determining the current control set** — Consult SYSTEM\Select and its "Current" value to find which control set was most recently in use. _Why:_ The authoritative pointer to the active control set. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Select\Current example** — In the demo, Select\Current = 1, consistent with there being only one control set on that machine. _Why:_ Illustrates how the value maps to a control-set number. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Entry Caps (Maximum Entries)

- **Windows XP cap** — Maximum ShimCache entries on Windows XP is 96. _Why:_ Bounds how much history XP can retain. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Server 2003 cap** — Maximum entries on Server 2003 is 512. _Why:_ Version-specific ceiling. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Server 2008 and later cap** — Maximum entries on Server 2008 and later is 1,024. _Why:_ Version-specific ceiling. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Vista and later cap** — Maximum entries on Vista and later is also 1,024. _Why:_ Version-specific ceiling matching modern desktop Windows. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Modern desktop cap** — Modern Windows (Windows 8 and later) caps at 1,024 entries. _Why:_ The practical ceiling on current systems. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Cap is per control set** — Two control sets (e.g. ControlSet001 + ControlSet002) can yield up to 2,048 total entries, because each control set holds its own ~1,024-entry ShimCache copy. _Why:_ Total recoverable entries can exceed the single-cache cap; do not treat 1,024 as the absolute maximum for the image. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Demo entry count** — In the live demo AppCompatCacheParser reported exactly 1,024 cache entries on the Windows 11 test box. _Why:_ Confirms the modern cap in practice. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### What Gets Tracked (Volumes)

- **Tracks more than C:** — ShimCache tracks executables beyond just the C: drive. _Why:_ Widens the evidence surface. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **"Sysvol" label** — Within ShimCache the C: drive (system volume) is referred to as "Sysvol". _Why:_ Examiners must recognise "Sysvol" in output as the system drive path prefix. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Other/mapped drives tracked** — ShimCache can track binaries on other drive letters such as D:, M:, X:, Z:, including mapped network locations. _Why:_ Execution/presence from network shares can surface here. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **USB drives tracked** — Executables on USB drives can also be tracked in ShimCache. _Why:_ Removable-media binaries may leave ShimCache traces. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Execution vs Presence (the CRITICAL nuance)

- **Windows XP execution semantics** — On Windows XP, anything in ShimCache had actually executed, so presence implied execution with reasonable confidence. _Why:_ XP is the one era where ShimCache ≈ execution evidence. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Modern ShimCache ≠ execution** — On modern Windows, presence in ShimCache does NOT mean the binary executed; it records that the binary was seen/enumerated, not that it ran. _Why:_ The single most misused fact about this artifact — presence is not proof of execution. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Vista through 8.1 execution indicator** — From Windows Vista through Windows 8.1, execution could only be inferred from the presence of an "InsertFlag" set to a specific value. _Why:_ Version-bounded method for execution inference. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **"Execution flag" is a myth/misnomer** — The community labelled the InsertFlag an "execution flag," but there was never an actual execution flag in ShimCache; it was an InsertFlag whose specific value the community interpreted as execution. _Why:_ Corrects a widespread misconception that could overstate a finding. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **InsertFlag reliability** — Seeing the InsertFlag with its specific value meant, with reasonable confidence (not certainty), that the item had executed. _Why:_ Even on Vista–8.1 the inference is probabilistic. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Windows 10 removed the InsertFlag** — Starting with Windows 10 in 2015, the InsertFlag / "execution flag" went away. _Why:_ Marks the point where the old execution-inference method stopped working. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Post-2015 belief** — For years after Windows 10 shipped, the community held that ShimCache on Windows 10+ could not be used to determine execution at all. _Why:_ Documents the (now-superseded) consensus; older training/reports reflect it. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Eric Zimmerman March 2023 research** — In March 2023 Eric Zimmerman researched and found four bytes present at the end of each ShimCache entry. _Why:_ The discovery that revived execution inference on Windows 10+. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Four-byte execution indicator** — If those four trailing bytes equal 1, it is reasonably confident that that particular binary executed. _Why:_ The modern (Win10+) execution-inference rule. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Applies only to non-native binaries** — The four-byte = 1 execution indicator holds today only for non-native Windows binaries (third-party executables). _Why:_ Scopes the reliability boundary of the indicator. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Definition of non-native** — "Non-native" means NOT built-in Windows binaries — not cmd.exe, not powershell.exe — but rather third-party binaries. _Why:_ Defines which files the indicator can classify. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Native binaries not tracked properly** — For native Windows binaries (cmd, PowerShell, etc.) the execution determination is not applicable; ShimCache does not track their execution status properly, for reasons unknown, as of the recording. _Why:_ Prevents false "did not execute" conclusions about system binaries. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Indicator existed since 2015 but undiscovered until 2023** — The four-byte behaviour was technically present since the original Windows 10 release (2015) but was not discovered/usable for execution determination until Zimmerman's March 2023 work. _Why:_ Explains why old tooling missed it. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Repurposing caveat** — ShimCache is being used for a purpose entirely different from its design (backwards compatibility), so execution inferences carry inherent uncertainty. _Why:_ Justifies hedged language in reports. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Corroboration recommended** — Do not take ShimCache at face value as sole 100% proof of execution; corroborate with other artifacts (e.g. Prefetch on desktop/non-server Windows) or another artifact type. _Why:_ ShimCache execution is "pretty likely," not conclusive; independent corroboration is the safe practice. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### AppCompatCacheParser Tool

- **Tool identity** — AppCompatCacheParser is the Eric Zimmerman tool that parses this artifact. _Why:_ Names the reference parser. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Up-to-date version required** — An up-to-date (post-March-2023) AppCompatCacheParser is needed to determine execution on Windows 10+ for non-native binaries. _Why:_ Tool version directly changes what conclusions are possible. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Modern output values** — A current AppCompatCacheParser reports a "Yes" or "No" in the Executed column. _Why:_ Interpreting the Executed column correctly. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Pre-March-2023 output values** — Older AppCompatCacheParser versions (before March 2023) reported "Yes", "No", or "NA" in the Executed column. _Why:_ Distinguishes legacy output for older reports/tooling. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **"NA" meaning** — An "NA" from an older parser meant the InsertFlag was absent and execution could not be determined — a strong indicator the data came from a Windows 10 or Windows 11 box. _Why:_ "NA" doubles as an OS-version tell. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **--csv is required** — The --csv option (output directory) is required by AppCompatCacheParser. _Why:_ Minimum flag to produce output. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **--csvf is optional filename** — The --csvf option specifies the output CSV file name (optional). _Why:_ Controls the output file naming. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **-f specifies offline hive** — The -f option gives the full path to a SYSTEM hive to process, important for dead-box forensics. _Why:_ The flag for offline/image-based parsing. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Live registry is the default** — If -f is not specified, AppCompatCacheParser uses the live registry. _Why:_ Default behaviour when no hive path is given. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Live parsing needs admin** — Parsing the live registry with AppCompatCacheParser requires administrative privileges (launch Windows Terminal / shell elevated). _Why:_ Operational requirement for live collection. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Control-set selection option** — AppCompatCacheParser can specify which control set to parse, but parsing all available control sets is recommended to capture every ShimCache copy. _Why:_ Avoids missing entries in secondary control sets. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Additional options** — The tool also offers timestamp and custom date/time format options; the most common flags in practice are --csv, --csvf, and -f (for offline hives). _Why:_ Focuses the examiner on the routine flags. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Live-parse status message** — When parsing live, the tool prints "processing the Live Registry". _Why:_ Confirms the mode being used. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Timeline Explorer for CSV review** — Associating .csv output with Timeline Explorer (another Zimmerman tool) eases review; output can be filtered (e.g. typing "Demo\" filters to that path). _Why:_ Practical review/filtering workflow. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Timestamp Semantics

- **Timestamp is the M time, not execution/shim time** — The ShimCache timestamp is the file's modification timestamp ("M" in MACB) — NOT the execution time and NOT the shim time. _Why:_ The most dangerous misreading; drawing an execution timeline from it is wrong. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **MACB definition** — MACB = Modification, Access, MFT-record/Metadata Change, and Birth. _Why:_ Clarifies which of the four timestamps is captured. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Corresponds to Explorer "Modified"** — The ShimCache timestamp equals the "Modified" timestamp shown in a file's Windows Explorer Properties dialog. _Why:_ A verifiable cross-reference for the timestamp meaning. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **64-bit resolution** — Behind the scenes the timestamp is a 64-bit value (sub-second / nanosecond granularity), even if displayed only to the second. _Why:_ High precision makes it near-unique per file, enabling correlation. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Timestamp as pseudo-hash** — The 64-bit timestamp is precise enough to act almost like a hash uniquely tying an entry to a specific file, so two entries sharing an identical 64-bit timestamp are very likely the same file. _Why:_ Basis for rename/move correlation across paths. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Demo timestamp value** — In the demo, all deleted-binary entries showed modification time 2013-09-10 00:30:08, the original binary's M time — not any execution or shim time. _Why:_ Concrete illustration that the timestamp is the source file's M time. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Timestomping Detection

- **Timestomp fits binary in among others** — A threat actor may timestomp a dropped binary (e.g. evil.exe in C:\Windows\Temp) to blend it with surrounding files so it appears legitimate. _Why:_ Common anti-forensic tactic ShimCache can help expose. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Timestomp targets M and/or B** — Timestomping is typically done against the modification and/or creation timestamps (the "M" and/or "B" in MACB). _Why:_ Identifies which timestamps an attacker alters. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Timestomp does not reshim** — Clobbering a file's timestamp does NOT trigger a reshim, so the existing ShimCache entry retains the ORIGINAL modification time. _Why:_ ShimCache preserves a pre-timestomp M time even after the file system value is overwritten. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Detecting timestomping** — Comparing the ShimCache M time to the current file-system M time and finding a difference can indicate timestomping occurred. _Why:_ Gives ShimCache a role as an anti-timestomping oracle. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Reshimming, Rename/Move Detection, Cache Entry Position

- **Rename/move triggers reshim** — Renaming or moving a file causes it to be reshimmed (a new ShimCache entry). _Why:_ Explains why the same content can appear under a new path. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Rename/move does not change M time** — Renaming or moving a file does not alter its modification timestamp, because the file's contents are unchanged; only metadata (the "C" timestamp) changes. _Why:_ Underpins matching a renamed/moved file by its unchanged M time. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Same timestamp, different paths = likely same file** — Two ShimCache entries with different paths but an identical timestamp likely represent the same file that was renamed or moved. _Why:_ A rename/move detection heuristic. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Cache Entry Position defined** — Cache Entry Position is a numerical value starting at 0. _Why:_ Names the ordering field in output. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **MRU ordering** — Lower Cache Entry Position numbers sit higher in the parsed output; position 0 is the most recently shimmed entry (most-recently-used ordering). _Why:_ Lets the examiner read recency/sequence from position. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Tool ordering** — Most tools, including AppCompatCacheParser, place the lowest Cache Entry Position (most recent) at the top of the list. _Why:_ Output-reading convention. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Position delta + identical timestamp = rename** — A Cache Entry Position gap between two entries that share an identical timestamp can be concluded to be a rename: the higher-position (older) entry is the original name, the lower-position (newer) entry the renamed file. _Why:_ Combining position and timestamp reconstructs attacker rename activity (e.g. evil.exe at position 20 later renamed to svchost.exe at position 5). _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Cannot time the rename from ShimCache alone** — ShimCache reveals that a rename happened but not when; determining the rename time requires another artifact such as the USN Journal. _Why:_ Bounds what ShimCache can and cannot establish about timing. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Real-world applicability** — The drop-then-rename pattern (e.g. a binary dropped as evil.exe, later renamed/moved to svchost.exe) is a genuine real-life scenario ShimCache has been used to detect. _Why:_ Confirms operational value, not just theory. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Write-on-Shutdown / Flush Behaviour

- **Flushed only at reboot/shutdown** — ShimCache contents are flushed to the SYSTEM registry hive ONLY on reboot or shutdown. _Why:_ Until then the on-disk hive lacks the latest entries; a live image may miss recent activity. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Deliberate reboot to capture ShimCache** — In real compromised-Windows-Server investigations, examiners have asked the customer to reboot the server specifically to flush ShimCache to disk. _Why:_ Shows the flush behaviour driving real acquisition decisions. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Memory first, then reboot** — Such a reboot-to-flush is done only AFTER acquiring volatile memory, which is always the first step. _Why:_ Correct order of volatility — never reboot before capturing RAM. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Parsing ShimCache from Memory

- **ShimCache recoverable from RAM** — ShimCache can, in some cases, be parsed directly from a memory image (e.g. capture RAM with DumpIt, then parse with Volatility), avoiding the reboot-to-flush requirement. _Why:_ Alternative path to current ShimCache without shutting the box down. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **shimcachemem plugin** — Mandiant released a Volatility plugin named "shimcachemem" for this. _Why:_ Names the memory-parsing tool. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Volatility 2 vs 3** — As of the recording, shimcachemem existed for Volatility 2, with no known Volatility 3 version (a v3 port may exist by viewing time). _Why:_ Tooling-availability caveat. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Prefetch-from-memory contrast** — Prefetch can likewise be parsed from memory, but Prefetch does not require a reboot/shutdown to be flushed, so memory-parsing it is less uniquely valuable than for ShimCache. _Why:_ Contrasts the two execution artifacts' flush behaviour. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Demonstration Findings (behavioural evidence)

- **Enumeration seeds ShimCache** — Merely enumerating/viewing files (e.g. a `dir` at the command prompt or opening a folder in Explorer) can add those binaries to ShimCache without executing them. _Why:_ Direct proof that presence ≠ execution. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Explorer viewport drives which entries appear** — Only the files actually rendered in the Windows Explorer window were added to ShimCache; the visible range (1.exe–18.exe) matched exactly what the Explorer window displayed, even though the folder held 100 files. _Why:_ Startling behaviour — ShimCache population tracks the GUI viewport, not the full folder. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Command-prompt `dir` did NOT add all 100** — Viewing the folder's full contents via `dir` at the command prompt did not populate ShimCache with all 100 files; only the Explorer-visible subset (plus the one executed file) appeared. _Why:_ The GUI-viewport effect is specific to Explorer rendering, not console listing. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Resizing Explorer adds more entries** — Enlarging the Explorer window to reveal more files (through part of 26.exe) caused the newly visible files (up to 26.exe) to enter ShimCache after the next reboot. _Why:_ Confirms viewport-driven population; even a partially visible file (26.exe) was added. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Executed file flagged Yes** — 100.exe, executed from the command prompt, showed "Yes" in the Executed column (a non-native/third-party binary), demonstrating the modern four-byte execution indicator. _Why:_ Validates execution detection on Win11 for a third-party binary. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Non-executed files flagged No** — Files that were only viewed (1.exe–26.exe) correctly showed "No" under Executed, since nothing but 100.exe had been run at that stage. _Why:_ Confirms the indicator's negative case. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Execution does not reshim / move position** — Double-clicking 1.exe in Explorer to run it flipped its Executed value to "Yes" but left it at its existing Cache Entry Position (28); it was shimmed when first made visible in Explorer, not reshimmed on execution. _Why:_ Execution updates the execution indicator without changing entry position — position reflects first-shim (visibility), not run time. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **Deleted binaries persist in ShimCache** — After deleting APG.exe and the entire Demo folder, the entries (and their original M timestamps) still appeared in ShimCache. _Why:_ ShimCache retains evidence of files that no longer exist on disk. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_
- **New entries push old ones down** — Newly shimmed entries occupy the top (lowest positions) and push earlier entries further down the list. _Why:_ Illustrates MRU ordering across reboots. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

### Overall Characterisation

- **Most complicated Windows artifact** — The instructor rates ShimCache as by far the most complicated Windows forensic artifact covered, and expects its behaviour to keep changing. _Why:_ Sets an appropriately cautious posture and a re-verification expectation. _[IWE ch04 · Evidence of Execution / ShimCache & AppCompatCache]_

## Chapter 04 · UserAssist

### Nature & Scope

- **Artifact classification** — UserAssist is a per-user evidence-of-execution artifact; each user account has its own independent UserAssist record. _Why:_ Attribution — activity ties to the specific user profile, not the machine as a whole. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **GUI-launch scope** — UserAssist tracks execution of GUI-based programs, i.e. programs launched interactively through the Windows graphical shell, not those started from the command line. _Why:_ A program run only from a shell/CLI will be absent, so absence from UserAssist is not evidence of non-execution. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Relationship to MUICache** — UserAssist and MUICache are both per-user, GUI-oriented evidence-of-execution artifacts, but they live in different hives (UserAssist in NTUSER.DAT, MUICache in UsrClass.dat). _Why:_ They corroborate each other and should be cross-checked, not treated as one source. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Parsing required vs MUICache** — Unlike MUICache, whose values are human-readable as stored, UserAssist value data must be parsed/decoded before it can be interpreted. _Why:_ Reading the raw registry key yields obfuscated names and binary blobs, not usable findings. _[IWE ch04 · Evidence of Execution / UserAssist]_

### Registry Location

- **Hive** — UserAssist data resides inside each user's NTUSER.DAT registry hive. _Why:_ To examine a specific user offline, load that user's NTUSER.DAT; the currently-logged-on user's data is reachable live under HKEY_CURRENT_USER. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Full key path** — The key is `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` (i.e. NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist when mounted). _Why:_ Exact path is needed to navigate in regedit/Registry Explorer or to target it in a RECmd batch. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **UserAssist sits under Explorer** — UserAssist is a subkey of the Explorer key under CurrentVersion. _Why:_ Consistent with its role tracking Explorer-shell (GUI) launches. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **GUID subkeys** — Beneath UserAssist are multiple subkeys each named as a GUID; the value data of interest lives under each GUID's `Count` subkey. _Why:_ The path pattern is `...\UserAssist\{GUID}\Count`. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Only two GUIDs carry data** — Of the several GUID subkeys present, generally only two hold substantive data; the others appear largely empty. _Why:_ Focus analysis on the two populated GUIDs. _[IWE ch04 · Evidence of Execution / UserAssist]_

### The Two GUIDs

- **Executables GUID (CEB…)** — The GUID beginning `CEB…`, under its Count subkey, tracks execution of applications/executables. _Why:_ This is where program-run entries are found. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Shortcut/LNK GUID (F4E…)** — The GUID beginning `F4E…`, under its Count subkey, tracks link (shortcut / .lnk) files. _Why:_ Separates direct-executable launches from shortcut-driven launches. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Each GUID scopes a distinct object class** — The two GUIDs partition tracked items by type (executables vs. shortcuts), so the same launch may surface differently depending on how it was invoked. _Why:_ Interpreting an entry requires knowing which GUID it came from. _[IWE ch04 · Evidence of Execution / UserAssist]_

### ROT13 Encoding

- **Value names are ROT13-encoded** — The value names (program paths/identifiers) under the Count subkeys are stored using ROT13 encoding, appearing as scrambled/unreadable text in a raw view. _Why:_ Raw registry inspection shows gibberish; decoding is mandatory to read the path. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **ROT13 definition** — ROT13 is a simple substitution cipher that rotates each alphabetic character by 13 positions (e.g. A→N, B→O, C→P). _Why:_ It is trivially reversible; applying ROT13 again decodes it. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Both GUIDs use ROT13** — Value names under both the executables (CEB…) and shortcut (F4E…) GUIDs are ROT13-encoded, not just one. _Why:_ The same decode step applies uniformly. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Decode example (path)** — A ROT13 value decodes to a real filesystem path, e.g. an encoded string resolves to something like `C:\Tools\Miscellaneous\backup.bat`. _Why:_ Confirms the value name is a full path to the executed item. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Decode example (LNK token)** — In the shortcut GUID, the recurring encoded token `YAX` decodes under ROT13 to `LNK`. _Why:_ Recognizable ROT13 fragments (e.g. YAX→LNK) help confirm you are reading shortcut entries. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Manual decode is feasible** — A single value name can be decoded by hand: copy the ROT13 value name and run it through a ROT13 decoder (e.g. CyberChef's ROT13 recipe). _Why:_ Useful for one-off verification, though impractical at scale. _[IWE ch04 · Evidence of Execution / UserAssist]_

### Parsed Fields

- **Program name** — After parsing, each entry exposes the decoded program/item name (the ROT13-decoded path). _Why:_ Identifies what was launched. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Run count** — Each entry records a run counter (number of times the item was executed). _Why:_ Indicates frequency of use; a nonzero count implies prior execution. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Focus count** — Each entry records a focus count (how many times the program's window received focus). _Why:_ Reflects interactive foreground use of a GUI window. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Focus time** — Each entry records a focus time (cumulative duration the program held window focus). _Why:_ Estimates how long a user actively interacted with the application. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Last executed time (UTC/FILETIME)** — Each entry records a last-execution timestamp; the parsed value is expressed in UTC. _Why:_ Anchors the execution to a point in time for timeline building. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Non-interactive programs lack focus data** — A background/non-interactive program (e.g. a batch file that flashes a console window) can legitimately show a run count but no focus count and no focus time. _Why:_ Absent focus fields are expected for non-interactive items and are not by themselves anomalous. _[IWE ch04 · Evidence of Execution / UserAssist]_

### Tools

- **regedit for live inspection** — On a live system the raw key can be browsed with regedit under HKEY_CURRENT_USER, but the data appears ROT13-encoded and unparsed. _Why:_ Suitable for a quick look, not for real casework. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Registry Explorer auto-parses** — Eric Zimmerman's Registry Explorer parses UserAssist automatically, decoding ROT13 and presenting program name, run count, focus count, focus time, and last-executed time in a table. _Why:_ Removes manual decode/parse steps for GUI-based analysis. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Registry Explorer surfaces summary at the key** — Selecting the top UserAssist key in Registry Explorer already shows pulled-out data from the subkeys, before drilling into each GUID's Count. _Why:_ Fast overview of the artifact. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **RECmd for scale** — RECmd, the command-line counterpart to Registry Explorer (part of the Zimmerman tools), is the preferred tool for processing UserAssist at scale across many hives. _Why:_ Scriptable/batch processing beats clicking through a GUI in larger investigations. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **RECmd is a single executable** — RECmd is delivered as one standalone executable that is driven by batch (map) files. _Why:_ Simple deployment; behavior is defined by the chosen batch file. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Kroll batch file covers UserAssist** — The Kroll batch (map) file distributed with RECmd includes the UserAssist key path among the artifacts it collects (searchable within the batch file for "UserAssist"). _Why:_ Running the Kroll batch auto-harvests UserAssist alongside many other registry artifacts. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Two RECmd usage modes** — RECmd can be pointed at a folder of collected data to run a full batch ("give me everything"), or targeted specifically at UserAssist alone. _Why:_ Flexibility between broad triage and focused extraction. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **CyberChef ROT13 recipe** — CyberChef includes a ROT13 decoder operation usable to manually decode a copied UserAssist value name. _Why:_ Handy independent verification of an automated tool's decode. _[IWE ch04 · Evidence of Execution / UserAssist]_

### Anomalies & Caveats

- **Reliability asterisk** — UserAssist is a "trust but verify" artifact: useful but requiring corroboration, especially on recent Windows versions. _Why:_ Some entries do not behave as classic documentation implies. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Anomaly scenario 1 — phantom entries** — A program that was never executed on the system can nonetheless appear in UserAssist. _Why:_ Presence in UserAssist is not conclusive proof the user ran it. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Anomaly scenario 2 — zero run count despite execution** — A program that was executed can register with a run count of zero, and in some cases the last-executed field is also blank. _Why:_ A zero/blank field does not prove non-execution; the entry itself is still meaningful. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Zero run count with a valid timestamp is contradictory** — An entry can show a real last-executed time yet a run count of zero, which is logically inconsistent and flags the recent-Windows tracking oddity. _Why:_ Analysts must not naively read run count as literal execution frequency. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Root cause unknown** — The precise reason recent Windows versions produce these inconsistent UserAssist entries is not definitively established; the behavior appears influenced by factors beyond manual user launching of programs. _Why:_ Interpret with caution and avoid overstating causation. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Supporting reference** — The "UserAssist with a Pinch of Salt as an Evidence of Execution" article on imphash.medium.com documents the two inconsistency scenarios above. _Why:_ An independent write-up to cite when relying on UserAssist reliability caveats. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **NTFS-epoch timestamp caveat** — A UserAssist last-execution timestamp of 1601-01-01 00:00:00 corresponds to the NTFS/Windows FILETIME epoch (the zero point of that timestamp format), i.e. an effectively null/bogus time. _Why:_ Such a value is a sentinel, not a genuine execution moment. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Non-user launch produces the epoch timestamp** — Entries showing the 1601-01-01 epoch time appear to arise when a program starts under the user's context without an explicit user click — e.g. via a service, a scheduled task, or a startup-folder / Start-menu autostart. _Why:_ Explains bogus timestamps and reinforces that not every entry reflects deliberate user action. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Corroboration principle** — Never rely on UserAssist as a single source; seek additional independent artifacts pointing to the same event before drawing conclusions. _Why:_ Multi-source confirmation is a core forensic tenet, especially given UserAssist's known oddities. _[IWE ch04 · Evidence of Execution / UserAssist]_
- **Evolving research** — UserAssist behavior and the understanding of these anomalies may change with newer Windows releases and future research. _Why:_ Re-verify current behavior against up-to-date primary sources rather than assuming static semantics. _[IWE ch04 · Evidence of Execution / UserAssist]_

## Chapter 05 · LSASS NTDS WDigest

### ATT&CK phase framing

- **PrivEsc ↔ Credential Access overlap** — Credential-theft techniques straddle two MITRE ATT&CK tactics simultaneously: Privilege Escalation and Credential Access; the same activity is often mapped to both because they are operationally coupled. _Why:_ Analysts should pivot detections across both tactics rather than treat them as separate silos. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### Privilege-escalation vectors (overview)

- **Phishing / social engineering as an initial vector** — A large share of major security incidents begin with a phishing email, making human-targeted social engineering a primary route to obtaining credentials and escalating privilege. _Why:_ Root-cause analysis often traces sophisticated breaches back to a single deceptive message. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Data breaches feeding credential leaks** — Weaknesses such as absent multi-factor authentication and publicly exposed services lead to data breaches; the leaked credential sets are then circulated online and reused for illicit access. _Why:_ Leaked corpora enable downstream attacks against unrelated systems. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Brute-force attacks** — Repeatedly trying different password combinations against an account until access succeeds; technically unsophisticated yet still effective, particularly against single-factor services like RDP exposed to the internet. _Why:_ Internet-facing single-factor endpoints remain routinely compromised this way. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Password spraying (definition)** — Taking one password (e.g. a season-plus-year like "Spring2023") and trying it a single time across many accounts, rather than many passwords against one account. _Why:_ Distinguishes the low-and-slow spray from a noisy brute force. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Password spraying is quieter than brute force** — Because it produces only one failed (or successful) authentication per account before moving on, spraying generates far less per-account noise than a brute force firing hundreds or thousands of attempts at a single account. _Why:_ Detection tuned only to per-account failure counts misses spraying. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Credential stuffing (definition)** — Reusing credential pairs stolen from one breach against other systems, typically by automating the logins for a large volume of previously stolen credential sets. _Why:_ Exploits password reuse across services. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Cookie / session theft** — Stealing a session cookie for an already-authenticated session lets an attacker resume as that authenticated session without ever needing the user's credentials. _Why:_ Bypasses password and even MFA because the session is already established. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### LSASS and credential dumping

- **LSASS = Local Security Authority Subsystem Service** — `lsass.exe` is the Windows process responsible for authentication and security functions. _Why:_ It is the container in which credential material lives in memory, so it is the prime dumping target. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **LSASS is the only process permitted to write the Security log** — LSASS is supposed to be the sole process allowed to write to the Windows Security event log. _Why:_ Any other writer to the Security log is anomalous and a tamper indicator. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Exactly one LSASS instance is expected** — On a healthy Windows system only a single `lsass.exe` process should be running at any moment. _Why:_ A second process named lsass (or a look-alike) is a strong indicator of masquerading/injection. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **LSASS appears under "Windows processes" in Task Manager** — In Task Manager's process list, "Local Security Authority Process" is grouped in the Windows-processes section; its Properties confirm the image is `lsass.exe`. _Why:_ Lets an examiner locate and verify the genuine process interactively. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Task Manager can dump LSASS interactively** — Right-clicking the LSASS process in Task Manager and choosing "Create Dump File" produces a memory dump of LSASS with no third-party tooling. _Why:_ A built-in, low-sophistication dumping method available to any interactive admin. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Default Task Manager dump path** — The Create Dump File action writes to the user's Local AppData Temp directory, i.e. `C:\Users\<username>\AppData\Local\Temp\`. _Why:_ Tells the examiner exactly where to hunt for LSASS dumps. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Default dump filename `lsass.DMP`** — The Task Manager dump is named `lsass.DMP` (lowercase lsass, `.DMP` extension) by default. _Why:_ That exact name in a user's Temp folder is a high-fidelity credential-dumping artifact. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Dump → Mimikatz → credentials** — Once an LSASS dump exists, it can be fed offline into a tool such as Mimikatz to recover credentials. _Why:_ Separates the on-host dump step from the offline extraction step, both of which leave evidence. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Windows Defender alerts on LSASS dumping** — On a modern Windows system with Defender enabled, dumping LSASS generates a Defender alert flagging the LSASS-dump attempt. _Why:_ Provides a native detection signal for the dump attempt. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Attackers disable AV/anti-malware first** — Threat actors commonly disable antivirus and anti-malware solutions early so that subsequent dumping stays undetected. _Why:_ Explains why the Defender alert may be absent; look for prior AV-tampering. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Dumping LSASS requires admin / elevated context** — Administrative privileges are needed to dump LSASS. _Why:_ Constrains which accounts could have produced a dump. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`whoami /priv` enumerates the caller's privileges** — Running `whoami /priv` lists the privileges the current token holds; a non-elevated prompt shows a short list, an elevated prompt shows substantially more. _Why:_ A quick way to confirm the privilege context an action ran under. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **SeDebugPrivilege is the specific right enabling LSASS dumps** — The privilege actually required to dump LSASS is `SeDebugPrivilege`, which appears under an elevated token. _Why:_ Admin group membership is not the fundamental requirement — the SeDebug right is; a delegated SeDebugPrivilege alone suffices. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **SeDebugPrivilege can be delegated without full admin** — An account granted SeDebugPrivilege as a delegated permission can dump LSASS even without being a full administrator. _Why:_ Broadens the set of accounts capable of credential dumping beyond the Administrators group. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Elevating a cmd prompt via Ctrl+Shift+Enter** — Typing `cmd` and pressing Ctrl+Shift+Enter launches an administrator (elevated) command prompt. _Why:_ Explains how an interactive elevation was obtained in a session under review. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### NTDS.dit extraction via Ntdsutil

- **Ntdsutil is a living-off-the-land binary** — `Ntdsutil` is a built-in Windows utility bundled with Windows Server operating systems (a LOLBin). _Why:_ Its use blends into normal admin activity and needs no dropped tooling. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Ntdsutil dumps NTDS.dit plus SYSTEM and SECURITY hives** — Ntdsutil can produce a copy of `NTDS.dit` and, in the same operation, dump the SYSTEM and SECURITY registry hives. _Why:_ A single command yields both the encrypted database and the key material needed to decrypt it. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **SYSTEM hive carries the syskey/boot key** — The SYSTEM registry hive contains the syskey (boot key) material; the SECURITY hive is largely unnecessary for this purpose. _Why:_ SYSTEM is the load-bearing companion file for decrypting NTDS.dit hashes. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **NTDS.dit hashes are encrypted at rest** — The password hashes inside `NTDS.dit` are stored encrypted, not in the clear. _Why:_ Possession of NTDS.dit alone is insufficient; decryption is a required step. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Decryption workflow: pull syskey from SYSTEM, decrypt NTDS.dit** — A program can automatically extract the key from the SYSTEM hive and use it to decrypt the encrypted hashes in NTDS.dit, yielding what are informally called "naked" (bare) hashes. _Why:_ Defines the end-to-end offline extraction pipeline the examiner is reconstructing. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Decrypted hashes are usable two ways** — Once decrypted, the hashes can either be passed directly (pass-the-hash) or cracked offline (brute force / Hashcat-style) to recover the plaintext password. _Why:_ Both downstream uses leave distinct evidence trails. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Ntdsutil is a domain-controller-only capability** — Ntdsutil runs meaningfully only on a machine promoted to the Domain Controller role; on a plain Windows Server (e.g. Server 2022 not yet promoted) the utility is not available/does not function, whereas a promoted DC (e.g. Server 2019) provides its interactive prompt. _Why:_ Scopes where NTDS.dit theft can occur — expect it on DCs. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Ntdsutil runs interactively by default** — Invoked with no parameters, Ntdsutil drops into its own interactive sub-prompt. _Why:_ Explains why attackers chain sub-commands and append `q`/`quit` to script it non-interactively. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **IFM = Install From Media** — In the Ntdsutil dump command the `IFM` token stands for "Install From Media," the mode used to snapshot the AD database. _Why:_ Recognising the sub-command clarifies intent when it appears in command-line logs. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Full Ntdsutil dump command shape** — A representative command is: `ntdsutil "ac i ntds" ifm "create full <path>" q q`, where the two trailing `q` tokens quit the nested interactive contexts. _Why:_ The double-quit signature and IFM/create-full sequence are a command-line detection pattern. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`ProgramData` is a favored dump destination** — Attackers frequently target `C:\ProgramData` (e.g. a `ProgramData\backup` path) as the output location for the Ntdsutil dump. _Why:_ ProgramData is a common attacker staging directory worth checking. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Ntdsutil dump is near-instant** — `create full` completes in real time ("creating snapshot" → done) with no artificial delay. _Why:_ Sets expectation that the operation leaves little time-window evidence. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Telltale directory structure: `Active Directory` + `registry`** — A successful Ntdsutil IFM dump creates, under the chosen output path, an `Active Directory` subdirectory (capital A, capital D, with a space) and a lowercase `registry` subdirectory. _Why:_ These two sibling directories are a filesystem signature of Ntdsutil use. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Even empty `Active Directory`/`registry` dirs are indicators** — Finding these subdirectories on the filesystem — even if now empty — is a telltale sign that Ntdsutil was likely used. _Why:_ Residual directory names persist as evidence after files are removed. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`Active Directory` subdir holds NTDS.dit + a JFM file** — Inside the `Active Directory` directory sits `NTDS.dit` (the primary file of interest) alongside a `.jfm` file, which is a flush-map file related to the database itself. _Why:_ Distinguishes the target database from its auxiliary ESE artifacts. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`registry` subdir holds SECURITY + SYSTEM hives** — The `registry` directory contains both the SECURITY and SYSTEM hives, but SYSTEM is the one actually needed to obtain the key to decrypt the NTDS.dit hashes. _Why:_ Pinpoints the single hive an examiner must recover for decryption. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### ESENT / Application-log event IDs for NTDS.dit dumping

- **Detection channel: Application log, ESENT provider** — NTDS.dit / ESE database creation events are logged in the Application channel under the `ESENT` provider. _Why:_ Tells the analyst exactly which log and provider to filter. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Relevant ESENT event IDs: 216, 325, 326, 327** — Event IDs 216, 325, 326 and 327 in the Application log (ESENT provider) are the pivot points for detecting Ntdsutil / ESE database activity. _Why:_ Concrete IDs to build a hunt query around. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Event ID 325 = "database engine created a new database"** — ESENT event 325 records that the database engine created a new database, and it includes the full path of that database. _Why:_ A new database named `ntds.dit` outside its normal location is the smoking gun. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Anomaly = NTDS.dit created outside its expected location** — Seeing event 325 report a newly created database named `ntds.dit` in a non-standard path (e.g. under ProgramData) is abnormal and a red flag. _Why:_ Legitimate NTDS.dit lives in its designated AD database path, not in an ad-hoc backup folder. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### WDigest plaintext-credential toggle

- **WDigest is a legacy challenge-response protocol** — WDigest is an old authentication (challenge-response) protocol dating to roughly the Windows Server 2003 era. _Why:_ Context for why re-enabling it is anomalous on modern systems. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **WDigest disabled by default, re-enableable for compatibility** — Modern Windows keeps WDigest off by default but retains the ability to turn it back on for backwards compatibility. _Why:_ The re-enable path is the attacker's lever. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **WDigest registry key path** — The relevant key is `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest` on a live system (or `ControlSet001`/`ControlSet002`/etc. under `System` on a dead/offline hive). _Why:_ Exact registry location to examine for tampering. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Dead-vs-live control set nuance** — On a live system the analysis is done under `CurrentControlSet`; on a dead/offline system there is no CurrentControlSet, so the examiner must look under the numbered control sets (`ControlSet001`, `ControlSet002`, …). _Why:_ Prevents an examiner from missing the value on an offline hive. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`UseLogonCredential` value does not exist by default** — Under the WDigest key the `UseLogonCredential` value is absent by default; its mere presence is meaningful. _Why:_ The value being created at all is the artifact. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`UseLogonCredential` exact name and type** — The value is named `UseLogonCredential` (capital U, capital L, capital C, no spaces), of type `REG_DWORD`. _Why:_ Precise name/type needed to write a reliable detection or grep. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **`UseLogonCredential = 1` re-enables plaintext credential caching** — Setting `UseLogonCredential` (REG_DWORD) to data value `1` re-enables WDigest and causes clear-text credentials to be stored in memory. _Why:_ This is the whole point — it makes plaintext passwords harvestable from LSASS memory. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Attacker motive for the toggle** — A threat actor sets this value specifically to force clear-text credentials into memory so they can be scraped. _Why:_ Explains intent behind the registry change. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Toggle is closely followed by a credential-theft tool** — The `UseLogonCredential=1` modification is typically followed shortly afterward by execution of a credential-theft tool (e.g. Mimikatz). _Why:_ A temporal sequencing heuristic — pivot from the registry change to nearby process execution. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### Pass-the-Hash

- **Pass-the-hash (definition)** — Instead of supplying a password, the attacker authenticates by passing the password's hash; the actual plaintext password is never needed. _Why:_ Explains why cracking is optional once a hash is obtained. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **A hash is a cryptographic representation of the password** — The hash used in pass-the-hash is a cryptographic representation of the user's password and can be presented directly for authentication. _Why:_ Grounds why the hash is credential-equivalent. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Pass-the-hash Security-log signature: 4648 + 4624 + 4672** — In the Security log, the trio Event ID 4648 (logon attempted using explicit credentials), 4624 (successful logon), and 4672 (special/admin privileges assigned to logon) appearing together / adjacent is a telltale sign that pass-the-hash may have occurred. _Why:_ A concrete, chainable event-ID pattern for PtH detection. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **4648 meaning** — Event ID 4648 = "A logon was attempted using explicit credentials." _Why:_ Component of the PtH signature. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **4672 meaning** — Event ID 4672 is the admin/special-privileges logon event (privileges assigned to a new logon). _Why:_ Component of the PtH signature indicating elevated context. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### Pass-the-Ticket / Kerberos

- **Kerberos is Active Directory's authentication protocol** — Kerberos is the authentication protocol used by Active Directory, built around the concept of tickets that grant access to services. _Why:_ Frames what a stolen ticket buys the attacker. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Pass-the-ticket (definition)** — A stolen Kerberos ticket can be used to authenticate to a domain and gain access to services without knowing the user's password (analogous to a movie ticket granting entry). _Why:_ Another passwordless lateral-movement/access technique to hunt for. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

### Mimikatz

- **Mimikatz core capabilities** — Mimikatz can extract plaintext passwords, password hashes, and Kerberos tickets from Windows memory. _Why:_ Defines the credential material it can harvest. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Mimikatz performs pass-the-hash and pass-the-ticket** — Beyond extraction, Mimikatz can carry out pass-the-hash and pass-the-ticket attacks. _Why:_ It is both a harvester and an attack tool. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Golden ticket = non-expiring Kerberos ticket** — Mimikatz can generate a "golden ticket," a non-expiring Kerberos ticket usable indefinitely, which is especially dangerous. _Why:_ Represents durable, hard-to-revoke domain persistence. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Mimikatz can patch the Event Log service and clear logs silently** — Mimikatz can patch the Windows Event Log service to clear logs without generating the usual clearing events. _Why:_ Absence of clearing events does not prove logs were untouched. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Event ID 1102 normally marks Security-log clearing** — Clearing the Security log normally produces Event ID 1102; Mimikatz's log-patching can suppress it. _Why:_ 1102 is the expected tamper signal, but it can be evaded. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Event ID 104 normally marks System/other-log clearing** — Clearing the System log (and other logs) normally produces Event ID 104; Mimikatz can suppress this too. _Why:_ 104 is the System-log counterpart tamper signal subject to the same evasion. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_
- **Detecting Mimikatz relies on the same event-log/registry methodology** — Hunting for Mimikatz uses the event-log detection methods and registry-key/value profiling covered elsewhere; it is a very common tool, so its indicators strongly help profile threat-actor activity. _Why:_ Ties Mimikatz detection back to the standard IWE artifact-profiling toolkit rather than a bespoke method. _[IWE ch05 · Persistence/PrivEsc/LatMov / LSASS, NTDS.dit, WDigest]_

## Chapter 05 · SMB RDP WMI PsExec UAL

### SMB (Server Message Block) lateral movement

- **SMB protocol role** — SMB (Server Message Block) is the native Windows file-sharing protocol, and threat actors routinely abuse it to move laterally across a network. _Why:_ SMB and RDP are among the two most common lateral-movement vectors, so profiling SMB is a first-order detection task. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 4624 (Security log)** — Event ID 4624 records successful account logons and is the primary event for detecting SMB connectivity. _Why:_ Successful-logon evidence anchors any lateral-movement timeline. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **4624 Logon Type 3 = network logon** — Within a 4624, Logon Type 3 specifically indicates a network logon, which is the signature of an inbound SMB connection. _Why:_ Filtering 4624 to Type 3 isolates network/SMB access from interactive and other logon classes. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 5140 (Security log)** — Event ID 5140 logs network share object access and helps profile SMB use. _Why:_ Records that a network share was accessed, tying an account to a specific share. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 5145 (Security log)** — Event ID 5145 also relates to network share object access and helps profile SMB use. _Why:_ Provides detailed-share-access records complementing 5140. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 5156 (Security log)** — Event ID 5156, "the Windows Filtering Platform has allowed a connection," shows connectivity between systems including the IP address and port involved, and can profile SMB. _Why:_ Ties a connection to concrete network endpoints (IP + port). _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **5156 not on the 13cubed cheat sheet** — 5156 was absent from the referenced Windows Event Log Cheat Sheet at recording time (instructor noted it should be added). _Why:_ Gotcha — analysts relying only on that cheat sheet may overlook a useful SMB-connectivity event. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Shellbags include network paths** — Shellbags (registry) record folders an interactive user browsed in Windows Explorer, and they also capture network/UNC locations, not just local directories. _Why:_ A shellbag entry for an SMB path can reveal a lateral-movement destination the actor browsed to. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Shellbags as "GPS for the file system"** — Shellbags document where an interactive user traversed via Windows Explorer; profiling a threat-actor account's shellbags can surface UNC paths such as `\\computername\financialdata\payroll`. _Why:_ Maps interactive traversal to remote shares, exposing destination systems and folders of interest. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Shellbags require interactive Explorer use** — Shellbag evidence exists only for locations reached interactively through Windows Explorer for that user account. _Why:_ Constrains what shellbags can prove — they show human GUI browsing, not programmatic access. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **RunMRU subkey** — The RunMRU subkey (under the Explorer subkey in the registry) tracks entries typed into the Run dialog, including network locations such as `\\ipaddress\d$`. _Why:_ Another source proving a user visited an SMB share (e.g. an admin/hidden share). _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Hidden/admin share syntax `\\host\d$`** — A path like `\\ipaddress\d$` targets the hidden administrative share of the D: volume on a remote host. _Why:_ `$`-suffixed drive shares (C$, D$, ADMIN$) are classic lateral-movement targets and appear in RunMRU/shellbags. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### RDP (Remote Desktop Protocol) lateral movement

- **RDP is a top lateral-movement method** — RDP is one of the most common lateral-movement techniques, ranked alongside SMB at the top. _Why:_ High prior probability makes RDP a priority to profile. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **RDP has a dedicated cheat-sheet section** — The Windows Event Log Cheat Sheet has a distinct RDP section (found near the bottom) enumerating the relevant Terminal Services logs and their event IDs. _Why:_ RDP evidence is spread across several operational logs, not just the Security log. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **TerminalServices-LocalSessionManager/Operational** — The Windows Terminal Services Local Session Manager Operational log is one of the RDP logs to profile for lateral movement. _Why:_ Captures local session lifecycle events on the RDP target. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **TerminalServices-RemoteConnectionManager/Operational** — The Remote Connection Manager Operational log is another RDP log to profile. _Why:_ Records inbound remote connection management events on the target. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **TerminalServices-RDPClient/Operational** — The Terminal Services RDPClient Operational log is an RDP log to profile. _Why:_ This is a SOURCE-side log — it records outbound RDP connections initiated from the host, useful for tracing where an actor RDP'd TO. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **RDP flow chart over raw event-ID lists** — 13cubed's RDP flow chart is a handier reference than the raw event-ID list; it presents scenarios at the top and the chain of event IDs (and which logs contain them) needed to confirm each. _Why:_ RDP determinations depend on event-ID *sequences* across multiple logs, not single events. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **RDP scenarios the flow chart distinguishes** — The flow chart separates: successful logon, unsuccessful logon, session disconnect with window close, session disconnect with start-menu disconnect, RDP session reconnect, and RDP session logoff. _Why:_ Each RDP outcome leaves a different event-ID signature; distinguishing them prevents misreading a disconnect as a logoff, etc. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### WMI (Windows Management Instrumentation) lateral movement

- **WMI as a remote-execution protocol** — Windows Management Instrumentation (WMI) can be leveraged as a lateral-movement/remote-execution protocol. _Why:_ WMI enables running commands on remote hosts without dropping a traditional service. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **WMIC command (deprecated but functional)** — WMIC (also written W-MIC) is an old-school command-line WMI client that is technically deprecated yet still works. _Why:_ Deprecated tooling still present on hosts remains an actor option; do not assume its absence. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **WMIC remote process creation syntax** — `wmic /node:<host> process call create <binary>` (e.g. `calc.exe`) executes the specified binary on the remote host given by `/node:` (which accepts an IP address). _Why:_ Canonical WMI lateral-movement invocation to recognise in command-line/process evidence. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **`/node:` accepts remote IP** — The `/node:` parameter of WMIC takes the target host (IP or name); `localhost` runs it against the local machine. _Why:_ The node value reveals the intended remote target in an investigation. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Microsoft-Windows-WMI-Activity/Operational log** — The primary event log for profiling WMI activity is Microsoft-Windows-WMI-Activity/Operational. _Why:_ This log is the go-to source for WMI-related evidence and is not one of the commonly examined logs. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### PowerShell Remoting / WinRM lateral movement

- **PowerShell Remoting rides on WinRM** — PowerShell Remoting is a PowerShell feature that uses the WinRM protocol behind the scenes to perform remote actions. _Why:_ WinRM is the transport; evidence can appear in both PowerShell and WinRM logs. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **WinRM can be invoked directly** — An actor can invoke PowerShell Remoting or call the underlying WinRM protocol directly. _Why:_ Detection must cover WinRM use that does not go through the PowerShell remoting cmdlets. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PowerShell Operational log — Event ID 4104** — The PowerShell Operational log's Event ID 4104 is script block text logging, useful for PowerShell-remoting evidence (other event IDs in that log may also help). _Why:_ 4104 captures the actual script content executed, high-value for reconstructing actions. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Microsoft-Windows-WinRM/Operational log** — Microsoft-Windows-WinRM/Operational is the event log for profiling WinRM use, the protocol underlying PowerShell Remoting. _Why:_ Dedicated WinRM log — not commonly examined — records the transport-level remoting activity. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### PsExec lateral movement

- **PsExec is a Sysinternals tool, not malware** — PsExec is part of the Sysinternals suite and is a legitimate, widely deployed utility; it is abused by threat actors but is not inherently malicious. _Why:_ Presence alone is not incriminating; context determines maliciousness. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec is inefficient/insecure vs alternatives** — Better, more efficient, and more secure remote-administration methods exist than PsExec, yet it remains common in legitimate and malicious use. _Why:_ Ubiquity means analysts encounter it constantly across benign and malicious scenarios. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec invocation syntax** — `psexec \\<target> -i -u <username> <command>` runs a command (e.g. `cmd.exe`) on the target; `-i` = interactive, `-u` = username. _Why:_ Canonical PsExec command form to recognise in shell history/command lines. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec password on command line** — PsExec accepts the password on the command line (via `-p`), or prompts if omitted. _Why:_ When supplied inline, credentials may be recoverable from command-line logging. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Running `psexec` bare shows options** — Executing PsExec with no arguments prints its available options. _Why:_ Recognising the option set aids interpreting observed flags. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec drops PSEXESVC.exe in system root** — Each PsExec run against a target creates `psexesvc.exe` in the system root (`%SystemRoot%`, typically `C:\Windows`) on that target. _Why:_ The dropped service binary is the key on-disk artifact proving the host was a PsExec TARGET. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec installs a service named PSEXESVC** — PsExec instantiates/installs a service (service name PSEXESVC) on the target every time it runs. _Why:_ Service installation is the reliable target-side signal of PsExec execution. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 7045 (System log)** — A new service installation generates Event ID 7045 ("a new service was installed in the system") in the System log; for PsExec this is the primary event to look for. _Why:_ 7045 with service name PSEXESVC confirms the host was a PsExec target. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Event ID 4697 (Security log)** — Event ID 4697 also records service installation (in the Security log), but 7045 is the one typically relied upon. _Why:_ 4697 is a corroborating source when Security auditing of service installs is enabled. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **7045 record fields for PSEXESVC** — The PSEXESVC 7045 record shows service name PSEXESVC, service file name under `%SystemRoot%`, start type "demand start," and the Local System account. _Why:_ These fields distinguish a genuine PsExec service install and characterise its privileges (SYSTEM). _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **7045 proves target, not source** — A 7045 PSEXESVC event proves the system was the TARGET of a PsExec command/session, i.e. the destination the session connected to. _Why:_ Directionality matters — this artifact does not indicate the host initiated PsExec. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **PsExec recreates the binary every run** — Every PsExec run creates a brand-new `psexesvc.exe` and a new service, even if run seconds apart. _Why:_ Each invocation freshly writes the file, which drives the timestamp behaviour exploited below. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **New-file MACB timestamps all equal creation time** — When NTFS creates a brand-new file, all four MACB timestamps — Modified, Accessed, MFT-record-Changed (metadata change), and Birth (created) — are set to the creation time. _Why:_ Underpins why a freshly dropped PSEXESVC's Modified time equals its creation time. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **MACB expansion** — MACB = M (modification), A (access), C (MFT record change / metadata change), B (birth/creation). _Why:_ Standard NTFS timestamp taxonomy needed to interpret the PsExec/shimcache trick. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Shimcache tracks the Modified (M) timestamp** — Shimcache (AppCompatCache) records a file's last modification timestamp, not its execution time. _Why:_ Normally shimcache's timestamp is NOT an execution time — a well-known gotcha. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Shimcache exception with PsExec** — Because a new PSEXESVC file's Modified time equals its creation time, a PSEXESVC shimcache entry's timestamp corresponds to when the file was created — effectively an execution time in this rare case. _Why:_ Combined with a 7045, PSEXESVC shimcache entries let you approximate when PsExec ran, unusual for shimcache. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Corroborate shimcache with 7045** — The PsExec/shimcache timing inference is used when you already know a 7045 exists and PsExec was in play, then match the PSEXESVC shimcache entries. _Why:_ Cross-validation prevents overreading shimcache timestamps outside this specific PsExec situation. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### Impacket lateral-movement framework

- **Impacket framework** — Impacket is a framework of many utilities frequently used by threat actors for privilege escalation and lateral movement. _Why:_ A dominant offensive toolkit; recognising its residue is essential for lateral-movement investigations. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Five Impacket exec utilities** — Impacket ships five utilities for remote command execution / lateral movement: `atexec.py`, `dcomexec.py`, `psexec.py`, `smbexec.py`, and `wmiexec.py`. _Why:_ Each leaves a distinct target-side event-log footprint; knowing the set scopes the hunt. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **`psexec.py` = Impacket's PsExec** — Impacket includes its own PsExec implementation (`psexec.py`), distinct from Sysinternals PsExec. _Why:_ Analysts must not conflate the two; artifacts differ. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **`smbexec.py` uses SMB** — `smbexec.py` uses the SMB protocol behind the scenes, as its name implies. _Why:_ Its transport dictates which artifacts/logs to examine. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **`wmiexec.py` uses WMI** — `wmiexec.py` uses WMI behind the scenes, as its name implies. _Why:_ Points investigators to WMI-Activity logging for this variant. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **smbexec.py default service name BTOBTO** — `smbexec.py` creates a Windows service whose default name is `BTOBTO`; the name is changeable but threat actors rarely change it. _Why:_ A service install named BTOBTO is a telltale sign of smbexec.py in use. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Look for Impacket residue on the TARGET** — The Impacket Exec Commands Cheat Sheet lists the Windows event-log residue to look for on the TARGET system (computer B) when a utility is run from computer A. _Why:_ Detection artifacts live on the destination host; the cheat sheet maps each utility to its target-side events. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **13cubed Impacket resources** — 13cubed publishes an "Impacket Exec Commands Cheat Sheet" (also as a scalable PDF poster) plus a companion 13Cubed episode detailing every utility's target-side event-log results. _Why:_ Reference pointer — the poster/PDF and episode enumerate per-utility artifacts. (Cite the underlying Impacket source/Mandiant, not 13cubed, in production.) _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### UAL (User Access Logging)

- **UAL definition** — User Access Logging (UAL) is a Windows Server feature that collects user-access and system statistical data in near real time. _Why:_ Provides a server-side record of which identities/IPs accessed the box — powerful for lateral-movement mapping. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL is server-only, Server 2012+** — UAL is enabled by default only on Windows Server operating systems, and only starting with Server 2012; pre-2012 servers have no UAL and client OSes have none. _Why:_ Scoping — do not expect UAL on workstations or legacy servers. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL data sources (roles/services)** — UAL collects from services and roles including File Server, DNS, DHCP, IAS, WSUS, and others. _Why:_ Access is logged per role, so the role context colours each record. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL stored as ESE .mdb files** — UAL data lives in multiple `.mdb` files in ESE (Extensible Storage Engine, "ESE database") format. _Why:_ Parsing requires ESE-aware tooling and ESE recovery handling. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL file location** — UAL databases reside at `%SystemRoot%\System32\LogFiles\SUM` (typically `C:\Windows\System32\LogFiles\SUM`). _Why:_ Collection target path; the folder is named SUM, not UAL. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Three UAL files of interest** — The SUM folder holds `Current.mdb`, `SystemIdentity.mdb`, and a GUID-named `<GUID>.mdb`. _Why:_ These three are the files to acquire and parse. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL retains ~2 years** — UAL retains up to two years of history. _Why:_ Long retention window makes UAL valuable for historical lateral-movement reconstruction. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Current.mdb copied to GUID.mdb every 24h** — While the service runs, UAL copies the active `Current.mdb` to a `<GUID>.mdb` file every 24 hours so an administrator can retrieve data. _Why:_ Explains the GUID database's role as a periodic snapshot of live data. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **New GUID database each year** — On the first day of each year UAL creates a new GUID-named database; the prior GUID database is retained as an archive. _Why:_ Year determines which GUID database holds a given period's data. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Two-year overwrite** — After two years the original GUID-named database is overwritten. _Why:_ Defines the hard end of UAL's retention. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL DB is locked/in use** — The live UAL database is locked while the service runs and cannot simply be copied off. _Why:_ Requires forensic acquisition (raw copy) rather than a normal file copy. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Acquire with FTK Imager or KAPE** — FTK Imager or KAPE can extract the locked UAL database files. _Why:_ Tooling options for collecting in-use files. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **KAPE SUM target, not "UAL"** — In KAPE the relevant target is found by searching for "sum" (the "SUM database" target), not "UAL"; a separate LogFiles target also includes sum. _Why:_ Gotcha — searching KAPE for UAL fails; the artifact is catalogued under SUM. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **KAPE can collect and parse (module) but caveats** — A KAPE module can both collect and parse UAL in one pass, but the instructor collected only (target) to demonstrate the dirty-database repair caveats separately. _Why:_ The one-shot module hides the ESE recovery step an analyst must understand. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **KAPE collection succeeds fast** — KAPE recreated the source path and reported "found three files," matching the expected three UAL databases. _Why:_ Sanity check — three files confirms a complete SUM collection. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **KAPE optional container/VSC handling** — KAPE can output to a container (zip/VHD/VHDX) and can process volume shadow copies, though neither is required for a simple UAL grab. _Why:_ VSCs could yield older UAL databases; containers aid evidence handling. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Parser: SumECmd (Eric Zimmerman)** — UAL databases are parsed with Eric Zimmerman's SumECmd tool. _Why:_ The standard EZ-tool for SUM/UAL parsing. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **SumECmd flags: `-d` and `--csv`** — SumECmd needs only `-d <directory of databases>` and `--csv <output directory>`. _Why:_ Minimal invocation to produce parsed CSV output. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Dirty-database error is expected** — SumECmd errors with "Database was not shut down cleanly. Recovery must first be run..." on a live-collected UAL DB; this is expected — do not panic, and the EZ GitHub repo documents the repair. _Why:_ Gotcha — the error is normal for an in-use ESE database, not a collection failure. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Repair with esentutl /p** — Repair the dirty databases with `esentutl` (built into Windows) using the repair (`/p`) command, run per database (Current.mdb, SystemIdentity.mdb, and the GUID.mdb). _Why:_ esentutl brings the ESE databases to a clean state so SumECmd can parse them. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **esentutl is built-in** — esentutl ships with Windows; nothing extra needs installing. _Why:_ Repair can be done on the host or any Windows box without added tooling. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **esentutl repair warning** — esentutl repair warns it should only be run on damaged/corrupted databases and will NOT apply transaction logs to the database. _Why:_ Repair discards unreplayed log data — an evidentiary consideration to document. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Repair is in-place** — esentutl repairs the databases in place; the directory looks unchanged afterward. _Why:_ No new files appear, so verify by re-running the parser rather than by inspecting the folder. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Post-repair SumECmd succeeds** — After esentutl repair, re-running SumECmd parses successfully and prints statistics about what it obtained. _Why:_ Confirms the repair-then-parse workflow is the correct sequence. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

### UAL parsed output (SumECmd CSVs)

- **SumECmd emits multiple CSVs** — SumECmd writes several CSV files, opened as tabs in Timeline Explorer. _Why:_ Different CSVs carry different UAL facets; know which to prioritise. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Primary CSV: DetailedClients output** — The "SumECmd detailed clients" output is one of the two main CSVs to examine. _Why:_ Holds the authenticated-user + IP records that map lateral movement. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Role GUID auto-resolved to name** — The DetailedClients output carries a Role GUID that maps to a known role; SumECmd automatically writes out the resolved role name. _Why:_ Saves manual GUID lookup; role context labels each access. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Most common roles: ADDS and File Server** — The two most ubiquitous roles seen are ADDS (Active Directory Domain Services) and File Server. _Why:_ Sets expectation for typical UAL role values on a domain server. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Username often the computer account** — In many UAL records the username is the machine/computer account rather than a human user; domain user accounts (e.g. `13cubed\administrator`) also appear. _Why:_ Analysts must distinguish machine-account noise from human-identity access. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **DetailedClients fields** — DetailedClients records include Role GUID/name, username, total accesses, insert date, last access date, client IP address, client name (if available), tenant ID, and the source database file. _Why:_ These fields let you correlate identity + IP + timing per server. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **DetailedClients = authenticated users + IPs that touched the box** — The DetailedClients output lists authenticated usernames and IP addresses that interacted with the server. _Why:_ Directly enumerates who connected to that host and from where. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL lateral-movement mapping across servers** — Collecting UAL from multiple servers and profiling a known-compromised/actor-controlled username shows exactly which servers that identity touched, mapping lateral-movement paths. _Why:_ Turns per-server UAL into an environment-wide movement map for a given account. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Second key CSV: Clients (DetailedClients vs Clients)** — The "clients detailed" / detailed clients output holds largely the same data as DetailedClients but broken down differently (by incrementing last-access dates, more verbose). _Why:_ The two client CSVs together are "where the meat is"; verbosity helps timeline granularity. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **DNS info CSV** — A DNS-related CSV surfaces DNS configuration information pulled from DNS on the box. _Why:_ Supplementary context (server DNS config), lower priority. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Role Accesses CSV** — A Role Accesses CSV breaks down which roles were in play and their first-seen/last-seen times. _Why:_ Shows role activity windows on the server. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Year-to-GUID-database mapping** — SumECmd output includes detail on which year's data is stored in which GUID-named database. _Why:_ Directs the analyst to the correct GUID DB for a target time period. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Role output CSV (names/products/GUID mapping)** — A role-output CSV maps role names and product names to the Role GUID; described as not extremely useful. _Why:_ Reference/lookup data, low investigative yield. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **SystemIdentity CSV = OS version** — The SystemIdentity CSV contains the OS major, minor, and build versions of the box. _Why:_ Identifies the server's OS build; minimal for movement analysis. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL directionality: parsed server is the connection subject** — The server whose UAL you parsed is the SUBJECT/destination of the connection; the records show the client IP that performed the connection plus the associated identity/username and role. _Why:_ Establishes which end is target vs source in UAL evidence. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **UAL granularity limited to role** — UAL detail bottoms out at the role description; much activity shows generically as "file server" with no finer breakdown. _Why:_ Gotcha — do not expect per-file or per-operation detail from UAL. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_
- **Analysis in Timeline Explorer** — The parsed UAL CSVs are reviewed in Eric Zimmerman's Timeline Explorer (multiple CSVs opened as tabs via File > Open, multi-select). _Why:_ Standard EZ-tools review workflow for the CSV output. _[IWE ch05 · Persistence/PrivEsc/LatMov / SMB, RDP, WMI, PsExec, UAL]_

## Chapter 05 · Services Scheduled Tasks

### MITRE ATT&CK framework

- **ATT&CK acronym** — ATT&CK expands to Adversarial Tactics, Techniques, and Common Knowledge. _Why:_ names the knowledge base that defines the shared vocabulary of an intrusion investigation. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ATT&CK viewpoint** — the framework catalogues technical objectives from the attacker's perspective rather than the defender's. _Why:_ maps observed artifacts to adversary intent, not just defensive controls. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ATT&CK cost/access** — the framework is a freely available resource. _Why:_ no licensing barrier to adopting it as an investigative reference. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ATT&CK purpose** — an organisation can use it to understand the lifecycle of an attack and drive defensive action. _Why:_ frames artifacts within a full intrusion lifecycle rather than in isolation. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ATT&CK phases** — the framework arranges techniques across distinct attack phases, among which persistence, privilege escalation, and lateral movement appear. _Why:_ these three phases scope this module. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### Core term definitions

- **Persistence** — the process by which a threat actor ensures survivability of access after gaining an initial foothold. _Why:_ persistence is the artifact class this lesson hunts for forensically. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Persistence — reboot survival** — persistence specifically maintains attacker access across reboots and other disruptive events, preserving a path back into the victim environment. _Why:_ mechanisms that re-establish access at boot/logon are the detection target. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Privilege escalation** — the process of elevating from the privileges of the initially compromised account to an account with local or domain administrative privileges. _Why:_ distinguishes initial-access artifacts from elevation artifacts. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Privilege escalation — precondition** — escalation is only needed if the initial account did not already hold administrative privileges. _Why:_ absence of escalation artifacts may mean the initial account was already privileged. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Lateral movement** — the process of moving through the victim environment to locate valuable assets and sensitive information. _Why:_ lateral-movement artifacts trace the attacker's path across hosts. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Actions on objectives** — "actions on objectives" is terminology for the threat actor's ultimate goals. _Why:_ standard phrasing in intrusion reporting. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### ASEPs (Auto-Start Extensibility Points)

- **ASEP acronym** — ASEP expands to Auto-Start Extensibility Point. _Why:_ the umbrella concept for every place persistence can be registered. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ASEP definition** — an ASEP is any location in Windows where an item can be configured to auto-start. _Why:_ enumerating ASEPs enumerates candidate persistence mechanisms. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ASEP trigger conditions** — an ASEP entry may start something at boot, at logon, or under some other condition. _Why:_ persistence can trigger on more than just user logon. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Run key — user scope** — the Run key exists under the current user, applying to that user only. _Why:_ per-user persistence lives in the user's hive. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Run key — machine scope (HKLM)** — the Run key also exists under HKLM, affecting all users on the system. _Why:_ machine-wide persistence lives in a system hive and hits every account. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ASEP breadth** — there are dozens upon dozens of locations in Windows where an auto-start item can be placed. _Why:_ manual review of each location is impractical, motivating tool-driven profiling. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **ASEP profiling value** — profiling ASEPs is presented as one of the main ways to enumerate potential persistence mechanisms on a Windows system. _Why:_ establishes the recommended investigative workflow for persistence. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Services are ASEPs** — services are one of the many ASEP locations and are included in ASEP profiling. _Why:_ a single ASEP sweep also surfaces service-based persistence. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### RECmd + the RegistryASEPs batch file

- **RECmd identity** — RECmd is the command-line counterpart to Registry Explorer. _Why:_ enables scripted/bulk registry parsing versus interactive GUI review. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RECmd batch capability** — RECmd can run a batch file to bulk-produce results across many registry locations. _Why:_ one command profiles all ASEPs at once. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RegistryASEPs.reb** — the batch file used for ASEP profiling is named RegistryASEPs.reb. _Why:_ identifies the exact artifact-definition file that drives the sweep. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **.reb extension** — the .reb extension denotes a Registry Explorer batch file. _Why:_ recognises the file type when locating or authoring batch definitions. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RegistryASEPs.reb path** — on the demo host the batch file lives under Tools\Zimmerman\net6\RECmd\BatchExamples. _Why:_ locates the shipped batch example within the Zimmerman tool layout. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RegistryASEPs.reb size** — the batch file is over 115 KB. _Why:_ its size reflects the very large number of enumerated ASEP locations. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Batch-file coverage caveat** — the batch file covers the vast majority of ASEP locations but is not claimed to be 100% inclusive of all of them. _Why:_ a negative ASEP result is not proof of no persistence. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Batch-file updates via GitHub** — the batch scripts are maintained and can be synced from the GitHub repository to pull the newest copies. _Why:_ keep ASEP coverage current with newly discovered persistence locations. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RECmd standalone workflow** — RECmd can be run directly against a folder of collected registry hives by pointing the RECmd binary at the batch file and at the hive directory, without KAPE. _Why:_ ASEP profiling does not depend on KAPE. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### KAPE orchestration of the ASEP sweep

- **KAPE binaries** — KAPE ships as kape.exe (command line) and gkape (graphical version). _Why:_ same collection engine, two front-ends. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **GUI builds the command line** — the gkape GUI displays the equivalent kape.exe command line as options are selected. _Why:_ the GUI teaches the exact CLI needed for scaled/scripted runs. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **KAPE target concept** — a KAPE "target" defines which artifact(s) to collect. _Why:_ separates collection scope from processing. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **KAPE module concept** — a KAPE "module" defines what to do with the data once collected. _Why:_ modules run tools (e.g. RECmd) against collected targets. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Target source** — the target source specifies where to collect from; here the live C: drive of the running system. _Why:_ KAPE can collect from a live system, not only an image. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Target destination** — the target destination is where collected target output is written. _Why:_ collected hives are staged before processing. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **registry-hives target** — the KAPE target named "registry-hives" collects system- and user-related registry hives. _Why:_ one target grabs every hive the ASEP module needs. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **User hives collected** — registry-hives includes the user-specific hives NTUSER.DAT and UsrClass.dat (userclass.dat). _Why:_ per-user ASEPs (e.g. user Run key) live in these hives. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **System hives collected** — registry-hives includes the core Windows system hives: DEFAULT, SAM, SECURITY, SOFTWARE, SYSTEM. _Why:_ machine-scope ASEPs and services live in SOFTWARE/SYSTEM. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Deduplicate option** — KAPE's Deduplicate checkbox is enabled by default for target collection. _Why:_ avoids collecting duplicate copies of the same file. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Container not needed here** — no container output is needed when the collected target will be fed directly into a module. _Why:_ containerisation is optional when processing happens in the same run. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Blank module source** — leaving the module source blank makes the module operate on the collected target output as its source. _Why:_ chains target→module in a single KAPE invocation. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Separate target vs module destinations** — the target destination and module destination must be two separate locations (named arbitrarily, e.g. ASEP-tout and ASEP-mout). _Why:_ collected files and processed output must not overwrite each other. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **RECmd_Registry_ASEPs module** — the KAPE module used is RECmd_Registry_ASEPs, described simply as "Registry ASEPs". _Why:_ this module runs the full ASEP batch across all hives. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Full vs targeted ASEP modules** — RECmd_Registry_ASEPs profiles all ASEPs, whereas other ASEP modules are targeted to a single source such as SOFTWARE, software classes, WoW64, or SYSTEM. _Why:_ pick the "all" module for a complete sweep, targeted ones for scoping. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### KAPE command-line flags observed

- **--tsource** — --tsource sets the target source (here C:). _Why:_ tells KAPE what to collect from. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--tdest** — --tdest sets the target destination for collected files. _Why:_ where staged targets land. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--tflush** — --tflush clears any pre-existing content in the target destination directory before writing (the directory is created if absent). _Why:_ guarantees a clean target output area per run. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--target** — --target names the target to collect (here registry-hives). _Why:_ selects the artifact set. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--mdest** — --mdest sets the module destination for processed output. _Why:_ where module results (CSV/console log) land. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--mflush** — --mflush clears any pre-existing content in the module destination directory before writing. _Why:_ clean processed-output area per run. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--module** — --module names the module to run (here RECmd_Registry_ASEPs). _Why:_ selects the processing step. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **--gui flag** — --gui is added by gkape and only keeps the command window open so results stay visible; it is unnecessary when pasting the command manually. _Why:_ distinguishes a cosmetic GUI-added flag from load-bearing ones. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Command portability** — the GUI-built command line (minus --gui) can be copied and run directly at a command prompt. _Why:_ enables scaling a GUI-designed collection to scripting. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### KAPE run output & CSV structure

- **Output format** — the module produces a CSV file. _Why:_ tabular output suited to timeline/spreadsheet review. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Preferred viewer** — the CSV is opened in Timeline Explorer, which is purpose-built for this kind of data (in preference to Excel). _Why:_ the recommended review tool for large forensic CSVs. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Output volume** — the demo run produced 92,295 lines of output. _Why:_ illustrates the scale of ASEP data and the need for filtering. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Run duration** — the full collect-and-parse run completed in under a minute. _Why:_ ASEP profiling is fast even at this scale. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Target output mirrors source path** — the target (tout) output recreates the original source paths of the collected hives (e.g. C\Users\<user>\NTUSER.DAT with its transaction logs; AppData location for UsrClass.dat and its logs; Windows\System32\config for core hives and their logs). _Why:_ collected files retain provenance of their on-disk location. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Transaction logs collected** — registry hives are collected alongside their transaction logs. _Why:_ transaction logs may hold un-committed registry data needed for full/accurate parsing. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Config hive location** — most core registry hives reside under Windows\System32\config. _Why:_ the canonical on-disk location of the system hives. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Module console log** — the module output directory (mout) also contains a console log in addition to the CSV. _Why:_ run-time logging accompanies the parsed results. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **CSV columns** — the ASEP CSV includes: hive path, hive type, category, description, key path, value name, value type, value data2, value data, comment, a deleted indicator, and last-write timestamp (plus further columns). _Why:_ these fields are the pivot points for triaging a persistence entry. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Value data reveals executables** — the value-data column exposes paths to executables directly. _Why:_ the target of an auto-start entry is visible without extra decoding. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Deleted-entry recovery** — a deleted indicator column flags recovered entries, because registry data can in many cases be recovered from the hive. _Why:_ removed persistence may still be recoverable and must be surfaced. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Last-write timestamp value** — the last-write timestamp on a key is highlighted as very valuable data. _Why:_ dates when a persistence key was last modified, anchoring it in the timeline. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### Triage examples & filtering

- **ZoomIt example** — searching for ZoomIt (a Sysinternals zoom utility set to auto-start) locates its Run-key entry with hive path, category "run", value name, value type, and the executable path. _Why:_ demonstrates confirming a known auto-start entry in the CSV. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Backblaze example — multiple entries** — searching for Backblaze (backup software) returns more than one hit: a Run-key entry and additional service-related entries. _Why:_ one product can persist via several ASEP types simultaneously. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Temp-directory hunting** — filtering for "temp" narrowed 92,000-plus lines to 68 results, which can be further refined (e.g. AppData\Local\Temp or other unusual temp locations). _Why:_ execution from temp directories is an abnormality worth surfacing. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Abnormal-location heuristic** — auto-start items running from temporary or otherwise weird locations are treated as abnormal and suspicious. _Why:_ location is a triage signal for malicious persistence. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### Alternative (image-based) workflow

- **Arsenal Image Mounter workflow** — an alternative to live KAPE collection: mount a forensic image with Arsenal Image Mounter, extract the wanted registry hives into a folder, then point RECmd at that folder. _Why:_ ASEP profiling works equally on dead-box images. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### Windows services

- **services.msc** — services.msc is the Microsoft snap-in that lists the services on a system. _Why:_ the native GUI for reviewing installed services. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Service definition** — a Windows service is analogous to a Linux/Unix daemon: a background process. _Why:_ frames services as long-running background execution — an attractive persistence vehicle. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **svchost role** — the service host process (svchost) is the service host controller process responsible for running services. _Why:_ malicious services are commonly hosted under svchost, aiding masquerade. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Example running services** — examples of services on the demo host include Windows Update, Windows Time, and the Windows Subsystem for Linux. _Why:_ illustrates the mix of legitimate services amid which malicious ones hide. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Service properties — executable path** — a service's Properties expose the full path of its executable. _Why:_ the ImagePath equivalent identifies what the service actually runs. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Service properties — logon identity** — every service is associated with a credential/account (an identity) shown in its logon information. _Why:_ the account context of a service is forensically relevant (privilege, attribution). _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Service properties — recovery** — a service's recovery configuration defines what happens if it fails. _Why:_ recovery actions are a scriptable execution path. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Recovery abuse** — threat actors can abuse service recovery by causing a service to fail so that, on first failure, it executes something of their choosing. _Why:_ a non-obvious service-based execution/persistence technique to check in recovery settings. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

### Autoruns / Scheduled tasks

- **Autoruns identity** — Autoruns is a Sysinternals utility shipped in the Sysinternals suite. _Why:_ a standard ASEP-enumeration tool available if the suite is installed. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Autoruns editions** — Autoruns has a GUI version and a command-line version named AutorunsC. _Why:_ AutorunsC enables scalable/scripted use across many hosts. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Autoruns overlaps ASEP output** — Autoruns shows information similar to the KAPE-via-RECmd ASEP batch output. _Why:_ a corroborating second source for auto-start entries. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Autoruns "Everything" tab** — Autoruns has an "Everything" view listing all auto-start entries together. _Why:_ single pane for a complete auto-start inventory. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Autoruns categorised tabs** — Autoruns separates entries into tabs including Logon, Scheduled Tasks, Services, Drivers, Boot Execute, Image Hijacks, and Event Logs. _Why:_ each tab is a distinct persistence/ASEP category to review. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Logon tab examples** — the Logon tab on the demo host shows entries such as Backblaze, ZoomIt, Google Chrome, and Adobe Creative Cloud. _Why:_ shows how legitimate logon persistence appears, against which anomalies stand out. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Scheduled task definition** — a scheduled task is analogous to a cron job in the Linux/Unix world: something that runs in the background on a set cadence (e.g. every day or every hour). _Why:_ frames scheduled tasks as timed execution, a common persistence vehicle. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Scheduled tasks as persistence** — scheduled tasks are explicitly leveraged by threat actors as persistence mechanisms and are important in Windows investigations. _Why:_ a priority artifact class for the persistence phase. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Autoruns Event Logs relevance** — Autoruns includes an Event Logs tab, and specific event IDs / event logs help profile scheduled tasks (referenced from earlier coverage). _Why:_ scheduled-task activity leaves an event-log trail complementing the on-disk task definitions. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_
- **Multiple execution paths caveat** — beyond Run keys, services, and scheduled tasks, Windows offers many different ways to execute things (drivers, boot execute, image hijacks, service recovery, etc.). _Why:_ persistence review must cover the full breadth of ASEP categories, not just the obvious keys. _[IWE ch05 · Persistence/PrivEsc/LatMov / Services & Scheduled Tasks]_

## Chapter 06 · I30 Index Attributes

### $I30 index — nature and purpose

- **$I30 directory index** — On NTFS, a directory's file-name index is referred to by the name "$I30"; it is the structure that holds the list of entries (files and subfolders) contained within that directory. _Why:_ Establishes what the artifact is and why it enumerates a folder's children. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **$I30 as an FTK Imager–exposable object** — When browsing an NTFS volume in FTK Imager, a directory can present an extractable "$I30" object alongside its normal contents. _Why:_ Tells the examiner the index can be exported as a discrete file for offline parsing. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **INDX signature/header** — The exported $I30 begins with an "INDX" record header, visible in a hex/ASCII view. _Why:_ Confirms record type and marks the start of the index record structure. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Filenames visible in raw ASCII** — Within the raw bytes of an $I30, some of the indexed file names are legible directly in the ASCII pane, even before formal parsing. _Why:_ Allows a quick eyeball confirmation that a file was once indexed in that directory. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### B-tree indexing and how slack is created

- **B-tree directory index** — NTFS organizes the directory index as a B-tree structure. _Why:_ The tree organization is the mechanism behind rebalancing and, therefore, slack generation. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Periodic rebalancing** — The B-tree index is rebalanced from time to time as entries are added and removed. _Why:_ Rebalancing is the specific event that leaves recoverable remnants behind. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Rebalancing produces index slack** — When the B-tree rebalances, it can leave stale/unused space (slack) inside the $I30 index. _Why:_ This slack is the region that preserves evidence of removed entries. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Index slack ≠ file slack** — The unused space inside an $I30 index record is a distinct kind of slack from the trailing unused bytes in a file's last allocated cluster. _Why:_ Prevents conflating two different recovery sources during analysis. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### Recovery of deleted filenames from index slack

- **Deleted-entry evidence in slack** — $I30 index slack can retain records for files that previously existed in that directory but have since been removed. _Why:_ Enables proof a file once lived in a folder even after deletion. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Recoverable field: file name** — A slack entry yields the deleted file's name. _Why:_ Identifies what was there. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Recoverable field: file size** — A slack entry also preserves the file's size. _Why:_ Adds quantitative detail about the vanished file. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Recoverable field: full timestamp set** — A slack entry preserves a complete set of timestamps for the removed file. _Why:_ Supplies a temporal record for a file no longer on disk. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **$FILE_NAME-style timestamps** — The timestamps stored in the index entry generally track the same values recorded in the file's $STANDARD_INFORMATION attribute. _Why:_ Lets an examiner cross-check index-slack times against expected MFT timestamps. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Evidence survives full deletion** — All of name, size, and timestamps can be recovered for a file that no longer exists on disk, purely from parsing the $I30 slack. _Why:_ Demonstrates the artifact's value when the file and its MFT record are gone. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Shift+Delete does not clear index slack** — A file removed with a permanent delete (Shift+Delete, bypassing the Recycle Bin) still leaves its entry recoverable in the directory's $I30 slack. _Why:_ Shows permanent deletion does not immediately purge index remnants. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### FTK Imager indicators

- **Red-X = previously existing content** — In FTK Imager a red-X overlay on an item marks it as previously existing (deleted/remnant) content rather than a live file. _Why:_ Visual cue distinguishing live entries from recoverable remnants. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **"$I30 INDX entry" label** — FTK Imager labels certain red-X remnant items as "$I30 INDX entry," identifying them as entries recovered from the directory index's slack. _Why:_ Directly attributes the remnant to index-slack recovery. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Export via right-click → Export Files** — The $I30 object is extracted from the image by right-clicking it and choosing Export Files, saving it to disk for tool parsing. _Why:_ Documents the extraction step preceding parsing. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### Parsing $I30 with MFTECmd

- **MFTECmd parses $I30** — Eric Zimmerman's MFTECmd can process exported $I30 files, not just $MFT. _Why:_ Identifies the tool for turning raw index bytes into structured output. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **-f (file) flag** — MFTECmd is pointed at the input artifact with the `-f` switch giving the path to the exported $I30. _Why:_ Core invocation parameter. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **--csv (output directory)** — The `--csv` switch specifies the directory into which results are written. _Why:_ Sets where output lands. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **--csvf (output filename)** — The `--csvf` switch names the output CSV file (e.g. `i30.csv`). _Why:_ Controls the result filename. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Automatic file-type detection** — On run, MFTECmd auto-detects the supplied artifact as an I30 file type without the examiner declaring it. _Why:_ Reduces operator error; confirms correct artifact was fed in. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### Interpreting the MFTECmd CSV output

- **"From Slack" column** — The output CSV contains a boolean "From Slack" column indicating whether each entry was recovered from the index's slack space (True) versus the active index area. _Why:_ Directly flags which rows are deleted-file remnants. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Filter From Slack = True** — Filtering the CSV on From Slack = True isolates exactly the entries recovered from $I30 slack. _Why:_ Fast triage to surface deleted-file evidence. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Timestamp columns** — The CSV exposes the recovered entry's full set of timestamps, which generally align with the file's $STANDARD_INFORMATION timestamps. _Why:_ Supplies the temporal evidence per recovered entry. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Physical size column** — The CSV reports a "physical size" for each entry (bytes actually allocated on disk). _Why:_ One of the two size figures needed for slack arithmetic. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Logical size column** — The CSV reports a "logical size" (the file's true content length). _Why:_ The second size figure; the difference from physical size is file slack. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Source file column** — The CSV includes a "source file" field identifying the origin of the recovered entry. _Why:_ Provenance for each row. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

### Physical vs logical size and cluster arithmetic

- **Physical size is a multiple of cluster size** — A file's physical (allocated) size is always an integer multiple of the NTFS cluster size, because storage is allocated in whole clusters. _Why:_ Underlies the divisibility check and slack calculation. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Default cluster size 4096 bytes** — The default NTFS cluster (allocation unit) size is 4096 bytes. _Why:_ The divisor for cluster-count arithmetic on typical volumes. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Cannot allocate less than one cluster** — NTFS allocates a minimum of one whole cluster to a file; partial clusters are not allocated. _Why:_ Explains why physical size rounds up to the next cluster boundary. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **Cluster count = physical size ÷ cluster size** — Dividing physical size by cluster size yields the whole number of clusters allocated (worked example: 57,020,416 ÷ 4096 = 13,921 clusters). _Why:_ Confirms the physical size is a clean cluster multiple and gives the allocation count. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **File slack = physical − logical** — Subtracting logical size from physical size gives the file slack (worked example: 57,020,416 − 57,019,510 = 906 bytes of slack in the last cluster). _Why:_ Quantifies leftover recoverable bytes in the final allocated cluster. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_
- **File slack lives in the last cluster** — The delta between physical and logical size is the unused tail of the final cluster allocated to the file, and constitutes (file) slack space. _Why:_ Locates where that recoverable slack physically sits. _[IWE ch06 · Anatomy of NTFS / $I30 Index Attributes]_

## Chapter 06 · MACB Timestamps

### MACB Definitions and the Four-Timestamp Model

- **MACB acronym** — Each NTFS file tracks four timestamps designated M, A, C, B: M = Modified (content), A = Accessed, C = MFT record / metadata change, B = Born (creation). _Why:_ Canonical vocabulary for timeline analysis; each letter maps to a distinct filesystem event. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **M (Modified)** — Records when the file's content was last modified. _Why:_ Reliable indicator of when data last changed. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A (Accessed)** — Records when the file was last accessed. _Why:_ Nominally last-read time, but heavily unreliable in practice. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **C (Change)** — Records when the MFT record / metadata changed, not content. _Why:_ Detects metadata-only events (rename, attribute change) invisible to the other timestamps. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **B (Born / creation)** — Records when the file was created. _Why:_ First-existence marker for the file object. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **C is metadata change, distinct from M** — The C timestamp reflects a change to the MFT record/metadata, whereas M reflects content change; the two can move independently. _Why:_ A metadata-only operation updates C while leaving M untouched, distinguishing rename/move from edit. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Windows API Exposure of Timestamps

- **Three of four MACB timestamps are exposed via the Windows API** — M, A, and B are available to userland via the Windows API; C is not. _Why:_ Standard tools (Explorer, dir, PowerShell) can only show three of the four, so the C timestamp requires forensic MFT parsing. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **C timestamp is NOT exposed via the Windows API** — The MFT-record-change / metadata-change timestamp cannot be retrieved through the Windows API. _Why:_ Analysts must parse the MFT directly (e.g. MFTECmd) to see C; it is a forensic-only artifact from the OS's perspective. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Explorer default column is Modified** — Windows Explorer shows the modification time ("Date modified") by default. _Why:_ The out-of-the-box view surfaces only M unless the analyst enables other columns. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **`dir` at the Command Prompt shows the modification time by default** — A plain `dir` listing displays the same M timestamp Explorer shows by default. _Why:_ CLI and GUI default to the same single timestamp. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### $STANDARD_INFORMATION vs $FILE_NAME vs $I30 — Which Timestamps Are Shown

- **API timestamps come from $STANDARD_INFORMATION** — For a given file, the timestamps exposed to the Windows API are taken from the $STANDARD_INFORMATION ($SI) attribute inside that file's MFT record. _Why:_ Establishes $SI as the "official" API-facing timestamp set. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Folder/directory listings pull timestamps from $I30, not $SI** — When viewing a folder of files in Explorer, or a directory listing via Command Prompt or PowerShell, the displayed timestamps come from the $I30 directory index, not from $STANDARD_INFORMATION. _Why:_ Counterintuitive: the timestamps shown in a listing are physically sourced from the index, a separate copy. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **$I30 stores $FILE_NAME timestamps** — The $I30 directory index holds a set of $FILE_NAME ($FN) timestamps for the files it indexes. _Why:_ The listing timestamps are $FN-derived index copies, explaining why they can differ from $SI in edge cases. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **$I30/$FN listing timestamps almost always align with $SI** — The $FILE_NAME timestamps stored in $I30 are almost always in alignment with the $STANDARD_INFORMATION timestamps in each file's MFT record, but they are a separate set. _Why:_ Usually redundant, but a divergence between the two sets is a forensic signal. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Reason Windows uses $I30 for listings is performance** — Reading $SI would require opening the MFT file record for every file in a folder just to build the listing; using the $FN timestamps already cached in the directory index lets Windows render folder contents much faster. _Why:_ Design rationale explains why a second, index-resident timestamp copy exists at all. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Single-file Properties (Explorer right-click) uses $STANDARD_INFORMATION** — Right-clicking a single file and opening Properties derives the timestamps from $SI, not $I30. _Why:_ The data source flips based on single-file vs folder view; analysts must know which they are reading. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Single-file property queries at CLI/PowerShell use $STANDARD_INFORMATION** — Inspecting a single file's properties via Command Prompt or PowerShell pulls timestamps from $SI. _Why:_ Same source-flip rule holds at the command line. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Rule of thumb for source selection** — Single-file inspection = $SI; folder/directory-of-files view = $I30/$FN. _Why:_ One-line heuristic for predicting which timestamp copy a given tool action reveals. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Explorer Timestamp Columns and Non-Filesystem Timestamps

- **Only three filesystem timestamp columns exist in Explorer** — Explorer can display Date modified, Date created, and Date accessed as the three file-system timestamps. _Why:_ Bounds what the GUI can natively surface (C is absent). _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **"Date taken / Date visited / Date sent" are metadata, not filesystem timestamps** — Additional date columns Explorer offers (date taken, date visited, date sent, etc.) are file-type-specific metadata, not NTFS filesystem timestamps. _Why:_ Prevents mistaking application/EXIF metadata for MACB filesystem timestamps in a timeline. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### FILETIME / Timestamp Storage Facts

- **Timestamps are stored in UTC and displayed in local time** — The Properties dialog can show a value like "one minute ago" relative, but the underlying stored value is a fixed absolute time (demonstrated as 12:30:42 local for the created file). _Why:_ Relative/friendly displays hide the true stored value; forensic parsing exposes the exact time. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **All four timestamps carry sub-second (seconds and finer) precision** — The created file's timestamps resolve to the second (12:30:42) across M, A, B, and even the hidden C. _Why:_ Second-and-finer granularity is what enables timestomping detection via truncation tells (below). _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Per-Operation MACB Rule Matrix

- **File CREATE → all four timestamps set to creation time** — On creating a brand-new file, M, A, C, and B are all set to the moment of creation. _Why:_ Baseline state; a fresh file legitimately has all four timestamps equal. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File CREATE rationale** — A brand-new file has no prior history, so every timestamp defaults to the creation time. _Why:_ Explains why "all equal" is normal for new files and not itself suspicious. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File ACCESS → A updates; M, C, B unchanged** — Merely opening/reading a file (e.g. double-clicking to view) updates the access timestamp only. _Why:_ Access is nominally isolated to A, though A's reliability is separately compromised. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File MODIFY → M and A update; B unchanged; C effectively changes** — Editing and saving a file's content updates M (content changed) and A (you accessed it to edit); creation (B) does not change because a file is created only once. _Why:_ Modify touches multiple timestamps; B staying put is the invariant that a modify cannot fabricate an earlier birth. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File MODIFY leaves B (creation) untouched** — Modifying content never updates the creation timestamp, because a file can only be created once. _Why:_ B is structurally immune to content edits; a changed B under a "modify only" story is anomalous. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File RENAME → only C (metadata change) updates; M, A, B unchanged** — Renaming a file changes only the MFT-record/metadata timestamp (C); M, A, and B do not move because content wasn't changed and the file wasn't accessed. _Why:_ Rename is the canonical "C-only" event and is invisible through the Windows API (which can't see C). _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **RENAME does not change content, so M stays** — Because renaming does not alter file contents, the modification timestamp is not updated. _Why:_ Distinguishes rename from edit in a timeline. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **RENAME does not count as an access, so A stays** — Renaming a file does not update the access timestamp. _Why:_ Rules out access-time movement as evidence of a rename. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **RENAME is the only common operation whose sole visible effect is on the API-invisible C** — The one timestamp a rename updates is exactly the one not exposed via the Windows API. _Why:_ A rename can occur with zero change to any timestamp a standard tool can display, so only MFT parsing reveals it. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File COPY → B and A set to copy time; M inherited from source; C updates** — Copying a file produces a new file whose creation (B) and access (A) equal the copy time, while the modification timestamp (M) is inherited from the original file. _Why:_ Copy is the classic case where M predates B, the tell-tale "modified before it existed" signature. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **COPY: a copy is itself a new file** — The destination of a copy is a new file object, which is why its B (creation) is set to the time the copy occurred. _Why:_ Explains why copies do not preserve the original's creation time. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **COPY: modification timestamp is inherited ("comes along for the ride")** — When copying, the source file's M value is carried to the destination file. _Why:_ Key concept; the inherited M is what makes copy detection possible. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **COPY signature: M earlier than B** — After a copy, seeing a modification time that precedes the creation time is almost always indicative of a file copy, since a file cannot logically be modified before it existed. _Why:_ Primary heuristic for identifying copied files in a timeline. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **COPY inheritance works across UNC paths / mapped network drives** — Copying a file from a mapped network/UNC drive (e.g. the N: drive) to the local drive still carries the source's modification timestamp along. _Why:_ Copy-detection heuristic holds even for network-to-local copies. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Local file MOVE (same volume) → B and M unchanged; C can change; A behaves anomalously** — Moving a file within the same volume leaves creation (B) and modification (M) unchanged because it is the same file and contents are unchanged; the C (metadata) timestamp can change in certain circumstances, and the access timestamp exhibits anomalous behavior (see below). _Why:_ Move preserves the identity-defining timestamps (B, M), which is how a move is distinguished from a copy. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **MOVE preserves creation because it's the same file, not a copy** — A move relocates the existing file rather than creating a new one, so B does not change. _Why:_ The unchanged B differentiates move from copy (where B updates). _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **MOVE preserves modification because contents don't change** — Moving a file does not alter its contents, so M is unchanged. _Why:_ Confirms move is content-neutral. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **MOVE can update C in certain circumstances** — The metadata/C timestamp may change on a file move depending on circumstances. _Why:_ C movement on a move is conditional, not guaranteed; must be tested per scenario. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File-move behavior varies by scenario** — Move outcomes differ across: local move (same drive), volume move (e.g. C: → D:), and by method (Command Prompt vs cut-and-paste); the method used affects the resultant timestamps. _Why:_ There is no single "move rule"; the analyst must match the exact scenario before drawing conclusions. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **File DELETE → no MACB timestamps update, in neither $SI nor $FN** — Deleting a file updates none of the four MACB timestamps, in neither $STANDARD_INFORMATION nor $FILE_NAME. _Why:_ Deletion time cannot be recovered from the file's own timestamps; a different artifact is required. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Deletion time must come from a journal (USN Journal)** — The only way to determine when a file was deleted is via a journal; the USN Journal records a "file delete" (close/delete) op code, and if the journal's coverage window includes the deletion, the deletion time can be recovered from it. _Why:_ Redirects the analyst from useless file timestamps to the USN Journal for deletion timing. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **USN Journal has a "file delete" op code** — Deletions are recorded in the USN Journal under a file-delete op code (reason flag). _Why:_ Names the specific journal artifact used to establish deletion time. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **USN Journal is coverage-window-limited** — Recovering a deletion time from the USN Journal requires that the journal still covers the time period in which the deletion occurred. _Why:_ The journal rotates/ages out; old deletions may be unrecoverable. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### The Access (A) Timestamp — History and Unreliability

- **A timestamp disabled by default from Windows Vista onward** — Starting with Windows Vista, the registry value `NtfsDisableLastAccessUpdate` was set so that the last-access timestamp was effectively turned off and not tracked. _Why:_ Explains why access times are absent/stale on Vista through many Windows 10 builds. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Registry control is `NtfsDisableLastAccessUpdate`** — The last-access-update behavior is governed by the `NtfsDisableLastAccessUpdate` registry value. _Why:_ Names the exact setting an analyst checks to know whether A was being tracked on a system. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Reason A was disabled: performance** — Tracking last-access times for every file access imposes significant overhead, so it was disabled for performance. _Why:_ Rationale for the long-standing default-off state. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A-disabled state persisted through many Windows 10 builds** — The last-access-update-off default remained in effect for a long time, into some builds of Windows 10. _Why:_ Sets the version boundary where analysts should assume A is unreliable/off. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A re-enabled conditionally on ≤128 GB boot drives (a Windows 10 build change)** — A few Windows 10 builds ago, the setting changed so that systems with a boot drive of 128 GB or smaller had the last-access timestamp turned back on and tracked. _Why:_ Introduces a drive-size-dependent A behavior an analyst must account for on specific builds. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A later fully re-enabled regardless of boot-drive size** — A subsequent change fully re-enabled last-access tracking irrespective of boot-drive size, applying through Windows 11. _Why:_ Modern Windows (through 11) tracks A again by default, reverting to pre-Vista behavior. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Modern Windows A behavior mirrors pre-Vista** — With A re-enabled, current Windows behaves as it did before Vista, where date-accessed is tracked. _Why:_ Frames the historical arc: on → off (Vista) → conditional → on again. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A is "the most useless timestamp in Windows" — do not trust it** — Even when tracked, the access timestamp should not be used to draw investigative conclusions because too many operations update it. _Why:_ Strong practitioner caution: exclude A from load-bearing timeline reasoning. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **A can be updated by AV/anti-malware scans and other organic operations** — Antivirus scans, anti-malware scans, and various background OS operations can update the access timestamp without user interaction. _Why:_ Explains why A is unreliable — it moves for reasons unrelated to user access. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Trust only M and B for investigative conclusions** — Practitioner guidance: rely on the modification and birth/creation timestamps; ignore access when drawing conclusions. _Why:_ Distills which timestamps carry evidential weight. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Anomalous A on local move (newer Windows 11 builds)** — On a local file move in a newer Windows 11 build, the access timestamp was updated to an approximate value that was neither the current time nor left unchanged — apparently set to the time the file was last actually accessed (~2 minutes before the move), not the move time. _Why:_ Demonstrates A's erratic, version-specific behavior and reinforces distrusting it. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Observed A-on-move contradicts the SANS poster** — The SANS "red poster" states the access time updates to the time of a local file move, but in the tested Windows 11 22H2 build A was NOT set to the move time. _Why:_ Concrete example that published rule charts lag actual OS behavior; verify empirically. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Timestomping Detection ($SI vs $FN)

- **$FILE_NAME timestamps are kernel-managed and not settable via the Windows API** — $FN timestamps cannot be directly set by userland/API calls the way $SI timestamps can; they are maintained by the kernel. _Why:_ Foundation of timestomping detection — attackers can rewrite $SI but not $FN through normal API means. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **$STANDARD_INFORMATION timestamps are user/API-settable** — $SI timestamps can be set through the Windows API (the surface timestomping tools manipulate). _Why:_ $SI is the manipulable set; a mismatch against $FN exposes tampering. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Timestomping tell: $SI earlier/inconsistent vs $FN** — A $SI timestamp that predates or is inconsistent with the corresponding $FN timestamp indicates possible timestomping, because a legitimate file's $SI and $FN normally align. _Why:_ Core anti-forensic detection heuristic; drives comparison of the two timestamp sets. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Nanosecond-truncation tell** — Some timestomping tools set $SI timestamps with zeroed sub-second (nanosecond) precision, so a $SI timestamp reading exactly on the second while $FN retains full precision is a manipulation indicator. _Why:_ Precision loss is a cheap, high-signal timestomping detector. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Timestamp Set Enumeration Per MFT Record

- **$FILE_NAME holds a second full MACB set** — Beyond $STANDARD_INFORMATION's four timestamps, $FILE_NAME stores its own second set of MACB timestamps. _Why:_ Two independent MACB sets per name enable cross-checking for tampering. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Long file names produce a second $FILE_NAME attribute (8.3 short name)** — A file with a long name (e.g. `Secret Chicken Recipe.docx`) also gets a short-name (8.3) $FILE_NAME attribute for backward compatibility, each with its own MACB set. _Why:_ Doubles the $FN timestamp sets, adding more cross-check surface. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **8.3 legacy: 8 chars name + 3 chars extension** — The DOS 8.3 convention allowed eight characters for the name and three for the extension; Windows retains a backward-compatible 8.3 short name (e.g. `SECRE~1.xxx`, truncated with a tilde). _Why:_ Explains the origin and format of the short-name attribute that carries extra timestamps. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Up to two $FILE_NAME attributes → up to 12 timestamps in the MFT record** — With both a long-name and a short-name $FN attribute plus $SI, a single MFT file record can hold up to 12 timestamps (4 in $SI + 4 + 4 in the two $FN attributes). _Why:_ Quantifies the timestamp surface inside one MFT record. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **$I30 stores its own MACB set aligning with $SI** — The $I30 directory index stores an additional MACB set that usually aligns with the $STANDARD_INFORMATION timestamps. _Why:_ Adds another comparison copy outside the MFT record. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **$I30 can store a second (short-name) MACB set** — When a long file name requires a short-name entry, the $I30 index can hold yet another MACB set for it. _Why:_ Explains how the total climbs beyond the in-record 12. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Grand total: up to 20 filesystem timestamps per file (plus USN)** — Summing $SI (4) + two $FN (8) + two $I30 (8) yields up to 20 timestamps for one file, and that count excludes the timestamp tracked in the USN Journal. _Why:_ Full accounting of the timestamp copies an analyst may need to reconcile for one file. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **USN Journal is an additional timestamp source beyond the 20** — The USN Journal tracks its own timestamp(s) for the file, separate from the ~20 filesystem timestamps. _Why:_ Reminds that journal-based timing supplements the record/index timestamps. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Reference Charts and Verification Discipline

- **SANS "red poster" = Windows Forensic Analysis poster** — The SANS Windows Forensic Analysis poster (nicknamed the "red poster") includes a "Windows Time Rules" section on its right side. _Why:_ Names the standard quick-reference for per-operation timestamp behavior. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Newer red poster shows $SI twice and dropped $FN** — Older versions of the poster showed both $STANDARD_INFORMATION and $FILE_NAME time rules; newer versions (e.g. Windows 11 22H2 edition) show $STANDARD_INFORMATION twice and no longer show $FILE_NAME. _Why:_ Analysts using the current poster lose the $FN column and must seek $FN rules elsewhere. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Poster versions referenced: Win10 1903 and Win11 22H2** — The lesson contrasts a Windows 10 version 1903 poster with a Windows 11 version 22H2 poster. _Why:_ Version-tags the rule charts, since timestamp rules are OS-version-specific. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Poster footnote: timestamp updates depend on OS version and specific action combinations** — The current poster explicitly warns that Windows timestamp updates are notoriously dependent on the OS version and a very specific combination of actions. _Why:_ Authoritative caveat that no static chart is universally correct. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Do not treat timestamp rules as gospel — test on the matching OS build** — When timestamps are load-bearing for a case, spin up a VM/sandbox with the exact same OS version and empirically test whether timestamps behave as expected before drawing conclusions. _Why:_ Prescribes the verification workflow that protects against version-specific timestamp behavior. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Timestamp behavior is still changing in the newest Windows 11 builds** — Timestamp update rules continue to change even in the latest Windows 11 builds. _Why:_ Justifies ongoing empirical testing rather than reliance on documented rules. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Alternative chart resource: khyrenz.com Windows 11 time rules** — A SANS instructor's chart at khyrenz.com (searchable as "khyrenz Windows 11 time rules") shows both $STANDARD_INFORMATION and $FILE_NAME rules, restoring the $FN column the SANS poster dropped. _Why:_ Named secondary reference that still covers $FN behavior. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Khyrenz chart color-codes recent Windows 11 changes (peach)** — On the khyrenz chart, cells shown in peach color mark behaviors specific to recent Windows 11 changes. _Why:_ Helps analysts spot which rules are new/volatile versus long-standing. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Chart example — file creation: all $SI and $FN MACB set to creation time** — The khyrenz chart shows file creation sets every MACB in both $SI and $FN to the creation time. _Why:_ Confirms the "all four equal on create" rule across both timestamp sets. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Chart example — file modification: $FN unchanged, $SI changes** — On file modification the $FILE_NAME timestamps show no change while $STANDARD_INFORMATION timestamps do change. _Why:_ $FN's immunity to content modification is exactly what makes $SI-vs-$FN timestomp detection work. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Charts can be wrong for your build — verified example (local move A time)** — The khyrenz/$SI chart lists local file move (cut & paste) on Windows 11 as updating access to "time of file move," yet live testing showed A was not updated to the move time. _Why:_ Reinforces that even the better chart diverges from observed behavior; test-and-verify remains mandatory. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **Related deep-dive: 13cubed "It's About Time"** — A companion 13cubed episode titled "It's About Time" covers these timestamps and their odd behavior in recent Windows builds, and features the khyrenz chart. _Why:_ Points to further material on anomalous modern timestamp behavior. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

### Tooling and Demo Context

- **Demo environment: Windows 11 Sandbox** — The operation walkthrough was performed in Windows 11 Sandbox. _Why:_ Sandbox/VM is the recommended safe surface for empirically testing timestamp rules on a target OS version. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **`copy con FILENAME` creates a file at the console (MS-DOS method)** — `copy con 13Cubed.txt` reads console input into a new file; F6 inserts the Ctrl-Z (`^Z`) EOF marker and Enter finalizes ("1 file copied"). _Why:_ Legacy file-creation technique used in the demo; useful for controlled timestamp tests. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_
- **MFTECmd is the tool used to parse these timestamps** — The lesson transitions to a demo of MFTECmd to parse the MFT and reveal these timestamps (including the API-invisible C). _Why:_ Names the primary MFT-parsing utility for extracting all $SI/$FN MACB sets forensically. _[IWE ch06 · Anatomy of NTFS / MACB Timestamps]_

## Chapter 06 · Metafiles MFT Journaling ADS

### NTFS metadata files (metafiles) — general

- **NTFS metafiles** — The "$"-prefixed files visible at the root of an NTFS volume are the NTFS metadata files (also called meta files); they are the structural building blocks of the file system. _Why:_ Establishes that these are OS-internal structures, not user files. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Metafile naming** — NTFS metadata files use a leading dollar sign in their names (e.g. $Boot, $MFT, $Bitmap). _Why:_ The "$" prefix is the visual cue that identifies a system metafile during triage. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Root-of-volume visibility** — These metafiles can be observed at the root of the OS partition using a forensic imaging tool such as FTK Imager (added via File → Add Evidence Item → Physical Drive → the OS volume/partition). _Why:_ Documents a practical way to surface metafiles for inspection. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **External reference resource** — ntfs.com (and its NTFS overview pages) is cited as an in-depth free reference on NTFS internals beyond lesson scope. _Why:_ Points to a secondary reference (still requires primary-source verification). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $Boot

- **$Boot / partition boot sector** — The first structure on an NTFS volume is the partition boot sector, also called sector zero. _Why:_ Defines the fixed starting point of an NTFS volume. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$Boot role — volume description** — The $Boot metafile describes basic volume information to the file system. _Why:_ $Boot is the bootstrap descriptor the OS reads to understand the volume geometry. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$Boot role — locating the MFT** — $Boot records the on-disk location of the main NTFS metadata file, the $MFT. _Why:_ Without $Boot's pointer, the OS cannot find the MFT to mount the volume; forensically it is how you locate the MFT start. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $MFT (Master File Table)

- **MFT is a database** — The $MFT is fundamentally a database and is the single most important component of the NTFS file system. _Why:_ Frames the MFT as the authoritative index all analysis depends on. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MFT holds filesystem namespace** — File names, directory names, and essentially everything a user interacts with on the file system are stored in the MFT. _Why:_ The MFT is where the human-visible namespace lives. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MFT as the map to data** — Without the MFT there is no map for the file system to find and recall data on the disk; the OS consults the MFT to learn where a file's pieces reside so it can reassemble and present the file. _Why:_ Loss/corruption of the MFT effectively orphans the data; explains why the MFT is the priority artifact. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MFT comprises file records** — The MFT is made up of database records, each of which is called a file record. _Why:_ Sets the unit of parsing for MFT analysis. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **File record size — 1024 bytes typical** — MFT file records are usually 1,024 bytes in size. _Why:_ The default record stride used when carving/parsing the MFT. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **File record size — up to 4096 bytes on AF drives** — File records can be up to 4,096 bytes on Advanced Format (AF) drives that use 4K sector sizes. _Why:_ Parsing must not assume a fixed 1024-byte stride; 4K-sector media can differ. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **File record signature "FILE"** — Each MFT file record begins with a magic signature: bytes 46 49 4C 45, which is ASCII "FILE". _Why:_ The record-start marker used to locate/validate file records in a hex view or carver. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Bad-record signature "BAAD"** — A file record may instead begin with ASCII "BAAD" (bytes 42 41 41 44), which indicates the record is bad/corrupted. _Why:_ Signals data corruption at that record; a diagnostic to flag rather than trust. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **One record per file** — Every file record represents a file; a file (e.g. 13cubed.txt on the desktop) has a corresponding file record in the MFT. _Why:_ One-to-one mapping is the basis for enumerating files from the MFT. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Record count scale** — A system can contain tens of thousands to hundreds of thousands of MFT file records. _Why:_ Sets expectations for MFT volume/size during processing. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Records contain attributes** — A single file record contains many structures/attributes (the lesson notes even its diagram does not cover them all). _Why:_ File records are attribute containers; parsing means walking attributes. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Manual hex extraction as fallback** — In cases of data corruption or when a tool cannot parse correctly, an examiner can open a hex editor and manually extract values (e.g. timestamps) directly from a file record. _Why:_ Justifies knowing the byte-level layout for edge cases; low-level knowledge is a real fallback. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $STANDARD_INFORMATION vs $FILE_NAME (timestamps)

- **$STANDARD_INFORMATION attribute** — One of the two most important structures in a file record; among other things it holds a set of MACB timestamps. _Why:_ Primary timestamp source consumed by the Windows API. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MACB definition** — MACB expands to Modification (M), Access (A), MFT-record change / metadata change (C), and Birth/creation (B). _Why:_ Fixes the meaning of each of the four timestamps analysts rely on. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **API exposes only M, A, B** — The Windows API exposes three of the four $STANDARD_INFORMATION timestamps: Modification, Access, and Birth. _Why:_ Explains what a user/tool sees via normal Windows properties. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **C timestamp hidden from API** — The C (MFT-record change / metadata change) timestamp is NOT exposed to the Windows API. _Why:_ The C value is only visible through forensic parsing, making it useful for detecting manipulation. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$FILE_NAME attribute** — The other key file-record structure; among other things it stores the file's name and its OWN set of MACB timestamps. _Why:_ There are two independent timestamp sets per file — a core anti-timestomping fact. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Two independent MACB sets** — A given file has two MACB timestamp sets: one in $STANDARD_INFORMATION and a separate one in $FILE_NAME, and they are not updated the same way. _Why:_ The divergence between the two sets is the basis for time-stomping detection. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$FILE_NAME timestamps hidden from API** — $FILE_NAME timestamps are not exposed to the Windows API. _Why:_ Only forensic tools surface them, so an attacker using API-level tools may not alter them. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$FILE_NAME kernel-only (nominally)** — $FILE_NAME timestamps are technically only supposed to be modifiable by the Windows kernel. _Why:_ Explains why they are considered harder to forge — but not impossible. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$FILE_NAME still forgeable** — "Kernel-only modifiable" does NOT mean $FILE_NAME timestamps can never be altered maliciously. _Why:_ Cautions against treating $FILE_NAME values as tamper-proof ground truth. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Time stomping detection

- **Time-stomping technique** — Threat actors alter (backdate) a file's creation/birth and modification timestamps to make a file appear to have been present longer than it has, so it blends in with surrounding files. _Why:_ Explains the adversary goal that the detection method counters. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Time-stomping example** — E.g. dropping a DLL into Windows\System32 and backdating it to approximate the dates of legitimate files already in that directory. _Why:_ Concrete anti-forensic scenario an examiner should anticipate. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Detection by SI-vs-FN comparison** — A standard detection method: compare the Birth (B) and Modification (M) timestamps in $STANDARD_INFORMATION against the B and M timestamps in $FILE_NAME. _Why:_ The canonical first-pass time-stomping check. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Detection signature** — If $STANDARD_INFORMATION timestamps appear backdated (older) while the corresponding $FILE_NAME timestamps are different / more recent (in the future relative to SI), the file was very likely time stomped. _Why:_ Defines the specific pattern that flags manipulation. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Evasion — stomp then rename/move** — An attacker can defeat the SI-vs-FN comparison by time stomping and then renaming or moving the file, because a rename/move causes the $FILE_NAME timestamps to be updated to match the (stomped) $STANDARD_INFORMATION values. _Why:_ Warns that a matching SI/FN pair does not prove innocence. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Recourse after evasion — the journal** — When rename/move has synchronized the SI and FN timestamps, the remaining way to determine that stomping occurred is to consult one of the file system journals (the USN Journal). _Why:_ Establishes the journal as the fallback evidence when timestamps have been reconciled. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $DATA — resident vs non-resident

- **$DATA attribute** — The $DATA structure in a file record holds (or points to) the file's content; every file is stored in one of two states, resident or non-resident. _Why:_ Determines where a file's bytes actually live and how to recover them. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Non-resident file** — A non-resident file is a typical file (e.g. a Word doc or an image of several hundred KB or several MB) whose content is stored out on disk, not inside the record. _Why:_ Most user files are non-resident; their bytes are recovered via cluster runs. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Data runs** — A non-resident file has one or more data runs that track which clusters on disk contain the file's data. _Why:_ Data runs are the map used to reassemble a non-resident file. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Data runs = cluster map** — The data runs act as a map telling the file system which clusters to read and in what order to reconstruct the file and present it. _Why:_ Core mechanic of file reconstruction and carving from MFT metadata. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Resident file** — A resident file is a very small file (typically 600 bytes or less) whose actual content is stored inside the MFT file record itself. _Why:_ Small-file content is recovered directly from the MFT with no disk read. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Resident threshold ~600 bytes** — If a file is roughly 600 bytes or less it is stored as a resident file. _Why:_ Rule of thumb for whether content lives in-record. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Resident content in-record example** — A small Notepad file (e.g. "Hello, I am a resident file. Also, please subscribe to 13cubed!") is stored verbatim within its own MFT file record because it is far under 600 bytes. _Why:_ Demonstrates that an MFT-only artifact can contain full file content. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Resident rationale — efficiency** — Storing tiny files resident avoids wasting a full cluster; the default NTFS cluster is 4 KB (4,096 bytes), so allocating a whole cluster for a sub-600-byte file would be wasteful. _Why:_ Explains the design motive behind residency. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Most files are non-resident** — The majority of files an analyst thinks of are non-resident because they exceed ~600 bytes. _Why:_ Sets the default expectation for content location. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $MFTMirr

- **$MFTMirr is a partial mirror** — $MFTMirr is not a mirror of the entire MFT; it is a duplicate image of only the first four records of the MFT. _Why:_ Corrects the common misconception that it backs up the whole table. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$MFTMirr purpose** — Its purpose is to guarantee access to the (start of the) MFT in the event of a single-sector failure on the drive — a contingency/recovery mechanism. _Why:_ Explains its redundancy role and why only the critical first records are duplicated. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $Bitmap and clusters

- **$Bitmap content** — $Bitmap is literally a bitmap: a list of ones and zeros tracking the clusters on the disk. _Why:_ It is the allocation ledger for the volume. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$Bitmap role** — $Bitmap records which clusters are in use versus not in use. _Why:_ Distinguishes allocated from unallocated space — foundational for recovery/carving. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Not-in-use means overwritable** — A cluster marked "not in use" is available to be written to. _Why:_ Explains why deleted-file clusters are at risk of being reused/overwritten. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Sector vs cluster** — A sector is the smallest hardware storage unit; within the OS the smallest unit of storage measurement is a cluster, which is a combination of multiple sectors. _Why:_ Clarifies the unit the file system actually allocates in. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Cluster is the lowest OS-level unit** — The cluster is the lowest-level allocation unit tracked by the file system. _Why:_ Allocation and data runs are expressed in clusters, not sectors. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Typical NTFS cluster size 4K** — A typical/default NTFS cluster size is 4 KB (4,096 bytes). _Why:_ Needed to convert cluster offsets to byte offsets and to reason about slack. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Multi-cluster files** — A single non-resident file may occupy dozens, hundreds, or more clusters. _Why:_ Files can be heavily fragmented across many cluster runs. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $Secure

- **$Secure role** — $Secure tracks security-related information for files. _Why:_ Central store for security descriptors/ACL data on the volume. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $I30 directory indexes

- **$I30 is per-directory** — A $I30 structure exists in every directory across the entire file system. _Why:_ Directory-listing metadata is pervasive and repeatable to analyze. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 = three attributes** — $I30 is a virtual representation of three attributes: $INDEX_ROOT, $INDEX_ALLOCATION, and $Bitmap. _Why:_ Identifies the underlying components a parser must handle. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 tracks directory contents** — $I30 records which files and directories are stored inside a given directory — a list of what is in that directory, not the contents of the files. _Why:_ It is a directory catalog, useful for reconstructing what a folder held. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 per-entry fields** — For each listed item, $I30 tracks a set of timestamps, the file name, and the file size. _Why:_ These fields survive in the index and can reconstruct metadata of listed/removed files. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 is a B-tree index** — $I30 is implemented as a B-tree index. _Why:_ Its tree structure is why entries shift and leave slack. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **B-tree rebalancing** — The B-tree index is rebalanced every time the directory's contents change (a file is added to or removed from the directory), shifting entries around. _Why:_ Rebalancing is the mechanism that creates recoverable slack. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 slack space** — Because of rebalancing, slack space can exist inside a $I30 index. _Why:_ That slack is the forensic payload of index analysis. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 slack evidences deleted files** — Slack in a directory's $I30 may retain evidence of a file that no longer exists on disk — sometimes the only proof a file was ever in that location. _Why:_ Enables proving prior existence of a since-deleted file. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$I30 slack recovers metadata** — From $I30 slack an examiner may recover the original file's timestamps, its name, and even its size. _Why:_ Concrete metadata recoverable even after deletion. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $Extend directory

- **$Extend is a directory** — $Extend is presented as a directory (not a file) and contains additional metadata. _Why:_ It is a container of further metafiles, including a journal. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$Extend contents** — $Extend holds items such as quotas, reparse point data, and object identifiers. _Why:_ Enumerates secondary metadata stores worth examining. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Reparse point = symlink analog** — A reparse point is similar to a symbolic link on a Unix/Linux system. _Why:_ Frames reparse points for cross-platform-familiar analysts. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$Extend holds a journal** — One of the two NTFS file system journals (the $UsnJrnl / USN Journal) is stored inside $Extend. _Why:_ Tells the analyst where to find the high-value USN Journal on disk. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### File system journaling — general

- **Journaling definition** — File system journaling is a record of what has happened on the file system — a log of all changes made to a volume. _Why:_ Establishes the journal as a change-history source. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Journaling operational purpose** — After a crash or power failure, the system uses journal information to roll back changes or resume where it left off, maintaining file-system integrity and preventing catastrophic outcomes like data loss. _Why:_ Explains the non-forensic reason journals exist (and thus why they are populated). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Two journals in NTFS** — NTFS has two file system journals: $LogFile and $UsnJrnl (the USN Journal). _Why:_ Analyst must know both exist and their different value. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Forensic value of journals** — Journals can supply evidence of file creations, deletions, renames, and more. _Why:_ Core reason journals are examined in investigations. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **No deletion timestamp in MACB** — MACB contains no "D" (deletion) timestamp; the file system does not store a deletion time in the standard timestamps. _Why:_ Motivates using the journal to establish deletion times. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Deletion time via journal** — One of the only ways to determine when something was deleted is via a file system journal. _Why:_ Positions the journal as the primary source for deletion timing. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $LogFile (low-level journal)

- **$LogFile granularity** — $LogFile tracks very low-level changes to the file system and is very busy. _Why:_ Its verbosity affects both its value and its short time horizon. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$LogFile op codes** — $LogFile contains many op codes (operation codes) such as "initialize file record segment", "add index entry allocation", and "delete index entry allocation". _Why:_ These low-level opcodes are harder to interpret than USN reason codes. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$LogFile short horizon** — Because it is so busy, $LogFile may only reach back hours or perhaps days — probably just hours. _Why:_ Its short retention limits its usefulness for older activity. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$LogFile secondary priority** — Forensically, $LogFile is generally not the journal of primary interest and is rarely examined in most cases, though it is not without value. _Why:_ Guides triage effort toward the USN Journal first. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### $UsnJrnl (USN Journal — high-level journal)

- **USN expansion** — $UsnJrnl is the USN Journal, i.e. the Update Sequence Number journal. _Why:_ Correct naming for reports and tool output. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN Journal priority artifact** — The USN Journal is the high-value, high-level file system journal and an important Windows forensic artifact analysts should know. _Why:_ Directs primary journal analysis to $UsnJrnl. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN tracks high-level changes** — The USN Journal records high-level changes to a volume and is efficient in how it monitors activity. _Why:_ Its higher abstraction makes its records easier to interpret than $LogFile. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN longer horizon** — The USN Journal's event horizon can extend days and possibly weeks depending on system busyness — further back in time than $LogFile. _Why:_ Enables reconstructing older activity than $LogFile allows. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN reason/op codes** — USN Journal op codes are intuitive, e.g. File Create, File Delete, Rename Old Name, Rename New Name, Data Overwrite. _Why:_ These reason codes directly map to investigative questions (what was created/deleted/renamed). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN detects deletions** — The USN Journal will show file deletions, making it valuable against anti-forensics (a threat actor deleting malware/tools to cover tracks). _Why:_ Recovers evidence of removed attacker artifacts. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **USN create-then-delete timeline** — The USN Journal can reveal exactly when something was created and subsequently deleted. _Why:_ Reconstructs the full lifecycle of a transient malicious file. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$UsnJrnl:$Max** — Inside $UsnJrnl, the $Max stream is just metadata for the journal. _Why:_ Distinguishes the metadata stream from the actual journal data. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$UsnJrnl:$J is the journal** — The $J stream is the actual journal — the meat of the file, the real record data — and is the target you point MFTECmd at. _Why:_ Tells the analyst which stream to parse. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$J is an ADS** — $J is an alternate data stream inside the $UsnJrnl file. _Why:_ Explains why the journal presents as a "file within a file" and how it is addressed. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$J is a sparse file** — The $J stream is also a sparse file: much of it is zero/empty and appears as long runs of zero bytes when viewed. _Why:_ Its apparent large size overstates real disk usage; parsing must handle sparse zero regions. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Sparse files

- **Sparse file definition** — A file is considered sparse when most of its data is zero/empty. _Why:_ Defines the class of files (like $J) whose stored size differs from allocated size. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Sparse allocation behavior** — For a sparse file the OS does not allocate real disk space except in regions that actually contain non-zero data; the zero regions take up no real space. _Why:_ Explains efficient storage and why apparent size can mislead. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Sparse purpose** — Sparse files provide efficient storage management for NTFS. _Why:_ Design rationale for the feature. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Alternate Data Streams (ADS)

- **ADS definition** — An alternate data stream (ADS) is an additional data stream attached to a file — another piece of data stored inside that file's NTFS MFT file record. _Why:_ Files can carry hidden secondary content beyond the visible primary stream. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS origin** — ADS was added to NTFS back in the Windows NT days for compatibility/interoperability with Macintosh HFS (Hierarchical File System), which used a resource fork and a data fork. _Why:_ Historical rationale explaining why the feature exists in NTFS. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS legitimate uses** — ADS is still used today for legitimate OS purposes (e.g. the $J USN Journal stream and the Zone.Identifier download marker). _Why:_ ADS is a normal, expected structure, not inherently malicious. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS abuse** — When ADS was first discovered it became a way to hide contraband or malware inside a file's alternate stream. _Why:_ Establishes ADS as a known hiding technique to check for. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS less stealthy now** — ADS hiding is less stealthy today because forensic practitioners know ADS exists and routinely look for them. _Why:_ Realistic assessment of the technique's current concealment value. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS naming syntax** — An ADS is addressed as `filename:streamname` (e.g. `13cubed.txt:secret`). _Why:_ The colon syntax is how ADS are created, read, and referenced. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS creation via Notepad** — An ADS can be created by opening `notepad filename.txt:streamname`, entering content, and saving (Notepad prompts to create the stream if absent). _Why:_ Demonstrates how trivially ADS content is written. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS invisible to size/date** — Adding an ADS does not change the host file's reported size or modification time in a normal `dir` listing (host file still shows the same byte count, e.g. 22 bytes, and same timestamp). _Why:_ Explains why ADS content is not obvious from ordinary directory metadata. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ADS invisible in Explorer properties** — A file carrying an ADS shows no indication of the hidden stream via right-click → Properties; it appears to be a normal text file. _Why:_ GUI inspection alone will miss ADS. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **dir /r reveals ADS** — The `dir /r` switch displays alternate data streams of files, listing the ADS beneath the host file name. _Why:_ The built-in command to enumerate ADS during triage. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Reading ADS content** — ADS content can be echoed with the built-in `more` command by feeding it the stream (e.g. `more < 13cubed.txt:secret`). _Why:_ A native way to view stream contents without extra tools. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Zone.Identifier / Mark-of-the-Web

- **Zone.Identifier is an OS-created ADS** — Files downloaded from internet locations get a Zone.Identifier alternate data stream automatically appended by the operating system (not by the user and not embedded in the download). _Why:_ Establishes provenance of the marker — it is OS-generated evidence of download. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Zone.Identifier stores host URL** — The Zone.Identifier ADS embeds metadata for the downloaded file, including the host URL — the actual source URL from which the file was downloaded. _Why:_ Directly attributes a suspicious file's origin. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Zone.Identifier read via ADS** — The Zone.Identifier can be read the same way as any ADS (e.g. `more < file:Zone.Identifier`). _Why:_ Practical retrieval method for the download provenance data. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ZoneId=3 = Internet** — A ZoneId value of 3 means the file came from the Internet — the typical value seen on internet-downloaded files. _Why:_ The most common MOTW zone in investigations, indicating external origin. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ZoneId=0 = Local Computer** — ZoneId 0 corresponds to the local computer. _Why:_ Distinguishes locally-originated files. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ZoneId=1 = Local Intranet** — ZoneId 1 is the local intranet zone. _Why:_ Indicates an intranet source. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ZoneId=2 = Trusted Site** — ZoneId 2 is a trusted site, definable on the system. _Why:_ Source was an admin-defined trusted location. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **ZoneId=4 = Restricted Site** — ZoneId 4 is a restricted site. _Why:_ Completes the zone enumeration (0–4). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Tools & workflow

- **MFTECmd (Eric Zimmerman)** — The MFT is parsed into human-readable output using MFTECmd, a tool from Eric Zimmerman. _Why:_ Names the standard tool for MFT parsing. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MFTECmd parses USN Journal** — MFTECmd is also used to parse the USN Journal, specifically pointed at the $J stream. _Why:_ Same tool covers both MFT and USN Journal; target the $J ADS. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Analysis uses parsed output** — Practical NTFS forensics is normally performed on the parsed, human-readable output of the MFT and journals, not raw hex. _Why:_ Sets realistic workflow expectations; hex is the exception. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **Anatomy-of-a-file-record reference** — 13cubed.com publishes an "Anatomy of an NTFS File Record" reference that documents exactly how a file record is constructed; memorization of the byte layout is unnecessary because the reference exists. _Why:_ Points to a layout reference for manual parsing (still needs primary-source cross-check). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **MACB behavior demo method** — MACB timestamp update behavior is demonstrated in Windows Sandbox by creating, copying, moving, and renaming files and observing how each MACB timestamp changes. _Why:_ Documents the experimental method for learning timestamp rules (covered in the next lesson). _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

### Other file-record fields noted

- **File Size field** — A file record also stores the File Size. _Why:_ Size is available directly from record metadata. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_
- **$EA extended attribute** — A file record can contain $EA (Extended Attribute) and extended-attribute information. _Why:_ Additional attribute type present in some records. _[IWE ch06 · Anatomy of NTFS / Metafiles, MFT, Journaling, ADS]_

## Chapter 06 · Parsing MFT USN

### Extracting the artifacts (prerequisite step)

- **MFTECmd input requirement** — Before MFTECmd can parse the `$MFT` and USN Journal, you must first export copies of those two NTFS metadata files off the target system; MFTECmd operates on the exported files, not the live volume. _Why:_ The metadata files are locked/special system files on a mounted NTFS volume and need a forensic extraction step first. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **FTK Imager export method** — One way to export the two NTFS metadata files is FTK Imager: locate the files, right-click each, and choose "Export Files." _Why:_ FTK Imager can read raw NTFS structures and copy protected system files a normal file copy cannot. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **CAPE as an alternative collector** — A collection tool (referred to as "CAPE" in the demo) can extract these artifacts using a predefined target called "file system." _Why:_ Automated targeted collection is faster and more repeatable than manually locating files. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **"file system" target scope** — The collector's "file system" target (described as "file system metadata") grabs the `$MFT`, the USN Journal, the `$LogFile` (the other NTFS journal), and several additional NTFS metadata files. _Why:_ A single target pulls all NTFS journaling/metadata artifacts at once. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Collector configuration** — In the demo the collector was configured with source = C (the C: volume), destination = a "demo" folder created on the desktop, and target = file system, with "use target options" enabled. _Why:_ Documents a minimal working collection configuration. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Collection runtime** — Extracting these file-system artifacts typically takes roughly 10–20 seconds. _Why:_ Sets an operational expectation for the collection step. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Only two artifacts needed for this workflow** — Although the collector grabs several metadata files, this parsing workflow only needs the `$MFT` and the USN Journal; MFTECmd is simply pointed at those two. _Why:_ Focuses effort on the two highest-value artifacts. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Volume Shadow Copy processing (extending the event horizon)

- **Process VSCs option** — The collector offers a "process VSCs" option that finds any Volume Shadow Copies on the system and parses the same artifacts from within those shadow copies. _Why:_ Shadow copies preserve older states of the file-system journals. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Why parse VSC journals** — The USN Journal is finite and rolls over; if a USN Journal event of interest predates the current journal's earliest entry, a Volume Shadow Copy (e.g. one from a week earlier) may contain a USN Journal that still covers that time period. _Why:_ Recovers evidence the live journal has already aged out. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Event-horizon extension** — Parsing the USN Journal from a Volume Shadow Copy shows what the journal looked like at the moment that shadow copy was created, effectively extending the investigative "event horizon" further back in time. _Why:_ A practical technique to look back beyond the current journal's window. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### MFTECmd — supported file types and options

- **`-f` flag** — MFTECmd uses `-f` to specify the file to process. _Why:_ Core input flag for all MFTECmd parsing. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Supported `$MFT` parsing** — MFTECmd parses the `$MFT`. _Why:_ The MFT is the master index of all files on an NTFS volume. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`$J` is the USN Journal data stream** — MFTECmd parses `$J`, which is the alternate data stream of the USN Journal (`$UsnJrnl:$J`) that holds the actual journal change records to be processed. _Why:_ The USN change data lives in the `$J` ADS, not the base file, so you must target `$J` specifically. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Supported `$I30` parsing** — MFTECmd also supports parsing `$I30` (NTFS directory index) files. _Why:_ `$I30` index records can reveal deleted directory entries. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`$LogFile` not supported** — MFTECmd does not (at the time of the lesson) parse `$LogFile`, the NTFS transaction log / the other journal. _Why:_ You need a different tool to analyze `$LogFile`; don't expect MFTECmd to handle it. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`--csv` output flag** — `--csv <path>` tells MFTECmd to write output in CSV format to the specified directory. _Why:_ CSV is the format consumed by Timeline Explorer for review. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`--csvf` output filename** — `--csvf <name>` optionally sets the output CSV's filename. _Why:_ Lets you name outputs meaningfully (e.g. `mft.csv`, `usn.csv`). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **The three common flags** — For most work only three MFTECmd options are needed: `-f` (input file), `--csv` (output directory), and `--csvf` (output filename). _Why:_ Keeps the common workflow simple. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`--dr` dumps resident files** — The `--dr` option tells MFTECmd to dump out the contents of resident files stored inside the MFT. _Why:_ Lets you recover small file contents directly from MFT records without touching the disk. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Running MFTECmd with no options** — Running `MFTECmd.exe` with no arguments prints the available options/help. _Why:_ Quick way to review the flag set. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **File-type auto-detection** — When fed a file, MFTECmd auto-detects and reports the artifact type (e.g. it prints "file type: MFT"), rather than requiring you to declare it. _Why:_ Confirms the tool correctly identified the artifact before parsing. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Parse runtime** — Parsing the MFT with MFTECmd typically takes roughly 10–20 seconds. _Why:_ Operational expectation for the parse step. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Resident files

- **Resident file definition** — A resident file is one small enough (approximately 600 bytes or less) that its entire contents fit inside its MFT file record itself, with no external data runs. _Why:_ Resident data is fully recoverable from the MFT alone. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Bulk resident extraction** — `--dr` can quickly dump all resident files present in an MFT in one pass. _Why:_ Efficient recovery of many small files' full contents from a single MFT. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Example MFTECmd invocations (from the demo)

- **MFT parse command shape** — The MFT was parsed by pointing `-f` at the extracted `$MFT` under `...\demo\C\$MFT`, with `--csv` set to the desktop and `--csvf mft.csv`. _Why:_ Concrete template for parsing an exported MFT. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **USN Journal path** — The USN Journal's `$J` stream is located at `\$Extend\$UsnJrnl:$J`; in the demo the input path was `...\demo\C\$Extend\$J` with `--csvf usn.csv`. _Why:_ The USN Journal lives under the NTFS `$Extend` metadata directory. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Two-output result** — The workflow produces two separate CSVs: `mft.csv` (parsed MFT) and `usn.csv` (parsed USN Journal). _Why:_ These two files are then correlated during review. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Reviewing the MFT CSV in Timeline Explorer

- **Timeline Explorer review** — The parsed CSVs are opened in Timeline Explorer for review. _Why:_ Timeline Explorer provides filtering, tagging, and searching over the large parsed output. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **MFT record volume** — A single MFT parse in the demo produced roughly 996,518 rows (nearly one million file records). _Why:_ Illustrates the scale of MFT data and the need for filtering/search. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Line number column** — The CSV includes a line-number column. _Why:_ Row reference for navigation. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Tag column** — Timeline Explorer provides a "Tag" checkbox column to mark rows of interest. _Why:_ Lets an examiner flag and collect relevant records during triage. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Entry and sequence number columns** — The MFT output includes an entry number and a sequence number, which together encode the numeric location of a given file record within the MFT. _Why:_ These uniquely identify each MFT record. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Entry number size** — The MFT entry number is a 6-byte value. _Why:_ Defines the addressable range of MFT records. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Sequence number size** — The MFT sequence number is a 2-byte value. _Why:_ Tracks record reuse generations. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **File reference number** — The entry number combined with the sequence number is called the file reference number. _Why:_ The file reference number is the canonical unique identifier used to cross-reference records (including from the USN Journal). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Entry 0 is the MFT itself** — MFT entry number 0 is the record for the `$MFT` itself. _Why:_ The MFT self-references as its first record. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Reserved early records** — The first MFT records point to the NTFS metadata "building blocks" — the MFT mirror, `$LogFile`, `$Volume`, and the other reserved NTFS meta files. _Why:_ Explains why the earliest entries are system structures, not user files. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### The "In Use" flag and deleted-file recovery

- **"In Use" column meaning** — The "In Use" column indicates whether the MFT file record itself is currently allocated/in use. _Why:_ Distinguishes live records from records available for reuse (deleted). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Deletion marks record not-in-use** — Deleting a file on NTFS marks its MFT file record as no longer in use, meaning the OS may reuse that record for another file. _Why:_ Deletion does not immediately erase the record's contents. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Reuse timing is variable** — Reuse of a deleted MFT record can happen immediately or after some time. _Why:_ The window to recover a deleted record is nondeterministic. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Record contents persist until reuse** — Until a deleted MFT record is reused, most of the information within it remains intact. _Why:_ This residual data is what makes undelete possible. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **How undelete works** — Undelete software scans the MFT for orphaned records (those marked not in use), recovers the record, and follows its data runs (which point to clusters) to read the file's content back off disk. _Why:_ Explains the mechanism behind NTFS file recovery. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Cluster-reuse caveat** — Recovering a deleted file's data succeeds only if the clusters referenced by its data runs have not themselves been reused/overwritten by another file. _Why:_ Even an intact MFT record can point to now-overwritten content. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Other MFT columns

- **Descriptive columns** — The MFT CSV includes parent path, file name, extension, is-directory flag, has-ADS / is-ADS flags, and file size. _Why:_ Provide the human-readable identity and structure of each record. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Alternate data stream indicators** — Separate columns indicate whether a record has an alternate data stream and whether the record itself is an alternate data stream. _Why:_ ADS can hide data or carry provenance (e.g. Zone.Identifier). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### MFT timestamps ($SI and $FN, MAC(b))

- **Eight timestamps per record** — Each MFT record exposes eight timestamps: one MAC(b) set from `$STANDARD_INFORMATION` and one MAC(b) set from `$FILE_NAME`. _Why:_ Two independent timestamp sets enable timestomping detection. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`$SI` attribute is hex 0x10** — Timestamp columns labeled with hex `10` come from the `$STANDARD_INFORMATION` attribute (attribute type 0x10). _Why:_ Identifies which attribute a timestamp originates from. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **`$FN` attribute is hex 0x30** — Timestamp columns labeled with hex `30` come from the `$FILE_NAME` attribute (attribute type 0x30). _Why:_ Identifies the second timestamp source. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **MAC(b) meaning** — For each attribute the four timestamps are B (born/created), M (modified), C (MFT/metadata changed), and A (accessed); "MAC(b)" denotes Modified, Accessed, Changed, with Born in parentheses. _Why:_ Standard NTFS timestamp taxonomy. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **"Created" column is $SI Born** — In the CSV the "Created" column is the B (born) timestamp from `$STANDARD_INFORMATION`. _Why:_ Maps a friendly column name to its underlying attribute/field. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Blank $FN timestamp convention** — A blank timestamp in a `$FILE_NAME` (hex 30) column means that value is identical to the adjacent `$STANDARD_INFORMATION` timestamp; it is left blank to avoid duplicating data and wasting space in the CSV. _Why:_ Prevents misreading a blank as "missing"; blank = "same as $SI." _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Timestomping and anti-forensic indicators

- **"SI < FN" column** — A column flagged "SI < FN" means the `$STANDARD_INFORMATION` timestamp is earlier than the corresponding `$FILE_NAME` timestamp. _Why:_ `$SI` predating `$FN` can indicate backdating / timestomping (users can alter $SI, but $FN is harder to change). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **"USEC0" (zero subseconds) indicator** — A "USEC0" flag means the timestamp has no sub-second precision (all sub-second digits are zero). _Why:_ Many timestomping tools only set times to whole-second granularity, so zeroed subseconds can indicate timestomping. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Copy indicator (modified-before-created)** — A "copied" indicator flags a file whose modification timestamp is earlier than its creation timestamp — an artifact of copying, because a file copy inherits the source's modification time while the destination gets a fresh creation time. _Why:_ Detects that a file was copied rather than originally created in place. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Additional MFT NTFS data columns

- **Zone ID / re-parse / reference-count columns** — Further right in the CSV are columns for Zone ID contents, re-parse point targets, and reference counts. _Why:_ Zone ID reveals download origin; reparse points indicate junctions/symlinks; reference counts track hard links. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Searching the MFT output

- **Search across name and path** — Searching a term (e.g. "13cubed") in Timeline Explorer returns rows where the term appears in either the file name or the parent path. _Why:_ One search covers both filename and directory-location matches. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Filtering scale** — In the demo, searching narrowed ~1,000,000 rows down to 67 visible matching rows. _Why:_ Demonstrates rapid triage of a massive MFT via search. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### Reviewing the USN Journal CSV

- **Single "Update Timestamp"** — Each USN Journal row has one timestamp, the update timestamp, which is when the journal logged that particular event. _Why:_ USN entries are event-time records, not file MAC times. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **"Name" column** — The USN "Name" column is the file name being referenced by that specific USN event. _Why:_ Identifies which file each change record concerns. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **No path in the USN Journal** — The USN Journal does not record the full file path — only the file name. _Why:_ You cannot read directory location directly from a USN entry. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Deriving path via MFT correlation** — You can reconstruct a USN event's full path by matching its entry and sequence numbers (file reference number) to the corresponding record in the parsed MFT and reading the parent path from there. _Why:_ Correlating $MFT with $UsnJrnl recovers the missing path context. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **USN also carries entry/sequence numbers** — The USN output includes the file's entry and sequence numbers, plus an extension column. _Why:_ These entry/sequence values are the join key back to the MFT. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Update Sequence Number (USN)** — The output has an update sequence number for the journal itself (the USN value). _Why:_ The monotonically increasing USN orders and uniquely marks each journal record. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

### USN reason (op) codes

- **"Update Reasons" column** — The "Update Reasons" column holds the USN reason codes (op codes) describing the action recorded for that entry. _Why:_ This is the primary column an examiner filters on. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Example reason codes** — Reason codes include File Create, File Delete, Rename Old Name, and Rename New Name (among others). _Why:_ These map directly to user/OS file operations. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Filter on File Delete** — Filtering the "Update Reasons" column on "File Delete" surfaces files that were deleted yet still recorded in the journal. _Why:_ Recovers evidence of deletions even after the file and its MFT record are gone. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Reconstructing renames** — A file rename is captured as a pair: "Rename Old Name" and "Rename New Name," letting you derive both the previous and the new file name. _Why:_ Recovers rename history (e.g. disguising a file by changing its name/extension). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Filter for creations/deletions** — Filter on "File Create" to see file creations and on "File Delete" to see file deletions. _Why:_ Direct mapping from reason code to investigative question. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **File attributes logged** — The USN output includes a file-attributes column recorded with each event. _Why:_ Attribute changes are themselves journaled events. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **Source file column** — The USN output includes a "source file" column indicating the location/artifact from which the parsed data originated. _Why:_ Provenance, especially useful when parsing multiple journals (e.g. from VSCs). _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

- **USN Journal forensic value** — The USN Journal is a rich source ("gold mine") of file-activity evidence and should always be parsed. _Why:_ It records file operations that leave no other trace once the file is gone. _[IWE ch06 · Anatomy of NTFS / Parsing the MFT & USN Journal]_

## Chapter 07 · Permanent Deletion

### Deletion triggers (equivalent operations)

- **Shift+Delete** — Holding Shift while deleting bypasses the Recycle Bin and performs a permanent delete rather than moving the file to the Recycle Bin. _Why:_ Permanent deletion produces a different on-disk footprint than a Recycle-Bin move, so the analyst must know which path the user took. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Equivalence of permanent-delete paths** — Shift+Delete, emptying a file out of the Recycle Bin, and deleting from a command prompt or PowerShell all trigger the identical sequence of underlying NTFS changes. _Why:_ The recovery workflow is the same regardless of which UI/CLI action the user used, so the analyst need not distinguish them for content recovery. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

### Resident vs non-resident file (prerequisite concept)

- **Resident file threshold** — A resident file is small enough (about 600 bytes or less) that its content is stored directly inside its own MFT file record. _Why:_ Whether content lives inside the MFT record or in external clusters changes what survives deletion and how recovery works. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Non-resident file** — A file too large to fit in the MFT record (the example was ~7.5 KB) is non-resident: its content is stored in clusters elsewhere on disk. _Why:_ Non-resident content persists in unallocated clusters after deletion and is recoverable independently of the MFT record. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Data runs point to content clusters** — A non-resident file has one or more data runs in its MFT record that point to the on-disk clusters holding the actual file contents. _Why:_ Data runs are the map from metadata to content; recovering a non-resident file means following (or reconstructing) that cluster layout. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

### What changes on permanent deletion

- **MFT record marked not-in-use** — On permanent deletion the file's MFT file record is updated to flag it as not in use, making the record available for reuse. _Why:_ The flag flip (rather than record erasure) is why "undelete" works — the record still describes the file until overwritten. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **MFT record otherwise largely intact** — Aside from the in-use flag and a couple of other minor changes within the record, the MFT file record remains largely intact and unchanged after deletion. _Why:_ The surviving record still carries recoverable metadata for the deleted file. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Metadata survives in the MFT record** — The original timestamps and the file name remain present in the MFT file record after deletion; only the not-in-use marking has changed. _Why:_ Name and timestamps of a deleted file can be recovered directly from the still-present MFT record before it is reused. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **$Bitmap frees the clusters** — The $Bitmap metadata file is updated so the clusters previously occupied by the file are marked available for reuse. _Why:_ $Bitmap is the allocation map; flipping those bits to free is what turns the file's clusters into unallocated space. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Content is not scrubbed on deletion** — The data in the freed clusters is not erased or scrubbed at deletion time; the clusters are only marked ready for reuse, so the original bytes remain until something overwrites them. _Why:_ This gap between "marked free" and "actually overwritten" is the entire basis of file recovery. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **$I30 index updated** — The $I30 directory index for the parent directory (e.g. `C:\Users\davisrg\Desktop`) is updated because a file entry was removed from that directory's listing. _Why:_ $I30 slack can retain remnants of the removed directory entry, another metadata recovery source. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **File system journals updated** — The file system journals are updated to record the transaction that just occurred — namely the deletion of the file. _Why:_ Journal entries ($LogFile/$UsnJrnl) provide an independent, timestamped record that the deletion happened and can corroborate or extend the timeline. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

### Recovery method 1 — Undelete (metadata-based)

- **Undelete scans for inactive MFT records** — Simple "undelete" software works by scanning for MFT file records that have been marked available for reuse / no longer active, then offering those files for recovery. _Why:_ Undelete is fast and recovers full metadata (name, timestamps, location) because it rides the still-present MFT record. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Undelete success depends on cluster non-reuse** — Undelete succeeds only if the clusters previously occupied by the file have not yet been overwritten by another file. _Why:_ A recovered record pointing to overwritten clusters yields corrupt/garbage content, so cluster state gates a successful undelete. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

### Recovery method 2 — File carving (content-based)

- **Carving applies when the MFT record is gone** — File carving is the more advanced recovery method used once the MFT file record no longer exists, so all of the file's metadata is completely gone. _Why:_ When metadata is destroyed, content can still be recovered — carving is the fallback that ignores the file system entirely. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Metadata lost with the MFT record** — When the MFT record is gone, the file's name, original location, timestamps, and size are all lost, because that information was stored within the MFT file record. _Why:_ Carved files come back nameless and undated; the analyst must attribute them by other means. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Carved file exists only as clusters in unallocated space** — After the record is gone the file exists as content floating in various clusters in unallocated space, having been marked free in the $Bitmap. _Why:_ Carving targets unallocated space directly rather than following file-system pointers. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Carving requires clusters not yet reused** — Carving can recover the data only as long as those unallocated clusters have not yet been reused/overwritten. _Why:_ Same overwrite-window constraint as undelete, but with no metadata safety net. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Carving works by file signatures** — Carving software scans clusters looking for known file types by their file header / signature / magic bytes (e.g. the leading bytes identifying a JPEG, PNG, EXE, etc.). _Why:_ Signature detection is how carving finds file starts without any file-system index. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **Contiguity requirement** — Carving is likely to recover a file only when its data is stored contiguously across clusters; if the file is fragmented, simple header-based carving may fail to reassemble it correctly. _Why:_ Fragmentation is the main failure mode of signature carving and explains partial/corrupt carved output. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

- **PhotoRec as a carving tool** — PhotoRec is a file-carving tool that recovers files from unallocated space, and despite its name it recovers many file types, not only photos. _Why:_ A concrete, freely-available carver for practitioners; the name understates its scope. _[IWE ch07 · Deletion & Recovery / Permanent Deletion]_

## Chapter 07 · PhotoRec Carving

### Tooling & Package Identity

- **TestDisk/PhotoRec bundle** — PhotoRec ships as part of the TestDisk software package; TestDisk and PhotoRec are distributed together as one bundle. _Why:_ Locating the carving tool means installing TestDisk even though carving is a PhotoRec function. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **PhotoRec role** — Within the TestDisk bundle, PhotoRec is the component used to perform file carving. _Why:_ Separates the disk-repair/partition-recovery role of TestDisk from the file-carving role of PhotoRec. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Two PhotoRec executables (Windows)** — The Windows distribution provides two PhotoRec binaries: `photorec_win.exe` (text user interface / TUI) and `qphotorec_win.exe` (graphical user interface / GUI). _Why:_ The examiner chooses an interface; both perform the same carving. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **TUI vs GUI equivalence** — The TUI (`photorec_win.exe`) and GUI (`qphotorec_win.exe`) present the same selections (drive, partition, file signatures, filesystem type, destination) and perform the identical carving operation. _Why:_ Interface choice is preference; the underlying carving workflow and options are the same. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Input Preparation & Disk Mounting

- **Raw image input** — PhotoRec can carve from a forensic disk image (e.g. a `.raw`/`image.raw` file) rather than only from live physical media. _Why:_ Carving is performed against acquired evidence images in a forensic workflow. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Mounting the image (Arsenal Image Mounter)** — A disk image can be mounted with Arsenal Image Mounter so it appears to the OS as a physical drive; the demonstrated mount option is "Disk device, read only." _Why:_ Read-only mounting exposes the image as a drive for tools while preserving evidence integrity (no writes to the source). _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Mounted image becomes a PhysicalDrive** — After mounting, the image surfaces as an additional physical drive (e.g. `PhysicalDrive1`, labeled "Arsenal Virtual"), distinct from the host's own `PhysicalDrive0`. _Why:_ The examiner must select the mounted virtual drive, not the host's system drive, to carve the evidence. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Multiple mount points from one image** — Mounting a single multi-partition image can expose several drive-letter mount points (e.g. D, E, F). _Why:_ A disk image commonly contains multiple partitions/volumes, each surfaced separately. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Drive & Partition Selection

- **Drive selection is the first choice** — Both PhotoRec interfaces first prompt for which disk to carve; the correct target is the mounted evidence drive (the Arsenal Virtual `PhysicalDrive1`), not the host physical drive. _Why:_ Selecting the wrong drive carves the host system instead of the evidence. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Partition list is enumerated** — After choosing the drive, PhotoRec lists the partitions it detects within the image, with "Whole disk" offered at the top of the list. _Why:_ The examiner scopes carving to the whole disk or a single partition. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Whole disk option** — Selecting "Whole disk" carves across the entire drive to avoid missing data that may fall outside recognized partitions. _Why:_ Maximizes recovery coverage when the examiner does not want to risk skipping a region. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Specific-partition option** — Alternatively the examiner can target a single partition, such as the "Basic data partition" that holds the OS and primary data. _Why:_ Narrows carving to the relevant volume, reducing runtime and noise. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Windows partition layout observed** — A typical Windows disk image enumerated by PhotoRec shows: EFI system partition, Microsoft reserved partition, Basic data partition, and Windows Recovery Environment (plus "Whole disk"). _Why:_ Recognizing the standard GPT Windows layout tells the examiner which partition (the Basic data partition) contains user/OS data. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Basic data partition = OS/data volume** — On the demonstrated image the "Basic data partition" (partition number three) is the volume containing the operating system and the data of interest. _Why:_ Directs the examiner to the correct partition for recovering user data. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Filesystem Type Selection

- **Filesystem type prompt** — PhotoRec asks the examiner to specify the filesystem type of the chosen partition, defaulting to the combined option `FAT/NTFS/HFS+/ReiserFS/...`. _Why:_ The filesystem type governs how PhotoRec interprets the volume before carving. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **NTFS uses the default option** — For an NTFS partition, the default `FAT/NTFS/HFS+/ReiserFS/...` selection is correct (as opposed to the separate ext2/ext3/ext4 option). _Why:_ Choosing the right filesystem family ensures correct handling; NTFS is covered by the default combined choice. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Free-Space vs Whole-Partition Scan

- **Free vs Whole scan choice** — After the filesystem prompt, PhotoRec asks whether to scan only free (unallocated) space or to extract files from the whole partition. _Why:_ Controls whether carving targets deleted/unallocated data only or all data including allocated files. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **"Free" = unallocated space only** — The "Free" option restricts carving to unallocated (free) space, recovering only files present there. _Why:_ For recovering deleted files, the examiner scans unallocated space where deleted content persists until overwritten. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Unallocated-space rationale** — Carving unallocated space is the way to recover files whose filesystem metadata (directory entries/MFT records) no longer references them, i.e. deleted files. _Why:_ Deleted files lose their metadata pointers but the underlying data remains in unallocated clusters until overwritten. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### File-Signature Selection (File Formats / File Options)

- **Signature-based carving** — PhotoRec recovers files by recognizing built-in file signatures (headers/format signatures), not by reading filesystem metadata. _Why:_ Signature detection is what lets carving work on unallocated space where no metadata survives. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Large built-in signature library** — PhotoRec/QPhotoRec ship with a large set of built-in file-type signatures; the list shown in the UI is only a small subset of the full library. _Why:_ Broad default coverage means many file types can be carved without configuration. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **File Formats (GUI) / File Options (TUI)** — Signature selection is done via the "File Formats" button in QPhotoRec and the "File Options" menu in the TUI; both let the examiner check/uncheck which file types to carve for. _Why:_ Same feature under different interface labels; controls the carving target set. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **TUI toggle mechanism** — In the TUI File Options list, the space bar toggles a signature type on or off. _Why:_ Practical operation detail for enabling/disabling specific file signatures. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Default selection is broad** — The default signature selection covers a wide variety of file types and is a reasonable general-purpose choice. _Why:_ Running defaults recovers many file types when the examiner is not targeting a specific one. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Targeting one type speeds carving** — Selecting only the needed signature(s) (e.g. only `7z` for 7-Zip archives) speeds up the carving process and yields less data to triage afterward. _Why:_ Restricting signatures reduces both runtime and downstream review burden when the examiner seeks a specific file type. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Custom signatures** — PhotoRec supports user-defined custom signatures for file headers not already in its library. _Why:_ Enables carving of proprietary or uncommon formats the built-in library does not cover. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Advanced Options Menu

- **Options menu contents** — The PhotoRec "Options" menu exposes: Paranoid, Keep Corrupted Files, Expert Mode, and Low Memory. _Why:_ These tunables adjust carving behavior for edge cases; the examiner should know they exist. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Options left at default** — The demonstrated workflow leaves all Options at their defaults; changing them is only for specific needs. _Why:_ Default carving behavior is adequate for the general case. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Destination & Running the Carve

- **Destination selection required** — PhotoRec requires the examiner to choose a destination directory into which recovered files are written (e.g. a `RECOVERED` folder created on the desktop). _Why:_ Recovered output must be directed to a location; best practice is a location separate from the source evidence. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **TUI directory navigation** — In the TUI destination chooser, `..` moves up one directory level; the examiner navigates up out of the Tools directories to a drive root, then down through `Users\<user>\Desktop` to the target folder. _Why:_ Operational detail for selecting the output path in the text interface. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Start key is "C"** — In the TUI, pressing `C` (with the destination selected) starts the file-carving process. _Why:_ The specific keystroke that launches carving in `photorec_win.exe`. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **GUI start is "Search"** — In QPhotoRec, clicking "Search" (after choosing partition, free-space option, and destination) starts carving. _Why:_ Equivalent launch action in the GUI. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Runtime is modest** — Carving the demonstrated partition found several hundred files and completed in a little over two minutes. _Why:_ Sets a rough expectation for carving duration on a small partition with default signatures. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Output Directory Structure

- **`recup_dir.N` output folders** — Recovered files are written into subdirectories named `recup_dir.N`, starting at `recup_dir.1` and incrementing. _Why:_ Predictable output layout the examiner navigates to find carved files. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **500 files per directory** — A new `recup_dir.N` directory is created for every 500 recovered files. _Why:_ The count of `recup_dir` folders roughly indicates recovery volume (a single folder implies fewer than 500 recovered files). _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **500-count excludes thumbnails and report** — The 500-files-per-directory count excludes embedded JPEG thumbnail files and the `report.xml` file. _Why:_ Prevents miscounting; thumbnails and the report do not consume the 500 quota. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **`report.xml` auto-generated** — PhotoRec automatically produces a `report.xml` file containing details about the recovered files. _Why:_ Provides a machine-readable manifest/log of the carving output. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Recovered File Naming Convention

- **Name pattern `<letter><number>.<ext>`** — Recovered files are named with a leading letter, then a seven-digit-or-longer number, then a file extension derived from the detected signature. _Why:_ Carving cannot recover original filenames, so PhotoRec synthesizes names from position and detected type. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Extension from signature** — The file extension on a recovered file is assigned from the detected file signature, not from any stored filename. _Why:_ The extension reflects PhotoRec's format identification, which may differ from the file's original name/extension. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Leading `f` = regular file** — A filename beginning with `f` denotes a regular (normal) recovered file; this is the most common prefix. _Why:_ Prefix decoding lets the examiner classify carved output at a glance. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Leading `b` = broken file** — A filename beginning with `b` denotes a broken file. _Why:_ Flags likely-incomplete/corrupt carves for the examiner. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Leading `t` = embedded JPEG thumbnail** — A filename beginning with `t` denotes an embedded JPEG thumbnail. _Why:_ Distinguishes extracted thumbnails from full images. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Numeric part is a computed offset** — The number in a recovered filename is not random; it is `(file location − partition offset) ÷ sector size`. _Why:_ The number encodes the file's sector position within the partition, giving provenance for where the carved data was found. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Number usually ignorable** — In most casework the examiner does not need to act on the numeric portion of the filename, though its derivation is worth knowing. _Why:_ Contextual — the number is informational, not required for downstream analysis. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Recovered filename example** — A carved JPEG was named `f3227528.jpg`, where `f` = regular file and `3227528` is the computed sector-offset value. _Why:_ Concrete illustration of the naming scheme in practice. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Metadata-Based Renaming

- **Filenames generally lost in carving** — File carving does not recover original filenames because it works from raw data/signatures, not filesystem metadata. _Why:_ Fundamental limitation: carved output is content without its original name/path. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Metadata can partially restore names** — In some cases metadata embedded inside a recovered file lets PhotoRec append a name; such files show the synthesized name plus an underscore and the embedded name (e.g. `f...._WindowsTrustedRTProxy_sys`). _Why:_ Internal metadata (e.g. a PE resource name, document title) can supply a human-meaningful label even when the filesystem name is gone. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Documents renamed by title** — For example, a document may be renamed using its embedded title metadata. _Why:_ Illustrates that recovered-file naming can draw on format-internal fields when present. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Recovered-File Timestamps

- **Default timestamps = recovery time** — By default, the creation and modification timestamps of recovered files are set to the time of recovery, not the original file times. _Why:_ Carving does not recover filesystem timestamps, so output times reflect when carving ran, not original activity. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Some types preserve original timestamps** — For specific file types such as JPEG images and Microsoft Office documents, PhotoRec attempts to preserve the original timestamps (from format-internal metadata). _Why:_ Certain formats carry their own dates, which PhotoRec can apply to the recovered file for organization. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Preserved timestamps need forensic caution** — Timestamps recovered from embedded metadata must be treated with caution in forensics; discrepancies arise from missing/incorrect timezone data or a wrong original-device clock, producing wrong resultant timestamps. _Why:_ Metadata-derived times can mislead a timeline; their reliability depends on the source device's clock and TZ correctness. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Epoch-zero timestamp is bogus** — A recovered-file timestamp of December 31, 1969 (Unix epoch boundary) is not a valid time and should be treated as bogus. _Why:_ Epoch-zero / near-epoch dates are artifacts of missing time data, not real file activity. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### File Carving Fundamentals & Limitations

- **Carving is not an exact science** — File carving is inherently imprecise; the software does its best to reconstruct a file but may not always get it right. _Why:_ Sets expectations that carved output can be imperfect and must be validated. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Truncation error (early/late)** — Carving an image can miss the file's true end, truncating it early or late, so the recovered file may not be completely intact. _Why:_ Without reliable footer/length data, the carver may cut a file at the wrong boundary. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Single-byte error breaks the hash** — If a carved file differs from the original by even one byte, its cryptographic hash (e.g. SHA-256) will be completely different, so an exact hash match fails. _Why:_ Cryptographic hashes are avalanche-sensitive; carving imprecision defeats exact-hash identification. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Fuzzy hashing as the workaround** — When exact hashes fail due to carving imprecision, fuzzy hashing (similarity hashing) can still find a near-match. _Why:_ Similarity digests tolerate small byte-level differences that break exact hashes, enabling identification of imperfectly-carved files. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Intact carves do match** — A file carved intact will produce the expected exact hash (the demonstrated `f3227528.jpg` JPEG matched its known SHA-256). _Why:_ Confirms exact-hash identification still works when carving happens to be byte-perfect. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

### Searching Recovered Data

- **Hash search over recovered set** — Recovered data can be searched for a known file by hashing every recovered file and matching against a target hash, subject to the exact-match caveat above. _Why:_ Lets an examiner locate a specific known file among hundreds of un-named carved outputs. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Hash-search command pattern** — The demonstrated hash search is `find . -type f -exec sha256sum {} \; | grep -i <hash>`: `find` walks the tree for regular files, `-exec sha256sum {}` hashes each (with `{}` as the filename placeholder), `\;` terminates the exec, and `grep -i` matches the target hash case-insensitively. _Why:_ Reproducible one-liner for hash-matching across the entire recovered directory. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **`grep -i` case-insensitivity rationale** — `grep -i` ignores case so a hex hash written with uppercase or lowercase A–F digits still matches. _Why:_ Hash strings vary in case between tools; case-insensitive match avoids false misses. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Recursive string search** — Recovered data can be string-searched with `grep -Rai <string>`: `-R` recursive, `-a` treats binary files as text (searches inside binaries), `-i` case-insensitive. _Why:_ Finds an identifier (username, IP, keyword) anywhere in the carved corpus regardless of file type. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **`-a` binary flag necessity** — The `-a` flag is what lets grep search within binary files rather than skipping them. _Why:_ Carved output is largely binary; without `-a`, matches inside binaries are missed. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **"Rail grep" mnemonic** — Adding `-l` to list only matching filenames (not matching content) makes the command `grep -Rail`, mnemonically called a "Rail grep" (R, a, i, l). _Why:_ Memory aid for the filename-only recursive-binary-insensitive search variant. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **`-l` lists filenames only** — The `grep -l` flag reports the names of files that contain a match instead of printing the matching content. _Why:_ Produces a concise hit list for triage rather than voluminous content output. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Typical search targets** — Common real-world string-search targets in carved data are an identity/username or an IP address of interest. _Why:_ These identifiers are frequently the pivot for locating relevant carved artifacts in investigations. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **WSL recommended for searching** — Searching PhotoRec output is easier under WSL (Linux `find`/`grep`) than under Windows Command Prompt or PowerShell. _Why:_ Unix text-processing tools make recursive hash/string searches over the recovered set far more practical. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

- **Recovered data is browsable** — The recovered directory can be opened in Windows Explorer and browsed like any normal folder to preview carved files (e.g. viewing a recovered JPEG). _Why:_ Manual visual review complements programmatic search for confirming what was recovered. _[IWE ch07 · Deletion & Recovery / File Carving with PhotoRec]_

## Chapter 07 · Recycle Bin

### Deletion scenarios / behaviour

- **Recycle-bin deletion path** — Deleting a file through the normal recycle-bin route (Explorer Delete key or "Delete" context action) moves the file into the recycle bin rather than freeing its data immediately. _Why:_ The file remains recoverable and its metadata is preserved in a companion artifact. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Recycle-bin bypass mechanisms** — Emptying the recycle bin, using Shift+Delete, or deleting via Command Prompt / PowerShell all bypass the recycle bin, so no $I/$R pair is created for that file. _Why:_ Absence of recycle-bin artifacts does not mean the file was never deleted; it may have been deleted by a bypass method. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **"Deleted" is really a move** — A file sent to the recycle bin is effectively moved into the recycle-bin structure, not truly deleted; the recorded timestamp is the moment it was moved to the bin, not a moment of data destruction. _Why:_ Correctly interpreting the timestamp semantics ("recycled on") avoids overstating what the artifact proves. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### Historical evolution of the recycle bin

- **Introduction in Windows 95** — The recycle bin feature was first introduced in Windows 95. _Why:_ Establishes the earliest OS version where recycle-bin artifacts exist. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **"Recycled" directory (9x/ME)** — On Windows 95, Windows 98, and Windows Millennium Edition (ME), the recycle-bin directory in the root of the drive is named `Recycled`. _Why:_ Locating the correct root directory name depends on the OS generation. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **"Recycler" directory (NT/2000/XP)** — On Windows NT, Windows 2000, and Windows XP, the recycle-bin directory in the root of the drive is named `Recycler`. _Why:_ The directory name changed across the NT-line OSes; examiners must know which name to look for. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **INFO2 metadata file (95 through XP)** — On every OS from Windows 95 through Windows XP, a single file named `INFO2` (I-N-F-O-2) resides inside the recycle-bin directory and serves as the recycle bin's metadata store. _Why:_ INFO2 is the parse target for recycle-bin metadata on all pre-Vista systems. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **INFO2 is a single consolidated metadata file** — In the pre-Vista design, one INFO2 file holds metadata for all deleted items, in contrast to the later per-file $I design. _Why:_ Changes how an examiner parses and correlates deleted-item metadata across OS generations. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **INFO2 recoverable fields** — Parsing INFO2 yields, per deleted file: the original path and name of the file, the size of the file, and the date/time the file was sent to the recycle bin. _Why:_ Defines exactly what metadata can be recovered from legacy recycle bins. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### Vista+ recycle-bin structure

- **`$Recycle.Bin` root directory (Vista onward)** — Starting with Windows Vista, the recycle-bin directory in the root of each drive is named `$Recycle.Bin`. _Why:_ This is the current-era artifact location for modern Windows. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **INFO2 removed in Vista+** — Beginning with Windows Vista, the single INFO2 metadata file no longer exists; it was replaced by per-file $I metadata files. _Why:_ The parsing approach differs fundamentally between XP-and-earlier and Vista-and-later. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **`$Recycle.Bin` is hidden** — `$Recycle.Bin` is a hidden directory; a plain `dir` at the drive root does not list it, whereas `dir /a` (show all files including hidden) reveals it. _Why:_ Investigators must enumerate hidden files or the artifact appears absent. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Per-SID subdirectories** — Inside `$Recycle.Bin`, every user on the system has their own recycle bin stored in a subdirectory named after that user's Security Identifier (SID). _Why:_ Attributes deleted files to a specific user account by SID. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Per-SID subdirectories are hidden** — The per-SID subdirectories under `$Recycle.Bin` are themselves hidden; `dir` shows the parent as apparently empty while `dir /a` reveals the hidden subdirectories (in the demonstrated case, three of them). _Why:_ The user-specific recycle bins are only visible when enumerating hidden entries. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **SID identifies the owning user** — The SID naming the subdirectory maps to a specific local/domain user; in the demonstration the logged-in `davisrg` user's SID ended with RID 1001. _Why:_ The trailing RID and full SID let an examiner tie a recycle bin to an account. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **RID 1001 example** — A SID ending in the relative identifier (RID) `1001` was the demonstrated user's SID; RIDs in this range are typical of ordinary (non-built-in) user accounts. _Why:_ Recognizing RID ranges helps distinguish standard user accounts from built-in accounts. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### The $I / $R file pair

- **Two files per deleted item** — In Vista+, each file sent to the recycle bin produces exactly two files inside the user's SID subdirectory: one beginning with `$I` and one beginning with `$R`. _Why:_ Recovery and metadata analysis both depend on locating and pairing these two files. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **$I is the metadata file** — The `$I`-prefixed file is the metadata file, functioning as the per-file replacement for the legacy INFO2. _Why:_ $I is the parse target for original path, size, and deletion timestamp. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **$R is the file contents** — The `$R`-prefixed file contains the actual data (contents) of the file that was sent to the recycle bin. _Why:_ $R is the recovery target — copying it out reconstitutes the original file. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Six random characters in the name** — After the `$I` / `$R` prefix, the filename contains six characters that are randomly generated. _Why:_ The random component prevents naming collisions and is not derived from the original filename. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Shared random characters pair $I with $R** — For a given deleted file, the six random characters are identical between its `$I` and `$R` files; this shared string is what pairs the metadata file to its content file. _Why:_ Examiners correlate a metadata record to its recoverable data by matching the six-character token. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Original extension preserved** — The recycle-bin filename ends with the original file extension of the deleted file (e.g. `.png` for a PNG), and this extension is identical on both the `$I` and `$R` members of the pair. _Why:_ The extension hints at the original file type without needing to parse $I. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Filename anatomy** — A recycle-bin filename decomposes as: prefix (`$I` or `$R`) + six random characters + original extension (e.g. `$I` + `XXXXXX` + `.png`). _Why:_ Understanding the naming scheme lets an examiner recognize and parse these files programmatically. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### $I file contents and manual inspection

- **Original path stored in $I** — The `$I` metadata file stores the original full path and name of the deleted file, which is how the recycle bin knows where to restore the file and what original location to display. _Why:_ Recovers where the file lived before deletion — key for attribution and reconstruction. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Restore uses $I path** — The Explorer "Restore" option works because the original location is recorded in the $I metadata file. _Why:_ Confirms the $I file is authoritative for the pre-deletion location. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Explorer recycle-bin columns come from $I** — The recycle-bin GUI columns (name, original location, date deleted, size, type, date modified) are populated from the $I metadata. _Why:_ Ties the user-visible recycle-bin view directly to the $I artifact examiners parse. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Original path readable in raw $I** — Dumping the raw bytes of a $I file (e.g. via the `type` command) shows binary "gibberish" followed by the original path/name of the file in readable form. _Why:_ Even without a parser, the original path can often be eyeballed in the raw $I data. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **$R is directly recoverable by copy** — Copying a `$R` file out of the recycle bin and renaming it reproduces the original file exactly (demonstrated by copying a `$R` PNG to the desktop as `test.png`, which opened as the original image). _Why:_ Recovery can be as simple as a file copy — no special carving tool required when $R is intact. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### RBCmd (Eric Zimmerman) parsing

- **RBCmd purpose** — Eric Zimmerman's `RBCmd` is the tool used to parse recycle-bin metadata files. _Why:_ Identifies the standard tooling for automated recycle-bin analysis. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **RBCmd parses both formats** — RBCmd parses both the legacy `INFO2` format (Windows 95 through XP) and the modern per-file `$I` format (Vista onward). _Why:_ One tool covers recycle-bin metadata across all Windows generations. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **`-f` single-file flag** — `RBCmd.exe -f <file>` processes a single specified metadata file. _Why:_ Targeted parsing of one $I/INFO2 file. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **`-d` directory flag (recursive)** — `RBCmd -d <directory>` processes a directory recursively, parsing all recycle-bin metadata files found beneath it. _Why:_ Bulk-processes an entire `$Recycle.Bin` tree or SID subdirectory in one run. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Standard-output by default** — RBCmd prints parsed results to standard output (the screen) by default, so writing to a file is not required for a quick look. _Why:_ Fast triage of a small number of files without extra flags. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **`--csv` output flag** — `--csv <dir>` writes RBCmd results out to a CSV file, following the same convention as other Eric Zimmerman tools. _Why:_ Preferred for parsing large numbers of files where screen output is impractical. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **`--csvf` filename flag** — The optional `--csvf <name>` flag specifies the output CSV's filename, matching the pattern used across the Zimmerman tool suite. _Why:_ Lets the examiner control the output artifact's name for case organization. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Tab auto-completion selects $I** — When supplying a path to RBCmd, pressing Tab in the demonstrated shell auto-completed to the `$I` file, since $I is the metadata file RBCmd needs (not $R). _Why:_ Reinforces that RBCmd is pointed at the $I (metadata) member, not the $R (content) member. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### RBCmd output fields

- **"Found one File" count** — RBCmd reports the number of files it parsed (e.g. "Found one File"). _Why:_ Confirms how many metadata records were successfully processed. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Version field (format version 2)** — RBCmd reports the $I format version; version `2` corresponds to Windows 10 / Windows 11 recycle-bin metadata. _Why:_ The format version distinguishes OS-generation variants of the $I structure. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Original file size reported** — RBCmd outputs the original file size, shown in both bytes and kilobytes. _Why:_ Size corroborates identity of the deleted file and helps assess data volume. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **File name with original path reported** — RBCmd outputs the file name including the full original path of where the file was located. _Why:_ Recovers pre-deletion location for attribution and timeline reconstruction. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **"Deleted On" timestamp reported** — RBCmd outputs a "deleted on" timestamp, which is the time the file was sent to the recycle bin (more accurately described as "recycled on," since the file was moved rather than destroyed). _Why:_ Establishes when the user sent the item to the bin — but must be interpreted as a move-to-bin event, not data destruction. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

### Investigative gotchas

- **Enumerate hidden files or miss the artifact** — Because both `$Recycle.Bin` and its per-SID subdirectories are hidden, an analyst using a non-hidden-aware listing will wrongly conclude nothing is present. _Why:_ Prevents a false-negative during triage. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Pair $I and $R by the six-character token** — To reunite metadata with recoverable content, match the shared six random characters plus extension across the $I and $R files. _Why:_ Without pairing, you have either metadata with no data or data with no context. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Timestamp is move-time, not deletion-time** — The recorded timestamp reflects when the file entered the recycle bin, not when it was originally created, last modified, or permanently destroyed. _Why:_ Guards against overstating the meaning of the recycle-bin timestamp in a report. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

- **Bypass deletions leave no $I/$R** — Files removed via empty-bin, Shift+Delete, or shell deletion produce no recycle-bin artifacts, so recovery must fall to other techniques (e.g. carving, journal analysis). _Why:_ Sets correct expectations about when recycle-bin analysis will and won't yield results. _[IWE ch07 · Deletion & Recovery / The Recycle Bin]_

## Chapter 08 · Jump Lists

### What a Jump List Is

- **Jump list — user-facing surface** — A jump list is the extra context menu that appears when a taskbar (or Start-menu) icon is right-clicked, exposing recent items or actions for that application. _Why:_ It is a user-interaction artifact even users rarely notice they are generating. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Jump list — underlying nature** — A jump list is nothing more than a collection of shell link (LNK) files bundled together in one container. _Why:_ Everything learned about parsing individual LNK files applies to jump-list entries. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Each tracked file is a LNK** — Every file listed inside a jump list is itself a link file embedded within that jump list. _Why:_ Jump-list entries carry the same rich LNK metadata (paths, timestamps, MAC address, volume data). _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Photoshop example** — Right-clicking a taskbar icon such as Adobe Photoshop shows the recent files Photoshop has interacted with. _Why:_ Demonstrates that per-application recent-file history is stored and recoverable. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Two jump-list types** — There are exactly two kinds of jump list: automatic destinations and custom destinations. _Why:_ Each type has a different on-disk container format and requires the correct parser path. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Automatic vs Custom Destinations — Roles

- **Automatic destinations = recent activity** — The automatic destinations jump list stores the "recent" items the OS auto-populates as the application is used. _Why:_ This is the richest, most forensically valuable jump-list data. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Custom destinations = pinned/customized** — The custom destinations jump list stores items the user has explicitly pinned, plus developer-defined custom entries/tasks. _Why:_ Distinguishes deliberate user pinning from automatic recent-file tracking. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Pinned items live in custom, not automatic** — When a user clicks the pin icon on an entry to keep it at the top of the jump list, that pinned item is recorded in the custom destinations jump list, while everything under "recent" stays in automatic destinations. _Why:_ Pinned vs recent status is inferable from which container an entry came from. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **"Pinned" section header** — In the live jump-list UI, pinned items appear under a "Pinned" heading at the top, above the "Recent" section. _Why:_ The visual layout maps directly to the automatic/custom container split. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### AppID (Application Identifier)

- **AppID identifies the application** — Each automatic destinations jump list is named/identified by an AppID that is specific to one application (e.g., a distinct AppID for Photoshop, another for Adobe Illustrator). _Why:_ The AppID is the key that attributes a jump list to a particular program. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Same AppID across both container types** — A given application uses the *same* AppID for both its automatic destinations and its custom destinations jump lists. _Why:_ You can correlate an app's automatic and custom files by matching the shared AppID prefix. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **AppID is the filename** — The AppID appears as the filename (the hex-looking identifier) of the jump-list file on disk, followed by the `.automaticDestinations-ms` or `.customDestinations-ms` extension. _Why:_ You can enumerate which apps produced jump lists just by listing the directory. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **AppID is not human-readable on its own** — Looking at a raw AppID (e.g., one beginning `163AA…`) gives no direct clue which application it belongs to. _Why:_ Requires an AppID-to-application lookup table to resolve. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **AppID resolution via lookup** — AppIDs are resolved to application names through a known-AppID mapping (some built into the tool, some supplied by the analyst); unresolved ones are reported as "unknown." _Why:_ Attribution depends on the completeness of the mapping table. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Example resolved AppID** — The AppID beginning `1CED…` resolves to Microsoft Visual Studio Code in the lesson's dataset. _Why:_ Concrete data point showing built-in resolution working. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Example unresolved AppID** — The Adobe Illustrator jump list's AppID (beginning `163AA…`) was reported as "unknown" by the tool, even though the analyst knew from prior notes it was Illustrator. _Why:_ "Unknown" does not mean unattributable — external knowledge or a fuller mapping can still identify it. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Manual AppID-to-app confirmation** — An analyst can confirm an unknown AppID by opening the live jump list for a known pinned taskbar app and matching its contents against the parsed entries. _Why:_ Provides an independent cross-check when the mapping table lacks the AppID. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### On-Disk Location

- **Jump-list parent directory** — Jump lists live under `\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`. _Why:_ Same Recent directory that holds standalone LNK files — one place to collect both artifacts. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Two subdirectories** — Inside `…\Windows\Recent\` there are two subdirectories: `AutomaticDestinations` and `CustomDestinations`. _Why:_ The container split is physical, one folder per jump-list type. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **AutomaticDestinations folder contents** — The `AutomaticDestinations` folder holds one file per application, each named `<AppID>.automaticDestinations-ms`. _Why:_ Enumerating this folder inventories every app with tracked recent activity for that user. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **CustomDestinations folder contents** — The `CustomDestinations` folder holds files named `<AppID>.customDestinations-ms`, same AppID naming scheme. _Why:_ Parallel structure lets you pair custom and automatic files by AppID. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Per-user artifact** — Jump lists are stored under each user's AppData\Roaming profile. _Why:_ Attribution to a specific user account is inherent to the path. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### File-Format Structure

- **Automatic = OLE compound file (OLECF)** — Automatic destinations jump lists are stored in the OLE Compound File (OLECF / "structured storage") format. _Why:_ Must be parsed as an OLECF container (multiple internal streams), not as a flat file. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Custom = concatenated LNKs** — Custom destinations jump lists are a plain serial concatenation of LNK files, one after another, with no OLECF wrapper. _Why:_ Different parsing approach — walk sequential LNK structures rather than open a compound file. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Both are ultimately LNK collections** — Regardless of container format (OLECF vs concatenated), both jump-list types are fundamentally collections of LNK files. _Why:_ The extractable per-entry evidence (LNK metadata) is the same in both. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### DestList Stream and Entry Fields (Automatic Destinations)

- **Entries are numbered** — A parsed automatic destinations jump list reports a set of numbered entries (e.g., 10 entries for the Illustrator file). _Why:_ Entry count is a quick sanity check against the live UI. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Expected vs actual entry counts** — The parser reports both an "expected entries" count and an "actual entries" count, which should match (e.g., expected 10 / actual 10; expected 9 / actual 9). _Why:_ A mismatch flags truncation, corruption, or deleted/unrecoverable entries. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **MRU ordering** — Entries carry a Most-Recently-Used position; MRU slot 0 is the most recently used item. _Why:_ Establishes the temporal order in which the app touched files. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Entry number vs MRU slot are distinct** — The internal "entry number" and the MRU slot are separate values (e.g., MRU 0 = entry 10; MRU 9 = entry 2). _Why:_ Don't conflate storage-entry index with recency ordering. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Full target path** — Each entry records the full path to the referenced file (e.g., an `.eps`, `.png`, `.ai`, or `.pdf` file). _Why:_ Proves the exact file the application opened, including its directory. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Pinned flag per entry** — Each entry has a boolean indicating whether it is pinned. _Why:_ Separates deliberately pinned items from auto-tracked recent ones within the same list. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Creation timestamp** — Each entry records a creation date/time. _Why:_ Contributes to timelining first interaction with the target. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Last-modification timestamp** — Each entry records a last-modified date/time. _Why:_ Contributes to timelining most recent interaction with the target. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Hostname field** — Each entry stores the hostname of the machine where the interaction occurred. _Why:_ Can reveal the file originated on / was accessed from a different named host (e.g., network or roamed profile). _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **MAC address field** — Each entry stores the MAC address of the host. _Why:_ Ties the activity to specific network-interface hardware — strong attribution/pivot data. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Interaction (access) count** — Each entry records an interaction count of how many times the item was accessed. _Why:_ Distinguishes a one-off open from repeated, deliberate use of a file. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Live-UI ↔ Parsed-Data Correlation

- **Top non-pinned = MRU 0** — The topmost non-pinned file shown in the live jump-list UI corresponds to MRU slot 0 in the parsed data (verified with `EZ_2_RGB_final.eps` for Illustrator). _Why:_ Confirms the parser's recency ordering reflects what the user actually saw. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **UI order matches MRU descending** — Successive files down the live list map to successive MRU slots (e.g., `test.png`, then `test.ai`), and the bottom item maps to the last MRU slot (MRU 9 = `impact_exec_commands_cheat_sheet_poster.pdf`, entry 2). _Why:_ End-to-end validation that parsed entries reconstruct the live jump list faithfully. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Automatic destinations hold the meaningful recent list** — Even for apps like VS Code, the useful recent-item entries (9 entries, e.g., ending with `DOSBox.conf`) reside in the *automatic* destinations file, matching the live right-click list exactly. _Why:_ When custom destinations look empty/uninformative, pivot to the automatic file for the same AppID. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Custom Destinations — Variability

- **Custom content is developer-defined** — What ends up in a custom destinations jump list depends entirely on how the application's developer chose to implement it. _Why:_ There is no universal schema — expect wide variation between apps. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Custom often less useful** — In practice, custom destinations frequently contain null/empty or low-value fields and are generally less forensically meaningful than automatic destinations. _Why:_ Set expectations — don't assume custom will yield rich file-access evidence. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Null-field example** — A randomly chosen custom destinations file in the lesson parsed to an unknown AppID with all fields listed as null. _Why:_ Illustrates that custom files can carry no usable data at all. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Custom can still carry paths/timestamps** — Some custom destinations (e.g., VS Code's, AppID `1CED…`, described "Microsoft Visual Studio Code") do contain an absolute path (pointing into Program Files) and date/timestamps. _Why:_ Custom is worth parsing despite variability — occasionally it yields real evidence. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Both types worth parsing** — Despite custom's inconsistency, both automatic and custom destinations should always be parsed. _Why:_ Skipping custom risks missing occasional pinned-item or developer-supplied evidence. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Forensic Significance

- **Proves file ↔ application association** — Jump lists prove which specific files a given application interacted with. _Why:_ Links a program's execution to the exact documents/data it touched. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Threat-actor interactive use** — When a threat actor interactively used a system and launched applications, jump lists reveal which files they opened with those apps. _Why:_ Reconstructs hands-on-keyboard activity and data of interest to the intruder. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Browser jump lists differ** — For browsers like Google Chrome, the jump list shows "most visited websites" and "recently closed tabs" instead of recent files. _Why:_ Browser jump lists can surface browsing artifacts even without touching the browser's own history stores. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Evidence of file existence** — Because entries store full target paths, a jump list evidences that a file existed and was accessed even if the file itself is now deleted. _Why:_ Recovers proof of files no longer present on the volume. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Tooling — JLECmd (Eric Zimmerman)

- **JLECmd is the parser** — Jump lists (both automatic and custom) are parsed with Eric Zimmerman's `JLECmd` tool. _Why:_ The go-to, format-aware tool for both container types. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Companion to LECmd** — `JLECmd` is the jump-list counterpart to `LECmd`, which parses standalone LNK files. _Why:_ Same author/ecosystem, consistent output conventions between the two. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **No-args usage help** — Running `JLECmd` with no options prints its available switches. _Why:_ Self-documenting; quick way to recall flags. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **`-f` single file** — `-f` points JLECmd at a single custom or automatic destinations jump-list file. _Why:_ For targeted examination of one AppID's list. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **`-d` directory (recursive)** — `-d` points JLECmd at a directory, which it processes recursively. _Why:_ Bulk-parse an entire AutomaticDestinations/CustomDestinations folder in one run. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **CSV output optional** — JLECmd can optionally write results to CSV (via a CSV output directory switch). _Why:_ Enables aggregate review of all metadata across many jump lists at once. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Standard-output display** — Without CSV, JLECmd displays parsed results to standard output (screen), like LECmd. _Why:_ Convenient for one-off inspection of a single file. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **`--appIds` mapping file** — The `--appIds` switch specifies the path to a file mapping AppIDs to descriptions (e.g., AppID = Photoshop). _Why:_ Lets the analyst supply/extend the AppID lookup so more AppIDs resolve instead of showing "unknown." _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Built-in AppID mappings** — JLECmd ships with some AppID mappings built in, so it auto-resolves certain AppIDs and marks the rest "unknown." _Why:_ Explains why some entries resolve without any user-supplied mapping. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **`--dumpTo` extract LNKs** — The `--dumpTo` switch takes a directory and exports the individual LNK files contained in the jump list into it. _Why:_ Recovers the raw embedded LNKs for separate analysis (e.g., with LECmd) or preservation. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Additional output formats** — JLECmd supports other output formats beyond CSV and various additional options. _Why:_ Fits different downstream tooling/reporting pipelines. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Path arg accepts full Recent path** — In practice you pass JLECmd a full path such as `…\Users\DavisRG\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms`. _Why:_ Documents the exact invocation form for a single-file parse. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

### Recommended Workflow / Gotchas

- **Preferred real-world method: CSV + directory** — In real casework, prefer parsing a whole directory of jump lists to CSV (rather than eyeballing standard output one file at a time). _Why:_ Reviewing all metadata together is faster and less error-prone than per-file inspection. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Mount-image workflow** — Typical process: mount the forensic image, collect the needed data, point JLECmd at the directory of jump lists, and output everything to CSV for one consolidated review. _Why:_ Repeatable acquisition-to-analysis pattern for jump lists. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Single-file mode is the exception** — Parsing one file to standard output is reserved for the occasional need to inspect a single jump list. _Why:_ Sets the default (bulk CSV) vs. exception (single stdout) expectation. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Empty-looking custom ≠ no data for that app** — If a custom destinations file yields nulls, don't conclude the app has no jump-list evidence — check the automatic destinations file for the same AppID. _Why:_ Prevents a false-negative conclusion from looking at only one container. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_
- **Keep an AppID crib** — Analysts should note/record known AppID-to-app mappings (the lesson relied on jotted-down AppIDs like `163AA…` = Illustrator, `1CED…` = VS Code). _Why:_ Speeds attribution when the built-in mapping lacks an AppID. _[IWE ch08 · LNK & Jump Lists / Jump Lists]_

## Chapter 08 · LNK Files

### What a LNK file is

- **LNK file (Shell Link) — definition** — A `.lnk` file is a Windows shortcut object that points to a target file, folder, or other shell item. _Why:_ It is the base artifact underlying both manual shortcuts and OS-generated recent-item tracking. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Manual LNK creation** — A user can create a LNK by right-clicking the desktop, choosing New → Shortcut, and pointing to a target file/folder. _Why:_ Establishes that LNK files exist both as deliberate user artifacts and as automatic OS artifacts. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Automatic OS creation** — Most LNK files on a system are created automatically by the operating system, not manually by the user. _Why:_ The forensic value lies in the automatic ones, which record user file-access activity without the user's knowledge. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Jump Lists are LNK-based** — Jump Lists are just different representations of LNK files; everything true of LNK files applies to Jump Lists. _Why:_ Consolidates the analysis — parsing/understanding LNK internals covers Jump Lists too. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Storage location (Recent folder)

- **Recent folder path** — Automatic LNK files live under `%AppData%\Roaming\Microsoft\Windows\Recent` (per user). _Why:_ Primary collection point when triaging a user's recent file-access activity. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **%AppData% resolves to Roaming** — Typing `%appdata%` in the Run prompt opens the user's `AppData\Roaming` folder, the parent of the `Microsoft\Windows\Recent` path. _Why:_ Fast operational way to reach the artifact on a live system. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **"Recent Items" is a display alias** — Windows Explorer displays the `Recent` folder as "Recent Items"; the real on-disk folder name is `Recent`. _Why:_ Prevents confusion — scripts and paths must use `Recent`, not the displayed label. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Per-user path substitution** — The Recent path is per user; substitute the sample username (e.g. `davisrg`) with the target account (`\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent`). _Why:_ Each user account has its own independent LNK history. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Recent folder holds many shortcuts** — The Recent folder typically contains a large number of shortcut (LNK) files, listed with file type "Shortcut". _Why:_ Volume of entries reflects breadth of user activity available for analysis. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Creation and trigger behavior

- **Legacy trigger (older Windows)** — Historically a LNK file was created when a file was opened (double-clicked) or when a downloaded file such as a zip was interacted with. _Why:_ Explains why LNK presence historically implied the file was actually opened. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Modern trigger (Windows 10/11)** — On modern Windows 10 and 11, a LNK file is created immediately upon creation of a file, not only upon opening it. _Why:_ LNK existence no longer proves the target was opened — only that it existed; changes the inference an examiner can draw. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Demonstrated creation-on-creation** — Creating a new empty text document (`HELLO-DEMO.txt`) on the desktop caused a corresponding `HELLO-DEMO.txt.lnk` to appear in the Recent folder immediately, with no open action. _Why:_ Empirically shows the modern immediate-on-creation behavior. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Hidden .lnk extension

- **.lnk extension is hidden** — Windows hides the `.lnk` extension even when "show file extensions" is enabled; `HELLO-DEMO.txt.lnk` displays as `HELLO-DEMO.txt`. _Why:_ Examiners must recognize an apparent `.txt` in the Recent folder is actually a `.lnk`; the real double extension only shows via CLI/dir. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Double extension on disk** — The true on-disk filename of the shortcut is target name plus `.lnk` (e.g. `HELLO-DEMO.txt.lnk`), revealed via a command-prompt `dir`. _Why:_ CLI enumeration is required to see the actual artifact names accurately. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### The LNK file's OWN timestamps (host $STANDARD_INFORMATION)

- **LNK creation time = target creation time** — The LNK file's own creation timestamp equals the moment its target file was created (created immediately on target creation). _Why:_ The LNK's birth time is a reliable proxy for when the target first existed on the system. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **dir /tc shows LNK creation** — The `dir /tc` switch displays the creation time of the LNK file. _Why:_ Operational method to read the LNK's own creation timestamp at the shell. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LNK modification = last target access** — The LNK file's own modification timestamp is updated to the moment the target file is next accessed/opened. _Why:_ The LNK's last-modified time serves as a "last accessed" indicator for the target. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Open-and-close still updates LNK mtime** — Merely opening and closing the target (without editing content) still updates the LNK file's modification timestamp. _Why:_ The LNK mtime reflects access, not content change — an open with no save still leaves a trace. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Content edit also updates LNK mtime** — Modifying and saving the target file also updates the LNK file's modification time. _Why:_ Confirms LNK mtime advances on any interaction, edit or not. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Persistence after target deletion

- **LNK survives target deletion** — Deleting the target file (including Shift+Delete / permanent delete) does NOT delete the associated LNK file; the LNK persists in the Recent folder. _Why:_ A LNK can prove a now-absent file once existed and was interacted with. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Shift+Delete demonstrated** — After Shift+Deleting `HELLO-DEMO.txt`, `dir HELLO-DEMO.txt.lnk` still returned the LNK file. _Why:_ Empirical confirmation that permanent deletion of the target leaves the LNK intact. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Proof of prior existence** — A surviving LNK demonstrates the existence of files that may no longer be on disk. _Why:_ Core investigative value — recover evidence of files an actor deleted to hide activity. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Embedded TARGET metadata (about the file the LNK points to)

- **Target's own three timestamps embedded** — The LNK stores the target file's Birth (B/creation), Access (A), and Modification (M) timestamps, captured from when the LNK was created/updated. _Why:_ Recovers the deleted target's original timeline even after the file and its MFT entry are gone. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Two distinct timestamp sets** — A LNK carries two separate timestamp sets: (1) the LNK file's own host timestamps and (2) the embedded target file timestamps. _Why:_ Examiners must not conflate the shortcut's dates with the pointed-to file's dates. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Target file size** — The LNK stores the target file's size (e.g. 30 bytes for the demo txt). _Why:_ Size of a deleted file recoverable from the LNK aids identification/reconstruction. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Volume label** — The LNK records the volume label of the drive where the target resided (e.g. `OS`). _Why:_ Identifies which volume/drive hosted the file. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Drive type** — The LNK records the drive type of the target's volume (fixed, removable, etc.). _Why:_ Distinguishes internal disk vs. removable media as the file's origin. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Volume serial number** — The LNK stores the serial number of the target's volume. _Why:_ Ties a file to a specific formatted volume, useful for correlating across images/devices. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Local base path** — The LNK stores the local base path where the target file was located. _Why:_ Reconstructs the full original path of a deleted file. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Relative path / working directory** — The LNK stores the relative path and the working directory in which the target file was located. _Why:_ Additional path context supporting reconstruction of file location. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **8.3 short name** — The LNK stores the target's short (8.3) name representation; for names ≤8 characters the short name equals the long name. _Why:_ Short-name capture aids matching against MFT and legacy naming. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Attributes and icon index** — The LNK stores file attributes and icon index values for the target. _Why:_ Additional target metadata surfaced by proper parsers. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Flags** — The LNK stores flag fields describing which optional structures/fields are present. _Why:_ Flags govern how the LNK is parsed and what data it contains. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Tracker (distributed-link) block — machine identity

- **Machine ID / machine name** — The LNK's tracker database block contains the machine ID (NetBIOS/machine name) of the computer where the target file was located. _Why:_ Attributes activity to a specific host — powerful when a file was moved/opened across machines. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **MAC address of NIC** — In many cases the LNK embeds the MAC address of the machine's network interface card. _Why:_ Hardware-level identifier tying the LNK to a specific physical machine/adapter. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Tracker block droid/creation IDs** — The tracker block includes object identifiers with their own creation information (droid/birth object IDs). _Why:_ Distributed-link-tracking GUIDs can link a file across systems and to a volume. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Removable media tracking

- **LNKs track removable-media files** — Opening, interacting with, or creating files on a USB flash drive or external hard drive still generates and updates LNK files, even though the file is not on the internal disk/SSD. _Why:_ LNK analysis reveals activity on devices no longer connected to the machine. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd removable-only filter** — LECmd has an option to process only LNK files that point to removable drives. _Why:_ Rapidly isolates external-device activity during triage. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Tool: ExifTool (improper but illustrative parser)

- **ExifTool parses LNK metadata** — ExifTool, though designed for image/photo metadata (EXIF, GPS), can be run against a `.lnk` file and returns substantial LNK metadata. _Why:_ Shows the richness of embedded LNK data even with a non-purpose-built tool. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **ExifTool install (WSL/Ubuntu)** — ExifTool installs on a Debian/Ubuntu system via `sudo apt install exiftool`, e.g. inside WSL2 (Ubuntu 22.04). _Why:_ Cross-platform reachability of the tool during analysis. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **ExifTool time display + offset** — ExifTool displays LNK timestamps in local time and shows the UTC offset (e.g. `-05:00`). _Why:_ Examiner must account for the local-time offset when normalizing to UTC. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **ExifTool top block = LNK's own metadata** — ExifTool's top section reports the LNK file itself (e.g. LNK size 569 bytes) with its M (modification), A (access), and Inode-change/C (metadata change) timestamps. _Why:_ Separates the shortcut's host filesystem times from the embedded target times. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Inode change = C timestamp** — ExifTool's "Inode change" field corresponds to the C timestamp (MFT record / metadata change time). _Why:_ Maps the Unix-tool label to the NTFS MACB model an examiner expects. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **ExifTool is not the proper parser** — Using ExifTool is not the correct way to parse a LNK; it is illustrative of available data only. _Why:_ A dedicated LNK parser is preferred for accurate, structured, complete output. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Tool: LECmd (Eric Zimmerman) — proper parser

- **LECmd is the purpose-built parser** — Eric Zimmerman's LECmd (in his EZ Tools suite) is the proper tool for parsing LNK files. _Why:_ Produces structured, section-organized, forensically complete output. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd -f (single file)** — The `-f` flag points LECmd at a single LNK file to parse it. _Why:_ Targeted parsing of one artifact. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd directory / recursive** — LECmd can point at a directory and recursively process all LNK files within it. _Why:_ Bulk-process an entire user's Recent folder in one pass. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd CSV output** — LECmd can output to multiple formats including CSV, writing all LNK metadata into individual columns in a single file. _Why:_ Aggregates every LNK's metadata into one reviewable spreadsheet for an investigation. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd against a mounted image path** — LECmd can be pointed directly at a Recent path on a mounted disk image for a specific user of interest. _Why:_ Dead-box workflow — parse LNKs straight from acquired evidence. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Admin not required for own user** — LECmd warns when not run as administrator, but admin is unnecessary when parsing the examiner's own local user data. _Why:_ Sets expectation — privilege only matters for other users' protected data. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd output sections** — LECmd presents output in readable sections: source-file (LNK-itself) info; target creation/modification/access timestamps; LNK file size; attributes; icon index; relative paths; working directories; flags; drive type; volume serial number; volume label; local path; 8.3 short name with its modification time; and a tracker database block with machine ID and MAC address (with its own creation info). _Why:_ Full field inventory an examiner can expect from a proper LNK parse. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **LECmd source vs target distinction** — In LECmd output, the "source" data pertains to the LNK file itself while the target timestamps/paths pertain to the file the LNK points to. _Why:_ Prevents misattributing the two timestamp sets. _[IWE ch08 · LNK & Jump Lists / LNK Files]_
- **Demo path used** — LECmd demo pointed at `\Users\davisrg\AppData\Roaming\Microsoft\Windows\Recent\HELLO-DEMO.txt.lnk`. _Why:_ Concrete example of the full artifact path syntax. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Cross-artifact corroboration example

- **USN.csv LNK recovery** — A previously deleted desktop file `USN.csv` (output written earlier by MFTECmd when parsing the NTFS USN Journal) still had a surviving LNK; parsing it recovered the deleted file's B/A/M timestamps and its (fairly large) file size. _Why:_ Real example of recovering a deleted artifact's full metadata from its lingering LNK long after the file is gone. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

### Summary significance

- **Why LNK files matter forensically** — LNK files persist long after the target file is removed and still contain extensive metadata about that file (timestamps, size, paths, volume, machine, MAC). _Why:_ They are a durable, high-value source of evidence about deleted/absent files and the machines/devices involved. _[IWE ch08 · LNK & Jump Lists / LNK Files]_

## Chapter 09 · MFTECmd

### MFTECmd as a Timelining Tool

- **MFTECmd (dual-purpose)** — Eric Zimmerman's MFTECmd, previously used to parse the MFT, doubles as a tool for building file-system timelines. _Why:_ One tool covers both artifact parsing and timeline generation, reducing toolchain sprawl in an examination. _[IWE ch09 · Timelining / MFTECmd]_
- **Parsing the MFT already produces a timeline** — Running MFTECmd to parse an MFT (as taught in the Anatomy of NTFS material) is effectively a file-system timelining operation, because the per-record timestamps it extracts constitute the timeline. _Why:_ The distinction between "parse the MFT" and "make a file-system timeline" is largely a framing difference, not a different workflow. _[IWE ch09 · Timelining / MFTECmd]_

### Input Acquisition (getting the MFT)

- **Extracting the $MFT** — The MFT was pulled from a disk image (an "ACME" disk image) using FTK Imager, done off-camera. _Why:_ FTK Imager is a standard, free way to export a single NTFS metadata file like the $MFT out of an acquired image for offline parsing. _[IWE ch09 · Timelining / MFTECmd]_
- **Filename without the leading `$`** — The extracted MFT was saved to disk simply as `MFT` (the leading dollar sign of `$MFT` dropped from the filename). _Why:_ The `$` prefix is an NTFS naming convention for system metadata files; it is not required in the on-disk filename you feed to MFTECmd, and dropping it avoids shell-escaping the `$`. _[IWE ch09 · Timelining / MFTECmd]_
- **Same source across lessons** — The MFT used here came from the same disk image as the two preceding lessons in the module. _Why:_ Consistent test data lets record counts and timestamps be compared directly across demonstrations. _[IWE ch09 · Timelining / MFTECmd]_

### Command Syntax — CSV Output Mode

- **`-f` specifies the input file** — The `-f` flag tells MFTECmd which file to process (here, the path to the extracted MFT). _Why:_ `-f` is the single-file input selector; correct input path is the precondition for everything downstream. _[IWE ch09 · Timelining / MFTECmd]_
- **Full input path example** — In the demo the input path was `\Users\davisrg\Desktop\MFT`. _Why:_ Illustrates that `-f` takes an ordinary filesystem path to the previously-exported MFT. _[IWE ch09 · Timelining / MFTECmd]_
- **`--csv` sets the output DIRECTORY** — The `--csv` flag specifies the directory (folder) into which results are written, not a file. _Why:_ Confusing `--csv` for a filename is a common error; it names a destination folder, with the filename set separately. _[IWE ch09 · Timelining / MFTECmd]_
- **`--csvf` sets the output FILENAME** — The `--csvf` flag specifies the output file name for CSV mode (e.g. `timeline.csv`). _Why:_ MFTECmd separates "where" (`--csv` directory) from "what to call it" (`--csvf` filename); both are needed to control the output precisely. _[IWE ch09 · Timelining / MFTECmd]_
- **Auto file-type detection** — MFTECmd automatically detected the input file type as an MFT without being told. _Why:_ The tool inspects file structure/signature rather than trusting the filename, so a renamed `$MFT` is still recognized. _[IWE ch09 · Timelining / MFTECmd]_
- **Processing speed** — Parsing the MFT completed in under two seconds. _Why:_ MFT parsing is fast enough to be a routine early step even on a large volume's metadata file. _[IWE ch09 · Timelining / MFTECmd]_
- **Record count reported** — The run found 186,889 FILE records. _Why:_ MFTECmd reports the count of FILE records parsed; this number is a sanity check and should be reproducible across output formats on the same input. _[IWE ch09 · Timelining / MFTECmd]_

### Reviewing CSV Output in Timeline Explorer

- **Open CSV in Timeline Explorer** — The generated `timeline.csv` is opened in Timeline Explorer (another Eric Zimmerman tool) to review and sort the timeline. _Why:_ Timeline Explorer is the paired viewer for EZ-tool CSV output, giving fast column sort/filter over large record sets. _[IWE ch09 · Timelining / MFTECmd]_
- **Sortable timestamp columns** — In Timeline Explorer the timeline can be sorted by any of the extracted timestamp columns. _Why:_ Sorting by a chosen timestamp is what turns a table of records into an ordered timeline for a given time axis. _[IWE ch09 · Timelining / MFTECmd]_
- **$STANDARD_INFORMATION timestamp column** — One sortable column is Standard Information "modification" (a `$SI` timestamp). _Why:_ `$SI` timestamps are what most tools and the OS surface, and are the ones malware "timestomping" typically alters. _[IWE ch09 · Timelining / MFTECmd]_
- **$FILE_NAME "birth" timestamp column** — Another sortable column is File Name "birth" (creation) drawn from the `$FN` attribute. _Why:_ `$FN` timestamps are updated differently from `$SI` and often resist naive timestomping, so comparing `$FN` against `$SI` can expose tampering. _[IWE ch09 · Timelining / MFTECmd]_
- **Multiple timestamps per record** — Beyond `$SI` modification and `$FN` birth, other timestamps are also extracted and available as columns. _Why:_ NTFS records carry several MACB timestamps across `$SI` and `$FN`; having all of them enables cross-comparison for anti-forensic detection. _[IWE ch09 · Timelining / MFTECmd]_
- **CSV output IS the file-system timeline** — The sorted CSV in Timeline Explorer is, in effect, the file-system timeline. _Why:_ No further conversion is required for the CSV path — the deliverable timeline is the parsed table itself. _[IWE ch09 · Timelining / MFTECmd]_

### Command Syntax — Bodyfile Output Mode

- **Bodyfile output capability** — MFTECmd can emit output in bodyfile format, matching what `fls` (Sleuth Kit) produces. _Why:_ Bodyfile is the interchange format that plugs into the mactime/super-timeline ecosystem, so this makes MFTECmd a drop-in bodyfile source. _[IWE ch09 · Timelining / MFTECmd]_
- **`--body` replaces `--csv`** — To produce a bodyfile, swap `--csv` for `--body` (still names the output directory). _Why:_ The output-format selector is what changes; input selection and directory semantics stay the same. _[IWE ch09 · Timelining / MFTECmd]_
- **`--bodyf` replaces `--csvf`** — The bodyfile output filename is set with `--bodyf` (analogous to `--csvf` in CSV mode). _Why:_ Consistent flag pairing: `--body`/`--bodyf` mirror `--csv`/`--csvf`. _[IWE ch09 · Timelining / MFTECmd]_
- **Extension is cosmetic** — Changing the output extension from `.csv` to `.body` is optional and not required for correct operation. _Why:_ MFTECmd's format is governed by the `--body`/`--csv` flag, not the file extension; the extension only aids human recognition. _[IWE ch09 · Timelining / MFTECmd]_
- **`--bdl` supplies the drive letter (REQUIRED for bodyfile)** — The `--bdl` option provides the drive letter from which the MFT was acquired, and is required in bodyfile mode. _Why:_ Without it the bodyfile paths would lack a volume root, breaking downstream path reconstruction. _[IWE ch09 · Timelining / MFTECmd]_
- **Why `--bdl` is needed** — A standalone MFT carries no record of which drive letter (C:, D:, E:, F:, etc.) the volume was mounted as, so the examiner must supply it. _Why:_ Drive-letter assignment is an OS mount-time property external to the MFT, so the tool genuinely cannot infer it. _[IWE ch09 · Timelining / MFTECmd]_
- **`--bdl` prepends to every path** — The value passed to `--bdl` is prepended to each path in the output file. _Why:_ This is how each bodyfile entry gets a full, rooted path (e.g. `c:\Users\...`). _[IWE ch09 · Timelining / MFTECmd]_
- **Any letter is technically accepted** — MFTECmd will accept an arbitrary drive letter (e.g. `Z:`) and still run successfully. _Why:_ The tool does not validate the letter against the source; correctness is the examiner's responsibility. _[IWE ch09 · Timelining / MFTECmd]_
- **Match the real source drive letter** — Best practice is to set `--bdl` to the actual drive letter the MFT came from. _Why:_ An incorrect drive letter yields misleading paths in the timeline and can confuse correlation with other artifacts. _[IWE ch09 · Timelining / MFTECmd]_
- **Bodyfile run parity** — The bodyfile run detected the file type the same way, finished in under two seconds, and reported the identical FILE-record count (186,889) as the CSV run. _Why:_ Only the output format changed; identical counts confirm the two formats describe the same parsed data. _[IWE ch09 · Timelining / MFTECmd]_

### Bodyfile Format Characteristics

- **Pipe-delimited format** — A bodyfile is a pipe (`|`) delimited text file. _Why:_ The pipe delimiter is the Sleuth Kit bodyfile convention; mactime and other consumers parse on `|`. _[IWE ch09 · Timelining / MFTECmd]_
- **Inspect with `type ... | more`** — The bodyfile can be viewed at the Windows shell with `type <path> | more`. _Why:_ Quick sanity check that the file is well-formed and that `--bdl` prepending worked before feeding downstream tools. _[IWE ch09 · Timelining / MFTECmd]_
- **Drive-letter prefix visible per line** — Each line of the bodyfile begins with the drive letter supplied via `--bdl` (e.g. `c:`). _Why:_ Confirms the `--bdl` prepend applied to every record, giving rooted paths throughout. _[IWE ch09 · Timelining / MFTECmd]_

### Downstream Timeline Pipelines

- **Feed bodyfile into mactime** — The MFTECmd bodyfile output can be piped into `mactime` to render a timeline. _Why:_ mactime is the Sleuth Kit tool that sorts a bodyfile into a chronological, human-readable timeline. _[IWE ch09 · Timelining / MFTECmd]_
- **Result equivalent to fls + mactime** — The mactime timeline built from MFTECmd's bodyfile is nearly identical to one produced from `fls` + `mactime`. _Why:_ MFTECmd and fls both emit standard bodyfiles, so the mactime output converges regardless of which produced the bodyfile. _[IWE ch09 · Timelining / MFTECmd]_
- **Feed bodyfile into Plaso / log2timeline** — The bodyfile can be ingested by Plaso and log2timeline, which has a parser that handles bodyfiles. _Why:_ This lets the MFTECmd output slot into a Plaso super-timeline alongside many other artifact sources. _[IWE ch09 · Timelining / MFTECmd]_
- **Plaso already has a native MFT parser** — Plaso / log2timeline ships its own built-in FILE-record (MFT) parser, so using MFTECmd's bodyfile is an alternative rather than a necessity. _Why:_ Examiners can choose MFTECmd bodyfile input when they prefer that parser's behavior over Plaso's native one, but it is not required. _[IWE ch09 · Timelining / MFTECmd]_
- **Broad bodyfile tool support** — Other tools beyond mactime and Plaso also consume bodyfiles. _Why:_ Emitting the standard bodyfile format maximizes interoperability across the timelining ecosystem. _[IWE ch09 · Timelining / MFTECmd]_

### Summary Positioning

- **Two distinct capabilities** — The key takeaway: MFTECmd can (1) produce file-system timelines directly (CSV → Timeline Explorer) and (2) produce bodyfile output for downstream timeline tools. _Why:_ Knowing both modes lets an examiner pick the fastest path — direct review vs. integration into a larger super-timeline. _[IWE ch09 · Timelining / MFTECmd]_

## Chapter 09 · Plaso Log2Timeline

### Plaso — nature and purpose

- **Plaso** — Plaso is a digital-forensics toolkit implemented in Python. _Why:_ language/runtime determines install path and dependencies. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Plaso** — Plaso can process a broad range of data sources, spanning log files, system artifacts, web browser histories, and application logs. _Why:_ single tool covers many artifact classes an examiner would otherwise parse separately. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Super timeline** — Plaso produces what are termed "super timelines," which merge disparate data types into one combined view of user and system activity. _Why:_ this is Plaso's defining output concept. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Super timeline vs file-system timeline** — Unlike a traditional file-system timeline (such as those built by `fls` and `mactime`), a super timeline offers a more detailed, event-rich view rather than just filesystem metadata timestamps. _Why:_ distinguishes super timeline from a plain MACB filesystem timeline. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Super timeline** — A super timeline gives a more complete picture of the actions that occurred on a device because it weaves together many artifact types. _Why:_ investigative rationale for building a super timeline. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Plaso toolkit — component tools

- **log2timeline** — `log2timeline` is the central/main tool of Plaso; the names "Plaso" and "Log2Timeline" have become effectively synonymous, though the more accurate reference is "Plaso/Log2Timeline." _Why:_ clarifies naming so an examiner recognizes both terms mean the same suite. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **log2timeline** — Log2Timeline is a parser that navigates a wide array of file types, system artifacts, and logs. _Why:_ defines the extraction role. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **log2timeline** — Log2Timeline automatically identifies and extracts timestamped events from sources such as browser histories, event logs, and application data. _Why:_ automatic event discovery is the core value of the collection stage. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **log2timeline** — Log2Timeline compiles the extracted events into a Plaso storage file, which is essentially a database. _Why:_ output of the collection stage is a storage database, not a flat timeline. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Plaso storage file** — The Plaso storage database acts as a comprehensive archive of the extracted timeline information. _Why:_ the storage file is the intermediate archive re-usable across many output runs. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **pinfo** — `pinfo` reports metadata about the Plaso storage file produced by Log2Timeline. _Why:_ inspection tool to understand a storage file without re-parsing. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **pinfo** — `pinfo` output includes the total count of events stored in the file. _Why:_ event count is a quick sanity/scope check. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **pinfo** — `pinfo` output includes the earliest and latest timestamps represented across the stored events. _Why:_ bounds the temporal coverage of the collection. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **pinfo** — `pinfo` output includes the types of data sources that were processed (for example web history, system logs, application data). _Why:_ shows which artifact classes were actually captured. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **pinfo** — `pinfo` output includes warnings and errors encountered during processing. _Why:_ surfaces parsing failures that could mean missing evidence. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psort** — `psort` sorts and categorizes the events held in the Plaso storage file. _Why:_ the ordering/output stage distinct from collection. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psort** — `psort` can filter events by criteria such as time ranges, event types, and sources. _Why:_ filtering at output stage narrows the timeline without re-collecting. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psort** — `psort` can output data in a variety of formats. _Why:_ decouples storage format from final deliverable format. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal** — `psteal` combines the capabilities of Log2Timeline and psort into a single streamlined operation. _Why:_ one-command path from image to timeline. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal** — `psteal` performs the dual tasks of extracting events from the selected data sources and organizing them, producing a ready-to-use output. _Why:_ explains what the combined step actually does. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal** — Using `psteal` can significantly speed up workflows in some cases by avoiding running the two tools separately. _Why:_ efficiency rationale for the combined tool. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **image_export** — `image_export` extracts files of interest from disk images based on predefined filters such as filenames, file types, or locations. _Why:_ targeted file carving/collection from an image. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **image_export** — `image_export` is useful for isolating relevant evidence from large datasets, making evidence collection more efficient. _Why:_ reduces reviewed volume by extracting only wanted files. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Installation

- **Install platform** — The lesson installs Plaso/Log2Timeline on Ubuntu running inside WSL 2 (Windows Subsystem for Linux 2). _Why:_ recommended environment for running Plaso from a Windows analysis workstation. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install platform** — Running Plaso/Log2Timeline under Ubuntu in WSL 2 is presented as far easier than getting it working natively on Windows. _Why:_ avoids the pain of native-Windows dependency setup. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install source** — Installation follows the Plaso/Log2Timeline user's guide, specifically the "installing the packaged release" instructions found under the Releases section. _Why:_ packaged release is the supported easy path. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install target OS** — The packaged-release instructions are written for Ubuntu 24.04 but also work on Ubuntu 22.04. _Why:_ version compatibility for the install steps. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install step 1 — universe repo** — The first install step adds the Ubuntu `universe` repository. _Why:_ prerequisite package source. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install step 2 — PPA** — The second step adds a PPA (Personal Package Archive), which is a different type of repository from `universe`. _Why:_ the Plaso packages live in a dedicated PPA. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install step 3 — apt update** — After adding the repositories, run `sudo apt update` to refresh the list of repos. _Why:_ index refresh is mandatory before install. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install ordering gotcha** — If `sudo apt update` is not run first, the subsequent install command will fail. _Why:_ common install failure cause is a stale package index. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install step 4 — package** — The tools are installed with `sudo apt install plaso-tools`. _Why:_ exact package name for the packaged release. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install dependencies** — Installing `plaso-tools` pulls in many supporting packages that back the various tools in the suite. _Why:_ the packaged release resolves all prerequisites automatically. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install rationale** — Installing the packaged release is more convenient than manually satisfying all prerequisites yourself. _Why:_ justifies choosing the packaged release over source. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Install verification** — Installation is verified by running `log2timeline.py` and confirming it responds/works. _Why:_ simple smoke test that the suite installed correctly. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Executable naming** — Plaso tools are invoked with a `.py` suffix (e.g. `log2timeline.py`, `psort.py`, `psteal.py`). _Why:_ correct command names at the shell. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Output formats

- **Output format list** — `psteal.py -o list` lists the output formats supported by the tool. _Why:_ discover valid `-o` values. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Shared format set** — The output formats supported by psteal are the same set supported by psort. _Why:_ format knowledge transfers between the two tools. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **dynamic format** — `dynamic` is the top listed output format and is the near-universal recommended choice. _Why:_ default deliverable format for modern Plaso. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **l2tcsv format** — `l2tcsv` is the legacy Log2Timeline output format containing 17 fixed fields; it was historically the go-to option. _Why:_ context for older workflows/documentation still referencing it. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **l2tcsv deprecation warning** — Modern Plaso versions warn against `l2tcsv`, citing limitations such as second-only date/time resolution and a limited predefined set of output fields, and recommend an alternative format like `dynamic`. _Why:_ l2tcsv loses sub-second precision and field richness. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Running psteal (one-step workflow)

- **psteal --source** — `psteal.py --source <image>` specifies the source disk image to process. _Why:_ input selection parameter. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal -o** — `-o <format>` (e.g. `-o dynamic`) sets the output format for psteal. _Why:_ chooses the deliverable format. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal -w** — `-w <filename>` sets the output file into which results are written (e.g. `timeline.csv`). _Why:_ names the resulting timeline file. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal full example** — A complete invocation is `psteal.py --source <ACME image> -o dynamic -w timeline.csv`. _Why:_ canonical one-line super-timeline command. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Partition prompt** — On running, psteal prompts the examiner to select which partition(s) to process. _Why:_ multi-partition images require an explicit choice. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Partition identifiers** — Partitions are presented with identifiers like `p3`; the same partitions are visible via `fdisk -l`. _Why:_ correlates Plaso's partition list with disk-tool output. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Windows partition selection** — In the ACME example the Windows partition is `p3`, and it is the largest of the listed partitions. _Why:_ the largest partition is typically the OS/data volume of interest. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **all partitions** — Typing `all` at the partition prompt processes every partition instead of a single one, which is a valid approach. _Why:_ avoids missing evidence on secondary partitions. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psteal internals** — Under the hood psteal enumerates the disk image with Log2Timeline and then creates the final timeline with psort, doing both in a single pass. _Why:_ confirms psteal = log2timeline + psort combined. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### The "kitchen sink" (unconstrained) run and its cost

- **Kitchen sink approach** — Running Plaso without any date-range or artifact-type constraints is the "kitchen sink" approach: it parses everything it knows how to parse and builds a giant super timeline. _Why:_ names the trade-off between completeness and volume. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Kitchen sink runtime** — The unconstrained ACME run took about 3.5 hours even on a 64-core Threadripper; slower hardware takes longer. _Why:_ sets realistic expectations for full-image super-timeline processing time. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Kitchen sink rationale** — The kitchen sink approach is the presenter's usual real-world choice because constraining risks inadvertently excluding and missing something important. _Why:_ completeness-first mindset in real investigations. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Kitchen sink caveat** — The kitchen sink approach is valid but not the most efficient; targeted options exist to speed it up when only a subset of data is needed. _Why:_ the "too much data" caveat motivates filtering. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Output file size** — The resulting `timeline.csv` from the ACME kitchen-sink run is about 800 MB. _Why:_ illustrates the volume problem of an unconstrained super timeline. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Workflow philosophy** — The presenter's typical method is to build a full super timeline, then filter it down based on what is already known, pivoting iteratively to discover more until as complete a picture as possible is assembled. _Why:_ describes the collect-broad-then-filter investigative loop. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Method frequency** — Building a full super timeline is what the presenter does roughly nine times out of ten when analyzing a full disk image, though event-log and file-system timelines are still created too. _Why:_ positions super timeline as the primary, not exclusive, technique. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### The .plaso storage file (two-step workflow)

- **.plaso is SQLite** — The Plaso storage file is a SQLite database; running `file` against it reports it as a SQLite database. _Why:_ the storage file can be inspected/queried as SQLite. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Two-step split** — The one-step psteal process can be split into two: first run Log2Timeline (whose output is the .plaso database), then run psort against that database to create the resulting timeline.csv. _Why:_ the manual pipeline that psteal automates. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **log2timeline --storage-file** — `log2timeline.py --storage-file <name> <image>` creates the Plaso storage file; the example names it `timeline.plaso`. _Why:_ exact syntax for the collection stage. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **.plaso extension convention** — The storage-file naming is arbitrary, but `.plaso` is the common conventional extension for a Plaso storage file. _Why:_ recognizable file convention. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **log2timeline partition prompt** — Standalone `log2timeline.py` also prompts for the partition to parse (again `p3` for the Windows partition in the ACME example). _Why:_ same partition-selection behavior as psteal. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **psort basic syntax** — `psort.py -o dynamic -w timeline2.csv timeline.plaso` reads the storage database and writes the sorted timeline; `-o` sets format, `-w` sets output filename, and the trailing argument is the .plaso database. _Why:_ exact syntax for the output stage. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Verifying one-step vs two-step equivalence

- **Line-count check** — `wc -l` gives the line count of a CSV timeline and is used to compare the psteal output against the two-step output. _Why:_ quick way to confirm two pipelines produced identical volume. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Equivalence result** — The psteal-produced `timeline.csv` and the manually produced `timeline2.csv` had exactly the same line count (2,028,296 lines), confirming the one-step and two-step workflows yield identical output. _Why:_ proves psteal is a true combination of log2timeline + psort. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Why run the tools separately (flexibility)

- **Reason to split** — Running Log2Timeline and psort separately is worthwhile to control what gets captured into the database (via Log2Timeline options) or what gets produced in the final timeline (via psort options). _Why:_ the two stages offer two distinct filtering points. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Collection-side filtering example** — Log2Timeline can be told to collect only browser artifacts, so that psort against that database yields a timeline containing only web browser artifacts and thus a much smaller dataset. _Why:_ filter at collection to shrink the storage file itself. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Output-side filtering example** — Alternatively, Log2Timeline can collect everything (kitchen sink) while psort filters the timeline to only a few days — useful when a threat actor was active in a known time window. _Why:_ collect broad, narrow at output for a specific incident window. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Flexibility summary** — The core reason to use Log2Timeline and psort independently rather than psteal is the added flexibility over what is collected and what ends up in the final timeline. _Why:_ the trade-off of two-step vs one-step. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Log2Timeline collection filtering (defines what enters the .plaso)

- **Two collection-filter methods** — There are two main ways to filter what Log2Timeline collects, and both define what ends up in the Plaso storage file/database. _Why:_ frames the collection-stage filtering options. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Artifact definitions source** — The first method uses forensic artifact definitions sourced from the digital-forensics ForensicArtifacts repository, a free, open-source knowledge base of digital forensic artifacts. _Why:_ artifact names come from a shared community repository, not arbitrary strings. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **--artifact-filters** — One or more artifact definitions are specified at the command line with the `--artifact-filters` parameter. _Why:_ exact flag for artifact-based targeted collection. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Artifact filter example** — The example artifact filter `WindowsEventLogSystem` captures the Windows System event log. _Why:_ concrete named-artifact example. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **--file-filter** — The second method uses a YAML-based filter file, supplied via the `--file-filter` parameter, that can include or exclude specific files from the collection. _Why:_ path-based targeted collection via a YAML file. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Filter-file dual example** — The example YAML filter includes all Windows event logs and excludes the Linux `/usr/bin` directory. _Why:_ shows include and exclude in one file. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### YAML filter-file fields

- **description field** — In the YAML filter file, `description` is an optional description of the purpose of a path filter. _Why:_ documents intent of each filter entry. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **type field** — `type` is the required filter type and must be `include` or `exclude`. _Why:_ mandatory field controlling filter direction. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Inclusion-before-exclusion** — Inclusion filters are applied before exclusion filters. _Why:_ ordering rule that determines the net result when include and exclude overlap. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Directory recursion** — Specifying a path of a directory includes or excludes all of its files and subdirectories, i.e. the filter is recursive. _Why:_ a single directory path covers the whole subtree. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **path_separator field** — `path_separator` is an optional path-segment separator, defaulting to forward slash `/`. _Why:_ controls how path segments are delimited. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **path_separator for Windows** — For Windows event log paths, `path_separator` must be set to backslash `\`, which is why it is explicitly defined in the Windows section of the example. _Why:_ Windows paths need backslash separators, unlike the default. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **path_separator for Linux** — For the Linux section, `path_separator` is not specified because the default forward slash `/` already applies. _Why:_ Linux paths use the default separator, so no override is needed. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **paths field** — `paths` contains one or more paths to filter, defined as regular expressions. _Why:_ path matching is regex-based, enabling pattern matching. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### psort advanced filtering (defines what enters the final timeline)

- **psort scope** — psort filtering options define which already-collected data in the Plaso storage file is actually used to build the final timeline; they do not change what was collected. _Why:_ psort filters output only, never re-collects. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **--slice (time slicing)** — psort's time-slicing feature focuses on events surrounding a specific point in time via the `--slice` option, collecting events occurring X minutes before and after the specified time. _Why:_ zoom into activity around a known event timestamp. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Default slice window** — The default slice window is five minutes (before and after the specified time). _Why:_ the out-of-the-box window if `--slice-size` is not set. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **--slice-size** — The slice window can be adjusted with `--slice-size` followed by the window size in minutes. _Why:_ widen/narrow the slice around the pivot time. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Slice time format** — The time given to `--slice` must be in ISO 8601 format complete with the timezone offset. _Why:_ correct timestamp format prevents parse errors and timezone ambiguity. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Date-range filtering** — psort can filter events by date ranges. _Why:_ restrict the timeline to a bounded window. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Date-range boundary example** — The example date range selects events after `2023-12-31 23:59:59` and before `2024-04-01 00:00:00`, i.e. January 1, 2024 through March 31, 2024. _Why:_ the exclusive-boundary phrasing yields the intended inclusive calendar-quarter. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Date-range syntax rigidity** — The exact date-range syntax shown must be used to perform date-range filtering. _Why:_ deviating from the required syntax breaks the filter. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

### Artifact classes visible in the ACME super timeline (Source Long column)

- **Timeline Explorer columns** — Timeline Explorer displays `Source` and `Source Long` columns; `Source Long` gives a more verbose description of each artifact's source type. _Why:_ identifies which artifact produced each timeline row. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Artifact breadth** — The ACME super timeline contained, among others: event logs, file-system entries, AmCache, AppCompatCache (Shimcache), Chrome, Firefox, NTFS-specific information, PowerShell, RDP, Recycle Bin, registry information, USB device information, UserAssist, Windows shortcut (LNK) files, and Prefetch. _Why:_ demonstrates the many artifact classes a single super timeline unifies. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_
- **Super-timeline advantage** — A super timeline provides far more artifact types than an event-log timeline or a file-system timeline alone, which is why it is called "super." _Why:_ the combined artifact breadth is the defining benefit. _[IWE ch09 · Timelining / Plaso & Log2Timeline]_

## Chapter 09 · TSK fls mactime

### The Sleuth Kit (TSK) — overview

- **The Sleuth Kit (TSK)** — a suite of command-line tools for low-level analysis of file systems. _Why:_ establishes the toolset that fls/mactime belong to. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **TSK — abbreviation** — "The Sleuth Kit" is commonly abbreviated TSK. _Why:_ naming/terminology for lookups. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **TSK — file system coverage** — TSK analyzes data and metadata across multiple file systems, not only NTFS. _Why:_ the same workflow applies beyond Windows volumes. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **TSK — capability** — supports in-depth examination of both file data and file system metadata. _Why:_ distinguishes metadata timelining from content carving. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Installing TSK (WSL / Ubuntu)

- **TSK install (Debian/Ubuntu)** — `sudo apt install sleuthkit` installs the package and its prerequisites. _Why:_ standard install path on Ubuntu. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **TSK under Windows** — TSK can be run inside Windows Subsystem for Linux (WSL) with an Ubuntu instance. _Why:_ lets a Windows examiner use the Linux-native tools without a separate box. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fdisk not preinstalled** — `fdisk` is often not installed by default on a fresh Ubuntu instance and can be added with `sudo apt install fdisk`. _Why:_ needed to read the partition table before running fls. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### fls — purpose

- **fls — role** — fls lists files and directories from a file system image and extracts their timestamps. _Why:_ this enumeration is the raw material for a file system timeline. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls — output for timelining** — fls can produce a "body file" that a companion tool converts into a timeline. _Why:_ fls is stage one of a two-stage pipeline. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **File system timeline concept** — a file system timeline is built from the MAC(B) timestamps of every file and directory on a volume. _Why:_ defines what the artifact represents. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls default output** — run with no arguments, fls prints its usage/options summary. _Why:_ quick way to review available flags. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### fls — options / flags

- **fls `-r`** — recurse through the entire file system, descending into all subdirectories. _Why:_ without it you only get the top level; a full timeline needs recursion. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-d`** — display only deleted entries. _Why:_ lets you build a timeline restricted to deleted files. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-p`** — display the full path for each file. _Why:_ gives per-entry location context in the output. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-m`** — emit output in mactime (body file) format. _Why:_ required so the mactime tool can consume the result. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-f`** — specify the file system type explicitly. _Why:_ overrides auto-detection when it fails or is ambiguous. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-f list`** — `-f list` prints the file system types TSK supports. _Why:_ shows valid values before forcing a type. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls `-o`** — specify the partition start offset (in sectors) within a multi-partition image. _Why:_ points fls at the correct partition inside a whole-disk image. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### fls — invocation & path argument

- **fls positional path** — the metadata/path argument (e.g. `"/"` in quotes) sets the starting point of enumeration; `/` means the file system root. _Why:_ combined with `-r`, `/` recurses the whole volume. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls path separator** — the root argument uses a forward slash `/`, not a Windows backslash `\`, even when imaging a Windows/NTFS volume. _Why:_ TSK uses Unix-style path syntax internally. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls image argument** — the disk image file is supplied as a positional argument after the options and path. _Why:_ tells fls which image to parse. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls output redirection** — fls writes to standard output; redirect with `>` to a file (e.g. `> timeline.body`) to capture the body file. _Why:_ the body file must be saved before mactime can read it. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Example fls command** — `fls -r -p -m "/" <image> -o <offset> > timeline.body` is the full recursive, full-path, mactime-format invocation with an explicit partition offset. _Why:_ canonical one-line recipe for a whole-volume body file. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls silent run = success** — after launching, fls returns no visible output and just shows a cursor while it works in the background; this is normal, not a hang. _Why:_ prevents the examiner from aborting a working job. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls runtime** — enumerating a full file system can take from a few minutes to 30 minutes or longer depending on file system size. _Why:_ sets expectations; the demo volume took ~20 minutes. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### "Cannot determine file system type" error

- **fls error — cause** — `Cannot determine file system type` appears when fls is pointed at a whole-disk image that has more than one partition, so it cannot find a single file system at the image start. _Why:_ the real problem is a missing offset, not an unknown FS. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls error — wrong fix** — forcing the file system type with `-f` (e.g. NTFS) does NOT resolve `Cannot determine file system type` on a multi-partition image. _Why:_ warns against the intuitive-but-useless remedy. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fls error — correct fix** — supply the partition's starting sector via `-o <offset>` so fls begins parsing at the file system's real start. _Why:_ the offset is the actual solution to the error. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Finding the partition offset (fdisk)

- **fdisk `-l`** — `fdisk -l <image>` lists the partition table of a disk image. _Why:_ reveals partitions and their start sectors for the `-o` value. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **fdisk output columns** — the listing includes Start, End, and Sectors for each partition. _Why:_ the Start column supplies the offset fls needs. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Offset = partition Start sector** — the value passed to fls `-o` is the "Start" sector of the target partition from `fdisk -l`. _Why:_ direct mapping between fdisk output and fls input. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Identifying the Windows partition** — on a typical Windows disk the OS/data partition is the largest one; select it when multiple partitions exist. _Why:_ heuristic to pick the right partition to timeline. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Typical Windows partition layout** — a modern Windows disk image commonly shows four partitions: EFI System, Microsoft Reserved, Microsoft Basic Data, and Windows Recovery Environment. _Why:_ knowing the standard layout helps locate the data partition. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Microsoft Basic Data = the target** — the "Microsoft basic data" partition (the large one, ~95 GB in the demo) holds the Windows file system to be timelined. _Why:_ identifies which of the four partitions to offset into. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Demo offset value** — in the demo the Windows partition's Start sector (the `-o` offset) was 239616. _Why:_ concrete example of a real offset (values differ per image). _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Body file — format & inspection

- **Body file — definition** — the "body file" fls produces is a pipe-delimited (`|`) text file of file system metadata. _Why:_ pipe delimiting is the intermediate format mactime parses. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Body file naming convention** — `.body` is the conventional extension, but the file may be named anything. _Why:_ convention aids recognition; not a hard requirement. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Body file timestamps — encoding** — timestamps inside the body file are stored as Unix/Linux epoch values (seconds since 1970), not human-readable dates. _Why:_ explains why raw body files look opaque; mactime converts them. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Body file size** — a full-volume body file can be large (~80–85 MB in the demo). _Why:_ storage expectation for whole-disk timelines. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Inspecting a body file** — `head timeline.body` shows the first lines so you can confirm the pipe-delimited structure. _Why:_ quick sanity check before running mactime. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### mactime — purpose & options

- **mactime — role** — mactime takes an fls body file and converts it into a sorted, human-readable MAC timeline. _Why:_ stage two of the pipeline; produces the usable output. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime `-b`** — `-b <body file>` specifies the input body file created by fls. _Why:_ tells mactime what to parse. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime `-d`** — output in comma-delimited (CSV) format. _Why:_ CSV opens directly in Timeline Explorer or Excel. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime `-y`** — output timestamps in ISO 8601 format AND standardize the time zone to UTC. _Why:_ one flag gives both a standard timestamp format and UTC normalization. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime `-z`** — specify an arbitrary output time zone. _Why:_ alternative to `-y` when a non-UTC zone is (rarely) wanted. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **`-y` and `-z` mutually exclusive** — `-z` does not work together with `-y`; use one or the other. _Why:_ avoids an invalid flag combination. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime default output** — with no output redirection mactime dumps the timeline to standard output (the screen). _Why:_ must redirect to a file to keep it. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime output redirection** — redirect with `>` to a file (e.g. `> timeline.csv`) to save the CSV timeline. _Why:_ produces the analyzable deliverable. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Example mactime command** — `mactime -b timeline.body -d -y > timeline.csv` produces a UTC, ISO 8601, CSV timeline. _Why:_ canonical recipe for the final timeline. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **mactime speed** — converting an already-built body file to CSV takes only seconds because the heavy enumeration was already done by fls. _Why:_ contrasts with the long fls stage; reformatting is cheap. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **CSV vs body file size** — the mactime CSV is larger than the source body file (~162 MB CSV vs ~85 MB body in the demo). _Why:_ the human-readable/expanded format inflates size. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### mactime — date-range filtering

- **mactime date range** — mactime accepts a date range to limit the timeline to a specific window. _Why:_ narrows huge timelines to the period of interest. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Date-range syntax** — the range is written `YYYY-MM-DD..YYYY-MM-DD` (two dots between start and end), e.g. `2024-01-01..2024-01-31` for January 2024. _Why:_ exact syntax to scope by date. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Time-zone discipline (forensics principle)

- **Standardize on UTC** — forensic timelines should be normalized to UTC. _Why:_ a single baseline avoids cross-time-zone confusion. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Why UTC** — investigations often span systems in different time zones (e.g. US East/West coast, Europe); mishandling zone conversions can produce serious errors when drawing conclusions from evidence. _Why:_ motivates the UTC-only rule. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Prefer `-y` over `-z`** — because UTC is the correct forensic baseline, `-y` (ISO 8601 + UTC) is preferred and `-z` (custom zone) should be avoided where possible. _Why:_ operationalizes the UTC discipline in the tool. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Timeline CSV — columns & interpretation

- **Timeline column set** — the mactime CSV columns are: Timestamp, MACB, meta, filename (full path), file size, UID, GID, permissions. _Why:_ defines the schema of the output. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Timeline Explorer extra columns** — Timeline Explorer prepends its own "Line" (row number) and "Tag" (checkbox) columns that are not part of the mactime data. _Why:_ distinguishes viewer chrome from actual timeline fields. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Tag column use** — the Tag checkbox lets you mark rows of interest and later filter to just the tagged rows. _Why:_ triage convenience during analysis. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **UID/GID/permissions on Windows** — the UID, GID, and permissions columns are meaningful for Unix/Linux file systems and can be ignored when analyzing a Windows/NTFS image. _Why:_ avoids over-reading empty/irrelevant fields on NTFS. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Default sort order** — the timeline is sorted by Timestamp oldest-to-newest by default. _Why:_ chronological order is the natural reading of a timeline. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **meta column** — the "meta" column holds the NTFS metadata (record) reference for the entry. _Why:_ ties a timeline row back to its MFT entry. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **filename column** — the filename column carries the full file path (when `-p` was used with fls). _Why:_ gives on-disk location for each timestamped event. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### MACB timestamps

- **MACB expansion** — MACB = Modification, Access, MFT-record Change, and Birth (creation). _Why:_ decodes the four NTFS timestamp types shown per row. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **"C" = MFT record change** — in the MACB scheme the C is the MFT *record change* time (`$STANDARD_INFORMATION` change), not a "created" time; Birth/B is the creation time. _Why:_ prevents the common confusion of C with creation. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **MACB dot notation** — a period/dot in a MACB position means that timestamp type does NOT apply to that row's timestamp; a letter (M/A/C/B) means it does. _Why:_ how to read which timestamp types a given time value represents. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **MACB collapsing** — one timeline row can represent several timestamp types at once; e.g. `M..B` means that single time value is both the Modification and Birth time but not Access or Change. _Why:_ mactime groups identical timestamps into one row flagged by MACB letters. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Invalid / placeholder timestamps

- **Bogus early timestamps are normal** — values like `1980-01-01 00:00` and `2001-01-01` appear when a file has no valid extractable timestamp; they are not tool errors. _Why:_ prevents misreading placeholder dates as tool failure. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Where bogus timestamps sit** — because the timeline sorts oldest-first, invalid/placeholder timestamps cluster at the very top of the output. _Why:_ scroll past them to reach the real activity. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Downstream viewing & analysis

- **Timeline Explorer / Excel** — the mactime CSV can be opened in Timeline Explorer or Excel; Timeline Explorer is recommended. _Why:_ CSV is the interchange format into an analysis GUI. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Associate .csv with Timeline Explorer** — setting the OS to open `.csv` files with Timeline Explorer lets you double-click a mactime output to load it directly. _Why:_ workflow convenience for repeated CSV analysis. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Timeline pivot technique** — locate a file/timestamp of interest, then examine the rows immediately before and after to see what else was created or modified around that moment. _Why:_ temporal proximity supplies investigative context. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **`ll` alias** — on Ubuntu `ll` is typically aliased to `ls -la` (long listing including hidden files); `ll -h` adds human-readable sizes. _Why:_ used to check body/CSV file sizes during the workflow. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

### Source image context

- **Demo image type** — the sample was a `-flat.vmdk` (VMware ESXi virtual machine disk); the `-flat.vmdk` naming indicates a VMware ESXi VM. _Why:_ shows fls/fdisk working directly on a VMDK. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_
- **Related TSK tools** — the broader TSK suite includes other command-line tools (e.g. mmls, istat, icat) alongside fls and mactime for partition and file/metadata analysis. _Why:_ situates fls/mactime within the full kit for follow-on work. _[IWE ch09 · Timelining / The Sleuth Kit fls & mactime]_

## Chapter 10 · Thumbcache

### What the artifacts are / purpose

- **Thumbs.db** — A per-folder cache database for thumbnail images, introduced with Windows 2000. _Why:_ Fixes the era and origin of the older artifact. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db trigger** — The file is created the first time a folder is opened in Windows Explorer and its contents are displayed in an icon-style (thumbnail) view. _Why:_ Presence of the file evidences that the folder was browsed in icon view. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db is hidden** — The file is a hidden file within the folder. _Why:_ It will not appear in a normal directory listing; must use `dir /a` or reveal hidden files. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db is a database** — Internally it is a database structure, not a single image. _Why:_ Requires a parser to read; can hold multiple cached thumbnails. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db purpose** — It caches the thumbnail images so that on a subsequent visit Explorer can pull them from the cache instead of regenerating them, making Explorer faster and improving user experience. _Why:_ Explains why the artifact exists and persists. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache** — Introduced in Windows Vista, it largely replaced Thumbs.db for local content while keeping mostly the same caching purpose. _Why:_ Fixes the Vista+ successor artifact. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache centralization** — Unlike Thumbs.db (one database per folder), Thumbcache stores all thumbnail databases in a single central location, holding thumbnails for paths across the whole system that were viewed in Explorer icon view. _Why:_ The defining architectural difference between the two artifacts; changes how you locate and interpret them. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Key contrast** — Thumbs.db is per-folder (exists in each individual folder viewed in icon view); Thumbcache is centrally located for the user. _Why:_ Core distinction to state in a report. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Locations / paths

- **Thumbcache path** — Thumbcache files live under each user's `%LocalAppData%\Microsoft\Windows\Explorer` (i.e. `AppData\Local\Microsoft\Windows\Explorer`). _Why:_ Where to collect Thumbcache per user profile. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache is per-user** — The path is inside a specific user's AppData, so each user account has its own Thumbcache. _Why:_ Attribution — thumbnails belong to a particular user profile. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db location today** — On modern Windows, Thumbs.db is created inside the specific folder that was viewed, for UNC/network paths. _Why:_ Where to look for surviving Thumbs.db on current systems. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Thumbcache file naming and size buckets

- **Filename pattern** — Thumbcache database files are named `thumbcache_<number>.db` (e.g. `thumbcache_1280.db`). _Why:_ Recognize the artifact by name. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Number = resolution bucket** — The number in the filename indicates the resolution of the thumbnails stored inside that database. _Why:_ Tells you which file holds larger/higher-quality thumbnails worth examining. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **1280 bucket** — `thumbcache_1280.db` corresponds to thumbnails at 1280×720. _Why:_ Resolution mapping. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **1920 bucket** — The 1920 file corresponds to 1920×1080. _Why:_ Resolution mapping. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **2560 bucket** — The 2560 file corresponds to 2560×1440. _Why:_ Resolution mapping; buckets continue upward ("and so on"). _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Modern thumbnails can be large/high-res** — Newer Windows can store large, high-resolution thumbnails to support high-resolution displays, unlike old Windows versions where thumbnails were tiny and hard to make out. _Why:_ Higher-res cached thumbnails are more probative (identifiable content). _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Empty bucket = ~24 bytes** — A Thumbcache file containing no thumbnails is essentially empty at about 24 bytes (observed for the 2560 and 1920 files in the demo). _Why:_ A ~24-byte size means nothing is cached in that bucket; skip it. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Populated bucket is large** — A populated bucket is much larger (the demo `thumbcache_1280.db` was over 33 MB). _Why:_ File size is a quick triage signal for which bucket holds evidence. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Forensic value — surviving thumbnails of deleted content

- **Core value** — Both Thumbs.db and Thumbcache can retain cached thumbnails for images that no longer exist on the system. _Why:_ The central reason these artifacts matter forensically. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Survives secure wiping** — A cached thumbnail can persist even after the original image was securely erased / securely wiped. _Why:_ Recovers evidence of images that anti-forensic wiping was meant to destroy. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Survives Volume Shadow Copy deletion** — Even if a suspect deletes all Volume Shadow Copies (to prevent recovery of historical on-disk image copies), the thumbnail cache may still hold representations of the images. _Why:_ Independent recovery path when VSS-based history is destroyed. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **VSS background** — Volume Shadow Copies can let an examiner "go back in time" and extract historical copies of images from disk; a knowledgeable suspect may delete them to defeat this. _Why:_ Context for why thumbnail cache is a valuable fallback. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Law-enforcement relevance** — The artifact is especially relevant to illicit-image investigations (viewing then wiping illicit images). _Why:_ Primary casework context. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Not only images — documents too** — Thumbnails are also generated for documents; a PDF is shown as a thumbnail of its first page. _Why:_ Broadens investigative value beyond photos to documents of interest. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbnail as content evidence** — A cached thumbnail can be legible enough to identify the document even without its filename (e.g. reading a cover-page title, or an author's name in a higher-resolution thumbnail). _Why:_ The thumbnail itself, not just metadata, can establish what content existed. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Proves existence** — A surviving thumbnail can establish that a particular document/image once existed on the system, which alone may be critical to a case. _Why:_ Existence-of-file finding independent of the deleted original. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache retains moved/deleted files** — In the demo, most files whose thumbnails appeared in Thumbcache had already been moved elsewhere or no longer existed, yet remained cached. _Why:_ Demonstrates persistence after move or deletion, not only after wiping. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Thumbs.db still exists on modern Windows (UNC/network paths)

- **Not fully replaced** — Thumbs.db still exists on modern Windows systems; the claim that Thumbcache completely replaced it is incorrect. _Why:_ Corrects a common misconception; don't ignore Thumbs.db on current systems. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Reason it survives** — Thumbs.db persists specifically to support UNC paths / network paths. _Why:_ Explains where to still expect Thumbs.db. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Creation condition** — Viewing a network location (e.g. `\\computername\C$`) in Explorer, navigating into a folder, and displaying it in an icon view can create a Thumbs.db in that UNC path. _Why:_ Precise trigger for a modern Thumbs.db. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Icon-view requirement** — Thumbs.db is created only when the folder is shown in some form of icon (thumbnail) view, not other view modes. _Why:_ Absence of Thumbs.db does not prove the folder was never opened — only that it may not have been viewed in icon mode. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Local path via loopback UNC** — `\\localhost\C$` is a UNC/network-nomenclature path that actually points to the local machine's C: drive (equivalent to `C:\`), because the default administrative shares `C$`, `ADMIN$`, and `IPC$` exist. _Why:_ Browsing a local folder through the loopback UNC share triggers Thumbs.db creation where browsing it directly as `C:\` would not. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Demonstrated behavior** — Opening a local folder directly (drive path) produced no Thumbs.db (`dir /a` showed none), but opening the same folder via `\\localhost\C$` in extra-large-icons view then produced a Thumbs.db in that folder. _Why:_ Concrete proof that the UNC access path, not the folder itself, drives Thumbs.db creation on modern Windows. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Test platform** — This behavior was shown on Windows 11 version 22H2. _Why:_ Anchors the observation to a specific OS build. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Viewing hidden files** — `dir /a` lists all files including hidden ones, revealing an otherwise-hidden Thumbs.db. _Why:_ Command to confirm Thumbs.db presence. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Tools

- **Two free tools** — Thumbcache Viewer (`Thumbcache_Viewer.exe`) parses Thumbcache; Thumbs Viewer (`Thumbs_Viewer.exe`) parses Thumbs.db; both are free. _Why:_ Named viewers for each artifact. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Open a hidden Thumbs.db by name** — In Thumbs Viewer's File > Open, even though the hidden Thumbs.db isn't shown in the dialog, you can type the filename `Thumbs.db` directly to open it. _Why:_ Practical way to open the hidden file in the GUI. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Deletion-survival demonstration** — After shift-deleting `secret.pdf`, re-opening the same Thumbs.db in Thumbs Viewer still showed the "super secret document" thumbnail, proving the cache survives the file's deletion. _Why:_ Empirical confirmation of the core forensic claim. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache Viewer output** — Opening `thumbcache_1280.db` in Thumbcache Viewer lists the cached thumbnails (right-pane image previews) — in the demo, video stills, screenshots, etc., including files already moved or deleted. _Why:_ Shows the viewer's role in surfacing surviving content. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Mapping Thumbcache entries back to original paths

- **The problem** — Because Thumbcache is centrally located (not per-folder), the original filesystem path of each cached thumbnail is not obvious, unlike Thumbs.db where the file's folder equals the source path. _Why:_ Explains why path reconstruction is needed for Thumbcache but not Thumbs.db. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbs.db path is implicit** — For Thumbs.db, the source path is trivially known: the folder containing the Thumbs.db is the folder whose thumbnails it holds. _Why:_ Advantage of the per-folder model for attribution. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Thumbcache IDs / hashes** — Thumbcache databases store Thumbcache IDs and hashes that can, in some cases, be mapped back to the original source-image path. _Why:_ The mechanism enabling path reconstruction from a central cache. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Partial mapping** — Path recovery works only "in some cases," not for every entry. _Why:_ Sets realistic expectations; not all thumbnails yield a path. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Map File Paths feature** — Thumbcache Viewer has a Tools > "Map File Paths" option to reconstruct original paths. _Why:_ Named tool feature for path mapping. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Method 1 — Windows Search DB** — Under Map File Paths, "Load ESE database" lets you feed the Windows Search database (the ESE DB backing Windows Search / start-menu search) from the system of interest so the tool can recreate the original paths the Thumbcache came from. _Why:_ An offline, evidence-friendly way to map paths using an existing artifact. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Method 2 — Scan Directory (live)** — On a live system where the Thumbcache was obtained, the "Scan Directory" option scans the filesystem to determine the original locations of the cached files. _Why:_ Alternate path-mapping method when working the live host. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_
- **Scan Directory caveat** — Scanning the whole system can take a long time. _Why:_ Practical performance consideration when choosing the live-scan method. _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

### Related registry cross-reference

- **Explorer's remembered path** — Explorer common dialogs remember the last-traversed path via the registry artifacts LastVisitedPidlMRU and OpenSavePidlMRU. _Why:_ These MRU artifacts store folder locations and corroborate where a user browsed (cross-linked from the registry module). _[IWE ch10 · Additional Content / Thumbs.db & Thumbcache]_

## Chapter 10 · Web Browser Forensics

### Scope & Reference Material

- **Browser coverage** — Windows web-browser forensics centres on three current browsers: Chromium-based Microsoft Edge, Google Chrome, and Mozilla Firefox. _Why:_ Defines the artifact set an examiner must know for a typical Windows endpoint. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Legacy browsers still relevant** — Two legacy browsers remain worth parsing: the pre-Chromium ("old") Microsoft Edge and Microsoft Internet Explorer. _Why:_ Their artifacts persist on modern systems and IE is still encountered in the field. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Cheat sheet** — A "Windows Browser Artifacts Cheat Sheet" enumerating per-browser profile locations, history, cookies, cache, sessions, and settings paths is distributed as a course download. _Why:_ Consolidated path reference for field work. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **SQLite is the core skill** — Most major artifacts of the major browsers are stored in SQLite databases, so competence with SQLite largely equals competence in browser forensics. _Why:_ Frames the whole discipline around one database format. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Windows Path Variables

- **Two base environment variables** — Every browser artifact path begins with either `%LOCALAPPDATA%` or `%APPDATA%`. _Why:_ Knowing which variable a browser uses tells you which subtree to collect. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`%LOCALAPPDATA%` resolution** — `%LOCALAPPDATA%` resolves to `C:\Users\<username>\AppData\Local`. _Why:_ Translates the variable to an absolute path during collection/mounting. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`%APPDATA%` resolution** — `%APPDATA%` resolves to `C:\Users\<username>\AppData\Roaming` (i.e. the same path as LocalAppData but with `Roaming` instead of `Local`). _Why:_ The Local-vs-Roaming distinction determines whether an artifact would follow a roaming profile. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Microsoft Edge (Chromium) — Profile & Layout

- **Profile root** — Edge (Chromium) stores its data under a `User Data` directory, inside which sits either a `Default` folder or numbered `Profile 1`, `Profile 2`, `Profile 3`, … folders. _Why:_ Identifies which subfolder holds the user's artifacts. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Default vs numbered profiles** — A clean install with no added profiles contains only `Default`; each additional browser profile a user creates produces `Profile 1`, then `Profile 2`, and so on. _Why:_ Presence of `Profile N` folders reveals that multiple in-browser identities were configured. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Creating a profile in the UI** — In Edge a new profile is added via the user/account icon at top-right → "other profiles" → "add profile", which then materialises `Profile 1` on disk. _Why:_ Correlates a UI action to the on-disk folder an examiner will find. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **History file** — Edge history lives in a file literally named `History` with **no file extension**, in the root of the profile folder, and it is a SQLite database. _Why:_ The extensionless name hides that it is a parseable SQLite DB. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **History file size is activity-dependent** — On a lightly-used system the History database can be very small (example shown ≈163 KB). _Why:_ Size roughly indexes browsing volume. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Manual parsing option** — Because History is plain SQLite, it can be opened directly in any SQLite viewer and parsed by hand, or by numerous dedicated tools. _Why:_ No proprietary decoding needed to read history. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Preferences file** — In the profile root, a `Preferences` file stores browser settings/configuration; it is a configuration file, **not** a SQLite database. _Why:_ Settings profiling for a user requires parsing this separately from SQLite artifacts. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Cookies database location** — Edge cookies are in a `Cookies` SQLite database (extensionless) inside the profile's `Network` subdirectory. _Why:_ Cookies moved under `Network\`, not the profile root. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Cache directory** — The `Cache` subdirectory holds the cached web content as many individual files (example showed 276 files on a lightly-used system). _Why:_ Cache is a folder of files, recoverable with cache-parsing tools. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Sessions directory** — A `Sessions` directory stores session-restore data, i.e. the tabs/state used by the "continue where you left off / reopen tabs" feature. _Why:_ Reveals what tabs a user had open, even without a visit landing in History. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Google Chrome — Layout

- **Chrome mirrors Edge** — Chrome's on-disk layout is identical to Chromium Edge's: extensionless `History` SQLite DB, `Cookies` SQLite DB, `Cache` directory, `Sessions` directory, and `Preferences` file, in the same relative positions. _Why:_ One mental model parses both browsers. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Only the vendor path differs** — The single difference between Chrome and Edge is the vendor path segment ("Google\Chrome\User Data" vs "Microsoft\Edge\User Data"). _Why:_ Pointing a tool at the right root is the only per-browser adjustment. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Shared engine explains parity** — Chrome and Edge share the same underlying (Chromium) engine, which is why their artifact layouts match. _Why:_ Explains the structural equivalence rather than treating it as coincidence. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Mozilla Firefox — Layout

- **Uses `%APPDATA%` (Roaming)** — Firefox artifact paths start with `%APPDATA%` (Roaming), not `%LOCALAPPDATA%` — the opposite base variable from Chromium browsers, with one exception (cache). _Why:_ Collection must target the Roaming tree for most Firefox artifacts. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Profiles path** — Firefox profiles live under `%APPDATA%\Mozilla\Firefox\Profiles\`, each named `<8 random alphanumeric characters>.<suffix>`. _Why:_ The random prefix means the profile folder name is not fixed and must be enumerated. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`.default-release` is the live profile** — Under `Profiles\` there are typically two folders, `<xxxxxxxx>.default` and `<xxxxxxxx>.default-release`; the `.default-release` one holds the real user data. _Why:_ Prevents wasting effort on the near-empty `.default` folder. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`.default` is near-empty** — The plain `.default` profile folder is not the one of interest; in the example it held essentially nothing but a single JSON file. _Why:_ Confirms which of the two folders to skip. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`places.sqlite`** — The primary Firefox database is `places.sqlite`, which contains history, bookmarks, and downloads together. _Why:_ One database yields three artifact classes for Firefox. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Firefox uses real `.sqlite` extension** — Unlike Chromium's extensionless `History`/`Cookies`, Firefox databases carry an explicit `.sqlite` extension. _Why:_ File-name recognition differs between engines. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`cookies.sqlite`** — Firefox cookies are stored in `cookies.sqlite`, a SQLite database. _Why:_ Cookie artifact location for Firefox. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`sessionstore-backups`** — Firefox session-restore data is in a `sessionstore-backups` directory within the profile. _Why:_ Firefox equivalent of Chromium's `Sessions` folder. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`prefs.js`** — Firefox preferences are stored in `prefs.js`, a JavaScript file holding browser preferences/settings. _Why:_ Firefox settings profiling target (analogue to Chromium `Preferences`). _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Cache is the Local exception** — Firefox cache lives under `%LOCALAPPDATA%` (Local), unlike the other Firefox artifacts which are under `%APPDATA%` (Roaming). _Why:_ Collection of the cache must target a different tree than the rest of the Firefox profile. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Cache profile name matches** — The Firefox cache folder is under a profile directory with the **same** `<xxxxxxxx>.default-release` name used in the Roaming tree, then a `cache2` subfolder. _Why:_ Lets an examiner locate the cache by reusing the profile identifier already found. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Why cache is Local (rationale)** — The instructor's stated assumption: cache was placed in LocalAppData so that, under roaming (Active Directory) profiles, the potentially large cache does not roam across the network with the user's profile. _Why:_ Plausible design rationale — treat as hypothesis, not confirmed fact, until verified. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Roaming profile concept** — A roaming profile follows a user across an Active Directory network so that logging into different computers reproduces the same settings/desktop. _Why:_ Background needed to understand the Local/Roaming split. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Legacy ("Old") Microsoft Edge & WebCacheV01.dat

- **Not present on modern Windows 11** — The pre-Chromium Edge is not installed on modern Windows 11, so its browser folder is absent. _Why:_ Sets expectation that the legacy Edge app itself won't be there. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`WebCacheV01.dat` persists anyway** — Despite legacy Edge's absence, the `WebCacheV01.dat` file still exists on modern Windows 11. _Why:_ A legacy-origin artifact continues to be actively written on current systems. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`WebCacheV01.dat` is an ESE database** — `WebCacheV01.dat` is an ESE (Extensible Storage Engine) database, not SQLite. _Why:_ Requires an ESE parser, a different toolchain than the SQLite artifacts. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Shared by legacy Edge and IE 11** — The same `WebCacheV01.dat` ESE database was used by the old Microsoft Edge and, before it, by Internet Explorer 11. _Why:_ One database format spans two legacy browsers. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Tracks local file access** — `WebCacheV01.dat` records local file access: parsing its history yields entries of the form `file:///<drive letter>:\<path>` for files that were opened locally. _Why:_ This is the standout evidentiary value of the ESE database on modern systems. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Legacy Edge also had cache/sessions/settings paths** — The cheat sheet lists cache, sessions, and settings/configuration locations for old Edge in addition to the history database. _Why:_ Completeness for the rare legacy-Edge case. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Internet Explorer — WebCacheV01.dat Containers & Cookie Storage

- **IE history is in WebCacheV01.dat** — Internet Explorer's history also resides in the `WebCacheV01.dat` ESE database. _Why:_ Same ESE parsing path as legacy Edge. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`History` container → history** — Within the ESE database, the History container holds browsing history. _Why:_ Tells the examiner which container maps to which artifact. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`Content` container → cache** — The Content container holds cached content. _Why:_ Cache retrieval from the ESE DB. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`Cookies` container → cookie metadata only** — The Cookies container holds only cookie **metadata**, not the cookies themselves. _Why:_ Prevents mistaking metadata for the actual cookie values. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **`IEDownload` container → downloads** — The IE download container holds download-related information. _Why:_ Download evidence location for IE. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Actual cookies on disk** — The real IE cookie files are stored at `%APPDATA%\Microsoft\Windows\Cookies`, or in some cases `%APPDATA%\Microsoft\Windows\Cookies\Low`. _Why:_ To recover cookie contents you must go to the filesystem, not the ESE metadata. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **IE session data location** — IE session-restore information is under `%LOCALAPPDATA%\Microsoft\Internet Explorer\Recovery`, in `.dat` files parseable by available tools. _Why:_ Recovers open-tab/session state for IE. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### NirSoft Tools

- **NirSoft freeware suite** — NirSoft publishes a broad set of free Windows utilities (password, programming, networking tools) including a dedicated "browser tools" category. _Why:_ A common free toolkit source for browser-artifact parsing. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **BrowsingHistoryView is the go-to parser** — The instructor's primary history parser is NirSoft's BrowsingHistoryView, which extracts history from all major browsers and merges it into a single unified view within seconds. _Why:_ One tool covers Chrome/Edge/Firefox/IE history at once. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Other NirSoft browser utilities** — NirSoft also offers cookie and cache viewers for Mozilla, Internet Explorer, Opera, and Safari, plus Flash-cookie viewers and Firefox download viewers. _Why:_ Covers browsers and artifact types beyond the big three. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Safari for Windows existed** — Safari was at one time available on Windows, which is why NirSoft ships a Windows Safari cache/cookie viewer. _Why:_ Explains why Safari artifacts may appear on a Windows host. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### BrowsingHistoryView Workflow & Options

- **Disk-image workflow** — For a disk image, the instructor mounts it with Arsenal Image Mounter, then points BrowsingHistoryView at the mounted user profile to pull that user's browser history. _Why:_ Standard mount-then-parse pipeline for dead-box browser forensics. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Default time window is 10 days** — On launch, BrowsingHistoryView's advanced-options window defaults to "load history items from the last 10 days." _Why:_ The default silently date-bounds results and can hide older activity. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Set to "any time"** — The recommended setting is "load history items from any time," so all available history is shown and date filtering is done afterward on the full dataset. _Why:_ Avoids missing evidence outside an arbitrary default window. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Explicit date range option** — BrowsingHistoryView can restrict output to a specific start/end date-time range. _Why:_ Scope results to an incident window when needed. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **URL whitelist/blacklist** — It accepts a comma-delimited list of whitelisted or blacklisted strings to include or exclude URLs. _Why:_ Focus or de-noise the output by domain/keyword. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **All browsers selected by default** — In the browser-selection list every supported browser is ticked by default, which the instructor keeps so nothing in use on the profile is missed. _Why:_ Ensures no browser's history is silently skipped. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Wide browser support incl. Pale Moon** — The tool supports far more than IE/Edge/Chrome/Firefox, including lesser-known browsers such as Pale Moon. _Why:_ Catches non-mainstream browsers a subject may have used. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **History-source options** — "Load history from" offers: the current running system (default), a specified profiles folder, or a specified single profile — e.g. `F:\Users\<profile>` on a mounted image. _Why:_ Directs the parse at a mounted image profile rather than the live host. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### BrowsingHistoryView Output Columns

- **Per-record fields** — For each history entry BrowsingHistoryView surfaces: URL, Title, Visit Time, Visit Count, Visited From, Type, Duration, Web Browser, User Profile, Browser Profile, URL Length, Typed Count, and the source History File. _Why:_ Defines the analytic fields available per visit. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Source-browser icon** — A left-column icon marks each row's source browser (Edge, Firefox, or Chrome). _Why:_ Immediate visual attribution of each URL to its browser. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **"User Profile" vs "Browser Profile"** — "User Profile" is the Windows account the data came from; "Browser Profile" is the in-browser profile (e.g. the Firefox `<xxxxxxxx>.default-release` folder) — two distinct columns. _Why:_ Distinguishes the OS account from the browser identity within it. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **"History File" column** — The History File column names the exact underlying artifact (e.g. the extensionless `History` SQLite DB) each row was pulled from. _Why:_ Traces every parsed row back to its source file for validation. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Firefox first-run privacy URL** — A Firefox privacy URL that appears in history is the page auto-shown on first launch after installation, not a deliberate visit. _Why:_ Avoids misreading an install-time page as user browsing. _[IWE ch10 · Additional Content / Web Browser Forensics]_

### Local File Access via file:/// URLs

- **Local file open recorded as file:///** — Double-clicking a local file (opening it in its default app, e.g. a `.txt` in Notepad) generates a `file:///C:/Users/<user>/Desktop/<file>` entry visible in BrowsingHistoryView after refresh (F5). _Why:_ File access is captured even with no browser involved. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **file:/// ≠ opened in a browser** — A `file:///` history entry does **not** mean the file was viewed inside a web browser; it records local file access tracked by the OS, even when the file opened in Notepad/another app. _Why:_ Critical to avoid the inference that the user browsed to the file. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Underlying store is WebCacheV01.dat** — These `file:///` local-access entries are tracked in the `WebCacheV01.dat` ESE database (the legacy-Edge/IE 11 store), still live on modern Windows 11. _Why:_ Ties the file:/// evidence back to a specific parseable artifact. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Applies to any file type** — Local-access tracking covers arbitrary file types — zip archives, Word documents, Excel spreadsheets, etc. — that the user interacted with. _Why:_ Broadens the evidentiary reach beyond text files. _[IWE ch10 · Additional Content / Web Browser Forensics]_
- **Threat-actor value** — `file:///` local-access entries can be highly valuable for tracking threat-actor (TA) behaviour on a system. _Why:_ Reveals which local files an intruder touched. _[IWE ch10 · Additional Content / Web Browser Forensics]_

## Chapter 10 · Windows Activity Timeline

### Feature Origin and Purpose

- **Windows Timeline (naming)** — The feature is officially "Windows 10 Timeline" but is commonly called the "Windows Activity Timeline." _Why:_ Reconciles the marketing name with the underlying activity-history artifact investigators reference. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Introduction version** — First shipped in Windows 10 version 1803. _Why:_ Absence of the artifact on a Win10 host may simply mean the OS predates 1803. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Introduction date** — Version 1803 was released in late April 2018. _Why:_ Anchors the earliest date activity-timeline evidence can exist. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Design purpose** — Built to aggregate a user's activities into one place so they could quickly resume interrupted work. _Why:_ Explains what user behaviour the artifact was designed to capture, and thus what it records. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **What it tracks** — Records recently run programs and recently accessed documents, images, videos, websites, and more. _Why:_ Broad execution- and file-access evidence, useful for reconstructing user activity. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Cross-device sync** — Activity was synchronized across all devices signed in with the same account. _Why:_ Evidence on one device may originate from user activity on another synced device. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **User access — keyboard** — The timeline UI is opened with Windows Key + Tab. _Why:_ Distinguishes the user-facing feature from the on-disk artifact. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **User access — taskbar** — The timeline UI is also opened via the Task View icon on the taskbar. _Why:_ Same UI, alternate trigger. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Windows 11 Support Caveat

- **Timeline UI removed in Win11** — The visible timeline feature was not carried forward into Windows 11. _Why:_ Investigators may wrongly assume the underlying artifact is also gone. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Conceptual successor** — The narrator characterizes the timeline as the conceptual predecessor ("grandfather") of Windows Recall. _Why:_ Contextualizes the artifact within Microsoft's activity-capture lineage. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Local collection persisted** — Despite the removed UI, local activity history continued to be collected in Windows 11 through version 22H2. _Why:_ The artifact remains forensically viable on Win11 up to 22H2. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Degradation at 23H2** — Testing shows that in 23H2 the ActivitiesCache.db database still exists but most of the useful information is no longer stored in it. _Why:_ Sets the practical upper OS boundary for expecting rich data. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **23H2 exception — clipboard** — On 23H2 the main remaining useful content is clipboard data. _Why:_ Even on a degraded version, clipboard artifacts may still be recoverable. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **23H2 clipboard precondition** — Clipboard data appears on 23H2 only when both "Clipboard history" and "Sync across your devices" are enabled. _Why:_ Absence of clipboard data does not exclude activity — it may just mean the settings were off. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Community underuse** — The artifact is frequently overlooked by forensic examiners due to misinformation that it ceased to exist. _Why:_ Flags an evidence source that is often missed. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Microsoft's Documented Behaviour (per MS support article)

- **Purpose statement** — Activity history tracks what the user does on the device, such as apps and services used, files opened, and websites browsed. _Why:_ Vendor confirmation of the recorded categories. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Local storage** — Activity history is stored locally on the device. _Why:_ The primary evidentiary copy is on the endpoint itself. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Cloud upload condition** — If signed in with a work or school account and permission is granted, Windows sends the activity history to Microsoft. _Why:_ Cloud-side copies may exist and may be obtainable via legal process for managed accounts. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Microsoft's use of the data** — Microsoft uses uploaded activity history to provide personalized experiences, e.g. ordering activities by duration of use and offering suggestions anticipating user needs. _Why:_ Explains why duration/focus fields are captured and populated. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Artifact Location and Format

- **Artifact filename** — Activity history is stored in a file named ActivitiesCache.db. _Why:_ The exact filename to search for / collect. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **File format** — ActivitiesCache.db is a SQLite database. _Why:_ Can be opened and queried with standard SQLite tooling. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Per-user scope** — The database is located within each user's profile (one per user). _Why:_ Each user account has its own activity record; collect all profiles. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Profile-relative path** — Path within the profile: AppData\Local\ConnectedDevicesPlatform. _Why:_ Exact directory to navigate to for collection. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Account-type subfolder** — Inside ConnectedDevicesPlatform there is a subdirectory whose name encodes the account type. _Why:_ You must descend one more level to reach the .db. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Local account prefix** — For local accounts the subfolder is prefixed "L." followed by the profile name (e.g. L.Jean-Luc). _Why:_ Identifies a local-account activity store and the owning user. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Online / Azure AD prefix** — For online accounts or Azure AD (now Entra ID), other prefixes appear; e.g. "AAD." followed not by a profile name but by a GUID associated with the identity. _Why:_ Distinguishes local vs cloud-identity stores and maps a GUID to an account. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Database Schema

- **Multiple tables** — The database contains several tables. _Why:_ Only a subset is forensically relevant; the rest are supporting. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Key tables** — The two most forensically interesting tables are Activity and Activity_PackageId. _Why:_ Focuses analysis on the tables carrying execution/file/timing evidence. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Activity table — fields** — The Activity table has numerous fields. _Why:_ Rich per-activity detail beyond just a name. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Activity table — timestamps** — Several Activity-table fields track timestamps. _Why:_ Multiple time anchors enable timeline reconstruction. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Activity_PackageId — contents** — The Activity_PackageId table holds records for applications, including paths to executable files, plus expiration times for each record. _Why:_ Maps activities to concrete executable paths. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Record retention** — Records are typically retained for 30 days. _Why:_ Bounds the evidentiary window for activity data. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Deleted-file evidence** — Records may reference executables or other files that are no longer present on disk. _Why:_ Provides proof of files/programs that once existed even after deletion. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Parsing Tool — WxTCmd

- **Manual option** — The database can be opened and browsed manually with any SQLite utility. _Why:_ A tool-independent verification path. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Dedicated parser** — Eric Zimmerman's tool WxTCmd parses this artifact. _Why:_ Purpose-built parser saves manual SQL work. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Two output files** — WxTCmd produces two output files: one for the Activity table and one for the Activity_PackageId table. _Why:_ Sets expectations for the parser's deliverables. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Primary output** — The Activity-table output file is the main file of interest. _Why:_ Directs the analyst to the richer of the two outputs. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Activity output contents** — The Activity output shows executables run interactively and the time they were executed. _Why:_ Interactive-execution evidence with timing. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **File paths captured** — The Activity output can include paths to some files, e.g. CSV files. _Why:_ Ties user activity to specific documents/paths. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Browser URLs captured** — URLs for Internet Explorer and legacy (pre-Chromium) Edge are tracked. _Why:_ Recovers browsing history for those legacy browsers from this artifact. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Flag -f** — WxTCmd uses -f to point to the file to process (consistent with other Zimmerman tools). _Why:_ Required input flag. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Flag --csv** — WxTCmd uses --csv to specify the output directory where the two result files are written. _Why:_ Required output flag; controls where results land. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Only two flags needed** — Running the parser requires effectively only -f and --csv. _Why:_ Minimal invocation; low operator error surface. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **No-argument help** — Running WxTCmd.exe with no options prints the available options. _Why:_ Discover usage without external docs. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Speed** — Parsing completes very quickly (less than one second in the demonstration). _Why:_ Cheap to run across many collected artifacts. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Timeline Explorer viewing** — Associating the CSV outputs with Eric Zimmerman's Timeline Explorer eases review. _Why:_ Recommended workflow to browse the output efficiently. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Mounting / Acquisition Gotchas

- **Write access required** — WxTCmd must write temporary files into the artifact's location, so it fails against a read-only mounted image. _Why:_ Explains parser failures and the need for a writable path. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Write-temporary overlay workaround** — In Arsenal Image Mounter, mount with "Disk device, write temporary" (not the default "Disk device, read only"); this creates a write overlay so changes are pretended, not written to the underlying image. _Why:_ Lets WxTCmd run directly against a mounted image while preserving the original. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Triage-copy alternative** — In practice the ActivitiesCache.db is usually pulled during a triage acquisition (e.g. with KAPE) among many artifacts, then WxTCmd is pointed at the collected copy on the analysis workstation. _Why:_ Avoids the mount/write-overlay dance entirely; standard workflow. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Activity Types and Timestamp Semantics

- **ExecuteOpen = execution** — An Activity Type of ExecuteOpen is associated with program execution. _Why:_ Identifies which rows are execution evidence. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **ExecuteOpen Start Time** — For an ExecuteOpen row, Start Time corresponds to the actual time the application was opened/launched. _Why:_ Provides a reliable program-launch timestamp. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **ExecuteOpen may lack End Time** — ExecuteOpen rows can have no End Time and therefore no Duration, because duration cannot be computed without both endpoints. _Why:_ Explains blank duration fields; don't over-interpret their absence. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **InFocus = active window** — An Activity Type of InFocus indicates the application had focus, i.e. its window was the active window on screen. _Why:_ Distinguishes "was launched" from "was actively being used." _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **InFocus has duration** — InFocus rows have both a Start Time and End Time and thus a computed Duration. _Why:_ Yields how long an app was actively in the foreground. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Expiration Time = +30 days** — The Expiration Time is exactly 30 days after the record's start, consistent with the ~30-day record lifespan. _Why:_ Corroborates retention and lets you back-calculate/validate timestamps. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Modification timestamps** — Records also carry Last Modified Time and Last Modified On Client time. _Why:_ Additional time anchors; "on client" distinguishes device-local modification. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Clipboard (CopyPaste) Activity

- **CopyPaste Activity Type** — A CopyPaste Activity Type may appear among the records. _Why:_ Signals recoverable clipboard evidence. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Clipboard capture precondition** — ActivitiesCache.db may store clipboard data only when both clipboard history and clipboard sync-across-devices are enabled. _Why:_ Same gating condition as the 23H2 clipboard exception; explains presence/absence. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Clipboard Start Time** — For clipboard records, Start Time records when the data was first copied to the clipboard. _Why:_ Timestamps the copy event. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Payload = source** — The Payload field shows the source of the clipboard data. _Why:_ Identifies where the copied content came from. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **ClipboardPayload = base64 content** — The Clipboard Payload field contains a base64-encoded string of the actual clipboard contents. _Why:_ The literal copied data can be recovered by base64-decoding this field. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

### Server OS Caveat

- **Executables not tracked on Server** — On Windows Server 2019 and Server 2022, executable files are not tracked by this artifact. _Why:_ Absence of execution evidence on a server is expected, not exculpatory. _[IWE ch10 · Additional Content / Windows Activity Timeline]_
- **Rationale (analogy to Prefetch)** — The narrator infers executables are untracked on Server for the same reason Windows Prefetch is disabled on servers: servers are not meant to be used interactively like desktop OSes. _Why:_ Explains the design intent behind the server limitation. _[IWE ch10 · Additional Content / Windows Activity Timeline]_

## Chapter 10 · Windows Search Index

### What the artifact is / scope

- **Windows Search Index** — records searches a user performs through the Windows Start Menu (Start-menu search box), and is a distinct artifact from those searches. _Why:_ places the artifact within user-activity reconstruction and disambiguates it from Explorer search. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Not WordWheelQuery** — the Start-Menu search artifact must not be confused with WordWheelQuery, a registry-based artifact that tracks queries typed into the Windows Explorer search box (top-right of an Explorer window). _Why:_ two different search UIs feed two different artifacts; conflating them misattributes evidence. _[IWE ch10 · Additional Content / Windows Search Index]_
- **WordWheelQuery is registry-based** — WordWheelQuery lives in the registry and covers the Explorer search box, whereas the Windows Search Index is a database covering Start-Menu search. _Why:_ distinguishes storage medium and source UI. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Windows Search = desktop search platform** — per Microsoft documentation, Windows Search is a desktop search platform offering instant search across most common file and data types. _Why:_ frames what the indexer is designed to do. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Windows Search Indexer is a service** — the indexer runs as a service whose purpose is to accelerate file searches. _Why:_ identifies the responsible OS component. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Indexer stores rich data** — the indexer holds large volumes of metadata, records of user interactions, and even partial file contents. _Why:_ establishes the breadth of recoverable evidence. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Forensic value** — because it captures metadata, user interactions, and partial content, the index is valuable for reconstructing user activity and can reveal things not evident from other artifacts. _Why:_ justifies parsing it in investigations. _[IWE ch10 · Additional Content / Windows Search Index]_

### Enablement / where it runs

- **Enabled on desktop (client) Windows by default** — the search indexer is on by default in non-server (desktop/client) Windows editions. _Why:_ predicts when the artifact should be present. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Disabled on Windows Server by default** — the search indexer is not enabled by default on Windows Server. _Why:_ explains absence of the artifact on servers. _[IWE ch10 · Additional Content / Windows Search Index]_

### Default indexed locations

- **`C:\Users\*` indexed by default** — on client Windows the entire Users tree is indexed by default. _Why:_ tells the examiner which user data is automatically captured. _[IWE ch10 · Additional Content / Windows Search Index]_
- **AppData excluded** — the default indexing of `C:\Users` excludes each user's AppData directory (everything under Users except AppData). _Why:_ bounds what is and isn't captured; explains gaps. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Global Start-Menu programs indexed** — `C:\ProgramData\Microsoft\Windows\Start Menu\Programs` is indexed by default. _Why:_ captures the all-users Start Menu contents. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Global vs user-specific Start Menu** — the indexed Start-Menu path is the all-users (global) Start Menu, not the per-user Start Menu. _Why:_ prevents over-attributing entries to a single user. _[IWE ch10 · Additional Content / Windows Search Index]_
- **User-pinned Start-Menu items not indexed** — items a user pins to their own Start Menu are not indexed, because that per-user path resides under AppData, which is excluded from the Users index. _Why:_ explains why user-pinned entries are absent. _[IWE ch10 · Additional Content / Windows Search Index]_

### Metadata captured per file

- **File paths stored** — the index stores file paths. _Why:_ locates files even after deletion. _[IWE ch10 · Additional Content / Windows Search Index]_
- **File owners stored** — the index records file owner information (when available). _Why:_ attributes files to accounts. _[IWE ch10 · Additional Content / Windows Search Index]_
- **MACB-style timestamps stored** — modification, access, and creation/birth timestamps are all stored per indexed file. _Why:_ supplies an independent timestamp set. _[IWE ch10 · Additional Content / Windows Search Index]_
- **File size stored** — the index/report includes a file size for files (not for directory rows). _Why:_ corroborates file identity and change. _[IWE ch10 · Additional Content / Windows Search Index]_

### Investigative applications

- **Staging/malware in user paths gets indexed** — because threat actors often stage files or drop malware in user-specific locations, and those locations fall under the indexed `C:\Users` tree, the malicious files' metadata is automatically captured. _Why:_ the artifact records adversary-placed files. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Timestomping detection via extra timestamp set** — the index's independently-stored timestamps provide an additional set to compare against other timestamp sources to detect potential timestomping. _Why:_ cross-source timestamp comparison exposes tampering. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Startup folder (ASEP) tracked** — the Start Menu's Startup folder, a commonly abused Auto-start Extensibility Point (ASEP), is indexed as part of the global Start Menu. _Why:_ surfaces a common persistence location. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Startup coverage is global-only** — the tracked Startup folder is the global Start Menu's, not the user-specific Startup folder. _Why:_ bounds which persistence entries appear. _[IWE ch10 · Additional Content / Windows Search Index]_

### Web / browser and per-user activity capture

- **Edge URLs may be indexed** — URLs visited in Microsoft Edge (outside Private/InPrivate browsing) may be indexed, alongside other program-specific user activity. _Why:_ provides a secondary browser-history source. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Private browsing excluded** — Edge activity in Private Browsing Mode is not indexed. _Why:_ explains gaps and limits inferences of "no activity". _[IWE ch10 · Additional Content / Windows Search Index]_
- **Web indexing is user-configurable** — whether program/web activity is indexed can be changed by the user. _Why:_ caution against assuming a fixed configuration. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Per-user file-open tracking** — the indexer records per-user file opens for certain file types, including Office documents and text files. _Why:_ evidences user access to specific documents. _[IWE ch10 · Additional Content / Windows Search Index]_
- **File-open records survive rename/delete** — per-user file-open information can persist even after the user renames or deletes the file. _Why:_ recovers evidence of access to now-gone files. _[IWE ch10 · Additional Content / Windows Search Index]_

### Auto Summary (partial content caching)

- **Auto Summary caches partial file contents** — the indexer caches portions of file content via a feature called Auto Summary. _Why:_ can recover file content itself, not just metadata. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Content recoverable after move/delete** — because of Auto Summary, parts of a file's content may remain recoverable in the index even after the file is moved or deleted. _Why:_ content survives destruction of the original. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Auto Summary content is variable in value** — cached Auto Summary content is often noise from system-related files but can be highly valuable depending on the investigation. _Why:_ sets realistic expectations for the field. _[IWE ch10 · Additional Content / Windows Search Index]_

### Database format change across Windows versions

- **ESE format on Windows 10 and earlier** — on Windows 10 and prior, the Windows Search Index database uses the Extensible Storage Engine (ESE) format. _Why:_ dictates the parser/tooling for legacy systems. _[IWE ch10 · Additional Content / Windows Search Index]_
- **SQLite format on Windows 11** — starting in Windows 11 the database format changed from ESE to SQLite. _Why:_ different tooling and schema apply on modern systems. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Schema changed with format** — the ESE-to-SQLite switch also changed the database schema, requiring substantial research to understand the new structure. _Why:_ warns that Win10 knowledge does not transfer directly to Win11. _[IWE ch10 · Additional Content / Windows Search Index]_

### Database file paths and names

- **Win Vista–Win10 path** — for Windows Vista through Windows 10 the database is at `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`. _Why:_ acquisition/target location on legacy systems. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Single `.edb` file on Win10** — the legacy database is the single file `Windows.edb` (ESE). _Why:_ one file to collect on Win10. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Three databases on Win11, same directory** — Windows 11 uses three databases in the same `...\Applications\Windows\` path: `Windows.db`, `Windows-gather.db`, and `Windows-usn.db`. _Why:_ all relevant files must be collected together. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`.db` extension on Win11** — Win11 databases use the `.db` extension rather than `.edb`, reflecting the move to SQLite. _Why:_ extension signals which format/parser to use. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`Windows-usn.db` less relevant** — of the three Win11 databases, `Windows-usn.db` is the least forensically relevant and is generally not used for this analysis. _Why:_ prioritizes the two useful databases. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Two relevant Win11 databases** — `Windows.db` and `Windows-gather.db` are the forensically relevant Win11 databases. _Why:_ focuses collection and parsing. _[IWE ch10 · Additional Content / Windows Search Index]_

### Key tables and their locations

- **Three key tables** — analysis focuses on three tables: `SystemIndex_Gthr` ("gather"), `SystemIndex_GthrPth` ("gather path"), and `SystemIndex_PropertyStore`. _Why:_ names the core schema objects to query. _[IWE ch10 · Additional Content / Windows Search Index]_
- **All three tables in `Windows.edb` on Win10** — on Windows 10 systems all three tables reside in the single `Windows.edb`. _Why:_ one-file querying on legacy. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Gather tables in `Windows-gather.db` on Win11** — on Win11 the two "Gthr"/gather tables (`SystemIndex_Gthr`, `SystemIndex_GthrPth`) live in `Windows-gather.db`. _Why:_ tells the examiner which Win11 file holds which table. _[IWE ch10 · Additional Content / Windows Search Index]_
- **PropertyStore in `Windows.db` on Win11, renamed** — on Win11 the PropertyStore table lives in `Windows.db` under the slightly different name `SystemIndex_1_PropertyStore`. _Why:_ the renamed table must be found in the correct Win11 file. _[IWE ch10 · Additional Content / Windows Search Index]_
- **PropertyStore Metadata table** — `Windows.db` also contains a `SystemIndex_1_PropertyStore_Metadata` table. _Why:_ needed to resolve property names. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Property ID → name mapping** — property IDs in the PropertyStore table map to their human-readable names via the PropertyStore Metadata table. _Why:_ decode step required to interpret PropertyStore columns. _[IWE ch10 · Additional Content / Windows Search Index]_

### Acquisition with KAPE

- **KAPE can acquire the databases** — KAPE (used earlier in the IWE course) can collect the Windows Search databases. _Why:_ standard collection tooling. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Target name `WindowsIndexSearch`** — KAPE has a target named `WindowsIndexSearch` that collects all the relevant search-index databases automatically. _Why:_ the exact target to select. _[IWE ch10 · Additional Content / Windows Search Index]_
- **GKAPE is the GUI front-end** — GKAPE is the graphical front-end to KAPE and can drive the same collection. _Why:_ option for users newer to KAPE. _[IWE ch10 · Additional Content / Windows Search Index]_
- **KAPE command flags built** — the KAPE collection command uses `--tsource` (source), `--tdest` (destination), `--tflush` (flush destination), and `--target` (target name). _Why:_ enables running collection directly from the command line. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`--tflush` purges destination first** — the Flush option (checked by default in GKAPE) removes/purges the contents of the target-destination path before acquisition, so it must be used carefully to avoid deleting wanted data. _Why:_ operational safety warning. _[IWE ch10 · Additional Content / Windows Search Index]_
- **VSC processing optional** — Volume Shadow Copies need not be processed for this collection (though it is possible). _Why:_ VSCs could yield historical index copies if desired. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Container = none for raw files** — set KAPE Container to "none" to obtain the raw files on the file system rather than a container. _Why:_ SIDR consumes the raw recreated path. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Admin prompt for CLI KAPE** — running the KAPE command directly requires an administrative command prompt. _Why:_ elevated rights needed to read the databases. _[IWE ch10 · Additional Content / Windows Search Index]_
- **KAPE recreates source path** — KAPE output preserves/recreates the original directory structure (`...\ProgramData\Microsoft\Search\Data\Applications\Windows\...`) under the destination folder. _Why:_ SIDR expects to scan this recreated tree. _[IWE ch10 · Additional Content / Windows Search Index]_

### Parsing tools

- **ESEDatabaseView for Win10** — NirSoft's ESEDatabaseView can open and browse the Win10 `Windows.edb` ESE database. _Why:_ manual inspection option for ESE. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Any SQLite browser for Win11** — the Win11 `.db` files can be opened with any SQLite browser. _Why:_ manual inspection option for SQLite. _[IWE ch10 · Additional Content / Windows Search Index]_
- **SIDR is purpose-built** — Search Index DB Reporter (SIDR, pronounced "cider") is a tool built specifically to parse this artifact. _Why:_ the recommended dedicated parser. _[IWE ch10 · Additional Content / Windows Search Index]_
- **SIDR handles both formats** — SIDR parses both ESE and SQLite formats, making it usable across Windows versions. _Why:_ one tool for Win10 and Win11. _[IWE ch10 · Additional Content / Windows Search Index]_
- **SIDR parses at scale** — SIDR parses these databases efficiently and at scale, reducing time and effort to extract the data. _Why:_ practical for large collections. _[IWE ch10 · Additional Content / Windows Search Index]_
- **SIDR surfaces user activity** — SIDR can identify user activities such as access to specific files/documents and interactions with web content, including across multiple machines. _Why:_ cross-host activity correlation. _[IWE ch10 · Additional Content / Windows Search Index]_

### Running SIDR

- **Usage form** — SIDR is invoked as `sidr.exe [options] <input>`, where input is the path to the input directory. _Why:_ correct command syntax. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Input is the KAPE output dir** — SIDR's input is the folder produced by the KAPE `WindowsIndexSearch` target (e.g., the "demo" collection folder). _Why:_ chains collection to parsing. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Recursive auto-detection** — SIDR recursively scans the input path and automatically finds the correct database, whether the Windows 10 (ESE) or Windows 11 (SQLite) version. _Why:_ no need to point at a specific file or specify OS version. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`-f` output format** — the `-f` option sets output report format; default is JSON. _Why:_ controls output type. _[IWE ch10 · Additional Content / Windows Search Index]_
- **CSV for Timeline Explorer** — `-f csv` produces CSV so the output can be opened in Timeline Explorer, an easy way to review the data. _Why:_ recommended review workflow. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`-r` report type / destination** — the `-r` option specifies report type; by default output is written to a file, but this option can direct results to on-screen printing instead. _Why:_ file-vs-screen output control. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`-o` output directory** — the `-o` option sets the output directory; without it, files are written to the current directory. _Why:_ controls where reports land. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Example invocation** — a typical run is `sidr.exe -f csv -o <output-dir> <input-dir>`. _Why:_ concrete working command. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Parsing is near-instant** — SIDR completes parsing of the collected databases almost immediately. _Why:_ sets performance expectation. _[IWE ch10 · Additional Content / Windows Search Index]_

### SIDR output reports

- **Three reports generated** — SIDR produces three reports: a File Report, an Internet History Report, and an Activity History Report. _Why:_ maps outputs to evidence categories. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Activity History often 0 bytes on Win11** — in testing, the Activity History Report is generally zero bytes on Windows 11 systems, with an open GitHub issue for the problem. _Why:_ known limitation; absence on Win11 is not evidentiary. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Activity History populated on Win10** — running SIDR against a Windows 10 system does populate the Activity History Report. _Why:_ the report is usable on legacy systems. _[IWE ch10 · Additional Content / Windows Search Index]_

### File Report columns

- **`System_ItemPathDisplay`** — the full path of the file described by that row. _Why:_ identifies the indexed file. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Three timestamp columns** — `System_DateModified`, `System_DateCreated`, and `System_DateAccessed` correspond to the M (modified), B (birth/created), and A (accessed) timestamps. _Why:_ the independent MACB-style set for comparison. _[IWE ch10 · Additional Content / Windows Search Index]_
- **File size column** — the report includes file size; directory rows have no size reported. _Why:_ size present only for actual files. _[IWE ch10 · Additional Content / Windows Search Index]_
- **File owner column** — a file owner column is populated when the information is available (e.g., a username such as an account owner). _Why:_ attributes files to accounts. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Auto Summary column** — an Auto Summary column may hold cached partial file contents. _Why:_ where recovered content appears. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Gather time column** — a gather-time column records when the item was indexed. _Why:_ dates the indexing event itself. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Item type column** — an item-type column shows either `directory` or a file extension (e.g., `.png`). _Why:_ distinguishes folders from files and identifies file type. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Directory-then-files pattern** — for an indexed folder, the first row is the directory itself and subsequent rows are the individual files within it. _Why:_ explains report row grouping. _[IWE ch10 · Additional Content / Windows Search Index]_

### Internet History Report columns

- **Derived from Microsoft Edge** — the Internet History Report is built from Microsoft Edge browser activity captured in the index. _Why:_ secondary browser-history source. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_ItemUrl`** — an item URL field, described as not extremely helpful on its own. _Why:_ lower-value field. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_Link_TargetUrl`** — a link-target URL field. _Why:_ records the URL target. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_ItemDate` and `System_DateCreated`** — date fields of higher interest for the browsing entry. _Why:_ times the web activity. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_Search_GatherTime`** — the indexing (gather) time for the web entry. _Why:_ dates when the URL was indexed. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_Title`** — the title of the visited page. _Why:_ human-readable page identification. _[IWE ch10 · Additional Content / Windows Search Index]_

### Activity History Report columns

- **`System_ItemNameDisplay`** — an item name-display field. _Why:_ names the activity item. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_ItemUrl`** — an item URL field, noted as not extremely helpful. _Why:_ lower-value field. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_ActivityHistory_StartTime` / `_EndTime`** — start and end times of the tracked activity. _Why:_ bounds when an app was in use. _[IWE ch10 · Additional Content / Windows Search Index]_
- **`System_Activity_AppDisplayName`** — the display name of the application associated with the activity. _Why:_ identifies which app was used; among the most important fields here. _[IWE ch10 · Additional Content / Windows Search Index]_
- **Most important Activity fields** — the start time, end time, and app display name are the key fields in the Activity History Report. _Why:_ prioritizes review. _[IWE ch10 · Additional Content / Windows Search Index]_

### Provenance / sourcing note

- **AON Cyber Solutions write-up** — much of the lesson's content is informed by an AON Cyber Solutions article on this topic (plus independent testing). _Why:_ points to a primary source to cite instead of the video. _[IWE ch10 · Additional Content / Windows Search Index]_
