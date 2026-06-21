# Validation

Doer-Checker evidence: where a `forensicnomicon` table is validated against
real-world data and an independent oracle, rather than only synthetic fixtures.

## Known-good Windows service-binary catalog — DC01 masquerade isolation

**Module:** [`forensicnomicon::services`](https://docs.rs/forensicnomicon/latest/forensicnomicon/services/) ·
`KNOWN_WINDOWS_SERVICE_BINARIES` / `is_known_service_binary`

**Claim under test.** The catalog of legitimate standalone-OwnProcess Windows
service binaries is the baseline a System32 service-masquerade detector
(MITRE [T1036.005](https://attack.mitre.org/techniques/T1036/005/) /
[T1543.003](https://attack.mitre.org/techniques/T1543/003/)) subtracts known-good
binaries against. To be useful it must cover the *legitimate* System32-root
service images on a real host while leaving an actual implant uncovered.

**Tier-1 ground truth (real-world data).** The
[DFIRMadness "Stolen Szechuan Sauce" Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/)
DC01 `SYSTEM` registry hive — a genuine, third-party-authored intrusion image
whose answer key documents `coreupdater.exe` as the attacker-installed service
implant (`C:\Windows\System32\coreupdater.exe`, registered as an auto-start
Win32 own-process service). This is not a fixture we constructed.

**Method (`tests/services_dc01_isolation.rs`, env-gated).** Parse the real hive
with `winreg-core` (a test-only dev-dependency; not in the published graph),
resolve the current control set via `Select\Current`, enumerate all services
under `ControlSet00N\Services`, and reduce to the **gate set**: every service of
type `0x10` (`SERVICE_WIN32_OWN_PROCESS`) with start `0`/`1`/`2`
(boot/system/automatic) whose `ImagePath` is a *bare* `<name>.exe` directly in
the `System32` root (no subdirectory, no driver `.sys`, no svchost `ServiceDll`).

**Result.** The hive holds **453 services**; 30 are type-`0x10`. The gate set is
exactly **7** bare-System32-exe auto-start own-process services:

| Service key | Image basename | In catalog? |
|---|---|---|
| `Dfs` | `dfssvc.exe` | ✅ |
| `DFSR` | `dfsrs.exe` | ✅ |
| `DNS` | `dns.exe` | ✅ |
| `IsmServ` | `ismserv.exe` | ✅ |
| `MSDTC` | `msdtc.exe` | ✅ |
| `sppsvc` | `sppsvc.exe` | ✅ |
| `coreupdater` | `coreupdater.exe` | ❌ (the implant) |

The test asserts that `coreupdater.exe` is the **lone** member of the gate set
for which `is_known_service_binary` returns `false` — i.e. all six legitimate
DC service binaries are catalogued and the masquerade is isolated on real data.

**Scope / honesty.** The catalog is explicitly **NON-EXHAUSTIVE** and gates a
*lead*, not a verdict: presence means the *name* is a documented legitimate
Windows service image (a masquerade reuses a legit name — corroborate path,
code-signature/hash, and process ancestry); absence means "investigate". This
real-hive test proves isolation on one authentic intrusion image; it does not
claim the catalog is complete across every Windows version, edition, or role.

**Reproduce.** The hive is a large gitignored corpus owned by `issen`
(see issen `docs/corpus-catalog.md` §A3). Point the test at it:

```bash
ISSEN_DC01_SYSTEM_HIVE=/path/to/szechuan-sauce-hives/SYSTEM \
  cargo test --test services_dc01_isolation
```

The test skips loud (prints `SKIP:` and passes) when the corpus is absent.

## Known-good svchost ServiceDll catalog — DC01 baseline completeness

**Module:** [`forensicnomicon::services`](https://docs.rs/forensicnomicon/latest/forensicnomicon/services/) ·
`KNOWN_WINDOWS_SERVICE_DLLS` / `is_known_service_dll`

**Claim under test.** The catalog of legitimate svchost-hosted `ServiceDll`s is
the baseline a ServiceDll-masquerade detector subtracts known-good DLLs against.
A malicious `ServiceDll` — a planted `.dll` registered as the code a
legitimate-looking, `svchost.exe`-hosted service loads (`Parameters\ServiceDll`)
— is the #1 svchost implant vector (MITRE
[T1543.003](https://attack.mitre.org/techniques/T1543/003/) /
[T1036.005](https://attack.mitre.org/techniques/T1036/005/)). To gate that lead
without flooding the analyst with false positives, the baseline must recognise
the *legitimate* ServiceDlls actually loaded on a real host.

**Tier — honest note.** This is **Tier 2 (real-corpus baseline completeness)**,
not a real-masquerade isolation proof. The DFIRMadness DC01 corpus contains the
`coreupdater.exe` implant, but that implant is a standalone **OwnProcess** service
(covered by the exe catalog above) — the hive carries **no malicious
`ServiceDll`**. So unlike the exe catalog, there is no real implant to isolate
here. The real-data claim is narrower and stated plainly: the catalog is
*complete* over the genuine set of ServiceDlls the DC actually loads. The
masquerade case (a planted `evil.dll` / a ServiceDll under `\Temp\`) is exercised
by committed synthetic unit tests (`tests/service_dlls_catalog.rs` and the
in-module `tests`).

**Method (`tests/service_dlls_dc01_baseline.rs`, env-gated).** Parse the same
real DC01 `SYSTEM` hive with `winreg-core` (test-only dev-dependency; not in the
published graph), resolve the current control set via `Select\Current`, and for
every service read `Parameters\ServiceDll`, reducing each raw value (which may be
a `REG_EXPAND_SZ` like `%SystemRoot%\System32\dnsrslvr.dll`) to its lowercase
`.dll` basename.

**Result.** The hive yields **117 ServiceDll rows → 106 unique DLL basenames**
(several DLLs host multiple services, e.g. `rpcss.dll` → `DcomLaunch` + `RpcSs`,
`icsvc.dll` → 7 Hyper-V integration services, `wdi.dll` → `WdiServiceHost` +
`WdiSystemHost`, `mmcss.dll` → `MMCSS` + `THREADORDER`). The test asserts every
one of the 106 basenames resolves `is_known_service_dll == true` — zero
real-corpus unknowns. (During development the real-data test caught one genuine
catalog gap, `w32time.dll` / W32Time, that the synthetic tests had missed — the
Doer-Checker payoff; it is now catalogued.)

**Scope / honesty.** The catalog is explicitly **NON-EXHAUSTIVE** and gates a
*lead*, not a verdict: presence means the *name* is a documented legitimate
ServiceDll (a masquerade reuses a legit name and/or an unexpected path —
corroborate that the DLL resolves under `System32`, plus code-signature/hash and
the hosting svchost group); absence means "investigate". Completeness is proven
over one authentic DC image, not across every Windows version, edition, or role.

**Reproduce.**

```bash
ISSEN_DC01_SYSTEM_HIVE=/path/to/szechuan-sauce-hives/SYSTEM \
  cargo test --test service_dlls_dc01_baseline
```

The test skips loud (prints `SKIP:` and passes) when the corpus is absent.

## LOLDrivers BYOVD denylist — DC01 driver-set validation

**Module:** [`forensicnomicon::drivers`](https://docs.rs/forensicnomicon/latest/forensicnomicon/drivers/) ·
`KNOWN_VULNERABLE_DRIVERS` / `is_known_vulnerable_driver`

**Claim under test.** The driver denylist (the **inverse** of the two service
allowlists above) flags driver `.sys` basenames that the
[LOLDrivers](https://www.loldrivers.io/) project tracks as known-vulnerable or
known-malicious — the Bring Your Own Vulnerable Driver vector (MITRE
[T1543.003](https://attack.mitre.org/techniques/T1543/003/) for the service
registration, [T1068](https://attack.mitre.org/techniques/T1068/) for the kernel
exploit). For drivers a *denylist* is the correct shape: a Windows host loads
hundreds of legitimate third-party drivers (AV/EDR, GPU, VPN, storage), so an
allowlist would false-flag essentially every one. To be useful the denylist must
not false-flag a real host's legitimate drivers.

**Source (independent third party).** The denylist is the de-duplicated set of
`.sys` basenames from the LOLDrivers dataset
([`drivers.json` API](https://www.loldrivers.io/api/drivers.json)), snapshot
`magicsword-io/LOLDrivers` `drivers/` at commit
`c7d28ccd6372035c3469bb7ef8243b3a35f17752` (2026-06-19): 653 entries (115
`malicious`, 538 `vulnerable driver`) reduced to **646** distinct real basenames.
Hash-only placeholder "names" (entries whose stored filename is itself a hash —
useless as a *name* lead) are excluded; **names only** keep this zero-dep
KNOWLEDGE leaf lean (no hash dataset embedded).

**Tier — honest note.** This is **Tier 2**: the denylist is sourced from the
authoritative LOLDrivers dataset (independent third party) and validated against
a real corpus, but that corpus contains **no BYOVD** — the DFIRMadness DC01
implant is a user-mode OwnProcess service (`coreupdater.exe`, covered by the exe
catalog), so this is a true-negative-style confirmation plus committed synthetic
positives, not a real-BYOVD-isolation proof.

**Method (`tests/drivers_dc01_clean.rs`, env-gated).** Parse the same real DC01
`SYSTEM` hive with `winreg-core`, resolve the current control set via
`Select\Current`, and collect every driver service's image basename — `Type`
`0x01` (`SERVICE_KERNEL_DRIVER`) or `0x02` (`SERVICE_FILE_SYSTEM_DRIVER`) — then
run each through `is_known_vulnerable_driver`.

**Result — and the name-matching limitation it exposes.** The DC carries **250+
driver services**. Name-only matching hits **exactly three**:

| Image basename | Genuine identity on this host | In LOLDrivers? |
|---|---|---|
| `afd.sys` | WinSock Ancillary Function Driver (Microsoft) | ✅ (also a tracked vulnerable sample) |
| `monitor.sys` | Monitor Class Function Driver (Microsoft) | ✅ (also a tracked vulnerable sample) |
| `usbxhci.sys` | USB 3.0 xHCI controller (Microsoft) | ✅ (also a tracked malicious sample) |

All three are genuine, Microsoft-shipped OS drivers on this clean DC; the hits
are **false positives of name-matching**, not BYOVD. This is the empirical
demonstration of the module-doc caveat — a name match is a *lead* a legitimate
namesake can trip (and a renamed malicious sample can evade); **hash-matching**
against the LOLDrivers Authentihash/SHA256 set is the precise form (a future
enhancement, deliberately out of scope to keep the crate lean). The test asserts
this *exact* collision set, so any **new, unexpected** match — a real BYOVD whose
name is not one of these three legit OS drivers — still fails loudly.

**Synthetic positives/negatives (`tests/drivers_catalog.rs`, committed).** Real
LOLDrivers names flagged — `rtcore64.sys` (RTCore64, the MSI Afterburner driver
abused across many BYOVD campaigns) and `dbutil_2_3.sys` (Dell firmware-update
driver, CVE-2021-21551); ordinary Windows drivers not flagged — `ntfs.sys`,
`tcpip.sys`; plus case-insensitivity and optional-`.sys` mechanics.

**Scope / honesty.** **DENYLIST** (presence is the lead, the inverse of the
service allowlists), **NON-EXHAUSTIVE** (LOLDrivers grows daily; this is a
point-in-time snapshot — absence does NOT mean safe), and **names-only**
(a lead, not a verdict — corroborate with the on-disk hash, Authenticode
signature, and load path).

**Reproduce.**

```bash
ISSEN_DC01_SYSTEM_HIVE=/path/to/szechuan-sauce-hives/SYSTEM \
  cargo test --test drivers_dc01_clean
```

The test skips loud (prints `SKIP:` and passes) when the corpus is absent.
