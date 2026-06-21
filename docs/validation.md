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
