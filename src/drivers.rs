//! Known-vulnerable / known-malicious **driver denylist** (Bring Your Own
//! Vulnerable Driver — BYOVD) sourced from the [LOLDrivers] project.
//!
//! This is the third service-masquerade vector catalogued in this crate, and the
//! **inverse** of the two service allowlists in [`services`](crate::services):
//!
//! - [`KNOWN_WINDOWS_SERVICE_BINARIES`](crate::services::KNOWN_WINDOWS_SERVICE_BINARIES)
//!   — an *allowlist* of legitimate standalone OwnProcess service `.exe`s; a
//!   System32 service image NOT on it is a lead.
//! - [`KNOWN_WINDOWS_SERVICE_DLLS`](crate::services::KNOWN_WINDOWS_SERVICE_DLLS)
//!   — an *allowlist* of legitimate svchost-hosted `ServiceDll`s; a `ServiceDll`
//!   NOT on it is a lead.
//! - [`KNOWN_VULNERABLE_DRIVERS`] (this module) — a **DENYLIST** of driver
//!   `.sys` basenames; a driver image that IS on it is a lead.
//!
//! ## Why a denylist (not an allowlist) for drivers
//!
//! The allowlist shape works for *services* because the legitimate set is small
//! and enumerable (a few dozen OwnProcess exes, ~100 svchost ServiceDlls). It is
//! the **wrong** shape for drivers: a Windows host loads hundreds of perfectly
//! legitimate third-party kernel drivers — AV/EDR, GPU, VPN, storage, virtual
//! audio, peripheral, and platform-vendor drivers — none of which ship with
//! Windows. An allowlist of "legit drivers" would false-flag essentially every
//! third-party driver on every real machine. The actionable knowledge is instead
//! the *bounded, curated set of drivers known to be vulnerable or malicious* —
//! which is exactly what the LOLDrivers project maintains.
//!
//! ## BYOVD (Bring Your Own Vulnerable Driver)
//!
//! Adversaries install a legitimately-signed but vulnerable kernel driver, then
//! exploit it to gain kernel-mode code execution — disabling EDR, terminating
//! protected processes, or tampering with kernel structures — bypassing Driver
//! Signature Enforcement because the driver is genuinely signed (MITRE ATT&CK
//! [T1543.003 — Create or Modify System Process: Windows Service] for the service
//! registration, and [T1068 — Exploitation for Privilege Escalation] for the
//! kernel exploit). Some entries are outright *malicious* rootkit drivers rather
//! than abused-legitimate ones; LOLDrivers tracks both.
//!
//! ## DENYLIST semantics — presence is the lead
//!
//! Unlike the service allowlists (where *absence* is the lead), here **presence**
//! is the indicator: a loaded/registered driver whose `.sys` basename is in
//! [`KNOWN_VULNERABLE_DRIVERS`] warrants investigation.
//!
//! ## Name-matching is a LEAD, not a verdict — hash-matching is the precise form
//!
//! This denylist matches on **basename only**. That is a deliberately coarse
//! lead: a vulnerable driver can be trivially **renamed** on disk (the kernel
//! does not care what the file is called), so a name match can miss a renamed
//! sample, and — conversely — a *benign, unrelated* file could share a name with
//! a denylisted one. Note in particular that several LOLDrivers basenames
//! collide with the names of legitimate, Microsoft-shipped OS drivers: on a
//! clean domain controller (the DFIRMadness DC01 corpus) the name-only denylist
//! hits exactly `afd.sys` (Winsock Ancillary Function Driver), `monitor.sys`
//! (Monitor Class Function Driver), and `usbxhci.sys` (USB 3.0 xHCI controller)
//! — each a genuine OS driver whose name LOLDrivers also tracks as a
//! vulnerable/malicious sample. A name hit on such an entry is precisely a *lead
//! to corroborate*, not a verdict. The precise form of BYOVD detection is **hash-matching** against
//! the LOLDrivers Authentihash / SHA256 set (a renamed sample still hashes the
//! same, and a benign namesake does not). Embedding the full hash dataset would
//! bloat this zero-dep KNOWLEDGE leaf by megabytes, so it is deliberately **out
//! of scope here** and flagged as a future enhancement; this module ships the
//! lean names-only lead gate. Corroborate a name hit with the on-disk hash, the
//! Authenticode signature, the load path, and the registering service before
//! concluding.
//!
//! ## NON-EXHAUSTIVE
//!
//! LOLDrivers grows continuously (a daily community feed). This embedded snapshot
//! is a point-in-time copy — see the source/date below — and the set varies as
//! new vulnerable drivers are catalogued. Absence from the list does NOT mean a
//! driver is safe; it means "not in this snapshot of the known-bad set". The
//! entries are the de-duplicated `.sys` basenames from the dataset's `Tags`,
//! `KnownVulnerableSamples[].Filename`, and `KnownVulnerableSamples[].OriginalFilename`
//! fields; hash-only placeholder filenames (entries whose stored "name" is itself
//! a hash, useless as a *name* lead) are excluded.
//!
//! # Sources
//!
//! - [LOLDrivers] — "Living Off The Land Drivers", the authoritative BYOVD /
//!   malicious-driver dataset (magicsword-io):
//!   <https://www.loldrivers.io/> · dataset API:
//!   <https://www.loldrivers.io/api/drivers.json>
//! - Dataset snapshot: `magicsword-io/LOLDrivers` `drivers/` at commit
//!   `c7d28ccd6372035c3469bb7ef8243b3a35f17752` (2026-06-19); the
//!   `drivers.json` API export carried 653 entries (115 `malicious`,
//!   538 `vulnerable driver`), de-duplicated to the basenames below.
//! - GentleKiller / Gentlemen RaaS EDR-killer suite: 10 driver drop-names added
//!   2026-06-24 from ESET's analysis (8 GentleKiller variants + bundled HexKiller /
//!   ThrottleBlood / HavocKiller); not yet in the LOLDrivers snapshot above:
//!   <https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/>
//! - MITRE ATT&CK T1543.003 / T1068:
//!   <https://attack.mitre.org/techniques/T1543/003/> ·
//!   <https://attack.mitre.org/techniques/T1068/>
//! - Microsoft — "Microsoft recommended driver block rules" (the OS-side
//!   counterpart, HVCI/WDAC blocklist):
//!   <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>
//!
//! [LOLDrivers]: https://www.loldrivers.io/
//! [T1543.003 — Create or Modify System Process: Windows Service]: https://attack.mitre.org/techniques/T1543/003/
//! [T1068 — Exploitation for Privilege Escalation]: https://attack.mitre.org/techniques/T1068/

/// Lowercase `.sys` basenames of drivers in the [LOLDrivers] dataset
/// (known-vulnerable + known-malicious — the BYOVD denylist).
///
/// **This is a DENYLIST**: presence of a driver image with one of these names is
/// a masquerade / BYOVD **lead**, the inverse of the service allowlists in
/// [`services`](crate::services) (where absence is the lead). **NON-EXHAUSTIVE**
/// and **names-only** — see the module docs: name-matching is a lead a renamed
/// sample can evade and a benign namesake can trip; hash-matching is the precise
/// form. Snapshot provenance is documented in the module header.
///
/// [LOLDrivers]: https://www.loldrivers.io/
pub const KNOWN_VULNERABLE_DRIVERS: &[&str] = &[
    "0x3040_blacklotus_beta_driver.sys",
    "0x3440_blacklotus_v2_driver.sys",
    "1.sys",
    "1109.sys",
    "2.sys",
    "360hvm64.sys",
    "360netmon_wfp.sys",
    "4.sys",
    "6c8a.sys",
    "7.sys",
    "80.sys",
    "81.sys",
    "834761775.sys",
    "8492937_2_driver.sys",
    "_xyzxbqvb.rdu_gfac_sys_x64.sys",
    "accellid.sys",
    "ace-base.sys",
    "acpix86.sys",
    "adrmdrvsys.sys",
    "adv64drv.sys",
    "advcare.sys",
    "afd.sys",
    "agent64.sys",
    "aida64driver.sys",
    "air_system10.sys",
    "alsysio.sys",
    "alsysio64.sys",
    "amd_rpmc_biostoolcommondriver.sys",
    "amdi2c.sys",
    "amdpowerprofiler.sys",
    "amdryzenmasterdriver.sys",
    "amifldrv.sys",
    "amifldrv64.sys",
    "amigendrv64.sys",
    "amp.sys",
    "ampa.sys",
    "amsdk.sys",
    "andappsvc2_64.sys",
    "aoddriver.sys",
    "aoddriver2.sys",
    "appshopdrv103.sys",
    "appvkgr.sys",
    "ardrv.sys",
    "argusmonitor.sys",
    "asas.sys",
    "asio.sys",
    "asio2.sys",
    "asio3.sys",
    "asio32.sys",
    "asio3_64.sys",
    "asio64.sys",
    "asmio.sys",
    "asmio64.sys",
    "asmmap.sys",
    "asmmap64.sys",
    "asrautochkupddrv.sys",
    "asrautochkupddrv_1_0_32.sys",
    "asrcddrv.sys",
    "asrdrv.sys",
    "asrdrv10.sys",
    "asrdrv101.sys",
    "asrdrv102.sys",
    "asrdrv103.sys",
    "asrdrv104.sys",
    "asrdrv106.sys",
    "asrdrv107.sys",
    "asrdrv107n.sys",
    "asribdrv.sys",
    "asromgdrv.sys",
    "asrrapidstartdrv.sys",
    "asrsetupdrv103.sys",
    "asrsmartconnectdrv.sys",
    "astra64.sys",
    "asupio.sys",
    "asupio64.sys",
    "aswarpot.sys",
    "aswvmm.sys",
    "athpexnt.sys",
    "atillk64.sys",
    "atlaccess.sys",
    "atomicredteamcapcom.sys",
    "atszio.sys",
    "atszio64.sys",
    "avalueio.sys",
    "avgarpot.sys",
    "avkiller.sys",
    "b.sys",
    "b1.sys",
    "b3.sys",
    "b4.sys",
    "bandai.sys",
    "bdapiutil.sys",
    "bdapiutil64.sys",
    "bedaisy.sys",
    "bin_intigua_driver64.sys",
    "biontdrv.sys",
    "biostoolcommondriver.sys",
    "black.sys",
    "blackbone.sys",
    "blackbonedrv10.sys",
    "blacklotus_beta_driver.sys",
    "blacklotus_beta_driver_2.sys",
    "blacklotus_beta_driver_3.sys",
    "blacklotus_beta_driver_4.sys",
    "blacklotus_driver.sys",
    "bootrepair.sys",
    "bs_def.sys",
    "bs_def64.sys",
    "bs_flash64.sys",
    "bs_hwmio64.sys",
    "bs_hwmio64_w10.sys",
    "bs_i2c64.sys",
    "bs_i2cio.sys",
    "bs_rcio.sys",
    "bs_rcio64.sys",
    "bs_rciow1064.sys",
    "bs_rvsio64.sys",
    "bsitf.sys",
    "bsmemx64.sys",
    "bsmi.sys",
    "bsmix64.sys",
    "bsmixp64.sys",
    "burntcigar.sys",
    "bw.sys",
    "bwrs.sys",
    "bwrsh.sys",
    "c.sys",
    "capcom.sys",
    "capcom2.sys",
    "cardio64.sys",
    "ccprotect.sys",
    "cg6kwin2k.sys",
    "changsha.sys",
    "chaos-rootkit.sys",
    "chinese_cheat_driver.sys",
    "citmdrv_amd64.sys",
    "citmdrv_ia64.sys",
    "cmupx.sys",
    "cndom6.sys",
    "computerz.sys",
    "controlcenter.sys",
    "cormem.sys",
    "corsairllaccess64.sys",
    "cp2x72c.sys",
    "cpqsysio.sys",
    "cpqsysio64.sys",
    "cpupress.sys",
    "cpuz.sys",
    "cpuz141.sys",
    "cpuz_x64.sys",
    "csagent.sys",
    "csc.sys",
    "ctiio64.sys",
    "cupfixerx64.sys",
    "cyvrlpc.sys",
    "d.sys",
    "d2.sys",
    "d3.sys",
    "d4.sys",
    "d591004.sys",
    "daxin_blank.sys",
    "daxin_blank1.sys",
    "daxin_blank2.sys",
    "daxin_blank3.sys",
    "daxin_blank4.sys",
    "daxin_blank5.sys",
    "daxin_blank6.sys",
    "dbk64.sys",
    "dbutil.sys",
    "dbutil_2_3.sys",
    "dbutildrv2.sys",
    "dcprotect.sys",
    "dcr.sys",
    "dddriver.sys",
    "dddriver64dcsa.sys",
    "deame.sys",
    "dellbios.sys",
    "dellinstrumentation.sys",
    "deresute64.sys",
    "devhost.sys",
    "devmemdrv.sys",
    "dh_kernel.sys",
    "dh_kernel_10.sys",
    "directio.sys",
    "directio32.sys",
    "directio32_legacy.sys",
    "directio64.sys",
    "ditpio64.sys",
    "dkrtk.sys",
    "dmx.sys",
    "dndrv.sys",
    "dpmemio.sys",
    "driver7-x64.sys",
    "driver7-x86-withoutdbg.sys",
    "driver7-x86.sys",
    "driver7.sys",
    "driver_win10.sys",
    "driverscloud_amd64.sys",
    "dsark.sys",
    "dsark64.sys",
    "dsark64_win10.sys",
    "dsark_win10.sys",
    "dtr_ec.sys",
    "dwadsafeload.sys",
    "dxiw8ez9ayxqyzgm.sys",
    "eb.sys",
    "echo.sys",
    "echo_driver.sys",
    "echodriver.sys",
    "ecsiodriver.sys",
    "ecsiodriverx64.sys",
    "eio.sys",
    "elbycdio.sys",
    "elrawdsk.sys",
    "ene.sys",
    "eneio64.sys",
    "energydriver.sys",
    "enetechio64.sys",
    "enportv.sys",
    "etdsupp.sys",
    "evga_kernel_driver-x64.sys",
    "f.sys",
    "fairplaykd.sys",
    "fastdumpx64.sys",
    "fdmcjhjyxziti.sys",
    "fgme.sys",
    "fh-ethercat_dio.sys",
    "fiddrv.sys",
    "fiddrv64.sys",
    "fidpcidrv.sys",
    "fidpcidrv64.sys",
    "fildds.sys",
    "filnk.sys",
    "filter.sys",
    "filwfp.sys",
    "fjfwupgd.sys",
    "foxkedriver64.sys",
    "fpcie2com.sys",
    "full.sys",
    "fur.sys",
    "g11.sys",
    "gamedriverx64.sys",
    "gameink.sys",
    "gametersafe.sys",
    "gdrv.sys",
    "gedevdrv.sys",
    "gftkyj64.sys",
    "ggprotect64.sys",
    "gibepext.sys",
    "glckio2.sys",
    "globalvistaventures_v3.sys",
    "gmer64.sys",
    "goad.sys",
    "gofly64.sys",
    "googleapiutil64.sys",
    "gpcidrv64.sys",
    "gpu-z.sys",
    "gtckmdfbs.sys",
    "gvcidrv64.sys",
    "hardwaremon-x86.sys",
    "havoc.sys",
    "hlpdrv.sys",
    "hostnt.sys",
    "hp64vision.sys",
    "hpportiox64.sys",
    "hw.sys",
    "hwauidoos2ec.sys",
    "hwdetectng.sys",
    "hwinfo32.sys",
    "hwinfo64i.sys",
    "hwos2ec.sys",
    "hwos2ec10x64.sys",
    "hwos2ec7x64.sys",
    "hwrwdrv.sys",
    "idmtdi.sys",
    "immunetutildriver.sys",
    "inetcache.sys",
    "inpout32.sys",
    "inpoutx64.sys",
    "ioaccess.sys",
    "iobios64.sys",
    "iobitunlocker.sys",
    "iocdrv.sys",
    "iomanager.sys",
    "iomap.sys",
    "iomap64.sys",
    "iomem.sys",
    "iomem64.sys",
    "ipctype.sys",
    "iqvw32.sys",
    "iqvw64.sys",
    "iqvw64e.sys",
    "irec.sys",
    "iscflashx64.sys",
    "isodrivep64.sys",
    "iuforcedelete.sys",
    "jnprva.sys",
    "jokercontroller.sys",
    "k7rkscan.sys",
    "kapchelper_x64.sys",
    "kbdcap64.sys",
    "kdhacker64_ev.sys",
    "kdriver.sys",
    "kevp64.sys",
    "kexplore.sys",
    "kfeco10x64.sys",
    "kfeco11x64.sys",
    "kfecodrv.sys",
    "khwmon.sys",
    "kinkajou.sys",
    "kmwpsms.sys",
    "kobjexp.sys",
    "kprocesshacker.sys",
    "kregexp.sys",
    "krpocesshacker.sys",
    "ksapi.sys",
    "ksld.sys",
    "kt2.sys",
    "ktdifilt.sys",
    "ktes.sys",
    "ktgn.sys",
    "ktmutil7odm.sys",
    "l1malwarebits.sys",
    "lallamon.sys",
    "lctka.sys",
    "lecomax.sys",
    "lecomax64.sys",
    "lenovodiagnosticsdriver.sys",
    "lgcoretemp.sys",
    "lgdatacatcher.sys",
    "lgdcatcher.sys",
    "lha.sys",
    "libnicm.sys",
    "lmiinfo.sys",
    "lnvmsrio.sys",
    "lsigetwin_sliffdriver.sys",
    "lurker.sys",
    "lv561av.sys",
    "magdrvamd64.sys",
    "malicious.sys",
    "mapmom.sys",
    "memctl.sys",
    "mhyprot.sys",
    "mhyprot2.sys",
    "mhyprot3.sys",
    "mhyprotect.sys",
    "mhyprotnap.sys",
    "mhyprotrpg.sys",
    "mimidrv.sys",
    "mimikatz.sys",
    "mjj0ge.sys",
    "mlgbbiicaihflrnh.sys",
    "mnemosyne.sys",
    "monitor.sys",
    "monitor_win10_x64.sys",
    "mpksldrv.sys",
    "msio32.sys",
    "msio64.sys",
    "msqpq.sys",
    "msr.sys",
    "msrhook.sys",
    "mst.sys",
    "mtcbsv64.sys",
    "mtxc9cb.sys",
    "mtxmem.sys",
    "my.sys",
    "mydrivers.sys",
    "naldrv.sys",
    "nbiolib_x64.sys",
    "nchgbios2x64.sys",
    "ncpl.sys",
    "ndislan.sys",
    "neacsafe64.sys",
    "neofltr.sys",
    "netfilter.sys",
    "netfilter2.sys",
    "netfilterdrv.sys",
    "netflt.sys",
    "netproxydriver.sys",
    "networklocker_x64.sys",
    "ngiodriver.sys",
    "ngstar.sys",
    "ni.sys",
    "nicm.sys",
    "nipalk.sys",
    "nlslexicons0024uvn.sys",
    "nodedriver.sys",
    "novawave_novabench_novabenchdriverwin10.sys",
    "npr0.sys",
    "nqrmq.sys",
    "nscm.sys",
    "nseckrnl.sys",
    "nstr.sys",
    "nstrwsk.sys",
    "nt2.sys",
    "nt3.sys",
    "nt4.sys",
    "nt5.sys",
    "nt6.sys",
    "ntbios.sys",
    "ntbios_2.sys",
    "ntiolib.sys",
    "ntiolib_x64.sys",
    "nvaudio.sys",
    "nvflash.sys",
    "nvflsh32.sys",
    "nvflsh64.sys",
    "nvoclock.sys",
    "nxeng.sys",
    "oatoolx64.sys",
    "openhardwaremonitorlib.sys",
    "openlibsys.sys",
    "otipcibus.sys",
    "otipcibus64.sys",
    "p2kghmzsary1.sys",
    "panio.sys",
    "paniox64.sys",
    "panmonflt.sys",
    "panmonfltx64.sys",
    "pcdsrvc_x64.sys",
    "pchunter.sys",
    "pciecubed.sys",
    "pctcore.sys",
    "pctcore64.sys",
    "pdfwkrnl.sys",
    "pgrhostcontrol.sys",
    "phlashnt.sys",
    "phydmaccx64.sys",
    "phydmaccx86.sys",
    "phymem.sys",
    "phymem64.sys",
    "phymem_ext64.sys",
    "phymemx64.sys",
    "physmem.sys",
    "piddrv.sys",
    "piddrv64.sys",
    "pmad.sys",
    "pmxdrv.sys",
    "pmxdrv64.sys",
    "poisonx.sys",
    "poisonx10.sys",
    "poisonx11.sys",
    "poisonx12.sys",
    "poisonx13.sys",
    "poisonx14.sys",
    "poisonx15.sys",
    "poisonx16.sys",
    "poisonx17.sys",
    "poisonx18.sys",
    "poisonx2.sys",
    "poisonx3.sys",
    "poisonx4.sys",
    "poisonx5.sys",
    "poisonx6.sys",
    "poisonx7.sys",
    "poisonx8.sys",
    "poisonx9.sys",
    "poortry.sys",
    "poortry1.sys",
    "poortry2.sys",
    "portwell.sys",
    "ppa_x64.sys",
    "probmon.sys",
    "processctr.sys",
    "processmonitordriver.sys",
    "procexp.sys",
    "procexp152.sys",
    "procexp1627.sys",
    "procobsrvesx.sys",
    "prokiller64.sys",
    "protects.sys",
    "proxy32.sys",
    "proxy64.sys",
    "proxydrv.sys",
    "psmounterex.sys",
    "pxitrig64.sys",
    "qu829.sys",
    "radhwmgr.sys",
    "realtimedriver.sys",
    "reddriver.sys",
    "rentdrv2.sys",
    "rootlaser.sys",
    "rspot.sys",
    "rtcore64.sys",
    "rtcoremini64.sys",
    "rtif.sys",
    "rtkio.sys",
    "rtkio64.sys",
    "rtkiow10x64.sys",
    "rtkiow8x64.sys",
    "rtport.sys",
    "rtsper.sys",
    "rtstpx.sys",
    "rtsuer.sys",
    "rwdriver.sys",
    "rwdrv.sys",
    "rwtkrl.sys",
    "rzpnk.sys",
    "sandra.sys",
    "sbiosio64.sys",
    "sdrv_win_sliff.sys",
    "se64a.sys",
    "seasunprotect.sys",
    "segwindrvx64.sys",
    "semav6msr.sys",
    "semav6msr64.sys",
    "sense5ext.sys",
    "sepdrv3_1.sys",
    "sfdrvx32.sys",
    "sfdrvx64.sys",
    "shield-async.sys",
    "shield.sys",
    "shieldwp.sys",
    "shimano32.sys",
    "shimano64.sys",
    "signeddrv.sys",
    "sioctl.sys",
    "sivx64.sys",
    "skill.sys",
    "smarteio64.sys",
    "smep_capcom.sys",
    "smep_namco.sys",
    "smserl64.sys",
    "sonixddrx64.sys",
    "sparkio.sys",
    "speedfan.sys",
    "spf.sys",
    "spwizimgvt.sys",
    "srswdrv.sys",
    "srvnet2.sys",
    "ssport.sys",
    "stdcdrv64.sys",
    "stdcdrvws64.sys",
    "stpm_new.sys",
    "stpm_old.sys",
    "stprocessmonitor.sys",
    "stprocessmonitor_v114.sys",
    "superbmc.sys",
    "superman.sys",
    "svioctrlx64.sys",
    "sysconp.sys",
    "sysdrv3s.sys",
    "sysfile_x64.sys",
    "sysinfo.sys",
    "sysinfodetectorx64.sys",
    "sysinfox64.sys",
    "szkg64.sys",
    "t.sys",
    "t3.sys",
    "t7.sys",
    "t8.sys",
    "tboflhelper.sys",
    "tbt_force_power_control_access64.sys",
    "tcio.sys",
    "tcrouter.sys",
    "tdeio64.sys",
    "tdevflt.sys",
    "tdklib64.sys",
    "telephonuafy.sys",
    "termdd.sys",
    "test2.sys",
    "testbone.sys",
    "tfbfs3ped.sys",
    "tfsysmon.sys",
    "tgsafe.sys",
    "thelper.sys",
    "throttleblood.sys",
    "throttlestop.sys",
    "titidrv.sys",
    "tm_filter.sys",
    "tmcomm.sys",
    "tmel.sys",
    "tmfsdrv2.sys",
    "tpwsav.sys",
    "trixx.sys",
    "truesight.sys",
    "tsdrvx64.sys",
    "tvicport64.sys",
    "typelibde.sys",
    "ucorew64.sys",
    "uddb2b6.sys",
    "umamusume64_2.sys",
    "unknown.sys",
    "usbxhci.sys",
    "usrdrv017764.sys",
    "usrdrv017864.sys",
    "usrdrv018064.sys",
    "usrdrv118064.sys",
    "utia2d4.sys",
    "vboxdrv.sys",
    "vboxguest.sys",
    "vboxmousent.sys",
    "vboxtap.sys",
    "vboxusb.sys",
    "vboxusbmon.sys",
    "vdbsv64.sys",
    "vgk.sys",
    "viraglt64.sys",
    "viragt.sys",
    "viragt64.sys",
    "viverraudio.sys",
    "vmdrv.sys",
    "vproeventmonitor.sys",
    "vsdatant.sys",
    "vusbbus.sys",
    "wamsdk.sys",
    "wantd.sys",
    "wantd_2.sys",
    "wantd_3.sys",
    "wantd_4.sys",
    "wantd_5.sys",
    "wantd_6.sys",
    "watabe.sys",
    "wcpu.sys",
    "wdisvhost.sys",
    "wdtkernel.sys",
    "wfs64.sys",
    "wfshbr32.sys",
    "wfshbr64.sys",
    "whql.sys",
    "windbg.sys",
    "windivert.sys",
    "windows-memory-informer.sys",
    "windows-xp-64.sys",
    "windows7-32.sys",
    "windows8-10-32.sys",
    "windows_cpu_temperature_component.sys",
    "winflash64.sys",
    "winio32.sys",
    "winio32a.sys",
    "winio32b.sys",
    "winio64.sys",
    "winio64a.sys",
    "winio64b.sys",
    "winio64c.sys",
    "winiodrv.sys",
    "winring0.sys",
    "winring0x64.sys",
    "wintapix.sys",
    "wirwadrv.sys",
    "wiseunlo.sys",
    "wnbios.sys",
    "wsdkd.sys",
    "wsftprm.sys",
    "wyproxy32.sys",
    "wyproxy64.sys",
    "xhunter1.sys",
    "xiaoh.sys",
    "xjokercontroller.sys",
    "xkpsm.sys",
    "xlha.sys",
    "yyprotect64.sys",
    "zam64.sys",
    "zamguard32.sys",
    "zamguard64.sys",
    "zyarkit.sys",
];

/// Returns `true` if `basename` is a known-vulnerable / known-malicious driver
/// from the [LOLDrivers] dataset (case-insensitive; accepts the name with or
/// without a `.sys` suffix).
///
/// **DENYLIST lead gate, not a verdict**: a `true` result means a driver with
/// this *name* appears in the BYOVD dataset and warrants investigation — it does
/// NOT prove this particular file is the vulnerable driver (a benign namesake can
/// trip it). A `false` result does NOT prove the driver is safe (a renamed
/// vulnerable sample evades a name match, and the snapshot is non-exhaustive).
/// Corroborate with the on-disk hash (the precise form), the Authenticode
/// signature, and the load path. See [`KNOWN_VULNERABLE_DRIVERS`].
///
/// [LOLDrivers]: https://www.loldrivers.io/
#[must_use]
pub fn is_known_vulnerable_driver(basename: &str) -> bool {
    let mut lower = basename.trim().to_ascii_lowercase();
    if !lower.ends_with(".sys") {
        lower.push_str(".sys");
    }
    KNOWN_VULNERABLE_DRIVERS.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_is_non_trivial() {
        assert!(KNOWN_VULNERABLE_DRIVERS.len() >= 500);
    }

    #[test]
    fn all_entries_lowercase_bare_sys() {
        for &d in KNOWN_VULNERABLE_DRIVERS {
            assert_eq!(d, d.to_ascii_lowercase());
            assert!(d.ends_with(".sys"));
            assert!(!d.contains('\\') && !d.contains('/'));
        }
    }

    #[test]
    fn no_duplicate_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for &d in KNOWN_VULNERABLE_DRIVERS {
            assert!(seen.insert(d), "duplicate: {d}");
        }
    }

    #[test]
    fn flags_rtcore64() {
        assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"rtcore64.sys"));
        assert!(is_known_vulnerable_driver("rtcore64.sys"));
        assert!(is_known_vulnerable_driver("rtcore64"));
    }

    #[test]
    fn flags_dbutil_2_3() {
        assert!(KNOWN_VULNERABLE_DRIVERS.contains(&"dbutil_2_3.sys"));
        assert!(is_known_vulnerable_driver("dbutil_2_3.sys"));
    }

    #[test]
    fn flags_case_insensitive() {
        assert!(is_known_vulnerable_driver("RTCore64.SYS"));
    }

    #[test]
    fn flags_trimmed() {
        assert!(is_known_vulnerable_driver("  rtcore64.sys  "));
    }

    #[test]
    fn does_not_flag_legit_windows_drivers() {
        assert!(!is_known_vulnerable_driver("ntfs.sys"));
        assert!(!is_known_vulnerable_driver("tcpip.sys"));
        assert!(!is_known_vulnerable_driver("NTFS.SYS"));
    }

    #[test]
    fn does_not_flag_empty_or_random() {
        assert!(!is_known_vulnerable_driver(""));
        assert!(!is_known_vulnerable_driver("totally-not-a-driver.sys"));
    }
}
