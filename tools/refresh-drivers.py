#!/usr/bin/env python3
"""Regenerate src/drivers_data.rs from the LOLDrivers dataset + a curated overlay.

Single mechanical step for a LOLDrivers bump:
    curl -sL https://www.loldrivers.io/api/drivers.json -o /tmp/loldrivers.json
    python3 tools/refresh-drivers.py /tmp/loldrivers.json

The LOLDrivers feed is the bulk source (basename, GUID, category, CVE, MITRE,
SHA-256 samples, HVCI-bypass). The CURATED overlay below is the hand-authored
knowledge NOT in the feed: service names (EVTX 7045 key), the EDR-killer flag,
and basename-only entries (e.g. GentleKiller drop-names absent from the snapshot).
All three public consts (BYOVD_DRIVERS, KNOWN_VULNERABLE_DRIVERS,
BYOVD_DRIVER_NAMES) are co-generated here so they cannot drift.
"""
import json, re, sys

# ── Curated overlay (hand-authored; survives feed refreshes) ──────────────────
SERVICE_NAMES = {
    "zamguard64.sys": ["ZemanaAntiMalware", "zamguard64", "ZAM"],
    "gdrv.sys": ["gdrv"], "asrdrv104.sys": ["AsrDrv104"], "asrdrv10.sys": ["AsrDrv10"],
    "rtcore64.sys": ["RTCore64"], "dbutil_2_3.sys": ["dbutil_2_3"],
    "atszio64.sys": ["ATSZIO64"], "winring0x64.sys": ["WinRing0_1_2_0"],
    "cpuz_x64.sys": ["cpuz136_x64"], "speedfan.sys": ["speedfan"],
}
# Drivers documented in public reporting as abused specifically to terminate
# AV/EDR processes (ransomware EDR-killers + the GentleKiller/Gentlemen suite).
EDR_KILLER = {
    "rtcore64.sys","dbutil_2_3.sys","zamguard64.sys","zam64.sys","mhyprot2.sys",
    "mhyprot3.sys","aswarpot.sys","truesight.sys","procexp152.sys","gdrv.sys",
    "iqvw64e.sys","viragt64.sys",
    # GentleKiller / Gentlemen RaaS (ESET 2026-06)
    "eb.sys","nseckrnl.sys","gamedriverx64.sys","vgk.sys","stpm_old.sys","stpm_new.sys",
    "dmx.sys","360netmon_wfp.sys","g11.sys","poisonx.sys","googleapiutil64.sys",
    "throttleblood.sys","throttlestop.sys","havoc.sys",
}
# Basename-only entries (not in the LOLDrivers snapshot): GentleKiller drops + ESET facts.
OVERLAY_ONLY = {
    "eb.sys":           ("malicious",  "GentleKiller Kaspersky variant (custom rootkit)", ["T1068"]),
    "vgk.sys":          ("vulnerable driver", "GentleKiller Valorant-variant drop (Tower of Fantasy anti-cheat)", ["T1068"]),
    "stpm_old.sys":     ("vulnerable driver", "Safetica ProcessMonitor (GentleKiller Javelin, old)", ["T1068"]),
    "stpm_new.sys":     ("vulnerable driver", "Safetica ProcessMonitor (GentleKiller Javelin, new)", ["T1068"]),
    "dmx.sys":          ("vulnerable driver", "Zemana WatchDog (GentleKiller WatchDog variant, CVE-2022-42045)", ["T1068"]),
    "throttleblood.sys":("vulnerable driver", "ThrottleStop drop name (ThrottleBlood EDR killer)", ["T1068"]),
}
CVE_OVERLAY = {
    "dmx.sys": ["CVE-2022-42045"], "dbutil_2_3.sys": ["CVE-2021-21551"],
    "rtcore64.sys": ["CVE-2019-16098"], "gdrv.sys": ["CVE-2018-19320"],
    "iqvw64e.sys": ["CVE-2015-2291"], "winring0x64.sys": ["CVE-2020-14979"],
}
# Clean human labels for famous drivers where the feed's sample description is empty.
LABEL_OVERRIDE = {
    "rtcore64.sys": "MSI Afterburner RTCore64", "dbutil_2_3.sys": "Dell DBUtil",
    "gdrv.sys": "Gigabyte GDRV", "iqvw64e.sys": "Intel Ethernet diagnostics",
    "zamguard64.sys": "Zemana AntiMalware", "truesight.sys": "Adlice TrueSight (EDRKillShifter)",
    "aswarpot.sys": "Avast aswArPot", "procexp152.sys": "Sysinternals Process Explorer",
    "mhyprot2.sys": "Genshin mhyprot2 anti-cheat", "viragt64.sys": "TG Soft ViRobot APT",
    "winring0x64.sys": "OpenLibSys WinRing0",
}
SHA_CAP = 3
# Drivers present in our prior snapshot but absent from the current LOLDrivers feed
# (LOLDrivers occasionally prunes/renames). A denylist must not shrink, so keep them.
PRESERVE_LEGACY = set(l.strip() for l in open("tools/legacy-basenames.txt") if l.strip())  # committed snapshot; never shrink
# Core/legitimate Windows drivers that malicious samples masquerade as — never
# denylist by name (would false-positive on every host). The canonical Tags rarely
# include these; this is belt-and-braces against a masquerade sample filename.
BENIGN_EXCLUDE = {"ntfs.sys","tcpip.sys","ndis.sys","http.sys","srv.sys","srv2.sys",
                  "fltmgr.sys","mup.sys","null.sys","beep.sys","kbdclass.sys"}

HEX64 = re.compile(r'^[a-f0-9]{64}$')
def nlist(v):
    if not v: return []
    if isinstance(v, str): v=[v]
    return [x.strip() for x in v if x and str(x).strip().lower() not in ("none","n/a","")]
def clean(s, n=64):
    s=re.sub(r'[^\x20-\x7e]', '', (s or "")).replace('\\','').replace('"',"'").strip()
    return s[:n].strip()

def build(path):
    data=json.load(open(path))
    m={}
    for e in data:
        guid=e.get("Id") or ""; cat=(e.get("Category") or "vulnerable driver").lower()
        cves=[c.upper() for c in nlist(e.get("CVE")) if c.upper().startswith("CVE-")]
        mitre=sorted({t.upper() for t in nlist(e.get("MitreID")) if re.match(r'^T\d{4}',t)})
        sha=[]; hvci=False; label=""
        bns=set(t.lower() for t in nlist(e.get("Tags")) if t.lower().endswith(".sys") and len(t)>4)
        for s in (e.get("KnownVulnerableSamples") or []):
            h=(s.get("SHA256") or "").lower().strip()
            if HEX64.match(h): sha.append(h)
            if str(s.get("LoadsDespiteHVCI") or "").upper()=="TRUE": hvci=True
            if not label: label=clean(s.get("Description") or s.get("Product") or s.get("Company"))
        for b in bns:
            c=m.setdefault(b,{"guid":guid,"cat":cat,"cve":set(),"mitre":set(),"sha":[],"hvci":False,"label":""})
            c["cve"]|=set(cves); c["mitre"]|=set(mitre); c["sha"]+=sha; c["hvci"]|=hvci
            if not c["label"]: c["label"]=label
            if not c["guid"]: c["guid"]=guid
    # merge overlay-only basenames
    for b,(cat,label,mitre) in OVERLAY_ONLY.items():
        c=m.setdefault(b,{"guid":"","cat":cat,"cve":set(),"mitre":set(),"sha":[],"hvci":False,"label":label})
        c["mitre"]|=set(mitre)
        if not c["label"]: c["label"]=label
        c["cat"]=cat
    for b,cves in CVE_OVERLAY.items():
        if b in m: m[b]["cve"]|=set(cves)
    for b in PRESERVE_LEGACY:
        m.setdefault(b,{"guid":"","cat":"vulnerable driver","cve":set(),"mitre":{"T1068"},"sha":[],"hvci":False,"label":""})
    for b in list(m):                      # benign/masquerade exclude — applied LAST
        if b in BENIGN_EXCLUDE: del m[b]
    return m

def emit(m):
    def rs_arr(xs): return "&[" + ", ".join(f'"{x}"' for x in xs) + "]"
    rows=[]
    for b in sorted(m):
        d=m[b]
        cat="Malicious" if d["cat"].startswith("malicious") else "Vulnerable"
        svc=SERVICE_NAMES.get(b, [])
        sha=sorted(set(d["sha"]))[:SHA_CAP]
        cve=sorted(d["cve"]); mitre=sorted(d["mitre"]) or (["T1068"] if not d["guid"] else [])
        ek="true" if b in EDR_KILLER else "false"
        hvci="true" if d["hvci"] else "false"
        lbl=LABEL_OVERRIDE.get(b) or clean(d["label"]) or b[:-4]
        rows.append(
            f'    VulnerableDriver {{ file_basename: "{b}", service_names: {rs_arr(svc)}, '
            f'label: "{lbl}", category: DriverCategory::{cat}, loldrivers_id: "{d["guid"]}", '
            f'cve: {rs_arr(cve)}, mitre: {rs_arr(mitre)}, sha256: {rs_arr(sha)}, '
            f'loads_despite_hvci: {hvci}, edr_killer: {ek} }},')
    basenames=sorted(m)
    svc_flat=[s for b in basenames for s in SERVICE_NAMES.get(b,[])]
    out=[]
    out.append("// @generated by tools/refresh-drivers.py from the LOLDrivers dataset + curated overlay.")
    out.append("// DO NOT EDIT BY HAND. Re-run the tool to refresh. See the module header in drivers.rs.")
    out.append("use super::{DriverCategory, VulnerableDriver};")
    out.append("")
    out.append(f"/// All BYOVD drivers (LOLDrivers snapshot + curated overlay): {len(basenames)} entries.")
    out.append("pub const BYOVD_DRIVERS: &[VulnerableDriver] = &[")
    out.extend(rows)
    out.append("];")
    out.append("")
    out.append("/// Driver `.sys` basenames (derived: every `BYOVD_DRIVERS` entry's basename).")
    out.append("pub const KNOWN_VULNERABLE_DRIVERS: &[&str] = &[")
    out.extend(f'    "{b}",' for b in basenames)
    out.append("];")
    out.append("")
    out.append("/// BYOVD driver service names (derived: flattened curated `service_names`).")
    out.append("pub const BYOVD_DRIVER_NAMES: &[&str] = &[")
    out.extend(f'    "{s}",' for s in svc_flat)
    out.append("];")
    return "\n".join(out)+"\n"

if __name__=="__main__":
    m=build(sys.argv[1] if len(sys.argv)>1 else "/tmp/loldrivers.json")
    open("/tmp/drivers_data.rs","w").write(emit(m))
    print("entries:",len(m))
