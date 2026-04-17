# Module Research Map

This crate has two layers:

- small zero-allocation indicator modules such as `ports`, `lolbins`, and `persistence`
- the larger [`artifact`](/Users/4n6h4x0r/src/forensic-catalog/src/artifact.rs:1) catalog, which models specific artifacts with decode logic, ATT&CK mappings, triage priority, retention, and per-artifact sources

The new [`references`](/Users/4n6h4x0r/src/forensic-catalog/src/references.rs:1) module turns module-level provenance into queryable static data.

## Coverage

`artifact`
Unified descriptor registry. Current implementation already carries 151 artifact descriptors with embedded `sources`, `related_artifacts`, decode schemas, and triage ordering. This is the richest part of the crate and the best place to keep growing artifact-specific research.

Authoritative references:
- MITRE ATT&CK: https://attack.mitre.org/
- Harlan Carvey Windows IR: http://windowsir.blogspot.com/
- Eric Zimmerman tool/index docs: https://ericzimmerman.github.io/#!index.md

Expansion targets:
- add more Linux event/log artifacts
- add macOS descriptor parity instead of path-only coverage
- normalize ATT&CK mappings where only parent techniques are present

`ports`
Attacker-favored ports tied to C2, Tor, WinRM, and commodity remote access.

Authoritative references:
- SANS ISC port database: https://isc.sans.edu/port.html
- Microsoft WinRM configuration: https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- Tor Project port guidance: https://support.torproject.org/tbb/tbb-firewall-ports/

Expansion targets:
- split by confidence or context instead of a single suspicious list
- attach protocol/service rationale for each port

`lolbins`
Windows LOLBAS and Linux GTFOBins coverage for proxy execution and execution chaining.

Authoritative references:
- LOLBAS: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- MITRE ATT&CK T1218: https://attack.mitre.org/techniques/T1218/

Expansion targets:
- track per-binary ATT&CK sub-techniques
- add execution mode metadata such as download, proxy execution, or UAC bypass

`processes`
Masquerade targets and offensive-tool process names for process tree review.

Authoritative references:
- MITRE ATT&CK T1036: https://attack.mitre.org/techniques/T1036/
- Microsoft svchost reference: https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring
- Microsoft authentication process overview: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication

Expansion targets:
- distinguish built-in process names from offensive framework names
- add parent/child expectations for high-value Windows processes

`commands`
Reverse shell, PowerShell abuse, and ingress tool transfer pattern sets.

Authoritative references:
- PayloadsAllTheThings reverse shell cheat sheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- MITRE ATT&CK T1059: https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/

Expansion targets:
- separate high-signal patterns from generic admin usage
- add shell family metadata for detection tuning

`paths`
Trusted library locations and suspicious staging paths.

Authoritative references:
- Microsoft file path naming: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
- Linux FHS 3.0: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
- MITRE ATT&CK T1574.001: https://attack.mitre.org/techniques/T1574/001/

Expansion targets:
- normalize Windows env-var paths
- add path classification instead of boolean-only helpers

`persistence`
Registry, cron, systemd, launchd, and hijack-based persistence locations.

Authoritative references:
- MITRE ATT&CK T1547: https://attack.mitre.org/techniques/T1547/
- Sysinternals Autoruns: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Windows IR persistence notes: http://windowsir.blogspot.com/2013/07/howto-detecting-persistence-mechanisms.html

Expansion targets:
- model per-location execution semantics
- add startup-folder and service-file nuance for Linux and macOS

`antiforensics`
Log wiping, rootkit, and timestomping indicators.

Authoritative references:
- MITRE ATT&CK T1070: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1070.006: https://attack.mitre.org/techniques/T1070/006/
- Windows IR timestomping analysis: http://windowsir.blogspot.com/2023/10/investigating-time-stomping.html

Expansion targets:
- add Linux-specific anti-forensic cleanup artifacts
- separate userland and kernel-level rootkit families

`encryption`
BitLocker, EFS, VeraCrypt, Tor, and archive tool registry evidence.

Authoritative references:
- Microsoft BitLocker policy reference: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings
- Microsoft EFS reference: https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption
- Belkasoft VeraCrypt forensics: https://belkasoft.com/veracrypt-forensics

Expansion targets:
- add file-system level evidence beyond registry paths
- distinguish credential storage from at-rest encryption

`remote_access`
LOLRMM and remote administration product indicators.

Authoritative references:
- LOLRMM: https://lolrmm.io/
- CISA AA23-025A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- Red Canary RMM abuse overview: https://redcanary.com/blog/threat-intelligence/remote-monitoring-management/

Expansion targets:
- map tool vendor, binary names, services, and install paths
- split benign enterprise usage from intrusion-relevant deployment signals

`third_party`
Third-party app registry artifacts for SSH clients, sync tools, and browsers.

Authoritative references:
- PuTTY registry appendix: https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html
- WinSCP registry storage: https://winscp.net/eng/docs/ui_pref_storage
- Chrome enterprise policies: https://chromeenterprise.google/policies/

Expansion targets:
- extend to Firefox, Edge, and additional cloud sync clients
- add saved-credential or recent-connection semantics where appropriate

`pca`
Windows 11 Program Compatibility Assistant execution artifacts.

Authoritative references:
- Andrea Fortuna PCA write-up: https://andreafortuna.org/2024/windows11-pca-artifact/
- MITRE ATT&CK T1204: https://attack.mitre.org/techniques/T1204/

Expansion targets:
- cross-link PCA records with Prefetch, Amcache, and UserAssist
- capture PCA coverage limitations more explicitly in user-facing docs

## Full-Blog Collection

The repository now includes [`scripts/scrape_blog.py`](/Users/4n6h4x0r/src/forensic-catalog/scripts/scrape_blog.py:1), a dependency-free archive tool intended for building a local research corpus from a DFIR blog.

Recommended target for Windows-focused artifact work:

- Windows Incident Response archive: https://windowsir.blogspot.com/

Why this blog:

- it is already cited repeatedly across the crate
- it spans many years of artifact-focused DFIR research
- archive pages exist by year, and Blogger feeds can be paged for full historical collection

Suggested command:

```bash
python3 scripts/scrape_blog.py \
  --url https://windowsir.blogspot.com \
  --output research/windowsir
```
