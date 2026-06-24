# Security Policy

## Antivirus / EDR false positives — expected, and why

`forensicnomicon` is a **forensic *knowledge* library**. Its data tables are the
product: attacker-tool names (`wmiexec`, `psexec`, `mimikatz`, …), LOLBAS/LOLDrivers
entries, BYOVD vulnerable-driver names, command-line attack patterns, ransomware
indicators, and MITRE ATT&CK mappings. These are **inert strings used for
substring/pattern matching** — not executable code, shellcode, payloads, or copies
of the tools themselves.

Because of that, signature/heuristic engines may flag the source files or the
compiled artifact, exactly as they sometimes flag a [YARA] rule file, a [Sigma]
ruleset, Volatility, or KAPE. **This is a false positive.** The crate ships:

- no executable malware, shellcode, or packed payloads;
- no copies of the named tools (e.g. there is **no** `wmiexec.py` file — only the
  string `"wmiexec"` in a lateral-movement detection table);
- reproducible builds from public source.

### Remediation

Pick the item matching where your scanner flags:

- **Compiled binary** (`4n6query`, `libforensicnomicon.rlib`, or a downstream tool
  that links the crate): add an AV/EDR **allowlist exclusion** for the binary, and
  submit a **false-positive report** to your vendor:
  - Microsoft Defender: <https://www.microsoft.com/wdsi/filesubmission>
  - Other vendors: use their FP / sample-submission portal.
- **Source checkout / IDE scan**: exclude the repository path from real-time
  scanning. The flagged content is detection-signature data, not code that runs.
- **CI**: exclude the `target/` build directory from any on-runner scanner.

### Verifying integrity (rule out a real compromise)

- Build from source and compare against the published crate
  (`cargo install` / the crates.io checksum).
- The threat-indicator strings live in auditable data tables under `src/`
  (`commands.rs`, `drivers.rs`, `lolbins.rs`, `heuristics/`, …) — review them
  directly; none execute.

We deliberately keep gratuitously "real" command lines out of source (examples use
placeholders like `<user>@<host>`), but the indicator strings themselves cannot be
removed without breaking detection — allowlisting is the correct fix.

## Reporting a real security issue

For an actual vulnerability in this crate (memory safety, a parser panic on
crafted input, supply-chain concern), email **albert@securityronin.com** with
details and a reproducer. Please do not open a public issue for security reports.

[YARA]: https://virustotal.github.io/yara/
[Sigma]: https://github.com/SigmaHQ/sigma
