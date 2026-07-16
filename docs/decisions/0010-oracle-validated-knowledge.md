# 0010 — Oracle-validated knowledge on real IR data; denylists non-exhaustive

**Status:** Accepted

## Context

A forensic knowledge base is only as trustworthy as its validation. A table checked against a
fixture the author wrote can be wrong and pass anyway (the self-authored-fixture trap). Knowledge
that will drive investigative decisions — "this service binary is legitimate", "this driver is
BYOVD" — must be checked against something the author did not author.

## Decision

Validate value-producing and denylist knowledge against an **independent oracle on real-world
data**, and document each check in `docs/validation.md` (name the oracle, state what is claimed,
show the reconciliation). Where a claim is only self-fixtured, it is not treated as validated.

Current validations reconcile against the public DC01 "Szechuan Sauce" IR dataset, skipping
loudly (`SKIP:` + pass) when the corpus is absent:

- **Known-good service-binary catalog** — isolates the `coreupdater.exe` masquerade against the
  real DC01 SYSTEM hive.
- **svchost `ServiceDll` baseline** — completeness against DC01 (the #1 svchost implant vector).
- **LOLDrivers BYOVD denylist** — validated against DC01's driver set, pinned to a specific
  `magicsword-io/LOLDrivers` commit; flags `rtcore64.sys`.

The BYOVD list is explicitly a **denylist**: **non-exhaustive** (a point-in-time snapshot;
absence ≠ safe), **names-only** (a lead — corroborate with on-disk hash / Authenticode / load
path). Findings state what the evidence *is*, not a legal or causal conclusion.

Evidence: `docs/validation.md`; `tests/services_dc01_isolation.rs`; `cargo test --test
drivers_dc01_clean` gated by `ISSEN_DC01_SYSTEM_HIVE`.

## Consequences

- **+** Knowledge claims are backed by an independent oracle on real data, not self-consistency.
- **+** Corpus-gated tests skip cleanly where the (large, non-committed) dataset is absent, so CI
  stays green without shipping the corpus.
- **+** Framing denylists as non-exhaustive, names-only leads keeps the tool honest about what
  absence and a name-match do and do not prove.
- **−** Validation depends on external corpora and pinned upstream commits — new claims need a
  sourced oracle, and pins must be refreshed deliberately. Accepted: unsourced knowledge is not
  shipped as validated.
