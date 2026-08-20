# forensicnomicon-core

The stable engine layer of the [ForensicNomicon](https://github.com/SecurityRonin/forensicnomicon):
the normalized DFIR report model and the structural format constants that sit
under it.

**Zero dependencies.** This crate is what other fleet analyzers depend on, so it
holds only what changes slowly: `Finding`, `Severity`, the `Observation` trait,
and format constants. The fast-moving detection knowledge lives in
[`forensicnomicon-data`](https://crates.io/crates/forensicnomicon-data), and the
two are separated precisely so a catalog update does not churn the type every
analyzer in the fleet compiles against.

```toml
[dependencies]
forensicnomicon-core = "1"
```

A `Finding` is an observation, never a legal conclusion — it says "consistent
with", and carries `Option<Severity>` where `None` means *not scored*, which is
a different claim from `Some(Info)`.

Full documentation, including the report model's rationale, is in the
[workspace README](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy](https://securityronin.github.io/forensicnomicon/privacy/) ·
[Terms](https://securityronin.github.io/forensicnomicon/terms/) ·
© Security Ronin Ltd
