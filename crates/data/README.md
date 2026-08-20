# forensicnomicon-data

The detection knowledge of the [ForensicNomicon](https://github.com/SecurityRonin/forensicnomicon):
the artifact descriptor catalog and the evidence and volatility lookups built on
top of it.

This is the **fast-moving** layer. It sits atop
[`forensicnomicon-core`](https://crates.io/crates/forensicnomicon-core), which
holds the types, so that adding an artifact or correcting a descriptor does not
disturb the model every fleet analyzer compiles against.

```toml
[dependencies]
forensicnomicon-data = "1"
```

Every descriptor carries its provenance. Where a claim about an artifact comes
from a published writeup, the source is cited in the descriptor itself rather
than inherited as folklore.

Full documentation is in the
[workspace README](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy](https://securityronin.github.io/forensicnomicon/privacy/) ·
[Terms](https://securityronin.github.io/forensicnomicon/terms/) ·
© Security Ronin Ltd
