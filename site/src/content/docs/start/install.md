---
title: "Install"
description: "Add the crate to the package that runs the SAML flow. This repository is 0.6.0. You need Rust 1.88 or newer."
---

Add the crate to the package that runs the SAML flow. This repository is 0.6.0. You need Rust 1.88 or newer.

```toml
[dependencies]
saml-rs = "0.6"
```

That default turns signing and encryption on with RustCrypto. Check the version you pin on [crates.io](https://crates.io/crates/saml-rs).

To build messages without cryptography:

```toml
[dependencies]
saml-rs = { version = "0.6", default-features = false }
```

Signing, verification, and encryption then return `SamlError::Unsupported`.

## Next

- [Crypto provider](../guides/crypto-provider.md) if you need AWS-LC or FIPS.
- [Cargo features](../reference/features.md) for the full flag list.
