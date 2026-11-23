---
title: "Install"
description: "Add the crate to the package that runs the SAML flow. You need Rust 1.88 or newer."
---

Add the crate to the package that runs the SAML flow. You need Rust 1.88 or newer.

```sh
cargo add saml-rs
```

Cargo records the latest published release. The default features turn signing and encryption on with RustCrypto. Releases are listed on [crates.io](https://crates.io/crates/saml-rs).

To build messages without cryptography:

```sh
cargo add saml-rs --no-default-features
```

Signing, verification, and encryption then return `SamlError::Unsupported`.

## Next

- [Crypto provider](../guides/crypto-provider.md) if you need AWS-LC or FIPS.
- [Cargo features](../reference/features.md) for the full flag list.
