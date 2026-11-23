---
title: "Install"
description: "Add the unreleased crate from main. You need Rust 1.88 or newer."
---

Add the unreleased crate from `main` to the package that runs the SAML flow. You need Rust 1.88 or newer.

```sh
cargo add saml-rs --git https://github.com/salasebas/saml-rs.git --branch main
```

The default features turn signing and encryption on with RustCrypto.

To build messages without cryptography:

```sh
cargo add saml-rs --git https://github.com/salasebas/saml-rs.git --branch main --no-default-features
```

Signing, verification, and encryption then return `SamlError::Unsupported`.

## Next

- [Crypto provider](../guides/crypto-provider.md) if you need AWS-LC or FIPS.
- [Cargo features](../reference/features.md) for the full flag list.
