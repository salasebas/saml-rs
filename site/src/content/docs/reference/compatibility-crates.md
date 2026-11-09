---
title: "Compatibility crates"
description: "New code depends on `saml-rs`. These three packages re-export the same API."
---

New code depends on `saml-rs`. These three packages re-export the same API.

| Package | Import | docs.rs |
| --- | --- | --- |
| [`opensaml`](https://crates.io/crates/opensaml) | `opensaml` | [docs](https://docs.rs/opensaml) |
| [`samlify`](https://crates.io/crates/samlify) | `samlify` | [docs](https://docs.rs/samlify) |
| [`samlet`](https://crates.io/crates/samlet) | `samlet` | [docs](https://docs.rs/samlet) |

`opensaml` still exports the deprecated `OpenSamlError` alias of `SamlError`. `opensaml`, `samlify`, and `samlet` are maintained with `saml-rs`.

These packages are separate from Shibboleth OpenSAML and from the Node.js samlify project. [`samael`](https://crates.io/crates/samael) is the other established Rust SAML crate. It commonly uses the native `xmlsec` stack.

An integration that still calls the raw types stays on `saml_rs::raw`. See [Raw API](../guides/raw-compatibility.md).
