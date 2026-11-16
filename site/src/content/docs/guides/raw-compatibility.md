---
title: "Raw API"
description: "Use this when an existing integration still calls `ServiceProvider`, `IdentityProvider`, `HttpRequest`, or `BindingContext`."
---

Use this when an existing integration still calls `ServiceProvider`, `IdentityProvider`, `HttpRequest`, or `BindingContext`.

```rust
use saml_rs::raw;
```

The runnable shape is [`examples/raw_compat.rs`](https://github.com/salasebas/saml-rs/blob/main/examples/raw_compat.rs).

The raw API is deprecated and is removed in the next minor release. Each raw message function warns with its typed replacement. New login and logout code uses `Saml::<Sp>` and `Saml::<Idp>`. Raw settings keep their historical defaults. A typed preset change does not rewrite them.

`opensaml` still exports the deprecated `OpenSamlError` alias of `SamlError`. The package names are in [Compatibility crates](../reference/compatibility-crates.md).
