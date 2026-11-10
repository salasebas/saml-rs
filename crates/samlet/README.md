# samlet

[![crates.io](https://img.shields.io/crates/v/samlet.svg)](https://crates.io/crates/samlet)
[![docs.rs](https://img.shields.io/docsrs/samlet)](https://docs.rs/samlet)
[![MIT licensed](https://img.shields.io/crates/l/samlet)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)

Compatibility re-export of [`saml-rs`](https://crates.io/crates/saml-rs). The
implementation, examples, and issue tracker are in
[salasebas/saml-rs](https://github.com/salasebas/saml-rs).

It is maintained with `saml-rs` and is pre-1.0. The import path is `samlet`.
There has been no external security audit.

New code depends on `saml-rs`. Keep `samlet` when an existing dependency
already uses this name.

**Help:** [open an issue](https://github.com/salasebas/saml-rs/issues) on the
source repository.

## How to keep an existing dependency

```sh
cargo add samlet
```

```rust
use samlet::{Saml, Sp};
```

Feature flags match `saml-rs` and are forwarded to it. With
`default-features = false`, select one crypto provider before calling signing
or encryption APIs. The feature list is in the
[saml-rs README](https://github.com/salasebas/saml-rs/blob/main/README.md#features).

## How to use the re-exported API

Follow the [saml-rs guide](https://github.com/salasebas/saml-rs/blob/main/README.md)
for service-provider SSO, logout, and upgrades:

- [Signed SSO example](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs)
- [Single Logout example](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs)
- [API reference](https://docs.rs/samlet)
- [Migration guides](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/README.md)

From a clone of the source repository:

```sh
cargo run -p saml-rs --example sso
```

## Security

`samlet` 0.5 and later forbid unsafe code and re-export the `saml-rs`
validation and crypto policy. The properties are the
[saml-rs security notes](https://github.com/salasebas/saml-rs/blob/main/README.md#security).

## License

[MIT](https://github.com/salasebas/saml-rs/blob/main/LICENSE).
