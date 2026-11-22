# samlify

[![crates.io](https://img.shields.io/crates/v/samlify.svg)](https://crates.io/crates/samlify)
[![docs.rs](https://img.shields.io/docsrs/samlify)](https://docs.rs/samlify)
[![MIT licensed](https://img.shields.io/crates/l/samlify)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)

**Deprecated.** `samlify` will no longer be maintained. Please use
[`saml-rs`](https://crates.io/crates/saml-rs).

In `Cargo.toml`, rename the `samlify` key to `saml-rs`. Keep its version,
`default-features`, and `features`, so the same crypto provider stays
selected:

```toml
[dependencies]
# Before
samlify = { version = "…", default-features = false, features = ["crypto-rustcrypto"] }
# Now
saml-rs = { version = "…", default-features = false, features = ["crypto-rustcrypto"] }
```

Then change the import path from `samlify` to `saml_rs`:

```rust
use saml_rs::{IdentityProvider, ServiceProvider};
```

The API and the feature flags are the same.

This package remains a compatibility re-export, so existing dependencies keep
resolving. Do not add `samlify` to a new project. This package is not the
Node.js samlify project.

The implementation, examples, and issue tracker are in
[salasebas/saml-rs](https://github.com/salasebas/saml-rs).

**Help:** [open an issue](https://github.com/salasebas/saml-rs/issues) on the
source repository.

## Use saml-rs

Follow the [saml-rs guide](https://github.com/salasebas/saml-rs/blob/main/README.md):

- [Signed SSO example](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs)
- [Single Logout example](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs)
- [API reference](https://docs.rs/saml-rs)
- [Migration guides](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/README.md)

From a clone of the source repository:

```sh
cargo run -p saml-rs --example sso
```

## Security

Read the
[saml-rs security notes](https://github.com/salasebas/saml-rs/blob/main/README.md#security)
before production use. This crate has not had an external security audit.

## License

[MIT](https://github.com/salasebas/saml-rs/blob/main/LICENSE).
