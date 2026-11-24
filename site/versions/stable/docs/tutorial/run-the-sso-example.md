---
title: "Run the example"
description: "You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository."
---

You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository.

## Run it

Clone the release and run the example from its repository root with current stable Rust.

```sh
git clone --branch v0.8.0 https://github.com/salasebas/saml-rs.git
cd saml-rs
cargo run -p saml-rs --example sso
```

The first build compiles the crate and bergshamra. The last line is:

```text
SP  <- authenticated   = alice@example.com
```

The request id changes every run. The example does not open a browser. It posts the same fields a browser would.

### Run on Rust 1.88

The release's `Cargo.lock` pins a version of `uuid` that requires Rust 1.89.
Select Rust 1.88 before you run these commands. If you use rustup, set a
toolchain override in the checkout with `rustup override set 1.88`.

```sh
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo update
cargo run -p saml-rs --example sso
```

`cargo update` rewrites the checkout's lockfile. Keep that change local.

## What it skips

The example has to compile on its own, so it imports unsigned metadata and does not store replay identifiers. A service you deploy pins the metadata signing certificate and passes a replay cache. That is [Service provider](../guides/service-provider-sso.md).

## Next

- Accept the login in your application: [Service provider](../guides/service-provider-sso.md).
- Issue the response yourself: [Identity provider](../guides/identity-provider-sso.md).
- Source of this lesson: [`examples/sso.rs`](https://github.com/salasebas/saml-rs/blob/v0.8.0/examples/sso.rs).
