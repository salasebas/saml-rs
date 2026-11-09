---
title: "Run the example"
description: "You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository."
---

You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository.

## Run it

From the repository root:

```sh
cargo run -p saml-rs --example sso
```

The first build compiles the crate and bergshamra. The last line is:

```text
SP  <- authenticated   = alice@example.com
```

The request id changes every run. The example does not open a browser. It posts the same fields a browser would.

## What it skips

The example has to compile on its own, so it imports unsigned metadata and does not store replay identifiers. A service you deploy pins the metadata signing certificate and passes a replay cache. That is [Service provider](../guides/service-provider-sso.md).

## Next

- Accept the login in your application: [Service provider](../guides/service-provider-sso.md).
- Issue the response yourself: [Identity provider](../guides/identity-provider-sso.md).
- Source of this lesson: [`examples/sso.rs`](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs).
