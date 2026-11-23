---
title: "Run the example"
description: "You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository."
---

You will run one program that plays both sides of a login. It prints `alice@example.com`. You need Rust 1.88 or newer and a checkout of this repository.

## Run it

From a checkout of `main`, run the example from the repository root.

```sh
cargo run -p saml-rs --example sso
```

The first build compiles the crate and bergshamra. The last line is:

```text
SP  <- authenticated   = alice@example.com
```

The request id changes every run. The example does not open a browser. It posts the same fields a browser would.

## Replay storage and metadata trust

The example imports unsigned metadata and keeps replay identifiers in memory for one run. In a deployment, pin the metadata signing certificate and share the replay cache across requests. See the [service provider guide](../guides/service-provider-sso.md).

## Next

- Accept the login in your application: [Service provider](../guides/service-provider-sso.md).
- Issue the response yourself: [Identity provider](../guides/identity-provider-sso.md).
- Source of this lesson: [`examples/sso.rs`](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs).
