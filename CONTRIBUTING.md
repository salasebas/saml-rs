# Contributing

`saml-rs` is an independent, unofficial Rust SAML 2.0 Service Provider and
Identity Provider toolkit.

## How to set up

```bash
cargo install --locked cargo-nextest
```

All published workspace packages require Rust 1.88. The default
`crypto-bergshamra` feature uses `bergshamra` 0.12 with `kryptering` 0.7 and
preserves the RustCrypto-backed defaults.

## How to run the checks

Verify the package plus plausible side effects:

```bash
cargo fmt --all --check
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps
cargo test -p saml-rs --doc --no-default-features
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps --no-default-features
cargo check -p saml-rs --no-default-features
cargo nextest run -p saml-rs --no-default-features --features crypto-rustcrypto
```

`--all-features` does not apply. Document-crypto providers are mutually
exclusive. AWS-LC, FIPS, and provider-specific rustdoc run in the Linux
`provider-matrix` job in `.github/workflows/ci.yml`.

`unwrap_used`, `expect_used`, and `panic` are package `warn` lints, so under
`-D warnings` they fail the build, including tests. In tests, return
`Result<_, Box<dyn std::error::Error>>` and use `?` rather than `.unwrap()`.

## How to change SAML behaviour

1. Ground the change in the SAML specifications or targeted interoperability
   evidence. The review steps are in
   [How to review a SAML change](docs/how-to-review-saml-behaviour.md). The
   reasons for those checks are in
   [standards conformance](docs/standards-conformance.md).
2. Write a focused Rust test.
3. Implement an idiomatic Rust equivalent with explicit errors.
4. Keep XML cryptography (XML-DSig, XML-Enc, C14N) delegated to `bergshamra`
   behind the optional `crypto-bergshamra` feature.

A security-sensitive fix includes a regression test and fails closed with an
explicit `SamlError` variant where practical. The sensitive surface is listed
in [Security](SECURITY.md#scope).

Propose new dependencies before adding them, and keep optional integrations
behind feature flags. Generated or vendor trees stay out of the repository.

Historical fixture provenance is recorded in
[`tests/fixtures/PROVENANCE.md`](tests/fixtures/PROVENANCE.md).

## How to add a migration guide

Add a guide in the same change that forces consumers to change code, runtime
behaviour, feature flags, or the minimum supported Rust version. Name the file
after that boundary, such as `docs/migrations/0.2-to-0.3.md`, and cover the
move from the latest patch of the source minor release.

In the guide, state what breaks, who must change, and the steps to upgrade.
Leave compatible features out; the changelog records those. Link the new guide
from [How to upgrade saml-rs](docs/migrations/README.md).

## How to open a pull request

Use a conventional commit-style title where possible: `fix: ...`, `feat: ...`,
or `feat!: ...`.
