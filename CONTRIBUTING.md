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

## Raise the MSRV only when needed

CI tests the `rust-version` in `Cargo.toml` and the latest stable Rust.
Raise it only when a needed language or standard library feature, or a
dependency with no compatible version, requires it. Keep it at least six
stable releases behind the latest. Make the change a breaking Conventional
Commit (`!`) with a note in the current [migration guide](docs/migrations/README.md).

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
cargo nextest run -p saml-rs --features serde
```

`--all-features` does not apply. Document-crypto providers are mutually
exclusive. AWS-LC, FIPS, and provider-specific rustdoc run in the Linux
`provider-matrix` job in `.github/workflows/ci.yml`.

`unwrap_used`, `expect_used`, and `panic` are package `warn` lints, so under
`-D warnings` they fail the build, including tests. In tests, return
`Result<_, Box<dyn std::error::Error>>` and use `?` rather than `.unwrap()`.

## How to change SAML behaviour

1. Ground the change in the SAML specifications or targeted interoperability
   evidence, and answer the review checklist in
   [standards conformance](docs/standards-conformance.md#review-checklist).
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
behaviour, feature flags, or the minimum supported Rust version. Cover the
upgrade from the latest patch of the source minor release.

Put the guide in the directory of the upgrade that the change belongs to. The
directory is named `<current>.x-to-<next>.0`, where `<current>` is the latest
published minor release and `<next>` is the release that ships the change. For
example, the guides for 0.8.0 are in `docs/migrations/0.7.x-to-0.8.0/`. Name the
guide's file for what it covers, such as `metadata-api.md`, without an
`unreleased-` prefix. Link the file from the directory's `README.md`.

If the directory does not exist yet, create it with an overview in `README.md`.
Link that `README.md` from [How to upgrade saml-rs](docs/migrations/README.md),
with the title `How to upgrade from X to Y`. If the upgrade has only one short
topic, keep it in that `README.md`.

In the guide, state what breaks, who must change, and the steps to upgrade.
The changelog records compatible features.

## How to open a pull request

Use a conventional commit-style title where possible: `fix: ...`, `feat: ...`,
or `feat!: ...`.
