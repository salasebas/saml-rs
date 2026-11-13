# Use a direct SHA-1 dependency for artifact SourceID

Status: accepted. Maintainer outcome: implementation plan approved on 2026-11-13.

The maintainer explicitly approved the dependency, API, and feature plan below
in the task conversation on 2026-11-13. This records the decision required by
issue [#523](https://github.com/salasebas/saml-rs/issues/523). Implementation
belongs to [#524](https://github.com/salasebas/saml-rs/issues/524). This change
adds documentation only. Closing #523 alone is not dependency approval; the
recorded outcome authorizes this scoped implementation plan.

## Decision

Replace the manual SHA-1 in `src/artifact.rs` with RustCrypto's `sha1` crate in
#524. The approved manifest entry is unconditional:

```toml
sha1 = { version = "0.11.0", default-features = false }
```

The audited version is exactly 0.11.0. The Cargo requirement permits compatible
0.11.x updates; `Cargo.lock` currently selects 0.11.0. Request no optional
features. Disabling defaults omits `sha1`'s `alloc` and `oid` requests, although
other dependencies can enable them through Cargo feature unification.
The one-shot API is `sha1::Sha1::digest(input)` through `sha1::Digest`, with
`.into()` producing `[u8; 20]`. This follows the
[official 0.11.0 example](https://docs.rs/sha1/0.11.0/sha1/#one-shot-api).

The [versioned manifest](https://github.com/RustCrypto/hashes/blob/sha1-v0.11.0/sha1/Cargo.toml)
declares Rust 1.85, below this package's Rust 1.88 MSRV. The pinned normal
dependency closure also declares MSRVs no greater than 1.85. This is a manifest
and graph audit, not a build on Rust 1.88.

## Alternatives

| Option | Decision rationale |
| --- | --- |
| Direct `sha1` 0.11.0, defaults off | Selected. Deletes the local hash implementation, its four implementation-vector tests, and their unused `hex` helper while keeping SourceID available without a crypto provider. Adds a direct dependency and expands three feature configurations described below. |
| Existing `bergshamra::crypto::digest::digest(uri, input)` | Available in Bergshamra 0.12.0 and returns `Result<Vec<u8>, Error>`. Its SHA-1 URI mapping is unconditional, not gated by `legacy-algorithms`. It dispatches to Kryptering 0.7.1, which requires provider initialization and support. Bergshamra is absent with no provider, and Kryptering's FIPS policy rejects SHA-1 digests. Reusing it would change availability and errors. |
| Keep the local SHA-1 implementation | Adds no dependencies and preserves every feature graph. Retains the 64-line primitive and four vector tests that a maintained crate can own. Rejected in favor of the maintained dependency. |

The existing abstraction and its limits come from the pinned
[Bergshamra digest implementation](https://github.com/kushaldas/bergshamra/blob/v0.12.0/crates/bergshamra-crypto/src/digest.rs),
[Kryptering digest dispatch](https://github.com/kushaldas/kryptering/blob/v0.7.1/src/digest.rs),
and [Kryptering provider policy](https://github.com/kushaldas/kryptering/blob/v0.7.1/src/backend.rs).
These APIs do not offer an always-available, provider-independent SourceID hash.

## Dependency and provider consequences

The pinned normal closure for `sha1` 0.11.0 includes `cfg-if` 1.0.4, `digest`
0.11.3, `block-buffer` 0.12.1, `crypto-common` 0.2.2, `hybrid-array` 0.4.13,
and `typenum` 1.20.1. `digest` enables its default `block-api` feature.
On aarch64, x86, and x86_64, `sha1` also selects `cpufeatures` 0.3.0.
On this audit's aarch64 Apple target, that adds an edge to `libc` 0.2.186,
which the package already uses. These are transitive dependencies even with
`sha1` defaults disabled.

A temporary copy of the workspace and lockfile was evaluated on
2026-11-13 at `eba129dc567c3c432732c9ec26bef331c5cff51b`, on
aarch64-apple-darwin with Cargo's existing lockfile resolution. Only the proposed
manifest entry differed. The resulting lockfile diff added exactly
`"sha1 0.11.0"` to `saml-rs`'s dependencies. No package, version, or checksum
changed.

| Configuration | Current `sha1` 0.11.0 | Newly selected normal package versions with the proposal |
| --- | --- | --- |
| Default RustCrypto | Present through Kryptering | None. Adds the direct edge and reuses the existing version and unified features. |
| `--no-default-features` | Absent | `sha1` 0.11.0, `digest` 0.11.3, `block-buffer` 0.12.1, `crypto-common` 0.2.2, `hybrid-array` 0.4.13, `typenum` 1.20.1, `cpufeatures` 0.3.0. |
| `--no-default-features --features crypto-aws-lc` | Absent | `sha1` 0.11.0, `digest` 0.11.3, `block-buffer` 0.12.1, `cpufeatures` 0.3.0. |
| `--no-default-features --features crypto-fips` | Absent | The same four package versions as AWS-LC. |

This deliberately adds a RustCrypto SHA-1 implementation outside the selected
XML crypto provider, including in FIPS builds. SourceID is a non-security
issuer identifier. The existing manual hash already runs outside that provider.
XML-DSig, XML-Enc, and detached signatures stay delegated to Bergshamra with
unchanged provider policy. This decision makes no FIPS certification or
validation claim for the hash, library, binary, or deployment. Deployments
that restrict all digest implementations to a validated module must assess
this dependency explicitly. Graph resolution does not prove provider runtime
support; Linux provider builds remain part of #524's validation.

## Protocol scope

The existing [artifact-issuance conformance row](../conformance/artifact-resolution.md#issuing-an-artifact)
owns this feature's normative note.

[OASIS SAML Bindings 3.6.4](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
recommends that the artifact issuer hash its identification URL with SHA-1 and
use the raw digest bytes. Section 3.6.4.2 defines the 20-byte SourceID and
requires distinct values for issuers sharing a receiver. The receiver uses
SourceID to locate a known issuer and resolution endpoint. That section does
not require receivers to reject every value other than an entity ID's hash.
[Approved Errata 05 E4](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html)
clarifies the permitted artifact formats and leaves the hash recommendation
unchanged. SourceID is a binary binding field, so no XML schema rule changes.

The approved implementation preserves the existing issuer bytes and raw
20-byte SHA-1 result. It introduces no receiver rejection, SHA-256 replacement,
new error, or public API change. SHA-1 remains unsuitable for security-critical
hashing, as the crate's documentation warns.

## Approved implementation plan for #524

In #524, add the approved dependency, replace the
local hash with the crate API, and remove the four local vector tests and their
now-unused `hex` test helper.
Retain `artifact_source_id_is_the_sha1_of_the_issuer_entity_id` in
`tests/artifact_resolution.rs`. Its expected bytes come from an independent
Python `hashlib` vector. Preserve artifact format, issuer bytes, error behavior,
and artifact support without a crypto provider.

Run focused artifact unit, `artifact_resolution`, and `artifact_sso` tests,
formatting, Clippy, the no-default-features check, applicable doctests and
rustdoc checks, and the Linux provider matrix required by #524. Local checks
for this documentation-only decision did not run the full suite or provider
builds. This PR's CI validates the existing manifest and implementation;
it does not validate the future #524 implementation.

## Audit commands

Inspect the pinned registry manifests and sources for `sha1` 0.11.0,
`bergshamra-crypto` 0.12.0, and `kryptering` 0.7.1. Reproduce the graph comparison
on both the unchanged workspace and a temporary copy with the proposed entry:

```text
cargo tree --offline -p saml-rs -i sha1@0.11.0 [configuration flags]
cargo tree --offline -p saml-rs -e normal --prefix none --format '{p}' [configuration flags]
cargo tree --offline -p saml-rs --no-default-features -e features -i sha1@0.11.0
diff -u Cargo.lock <temporary-copy>/Cargo.lock
```

Use each configuration in the table. The initial reverse query exits 101 for
absent packages in the three non-default configurations; all proposed reverse
queries exit 0. The feature query confirms no `sha1` feature is requested by
the proposed direct dependency without a provider. The experiment leaves the
repository's manifest, lockfile, and production code unchanged.
