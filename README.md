# saml-rs

[![crates.io](https://img.shields.io/crates/v/saml-rs.svg)](https://crates.io/crates/saml-rs)
[![docs.rs](https://img.shields.io/docsrs/saml-rs)](https://docs.rs/saml-rs)
[![codecov](https://codecov.io/gh/salasebas/saml-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/salasebas/saml-rs)
[![MIT licensed](https://img.shields.io/crates/l/saml-rs)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

Pure-Rust SAML 2.0 for service providers and identity providers: browser Web
SSO, metadata, and Single Logout. No `libxml2`, `xmlsec1`, or OpenSSL build
chain. XML signatures and encryption go through
[`bergshamra`](https://crates.io/crates/bergshamra).

> **Pre-1.0.** A minor release can change the API or runtime behaviour, and
> the crate has had no external security audit. Review it, your configuration,
> and your peers' metadata trust before production use.

## Project goals

- Follow the applicable SAML 2.0 requirements for each supported exchange.
  The [conformance index](docs/conformance/README.md) records the scope by
  role and binding, the choices the crate makes, and known gaps.
- Provide a typed Rust API for starting, receiving, and completing SAML
  exchanges. Expose deployment choices through named options.
- Fit into the application's web stack. The crate builds and validates SAML
  messages. Your application owns HTTP transport, user authentication,
  sessions, and storage.

## Install the published crate

```sh
cargo add saml-rs
```

Use Rust 1.88 or newer. To prefer dependencies compatible with your package's
`rust-version` during Cargo resolution, use resolver `"3"` or set
`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`. An existing lockfile
keeps its selections until you update them. The import path is `saml_rs`.

Follow the [Stable service provider guide](https://samlrs.vercel.app/guides/service-provider-sso/)
for the published API.

## Try the service provider API on main

Install from `main` to use the example below.

```sh
cargo add saml-rs --git https://github.com/salasebas/saml-rs.git --branch main
```

Use IdP metadata that advertises an HTTP-Redirect single sign-on endpoint.

```rust
use std::time::SystemTime;

use saml_rs::{
    AcsEndpoint, CertificatePem, EntityId, FormField, IdpDescriptor, Inbound, MetadataTrustPolicy,
    ReplayCache, ReplayPolicy, SamlError, SamlValidationContext, ServiceProvider, SpConfig,
    StartSso,
};

fn sign_in(
    idp_metadata_xml: &str,
    idp_metadata_signer: CertificatePem,
    replay_cache: &mut dyn ReplayCache,
    posted_form: Vec<FormField>,
) -> Result<(), SamlError> {
    let sp = ServiceProvider::new(
        SpConfig::builder(
            EntityId::try_new("https://sp.example.com/metadata")?,
            AcsEndpoint::post("https://sp.example.com/acs")?,
        )
        .build()?,
    );

    let idp = IdpDescriptor::from_metadata_xml(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp_metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: &[idp_metadata_signer],
        },
    )?;

    // Send the browser to `redirect_url` with `started.outbound.headers()`, and keep
    // `started.pending` in its session.
    let started = sp.start_sso(&idp, StartSso::redirect())?;
    let redirect_url = started.outbound.redirect_url()?;

    // Later, at the ACS: finish with the posted form and the stored pending value.
    let session = sp.finish_sso(
        &idp,
        &started.pending,
        Inbound::post(posted_form),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(replay_cache)),
    )?;
    if let Some(name_id) = session.name_id() {
        println!("{redirect_url} signed in {}", name_id.value());
    }
    Ok(())
}
```

Three choices in this example matter in production:

- **Validation preset.** `SpConfig::builder` starts on Recommended. Add a
  hardening or relax a rule by assigning the field that names it. See
  [validation presets](https://samlrs.vercel.app/next/explanation/validation-presets/).
- **Metadata trust.** `RequireSignature` pins the certificate that signs the
  IdP metadata. See
  [metadata trust](https://samlrs.vercel.app/next/reference/conformance/metadata-and-replay/#metadata-trust).
- **Replay cache.** HTTP-POST bearer assertions must not be replayed
  ([Profiles §4.1.4.5](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)).
  Use
  `InMemoryReplayCache`
  for a single process, shared across request handlers with a `Mutex`.
  It expires entries and supports a limit that refuses new keys when full.
  Its state is lost on restart. For multiple processes or protection across
  restarts, implement
  `ReplayCache`
  on storage that every ACS process shares. See
  [replay](docs/conformance/metadata-and-replay.md#replay).

To run both sides of a login from a checkout, follow the
[Next checkout tutorial](https://samlrs.vercel.app/next/tutorial/run-the-sso-example/).

## What main covers

| Area | Typed `ServiceProvider` and `IdentityProvider` API |
| --- | --- |
| Web SSO | The SP sends `AuthnRequest` over HTTP-POST, HTTP-Redirect, or HTTP-POST-SimpleSign. The IdP sends `Response` over HTTP-POST, HTTP-POST-SimpleSign, or HTTP-Artifact |
| Single Logout | HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign, and SOAP |
| Metadata | Parse peer metadata, generate SP and IdP metadata, verify signed metadata |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` |
| Name identifier management | HTTP-Redirect for both roles, SOAP for the identity provider |
| Identity Provider Discovery | The `_saml_idp` cookie |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through `bergshamra` |

The deployment sends SOAP HTTP requests itself. What each flow checks, and what
is out of scope, is in the [conformance records](docs/conformance/).

## Security

- `#![forbid(unsafe_code)]`.
- DOCTYPE and XXE rejection, with bounded XML parsing before authentication.
- Signature-wrapping checks on signed references, and signed metadata that
  must cover its root.
- Issuer, audience, destination, recipient, bearer confirmation, time window,
  and `InResponseTo` checks on responses.
- Bounded HTTP-Redirect DEFLATE output.
- Optional schema validation through `XmlPolicy::schema_validator`, scoped to
  each local role. It covers received protocol XML, SOAP envelopes,
  and decrypted protocol documents. Import peer metadata with
  `IdpDescriptor::from_metadata_xml_with_xml_policy` or
  `SpDescriptor::from_metadata_xml_with_xml_policy` to apply it there too. The
  callback runs after baseline parsing and can run multiple times per operation.
  No schema validator is installed by default. See
  [schema validation scope](docs/conformance/xml-schema-validation.md) and the
  [migration guide](docs/migrations/0.8-to-0.9/xml-policy.md).

To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## Features

The default `crypto-bergshamra` feature uses RustCrypto. AWS-LC and FIPS are
available with the default features off. Without a provider
(`--no-default-features`), the crate builds and parses messages, and signing,
verification, and encryption return `SamlError::Unsupported`. Details are in
[crypto providers on Next](https://samlrs.vercel.app/next/guides/crypto-provider/).

On `main`, the `serde` feature is off by default. It implements `Serialize` and
`Deserialize` for the pending snapshot types, so you can keep pending state in
a session store:

```rust,ignore
store.set(key, serde_json::to_string(&started.pending.snapshot())?)?;
```

The stored format is in
[Cargo features on Next](https://samlrs.vercel.app/next/reference/features/#serialize-pending-snapshots-with-serde).

## Documentation

| Need | Read |
| --- | --- |
| Guides | [Stable](https://samlrs.vercel.app), [Next](https://samlrs.vercel.app/next/) |
| Published API reference | [docs.rs](https://docs.rs/saml-rs/latest/saml_rs/) |
| Identity provider and logout examples | [`examples/sso.rs`](examples/sso.rs), [`examples/slo.rs`](examples/slo.rs) |
| Upgrade an existing integration | [Migration guides](docs/migrations/README.md) |
| See the rules each flow claims | [Conformance records](docs/conformance/README.md) |
| Contribute | [Contributing](CONTRIBUTING.md) |

The [`opensaml`](https://crates.io/crates/opensaml) and
[`samlet`](https://crates.io/crates/samlet) crates re-export this API under
other names. New code depends on `saml-rs`.
[`samlify`](https://crates.io/crates/samlify) is deprecated and will no longer
be maintained. Please use `saml-rs`.

## License

[MIT](LICENSE).
