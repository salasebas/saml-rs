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

## Install

```sh
cargo add saml-rs
```

Rust 1.88 or newer. The import path is `saml_rs`.

## Quick start: service provider login

```rust
use std::time::SystemTime;

use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, EntityId, FormField, IdpDescriptor,
    MetadataTrustPolicy, ReplayCache, ReplayPolicy, Saml, SamlError, SamlValidationContext,
    SpConfig, SsoResponse, StartSso,
};

fn sign_in(
    idp_metadata_xml: &str,
    idp_metadata_signer: CertificatePem,
    replay_cache: &mut dyn ReplayCache,
    posted_form: Vec<FormField>,
) -> Result<(), SamlError> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .build()?,
    )?;

    let idp = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp_metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: &[idp_metadata_signer],
        },
    )?;

    // Send the browser to `redirect_url` and keep `started.pending` in its session.
    let started = sp.start_sso(&idp, StartSso::redirect())?;
    let redirect_url = started.outbound.redirect_url()?;

    // Later, at the ACS: finish with the posted form and the stored pending value.
    let session = sp.finish_sso(
        &idp,
        &started.pending,
        BrowserInput::<SsoResponse>::post(posted_form),
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(replay_cache)),
    )?;
    println!("{redirect_url} signed in {}", session.name_id().value());
    Ok(())
}
```

Three choices in this example matter in production:

- **Validation preset.** `SpConfig::builder` starts on Recommended. Add
  hardenings as fields, or pick `compatibility()` by name. See
  [validation presets](docs/adr/0002-validation-presets.md).
- **Metadata trust.** `RequireSignature` pins the certificate that signs the
  IdP metadata. See
  [metadata trust](https://docs.rs/saml-rs/latest/saml_rs/#metadata-trust).
- **Replay cache.** HTTP-POST bearer assertions must not be replayed
  ([Profiles §4.1.4.5](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)).
  Use
  [`InMemoryReplayCache`](https://docs.rs/saml-rs/latest/saml_rs/model/struct.InMemoryReplayCache.html)
  for a single process, shared across request handlers with a `Mutex`.
  It expires entries and supports a limit that refuses new keys when full.
  Its state is lost on restart. For multiple processes or protection across
  restarts, implement
  [`ReplayCache`](https://docs.rs/saml-rs/latest/saml_rs/model/trait.ReplayCache.html)
  on storage that every ACS process shares. See
  [replay](docs/conformance/metadata-and-replay.md#replay).

Run a full SP → IdP → SP round trip:

```sh
cargo run -p saml-rs --example sso
```

## What it covers

| Area | Typed `Saml` API |
| --- | --- |
| Web SSO | `AuthnRequest` and `Response` over HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign, and HTTP-Artifact responses |
| Enhanced Client/Proxy | Service provider and identity provider over PAOS |
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
- Optional schema validation through `context::set_schema_validator`.

To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## Features

The default `crypto-bergshamra` feature uses RustCrypto. AWS-LC and FIPS are
available with the default features off. Without a provider
(`--no-default-features`), the crate builds and parses messages, and signing,
verification, and encryption return `SamlError::Unsupported`. Details are in
[crypto providers](docs/crypto-providers.md).

## Documentation

| Need | Read |
| --- | --- |
| Guides | [samlrs.vercel.app](https://samlrs.vercel.app) |
| API reference | [docs.rs](https://docs.rs/saml-rs/latest/saml_rs/) |
| Identity provider and logout examples | [`examples/sso.rs`](examples/sso.rs), [`examples/slo.rs`](examples/slo.rs) |
| Upgrade an existing integration | [Migration guides](docs/migrations/README.md) |
| Keep a `ServiceProvider` / `IdentityProvider` integration | [`saml_rs::raw`](examples/raw_compat.rs) |
| Choose a crypto provider | [Crypto providers](docs/crypto-providers.md) |
| See the rules each flow claims | [Conformance records](docs/conformance/) |
| Contribute | [Contributing](CONTRIBUTING.md) |

The [`opensaml`](https://crates.io/crates/opensaml),
[`samlify`](https://crates.io/crates/samlify), and
[`samlet`](https://crates.io/crates/samlet) crates re-export this API under
other names. New code depends on `saml-rs`.

## License

[MIT](LICENSE).
