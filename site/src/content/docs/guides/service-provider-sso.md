---
title: "Service provider"
description: "Accept a browser login. You already have an identity provider, an assertion consumer URL, and a signing credential."
---

Accept a browser login. You already have an identity provider, an assertion consumer URL, and a signing credential.

Keep the `Pending<_>` value with the browser session until the person returns.

## Calls

1. Build `SpConfig` and call `Saml::sp`.
2. Import the identity provider metadata, pinned to the certificate you trust.
3. Call `start_sso`. Store `started.pending`, and send `started.outbound` to the browser.
4. When the browser posts back, load that pending value and call `finish_sso`.

```rust
let sp = Saml::sp(
    SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(credentials)
        .validation(SpValidationPolicy::recommended())
        .build()?,
)?;

let idp = IdpDescriptor::from_metadata_xml_for(
    EntityId::try_new("https://idp.example.com/metadata")?,
    idp_metadata_xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &[metadata_signing_cert],
    },
)?;

let started = sp.start_sso(&idp, StartSso::redirect())?;
store_with_session(started.pending.snapshot());
send_to_browser(started.outbound);

let validation = SamlValidationContext::new(
    now,
    ReplayPolicy::RequireCache(&mut replay_cache),
);
let pending = Pending::<AuthnRequest>::from_snapshot(load_snapshot())?;
let session = sp.finish_sso(
    &idp,
    &pending,
    BrowserInput::<SsoResponse>::post(form_fields),
    validation,
)?;

let name_id = session.subject().name_id().value();
```

`credentials`, `idp_metadata_xml`, `metadata_signing_cert`, `now`, `replay_cache`, and `form_fields` come from your application. The block omits `use` and `fn main`. It is the shape of the calls, not a file that compiles alone. `session` is an `SsoSession`.

`session.attributes()` holds the attributes of the assertion. `Attribute::format()` is the attribute's `AttributeNameFormat`, and is `None` when the identity provider sent no `NameFormat`. A persistent or transient name identifier is reported as it was sent. The rules are in [SAML-defined identifiers](../reference/conformance/identifiers.md).

`start_sso` also accepts `StartSso::post()` and `StartSso::simple_sign()`. Those constructors leave the generation rules off. Call `apply_web_browser_sso_generation_rules()` when you want the producer rules in [SSO generation](../reference/conformance/web-browser-sso-generation.md).

## Replay

`ReplayPolicy::RequireCache` stores identifiers in the cache you pass. The context has no hidden cache. `ReplayPolicy::DisabledForCompatibility` stores nothing. The rules are in [Metadata and replay](../reference/conformance/metadata-and-replay.md).

A new validation context allows five minutes of clock skew. Pass `ClockSkew::strict()` for zero skew.

## Signatures

`recommended()` is the preset for claimed features. It does not require a signature on the Assertion, and it does not select the RSA-SHA2 XML-DSig profile. Add either one by name. The calls are in [Validation](validation-preset.md).

`finish_sso` records embedded XML signature evidence on `verified_xml_signatures()`. `sig_alg()` is only the detached `SigAlg` from HTTP-Redirect or HTTP-POST-SimpleSign.

## Next

```sh
cargo run -p saml-rs --example sso
```

The same calls, checked by `cargo test --doc`, are in the [crate-root SSO example](https://docs.rs/saml-rs/latest/saml_rs/#sp-initiated-sso).

Issue the response with [Identity provider](identity-provider-sso.md). End the session with [Single Logout](single-logout.md).
