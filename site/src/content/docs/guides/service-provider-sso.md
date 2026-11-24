---
title: "Service provider"
description: "Accept a browser login. You already have an identity provider, an assertion consumer URL, and a signing credential."
---

Accept a browser login. You already have an identity provider, an assertion consumer URL, and a signing credential.

Keep the `Pending<_>` value with the browser session until the person returns.

## Calls

1. Build `SpConfig` and pass it to `ServiceProvider::new`.
2. Import the identity provider metadata, pinned to the certificate you trust.
3. Call `start_sso`. Store `started.pending`, and send `started.outbound` to the browser.
4. When the browser posts back, load that pending value and call `finish_sso`.

```rust
let sp = ServiceProvider::new(
    SpConfig::builder(
        EntityId::try_new("https://sp.example.com/metadata")?,
        AcsEndpoint::post("https://sp.example.com/acs")?,
    )
    .credentials(credentials)
    .build()?,
);

let idp = IdpDescriptor::from_metadata_xml(
    EntityId::try_new("https://idp.example.com/metadata")?,
    idp_metadata_xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &[metadata_signing_cert],
    },
)?;

let started = sp.start_sso(&idp, StartSso::post())?;
store_with_session(started.pending.snapshot());
send_to_browser(started.outbound);

let validation = SamlValidationContext::new(
    now,
    ReplayPolicy::RequireCache(&mut replay_cache),
);
let pending = PendingAuthnRequest::from_snapshot(load_snapshot())?;
let session = sp.finish_sso(
    &idp,
    &pending,
    Inbound::post(form_fields),
    validation,
)?;

let name_id = session.name_id().value();
```

`credentials`, `idp_metadata_xml`, `metadata_signing_cert`, `now`, `replay_cache`, and `form_fields` come from your application. The block omits `use` and `fn main`. It is the shape of the calls, not a file that compiles alone. `session` is an `SsoSession`.

With the `serde` feature, the snapshot serializes to JSON for your session store. `finish_sso` trusts the snapshot to name the request the response answers, so keep it on the server, or authenticate it when the browser carries it. The stored format is in [Cargo features](../reference/features.md#serialize-pending-snapshots-with-serde).

`session.attributes()` holds the attributes of the assertion. `first_value("mail")` returns the first value of the first attribute named `mail`. `Attribute::name_format()` is the attribute's `AttributeNameFormat`, and is `None` when the identity provider sent no `NameFormat`. `Attribute::friendly_name()` is its `FriendlyName`, and `get_by_friendly_name("mail")` finds the first attribute with that label. The identity provider chooses the label, and two attributes can share it, so select an attribute that decides access by its `Name` and `NameFormat`. A persistent or transient name identifier is reported as it was sent. The rules are in [SAML-defined identifiers](../reference/conformance/identifiers.md).

`session.subject_id()` and `session.pairwise_id()` return the `subject-id` and `pairwise-id` attributes as a `SubjectId` and a `PairwiseId`. Each returns `None` when the assertion does not have the attribute, and `SamlError::ProtocolProfile` when the value is malformed. Two identifiers that differ only in case are equal. Another identity provider can send the same `pairwise-id` value for another subject, so key an account on the issuer together with the value.

Before you use an identifier, call `session.scoped_attribute_violations()` with the attribute's SAML name and an issuer-specific policy. With local configuration, pass `AttributeScopePolicy::Explicit` with the configured issuer and allowed scopes. For federation metadata, import the descriptor with `MetadataTrustPolicy::RequireRegistrationAuthoritySignature` and pass it in `AttributeScopePolicy::RegistrationAuthority`. Pin the trusted authority's certificate independently of the IdP. The policy compares literal scopes case-sensitively and reports each value to discard or reject before account lookup. See [scoped attributes](../reference/conformance/web-browser-sso-acceptance.md#scoped-attributes).

The paired [identity provider guide](identity-provider-sso.md) publishes an HTTP-POST SSO endpoint. For another IdP, match the request binding to a `SingleSignOnService` in its metadata. Use `StartSso::redirect()` for HTTP-Redirect or `StartSso::simple_sign()` for HTTP-POST-SimpleSign. All three constructors enforce the producer rules in [SSO generation](../reference/conformance/web-browser-sso-generation.md).

## Cap the application session

After SSO succeeds, set your local session's expiry to the earlier of your application's deadline and the deadline from `session.session_not_on_or_after()`. The method returns the earliest `SessionNotOnOrAfter` in the consumed assertion before validation clock skew. If the identity provider sent no deadline, use your application's deadline.

```rust
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

let expires_at = match session.session_not_on_or_after() {
	Some(bound) => local_deadline.min(OffsetDateTime::parse(bound.as_str(), &Rfc3339)?),
	None => local_deadline,
};
```

This example uses the `time` crate with the `parsing` feature and an `OffsetDateTime` for `local_deadline`. If `expires_at` has already passed, require a new login before you create a local session. Use `session.not_on_or_after()` for the assertion's `Conditions@NotOnOrAfter`.

## Replay

HTTP-POST SSO requires `ReplayPolicy::RequireCache`. Reuse the cache across requests. If several nodes accept logins, use shared storage that atomically records each identifier. A duplicate, a missing cache, or a storage failure prevents acceptance. The rules are in [Metadata and replay](../reference/conformance/metadata-and-replay.md).

A new validation context allows five minutes of clock skew. Pass `ClockSkew::strict()` for zero skew.

## Signatures

The builder uses the recommended policy by default. It does not require a signature on the Assertion, and it does not select the RSA-SHA2 XML-DSig profile. Add either one by name. The calls are in [Validation](validation-preset.md).

`finish_sso` records embedded XML signature evidence on `verified_xml_signatures()`. `binding_signature_algorithm_uri()` is only the `SigAlg` of an HTTP-POST-SimpleSign signature, which travels next to the message instead of inside the XML.

## Next

Follow [Run the example](../tutorial/run-the-sso-example.md) to run both sides from a checkout.

The same calls are in the [crate-root SSO example](https://github.com/salasebas/saml-rs/blob/main/src/lib.rs). Run `cargo doc -p saml-rs --open` from the repository root to read the API reference for `main`.

Issue the response with [Identity provider](identity-provider-sso.md). End the session with [Single Logout](single-logout.md).
