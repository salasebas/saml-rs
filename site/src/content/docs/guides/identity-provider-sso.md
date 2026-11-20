---
title: "Identity provider"
description: "Issue a browser SSO response. You already have a service-provider peer, an SSO URL, and a signing credential."
---

Issue a browser SSO response. You already have a service-provider peer, an SSO URL, and a signing credential.

## Calls

1. Build `IdpConfig` and call `Saml::idp`.
2. Import the service provider metadata.
3. Call `receive_sso` with the browser fields from the `AuthnRequest`.
4. Call `respond_sso` with an `SsoAssertion` for the subject you authenticated.

```rust
let idp = Saml::idp(
    IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .credentials(credentials)
    .validation(IdpValidationPolicy::recommended())
    .build()?,
);

let sp = SpDescriptor::from_metadata_xml(
    EntityId::try_new("https://sp.example.com/metadata")?,
    sp_metadata_xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &[metadata_signing_cert],
    },
)?;

let request = idp.receive_sso(
    &sp,
    Inbound::post(request_fields),
    validation,
)?;

let response = idp.respond_sso(
    &sp,
    &request,
    SsoAssertion::new(NameId::new("alice@example.com")),
    RespondSso::post().apply_producer_rules(),
)?;
```

Send `response` back through the browser to the service provider's assertion consumer service. The identity provider writes the assertion `Subject` itself: the `NameId` of the `SsoAssertion` and one bearer `SubjectConfirmation`.

The third argument says what the response reports. `RespondSso` says how it is delivered and signed, and whether the generation rules apply. When the user cannot be authenticated, answer with an error status and no assertion:

```rust
let response = idp.respond_sso(
    &sp,
    &request,
    SsoOutcome::Failure(Status::responder()),
    RespondSso::post().apply_producer_rules(),
)?;
```

A failure with the top-level `Success` status is rejected with `SamlError::Invalid`, because a successful response carries an assertion.

The response carries the exact `RelayState` that arrived with the request. `RespondSso::relay_state` sets one only for an unsolicited response or for a request that carried none.

`post()`, `redirect()`, and `simple_sign()` leave the generation rules off until you call `apply_producer_rules()`. Those rules are the producer rows in [SSO generation](../reference/conformance/web-browser-sso-generation.md).

## Encrypted assertions

A typed identity provider signs the Response when it generates an `EncryptedAssertion` with a known CBC-mode algorithm. That follows Approved Errata 05 E93. To keep an unsigned CBC response for a legacy peer:

```rust
let response = idp.respond_sso(
    &sp,
    &request,
    SsoAssertion::new(name_id),
    RespondSso::post().allow_unsigned_encrypted_cbc(),
)?;
```

`allow_unsigned_encrypted_cbc()` relaxes that recommendation only. It is not the Compatibility preset. A service provider that already requires the signature still rejects the relaxed response.

Assertion encryption stays off until you set `XmlEncryptionPolicy::assertions` to `AssertionEncryptionPolicy::EncryptAssertions`.

## Attributes and name identifiers

Pass the attributes with `SsoAssertion::with_attributes`. `with_name_format` sets an attribute's format: `Unspecified`, `Uri`, `Basic`, or `Custom` for another URI. An attribute without it has no `NameFormat`, which SAML reads as `Unspecified`.

```rust
let attributes = Attributes::new([
    Attribute::new(
        "urn:oid:0.9.2342.19200300.100.1.3",
        [AttributeValue::new("alice@example.com")],
    )
    .with_name_format(AttributeNameFormat::Uri),
    Attribute::new(
        "eduPersonAffiliation",
        [AttributeValue::new("member"), AttributeValue::new("staff")],
    )
    .with_name_format(AttributeNameFormat::Basic),
]);

let response = idp.respond_sso(
    &sp,
    &request,
    SsoAssertion::new(NameId::generate_transient()).with_attributes(attributes),
    RespondSso::post(),
)?;
```

A `Basic` name that is not an XML name is rejected. `with_attributes` cannot be combined with an SSO response template set with `IdpConfigBuilder::sso_response_template`.

`NameId::generate_transient()` returns a new opaque value on every call. For a persistent identifier, call `NameId::generate_persistent()` once for a principal and service provider, store the value, and pass it to `NameId::persistent(stored)` on later responses. Do not issue a stored value for another principal. `NameId::new` takes any value and `with_format` takes any format, but a persistent or transient value longer than 256 characters is rejected when the response is generated. `with_name_qualifier`, `with_sp_name_qualifier`, and `with_sp_provided_id` set the qualifier attributes. The rules are in [SAML-defined identifiers](../reference/conformance/identifiers.md).

## Discovery cookie

After authentication, ask the identity provider above for the `_saml_idp` cookie and write the header yourself. `respond_sso` does not write it. A service provider has no method that sets or reads it.

```rust
let cookie = idp.common_domain_cookie(RememberIdentityProvider::new(
    "example.org",
    CommonDomainCookieLifetime::Session,
))?;
```

Pass the common domain without a leading period. The cookie domain is `.example.org`, the path is `/`, and the cookie is `Secure`. The rules are in [Identity Provider Discovery](../reference/conformance/identity-provider-discovery.md).

## Next

The paired flow is [Service provider](service-provider-sso.md). A round trip that includes logout is [`examples/slo.rs`](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs).
