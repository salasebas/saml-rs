---
title: "Identity provider"
description: "Issue a browser SSO response. You already have a service-provider peer, an SSO URL, and a signing credential."
---

Issue a browser SSO response. You already have a service-provider peer, an SSO URL, and a signing credential.

## Calls

1. Build `IdpConfig` and pass it to `IdentityProvider::new`.
2. Import the service provider metadata.
3. Call `receive_sso` with the browser fields from the `AuthnRequest`.
4. Call `respond_sso` with an `SsoAssertion` for the subject you authenticated.

```rust
let idp = IdentityProvider::new(
    IdpConfig::builder(
        EntityId::try_new("https://idp.example.com/metadata")?,
        SsoEndpoint::post("https://idp.example.com/sso")?,
    )
    .credentials(credentials)
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

let name_id = NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress);
let response = idp.respond_sso(
    &sp,
    &request,
    SsoAssertion::new(name_id),
    RespondSso::post(),
)?;
```

Send `response` back through the browser to the service provider's assertion consumer service. The identity provider writes the assertion `Subject` itself: the `NameId` of the `SsoAssertion` and one bearer `SubjectConfirmation`.

The third argument says what the response reports. `RespondSso` says how it is delivered and signed. When the user cannot be authenticated, answer with an error status and no assertion:

```rust
let response = idp.respond_sso(
    &sp,
    &request,
    SsoOutcome::Failure(Status::responder()),
    RespondSso::post(),
)?;
```

A failure with the top-level `Success` status is rejected with `SamlError::Invalid`, because a successful response carries an assertion.

The response carries the exact `RelayState` that arrived with the request. `RespondSso::relay_state` sets one only for an unsolicited response or for a request that carried none.

A successful response carries an authentication statement. An IdP that advertises Single Logout includes its session index. See [SSO generation](../reference/conformance/web-browser-sso-generation.md).

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

`allow_unsigned_encrypted_cbc()` relaxes that recommendation only. A service provider that already requires the signature still rejects the relaxed response.

Assertion encryption stays off until you set `XmlEncryptionPolicy::assertions` to `AssertionEncryptionPolicy::EncryptAssertions`.

When `NameIDPolicy` requests `encrypted`, set `XmlEncryptionPolicy::identifiers` to `IdentifierEncryptionPolicy::EncryptIdentifiers` and use SP metadata with an encryption certificate. Pass the identifier in its actual format. The assertion subject contains `EncryptedID`. If you cannot meet the policy, send `SsoOutcome::Failure` with an error status.

## Attributes and name identifiers

Use `request.message().name_id_policy()` to read the requested format. If the request names a specific standard format, supply an identifier in that format for the authenticated principal. When a requested `SPNameQualifier` applies, pass it with `with_sp_name_qualifier`.

If the request combines the `entity` format with `SPNameQualifier`, send a failure outcome. SAML requires entity identifiers to omit qualifiers.

Pass the attributes with `SsoAssertion::attributes`. `with_name_format` sets an attribute's format: `Unspecified`, `Uri`, `Basic`, or `Custom` for another URI. An attribute without it has no `NameFormat`, which SAML reads as `Unspecified`.

`with_friendly_name` adds a `FriendlyName`, a readable label such as `mail` for an OID name. The service provider still identifies the attribute by its `Name` and `NameFormat`.

```rust
let attributes = Attributes::new([
    Attribute::new(
        "urn:oid:0.9.2342.19200300.100.1.3",
        [AttributeValue::new("alice@example.com")],
    )
    .with_name_format(AttributeNameFormat::Uri)
    .with_friendly_name("mail"),
    Attribute::new(
        "eduPersonAffiliation",
        [AttributeValue::new("member"), AttributeValue::new("staff")],
    )
    .with_name_format(AttributeNameFormat::Basic),
]);

let response = idp.respond_sso(
    &sp,
    &request,
    SsoAssertion::new(name_id).attributes(attributes),
    RespondSso::post(),
)?;
```

A `Basic` name that is not an XML name is rejected.

To identify the subject with the `subject-id` or `pairwise-id` attribute, create a `SubjectId` or `PairwiseId` from its `uniqueID@scope` text and add it with `Attribute::from`. `try_new` rejects text outside the profile's syntax. The response is rejected when the scope has an upper case letter, or the unique ID has both upper and lower case letters.

```rust
let attributes = Attributes::new([
    Attribute::from(SubjectId::try_new("idm123456789@example.com")?),
    Attribute::from(PairwiseId::try_new(format!("{unique_id}@example.com"))?),
]);
```

Give each subject one stable `pairwise-id` value for each service provider, and a different value for every other service provider. The `PairwiseId` documentation shows one way to derive `unique_id`.

If you publish metadata for these identifiers, pass the scopes you issue to `IdpConfigBuilder::scopes`. For a saml2int deployment, list each scope as a `MetadataScope` with `regexp: false`. The scopes appear in the IdP role's `Extensions`. See [IdP scope declarations](../reference/conformance/metadata-and-replay.md#idp-scope-declarations).

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
