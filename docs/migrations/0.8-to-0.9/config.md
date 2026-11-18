# Upgrade typed config code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers callers that build an `SpConfig` or `IdpConfig`, fill
`Credentials`, or set an `XmlEncryptionPolicy`, `AudienceValidationPolicy`, or
`TemplatePolicy`. Apply the sections that match your integration.

## Pass the first endpoint to `builder`

**Affects:** every call to `SpConfig::builder` and `IdpConfig::builder`.

**Before:** `builder` took the entity ID alone. `build()` returned
`SamlError::MissingMetadata("AssertionConsumerService")` for an SP without
`acs_endpoint`, and `MissingMetadata("SingleSignOnService")` for an IdP
without `sso_endpoint`.

**Now:** `SpConfig::builder(entity_id, acs)` takes the first
`AssertionConsumerService` endpoint, and `IdpConfig::builder(entity_id, sso)`
takes the first `SingleSignOnService` endpoint. The metadata schema requires
one of each, so a config without one no longer compiles. `acs_endpoint` and
`sso_endpoint` append the next endpoints, as before.

**Upgrade:** move the first `acs_endpoint` or `sso_endpoint` argument into
`builder`:

```rust
// Before
let sp = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?.with_default())
    .acs_endpoint(AcsEndpoint::artifact("https://sp.example.com/acs/artifact")?)
    .build()?;

// Now
let sp = SpConfig::builder(
    EntityId::try_new("https://sp.example.com/metadata")?,
    AcsEndpoint::post("https://sp.example.com/acs")?.with_default(),
)
.acs_endpoint(AcsEndpoint::artifact("https://sp.example.com/acs/artifact")?)
.build()?;
```

Remove the `MissingMetadata` arms that handled a missing endpoint from
`build()`.

## Remove the `?` after `Saml::sp` and `Saml::idp`

**Affects:** every call to `Saml::sp` and `Saml::idp`.

**Before:** both returned `Result`. `build()` had already generated the
metadata and built the provider to check the config, so the `Result` was never
an error, and the facade generated the same metadata again.

**Now:** the built config keeps the provider that `build()` made.
`Saml::sp(config)` returns `Saml<Sp>` and `Saml::idp(config)` returns
`Saml<Idp>`.

**Upgrade:** delete the `?`, or the error handling, after the call:

```rust
// Before
let sp = Saml::sp(config)?;

// Now
let sp = Saml::sp(config);
```

A function that returned `Saml::sp(..)` as its `Result` wraps it in `Ok`.

The `Debug` output of `SpConfig` and `IdpConfig` lists the same fields and
ends with `..`, for the provider it leaves out. Update a snapshot that
compares it.

## Publish an SP name identifier management endpoint by URL

**Affects:** service providers that call `SpConfigBuilder::manage_name_id_service`.

**Before:** it took a `ManageNameIdService`. `build()` returned
`SamlError::Unsupported` for `ManageNameIdService::soap`, because a service
provider has no SOAP endpoint for name identifier management.

**Now:** it takes the `EndpointUrl` of the HTTP-Redirect endpoint. The
identity provider's `manage_name_id_service` still takes a
`ManageNameIdService`.

**Upgrade:** pass the URL:

```rust
// Before
let builder = builder.manage_name_id_service(ManageNameIdService::redirect(
    EndpointUrl::try_new("https://sp.example.com/nameid")?,
));

// Now
let builder = builder.manage_name_id_service(EndpointUrl::try_new(
    "https://sp.example.com/nameid",
)?);
```

## Name metadata element groups with `SpMetadataElement` and `IdpMetadataElement`

**Affects:** callers that pass `elements_order` to `SpConfigBuilder` or
`IdpConfigBuilder`, or read it back.

**Before:** `elements_order` took a `Vec<String>`, and `build()` returned
`SamlError::Invalid` for an unknown name.

**Now:** `SpConfigBuilder::elements_order` takes an iterator of
`SpMetadataElement`, and `IdpConfigBuilder::elements_order` takes an iterator
of `IdpMetadataElement`. An unknown group no longer compiles. `build()` still
returns `SamlError::Invalid` for a repeated group. The getters return
`Option<&[SpMetadataElement]>` and `Option<&[IdpMetadataElement]>`. The raw
generator input keeps its `Vec<String>`.

| Group name | Variant |
| --- | --- |
| `KeyDescriptor` | `KeyDescriptor` |
| `ArtifactResolutionService` | `IdpMetadataElement::ArtifactResolutionService` |
| `SingleLogoutService` | `SingleLogoutService` |
| `ManageNameIDService` | `ManageNameIdService` |
| `NameIDFormat` | `NameIdFormat` |
| `SingleSignOnService` | `IdpMetadataElement::SingleSignOnService` |
| `AssertionConsumerService` | `SpMetadataElement::AssertionConsumerService` |
| `AttributeConsumingService` | None. The group wrote nothing. Delete it |

**Upgrade:** replace each name with its variant. For example, the OneLogin
SP order becomes:

```rust
// Before
let builder = builder.elements_order(
    elements_order::ONELOGIN.iter().map(|name| name.to_string()).collect(),
);

// Now
let builder = builder.elements_order([
    SpMetadataElement::KeyDescriptor,
    SpMetadataElement::NameIdFormat,
    SpMetadataElement::SingleLogoutService,
    SpMetadataElement::AssertionConsumerService,
]);
```

## Read config fields and fill credentials

Section 1.8 of [Fix compile errors](compile-errors.md#18-read-config-fields-through-getters)
lists the getters that replace the 0.8 config fields, including the plural
endpoint lists such as `acs_endpoints()`. Section
[1.9](compile-errors.md#19-fill-credentials-with-the-with-methods) shows how
to fill `Credentials` with `X509Credential`, which replaces
`DecryptionCredential`.

## Set `XmlEncryptionPolicy` fields directly

**Affects:** callers of `XmlEncryptionPolicy::encrypt_assertions`,
`encrypt_ids`, `encrypt_attributes`, `with_max_decryption_work`,
`max_decryption_work()`, or `with_rsa15_key_transport_decryption_allowed`.

**Before:** three presets each set one field, two settings were private
fields behind `with_` methods, and the other three were public fields.

**Now:** every setting is a public field, and you write a struct literal over
`XmlEncryptionPolicy::default()`. The RSA-v1.5 opt-in is the
`rsa15_key_transport` field, a `Rsa15KeyTransportPolicy`. Defaults do not
change.

| 0.8 | 0.9 |
| --- | --- |
| `XmlEncryptionPolicy::encrypt_assertions()` | `assertions: AssertionEncryptionPolicy::EncryptAssertions` |
| `XmlEncryptionPolicy::encrypt_ids()` | `identifiers: IdentifierEncryptionPolicy::EncryptIdentifiers` |
| `XmlEncryptionPolicy::encrypt_attributes()` | `attributes: AttributeEncryptionPolicy::EncryptAttributes` |
| `.with_max_decryption_work(n)`, `.max_decryption_work()` | `max_decryption_work: n`, `.max_decryption_work` |
| `.with_rsa15_key_transport_decryption_allowed()` | `rsa15_key_transport: Rsa15KeyTransportPolicy::AllowDecryption` |

**Upgrade:** write the fields you select:

```rust
// Before
let encryption = XmlEncryptionPolicy::encrypt_assertions()
    .with_max_decryption_work(64)
    .with_rsa15_key_transport_decryption_allowed();

// Now
let encryption = XmlEncryptionPolicy {
    assertions: AssertionEncryptionPolicy::EncryptAssertions,
    rsa15_key_transport: Rsa15KeyTransportPolicy::AllowDecryption,
    max_decryption_work: 64,
    ..XmlEncryptionPolicy::default()
};
```

## Rename `AudienceValidationPolicy::Validate` to `RequireRestriction`

**Affects:** code that names `AudienceValidationPolicy::Validate`.

**Before:** `Validate` was the strictest value. It also rejected a bearer
assertion without `<AudienceRestriction>`, which the recommended
`EvaluatePresentRestrictions` accepts.

**Now:** the variant is `RequireRestriction`. The behavior is the same.

**Upgrade:** rename each use:

```rust
let validation = SpValidationPolicy {
    // Before: AudienceValidationPolicy::Validate
    audience: AudienceValidationPolicy::RequireRestriction,
    ..SpValidationPolicy::recommended()
};
```

## Send RelayState per request

**Affects:** service providers that set `TemplatePolicy::relay_state`.

**Before:** `start_sso` without `StartSso::relay_state` sent
`TemplatePolicy::relay_state` as the RelayState. The pending request did not
record it, so `finish_sso` did not compare the RelayState the identity
provider returned.

**Now:** the field is removed. A request carries no RelayState unless you set
one, and the pending request records what was sent.

**Upgrade:** pass the value on each request that needs it:

```rust
// Before
let sp = Saml::sp(
    SpConfig::builder(entity_id)
        .acs_endpoint(acs)
        .templates(TemplatePolicy {
            relay_state: "/home".into(),
            ..TemplatePolicy::default()
        })
        .build()?,
)?;
let started = sp.start_sso(&idp, StartSso::redirect())?;

// Now
let sp = Saml::sp(SpConfig::builder(entity_id, acs).build()?);
let started = sp.start_sso(
    &idp,
    StartSso::redirect().relay_state(RelayState::try_new("/home")?),
)?;
```

## Set the EncryptedAssertion prefix with the assertion prefix

**Affects:** identity providers that set
`TemplatePolicy::tag_prefix_encrypted_assertion`.

**Before:** the field set the prefix of a generated `<EncryptedAssertion>`,
apart from `tag_prefix_assertion`, although both elements are in the
assertion namespace.

**Now:** the field is removed. A typed identity provider writes
`<EncryptedAssertion>` with `tag_prefix_assertion`, which defaults to `saml`,
as the old field did. The raw `EntitySetting` keeps its field.

**Upgrade:** delete the field. If you set it to a value other than
`tag_prefix_assertion`, an encrypted response now uses the assertion prefix.
The namespace is the same, so a peer that reads namespaces reads the same
element.
