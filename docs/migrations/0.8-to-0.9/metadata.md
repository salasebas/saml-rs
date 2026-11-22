# Update metadata configuration and trust

[How to upgrade from 0.8 to 0.9](README.md)

## 6. Handle metadata errors from build()

**Affects:** code that builds an `SpConfig` or `IdpConfig`, and code that
calls `generate_sp_metadata` or `generate_idp_metadata` directly.

**Before:** `SpConfigBuilder::build` and `IdpConfigBuilder::build` accepted a
config that `Saml::sp` or `Saml::idp` then rejected while generating metadata:

- a `NameIdFormat::Custom` value that is not an absolute URI reference
- two `AcsEndpoint`s with the same `with_index` value
- more `AcsEndpoint`s than `unsignedShort` indexes
- a `MetadataLifetime` `validUntil` outside the years 0001 through 9999

A `TemplatePolicy::tag_prefix_protocol` or `tag_prefix_assertion` that is not
an XML NCName, is `xml` or `xmlns`, or equals the other prefix failed later
still, when the first message was rendered.

`generate_sp_metadata` wrote an `SPSSODescriptor` with no
`AssertionConsumerService`, and `generate_idp_metadata` wrote an
`IDPSSODescriptor` with no `SingleSignOnService`. The metadata schema requires
at least one of each.

**Now:** `build()` returns each of these errors, with the same `SamlError`
variant and message. `ServiceProvider::new` and `IdentityProvider::new`,
which replace `Saml::sp` and `Saml::idp`, take the built config and return
the provider without a `Result`. `generate_sp_metadata` returns
`SamlError::MissingMetadata("AssertionConsumerService")` and
`generate_idp_metadata` returns
`SamlError::MissingMetadata("SingleSignOnService")` for a config without that
endpoint.

**Upgrade:** handle these errors where you call `build()`. A config with a
bad tag prefix that never sent a message now fails to build, so fix the
prefix:

```rust
// Before: build() and Saml::idp succeeded; respond_sso failed.
let config = IdpConfig::builder(entity_id)
    .sso_endpoint(sso)
    .templates(TemplatePolicy {
        tag_prefix_protocol: "saml:p".into(),
        ..TemplatePolicy::default()
    })
    .build()?;

// Now: build() returns SamlError::Invalid. Use an NCName.
let mut templates = TemplatePolicy::default();
templates.tag_prefix_protocol = "samlp2".into();
let config = IdpConfig::builder(entity_id, sso)
    .templates(templates)
    .build()?;
```

Add an endpoint to every `SpMetadataInput` and `IdpMetadataInput` you pass
to the generators:

```rust
let mut input = SpMetadataInput::default();
input.entity_id = "https://sp.example.com/metadata".into();
input.assertion_consumer_service = vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
let xml = generate_sp_metadata(&input)?;
```

## 7. Verify signed metadata on import

**Affects:** callers of `Metadata::verify_signature`,
`verify_signature_with_limits`, `verify_signature_detailed`, or
`verify_signature_detailed_with_limits`, including calls through
`IdpMetadata` and `SpMetadata`. It also affects callers of
`crypto::verify_metadata_signature`, its three variants, and
`MetadataSignatureVerification`.

**Before:** the old verifiers returned `Ok(false)` or an unverified result
when metadata was unsigned or its signature failed verification. A call that
only applied `?` to the result therefore accepted unsigned metadata:

```rust
use saml_rs::crypto::verify_metadata_signature;
verify_metadata_signature(&xml, &[certificate_pem])?;
```

**Upgrade:** the old verifiers and `MetadataSignatureVerification` are
removed. Import the metadata with `IdpDescriptor::from_metadata_xml` or
`SpDescriptor::from_metadata_xml` and `MetadataTrustPolicy::RequireSignature`.
The import returns `SamlError::SignatureVerification` when the signature is
missing or does not verify against a pinned certificate:

```rust
use saml_rs::{CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy};

let certificates = [CertificatePem::new(certificate_pem)];
let idp = IdpDescriptor::from_metadata_xml(
    EntityId::try_new("https://idp.example.com/metadata")?,
    &xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &certificates,
    },
)?;
let signed_descriptor = idp.signed_metadata_xml();
```

The import enforces these signature rules:

- The document holds exactly one signature, directly under the metadata
  root. That signature has one reference, to the root's `ID` as `#ID`, with
  the enveloped-signature transform. Any other shape, such as `URI=""` or a
  reference to a child element, returns `SamlError::SignedReferenceMismatch`.
- `RequireSignature` accepts only the enveloped-signature and exclusive
  canonicalization transforms. For inclusive canonicalization, use
  `RequireSignatureAllowingOtherCanonicalization`.
- On a build that verifies MD5 or RIPEMD-160, `RequireSignature` rejects
  them with `SamlError::AlgorithmUnsupported`. It does not verify with an RSA
  key shorter than 2048 bits. Until the publisher signs with stronger
  algorithms, use `RequireSignatureAllowingWeakAlgorithms`, which accepts
  them where the crypto provider verifies them. See the
  [metadata trust](../../conformance/metadata-and-replay.md#metadata-trust) rows.
- `from_metadata_xml` parses with the default `XmlLimits`. Use
  `from_metadata_xml_with_policy` to supply limits for parsing and signature
  verification, and to configure an optional schema validator.

## 8. Remove metadata element orders

If you set `elements_order` on `metadata::SpMetadataConfig` or
`metadata::IdpMetadataConfig`, delete the assignment when you switch to
`SpMetadataInput` or `IdpMetadataInput`. Remove imports of `constants::elements_order`, including
the `idp` submodule. Both roles' `DEFAULT`, `SHIBBOLETH`, and `ONELOGIN`
constants have been removed. For builder calls, see [Remove `elements_order` from typed builders](config.md#remove-elements_order-from-typed-builders).

```diff
- use saml_rs::constants::elements_order;
- sp.elements_order = Some(elements_order::ONELOGIN.iter().map(|s| s.to_string()).collect());
  let xml = generate_sp_metadata(&sp)?;
```

Both generators write populated groups in schema order. If you used `ONELOGIN`,
expect `SingleLogoutService` before `NameIDFormat` when both appear. If you
used a partial order to omit optional data, configure only the data you want
to publish. SP metadata still advertises the email-address NameID format when
the format list is empty. To choose the order of endpoints of the same kind,
supply them in that order in the endpoint list.

## 10. Update expectations for the generated root

SP and IdP metadata generated without a configured lifetime now includes
`cacheDuration="PT86400S"` on the root `EntityDescriptor`. Consumers can
use it to schedule a refresh after one day. It sets no expiration time.
Explicitly configured `validUntil`, `cacheDuration`, or both take precedence.

If your tests compare generated XML byte for byte, update the expected root
attribute. The same generator and builder calls apply. To publish a different
refresh interval, assign `Some(MetadataLifetime::CacheDuration(duration))`
to the standalone input's `lifetime` field or call
`.metadata_lifetime(MetadataLifetime::CacheDuration(duration))` on the builder.
