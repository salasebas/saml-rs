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
variant and message. `Saml::sp` and `Saml::idp` take the built config and
return the facade without a `Result`. `generate_sp_metadata` returns
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
`crypto::verify_metadata_signature` and its three variants.

**Now:** the `Metadata` methods are removed. The `crypto` functions remain
deprecated. Those functions return `Ok(false)`, or an unverified
`MetadataSignatureVerification`, when the metadata is unsigned or its
signature does not verify. They also accept MD5, RIPEMD-160, and RSA keys
shorter than 2048 bits where the crypto provider verifies them.
`MetadataSignatureVerification` is deprecated with them. Its `verified()`
returns `true` exactly when `signed_metadata_xml()` returns `Some`. A call
that only applies `?` to the result accepts unsigned metadata:

```rust
use saml_rs::crypto::verify_metadata_signature;
verify_metadata_signature(&xml, &[certificate_pem])?;
```

**Upgrade:** import the metadata with `IdpDescriptor::from_metadata_xml` or
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

The import checks more than the deprecated `crypto` functions:

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
  `from_metadata_xml_with_policy` to supply other limits and an optional schema
  validator.

## 8. Update metadata element orders

**Affects:** callers that set `elements_order` on raw metadata generation
config, including through the compatibility crates. The typed builders no
longer take an order; see
[Remove `elements_order` from typed builders](config.md#remove-elements_order-from-typed-builders).

### 8.1 Remove unknown and duplicate group names

**Before:** generation silently ignored unknown names and wrote repeated
groups again.

**Now:** raw generation returns `SamlError::Invalid` when an order contains an
unknown name or repeats a group.

**Upgrade:** correct spelling and use each group name once. Raw SP orders
accept `KeyDescriptor`, `SingleLogoutService`, `ManageNameIDService`,
`NameIDFormat`, and `AssertionConsumerService`. The raw
`AttributeConsumingService` slot remains accepted for the existing Shibboleth
profile, but writes nothing because the generator has no configuration for
it.

Raw IdP orders accept `KeyDescriptor`, `ArtifactResolutionService`,
`SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`, and
`SingleSignOnService`.

Remove `Organization` and `ContactPerson` from the order. Configure those
entity-level elements with `organization` and `contacts`, or the builder's
`organization` and `contact` methods. They still follow the role descriptor.

### 8.2 Select published data in the config

**Before:** an order could filter out configured groups. For example, with a
signing certificate, logout endpoint, NameID format, and ACS configured,
an order of only `AssertionConsumerService` wrote only the ACS.

**Now:** an order controls placement, including when it is empty. It no
longer filters configured groups. Missing groups are inserted before the
first listed group that follows them in the metadata schema, or at the end
if there is none. Explicitly listed groups keep their relative order.

The example now writes `KeyDescriptor`, `SingleLogoutService`,
`NameIDFormat`, and `AssertionConsumerService`. SP generation also keeps its
default email-address NameID format when the order does not mention
`NameIDFormat`.

**Upgrade:** to omit optional data, remove it from the metadata config or
credentials instead of leaving its group out of the order. Do not remove a
credential that your signing or decryption policy requires. If you need a
separately curated document, generate it with a separate raw metadata config.

Default profiles retain their output. Explicit non-schema compatibility
orders, including ONELOGIN, retain their relative order and can still produce
schema-invalid metadata. Use the default order for the schema sequence.
