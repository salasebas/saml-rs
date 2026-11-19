# Update metadata imports and accessors

[How to upgrade from 0.8 to 0.9](README.md)

These changes apply to callers of `saml_rs::metadata` and peer descriptors.
The compatibility crates re-export the same API.

## Parse without extractor fields

Remove the extractor list from `Metadata::parse`, `parse_with_limits`, and
`parse_with_policy`. Custom extraction remains an implementation detail.

Before:

```rust,ignore
let metadata = Metadata::parse(xml, Vec::new())?;
let limited = Metadata::parse_with_limits(xml, Vec::new(), limits)?;
let checked = Metadata::parse_with_policy(xml, Vec::new(), &policy)?;
```

After:

```rust
# fn run(xml: &str) -> Result<(), saml_rs::SamlError> {
use saml_rs::metadata::Metadata;
use saml_rs::{XmlLimits, XmlPolicy};
let limits = XmlLimits::default();
let policy = XmlPolicy { limits, ..XmlPolicy::default() };
let metadata = Metadata::parse(xml)?;
let limited = Metadata::parse_with_limits(xml, limits)?;
let checked = Metadata::parse_with_policy(xml, &policy)?;
# Ok(()) }
```

The default, explicit-limit, and explicit-policy constructors remain available.
`IdpDescriptor::from_metadata_xml` and `SpDescriptor::from_metadata_xml` still
require an explicit `MetadataTrustPolicy`. Use their `_with_policy` variants
when you need custom XML limits or a schema validator.

## Read typed peer endpoints

`IdpDescriptor::metadata()` and `SpDescriptor::metadata()` are private. Read
endpoints from the descriptor with the binding type for that operation.

Before:

```rust,ignore
let sso: Option<String> = idp.metadata().get_single_sign_on_service(Binding::Post);
```

After:

```rust
# fn run(idp: &saml_rs::IdpDescriptor, sp: &saml_rs::SpDescriptor) -> Result<(), saml_rs::SamlError> {
use saml_rs::{EndpointUrl, LogoutBinding, SsoRequestBinding, SsoResponseBinding};
let sso: Option<EndpointUrl> = idp.single_sign_on_location(SsoRequestBinding::Post)?;
let acs = sp.assertion_consumer_location(SsoResponseBinding::Post)?;
let logout = idp.single_logout_location(LogoutBinding::Post)?;
let response = idp.single_logout_response_location(LogoutBinding::Post)?;
let sp_logout = sp.single_logout_location(LogoutBinding::Post)?;
let sp_response = sp.single_logout_response_location(LogoutBinding::Post)?;
# Ok(()) }
```

These methods return `Ok(None)` for an absent endpoint and
`SamlError::Invalid` when its selected location is not an absolute HTTP(S) URL.
Import does not reject those locations. HTTP(S) is the library's typed endpoint
contract, not a general metadata schema restriction. Invalid-location errors
identify the metadata element and binding. For SOAP, the logout response
location is descriptive metadata only; the response returns on the HTTP
exchange rather than being sent to that URL.

The following replacements apply to both peer descriptors:

| Before | After |
| --- | --- |
| `peer.metadata().get_name_id_format()` | `peer.name_id_formats()`, returning `Vec<NameIdFormat>` |
| `peer.metadata().organization()?` | `peer.organization()?` |
| `peer.metadata().contacts()?` | `peer.contacts()?` |

`metadata_xml()` still returns the original XML. For raw
metadata inspection, parse that XML with `metadata::IdpMetadata` or
`metadata::SpMetadata`. Reuse the import policy when you used custom XML limits
or a schema validator:

```rust
# fn run(idp: &saml_rs::IdpDescriptor, same_policy: &saml_rs::XmlPolicy) -> Result<(), saml_rs::SamlError> {
use saml_rs::metadata::IdpMetadata;
let raw = IdpMetadata::from_xml_with_policy(idp.metadata_xml(), same_policy)?;
let certificates = raw.as_metadata().x509_certificates(
	saml_rs::constants::CertUse::Signing,
);
# Ok(()) }
```

The same pattern applies to `SpMetadata`. Reparsing with `from_xml` uses the
default policy, which can reject XML the original custom policy accepted.

## Rename raw metadata getters

| Before | After |
| --- | --- |
| `get_metadata()` | `metadata_xml()` |
| `get_entity_id()` | `entity_id()` |
| `get_name_id_format()` | `name_id_formats()` |
| `get_support_bindings()` | `single_logout_bindings()` |
| `get_single_sign_on_service(binding)` | `single_sign_on_location(binding)` |
| `get_assertion_consumer_service(binding)` | `assertion_consumer_location(binding)` |
| `get_single_logout_service(binding)` | `single_logout_location(binding)` |
| `get_single_logout_response_service(binding)` | `single_logout_response_location(binding)` |
| `is_want_authn_requests_signed()` | `want_authn_requests_signed()` |
| `is_want_assertions_signed()` | `want_assertions_signed()` |
| `is_authn_request_signed()` | `authn_requests_signed()` |

`name_id_formats()` returns `Vec<NameIdFormat>` instead of `Vec<String>`.
Known URIs become their named variants. Other values remain
`NameIdFormat::Custom`, in the same document order, including repeats. XML Schema
whitespace collapse applies before mapping: leading and trailing XML whitespace
is removed, and internal runs become one space. This also changes the formats
used by raw provider settings and generated protocol messages. Use
`format.as_uri()` when you need the normalized URI string.

`single_logout_bindings()` lists bindings with non-empty logout request
locations. It does not report SSO or assertion consumer bindings.

## Borrow certificates and write XML yourself

`get_x509_certificate(use_)` is removed. `x509_certificates(use_)` borrows a
`&[String]` instead of cloning a `Vec<String>`. Use `.first()` when you
intentionally select one certificate, or `.to_vec()` when you need ownership.

Before:

```rust,ignore
let first = metadata.get_x509_certificate(CertUse::Signing);
metadata.export_metadata(path)?;
```

After:

```rust
# fn run(metadata: &saml_rs::metadata::Metadata, path: &std::path::Path) -> Result<(), std::io::Error> {
use saml_rs::constants::CertUse;
let certificates = metadata.x509_certificates(CertUse::Signing);
let first: Option<&String> = certificates.first();
let owned_first: Option<String> = certificates.first().cloned();
let owned_certificates: Vec<String> = certificates.to_vec();
std::fs::write(path, metadata.metadata_xml())?;
# Ok(()) }
```

The certificate strings remain the raw metadata values, not newly encoded PEM.

## Import items from their public module

The `metadata::sp`, `metadata::idp`, and `metadata::generate` modules are
private. Use these public paths:

| Before | After |
| --- | --- |
| `metadata::sp::SpMetadata` | `metadata::SpMetadata` |
| `metadata::idp::IdpMetadata` | `metadata::IdpMetadata` |
| `metadata::idp::ArtifactResolutionServiceEndpoint` | `metadata::ArtifactResolutionServiceEndpoint` |
| `metadata::generate::Endpoint` | `metadata::Endpoint` |
| `metadata::generate::generate_sp_metadata` | `metadata::generate_sp_metadata` |
| `metadata::generate::generate_idp_metadata` | `metadata::generate_idp_metadata` |
| `metadata::generate::SpMetadataConfig` | `metadata::SpMetadataInput` |
| `metadata::generate::IdpMetadataConfig` | `metadata::IdpMetadataInput` |
| `metadata::generate::ArtifactResolutionEndpoint` | crate-root `ArtifactResolutionService` |

Replace `metadata::ArtifactResolutionEndpoint` with the existing crate-root
`ArtifactResolutionService`. Both raw and typed publishing use it:

```rust
# fn run() -> Result<(), saml_rs::SamlError> {
use saml_rs::{ArtifactResolutionService, EndpointUrl};
use saml_rs::metadata::IdpMetadataInput;
let config = IdpMetadataInput {
	artifact_resolution_service: vec![ArtifactResolutionService::new(
		0,
		EndpointUrl::try_new("https://idp.example.com/artifact")?,
	)],
	..Default::default()
};
# Ok(()) }
```

The publisher now requires an HTTP(S) location. The raw reader still returns
`ArtifactResolutionServiceEndpoint`, including unknown binding URIs. Artifact
resolution still refuses a selected non-SOAP binding.

## Verify signatures when importing peers

These four `Metadata` methods are removed, including access through the raw
IdP and SP readers:

- `verify_signature(certificates)`
- `verify_signature_with_limits(certificates, limits)`
- `verify_signature_detailed(certificates)`
- `verify_signature_detailed_with_limits(certificates, limits)`
Import with `IdpDescriptor::from_metadata_xml` or
`SpDescriptor::from_metadata_xml` and `MetadataTrustPolicy::RequireSignature`.
A failed verification then returns an error that `?` propagates. See
[Verify signed metadata on import](metadata.md#7-verify-signed-metadata-on-import)
for the replacement. The separate deprecated `crypto::verify_metadata_signature*`
functions remain for their own removal task. For the former limited variants,
configure `XmlPolicy::limits` and import with `from_metadata_xml_with_policy`.
For the former detailed variants, read `signed_metadata_xml()` from the
imported descriptor. The import contract also checks expected identity and
its selected signature policy; it is not just a rename of the old verifier.

## Borrow common fields explicitly from raw readers

`IdpMetadata` and `SpMetadata` no longer implement `Deref<Target = Metadata>`.
Use `as_metadata()` for shared fields. Role-specific endpoints and signing
flags stay on their raw reader.

Before:

```rust,ignore
let raw = IdpMetadata::from_xml(xml)?;
let entity_id = raw.get_entity_id();
let formats = raw.get_name_id_format();
```

After:

```rust
# fn run(xml: &str) -> Result<(), saml_rs::SamlError> {
use saml_rs::metadata::IdpMetadata;
let raw = IdpMetadata::from_xml(xml)?;
let entity_id = raw.as_metadata().entity_id();
let formats = raw.as_metadata().name_id_formats();
# Ok(()) }
```

The shared view contains only the role selected by the reader. For example,
an IdP reader's `as_metadata().x509_certificates(use_)` still reads IdP keys.
When a raw helper takes `&Metadata`, pass `raw.as_metadata()` instead of `&raw`.
This is a borrowed view and does not reparse or clone the metadata.

## Distinguish raw generation inputs from typed configs

The raw `metadata::SpMetadataConfig` and `metadata::IdpMetadataConfig` types
are renamed to `metadata::SpMetadataInput` and `metadata::IdpMetadataInput`.
They are the records passed to `generate_sp_metadata`, `generate_idp_metadata`,
and the raw providers' `from_config` constructors. Their fields keep their
names and meanings. The crate-root typed `SpMetadataConfig` and
`IdpMetadataConfig` readers keep their names.

Before:

```rust,ignore
use saml_rs::metadata::{generate_sp_metadata, Endpoint, SpMetadataConfig};
use saml_rs::constants::Binding;
let input = SpMetadataConfig {
	entity_id: "https://sp.example.com/metadata".into(),
	assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")],
	..Default::default()
};
let xml = generate_sp_metadata(&input)?;
```

After:

```rust,no_run
# fn run() -> Result<(), saml_rs::SamlError> {
use saml_rs::metadata::{generate_sp_metadata, SpMetadataInput};
let input = SpMetadataInput {
	entity_id: "https://sp.example.com/metadata".into(),
	assertion_consumer_service: vec![saml_rs::metadata::Endpoint::new(
		saml_rs::constants::Binding::Post,
		"https://sp.example.com/acs",
	)],
	..Default::default()
};
let xml = generate_sp_metadata(&input)?;
# Ok(()) }
```

The typed config readers expose the former `name_id_format` field through
`name_id_formats()`. The builder setter stays `name_id_format(format)` because
it adds one format per call. Code using the earlier unreleased getter
`config.metadata().name_id_format()` must use the plural getter too.

Before:

```rust,ignore
let formats = config.metadata.name_id_format;
```

After:

```rust
# fn run(config: &saml_rs::SpConfig) {
let formats = config.metadata().name_id_formats();
# }
```

## Read metadata signature status and evidence

On both peer descriptors, `was_verified_with_pinned_certificates()` is
removed. It returned `true` exactly when `signed_metadata_xml()` returns
`Some`, so read that instead. `Some` records verification at import with the
caller-pinned certificates under the selected policy. It does not check
expiration and does not imply that the caller selected the default algorithm
policy. Import with `AllowUnsigned` returns `None` even if XML has a signature.

`signed_entity_descriptor_xml()` becomes `signed_metadata_xml()` on both
peer descriptors and on the deprecated `MetadataSignatureVerification`. The result
can be a signed `EntityDescriptor` or a covering `EntitiesDescriptor`, so the
new name covers both. The original signed XML is retained.

Before:

```rust,ignore
let verified = idp.was_verified_with_pinned_certificates();
let evidence = idp.signed_entity_descriptor_xml();
```

After:

```rust
# fn run(idp: &saml_rs::IdpDescriptor) {
let evidence = idp.signed_metadata_xml();
let verified = evidence.is_some();
# }
```
