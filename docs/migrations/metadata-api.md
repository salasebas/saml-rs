# Update metadata imports and accessors

This guide covers callers of `saml_rs::metadata` and peer descriptors in the
unreleased metadata API cleanup. The compatibility crates re-export the same
API.

## Parse without extractor fields

Remove the extractor list from `Metadata::parse`, `parse_with_limits`, and
`parse_with_policy`. Custom extraction remains an implementation detail.

Before:

```rust,ignore
let metadata = Metadata::parse(xml, Vec::new())?;
```

After:

```rust
# fn run(xml: &str) -> Result<(), saml_rs::SamlError> {
use saml_rs::metadata::Metadata;
let metadata = Metadata::parse(xml)?;
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
let sso: Option<EndpointUrl> = idp.single_sign_on_service(SsoRequestBinding::Post)?;
let acs = sp.assertion_consumer_service(SsoResponseBinding::Post)?;
let logout = idp.single_logout_service(LogoutBinding::Post)?;
let response = idp.single_logout_response_service(LogoutBinding::Post)?;
# Ok(()) }
```

These methods return `Ok(None)` for an absent endpoint and
`SamlError::Invalid` when its selected location is not an absolute HTTP(S) URL.
Import does not reject those locations. HTTP(S) is the library's typed endpoint
contract, not a general metadata schema restriction.

Both descriptors also expose `name_id_formats()`, `organization()`, and
`contacts()`. `metadata_xml()` still returns the original XML. For raw
metadata inspection, parse that XML with `metadata::IdpMetadata` or
`metadata::SpMetadata`.

## Rename raw metadata getters

| Before | After |
| --- | --- |
| `get_metadata()` | `metadata_xml()` |
| `get_entity_id()` | `entity_id()` |
| `get_name_id_format()` | `name_id_formats()` |
| `get_support_bindings()` | `single_logout_bindings()` |
| `get_single_sign_on_service(binding)` | `single_sign_on_service(binding)` |
| `get_assertion_consumer_service(binding)` | `assertion_consumer_service(binding)` |
| `get_single_logout_service(binding)` | `single_logout_service(binding)` |
| `get_single_logout_response_service(binding)` | `single_logout_response_service(binding)` |
| `is_want_authn_requests_signed()` | `want_authn_requests_signed()` |
| `is_want_assertions_signed()` | `want_assertions_signed()` |
| `is_authn_request_signed()` | `authn_requests_signed()` |

`name_id_formats()` returns `Vec<NameIdFormat>` instead of `Vec<String>`.
Known URIs become their named variants. Other values remain
`NameIdFormat::Custom`, in the same document order, including repeats. Use
`format.as_uri()` when you need the original string.

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
let first = certificates.first();
std::fs::write(path, metadata.metadata_xml())?;
# Ok(()) }
```

The certificate strings remain the raw metadata values, not newly encoded PEM.

## Import items from their public module

The `metadata::sp`, `metadata::idp`, and `metadata::generate` modules are
private. Import their public items directly from `saml_rs::metadata`.

Replace `metadata::ArtifactResolutionEndpoint` with the existing crate-root
`ArtifactResolutionService`. Both raw and typed publishing use it:

```rust
# fn run() -> Result<(), saml_rs::SamlError> {
use saml_rs::{ArtifactResolutionService, EndpointUrl};
use saml_rs::metadata::IdpMetadataConfig;
let config = IdpMetadataConfig {
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

The four deprecated `Metadata::verify_signature*` methods are removed.
Import with `IdpDescriptor::from_metadata_xml` or
`SpDescriptor::from_metadata_xml` and `MetadataTrustPolicy::RequireSignature`.
A failed verification then returns an error that `?` propagates. See
[Verify signed metadata on import](0.8-to-0.9.md#7-verify-signed-metadata-on-import)
for the replacement. The separate deprecated `crypto::verify_metadata_signature*`
functions remain for their own removal task.
