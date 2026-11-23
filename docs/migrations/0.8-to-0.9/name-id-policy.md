# Honor the requested NameID format

This change affects identity providers that answer an `AuthnRequest` with
`respond_sso` or `respond_sso_artifact`.
When the requester names a specific standard format in `NameIDPolicy`, the
IdP checks the identifier's effective format before it issues an assertion.

## Supply a matching identifier

Read the request with `request.message().name_id_policy()`. Choose an
identifier for the authenticated principal in the requested format. When the
request also names an `SPNameQualifier`, supply that qualifier for the
appropriate service provider or affiliation.

If the request combines the `entity` format with `SPNameQualifier`, answer
with `SsoOutcome::Failure`. Core §8.3.6 forbids qualifiers on an entity
identifier, and E15 requires the requested qualifier on a successful
response. [Core §8.3.6](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=79) and
[Errata 05 E15](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).

If the service provider uses the default `emailAddress` request format and
you issue email addresses, add the format to your `NameId`.

```diff
-let name_id = NameId::new(verified_email);
+let name_id = NameId::new(verified_email).with_format(NameIdFormat::EmailAddress);
 let response = idp.respond_sso(&sp, &request, SsoAssertion::new(name_id), RespondSso::post())?;
```

You can also set the IdP's default with
`IdpConfigBuilder::name_id_format` when that format applies to the identifiers
you issue without an explicit format. If the effective format still
differs, the call returns `SamlError::NameIdPolicyFormatMismatch` with
the requested and issued formats. An omitted effective format is `None`.

## Configure the request format on a saml-rs service provider

A saml-rs SP with no configured format requests `emailAddress`. If your IdP
issues persistent identifiers, configure the SP to request `Persistent`.

```rust
let config = builder.name_id_format(NameIdFormat::Persistent).build()?;
```

Use `NameIdFormat::Unspecified` if the SP can accept the identifier format the
IdP chooses.

## Answer a request for an encrypted identifier

To satisfy the special `encrypted` format, configure the IdP to encrypt
identifiers and use SP metadata with an encryption certificate.

```rust
let mut xml = XmlPolicy::default();
xml.encryption.identifiers = IdentifierEncryptionPolicy::EncryptIdentifiers;
let config = builder.xml(xml).build()?;
```

Pass the underlying `NameId` in its actual format. The IdP writes
`EncryptedID` inside the assertion subject. If identifier encryption is
disabled, the call returns `SamlError::NameIdPolicyRequiresEncryptedId`.
`AssertionEncryptionPolicy::EncryptAssertions` alone does not produce an
`EncryptedID` inside the assertion.

## Return an error to the requester

If you cannot satisfy the policy, send a failure outcome. SAML allows
`InvalidNameIDPolicy` as the subordinate status code.

```rust
use saml_rs::constants::status_code::INVALID_NAME_ID_POLICY;
use saml_rs::{RespondSso, SsoOutcome, Status, SubordinateStatusCode};

let status = Status::responder()
	.with_subordinate(SubordinateStatusCode::try_new(INVALID_NAME_ID_POLICY)?);
let response = idp.respond_sso(&sp, &request, SsoOutcome::Failure(status), RespondSso::post())?;
```

The response carries the error status and no assertion.

[SSO generation rules](../../conformance/web-browser-sso-generation.md)
