# 1. Fix compile errors

[How to upgrade from 0.8 to 0.9](README.md)

| You use | What changed | Section |
| --- | --- | --- |
| `IdpDescriptor::from_metadata_xml(xml, trust)`, `SpDescriptor::from_metadata_xml(xml, trust)` | Takes the expected entity ID first | [1.1](#11-pass-the-expected-entity-id-to-from_metadata_xml) |
| `IdpDescriptor::from_metadata_xml_for`, `SpDescriptor::from_metadata_xml_for` | Renamed to `from_metadata_xml` | [1.1](#11-pass-the-expected-entity-id-to-from_metadata_xml) |
| `EntityId::new` | Removed; use `EntityId::try_new` | [1.2](#12-replace-entityidnew) |
| `PrivateKeyPem::as_str`, `Passphrase::as_str`, `CertificatePem::as_str`, `HmacSecret::as_bytes` | Removed | [1.3](#13-keep-your-own-copy-of-credential-material) |
| A path under `saml_rs::api`, `opensaml::api`, or `samlet::api` | Removed | [1.4](#14-import-the-typed-api-from-the-crate-root) |
| `XmlSignatureProfile::default`, `ResponseSignaturePolicy::default`, `AuthnRequestValidationPolicy::default`, `AudienceValidationPolicy::default` | Removed | [1.5](#15-take-security-policy-fields-from-a-preset) |
| `SamlError::UnmatchIssuer`, `UnmatchAudience`, `UnmatchDestination`, `FailedStatus`, `ExpiredSession`, `SubjectUnconfirmed`, `FailedMessageSignatureVerification`, `FailedToVerifySignature`, `UnmatchCertificate`, `CertificateMismatch`, `MissingSigAlg` | Removed | [1.6](#16-match-the-samlerror-variant-the-crate-returns) |
| `SpConfig::new`, `SpConfig::try_new`, `IdpConfig::new`, `IdpConfig::try_new`, or a struct literal of `SpConfig` or `IdpConfig` | Removed; use the builder | [1.7](#17-build-configs-with-the-builder) |
| `SpConfig::validate`, `IdpConfig::validate`, `SpMetadataConfig::validate`, `IdpMetadataConfig::validate` | Removed; `build()` validates | [1.7](#17-build-configs-with-the-builder) |
| `SpMetadataConfig::new`, `try_new`, `IdpMetadataConfig::new`, `try_new`, or a struct literal of either | Removed; use the builder setters | [1.7](#17-build-configs-with-the-builder) |
| A field of `SpConfig`, `IdpConfig`, `SpMetadataConfig`, or `IdpMetadataConfig`, read or assigned | Private; read it through the getter of the same name | [1.8](#18-read-config-fields-through-getters) |
| A struct literal of `Credentials`, one of its fields, or `DecryptionCredential` | Private; set them with the `with_*` methods and `X509Credential`, and read them through getters | [1.9](#19-fill-credentials-with-the-with-methods) |
| `EntitySetting::try_from(&SpConfig)` or `EntitySetting::try_from(&IdpConfig)` | Removed | [1.10](#110-stop-converting-typed-configs-to-entitysetting) |
| `saml_rs::ServiceProvider`, `saml_rs::IdentityProvider`, `saml_rs::EntitySetting` | Removed from the crate root | [1.11](#111-import-the-raw-roles-from-raw) |
| `saml_rs::raw::metadata` | Removed | [1.12](#112-import-metadata-from-metadata) |
| `ServiceProvider::create_login_request_with_options` | Renamed to `create_login_request` | [1.13](#113-pass-options-to-create_login_request) |
| `ServiceProvider::create_login_request(idp, binding, custom)` | Takes `&LoginRequestOptions` | [1.13](#113-pass-options-to-create_login_request) |
| `ServiceProvider::parse_login_response` | Removed | [1.14](#114-call-parse_unsolicited_login_response) |
| `BindingContext::try_post_form`, `binding::try_saml_post_binding_form` | Renamed to `post_form` and `saml_post_binding_form` | [1.15](#115-handle-the-post-form-error) |
| `BindingContext::post_form`, `binding::saml_post_binding_form` | Return `Result` | [1.15](#115-handle-the-post-form-error) |
| A variant ending in `ForCompatibility`, `DataEncryptionAlgorithm::Aes128`, `Aes256`, or `TripleDes` | Renamed | [1.16](#116-rename-the-relaxed-policy-and-algorithm-variants) |
| `XmlPolicy::clock_drifts` | Removed; set `ClockSkew` on `SamlValidationContext` | [1.17](#117-set-clock-skew-on-the-validation-context) |
| `metadata::try_generate_idp_metadata` | Removed; call `generate_idp_metadata` | [1.18](#118-call-generate_idp_metadata) |
| `SpConfig::builder(entity_id)` or `IdpConfig::builder(entity_id)` | Takes the first ACS or SSO endpoint too | [Typed config](config.md#pass-the-first-endpoint-to-builder) |
| `Saml::sp(config)?` or `Saml::idp(config)?` | Returns the facade, not a `Result` | [Typed config](config.md#remove-the--after-samlsp-and-samlidp) |
| `SpConfigBuilder::manage_name_id_service(ManageNameIdService)` | Renamed `manage_name_id_redirect_service`. Takes the `EndpointUrl` of the HTTP-Redirect endpoint | [Typed config](config.md#publish-an-sp-name-identifier-management-endpoint-by-url) |
| `elements_order` on a typed builder | Removed. Typed metadata always follows the schema sequence | [Typed config](config.md#remove-elements_order-from-typed-builders) |
| `XmlEncryptionPolicy::encrypt_assertions`, `encrypt_ids`, `encrypt_attributes`, or a `with_` method | Removed; set the public fields | [Typed config](config.md#set-xmlencryptionpolicy-fields-directly) |
| `AudienceValidationPolicy::Validate` | Renamed to `RequireRestriction` | [Typed config](config.md#rename-audiencevalidationpolicyvalidate-to-requirerestriction) |
| `TemplatePolicy::relay_state` or `tag_prefix_encrypted_assertion` | Removed | [Typed config](config.md#send-relaystate-per-request) |
| `context::set_schema_validator` | Configure `XmlPolicy::schema_validator` | [9.1](xml-policy.md#91-configure-each-local-role) |
| A full struct literal of `XmlPolicy` | Has a new `schema_validator` field | [9.1](xml-policy.md#91-configure-each-local-role) |
| `Metadata::parse` and its variants, raw metadata `Deref`, generation config names, signature evidence names, raw `get_*` and signing flag getters, `x509_certificates()`, `export_metadata()`, descriptor `metadata()`, `metadata::{sp,idp,generate}` paths, `ArtifactResolutionEndpoint`, or `Metadata::verify_signature*` | Parser arguments, getter names and types, endpoint publishing, and public paths changed; obsolete methods removed | [Metadata API](metadata-api.md) |
| `AuthnRequestAgePolicy` or `ManageNameIdRequestAgePolicy` | Both become `RequestAgePolicy` | [Request age policy](logout-validation-replay.md#use-one-request-age-policy-type) |
| `ClockSkew::default()`, the component setters, or `as_millis()` | Select skew explicitly and use named getters | [Clock skew](logout-validation-replay.md#select-and-read-clock-skew-explicitly) |
| `LogoutSubject` constructors or `session_index()`, `OutstandingLogout::principal()` or `sessions()` | Use `LogoutSubject::new(name_id)`, the append methods, and the renamed getters | [Logout subjects](logout-validation-replay.md#build-a-logout-subject-with-session-indexes) |
| `LogoutCompleted` constructors, `status()`, optional `response()` or `raw_flow()`, or equality | Obtain the completion from `finish_slo` and read the response directly | [Logout completions](logout-validation-replay.md#obtain-the-completed-response-through-finish_slo) |
| `ReplayKey` variants ending in `Id` or `SamlValidationContext::replay_retention()` | Rename variants and keep the retention duration in your configuration | [Replay keys and cache](logout-validation-replay.md#update-replay-keys-and-cache-access) |
| `RelayStateParam`, or a `relay_state` setter or getter | Setters take `RelayState`, getters return `Option<&RelayState>` | [RelayState](browser-transport.md#replace-relaystateparam-with-relaystate) |
| `PendingSnapshot`, `Pending::try_new`, or a pending `with_*` setter | Use the snapshot for the message and `from_snapshot` | [Pending snapshots](browser-transport.md#store-pending-state-with-the-snapshot-for-its-message) |
| Pending `id()`, `issued_at()`, `expires_at()`, or `response_binding()`; `PendingAuthnRequest::peer_entity_id()`; `request_binding()` on `PendingAuthnRequest` or `PendingManageNameIdRequest` | Renamed or removed | [Pending accessors](browser-transport.md#read-pending-state-through-one-accessor-each) |
| `BrowserInput`, a `BrowserInput` variant, `BrowserInput::soap`, or `soap_with_channel` | Renamed to `Inbound`. Build it with a constructor. `soap` takes the channel | [Inbound messages](browser-transport.md#build-received-messages-with-inbound) |
| `BrowserInput::simple_sign_body` or `SimpleSignPost { raw_body, .. }` | Pass parsed fields to `simple_sign` | [SimpleSign input](browser-transport.md#pass-parsed-fields-to-inboundsimple_sign) |
| `AcsEndpoint::mark_default`, `as_binding()`, `Received::new`, or `PostForm::new` | Renamed or removed | [Remaining calls](browser-transport.md#rename-the-remaining-calls) |
| `Subject`, or `NameId::new(value, format)` and `NameId::with_qualifiers` | Response methods borrow a `NameId`; set the format and qualifiers with `with_` methods | [Response methods](sso-results-and-identities.md#pass-a-nameid-to-the-response-methods), [NameId](sso-results-and-identities.md#build-a-nameid-with-its-with_-methods) |
| `Attribute::new(name, format, values)`, `Attribute::with_name_format(name, format, values)`, `Attribute::format()`, or `Attributes::new(iter.collect())` | `Attribute::new(name, values).with_name_format(format)`; read `name_format()`; pass the iterator | [Attributes](sso-results-and-identities.md#build-attributes-with-with_name_format) |
| `SsoSession::subject()`, `authn_session()`, `authn_sessions()`, `assertion()`, or `replay_keys()`, `AuthnSession`, or `Assertion` | Read the session accessors; `AuthnStatement` and `authn_statements()`; `session_not_on_or_after()` | [SSO session](sso-results-and-identities.md#read-the-sso-session-without-the-removed-views) |
| `SsoSession::audience()`, `SsoSession::sig_alg()`, or `AuthnRequest::is_passive()` | Read `audience_restrictions()`; the others are renamed `binding_signature_algorithm_uri()` and `passive()` | [Audiences and renamed accessors](sso-results-and-identities.md#read-audiences-per-restriction-and-call-the-renamed-accessors) |
| `SsoSession::check_and_store_replay` or `AuthnRequest::check_and_store_replay` | Removed; the receiving method stores the keys | [Replay](sso-results-and-identities.md#let-the-receiving-method-check-replay) |
| `NameIdPolicy` constructors or `allow_create()`, `AuthnSession::new`, `SubjectConfirmation::from_raw_xml`, or `SsoResponse` accessors | Removed; read them from the received message | [Received values](sso-results-and-identities.md#stop-building-values-that-only-a-received-message-carries) |
| `RequestedAuthnContext::new` | Renamed to `try_new` | [RequestedAuthnContext](sso-results-and-identities.md#call-requestedauthncontexttry_new) |
| `SamlError::StatusNotSuccess { top, second }`, `ReplayDetected { key }` as a string, `UndefinedBinding`, `UndefinedStatus`, `Xml(message)`, `Crypto(message)`, `Base64(error)`, `Deflate(error)`, or `?` from a `base64::DecodeError` or `std::io::Error` into `SamlError` | Typed payloads, new variants, and no third-party `From` | [Typed errors](errors.md) |

## 1.1 Pass the expected entity ID to `from_metadata_xml`

**Affects:** code that imports peer metadata into `IdpDescriptor` or
`SpDescriptor`.

**Before:** `from_metadata_xml(xml, trust)` accepted whatever `entityID` the
metadata declared, and `from_metadata_xml_for(expected_entity_id, xml, trust)`
checked it.

**Now:** only the checking constructor remains, under the name
`from_metadata_xml`. It returns `SamlError::Invalid` when the metadata
`entityID` differs from the expected one.

**Upgrade:** rename `from_metadata_xml_for` to `from_metadata_xml`. Where you
called the two-argument form, pass the entity ID you registered for that peer:

```rust
// Before
let idp = IdpDescriptor::from_metadata_xml(idp_xml, trust)?;

// Now
let idp = IdpDescriptor::from_metadata_xml(
    EntityId::try_new("https://idp.example.com/metadata")?,
    idp_xml,
    trust,
)?;
```

Take the expected entity ID from your own configuration, not from the
metadata you are importing.

## 1.2 Replace `EntityId::new`

**Affects:** code that calls `EntityId::new`, and code that relies on
`EntityId::try_new`, `EntityId::from_str`, or `EntityId::try_from` to reject an
entity ID that is not a URI.

**Before:** `EntityId::new` wrapped any string, including an empty one,
without a check. `EntityId::try_new`, `from_str`, and `try_from` returned
`SamlError::Invalid` unless the value was an absolute URI reference of at most
1024 characters with collapsed whitespace.

**Now:** `EntityId::new` is removed, and every `EntityId` constructor has the
same rule: it returns `SamlError::Invalid` only for a value without a
non-whitespace character. A peer whose entity ID is not a URI, such as
`idp.example.com`, is named with `EntityId::try_new`. The URI rule for your own
entity ID is checked where it is written: `SpConfigBuilder::build`,
`IdpConfigBuilder::build`, and metadata generation.

**Upgrade:** replace `EntityId::new(value)` with `EntityId::try_new(value)?`:

```rust
// Before
let expected = EntityId::new("idp.example.com");

// Now
let expected = EntityId::try_new("idp.example.com")?;
```

If you validated your own entity ID from configuration with
`EntityId::try_new`, that error now comes from `build()` instead. Handle the
`SamlError::Invalid` there.

## 1.3 Keep your own copy of credential material

**Affects:** code that reads PEM text, a passphrase, or HMAC secret bytes back
out of `PrivateKeyPem`, `Passphrase`, `CertificatePem`, or `HmacSecret`.

**Before:** `as_str()` and `as_bytes()` returned the wrapped value.

**Now:** these accessors are crate-private. The wrappers only carry material
into the library.

**Upgrade:** read the value from the source you built the wrapper from, such
as your secret store or the PEM file, and keep that copy where your
application needs it.

## 1.4 Import the typed API from the crate root

**Affects:** code that names a path under `saml_rs::api`, `opensaml::api`, or
`samlet::api`, such as `saml_rs::api::Saml`.

**Before:** `api` was a public module hidden from docs.rs. The crate root
already exported every item in it.
**Now:** `api` is private. Import the same items from the root of the crate
you depend on, such as `opensaml::Saml` through `opensaml`:

```rust
use saml_rs::{Saml, Sp, StartSso};
```

## 1.5 Take security policy fields from a preset

**Affects:** code that calls `default()` or `Default::default()` on
`XmlSignatureProfile`, `ResponseSignaturePolicy`,
`AuthnRequestValidationPolicy`, or `AudienceValidationPolicy`, and code that
needs `Default` on one of them through a generic bound or a derived `Default`.
Code that builds `SpValidationPolicy` or `IdpValidationPolicy` from
`recommended()`, `compatibility()`, or `default()` does not change.

**Before:** each enum had a `Default` that differed from its value in
`recommended()`:

| Enum | `Default` in 0.8 | `recommended()` |
| --- | --- | --- |
| `XmlSignatureProfile` | `AllowProviderSupportedForCompatibility` | `ExcludeWeakAlgorithms` |
| `ResponseSignaturePolicy` | `AllowUnsignedEncryptedCbc` | `RequireForEncryptedCbc` |
| `AuthnRequestValidationPolicy` | `AllowUnsignedForCompatibility` | `AllowUnsignedVerifyIfPresent` |
| `AudienceValidationPolicy` | `Validate` | `EvaluatePresentRestrictions` |

**Now:** these enums have no `Default`.

**Upgrade:** take the field from the preset you start from:

```rust
let policy = SpValidationPolicy {
    xml_signatures: SpValidationPolicy::recommended().xml_signatures,
    ..current_policy
};
```

To keep the 0.8 behavior, name the variant from the `Default` in 0.8 column
instead. For the first three enums, that variant is the `compatibility()`
value, which relaxes a recommended check. `AudienceValidationPolicy::Validate`
is now `RequireRestriction`. It is stricter than Recommended: it also rejects
a bearer assertion that omits `<AudienceRestriction>`.

## 1.6 Match the `SamlError` variant the crate returns

**Affects:** code that names one of these `SamlError` variants in a `match`,
in `matches!`, or as a value. Code that only propagates `SamlError`, or that
matches other variants, is not affected.

**Before:** nine variants were never returned. A match arm for one of them
never ran:

| Removed | The crate returns |
| --- | --- |
| `UnmatchIssuer` | `IssuerMismatch` |
| `UnmatchAudience` | `AudienceMismatch` |
| `UnmatchDestination` | `DestinationMismatch` |
| `FailedStatus` | `StatusNotSuccess` |
| `ExpiredSession` | `TimeWindowInvalid` |
| `SubjectUnconfirmed` | `SubjectConfirmationInvalid` |
| `FailedMessageSignatureVerification` | `SignatureVerification` with `SignatureVerificationReason::DetachedMessageSignature` |
| `UnmatchCertificate` | `SignatureVerification` with `SignatureVerificationReason::XmlSignature` |
| `CertificateMismatch` | `SignatureVerification` with `SignatureVerificationReason::XmlSignature` |

Two other variants were still returned:

| Removed | Returned by |
| --- | --- |
| `FailedToVerifySignature` | `BergshamraBackend::verify_signature`, when no trusted key verifies the signature |
| `MissingSigAlg` | An HTTP-POST-SimpleSign `BrowserInput` without a `SigAlg` field |

**Now:** all eleven variants are removed. `BergshamraBackend::verify_signature`
returns `SignatureVerification` with `SignatureVerificationReason::XmlSignature`.
A SimpleSign input without `SigAlg` returns
`MissingBindingParameter { name: "SigAlg" }`. The same inputs are rejected as
in 0.8.

**Upgrade:** delete the arms for the nine variants that were never returned,
or match the variant in the right column of the first table. Replace the other
two:

```rust
use saml_rs::error::SignatureVerificationReason;
use saml_rs::SamlError;

fn describe(error: &SamlError) -> &'static str {
    match error {
        // Before: SamlError::FailedToVerifySignature
        SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
            ..
        } => "untrusted XML signature",
        // Before: SamlError::MissingSigAlg
        SamlError::MissingBindingParameter { name: "SigAlg", .. } => "missing SigAlg",
        _ => "other",
    }
}
```

The `Display` text changes with the variant. `FAILED_TO_VERIFY_SIGNATURE` is
now `signature verification failed: xml signature`, and `ERR_MISSING_SIG_ALG`
is now `required binding parameter missing: SigAlg`. Update log filters and
tests that compare these strings.

`SamlError::UndefinedBinding` is removed too. See
[Replace the binding and status variants](errors.md#replace-the-binding-and-status-variants).

## 1.7 Build configs with the builder

**Affects:** callers that build an `SpConfig` or `IdpConfig` without
`SpConfig::builder` or `IdpConfig::builder`, or that call `validate()`.

`builder(..).build()` is now the only way to make a config, and `build()`
validates it once. A built config cannot change afterwards, and it keeps the
provider `build()` made, so `Saml::sp` and `Saml::idp` return the facade
without a `Result`. See
[section 6](metadata.md#6-handle-metadata-errors-from-build).

Before:

```rust
let mut config = SpConfig::new(
    EntityId::try_new("https://sp.example.com/metadata")?,
    SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
);
config.metadata.name_id_format = vec![NameIdFormat::EmailAddress];
config.xml.redirect_inflate_max_bytes = 256 * 1024;
config.validate()?;
let sp = Saml::sp(config)?;
```

After:

```rust
let config = SpConfig::builder(
    EntityId::try_new("https://sp.example.com/metadata")?,
    AcsEndpoint::post("https://sp.example.com/acs")?,
)
.name_id_format(NameIdFormat::EmailAddress)
.xml(XmlPolicy {
    redirect_inflate_max_bytes: 256 * 1024,
    ..XmlPolicy::default()
})
.build()?;
let sp = Saml::sp(config);
```

`SpConfig::builder` takes the first ACS endpoint and `IdpConfig::builder` the
first SSO endpoint. Each other metadata field has a builder setter:
`acs_endpoint`, `sso_endpoint`, `slo_endpoint`, `artifact_resolution_service`,
`manage_name_id_service` (`manage_name_id_redirect_service` on the SP),
`name_id_format`, and `contact` append one entry each, in call order. `acs_endpoints`, `sso_endpoints`, `slo_endpoints`,
`name_id_formats`, and `contacts` append several. `organization`,
`error_url`, and `metadata_lifetime` set the rest. `elements_order` is
removed, as [Typed config](config.md#remove-elements_order-from-typed-builders)
describes.
Policy fields have the setters `credentials`, `validation`, `algorithms`,
`xml`, `templates`, and, on the identity provider, `issuance_lifetime`.

`SpConfig::new` and `IdpConfig::new` started on the same preset as the
builder, so the defaults do not change. The errors that `validate()` returned
now come from `build()`, unchanged.

To change a config after you built it, keep the builder instead, clone it,
and build again:

```rust
let base = SpConfig::builder(entity_id, acs);
let strict = base.clone().validation(SpValidationPolicy::recommended()).build()?;
let relaxed = base.validation(SpValidationPolicy::compatibility()).build()?;
```

## 1.8 Read config fields through getters

**Affects:** callers that read a field of a built config.

Former fields are borrowing getters. A getter keeps the field's name, except
that each list getter takes the plural of the builder setter that appends one
item, such as `acs_endpoints()` for `acs_endpoint`:

| Before | After |
| --- | --- |
| `config.entity_id` | `config.entity_id()` |
| `config.validation` | `config.validation()` |
| `config.metadata.assertion_consumer_service` | `config.metadata().acs_endpoints()` |
| `config.metadata.single_logout_service` | `config.metadata().slo_endpoints()` |
| `config.metadata.single_sign_on_service` | `config.metadata().sso_endpoints()` |
| `config.metadata.manage_name_id_service` | `config.metadata().manage_name_id_services()` |
| `config.metadata.artifact_resolution_service` | `config.metadata().artifact_resolution_services()` |
| `config.metadata.name_id_format` | `config.metadata().name_id_formats()` |
| `config.metadata.elements_order` | Removed. See [Typed config](config.md#remove-elements_order-from-typed-builders) |
| `config.issuance_lifetime` | `config.issuance_lifetime()` |

The same borrowing pattern applies to `credentials`, `algorithms`, `xml`, and
`templates`, and to the other fields of `SpMetadataConfig` and
`IdpMetadataConfig`. Collections are returned as slices.

## 1.9 Fill credentials with the with methods

**Affects:** callers that build `Credentials` with a struct literal or assign
its fields.

`DecryptionCredential` is renamed `X509Credential`: a private key, the
certificate of its public key, and an optional passphrase. Its fields are
private. Build one with `X509Credential::new(certificate, key)`, and add
`.with_passphrase(passphrase)` for an encrypted key. Signing takes one too.
Start from `Credentials::default()` and chain one method per value:

| Former field | Method |
| --- | --- |
| `signing_key`, `signing_key_passphrase`, and `signing_certificate` | `with_signing_credential(X509Credential::new(certificate, key))` |
| `additional_signing_certificates` | `with_additional_signing_certificate(certificate)`, once per certificate, in publication order |
| `hmac_secret` | `with_hmac_secret(secret)` |
| `encryption_certificate`, `decryption_key`, `decryption_key_passphrase`, and `additional_decryption_keys` | `with_decryption_credential(credential)` once per credential, or `with_decryption_credentials(credentials)`, in decryption order. Pass the former primary key first |

Before:

```rust
let credentials = Credentials {
    signing_key: Some(PrivateKeyPem::new(signing_key_pem)),
    signing_certificate: Some(CertificatePem::new(signing_cert_pem)),
    encryption_certificate: Some(CertificatePem::new(encryption_cert_pem)),
    decryption_key: Some(PrivateKeyPem::new(decryption_key_pem)),
    ..Credentials::default()
};
```

After:

```rust
let credentials = Credentials::default()
    .with_signing_credential(X509Credential::new(
        CertificatePem::new(signing_cert_pem),
        PrivateKeyPem::new(signing_key_pem),
    ))
    .with_decryption_credential(X509Credential::new(
        CertificatePem::new(encryption_cert_pem),
        PrivateKeyPem::new(decryption_key_pem),
    ));
```

Each key now travels with its certificate and passphrase. These combinations
can no longer be expressed:

- A passphrase without its key. `build()` used to reject it with
  `SamlError::MissingKey`; now the code does not compile.
- A signing key without a signing certificate. `build()` rejected it with
  `SamlError::MissingKey("signing_certificate")` only for a service provider
  that signs AuthnRequests. Other signing, such as an HTTP-Redirect logout
  message, used the key alone. Give `with_signing_credential` the matching
  certificate, which your metadata then publishes.
- A signing certificate without a signing key. To publish a certificate you do
  not sign with, such as the next one in a rollover, pass it to
  `with_additional_signing_certificate`.
- A decryption key without an encryption certificate, or an encryption
  certificate without a decryption key. Give `with_decryption_credential` the
  certificate that peers encrypt for. That certificate is published in your
  metadata, as before.
- An additional decryption key without a primary one, which `build()`
  rejected with `SamlError::MissingKey("decryption_key")`. The decryption
  credentials are now one list. Decryption tries them, and metadata publishes
  their certificates, in the order added.

The `MissingKey` values that `build()` returns name the credential.
`"signing_credential"` replaces `"signing_key"` for a policy that signs
without one. `"decryption_credential"` replaces `"decryption_key"` for
selected encryption without a decryption credential. Update a check that
compares these strings.

To read credentials, use the getters:

| Former field read | Getter |
| --- | --- |
| `signing_key`, `signing_key_passphrase`, `signing_certificate` | `signing_credential()`, then its `key()`, `passphrase()`, and `certificate()` getters |
| `hmac_secret` | `hmac_secret()`, an `Option` of a reference |
| `additional_signing_certificates` | `additional_signing_certificates()`, a slice |
| `encryption_certificate`, `decryption_key`, `decryption_key_passphrase`, `additional_decryption_keys` | `decryption_credentials()`, a slice in decryption order. The first credential holds the former primary key |

The getters return the typed wrappers, which no longer give the PEM text or
secret back. See [1.3](#13-keep-your-own-copy-of-credential-material).

## 1.10 Stop converting typed configs to EntitySetting

**Affects:** callers that converted a typed config into the raw
`EntitySetting` with `TryFrom`.

The conversion is now internal to `Saml::sp` and `Saml::idp`. Keep the typed
config and pass it to `Saml::sp` or `Saml::idp`. A raw integration builds its
own `EntitySetting`, as the raw API always has.

## 1.11 Import the raw roles from `raw`

**Affects:** code that imports `ServiceProvider`, `IdentityProvider`, or
`EntitySetting` from the crate root.

**Now:** each item has one path, under `raw`:

```rust
use saml_rs::raw::{EntitySetting, IdentityProvider, ServiceProvider};
```

## 1.12 Import metadata from `metadata`

**Affects:** code that imports through `saml_rs::raw::metadata`.

**Now:** use the `metadata` module directly. Raw generator configs are now
named `IdpMetadataInput` and `SpMetadataInput`:

```rust
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
```

## 1.13 Pass options to `create_login_request`

**Affects:** raw service providers that build an `AuthnRequest` with
`create_login_request` or `create_login_request_with_options`.

**Before:** `create_login_request` took an optional template replacement, and
`create_login_request_with_options` took `&LoginRequestOptions`.
**Now:** one `create_login_request` takes `&LoginRequestOptions`.

Replace `None` with the default options:

```rust
use saml_rs::raw::LoginRequestOptions;

let request = sp.create_login_request(&idp, Binding::Redirect, &LoginRequestOptions::default())?;
```

Move a template replacement into `custom`:

```rust
let request = sp.create_login_request(
    &idp,
    Binding::Post,
    &LoginRequestOptions {
        custom: Some(&replace),
        ..Default::default()
    },
)?;
```

Rename calls to `create_login_request_with_options`; the arguments do not
change.

## 1.14 Call `parse_unsolicited_login_response`

**Affects:** raw service providers that call `parse_login_response`.

**Before:** `parse_login_response` was another name for
`parse_unsolicited_login_response`. It accepted only an unsolicited response
and rejected a non-empty `InResponseTo`.
**Now:** it is removed. Rename the call; the behaviour is the same:

```rust
let result = sp.parse_unsolicited_login_response(&idp, Binding::Post, &request)?;
```

If the response answers an `AuthnRequest` you sent, call
`parse_login_response_with_request_id` with that request's ID instead.

## 1.15 Handle the POST form error

**Affects:** code that renders an HTTP-POST form with `BindingContext::post_form`,
`BindingContext::try_post_form`, `binding::saml_post_binding_form`, or
`binding::try_saml_post_binding_form`.

**Before:** `post_form` and `saml_post_binding_form` rendered any form
`action`, and dropped a detached SimpleSign signature that had only one of
`SigAlg` or `Signature`. The `try_` versions rejected both cases.
**Now:** only the checked versions remain, under the shorter names.
`post_form` and `saml_post_binding_form` return `SamlError::Invalid` when the
action is not an absolute `http` or `https` URL, or when the SimpleSign
signature state is partial:

```rust
let html = context.post_form()?;
let html = saml_rs::binding::saml_post_binding_form(action, "SAMLResponse", &b64, None)?;
```

Rename calls to the `try_` versions. Add `?` or error handling to calls to the
old unchecked versions. An endpoint that the unchecked version accepted, such as
a relative path or a `javascript:` URL, now fails; configure the absolute URL
of the peer's endpoint.

## 1.16 Rename the relaxed policy and algorithm variants

**Affects:** code that names one of the variants below, in a value, a `match`,
or a `use`. Behaviour, defaults, and the URIs the algorithms return are
unchanged. Only the names change. The compiler finds each qualified use, such
as `ReplayPolicy::DisabledForCompatibility`. An old variant name written bare in
a pattern, after a glob import such as `use saml_rs::ReplayPolicy::*;`, still
compiles as a binding that matches every value, so search for the old names
too.

**Before:** a relaxed option ended in `ForCompatibility`, which said why it
existed rather than what it allowed.
**Now:** a relaxed option is named after what it allows.

| 0.8 | 0.9 |
| --- | --- |
| `MetadataTrustPolicy::UnsignedForCompatibility` | `MetadataTrustPolicy::AllowUnsigned` |
| `MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithmsForCompatibility` | `MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` |
| `XmlSignatureProfile::AllowProviderSupportedForCompatibility` | `XmlSignatureProfile::AllowWeakAlgorithms` |
| `AssertionSignaturePolicy::AllowUnsignedForCompatibility` | `AssertionSignaturePolicy::AllowUnsigned` |
| `AuthnRequestValidationPolicy::AllowUnsignedForCompatibility` | `AuthnRequestValidationPolicy::AllowUnsigned` |
| `LogoutSignaturePolicy::AllowUnsignedForCompatibility` | `LogoutSignaturePolicy::AllowUnsigned` |
| `AuthnRequestSigningPolicy::DoNotSignForCompatibility` | `AuthnRequestSigningPolicy::DoNotSign` |
| `LogoutSigning::DoNotSignForCompatibility` | `LogoutSigning::DoNotSign` |
| `ReplayPolicy::DisabledForCompatibility` | `ReplayPolicy::Disabled` |
| `AudienceValidationPolicy::SkipForCompatibility` | `AudienceValidationPolicy::Skip` |
| `DigestAlgorithm::Sha1ForCompatibility` | `DigestAlgorithm::Sha1` |
| `KeyEncryptionAlgorithm::Rsa15ForCompatibility` | `KeyEncryptionAlgorithm::Rsa15` |
| `DataEncryptionAlgorithm::TripleDesForCompatibility` | `DataEncryptionAlgorithm::TripleDesCbc` |
| `DataEncryptionAlgorithm::Aes128` | `DataEncryptionAlgorithm::Aes128Cbc` |
| `DataEncryptionAlgorithm::Aes256` | `DataEncryptionAlgorithm::Aes256Cbc` |

The deprecated aliases `DigestAlgorithm::Sha1`, `KeyEncryptionAlgorithm::Rsa15`,
and `DataEncryptionAlgorithm::TripleDes` are removed. `Sha1` and `Rsa15` are
now the regular names of the same algorithms, so code that used them compiles
without the deprecation warning. Replace `TripleDes` with `TripleDesCbc`.

**Upgrade:** rename each use. For example:

```rust
// Before
let idp = IdpDescriptor::from_metadata_xml(
    entity_id,
    &metadata,
    MetadataTrustPolicy::UnsignedForCompatibility,
)?;
let context = SamlValidationContext::new(now, ReplayPolicy::DisabledForCompatibility);

// Now
let idp = IdpDescriptor::from_metadata_xml(
    entity_id,
    &metadata,
    MetadataTrustPolicy::AllowUnsigned,
)?;
let context = SamlValidationContext::new(now, ReplayPolicy::Disabled);
```

This command renames them in a Rust source tree. Run the substitutions in this
order, so that `AllowUnsignedForCompatibility` is not renamed twice:

```bash
rg -l 'ForCompatibility|Aes128\b|Aes256\b|TripleDes\b' --type rust | xargs perl -pi -e '
s/\bRequireSignatureAllowingWeakAlgorithmsForCompatibility\b/RequireSignatureAllowingWeakAlgorithms/g;
s/\bAllowProviderSupportedForCompatibility\b/AllowWeakAlgorithms/g;
s/\bAllowUnsignedForCompatibility\b/AllowUnsigned/g;
s/\bUnsignedForCompatibility\b/AllowUnsigned/g;
s/\bDoNotSignForCompatibility\b/DoNotSign/g;
s/\bDisabledForCompatibility\b/Disabled/g;
s/\bSkipForCompatibility\b/Skip/g;
s/\bSha1ForCompatibility\b/Sha1/g;
s/\bRsa15ForCompatibility\b/Rsa15/g;
s/\bTripleDesForCompatibility\b/TripleDesCbc/g;
s/\bTripleDes\b/TripleDesCbc/g;
s/\bAes128\b/Aes128Cbc/g;
s/\bAes256\b/Aes256Cbc/g;
'
```

Review the result before you commit it: the last three lines also rename an
unrelated `TripleDes`, `Aes128`, or `Aes256` identifier of your own.

The `Debug` output of these values shows the new names. Update a log check or
snapshot that compares it.

## 1.17 Set clock skew on the validation context

**Affects:** code that sets `XmlPolicy::clock_drifts` on an `SpConfig` or
`IdpConfig`.

**Before:** `XmlPolicy::clock_drifts` compiled, but no typed operation read
it. `finish_sso`, `accept_unsolicited_sso`, `receive_sso`, `receive_slo`,
`finish_slo`, and the other typed receive operations took their clock skew
from `SamlValidationContext`. A response inside the configured drift but
outside the context's skew failed with `SamlError::TimeWindowInvalid`. Only
the deprecated raw functions, reached through `raw_service_provider` or
`raw_identity_provider`, read the configured drift.

**Now:** the field is removed. `SamlValidationContext` is the only place that
sets clock skew for a typed operation. The raw `ServiceProvider` and
`IdentityProvider` that a typed facade wraps check time windows with no drift.

**Upgrade:** delete the field from the `XmlPolicy` literal. To keep the
tolerance it named, pass the same values to every validation context.
`SamlValidationContext::new` starts at five minutes on each side:

```rust
// Before
let config = SpConfig::builder(entity_id)
    .acs_endpoint(acs)
    .xml(XmlPolicy {
        clock_drifts: (-120_000, 180_000),
        ..XmlPolicy::default()
    })
    .build()?;
let validation = SamlValidationContext::new(now, replay);

// Now
let config = SpConfig::builder(entity_id, acs).build()?;
let validation = SamlValidationContext::new(now, replay)
    .with_clock_skew(ClockSkew::from_millis(-120_000, 180_000));
```

If you call a deprecated raw function through `raw_service_provider` or
`raw_identity_provider` and depend on the drift, move that call to the typed
operation in [section 3](raw-api.md#3-move-off-the-deprecated-raw-api).

## 1.18 Call `generate_idp_metadata`

**Affects:** code that calls `saml_rs::metadata::try_generate_idp_metadata`.

**Before:** `try_generate_idp_metadata` returned
`SamlError::MissingMetadata("SingleSignOnService")` for a config with no
`SingleSignOnService` endpoint. `generate_idp_metadata` wrote an
`IDPSSODescriptor` without one, which the metadata schema does not allow.

**Now:** `try_generate_idp_metadata` is removed. `generate_idp_metadata`
returns the same `SamlError::MissingMetadata("SingleSignOnService")`.

**Upgrade:** rename the call:

```rust
// Before
let xml = try_generate_idp_metadata(&config)?;

// Now
let xml = generate_idp_metadata(&config)?;
```
