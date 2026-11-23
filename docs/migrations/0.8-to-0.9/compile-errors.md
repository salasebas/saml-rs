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
| The raw `saml_rs::ServiceProvider` or `saml_rs::IdentityProvider` methods, `saml_rs::EntitySetting`, or a path under `saml_rs::raw` | Removed. The two names now belong to the typed providers | [1.11](#111-move-the-raw-roles-to-the-typed-api) |
| `saml_rs::raw::metadata` | Removed | [1.12](#112-import-metadata-from-metadata) |
| `ServiceProvider::create_login_request`, `create_login_request_with_options`, or `parse_login_response_with_request_id` | Removed | [1.13](#113-start-sso-instead-of-create_login_request) |
| `ServiceProvider::parse_unsolicited_login_response` or `parse_login_response` | Removed | [1.14](#114-accept-unsolicited-sso-instead-of-parse_unsolicited_login_response) |
| `BindingContext::post_form` or `try_post_form` | Removed | [1.15](#115-render-the-outbound-post-form) |
| `binding::try_saml_post_binding_form` or `saml_post_binding_form` | Use `Outbound::post_form()` | [1.15](#115-render-the-outbound-post-form) |
| A variant ending in `ForCompatibility`, `DataEncryptionAlgorithm::Aes128`, `Aes256`, or `TripleDes` | Renamed | [1.16](#116-rename-the-relaxed-policy-and-algorithm-variants) |
| `XmlPolicy::clock_drifts` | Removed; set `ClockSkew` on `SamlValidationContext` | [1.17](#117-set-clock-skew-on-the-validation-context) |
| `metadata::try_generate_idp_metadata` | Removed; call `generate_idp_metadata` | [1.18](#118-call-generate_idp_metadata) |
| `constants::SOAP_BINDING_URN` | Removed; call `Binding::Soap.urn()` | [1.19](#119-call-bindingsoapurn) |
| `constants::namespace::USER_LOGOUT` or `constants::namespace::ADMIN_LOGOUT` | Removed | [1.20](#120-write-the-logout-reason-uri-where-you-need-it) |
| `constants::url_params` | No longer public; write the parameter name | [1.21](#121-write-the-binding-parameter-names) |
| `constants::MessageSignatureOrder`, `AlgorithmPolicy::message_signing_order`, or `EntitySetting::message_signing_order` | Removed; saml-rs never used the value | [1.22](#122-remove-message_signing_order) |
| `MessageSignatureOrder::as_str` or `ParserType::as_str` | Removed | [1.23](#123-replace-parsertypeas_str) |
| `constants::status_code::AUTH_FAILED` | Renamed to `AUTHN_FAILED` | [1.24](#124-rename-auth_failed-to-authn_failed) |
| `FlowOptions` or any of its fields | Removed with the raw API; set signature rules on the typed validation policies and clock skew on `SamlValidationContext` | [3](raw-api.md) |
| A helper from a hidden module, such as `binding::xml_escape`, `util::camel_case`, `entity::generate_id`, `validator::verify_time`, `binding::deflate_raw_decode`, or `validator::check_status` | No longer public | [2.5](public-imports.md#25-replace-the-helpers-that-are-no-longer-public) |
| `SpConfig::builder(entity_id)` or `IdpConfig::builder(entity_id)` | Takes the first ACS or SSO endpoint too | [Typed config](config.md#pass-the-first-endpoint-to-builder) |
| `Saml`, `Sp`, `Idp`, or `Unknown` | Removed; use `ServiceProvider` and `IdentityProvider` | [1.25](#125-replace-samlsp-and-samlidp-with-serviceprovider-and-identityprovider) |
| `SpValidationPolicy::compatibility` or `IdpValidationPolicy::compatibility` | Removed; set the fields it relaxed | [1.26](#126-replace-compatibility-with-the-fields-it-relaxed) |
| `LogoutPolicy`, `LogoutSignaturePolicy`, or either role's `validation.logout` | Remove the logout policy and configure the peer to sign browser messages | [Authenticate browser logout messages](logout-authentication.md) |
| `recommended()` on a validation policy | Use `default()` for the same settings | [1.27](#127-replace-recommended-with-default) |
| `Saml::sp(config)?` or `Saml::idp(config)?` | `ServiceProvider::new(config)` and `IdentityProvider::new(config)` return the provider, not a `Result` | [Typed config](config.md#call-serviceprovidernew-and-identityprovidernew-without-) |
| `SpConfigBuilder::manage_name_id_service(ManageNameIdService)` | Renamed `manage_name_id_redirect_service`. Takes the `EndpointUrl` of the HTTP-Redirect endpoint | [Typed config](config.md#publish-an-sp-name-identifier-management-endpoint-by-url) |
| `elements_order` on a typed builder | Removed. Typed metadata always follows the schema sequence | [Typed config](config.md#remove-elements_order-from-typed-builders) |
| `elements_order` on a standalone metadata input, or `constants::elements_order` | Removed. Both generators write role children in schema order | [8](metadata.md#8-remove-metadata-element-orders) |
| `XmlEncryptionPolicy::encrypt_assertions`, `encrypt_ids`, `encrypt_attributes`, or a `with_` method | Removed; set the public fields | [Typed config](config.md#set-xmlencryptionpolicy-fields-directly) |
| `AudienceValidationPolicy::Validate` | Renamed to `RequireRestriction` | [Typed config](config.md#rename-audiencevalidationpolicyvalidate-to-requirerestriction) |
| `StartSlo::signing` or `LogoutSigning` | Remove the option and configure signing credentials | [Typed operations](typed-operations.md#generate-sso-and-single-logout-messages) |
| `TemplatePolicy::relay_state` | Removed; pass RelayState on each request | [Typed config](config.md#send-relaystate-per-request) |
| `TemplatePolicy::tag_prefix_encrypted_assertion` | Removed; `tag_prefix_assertion` sets the prefix | [Typed config](config.md#set-the-encryptedassertion-prefix-with-the-assertion-prefix) |
| `TemplatePolicy::login_request_template` or `login_response_template` | Removed along with the role-specific setters and getters. Use typed SSO inputs | [Typed config](config.md#replace-sso-templates-with-typed-options) |
| `TemplatePolicy::logout_request_template` or `logout_response_template`, or either `LOGOUT_*_TEMPLATE` constant | Removed. Use the typed logout operations | [Typed config](config.md#replace-logout-templates-with-typed-operations) |
| `E0639` on a struct literal of `SpValidationPolicy`, `IdpValidationPolicy`, `XmlEncryptionPolicy`, `XmlPolicy`, `AlgorithmPolicy`, `TemplatePolicy`, `XmlLimits`, `SignatureConfig`, `Organization`, `ContactPerson`, `Endpoint`, `SpMetadataInput`, or `IdpMetadataInput` | Assign the fields on a preset, `Default`, or a value from a constructor | [Typed config](config.md#assign-fields-instead-of-writing-a-struct-literal) |
| `E0638` on a struct pattern of one of those structs, or `Started`, or `E0639` on a struct literal of a started flow | Non-exhaustive; end the pattern with `..`, and keep the started flow the operation returned | [Typed config](config.md#destructure-with-a-rest-pattern) |
| `E0004` on a `match` over a signature, audience, or encryption policy enum | Non-exhaustive; add a `_` arm | [Typed config](config.md#add-a-wildcard-arm-to-a-match-on-a-policy-enum) |
| `context::set_schema_validator` | Configure `XmlPolicy::schema_validator` | [9.1](xml-policy.md#91-configure-each-local-role) |
| A full struct literal of `XmlPolicy` | Has a new `schema_validator` field; assign it on `XmlPolicy::default()` | [9.1](xml-policy.md#91-configure-each-local-role) |
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
| `Subject`, or `NameId::new(value, format)` and `NameId::with_qualifiers` | Response methods take an `SsoAssertion` or an `SsoOutcome`; set the format and qualifiers with `with_` methods | [Response methods](sso-results-and-identities.md#answer-with-an-ssoassertion-or-an-ssooutcome), [NameId](sso-results-and-identities.md#build-a-nameid-with-its-with_-methods) |
| `RespondSso::attributes`, `RespondSso::authn_context`, `RespondSso::authn_instant`, or `RespondSso::status` | Removed; call `attributes`, `authn_context`, or `authn_instant` on `SsoAssertion`, and pass `SsoOutcome::Failure(status)` for an error response | [Response methods](sso-results-and-identities.md#answer-with-an-ssoassertion-or-an-ssooutcome) |
| `Attribute::new(name, format, values)`, `Attribute::with_name_format(name, format, values)`, `Attribute::format()`, or `Attributes::new(iter.collect())` | `Attribute::new(name, values).with_name_format(format)`; read `name_format()`; pass the iterator | [Attributes](sso-results-and-identities.md#build-attributes-with-with_name_format) |
| `SsoSession::subject()`, `authn_session()`, `authn_sessions()`, `assertion()`, or `replay_keys()`, `AuthnSession`, or `Assertion` | Read the session accessors; `AuthnStatement` and `authn_statements()`; `session_not_on_or_after()` | [SSO session](sso-results-and-identities.md#read-the-sso-session-without-the-removed-views) |
| `AuthnSession::authn_context()` used as an `Option` | `AuthnStatement::authn_context()` returns `&AuthnContext` | [Authentication context](sso-results-and-identities.md#send-exactly-one-authentication-context-per-statement) |
| `AuthnSession::authn_instant()` used as an `Option` | `AuthnStatement::authn_instant()` returns `&SamlInstant` | [Authentication instant](sso-results-and-identities.md#send-a-utc-authninstant-in-every-statement) |
| `SsoSession::audience()`, `SsoSession::sig_alg()`, or `AuthnRequest::is_passive()` | Read `audience_restrictions()`; the others are renamed `binding_signature_algorithm_uri()` and `passive()` | [Audiences and renamed accessors](sso-results-and-identities.md#read-audiences-per-restriction-and-call-the-renamed-accessors) |
| `SsoSession::check_and_store_replay` or `AuthnRequest::check_and_store_replay` | Removed; the receiving method stores the keys | [Replay](sso-results-and-identities.md#let-the-receiving-method-check-replay) |
| `NameIdPolicy` constructors or `allow_create()`, `AuthnSession::new`, `SubjectConfirmation::from_raw_xml`, or `SsoResponse` accessors | Read the received values or the corresponding `SsoSession` accessors | [Received values](sso-results-and-identities.md#stop-building-values-that-only-a-received-message-carries) |
| `RequestedAuthnContext::new` | Renamed to `try_new` | [RequestedAuthnContext](sso-results-and-identities.md#call-requestedauthncontexttry_new) |
| `SignatureVerificationReason::DetachedMessageSignature` | Renamed to `BindingSignature` | [BindingSignature](errors.md#match-bindingsignature) |
| `soap_action()`, `cache_control()`, `pragma()`, or `content_type()` on `SoapRequest` or `SoapResponse` | Removed; send every header from `headers()` | [SOAP headers](soap-artifact-discovery.md#send-the-soap-headers-from-headers) |
| `ArtifactDelivery::CACHE_CONTROL` or `ArtifactDelivery::PRAGMA` | Removed; send `Outbound::headers()` | [Browser headers](soap-artifact-discovery.md#send-the-browser-headers-from-outboundheaders) |
| `SoapProtocolMessage::request` or `SoapProtocolMessage::response_envelope` | Removed; use `SoapRequest::try_new` or `SoapResponse::try_new` | [SOAP envelopes](soap-artifact-discovery.md#build-soap-envelopes-with-soaprequesttry_new-and-soapresponsetry_new) |
| `SoapProtocolMessage` or `Absent` on a SOAP channel attestation enum | Use `SoapBodyElement` or the enum's `Unattested` variant | [SOAP body and channel names](soap-body-and-channel.md) |
| `AnsweredArtifact::envelope()` or a header method on `AnsweredArtifact` | Removed; read `response()` | [Artifact response](soap-artifact-discovery.md#read-the-artifact-response-from-answeredartifactresponse) |
| `IssuedMessage`, or `issue_artifact` with an `IssuedMessage` | Removed; pass the protocol XML | [Issue an artifact](soap-artifact-discovery.md#pass-the-protocol-xml-to-issue_artifact) |
| `ArtifactDereference`, `ArtifactUses`, or `resolve_artifact(idp, artifact, dereference, uses)` | Removed; pass the `SoapChannel` and a `SamlValidationContext` | [Resolve an artifact](soap-artifact-discovery.md#resolve-an-artifact-with-a-channel-and-a-validation-context) |
| `Artifact::try_from_encoded` | Renamed to `try_new` | [Artifact](soap-artifact-discovery.md#call-artifacttry_new) |
| `CommonDomainCookie::name`, `path`, or `secure` | Removed; use `NAME` and `PATH`, and mark the cookie `Secure` | [Discovery cookie](soap-artifact-discovery.md#write-the-discovery-cookie-name-and-path-from-the-constants) |
| `RememberIdentityProvider::with_existing_cookie` | Call `RememberIdentityProvider::existing_cookie` with the same value | [Existing discovery cookie](soap-artifact-discovery.md#pass-the-existing-discovery-cookie) |
| `is_passive`, `assertion_consumer_service_index`, `apply_web_browser_sso_generation_rules`, `apply_single_logout_generation_rules`, `allow_http_single_logout`, or `allow_http_name_id_management` on an options type | Renamed `passive`, `acs_index`, and `allow_http`. Remove the producer-rule calls | [Option setters](typed-operations.md#rename-the-shared-option-setters) |
| `StartNameIdManagement::redirect`, `ReceiveNameIdManagement::redirect`, or `RespondNameIdManagement::redirect` | Renamed `new` | [Name identifier management options](typed-operations.md#build-name-identifier-management-options-with-new) |
| `start_name_id_management` with an `IdentifierEncryptionPolicy` | Takes `StartNameIdManagement` | [SOAP name identifier management](typed-operations.md#pass-startnameidmanagement-to-start_name_id_management) |
| `RespondSlo::status` or `RespondNameIdManagement::status` | Removed; pass the `&Status` to the operation | [Response status](typed-operations.md#pass-the-response-status-to-respond_slo-and-respond_name_id_management_redirect) |
| `respond_slo` or `respond_name_id_management_redirect` without a status argument | Takes a `&Status` after the request | [Response status](typed-operations.md#pass-the-response-status-to-respond_slo-and-respond_name_id_management_redirect) |
| `ReceivedNameIdManagement` or `ReceivedNameIdManagementRedirect` | Renamed `NameIdManagementReceipt` and `NameIdManagementRedirectReceipt` | [Receipts](typed-operations.md#match-nameidmanagementreceipt) |
| `StartPaosSso`, `StartedPaosSso`, `PendingPaosSso`, `PendingPaosSsoSnapshot`, `PaosClientRequest`, `PaosAuthnRequest`, `PaosSsoResponse`, `RespondPaosSso`, `PaosHttpResponse`, `SoapFault`, `paos_soap_fault`, or a `*_paos_sso` operation | Removed with Enhanced Client/Proxy SSO | [ECP removal](ecp-removal.md) |
| `Saml<Idp>::remember_identity_provider` | Renamed `common_domain_cookie` | [Discovery cookie](typed-operations.md#build-the-discovery-cookie-with-common_domain_cookie) |
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
`samlet::api`, such as `saml_rs::api::StartSso`.

**Before:** `api` was a public module hidden from docs.rs. The crate root
already exported every item in it.
**Now:** `api` is private. Import the same items from the root of the crate
you depend on, such as `opensaml::StartSso` through `opensaml`:

```rust
use saml_rs::{ServiceProvider, StartSso};
```

## 1.5 Take security policy fields from a preset

**Affects:** code that calls `default()` or `Default::default()` on
`XmlSignatureProfile`, `ResponseSignaturePolicy`,
`AuthnRequestValidationPolicy`, or `AudienceValidationPolicy`, and code that
needs `Default` on one of them through a generic bound or a derived `Default`.
For the enclosing policies, replace [`compatibility()`](#126-replace-compatibility-with-the-fields-it-relaxed)
or [`recommended()`](#127-replace-recommended-with-default).

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
let mut policy = current_policy;
policy.xml_signatures = SpValidationPolicy::default().xml_signatures;
```

To keep the 0.8 behavior, name the variant from the `Default` in 0.8 column
instead. For the first three enums, that variant relaxes a recommended check.
`AudienceValidationPolicy::Validate` is now `RequireRestriction`. It is
stricter than Recommended: it also rejects a bearer assertion that omits
`<AudienceRestriction>`.

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
| `FailedMessageSignatureVerification` | `SignatureVerification` with `SignatureVerificationReason::BindingSignature` |
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
provider `build()` made, so `ServiceProvider::new` and
`IdentityProvider::new` return the provider without a `Result`. See
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
let mut xml = XmlPolicy::default();
xml.redirect_inflate_max_bytes = 256 * 1024;
let config = SpConfig::builder(
    EntityId::try_new("https://sp.example.com/metadata")?,
    AcsEndpoint::post("https://sp.example.com/acs")?,
)
.name_id_format(NameIdFormat::EmailAddress)
.xml(xml)
.build()?;
let sp = ServiceProvider::new(config);
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
let recommended = base.clone().build()?;
let mut signed_assertions = SpValidationPolicy::default();
signed_assertions.assertions = AssertionSignaturePolicy::RequireSigned;
let strict = base.validation(signed_assertions).build()?;
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

The conversion is now internal to `SpConfigBuilder::build` and
`IdpConfigBuilder::build`, and `EntitySetting` is no longer public. Keep the
typed config and pass it to `ServiceProvider::new` or `IdentityProvider::new`.

## 1.11 Move the raw roles to the typed API

**Affects:** code that calls the raw `ServiceProvider` or `IdentityProvider`
methods, or imports `EntitySetting` from the crate root or from
`saml_rs::raw`.

**Now:** the raw API is removed. `ServiceProvider` and `IdentityProvider` at
the crate root are now the typed providers that replace `Saml<Sp>` and
`Saml<Idp>`, so an old import still compiles and the raw method calls fail.
Configure `SpConfig` or `IdpConfig` and call the typed operations, as
[section 3](raw-api.md) shows.

## 1.12 Import metadata from `metadata`

**Affects:** code that imports through `saml_rs::raw::metadata`.

**Now:** use the `metadata` module directly. Raw generator configs are now
named `IdpMetadataInput` and `SpMetadataInput`:

```rust
use saml_rs::metadata::{Endpoint, IdpMetadataInput, SpMetadataInput};
```

## 1.13 Start SSO instead of `create_login_request`

**Affects:** raw service providers that call `create_login_request`,
`create_login_request_with_options`, or `parse_login_response_with_request_id`.

**Now:** these functions are removed with the raw API. Call
`ServiceProvider::start_sso`, then `finish_sso` for the response, as
[section 3](raw-api.md) shows.

## 1.14 Accept unsolicited SSO instead of `parse_unsolicited_login_response`

**Affects:** raw service providers that call `parse_unsolicited_login_response`,
or `parse_login_response`, which was another name for it.

**Now:** both are removed with the raw API. Call
`ServiceProvider::accept_unsolicited_sso`. It rejects an unsolicited response that
carries `InResponseTo`, including an empty one.

## 1.15 Render the outbound POST form

**Affects:** code that renders an HTTP-POST form with
`binding::saml_post_binding_form` or `binding::try_saml_post_binding_form`.
This also affects callers of `BindingContext::post_form` and `try_post_form`.

**Now:** these helpers are removed. For an outgoing POST or SimpleSign message,
get the form data from `Outbound::post_form()` and render it in your
application:

```rust
let form = outbound.post_form()?;
let action = form.action();
let fields = form.fields();
```

Configure an absolute HTTP(S) URL for the peer's POST endpoint. If you render
forms for XML outside the typed flows, escape the action and field names and
values in your HTML template.

## 1.16 Rename the relaxed policy and algorithm variants

**Affects:** code that names one of the variants below, in a value, a `match`,
or a `use`. Renames preserve defaults and algorithm URIs. For changes in
behaviour, see [AuthnRequest signature verification](authn-request-signatures.md),
[audience restrictions](sso-results-and-identities.md#check-audience-restrictions-before-accepting-a-session), the row for `LogoutSigning`, and
[replay storage for HTTP-POST SSO](logout-validation-replay.md#supply-replay-storage-for-http-post-sso).
The compiler finds each qualified use, such
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
| `AuthnRequestValidationPolicy::AllowUnsignedForCompatibility`, `AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent` | `AuthnRequestValidationPolicy::AllowUnsigned` |
| `LogoutSignaturePolicy`, `LogoutPolicy`, or either role's `validation.logout` | Removed. [Authenticate browser logout messages](logout-authentication.md). |
| `AuthnRequestSigningPolicy::DoNotSignForCompatibility` | `AuthnRequestSigningPolicy::DoNotSign` |
| `LogoutSigning::DoNotSignForCompatibility` | Remove the signing option. Outgoing logout is signed. |
| `ReplayPolicy::DisabledForCompatibility` | `ReplayPolicy::Disabled` |
| `AudienceValidationPolicy::SkipForCompatibility` | Removed. [Keep the default audience policy](sso-results-and-identities.md#check-audience-restrictions-before-accepting-a-session) |
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
let idp = IdpDescriptor::from_metadata_xml_for(
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

The command below renames the remaining variants in a Rust source tree.
Run the substitutions in this order so that `AllowUnsignedForCompatibility` is not renamed twice:

```bash
rg -l 'ForCompatibility|AllowUnsignedVerifyIfPresent|Aes128\b|Aes256\b|TripleDes\b' --type rust | xargs perl -pi -e '
s/\bRequireSignatureAllowingWeakAlgorithmsForCompatibility\b/RequireSignatureAllowingWeakAlgorithms/g;
s/\bAllowProviderSupportedForCompatibility\b/AllowWeakAlgorithms/g;
s/\bAllowUnsignedVerifyIfPresent\b/AllowUnsigned/g;
s/\bAllowUnsignedForCompatibility\b/AllowUnsigned/g;
s/\bUnsignedForCompatibility\b/AllowUnsigned/g;
s/\bDoNotSignForCompatibility\b/DoNotSign/g;
s/\bDisabledForCompatibility\b/Disabled/g;
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
the raw functions read the configured drift.

**Now:** the field is removed. `SamlValidationContext` is the only place that
sets clock skew.

**Upgrade:** stop setting `clock_drifts`. To keep the tolerance it named, pass
the same values to every validation context.
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

## 1.19 Call `Binding::Soap.urn()`

**Affects:** code that reads `saml_rs::constants::SOAP_BINDING_URN`.

**Before:** the constant held the SOAP binding URN, the value that
`Binding::Soap.urn()` returns.

**Now:** the constant is removed.

**Upgrade:** call `urn()` on the binding. It is a `const fn`, so it also
initializes a constant:

```rust
// Before
let urn = saml_rs::constants::SOAP_BINDING_URN;

// Now
let urn = saml_rs::constants::Binding::Soap.urn();
```

## 1.20 Write the logout reason URI where you need it

**Affects:** code that reads `saml_rs::constants::namespace::USER_LOGOUT` or
`saml_rs::constants::namespace::ADMIN_LOGOUT`.

**Before:** the constants held the `urn:oasis:names:tc:SAML:2.0:logout:user`
and `urn:oasis:names:tc:SAML:2.0:logout:admin` reason URIs. No saml-rs API
wrote them to the `Reason` attribute of a `<LogoutRequest>` or read them from
it.

**Now:** both constants are removed. saml-rs has no API for the logout
`Reason`.

**Upgrade:** define the URI in your own code:

```rust
const USER_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";
```

## 1.21 Write the binding parameter names

**Affects:** code that reads a constant from `saml_rs::constants::url_params`.

**Before:** the module held the names of the HTTP binding parameters.

**Now:** the module is crate-private. `Inbound` reads these parameters and
`Outbound` writes them, so code that uses the typed API does not need their
names.

**Upgrade:** write the parameter name as a string:

| Constant | Parameter name |
| --- | --- |
| `url_params::SAML_REQUEST` | `"SAMLRequest"` |
| `url_params::SAML_RESPONSE` | `"SAMLResponse"` |
| `url_params::RELAY_STATE` | `"RelayState"` |
| `url_params::SIG_ALG` | `"SigAlg"` |
| `url_params::SIGNATURE` | `"Signature"` |
| `url_params::SAML_ART` | `"SAMLart"` |

## 1.22 Remove `message_signing_order`

**Affects:** code that names `saml_rs::constants::MessageSignatureOrder`, or
sets `AlgorithmPolicy::message_signing_order` or
`EntitySetting::message_signing_order`.

**Before:** both fields compiled, but saml-rs never used them to order signing
and encryption. A value of `MessageSignatureOrder::EncryptThenSign` changed
nothing.

**Now:** the enum and both fields are removed. An identity provider always
builds a login response in this order: it encrypts the identifiers and
attributes, signs the assertion, encrypts the assertion, and then signs the
response. It skips each step that the configuration does not select.

**Upgrade:** delete the field. `AlgorithmPolicy` is also non-exhaustive now,
so [assign the fields you keep](config.md#assign-fields-instead-of-writing-a-struct-literal):

```rust
// Before
let algorithms = AlgorithmPolicy {
    signature: SignatureAlgorithm::RsaSha256,
    message_signing_order: MessageSignatureOrder::EncryptThenSign,
    ..AlgorithmPolicy::default()
};

// Now
let mut algorithms = AlgorithmPolicy::default();
algorithms.signature = SignatureAlgorithm::RsaSha256;
```

Delete each assignment to `EntitySetting::message_signing_order`.

## 1.23 Replace `ParserType::as_str`

**Affects:** code that calls `ParserType::as_str` or
`MessageSignatureOrder::as_str`.

**Before:** `ParserType::as_str` returned `SAMLRequest` or `SAMLResponse` for a
login request or response, and the root element name, such as
`LogoutRequest`, for the other message types. No saml-rs code called it.

**Now:** the method is removed. `MessageSignatureOrder::as_str` is removed with
its type. See [1.22](#122-remove-message_signing_order).

**Upgrade:** to name the HTTP parameter that carries a message, call
`ParserType::query_param`. It returns `SAMLRequest` for every request type and
`SAMLResponse` for every response type:

```rust
// Before
let name = parser_type.as_str();

// Now
let parameter = parser_type.query_param();
```

If you need the strings that `as_str` returned, write them in a `match` of your
own. `ParserType` is `#[non_exhaustive]`, so the `match` needs a `_` arm.

## 1.24 Rename `AUTH_FAILED` to `AUTHN_FAILED`

**Affects:** code that reads `saml_rs::constants::status_code::AUTH_FAILED`.

**Before:** the constant held the
`urn:oasis:names:tc:SAML:2.0:status:AuthnFailed` status code under the name
`AUTH_FAILED`.

**Now:** the constant is named `AUTHN_FAILED`, after the `AuthnFailed` code in
Core §3.2.2.2. Its value is the same.

**Upgrade:** rename each use:

```rust
// Before
let code = saml_rs::constants::status_code::AUTH_FAILED;

// Now
let code = saml_rs::constants::status_code::AUTHN_FAILED;
```

## 1.25 Replace `Saml<Sp>` and `Saml<Idp>` with `ServiceProvider` and `IdentityProvider`

**Affects:** every typed integration. It names `Saml`, `Sp`, or `Idp`.

**Before:** `Saml::sp(config)` returned `Result<Saml<Sp>, SamlError>` and
`Saml::idp(config)` returned `Result<Saml<Idp>, SamlError>`. `Sp`, `Idp`, and
`Unknown` were the role parameters.

**Now:** the two roles are two types. `Saml`, `Sp`, `Idp`, and `Unknown` are
removed. The methods move to the new types. The methods that 0.9 renames or
changes, such as `remember_identity_provider`, are in the table at the top of
this page.

| 0.8 | 0.9 |
| --- | --- |
| `Saml::sp(config)` | `ServiceProvider::new(config)` |
| `Saml::idp(config)` | `IdentityProvider::new(config)` |
| `Saml<Sp>`, `Saml::<Sp>::method` | `ServiceProvider`, `ServiceProvider::method` |
| `Saml<Idp>`, `Saml::<Idp>::method` | `IdentityProvider`, `IdentityProvider::method` |
| `use saml_rs::{Saml, Sp, Idp}` | `use saml_rs::{IdentityProvider, ServiceProvider}` |

`ServiceProvider::new` and `IdentityProvider::new` return the provider, not a
`Result`. [Typed config](config.md#call-serviceprovidernew-and-identityprovidernew-without-)
explains why.

**Upgrade:**

1. Rewrite the constructors and types. The command works with GNU and BSD
   `sed`, and leaves a `.bak` copy of each file it changes:

   ```sh
   rg -l0 --type rust 'Saml' . | xargs -0 sed -i.bak -E \
   	-e 's/(^|[^[:alnum:]_])Saml::sp\(/\1ServiceProvider::new(/g' \
   	-e 's/(^|[^[:alnum:]_])Saml::idp\(/\1IdentityProvider::new(/g' \
   	-e 's/(^|[^[:alnum:]_])Saml(::)?<([a-z_]+::)*Sp>/\1ServiceProvider/g' \
   	-e 's/(^|[^[:alnum:]_])Saml(::)?<([a-z_]+::)*Idp>/\1IdentityProvider/g'
   ```

2. Delete the `?` or the error handling after each `ServiceProvider::new(..)`
   and `IdentityProvider::new(..)`. Keep the `?` after `build()`. The compiler
   reports each `?` that is left with error E0277.
3. In each `use` list, replace `Saml`, `Sp`, and `Idp` with
   `ServiceProvider`, `IdentityProvider`, or both. The compiler names each
   import that is left.
4. Delete the `.bak` files.

```rust
// Before
use saml_rs::{Idp, Saml, Sp};

fn providers(sp: SpConfig, idp: IdpConfig) -> Result<(Saml<Sp>, Saml<Idp>), SamlError> {
    Ok((Saml::sp(sp)?, Saml::idp(idp)?))
}

// Now
use saml_rs::{IdentityProvider, ServiceProvider};

fn providers(sp: SpConfig, idp: IdpConfig) -> (ServiceProvider, IdentityProvider) {
    (ServiceProvider::new(sp), IdentityProvider::new(idp))
}
```

## 1.26 Replace `compatibility()` with the fields it relaxed

**Affects:** code that calls `SpValidationPolicy::compatibility`
or `IdpValidationPolicy::compatibility`.

**Before:** each `compatibility()` returned the legacy permissive preset, the
behaviour of the samlify port. One call relaxed several checks at once.

**Now:** the compatibility functions are removed. Recommended is the only preset. You
relax a check by assigning the field that names it.

**Upgrade:** start from `default()` and set only the fields
your deployment needs. These are the fields where `compatibility()` differed
from `recommended()`. The table uses the 0.9 variant names;
[1.16](#116-rename-the-relaxed-policy-and-algorithm-variants) maps them to the
0.8 names:

| Policy | Field | Former `compatibility()` | Current `default()` |
| --- | --- | --- | --- |
| `SpValidationPolicy` | `responses` | `ResponseSignaturePolicy::AllowUnsignedEncryptedCbc` | `RequireForEncryptedCbc` |
| `SpValidationPolicy` | `xml_signatures` | `XmlSignatureProfile::AllowWeakAlgorithms` | `ExcludeWeakAlgorithms` |
| `SpValidationPolicy` | `audience` | Skipped evaluation (removed) | `EvaluatePresentRestrictions` |
| `IdpValidationPolicy` | `authn_requests` | Skipped verification (removed) | `AllowUnsigned` |
| `IdpValidationPolicy` | `xml_signatures` | `XmlSignatureProfile::AllowWeakAlgorithms` | `ExcludeWeakAlgorithms` |

Browser logout always requires a verified signature. See [Authenticate browser logout messages](logout-authentication.md).

To select the former SP settings, set the fields below. Keep only the
relaxations your deployment needs. The SP
[checks every present audience restriction](sso-results-and-identities.md#check-audience-restrictions-before-accepting-a-session) and
[verifies every present SSO signature](logout-validation-replay.md#verify-every-signature-on-sso-responses).

```rust
use saml_rs::{
    ResponseSignaturePolicy, SpValidationPolicy, XmlSignatureProfile,
};

// Before
let validation = SpValidationPolicy::compatibility();

// Now
let mut validation = SpValidationPolicy::default();
validation.responses = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
validation.xml_signatures = XmlSignatureProfile::AllowWeakAlgorithms;
```

For the identity provider:

```rust
use saml_rs::{
    IdpValidationPolicy, XmlSignatureProfile,
};

// Before
let validation = IdpValidationPolicy::compatibility();

// Now
let mut validation = IdpValidationPolicy::default();
validation.xml_signatures = XmlSignatureProfile::AllowWeakAlgorithms;
```

The IdP now [verifies every AuthnRequest signature](authn-request-signatures.md),
including when you select the remaining compatibility settings.

If you built without a crypto provider feature, `compatibility()` was the
preset that `build()` accepted. Without a provider, `build()` returns
`SamlError::Unsupported` for a policy that requires a signature. Under
Recommended, set these fields before you call `build()`:

- `SpValidationPolicy`: set `responses` to `AllowUnsignedEncryptedCbc`.
- `IdpValidationPolicy`: use the default policy.

## 1.27 Replace `recommended()` with `default()`

**Affects:** callers of `recommended()` on `SpValidationPolicy`
or `IdpValidationPolicy`.

**Before:** both `recommended()` and `default()` returned the same policy.

**Now:** `default()` is the sole preset on both role policies.

**Upgrade:** replace each call to keep the same validation settings.

```diff
-let sp = SpValidationPolicy::recommended();
+let sp = SpValidationPolicy::default();
-let idp = IdpValidationPolicy::recommended();
+let idp = IdpValidationPolicy::default();
```

The SP and IdP config builders already select these values. If a builder
passed the recommended policy without modifying it, omit the `.validation(...)`
call. Types that derive `Default` through one of these policies still compile.
