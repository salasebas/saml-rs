# Web Browser SSO generation

`ServiceProvider::start_sso` writes the Web Browser SSO `AuthnRequest` and
returns the browser action that carries it over HTTP-Redirect, HTTP-POST, or
HTTP-POST-SimpleSign. `IdentityProvider::respond_sso`, `respond_sso_refusal`,
and `initiate_sso` write the `Response` and return its HTTP-POST or
HTTP-POST-SimpleSign action, and `respond_sso_artifact`,
`respond_sso_refusal_artifact`, and `initiate_sso_artifact` write the same
`Response` and store it for an artifact. The application sends each action,
as [browser bindings](browser-bindings.md#application-duties) describes.

Normative text is [Core §3.4](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf),
[Profiles §4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
and [Bindings §3.4 to §3.6](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf),
as corrected by [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/),
and the HTTP-POST-SimpleSign
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html)
(CS-01). [Browser bindings](browser-bindings.md) has the encoding,
`RelayState`, cache-header, and HTTP delivery rules that every flow shares.
[HTTP-Artifact response](web-browser-sso-artifact.md) covers delivery of a
stored response, and [SSO acceptance](web-browser-sso-acceptance.md) covers
the receiving side. See
[validation defaults](https://samlrs.vercel.app/explanation/validation-presets/)
for the initial role policies.

The statuses hold on builds with a crypto provider. A build without one sends
only an unsigned `AuthnRequest` over HTTP-Redirect or HTTP-POST, because
`SpConfigBuilder::build` refuses a signing policy and `start_sso` refuses
HTTP-POST-SimpleSign and an identity provider whose metadata sets
`WantAuthnRequestsSigned`. Its identity provider issues no `Response`,
success or error.

## Support

### `AuthnRequest`

| Feature | Section | Service provider |
| --- | --- | --- |
| `AuthnRequest` over HTTP-Redirect | Bindings §3.4, Profiles §4.1.3.3 | Supported |
| `AuthnRequest` over HTTP-POST | Bindings §3.5, Profiles §4.1.3.3 | Supported |
| `AuthnRequest` over HTTP-POST-SimpleSign | CS-01 §2 | Supported |
| `AuthnRequest` over HTTP-POST-SimpleSign without `SigAlg` and `Signature` | CS-01 §2.4 | Not supported |
| `AuthnRequest` by HTTP-Artifact | Bindings §3.6, Profiles §4.1.3.3 | Not supported |
| `RelayState` with the request | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Supported |
| XML signature on the request over HTTP-POST | Profiles §4.1.3.3, §4.1.4.1, Bindings §3.5.5.2 | Supported |
| `SigAlg` and `Signature` on the request over HTTP-Redirect and HTTP-POST-SimpleSign | Profiles §4.1.3.3, §4.1.4.1, Bindings §3.4.4.1, CS-01 §2.4 | [Partial](browser-bindings.md#detached-signatures) |
| `Destination` | Core §3.2.1 | Supported |
| `Consent` | Core §3.2.1, §8.4 | Not supported |
| `Extensions` | Core §3.2.1 | Supported |
| Requested `Subject` | Core §3.4.1, Profiles §4.1.4.1 | Not supported |
| `NameIDPolicy` with `Format`, `SPNameQualifier`, and `AllowCreate` | Core §3.4.1.1, E14 | Supported |
| An `AuthnRequest` without `NameIDPolicy`, or a `NameIDPolicy` without `Format` | Core §3.4.1, §3.4.1.1 | Not supported |
| `Conditions` | Core §3.4.1 | Not supported |
| `RequestedAuthnContext` | Core §3.3.2.2.1, §3.4.1, E45 | Supported |
| `Scoping`, with `IDPList`, `RequesterID`, and `ProxyCount` | Core §3.4.1.2 | Not supported |
| `ForceAuthn` | Core §3.4.1 | Supported |
| `IsPassive` | Core §3.4.1 | Supported |
| `AssertionConsumerServiceURL` with `ProtocolBinding` | Core §3.4.1 | Supported |
| `AssertionConsumerServiceIndex` | Core §3.4.1 | Supported |
| `AssertionConsumerServiceURL` without `ProtocolBinding`, `ProtocolBinding` without `AssertionConsumerServiceURL`, or none of the three endpoint attributes | Core §3.4.1 | Not supported |
| `AttributeConsumingServiceIndex` | Core §3.4.1 | Not supported |
| `ProviderName` | Core §3.4.1 | Supported |

### `Response`

| Feature | Section | Identity provider |
| --- | --- | --- |
| `Response` over HTTP-POST | Bindings §3.5, Profiles §4.1.3.5 | Supported |
| `Response` over HTTP-POST-SimpleSign | CS-01 §2 | Supported |
| `Response` over HTTP-POST-SimpleSign without `SigAlg` and `Signature` | CS-01 §2.4 | Not supported |
| `Response` by HTTP-Artifact | Bindings §3.6, Profiles §4.1.3.5 | Supported |
| Error `Response` with no assertion | Core §3.4.1.4, Profiles §4.1.3.5, §4.1.4.1, §4.1.4.2, E85 | Supported |
| `StatusMessage` in an error `Response` | Core §3.2.2.3 | Supported |
| `StatusDetail` | Core §3.2.2.4 | Not supported |
| Unsolicited `Response` | Profiles §4.1.5 | Supported |
| `RelayState` with the `Response` | Bindings §3.5.3, CS-01 §2.3, Profiles §4.1.5 | Supported |
| `Consent` | Core §3.2.2, §8.4 | Not supported |
| `Extensions` | Core §3.2.2 | Not supported |
| XML signature on the `Response` or on each assertion | Profiles §4.1.3.5, §4.1.4.5, E26, E93 | Supported |
| SimpleSign signature on the `Response` | CS-01 §2.4, §2.5 | [Partial](browser-bindings.md#detached-signatures) |
| One bearer assertion with an `AuthnStatement` and an `AudienceRestriction` for the service provider | Profiles §4.1.4.2, E26 | Supported |
| More than one assertion | Profiles §4.1.4.2, E26 | Not supported |
| `EncryptedAssertion` | Core §2.3.4, §6.1 | Supported |
| `NameID` in the assertion `Subject`, with `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` | Core §2.2.2, §2.4.1 | Supported |
| `EncryptedID` in the assertion `Subject` | Core §2.2.4, §3.4.1.1 | Supported |
| An assertion `Subject` with a `BaseID`, or with no identifier | Core §2.4.1 | Not supported |
| Additional `SubjectConfirmation` elements in a bearer assertion | Profiles §4.1.4.2, E26 | Not supported |
| `Address` on the bearer `SubjectConfirmationData` | Profiles §4.1.4.2, E26 | Not supported |
| `Conditions` with `NotBefore` and `NotOnOrAfter` | Core §2.5.1.2 | Supported |
| Conditions other than the `AudienceRestriction`, and other `Audience` values | Core §2.5.1, Profiles §4.1.4.2, E26 | Not supported |
| The `Conditions` that the `AuthnRequest` requests | Core §3.4.1, Profiles §4.1.4.2, E26 | Not supported |
| `Advice` | Core §2.3.3 | Not supported |
| `SessionIndex` | Core §2.7.2, Profiles §4.1.4.2, E26 | Supported |
| `SessionNotOnOrAfter` | Core §2.7.2, E79 | Supported |
| An authentication context class reference or declaration reference | Core §2.7.2.2 | Supported |
| An authentication context declaration by value, or a class reference together with a declaration | Core §2.7.2.2 | Not supported |
| `SubjectLocality` and `AuthenticatingAuthority` | Core §2.7.2.1, §2.7.2.2 | Not supported |
| `AttributeStatement` | Core §2.7.3, Profiles §4.1.4.2 | Supported |
| `EncryptedAttribute` | Core §2.7.3.2 | Supported |
| Statements other than the `AuthnStatement` and the `AttributeStatement` | Profiles §4.1.4.2, E26 | Not supported |
| Holder-of-key Web Browser SSO | Holder-of-Key Web Browser SSO Profile | Not supported |

[Common message fields](common-message-fields.md#library-policies) keeps the
policies that write no `Consent` and no `StatusDetail`, and
[identifiers](identifiers.md#support) lists the name identifier formats and
attribute values that the identity provider writes. Profiles §4.1.4.2, as E26
amends it, does not oblige the identity provider to honor the `Conditions`
that an `AuthnRequest` requests.

## Rules

<a id="service-provider-authnrequest"></a>

### Service provider: `start_sso`

Code: `src/api/sp.rs`, `src/api/peer.rs`, `src/sp.rs`, `src/sp/authn_request.rs`, `src/entity.rs`, `src/model/extension.rs`, `src/model/authn_context.rs`, `src/config/policies.rs`, `src/metadata/generate.rs`, `src/crypto/sign.rs`, `src/binding/signing.rs`

#### Request fields

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `Issuer` as the service provider identifier, with `Format` omitted (the profile also permits `entity`) | Mandatory | Profiles §4.1.4.1 | Always |
| Write `ID`, `Version` `2.0`, and `IssueInstant` | Mandatory | Core §3.2.1, `RequestAbstractType` | Always |
| Write every time value in UTC, and never a leap second | Mandatory | Core §1.3.3 | Always |
| Write `Destination` on a signed request as the URL the user agent is sent to | Mandatory | Bindings §3.4.5.2, §3.5.5.2, CS-01 §2.4 | Always |
| Write `ForceAuthn` | Optional | Core §3.4.1 | `StartSso::force_authn` |
| Write `IsPassive` | Optional | Core §3.4.1 | `StartSso::passive` |
| Write `ProviderName` | Optional | Core §3.4.1, `AuthnRequestType` | `StartSso::provider_name` |
| Reject a `ProviderName` that is empty or has only XML whitespace | Mandatory | Core §1.3.1, `AuthnRequestType` | Always |
| Write supplied elements in call order inside `Extensions`, after `Issuer` and any embedded signature, before `NameIDPolicy` | Optional | Core §3.2.1, `RequestAbstractType`, `AuthnRequestType` | `StartSso::extension` |
| Require each extension's root to use a namespace. Reject the target namespace of every SAML V2.0 schema and the SAML V1.x assertion and protocol namespaces. Accept the namespaces of approved SAML extensions | Mandatory | Core §3.2.1, `ExtensionsType` | `ExtensionElement::from_xml` |

#### Assertion consumer service

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `AssertionConsumerServiceIndex` in place of `AssertionConsumerServiceURL` and `ProtocolBinding` | Optional | Core §3.4.1 | `StartSso::acs_index` |

#### Name identifier policy

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For a non-transient format, write `AllowCreate="true"`. `NameIdCreationPolicy::DoNotAllowCreate` writes `false` instead | Recommended | Core §3.4.1.1, E14 | `SpValidationPolicy::name_id_creation` |
| Omit `AllowCreate` when the `NameIDPolicy` format is transient | Mandatory | Core §3.4.1.1, E14 | Always |
| Write the requested SP or affiliation as `NameIDPolicy@SPNameQualifier`. Omit it by default | Optional | Core §3.4.1.1, `NameIDPolicyType` | `StartSso::sp_name_qualifier` |

#### Requested authentication context

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `RequestedAuthnContext` with an explicit `Comparison`, after `NameIDPolicy`, with the references in the order given | Optional | Core §3.3.2.2.1, §3.4.1, E45 | `StartSso::requested_authn_context` |
| Reject a `RequestedAuthnContext` with no reference, or with both class and declaration references | Mandatory | `RequestedAuthnContextType` | Always |
| Reject a requested authentication context reference that is not an absolute URI reference | Mandatory | Core §1.3.2 | Always |

#### Signing

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Sign the request, and publish `AuthnRequestsSigned="true"` in the service provider metadata | Optional | Profiles §4.1.4.1, Bindings §3.4.5.2, §3.5.5.2, Metadata §2.4.4, E7 | `AuthnRequestSigningPolicy::Sign` |
| Sign the request only when the identity provider publishes `WantAuthnRequestsSigned` as `true` or `1`, and publish `AuthnRequestsSigned="false"` in the service provider metadata | Optional | Profiles §4.1.3.3, §4.1.4.1, Metadata §2.4.3, §2.4.4, E7 | `AuthnRequestSigningPolicy::SignWhenIdpWants` |

[Browser bindings](browser-bindings.md#sending-a-relaystate) keeps the rules
for the `RelayState` of the request, and for its encoding and detached
signature. [Identifiers](identifiers.md#name-identifier-formats) keeps the
rule that rejects a `NameIDPolicy` `Format` that is not an absolute URI
reference.

<a id="identity-provider-response"></a>

### Identity provider: `respond_sso`, `respond_sso_refusal`, `initiate_sso`

Code: `src/api/idp.rs`, `src/api/sso_outcome.rs`, `src/api/response_acs.rs`, `src/idp.rs`, `src/idp/login_response.rs`, `src/model/authn.rs`, `src/model/status.rs`, `src/xml/name.rs`, `src/entity.rs`, `src/metadata/sp.rs`, `src/crypto/sign.rs`

Where [HTTP-Artifact response](web-browser-sso-artifact.md) states no
difference, these rows also cover the `Response` that `respond_sso_artifact`,
`respond_sso_refusal_artifact`, and `initiate_sso_artifact` store.
`respond_sso_refusal` answers a request that `receive_sso` refuses.

#### Status and errors

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write an error `Response` with the status the caller passes and no assertion | Mandatory | Profiles §4.1.4.1, §4.1.4.2, Core §3.4.1.4 | `SsoOutcome::Failure` |
| Write a `Success` response only with an assertion, and reject `SsoOutcome::Failure` with a top-level `Success` status | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write a correlated SAML error for a refused request when a trusted ACS supports the selected response binding | Mandatory | Profiles §4.1.4.1, Metadata §2.4.4, E7, Core §3.2.2 | Always |
| Write top-level `Requester` in the error `Response` to a request refused as invalid: content that breaks the schema of `AuthnRequestType` or of an element it contains, an `AssertionConsumerServiceURL` next to an `AssertionConsumerServiceIndex`, a repeated `NameIDPolicy`, a `ProtocolBinding` of HTTP-Redirect or SOAP, or an unsigned request from a service provider whose metadata sets `AuthnRequestsSigned` | Mandatory | Core §3.2.1, §3.4.1, Profiles §4.1.2, Metadata §2.4.4, E7 | Always |
| Write top-level `VersionMismatch` in the error `Response` to a request refused for its `Version`, with the subordinate `RequestVersionTooHigh` for a later major version | Mandatory | Core §4.1.3.2 | Always |
| Support delivery of an error when the user agent remains available and an acceptable response location exists | Recommended | Profiles §4.1.3.5, E85 | Always |
| Write an unsolicited error `Response` for a login the identity provider started | Optional | Profiles §4.1.4.2, §4.1.5 | `initiate_sso`, `initiate_sso_artifact` |
| Write caller-supplied plain text as `StatusMessage` after the complete `StatusCode` in a failed login `Response` before signing. Omit empty or unset text | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | `RespondSso::status_message` |
| Write only characters permitted in XML 1.0 in `StatusMessage` | Mandatory | [XML 1.0 §2.2](https://www.w3.org/TR/xml/#charsets) | Always |
| Reject a `StatusMessage` with no non-whitespace character | Mandatory | Core §1.3.1, §3.2.2.3 | `RespondSso::status_message` |
| Reject a subordinate `StatusCode` `Value` that is not an absolute URI reference, including one read from a received response | Mandatory | Core §1.3.2, §3.2.2.2 | `SsoOutcome::Failure` |

#### Response fields

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `ID`, `Version` `2.0`, and `IssueInstant` on the `Response` and on the assertion | Mandatory | Core §2.3.3, §3.2.2, `StatusResponseType`, `AssertionType` | Always |
| Write `Issuer` on a successful `Response` that is signed or carries an encrypted assertion | Mandatory | Profiles §4.1.4.2, E17 | Always |
| Write the issuing identity provider's identifier in each `Response` `Issuer`, with `Format` omitted (the profile also permits `entity`) | Mandatory | Profiles §4.1.4.2, E17 | Always |
| On a signed `Response` over HTTP-POST or HTTP-POST-SimpleSign, write `Destination` as the assertion consumer service URL | Mandatory | Bindings §3.5.5.2, CS-01 §2.4 | Always |
| Write every time value in UTC, and never a leap second | Mandatory | Core §1.3.3 | Always |
| Match `InResponseTo`, on the `Response` and on the bearer `SubjectConfirmationData`, to the `AuthnRequest` `ID` | Mandatory | Core §3.2.2, Profiles §4.1.4.2, E26 | Always |
| Reject a response to a request whose `ID` is not an `xs:NCName`, because `InResponseTo` cannot carry it | Mandatory | Core §1.3.4, `StatusResponseType`, `SubjectConfirmationDataType` | Always |
| Omit `InResponseTo` from an unsolicited `Response`, including an error for a request whose `ID` cannot be determined | Mandatory | Core §3.2.2, Profiles §4.1.5 | Always |
| Send a `RelayState` the identity provider chooses, when the request carried none or the response is unsolicited | Optional | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | `RespondSso::relay_state` |

#### Bearer assertion

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write a bearer assertion that has an `AuthnStatement` | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write `Issuer` on the assertion as the responding identity provider, with `Format` omitted (the profile also permits `entity`) | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write an `AudienceRestriction` for the service provider | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write `Recipient` and `NotOnOrAfter` on the bearer `SubjectConfirmationData`, and no `NotBefore` | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write `SessionIndex` on the `AuthnStatement` when the identity provider metadata advertises `SingleLogoutService` | Mandatory | Profiles §4.1.4.2, E26 | `IdpConfigBuilder::slo_endpoint` |

[Identifiers](identifiers.md#identity-provider-sessionindex-of-a-login-response)
keeps the rule that writes the assertion `ID` as the `SessionIndex`.

<a id="endpoint-selection"></a>

#### Assertion consumer service

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a request without an ACS URL, ACS index, or `ProtocolBinding` at the default `AssertionConsumerService`. Fail if that default is unsupported or incompatible with the selected response binding | Mandatory | Core §3.4.1, Profiles §4.1.6, Metadata §2.2.3 | Always |
| Take that default from the endpoints of the SAML 2.0 service provider role, before filtering by binding | Mandatory | Core §3.4.1, Metadata §2.2.3, §2.4.1, E37 | Always |
| Refuse a response binding that differs from the request's `ProtocolBinding` or from the binding of its indexed `AssertionConsumerService` | Mandatory | Profiles §4.1.3.5, Core §3.4.1 | Always |
| Send the response to a request at the chosen `AssertionConsumerService` whether its `Location` is `http` or `https` | Mandatory | Core §3.4.1, Profiles §4.1.3.5 | Always |
| Deliver an unsolicited response to the default `AssertionConsumerService`. Fail if that default is unsupported or incompatible with the selected response binding | Recommended | Profiles §4.1.5 | Always |

[Metadata and replay](metadata-and-replay.md#typed-metadata-accessors) keeps
the rules that choose the default of an indexed set and read `isDefault` as
an `xs:boolean`. [SSO acceptance](web-browser-sso-acceptance.md#identity-provider-requested-assertion-consumer)
keeps the rule that verifies a requested ACS URL or index against the service
provider metadata.

#### Signing

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Protect each assertion over HTTP-POST by a signature on the assertion or on the `Response` | Mandatory | Profiles §4.1.4.5, §4.1.3.5, E26, E93 | Always |
| Sign the `Response` that contains a CBC-encrypted assertion | Recommended | Profiles §4.1.3.5, E93 | `RespondSso::allow_unsigned_encrypted_cbc` |

[HTTP-Artifact response](web-browser-sso-artifact.md#identity-provider-delivery)
keeps the rule that signs the assertions or the `Response` that an artifact
delivers.

### Identity provider: `SsoAssertion`

Code: `src/api/sso_outcome.rs`, `src/idp.rs`, `src/idp/login_response.rs`, `src/model/authn_context.rs`, `src/model/subject.rs`

These rows cover the assertion of a `Success` response, and its checks
against the `RequestedAuthnContext`, the `NameIDPolicy`, and the requested
`Subject` of the `AuthnRequest` it answers.

#### Authentication statement

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `AuthnInstant` and an `AuthnContext` on the `AuthnStatement` | Mandatory | Core §2.7.2, `AuthnStatementType` | Always |
| Write the authentication time that `SsoAssertion::new` takes as `AuthnInstant`, in UTC | Mandatory | Core §2.7.2, §1.3.3 | `SsoAssertion::new` |
| Write the caller's session deadline in UTC as `SessionNotOnOrAfter`. Omit it when unset | Optional | Core §1.3.3, §2.7.2, `AuthnStatementType`, E79 | `SsoAssertion::session_not_on_or_after` |
| Reject a success response whose context is not one of the requested references of the same kind, when `Comparison` is `exact` or omitted | Mandatory | Core §3.3.2.2.1 | `SsoAssertion::authn_context` |
| Reject an authentication context reference that is not an absolute URI reference, including one read from a received request | Mandatory | Core §1.3.2, §2.7.2.2 | `SsoAssertion::authn_context` |

#### Subject identifier

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from the issued `NameId`, and omit each one that is unset. An `entity` `NameID` takes none of them, as [name identifier formats](identifiers.md#name-identifier-formats) states | Optional | `NameIDType` | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier`, `NameId::with_sp_provided_id` |
| Issue the `NameID` `Format` the `NameIDPolicy` names, when it is a Core §8.3 format other than `unspecified` or `encrypted` | Mandatory | Core §3.4.1.1, E15, `NameIDPolicyType` | Always |
| Issue the `SPNameQualifier` the `NameIDPolicy` names, under the same condition | Mandatory | Core §3.4.1.1, E15 | Always |
| Honor the requested `SPNameQualifier` namespace when `NameIDPolicy` omits `Format` or requests `unspecified`. A persistent or pairwise transient identifier can omit the qualifier for the direct SP namespace | Mandatory | Core §3.4.1.1, §8.3.7, §8.3.8 | Always |
| Write an `EncryptedID` in each issued assertion subject when `NameIDPolicy` names `encrypted` | Mandatory | Core §3.4.1.1, E6, E15, `SubjectType` | `XmlEncryptionPolicy::identifiers` |
| Issue a `Subject` that strongly matches the requested `NameID` in value, `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`, unless the next row applies. Compare formats after `xs:anyURI` whitespace collapse, and read an omitted format as `unspecified` | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |
| Issue a `NameID` in another format than the requested one when it is the format the `NameIDPolicy` names, without comparing value and qualifiers | Optional | Core §3.4.1.4, E75 | Always |
| Reject a success response to a requested `BaseID`, which an issued `NameID` cannot strongly match | Mandatory | Core §3.4.1.4, §3.3.4 | Always |
| Reject a success response to a requested `EncryptedID` that was not decrypted | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |
| Reject a success response when the requested `Subject` has `SubjectConfirmation` elements and none uses the bearer `Method`, the only one the assertion carries. Compare `Method` after `xs:anyURI` whitespace collapse | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |

[Identifiers](identifiers.md#name-identifier-formats) keeps the rule that
rejects an issued `Format` that is not an absolute URI reference, and the
rules for the `NameID` value and qualifiers.

### Identity provider: `XmlEncryptionPolicy`

Code: `src/crypto/enc/encrypt.rs`, `src/idp.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Encrypt each assertion as an `EncryptedAssertion` | Optional | Core §2.3.4 | `XmlEncryptionPolicy::assertions` |
| Encrypt each subject `NameID` as an `EncryptedID` | Optional | Core §2.2.4, §3.4.1.1 | `XmlEncryptionPolicy::identifiers` |
| Encrypt each `Attribute` as an `EncryptedAttribute` | Optional | Core §2.7.3.2 | `XmlEncryptionPolicy::attributes` |
| Replace `NameID` with `EncryptedID` and `Attribute` with `EncryptedAttribute` in the same location. Each wrapper contains `EncryptedData` for the original element | Mandatory | Core §2.2.4, §2.7.3.2, §6.1, E30 | Always |
| Include `Type` on `EncryptedData` | Recommended | Core §2.2.4, §2.3.4, §2.7.3.2, §6.1 | Always |
| Set a present `EncryptedData` `Type` to `http://www.w3.org/2001/04/xmlenc#Element` | Mandatory | Core §2.2.4, §2.3.4, §2.7.3.2, §6.1 | Always |
| Write different `EncryptedData` ciphertext each time an `EncryptedID` is generated, even for the same `NameID` | Mandatory | Core §2.2.4 | Always |
| Name the chosen certificate in each `EncryptedKey`, as a `ds:X509Certificate` in the `ds:X509Data` of its `ds:KeyInfo` | Recommended | Metadata §2.4.1.1, E68, XML Encryption §3.5.1 | Always |

[XML Signature and XML Encryption algorithms](xml-security-algorithms.md#encrypter-algorithmpolicy)
keeps the rule that embeds the `EncryptedKey` in the `ds:KeyInfo` of
`EncryptedData`, as `EncryptedAssertion` does, and the encryption algorithms.

### Identity provider and service provider: signing flags of `IdpDescriptor` and `SpDescriptor`

Code: `src/metadata/role.rs`, `src/metadata/idp.rs`, `src/metadata/sp.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read `WantAuthnRequestsSigned`, `AuthnRequestsSigned`, and `WantAssertionsSigned` as unqualified `xs:boolean`, and read an omitted one as false | Mandatory | Metadata §2.4.3, §2.4.4, `IDPSSODescriptorType`, `SPSSODescriptorType` | Always |
| On the selected SAML 2.0 role, reject a signing flag qualified with the metadata namespace or carrying an invalid `xs:boolean` value, and ignore same-named foreign attributes | Mandatory | `IDPSSODescriptorType`, `SPSSODescriptorType`, `RoleDescriptorType` | Always |

## Library policies

### Service provider: `start_sso`

Code: `src/sp.rs`, `src/sp/authn_request.rs`, `src/browser/outbound.rs`, `src/config/descriptors.rs`, `src/metadata/generate.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write `Destination` on an unsigned request too | Without it, the identity provider cannot discard a request that reaches an endpoint other than the one the service provider chose. | Core §3.2.1 | Always |
| Send the request to the first identity provider `SingleSignOnService` for the binding with an `https` `Location` | An earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.1.3.3 | Always |
| When no `SingleSignOnService` for the binding has an `https` `Location`, send the request to the first one, even an `http` one | Login keeps working with an identity provider that publishes only `http` endpoints, and a refusal would not move the exchange onto TLS. | Profiles §4.1.3.3 | Always |
| Require `SigAlg` and `Signature` to send an `AuthnRequest` over SimpleSign | Choosing SimpleSign commits the SP to authenticating the request and binding any `RelayState` to it. | CS-01 §2.4, §2.7.2 | Always |
| Refuse to build an unsigned request when the identity provider publishes `WantAuthnRequestsSigned` as `true` or `1` | E7 does not require the refusal, but the service provider can reasonably expect the identity provider to reject an unsigned request. | Metadata §2.4.3, E7 | `SpValidationPolicy::authn_request_signing` |
| Reject a `ProviderName` with a character XML 1.0 forbids | The XML writer cannot represent the character. | `AuthnRequestType` | Always |
| Request the first configured NameID format. With none configured, request the `emailAddress` format that the [generated metadata](metadata-and-replay.md#generating-metadata) advertises | The request then asks for a format the service provider metadata advertises. | Core §3.4.1.1 | `name_id_format`, `name_id_formats` |
| Require the `SPNameQualifier` to be an absolute URI reference of at most 1024 characters with collapsed whitespace | The API uses the syntax of a SAML entity identifier for the requested namespace. | Core §3.4.1.1, §8.3.6 | Always |
| Return an error when a qualifier is set and the requested format is `entity` | No issued entity identifier can satisfy both request conditions. | Core §8.3.6, E15 | Always |
| Write `AssertionConsumerServiceURL` and `ProtocolBinding` from the default endpoint of the response binding, unless an index is set | The request then names its endpoint explicitly. | Core §3.4.1 | `StartSso::acs_index` |

[Browser bindings](browser-bindings.md#sending-relaystate-policies) keeps the
policies for the `RelayState` of the request, and
[for its endpoint query](browser-bindings.md#redirect-endpoint-query-policies).

### Identity provider: `respond_sso`, `respond_sso_refusal`, `initiate_sso`

Code: `src/api/idp.rs`, `src/api/response_acs.rs`, `src/metadata/sp.rs`, `src/idp.rs`, `src/idp/login_response.rs`, `src/model/authn.rs`, `src/entity.rs`, `src/browser/outbound.rs`

<a id="refusal-status-policies"></a>

#### Status and errors

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write top-level `Requester` for a request refused for its age, for a `ProtocolBinding` URI other than HTTP-Redirect and SOAP that this identity provider does not support, for an `AssertionConsumerServiceURL` that is not an absolute HTTP(S) URL, or for a missing signature that only this identity provider requires | The fault lies in the request, which the service provider can send again fresh, signed, or with another binding or location. | Core §3.2.2.2, Profiles §4.1.4.1 | Always |
| Add the subordinate `UnsupportedBinding` to the error `Response` to a request refused for its `ProtocolBinding` | It tells the service provider that the request asked for a response binding this identity provider cannot use. | Core §3.2.2.2 | Always |

[crewjam/saml v0.6.3](https://github.com/crewjam/saml/blob/v0.6.3/identity_provider_error_response.go#L194-L206)
answers a request for an assertion consumer service it cannot send to with
the same status, at the default assertion consumer service.
[Shibboleth IdP 5.2.3](https://codeberg.org/Shibboleth/java-identity-provider/src/tag/5.2.3/idp-conf-impl/src/main/resources/net/shibboleth/idp/module/conf/errors.xml#L24-L29)
shows a local error page when it cannot resolve the requested endpoint.

#### Assertion consumer service

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Answer at the default `AssertionConsumerService` of the SP metadata a refused request whose `AssertionConsumerServiceURL`, `ProtocolBinding`, or `AssertionConsumerServiceIndex` cannot be read, one that carries both an `AssertionConsumerServiceURL` and an `AssertionConsumerServiceIndex`, and one whose `Version` is later than `2.0`, whatever its refusal reason. Fail if the default's binding is not the selected one | An unreadable or doubled field names no single location, the content of a request of a later version is not read, and the metadata default is one the service provider controls, so the error never goes to a location that only the request names. | Core §3.4.1, §4.1.3.1, Profiles §4.1.4.1 | Always |
| Use the current metadata default ACS for an absent index mapping only for an error and when its binding matches the chosen delivery | The identity provider honors the requested index for assertions and uses current metadata to authorize the error route. | Core §3.4.1, Profiles §4.1.4.1, E85 | Always |
| Answer a request that names only a `ProtocolBinding` at the first SAML 2.0 service provider role that publishes that binding, at the endpoint the `isDefault` rule chooses among that role's endpoints of that binding | The role default can use another binding, and the requested binding must be honored, so the default rule applies to that binding's endpoints. | Core §3.4.1, Profiles §4.1.3.5, Metadata §2.2.3 | Always |

#### Signing

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Sign an error `Response` over HTTP-POST | An error carries no assertion to sign, and the signature lets the service provider authenticate its status, `InResponseTo`, and `Destination`. | Profiles §4.1.3.5, §4.1.4.5, E26, E93, Bindings §3.5.5.2 | Always |
| Over HTTP-POST, sign each assertion when the service provider metadata sets `WantAssertionsSigned`, and sign the `Response` otherwise | A `Response` signature also authenticates the status, `InResponseTo`, and `Destination`, and a service provider that asks for assertion signatures gets them. | Profiles §4.1.3.5, §4.1.6, E93 | `RespondSso::sign_response` |
| Require `SigAlg` and `Signature` to send any `Response` over SimpleSign, including an error response | The detached signature authenticates the response and binds any `RelayState` to it. | CS-01 §2.4, §2.7.2 | Always |

#### Response content

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write `Issuer` on every `Response`, also on an error `Response` and on an unsigned one without an encrypted assertion | Reason not recorded. | Core §3.2.2, Profiles §4.1.4.2, E17 | Always |
| Write `Destination` as the assertion consumer service URL also on an HTTP-POST `Response` whose only signatures are on its assertions | Core §3.2.2 makes a recipient discard a response whose present `Destination` names another location, which keeps a forwarded response from reaching an unintended recipient. | Core §3.2.2, Bindings §3.5.5.2 | Always |
| Omit `InResponseTo` from the bearer `SubjectConfirmationData` of an unsolicited response | Profiles §4.1.4.3 has the service provider verify that an unsolicited response carries none, so a value would make it refuse the response. | Profiles §4.1.5 | Always |
| Write the assertion `IssueInstant` as `Conditions` `NotBefore`, and end `Conditions` and the bearer `SubjectConfirmationData` at `IssueInstant` plus the issuance lifetime, 300 seconds by default | The window starts when the assertion exists and bounds how long a bearer assertion can be delivered and replayed, and five minutes leaves time for the browser to deliver it. | Core §2.5.1.2, Profiles §4.1.4.2, E26 | `IdpConfigBuilder::issuance_lifetime` |

#### RelayState

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject `RespondSso::relay_state` on a request that carried a `RelayState`, even with the same value | The response returns the received value, so a second value from the caller is either the same or a value the response must not send. | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |
| In `respond_sso_refusal`, reject every explicit `RespondSso::relay_state`, also when the refused request carried none | Reason not recorded. | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |

[Browser bindings](browser-bindings.md#returning-relaystate-policies) keeps
the policy that returns a received `RelayState` over 80 bytes unchanged, and
[HTTP-Artifact response](web-browser-sso-artifact.md#library-policies) the
`Destination` of a stored `Response`.

### Identity provider: `SsoAssertion`

Code: `src/idp.rs`, `src/model/subject.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a supplied session deadline outside years 1 through 9999 | This is the date range supported by the session time parser. | Core §1.3.3 | `SsoAssertion::session_not_on_or_after` |
| Reject an authentication time later than the moment the response is issued, compared before rounding to the second | An assertion cannot report an authentication after it was issued. | Core §2.7.2 | `SsoAssertion::new` |
| Reject an `AuthnInstant` before year 1 | The formatter writes a four-digit non-negative year. | Core §1.3.3 | `SsoAssertion::new` |
| Write the unspecified class as the authentication context when the caller sets none | The schema requires a context, and that class is the Authentication Context class for unspecified means. | Core §2.7.2.2 | `SsoAssertion::authn_context` |
| When the issued `NameId` has no format, write the first configured NameID format, and omit `Format` when none is configured | Reason not recorded. | Core §2.2.2, E60 | `IdpConfigBuilder::name_id_format`, `IdpConfigBuilder::name_id_formats` |
| Reject a success response when every bearer `SubjectConfirmation` in the requested `Subject` has an identifier or `SubjectConfirmationData` | Such data can constrain the recipient, time, or address in ways the issued bearer confirmation does not meet, and service providers must not send `SubjectConfirmation` (Profiles §4.1.4.1), so the crate does not compare it. | Core §3.3.4, §2.4.1.2 | Always |

<a id="encryption"></a>

### Identity provider: `XmlEncryptionPolicy`

Code: `src/crypto/enc/encrypt.rs`, `src/crypto/enc.rs`, `src/crypto/keys.rs`, `src/metadata/key_certificates.rs`, `src/metadata/sp.rs`, `src/idp.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Encrypt for the first service provider encryption key the configured algorithms can use. Skip a key that does not load or that the crypto provider refuses, such as an EC key or an RSA key too small for the key transport | E68 lets the encrypting party use any published key, and OpenSAML 5.2.0 also skips a credential without a usable key transport. | Metadata §2.4.1.1, E62, E68 | Always |
| Take the keys of the SP role whose `AssertionConsumerService` receives the response. When the request names only its location, and several roles publish that location and binding, take the first such role in document order | E68 scopes keys to one role, and roles that publish one location and binding name one recipient, so document order picks one role's keys without mixing roles. | Metadata §2.4.1.1, E62, E68 | Always |
| Read one key from each `ds:X509Data` of a `KeyDescriptor` whose `use` is `encryption` or absent, in document order. Its sole certificate is the entity certificate, whatever else the `KeyInfo` declares. Among several certificates, the entity certificate is the first one that issued none of the others. If each issued another, it is the first certificate. When the crypto provider refuses a certificate signature, such as SHA-1, its signer does not count as having issued that certificate | XML Signature allows the certificates of an `X509Data` in any order, and OpenSAML 5.2.0 [`InlineX509DataProvider`](https://codeberg.org/Shibboleth/java-opensaml/src/tag/5.2.0/opensaml-xmlsec-impl/src/main/java/org/opensaml/xmlsec/keyinfo/impl/provider/InlineX509DataProvider.java) also reads one credential per `X509Data`, takes a sole certificate as the entity certificate, and falls back to the first certificate. | XML Signature §4.4, §4.4.4, Metadata §2.4.1.1 | Always |
| Look up that certificate only when the response has an element to encrypt | A response without such an element uses no encryption key. | Core §2.7.3.2, E68 | Always |
| Encrypt the inclusive canonical form of the `NameID` or `Attribute` | That form declares every namespace in scope. | Core §6.1 | Always |
| Encrypt each content key for one recipient, and write no `Recipient` on its `EncryptedKey` | The message has one receiving entity, Core §2.2.4, §2.3.4, and §2.7.3.2 recommend `Recipient` for an `EncryptedKey` beside `EncryptedData`, and with one embedded key a decrypter has no key to choose between. | Core §2.2.4, §2.3.4, §2.7.3.2, E43 | Always |
| Encrypt the `NameID` or `Attribute` before the assertion or response is signed | The signature then covers the ciphertext, and E43 and E93 replace the original Core §6.2 ordering rule. | Core §6.2, E43, E93 | Always |

The identity provider encrypts with the configured `AlgorithmPolicy`
algorithms and reads no `md:EncryptionMethod` of a `KeyDescriptor`
(Metadata §2.4.1.1), so it neither chooses an algorithm from them nor prefers
a key that lists the configured one. [Metadata and replay](metadata-and-replay.md#not-implemented)
lists that gap. OpenSAML 5.2.0
[`SAMLMetadataEncryptionParametersResolver`](https://codeberg.org/Shibboleth/java-opensaml/src/tag/5.2.0/opensaml-saml-impl/src/main/java/org/opensaml/saml/security/impl/SAMLMetadataEncryptionParametersResolver.java)
also keeps a credential whose listed methods it cannot use and encrypts with
its configured algorithms.

<a id="not-implemented"></a>
<a id="deployment-duties-for-the-request"></a>

## Application duties

The identity provider application reads the request through the
`Received<AuthnRequest>` that `receive_sso` returns, and the crate enforces
none of these duties.

| Duty | Level | Section |
| --- | --- | --- |
| Make the HTTP exchanges that carry the request over TLS: the service provider serves its redirect or form over `https`, and the identity provider publishes an `https` `SingleSignOnService` | Recommended | Profiles §4.1.3.3 |
| Make the HTTP requests that deliver the `Response` or its artifact over TLS: the service provider publishes `https` `AssertionConsumerService` locations, and the identity provider serves its form or redirect over `https` | Recommended | Profiles §4.1.3.5, E93 |
| When `AuthnRequest::force_authn` is true, authenticate the principal directly. When `ForceAuthn` and `IsPassive` are both true, do not freshly authenticate unless the `IsPassive` constraints can be met | Mandatory | Core §3.4.1 |
| When `AuthnRequest::passive` is true, do not let the identity provider or the user agent visibly take control of the user interface | Mandatory | Core §3.4.1 |
| Judge the `minimum`, `better`, and `maximum` comparisons of `AuthnRequest::requested_authn_context` | Mandatory | Core §3.3.2.2.1, E45 |
| When no requested context can be met, pass `SsoOutcome::Failure` with a top-level `Responder` status, optionally with `NoAuthnContext` | Mandatory | Core §3.3.2.2.1, E65 |
| Pass `SsoOutcome::Failure`, which writes no assertion, when authentication fails, the requested principal is unrecognized, or identity provider policy prevents issuance | Mandatory | Core §3.4.1.4, Profiles §4.1.4.1, §4.1.4.2, E75 |
| Pass `SsoOutcome::Failure` when the `NameIDPolicy` cannot be met, optionally with `InvalidNameIDPolicy` | Mandatory | Core §3.4.1.1 |
| Pass `SsoOutcome::Failure` when `NameIDPolicy` requests both the `entity` format and an `SPNameQualifier`, which no issued entity identifier can satisfy | Mandatory | Core §8.3.6, E15 |
| Pass `SsoAssertion::new` the time at which the subject authenticated, which only the caller knows | Mandatory | Core §2.7.2 |
| When the issued `NameID` takes the `NameIDPolicy` format in place of the format of the requested `NameID`, establish that both identifiers name the same principal | Mandatory | Core §3.4.1.4, E75 |

<a id="not-implemented-in-the-service-provider-request"></a>

## Not supported

- An `AuthnRequest` by HTTP-Artifact. Optional, Profiles §4.1.3.3.
  [HTTP-Artifact response](web-browser-sso-artifact.md#not-supported) lists
  it for both roles.
- An `AuthnRequest` or a `Response` over HTTP-POST-SimpleSign without
  `SigAlg` and `Signature`. Optional, CS-01 §2.4. Send a message that needs
  no detached signature over HTTP-POST when the peer supports that binding. [Single Logout](single-logout.md) keeps the signing rules of its
  own messages.
- `Scoping`, with `IDPList`, `RequesterID`, and `ProxyCount`, in the service
  provider request. Optional, Core §3.4.1.2. An application that proxies the
  request outside the crate applies Core §3.4.1.5 itself.
- The holder-of-key Web Browser SSO profile, which the
  [SAML V2.0 Holder-of-Key Web Browser SSO Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf)
  (Committee Specification 02) defines. The identity provider writes only the
  bearer confirmation.
