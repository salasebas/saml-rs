# Name identifier management

`IdentityProvider` and `ServiceProvider` change or end a name identifier they
share. Over HTTP-Redirect, either role sends a `ManageNameIDRequest` with
`start_name_id_management_redirect`, reads one with
`receive_name_id_management_redirect`, answers it with
`respond_name_id_management_redirect`, and reads the answer with
`finish_name_id_management_redirect`. Over SOAP, only the identity provider
takes part: `start_name_id_management` sends a request and
`StartedNameIdManagement::finish` reads the answer, and
`receive_name_id_management` reads a service provider's request and
`respond_name_id_management` answers it.

Normative text is Core §3.2 and §3.6, Profiles §4.5, Bindings §3.2 and §3.4,
and Metadata §2.4.2, as corrected by Approved Errata 05 (E8, E11, E12, E14,
E19, E43, E55). Conformance Table 2 makes HTTP-Redirect `MUST` for the IdP and
the SP, SOAP `MUST` for the IdP and `OPTIONAL` for the SP, and every cell
`MUST NOT` for IdP Lite and SP Lite. This record does not claim the IdP or SP
operational mode.

[Identifiers](identifiers.md#name-identifier-formats) has the `NameID`
format, length, and whitespace rules, and both bindings use its
[issuer](identifiers.md#entity-identifiers) rules and the shared
[status code](web-browser-sso-acceptance.md#status-codes) rules.
[Browser bindings](browser-bindings.md) has the HTTP-Redirect encoding,
`RelayState`, signature-input, and cache-header rules, and the HTTP duties of
the application. The [SOAP envelope rules](artifact-resolution.md#soap-envelope-rules)
cover the SOAP envelope and its body, the HTTP headers of a SOAP request and
response, and the transport.

The statuses hold on builds with a crypto provider. On a build without one,
`start_name_id_management_redirect` and `respond_name_id_management_redirect`
return `SamlError::Unsupported`, and the HTTP-Redirect receive operations
refuse every message, because the build neither signs nor verifies. Over
SOAP, its identity provider still exchanges unsigned messages on the
`SoapChannel`, returns an error for an identifier it would encrypt, answers a
received encrypted one as undecryptable, and refuses a signed request with
`Responder`, or with an error when the request declares a later major version.

## Support

### Messages and bindings

A status covers the role's part in the feature: sending, receiving, or both.

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `ManageNameIDRequest` over HTTP-Redirect, sent and received | Profiles §4.5.3.1, Bindings §3.4 | Supported | Supported |
| `ManageNameIDResponse` over HTTP-Redirect, sent and received | Profiles §4.5.3.2, Bindings §3.4 | Supported | Supported |
| `RelayState` with an HTTP-Redirect request | Profiles §4.5.3.1, Bindings §3.4.3 | Supported | Supported |
| `ManageNameIDRequest` over SOAP, sent and received | Profiles §4.5.3.1, Bindings §3.2 | Supported | Not supported |
| `ManageNameIDResponse` over SOAP, sent and received | Profiles §4.5.3.2, Bindings §3.2 | Supported | Not supported |
| `ManageNameIDRequest` and `ManageNameIDResponse` over HTTP-POST | Profiles §4.5.3.1, §4.5.3.2, Bindings §3.5 | Not supported | Not supported |
| `ManageNameIDRequest` and `ManageNameIDResponse` over HTTP-Artifact | Profiles §4.5.3.1, §4.5.3.2, Bindings §3.6 | Not supported | Not supported |
| A signature on each HTTP-Redirect message sent, and its verification on a received one | Profiles §4.5.3.1, §4.5.3.2, Bindings §3.4.4.1 | [Partial](browser-bindings.md#detached-signatures) | [Partial](browser-bindings.md#detached-signatures) |
| A signature on a SOAP message, sent | Core §3.6.1, §3.6.2, Profiles §4.5.4.1, §4.5.4.2 | Not supported | Not supported |
| A signature on a SOAP message, verified on receipt | Core §3.2.1, §3.2.2, Profiles §4.5.4.1, §4.5.4.2 | Supported | Not supported |
| An unsigned SOAP message that the channel authenticates, sent and received | Profiles §4.5.3.1, §4.5.3.2, §4.5.4.1, §4.5.4.2 | Supported | Not supported |
| `ManageNameIDService` endpoints of the peer's metadata, `ResponseLocation` included | Profiles §4.5.3.1, §4.5.3.2, §4.5.5, Metadata §2.4.2, E41 | Supported | Supported |

[Metadata documents](metadata-and-replay.md#metadata-documents) has the
support for publishing `ManageNameIDService`, which the generators write
without `ResponseLocation`.

### Requests

A status covers each binding on which the role takes part: HTTP-Redirect at
both roles, and SOAP at the identity provider.

| Feature | Section | Identity provider sends | Identity provider receives | Service provider sends | Service provider receives |
| --- | --- | --- | --- | --- | --- |
| `NameID` of the identifier as both providers know it | Core §3.6.1, §3.6.3 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| `NewID` from the identity provider, the new `NameID` value | Core §3.6.1, §3.6.3, E12, E55 | Supported | — | — | Supported |
| `NewID` from the service provider, the new `SPProvidedID` | Core §3.6.1, §3.6.3, E55 | — | Supported | Supported | — |
| `Terminate` | Core §3.6.1, §3.6.3, E8, E14, E55 | Supported | Supported | Supported | Supported |
| `EncryptedID` in place of `NameID` | Core §3.6.1, §3.6.3, Conformance §3.4 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| `NewEncryptedID` in place of `NewID` | Core §3.6.1, §3.6.3, E12 | Supported | Supported | Supported | Supported |
| `EncryptedID` with a plaintext `NewID`, or `NameID` with `NewEncryptedID` | Core §3.6.3 | Not supported | Supported | Not supported | Supported |

### Responses

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| Top-level `StatusCode` with an optional subordinate code, such as `UnknownPrincipal` | Core §3.2.2.2, §3.6.3 | Supported | Supported |
| `StatusMessage` | Core §3.2.2.1, §3.2.2.3 | Not supported | Not supported |
| `VersionMismatch` answer to a request of a newer version | Core §4.1.3.1, §4.1.3.2 | Supported | Supported |
| The request's `RelayState`, returned in an HTTP-Redirect response | Bindings §3.4.3 | Supported | Supported |
| Adding a `RelayState` to a response when the request carried none | Bindings §3.4.3 | Not supported | Not supported |

`Consent`, caller extensions, and `StatusDetail` are in
[common message fields](common-message-fields.md).

## Partial support

### Service provider requests

- **Supported:** `ServiceProvider::start_name_id_management_redirect` writes
  the `NameID` of the `NameId` it is given and the new value as `NewID`, in
  the clear or encrypted. It refuses a `Format` that is not an absolute URI
  reference, and a `NameID` value or qualifier, or a `NewID`, that is empty or
  holds only XML whitespace. A `NewID` becomes the `SPProvidedID` that the
  identity provider sends from then on.
- **Not supported:** it writes an `entity` `NameID` that breaks Core §8.3.6
  unchanged, as [identifiers](identifiers.md#service-provider-requests)
  records for both service provider requests.

## Rules

<a id="turning-the-protocol-on"></a>

### Identity provider and service provider: `start_name_id_management`, `start_name_id_management_redirect`

Code: `src/name_id_management/xml.rs`, `src/model/subject.rs`, `src/entity.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Do not create a request for a transient identifier, including an unformatted `NameId` whose identity-provider default format is transient. Both operations return an error | Mandatory | Core §3.6, E14 | Always |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Write the requesting entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.1 | Always |
| Write the value of the `NameId` given as the `NameID`, with its `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` | Mandatory | Core §3.6.1, §3.6.3 | Always |
| For a persistent identifier, write each qualifier whose established value differs from `Issuer`. The writer fills a missing `NameQualifier` with the identity provider's entity ID and a missing `SPNameQualifier` with the service provider's | Mandatory | Core §3.6.3 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Write each persistent qualifier also when it equals `Issuer`, which Core §3.6.3 lets the requester omit | Recommended | Core §3.6.3 | Always |
| Write `NewID` with the new value only, or an empty `Terminate` | Mandatory | E12, E55, `TerminateType` | `NameIdChange` |

The identity provider's whitespace, length, and `entity` checks on its
`NameID` and `NewID` are in [identifiers](identifiers.md#name-identifier-formats).
A service provider refuses a blank `NameID` value, qualifier, or `NewID`, as
its [identifier rule](identifiers.md#service-provider-name-id-strings) says.
It writes its `NameID` value and qualifiers otherwise unchanged, as the
[service provider request policy](identifiers.md#service-provider-request-policy)
records, and its `NewID` sets an `SPProvidedID`, which has no 256-character
limit.

### Identity provider and service provider: `ManageNameIDService` endpoints

Code: `src/config/descriptors.rs`, `src/config/builders.rs`, `src/metadata/generate.rs`, `src/metadata/mod.rs`, `src/api/peer.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish a `ManageNameIDService` for each configured endpoint: SOAP and HTTP-Redirect at the identity provider, and HTTP-Redirect at the service provider | Optional | Metadata §2.4.2 | `IdpConfigBuilder::manage_name_id_service`, `SpConfigBuilder::manage_name_id_redirect_service` |
| Address the peer by its role descriptor: the `Binding` and `Location` of a `ManageNameIDService` for a request, and its `ResponseLocation`, else `Location`, for an HTTP-Redirect response | Optional | Profiles §4.5.3.1, §4.5.3.2, Metadata §2.2.2, E41 | Always |
| On HTTP-Redirect, send a request or a response only to an `https` peer endpoint | Recommended | Profiles §4.5.3.1, §4.5.3.2 | `StartNameIdManagement::allow_http`, `RespondNameIdManagement::allow_http`, `ReceiveNameIdManagement::allow_http` for a refusal |

[Metadata generation](metadata-and-replay.md#roles-endpoints-and-keys) writes
`ManageNameIDService` in schema order, after `SingleLogoutService` and before
`NameIDFormat`.

<a id="soap-managenameidrequest-from-the-identity-provider"></a>

### Identity provider: `start_name_id_management`

Code: `src/name_id_management.rs`, `src/soap.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the request over SOAP 1.1 | Optional | Profiles §4.5.3.1, Bindings §3.2.2 | `start_name_id_management` |
| Set `Destination` to the `Location` of the service provider's first SOAP `ManageNameIDService` | Optional | Core §3.2.1 | Always |
| Authenticate the identity provider to the service provider and protect message integrity, by signing or by a binding mechanism. The crate does not sign the request and sends it over a mutually authenticated, integrity-protected `SoapChannel` | Mandatory | Profiles §4.5.3.1, §4.5.4.1 | `SoapChannel` |

<a id="http-redirect-managenameidrequest"></a>

### Identity provider and service provider: `start_name_id_management_redirect`

Code: `src/api/name_id_management/redirect.rs`, `src/name_id_management/redirect.rs`, `src/binding/signed_message.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Sign the request | Mandatory | Profiles §4.5.3.1 | Always |
| Set `Destination` to the `Location` of the peer endpoint | Mandatory | Bindings §3.4.5.2 | Always |
| Send a caller-supplied `RelayState` with the request | Optional | Profiles §4.5.3.1, Bindings §3.4.3 | `StartNameIdManagement::relay_state` |

### Identity provider and service provider: `receive_name_id_management`, `receive_name_id_management_redirect`

Code: `src/name_id_management.rs`, `src/name_id_management/redirect.rs`, `src/model/status.rs`

These rows apply to an authenticated request from the peer at this provider's
endpoint. Over SOAP, the `SoapChannel` and any present signature authenticate
the request, and over HTTP-Redirect its verified signature does.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require at most one `Issuer`, `ds:Signature`, and `Extensions` in that order, then one `NameID` or `EncryptedID`, then one `NewID`, `NewEncryptedID`, or `Terminate`, with text-only `NameID` and `NewID` and an empty `Terminate` | Mandatory | `RequestAbstractType`, `ManageNameIDRequestType`, `TerminateType` | Always |
| Answer a request whose content breaks those rules with `Requester` | Mandatory | Profiles §4.5.3.2, Core §3.2.1 | `NameIdManagementRefusal::MalformedRequest` |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer request version with `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version | Mandatory | Core §4.1.3.2, Profiles §4.5.3.2 | `NameIdManagementRefusal::VersionMismatch` |
| Return an error for an older request version that forbids a SAML 2.0 response, also over SOAP when its signature does not verify | Mandatory | Core §4.1.3.2 | Always |
| Answer a request that the age window refuses with top-level `Requester` | Mandatory | Core §3.2.1, Profiles §4.5.3.2 | `NameIdManagementRefusal::RequestAgeOutsideWindow` |

<a id="soap-managenameidrequest-from-the-service-provider"></a>

### Identity provider: `receive_name_id_management`

Code: `src/name_id_management.rs`, `src/soap.rs`, `src/crypto/verify.rs`, `src/model/status.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present request signature, including on a protected channel, and pass no change from a request whose signature is invalid | Mandatory | Core §3.2.1 | Always |
| Require the verified signature to cover the request element | Mandatory | Core §3.2.1 | Always |
| Answer a request from the service provider, on its attested `SoapChannel` and at this identity provider's endpoint, whose present signature does not verify with `Requester`, before replay storage | Mandatory | Core §3.2.1, Profiles §4.5.3.2 | `NameIdManagementRefusal::RequestDenied` |
| Add the second-level status `RequestDenied` to that answer | Optional | Core §3.2.2.2 | Always |
| Answer such a request whose present signature this build cannot verify, because it has no crypto provider or the provider fails to start, with `Responder`, before replay storage | Mandatory | Core §3.2.2.2, Profiles §4.5.3.2 | `NameIdManagementRefusal::VerificationUnavailable` |
| Answer a request that declares a later major version with neither `Requester` nor `Responder`, also when its signature does not verify or cannot be verified | Mandatory | Core §4.1.3.2 | Always |
| Compare a present `Destination` with the receiving SOAP `ManageNameIDService` after collapsing XML whitespace. Accept an absent value | Mandatory | Core §3.2.1, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |

<a id="http-redirect-receiving-a-managenameidrequest"></a>

### Identity provider and service provider: `receive_name_id_management_redirect`

Code: `src/name_id_management/redirect.rs`, `src/flow.rs`, `src/flow/detached.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require `Destination` on the signed request. Compare it with the receiving `ManageNameIDService` after collapsing XML whitespace | Mandatory | Core §3.2.1, Bindings §3.4.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |

### Identity provider and service provider: `respond_name_id_management`, `respond_name_id_management_redirect`

Code: `src/name_id_management.rs`, `src/name_id_management/xml.rs`, `src/api/name_id_management/redirect.rs`, `src/model/status.rs`, `src/xml/name.rs`, `src/xml/write.rs`

These rows also cover the refusal that `receive_name_id_management` and
`receive_name_id_management_redirect` return.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer every processed request with a `ManageNameIDResponse` | Mandatory | Core §3.6.2, Profiles §4.5.3.2 | `respond_name_id_management`, `respond_name_id_management_redirect` |
| Answer an HTTP-Redirect request over HTTP-Redirect, through the user agent to the requester's response endpoint | Optional | Profiles §4.5.3.2 | Always |
| For a `2.0` request, write `ID`, `Version` `2.0`, a UTC `IssueInstant`, and `InResponseTo` equal to the request `ID` | Mandatory | `StatusResponseType`, Core §3.2.2, §4.1.3.2 | Always |
| Write `InResponseTo` only as an `xs:NCName` | Mandatory | `StatusResponseType` | Always |
| Write the responding entity's ID as `Issuer`, with `Format` omitted or `entity`. The writer omits `Format` | Mandatory | Profiles §4.5.4.2 | Always |
| Refuse to write a subordinate status code that is not an absolute URI, including one read from a peer's response | Mandatory | Core §1.3.2, `StatusCodeType` | Always |

The application chooses the `status` argument, as the
[application duties](#application-duties) describe.

<a id="soap-managenameidresponse-from-the-identity-provider"></a>

### Identity provider: `respond_name_id_management`

Code: `src/name_id_management.rs`, `src/soap.rs`, `src/xml/name.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Omit `InResponseTo` from the response, a refusal included, to a request whose `ID` is not an `xs:NCName` | Mandatory | Core §3.2.2, Profiles §4.5.3.2 | Always |
| Authenticate the identity provider to the service provider and protect message integrity, by signing or by a binding mechanism. The crate does not sign the response and returns it on the request's mutually authenticated, integrity-protected `SoapChannel` | Mandatory | Profiles §4.5.3.2, §4.5.4.2 | `SoapChannel` |
| Omit `Destination` | Optional | Core §3.2.2 | Always |

<a id="http-redirect-managenameidresponse"></a>

### Identity provider and service provider: `respond_name_id_management_redirect`

Code: `src/api/name_id_management/redirect.rs`, `src/name_id_management/redirect.rs`, `src/binding/signed_message.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Sign the response, a refusal included | Mandatory | Profiles §4.5.3.2 | Always |
| Set `Destination` to the peer endpoint that receives the response | Mandatory | Bindings §3.4.5.2 | Always |

### Identity provider and service provider: `StartedNameIdManagement::finish`, `finish_name_id_management_redirect`

Code: `src/xml/status.rs`, `src/model/status.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require one `Status` with one direct `StatusCode` | Mandatory | `StatusResponseType`, `StatusType` | Always |

<a id="soap-managenameidresponse-from-the-service-provider"></a>

### Identity provider: `StartedNameIdManagement::finish`

Code: `src/name_id_management.rs`, `src/soap.rs`, `src/crypto/verify.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present response signature, including on a protected channel, and rely on no content of a response whose signature is invalid | Mandatory | Core §3.2.2 | Always |
| Require the verified signature to cover the response element | Mandatory | Core §3.2.2 | Always |

<a id="http-redirect-receiving-a-managenameidresponse"></a>

### Identity provider and service provider: `finish_name_id_management_redirect`

Code: `src/api/name_id_management/redirect.rs`, `src/name_id_management/redirect.rs`, `src/flow.rs`, `src/flow/detached.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require `Destination` on the signed response. Compare it with this provider's response location after collapsing XML whitespace | Mandatory | Core §3.2.2, Bindings §3.4.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |

<a id="encryptedid-and-newencryptedid"></a>

### Identity provider and service provider: `EncryptedID` and `NewEncryptedID`

Code: `src/name_id_management/encryption.rs`, `src/name_id_management.rs`, `src/crypto/enc/encrypt.rs`, `src/crypto/enc/decrypt.rs`

These rows apply to SOAP at the identity provider and to HTTP-Redirect at
either provider.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send `NameID` and `NewID` by default, or both encrypted as `EncryptedID` and `NewEncryptedID`, whose plaintext is a `NewID` with the new value only. No option encrypts only one, and `Terminate` is never encrypted | Optional | Core §3.6.1, §3.6.3, E12 | `StartNameIdManagement::identifier_encryption`, `IdentifierEncryptionPolicy::EncryptIdentifiers` |
| Support `EncryptedID` wherever the operational mode requires `NameID` support | Mandatory | Conformance §3.4 | `IdentifierEncryptionPolicy::EncryptIdentifiers`, `Credentials::with_decryption_credential` |
| Require the `NewEncryptedID` plaintext to be one text-only `NewID` | Mandatory | E12, `NewID` | Always |
| Require text-only content in a `NameID` that `EncryptedID` carries | Mandatory | `NameIDType` | Always |
| With a crypto provider and decryption credentials, accept `NameID` or `EncryptedID`, whatever `XmlEncryptionPolicy::identifiers` says | Mandatory | Conformance §3.4 | `Credentials::with_decryption_credential` |
| Accept `NewID` or `NewEncryptedID`, whichever form the identifier has, under the same conditions | Optional | Core §3.6.1, §3.6.3 | `Credentials::with_decryption_credential` |
| For a SAML-domain decryption error over SOAP, return a SAML error status in the response | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | Always |

The responder finds the key of each encrypted identifier by the
[key resolution rules](xml-security-algorithms.md#key-resolution).

## Library policies

### Identity provider and service provider: `start_name_id_management`, `start_name_id_management_redirect`

Code: `src/name_id_management/xml.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write an identity provider `NameId` without a format with the first configured NameID format, if any, and a service provider one without `Format`. A caller passes any other established format, `Unspecified` for an omitted one | Responses and `LogoutRequest` write that `NameId` the same way. | Core §2.2.2, E60 | `NameId::with_format` |

### Identity provider and service provider: `ManageNameIDService` endpoints

Code: `src/config/descriptors.rs`, `src/name_id_management.rs`, `src/api/name_id_management/redirect.rs`, `src/api/peer.rs`, `src/model/validation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Neither send nor accept the protocol on a binding without a published `ManageNameIDService` for it | Table 2 prohibits the protocol for IdP Lite and SP Lite, and only the endpoint tells a full configuration from a Lite one. | Conformance Table 2 | `IdpConfigBuilder::manage_name_id_service`, `SpConfigBuilder::manage_name_id_redirect_service` |
| On HTTP-Redirect, send a request to the peer's first `ManageNameIDService` whose `Location` is `https`, and a response to the first whose response endpoint is `https`, or to the first one under `allow_http` | An earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.5.3.1, §4.5.3.2 | `StartNameIdManagement::allow_http`, `RespondNameIdManagement::allow_http`, `ReceiveNameIdManagement::allow_http` for a refusal |
| Reject a supplied receiving URL that this provider does not publish as a `ManageNameIDService` for the binding and direction | The URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this party does not operate. | Core §3.2.1, §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Without a supplied URL, reject several published `ManageNameIDService` locations for the binding and direction when a `Destination` is compared. A SOAP request without `Destination` needs no unique local endpoint | The library is not told which endpoint received the message, and accepting any published one would not check the location that received it. | Core §3.2.1, §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |

### Identity provider: `start_name_id_management`

Code: `src/api/name_id_management.rs`, `src/logout/creation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a `RelayState` | The SOAP binding has no place to carry `RelayState`, so it is rejected rather than dropped. | Bindings §3.2, §3.4.3 | `StartNameIdManagement::relay_state` |

### Identity provider and service provider: `receive_name_id_management`, `receive_name_id_management_redirect`

Code: `src/name_id_management.rs`, `src/name_id_management/redirect.rs`, `src/model/validation.rs`, `src/xml/protocol_element.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Require `ID`, `Version`, and a UTC `IssueInstant` | [Baseline receipt](xml-schema-validation.md#baseline-receipt) gives the reason. | `RequestAbstractType`, Core §1.3.3 | Always |
| Return an error, with no response, for a request that is not authenticated as the peer's, by the `SoapChannel` over SOAP and by its signature over HTTP-Redirect, that is not from the peer, or that is misaddressed, and for a stored request `ID` | Only a request authenticated as the peer's identifies the requesting provider that Profiles §4.5.3.2 has the responder answer, Core §3.2.1 discards a misaddressed request, and the first copy of a repeated request was already answered. | Profiles §4.5.3.2, Core §3.2.1 | Always |
| Refuse an authenticated 2.0 request outside the configured age window, before replay storage and decryption, so its `ID` stays out of the replay cache | The age window limits acceptance after replay storage expires. | Core §1.3.3 | `SamlValidationContext::with_manage_name_id_request_age`. Disabled by default |
| Add no subordinate code to the `Requester` status of that refusal | Core defines no subordinate code for a stale request, and the caller reads the reason from the refusal. | Core §3.2.2.2 | Always |
| Reject a repeated request `ID`. Store it as the [protocol message ID rule](metadata-and-replay.md#protocol-message-ids) states | Name identifier management requires no identifier cache, so the cache is the caller's choice. | — | `ReplayPolicy::RequireCache`, `SamlValidationContext::with_replay_retention` |
| Accept a persistent `NameID` without its qualifiers | The receiver preserves the identifier as sent, including absent qualifiers. | Core §3.6.3 | Always |
| Return a request with a transient `NameID` to the caller, who answers with an error status | E14 binds the requester, and Core §3.6.2 still requires an answer. | E14, Core §3.6.2 | Always |

With an enabled age window, a `with_replay_retention` longer than `max_age`
plus both clock-skew tolerances covers the full window on either binding,
because the window includes both ends and a stored `ID` expires at its
deadline.

### Identity provider: `receive_name_id_management`

Code: `src/name_id_management.rs`, `src/soap.rs`, `src/crypto/verify.rs`, `src/model/status.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a SOAP body that holds anything but one `ManageNameIDRequest` | A `Body` without one `ManageNameIDRequest` does not identify the request to process. | Bindings §3.2.2.1 | Always |
| Require a mutually authenticated, integrity-protected `SoapChannel`, for a signed request as well | Profiles §4.5.4.1 lets the service provider authenticate by signing alone, but the crate's unsigned SOAP response needs the channel to authenticate the identity provider under Profiles §4.5.4.2, and `SoapChannel` can attest only mutual authentication, not the server side alone. | Profiles §4.5.4.1, §4.5.4.2 | `SoapChannel` |
| Verify a request signature with the SP's configured signing keys or HMAC secret | The caller binds the receipt to the SP it authenticated on the SOAP channel. | Profiles §4.5.4.1 | SP metadata or HMAC secret |
| Require the verified signature to reference the request's `ID`. See [SOAP body signatures](xml-security-algorithms.md#soap-body-signatures) | Core §5.4.2 binds the signer, and the receiver accepts only a signature over the request it reads. | Core §5.4.2 | Always |
| Allow enveloped signature and canonicalization transforms | A signature must cover the entire request. | Core §5.4.4 | Always |
| Require an `Issuer` equal to the service provider | The responder ties the change to the service provider by that `Issuer` and the `SoapChannel`. | Profiles §4.5.4.1 | Always |
| Refuse an `Issuer` whose `Format` is neither omitted nor `entity` | Reason not recorded. | Profiles §4.5.4.1 | Always |
| Return the signature error, and no refusal, for a request of a later major version whose present signature does not verify or cannot be verified | A `Requester` or `Responder` answer would break Core §4.1.3.2 if that version is genuine, and a `VersionMismatch` answer would rely on the `Version` of a request whose signature failed, which Core §3.2.1 forbids. | Core §3.2.1, §4.1.3.2, Profiles §4.5.3.2 | Always |

[PySAML2 v7.5.5](https://github.com/IdentityPython/pysaml2/blob/v7.5.5/src/saml2/request.py#L60-L71)
raises `IncorrectlySigned` for a `ManageNameIDRequest` whose signature does
not verify, before it
[reads the `Version`](https://github.com/IdentityPython/pysaml2/blob/v7.5.5/src/saml2/request.py#L126-L129),
and writes no response. Shibboleth IdP 5.2.3 and SimpleSAMLphp 2.5.5
implement no name identifier management.

### Identity provider and service provider: `receive_name_id_management_redirect`

Code: `src/name_id_management/redirect.rs`, `src/api/name_id_management/redirect.rs`, `src/api/peer.rs`, `src/flow.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an unsigned request | The Redirect signature authenticates the peer and protects the message across the browser redirect. | Profiles §4.5.3.1, §4.5.4.1 | Always. An HMAC signature uses the secret from `with_hmac_secret` on the peer descriptor |
| Require an `Issuer` equal to the peer descriptor's entity ID | Profiles §4.5.4.1 requires an `Issuer` and does not name the descriptor, and the signature is verified with that descriptor's keys, so the change is attributed to it. | Profiles §4.5.4.1 | Always |
| Compare only the `Issuer` value, and accept any `Format` | The signature verified with the peer descriptor's keys attributes the request, so a peer that writes another `Format` still completes the exchange. | Profiles §4.5.4.1 | Always |

### Identity provider and service provider: `respond_name_id_management`, `respond_name_id_management_redirect`

Code: `src/name_id_management.rs`, `src/api/name_id_management/redirect.rs`, `src/api/peer.rs`, `src/xml/name.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Over HTTP-Redirect, for a request whose `ID` is not an `xs:NCName`, return an error and write no response, also where the receiver would answer a refusal | The response reaches the requester through the user agent, and without the `InResponseTo` that Core §3.2.2 omits for such a request nothing ties it to the pending request. | Core §3.2.1, §3.2.2 | Always |
| Answer only a request received from the given peer | The receipt records the peer that sent the request, and a response built for another descriptor would answer for a peer that did not send it, at another party's endpoint on HTTP-Redirect. | — | Always |
| Answer only a request received over the operation's binding: SOAP for `respond_name_id_management`, and HTTP-Redirect for `respond_name_id_management_redirect` | A SOAP response answers the synchronous exchange of its request. | Profiles §4.5.3.2 | Always |

### Identity provider and service provider: `StartedNameIdManagement::finish`, `finish_name_id_management_redirect`

Code: `src/soap.rs`, `src/name_id_management.rs`, `src/flow.rs`, `src/xml/status.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Require the unqualified response `InResponseTo`, after XML whitespace collapse, to equal the pending request ID, including on an error response | A missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2, `StatusResponseType`, XML Schema Part 2 §4.3.6 | Always |
| Report a status other than `Success` as an error that carries the peer's status, after the signature, issuer, and `InResponseTo` checks, and on HTTP-Redirect the `Destination` check | Only `Success` confirms the change, the caller needs the peer's refusal status, and failed authentication or correlation takes precedence over a reported status. | Core §3.2.2.2, §3.6.3 | Always |

### Identity provider: `StartedNameIdManagement::finish`

Code: `src/name_id_management.rs`, `src/soap.rs`, `src/crypto/verify.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a SOAP body that holds anything but one `ManageNameIDResponse` | A `Body` without one `ManageNameIDResponse` does not identify the response to read. | Bindings §3.2.2.1 | Always |
| Require `ID`, `Version`, and a UTC `IssueInstant` | [Baseline receipt](xml-schema-validation.md#baseline-receipt) gives the reason. | `StatusResponseType`, Core §1.3.3, §3.2.2 | Always |
| Accept only response version `2.0` | The reader implements only SAML 2.0, and Core §4.1.3.2 bars a higher response version for a 2.0 request. | Core §4.1.3.2 | Always |
| Require an `Issuer` equal to the service provider | The requester attributes the response to the service provider by that `Issuer` and the `SoapChannel`. | Profiles §4.5.4.2 | Always |
| Refuse an `Issuer` whose `Format` is neither omitted nor `entity` | Reason not recorded. | Profiles §4.5.4.2 | Always |
| Accept a present `Destination` without comparing it | [Artifact resolution](artifact-resolution.md#service-provider-acceptance) gives the reason and the reading of Core §3.2.2 for a SOAP reply. | Core §3.2.2, Bindings §3.2 | Always |
| Require the mutually authenticated, integrity-protected `SoapChannel` attested at start, for a signed response as well | The crate sends the request unsigned, so the channel must authenticate the identity provider to the service provider under Profiles §4.5.4.1, and `SoapChannel` can attest that only as mutual authentication. | Profiles §4.5.4.1, §4.5.4.2 | `SoapChannel` |
| Verify a response signature with the SP's signing keys captured at start, or its HMAC secret | The caller binds the response to the authenticated peer and its pending SOAP exchange. | Profiles §4.5.4.2 | SP metadata or HMAC secret |
| Require the verified signature to reference the response's `ID`. See [SOAP body signatures](xml-security-algorithms.md#soap-body-signatures) | Core §5.4.2 binds the signer, and the receiver accepts only a signature over the response it reads. | Core §5.4.2 | Always |
| Allow enveloped signature and canonicalization transforms | A signature must cover the entire response. | Core §5.4.4 | Always |

### Identity provider and service provider: `finish_name_id_management_redirect`

Code: `src/api/name_id_management/redirect.rs`, `src/name_id_management/redirect.rs`, `src/api/peer.rs`, `src/flow.rs`, `src/model/validation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an unsigned response | The Redirect signature authenticates the peer and protects the message across the browser redirect. | Profiles §4.5.3.2, §4.5.4.2 | Always. An HMAC signature uses the secret from `with_hmac_secret` on the peer descriptor |
| Require the response to come from the peer the request went to | Another peer must not complete the pending transaction. | Profiles §4.5.4.2 | Always |
| Compare only the `Issuer` value, and accept any `Format` | The signature verified with the peer descriptor's keys attributes the response, so a peer that writes another `Format` still completes the exchange. | Profiles §4.5.4.2 | Always |
| Require the `RelayState` the request carried, and accept any when it carried none | Bindings §3.4.3 binds the responder, and another transaction's state must not complete this one. | Bindings §3.4.3 | Always |
| Reject a repeated `Success` response `ID`. A response with another status is not stored, as the [protocol message ID rule](metadata-and-replay.md#protocol-message-ids) states | Name identifier management requires no identifier cache, so the cache is the caller's choice. | — | `ReplayPolicy::RequireCache`, `SamlValidationContext::with_replay_retention` |

### Identity provider and service provider: `EncryptedID` and `NewEncryptedID`

Code: `src/name_id_management/encryption.rs`, `src/name_id_management.rs`, `src/crypto/enc/encrypt.rs`, `src/crypto/enc/decrypt.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Encrypt for a key of the responder role that publishes the receiving `ManageNameIDService`, or of the first such role when several do. Never use a key of another role | E62 declares a key for the entity acting in its own role, so another role's key may not reach the receiving endpoint. | Profiles §4.5.5, Metadata §2.4.1, E62, E68 | `StartNameIdManagement::identifier_encryption` |
| Within that role, read the keys as for [SSO responses](web-browser-sso-generation.md#encryption) and use the first one the configured algorithms can use. Skip a key that does not load or that the crypto provider refuses | E68 lets the encrypting party use any key of the role, and OpenSAML 5.2.0 also skips a credential without a usable key transport. | Metadata §2.4.1.1, E68 | `AlgorithmPolicy::data_encryption`, `AlgorithmPolicy::key_encryption` |
| Accept only a `NameID` as the `EncryptedID` plaintext, not a `BaseID` or an `Assertion` | The plaintext request offers only `NameID` beside `EncryptedID`, so another decrypted type has no plaintext form to manage. | Core §2.2.4, `ManageNameIDRequestType` | Always |
| Answer an element that does not decrypt, including a missing key, or whose plaintext breaks the rules above, with `Requester` and `UnknownPrincipal` for `EncryptedID` and `Requester` for `NewEncryptedID` | Reason not recorded. | Core §3.6.2, §3.6.3, E19 | `NameIdManagementRefusal::UndecryptableIdentifier`, `NameIdManagementRefusal::UndecryptableNewIdentifier` |

[Shibboleth SP 3.6.0](https://codeberg.org/Shibboleth/cpp-sp/src/tag/3.6.0/shibsp/handler/impl/SAML2NameIDMgmt.cpp#L297-L393)
answers the same decryption failures with the same status codes.

<a id="after-the-exchange"></a>

## Application duties

The crate keeps no identifier state or sessions. The actor is the provider
that sent or received the request.

| Duty | Level | Section |
| --- | --- | --- |
| Requester: pass `start_name_id_management` or `start_name_id_management_redirect` the identifier as most recently established between the providers, with its latest `SPProvidedID`, and, for a persistent identifier established with an affiliation, the affiliation's ID through `NameId::with_sp_name_qualifier` | Mandatory | Core §3.6.3 |
| Responder: return the `SoapResponse` of `respond_name_id_management`, or of a refusal, as the HTTP response to the SOAP request, and send the `Outbound` of `respond_name_id_management_redirect`, or of a refusal, through the user agent | Mandatory | Profiles §4.5.3.2 |
| Responder that does not recognize the identifier: answer with an error status, `Status::requester` or `Status::responder`, passed to `respond_name_id_management` or `respond_name_id_management_redirect` | Mandatory | Core §3.6.3 |
| Responder that does not recognize the identifier: add `SubordinateStatusCode::unknown_principal` to that status | Optional | Core §3.6.3 |
| Requester that intends logout with a termination: send the `LogoutRequest` before the terminating `ManageNameIDRequest`, never after | Mandatory | E8 |
| Identity provider that received the service provider's `NewID`: when it next uses that primary identifier with that service provider, include the new value as `SPProvidedID` with `NameId::with_sp_provided_id` | Mandatory | Core §3.6.3, §8.3.7, E55 |
| Service provider that received the identity provider's `NewID`: use the new `NameID` wherever the changed identifier would have been used with that identity provider | Mandatory | Core §3.6.3, E55 |
| Receiver that keeps state for the identifier, such as an `SPProvidedID`, after `Terminate`: delete that state or mark it obsolete | Recommended | Core §3.6.3, E14 |
| Receiver, after `Terminate`: carry out later operations for that sender about the principal, such as a later `AuthnRequest`, as if no previous state existed | Recommended | Core §3.6.3, E14 |
| Receiver, after `Terminate`: keep the principal's active sessions. A receiving identity provider also keeps the principal's sessions with other service providers | Recommended | E8 |
| Requester: reveal as little as possible in `StartNameIdManagement::relay_state`, unless the deployment needs no privacy | Recommended | Profiles §4.5.3.1 |

Core §3.6.1 and §3.6.3, as E12 and E55 change them, state without an RFC 2119
keyword that an identity provider's `NewID` becomes the `NameID` content of its
later assertions, and that a requester that sends `Terminate` no longer
issues, as the identity provider, or accepts, as the service provider,
assertions with that identifier. Core §3.6.3 also suggests, without a keyword,
that each provider accept the old or the new identifier while a change
propagates. The [browser binding duties](browser-bindings.md#application-duties)
cover a received `RelayState` that the provider uses in a redirect or in
response content.

<a id="outside-this-flow"></a>

## Not supported

[IdP and SP operational modes](idp-sp-operational-modes.md#exchanges-not-implemented)
lists the exchanges that saml-rs does not implement and the operational modes
it does not claim.

- SOAP at the service provider: sending, receiving, and answering a
  `ManageNameIDRequest`. Optional, Conformance Table 2. The service provider
  uses HTTP-Redirect.
- A signature on a SOAP message that the identity provider sends. Optional,
  Profiles §4.5.3.1, §4.5.3.2. The identity provider sends the message
  unsigned on a `SoapChannel` that authenticates both parties.
