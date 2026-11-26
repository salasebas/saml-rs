# Single Logout

<a id="single-logout-rules"></a>

`ServiceProvider` and `IdentityProvider` run Single Logout through
`start_slo`, `receive_slo`, `respond_slo`, `respond_slo_refusal`, and
`finish_slo`, over HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and SOAP.
The identity provider is the session authority, and the service provider is
a session participant. `ServiceProvider::start_async_slo` and
`IdentityProvider::receive_slo_with_async` add asynchronous logout over
HTTP-Redirect and HTTP-POST.

Normative text is Core §3.7, Profiles §4.4, and Bindings §3.2, §3.4, and
§3.5, as corrected by Approved Errata 05, the HTTP-POST-SimpleSign
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html)
(CS-01), and the
[Asynchronous Single Logout Profile Extension](https://docs.oasis-open.org/security/saml/Post2.0/saml-async-slo/v1.0/saml-async-slo-v1.0.html)
(Async SLO). [Identifiers](identifiers.md#name-identifier-formats) has the
rules for principal identifiers, and the shared
[SOAP envelope rules](artifact-resolution.md#soap-envelope-rules) cover header
order, `mustUnderstand`, and body contents.

<a id="builds-without-a-crypto-provider"></a>

The statuses hold on builds with a crypto provider. A build without one
neither signs nor verifies, and neither encrypts nor decrypts. `start_slo`,
`start_async_slo`, `respond_slo`, and `respond_slo_refusal` return
`SamlError::Unsupported`, and `receive_slo` and `finish_slo` refuse a
message over a browser binding, so no logout exchange completes.

## Support

A status covers the role's part in the feature: sending, receiving, or both.

### Messages and bindings

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `LogoutRequest` over HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign, sent and received | Profiles §4.4.3.1, §4.4.3.3, Bindings §3.4, §3.5, CS-01 §2.4 | Supported | Supported |
| `LogoutResponse` over HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign, sent and received | Profiles §4.4.3.4, §4.4.3.5, Bindings §3.4, §3.5, CS-01 §2.4 | Supported | Supported |
| A `LogoutResponse` on another of those bindings than its request | Profiles §4.4.3.4, §4.4.3.5 | Supported | Supported |
| `LogoutRequest` over SOAP, sent and received | Profiles §4.4.3.1, §4.4.3.3, Bindings §3.2 | Supported | Supported |
| `LogoutResponse` over SOAP, sent and received | Profiles §4.4.3.4, §4.4.3.5, Bindings §3.2 | Supported | Supported |
| `LogoutRequest` and `LogoutResponse` over HTTP-Artifact | Profiles §4.4.3.1, §4.4.3.4, Bindings §3.6 | Not supported | Not supported |
| An XML signature on each message sent over HTTP-POST or SOAP, and its verification on a received one | Core §3.7.1, §3.7.2, Profiles §4.4.4.1, §4.4.4.2 | Supported | Supported |
| `SigAlg` and `Signature` on each message sent over HTTP-Redirect or HTTP-POST-SimpleSign, and their verification on a received one | Profiles §4.4.4.1, §4.4.4.2, Bindings §3.4.4.1, CS-01 §2.4 | [Partial](browser-bindings.md#detached-signatures) | [Partial](browser-bindings.md#detached-signatures) |
| An unsigned SOAP message that the channel authenticates, received | Profiles §4.4.3.1, §4.4.3.4, §4.4.4.1, §4.4.4.2 | Supported | Supported |
| An unsigned SOAP message that the channel authenticates, sent | Profiles §4.4.3.1, §4.4.3.4, §4.4.4.1, §4.4.4.2 | Not supported | Not supported |
| `SingleLogoutService` endpoints of the peer's metadata, `ResponseLocation` included | Profiles §4.4.3.1, §4.4.5, Metadata §2.2.2, §2.4.2, E41 | Supported | Supported |

<a id="browser-bindings"></a>

[Browser bindings](browser-bindings.md) has the encoding, base64, `RelayState`,
signature-input, and cache-header rules of HTTP-Redirect, HTTP-POST, and
HTTP-POST-SimpleSign, and the HTTP duties of the application.
`StartSlo::relay_state` sends a `RelayState` under the
[creator limit](browser-bindings.md#sending-a-relaystate), and `respond_slo`
returns a received one unchanged.

### Logout requests

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `NameID` as the principal identifier | Core §3.7.1, Profiles §4.4.4.1 | Supported | [Partial](#service-provider-nameid) |
| `EncryptedID` as the principal identifier | Core §3.7.1, §6.1, Profiles §4.4.5, Conformance §3.4 | Supported | [Partial](#service-provider-nameid) |
| `BaseID` as the principal identifier | Core §2.2.1, §3.7.1 | [Partial](#baseid-principal-identifier) | [Partial](#baseid-principal-identifier) |
| `SessionIndex` | Core §3.7.1, Profiles §4.4.4.1, E38 | Supported | Supported |
| A request without `SessionIndex`, for all of the principal's sessions | Profiles §4.4.4.1, E38 | Supported | Supported |
| `NotOnOrAfter` on a sent request | Core §3.7.1, §3.7.3.2 | Supported | Not supported |
| `NotOnOrAfter` on a received request | Core §3.7.1 | Supported | Supported |
| `NotOnOrAfter` at or after that of the latest assertion of the targeted session | Core §3.7.3.2 | Not supported | — |
| `Reason`, sent and received | Core §3.7.1, §3.7.3, E10 | Supported | Supported |
| The asynchronous marker on HTTP-Redirect and HTTP-POST | Async SLO §2.1, §2.2 | Supported | Supported |
| The asynchronous marker on HTTP-POST-SimpleSign and SOAP | Async SLO §2.1 | Not supported | Not supported |
| `supportsAsynchronous` on a metadata endpoint | Async SLO §2.3 | Not supported | Not supported |

The identity provider recognizes the asynchronous marker, and the service
provider sends it. `Consent`, caller extensions, and `StatusDetail` are in
[common message fields](common-message-fields.md).

### Logout responses

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| Top-level `Success`, `Requester`, `Responder`, or `VersionMismatch`, with an optional subordinate code | Core §3.2.2.2, §3.7.2 | Supported | Supported |
| `PartialLogout` under the session authority's top-level status | Core §3.7.3.2 | Supported | Supported |
| `StatusMessage` | Core §3.2.2.1, §3.2.2.3 | Supported | Supported |
| `VersionMismatch` answer to a request of a newer version | Core §4.1.3.1, §4.1.3.2 | Supported | Supported |
| The request's `RelayState`, returned in the response | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Supported | Supported |
| Adding a `RelayState` to a response when the request carried none | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Not supported | Not supported |

### Sessions and propagation

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| Matching a received request with a stored service provider session | Core §3.7.3.1 | — | [Partial](#session-matching) |
| Applying a received request to an assertion that arrives later | Core §3.7.3.1 | — | [Partial](#session-matching) |
| Propagation to the other session participants, one `LogoutRequest` each | Core §3.7.3.2, Profiles §4.4.3.2, §4.4.3.3 | Supported | — |
| A `LogoutRequest` to an upstream session authority that the identity provider proxied | Core §3.7.3.2 | Not supported | — |

## Partial support

### Service provider `NameID`

- **Supported:** `ServiceProvider::start_slo` writes the `NameID` of the
  `NameId` it is given, in the clear or in an `EncryptedID`, and refuses a
  value or qualifier with only XML whitespace. `SsoSession::logout_subject`
  gives no subject for such a value, and keeps such a qualifier so that
  `matches_sp_session` still matches the identity provider's request.
- **Not supported:** an `entity` `NameID` that breaks Core §8.3.6 is written
  unchanged, as [identifiers](identifiers.md#service-provider-requests)
  records.

### `BaseID` principal identifier

- **Supported:** both roles accept an authenticated request whose principal
  is a `BaseID`, a decrypted one included, and answer it with `respond_slo`.
  Such a request names no session of either role: a `BaseID` strongly
  matches only an identical `BaseID` (Core §3.3.4, Profiles §4.4.4.1), and
  neither role issues or accepts an assertion whose `Subject` holds one.
  `matches_sp_session` matches no session, and `OutstandingLogout::try_new`,
  which takes a `NameId`, cannot record the request. No later assertion
  could match it.
- **Not supported:** neither role sends a `BaseID` or returns the identifier
  in one, as [identifiers](identifiers.md#not-supported) records, so
  `LogoutRequest::name_id` is `None`.

### Session matching

- **Supported:** `matches_sp_session` matches a stored session, and
  `OutstandingLogout::try_new` records the request for a later assertion, by
  the plaintext `NameID` or the one decrypted from the `EncryptedID`. A
  `BaseID` principal names no session, as the
  [`BaseID` entry](#baseid-principal-identifier) explains.
- **Not supported:** a request whose `EncryptedID` no configured key
  decrypts carries no `NameID`, so `matches_sp_session` matches no session
  and `OutstandingLogout::try_new` cannot record it, as the
  [session matching policy](#session-matching-policies) records.

## Rules

<a id="logoutrequest-from-a-session-participant"></a>
<a id="logoutrequest-reason"></a>

### Identity provider and service provider: `start_slo`

Code: `src/api/slo.rs`, `src/logout/creation.rs`, `src/logout/rendering.rs`, `src/model/subject.rs`, `src/binding/signed_message.rs`, `src/xml/profile/outbound_logout_request.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `Issuer` without `Format` or with the `entity` format | Mandatory | Profiles §4.4.4.1 | Always |
| Write the local entity identifier as `Issuer`, which typed configuration holds to the [entity identifier rule](identifiers.md#entity-identifiers) | Mandatory | Profiles §4.4.4.1, Core §8.3.6 | `SpConfigBuilder::build`, `IdpConfigBuilder::build` |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant`, and never a time with a leap second | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Identify the principal with `NameID`, or `EncryptedID` when selected | Mandatory | Profiles §4.4.4.1, `LogoutRequestType` | `StartSlo::identifier_encryption` |
| Copy `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from the `LogoutSubject` `NameId` | Mandatory | Profiles §4.4.4.1, Core §3.7.1, §3.3.4 | Always |
| Reject a `Format` that is not an absolute URI reference, also when the `NameId` came from an accepted assertion | Mandatory | Core §1.3.2 | Always |
| Sign the request on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. CS-01 §2.4 makes the SimpleSign signature optional, but the profile requires the requester to authenticate by signing | Mandatory | Profiles §4.4.3.1, §4.4.4.1, CS-01 §2.4 | Always |
| Write a caller-supplied `Reason`, covered by the request signature, and omit it when unset | Optional | Core §3.7.1, §3.7.3 | `StartSlo::reason` |
| Require an absolute URI reference for a typed `Reason`, with the `anyURI` whitespace and syntax rules of [identifier formats](identifiers.md#name-identifier-formats) | Mandatory | Core §1.3.2, §3.7.1, E10 | `StartSlo::reason` |

### Service provider: `start_slo`

Code: `src/api/slo.rs`, `src/api/peer.rs`, `src/logout/creation.rs`, `src/model/subject.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Omit `Format` when the `NameId` has none | Optional | Core §2.2.2, E60 | Always |
| Reject a value or qualifier with only XML whitespace, under the [service provider request rule](identifiers.md#service-provider-name-id-strings) | Mandatory | Core §1.3.1, XML 1.0 §2.3 | Always |
| Include at least one `SessionIndex` | Mandatory | Profiles §4.4.4.1, E38 | Always |
| Send the user agent to an `https` `SingleLogoutService`. A recipient does not reject an `http` `Destination` | Recommended | Profiles §4.4.3.1 | `StartSlo::allow_http` |
| Omit `NotOnOrAfter` | Optional | Core §3.7.1, §3.7.3.2 | Always |
| Refuse the `global-timeout` and `sp-timeout` reasons, which only the session authority sends, after whitespace collapse, on ordinary and asynchronous logout | Mandatory | Core §3.7.3.2, E0 | Always |

<a id="logout-subject"></a>

### Service provider: `SsoSession::logout_subject`

Code: `src/model/sso.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Give no logout subject for an accepted assertion without a `NameID`, because no identifier can strongly match it | Mandatory | Profiles §4.4.4.1, Core §3.3.4 | Always |
| Give no logout subject when the `NameID` value is empty or only XML whitespace, because the request copies the value and a SAML string needs another character. U+00A0 is not XML whitespace | Mandatory | Core §1.3.1, XML 1.0 §2.3 | Always |
| Keep each qualifier of the accepted `NameID` as received, one with only XML whitespace included, so that `matches_sp_session` matches the identity provider's request for the session. `start_slo` refuses to send such a qualifier | Mandatory | Core §3.7.3.1, §3.3.4 | Always |

<a id="asynchronous-single-logout"></a>

### Service provider: `start_async_slo`

Code: `src/api/slo.rs`, `src/logout/rendering.rs`, `src/binding/signed_message.rs`

`start_async_slo` is the request initiator of Async SLO on HTTP-Redirect and
HTTP-POST, and the `start_slo` rules above also apply. Under Async SLO §2.2,
the identity provider gives the user the outcome and sends no
`LogoutResponse` to the initiator.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Include an empty `aslo:Asynchronous` in `samlp:Extensions` after the issuer and any embedded signature, before the principal identifier | Mandatory | Async SLO §2.1, `RequestAbstractType`, `LogoutRequestType` | `start_async_slo` |
| Cover the extension with the query signature on Redirect and the embedded signature on POST | Mandatory | Profiles §4.4.4.1, Bindings §3.4.4.1, §3.5.5.2 | Always |

<a id="logoutrequest-from-a-session-authority"></a>

### Identity provider: `start_slo`

Code: `src/api/slo.rs`, `src/entity.rs`, `src/logout/creation.rs`, `src/model/subject.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Set `NotOnOrAfter` from the issuance lifetime and the same `IssueInstant` | Mandatory | Core §3.7.3.2 | Always |
| After choosing the `Format` and before encrypting and signing, reject a value or qualifier with only XML whitespace, a persistent or transient value over 256 characters, an `entity` value that is not an absolute URI reference of at most 1024 characters, and an `entity` `NameID` with a qualifier | Mandatory | Core §1.3.1, §1.3.2, §8.3.6, §8.3.7, §8.3.8 | Always |
| Omit every `SessionIndex` to end all applicable sessions of the principal | Optional | Profiles §4.4.4.1, E38 | Always |

Profiles §4.4.3.3 and §4.4.3.5 do not repeat the `https` recommendation of
§4.4.3.1 and §4.4.3.4, so the identity provider's request and response have
no `https` check.

<a id="peer-endpoints"></a>

### Identity provider and service provider: peer endpoints

Code: `src/api/slo.rs`, `src/metadata/mod.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the peer `SingleLogoutService` from the role descriptor of the peer role, never from the other role of an entity that plays both | Optional | Metadata §2.4.2, Profiles §4.4.3.1, §4.4.5 | Always |

<a id="logoutresponse"></a>

### Identity provider and service provider: `respond_slo`, `respond_slo_refusal`

Code: `src/api/slo.rs`, `src/logout/creation.rs`, `src/logout/rendering.rs`, `src/model/logout.rs`, `src/model/status.rs`, `src/xml/write.rs`, `src/browser/outbound.rs`, `src/xml/profile/outbound_logout.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a `LogoutRequest` with a `LogoutResponse` | Mandatory | Core §3.7.2, Profiles §4.4.3.4, §4.4.3.5 | `respond_slo` |
| Answer an authenticated request with a newer major version with `VersionMismatch` and the second-level `RequestVersionTooHigh` | Mandatory | Core §4.1.3.1, §4.1.3.2, Profiles §4.4.3.4, §4.4.3.5 | `respond_slo_refusal` |
| Answer an authenticated request of a later 2.x version, such as 2.1, with `VersionMismatch` rather than process it | Optional | Core §4.1.3.1, §4.1.3.2 | `respond_slo_refusal` |
| Write `Issuer` without `Format` or with the `entity` format. Typed configuration holds its value to the [entity identifier rule](identifiers.md#entity-identifiers) | Mandatory | Profiles §4.4.4.2, Core §8.3.6 | Always |
| Write `ID`, `Version` `2.0`, a UTC `IssueInstant` without a leap second, and `InResponseTo` equal to the request `ID` | Mandatory | `StatusResponseType`, Core §3.2.2, §1.3.3 | Always |
| Sign the response on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. CS-01 §2.4 makes the SimpleSign signature optional, but the profile requires the responder to authenticate by signing | Mandatory | Profiles §4.4.3.4, §4.4.4.2, CS-01 §2.4 | Always |
| Return the exact `RelayState` of the request, including a value over 80 bytes up to the receive limit, with no setter to replace or drop it | Mandatory | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |
| Return a SOAP reply on the request's exchange, without reading a peer `SingleLogoutService`. Return a reply to a browser request through the user agent | Mandatory | Profiles §4.4.3.4, §4.4.3.5 | `respond_slo`, `respond_slo_refusal` |
| Choose any supported browser response binding that the peer publishes | Optional | Profiles §4.4.3.4, §4.4.3.5 | `RespondSlo` |
| Write a top-level `StatusCode` of `Success`, `Requester`, `Responder`, or `VersionMismatch`, with an optional subordinate code | Mandatory | Core §3.2.2.2 | `status` argument |
| Write caller-supplied plain text as `StatusMessage` after `StatusCode` before signing. Omit the element by default | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | `RespondSlo::status_message` |
| Write a `StatusMessage` only with a character other than XML whitespace. An empty string omits the element, and other text with only XML whitespace is refused | Mandatory | Core §1.3.1, §3.2.2.3 | Always |
| Write a subordinate `StatusCode` `Value` that is an absolute URI reference read as an `xs:anyURI`, as for [identifier formats](identifiers.md#name-identifier-formats), with its XML whitespace collapsed | Mandatory | Core §1.3.2, `StatusCodeType`, XML Schema Part 2 §3.2.17 | `SubordinateStatusCode::try_new` |

The application chooses the `status` argument, as
[application duties](#application-duties) describe.

### Service provider: `respond_slo`, `respond_slo_refusal`

Code: `src/api/slo.rs`, `src/api/peer.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the response to an `https` `SingleLogoutService` | Recommended | Profiles §4.4.3.4 | `RespondSlo::allow_http` |

<a id="logout-acceptance"></a>

### Identity provider and service provider: `receive_slo`, `finish_slo`

Code: `src/api/slo.rs`, `src/logout/parsing.rs`, `src/flow.rs`, `src/flow/detached.rs`, `src/model/validation.rs`, `src/validator.rs`, `src/model/logout.rs`, `src/xml/profile.rs`, `src/xml/status.rs`

Response recipients apply the shared
[status code rule](web-browser-sso-acceptance.md#status-codes).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a verified signature on a `LogoutRequest` received over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign. CS-01 §2.4 makes the SimpleSign signature optional, but the profile requires authentication by signing | Mandatory | Core §3.7.3.1, §3.7.3.2, Profiles §4.4.3.1, §4.4.4.1, CS-01 §2.4 | `receive_slo` |
| Require a verified signature on a `LogoutResponse` received over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign. CS-01 §2.4 makes the SimpleSign signature optional, but the profile requires authentication by signing | Mandatory | Profiles §4.4.3.4, §4.4.4.2, CS-01 §2.4 | `finish_slo` |
| For browser messages and SOAP requests, compare a present `Destination` after collapsing XML whitespace. Use the supplied receiving URL or infer the unique published endpoint for the binding and direction | Mandatory | Core §3.2.1, §3.2.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Require `Destination` on a signed message from a browser binding | Mandatory | Bindings §3.4.5.2, §3.5.5.2, CS-01 §2.4 | Always |
| Accept a response over any of HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign that the local metadata publishes, after a request sent over one of them. Compare `Destination` with the local `SingleLogoutService` of the arrival binding | Optional | Profiles §4.4.3.4, §4.4.3.5 | Always |
| Accept a `RelayState`, an empty one included, that the responder adds to a request that carried none | Optional | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |
| Return the optional subordinate status code on a successful response, including `PartialLogout` | Optional | Core §3.2.2.2, §3.7.3.2 | `LogoutCompleted::response`, `LogoutResponse::status` |
| Return one nonempty, text-only protocol `StatusMessage` directly under the authenticated and correlated response's `Status`. Omit diagnostics with attributes, child elements, or ambiguous cardinality | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType`, Profiles §4.4.4.2 | `finish_slo` |
| Require exactly one direct `BaseID`, `NameID`, or `EncryptedID` child in the SAML assertion namespace on every supported binding | Mandatory | Core §3.7.1, `LogoutRequestType` | Always |
| Read an optional unqualified `Reason` from an authenticated request as an `xs:string`, preserving its XML-normalized value and absence without URI validation or `anyURI` whitespace collapse. Ignore a qualified attribute with the same local name | Optional | Core §3.7.1, §3.7.3, `LogoutRequestType`, E10 | `LogoutRequest::reason` |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Allow the validation-context clock skew on `LogoutRequest` `NotOnOrAfter`, five minutes by default | Recommended | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew` |
| Discard a `LogoutRequest` at or after its skew-adjusted `NotOnOrAfter` | Optional | Core §3.7.1 | `ClockSkew` |

<a id="asynchronous-single-logout-at-the-session-authority"></a>

### Identity provider: `receive_slo_with_async`

Code: `src/api/slo.rs`, `src/logout/parsing.rs`

`receive_slo_with_async` recognizes the marker on HTTP-Redirect and HTTP-POST,
and the `receive_slo` rules above also apply.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Recognize an empty `aslo:Asynchronous` element only as a direct child of `samlp:LogoutRequest/samlp:Extensions` in the authenticated request | Mandatory | Async SLO §2.1, `AsynchronousType`, `RequestAbstractType` | `receive_slo_with_async` |
| Accept `xsi:schemaLocation` and `xsi:noNamespaceSchemaLocation` on the marker | Mandatory | Async SLO §2.1, `AsynchronousType`, XML Schema Part 1 §3.4.4 | `receive_slo_with_async` |
| Accept an `xsi:type` of `AsynchronousType` written with any prefix bound to the extension namespace, or unprefixed under it as the default namespace | Mandatory | Async SLO §2.1, §2.2, `AsynchronousType`, XML Schema Part 1 §3.3.4 | `receive_slo_with_async` |
| Return a request with the marker as `IdpLogoutAction::CompleteLocally`, which sends no `LogoutResponse` to the initiator | Mandatory | Async SLO §2.2, Core §3.7.3.2 | `IdpLogoutAction::CompleteLocally` |
| When it refuses a request with the marker for its version, return an error and no `VersionMismatch` refusal to send | Mandatory | Async SLO §2.2, Core §4.1.3.1 | Always |

<a id="sp-session-selection"></a>

### Service provider: `matches_sp_session`, `OutstandingLogout::try_new`

Code: `src/model/logout.rs`, `src/model/subject.rs`, `src/model/outstanding_logout.rs`, `src/api/sp.rs`

`Received<LogoutRequest>::matches_sp_session` checks one stored session
against a request that `ServiceProvider::receive_slo` authenticated.
`OutstandingLogout::try_new` records the same request for the
[later-assertion check](web-browser-sso-acceptance.md#service-provider-outstanding-logout).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Match only sessions established by an assertion from the request issuer | Mandatory | Core §3.7.3.1 | `matches_sp_session` |
| Compare the `NameID` value, effective `Format`, and all three qualifier attributes. An omitted `Format` means `unspecified` | Mandatory | Core §2.2.2, §3.3.4, §3.7.3.1, Profiles §4.4.4.1, E60, `NameIDType` | `matches_sp_session` |
| With one or more `SessionIndex` elements, require at least one match. With none, select every session from that authority with the matching `NameID` | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, E38, `LogoutRequestType` | `matches_sp_session` |
| Record the request `NameID` whatever its value, an empty or whitespace-only one included | Mandatory | Core §3.7.3.1 | `OutstandingLogout::try_new` |
| Match later assertions to the decrypted `NameID` through `OutstandingLogout` | Mandatory | Core §3.7.3.1 | `ServiceProvider::finish_sso_with_outstanding_logout` |

<a id="encrypted-principal-identifier"></a>

### Identity provider and service provider: encrypted principal identifier

Code: `src/logout/encrypted_id.rs`, `src/crypto/enc/encrypt.rs`, `src/crypto/enc/decrypt.rs`, `src/api/slo.rs`

`StartSlo::identifier_encryption` and `receive_slo` handle `EncryptedID` on
HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and SOAP. Conformance §3.4
requires every relevant operational mode to process or generate
`EncryptedID` wherever it processes or generates `NameID`, and these rows do
not claim the IdP or SP operational mode.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send `EncryptedID` in place of `NameID` | Optional | Core §3.7.1, §6.1 | `StartSlo::identifier_encryption` |
| Process a received `EncryptedID` with the local decryption key, whatever the `XmlEncryptionPolicy`, and accept a plaintext `NameID` | Mandatory | Conformance §3.4 | Always |

<a id="soap-binding"></a>

### Identity provider and service provider: `StartSlo::soap`, `RespondSlo::soap`, `Inbound::soap`

Code: `src/soap.rs`, `src/api/slo.rs`, `src/logout/creation.rs`, `src/logout/parsing.rs`, `src/http_header.rs`, `src/browser/endpoints.rs`, `src/metadata/generate.rs`

These operations carry one SOAP request and its response, which either role
can start. The `start_slo`, `respond_slo`, and `receive_slo` rules above also
apply.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the request on a synchronous binding | Optional | Profiles §4.4.3.1, §4.4.3.3 | `StartSlo::soap` |
| Put exactly one SAML request or response in the SOAP body, with no other element | Mandatory | Bindings §3.2.2.1, E19 | Always |
| Authenticate the requester and protect message integrity. Typed SOAP generation signs the `LogoutRequest` | Mandatory | Profiles §4.4.3.1, §4.4.4.1 | Always |
| Authenticate the responder and protect message integrity. Typed SOAP generation signs the `LogoutResponse` | Mandatory | Profiles §4.4.3.4, §4.4.4.2 | Always |
| Authenticate a received `LogoutRequest` or `LogoutResponse`. Require its XML signature unless the channel attests mutual authentication and integrity, and verify a present signature either way | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, §4.4.4.2 | `Inbound::soap`, `SoapChannel` |
| Set the request `Destination` to the peer SOAP `SingleLogoutService` `Location` | Optional | Core §3.2.1 | Always |
| Compare a present `LogoutRequest` `Destination` with the local SOAP `SingleLogoutService` after collapsing XML whitespace. Accept a signed SOAP request without it | Mandatory | Core §3.2.1, Bindings §3.4.5.2, §3.5.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Omit `Destination` from the `LogoutResponse` | Optional | Core §3.2.2 | Always |
| Publish a SOAP `SingleLogoutService` as the endpoint that accepts SOAP logout requests. A SOAP reply reads no peer endpoint; see the [response rules](#logoutresponse) | Recommended | Bindings §3.2.3.4 | `SloEndpoint::soap` |
| Send `http://www.oasis-open.org/committees/security` as the `SOAPAction` value, bare, as Bindings §3.2.3 and its examples write it | Optional | [Bindings §3.2.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=11), §3.2.3.5, §3.6.8 | `SoapRequest::headers` |
| Use the `text/xml` media type for a SOAP entity body. The crate sends `charset=utf-8` | Mandatory | SOAP 1.1 §6 | `SoapRequest::headers`, `SoapResponse::headers` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` on the request | Recommended | Bindings §3.2.3.2 | `SoapRequest::headers` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` on the response | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers` |
| Report a SAML-domain error as a `LogoutResponse` status, not a SOAP fault | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | `respond_slo` `status` |

The deployment owns the connection, TLS, and HTTP authentication of the SOAP
exchange, as [SOAP and URI security models](idp-sp-operational-modes.md#soap-and-uri-security-models)
describes. `allow_http` has no effect on SOAP.

## Library policies

### Service provider: `start_slo`

Code: `src/api/slo.rs`, `src/api/peer.rs`, `src/logout/creation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Send the `NameId` value and qualifiers unchanged, without the identity provider's length and `entity` checks | The request identifies the principal as the identity provider issued it, as the [service provider request policy](identifiers.md#service-provider-request-policy) records. | Profiles §4.4.4.1, Conformance §3.3 | Always |
| On a browser binding, send to the first peer `SingleLogoutService` for the binding with an `https` `Location`, or the first one under `allow_http` | An earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.4.3.1 | `StartSlo::allow_http` |

### Service provider: `start_async_slo`

Code: `src/api/slo.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Use an explicit call for an IdP endpoint that the application knows supports asynchronous logout | Support can be configured out of band because publishing it in metadata is optional. | Async SLO §2.3 | `start_async_slo` |

### Identity provider: `start_slo`

Code: `src/api/slo.rs`, `src/entity.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Use the configured issuance lifetime, five minutes by default | This identity provider's assertions use the same lifetime, so while it is unchanged the deadline is no earlier than theirs, as in SimpleSAMLphp 2.5.4. | Core §3.7.3.2 | `IdpConfigBuilder::issuance_lifetime` |
| When the subject has no `Format`, use the first configured NameID format, or omit `Format` if none is configured | `respond_sso` uses the same format for that subject. | Core §2.2.2, E60 | Always |

### Identity provider and service provider: peer endpoints

Code: `src/api/slo.rs`, `src/api/peer.rs`, `src/metadata/mod.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Send the response to `ResponseLocation` when present, otherwise `Location`, after `anyURI` whitespace collapse. A request uses `Location` | The peer's metadata names where it handles responses, so the response goes to the endpoint the peer operates for them. | Metadata §2.2.2, E41 | Always |
| A session authority's browser messages and SOAP requests from either role use the first endpoint for the binding. A session participant's browser messages use the endpoint its `start_slo` and `respond_slo` policies describe | Metadata order is the only preference the peer publishes for endpoints of one binding, and OpenSAML 5.2.3 and crewjam/saml v0.4.14 also take the first. | Metadata §2.2.2 | Always |

### Identity provider and service provider: `respond_slo`, `respond_slo_refusal`

Code: `src/api/slo.rs`, `src/api/peer.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a `LogoutRequest` whose issuer is not the peer descriptor entity | A response must not go to another party's `SingleLogoutService`. | — | Always |

### Service provider: `respond_slo`, `respond_slo_refusal`

Code: `src/api/slo.rs`, `src/api/peer.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| On a browser binding, answer at the first peer endpoint for the binding whose response URL is `https`, or the first one under `allow_http` | An earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.4.3.4 | `RespondSlo::allow_http` |

### Identity provider and service provider: `receive_slo`, `finish_slo`

Code: `src/api/slo.rs`, `src/api/peer.rs`, `src/logout/parsing.rs`, `src/flow.rs`, `src/model/validation.rs`, `src/model/logout.rs`, `src/validator.rs`, `src/xml/date_time.rs`, `src/crypto/signature_profile.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an `IssueInstant` that is not a UTC `xs:dateTime` | [Baseline receipt](xml-schema-validation.md#baseline-receipt) gives the reason. | Core §1.3.3 | Always |
| Accept an `IssueInstant` with a leap second | Core §1.3.3 forbids only writing one, `xs:dateTime` admits second 60, and no logout check compares `IssueInstant` with the clock, so a message from a peer whose clock wrote a leap second still completes the exchange. | Core §1.3.3, XML Schema Part 2 §D.1 | Always |
| Reject a `LogoutRequest` `NotOnOrAfter` the runtime clock cannot represent, a leap second included | The expiration check fails closed on a value it cannot compare. | Core §1.3.3, §3.7.1 | Always |
| Reject a supplied receiving URL that the local role descriptor does not publish for the binding and direction. For a SOAP response, only when it has `Destination` | The URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this party does not operate. | Core §3.2.1, §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Without a supplied URL, reject several published URLs for the binding and direction when a `Destination` is compared. A SOAP message without `Destination` needs no unique local endpoint | The library is not told which endpoint received the message, and accepting any published one would not check the location that received it. | Core §3.2.1, §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Keep a SOAP response on the SOAP request's exchange, and reject crossing between SOAP and browser delivery | A SOAP response answers the synchronous exchange of its request. | Profiles §4.4.3.4, §4.4.3.5 | Always |
| Require the unqualified response `InResponseTo`, after XML whitespace collapse, to equal the pending request `ID` | A missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2, `StatusResponseType`, XML Schema Part 2 §4.3.6 | Always |
| Require the returned `RelayState` to equal the one the request carried, an empty value included | Bindings §3.5.5.2 leaves the association with the form's `RelayState` unprotected under an HTTP-POST XML signature. | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |
| Return a status other than `Success` as an error that carries the authenticated status and `StatusMessage` | Only a top-level `Success` reports that the responder ended its session, so only it completes the call, as in crewjam/saml v0.4.14 and ruby-saml 1.18.1. | Core §3.2.2.2, §3.7.3.2 | `finish_slo` |
| Apply the [signature algorithm profile](xml-security-algorithms.md#weak-algorithms-and-keys) to an embedded signature and a detached `SigAlg`, including the mandatory logout signatures | The linked rows state the reason for each profile. | XMLDSig 1.1 §6.2, §6.4.2, Conformance §4.1 | `XmlSignatureProfile`: `ExcludeWeakAlgorithms` by default, `StrictRsaSha2` or `AllowWeakAlgorithms` when selected |

### Identity provider: `receive_slo_with_async`

Code: `src/logout/parsing.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Recognize the marker by its element name whatever its `xsi:type` value names | The element name identifies the extension, as Shibboleth IdP 5.2.3 and simplesamlphp/saml2 at `9576aff` also read it, so the type value is not compared. | Async SLO §2.1, XML Schema Part 1 §3.3.4 | Always |
| Treat a marker with any other attribute, `xsi:nil` included, as absent, and keep the request on the response path | `AsynchronousType` declares no attributes and the element is not nillable, so that element is not the empty marker §2.1 defines. | Async SLO §2.1, XML Schema Part 1 §3.3.4 | Always |

<a id="session-matching-policies"></a>

### Service provider: `matches_sp_session`, `OutstandingLogout::try_new`

Code: `src/model/logout.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Return no built-in match for a `BaseID` or an `EncryptedID` that could not be decrypted to a `NameID` | The helper needs a `NameID` to compare. | Core §2.2.1, §3.3.4, §3.7.3.1 | `matches_sp_session` |

### Identity provider and service provider: encrypted principal identifier

Code: `src/logout/creation.rs`, `src/logout/encrypted_id.rs`, `src/crypto/enc/encrypt.rs`, `src/crypto/enc/decrypt.rs`, `src/api/slo.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| When encrypting the identifier, encrypt it before signing the containing message | The signature then covers the ciphertext, and E93 replaced the original Core §6.2 ordering rule. | Core §6.2, E93 | Always |
| Encrypt for a key of the peer role that publishes the receiving `SingleLogoutService`, or of the first such role when several do. Never use a key of another role | E62 declares a key for the entity acting in its own role, so another role's key may not reach the receiving endpoint. | Profiles §4.4.5, Metadata §2.4.1, E62, E68 | `StartSlo::identifier_encryption` |
| Within that role, read the keys as for [SSO responses](web-browser-sso-generation.md#encryption) and use the first one the configured algorithms can use. Skip a key that does not load or that the crypto provider refuses | E68 lets the encrypting party use any key of the role, and OpenSAML 5.2.0 also skips a credential without a usable key transport. | Metadata §2.4.1.1, E68 | `StartSlo::identifier_encryption` |
| Accept an authenticated request whose `EncryptedID` no configured key decrypts, RSA-v1.5 key transport not allowed included, without a `NameID`. A key that fails to load is an error | Core §3.7.2 requires the recipient to answer, so an undecryptable identifier must not block the answer. | Core §3.7.2, §3.7.3.2 | Always |
| Require the plaintext to be one `NameID` or `BaseID` in the assertion namespace. For a `BaseID`, return the authenticated request without a `NameID` | Core §2.2.4 allows extension types, and the library cannot interpret extension element names. | Core §2.2.4 | Always |
| Decrypt only an authenticated request, and after replay storage when a replay cache is supplied | Unauthenticated ciphertext never reaches the decryptor. | — | Always |

### Identity provider and service provider: `StartSlo::soap`, `RespondSlo::soap`, `Inbound::soap`

Code: `src/logout/creation.rs`, `src/api/slo.rs`, `src/logout/parsing.rs`, `src/flow.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject `RelayState` on a SOAP message | The SOAP binding has no place to carry it, so a value is rejected rather than dropped. | Bindings §3.2 | `StartSlo::relay_state` |
| Compare a present `LogoutResponse` `Destination` with the location that received the response, after collapsing XML whitespace | Reason not recorded. | Core §3.2.2, XML Schema Part 2 §4.3.6 | Always |
| Take the local SOAP `SingleLogoutService` `Location` as the location that received a SOAP response. Without `Destination`, require no local SOAP endpoint | A SOAP response has no HTTP endpoint of its own, and a responder that sets `Destination` names the requester's SOAP endpoint, as [Keycloak 26.8.2](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/protocol/saml/SamlService.java#L742-L745) does. | Core §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |

## Application duties

<a id="session-authority-application-duties"></a>

### Identity provider

The identity provider application owns the session store, participant
tracking, propagation, and the aggregate outcome. The typed APIs build and
validate each exchange with one service provider.

| Duty | Level | Section |
| --- | --- | --- |
| Determine the sessions to terminate from the issuer, the identifier, and any `SessionIndex` values that `IdentityProvider::receive_slo` or `receive_slo_with_async` returns, or from its own records when it starts logout | Mandatory | Profiles §4.4.3.2 |
| Pass `IdentityProvider::start_slo` the `NameId` of the issued assertion, with the qualifiers that `respond_sso` wrote, so the request strongly matches it | Mandatory | Profiles §4.4.4.1, Core §3.3.4 |
| For a request from a participant in the current session, contact the upstream authority when applicable, then each other participant with `IdentityProvider::start_slo`, then end the local session. Skip the originator, and keep trying the other participants after a failure | Recommended | Core §3.7.3.2, Profiles §4.4.3.2, §4.4.3.3 |
| After a request that arrived over SOAP, propagate with `StartSlo::soap`, because no user agent is present. After a browser request, propagate over SOAP or a browser binding that each participant supports | Recommended | Profiles §4.4.3.1, §4.4.3.3 |
| When replying to the original requester, pass `IdentityProvider::respond_slo` a top-level `Success` if the local logout succeeded or a top-level error if it failed. Add the second-level `PartialLogout` if an applicable participant could not be contacted or did not confirm its logout | Mandatory | Core §3.7.3.2, Profiles §4.4.3.5 |
| After `IdpLogoutAction::CompleteLocally`, present the logout outcome at the identity provider, on success and on failure | Mandatory | Async SLO §2.2 |

<a id="session-participant-application-duties"></a>

### Service provider

| Duty | Level | Section |
| --- | --- | --- |
| Call `ServiceProvider::start_slo` once for each identity provider that issued an assertion for the sessions being ended | Mandatory | Profiles §4.4.3.1 |
| Start logout with `StartSlo::redirect` or `StartSlo::post` when the principal's user agent is present. A SOAP request bypasses the user agent, and the identity provider then propagates over SOAP | Recommended | Profiles §4.4.3.1 |
| Reveal as little as possible in `StartSlo::relay_state`, such as an opaque reference to local state, unless the deployment needs no privacy | Recommended | Profiles §4.4.3.1 |
| Store `SsoSession::issuer` and `SsoSession::logout_subject` when the sign-in is accepted. After `ServiceProvider::receive_slo`, invalidate each stored session for which `matches_sp_session` returns true | Mandatory | Core §3.7.3.1 |
| Pass `ServiceProvider::respond_slo` a status that reports the outcome after the request is processed, or the error | Mandatory | Profiles §4.4.3.4, Core §3.7.3.1 |

### Identity provider and service provider

| Duty | Level | Section |
| --- | --- | --- |
| Send `Outbound::soap_response` from `respond_slo` or `respond_slo_refusal` as the HTTP 200 body of the SOAP request, for an error status too | Recommended | Bindings §3.2.3.3, E19 |

<a id="outside-this-flow"></a>

## Not supported

[IdP and SP operational modes](idp-sp-operational-modes.md#exchanges-not-implemented)
lists the exchanges that saml-rs does not implement and the operational modes
it does not claim.

- A session authority `NotOnOrAfter` at or after the `NotOnOrAfter` of the
  latest assertion of the targeted session. Recommended, Core §3.7.3.2.
  `IdentityProvider::start_slo` receives no assertion and takes the deadline
  from `IdpConfigBuilder::issuance_lifetime`, and
  [ADR 0001](https://samlrs.vercel.app/explanation/logout-expiration/)
  records the choice.
- A `LogoutRequest` from the identity provider to an upstream session
  authority on whose behalf it proxied the authentication. Recommended,
  [Core §3.7.3.2](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=62).
  The identity provider APIs exchange logout messages with service providers
  only, and [Profiles §4.4.3](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf#page=34)
  describes the deployment flow.
- The asynchronous marker on HTTP-POST-SimpleSign and SOAP, at both roles,
  Async SLO §2.1. `start_async_slo` sends it, and `receive_slo_with_async`
  recognizes it, on HTTP-Redirect and HTTP-POST only.
- `supportsAsynchronous` on a metadata endpoint. Optional, Async SLO §2.3.
  The application calls `start_async_slo` for an identity provider endpoint
  that it knows supports the extension.
