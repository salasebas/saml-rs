# Single Logout rules

`ServiceProvider` and `IdentityProvider` run Single Logout through `start_slo`, `receive_slo`, `respond_slo`, and `finish_slo`. Normative text is Core §3.7, Profiles §4.4, and Bindings §3.2, §3.4, and §3.5, as corrected by Approved Errata 05, plus the HTTP-POST-SimpleSign Committee Draft 04 (CD-04). Both roles sign outgoing messages, and the role sets the `SessionIndex` and `NotOnOrAfter` duties. Principal identifiers are in [identifiers](identifiers.md#name-identifier-formats), and SOAP logout uses the shared [SOAP envelope rules](artifact-resolution.md#soap-envelope-rules) for header order, `mustUnderstand`, and body contents.

Find the rules by operation.

- Start a logout as a [session participant](#logoutrequest-from-a-session-participant) or [session authority](#logoutrequest-from-a-session-authority).
- Receive or reply to a logout. See [acceptance](#logout-acceptance), [session selection](#sp-session-selection), and [response generation](#logoutresponse).
- Check [browser bindings](#browser-bindings), [asynchronous logout](#asynchronous-single-logout), or [SOAP](#soap-binding).

## LogoutRequest from a session participant

`ServiceProvider::start_slo` is this actor.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `Issuer` without `Format` or with the `entity` format | Mandatory | Profiles §4.4.4.1 | Always |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §1.3.3 | Always |
| Never write a time with a leap second | Mandatory | Core §1.3.3 | Always |
| Identify the principal with `NameID`, or `EncryptedID` when selected | Mandatory | Profiles §4.4.4.1, `LogoutRequestType` | `StartSlo::identifier_encryption` |
| Give no logout subject for an accepted assertion without a `NameID`, because no identifier can strongly match it | Mandatory | Profiles §4.4.4.1, Core §3.3.4 | `SsoSession::logout_subject` |
| Copy `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from the `LogoutSubject` `NameId` | Mandatory | Profiles §4.4.4.1, Core §3.7.1, §3.3.4 | Always |
| Omit `Format` when the `NameId` has none | Optional | Core §2.2.2, E60 | Always |
| Reject a `Format` that is not an absolute URI reference, also when the `NameId` came from an accepted assertion | Mandatory | Core §1.3.2 | Always |
| Send the `NameId` value and qualifiers without the length and `entity` checks of [identifier formats](identifiers.md#name-identifier-formats) | Library policy: the request identifies the principal as the identity provider issued it, and Core §8.3 binds that producer. | Profiles §4.4.4.1, Conformance §3.3 | Always |
| Include at least one `SessionIndex` | Mandatory | Profiles §4.4.4.1, E38 | Always |
| Sign the request on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. CD-04 §2.4 makes the SimpleSign signature optional, but the profile requires the requester to authenticate by signing, so for logout it is mandatory | Mandatory | Profiles §4.4.3.1, §4.4.4.1, CD-04 §2.4 | Always |
| Send the user agent to an `https` `SingleLogoutService`. A recipient does not reject an `http` `Destination` | Recommended | Profiles §4.4.3.1 | `StartSlo::allow_http` |
| On a browser binding, send to the first peer `SingleLogoutService` for the binding with an `https` `Location`, or the first one under `allow_http` | Library policy: an earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.4.3.1 | `StartSlo::allow_http` |
| Omit `NotOnOrAfter` in session participant requests | Optional | Core §3.7.1, §3.7.3.2 | Always |

### Asynchronous Single Logout

`ServiceProvider::start_async_slo` implements the request initiator role of
the [Asynchronous Single Logout Profile Extension](https://docs.oasis-open.org/security/saml/Post2.0/saml-async-slo/v1.0/saml-async-slo-v1.0.html)
for HTTP-Redirect and HTTP-POST. The participant rules above also apply.
Under §2.2, the IdP gives the user the outcome and sends no `LogoutResponse`
to the initiator.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Include an empty `aslo:Asynchronous` in `samlp:Extensions` after the issuer and any embedded signature, before the principal identifier | Mandatory | Async SLO §2.1, `RequestAbstractType`, `LogoutRequestType` | `start_async_slo` |
| Cover the extension with the query signature on Redirect and the embedded signature on POST | Mandatory | Profiles §4.4.4.1, Bindings §3.4.4.1, §3.5.5.2 | Always |
| Use an explicit call for an IdP endpoint that the application knows supports asynchronous logout | Library policy: support can be configured out of band because publishing it in metadata is optional. | Async SLO §2.3 | `start_async_slo` |

### Asynchronous Single Logout at the session authority

`IdentityProvider::receive_slo_with_async` supports HTTP-Redirect and HTTP-POST.
The [logout acceptance rules](#logout-acceptance) apply. The application owns
session lookup, session termination, and propagation to other participants.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Recognize an empty `aslo:Asynchronous` element only as a direct child of `samlp:LogoutRequest/samlp:Extensions` in the authenticated request | Mandatory | Async SLO §2.1, `AsynchronousType`, `RequestAbstractType` | `receive_slo_with_async` |
| Accept `xsi:schemaLocation` and `xsi:noNamespaceSchemaLocation` on the marker | Mandatory | Async SLO §2.1, `AsynchronousType`, XML Schema Part 1 §3.4.4 | `receive_slo_with_async` |
| Accept an `xsi:type` of `AsynchronousType` written with the marker's own prefix, or unprefixed on an unprefixed marker | Mandatory | Async SLO §2.1, `AsynchronousType`, XML Schema Part 1 §3.3.4 | `receive_slo_with_async` |
| Treat a marker whose `xsi:type` uses another prefix or names another type as absent, and keep the request on the response path | Library policy: the marker's name already relies on its own prefix, so the type resolves with the element, and the library knows no type derived from `AsynchronousType`. | XML Schema Part 1 §3.3.4 | Always |
| Treat a marker with any other attribute, `xsi:nil` included, as absent, and keep the request on the response path | Library policy: `AsynchronousType` declares no attributes and the element is not nillable, so that element is not the empty marker §2.1 defines. | Async SLO §2.1, XML Schema Part 1 §3.3.4 | Always |
| Finish at the IdP without a `LogoutResponse` to the initiator. The application presents the outcome on success or failure | Mandatory | Async SLO §2.2, Core §3.7.3.2 | `IdpLogoutAction::CompleteLocally` |

## LogoutRequest from a session authority

`IdentityProvider::start_slo` is this actor.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Set `NotOnOrAfter` from the issuance lifetime and the same `IssueInstant` | Mandatory | Core §3.7.3.2 | Always |
| Use the configured issuance lifetime, five minutes by default | Library policy: reason not recorded. | Core §3.7.3.2 | `IdpConfigBuilder::issuance_lifetime` |
| Write `Issuer`, `ID`, `Version`, `IssueInstant`, and the principal identifier, and never a leap second, as the participant does | Mandatory | Profiles §4.4.4.1, Core §1.3.3 | Always |
| Write a principal identifier that strongly matches the one in the issued assertion, with the `NameId` attributes copied as the participant does | Mandatory | Profiles §4.4.4.1, Core §3.3.4, §3.7.1 | Always |
| After choosing the `Format`, reject a persistent or transient value over 256 characters and an `entity` `NameID` that [identifier formats](identifiers.md#name-identifier-formats) refuses, before encrypting and signing | Mandatory | Core §8.3.6, §8.3.7, §8.3.8 | Always |
| When the subject has no `Format`, use the first configured NameID format, or omit `Format` if none is configured | Library policy: `respond_sso` uses the same format for that subject. | Core §2.2.2, E60 | Always |
| Omit every `SessionIndex` to end all applicable sessions of the principal | Optional | Profiles §4.4.4.1, E38 | Always |
| Sign the request on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. CD-04 §2.4 makes the SimpleSign signature optional, but §4.4.4.1 requires the requester to authenticate by signing | Mandatory | Profiles §4.4.4.1, CD-04 §2.4 | Always |

## LogoutRequest reason

`start_slo` on both roles can write `Reason` on HTTP-Redirect, HTTP-POST,
HTTP-POST-SimpleSign, and SOAP, covered by the request signature. `receive_slo`
on both roles exposes the received attribute through `LogoutRequest::reason`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write a caller-supplied `Reason` and omit it when unset | Optional | Core §3.7.1, §3.7.3 | `StartSlo::reason` |
| Require an absolute URI reference for a typed `Reason`, using the same `anyURI` whitespace and syntax rules as [identifier formats](identifiers.md#name-identifier-formats) | Mandatory | Core §1.3.2, §3.7.1, E10 | `StartSlo::reason` |
| Send the `global-timeout` and `sp-timeout` reasons only from the identity provider, which is the session authority. The service provider refuses them on ordinary and asynchronous logout, after whitespace collapse | Mandatory | Core §3.7.3.2, E0 | Always |
| Read an optional unqualified `Reason` from an authenticated request as an `xs:string`, preserving its XML-normalized value and absence without URI validation or `anyURI` whitespace collapse. Ignore a qualified attribute with the same local name | Optional | Core §3.7.1, §3.7.3, `LogoutRequestType`, E10 | `LogoutRequest::reason` |

## Peer endpoints

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the peer `SingleLogoutService` from the role descriptor of the peer role, never from the other role of an entity that plays both | Optional | Metadata §2.4.2, Profiles §4.4.3.1, §4.4.5 | Always |
| Send the response to `ResponseLocation` when present, otherwise `Location`, after `anyURI` whitespace collapse. A request uses `Location` | Recommended | Metadata §2.2.2, E41 | Always |
| A session authority's browser messages and SOAP requests from either role use the first endpoint for the binding. A session participant's browser messages use the endpoint the participant rows describe | Library policy: metadata order is the only preference the peer publishes for endpoints of one binding, and OpenSAML 5.2.3 and crewjam/saml v0.4.14 also take the first. | Metadata §2.2.2 | Always |

## LogoutResponse

`respond_slo` and `respond_slo_refusal` on either role.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a `LogoutRequest` with a `LogoutResponse` | Mandatory | Core §3.7.2, Profiles §4.4.3.4, §4.4.3.5 | `respond_slo` |
| Answer an authenticated newer request version with `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version | Mandatory | Core §4.1.3.1, §4.1.3.2, Profiles §4.4.3.4, §4.4.3.5 | `respond_slo_refusal` |
| Write `Issuer` without `Format` or with the `entity` format | Mandatory | Profiles §4.4.4.2 | Always |
| Write `ID`, `Version` `2.0`, a UTC `IssueInstant` without a leap second, and `InResponseTo` equal to the request `ID` | Mandatory | `StatusResponseType`, Core §3.2.2, §1.3.3 | Always |
| Sign the response on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. CD-04 §2.4 makes the SimpleSign signature optional, but the profile requires the responder to authenticate by signing, so for logout it is mandatory | Mandatory | Profiles §4.4.3.4, §4.4.4.2, CD-04 §2.4 | Always |
| A session participant sends the response to an `https` `SingleLogoutService`. A session authority's response has no such check | Recommended | Profiles §4.4.3.4 | `RespondSlo::allow_http` |
| A session participant on a browser binding answers at the first peer endpoint for the binding whose response URL is `https`, or the first one under `allow_http` | Library policy: an earlier `http` entry would otherwise hide an advertised `https` one. | Metadata §2.2.2, Profiles §4.4.3.4 | `RespondSlo::allow_http` |
| Return the exact `RelayState` of the request, including a value over 80 bytes up to the receive limit, with no setter to replace or drop it | Mandatory | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Return a SOAP reply on the request's exchange. Return a reply to a browser request through the user agent | Mandatory | Profiles §4.4.3.4, §4.4.3.5 | `respond_slo`, `respond_slo_refusal` |
| Choose any supported browser response binding that the peer publishes | Optional | Profiles §4.4.3.4, §4.4.3.5 | `RespondSlo` |
| Reject a `LogoutRequest` whose issuer is not the peer descriptor entity | Library policy: a response must not go to another party's `SingleLogoutService`. | — | Always |
| Write a top-level `StatusCode` of `Success`, `Requester`, `Responder`, or `VersionMismatch`, with an optional subordinate code | Mandatory | Core §3.2.2.2 | `status` argument |
| Write caller-supplied plain text as `StatusMessage` after `StatusCode` before signing. Omit the element by default | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | `RespondSlo::status_message` |
| Write a `StatusMessage` only with a character other than XML whitespace. An empty string omits the element, and other text with only XML whitespace is refused | Mandatory | Core §1.3.1, §3.2.2.3 | Always |
| Write a subordinate `StatusCode` `Value` that is an absolute URI reference | Mandatory | Core §1.3.2 | `SubordinateStatusCode::try_new` |
| Reject whitespace, `"`, `<`, and `>` in a caller-supplied subordinate code, and whitespace in the outbound response `Issuer` | Library policy: reason not recorded. | Core §1.3.2 | Always |
| Return the application's local logout status and any required `PartialLogout` in the reply to the initiator | Mandatory for the session authority. See [application duties](#session-authority-application-duties) | Core §3.7.3.2 | `IdentityProvider::respond_slo` `status` |
| A session participant returns an appropriate status after processing the request or on error. The caller passes the status | Mandatory | Profiles §4.4.3.4, Core §3.7.3.1 | `ServiceProvider::respond_slo` `status` |

## Session authority application duties

The IdP application owns the session store, participant tracking, propagation,
and the aggregate outcome. The typed APIs build and validate individual
exchanges.

| Rule | Level | Section | Actor |
| --- | --- | --- | --- |
| Determine the sessions to terminate from the identifier and any session indexes when starting logout or handling a valid `LogoutRequest` | Mandatory | Profiles §4.4.3.2 | IdP application |
| For a request from a participant in the current session, contact the upstream authority when applicable, then the other participants, then end the local session. Skip the originator and continue attempting other peers after failures | Recommended | Core §3.7.3.2, Profiles §4.4.3.2–§4.4.3.3 | IdP application |
| When replying to the original requester, use top-level `Success` if local logout succeeded or a top-level error if it failed. Include second-level `PartialLogout` if an applicable participant could not be contacted or failed to confirm logout | Mandatory | Core §3.7.3.2, Profiles §4.4.3.5 | IdP application |

The standard describes an upstream propagation step for a proxy. This crate's
IdP APIs cover per-peer exchanges with SPs. [Core §3.7.3.2](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=62)
and [Profiles §4.4.3](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf#page=34)
describe the deployment flow.

## Logout acceptance

`receive_slo` and `finish_slo` on both roles. Response recipients apply the
shared [status code rule](web-browser-sso-acceptance.md#status-codes).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a verified signature on a `LogoutRequest` received over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign. CD-04 §2.4 makes the SimpleSign signature optional, but the profile requires authentication by signing | Mandatory | Core §3.7.3.1, §3.7.3.2, Profiles §4.4.3.1, §4.4.4.1, CD-04 §2.4 | `receive_slo` |
| Require a verified signature on a `LogoutResponse` received over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign. CD-04 §2.4 makes the SimpleSign signature optional, but the profile requires authentication by signing | Mandatory | Profiles §4.4.3.4, §4.4.4.2, CD-04 §2.4 | `finish_slo` |
| Reject an `IssueInstant` that is not a UTC `xs:dateTime` | Mandatory | Core §1.3.3 | Always |
| Accept an `IssueInstant` with a leap second | Library policy: Core §1.3.3 binds the producer only. | Core §1.3.3 | Always |
| Reject a `LogoutRequest` `NotOnOrAfter` the runtime clock cannot represent, a leap second included | Library policy: the expiration check fails closed on a value it cannot compare. | Core §1.3.3, §3.7.1 | Always |
| For browser messages and SOAP requests, compare a present `Destination` after collapsing XML whitespace. Use the supplied receiving URL or infer the unique published endpoint for the binding and direction | Mandatory | Core §3.2.1, §3.2.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Require `Destination` on a signed message from a browser binding | Mandatory | Bindings §3.4.5.2, §3.5.5.2, CD-04 §2.4 | Always |
| Accept only a receiving URL published in the local role descriptor for the binding and direction, and reject several published URLs without an explicit one | Library policy: reason not recorded. | Core §3.2.1 | `SamlValidationContext::with_recipient_endpoint` |
| Accept a response over any of HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign that the local metadata publishes, after a request sent over one of them. Compare `Destination` with the local `SingleLogoutService` of the arrival binding | Optional | Profiles §4.4.3.4, §4.4.3.5 | Always |
| Keep a SOAP response on the SOAP request's exchange, and reject crossing between SOAP and browser delivery | Library policy: a SOAP response answers the synchronous exchange of its request. | Profiles §4.4.3.4, §4.4.3.5 | Always |
| Require the unqualified response `InResponseTo`, after XML whitespace collapse, to equal the pending request `ID` | Library policy: a missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2, `StatusResponseType`, XML Schema Part 2 §4.3.6 | Always |
| Require the returned `RelayState` to equal the one the request carried, an empty value included | Library policy: Bindings §3.5.5.2 leaves the association with the form's `RelayState` unprotected under an HTTP-POST XML signature. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Accept a `RelayState`, an empty one included, that the responder adds to a request that carried none | Optional | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Return a status other than `Success` as an error | Library policy: no OASIS rule orders the checks, so an unauthenticated or unrelated error response must not be reported as a status. | Core §3.2.2.2 | `finish_slo` |
| Return the optional subordinate status code on a successful response, including `PartialLogout` | Optional | Core §3.2.2.2, §3.7.3.2 | `LogoutCompleted::response`, `LogoutResponse::status` |
| Return one nonempty, text-only protocol `StatusMessage` directly under the authenticated and correlated response's `Status`. Omit diagnostics with attributes, child elements, or ambiguous cardinality | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType`, Profiles §4.4.4.2 | `finish_slo` |
| Require exactly one direct `BaseID`, `NameID`, or `EncryptedID` child in the SAML assertion namespace on every supported binding | Mandatory | Core §3.7.1, `LogoutRequestType` | Always |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Allow the validation-context clock skew on `LogoutRequest` `NotOnOrAfter`, five minutes by default | Recommended | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew` |
| Discard a `LogoutRequest` at or after its skew-adjusted `NotOnOrAfter` | Library policy: Core §3.7.1 only permits discarding an expired request. | Core §3.7.1 | `ClockSkew` |
| Apply the [signature algorithm profile](xml-security-algorithms.md#weak-algorithms-and-keys) to an embedded signature and a detached `SigAlg`, including the mandatory logout signatures | Library policy: hardening beyond the default exclusions. | — | `XmlSignatureProfile::StrictRsaSha2` |

## SP session selection

`Received<LogoutRequest>::matches_sp_session` checks one local session after
`ServiceProvider::receive_slo` authenticates the IdP request. The application
stores the assertion issuer and logout subject, looks up candidate sessions,
and invalidates each match.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Match only sessions established by an assertion from the request issuer | Mandatory | Core §3.7.3.1 | `matches_sp_session` |
| Compare the `NameID` value, effective `Format`, and all three qualifier attributes. An omitted `Format` means `unspecified` | Mandatory | Core §2.2.2, §3.3.4, §3.7.3.1, Profiles §4.4.4.1, E60, `NameIDType` | `matches_sp_session` |
| With one or more `SessionIndex` elements, require at least one match. With none, select every session from that authority with the matching `NameID` | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, E38, `LogoutRequestType` | `matches_sp_session` |
| Return no built-in match for a `BaseID` or an `EncryptedID` that could not be decrypted to a `NameID` | Library policy: the helper needs a `NameID` to compare. | Core §2.2.1, §3.3.4, §3.7.3.1 | `matches_sp_session` |

## Encrypted principal identifier

`StartSlo::identifier_encryption` and `receive_slo` on both roles, on HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and SOAP. Conformance Requirements §3.4 requires every relevant operational mode to process or generate `<saml:EncryptedID>` wherever it processes or generates `<saml:NameID>`. These rows do not claim the IdP or SP operational mode.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send `EncryptedID` in place of `NameID` | Optional | Core §3.7.1, §6.1 | `StartSlo::identifier_encryption` |
| When encrypting the identifier, encrypt it before signing the containing message | Library policy: the signature then covers the ciphertext, and E93 replaced the original Core §6.2 ordering rule. | Core §6.2, E93 | Always |
| Encrypt for a key of the peer role that publishes the receiving `SingleLogoutService`, or of the first such role when several do. Never use a key of another role | Library policy: E62 declares a key for the entity acting in its own role, so another role's key may not reach the receiving endpoint. | Profiles §4.4.5, Metadata §2.4.1, E62, E68 | `StartSlo::identifier_encryption` |
| Within that role, read the keys as for [SSO responses](web-browser-sso-generation.md#encryption) and use the first one the configured algorithms can use. Skip a key that does not load or that the crypto provider refuses | Library policy: E68 lets the encrypting party use any key of the role, and OpenSAML 5.2.0 also skips a credential without a usable key transport. | Metadata §2.4.1.1, E68 | `StartSlo::identifier_encryption` |
| Process a received `EncryptedID` with the local decryption key, whatever the `XmlEncryptionPolicy`, and accept a plaintext `NameID` | Mandatory | Conformance §3.4 | Always |
| Accept an authenticated request whose `EncryptedID` no configured key decrypts, RSA-v1.5 key transport not allowed included, without a `NameID`. A key that fails to load is an error | Library policy: Core §3.7.2 requires the recipient to answer, so an undecryptable identifier must not block the answer. | Core §3.7.2, §3.7.3.2 | Always |
| Require the plaintext to be one `NameID` or `BaseID` in the assertion namespace. For a `BaseID`, return the authenticated request without a `NameID` | Library policy: Core §2.2.4 allows extension types, and the library cannot interpret extension element names. | Core §2.2.4 | Always |
| Decrypt only an authenticated request, and after replay storage when a replay cache is supplied | Library policy: unauthenticated ciphertext never reaches the decryptor. | — | Always |
| Match later assertions to the decrypted `NameID` through `OutstandingLogout` | Mandatory | Core §3.7.3.1 | `ServiceProvider::finish_sso_with_outstanding_logout` |

## Browser bindings

Typed logout send and receive use HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign for `LogoutRequest` and `LogoutResponse`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a request `RelayState` over 80 bytes | Mandatory | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | `StartSlo::relay_state` |
| Accept a received `RelayState` up to `MAX_RECEIVED_RELAY_STATE_BYTES`, 4096 bytes | Library policy: a resource limit on unauthenticated input, because the bindings bind the sender only. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Reject a second `RelayState`, matched by its decoded name | Library policy: the library compares, reports, or echoes one value, and a caller's framework may read another. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| HTTP-Redirect: remove a protocol `ds:Signature`, DEFLATE, then sign `SAMLRequest` or `SAMLResponse`, `RelayState` when present, and `SigAlg` | Mandatory | Bindings §3.4.4.1 | Always |
| HTTP-Redirect: verify the signature over the original URL-encoded values of the parameters found by decoded name, omitting an absent `RelayState` | Mandatory | Bindings §3.4.4.1 | Always |
| HTTP-Redirect: raw-inflate the message when `SAMLEncoding` is absent or names DEFLATE | Mandatory | Bindings §3.4.4 | Always |
| HTTP-Redirect: reject a repeated `SAMLEncoding`, or one that names another encoding, an empty value included | Library policy: saml-rs implements only DEFLATE, and inflating another encoding misreads the message. | Bindings §3.4.4 | Always |
| HTTP-Redirect: reject a received `RelayState`, or another SAML parameter the message reads, that is not UTF-8 after percent-decoding | Library policy: `RelayState` is text, and replacing the bytes would change the value the responder returns. | Bindings §3.4.3 | Always |
| HTTP-Redirect: keep the endpoint's own query parameters before the SAML parameters, and refuse an endpoint query that already has `SAMLRequest`, `SAMLResponse`, `SAMLart`, `RelayState`, `SigAlg`, `Signature`, or `SAMLEncoding`, by decoded name | Library policy: the bindings name these parameters, so a configured one can repeat a message field or be read as one by an endpoint that serves several bindings. | Bindings §3.4.4 | Always |
| Refuse a form `RelayState` with a CR or LF outside a CRLF pair, a received one included | Library policy: HTML form submission sends the character as CRLF, so the form cannot return the exact value. | Bindings §3.1.1, §3.5.4, CD-04 §2.3 | Always |
| Refuse a form `RelayState` with a character outside the XML `Char` production, such as U+0000, a received one included | Mandatory | Bindings §3.5.4, XML 1.0 §2.2 | Always |
| HTTP-POST-SimpleSign: sign and verify the raw XML octets, `RelayState` when present, then `SigAlg`, and leave an XML signature in the message intact | Mandatory | CD-04 §2.4, §2.5, §2.6 | Always |
| Ignore ASCII whitespace in base64 message content and the detached `Signature`, and reject any other character outside the alphabet | Library policy: the sender removes whitespace (Bindings §3.4.4.1) or only wraps lines (§3.5.4), so another character means the value was altered. | Bindings §3.4.4.1, §3.5.4 | Always |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Recommended | Bindings §3.4.5.1, §3.5.5.1, CD-04 §2.7.1 | `Outbound::headers` |

## SOAP binding

`StartSlo::soap` and `RespondSlo::soap` cover one SOAP request and response
between an SP and an IdP. Either role can initiate the exchange.
The generation rules above apply on SOAP. The deployment owns the connection,
TLS, and HTTP authentication. The IdP application handles
[propagation and the aggregate status](#session-authority-application-duties).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the request on a synchronous binding | Optional | Profiles §4.4.3.1, §4.4.3.3 | `StartSlo::soap` |
| Put exactly one SAML request or response in the SOAP body, with no other element | Mandatory | Bindings §3.2.2.1, E19 | Always |
| Authenticate the requester and protect message integrity. Typed SOAP generation signs the `LogoutRequest` | Mandatory | Profiles §4.4.3.1, §4.4.4.1 | Always |
| Authenticate the responder and protect message integrity. Typed SOAP generation signs the `LogoutResponse` | Mandatory | Profiles §4.4.3.4, §4.4.4.2 | Always |
| Authenticate a received `LogoutRequest` or `LogoutResponse`. Require its XML signature unless the channel attests mutual authentication and integrity, and verify a present signature either way | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, §4.4.4.2 | `Inbound::soap`, `SoapChannel` |
| Reject `RelayState` on a SOAP message | Library policy: the SOAP binding has no place to carry it, so a value is rejected rather than dropped. | Bindings §3.2 | `StartSlo::relay_state` |
| Set the request `Destination` to the peer SOAP `SingleLogoutService` `Location` | Optional | Core §3.2.1 | Always |
| Compare a present `LogoutRequest` `Destination` with the local SOAP `SingleLogoutService` after collapsing XML whitespace. Accept a signed SOAP request without it | Mandatory | Core §3.2.1, Bindings §3.4.5.2, §3.5.5.2, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Omit `Destination` from the `LogoutResponse` | Optional | Core §3.2.2 | Always |
| Compare a present `LogoutResponse` `Destination` with the location that received the response, after collapsing XML whitespace | Mandatory | Core §3.2.2, XML Schema Part 2 §4.3.6 | Always |
| Take the local SOAP `SingleLogoutService` `Location` as the location that received a SOAP response. Without `Destination`, require no local SOAP endpoint | Library policy: a SOAP response has no HTTP endpoint of its own, and a responder that sets `Destination` names the requester's SOAP endpoint, as [Keycloak 26.8.2](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/protocol/saml/SamlService.java#L742-L745) does. | Core §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Publish a SOAP `SingleLogoutService`, and do not read its `ResponseLocation` | Recommended | Bindings §3.2.3.4, Profiles §4.4.5 | `SloEndpoint::soap` |
| Send a `SOAPAction` header | Mandatory | SOAP 1.1 §6.1.1 | `SoapRequest::headers` |
| Write the `SOAPAction` URI `http://www.oasis-open.org/committees/security` bare, as in the [SOAP envelope rules](artifact-resolution.md#soap-envelope-rules) | Library policy: Bindings §3.2.3 writes the value bare, while SOAP 1.1 §6.1.1 quotes it. | Bindings §3.2.3, SOAP 1.1 §6.1.1 | `SoapRequest::headers` |
| Use the `text/xml` media type for a SOAP entity body. The crate sends `charset=utf-8` | Mandatory | SOAP 1.1 §6 | `SoapRequest::headers`, `SoapResponse::headers` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` on the request | Recommended | Bindings §3.2.3.2 | `SoapRequest::headers` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` on the response | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers` |
| Report a SAML-domain error as a `LogoutResponse` status with HTTP 200, not a SOAP fault | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | `respond_slo` `status` |

## Outside this flow

- Setting `Consent` or caller-defined extensions on outbound logout messages, or `StatusDetail` on outbound responses. Optional, `RequestAbstractType`, `StatusResponseType`, `StatusType`.
- Propagating logout to other participants. See [session authority application duties](#session-authority-application-duties).
- Session invalidation and session tracking. The caller owns them. Mandatory for the participant, Core §3.7.3.1.
- Setting `NotOnOrAfter` at or after the latest assertion `NotOnOrAfter`. Recommended, Core §3.7.3.2. Typed `start_slo` receives no assertion, and [ADR 0001](https://samlrs.vercel.app/explanation/logout-expiration/) records the choice.
- Adding `RelayState` in `respond_slo` when the request carried none. Optional for the responder, Bindings §3.4.3, §3.5.3, CD-04 §2.3.
- An `https` check on a session authority's `LogoutRequest`. Profiles §4.4.3.3 does not repeat the §4.4.3.1 recommendation.
- TLS and HTTP authentication of the SOAP exchange. Deployment duty, Conformance Requirements §3.5. `allow_http` has no effect on SOAP.
- An unsigned SOAP message that relies on another binding-supported mechanism when generating. Optional, Profiles §4.4.4.1, §4.4.4.2.
- HTTP-Artifact logout. Optional, Profiles §4.4.3.1, §4.4.3.4.
- The IdP Lite and SP Lite SOAP cells of Conformance Requirements Table 2. Optional.
