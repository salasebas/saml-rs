# Artifact resolution over SOAP

`IdentityProvider::issue_artifact`, `IdentityProvider::answer_artifact_resolve`, `ServiceProvider::resolve_artifact`, and `ArtifactResolution::finish` implement artifact resolution. `finish` reads the protocol message from the SOAP response and does not accept a Web SSO session.
Normative text is SAML Core, Bindings, Profiles, and Metadata 2.0 as corrected by Approved Errata 05, plus SOAP 1.1 and WS-I Basic Profile 1.1 for the shared [SOAP envelope rules](#soap-envelope-rules).
The deployment POSTs the envelope. TLS, HTTP authentication, and the HTTP 500 SOAP fault stay there, and `SoapChannel` records the protection it provided (Conformance Requirements §3.5 and §5).
Browser delivery of a Web SSO artifact is in [HTTP-Artifact response](web-browser-sso-artifact.md).

## Issuing an artifact

`IdentityProvider::issue_artifact` is the artifact issuer.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish an indexed `ArtifactResolutionService` | Recommended | Bindings §3.6.7, Metadata §2.4.2, Profiles §5.5, E2 | `IdpConfigBuilder::artifact_resolution_service` |
| Issue only for a SOAP `ArtifactResolutionService` at the given `EndpointIndex` | Library policy: this flow resolves over SOAP only, the one synchronous binding the crate implements. | Bindings §3.2, Profiles §5.3.1 | Always |
| Build the artifact from type code `0x0004`, a two-byte `EndpointIndex`, a 20-byte `SourceID`, and a 20-byte `MessageHandle` | Mandatory | Bindings §3.6.4.2, E4 | Always |
| Set `SourceID` to the raw SHA-1 of the issuer entity ID, not hexadecimal | Recommended | Bindings §3.6.4 | Always |
| Make a valid outstanding `MessageHandle` infeasible to construct or guess | Mandatory | Bindings §3.6.4.2 | Always |
| Generate the `MessageHandle` from a cryptographically strong random sequence | Recommended | Bindings §3.6.4 | Always |
| Encode the 44 artifact bytes as padded base64 | Mandatory | Bindings §3.6.4 | Always |
| Accept an unpadded artifact and normalize it to padded base64 for lookup | Library policy: reason not recorded. | Bindings §3.6.4 | Always |
| Reject whitespace in the value passed to `Artifact::try_new`. The SOAP reader first trims whitespace around the `Artifact` text | Library policy: strict decoding does not silently skip characters outside the alphabet (RFC 4648 §3.3), while RFC 2045 permits whitespace. | Bindings §3.6.4 | Always |
| Associate the stored message with the service provider it is for | Mandatory | Core §3.5.3, Profiles §4.1.4.4 | Always |
| Store only one element in the SAML protocol namespace | Library policy: `ArtifactResolution::finish` rejects any other payload, so another element could never be resolved. | Bindings §3.6 | Always |
| Reject processing instructions inside the element before issuing an artifact | Library policy: the stored element must be deliverable in a SOAP response when the artifact resolves. | SOAP 1.1 §3 | Always |

## ArtifactResolve

`ServiceProvider::resolve_artifact` is the requester. `IdentityProvider::answer_artifact_resolve` applies the two rejection rows.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send `ArtifactResolve` directly to the issuer using a synchronous binding and the endpoint identified by `EndpointIndex` | Mandatory | Profiles §5.3.1, §5.5, Bindings §3.6.4.2, E31 | Always |
| Include the requester's entity ID in `Issuer` and omit `Format` or set it to `entity` | Mandatory | Profiles §5.4.1 | Always |
| Include `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §3.2.1, §1.3.3 | Always |
| Do not generate a leap-second instant | Mandatory | Core §1.3.3 | Always |
| Set `Destination` to the endpoint location | Optional | Core §3.2.1 | Always |
| Send exactly one `samlp:Artifact` containing the received artifact value | Mandatory | `ArtifactResolveType` | Always |
| Reject a request missing `samlp:Artifact` or containing a second direct child named `Artifact` in any namespace | Mandatory | `ArtifactResolveType` | Always |
| Reject an `ArtifactResolve` with a second `Issuer` | Mandatory | `RequestAbstractType` | Always |
| Authenticate to the responder and protect integrity | Recommended | Profiles §5.3.1, §5.4.1 | Always |
| Require a confidential dereference for every artifact | Library policy: the artifact does not say which message it refers to, so the requester learns that only after the message has crossed the channel, and a Web SSO `<Response>` requires confidentiality. | Profiles §5.3.1, §5.4.1, §4.1.4.4 | Always |

## ArtifactResponse

`IdentityProvider::answer_artifact_resolve` is the artifact issuer.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present `ArtifactResolve` signature over the SOAP body message using the expected SP's signing keys before acting on the request | Mandatory | Core §3.2.1, §5.4.1–§5.4.2 | Always |
| Answer an understood `ArtifactResolve` with status Success, and omit the message for an unauthorized presenter or an artifact that is not outstanding | Mandatory | Bindings §3.6.6, Core §3.5.3, Profiles §5.3.2 | Always |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer request version with `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version and keep the artifact outstanding | Mandatory | Core §4.1.3.2 | Always |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Return the message only to the service provider it was issued to, authenticated by `SoapChannel` | Mandatory | Core §3.5.3, Bindings §3.6.5.2, Profiles §4.1.4.4 | Always |
| Treat a missing or different `Issuer`, or one with a format other than omitted or `entity`, as an unauthorized presenter | Library policy: the presenter check ties the request to the service provider the artifact was issued to. | Profiles §5.4.1, Bindings §3.6.6 | Always |
| Return the stored message at most once | Mandatory | Core §3.5.3, Bindings §3.6.5.2 | Always |
| Keep an outstanding artifact after withholding its message | Library policy: the intended recipient can still resolve it within its lifetime. | Core §3.5.3 | Always |
| Withhold the message when a present `Destination`, after XML whitespace collapse, differs from this endpoint | Mandatory | Core §3.2.1, `RequestAbstractType`, XML Schema Part 2 §4.3.6 | Always |
| Expire the artifact after the configured lifetime. The issuer should choose the shortest practical lifetime | Recommended | Core §3.5.3 | `IssuedArtifacts::expire_after` |
| Include the artifact issuer's entity ID in `Issuer` and omit `Format` or set it to `entity` | Mandatory | Profiles §5.4.2 | Always |
| Set `InResponseTo` to the request `ID` | Mandatory | Core §3.2.2, §3.5.3 | Always |
| Authenticate the responder and protect integrity | Mandatory | Profiles §5.3.2, §5.4.2 | `SoapChannel` |

## Web Browser SSO response artifact

Profiles §4.1.4.4 governs a Web Browser SSO `<Response>` delivered by artifact. The issuer applies the same channel checks to every stored `samlp:Response`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Dereference over a mutually authenticated, integrity-protected, confidential channel | Mandatory | Profiles §4.1.4.4 | Always |
| Take the confidential release for every stored `<Response>` | Library policy: the issuer cannot tell from the element which profile produced it, and every `<Response>` can carry an assertion. | Profiles §4.1.4.4 | Always |

## Service provider acceptance

`ArtifactResolution::finish` and `ServiceProvider::resolve_artifact` are the requester.

Both parties read `Issuer` as described in [entity identifiers](identifiers.md#entity-identifiers).
The requester reads the [status codes](web-browser-sso-acceptance.md#status-codes)
using XML Schema whitespace collapse.
Unsigned messages can use the required SOAP channel protection. A present XML
signature requires a crypto provider and uses the receiver's XML signature
profile. Web SSO applies its own checks to the dereferenced response.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a SOAP body that is not an `ArtifactResponse` | Mandatory | Core §3.5.2 | Always |
| Require `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `StatusResponseType`, Core §3.2.2, §1.3.3 | Always |
| Require exactly one `Status` | Mandatory | `StatusResponseType` | Always |
| Require the response `InResponseTo` to equal the pending request ID | Library policy: a missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2 | Always |
| Verify a present `ArtifactResponse` signature over the SOAP body message using the expected IdP's signing keys before reporting its status or returning its message | Mandatory | Core §3.2.2, §5.4.1–§5.4.2 | Always |
| Reject an `ArtifactResponse` with more than one message element | Mandatory | `ArtifactResponseType` | Always |
| Return a message only from a Success status that carries one | Library policy: reason not recorded. | Profiles §5.3.2, Core §3.5.3 | Always |
| Require an `Issuer` equal to the identity provider that omits `Format` or sets it to `entity` | Library policy: the requester attributes the responder by this `Issuer` together with `SoapChannel`, so without it `finish` would return a message not attributed to the artifact issuer. | Profiles §5.4.2 | Always |
| Require the message to be one element in the SAML protocol namespace | Library policy: `finish` returns the dereferenced protocol message, and another element would be presented as that message. | `ArtifactResponseType`, Profiles §5.3.2 | Always |
| Record the artifact when resolution starts. Refuse repeats during retention even if resolution fails. Choose retention longer than the issuer's acceptance period | Recommended | Bindings §3.6.5.2 | `ReplayPolicy::RequireCache`, `ReplayPolicy::NoCache`, `SamlValidationContext::with_replay_retention` |

## SOAP envelope rules

`SoapRequest`, `SoapResponse`, and `SoapProtocolMessage::from_envelope`
write and read envelopes for artifact resolution,
[Single Logout](single-logout.md#soap-binding), and
[name identifier management](name-id-management.md). SOAP 1.1 governs
`actor` and `mustUnderstand` in these flows.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept only the SOAP 1.1 envelope namespace | Mandatory | Bindings §3.2.2 | Always |
| Carry one SAML request or response in the `Body`, with no other `Body` element, and reject a body with none, several, or extra elements | Mandatory | Bindings §3.2.2.1, E19, SOAP 1.1 §4.3 | Always |
| Emit requests and responses without processing instructions | Mandatory | [SOAP 1.1 §3](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383492) | Always |
| Treat only attributes in the SOAP 1.1 envelope namespace as `actor` and `mustUnderstand` | Mandatory | SOAP 1.1 §4.2.2, §4.2.3 | Always |
| Process only header entries addressed to this endpoint: no `actor`, or `http://schemas.xmlsoap.org/soap/actor/next`. Ignore entries for other actors | Mandatory | SOAP 1.1 §4.2.2 | Always |
| Refuse a local header entry with `mustUnderstand="1"` that the endpoint does not process | Mandatory | SOAP 1.1 §4.2.3 | Always |
| Require no header to process the SAML message | Mandatory | Bindings §3.2.2.2 | Always |
| Treat an empty `actor` as local | Library policy: an empty value identifies no other actor, so the receiver keeps responsibility for mandatory headers. | SOAP 1.1 §4.2.2 | Always |
| Treat a local `mustUnderstand="true"` as mandatory | Library policy: SOAP 1.1 specifies `0` and `1`, and skipping `true` would silently ignore processing the sender asked for. | SOAP 1.1 §4.2.3 | Always |
| Reject a second `Header` or a `Header` that does not immediately precede `Body` | Library policy: reason not recorded. | SOAP 1.1 §4, §4.3 | Always |
| Reject an element after the `Body` | Library policy: SOAP 1.1 permits these trailers, and WS-I Basic Profile 1.1 forbids them, so rejection keeps the crate interoperable. | SOAP 1.1 §4, WS-I BP 1.1 R1011 | Always |
| Use `http://www.oasis-open.org/committees/security` as the `SOAPAction` value | Optional | Bindings §3.2.3 | `SoapRequest::headers` |
| Send the `SOAPAction` value without quotes | Library policy: Bindings §3.2.3 writes the value bare, and OpenSAML and Keycloak send it bare, while SOAP 1.1 and R1109 require a quoted string. | Bindings §3.2.3, SOAP 1.1 §6.1.1, WS-I BP 1.1 R1109 | `SoapRequest::headers` |
| Process the request independently of the `SOAPAction` value | Mandatory | Bindings §3.2.3 | Always |
| Return a SAML-domain error as a status in a SAML response, not as a SOAP fault | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | Always |
| Send SOAP entity bodies with the `text/xml` media type | Mandatory | SOAP 1.1 §6 | `SoapRequest::headers`, `SoapResponse::headers` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` with a request | Recommended | Bindings §3.2.3.2 | `SoapRequest::headers` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` with a response | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers` |

## SOAP for another protocol message

`SoapRequest::try_new` and `SoapResponse::try_new` place one SAML protocol element in a SOAP 1.1 body, and `SoapProtocolMessage::from_envelope` reads one element back. The envelope rules above apply to each.

## Outside this flow

- Browser delivery of an artifact: [HTTP-Artifact response](web-browser-sso-artifact.md).
- `AuthnRequest` over HTTP-Artifact. Optional, Bindings §3.6.
- Signing outbound `ArtifactResolve` or `ArtifactResponse`. Optional, Profiles §5.3.1, §5.3.2.
- The assertion query/request profile over SOAP. Requirements vary by query and operational mode. Profiles §6, Conformance §3.2 Table 4.
- The IdP operational mode and the SP operational mode: [IdP and SP operational modes](idp-sp-operational-modes.md).
