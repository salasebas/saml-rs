# Artifact resolution over SOAP

`IdentityProvider::issue_artifact` and `IdentityProvider::answer_artifact_resolve` are the issuer APIs. The service provider prepares a request with `resolve_artifact` or `resolve_artifact_with_signed_request`. `ArtifactResolution::finish` reads the protocol message from the SOAP response. The Web SSO API accepts the session.
Normative text is SAML Core, Bindings, Profiles, and Metadata 2.0 as corrected by Approved Errata 05, plus SOAP 1.1 and WS-I Basic Profile 1.1 for the shared [SOAP envelope rules](#soap-envelope-rules).
The deployment POSTs the envelope. TLS, HTTP authentication, and the HTTP status code stay there, and `SoapChannel` records the protection it provided (Conformance Requirements §3.5 and §5). `SoapFault` writes the body of a SOAP fault.
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
| Decode a received `SAMLart` or SOAP `Artifact` with the shared [base64 rules](single-logout.md#browser-bindings). The SOAP reader first trims whitespace around the `Artifact` text, non-ASCII whitespace included. Look the artifact up and consume it by its padded base64 without whitespace, which `Artifact::as_str` returns | Library policy: every spelling of one artifact names the same 44 bytes, so the spelling must not decide which artifact resolves or whether it resolves again. | Bindings §3.6.4, RFC 2045 §6.8 | Always |
| Associate a message intended for a specific service provider with that service provider | Mandatory | Core §3.5.3, Profiles §4.1.4.4 | Always |
| Associate every stored message with the service provider passed to `issue_artifact`, including one that any party may consume | Library policy: the issuer cannot tell from the element whether any party may consume it, and one presenter per artifact never releases a recipient-specific message to another. | Core §3.5.3 | Always |
| Store only one element in the SAML protocol namespace | Library policy: `ArtifactResolution::finish` rejects any other payload, so another element could never be resolved. | Bindings §3.6 | Always |
| Refuse an element with processing instructions before issuing an artifact | Library policy: the SOAP response that releases the element [must carry no processing instructions](#soap-envelope-rules), and refusing at issuance keeps the artifact from becoming unresolvable. | SOAP 1.1 §3 | Always |
| Budget the complete SOAP response before storing the message | Library policy: issue only artifacts whose responses fit the crate's XML limits. | Core §3.5.3, Bindings §3.2.2.1, E19 | Default `XmlLimits` |

### SOAP response size budget

For a valid artifact, SAML 2.0 Core §3.5.3 requires the IdP responder to
return the stored message once. Bindings §3.2.2.1, as corrected by E19,
says the responder should return a SAML response or a SOAP fault, and forbids
a second response or another body element. Those clauses set the response
shape and single-use rule. The XML resource budget is
library policy. [Core §3.5.3](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=56),
[Bindings §3.2.2.1](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=10),
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).

OpenSAML 5.2.3 stores the outgoing message in `HTTPArtifactEncoder` and
attaches it to the SOAP response in `ResolveArtifact`. Before the IdP issues
an artifact, saml-rs checks the SOAP envelope and `ArtifactResponse` with the
final payload, any embedded signatures, and space for the largest request ID
the response can echo. It checks the actual envelope again before consuming
the entry. The fixed outbound budget uses default `XmlLimits`, including
1 MiB for the full envelope. `XmlPolicy::limits` configures inbound parsing.
This bounds XML processing and avoids issuing an artifact that cannot be
released, at the cost of rejecting large schema-valid messages that a peer
with a higher receive limit could accept. [OpenSAML 5.2.3 source release](https://build.shibboleth.net/maven/releases/org/opensaml/opensaml-saml-impl/5.2.3/).

## ArtifactResolve

`ServiceProvider::resolve_artifact` and `ServiceProvider::resolve_artifact_with_signed_request` are the requester APIs. `IdentityProvider::answer_artifact_resolve` applies the two rejection rows.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send `ArtifactResolve` directly to the issuer using a synchronous binding and the endpoint identified by `EndpointIndex` | Mandatory | Profiles §5.3.1, §5.5, Bindings §3.6.4.2, E31 | Always |
| Resolve only an artifact whose `SourceID` is the SHA-1 of the selected identity provider's entity ID | Library policy: SAML V2.0 metadata publishes no other `SourceID`, so another value names an issuer that the selected descriptor cannot be shown to be. | Bindings §3.6.4, §3.6.4.2 | Always |
| Include the requester's entity ID in `Issuer` and omit `Format` or set it to `entity` | Mandatory | Profiles §5.4.1 | Always |
| Include `ID`, `Version` `2.0`, and a UTC `IssueInstant` | Mandatory | `RequestAbstractType`, Core §3.2.1, §1.3.3 | Always |
| Do not generate a leap-second instant | Mandatory | Core §1.3.3 | Always |
| Set `Destination` to the endpoint location | Optional | Core §3.2.1 | Always |
| Send exactly one `samlp:Artifact` containing the received artifact value | Mandatory | `ArtifactResolveType` | Always |
| Reject a request missing `samlp:Artifact` or containing a second direct child named `Artifact` in any namespace | Mandatory | `ArtifactResolveType` | Always |
| Reject an `ArtifactResolve` with a second `Issuer` | Mandatory | `RequestAbstractType` | Always |
| Authenticate to the responder and protect integrity | Recommended | Profiles §5.3.1, §5.4.1 | Always |
| Sign the outbound SOAP body message with the SP signing credential | Optional | Core §3.5.1, Profiles §5.3.1, §5.4.1 | `ServiceProvider::resolve_artifact_with_signed_request` with a crypto provider |
| When signing, place the enveloped signature after `Issuer` and reference the `ArtifactResolve` ID | Mandatory | `RequestAbstractType`, `ArtifactResolveType`, Core §5.4.1, §5.4.2 | When signing |
| Require a confidential dereference for every artifact | Library policy: the artifact does not say which message it refers to, so the requester learns that only after the message has crossed the channel, and a Web SSO `<Response>` requires confidentiality. | Profiles §5.3.1, §5.4.1, §4.1.4.4 | Always |

## ArtifactResponse

`IdentityProvider::answer_artifact_resolve` is the artifact issuer.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present `ArtifactResolve` signature over the SOAP body message using the expected SP's signing keys before acting on the request | Mandatory | Core §3.2.1, §5.4.1–§5.4.2 | Always |
| When a present signature on a `Version` `2.0` request with an `xs:NCName` `ID` does not verify, answer status `Requester` without the message and keep the artifact outstanding | Mandatory | Core §3.2.1, Profiles §5.3.2 | Always |
| Add the second-level status `RequestDenied` to that answer | Recommended | Bindings §3.6.6, Core §3.2.2.2 | Always |
| Answer an understood `ArtifactResolve` with status Success, and omit the message for an unauthorized presenter or an artifact that is not outstanding | Mandatory | Bindings §3.6.6, Core §3.5.3, Profiles §5.3.2 | Always |
| Answer an empty `Artifact` as an artifact that is not outstanding | Mandatory | `ArtifactResolveType`, Core §3.5.3, Bindings §3.6.6 | Always |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer request version with `VersionMismatch`. Add `RequestVersionTooHigh` for a newer major version and keep the artifact outstanding | Mandatory | Core §4.1.3.2 | Always |
| Return an error for an older request version that forbids a SAML 2.0 response | Mandatory | Core §4.1.3.2 | Always |
| Return the message only to the service provider it was issued to, authenticated by `SoapChannel` | Mandatory | Core §3.5.3, Bindings §3.6.5.2, Profiles §4.1.4.4 | Always |
| Treat a missing or different `Issuer`, or one with a format other than omitted or `entity`, as an unauthorized presenter | Library policy: the presenter check ties the request to the service provider the artifact was issued to. | Profiles §5.4.1, Bindings §3.6.6 | Always |
| Return the stored message at most once | Mandatory | Core §3.5.3, Bindings §3.6.5.2 | Always |
| Resolve artifacts across clustered nodes through a shared atomic store, or route each node's artifacts through a per-node `ArtifactResolutionService` `EndpointIndex` | Optional | Core §3.5.3, Bindings §3.6.4.2, §3.6.5.2, Profiles §5.5 | `ArtifactStore`, `IdpConfigBuilder::artifact_resolution_service` |
| Keep an outstanding artifact after withholding its message | Library policy: the intended recipient can still resolve it within its lifetime. | Core §3.5.3 | Always |
| Release an outstanding artifact whose `EndpointIndex` this identity provider no longer publishes | Library policy: the index tells the receiver where to send the request, and the presenter, the receiving URL, and the stored entry are checked without it. | Bindings §3.6.4.2, Core §3.5.3 | Always |
| Check the actual SOAP envelope before consuming the artifact | Library policy: keep the entry for retry if the response exceeds the [SOAP response size budget](#soap-response-size-budget). | Core §3.5.3, Bindings §3.2.2.1, E19 | Default `XmlLimits` |
| Answer status Success without the message when the artifact store cannot look up, time, or consume the entry | Mandatory | Bindings §3.6.6, §3.6.5.2, Core §3.5.3, Profiles §5.3.2 | Always |
| Withhold the message when a present `Destination`, after XML whitespace collapse, differs from the URL that received the request | Mandatory | Core §3.2.1, `RequestAbstractType`, XML Schema Part 2 §4.3.6 | `answer_artifact_resolve` `received_at` |
| Reject a receiving URL that this identity provider does not publish as a SOAP `ArtifactResolutionService` | Library policy: the URL is caller input, and the restriction keeps the handler from naming an endpoint this identity provider does not operate. | Core §3.2.1 | Always |
| Expire the artifact after the configured lifetime. The issuer should choose the shortest practical lifetime | Recommended | Core §3.5.3 | `ArtifactStore::lifetime`, `IssuedArtifacts::expire_after` |
| Include the artifact issuer's entity ID in `Issuer` and omit `Format` or set it to `entity` | Mandatory | Profiles §5.4.2 | Always |
| Set `InResponseTo` to the request `ID` | Mandatory | Core §3.2.2, §3.5.3 | Always |
| Authenticate the responder and protect integrity on every `ArtifactResponse`, including one that withholds the message or reports `VersionMismatch`. saml-rs does not sign it, so `SoapChannel` must attest both | Mandatory | Profiles §5.3.2, §5.4.2 | `SoapChannel` |
| Refuse the exchange before reading the request when `SoapChannel` does not attest mutual authentication and integrity | Library policy: `SoapChannel` cannot attest responder-only authentication, and the issuer needs the presenter authenticated before it releases a message. | Profiles §5.3.2, §5.4.1 | Always |

## Web Browser SSO response artifact

Profiles §4.1.4.4 governs a Web Browser SSO `<Response>` delivered by artifact. The issuer applies the same channel checks to every stored `samlp:Response`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Dereference over a mutually authenticated, integrity-protected, confidential channel | Mandatory | Profiles §4.1.4.4 | Always |
| Take the confidential release for every stored `<Response>` | Library policy: the issuer cannot tell from the element which profile produced it, and every `<Response>` can carry an assertion. | Profiles §4.1.4.4 | Always |

## Service provider acceptance

`ArtifactResolution::finish` processes the response on the service provider.

Both parties read `Issuer` as described in [entity identifiers](identifiers.md#entity-identifiers).
The requester reads the [status codes](web-browser-sso-acceptance.md#status-codes)
using XML Schema whitespace collapse.
Unsigned messages can use the required SOAP channel protection. A present XML
signature requires a crypto provider and uses the receiver's XML signature
profile. Web SSO applies its own checks to the dereferenced response.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a SOAP body that is not an `ArtifactResponse` | Mandatory | Core §3.5.2 | Always |
| Accept only response version `2.0` | Library policy: the reader implements only SAML 2.0, and Core §4.1.3.2 bars a higher response version for a 2.0 request. | Core §4.1.3.2 | Always |
| Require `ID` and a UTC `IssueInstant` | Library policy: [baseline receipt](xml-schema-validation.md#baseline-receipt) gives the reason. | `StatusResponseType`, Core §1.3.3 | Always |
| Require exactly one `Status` | Mandatory | `StatusResponseType` | Always |
| Require the unqualified response `InResponseTo`, after XML whitespace collapse, to equal the pending request ID | Library policy: a missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2, `StatusResponseType`, XML Schema Part 2 §4.3.6 | Always |
| Verify a present `ArtifactResponse` signature over the SOAP body message using the expected IdP's signing keys before reporting its status or returning its message | Mandatory | Core §3.2.2, §5.4.1–§5.4.2 | Always |
| Reject an `ArtifactResponse` with more than one message element | Mandatory | `ArtifactResponseType` | Always |
| Return a message only from a Success status that carries one | Library policy: Core §3.5.3 pairs a returned message with `Success`, so a message under another status has no defined meaning. | Profiles §5.3.2, Core §3.5.3 | Always |
| Reject a second direct `Issuer` | Mandatory | `StatusResponseType` | Always |
| Require an `Issuer` equal to the identity provider that omits `Format` or sets it to `entity` | Library policy: the requester attributes the responder by this `Issuer` together with `SoapChannel`, so without it `finish` would return a message not attributed to the artifact issuer. | Profiles §5.4.2 | Always |
| Require the message to be one element in the SAML protocol namespace | Library policy: `finish` returns the dereferenced protocol message, and another element would be presented as that message. | `ArtifactResponseType`, Profiles §5.3.2 | Always |
| Record the artifact when resolution starts. Refuse repeats during retention even if resolution fails. Choose retention longer than the issuer's acceptance period | Recommended | Bindings §3.6.5.2 | `ReplayPolicy::RequireCache`, `ReplayPolicy::NoCache`, `SamlValidationContext::with_replay_retention` |

## SOAP envelope rules

`SoapRequest`, `SoapResponse`, and `SoapBodyElement::from_envelope`
write and read envelopes for artifact resolution,
[Single Logout](single-logout.md#soap-binding), and
[name identifier management](name-id-management.md). SOAP 1.1 governs
`actor` and `mustUnderstand` in these flows.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept only the SOAP 1.1 envelope namespace | Mandatory | Bindings §3.2.2 | Always |
| Compare namespace names in a received envelope after normalizing the declaration value. Accept an explicit declaration of the `xml` prefix whose normalized value is the XML namespace | Mandatory | Namespaces in XML 1.0 §2.3, §3 | Always |
| Resolve names in received `ArtifactResponse`, `ManageNameIDResponse`, and SOAP `LogoutResponse` bodies against normalized namespace declarations, including declarations inherited from the envelope | Mandatory | [Namespaces in XML 1.0 §2.3](https://www.w3.org/TR/REC-xml-names/#NSNameComparison), §3, §6.1 | Always |
| Send one SAML request as the only element in the request `Body` | Mandatory | Bindings §3.2.2.1 | Always |
| Answer with a SOAP message whose `Body` holds a SAML response or a SOAP fault | Recommended | Bindings §3.2.2.1, E19 | `SoapResponse::try_new`, `SoapFault::new` |
| Put no second SAML response and no other element in the response `Body` | Mandatory | Bindings §3.2.2.1, E19 | Always |
| Reject a received `Body` with no element or with several elements | Library policy: SOAP 1.1 §4.3 sets no count and WS-I R9981 allows at most one, and a `Body` without one element does not identify the message to process. | Bindings §3.2.2.1, SOAP 1.1 §4.3, WS-I BP 1.1 R9981 | Always |
| Emit requests and responses without a `DOCTYPE` or processing instructions | Mandatory | [SOAP 1.1 §3](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383492) | Always |
| Refuse a received envelope with a `DOCTYPE` | Library policy: a DTD can declare entities that expand the input, and SOAP 1.1 §3 already forbids one in every SOAP message. | SOAP 1.1 §3, WS-I BP 1.1 R1008 | Always |
| Accept a received envelope with processing instructions, other than the `xml-stylesheet` ones the XML reader refuses, and act on none | Library policy: SOAP 1.1 §3 forbids them in a message but gives the receiver no rule, and ignoring them changes no SAML processing. | SOAP 1.1 §3 | Always |
| Treat only attributes in the SOAP 1.1 envelope namespace as `actor` and `mustUnderstand` | Mandatory | SOAP 1.1 §4.2.2, §4.2.3 | Always |
| Process only header entries addressed to this endpoint: no `actor`, or `http://schemas.xmlsoap.org/soap/actor/next`. Ignore entries for other actors | Mandatory | SOAP 1.1 §4.2.2 | Always |
| Refuse a local header entry with `mustUnderstand="1"` that the endpoint does not process | Mandatory | SOAP 1.1 §4.2.3 | Always |
| Require no header to process the SAML message | Mandatory | Bindings §3.2.2.2 | Always |
| Treat an empty `actor` as local | Library policy: an empty value identifies no other actor, so the receiver keeps responsibility for mandatory headers. | SOAP 1.1 §4.2.2 | Always |
| Treat a local `mustUnderstand="true"` as mandatory | Library policy: SOAP 1.1 specifies `0` and `1`, and skipping `true` would silently ignore processing the sender asked for. | SOAP 1.1 §4.2.3 | Always |
| Reject a second `Header` or a `Header` that does not immediately precede `Body` | Library policy: SOAP 1.1 §4 allows one `Header`, first in the `Envelope`, so another layout is not a SOAP envelope, and the receiver cannot tell which header entries it must process. | SOAP 1.1 §4, §4.3, WS-I BP 1.1 R9980 | Always |
| Reject an element after the `Body` | Library policy: SOAP 1.1 permits these trailers, and WS-I Basic Profile 1.1 forbids them, so rejection keeps the crate interoperable. | SOAP 1.1 §4, WS-I BP 1.1 R1011 | Always |
| Send `http://www.oasis-open.org/committees/security` as the `SOAPAction` value, bare, as Bindings §3.2.3 and its examples write it | Optional | [Bindings §3.2.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=11), §3.2.3.5, §3.6.8 | `SoapRequest::headers` |
| Process the request independently of the `SOAPAction` value | Mandatory | Bindings §3.2.3 | Always |
| Return a SAML-domain error as a status in a SAML response, not as a SOAP fault | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | Always |
| Report a received `Envelope` outside the SOAP 1.1 namespace as `SamlError::SoapEnvelope` with the `VersionMismatch` fault code | Mandatory | SOAP 1.1 §4.1.2, §4.4.1 | Always |
| Report a refused local header entry with the `MustUnderstand` fault code | Mandatory | SOAP 1.1 §4.2.3, §4.4.1 | Always |
| Report every other envelope failure, including an XML limit, with the `Client` fault code | Library policy: SOAP 1.1 §4.4.1 gives `Client` to a message that must change before a resend, and no code fits a limit better. | SOAP 1.1 §4.4.1 | Always |
| Write an empty `detail` in a `Client` or `Server` fault, and none in a `VersionMismatch` or `MustUnderstand` fault | Library policy: SOAP 1.1 requires `detail` when the `Body` was not processed, and an empty one carries no header information when the failure was elsewhere in the envelope. | SOAP 1.1 §4.4 | `SoapFault::new` |
| Write a SOAP fault for a SOAP processing failure. The deployment sends it with HTTP 500 | Mandatory | Bindings §3.2.3.3, SOAP 1.1 §6.2 | `SoapFault::new` |
| Refuse an exchange over a channel without the required protection with `SamlError::SoapChannelProtection`. The deployment answers HTTP 403 | Recommended | Bindings §3.2.3.3 | Always |
| Send SOAP entity bodies with the `text/xml` media type | Mandatory | SOAP 1.1 §6 | `SoapRequest::headers`, `SoapResponse::headers` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` with a request | Recommended | Bindings §3.2.3.2 | `SoapRequest::headers` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` with a response | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers` |
| Send no validator, such as `Last-Modified` or `ETag`, with a response. The deployment adds none | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers`, `SoapFault::headers` |
| Process the SAML message without any HTTP request header. The receive APIs take none | Mandatory | Bindings §3.2.3.1 | Always |
| Let the deployment add HTTP headers to a request beyond those in `SoapRequest::headers` | Optional | Bindings §3.2.3.1 | `SoapRequest::headers` |

## SOAP envelope helpers

`SoapRequest::try_new` and `SoapResponse::try_new` wrap one XML element in a
SOAP 1.1 body. `SoapFault::new` writes a SOAP 1.1 fault. `SoapBodyElement::from_envelope` checks the envelope structure
and reads its body element. Typed SAML operations validate the payload for
their protocol flow.

## Outside this flow

- Browser delivery of an artifact: [HTTP-Artifact response](web-browser-sso-artifact.md).
- `AuthnRequest` over HTTP-Artifact. Optional, Bindings §3.6.
- Signing outbound `ArtifactResponse`. Optional, Profiles §5.3.2.
- Adding SOAP header entries, such as WS-Security, to an outgoing message. Optional, Bindings §3.2.2.2. Received header entries follow the [SOAP envelope rules](#soap-envelope-rules).
- The assertion query/request profile over SOAP. Requirements vary by query and operational mode. Profiles §6, Conformance §3.2 Table 4.
- The IdP operational mode and the SP operational mode: [IdP and SP operational modes](idp-sp-operational-modes.md).
