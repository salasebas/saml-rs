# Artifact resolution over SOAP

`IdentityProvider::issue_artifact` stores a SAML protocol message and returns
its artifact, and `IdentityProvider::answer_artifact_resolve` answers the
`ArtifactResolve` that presents it. `ServiceProvider::resolve_artifact` and
`resolve_artifact_with_signed_request` prepare that request, and
`ArtifactResolution::finish` reads the message from the SOAP
`ArtifactResponse`. `SoapRequest`, `SoapResponse`, `SoapFault`, and
`SoapBodyElement::from_envelope` write and read the SOAP 1.1 envelopes of
this exchange, of [Single Logout](single-logout.md#soap-binding), and of
[name identifier management](name-id-management.md).

Normative text is Core §3.5, Bindings §3.2 and §3.6, Profiles §5 and
§4.1.4.4, and Metadata §2.4.2, as corrected by
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/),
with [SOAP 1.1](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/) and
[WS-I Basic Profile 1.1](https://ws-i.org/Profiles/BasicProfile-1.1.html)
for the SOAP envelope. Browser delivery of a Web SSO artifact, and the
acceptance of the resolved `Response`, are in
[HTTP-Artifact response](web-browser-sso-artifact.md). Both roles read
`Issuer` as [entity identifiers](identifiers.md#entity-identifiers) describes,
and verify a present signature under their own `XmlSignatureProfile` and the
[SOAP body signature policy](xml-security-algorithms.md#soap-body-signatures).
`Consent`, `Extensions`, and `StatusDetail` are in
[common message fields](common-message-fields.md).

The statuses hold on builds with a crypto provider. A build without one
neither signs nor verifies: `resolve_artifact_with_signed_request` returns
`SamlError::Unsupported`, `ArtifactResolution::finish` returns it for a
response that carries a signature, and `answer_artifact_resolve` answers a
signed request with `Responder`, or with an error when the request declares a
later major version. Unsigned exchanges over an attested `SoapChannel`
complete.

## Support

### Artifact exchange

A status covers the role's part in the feature: the identity provider issues
and answers, and the service provider resolves.

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `ArtifactResolve` from the service provider and `ArtifactResponse` from the identity provider, over SOAP | Profiles §5.3, Core §3.5.1, §3.5.2, Bindings §3.2 | Supported | Supported |
| `ArtifactResolve` from the identity provider for an artifact that the service provider issued | Profiles §5.3, Core §3.5 | Not supported | Not supported |
| Type `0x0004` artifact | Bindings §3.6.4.2, E4 | Supported | Supported |
| `EndpointIndex` that selects an indexed `ArtifactResolutionService` | Bindings §3.6.4.2, Profiles §5.5, E2 | Supported | Supported |
| A SAML protocol request or response as the resolved message | Core §3.5, §3.5.2 | Supported | Supported |
| Signed `ArtifactResolve` | Core §3.5.1, Profiles §5.3.1, §5.4.1 | Supported | Supported |
| Unsigned `ArtifactResolve` over a channel that authenticates the requester and protects integrity | Profiles §5.3.1, §5.4.1 | Supported | Supported |
| Signed `ArtifactResponse` | Core §3.5.2, Profiles §5.3.2, §5.4.2 | Not supported | Supported |
| Unsigned `ArtifactResponse` over a channel that authenticates the responder and protects integrity | Profiles §5.3.2, §5.4.2 | Supported | Supported |
| A signature as the only authentication of a party, over a channel without mutual authentication | Profiles §5.3.1, §5.3.2 | Not supported | Not supported |
| Confidential dereference of a Web Browser SSO `<Response>` | Profiles §4.1.4.4 | Supported | Supported |
| `Success` without the message, for an artifact that is not released | Core §3.5.3, Bindings §3.6.6 | Supported | Supported |
| `Requester` with `RequestDenied` for a request whose signature does not verify, and `VersionMismatch` for a newer request version | Bindings §3.6.6, Core §4.1.3 | Supported | Supported |
| `Requester` for a malformed request, and `Responder` for a request signature that the identity provider cannot verify | Core §3.2.1, §3.2.2.2, Profiles §5.3.2 | Supported | Supported |
| Release to any presenter, for a message that any party may consume | Core §3.5.3 | Not supported | — |
| Single use enforced by the artifact issuer | Core §3.5.3, Bindings §3.6.5.2 | Supported | — |
| Single use enforced by the artifact receiver | Bindings §3.6.5.2 | — | Supported |
| Time limit on the use of an artifact | Core §3.5.3 | Supported | — |

Both roles require `SoapChannel` to attest mutual authentication and
integrity protection, and the service provider also confidentiality for every
artifact, as the [library policies](#library-policies) record.

### SOAP binding

These statuses cover the SOAP layer of every supported SOAP exchange. The
requester sends a SAML request and reads the response, and the responder
reads the request and answers it.

| Feature | Section | Requester | Responder |
| --- | --- | --- | --- |
| SOAP 1.1 envelope with one SAML message as the only `Body` element | Bindings §3.2.2, §3.2.2.1, E19 | Supported | Supported |
| SOAP over HTTP, with the `text/xml` media type and the cache headers | Bindings §3.2.3, §3.2.3.2, SOAP 1.1 §6 | Supported | Supported |
| `SOAPAction` with the OASIS URI | Bindings §3.2.3 | Supported | Supported |
| A SAML status for a SAML-domain error, a SOAP fault for a SOAP processing failure, and HTTP 403 for a refused exchange | Bindings §3.2.2.1, §3.2.3.3, E19 | — | Supported |
| The fault code of a received SOAP fault | SOAP 1.1 §4.4 | Not supported | — |
| Header entries in a sent message | Bindings §3.2.2.2, SOAP 1.1 §4.2 | Not supported | Not supported |
| Header entries in a received message, by `actor` and `mustUnderstand` | Bindings §3.2.2.2, SOAP 1.1 §4.2 | Supported | Supported |

## Rules

<a id="issuing-an-artifact"></a>

### Identity provider: `issue_artifact`, `IdpConfigBuilder::artifact_resolution_service`

Code: `src/artifact.rs`, `src/entity.rs`, `src/config/builders.rs`, `src/metadata/generate.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish an indexed `ArtifactResolutionService` in this identity provider's metadata | Recommended | Bindings §3.6.7, E2, Metadata §2.4.2, Profiles §5.5 | `IdpConfigBuilder::artifact_resolution_service` |
| Build the artifact as the padded base64 of the type code `0x0004`, a two-byte `EndpointIndex`, a 20-byte `SourceID`, and a 20-byte `MessageHandle` | Mandatory | Bindings §3.6.4, §3.6.4.2, E4 | Always |
| Set `SourceID` to the SHA-1 of the issuer's entity ID, not encoded in hexadecimal | Recommended | Bindings §3.6.4 | Always |
| Make a valid outstanding `MessageHandle` infeasible to construct or guess | Mandatory | Bindings §3.6.4.2 | Always |
| Take the `MessageHandle` from a cryptographically strong random sequence | Recommended | Bindings §3.6.4 | Always |
| Associate a message intended for a specific service provider with that service provider | Mandatory | Core §3.5.3, Profiles §4.1.4.4 | Always |

<a id="artifactresolve"></a>

### Service provider: `resolve_artifact`, `resolve_artifact_with_signed_request`

Code: `src/artifact.rs`, `src/metadata/idp.rs`, `src/entity.rs`, `src/binding/signed_message.rs`, `src/model/validation.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Prepare `ArtifactResolve` for SOAP, a synchronous binding, addressed directly to the artifact issuer's endpoint that the `EndpointIndex` names | Mandatory | Profiles §5.3.1, §5.5, Bindings §3.6.4.2, E31 | Always |
| Write `Issuer` with the service provider's entity ID, without `Format` or with the `entity` format. The crate omits `Format` | Mandatory | Profiles §5.4.1 | Always |
| Write `ID`, `Version` `2.0`, and a UTC `IssueInstant`, and never a time with a leap second | Mandatory | `RequestAbstractType`, Core §3.2.1, §1.3.3 | Always |
| Set `Destination` to the endpoint location | Optional | Core §3.2.1 | Always |
| Send exactly one `samlp:Artifact` that holds the received artifact | Mandatory | `ArtifactResolveType` | Always |
| Authenticate to the responder and protect integrity | Recommended | Profiles §5.3.1, §5.4.1 | Always |
| Dereference a Web Browser SSO `<Response>` only over an exchange that is mutually authenticated, integrity-protected, and confidential | Mandatory | Profiles §4.1.4.4 | `SoapChannel` |
| Sign the `ArtifactResolve` with the service provider's signing credential | Optional | Core §3.5.1, Profiles §5.3.1, §5.4.1 | `resolve_artifact_with_signed_request` |
| When signing, place the enveloped signature after `Issuer` and reference the `ArtifactResolve` `ID` | Mandatory | `RequestAbstractType`, `ArtifactResolveType`, Core §5.4.1, §5.4.2 | `resolve_artifact_with_signed_request` |
| Record the artifact in the replay cache when the request is prepared, and refuse it again during the retention, also after a resolution that failed | Recommended | Bindings §3.6.5.2 | `ReplayPolicy::RequireCache`, `ReplayPolicy::NoCache`, `SamlValidationContext::with_replay_retention` |

<a id="artifactresponse"></a>
<a id="web-browser-sso-response-artifact"></a>

### Identity provider: `answer_artifact_resolve`

Code: `src/artifact.rs`, `src/artifact/store.rs`, `src/soap.rs`, `src/crypto/verify.rs`, `src/model/status.rs`, `src/xml/name.rs`, `src/xml/protocol_element.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a `2.0` request without `samlp:Artifact`, with a second direct child named `Artifact` in any namespace, or with a second `Issuer` with status `Requester`, without the message | Mandatory | `RequestAbstractType`, `ArtifactResolveType`, Core §3.2.1, Profiles §5.3.2 | Always |
| Answer a request without `Version`, or whose `Version` is not a `major.minor` number, and a `2.0` request without `ID` or a UTC `IssueInstant`, with status `Requester`, without the message | Mandatory | `RequestAbstractType`, Core §3.2.1, §4.1.3, Profiles §5.3.2 | Always |
| Verify a present `ArtifactResolve` signature over the SOAP body message with the expected service provider's signing keys before acting on the request | Mandatory | Core §3.2.1, §5.4.1–§5.4.2 | Always |
| When a present signature does not verify, answer a request of major version 2, or without a `major.minor` `Version`, with status `Requester`, without the message, and keep the artifact outstanding | Mandatory | Core §3.2.1, Profiles §5.3.2 | Always |
| Add the second-level status `RequestDenied` to that answer | Recommended | Bindings §3.6.6, Core §3.2.2.2 | Always |
| When this build cannot verify a present signature, because it has no crypto provider or the provider fails to start, answer a request of major version 2, or without a `major.minor` `Version`, with status `Responder`, without the message, and keep the artifact outstanding | Mandatory | Core §3.2.2.2, Profiles §5.3.2 | Always |
| Answer a request that declares a later major version with neither `Requester` nor `Responder`, also when its signature does not verify or cannot be verified | Mandatory | Core §4.1.3.2 | Always |
| Reject an unsupported major request version | Mandatory | Core §4.1.3.1 | Always |
| Reject a higher minor request version | Optional | Core §4.1.3.1 | Always |
| Answer a newer request version with `VersionMismatch` once its signature, when present, verifies. Add `RequestVersionTooHigh` for a newer major version and keep the artifact outstanding | Mandatory | Core §4.1.3.2 | Always |
| Return an error for an older request version that forbids a SAML 2.0 response, also when its signature does not verify or the request is malformed | Mandatory | Core §4.1.3.2 | Always |
| Answer an understood `ArtifactResolve` with status `Success`, and omit the message for an unauthorized presenter or an artifact that is not outstanding | Mandatory | Bindings §3.6.6, Core §3.5.3, Profiles §5.3.2 | Always |
| Answer an empty `Artifact` as an artifact that is not outstanding | Mandatory | `ArtifactResolveType`, Core §3.5.3, Bindings §3.6.6 | Always |
| Answer status `Success` without the message when the artifact store cannot look up, time, or consume the entry | Mandatory | Bindings §3.6.6, §3.6.5.2, Core §3.5.3, Profiles §5.3.2 | Always |
| Return the message only to the service provider it was issued to, authenticated by `SoapChannel` | Mandatory | Core §3.5.3, Bindings §3.6.5.2, Profiles §4.1.4.4 | Always |
| Release a Web Browser SSO `<Response>` only over an exchange that is mutually authenticated, integrity-protected, and confidential | Mandatory | Profiles §4.1.4.4 | `SoapChannel` |
| Return the stored message at most once | Mandatory | Core §3.5.3, Bindings §3.6.5.2 | Always |
| Withhold the message when a present `Destination`, after XML whitespace collapse, differs from the URL that received the request | Mandatory | Core §3.2.1, `RequestAbstractType`, XML Schema Part 2 §4.3.6 | `answer_artifact_resolve` `received_at` |
| Treat an artifact as not outstanding from the end of the `ArtifactStore::lifetime` that applied when it was issued | Recommended | Core §3.5.3 | `ArtifactStore::lifetime`, `IssuedArtifacts::expire_after` |
| Write `Issuer` with the identity provider's entity ID, without `Format` or with the `entity` format. The crate omits `Format` | Mandatory | Profiles §5.4.2 | Always |
| Set `InResponseTo` to the request `ID`, and write it only as an `xs:NCName` | Mandatory | Core §3.2.2, §3.5.3, `StatusResponseType` | Always |
| Omit `InResponseTo` from the answer to a request whose `ID` is missing or not an `xs:NCName` | Mandatory | Core §3.2.2 | Always |
| Authenticate the responder and protect integrity on every `ArtifactResponse`, including one that withholds the message or reports `VersionMismatch`. saml-rs does not sign it, so `SoapChannel` must attest both | Mandatory | Profiles §5.3.2, §5.4.2 | `SoapChannel` |

### Service provider: `ArtifactResolution::finish`

Code: `src/artifact.rs`, `src/soap.rs`, `src/crypto/verify.rs`, `src/xml/protocol_element.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present `ArtifactResponse` signature over the SOAP body message with the expected identity provider's signing keys before reporting its status or returning its message | Mandatory | Core §3.2.2, §5.4.1–§5.4.2 | Always |
| Reject a second direct `Issuer` | Mandatory | `StatusResponseType` | Always |
| Reject an `ArtifactResponse` with more than one message element | Mandatory | `ArtifactResponseType` | Always |

`finish` reads `Status` by the shared
[status code rules](web-browser-sso-acceptance.md#status-codes), which require
one `Status` and collapse XML whitespace in each `StatusCode` value.
[HTTP-Artifact response](web-browser-sso-artifact.md#service-provider-receipt)
keeps the checks that Web SSO applies to the resolved `Response`.

<a id="soap-envelope-rules"></a>
<a id="soap-envelope-helpers"></a>

### SOAP sender: `SoapRequest`, `SoapResponse`, `SoapFault`

Code: `src/soap.rs`, `src/http_header.rs`

These rows and the [SOAP envelope policies](#soap-envelope-policies) apply to
every supported SOAP exchange. `SoapRequest::try_new` and
`SoapResponse::try_new` wrap one XML element of any name, and the typed SOAP
operations pass them their SAML message.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Put exactly one SAML request or response in the SOAP `Body`, with no other element | Mandatory | Bindings §3.2.2.1, E19 | Always |
| Answer with a SOAP message whose `Body` holds a SAML response or a SOAP fault | Recommended | Bindings §3.2.2.1, E19 | `SoapResponse::try_new`, `SoapFault::new` |
| Write no `DOCTYPE` and no processing instructions | Mandatory | [SOAP 1.1 §3](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383492) | Always |
| Write a SOAP fault for a SOAP processing failure | Mandatory | Bindings §3.2.3.3, SOAP 1.1 §6.2 | `SoapFault::new` |
| Send `http://www.oasis-open.org/committees/security` as the `SOAPAction` value, bare, as Bindings §3.2.3 and its examples write it | Optional | [Bindings §3.2.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf#page=11), §3.2.3.5, §3.6.8 | `SoapRequest::headers` |
| Send SOAP entity bodies with the `text/xml` media type | Mandatory | SOAP 1.1 §6 | `SoapRequest::headers`, `SoapResponse::headers`, `SoapFault::headers` |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` with a request | Recommended | Bindings §3.2.3.2 | `SoapRequest::headers` |
| Send `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` with a response | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers`, `SoapFault::headers` |
| Return no validator, such as `Last-Modified` or `ETag`, in the response headers | Recommended | Bindings §3.2.3.2 | `SoapResponse::headers`, `SoapFault::headers` |

### SOAP receiver: SOAP receive operations

Code: `src/soap.rs`, `src/xml/dom.rs`, `src/xml/dom/element.rs`, `src/xml/fragment.rs`

These rows cover `SoapBodyElement::from_envelope` and every typed operation
that reads a SOAP request or response.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept only the SOAP 1.1 envelope namespace | Mandatory | Bindings §3.2.2, SOAP 1.1 §4.1.2 | Always |
| Compare namespace names in a received envelope after normalizing the declaration value. Accept an explicit declaration of the `xml` prefix whose normalized value is the XML namespace | Mandatory | Namespaces in XML 1.0 §2.3, §3 | Always |
| Resolve names in received `ArtifactResponse`, `ManageNameIDResponse`, and SOAP `LogoutResponse` bodies against normalized namespace declarations, including declarations inherited from the envelope | Mandatory | [Namespaces in XML 1.0 §2.3](https://www.w3.org/TR/REC-xml-names/#NSNameComparison), §3, §6.1 | Always |
| Treat only attributes in the SOAP 1.1 envelope namespace as `actor` and `mustUnderstand` | Mandatory | SOAP 1.1 §4.2.2, §4.2.3 | Always |
| Process only header entries addressed to this endpoint: no `actor`, or `http://schemas.xmlsoap.org/soap/actor/next`. Ignore entries for other actors | Mandatory | SOAP 1.1 §2, §4.2.2 | Always |
| Refuse a local header entry with `mustUnderstand="1"` that the endpoint does not process | Mandatory | SOAP 1.1 §2, §4.2.3 | Always |
| Report a received `Envelope` outside the SOAP 1.1 namespace with the `VersionMismatch` fault code | Mandatory | SOAP 1.1 §4.1.2, §4.4.1 | Always |
| Report a refused local header entry with the `MustUnderstand` fault code | Mandatory | SOAP 1.1 §4.2.3, §4.4.1 | Always |

### SOAP responder: SOAP request receive operations

Code: `src/soap.rs`, `src/artifact.rs`, `src/browser/input.rs`, `src/name_id_management.rs`

These rows cover `answer_artifact_resolve`, `receive_slo` with
`Inbound::soap`, and `receive_name_id_management`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require no header entry to process the SAML message | Mandatory | Bindings §3.2.2.2 | Always |
| Process the request independently of the `SOAPAction` value | Mandatory | Bindings §3.2.3 | Always |
| Process the SAML message without any HTTP request header. The receive operations take none | Mandatory | Bindings §3.2.3.1 | Always |
| Return a SAML-domain error as a status in a SAML response, not as a SOAP fault | Recommended | Bindings §3.2.2.1, §3.2.3.3, E19 | Always |

### SOAP requester: `ArtifactResolution::finish`, `StartedNameIdManagement::finish`, `finish_slo`

Code: `src/artifact.rs`, `src/name_id_management.rs`, `src/api/slo.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Send the responder nothing after reading its SAML response: `finish` returns its result to the caller | Mandatory | Bindings §3.2.2.1 | Always |

## Library policies

<a id="soap-response-size-budget"></a>

### Identity provider: `issue_artifact`

Code: `src/artifact.rs`, `src/soap.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Issue only for a SOAP `ArtifactResolutionService` at the given `EndpointIndex` | SOAP is the only synchronous binding the crate implements, so an artifact for another endpoint could not be resolved. | Bindings §3.2, Profiles §5.3.1 | Always |
| Associate every stored message with the service provider passed to `issue_artifact`, including one that any party may consume | The issuer cannot tell from the element whether any party may consume it, and one presenter per artifact never releases a recipient-specific message to another. | Core §3.5.3 | Always |
| Store only one element in the SAML protocol namespace | `ArtifactResolution::finish` rejects any other payload, so another element could never be resolved. | Core §3.5.2, `ArtifactResponseType` | Always |
| Refuse an element with processing instructions before issuing an artifact | The SOAP response that releases the element [must carry no processing instructions](#soap-envelope-rules), and refusing at issuance keeps the artifact from becoming unresolvable. | SOAP 1.1 §3 | Always |
| Before storing the message, check that the SOAP `ArtifactResponse` that releases it, with room for the longest request `ID` it can echo, fits the default `XmlLimits`, 1 MiB for the envelope. `XmlPolicy::limits` sets only inbound parsing | The check bounds XML processing and keeps the identity provider from issuing an artifact that it could not release. | Core §3.5.3, Bindings §3.2.2.1, E19 | Always |

The fixed budget refuses a large schema-valid message that a peer with a
higher receive limit would accept.
[OpenSAML 5.2.3](https://build.shibboleth.net/maven/releases/org/opensaml/opensaml-saml-impl/5.2.3/)
stores the outgoing message in `HTTPArtifactEncoder` and attaches it to the
SOAP response in `ResolveArtifact`.

### Service provider: `resolve_artifact`, `resolve_artifact_with_signed_request`

Code: `src/artifact.rs`, `src/metadata/idp.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Resolve only an artifact whose `SourceID` is the SHA-1 of the selected identity provider's entity ID | SAML V2.0 metadata publishes no other `SourceID`, so another value names an issuer that the selected descriptor cannot be shown to be. | Bindings §3.6.4, §3.6.4.2 | Always |
| Look up the `EndpointIndex` within each SAML 2.0 `IDPSSODescriptor`, and refuse an index that more than one of them publishes | Metadata §2.2.3 makes an index unique only within its parent role, so an index that two roles publish names no single endpoint. | Metadata §2.2.3, Bindings §3.6.4.2 | Always |
| Require `SoapChannel` to attest mutual authentication, integrity protection, and confidentiality for every artifact, not only for a `<Response>`, whether or not the request is signed | The artifact does not say which message it refers to, so the requester learns that only after the message has crossed the channel, and a Web SSO `<Response>` requires confidentiality. | Profiles §5.3.1, §5.4.1, §4.1.4.4 | Always |

### Identity provider: `answer_artifact_resolve`

Code: `src/artifact.rs`, `src/artifact/store.rs`, `src/model/status.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Refuse the exchange before reading the request when `SoapChannel` does not attest mutual authentication and integrity | `SoapChannel` cannot attest responder-only authentication, and the issuer needs the presenter authenticated before it releases a message. | Profiles §5.3.2, §5.4.1 | Always |
| Reject a receiving URL that this identity provider does not publish as a SOAP `ArtifactResolutionService` | The URL is caller input, and the restriction keeps the handler from naming an endpoint this identity provider does not operate. | Core §3.2.1 | Always |
| Treat a missing or different `Issuer`, or one with a `Format` other than omitted or `entity`, as an unauthorized presenter | The presenter check ties the request to the service provider the artifact was issued to. | Profiles §5.4.1, Bindings §3.6.6 | Always |
| Require `SoapChannel` to attest confidentiality, too, before releasing any stored `<Response>`, whatever profile stored it | The issuer cannot tell from the element which profile produced it, and every `<Response>` can carry an assertion. | Profiles §4.1.4.4 | Always |
| Keep an outstanding artifact after withholding its message | The intended recipient can still resolve it within its lifetime. | Core §3.5.3 | Always |
| Release an outstanding artifact whose `EndpointIndex` this identity provider no longer publishes | The index tells the receiver where to send the request, and the presenter, the receiving URL, and the stored entry are checked without it. | Bindings §3.6.4.2, Core §3.5.3 | Always |
| Check the actual SOAP envelope against the default `XmlLimits` before consuming the artifact | The entry stays outstanding for a retry when the response exceeds the [SOAP response size budget](#soap-response-size-budget). | Core §3.5.3, Bindings §3.2.2.1, E19 | Always |
| Answer a request whose `ID` is not an `xs:NCName` as a malformed request, with status `Requester` and without the message, and keep the artifact outstanding | An answer that releases the message must carry the request `ID` as its `InResponseTo`, which `StatusResponseType` types as `xs:NCName`, so the message cannot be released for such a request. | Core §3.2.1, §3.2.2, §3.5.3 | Always |
| Return the signature error, and no answer, for a request of a later major version whose present signature does not verify or cannot be verified, and keep the artifact outstanding | A `Requester` or `Responder` answer would break Core §4.1.3.2 if that version is genuine, and a `VersionMismatch` answer would rely on the `Version` of a request whose signature failed, which Core §3.2.1 forbids. | Core §3.2.1, §4.1.3.2, Profiles §5.3.2 | Always |
| Keep issued artifacts in the caller's `ArtifactStore`, whose `consume` succeeds for at most one concurrent caller. Nodes share one store, or each node publishes its own `ArtifactResolutionService` index | Any node behind one endpoint can then answer for an artifact that another node issued, and the message is still released once. | Core §3.5.3, Bindings §3.6.4.2, §3.6.5.2, Profiles §5.5 | `ArtifactStore`, `IdpConfigBuilder::artifact_resolution_service` |

[Shibboleth IdP 5.2.3](https://codeberg.org/Shibboleth/java-identity-provider/src/tag/5.2.3/idp-conf-impl/src/main/resources/net/shibboleth/idp/flows/saml/saml-abstract-flow.xml#L17-L53)
checks the major version before the subflow that verifies the signature, and
answers every early failure with a
[`Success` `ArtifactResponse`](https://codeberg.org/Shibboleth/java-identity-provider/src/tag/5.2.3/idp-conf-impl/src/main/resources/net/shibboleth/idp/flows/saml/saml2/artifact-resolution-flow.xml#L49-L65).
[SimpleSAMLphp 2.5.5](https://github.com/simplesamlphp/saml2-legacy/blob/v4.20.10/src/SAML2/Message.php#L159-L162)
throws on any `Version` other than `2.0` while it reads the request, before
it reads a signature, and sends no `ArtifactResponse`.

<a id="service-provider-acceptance"></a>

### Service provider: `ArtifactResolution::finish`

Code: `src/artifact.rs`, `src/soap.rs`, `src/model/status.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a SOAP body that is not an `ArtifactResponse`, a SOAP fault included | `finish` reads the protocol message from an `ArtifactResponse`, and no other body answers the pending `ArtifactResolve`. | Core §3.5.2 | Always |
| Accept only response version `2.0` | The reader implements only SAML 2.0, and Core §4.1.3.2 bars a higher response version for a 2.0 request. | Core §4.1.3.2 | Always |
| Require `ID` and a UTC `IssueInstant` | [Baseline receipt](xml-schema-validation.md#baseline-receipt) gives the reason. | `StatusResponseType`, Core §1.3.3 | Always |
| Require the unqualified response `InResponseTo`, after XML whitespace collapse, to equal the pending request `ID` | A missing or different value cannot identify this response as the answer to the pending request. | Core §3.2.1, §3.2.2, `StatusResponseType`, XML Schema Part 2 §4.3.6 | Always |
| Require an `Issuer` equal to the identity provider, without `Format` or with the `entity` format | The requester attributes the responder by this `Issuer` together with `SoapChannel`, so without it `finish` would return a message not attributed to the artifact issuer. | Profiles §5.4.2 | Always |
| Return a message only from a `Success` status that carries one | Core §3.5.3 pairs a returned message with `Success`, so a message under another status has no defined meaning. | Profiles §5.3.2, Core §3.5.3 | Always |
| Require the message to be one element in the SAML protocol namespace | `finish` returns the dereferenced protocol message, and another element would be presented as that message. | `ArtifactResponseType`, Profiles §5.3.2 | Always |
| Accept a present `Destination` without comparing it | The reply arrives on the HTTP exchange that the requester opened, not at a location of its own, and `InResponseTo` and `SoapChannel` tie it to the request. | Core §3.2.2, Bindings §3.2 | Always |

Core §3.2.2 has the actual recipient check that a present `Destination`
identifies the location at which the message was received. A SOAP reply is the
HTTP response to the requester's own POST, and Bindings names that location
only for HTTP-Redirect (§3.4.5.2) and HTTP-POST (§3.5.5.2), so this record and
[name identifier management](name-id-management.md#soap-managenameidresponse-from-the-service-provider)
read a SOAP reply as received at no location.
[OpenSAML C++ 3.3.1](https://codeberg.org/Shibboleth/cpp-opensaml/src/tag/3.3.1/saml/saml2/binding/impl/SAML2SOAPClient.cpp#L70-L118)
and [PySAML2 v7.5.5](https://github.com/IdentityPython/pysaml2/blob/v7.5.5/src/saml2/response.py#L414-L419),
which [skips that check for SOAP](https://github.com/IdentityPython/pysaml2/blob/v7.5.5/src/saml2/entity.py#L1412-L1416),
do not compare it on an `ArtifactResponse` or a `ManageNameIDResponse`, and
[simplesamlphp/saml2 v6.0.0](https://github.com/simplesamlphp/saml2/blob/v6.0.0/src/Binding/HTTPArtifact.php#L130-L209)
and [crewjam/saml v0.6.3](https://github.com/crewjam/saml/blob/v0.6.3/service_provider.go#L1487-L1519)
do not on an `ArtifactResponse`.

<a id="soap-envelope-policies"></a>

### SOAP sender: `SoapFault::new`

Code: `src/soap.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write an empty `detail` in a `Client` or `Server` fault, and none in a `VersionMismatch` or `MustUnderstand` fault | SOAP 1.1 requires `detail` when the `Body` was not processed, and an empty one carries no header information when the failure was elsewhere in the envelope. | SOAP 1.1 §4.4 | `SoapFault::new` |

<a id="soap-receiver-policies"></a>

### SOAP receiver: SOAP receive operations

Code: `src/soap.rs`, `src/xml/dom.rs`, `src/xml/schema_value.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a received `Body` with no element or with several elements | SOAP 1.1 §4.3 sets no count and WS-I R9981 allows at most one, and a `Body` without one element does not identify the message to process. | Bindings §3.2.2.1, SOAP 1.1 §4.3, WS-I BP 1.1 R9981 | Always |
| Refuse a received envelope with a `DOCTYPE` | A DTD can declare entities that expand the input, and SOAP 1.1 §3 already forbids one in every SOAP message. | SOAP 1.1 §3, WS-I BP 1.1 R1008 | Always |
| Accept a received envelope with processing instructions, other than the `xml-stylesheet` ones the XML reader refuses, and act on none | SOAP 1.1 §3 forbids them in a message but gives the receiver no rule, and ignoring them changes no SAML processing. | SOAP 1.1 §3 | Always |
| Reject a second `Header` or a `Header` that does not immediately precede `Body` | SOAP 1.1 §4 allows one `Header`, first in the `Envelope`, so another layout is not a SOAP envelope, and the receiver cannot tell which header entries it must process. | SOAP 1.1 §4, §4.3, WS-I BP 1.1 R9980 | Always |
| Reject an element after the `Body` | SOAP 1.1 permits these trailers, and WS-I Basic Profile 1.1 forbids them, so rejection keeps the crate interoperable. | SOAP 1.1 §4, WS-I BP 1.1 R1011 | Always |
| Treat an empty `actor` as local | An empty value identifies no other actor, so the receiver keeps responsibility for mandatory headers. | SOAP 1.1 §4.2.2 | Always |
| Treat a local `mustUnderstand="true"` as mandatory | SOAP 1.1 specifies `0` and `1`, and skipping `true` would silently ignore processing the sender asked for. | SOAP 1.1 §4.2.3 | Always |
| Read a local `mustUnderstand` after trimming space, tab, carriage return, and line feed, and treat a value that is not an `xs:boolean`, such as `yes` or `&#xA0;1`, as optional | SOAP 1.1 gives the receiver no rule for such a value, and Bindings §3.2.2.2 lets SOAP software add headers the SAML sender does not control, so the message is still processed. | SOAP 1.1 §4.2.3, Bindings §3.2.2.2 | Always |
| Report every other envelope failure, including an XML limit, with the `Client` fault code | SOAP 1.1 §4.4.1 gives `Client` to a message that must change before a resend, and no code fits a limit better. | SOAP 1.1 §4.4.1 | Always |

### Identity provider and service provider: `Artifact`

Code: `src/artifact.rs`, `src/binding/encoding.rs`, `src/artifact/store.rs`, `src/model/validation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Decode a received `SAMLart` or SOAP `Artifact` by the shared [base64 rules](browser-bindings.md#base64), after trimming whitespace, non-ASCII whitespace included, around the SOAP `Artifact`. Look up, record, and consume the artifact by its padded base64 without whitespace, which `Artifact::as_str` returns | Every spelling of one artifact names the same 44 bytes, so the spelling must not decide which artifact resolves or whether it resolves again. | Bindings §3.6.4, RFC 2045 §6.8 | Always |

## Application duties

The deployment owns the connection, its TLS, and its HTTP authentication, as
[SOAP and URI security models](idp-sp-operational-modes.md#soap-and-uri-security-models)
describes.

| Duty | Level | Section |
| --- | --- | --- |
| POST `SoapRequest::envelope` with `SoapRequest::headers` to `SoapRequest::endpoint`, and pass the body of the HTTP response to `ArtifactResolution::finish` | Mandatory | Profiles §5.3.1, Bindings §3.2.3 |
| Pass `SoapChannel` only the protection that the TLS and HTTP authentication of the exchange established | Mandatory | Profiles §4.1.4.4, §5.3.2, §5.4.2 |
| Send `AnsweredArtifact::response` as the HTTP 200 body with `SoapResponse::headers`, also when it withholds the message, reports an error status, or follows a store failure | Recommended | Bindings §3.2.3.3, E19 |
| Answer a SOAP processing failure with a `SoapFault::new` envelope, `SoapFault::headers`, and HTTP 500. Pass the fault code of `SamlError::SoapEnvelope`, or for another error `Client` or `Server` as the `SoapFault` rustdoc describes | Mandatory | Bindings §3.2.3.3, SOAP 1.1 §6.2 |
| Answer HTTP 403 Forbidden when a receive operation refuses the channel with `SamlError::SoapChannelProtection` | Recommended | Bindings §3.2.3.3 |
| Add no validator, such as `Last-Modified` or `ETag`, to a SOAP response | Recommended | Bindings §3.2.3.2 |
| Send the responder no SOAP fault or other error message after `ArtifactResolution::finish`, `StartedNameIdManagement::finish`, or `finish_slo` reads its SAML response | Mandatory | Bindings §3.2.2.1 |
| Add HTTP headers to a request beyond `SoapRequest::headers` when the deployment needs them | Optional | Bindings §3.2.3.1 |
| Choose for `ArtifactStore::lifetime` the shortest period in which the service provider can receive the artifact and resolve it | Recommended | Core §3.5.3 |
| Pass `SamlValidationContext::with_replay_retention` a retention longer than the period in which the identity provider would resolve the artifact | Recommended | Bindings §3.6.5.2 |

<a id="outside-this-flow"></a>

## Not supported

[IdP and SP operational modes](idp-sp-operational-modes.md#exchanges-not-implemented)
lists the exchanges that saml-rs does not implement and the operational modes
it does not claim.

- An artifact that the service provider issues and the identity provider
  resolves, at both roles. Optional, Bindings §3.6, Profiles §5. The service
  provider sends its requests and logout messages by value.
- Release of an artifact to any presenter, for a message that any party may
  consume. Optional, Core §3.5.3. `issue_artifact` ties every message to the
  service provider it is given.
- A signed `ArtifactResponse` at the identity provider. Optional, Core §3.5.2,
  Profiles §5.3.2. `SoapChannel` must attest that the channel authenticates
  the identity provider and protects integrity.
- A signature as the only authentication of the requester or the responder,
  at both roles. Optional, Profiles §5.3.1, §5.3.2. Both roles require a
  `SoapChannel` that attests mutual authentication and integrity protection.
- Header entries, such as WS-Security, in a sent SOAP message, at both roles.
  Optional, Bindings §3.2.2.2. Received header entries follow the
  [SOAP envelope rules](#soap-envelope-rules).
- The fault code of a SOAP fault that the requester receives. SOAP 1.1 §4.4.
  `ArtifactResolution::finish`, `StartedNameIdManagement::finish`, and
  `finish_slo` refuse a body that is not the expected SAML response, and
  `SoapBodyElement::from_envelope` returns the `Fault` element for the caller
  to read.
