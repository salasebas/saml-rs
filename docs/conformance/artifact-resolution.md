# Artifact resolution over SOAP

Rules for typed artifact resolution: `Saml<Idp>::issue_artifact`,
`Saml<Idp>::answer_artifact_resolve`, and `Saml<Sp>::resolve_artifact`.
`ArtifactResolution::finish` reads the protocol message from the SOAP
response. It does not accept a Web SSO session.

This flow is the identity provider storing a protocol message and the service
provider resolving it. Browser delivery of a Web SSO response artifact is in
[HTTP-Artifact response](web-browser-sso-artifact.md). This flow does not
resolve an `AuthnRequest` artifact issued by the service provider. It does not
claim the IdP or SP operational mode in the SAML V2.0 conformance
specification.

Normative text is SAML Core 2.0, Bindings 2.0, Profiles 2.0, and Metadata
2.0, as corrected by Approved Errata 05. Schema citations are the OASIS
protocol and metadata schemas. Errata that change this flow are E4, E19, and
E31. E2 and E59 govern HTTP-Artifact metadata and browser delivery. They are
recorded with the [HTTP-Artifact response](web-browser-sso-artifact.md).

The deployment POSTs the SOAP envelope. TLS, HTTP authentication, and an HTTP
500 SOAP fault stay there. Conformance Requirements §3.5 and §5 are those
deployment duties. `SoapChannel` records the protection the deployment
provided. saml-rs does not open a socket or check a certificate.

## Issuing an artifact

`Saml<Idp>::issue_artifact` is this actor. Bindings §3.6.4 and Profiles §5.5.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Publish an indexed `ArtifactResolutionService` | Artifact issuer | IdP metadata | The profile uses this endpoint. Metadata defines `ArtifactResolutionService` as an indexed endpoint. The `index` is the artifact `EndpointIndex` |
| The resolution endpoint binding is SOAP | Artifact issuer | IdP metadata | This flow's synchronous binding. Bindings §3.2; Profiles §5.3.1. A peer endpoint with another binding is not used |
| Type code `0x0004`, two-byte `EndpointIndex`, 20-byte `SourceID`, 20-byte `MessageHandle` | Artifact issuer | Create artifact | Mandatory for the SAML V2.0 artifact. Bindings §3.6.4.2. Errata 05 E4: an artifact format not defined for SAML V2.0 must not be used |
| `SourceID` is the raw SHA-1 of the issuer entity ID, not hexadecimal | Artifact issuer | Create artifact | Recommendation. Bindings §3.6.4. Enforced. There is no switch for another `SourceID` construction. This SHA-1 is the artifact identifier. It is not the signature-algorithm SHA-1 policy |
| `MessageHandle` is 20 bytes from a cryptographically strong generator | Artifact issuer | Create artifact | Mandatory infeasibility requirement, with a recommended construction. Bindings §3.6.4. The handle is 20 random bytes from two `uuid` v4 values, without the bytes that carry the fixed version and variant bits |
| Base64 of the 44 artifact bytes | Artifact issuer | Create artifact | Mandatory encoding. Bindings §3.6.4, RFC 2045. Generation uses standard padding. A received value may omit padding. Whitespace in the value is rejected as library policy: RFC 2045 allows linear whitespace, and Bindings §3.6.4 does not require a receiver to reject it. The looser rule cannot be applied because the artifact is one compact 44-byte token; whitespace would stop that token from matching the stored message |
| The artifact refers to one service provider | Artifact issuer | Store the message | Profiles §4.1.4.4 for a Web SSO `<Response>`. Every issued message in this API names the service provider that may receive it |

`issue_artifact` fails when the local metadata has no SOAP
`ArtifactResolutionService` at that index. An empty list omits the element.

## ArtifactResolve

`Saml<Sp>::resolve_artifact` is this actor. Profiles §5.3.1 and §5.4.1.
Errata 05 E31 replaces "direct binding" with "synchronous binding" in
Bindings §3.6.5.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send `ArtifactResolve` on a synchronous binding | Requester | Generate ArtifactResolve | Mandatory. Profiles §5.3.1. The binding is SOAP 1.1 |
| Look up the endpoint by `EndpointIndex` | Requester | Generate ArtifactResolve | Profiles §5.5. A missing SOAP endpoint is `SamlError::MissingMetadata` |
| `Issuer` is present and omits `Format` or sets it to `entity` | Requester | Generate ArtifactResolve | Mandatory. Profiles §5.4.1. Generation omits `Format` |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Requester | Generate ArtifactResolve | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| Do not generate a leap-second time | Requester | Generate any instant | Mandatory. Core §1.3.3. Receivers are not required to reject a leap second |
| `Destination` is the artifact resolution endpoint | Requester | Generate ArtifactResolve | Set to the metadata location. Core treats `Destination` as optional. When a received request includes it, a different value does not release the message |
| One `Artifact` value | Requester | Generate ArtifactResolve | Mandatory. Protocol schema `ArtifactResolveType`. The value is the protocol element. A second direct child named `Artifact`, including one outside the protocol namespace, is malformed; the responder returns `SamlError` and leaves the artifact outstanding |
| At most one `Issuer` | Requester | Generate ArtifactResolve | Protocol schema `ArtifactResolveType`. A second `Issuer` is malformed; the responder returns `SamlError` so the deployment can refuse it at HTTP |
| Authenticate to the responder and protect integrity | Requester | Send ArtifactResolve | Recommendation. Profiles §5.3.1 and §5.4.1. Enforced for every dereference. There is no relaxation. Web SSO makes the same properties mandatory and adds confidentiality; that row is below |
| The SOAP body contains exactly one SAML request | Requester | SOAP envelope | Mandatory. Bindings §3.2.2.1, as left by Errata 05 E19 |
| `SOAPAction` may be `http://www.oasis-open.org/committees/security` | Requester | HTTP | Optional. Bindings §3.2.3. The helper reports that value. The responder does not read the header |
| `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Requester | HTTP | Recommendation. Bindings §3.2.3.2. The helper reports those values. saml-rs does not send the request |
| `Content-Type: text/xml; charset=utf-8` | Requester | HTTP | SOAP 1.1 content type. The helper reports it |

`ArtifactDereference::protocol` is a protocol message other than a Web SSO
response. `ArtifactDereference::web_browser_sso` is a Web SSO `<Response>`.
The caller chooses. A channel that lacks the required protection returns
`SamlError::SoapChannelProtection` before a request is built.

## ArtifactResponse

`Saml<Idp>::answer_artifact_resolve` is this actor. Profiles §5.3.2 and
§5.4.2, Bindings §3.6.5.2 and §3.6.6, and Core §3.2.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Return `ArtifactResponse` for an understood `ArtifactResolve` | Artifact issuer | Generate ArtifactResponse | Mandatory. Bindings §3.6.6 and Profiles §5.3.2. The SOAP envelope is that return value. A SOAP message this method cannot read returns `SamlError`, and the deployment can answer HTTP 500 with a SOAP fault |
| Do not use a SOAP fault for a SAML-domain error | Artifact issuer | Generate ArtifactResponse | Errata 05 E19. Wrong presenter, weak channel, unknown artifact, and a `Destination` that is not this endpoint are SAML responses, not faults |
| `Version` other than `2.0` is `VersionMismatch` | Artifact issuer | Generate ArtifactResponse | Core §3.2.2. The artifact stays outstanding |
| Success even when the protocol message is omitted | Artifact issuer | Generate ArtifactResponse | Mandatory. Bindings §3.6.6. The status is Success for an unauthorized requester or an artifact that is not outstanding |
| Include the protocol message only for the service provider it was issued to | Artifact issuer | Generate ArtifactResponse | Mandatory when the message was issued to a specific recipient. Profiles §4.1.4.4 and Bindings §3.6.5.2. Another presenter receives Success and no message |
| Authenticate the requester before returning the message | Artifact issuer | Generate ArtifactResponse | Mandatory for a message issued to a specific recipient. Bindings §3.6.5.2. The check is `SoapChannel`, not an XML signature |
| An artifact is single-use | Artifact issuer | Generate ArtifactResponse | Mandatory. Bindings §3.6.5.2. The message is returned at most once, and that return consumes the artifact. A request that does not return the message leaves it outstanding, including a different presenter, a channel that lacks the required protection, and a `Destination` that is not this endpoint. The service provider the artifact was issued to can still resolve it |
| `Issuer` is present and omits `Format` or sets it to `entity` | Artifact issuer | Generate ArtifactResponse | Mandatory. Profiles §5.4.2. Generation omits `Format` |
| `InResponseTo` matches the request `ID` | Artifact issuer | Generate ArtifactResponse | Mandatory. Core §3.2.2 |
| The responder authenticates itself and protects integrity | Artifact issuer | SOAP exchange | Mandatory. Profiles §5.4.2. Satisfied by the caller's `SoapChannel`, which is the binding mechanism. An XML signature on `ArtifactResponse` is the profile's other mechanism and is not generated |
| `Cache-Control: no-cache, no-store, must-revalidate, private` and `Pragma: no-cache` | Artifact issuer | HTTP | Recommendation. Bindings §3.2.3.2. The helper reports those values |
| Exactly one SAML response in the SOAP body | Artifact issuer | SOAP envelope | Mandatory. Bindings §3.2.2.1 and Errata 05 E19 |
| Ignore SOAP headers this responder does not process | Artifact issuer | SOAP envelope | Bindings §3.2.2.2: a responder must not require headers for the SAML message. A header with SOAP `mustUnderstand="1"` or `"true"` is refused, because SOAP 1.1 requires a fault when that header is not processed. An unprefixed `mustUnderstand` is refused the same way, fail-closed, as library policy. The deployment sends the fault |

A missing `Issuer`, or an `Issuer` whose `Format` is not omitted and not
`entity`, does not release the message. The status is still Success, and the
artifact stays outstanding. That classification is library policy. Profiles
§5.4.1 requires the requester to send an entity `Issuer` and does not require
the issuer to choose this status. Bindings §3.6.6 requires Success without
the message for an unauthorized requester, and Errata 05 E19 does not allow a
SOAP fault for that SAML error. The looser rule, treating a request with no
usable `Issuer` as the named presenter, cannot be applied because the
presenter check compares that `Issuer` with the service provider the artifact
was issued to.

## Web Browser SSO response artifact

Profiles §4.1.4.4 applies only when the caller stores the message with
`IssuedMessage::web_browser_sso_response` and resolves it with
`ArtifactDereference::web_browser_sso`.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The dereference is mutually authenticated, integrity protected, and confidential | Both parties | SOAP exchange | Mandatory for this profile. Profiles §4.1.4.4. The caller attests all three on `SoapChannel`. Confidentiality is not required for `IssuedMessage::protocol` |
| A Web SSO `<Response>` is stored only with `web_browser_sso_response` | Artifact issuer | Store the message | Library policy. `IssuedMessage::protocol` rejects a `Response`, so the call site cannot downgrade the confidentiality requirement above |
| Only the service provider the response was issued to receives it | Artifact issuer | Generate ArtifactResponse | Mandatory. Profiles §4.1.4.4 |

The binding, not a message signature, is the authentication mechanism from
§4.1.4.4 for this dereference. `ArtifactResolution::finish` returns the
message and does not accept a session. `finish_sso` accepts it through
`BrowserInput::artifact`, under the rules in
[HTTP-Artifact response](web-browser-sso-artifact.md).

## Service provider acceptance

`ArtifactResolution::finish` is this actor.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The SOAP body is one `ArtifactResponse` | Requester | Inbound ArtifactResponse | Bindings §3.2.2.1 |
| `Version` is `2.0` | Requester | Inbound ArtifactResponse | Protocol schema |
| `ID` is present and `IssueInstant` is a UTC `xs:dateTime` | Requester | Inbound ArtifactResponse | Protocol schema; Core §1.3.3 for the instant. Mirrors the `ArtifactResolve` check |
| One `Status` | Requester | Inbound ArtifactResponse | Protocol schema. A second `Status` is malformed |
| `InResponseTo` is present and equals the request `ID` | Requester | Inbound ArtifactResponse | Mandatory. Core §3.2.2 |
| Top-level status is Success, and one protocol message is present | Requester | Inbound ArtifactResponse | The success case of Profiles §5.3.2. Success without a message is `SamlError::ArtifactNotReturned` |
| `Issuer` is present, equals the identity provider, and omits `Format` or sets it to `entity` | Requester | Inbound ArtifactResponse | Library policy. Profiles §5.4.2 requires the issuer to send that `Issuer` and does not require the requester to reject another response. The looser rule cannot be applied because this requester attributes the responder by that `Issuer` together with `SoapChannel`. Without it, `finish` would return a message that is not attributed to the artifact issuer |
| The payload is one element in the SAML protocol namespace | Requester | Inbound ArtifactResponse | Library policy. The schema allows another child, and Profiles §5.3.2 does not require the requester to reject it. The looser rule cannot be applied because `finish` returns the dereferenced protocol message; a different element would be presented as that message. A Web SSO dereference also rejects a local name other than `Response` for the same reason |
| A `protocol` dereference does not return a `Response` | Requester | Inbound ArtifactResponse | Library policy. Profiles §4.1.4.4 requires confidentiality for the Web SSO dereference and does not require the requester to reject the payload. The looser rule cannot be applied because `ArtifactDereference::protocol` does not require a confidential channel; returning a `Response` from it would accept a Web SSO response dereferenced without that protection |
| The same artifact value is resolved once | Requester | Inbound artifact | Recommendation. Bindings §3.6.5.2. `ArtifactUses::enforce_single_use` is the default. `ArtifactUses::allow_reuse` relaxes this recommendation only. The issuer still returns the message once |

## SOAP for another protocol message

`SoapProtocolMessage` places one SAML protocol element in a SOAP 1.1 body and
reads one element back. A later logout or name-identifier exchange can use
that envelope. This ticket does not implement those profiles. ECP, PAOS, and
the assertion query profile are not implemented.

## Outside this flow

- Browser delivery of an artifact, which is the [HTTP-Artifact response](web-browser-sso-artifact.md) for a Web SSO `<Response>`.
- `AuthnRequest` over HTTP-Artifact.
- Signing `ArtifactResolve` or `ArtifactResponse`.
- The IdP operational mode and the SP operational mode.
