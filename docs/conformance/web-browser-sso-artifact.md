# Web Browser SSO response over HTTP-Artifact

Rules for a typed Web Browser SSO `<Response>` delivered as an HTTP-Artifact:
identity-provider `respond_sso_artifact` and `initiate_sso_artifact`, and
service-provider `DeliveredArtifact`, `finish_sso`, and
`accept_unsolicited_sso` with `BrowserInput::artifact`. The dereference
between the two is [artifact resolution](artifact-resolution.md). The content
of the `<Response>` is in
[generation](web-browser-sso-generation.md), and assertion acceptance is in
[acceptance](web-browser-sso-acceptance.md). This page records what the
binding adds or changes.

This flow is the feature "Web SSO, `<Response>`, HTTP artifact" in Conformance
Requirements Table 2, for the IdP, IdP Lite, SP, and SP Lite columns. It does
not claim the IdP or SP operational mode. An `<AuthnRequest>` over
HTTP-Artifact is not implemented.

Normative text is SAML Bindings 2.0 §3.6 and Profiles 2.0 §4.1, as corrected
by Approved Errata 05. Errata that change this flow are E2, E4, E26, E31, E59,
E85, and E90.

The deployment sends the HTTP response that carries the artifact and receives
the request at the assertion consumer. TLS for that exchange stays there.

## Identity provider delivery

`Saml<Idp>::respond_sso_artifact` and `Saml<Idp>::initiate_sso_artifact` are
this actor.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The response is stored while its artifact is outstanding | Identity provider | Generate Response | Bindings §3.6.2: the artifact issuer maintains state while the artifact is pending. The caller owns `IssuedArtifacts` |
| Publish at least one `ArtifactResolutionService` | Identity provider | IdP metadata | Mandatory. Profiles §4.1.6. Errata 05 E2 recommends indexed endpoints. A delivery whose index has no SOAP endpoint in local metadata is `SamlError::MissingMetadata`, and nothing is stored |
| URL encoding places the URL-encoded artifact in a `SAMLart` query parameter | Identity provider | Deliver artifact | Mandatory when that encoding is used. Bindings §3.6.3.2. `ArtifactDelivery::redirect`. The parameter follows any query the assertion consumer URL already has |
| The URL-encoded artifact is returned with HTTP 302 or 303 | Identity provider | HTTP | Mandatory. Bindings §3.6.5. `Outbound::redirect_url` is the `Location`. The deployment sends the status |
| Form encoding places the artifact in a hidden control named `SAMLart`, in a form whose action is the assertion consumer and whose method is `POST` | Identity provider | Deliver artifact | Mandatory when that encoding is used. Bindings §3.6.3.3. `ArtifactDelivery::post_form`. `Outbound::post_form` is the action and the controls. The caller renders the XHTML document |
| `RelayState` accompanies the artifact in a `RelayState` query parameter or hidden control | Identity provider | Deliver artifact | Mandatory when a value accompanies the artifact. Bindings §3.6.3.2 and §3.6.3.3 |
| `RelayState` received with the `AuthnRequest` is returned unchanged | Identity provider | Deliver artifact | Mandatory. Bindings §3.4.3 and §3.5.3 require a response binding with a RelayState mechanism and the exact value. `RespondSso::relay_state` replaces it, as it does for HTTP-POST |
| `RelayState` does not exceed 80 bytes | Identity provider | Deliver artifact | Mandatory prohibition. Bindings §3.6.3.1. Integrity protection of the value remains a recommendation for the party that creates it |
| `Cache-Control: no-cache, no-store` and `Pragma: no-cache` | Identity provider | HTTP | Recommendation. Bindings §3.6.5.1. `ArtifactDelivery::CACHE_CONTROL` and `ArtifactDelivery::PRAGMA` report those values. saml-rs does not send the response |
| Honour the binding and assertion consumer the `AuthnRequest` names | Identity provider | Deliver artifact | Mandatory when the identity provider can. Profiles §4.1.3.5. A request whose `ProtocolBinding` is HTTP-Artifact is not answered by `respond_sso`, and a request that names another binding is not answered by `respond_sso_artifact`. Profiles §4.1.4.1 requires the named consumer to belong to the service provider |
| An unsolicited artifact goes to the default assertion consumer | Identity provider | Deliver artifact | Recommendation. Profiles §4.1.5. The caller selects the binding, so the consumer is the HTTP-Artifact one marked default, or the first HTTP-Artifact one when none is. A default consumer with another binding is not used |
| Sign the assertions | Identity provider | Generate Response | Optional on this binding. Profiles §4.1.3.5. Library policy: the stored response is signed the way an HTTP-POST response is. The assertion is signed when the service provider metadata sets `WantAssertionsSigned`, and the `Response` is signed otherwise |
| `Destination` | Identity provider | Generate Response | Unspecified by this binding. Errata 05 E59. Generation writes the assertion consumer URL, as it does for HTTP-POST |
| An error `Response` is delivered as an artifact | Identity provider | Deliver artifact | Recommendation. Profiles §4.1.3.5 and Errata 05 E85. `RespondSso::status`. It carries no assertion (Profiles §4.1.4.2) and follows the same store and delivery |
| Do not use an HTTP error status for a SAML failure | Identity provider | HTTP | Mandatory prohibition. Bindings §3.6.6. The failure is the status of the stored `Response`. The deployment chooses the HTTP status |

Artifact construction, the single-use rule, and the release of the message
only to the service provider it was issued to are in
[artifact resolution](artifact-resolution.md).

## Service provider receipt

`DeliveredArtifact`, `Saml<Sp>::finish_sso`, and
`Saml<Sp>::accept_unsolicited_sso` are this actor.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An endpoint that supports this binding accepts both encodings | Service provider | Inbound artifact | Mandatory. Bindings §3.6.3. `DeliveredArtifact::from_query` reads an HTTP GET, and `DeliveredArtifact::from_form` reads an HTTP POST. The deployment routes both methods to the assertion consumer |
| Publish the assertion consumer with the HTTP-Artifact binding | Service provider | SP metadata | Recommendation. Bindings §3.6.7 as replaced by Errata 05 E2. `AcsEndpoint::artifact` |
| Other controls are not required to process the artifact | Service provider | Inbound artifact | Mandatory. Bindings §3.6.3.3. Parameters other than `SAMLart` and `RelayState` are ignored |
| One `SAMLart` value and at most one `RelayState` value | Service provider | Inbound artifact | Library policy. Bindings §3.6.3 names one parameter of each and does not require a receiver to reject a repeat. The looser rule cannot be applied because two artifact values refer to two stored messages, and two `RelayState` values cannot both equal the one the service provider sent |
| The artifact is the SAML V2.0 type `0x0004` | Service provider | Inbound artifact | Mandatory. Errata 05 E4: an artifact format not defined for SAML V2.0 must not be used with this binding |
| `RelayState` does not exceed 80 bytes | Service provider | Inbound artifact | Mandatory prohibition. Bindings §3.6.3.1 |
| `RelayState` is the value the service provider sent | Service provider | Inbound `finish_sso` | Library policy, as for HTTP-POST. Bindings §3.6.5.2 says nothing protects the pairing of an artifact and its `RelayState`, and requires the consumer to take care. It does not require this comparison. The looser rule cannot be applied because the pending login is the only value `finish_sso` can check the delivered one against |
| A URL taken from `RelayState` is sanitized | Service provider | Inbound artifact | Mandatory for the party that uses the value that way. Bindings §3.6.5.2 as amended by Errata 05 E90. saml-rs does not interpret `RelayState`. The caller sanitizes it |
| Resolve the artifact on a synchronous binding that does not use the browser | Service provider | Resolve artifact | Mandatory. Bindings §3.6.5, Errata 05 E31. `Saml<Sp>::resolve_artifact` over SOAP |
| The dereference is mutually authenticated, integrity protected, and confidential | Both parties | Resolve artifact | Mandatory. Profiles §4.1.4.4. `BrowserInput::artifact` takes the message `ArtifactResolution::finish` returned, and that method returns a `Response` only from `ArtifactDereference::web_browser_sso` |
| The message is the one resolved from the delivered artifact, by the identity provider being accepted | Service provider | Inbound `finish_sso` and `accept_unsolicited_sso` | Mandatory. Profiles §4.1.3.5: the service provider retrieves the `Response` for the artifact it received from the identity provider that issued it. A message resolved from another artifact or from another identity provider is rejected |
| Enforce single use of a received artifact, and do not retry one whose resolution did not complete | Service provider | Resolve artifact | Recommendation. Bindings §3.6.5.2. `ArtifactUses::enforce_single_use` records the artifact when resolution starts. `ArtifactUses::allow_reuse` relaxes it |
| Verify any signature on the `Response` or an assertion | Service provider | Inbound | Mandatory. Profiles §4.1.4.3 |
| The `Response` or each assertion is signed | Service provider | Inbound | Library policy. Profiles §4.1.3.5 lets an assertion on this binding be unsigned, and §4.1.4.4 lets the dereference binding authenticate the parties. The looser rule cannot be applied because the typed session reads the subject, conditions, and attributes from signature-verified XML, and `SoapChannel` is the caller's attestation, which saml-rs does not check. `AssertionSignaturePolicy` and `ResponseSignaturePolicy` apply as they do for HTTP-POST |
| Bearer `Recipient` is the assertion consumer the artifact was delivered to | Service provider | Inbound | Mandatory. Profiles §4.1.4.3 as replaced by Errata 05 E26. `finish_sso` uses the pending assertion consumer. `accept_unsolicited_sso` uses the local HTTP-Artifact consumer marked default, or the first one when none is |
| A present `Destination` is that assertion consumer | Service provider | Inbound | Mandatory when the attribute is present. Core §3.2.2 |
| A signed `Response` may omit `Destination` | Service provider | Inbound | Errata 05 E59 leaves the attribute unspecified on this binding. The HTTP-POST rule that a signed message carries it (Bindings §3.5.5.2) is not applied |
| A status other than Success does not establish a session | Service provider | Inbound | Mandatory. Profiles §4.1.4.2: an error `Response` carries no assertion. `SamlError::StatusNotSuccess` carries the status codes |
| Do not replay a bearer assertion | Service provider | Inbound | Profiles §4.1.4.5 states this for HTTP-POST. On this binding it is the caller's `ReplayPolicy`, classified in [metadata and replay](metadata-and-replay.md) |
| Accepting an unsolicited response can be disabled | Service provider | Inbound | Recommendation. Profiles §4.1.5 as amended by Errata 05 E90. `accept_unsolicited_sso` is a separate call. `finish_sso` does not accept one |

The remaining acceptance rows, including bearer `NotOnOrAfter`,
`InResponseTo`, audience, conditions, and clock skew, are the HTTP-POST rows
in [acceptance](web-browser-sso-acceptance.md).

## Outside this flow

- `<AuthnRequest>` over HTTP-Artifact, and Single Logout over HTTP-Artifact.
- The HTTP response that carries the artifact, including the XHTML form document, and TLS for the browser exchange.
- Accepting a `Response` that carries no XML signature on the strength of the dereference channel alone.
- The IdP operational mode and the SP operational mode.
