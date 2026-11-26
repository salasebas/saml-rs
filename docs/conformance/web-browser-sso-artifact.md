# Web Browser SSO response over HTTP-Artifact

`IdentityProvider::respond_sso_artifact`, `respond_sso_refusal_artifact`, and
`initiate_sso_artifact` store a Web Browser SSO `Response` and return the
browser action that carries its artifact. At the service provider,
`DeliveredArtifact` reads the artifact, and `finish_sso`, `accept_unsolicited_sso`,
and their outstanding-logout variants accept the resolved `Response` through
`Inbound::artifact`. The record covers the "Web SSO, `<Response>`, HTTP
artifact" feature of Conformance Table 2, and for the service provider only
sessions where an XML signature protects the response or each assertion.

Normative text is [Bindings §3.6](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
and [Profiles §4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf),
as corrected by [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
Where this record states no difference, the `Response` follows
[SSO generation](web-browser-sso-generation.md) and [identifiers](identifiers.md),
and its acceptance follows the HTTP-POST rows of
[SSO acceptance](web-browser-sso-acceptance.md).

<a id="partial-support"></a>
<a id="builds-without-a-crypto-provider"></a>

The statuses hold on builds with a crypto provider. A build without one
writes no Web SSO `Response` at the identity provider, so it delivers no
artifact. Its service provider verifies no XML signature, so it establishes
no session, reports the status of an unsigned error `Response`, and refuses
a signed one.

## Support

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `Response` by artifact, in a `SAMLart` query parameter or form control | Bindings §3.6.3, Profiles §4.1.3.5 | Supported | Supported |
| Error `Response` by artifact | Profiles §4.1.3.5, §4.1.4.2, E85 | Supported | Supported |
| Unsolicited `Response` by artifact | Profiles §4.1.5 | Supported | Supported |
| `RelayState` with a `Response` artifact | Bindings §3.6.3.1, Profiles §4.1.5 | Supported | Supported |
| XML signature on the `Response` or on each assertion | Profiles §4.1.3.5, E93 | Supported | Supported |
| Namespace names in the resolved `Response` compared after normalizing the declaration value | Namespaces in XML 1.0 §2.3 | — | [Partial](web-browser-sso-acceptance.md#namespace-declarations-with-character-references) |
| Successful `Response` without an XML signature, protected by the artifact resolution channel | Profiles §4.1.3.5, §4.1.4.4, E93 | Not supported | Not supported |
| `AuthnRequest` by artifact, with its `RelayState` | Profiles §4.1.3.3, Bindings §3.6.3.1 | Not supported | Not supported |
| HTTP-Artifact `AssertionConsumerService` in service provider metadata | Bindings §3.6.7, E2 | Supported | Supported |
| `ArtifactResolutionService` in identity provider metadata | Profiles §4.1.6, Bindings §3.6.7, E2 | Supported | Supported |

The artifact format, the dereference over a mutually authenticated,
integrity-protected, and confidential channel (Profiles §4.1.4.4), the single
use of the artifact, and its release only to the service provider the
`Response` was issued to are in [Artifact resolution](artifact-resolution.md).

## Rules

<a id="identity-provider-delivery"></a>

### Identity provider: `respond_sso_artifact`, `respond_sso_refusal_artifact`, `initiate_sso_artifact`

Code: `src/api/idp.rs`, `src/api/response_acs.rs`, `src/artifact.rs`, `src/browser/outbound.rs`, `src/binding/redirect.rs`, `src/idp.rs`, `src/api/options.rs`, `src/metadata/generate.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Store the `Response` while its artifact is outstanding | Mandatory | Bindings §3.6.2, Core §3.5.3 | `ArtifactStore`, `IssuedArtifacts::expire_after` |
| Publish at least one `ArtifactResolutionService` in this identity provider's metadata to deliver a response by artifact | Mandatory | Profiles §4.1.6 | `IdpConfigBuilder::artifact_resolution_service` |
| Put the URL-encoded artifact in a `SAMLart` query parameter, and a present `RelayState`, URL-encoded, in a `RelayState` query parameter | Mandatory | Bindings §3.6.3.2 | `ArtifactDelivery::redirect` |
| Put the artifact in a `SAMLart` field, and a present `RelayState` in a `RelayState` field, of one form whose action is the assertion consumer | Mandatory | Bindings §3.6.3.3 | `ArtifactDelivery::post_form` |
| Send a `RelayState` the identity provider chooses when the request carried none, a refused request included, or with an unsolicited response | Optional | Bindings §3.4.3, §3.5.3, §3.6.3.1, CS-01 §2.3 | `RespondSso::relay_state` |
| Honor a requested binding and assertion consumer when possible, and verify that the consumer belongs to the service provider | Mandatory | Profiles §4.1.3.5, §4.1.4.1 | Always |
| Deliver an unsolicited artifact to the default assertion consumer | Recommended | Profiles §4.1.5 | Always |
| Sign the assertions or the `Response` | Optional | Profiles §4.1.3.5, E93 | Always |
| Sign the `Response` when an `EncryptedAssertion` uses a CBC algorithm | Recommended | Profiles §4.1.3.5, E93 | `RespondSso::allow_unsigned_encrypted_cbc` |
| Support error delivery by artifact when the user agent remains available and an acceptable response location exists | Recommended | Profiles §4.1.3.5, E85 | `SsoOutcome::Failure`, `respond_sso_refusal_artifact` |

[Browser bindings](browser-bindings.md#sending-a-relaystate) keeps the rules
that return a received `RelayState` unchanged, limit one the identity provider
creates to 80 bytes, and refuse a form `RelayState` that the form cannot carry
unchanged. It also keeps the cache headers that `Outbound::headers` returns
with the artifact. [SSO generation](web-browser-sso-generation.md#identity-provider-response)
keeps the rules for the `Response` content, such as an error without
assertions and the refusal of `SsoOutcome::Failure` with a top-level `Success`
status.

<a id="service-provider-receipt"></a>

### Service provider: `DeliveredArtifact`, `finish_sso`, `accept_unsolicited_sso`

Code: `src/browser/artifact.rs`, `src/api/sp.rs`, `src/api/peer.rs`, `src/flow.rs`, `src/assertion_acceptance.rs`, `src/browser/endpoints.rs`, `src/metadata/generate.rs`

These rows cover `finish_sso`, `finish_sso_with_outstanding_logout`,
`accept_unsolicited_sso`, and `accept_unsolicited_sso_with_outstanding_logout`
with `Inbound::artifact`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept the artifact from an HTTP GET query and from an HTTP POST form | Mandatory | Bindings §3.6.3 | `DeliveredArtifact::from_query`, `DeliveredArtifact::from_form` |
| Publish an assertion consumer with the HTTP-Artifact binding | Recommended | Bindings §3.6.7, E2 | `AcsEndpoint::artifact` |
| Accept only a dereferenced `samlp:Response` as the Web SSO message | Mandatory | Profiles §4.1.3.5, Core §3.5.3 | Always |
| Compare a present `Destination` and the bearer `Recipient`, after XML whitespace collapse, with the assertion consumer the artifact was delivered to | Mandatory | Core §3.2.2, Profiles §4.1.4.3, E26, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Allow `Destination` to be omitted from a signed `Response` | Optional | Core §3.2.2, Bindings §3.6.5.2, E59 | Always |
| Accept an IdP-supplied `RelayState` on an unsolicited artifact response or when the request carried none | Optional | Bindings §3.6.3.1, Profiles §4.1.5 | Always |
| Allow the service provider to refuse unsolicited responses | Recommended | Profiles §4.1.5, E90 | Do not call `accept_unsolicited_sso` |

E59 leaves the `Destination` of the dereferenced message unspecified. The
record reads the assertion consumer that received the artifact as the
location that Core §3.2.2 compares a present `Destination` with.

`DeliveredArtifact` decodes `SAMLart` by the shared
[base64 rules](browser-bindings.md#base64), and
[browser bindings](browser-bindings.md) keeps the receiver rules that read
only the `SAMLart` and `RelayState` fields. Signature verification, the bearer
`NotOnOrAfter`, `InResponseTo`, audience, conditions, and clock skew follow
the HTTP-POST rows of [SSO acceptance](web-browser-sso-acceptance.md). A
status other than `Success` establishes no session, under the shared
[status code rules](web-browser-sso-acceptance.md#status-codes).

## Library policies

### Identity provider: `respond_sso_artifact`, `respond_sso_refusal_artifact`, `initiate_sso_artifact`

Code: `src/artifact.rs`, `src/api/idp.rs`, `src/api/response_acs.rs`, `src/idp.rs`, `src/idp/login_response.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a delivery whose index does not name a SOAP `ArtifactResolutionService` in the local metadata, and store nothing | SOAP is the only synchronous resolution binding the crate implements, so an artifact for another endpoint could not be resolved. | Bindings §3.6.4 | `ArtifactDelivery::redirect`, `ArtifactDelivery::post_form` |
| Reject an explicit `RespondSso::relay_state` whenever the request supplied a `RelayState` | The response must carry the received value exactly, so the crate copies it, and refusing every explicit value reports the misuse even when a test request carries the same value. | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |
| Require the selected consumer to appear in the service provider metadata | The identity provider uses the service provider metadata to establish endpoint ownership. | Profiles §4.1.3.5, §4.1.4.1 | Always |
| Reject an unsolicited artifact when the default assertion consumer does not use HTTP-Artifact | Another consumer would depart from the recommended default, and `initiate_sso` serves a default that uses another binding. | Profiles §4.1.5 | Always |
| For `Success`, sign the assertion when the SP metadata sets `WantAssertionsSigned`, and sign the `Response` otherwise. For an error, sign the `Response` | A service provider that requires an XML signature, as this crate's does, rejects an unsigned response, and an error has no assertion to sign. | Profiles §4.1.3.5 | `RespondSso::sign_response` also signs a `Success` `Response` |
| Write the assertion consumer URL in `Destination` | E59 leaves the value unspecified for the dereferenced message, and the URL the artifact was delivered to is the one a receiver that compares a present `Destination` can match. | Core §3.2.2, Bindings §3.6.5.2, E59 | Always |

[Browser bindings](browser-bindings.md) keeps the policies that
[refuse a form `RelayState`](browser-bindings.md#sending-relaystate-policies)
with a CR or LF outside a CRLF pair,
[return a received `RelayState`](browser-bindings.md#returning-relaystate-policies)
over 80 bytes unchanged, and keep the
[endpoint's own query parameters](browser-bindings.md#redirect-endpoint-query-policies)
before `SAMLart`.

### Service provider: `DeliveredArtifact`, `finish_sso`, `accept_unsolicited_sso`

Code: `src/browser/artifact.rs`, `src/binding/parameters.rs`, `src/artifact.rs`, `src/api/sp.rs`, `src/api/peer.rs`, `src/sp.rs`, `src/flow/error_response.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Require exactly one `SAMLart` | The service provider resolves one artifact per delivery. | Bindings §3.6.3 | Always |
| Accept only an artifact of the SAML V2.0 type `0x0004` | The resolver checks the selected identity provider against the `SourceID` of that type, and E4 already excludes the formats of earlier SAML versions. | Bindings §3.6.4, §3.6.4.2, E4 | Always |
| Compare the `RelayState` with the pending login when the SP sent one | Nothing protects the pairing of an artifact and its `RelayState`. | Bindings §3.6.5.2 | `ServiceProvider::finish_sso` |
| Accept only the message that the accepted IdP returned for the delivered artifact | `Inbound::artifact` pairs two caller values, and a mismatched pair would accept a message for another artifact or identity provider. | Profiles §4.1.3.5 | `Inbound::artifact` |
| Require an XML signature on the `Response` or on each assertion of a `Success` response | `SsoSession` takes the subject, conditions, and attributes only from XML verified against the IdP signing key. | Profiles §4.1.3.5, §4.1.4.4, E93, `StatusResponseType`, `AssertionType` | Always |
| Without a recipient endpoint, expect the assertion consumer of the pending request in `finish_sso`, and the default HTTP-Artifact assertion consumer in `accept_unsolicited_sso` | Without a supplied URL, the library is not told which URL received the artifact. | Profiles §4.1.4.3 | `SamlValidationContext::with_recipient_endpoint` |
| Expose a login error diagnostic only if an XML signature covers the inner `Response` and its issuer, recipient, and correlation checks pass | Evidence for the resolution exchange alone cannot authorize disclosure of login diagnostics. | Core §3.2.2.3, Bindings §3.6.4, Profiles §4.1.4.4 | Always |

[Browser bindings](browser-bindings.md) keeps the policies that
[reject a second `RelayState` and a received `RelayState` over 4096 bytes](browser-bindings.md#received-value-policies),
and [a query `SAMLart` or `RelayState` that is not UTF-8](browser-bindings.md#received-query-policies).
[Metadata and replay](metadata-and-replay.md#sso-replay-deadlines) keeps the
policy that stores the bearer assertion `ID` of an artifact response only when
the caller passes a replay cache.

<a id="outside-this-flow"></a>

## Application duties

| Duty | Level | Section |
| --- | --- | --- |
| Protect the transmission of the artifact to and from the user agent with TLS | Recommended | Bindings §3.6.5.2, Profiles §4.1.3.5 |

[Browser bindings](browser-bindings.md#application-duties) keeps the other
duties of an artifact delivery: the HTTP 302 or 303 status of
`Outbound::redirect_url`, the XHTML form of `Outbound::post_form` with hidden
controls, no HTTP error status for a SAML failure, safe URL schemes for a
`RelayState`, no sensitive state attached to a `RelayState` without a further
check, and the integrity of a `RelayState` the application sets.

## Not supported

- An `AuthnRequest` by HTTP-Artifact, at the service provider and the identity
  provider, with the `RelayState` that accompanies its artifact. Optional,
  Profiles §4.1.3.3, Bindings §3.6. `start_sso` sends the request by
  HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign, and `receive_sso` reads
  those bindings, as
  [exchanges not implemented](idp-sp-operational-modes.md#exchanges-not-implemented)
  also lists.
- A successful `Response` without an XML signature, protected only by the
  artifact resolution channel. Optional, Profiles §4.1.3.5, §4.1.4.4, E93.
  The identity provider always signs the `Response` or its assertions, and
  the service provider requires that signature to establish a session.
