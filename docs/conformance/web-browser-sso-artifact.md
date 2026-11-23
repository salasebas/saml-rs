# Web Browser SSO response over HTTP-Artifact

Rules for a Web Browser SSO `<Response>` delivered as an HTTP-Artifact: `IdentityProvider::respond_sso_artifact` and `initiate_sso_artifact`, and `DeliveredArtifact`, `ServiceProvider::finish_sso`, and `accept_unsolicited_sso` with `Inbound::artifact`.
The normative documents are [Bindings §3.6](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) and [Profiles §4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf), as corrected by [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
This record lists only the differences from the HTTP-POST rows in [acceptance](web-browser-sso-acceptance.md), the `<Response>` content in [generation](web-browser-sso-generation.md) and [identifiers](identifiers.md), and the SOAP dereference in [artifact resolution](artifact-resolution.md).
It covers the "Web SSO, `<Response>`, HTTP artifact" feature of Conformance Requirements Table 2 (Conformance §3.2).
For the SP and SP Lite columns, the claim covers only sessions where an XML signature protects the response or each assertion.

## Identity provider delivery

`IdentityProvider::respond_sso_artifact` and `IdentityProvider::initiate_sso_artifact` store the response and return the browser action that carries the artifact.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Store the `Response` while its artifact is outstanding | Mandatory | Bindings §3.6.2 | `IssuedArtifacts::expire_after` |
| Publish at least one `ArtifactResolutionService` when delivering a Web SSO response by artifact | Mandatory | Profiles §4.1.6, E2 | `IdpConfigBuilder::artifact_resolution_service` |
| Reject a delivery whose index does not name a SOAP `ArtifactResolutionService` in the local metadata, and store nothing | Library policy: SOAP is the only synchronous resolution binding the crate implements. | Bindings §3.6.4 | `ArtifactDelivery::redirect`, `ArtifactDelivery::post_form` |
| Put the URL-encoded artifact in a `SAMLart` query parameter | Mandatory | Bindings §3.6.3.2 | `ArtifactDelivery::redirect` |
| Put the artifact in a hidden control named `SAMLart`, in a form posted to the assertion consumer | Mandatory | Bindings §3.6.3.3 | `ArtifactDelivery::post_form` |
| Carry a `RelayState` that accompanies the artifact in a `RelayState` query parameter or hidden control | Mandatory | Bindings §3.6.3.2, §3.6.3.3 | Always |
| Return the `RelayState` received with the `AuthnRequest` unchanged, including values over 80 bytes | Mandatory | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Reject an explicit `RespondSso::relay_state` whenever the request supplied a `RelayState` | Library policy: reason not recorded. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Reject a `RelayState` over 80 bytes that the IdP sets | Mandatory | Bindings §3.6.3.1 | Always |
| Send `Cache-Control: no-cache, no-store` and `Pragma: no-cache` with the artifact | Recommended | Bindings §3.6.5.1 | `Outbound::headers` |
| Honor a requested binding and assertion consumer when possible, and verify that the consumer belongs to the service provider | Mandatory | Profiles §4.1.3.5, §4.1.4.1 | Always |
| Require the selected consumer to appear in the service provider metadata | Library policy: the IdP uses the SP metadata to establish endpoint ownership. | Profiles §4.1.3.5, §4.1.4.1 | Always |
| Deliver an unsolicited artifact to the default assertion consumer, and reject a default that is not HTTP-Artifact | Recommended | Profiles §4.1.5 | Always |
| Sign the assertions or the `Response` | Optional | Profiles §4.1.3.5, E93 | Always |
| For `Success`, sign the assertion when the SP metadata sets `WantAssertionsSigned`, and sign the `Response` otherwise. For an error, sign the `Response` | Library policy: reason not recorded. | Profiles §4.1.3.5 | `RespondSso::sign_response` also signs a `Success` `Response` |
| Sign the `Response` when an `EncryptedAssertion` uses a CBC algorithm | Recommended | Profiles §4.1.3.5, E93 | `RespondSso::allow_unsigned_encrypted_cbc` |
| Write the assertion consumer URL in `Destination` | Library policy: reason not recorded. | Core §3.2.2, Bindings §3.6.5.2, E59 | Always |
| Support error delivery by artifact when the user agent remains available and an acceptable response location exists | Recommended | Profiles §4.1.3.5, E85 | `SsoOutcome::Failure` |
| Omit all assertions from an error `Response` | Mandatory | Profiles §4.1.4.2 | `SsoOutcome::Failure` |
| Reject `SsoOutcome::Failure` with a top-level `Success` status | Mandatory | Profiles §4.1.4.2, E26 | Always |

## Service provider receipt

`DeliveredArtifact`, `ServiceProvider::finish_sso`, and `ServiceProvider::accept_unsolicited_sso` receive the artifact and accept the resolved `Response`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Accept the artifact from an HTTP GET query and from an HTTP POST form | Mandatory | Bindings §3.6.3 | `DeliveredArtifact::from_query`, `DeliveredArtifact::from_form` |
| Publish an assertion consumer with the HTTP-Artifact binding | Recommended | Bindings §3.6.7, E2 | `AcsEndpoint::artifact` |
| Process a form without requiring any additional controls, and ignore controls other than `SAMLart` and `RelayState` | Mandatory | Bindings §3.6.3.3 | Always |
| Require exactly one `SAMLart` and at most one `RelayState` | Library policy: two artifact values refer to two stored messages, and two `RelayState` values cannot both equal the one the service provider sent. | Bindings §3.6.3 | Always |
| Reject an artifact that is not the SAML V2.0 type `0x0004` | Mandatory | Bindings §3.6.4.2, E4 | Always |
| Accept a received `RelayState` of 81 to 4096 bytes, and reject a longer one | Library policy: the 80-byte limit binds only the creator, and 4096 bytes is a resource limit on unauthenticated input. | Bindings §3.6.3.1 | Always |
| Compare the `RelayState` with the pending login when the SP sent one | Library policy: nothing protects the pairing of an artifact and its `RelayState`. | Bindings §3.6.5.2 | `ServiceProvider::finish_sso` |
| Accept only the message that the accepted IdP returned for the delivered artifact | Library policy: `Inbound::artifact` pairs two caller values, and a mismatched pair would accept a message for another artifact or identity provider. | Profiles §4.1.3.5 | `Inbound::artifact` |
| Require an XML signature on the `Response` or on each assertion of a `Success` response | Library policy: `SsoSession` takes the subject, conditions, and attributes only from XML verified against the IdP signing key. | Profiles §4.1.3.5, §4.1.4.4, E93, `StatusResponseType`, `AssertionType` | Always |
| Compare a present `Destination` and the bearer `Recipient` with the assertion consumer the artifact was delivered to | Mandatory | Core §3.2.2, Profiles §4.1.4.3, E26 | Always for `finish_sso`. `SamlValidationContext::with_recipient_endpoint` selects the endpoint for `accept_unsolicited_sso` |
| Expect the default HTTP-Artifact assertion consumer when `accept_unsolicited_sso` gets no recipient endpoint | Library policy: without a supplied URL, `accept_unsolicited_sso` is not told which URL received the artifact. | Profiles §4.1.4.3 | `SamlValidationContext::with_recipient_endpoint` |
| Allow `Destination` to be omitted from a signed `Response` | Optional | Core §3.2.2, Bindings §3.6.5.2, E59 | Always |
| Store the bearer assertion `ID` only when the caller passes a replay cache | Library policy: Profiles §4.1.4.5 states the replay duty for HTTP-POST only. | Profiles §4.1.4.5 | `ReplayPolicy` |
| Accept an IdP-supplied `RelayState` on an unsolicited artifact response or when the request carried none | Optional | Bindings §3.6.3.1, Profiles §4.1.5 | Always |
| Allow the SP to refuse unsolicited responses | Recommended | Profiles §4.1.5, E90 | Do not call `accept_unsolicited_sso` |

The artifact value, the mutually authenticated, integrity-protected, and confidential SOAP dereference, single use of the received artifact, and release only to the service provider the response was issued to are in [artifact resolution](artifact-resolution.md). Signature verification, `Recipient` and `NotOnOrAfter`, `InResponseTo`, audience, conditions, the status check, and clock skew are the HTTP-POST rows in [acceptance](web-browser-sso-acceptance.md).

## Outside this flow

- Sanitizing a URL taken from `RelayState`. Mandatory, Bindings §3.6.5.2 and E90. The caller does it, because saml-rs does not interpret `RelayState`.
- Integrity protection of a `RelayState` the application sets. Recommended, Bindings §3.6.3.1.
- The HTTP 302 or 303 status for a URL-encoded artifact, and no HTTP error status for a SAML failure. Mandatory, Bindings §3.6.5 and §3.6.6. The deployment sends the response. `Outbound::redirect_url` is the `Location`.
- The XHTML document and `method="POST"` of the form-encoded artifact. Mandatory, Bindings §3.6.3.3. The caller renders `Outbound::post_form`.
- TLS for the browser exchange. Recommended, Bindings §3.6.5.2 and Profiles §4.1.3.5.
- Accepting a `Response` with no XML signature on the strength of the dereference channel alone. Optional, Profiles §4.1.4.4.
- `<AuthnRequest>` over HTTP-Artifact, and Single Logout over HTTP-Artifact. Optional, Bindings §3.6.
- The IdP operational mode and the SP operational mode. Conformance §3.1.
