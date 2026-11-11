# Single Logout rules

Rules for typed Single Logout: `start_slo`, `respond_slo`, and `finish_slo` on
both roles. `receive_slo` reads the same request-signature field as the accept
combination below. `LogoutPolicy::recommended`, and the `logout` field of
`SpValidationPolicy::recommended` and `IdpValidationPolicy::recommended`,
publish that accept combination. `Default`, `new`, `try_new`, and the
config builders are Recommended. Raw logout generation and parsing keep
their existing validation defaults. The preset distinction is recorded in
[validation presets](../adr/0002-validation-presets.md).

Normative text is SAML Core 2.0, Profiles 2.0, and Bindings 2.0, as corrected
by Approved Errata 05. HTTP-POST-SimpleSign is the supported CD04 binding.
Schema citations are the OASIS protocol schema. A profile or binding rule is
used when it narrows Core for this flow.

`StartSlo::apply_single_logout_generation_rules` and
`RespondSlo::apply_single_logout_generation_rules` select the producer rules
below. The constructors `redirect`, `post`, and `simple_sign` leave that
selection off, which is the samlify-port generation kept for callers leaving
the raw API. `soap` always selects it. The SOAP rules are in
[SOAP binding](#soap-binding).

`finish_slo` reads `LogoutPolicy::responses`. The accept combination is
`LogoutSignaturePolicy::RequireSigned` for both `requests` and `responses`.
`LogoutPolicy::compatibility` remains the legacy permissive unsigned hatch.
`LogoutPolicy::recommended` is the accept combination. `LogoutPolicy::default`
matches it.

## LogoutRequest from a session participant

`Saml<Sp>::start_slo` is this actor. Profiles §4.4.3.1 and §4.4.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `Issuer` is present and omits `Format` or sets it to `entity` | Session participant | Generate LogoutRequest | Mandatory. Profiles §4.4.4.1. Enforced when producer rules are selected |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Session participant | Generate LogoutRequest | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| Do not generate a leap-second time | Session participant | Generate any instant | Mandatory. Core §1.3.3 `MUST NOT` generate leap seconds. Receivers are not required to reject them |
| Identify the principal with `NameID` | Session participant | Generate LogoutRequest | Mandatory. Profiles §4.4.4.1 and the schema's required identifier choice. Typed generation emits `NameID`, or `EncryptedID` when [selected](#encrypted-principal-identifier) |
| Send the `NameID` with the attributes the principal is known by | Session participant | Generate LogoutRequest | Mandatory. Core §3.7.1 names the identifier and its associated attributes as currently recognized by both providers. Typed generation copies `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from the `LogoutSubject` `NameId`. When the `NameId` has no `Format`, the request omits it. Core §2.2.2 treats an omitted `Format` as unspecified (§8.3.1), so a custom template may write that URI for such a `NameId`. When producer rules are selected, the outbound check rejects a custom template that drops or changes these attributes. It compares `Format` after `anyURI` whitespace collapse. A `Format` that is not an absolute URI reference is `SamlError::Invalid` with or without producer rules ([identifiers](identifiers.md#name-identifier-formats)), also when the `NameId` came from an accepted assertion |
| Include at least one `SessionIndex` | Session participant | Generate LogoutRequest | Mandatory. Profiles §4.4.4.1 as replaced by Errata 05 E38. Enforced when producer rules are selected. Samlify-port generation may omit it |
| Sign the message on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign | Session participant | Generate LogoutRequest | Mandatory for these bindings. Profiles §4.4.3.1 requires a signature for HTTP POST and HTTP Redirect. §4.4.4.1 requires the requester to authenticate by signing or a binding-specific mechanism; SimpleSign's mechanism is its signature. Core §3.7.1's general `SHOULD` is not applied on top of that profile rule. `LogoutSigning::DoNotSignForCompatibility` is rejected when producer rules are selected. Samlify-port generation may still omit the signature. Requiring it on generation does not add a receiver rule; the recipient's duty to authenticate is the separate accept rule below |
| Send the user agent to an `https` `SingleLogoutService` | Session participant | Generate LogoutRequest | Recommendation. Profiles §4.4.3.1 recommends SSL or TLS for the HTTP exchange. saml-rs follows it by requiring an `https` location. `StartSlo::allow_http_single_logout` relaxes that recommendation alone. A recipient does not reject `http` in `Destination` because of it |
| `NotOnOrAfter` | Session participant | Generate LogoutRequest | Optional. The schema marks it optional, and Core §3.7.3.2 assigns the duty to set it to the session authority only. Typed session-participant generation does not synthesize it |
| `Reason` | Session participant | Generate LogoutRequest | Optional. Core §3.7.3. Default generation omits it. Errata 05 E10 requires a URI when a producer includes the attribute. This crate does not emit `Reason` and does not add a receiver rejection for its form |

## LogoutRequest from a session authority

`Saml<Idp>::start_slo` is this actor. Core §3.7.3.2 and Profiles §4.4.3.3 and
§4.4.4.1.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Set `NotOnOrAfter` | Session authority | Generate LogoutRequest | Mandatory. Core §3.7.3.2. Always emitted from the configured issuance lifetime and the same `IssueInstant`. It cannot be disabled. The five-minute lifetime is library policy, not an OASIS duration |
| Compare `NotOnOrAfter` with the latest assertion `NotOnOrAfter` | Session authority | Generate LogoutRequest | Outside this operation. Core §3.7.3.2 `SHOULD` compares the request instant with the assertion most recently issued for the session. Typed `start_slo` does not receive that assertion. [ADR 0001](../adr/0001-session-authority-logout-expiration.md) records that the issuance lifetime does not claim that ordering. It is not a preset field and it has no relaxation switch |
| Send the `NameID` with the attributes the principal is known by | Session authority | Generate LogoutRequest | Mandatory. Core §3.7.1. Same behaviour as the participant row, except for a `NameId` without a `Format`: the request carries the first configured NameID format, which is the `Format` `respond_sso` writes in the assertion for that `NameId`. With no configured format both omit `Format`: Core §1.3.2 does not allow an empty URI value, and Core §2.2.2 with Errata 05 E60 puts `unspecified` in effect when `Format` is omitted. Samlify-port `create_logout_request` omits it the same way. A `Format` that is not an absolute URI reference is `SamlError::Invalid`, as for the participant. `respond_sso` writes the `NameID` value, `Format`, and `SPProvidedID`, so the caller passes `NameQualifier` and `SPNameQualifier` only when its assertion carried them. The outbound check always runs for this role |
| `SessionIndex` may be omitted | Session authority | Generate LogoutRequest | Optional. Profiles §4.4.4.1 / E38 says the session authority `MAY` omit every `SessionIndex` to end the principal's applicable sessions. The participant's `MUST` include one is not copied onto this role |
| `Issuer`, `ID`, `Version` `2.0`, UTC `IssueInstant`, principal identifier, and no leap-second time | Session authority | Generate LogoutRequest | Mandatory. Same sources as the participant rows. Enforced by the existing session-authority outbound checks, with and without producer rules |
| Sign the message on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign | Session authority | Generate LogoutRequest | Mandatory for these bindings. Profiles §4.4.4.1. Same signing behaviour as the participant when producer rules are selected |
| Send the user agent over TLS | Session authority | Generate LogoutRequest | Not applied. Profiles §4.4.3.1 states that recommendation for the session participant's request. §4.4.3.3 does not repeat it |

Propagating logout to every other participant is outside one `start_slo` or
`respond_slo` call. Each call addresses one peer.

## LogoutResponse

`respond_slo` on either role. Profiles §4.4.3.4, §4.4.3.5, and §4.4.4.2.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Answer a `LogoutRequest` with a `LogoutResponse` | Responder | Generate LogoutResponse | Mandatory. Core §3.7.2. `respond_slo` is that answer |
| `Issuer` is present and omits `Format` or sets it to `entity` | Responder | Generate LogoutResponse | Mandatory. Profiles §4.4.4.2. Typed response generation already rejects a message that breaks this |
| Sign the message on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign | Responder | Generate LogoutResponse | Mandatory for these bindings. Profiles §4.4.3.4 requires a signature when the response returns to the identity provider over HTTP POST or Redirect. §4.4.4.2 requires the responder to authenticate. Typed `respond_slo` always signs. There is no off switch, including under the samlify-port preset |
| Send the response to `ResponseLocation` when present, otherwise `Location` | Responder | Generate LogoutResponse | Metadata §2.2.2/E41. The first `SingleLogoutService` for the response binding supplies the URL. Requests use its `Location`. XML Schema `anyURI` whitespace is collapsed; foreign attributes do not control routing |
| Read the peer's `SingleLogoutService` from its role descriptor | Requester and responder | Generate LogoutRequest and LogoutResponse | Metadata §2.4.2 defines `SingleLogoutService` on each `SSODescriptorType`, and Profiles §4.4.5 names it as this profile's endpoint. An `SpDescriptor` supplies its `SPSSODescriptor` endpoints and an `IdpDescriptor` its `IDPSSODescriptor` endpoints. An entity that plays both roles is never addressed at its other role's endpoint. Raw `SpMetadata` and `IdpMetadata` read the same way; `Metadata::parse` reads every SSO role |
| Deliver a service-provider response to an `https` `SingleLogoutService` | Session participant | Generate LogoutResponse | Recommendation. Profiles §4.4.3.4 recommends SSL or TLS for that HTTP exchange. Starts enabled when the service provider selects producer rules. The URL checked is the response destination above. `RespondSlo::allow_http_single_logout` relaxes it alone and leaves the response signed. The identity provider's response is §4.4.3.5, which does not repeat the recommendation, so `Saml<Idp>::respond_slo` does not gain the check |
| Return the exact RelayState received with the request, on a binding that carries RelayState | Responder | Generate LogoutResponse | Mandatory. Bindings §3.1.1, §3.4.3, and §3.5.3. HTTP-POST-SimpleSign responses echo it the same way. `respond_slo` writes the RelayState of `Received<LogoutRequest>`: absent, present empty, and present value stay distinct. `RespondSlo` has no setter to replace or drop it. `RespondSlo::soap` returns `ProtocolProfile` for a request that carried RelayState. Bindings §3.4.3 lets a responder add RelayState to a response whose request had none; the Single Logout profile defines no such use, so `respond_slo` does not offer it |
| `LogoutRequest` issuer equals the peer descriptor entity ID | Responder | `respond_slo` | Library policy. The same guard as `respond_sso`. A mismatch returns `IssuerMismatch` and does not build a response for another party's `SingleLogoutService`. This is not an OASIS receiver requirement |
| Do not generate a leap-second time | Responder | Generate any instant | Mandatory. Core §1.3.3 |
| Top-level `StatusCode`, with an optional subordinate code | Session participant or session authority | Generate LogoutResponse | Core §3.2.2.2 requires `Success`, `Requester`, `Responder`, or `VersionMismatch`, and allows one subordinate code. Core §3.7.3.2: the session authority's top-level code reports only its own session; subordinate `PartialLogout` reports incomplete propagation. `respond_slo` writes the status the caller passes. Omitting it emits top-level `Success`. That omission is library policy, not an OASIS rule. Core §1.3.2 makes the `Value` of a subordinate code an absolute URI reference, read as in [identifiers](identifiers.md#name-identifier-formats). `SubordinateStatusCode::try_new` returns `SamlError::Invalid` for one that is not. It also rejects whitespace and `&`, `"`, `'`, `<`, and `>`, which is library policy. The outbound check reads `Consent`, each `StatusCode` `Value`, and the `Issuer` by the same rule, and rejects whitespace in them, which is library policy |

## Logout acceptance

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Authenticate a `LogoutRequest` by requiring its signature | Session participant or session authority receiving the request | Inbound `receive_slo` | Mandatory for HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. Core §3.7.3.1 and §3.7.3.2 require the recipient to authenticate the sender. Profiles §4.4.3.1 and §4.4.4.1 require the signature for these bindings. Accept combination: `LogoutPolicy.requests = RequireSigned`. `AllowUnsignedForCompatibility` is the samlify-port hatch. It does not apply to SOAP |
| Authenticate a `LogoutResponse` by requiring its signature | Original requester finishing logout | Inbound `finish_slo` | Mandatory for those bindings. Profiles §4.4.3.4 and §4.4.4.2. Accept combination: `LogoutPolicy.responses = RequireSigned`. The unsigned variant is the samlify-port hatch, not a recommendation relaxation |
| UTC `IssueInstant` | Logout recipient | Inbound | Mandatory. No off switch. Inbound leap-second values stay accepted |
| A present `Destination` matches the actual receiving URL, and a signed message carries `Destination` | Logout recipient | Inbound | Mandatory. Core §§3.2.1, 3.2.2; Bindings §§3.4.5.2, 3.5.5.2; SimpleSign §2.4. `with_recipient_endpoint` supplies the URL, or a unique URL published in the local role descriptor for the binding and direction is inferred. Explicit selection for multiple endpoints and the published-URL restriction are library policy |
| Accept the response over any front-channel binding both entities support | Original requester | Inbound `finish_slo` | Profiles §4.4.3.4 and §4.4.3.5: after an asynchronous request, the responder MAY answer over any asynchronous binding both entities support. So a request sent over HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign accepts a response over any of the three that the local metadata publishes. The `Destination` is compared with the local `SingleLogoutService` for the binding the response arrived on; a binding the local metadata does not publish returns `MissingMetadata`. Library policy, kept behaviour: a SOAP response to a front-channel request, or a front-channel response to a SOAP request, returns `UnsupportedBinding`. §4.4.3.4 describes the responder returning a synchronous request's response on the same exchange; it is not an OASIS receiver requirement |
| Typed `InResponseTo` matches the pending `LogoutRequest` | Original requester | Inbound `finish_slo` | Mandatory for this typed exchange. Core §3.2.2 |
| `RelayState` the request carried comes back unchanged | Original requester | Inbound `finish_slo` | Library policy. Bindings §3.4.3 and §3.5.3 oblige the responder to return the exact value and have no receiver rule. A different, empty, or missing value returns `SamlError::RelayStateMismatch`. An empty value the request carried is compared the same way |
| `RelayState` the responder adds to a request that carried none is accepted | Original requester | Inbound `finish_slo` | Optional for the responder. Bindings §3.4.3 and §3.5.3 let it include RelayState, to be interpreted by profile or prior agreement. An empty value is accepted the same way. `LogoutCompleted::relay_state` reports the value |
| A status other than `Success` is returned as an error | Original requester | Inbound `finish_slo` | `SamlError::StatusNotSuccess` with both codes. Library policy: the status is read only after the signature, `Issuer`, `InResponseTo`, and `Destination` checks pass, so an unauthenticated or unrelated error response returns that check's error. No OASIS rule orders these checks |
| A `Success` response returns its subordinate code | Original requester | Inbound `finish_slo` | Core §3.2.2.2 allows one subordinate `StatusCode`, and Core §3.7.3.2 uses `PartialLogout` under `Success` to report that the session authority could not log out every other session participant. `LogoutResponse::status` returns the top-level code and the subordinate code as received. `LogoutCompleted::status` stays the top-level URI. No receiver rejection is added for the subordinate value |
| Return the `NameID` with the attributes it was received with | Logout recipient | Inbound `receive_slo` | Core §3.7.1 names the identifier and its associated attributes. Core §3.7.3.1 applies the request to assertions whose subject strongly matches it (§3.3.4). `LogoutRequest::name_id` carries the received `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. A `Format` that is not an absolute URI reference is reported as sent, as in [identifiers](identifiers.md#name-identifier-formats) |
| Allow the validation-context clock skew on `LogoutRequest@NotOnOrAfter` | Logout recipient | Inbound | Recommendation. Approved Errata 05 E92 adds the Core §1.3.3 guidance to this attribute. A new `SamlValidationContext` allows the same five minutes used for assertion conditions. `ClockSkew::strict` is zero. An explicit skew replaces it. This is not a validation-preset field |
| Discard a `LogoutRequest` at or after its skew-adjusted `NotOnOrAfter` | Logout recipient | Inbound | Library policy. Core §3.7.1 says the recipient may discard the message after that instant. saml-rs rejects it at the exclusive skew-adjusted deadline. That rejection is not an OASIS receiver `MUST` and is not part of the accept combination |
| XML-signature algorithm profile, for an embedded signature and a detached `SigAlg` | Logout recipient | Inbound | Library hardening. Off unless `XmlSignatureProfile::StrictRsaSha2` is selected in `SpValidationPolicy` or `IdpValidationPolicy`. Recommended uses `ExcludeWeakAlgorithms`, library policy that excludes [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys). Independent of the logout accept combination |

An `http` `Destination` remains acceptable when it is the recipient's
endpoint. The TLS recommendation obligates the party sending the user agent.
It does not become a receiver rejection.

## Encrypted principal identifier

`StartSlo::identifier_encryption` and `receive_slo` on both roles, on
HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and SOAP. Conformance
Requirements §3.4 requires every relevant operational mode to process or
generate `<saml:EncryptedID>` wherever it processes or generates
`<saml:NameID>`, and Core §3.7.1 lets a `LogoutRequest` carry either. These
rows do not claim the IdP or SP operational mode.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send the principal as `EncryptedID` | Session participant or session authority | Generate LogoutRequest | Optional. Core §3.7.1. Off until `StartSlo::identifier_encryption` selects `IdentifierEncryptionPolicy::EncryptIdentifiers`, matching `XmlEncryptionPolicy::encrypt_ids` for the assertion. That configuration field does not select it. The `<NameID>` is replaced in the same location (Core §6.1) after the outbound checks and before signing, so the signature covers the `EncryptedID`. Its plaintext is the inclusive canonical form of the `<NameID>`, as for the assertion |
| Encrypt for the responder's `KeyDescriptor` with `use="encryption"` | Requester | Generate LogoutRequest | Profiles §4.4.5. The first encryption certificate in the peer metadata is used, with the configured data and key encryption algorithms. A peer without one returns `MissingMetadata` |
| Process a received `EncryptedID` | Logout recipient | Inbound `receive_slo` | Mandatory. Conformance Requirements §3.4. Decrypted with the local `decryption_key` whatever the configured `XmlEncryptionPolicy`, and returned as the request `NameID`. The `EncryptedKey` is found as for the assertion `EncryptedID`. A receiver without a `decryption_key` cannot process it: the request is accepted with no `NameID`, as before, so its `SessionIndex` values stay usable. A plaintext `NameID` is still accepted: no receiver rule requires the encrypted form |
| One `BaseID`, `NameID`, or `EncryptedID` | Logout recipient | Inbound `receive_slo` | Mandatory. Protocol schema `LogoutRequestType`. Checked when an `EncryptedID` is present. Another count returns `ProtocolProfile` |
| The plaintext is one `<NameID>` in the assertion namespace | Logout recipient | Inbound `receive_slo` | Library policy, as for the assertion `EncryptedID`. A `<BaseID>`, which Core allows, returns `Unsupported`. Any other content returns `ProtocolProfile`. The decrypted request is validated again against the protocol profile |
| Decrypt only an authenticated request | Logout recipient | Inbound `receive_slo` | Library policy. A verified signature, or a `SoapChannel` that authenticates the peer, must cover the `EncryptedID`, so unauthenticated ciphertext never reaches the decryptor. An unsigned request accepted under `LogoutPolicy::compatibility` keeps its `EncryptedID` unread and has no `NameID` |
| Outstanding logout uses the decrypted `NameID` | Session participant | Inbound `finish_sso_with_outstanding_logout` | Core §3.7.3.1. The `NameID` that `receive_slo` returns is the plaintext, so an `OutstandingLogout` built from it matches later assertions for the same principal |

## Browser bindings

Typed logout send and receive use HTTP-Redirect, HTTP-POST, and
HTTP-POST-SimpleSign for `LogoutRequest` and `LogoutResponse`.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `RelayState` does not exceed 80 bytes | Either role | Generate and inbound | Mandatory prohibition. Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3. Integrity protection remains a recommendation |
| HTTP-Redirect removes a protocol `ds:Signature` before raw DEFLATE and signs or verifies `SAMLRequest` or `SAMLResponse`, `RelayState` when present, then `SigAlg` | Either role | Generate and inbound | Mandatory. Bindings §3.4.4.1. Generation rejects an unsigned redirect that still has a protocol signature. Inbound verification uses the original URL-encoded values. An absent `RelayState` is omitted |
| HTTP-POST-SimpleSign signs or verifies the raw XML octets, then `RelayState` when present, then `SigAlg` | Either role | Generate and inbound | Mandatory when that binding is used. CD-04 §2.5 and §2.6. An XML signature inside the message stays |
| Base64 message content and the detached `Signature` value ignore ASCII whitespace and reject any other character outside the alphabet | Either role | Inbound | Library policy. Bindings §3.4.4.1 and §3.5.4 encode the message with RFC 2045 base64, and RFC 2045 §6.8 says a decoder ignores characters outside the base64 alphabet. Space, tab, line feed, form feed, and carriage return are ignored. Any other character, including vertical tab and Unicode spaces, is rejected. The looser rule is not applied because Bindings §3.4.4.1 requires the sender to remove whitespace and §3.5.4 allows only line wrapping, so any other character means the value was altered, and ignoring it would hide that. HTTP-POST-SimpleSign uses the same decoder. The detached `Signature` value of HTTP-Redirect and HTTP-POST-SimpleSign follows the same rule; Bindings §3.4.4.1 also requires the sender to remove whitespace from it |

## SOAP binding

`StartSlo::soap` and `RespondSlo::soap` run the four calls over the SAML SOAP
binding, the synchronous exchange that [artifact resolution](artifact-resolution.md)
uses. `Outbound::soap_request` is the envelope the deployment POSTs to the
peer. `BrowserInput::soap` reads a received envelope. `Outbound::soap_response`
is the envelope the deployment returns as the HTTP 200 body. TLS and HTTP
authentication stay with the deployment, as in artifact resolution. saml-rs
does not open the connection.

This claims the IdP and SP cells of Single Logout (IdP-initiated) – SOAP and
Single Logout (SP-initiated) – SOAP in Conformance Requirements Table 2. Those
cells are `OPTIONAL` for IdP Lite and SP Lite, and this flow does not claim
them. It does not claim the IdP or SP operational mode.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Send the request on a synchronous binding, and return the response on the same exchange | Requester and responder | SOAP exchange | Optional binding. Profiles §4.4.3.1 lets the session participant use SOAP, and §4.4.3.3 lets the session authority use it. §4.4.3.4 returns the response directly. `respond_slo` does not record the binding a request arrived on, so the caller answers `BrowserInput::soap` with `RespondSlo::soap` |
| Exactly one SAML request or response in the SOAP body | Requester and responder | SOAP envelope | Mandatory. Bindings §3.2.2.1, as left by Errata 05 E19. The envelope is `SoapProtocolMessage`. A header with SOAP `mustUnderstand`, a `Header` after the `Body`, and a second `Header` are refused, as in artifact resolution |
| The requester authenticates itself and protects integrity by signing the `LogoutRequest` | Session participant or session authority | Generate LogoutRequest | Mandatory. Profiles §4.4.3.1 and §4.4.4.1 require signing or a binding-supported mechanism. Typed SOAP generation always signs. `LogoutSigning::DoNotSignForCompatibility` is rejected |
| The responder authenticates itself and protects integrity by signing the `LogoutResponse` | Responder | Generate LogoutResponse | Mandatory. Profiles §4.4.3.4 and §4.4.4.2. Typed `respond_slo` always signs |
| Authenticate a received SOAP `LogoutRequest` or `LogoutResponse` | Logout recipient | Inbound `receive_slo` and `finish_slo` | Mandatory. Core §3.7.3.1 requires the recipient to authenticate the message. Profiles §4.4.4.1 and §4.4.4.2 allow an XML signature or a binding-supported mechanism. `BrowserInput::soap` requires the XML signature under every `LogoutPolicy`, including `compatibility`, because saml-rs does not see the TLS session. `BrowserInput::soap_with_channel` takes the deployment's `SoapChannel`: when it attests mutual authentication and integrity, an unsigned message is accepted, and a present signature is still verified. The caller attests only a TLS or HTTP credential that belongs to the peer descriptor |
| Single Logout generation rules always apply | Session participant or session authority | Generate LogoutRequest | `StartSlo::soap` selects them. A session participant includes at least one `SessionIndex`, Profiles §4.4.4.1 as replaced by Errata 05 E38. A session authority sets `NotOnOrAfter`, Core §3.7.3.2. There is no samlify-port SOAP generation to keep |
| No RelayState | Requester and responder | Generate | Library policy. RelayState is defined by the HTTP bindings, Bindings §3.4.3 and §3.5.3. The SOAP binding, Bindings §3.2, has no place to carry it, so a present `relay_state` is rejected rather than dropped |
| `LogoutRequest` `Destination` is the peer SOAP `SingleLogoutService` `Location` | Requester | Generate LogoutRequest | Core §3.2.1 makes `Destination` optional. Typed generation sets it |
| A present `LogoutRequest` `Destination` matches the local SOAP `SingleLogoutService` | Logout recipient | Inbound `receive_slo` | Mandatory. Core §3.2.1. A signed SOAP request without `Destination` is accepted. Bindings §3.4.5.2 and §3.5.5.2 require it only for HTTP-Redirect and HTTP-POST |
| `LogoutResponse` omits `Destination` | Responder | Generate LogoutResponse | Core §3.2.2 makes `Destination` optional. The response returns on the requester's own HTTP exchange, which has no URL to name. A logout-response template that writes one is rejected |
| A present `LogoutResponse` `Destination` is not compared | Original requester | Inbound `finish_slo` | Core §3.2.2 compares `Destination` with the location where the recipient received the message. A SOAP response arrives on the HTTP exchange the requester opened, not at a requester endpoint, so there is no location to compare. `ArtifactResolution::finish` treats `ArtifactResponse` the same way |
| Send the exchange over TLS | Session participant | SOAP exchange | Not applied. Profiles §4.4.3.1 and §4.4.3.4 recommend TLS for the asynchronous bindings only. Conformance Requirements §3.5 leaves SOAP transport security to the deployment. `allow_http_single_logout` has no effect on SOAP |
| Publish a SOAP `SingleLogoutService` | Either role | Metadata | Recommendation. Bindings §3.2.3.4 and Profiles §4.4.5. `SloEndpoint::soap` publishes it. A SOAP endpoint's `ResponseLocation` is not used |
| `SOAPAction`, `Cache-Control`, `Pragma`, and `Content-Type` | Requester and responder | HTTP | Bindings §3.2.3 and §3.2.3.2. `SoapRequest` and `SoapResponse` report the values. saml-rs does not send them |
| A SAML error is a `LogoutResponse` status, not a SOAP fault | Responder | SOAP exchange | Errata 05 E19. Pass the status to `RespondSlo::status`. A request `receive_slo` cannot read returns `SamlError`, and the deployment can answer HTTP 500 with a SOAP fault, Bindings §3.2.3.3 |

Propagating logout to other participants over SOAP, which Profiles §4.4.3.1
recommends after a SOAP request, is outside one call. Generating an unsigned
SOAP message, HTTP-Artifact logout, and the IdP Lite and SP Lite SOAP cells
are outside this flow.
