# Single Logout rules

Rules for typed Single Logout: `start_slo`, `respond_slo`, and `finish_slo` on
both roles. `receive_slo` reads the same request-signature field as the accept
combination below. `LogoutPolicy::recommended`, and the `logout` field of
`SpValidationPolicy::recommended` and `IdpValidationPolicy::recommended`,
publish that accept combination. `Default`, `new`, `try_new`, and the
config builders are Recommended. Raw logout generation and parsing are
unchanged. The preset distinction is recorded in
[validation presets](../adr/0002-validation-presets.md).

Normative text is SAML Core 2.0, Profiles 2.0, and Bindings 2.0, as corrected
by Approved Errata 05. HTTP-POST-SimpleSign is the supported CD04 binding.
Schema citations are the OASIS protocol schema. A profile or binding rule is
used when it narrows Core for this flow.

`StartSlo::apply_single_logout_generation_rules` and
`RespondSlo::apply_single_logout_generation_rules` select the producer rules
below. The constructors `redirect`, `post`, and `simple_sign` leave that
selection off, which is the samlify-port generation kept for callers leaving
the raw API.

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
| Identify the principal with `NameID` | Session participant | Generate LogoutRequest | Mandatory. Profiles §4.4.4.1 and the schema's required identifier choice. Typed generation emits `NameID`. `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` are copied from the `LogoutSubject` `NameID` (Core §2.2.1 and §3.7.3.2). When that `NameID` has no `Format`, the first configured NameID format is used. An empty resolved format is omitted |
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
| `SessionIndex` may be omitted | Session authority | Generate LogoutRequest | Optional. Profiles §4.4.4.1 / E38 says the session authority `MAY` omit every `SessionIndex` to end the principal's applicable sessions. The participant's `MUST` include one is not copied onto this role |
| `Issuer`, `ID`, `Version` `2.0`, UTC `IssueInstant`, principal identifier, and no leap-second time | Session authority | Generate LogoutRequest | Mandatory. Same sources as the participant rows, including the subject's `NameID` `Format` and qualifiers. Enforced by the existing session-authority outbound checks, with and without producer rules |
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
| Send the response to `ResponseLocation` when present, otherwise `Location` | Responder | Generate LogoutResponse | Metadata §2.2.2. The endpoint is the first `SingleLogoutService` for the response binding. A `LogoutRequest` still uses that endpoint's `Location` |
| Deliver a service-provider response to an `https` `SingleLogoutService` | Session participant | Generate LogoutResponse | Recommendation. Profiles §4.4.3.4 recommends SSL or TLS for that HTTP exchange. Starts enabled when the service provider selects producer rules. The URL checked is the response destination above. `RespondSlo::allow_http_single_logout` relaxes it alone and leaves the response signed. The identity provider's response is §4.4.3.5, which does not repeat the recommendation, so `Saml<Idp>::respond_slo` does not gain the check |
| `LogoutRequest` issuer equals the peer descriptor entity ID | Responder | `respond_slo` | Library policy. The same guard as `respond_sso`. A mismatch returns `IssuerMismatch` and does not build a response for another party's `SingleLogoutService`. This is not an OASIS receiver requirement |
| Do not generate a leap-second time | Responder | Generate any instant | Mandatory. Core §1.3.3 |
| Top-level `StatusCode`, with an optional subordinate code | Session participant or session authority | Generate LogoutResponse | Core §3.2.2.2 requires `Success`, `Requester`, `Responder`, or `VersionMismatch`, and allows one subordinate code. Core §3.7.3.2: the session authority's top-level code reports only its own session; subordinate `PartialLogout` reports incomplete propagation. `respond_slo` writes the status the caller passes. Omitting it emits top-level `Success`. That omission is library policy, not an OASIS rule |

## Logout acceptance

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Authenticate a `LogoutRequest` by requiring its signature | Session participant or session authority receiving the request | Inbound `receive_slo` | Mandatory for HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. Core §3.7.3.1 and §3.7.3.2 require the recipient to authenticate the sender. Profiles §4.4.3.1 and §4.4.4.1 require the signature for these bindings. Accept combination: `LogoutPolicy.requests = RequireSigned`. `AllowUnsignedForCompatibility` is the samlify-port hatch |
| Authenticate a `LogoutResponse` by requiring its signature | Original requester finishing logout | Inbound `finish_slo` | Mandatory for those bindings. Profiles §4.4.3.4 and §4.4.4.2. Accept combination: `LogoutPolicy.responses = RequireSigned`. The unsigned variant is the samlify-port hatch, not a recommendation relaxation |
| UTC `IssueInstant` | Logout recipient | Inbound | Mandatory. No off switch. Inbound leap-second values stay accepted |
| A present `Destination` matches a published `Location` or `ResponseLocation` for the binding, and a signed message carries `Destination` | Logout recipient | Inbound | Mandatory. Core §3.2.1 and §3.2.2; Bindings §3.4.5.2 and §3.5.5.2; SimpleSign §2.4 when the message is signed. Metadata §2.2.2 allows more than one endpoint for a binding. Each published location is this recipient |
| Typed `InResponseTo` matches the pending `LogoutRequest` | Original requester | Inbound `finish_slo` | Mandatory for this typed exchange. Core §3.2.2 |
| Allow the validation-context clock skew on `LogoutRequest@NotOnOrAfter` | Logout recipient | Inbound | Recommendation. Approved Errata 05 E92 adds the Core §1.3.3 guidance to this attribute. A new `SamlValidationContext` allows the same five minutes used for assertion conditions. `ClockSkew::strict` is zero. An explicit skew replaces it. This is not a validation-preset field |
| Discard a `LogoutRequest` at or after its skew-adjusted `NotOnOrAfter` | Logout recipient | Inbound | Library policy. Core §3.7.1 says the recipient may discard the message after that instant. saml-rs rejects it at the exclusive skew-adjusted deadline. That rejection is not an OASIS receiver `MUST` and is not part of the accept combination |
| Embedded XML-signature algorithm profile | Logout recipient | Inbound | Library hardening. Off unless `XmlSignatureProfile::StrictRsaSha2` is selected. Independent of the logout accept combination |

An `http` `Destination` remains acceptable when it is the recipient's
endpoint. The TLS recommendation obligates the party sending the user agent.
It does not become a receiver rejection.

## Browser bindings

Typed logout send and receive use HTTP-Redirect, HTTP-POST, and
HTTP-POST-SimpleSign for `LogoutRequest` and `LogoutResponse`.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `RelayState` does not exceed 80 bytes | Either role | Generate and inbound | Mandatory prohibition. Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3. Integrity protection remains a recommendation |
| HTTP-Redirect removes a protocol `ds:Signature` before raw DEFLATE and signs or verifies `SAMLRequest` or `SAMLResponse`, `RelayState` when present, then `SigAlg` | Either role | Generate and inbound | Mandatory. Bindings §3.4.4.1. Generation rejects an unsigned redirect that still has a protocol signature. Inbound verification uses the original URL-encoded values. An absent `RelayState` is omitted |
| HTTP-POST-SimpleSign signs or verifies the raw XML octets, then `RelayState` when present, then `SigAlg` | Either role | Generate and inbound | Mandatory when that binding is used. CD-04 §2.5 and §2.6. An XML signature inside the message stays |
