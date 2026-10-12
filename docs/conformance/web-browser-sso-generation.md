# Web Browser SSO generation rules

Producer rules for typed Web Browser SSO generation: service-provider
`start_sso`, and identity-provider `respond_sso` and `initiate_sso`.
`SpValidationPolicy::recommended` leaves AuthnRequest signing and identifier
creation off. `IdpValidationPolicy::recommended` does not turn assertion
encryption on. `Default`, `new`, `try_new`, and the config builders are
Recommended. Raw generation is unchanged. The preset distinction is
recorded in
[validation presets](../adr/0002-validation-presets.md).

Normative text is SAML Core 2.0, Profiles 2.0, and Bindings 2.0, as corrected
by Approved Errata 05. HTTP-POST-SimpleSign is the supported CD04 binding.
Schema citations are the OASIS assertion and protocol schemas. A profile or binding rule is used when it narrows Core for this flow.

`StartSso::apply_web_browser_sso_generation_rules` and
`RespondSso::apply_web_browser_sso_generation_rules` select the producer rules below.
The constructors `redirect`, `post`, and `simple_sign` leave that selection
off, which is the samlify-port generation kept for callers leaving the raw
API.

## Service provider AuthnRequest

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `Issuer` is present, is the service provider's identifier, and omits `Format` or sets it to `entity` | Service provider | Generate AuthnRequest | Mandatory. Profiles §4.1.4.1 |
| `ID`, `Version` `2.0`, and UTC `IssueInstant` are present | Service provider | Generate AuthnRequest | Mandatory. Protocol schema `RequestAbstractType`; Core §1.3.3 |
| Do not generate a leap-second time | Service provider | Generate any instant | Mandatory. Core §1.3.3 `MUST NOT` generate leap seconds. Receivers are not required to reject them |
| If the AuthnRequest is signed, `Destination` is the URL where the user agent is sent | Service provider | Generate AuthnRequest | Mandatory when the message is signed. Bindings §3.4.5.2 and §3.5.5.2 |
| `RelayState` does not exceed 80 bytes | Service provider | Generate AuthnRequest | Mandatory prohibition. Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3. Integrity protection remains a recommendation |
| HTTP-Redirect removes a protocol `ds:Signature`, raw-DEFLATEs the rest, and signs `SAMLRequest`, `RelayState` when present, then `SigAlg` | Service provider | Generate AuthnRequest | Mandatory. Bindings §3.4.4.1. An assertion signature stays. An unsigned redirect that still has a protocol signature is rejected. An absent `RelayState` is omitted |
| HTTP-POST-SimpleSign signs the raw XML octets, then `RelayState` when present, then `SigAlg` | Service provider | Generate AuthnRequest | Mandatory when that binding is used. CD-04 §2.5 and §2.6. An XML signature inside the message stays |
| Do not emit `AllowCreate` when the requested name-identifier format is `transient` | Service provider | Generate AuthnRequest | Mandatory prohibition. Core §3.4.1.1 as replaced by Errata 05 E14. Enforced only when producer rules are selected. Samlify-port generation still emits the attribute |
| Sign the AuthnRequest | Service provider | Generate AuthnRequest | Optional for this profile. Profiles §4.1.4.1 says the request `MAY` be signed as directed by the binding. Bindings §3.4.5.2 and §3.5.5.2 say the encoded message `MAY` be signed. Core §3.4.1's general `SHOULD` is not applied on top of that profile rule. Stays off unless `AuthnRequestSigningPolicy::Sign`. That choice does not make the identity provider reject an unsigned request |
| `ForceAuthn` | Service provider | Generate AuthnRequest | Optional. Core §3.4.1, default false when omitted. Stays omitted unless `StartSso::force_authn` |
| Identifier creation (`AllowCreate="true"`) | Service provider | Generate AuthnRequest | Optional capability. Errata 05 E14 says a requester that does not make specific use of the attribute `SHOULD` generally set it to true, and the schema default is false when the attribute is omitted. `NameIdCreationPolicy` is that specific use. The capability stays off (`AllowCreate="false"`) unless `NameIdCreationPolicy::AllowCreate`. It is not emitted at all for a transient format when producer rules are selected. An empty `Format` is omitted under those rules because it is not a format URI; Core treats a missing `Format` as unspecified. Typed service providers with no configured format already advertise and request `emailAddress` |

## Identity provider Response

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An error `Response` carries the caller-supplied status and no assertions | Identity provider | Generate Response | Mandatory prohibition on assertions. Profiles §4.1.4.2, which E26 does not replace: if the identity provider returns an error, it MUST NOT include any assertions. Profiles §4.1.4.1 requires that response when the request cannot be satisfied, including when the requested subject is not recognized. Core §3.4.1.4 requires a `Status` describing the error when the presenter cannot be authenticated, the requested subject is not recognized, or local policy prevents an assertion. `RespondSso::status` writes the `Status` the caller passes. A top-level code other than `Success` omits assertions. Omitting `status` emits `Success` and the assertions. That omission is library policy for the successful path. The caller chooses any subordinate code, such as `NoPassive` or `AuthnFailed`. The library does not infer one. A login response template cannot carry this response |
| Error `Response` `Issuer`, `InResponseTo`, and `Destination` follow the successful response | Identity provider | Generate Response | The successful-response rows below. `Issuer` is always present. A solicited `InResponseTo` matches the `AuthnRequest` `ID` (Core §3.2.2). An unsolicited `InResponseTo` is omitted when producer rules are selected, and remains an empty attribute in samlify-port generation (Core §3.2.2 and Profiles §4.1.5). `Destination` is the assertion consumer service URL |
| HTTP-POST signs an error `Response` | Identity provider | Generate Response | Library policy. Profiles §4.1.4.5 as replaced by E26 protects each assertion by a signature on the assertion or the `Response`. An error `Response` has no assertion, so that requirement does not apply. Typed HTTP-POST still signs the `Response`, which is how a signed message carries `Destination` (Bindings §3.5.5.2). HTTP-POST-SimpleSign keeps its detached signature over the response octets |
| A successful response contains at least one bearer assertion with an `AuthnStatement` | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2 as replaced by Errata 05 E26, including a response that is not tied to a request. Enforced when producer rules are selected. Samlify-port generation still omits the statement, and receivers are not given a new rejection for that omission |
| `AuthnInstant` and `AuthnContext` accompany that statement | Identity provider | Generate Response | Mandatory schema children of `AuthnStatement` (Core §2.7.2) once the statement is emitted. `AuthnInstant` is the assertion `IssueInstant` because the typed subject has no separate authentication time. That equality is library policy. The class `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` is the Authentication Context class for unspecified means |
| `SessionIndex` on each authentication statement when this identity provider supports Single Logout | Identity provider | Generate Response | Mandatory when Single Logout is supported. Profiles §4.1.4.2 / E26. Support here means the identity provider metadata advertises `SingleLogoutService`. The value is the assertion `ID`, one of the two approaches Core §2.7.2 lists as `RECOMMENDED` for privacy. No `SessionIndex` is emitted when logout is not advertised |
| Bearer `SubjectConfirmationData` has `Recipient` and `NotOnOrAfter`, and no `NotBefore` | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2 / E26 |
| Bearer assertion `Issuer` is the responding identity provider, with `Format` omitted or `entity` | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2 / E26 |
| Bearer assertion includes `AudienceRestriction` for the service provider | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2 / E26 |
| Response `Issuer` is present when the response is signed or an assertion is encrypted | Identity provider | Generate Response | Mandatory when that condition holds. Errata 05 E17. Typed responses always include it |
| Solicited response `InResponseTo` matches the AuthnRequest `ID` | Identity provider | Generate Response | Mandatory. Core §3.2.2. The same match is required on bearer `SubjectConfirmationData` by Profiles §4.1.4.2 / E26 |
| Unsolicited response omits `InResponseTo` | Identity provider | Generate Response | Mandatory prohibition. Core §3.2.2 and Profiles §4.1.5. Bearer subject confirmation data omits it as well: Profiles §4.1.5 says it should not be present, and E26 requires the service provider to verify that it is absent. Samlify-port generation still emits an empty attribute |
| When the request names neither an ACS URL nor an ACS index, `Destination` is the default `AssertionConsumerService` for the response binding | Identity provider | Generate Response | Profiles §4.1.4.1. Metadata §2.2.3 selects, among endpoints for that binding, the first with `isDefault` true, otherwise the first whose `isDefault` is not false, otherwise the first. `true` and `1` are true. `false` and `0` are false. The same endpoint is `AssertionConsumerServiceURL` when `start_sso` does not select an index |
| HTTP-POST protects each assertion by a signature on the assertion or on the response | Identity provider | Generate Response | Mandatory for HTTP-POST. Profiles §4.1.4.5 as replaced by E26, and §4.1.3.5 as replaced by E93. Existing typed POST signing already does this |
| Sign a response that contains a CBC `EncryptedAssertion` | Identity provider | Generate Response | Recommendation. Errata 05 E93. Starts enabled on `RespondSso::post` and `RespondSso::simple_sign`. `RespondSso::allow_unsigned_encrypted_cbc` relaxes that recommendation alone. It is not the Compatibility preset. It does not add a receiver rejection; a relying party that already requires the signature still rejects the relaxed response |
| Assertion encryption | Identity provider | Generate Response | Optional. Stays off unless `XmlEncryptionPolicy::encrypt_assertions` |
| Do not generate a leap-second time | Identity provider | Generate any instant | Mandatory. Core §1.3.3 |
| `RelayState` does not exceed 80 bytes | Identity provider | Generate Response | Mandatory prohibition. Bindings §3.5.3 and HTTP-POST-SimpleSign CD-04 §2.3 |
| HTTP-POST-SimpleSign signs the raw XML octets, then `RelayState` when present, then `SigAlg` | Identity provider | Generate Response | Mandatory when that binding is used. CD-04 §2.5 and §2.6. An assertion signature stays |

Direct Assertion signatures and the RSA-SHA2 XML signature profile are
library hardening on acceptance. They are not turned on by these producer
rules.
