# Web Browser SSO generation rules

`ServiceProvider::start_sso` writes the `AuthnRequest`. `IdentityProvider::respond_sso`, `initiate_sso`, `respond_sso_artifact`, and `initiate_sso_artifact` write the `Response`.

Normative text is Core, Profiles, and Bindings 2.0 as corrected by Approved Errata 05, and the HTTP-POST-SimpleSign CD-04 binding. [HTTP-Artifact response](web-browser-sso-artifact.md) covers delivery of a stored response, and [acceptance rules](web-browser-sso-acceptance.md) cover the receiving side. See [validation defaults](https://samlrs.vercel.app/explanation/validation-presets/) for the initial role policies.

[SimpleSign CD-04 §2.4](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html) makes the detached signature optional. For Web SSO messages that need no detached signature, use HTTP-POST if the peer supports it. The [Single Logout profile](single-logout.md) has its own authentication requirements.

## Service provider AuthnRequest

`start_sso` builds the request for HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `Issuer` as the service provider identifier, with `Format` omitted (the profile also permits `entity`) | Mandatory | Profiles §4.1.4.1 | Always |
| Write `ID`, `Version` `2.0`, and `IssueInstant` | Mandatory | Core §3.2.1, `RequestAbstractType` | Always |
| Write every time value in UTC, and never a leap second | Mandatory | Core §1.3.3 | Always |
| Write `Destination` on a signed request as the URL the user agent is sent to | Mandatory | Bindings §3.4.5.2, §3.5.5.2, CD-04 §2.4 | Always |
| Write `Destination` on an unsigned request too | Library policy: without it, the identity provider cannot discard a request that reaches an endpoint other than the one the service provider chose. | Core §3.2.1 | Always |
| Limit `RelayState` to 80 bytes | Mandatory | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | `RelayState::try_new` |
| Refuse a form `RelayState` with a CR or LF outside a CRLF pair | Library policy: HTML form submission sends the character as CRLF, so the receiver gets another value and a SimpleSign signature over it fails. | Bindings §3.5.4, CD-04 §2.3 | Always |
| Refuse a form `RelayState` with a character outside the XML `Char` production, such as U+0000 | Mandatory | Bindings §3.5.4, XML 1.0 §2.2 | Always |
| Keep the endpoint's own query parameters before the SAML parameters, and refuse an endpoint query that already has `SAMLRequest`, `SAMLResponse`, `SAMLart`, `RelayState`, `SigAlg`, `Signature`, or `SAMLEncoding`, by decoded name | Library policy: the bindings name these parameters, so a configured one can repeat a message field or be read as one by an endpoint that serves several bindings. | Bindings §3.4.4 | Always |
| Sign a request over HTTP-Redirect by removing any protocol `ds:Signature`, DEFLATE-encoding the XML, and signing `SAMLRequest`, `RelayState` when present, then `SigAlg` | Mandatory | Bindings §3.4.4.1 | `SpValidationPolicy::authn_request_signing` |
| When signing a SimpleSign request, sign the raw XML, then `RelayState` when present, then `SigAlg`. Preserve any XML signature | Mandatory | CD-04 §2.4, §2.5 | Always |
| Require `SigAlg` and `Signature` to send an `AuthnRequest` over SimpleSign | Library policy: choosing SimpleSign commits the SP to authenticating the request and binding any `RelayState` to it. | CD-04 §2.4, §2.7.2 | Always |
| Sign the request, and publish `AuthnRequestsSigned="true"` in the service provider metadata | Optional | Profiles §4.1.4.1, Bindings §3.4.5.2, §3.5.5.2, Metadata §2.4.4, E7 | `SpValidationPolicy::authn_request_signing` |
| Refuse to build an unsigned request when the identity provider publishes `WantAuthnRequestsSigned` as `true` or `1` | Library policy: E7 does not require the refusal, but the service provider can reasonably expect the identity provider to reject an unsigned request. | Metadata §2.4.3, E7 | `SpValidationPolicy::authn_request_signing` |
| Write `ForceAuthn` | Optional | Core §3.4.1 | `StartSso::force_authn` |
| Write `IsPassive` | Optional | Core §3.4.1 | `StartSso::passive` |
| Write supplied elements in call order inside `Extensions`, after `Issuer` and any embedded signature, before `NameIDPolicy` | Optional | Core §3.2.1, `RequestAbstractType`, `AuthnRequestType` | `StartSso::extension` |
| Require each extension's root to use a namespace. Reject the target namespace of every SAML V2.0 schema and the SAML V1.x assertion and protocol namespaces. Accept the namespaces of approved SAML extensions | Mandatory | Core §3.2.1, `ExtensionsType` | `ExtensionElement::from_xml` |
| Write `ProviderName` | Optional | Core §3.4.1, `AuthnRequestType` | `StartSso::provider_name` |
| Reject a `ProviderName` with a character XML 1.0 forbids | Library policy: the XML writer cannot represent the character. | `AuthnRequestType` | Always |
| Reject a `ProviderName` that is empty or has only XML whitespace | Mandatory | Core §1.3.1, `AuthnRequestType` | Always |
| Write `RequestedAuthnContext` with an explicit `Comparison`, after `NameIDPolicy`, with the references in the order given | Optional | Core §3.3.2.2.1, §3.4.1, E45 | `StartSso::requested_authn_context` |
| Reject a `RequestedAuthnContext` with no reference, or with both class and declaration references | Mandatory | `RequestedAuthnContextType` | Always |
| Reject a requested authentication context reference that is not an absolute URI reference | Mandatory | Core §1.3.2 | Always |
| For a non-transient format, write `AllowCreate="true"`. `NameIdCreationPolicy::DoNotAllowCreate` writes `false` instead | Recommended | Core §3.4.1.1, E14 | `SpValidationPolicy::name_id_creation` |
| Omit `AllowCreate` when the `NameIDPolicy` format is transient | Mandatory | Core §3.4.1.1, E14 | Always |
| Write the requested NameID format as an absolute URI reference | Mandatory | Core §1.3.2, §3.4.1.1 | Always |
| Request the first configured NameID format. With none configured, request the `emailAddress` format that the [generated metadata](metadata-and-replay.md#generating-metadata) advertises | Library policy: the request then asks for a format the service provider metadata advertises. | Core §3.4.1.1 | `name_id_format`, `name_id_formats` |
| Write the requested SP or affiliation as `NameIDPolicy@SPNameQualifier`. Omit it by default | Optional | Core §3.4.1.1, `NameIDPolicyType` | `StartSso::sp_name_qualifier` |
| Require the qualifier to be an absolute URI reference of at most 1024 characters with collapsed whitespace | Library policy: the API uses the syntax of a SAML entity identifier for the requested namespace. | Core §3.4.1.1, §8.3.6 | Always |
| Return an error when a qualifier is set and the requested format is `entity` | Library policy: no issued entity identifier can satisfy both request conditions. | Core §8.3.6, E15 | Always |
| Write `AssertionConsumerServiceURL` and `ProtocolBinding` from the default endpoint of the response binding, unless an index is set | Library policy: the request then names its endpoint explicitly. | Core §3.4.1 | `StartSso::acs_index` |
| Return `Cache-Control: no-cache, no-store` and `Pragma: no-cache` for the redirect, the POST form, and the SimpleSign form | Recommended | Bindings §3.4.5.1, §3.5.5.1, CD-04 §2.7.1 | Always |

### Not implemented in the service provider request

`start_sso` writes none of these optional parts of an `AuthnRequest`.

- A requested `Subject` that names the principal. Optional, Core §3.4.1, Profiles §4.1.4.1.
- `Conditions` for the issued assertion. Optional, Core §3.4.1. The identity provider may change or add to them.
- `Scoping`, with `IDPList`, `RequesterID`, and `ProxyCount`. Optional, Core §3.4.1.2. An application that proxies the request outside the crate applies Core §3.4.1.5 itself.
- `AttributeConsumingServiceIndex`. Optional, Core §3.4.1.
- An `AuthnRequest` without `NameIDPolicy`. Optional, Core §3.4.1. `start_sso` always writes one.

## Identity provider Response

`respond_sso` answers an `AuthnRequest`, and `initiate_sso` sends an unsolicited response.
`respond_sso_refusal` and `respond_sso_refusal_artifact` return an error for a
request that `receive_sso` refuses.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write an error `Response` with the status the caller passes and no assertion | Mandatory | Profiles §4.1.4.1, §4.1.4.2, Core §3.4.1.4 | `SsoOutcome::Failure` |
| Write a correlated SAML error for a refused request when a trusted ACS supports the selected response binding | Mandatory | Profiles §4.1.4.1, Metadata §2.4.4, E7, Core §3.2.2 | Always |
| Support delivery of an error when the user agent remains available and an acceptable response location exists | Recommended | Profiles §4.1.3.5, E85 | Always |
| Use the current metadata default ACS for an absent index mapping only for an error and when its binding matches the chosen delivery | Library policy: the IdP honors the requested index for assertions and uses current metadata to authorize the error route. | Core §3.4.1, Profiles §4.1.4.1, E85 | Always |
| Write caller-supplied plain text as `StatusMessage` after the complete `StatusCode` in a failed login `Response` before signing. Omit empty or unset text | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | `RespondSso::status_message` |
| Write only characters permitted in XML 1.0 in `StatusMessage` | Mandatory | [XML 1.0 §2.2](https://www.w3.org/TR/xml/#charsets) | Always |
| Reject a `StatusMessage` with no non-whitespace character | Mandatory | Core §1.3.1, §3.2.2.3 | `RespondSso::status_message` |
| Reject a subordinate `StatusCode` `Value` that is not an absolute URI reference, including one read from a received response | Mandatory | Core §1.3.2, §3.2.2.2 | `SsoOutcome::Failure` |
| Write a `Success` response only with an assertion, and reject `SsoOutcome::Failure` with a top-level `Success` status | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write an unsolicited error `Response` for a login the identity provider started | Optional | Profiles §4.1.4.2, §4.1.5 | `initiate_sso`, `initiate_sso_artifact` |
| Sign an error `Response` over HTTP-POST | Library policy: an error carries no assertion to sign, and the signature lets the service provider authenticate its status, `InResponseTo`, and `Destination`. | Profiles §4.1.3.5, §4.1.4.5, E26, E93, Bindings §3.5.5.2 | Always |
| Over HTTP-POST, sign each assertion when the service provider metadata sets `WantAssertionsSigned`, and sign the `Response` otherwise | Library policy: a `Response` signature also authenticates the status, `InResponseTo`, and `Destination`, and a service provider that asks for assertion signatures gets them. | Profiles §4.1.3.5, §4.1.6, E93 | `RespondSso::sign_response` |
| Write the issuing identity provider's identifier as `Response` `Issuer`, with `Format` omitted. The `Response` needs it when signed or when an assertion is encrypted, and the crate always writes it | Mandatory | Profiles §4.1.4.2, E17 | Always |
| Write `Destination` as the assertion consumer service URL. A signed message needs it, and the crate writes it on every response | Mandatory | Bindings §3.5.5.2, CD-04 §2.4 | Always |
| Write every time value in UTC, and never a leap second | Mandatory | Core §1.3.3 | Always |
| Match `InResponseTo`, on the `Response` and on the bearer `SubjectConfirmationData`, to the `AuthnRequest` `ID` | Mandatory | Core §3.2.2, Profiles §4.1.4.2, E26 | Always |
| Reject a response to a request whose `ID` is not an `xs:NCName`, because `InResponseTo` cannot carry it | Mandatory | Core §1.3.4, `StatusResponseType`, `SubjectConfirmationDataType` | Always |
| Omit `InResponseTo` from an unsolicited `Response`, including an error for a request whose `ID` cannot be determined | Mandatory | Core §3.2.2, Profiles §4.1.5 | Always |
| Omit `InResponseTo` from the bearer `SubjectConfirmationData` of an unsolicited response | Recommended | Profiles §4.1.5 | Always |
| Write a bearer assertion that has an `AuthnStatement` | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write `Issuer` on the assertion as the responding identity provider, with `Format` omitted (the profile also permits `entity`) | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write an `AudienceRestriction` for the service provider | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write `Recipient` and `NotOnOrAfter` on the bearer `SubjectConfirmationData`, and no `NotBefore` | Mandatory | Profiles §4.1.4.2, E26 | Always |
| Write the assertion `IssueInstant` as `Conditions` `NotBefore`, and end `Conditions` and the bearer `SubjectConfirmationData` at `IssueInstant` plus the issuance lifetime, 300 seconds by default | Library policy: the window starts when the assertion exists and bounds how long a bearer assertion can be delivered and replayed, and five minutes leaves time for the browser to deliver it. | Core §2.5.1.2, Profiles §4.1.4.2, E26 | `IdpConfigBuilder::issuance_lifetime` |
| Write `SessionIndex` on the `AuthnStatement` when the identity provider metadata advertises `SingleLogoutService` | Mandatory | Profiles §4.1.4.2, E26 | `IdpConfigBuilder::slo_endpoint` |
| Write the assertion ID as the `SessionIndex` | Recommended | Core §2.7.2 | Always |
| Write `AuthnInstant` and an `AuthnContext` on the `AuthnStatement` | Mandatory | Core §2.7.2, `AuthnStatementType` | Always |
| Write the caller's authentication time in UTC as `AuthnInstant` | Mandatory | Core §2.7.2, §1.3.3 | `SsoAssertion::authn_instant` |
| Write the caller's session deadline in UTC as `SessionNotOnOrAfter`. Omit it when unset | Optional | Core §1.3.3, §2.7.2, `AuthnStatementType`, E79 | `SsoAssertion::session_not_on_or_after` |
| Reject a supplied session deadline outside years 1 through 9999 | Library policy: this is the date range supported by the session time parser. | Core §1.3.3 | `SsoAssertion::session_not_on_or_after` |
| Write the assertion `IssueInstant` as `AuthnInstant` when the caller sets none | Library policy: reason not recorded. | Core §2.7.2 | `SsoAssertion::authn_instant` |
| Reject an `AuthnInstant` later than the response `IssueInstant` | Library policy: an assertion cannot report an authentication after it was issued. | Core §2.7.2 | `SsoAssertion::authn_instant` |
| Reject an `AuthnInstant` before year 1 | Library policy: the formatter writes a four-digit non-negative year. | Core §1.3.3 | `SsoAssertion::authn_instant` |
| Write the unspecified class as the authentication context when the caller sets none | Library policy: the schema requires a context, and that class is the Authentication Context class for unspecified means. | Core §2.7.2.2 | `SsoAssertion::authn_context` |
| Reject a success response whose context is not one of the requested references of the same kind, when `Comparison` is `exact` or omitted | Mandatory | Core §3.3.2.2.1 | `SsoAssertion::authn_context` |
| Reject an authentication context reference that is not an absolute URI reference, including one read from a received request | Mandatory | Core §1.3.2, §2.7.2.2 | `SsoAssertion::authn_context` |
| Write the issued `NameID` `Format` as an absolute URI reference. If unset, use the first configured format, and omit `Format` when there is none | Mandatory | Core §1.3.2, §2.2.2, E60 | Always |
| Write `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` from the issued `NameId`, and omit each one that is unset | Optional | `NameIDType` | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier`, `NameId::with_sp_provided_id` |
| Issue the `NameID` `Format` the `NameIDPolicy` names, when it is a Core §8.3 format other than `unspecified` or `encrypted` | Mandatory | Core §3.4.1.1, E15, `NameIDPolicyType` | Always |
| Issue the `SPNameQualifier` the `NameIDPolicy` names, under the same condition | Mandatory | Core §3.4.1.1, E15 | Always |
| Honor the requested `SPNameQualifier` namespace when `NameIDPolicy` omits `Format` or requests `unspecified`. A persistent or pairwise transient identifier can omit the qualifier for the direct SP namespace | Mandatory | Core §3.4.1.1, §8.3.7, §8.3.8 | Always |
| Write an `EncryptedID` in each issued assertion subject when `NameIDPolicy` names `encrypted` | Mandatory | Core §3.4.1.1, E6, E15, `SubjectType` | `XmlEncryptionPolicy::identifiers` |
| Issue a `Subject` that strongly matches the requested `<NameID>` in value, `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. Compare formats after `xs:anyURI` whitespace collapse, and read an omitted format as `unspecified` | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |
| Allow the `NameIDPolicy` `Format` to differ from the requested `<NameID>` format. The caller must establish that both identifiers name the same principal | Optional | Core §3.4.1.4, E75 | Always |
| Reject a success response to a requested `<BaseID>`, which an issued `<NameID>` cannot strongly match | Mandatory | Core §3.4.1.4, §3.3.4 | Always |
| Reject a success response to a requested `<EncryptedID>` that was not decrypted | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |
| Reject a success response when the requested `Subject` has `<SubjectConfirmation>` elements and none uses the bearer `Method`, the only one the assertion carries. Compare `Method` after `xs:anyURI` whitespace collapse | Mandatory | Core §3.4.1.4, §3.3.4, E75 | Always |
| Also reject it when every requested bearer `<SubjectConfirmation>` has an identifier or `<SubjectConfirmationData>` | Library policy: such data can constrain the recipient, time, or address in ways the issued bearer confirmation does not meet, and service providers must not send `<SubjectConfirmation>` (Profiles §4.1.4.1), so the crate does not compare it. | Core §3.3.4, §2.4.1.2 | Always |
| Return the exact `RelayState` received with the request, including a value over 80 bytes. Reject `RespondSso::relay_state` on a request that carried one | Mandatory | Bindings §3.1.1, §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Send a `RelayState` the identity provider chooses, when the request carried none or the response is unsolicited | Optional | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | `RespondSso::relay_state` |
| Limit a `RelayState` the identity provider chooses to 80 bytes | Mandatory | Bindings §3.5.3, CD-04 §2.3 | `RespondSso::relay_state` |
| Refuse a form `RelayState` with a CR or LF outside a CRLF pair, a received one included | Library policy: HTML form submission sends the character as CRLF, so the form cannot return the exact value. | Bindings §3.1.1, §3.5.4, CD-04 §2.3 | Always |
| Refuse a form `RelayState` with a character outside the XML `Char` production, such as U+0000, a received one included | Mandatory | Bindings §3.5.4, XML 1.0 §2.2 | Always |
| Protect each assertion over HTTP-POST by a signature on the assertion or on the `Response` | Mandatory | Profiles §4.1.4.5, §4.1.3.5, E26, E93 | Always |
| Protect each assertion in a stored HTTP-Artifact response with an assertion or `Response` signature | Optional | Profiles §4.1.3.5, E93 | Always |
| When signing a SimpleSign response, sign the raw XML, then `RelayState` when present, then `SigAlg`. Preserve any XML signatures | Mandatory | CD-04 §2.4, §2.5 | Always |
| Require `SigAlg` and `Signature` to send any `Response` over SimpleSign, including an error response | Library policy: the detached signature authenticates the response and binds any `RelayState` to it. | CD-04 §2.4, §2.7.2 | Always |
| Sign the `Response` that contains a CBC-encrypted assertion | Recommended | Profiles §4.1.3.5, E93 | `RespondSso::allow_unsigned_encrypted_cbc` |
| Return `Cache-Control: no-cache, no-store` and `Pragma: no-cache` for the POST form and the SimpleSign form | Recommended | Bindings §3.5.5.1, CD-04 §2.7.1 | Always |

### Encryption

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Encrypt each assertion as an `EncryptedAssertion` | Optional | Core §2.3.4 | `XmlEncryptionPolicy::assertions` |
| Encrypt each subject `NameID` as an `EncryptedID`, for the encryption certificate in the service provider metadata | Optional | Core §2.2.4, §3.4.1.1 | `XmlEncryptionPolicy::identifiers` |
| Encrypt each `Attribute` as an `EncryptedAttribute` | Optional | Core §2.7.3.2 | `XmlEncryptionPolicy::attributes` |
| Replace `NameID` with `EncryptedID` and `Attribute` with `EncryptedAttribute` in the same location. Each wrapper contains `EncryptedData` for the original element | Mandatory | Core §2.2.4, §2.7.3.2, §6.1, E30 | Always |
| Include `Type` on `EncryptedData` | Recommended | Core §2.2.4, §2.7.3.2, §6.1 | Always |
| Set a present `EncryptedData` `Type` to `http://www.w3.org/2001/04/xmlenc#Element` | Mandatory | Core §2.2.4, §2.7.3.2, §6.1 | Always |
| Encrypt the inclusive canonical form of the `NameID` or `Attribute` | Library policy: that form declares every namespace in scope. | Core §6.1 | Always |
| Embed the `EncryptedKey` in the `ds:KeyInfo` of `EncryptedData`, as `EncryptedAssertion` does | Optional | Core §6.2, E43 | Always |
| Encrypt the `NameID` or `Attribute` before the assertion or response is signed | Library policy: the signature then covers the ciphertext, and E43 and E93 replace the original Core §6.2 ordering rule. | Core §6.2, E43, E93 | Always |
| Encrypt for the first service provider encryption key the configured algorithms can use. Skip a key that does not load or that the crypto provider refuses, such as an EC key or an RSA key too small for the key transport | Library policy: E68 lets the encrypting party use any published key, and OpenSAML 5.2.0 also skips a credential without a usable key transport. | Metadata §2.4.1.1, E62, E68 | Always |
| Take the keys of the SP role whose `AssertionConsumerService` receives the response. When the request names only its location, and several roles publish that location and binding, take the first such role in document order | Library policy: E68 scopes keys to one role, and roles that publish one location and binding name one recipient, so document order picks one role's keys without mixing roles. | Metadata §2.4.1.1, E62, E68 | Always |
| Read one key from each `ds:X509Data` of a `KeyDescriptor` whose `use` is `encryption` or absent, in document order. Its sole certificate is the entity certificate, whatever else the `KeyInfo` declares. Among several certificates, the entity certificate is the first one that issued none of the others. If each issued another, it is the first certificate | Library policy: XML Signature allows the certificates of an `X509Data` in any order. OpenSAML 5.2.0 `InlineX509DataProvider` also reads one credential per `X509Data`, takes a sole certificate as the entity certificate, and falls back to the first certificate. When the crypto provider refuses a certificate signature, such as SHA-1, its signer does not count as having issued that certificate. | XML Signature §4.4, §4.4.4, Metadata §2.4.1.1 | Always |
| Look up that certificate only when the response has an element to encrypt | Library policy: a response without such an element uses no encryption key. | Core §2.7.3.2, E68 | Always |
| Name the chosen certificate in each `EncryptedKey`, as a `ds:X509Certificate` in the `ds:X509Data` of its `ds:KeyInfo` | Recommended | Metadata §2.4.1.1, E68, XML Encryption §3.5.1 | Always |

The identity provider encrypts with the configured `AlgorithmPolicy` algorithms. It does not read the optional `md:EncryptionMethod` elements of a `KeyDescriptor` (Metadata §2.4.1.1), so it neither chooses an algorithm from them nor prefers a key that lists the configured one. OpenSAML 5.2.0 `SAMLMetadataEncryptionParametersResolver` also keeps a credential whose listed methods it cannot use and encrypts with its configured algorithms.

## Endpoint selection

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Answer a request without an ACS URL, ACS index, or `ProtocolBinding` at the default `AssertionConsumerService`. Fail if that default is unsupported or incompatible with the selected response binding | Mandatory | Core §3.4.1, Profiles §4.1.6, Metadata §2.2.3 | Always |
| Take that default from the endpoints of the SAML 2.0 service provider role, before filtering by binding | Mandatory | Metadata §2.2.3, §2.4.1, E37 | Always |
| Choose the default endpoint as the first with `isDefault` true, else the first not false, else the first | Mandatory | Metadata §2.2.3 | Always |
| Read `isDefault` as an unqualified `xs:boolean`: `true`, `1`, `false`, or `0` with surrounding XML whitespace | Mandatory | `IndexedEndpointType` | Always |
| Answer a request that names only a `ProtocolBinding` at the first SAML 2.0 service provider role that publishes that binding, at the endpoint the `isDefault` rule chooses among that role's endpoints of that binding | Library policy: the role default can use another binding, and the requested binding must be honored, so the default rule applies to that binding's endpoints. | Core §3.4.1, Profiles §4.1.3.5, Metadata §2.2.3 | Always |
| Refuse a response binding that differs from the request's `ProtocolBinding` or from the binding of its indexed `AssertionConsumerService` | Mandatory | Profiles §4.1.3.5, Core §3.4.1 | Always |
| Deliver an unsolicited response to the default `AssertionConsumerService`. Fail if that default is unsupported or incompatible with the selected response binding | Recommended | Profiles §4.1.5 | Always |
| Read `WantAuthnRequestsSigned`, `AuthnRequestsSigned`, and `WantAssertionsSigned` as unqualified `xs:boolean`, and read an omitted one as false | Mandatory | Metadata §2.4.3, §2.4.4, `IDPSSODescriptorType`, `SPSSODescriptorType` | Always |
| On the selected SAML 2.0 role, reject a signing flag qualified with the metadata namespace or carrying an invalid `xs:boolean` value, and ignore same-named foreign attributes | Mandatory | `IDPSSODescriptorType`, `SPSSODescriptorType`, `RoleDescriptorType` | Always |

## Not implemented

The caller or the deployment handles these duties. The crate exposes the request through `Received<AuthnRequest>` and enforces none of them.

- Authenticate the principal directly when `ForceAuthn` is true, and do not freshly authenticate when `ForceAuthn` and `IsPassive` are both true unless the `IsPassive` constraints can be met. Mandatory for the identity provider, Core §3.4.1.
- Not visibly take control of the user interface when `IsPassive` is true. Mandatory for the identity provider and the user agent, Core §3.4.1.
- Judge the `minimum`, `better`, and `maximum` comparisons of `RequestedAuthnContext`. Mandatory, Core §3.3.2.2.1, E45.
- Answer a top-level `Responder` status, optionally with `NoAuthnContext`, when no requested context can be met. Mandatory, Core §3.3.2.2.1, E65. The caller passes `SsoOutcome::Failure`.
- Return an error `Response` with no assertions when authentication fails, the requested principal is unrecognized, or identity provider policy prevents issuance. Mandatory, Core §3.4.1.4, Profiles §4.1.4.1, §4.1.4.2, E75.
- Return an error `Response` with no assertions when the `NameIDPolicy` cannot be met, optionally with `InvalidNameIDPolicy`. Mandatory, Core §3.4.1.1.
- Return an error `Response` when `NameIDPolicy` requests both the `entity` format and an `SPNameQualifier`. No issued entity identifier can satisfy both. Mandatory, Core §8.3.6, E15.
- Provide independent `RelayState` integrity protection for HTTP-POST and unsigned Redirect. Recommended, Bindings §3.4.3, §3.5.3, E1. A signed Redirect or SimpleSign message already protects `RelayState` with the binding signature (CD-04 §2.3).

The assertion builder writes one assertion with one bearer `SubjectConfirmation`, one `AudienceRestriction` for the service provider, one `AuthnStatement`, and an `AttributeStatement` when the caller sets attributes. It does not write these optional forms:

- Additional `SubjectConfirmation` elements in a bearer assertion. Optional, Profiles §4.1.4.2, E26.
- `Address` on the bearer `SubjectConfirmationData`. Optional, Profiles §4.1.4.2, E26.
- More than one assertion, and statements other than the `AuthnStatement` and the `AttributeStatement`. Optional, Profiles §4.1.4.2, E26.
- `Advice`, conditions other than the `AudienceRestriction`, and other `Audience` values. Optional, Core §2.3.3, §2.5.1, Profiles §4.1.4.2, E26.
- `SubjectLocality`, `AuthenticatingAuthority`, an authentication context declaration by value, and a class reference together with a declaration. Optional, Core §2.7.2, §2.7.2.2.
- `Extensions` on the `Response`, and `StatusDetail` on an error. Optional, Core §3.2.2, §3.2.2.4.
- The requested `Conditions`. Profiles §4.1.4.2, E26, does not oblige the identity provider to honor them.
- The holder-of-key Web Browser SSO profile. Unsupported.
