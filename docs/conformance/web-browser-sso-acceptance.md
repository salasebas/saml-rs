# Web Browser SSO acceptance

<a id="web-browser-sso-acceptance-rules"></a>

`ServiceProvider::finish_sso`, `accept_unsolicited_sso`, and their
outstanding-logout variants `finish_sso_with_outstanding_logout` and
`accept_unsolicited_sso_with_outstanding_logout` accept a Web Browser SSO
`Response` over HTTP-POST and HTTP-POST-SimpleSign, and
`accept_unsolicited_sso_with_resolver` accepts one over HTTP-POST. The
service provider rows apply to each of these operations on the bindings it
accepts. `IdentityProvider::receive_sso` accepts an `AuthnRequest` over
HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign. `SpValidationPolicy` and
`IdpValidationPolicy` select the options, and the
[validation defaults](https://samlrs.vercel.app/explanation/validation-presets/)
list their defaults.

Normative text is Core 2.0, Profiles 2.0 §4.1, and Bindings 2.0 as corrected
by [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/),
and the HTTP-POST-SimpleSign
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html)
(CS-01). The scoped attribute rows cite the
[Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/saml-subject-id-attr-v1.0.html)
and the [saml2int deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).
[Browser bindings](browser-bindings.md) has the decoding,
[base64](browser-bindings.md#base64), `RelayState`, and signature-input rules
that every browser flow shares. A `Response` delivered by HTTP-Artifact
follows the HTTP-POST rows here where
[HTTP-Artifact response](web-browser-sso-artifact.md) states no difference.
[Single Logout](single-logout.md) and
[metadata trust and replay](metadata-and-replay.md) have their own records.

<a id="builds-without-a-crypto-provider"></a>

The statuses hold on builds with a crypto provider. A build without one
verifies no signature and decrypts nothing, so its service provider
establishes no session, reports the status of an unsigned error `Response`,
and refuses a signed one. Its identity provider refuses a signed
`AuthnRequest`, and reads an unsigned one without decrypting a requested
`EncryptedID`.

## Support

### Service provider: delivery and signatures

| Feature | Section | Service provider |
| --- | --- | --- |
| `Response` by HTTP-POST | Profiles §4.1.3.5, Bindings §3.5 | Supported |
| `Response` by HTTP-POST-SimpleSign | CS-01 §2.4 | Supported |
| `Response` by HTTP-Artifact, with an XML signature on the `Response` or on each assertion of a successful one | Profiles §4.1.3.5, Bindings §3.6, E93 | Supported |
| Successful `Response` by HTTP-Artifact without an XML signature | Profiles §4.1.3.5, §4.1.4.4, E93 | Not supported |
| Unsolicited `Response` | Profiles §4.1.5 | Supported |
| Selection of the identity provider by the `Issuer` of an unsolicited `Response` | Profiles §4.1.5, E17 | [Partial](#identity-provider-lookup-for-an-unsolicited-response) |
| Error `Response` | Profiles §4.1.4.2, Core §3.2.2.2 | Supported |
| `StatusMessage` in an error `Response` | Core §3.2.2.1, §3.2.2.3 | Supported |
| `RelayState` with the `Response` | Bindings §3.5.3, CS-01 §2.3, Profiles §4.1.5 | Supported |
| `InResponseTo` and `Destination` of the `Response` | Core §3.2.2 | Supported |
| XML signature on the `Response` or on each assertion | Profiles §4.1.4.5, E26 | Supported |
| SimpleSign `SigAlg` and `Signature` on the `Response` | CS-01 §2.4 to §2.6 | [Partial](browser-bindings.md#detached-signatures) |
| Unsigned error `Response` | Core §3.2.2, Profiles §4.1.4.5, E26 | Supported |
| `WantAssertionsSigned` in the service provider's metadata | Metadata §2.4.4, Profiles §4.1.6 | Supported |
| Namespace names compared after normalizing the declaration value | Namespaces in XML 1.0 §2.3 | [Partial](#namespace-declarations-with-character-references) |

[XML Signature and XML Encryption algorithms](xml-security-algorithms.md) has
the algorithms that each build verifies and decrypts, and
[HTTP-Artifact response](web-browser-sso-artifact.md) the artifact delivery.

### Service provider: assertions and statements

| Feature | Section | Service provider |
| --- | --- | --- |
| Several assertions in one `Response`, with or without a bearer `SubjectConfirmation` | Profiles §4.1.4.2, E26 | Supported |
| `EncryptedAssertion`, alone or beside plaintext assertions | Core §2.3.4, §3.3.3, Conformance §3.4 | Supported |
| `EncryptedID` that carries a `NameID`, in an assertion `Subject` | Core §2.2.4, §2.4.1 | Supported |
| `EncryptedAttribute` | Core §2.7.3.2 | Supported |
| `EncryptedID` that carries a `BaseID` or an `Assertion` | Core §2.2.4 | Not supported |
| `NameID` in the assertion `Subject` | Core §2.2.3, §2.4.1 | Supported |
| An assertion `Subject` without an identifier | Core §2.4.1 | Supported |
| `BaseID` in the assertion `Subject` | Core §2.2.1, §2.4.1 | Not supported |
| Several `AuthnStatement` elements | Profiles §4.1.4.2, E26 | Supported |
| `AuthnInstant`, `SessionIndex`, and `SubjectLocality` | Core §2.7.2, §2.7.2.1 | Supported |
| `AuthnContextClassRef`, `AuthnContextDeclRef`, and `AuthenticatingAuthority` | Core §2.7.2.2 | Supported |
| `AuthnContextDecl` by value | Core §2.7.2.2 | [Partial](#authncontextdecl-by-value) |
| `SessionNotOnOrAfter` | Core §2.7.2, Profiles §4.1.4.3, E26 | Supported |
| `AttributeStatement` | Core §2.7.3, Profiles §4.1.4.2 | Supported |
| Check of scoped attribute values after acceptance | Subject Identifier §4.2, saml2int SDP-SP17 | Supported |

[Identifiers](identifiers.md) has the rules for the `NameID` and the
attributes that the session reports.

### Service provider: confirmation and conditions

| Feature | Section | Service provider |
| --- | --- | --- |
| Bearer `SubjectConfirmation` with `Recipient`, `NotOnOrAfter`, and `InResponseTo` | Profiles §4.1.4.3, E26 | Supported |
| Check of the bearer `Address` against the client address | Profiles §4.1.4.3 | Not supported |
| Confirmation by holder-of-key, sender-vouches, or another method | Profiles §3.1, §3.2, E26 | Not supported |
| `Conditions` `NotBefore` and `NotOnOrAfter` | Core §2.5.1.2 | Supported |
| `AudienceRestriction` | Core §2.5.1.4, E46 | Supported |
| `ProxyRestriction` | Core §2.5.1.6 | Supported |
| A `Condition` of an extension type | Core §2.5.1.1, §2.5.1.3 | Not supported |

[Metadata and replay](metadata-and-replay.md#replay-detection) has the status
of replay detection and of `OneTimeUse`, and
[Single Logout](single-logout.md#sessions-and-propagation) the status of
applying a logout to an assertion that arrives later.

### Identity provider: `AuthnRequest`

| Feature | Section | Identity provider |
| --- | --- | --- |
| `AuthnRequest` by HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign | Profiles §4.1.3.3, Bindings §3.4, §3.5, CS-01 §2.4 | Supported |
| `AuthnRequest` by HTTP-Artifact | Profiles §4.1.3.3, Bindings §3.6 | Not supported |
| `RelayState` with the request | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Supported |
| Unsigned `AuthnRequest` | Profiles §4.1.4.1 | Supported |
| XML signature on the request | Profiles §4.1.4.1, Core §3.2.1 | Supported |
| HTTP-Redirect or SimpleSign `SigAlg` and `Signature` on the request | Bindings §3.4.4.1, CS-01 §2.4 to §2.6 | [Partial](browser-bindings.md#detached-signatures) |
| `WantAuthnRequestsSigned` in the identity provider's metadata | Metadata §2.4.3, E7 | Supported |
| `AuthnRequestsSigned` in the service provider's metadata | Metadata §2.4.4, E7 | Supported |
| Error `Response` to a request that the identity provider refuses | Profiles §4.1.4.1, Core §3.2.1 | [Partial](#error-response-to-a-refused-request) |
| `Destination` | Core §3.2.1 | Supported |
| Namespace names compared after normalizing the declaration value | Namespaces in XML 1.0 §2.3 | Supported |
| `ForceAuthn`, `IsPassive`, and `ProviderName` | Core §3.4.1 | Supported |
| `RequestedAuthnContext` | Core §3.3.2.2.1, §3.4.1 | Supported |
| `NameIDPolicy` | Core §3.4.1, §3.4.1.1 | Supported |
| Requested `Subject` with a `NameID` | Core §3.4.1 | Supported |
| Requested `Subject` with an `EncryptedID` that carries a `NameID` | Core §2.2.4, §3.4.1, Conformance §3.4 | Supported |
| Requested `Subject` with an `EncryptedID` that carries a `BaseID` or an `Assertion` | Core §2.2.4, §3.4.1 | Not supported |
| Requested `Subject` with a `BaseID` | Core §2.2.1, §3.4.1 | [Partial](#requested-baseid) |
| `SubjectConfirmation` in the requested `Subject` | Core §3.4.1, Profiles §4.1.4.1, E75 | Supported |
| `AssertionConsumerServiceURL`, `AssertionConsumerServiceIndex`, and `ProtocolBinding` | Core §3.4.1, Profiles §4.1.4.1 | Supported |
| `AttributeConsumingServiceIndex` | Core §3.4.1, Metadata §2.4.4.1 | Not supported |
| `Conditions` in the request | Core §3.4.1 | Not supported |
| `Scoping`, and proxying the request to another identity provider | Core §3.4.1.2, §3.4.1.5 | Not supported |

`Consent` and caller extensions are in
[common message fields](common-message-fields.md), and
[SSO generation](web-browser-sso-generation.md#identity-provider-response)
has how `respond_sso` answers the request.

## Partial support

<a id="detached-signatures"></a>

[Browser bindings](browser-bindings.md#detached-signatures) explains the
`Partial` detached signatures of both roles.

### Identity provider lookup for an unsolicited `Response`

- **Supported:** `accept_unsolicited_sso_with_resolver` selects a configured
  identity provider by the `Issuer` of an unsolicited HTTP-POST `Response`.
- **Not supported:** it refuses HTTP-POST-SimpleSign and HTTP-Artifact. For
  those bindings, the caller selects the `IdpDescriptor` and calls
  `accept_unsolicited_sso`.

### Namespace declarations with character references

- **Supported:** the service provider reads a `Response` whose protocol and
  assertion namespace declarations spell the namespace without character
  references.
- **Not supported:** an otherwise valid `Response`, over HTTP-POST or
  HTTP-POST-SimpleSign or resolved from an artifact, can fail when a
  declaration spells the protocol or assertion namespace with an XML
  character reference, because the protocol profile and assertion condition
  checks compare raw namespace bindings. No option changes it, and Namespaces
  in XML 1.0 §2.3 requires comparing the normalized values.

[Namespaces in XML 1.0 §2.3](https://www.w3.org/TR/REC-xml-names/#NSNameComparison)
defines the comparison.
[SimpleSAMLphp 6.0.0](https://github.com/simplesamlphp/saml2/blob/v6.0.0/src/Binding/HTTPPost.php#L89-L105)
passes normalized DOM names to its HTTP-POST message reader.

### Error `Response` to a refused request

- **Supported:** `receive_sso` returns refusal data for a request that
  passed its signature, `Issuer`, and `Destination` checks and that the
  identity provider refuses for its signature policy, a `ProtocolBinding`
  the `Response` cannot use, content it cannot read, a repeated
  `NameIDPolicy`, or its age. `respond_sso_refusal` and
  `respond_sso_refusal_artifact` build the error `Response` and return the
  browser action that the application sends.
- **Not supported:** an error `Response` to a request that fails a check made
  before its signature is verified: the `XmlPolicy` schema check and the
  protocol profile, which covers qualified attributes, elements in a
  foreign namespace, and a `Version` other than `2.0`. Nor to a request
  whose decrypted requested `Subject` the `XmlPolicy` schema check refuses.
  Nor to a request whose signature does not verify: Core §3.2.1 recommends
  an error but forbids relying on the content that names the requester and
  the `ID` to answer. `receive_sso` returns the error, and the identity provider
  application shows a local error page.

### Requested `BaseID`

- **Supported:** `receive_sso` accepts a requested `Subject` that holds a
  `BaseID` and reports it as `RequestedSubjectIdentifier::BaseId`, and the
  identity provider answers it with an error `Response`.
- **Not supported:** a successful `Response`, whose assertion `Subject`
  would need an identical `BaseID` (Core §3.3.4, §3.4.1.4), and the
  identifier in the `BaseID`, as [identifiers](identifiers.md#not-supported)
  records.

### `AuthnContextDecl` by value

- **Supported:** the service provider accepts an `AuthnContext` that holds
  an `AuthnContextDecl`, under the content rule below, and
  `AuthnContext::has_declaration` reports it.
- **Not supported:** no accessor returns the content of the declaration.

## Rules

<a id="service-provider"></a>

### Service provider: signatures

Code: `src/sp.rs`, `src/flow.rs`, `src/flow/embedded.rs`, `src/flow/detached.rs`, `src/flow/error_response.rs`, `src/browser/input.rs`, `src/crypto/verify.rs`, `src/model/sso.rs`, `src/metadata/generate.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For HTTP-POST, require an XML signature on the successful `Response` or on each assertion | Mandatory | Profiles §4.1.4.5, E26, E93 | Always |
| Verify every signature on the `Response` and on its assertions, including decrypted ones, and rely on no `Response` or assertion whose signature fails | Mandatory | Profiles §4.1.4.3, E26, Core §2.3.3, §3.2.2 | Always |
| Require a signature on the `Response` when an `EncryptedAssertion` uses AES-CBC or Triple DES | Recommended | Core §6.2, Profiles §4.1.4.3, E93 | `ResponseSignaturePolicy::AllowUnsignedEncryptedCbc` relaxes it |
| Require `SigAlg` with a SimpleSign `Signature` | Mandatory | CS-01 §2.6 | Always |
| Permit an unsigned error `Response` | Optional | Core §3.2.2, Profiles §4.1.4.5, E26 | Always |
| Report each verified embedded signature that covers the `Response` or directly covers the selected assertion, including after SimpleSign verification or assertion decryption | Optional | Core §5.4, CS-01 §2.4 to §2.6 | `SsoSession::verified_xml_signatures` |
| Write `WantAssertionsSigned="true"` in the generated service provider metadata | Optional | Metadata §2.4.4 | `AssertionSignaturePolicy::RequireSigned` |

[XML Signature and XML Encryption algorithms](xml-security-algorithms.md#inbound-xml-signature-verification)
keeps the verifier rules of both roles: the
[weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys)
that `XmlSignatureProfile::AllowWeakAlgorithms` accepts again, and
`XmlSignatureProfile::StrictRsaSha2`, which the default profile does not
select.

### Service provider: encrypted elements

Code: `src/flow.rs`, `src/flow/embedded.rs`, `src/encrypted_elements.rs`, `src/crypto/enc.rs`, `src/crypto/enc/decrypt.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Decrypt each `EncryptedAssertion`, each `EncryptedID` in an assertion `Subject`, and each `EncryptedAttribute`, whatever `XmlEncryptionPolicy` selects. Evaluate each decrypted assertion as a plaintext one. Without a decryption key, an encrypted assertion or `NameID` leaves nothing to accept, and an `EncryptedAttribute` is not decoded | Mandatory | Conformance §3.4, Core §2.3.4, §2.2.4, §2.7.3.2 | Always |
| Verify a signature that covers a CBC-encrypted `EncryptedID` or `EncryptedAttribute` before decrypting it | Recommended | Core §6.2, E93 | Always |
| Reject an `EncryptedAssertion` that holds anything but one `EncryptedData` followed only by `EncryptedKey` elements | Mandatory | Core §2.3.4, `EncryptedElementType` | Always |

The [key resolution rules](xml-security-algorithms.md#key-resolution) and
their [limits](xml-security-algorithms.md#not-implemented-in-the-decrypter)
apply to each encrypted element the service provider receives.

### Service provider: assertion selection and content

Code: `src/assertion_acceptance.rs`, `src/model/sso.rs`, `src/model/extract.rs`, `src/model/authn_details.rs`, `src/model/authn_statement.rs`, `src/xml/profile.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Evaluate the selected bearer assertion on its own: bearer confirmation, audience, `Conditions` children and window, and `SessionNotOnOrAfter` | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Discard an unselected assertion that is invalid or cannot be confirmed: the session reads no value from it, and its bearer confirmation, audience, `Conditions`, and `SessionNotOnOrAfter` do not reject the response | Recommended | Profiles §4.1.4.3, E26 | Always |
| Reject a response whose assertions repeat an `ID`, compared after XML whitespace collapse, including after decryption and without an embedded signature | Mandatory | XML 1.0 VC: ID, `AssertionType`, XML Schema Part 2 §3.3.8 | Always |
| Reject the selected assertion when it has a second `Issuer` or a second `Subject`, even when only one `Subject` holds a `NameID` | Recommended | `AssertionType`, Profiles §4.1.4.3 | Always |
| Treat the `Subject` identifier of the selected assertion as optional. Without one, report no `NameID` | Mandatory | Core §2.4.1, `SubjectType` | `SsoSession::name_id` |
| Without a direct `NameID`, reject a `Subject` child other than `SubjectConfirmation`, `BaseID`, or `EncryptedID` | Mandatory | `SubjectType` | Always |
| In the selected bearer assertion, require `AuthnInstant`, exactly one direct SAML `AuthnContext`, and at most one direct SAML `SubjectLocality` in each `AuthnStatement` | Mandatory | Core §2.7.2, `AuthnStatementType` | Always |
| Require each such `AuthnContext` to hold a class reference, a declaration or declaration reference, or a class reference and one of those, with no second class reference or declaration | Recommended | Core §2.7.2.2, `AuthnContextType`, Profiles §4.1.4.3 | Always |
| Reject the selected assertion when its `Issuer`, its `Subject` `NameID`, or an `AuthnContextClassRef`, `AuthnContextDeclRef`, or `AuthenticatingAuthority` of such an `AuthnContext` holds a child element, instead of reading the text around it | Recommended | `AssertionType`, `NameIDType`, `AuthnContextType`, Profiles §4.1.4.3 | Always |
| Require each such `AuthnInstant` to be a UTC `xs:dateTime`. A leap second is accepted, as for `IssueInstant` | Recommended | Core §1.3.3, §2.7.2, Profiles §4.1.4.3 | Always |
| Reject an `Assertion` `IssueInstant` that is not UTC. A leap second is accepted | Recommended | Core §1.3.3, Profiles §4.1.4.3 | Always |
| Expose the context and locality of each accepted statement. Keep references and authorities in document order and collapse URI whitespace | Optional | Core §2.7.2, §2.7.2.1, §2.7.2.2 | `AuthnStatement::authn_context`, `AuthnStatement::subject_locality` |
| Permit schema-allowed foreign attributes on `SubjectConfirmationData` and `Attribute`. Read bearer checks and SAML attribute names, formats, and labels from unqualified attributes | Mandatory | Core §2.4.1.2, §2.7.3.1, `SubjectConfirmationDataType`, `AttributeType`, Profiles §4.1.4.3, E26 | Always |

### Service provider: bearer confirmation

Code: `src/assertion_acceptance.rs`, `src/flow.rs`, `src/model/validation.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Identify bearer confirmations by the bearer URI after collapsing XML whitespace in `Method`. Use the same comparison for assertion selection, confirmation, and replay expiry | Mandatory | Core §1.3.2, §2.4.1.1, `SubjectConfirmationType`, Profiles §4.1.4.3, E26 | Always |
| Verify that a bearer confirmation's `NotOnOrAfter` has not passed and its whitespace-collapsed `Recipient` matches the assertion consumer URL. For a solicited response, also match the whitespace-collapsed `InResponseTo` to the request ID | Mandatory | Profiles §4.1.4.3, E26, `SubjectConfirmationDataType`, XML Schema Part 2 §4.3.6 | Always |
| Require the selected bearer assertion of a solicited or unsolicited response to have one satisfied confirmation whose `Recipient` matches the receiving assertion consumer URL | Mandatory | Core §3.2.2, Profiles §4.1.3, §4.1.4.3, E26 | `SamlValidationContext::with_recipient_endpoint` |
| Accept one satisfied confirmation as sufficient to confirm the assertion | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Leave a bearer confirmation without `NotOnOrAfter` unsatisfied, because its expiry cannot be verified | Mandatory | Profiles §4.1.4.3, E26, E52 | Always |
| Leave a bearer confirmation of an unsolicited response unsatisfied when it carries `InResponseTo`, empty or not. Another bearer confirmation can still confirm the assertion | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Reject a bearer confirmation whose `NotBefore` has not been reached, after skew. A `NotBefore` that has been reached is accepted | Mandatory | Core §2.4.1.2, Profiles §4.1.4.2, §4.1.4.3, E26 | Always |

### Service provider: conditions and time windows

Code: `src/assertion_acceptance.rs`, `src/validator.rs`, `src/model/extract.rs`, `src/model/sso.rs`, `src/model/validation.rs`, `src/xml/date_time.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject the selected assertion when a `Conditions` child is not understood | Mandatory | Core §2.5.1.1 | Always |
| Reject the selected assertion when its `Conditions`, `AudienceRestriction`, `OneTimeUse`, or `ProxyRestriction` carries an attribute that its type does not declare, unqualified or in a namespace. Namespace declarations do not count | Mandatory | Core §2.5.1.1, `ConditionsType`, `AudienceRestrictionType`, `OneTimeUseType`, `ProxyRestrictionType` | Always |
| Reject the selected bearer assertion when any `AudienceRestriction` lacks the SP's entity ID among its whitespace-collapsed `Audience` values | Mandatory | Core §2.5.1.1, §2.5.1.4, E46, XML Schema Part 2 §4.3.6 | Always |
| Reject the selected assertion when an `Audience` of its `AudienceRestriction` holds a child element | Mandatory | Core §2.5.1.1, `AudienceRestrictionType` | Always |
| Accept `OneTimeUse` and `ProxyRestriction`. The SP keeps no assertion of its own and issues no later assertion. The [application duties](metadata-and-replay.md#onetimeuse-application-duties) cover the returned session | Mandatory | Core §2.5.1.5, §2.5.1.6 | Always |
| Read `Conditions@NotBefore` and `NotOnOrAfter` only as a UTC `xs:dateTime`. A value with an offset or no time zone fails the check | Mandatory | Core §1.3.3, §2.5.1.1 | Always |
| Read bearer `SubjectConfirmationData@NotBefore` and `NotOnOrAfter`, and `AuthnStatement@SessionNotOnOrAfter`, only as a UTC `xs:dateTime`. A value with an offset or no time zone fails its check | Recommended | Core §1.3.3, §2.4.1.2, §2.7.2, Profiles §4.1.4.3, E79 | Always |
| Require `NotBefore` to precede `NotOnOrAfter` when both appear in `Conditions` or bearer `SubjectConfirmationData`. Compare the bounds before applying clock skew | Mandatory | Core §2.4.1.2, §2.5.1.1, §2.5.1.2, E92 | Always |
| Allow five minutes of clock skew on `NotBefore` and `NotOnOrAfter` | Recommended | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew`, `ClockSkew::strict` |
| Reject an assertion whose earliest `SessionNotOnOrAfter`, widened by the `NotOnOrAfter` skew, has passed | Recommended | Profiles §4.1.4.3, E26, E79, E92 | `SamlValidationContext::with_clock_skew` |
| Expose the earliest explicit `SessionNotOnOrAfter` of the consumed assertion, before clock skew and as a `SystemTime`, so the application can cap its session | Optional | Profiles §4.1.4.3, E26, E79 | `SsoSession::session_not_on_or_after` |

[Metadata and replay](metadata-and-replay.md#replay) keeps the rules that
treat `OneTimeUse` as valid, report it with `SsoSession::is_one_time_use`, and
retain each bearer assertion `ID` with a replay cache.

### Service provider: response fields and `Destination`

Code: `src/api/sp.rs`, `src/flow.rs`, `src/flow/response_issuer.rs`, `src/model/validation.rs`, `src/model/status.rs`, `src/xml/protocol_element.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a second direct `Issuer` on the `Response` | Mandatory | Core §3.2.2, `StatusResponseType` | Always |
| For the session, correlation, repeated-ID, and replay checks, read the `Response` `ID`, `IssueInstant`, `Destination`, and `InResponseTo`, and the assertion `ID` and `IssueInstant`, only from unqualified attributes | Mandatory | `StatusResponseType`, `AssertionType` | Always |
| Compare a present `Destination` with the receiving URL after collapsing XML whitespace. Require it on a signed browser POST response | Mandatory | Core §3.2.2, Bindings §3.5.5.2, CS-01 §2.4, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| Reject a top-level `StatusCode` other than the four that Core lists | Mandatory | Core §3.2.2.2 | Always |
| Accept a `RelayState` the identity provider adds when the request carried none, and on an unsolicited response | Optional | Bindings §3.4.3, §3.5.3, CS-01 §2.3 | Always |

[Identifiers](identifiers.md#identity-provider-and-service-provider-received-issuer)
keeps how a received `Issuer` is compared, and
[baseline receipt](xml-schema-validation.md#baseline-receipt) the policy that
reads the `Response` `IssueInstant` only in UTC, a leap second included.

### Service provider: `accept_unsolicited_sso_with_resolver`

Code: `src/api/sp.rs`, `src/flow/response_issuer.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For unsolicited HTTP-POST, select a configured IdP by the direct SAML response issuer. When the response is unsigned and omits its issuer, use the common issuer of its plaintext assertions. Verify the message with the selected IdP | Optional | Profiles §4.1.4.2, §4.1.4.3, §4.1.5, E17 | `accept_unsolicited_sso_with_resolver` |

<a id="service-provider-outstanding-logout"></a>

### Service provider: `finish_sso_with_outstanding_logout`, `accept_unsolicited_sso_with_outstanding_logout`

Code: `src/model/outstanding_logout.rs`, `src/api/sp.rs`, `src/validator.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an otherwise valid later assertion that matches a caller-supplied unexpired logout from the assertion issuer | Mandatory | Core §3.7.3.1 | Always |
| Match the `NameID` value, `NameQualifier`, `SPNameQualifier`, `SPProvidedID`, and effective `Format`. Collapse XML whitespace in the format URI and read an omitted format as `unspecified`. An assertion without a `NameID` does not match | Mandatory | Core §2.2.2, §3.3.4, §3.7.3.1, E60, `NameIDType` | Always |
| Require at least one matching `SessionIndex` when the request lists indexes. Apply a request without indexes to all sessions for that issuer and principal | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, E38, `LogoutRequestType` | Always |
| Stop applying the logout once its `NotOnOrAfter` is reached | Mandatory | Core §3.7.3.1 | Always |
| Apply the `NotOnOrAfter` clock skew to the logout deadline | Recommended | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew`, `ClockSkew::strict` |

<a id="scoped-attributes"></a>

### Service provider: `SsoSession::scoped_attribute_violations`

Code: `src/model/attribute_scope.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Check the named attributes after acceptance against the assertion issuer's explicit policy or its unexpired registration-authority-signed metadata. Compare literal scopes case-sensitively | Mandatory | Subject Identifier §3.5.2, §4.2, saml2int SDP-SP17, E94 | Always |
| Ignore regular expression declarations for authorization | Optional | saml2int SDP-SP17 | Always |

Subject Identifier §4.2 requires a relying party that consumes metadata to
support this check.

<a id="operator-diagnostics"></a>

### Service provider: error responses

Code: `src/flow.rs`, `src/flow/error_response.rs`, `src/xml/protocol_element.rs`

These rows cover a non-success HTTP-POST or HTTP-POST-SimpleSign `Response`.
[Artifact acceptance](web-browser-sso-artifact.md#service-provider-receipt)
covers HTTP-Artifact.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read one nonempty, text-only protocol `StatusMessage` directly under `Status`. Omit diagnostics with attributes, child elements, or ambiguous cardinality | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | Always |

<a id="status-codes"></a>

### Response recipient: `Status`

Code: `src/xml/status.rs`, `src/model/status.rs`

These rules apply to response recipients in SSO, Single Logout, name
identifier management, and artifact resolution.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require one `Status` with one top-level `StatusCode`, at most one subordinate `StatusCode`, and a `Value` on each of them | Mandatory | `StatusResponseType`, `StatusType`, `StatusCodeType` | Always |
| Collapse XML whitespace in both `StatusCode` values before comparing or reporting them | Mandatory | Core §3.2.2.2, `StatusCodeType`, [XML Schema Part 2 §4.3.6](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) | Always |

<a id="identity-provider"></a>

### Identity provider: `receive_sso` signatures and refusals

Code: `src/api/idp.rs`, `src/idp.rs`, `src/flow.rs`, `src/flow/embedded.rs`, `src/flow/detached.rs`, `src/browser/input.rs`, `src/model/authn.rs`

`receive_sso` reads `IdpValidationPolicy::authn_request_signatures` and
`IdpValidationPolicy::xml_signatures`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a signed `AuthnRequest`. Return only refusal data for an otherwise valid unsigned request | Optional | Metadata §2.4.3, E7 | `AuthnRequestValidationPolicy::RequireSigned` |
| Refuse an unsigned `AuthnRequest` when any SAML 2.0 `SPSSODescriptor` for the service provider sets `AuthnRequestsSigned` to true. Return only refusal data for an otherwise valid request | Mandatory | Metadata §2.4.4, E7 | Always |
| Verify a signature on an `AuthnRequest` against the SP's signing credentials. The request has at most one direct `ds:Signature`. Redirect also verifies the query signature, and SimpleSign the detached signature when present, even when the request also carries an XML signature | Mandatory | Core §3.2.1, Bindings §3.4.4.1, CS-01 §2.4 to §2.6, §2.10 | Always |
| Parse a SimpleSign `AuthnRequest` with neither `Signature` nor `SigAlg` as HTTP-POST and apply the same request signature policy. Use the original binding to select the endpoint for the `Destination` check | Optional | CS-01 §2.10 | Always |
| Return refusal data, with its `AuthnRequestRefusalReason`, for an otherwise valid request refused for its signature, its `ProtocolBinding`, content it cannot read, a repeated `NameIDPolicy`, or its age, so the caller can send the error `Response` | Mandatory | Profiles §4.1.4.1, Core §3.4.1.4 | Always |
| Refuse a `ProtocolBinding` that is HTTP-Redirect, SOAP, or a URI other than HTTP-POST, HTTP-POST-SimpleSign, and HTTP-Artifact, because the `Response` cannot use it | Mandatory | Profiles §4.1.3.5, §4.1.4.1, Core §3.4.1 | Always |
| Return no refusal data for a request whose present `Destination` names another location | Mandatory | Core §3.2.1 | Always |

[XML Signature and XML Encryption algorithms](xml-security-algorithms.md#weak-algorithms-and-keys)
keeps the weak algorithms and keys that the identity provider rejects in a
request signature unless `XmlSignatureProfile::AllowWeakAlgorithms` accepts
them.

### Identity provider: `receive_sso` request fields

Code: `src/api/idp.rs`, `src/model/authn.rs`, `src/model/extract.rs`, `src/xml/profile.rs`, `src/model/validation.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Compare XML namespace names in an `AuthnRequest` after normalizing the declaration value | Mandatory | Namespaces in XML 1.0 §2.3, `AuthnRequestType` | Always |
| Compare a present `Destination` with the receiving `SingleSignOnService` `Location` after collapsing XML whitespace. Require it on a signed request. `ResponseLocation` is unused | Mandatory | Core §3.2.1, Bindings §3.4.5.2, §3.5.5.2, CS-01 §2.4, Metadata §2.2.2, E41 | `SamlValidationContext::with_recipient_endpoint` |
| Expose `ForceAuthn`, `IsPassive`, `RequestedAuthnContext`, the requested `Subject`, and `NameIDPolicy`. Presence never rejects the request, and the caller decides how to authenticate. A `Subject` with no identifier means the presenter | Optional | Core §3.4.1, §3.4.1.1, §3.4.1.4, E45, E75 | Always |
| Read the `ID` with XML whitespace collapsed. `respond_sso` writes that value as `InResponseTo` | Mandatory | `RequestAbstractType`, Core §3.2.2, XML Schema Part 2 §3.3.8, §4.3.6 | `AuthnRequest::id` |
| Read `ForceAuthn`, `IsPassive`, and `AllowCreate` as `xs:boolean` and `AssertionConsumerServiceIndex` as `xs:unsignedShort`, with XML whitespace collapsed. Refuse another value, and reject a qualified attribute | Mandatory | `AuthnRequestType`, `NameIDPolicyType`, XML Schema Part 2 §3.2.2, §3.3.23, §4.3.6 | Always |
| Reject a qualified `Format`, `SPNameQualifier`, or `AllowCreate` on `NameIDPolicy`, and a qualified `Format`, `NameQualifier`, `SPNameQualifier`, or `SPProvidedID` on the requested `NameID` | Mandatory | Core §2.2.2, §3.4.1.1, `NameIDType`, `NameIDPolicyType` | Always |

[Baseline receipt](xml-schema-validation.md#baseline-receipt) keeps the policy
that reads the `AuthnRequest` `IssueInstant` only in UTC, a leap second
included.

### Identity provider: requested assertion consumer

Code: `src/api/response_acs.rs`, `src/metadata/sp.rs`, `src/model/extract.rs`

`receive_sso` returns the requested URL and index without checking them
against the service provider metadata.
`respond_sso`, `respond_sso_refusal`, `respond_sso_artifact`, and
`respond_sso_refusal_artifact` check them before they deliver the response.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify that a requested ACS URL or index used for delivery names the SP's assertion consumer. Collapse XML whitespace in a requested URL before comparing | Mandatory | Profiles §4.1.4.1, `AuthnRequestType`, XML Schema Part 2 §4.3.6 | Always |

[SSO generation](web-browser-sso-generation.md#endpoint-selection) keeps how
those operations choose the assertion consumer.

### Identity provider: `RequestedAuthnContext`

Code: `src/model/authn_context.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Refuse a second `RequestedAuthnContext` | Mandatory | `AuthnRequestType` | Always |
| Refuse a `RequestedAuthnContext` without references or with both class and declaration references, and reject a reference in another namespace | Mandatory | `RequestedAuthnContextType` | Always |
| Keep the references in request order, most preferred first | Mandatory | Core §3.3.2.2.1, E45 | Always |
| Read an optional unqualified `Comparison` as `exact`, `minimum`, `maximum`, or `better`, and default it to `exact`. Refuse another value | Mandatory | Core §3.3.2.2.1, E45, `RequestedAuthnContextType` | Always |

### Identity provider: requested `Subject`

Code: `src/model/authn.rs`, `src/model/subject.rs`, `src/api/requested_subject.rs`, `src/crypto/enc/decrypt.rs`, `src/xml/profile.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Refuse a second `Subject` or a second identifier in a requested `Subject`, and reject an identifier in a foreign namespace | Mandatory | Core §3.4.1, `SubjectType` | Always |
| Permit schema-allowed foreign attributes on `SubjectConfirmationData` in the requested `Subject` | Mandatory | Core §2.4.1.2, §3.4.1, `SubjectConfirmationDataType` | Always |
| Process a requested encrypted `NameID` when decryption succeeds. If the key is absent, the unsigned ciphertext is ineligible, or decryption does not yield one `NameID`, retain the unread `EncryptedID`. Only an error response can answer that request | Mandatory | Conformance §3.4, Core §3.4.1, §3.4.1.4 | Always |
| Refuse a request whose decrypted `NameID` breaks the protocol profile | Mandatory | Core §3.4.1.4, Profiles §4.1.4.1 | Always |

## Library policies

### Service provider: signatures

Code: `src/flow.rs`, `src/flow/embedded.rs`, `src/flow/detached.rs`, `src/crypto/response_root.rs`, `src/browser/input.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Require each `Assertion`, a decrypted one included, to be covered by a verified signature that references it. A `Response` or SimpleSign signature alone does not count | The service provider enforces the `WantAssertionsSigned` it publishes, and an assertion that only inherits the `Response` signature loses it once taken out of the response. | Metadata §2.4.4, Core §5.3, Profiles §4.1.4.5, E26 | `AssertionSignaturePolicy::RequireSigned` |
| Require a signature covering every successful `Response`. A SimpleSign detached signature counts, and an error `Response` may be unsigned | A `Response` signature also protects the response fields, such as `InResponseTo` and `Destination`, and the set of assertions, which assertion signatures do not. | Profiles §4.1.4.5, E26, E93 | `ResponseSignaturePolicy::RequireSigned` |
| Reject an `EncryptedAssertion` with a missing or unrecognized data-encryption algorithm | The service provider cannot tell whether the ciphertext is CBC. | Core §6.2, E93 | `ResponseSignaturePolicy::RequireForEncryptedCbc` |
| Reject the whole response when a signature on the `Response` or on one of its assertions, a decrypted one included, fails, even when another assertion verifies | The service provider does not choose among the assertions of one response by their signature result. | Profiles §4.1.4.3, E26 | Always |
| Treat a SimpleSign `Response` without `Signature` as carrying no detached signature, with or without `SigAlg` | CS-01 §2.10 identifies a SimpleSign signature by the `Signature` field, and a `SigAlg` alone leaves nothing to verify. | CS-01 §2.4, §2.10 | Always |
| Require a verified detached signature on a successful SimpleSign `Response`, even if it carries an XML signature | The detached signature authenticates the full response and covers any `RelayState`. | CS-01 §2.4, §2.7.2 | Always |
| For a SimpleSign error `Response`, allow `Signature` to be absent only if neither the response nor its assertions carry an XML signature | Unsigned errors cannot establish sessions. | CS-01 §2.4, §2.6, Profiles §4.1.4.3 | Always |

### Service provider: encrypted elements

Code: `src/flow.rs`, `src/flow/embedded.rs`, `src/encrypted_elements.rs`, `src/crypto/enc.rs`, `src/crypto/enc/decrypt.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a response when an `EncryptedAssertion` or `EncryptedAttribute` does not decrypt, such as one encrypted for another recipient | A ciphertext the configured keys cannot decrypt can come from a missed key rollover, a wrong certificate, or an unsupported algorithm, and skipping it would complete a login from a response read only in part. | Conformance §3.4 | Always |
| Reject an unsigned `Response` that mixes `Assertion` and `EncryptedAssertion` children when only the plaintext assertions are signed | Those signatures do not cover an encrypted sibling. | Core §3.3.3 | Always |
| Reject a plaintext `Assertion`, `NameID`, or `Attribute` once its encrypted form is required | Encrypting a sibling leaves the plaintext element exposed. | Core §3.3.3, §2.4.1, §2.7.3 | `XmlEncryptionPolicy` fields `assertions`, `identifiers`, and `attributes` set to `EncryptAssertions`, `EncryptIdentifiers`, and `EncryptAttributes` |
| Verify a signature that covers an `EncryptedID` or `EncryptedAttribute` before decrypting it under every non-CBC data-encryption algorithm | On every supported binding an accepted assertion is covered by a verified signature, so decrypting first would only expose the decryption key to ciphertext no signature covers, and an AES-GCM tag does not show who encrypted. | Core §6.2, E93 | Always |
| With several assertions, refuse an `EncryptedID` or `EncryptedAttribute` unless a `Response` signature or a SimpleSign detached signature authenticates the message | The nested decryption step learns only whether the `Response` is authenticated, not whether each assertion's own signature covers it. | Core §6.2, Profiles §4.1.4.5, E26, E93 | Always |
| Reject an `EncryptedAssertion` whose plaintext is not one `Assertion`, and an `EncryptedID` or `EncryptedAttribute` whose plaintext is not one `NameID` or `Attribute` in the assertion namespace | The decrypted element takes the place of its wrapper, so the service provider reads it only by the rules of the plaintext element it replaces. | Core §2.3.4, §2.2.4, §2.7.3.2 | Always |

<a id="assertion-selection-policies"></a>

### Service provider: assertion selection and content

Code: `src/assertion_acceptance.rs`, `src/model/sso.rs`, `src/model/extract.rs`, `src/api/sp.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Use the first bearer assertion with an `AuthnStatement` for the session | `SsoSession` exposes the fields of one assertion. | Profiles §4.1.4.2, §4.1.4.3, E26 | Always |
| Reject a response in which no bearer assertion has an `AuthnStatement` | Without one, the identity provider does not state that the principal authenticated, so the assertion cannot start a login session. | Profiles §4.1.4.2, E26 | Always |
| Reject the whole response, without falling back to another assertion, when the selected bearer assertion fails its confirmation, audience, or `Conditions` check, or breaks a statement-shape or `AuthnInstant` rule | Accepting another assertion would discard the authentication evidence selected for the session. | Profiles §4.1.4.3, E26 | Always |
| Permit other assertions beside the selected one, with or without a bearer confirmation, whatever their `Subject`. Apply the issuer and signature rules to each. The session reads no value from them | E26 leaves their processing outside the profile and lets their `Subject` content differ, and these rules keep every assertion of one response tied to one IdP. | Profiles §4.1.4.2, E26 | Always |
| Reject the whole response if any assertion's `Issuer` differs from the responding identity provider's entity ID | All assertion IDs recorded for one session must belong to the same identity provider. | Profiles §4.1.4.2, §4.1.4.3, E26 | Always |
| Reject a selected assertion whose `Subject` names the principal with a `BaseID` | Core §3.7.3.1 requires the SP to apply a logout that names this `BaseID`, and the library cannot interpret or compare an extension identifier. | Core §2.2.1, §2.4.1, §3.7.3.1 | Always |
| For a solicited login, require at least one validated `AuthnStatement` of the consumed assertion to match a requested class or declaration reference stored in pending state | Core §3.3.2.2.1 obligates the IdP, and step-up logins need to reject weaker or missing contexts. | Core §3.3.2.2.1, E45 | `StartSso::require_exact_authn_context` |
| With a replay cache, store every direct assertion `ID`. Use each sibling's latest bearer expiration plus skew, or the selected assertion's [replay deadline](metadata-and-replay.md#sso-replay-deadlines) when the sibling has no bearer expiration that is still ahead | It keeps each identifier at least as long as the confirmation that satisfied the checks. | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |

### Service provider: conditions and time windows

Code: `src/assertion_acceptance.rs`, `src/validator.rs`, `src/model/sso.rs`, `src/xml/date_time.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Treat a generic `Condition` as not understood, even when its `xsi:type` names `AudienceRestrictionType`, `OneTimeUseType`, or `ProxyRestrictionType` | The audience check reads only `AudienceRestriction` elements, Profiles §4.1.4.2 requires that element, and OpenSAML Java 5.2.3 also rejects this form. | Core §2.5.1, §2.5.1.1, `ConditionsType` | Always |
| Accept an attribute in the XML Schema instance namespace, such as `xsi:type`, `xsi:schemaLocation`, or `xsi:nil`, on `Conditions`, `AudienceRestriction`, `OneTimeUse`, and `ProxyRestriction`, and evaluate the element as the condition its name declares, whatever type `xsi:type` names | It keeps conditions that carry schema annotations usable, as in OpenSAML Java 5.2.3 and C++ 3.3.1, because the SP evaluates a known condition by its element name. | Core §2.5.1.1, §2.5.1.3, XML Schema Part 1 §3.3.4, §3.4.4 | Always |
| Require an `AudienceRestriction` in the selected bearer assertion | The deployment requires explicit audience targeting. | Profiles §4.1.4.2, E26 | `AudienceValidationPolicy::RequireRestriction` |
| Fail the check of a UTC bound that the runtime cannot compare with the clock: a year outside 0001 through 9999, `24:00:00`, or a leap second outside the last minute of a UTC month | Such a value cannot be compared with the clock. | Core §1.3.3 | Always |
| For `Conditions` and bearer confirmation, treat an upper bound shifted past year 9999 as open and reject an unrepresentable shifted `NotBefore`. Reject an unrepresentable shifted session or replay deadline | The runtime cannot represent the shifted instant. | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew` |

### Service provider: response fields and `Destination`

Code: `src/api/sp.rs`, `src/api/peer.rs`, `src/flow.rs`, `src/flow/response_issuer.rs`, `src/assertion_acceptance.rs`, `src/model/validation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a present `Response` issuer other than the IdP's entity ID. An omitted issuer is accepted with a supplied descriptor, or by the resolver only through the plaintext fallback | A successful response then gets the `Issuer` check that an error response gets, so no session is accepted from a `Response` whose `Issuer` names another entity. | Profiles §4.1.4.2, E17, Core §3.2.2 | Always |
| Require a successful solicited `Response` to carry the pending request ID in `InResponseTo`, compared after XML whitespace collapse | Otherwise an assertion with a matching bearer confirmation could complete a pending login inside a response whose own request correlation is missing or inconsistent. | Core §3.2.2, Profiles §4.1.4.3, E26 | Always |
| Reject a response-level `InResponseTo` on an unsolicited `Success` response, empty or not | Profiles §4.1.4.3 names only the bearer confirmation, and a reply tied to a request must pass the pending request's correlation checks. | Core §3.2.2, Profiles §4.1.5 | Always |
| In `finish_sso`, require the response to name the assertion consumer the pending request asked for, and reject a supplied receiving URL other than that one | The `AuthnRequest` selected that consumer, so a response that names or reaches another one does not answer the request as sent. | Profiles §4.1.4.1, §4.1.4.3 | Always |
| Reject a supplied recipient endpoint that this SP does not publish as an `AssertionConsumerService` for the incoming binding | The URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this SP does not operate for that binding. | Core §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Without a supplied URL, expect the assertion consumer the pending request asked for in `finish_sso`, and the default `AssertionConsumerService` for the incoming binding in `accept_unsolicited_sso` | The library is not told which endpoint received the response. | Profiles §4.1.4.1, §4.1.5 | `SamlValidationContext::with_recipient_endpoint` |
| In `finish_sso`, require the session `RelayState` to equal the pending request's when the request supplied one, empty or not | Bindings §3.5.5.2 warns that an attacker can swap the `RelayState` values of two valid POST responses. | Bindings §3.4.3, §3.5.3, §3.5.5.2, CS-01 §2.3 | Always |

### Service provider: `accept_unsolicited_sso_with_resolver`

Code: `src/flow/response_issuer.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| For IdP lookup, require one `Issuer` with an omitted or `entity` `Format` and no qualifier or child element | The SP needs one usable key to select the credentials, and only an unqualified entity `Issuer` is that key. | Core §2.2.5, §8.3.6, Profiles §4.1.4.2, E17 | Always |

[Identifiers](identifiers.md#identity-provider-and-service-provider-entityidtry_new-accept_unsolicited_sso_with_resolver)
keeps the policy that passes an `Issuer` that is not a URI, or is longer than
1024 characters, to the resolver.

### Service provider: `SsoSession::scoped_attribute_violations`

Code: `src/model/attribute_scope.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Report unscoped and unauthorized values, and leave the decision on them to the application | Applications choose which attributes they use and how to handle violations. | Subject Identifier §3.5.2 | Always |

### Service provider: error responses

Code: `src/flow.rs`, `src/flow/error_response.rs`, `src/api/sp.rs`

The two diagnostic rows cover a non-success HTTP-POST or
HTTP-POST-SimpleSign `Response`, as the error response rules do.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Report a status other than `Success` as an error after the signature, `Issuer`, correlation, and `Destination` checks | A failed check then takes precedence over the peer's status, so an unrelated or tampered error response reports the check it fails. | Core §3.2.2.2, Profiles §4.1.4.3 | Always |
| Permit omission of `InResponseTo` on an error `Response`. Compare a present value with the pending request ID after XML whitespace collapse for solicited errors, empty or not. Skip correlation for unsolicited errors | A value for another request indicates a different exchange. | Core §3.2.2 | Always |
| Expose the diagnostic after issuer and recipient checks only if a response signature or detached SimpleSign signature covers it | The text must be attributable to the peer. | Core §3.2.2, Bindings §3.5.5.2, CS-01 §2.4 | Always |
| For solicited errors, expose the diagnostic only when `InResponseTo` and any requested `RelayState` match. For unsolicited errors, require an absent `InResponseTo` to expose it | The text is then attached only to an error attributable to the current exchange. | Core §3.2.2, Bindings §3.5.3, CS-01 §2.3 | Always |

### Identity provider: `receive_sso` signatures and refusals

Code: `src/api/idp.rs`, `src/browser/input.rs`, `src/model/authn.rs`, `src/model/validation.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a SimpleSign `AuthnRequest` that carries only one of `Signature` and `SigAlg` | Either field signals a detached signature, which requires both fields to verify. | CS-01 §2.4, §2.5, §2.10 | Always |
| Refuse an `AuthnRequest` with more than one `NameIDPolicy` | Core §3.4.1.1 binds the identity provider to the requested policy, and reading one of two policies, or neither, could issue an identifier that the other excludes. | `AuthnRequestType`, Core §3.2.1, §3.4.1.1 | Always |
| Return no refusal data for an authenticated request that passes every refusal check and whose `ID` the replay cache already holds | `receive_sso` already returned the first copy for the application to answer, and Core §3.4.1.4 asks for one reply to a request. | Core §3.4.1.4 | `ReplayPolicy::RequireCache` |
| Accept an `AuthnRequest` `IssueInstant` from now − `max_age` − past tolerance through now + future tolerance, inclusive. A positive `NotOnOrAfter` skew supplies the past tolerance, and a negative `NotBefore` skew supplies the future tolerance | Reason not recorded. | Core §1.3.3 | `SamlValidationContext::with_authn_request_age`, `RequestAgePolicy::Bounded` |

### Identity provider: `receive_sso` request fields

Code: `src/api/idp.rs`, `src/model/validation.rs`, `src/model/authn.rs`, `src/model/endpoint.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| When checking `Destination` in `receive_sso`, reject a supplied receiving URL that is not published for the incoming binding, and several published URLs without an explicit one | The URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this identity provider does not operate for that binding. | Core §3.2.1 | `SamlValidationContext::with_recipient_endpoint` |
| Refuse an `AssertionConsumerServiceURL` that is not an absolute HTTP(S) URL | The browser bindings deliver the `Response` to an HTTP endpoint, so another URI cannot receive it. | Core §3.4.1, Bindings §3.5.4, §3.6.3 | Always |

### Identity provider: `RequestedAuthnContext`

Code: `src/model/authn_context.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Read context references with XML whitespace collapsed, including relative references | Reason not recorded. | Core §1.3.2, XML Schema Part 2 §4.3.6 | `AuthnRequest::requested_authn_context` |

### Identity provider: requested `Subject`

Code: `src/model/authn.rs`, `src/model/subject.rs`, `src/crypto/enc/decrypt.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept and expose a `SubjectConfirmation` in the requested `Subject` | Accepting it keeps working a request that Core §3.4.1 allows, since Profiles §4.1.4.1 forbids it only to the service provider and gives the identity provider no rejection rule. | Core §3.4.1, Profiles §4.1.4.1 | Always |
| Decrypt an unsigned request's `EncryptedID` only when its `EncryptedData` is AES-GCM | Any sender chooses the ciphertext of an unsigned request, E93 shows that CBC ciphertext without integrity protection is open to chosen-ciphertext attacks, and AES-GCM authenticates the ciphertext. | Profiles §4.1.4.1, E93 | Always |

<a id="caller-duties-in-the-identity-provider"></a>

## Application duties

| Duty | Level | Section |
| --- | --- | --- |
| Service provider: end the application session at the earliest `SessionNotOnOrAfter`, which `SsoSession::session_not_on_or_after` returns, unless the principal signs in again | Recommended | Profiles §4.1.4.3, E26 |
| Service provider: in a saml2int deployment, accept a scoped identifier only from an identity provider authorized to assert its scope, with `SsoSession::scoped_attribute_violations` or a policy set another way | Mandatory | saml2int SDP-SP17 |
| Identity provider: treat the content of an unauthenticated `AuthnRequest` as advisory. `Received::authentication` reports `MessageAuthentication::Unauthenticated` when no verified signature covers the request | Mandatory | Profiles §4.1.4.1 |
| Identity provider: read an absent `AllowCreate`, or an absent `NameIDPolicy`, as `false`. `NameIdCreationRequest::Unspecified` and a `None` policy report the absence | Mandatory | Core §3.4.1.1, E14 |
| Identity provider: ignore `AllowCreate` in a request for the transient format | Recommended | Core §3.4.1.1, E14 |

[Metadata and replay](metadata-and-replay.md#onetimeuse-application-duties)
keeps the `OneTimeUse` duties for the returned session, and
[identifiers](identifiers.md#application-duties) the duty to check the scope
of a subject identifier. The identity provider's authentication and error
decisions are in
[SSO generation](web-browser-sso-generation.md#not-implemented).

<a id="not-implemented-in-the-service-provider"></a>
<a id="not-implemented-in-the-identity-provider"></a>

## Not supported

- Service provider: the check of the bearer `Address` against the client
  address. Optional, Profiles §4.1.4.3. `SsoSession::subject_confirmations`
  returns each `SubjectConfirmation` as XML for an application that checks
  it.
- Service provider: confirmation by holder-of-key, sender-vouches, or another
  method than bearer. The
  [SAML V2.0 Holder-of-Key Web Browser SSO Profile](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso.html)
  defines a holder-of-key login, and E26 leaves other confirmation methods
  outside this profile. The service provider confirms an assertion only by a
  bearer `SubjectConfirmation`.
- Both roles: the identifier in a `BaseID`, and in an `EncryptedID` that
  carries a `BaseID` or an `Assertion`, as
  [identifiers](identifiers.md#not-supported) records. Decoding a `BaseID` in
  a requested `Subject` is Optional, Core §3.4.1. An `EncryptedID` that
  carries a `BaseID` or an `Assertion` is Optional, Core §2.2.4.
- Service provider: a successful `Response` by HTTP-Artifact without an XML
  signature. Optional, Profiles §4.1.3.5, §4.1.4.4, E93. Identity provider:
  an `AuthnRequest` by HTTP-Artifact. Optional, Profiles §4.1.3.3, Bindings
  §3.6. The [HTTP-Artifact response](web-browser-sso-artifact.md#not-supported)
  record says what each side does instead.
- Identity provider: reading `Conditions`, `Scoping`, and
  `AttributeConsumingServiceIndex` in a received request. Optional, Core
  §3.4.1, §3.4.1.2. `receive_sso` exposes none of them.
- Identity provider: proxying the request to another identity provider.
  Optional, Core §3.4.1.5.
