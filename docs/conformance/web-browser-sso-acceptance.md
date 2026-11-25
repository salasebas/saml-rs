# Web Browser SSO acceptance rules

Inbound rules for typed Web Browser SSO cover `ServiceProvider::finish_sso`,
`ServiceProvider::accept_unsolicited_sso`,
`ServiceProvider::accept_unsolicited_sso_with_resolver`, and
`IdentityProvider::receive_sso`.
`SpValidationPolicy` and `IdpValidationPolicy` select the options. The
[validation presets](https://samlrs.vercel.app/explanation/validation-presets/)
list their defaults.
Normative text is SAML Core 2.0, Profiles 2.0, and Bindings 2.0 as corrected by Approved Errata 05, and the HTTP-POST-SimpleSign CD-04 binding.
[Single Logout](single-logout.md), [metadata trust and replay](metadata-and-replay.md),
and [HTTP-Artifact](web-browser-sso-artifact.md) have their own records.
Artifact acceptance follows the HTTP-POST rows where its record specifies no
difference.

## Service provider

`finish_sso` and both unsolicited SSO entry points apply the relevant rows
for their binding. The SP compares a received `Issuer` as described in
[entity identifiers](identifiers.md#entity-identifiers).

An otherwise valid browser `Response` can fail when a declaration spells the
protocol or assertion namespace with an XML character reference. The protocol
profile and assertion condition checks still use raw namespace bindings.
This conformance gap has no caller option. Namespaces in XML 1.0 §2.3 requires
comparing the normalized values. SimpleSAMLphp 6.0.0 passes normalized DOM
names to its HTTP-POST message reader. [Namespaces in XML 1.0 §2.3](https://www.w3.org/TR/REC-xml-names/#NSNameComparison) ·
[SimpleSAMLphp 6.0.0](https://github.com/simplesamlphp/saml2/blob/v6.0.0/src/Binding/HTTPPost.php#L89-L105) ·
[Issue #629](https://github.com/salasebas/saml-rs/issues/629)

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For unsolicited HTTP-POST, select a configured IdP by the direct SAML response issuer. When the response is unsigned and omits its issuer, use the common issuer of its plaintext assertions. Verify the message with the selected IdP | Optional | Profiles §4.1.4.2, §4.1.4.3, §4.1.5, E17 | `accept_unsolicited_sso_with_resolver` |
| Require an unambiguous entity identifier for IdP lookup | Library policy: the SP needs one usable key to select the credentials for verification. | Core §2.2.5, §8.3.6, Profiles §4.1.4.2, E17 | `accept_unsolicited_sso_with_resolver` |
| Use the first bearer assertion with an `AuthnStatement` for the session. If none has one, use the first bearer assertion | Library policy: `SsoSession` exposes the fields of one assertion and prefers authentication evidence. | Profiles §4.1.4.2, §4.1.4.3, E26 | Always |
| In the selected bearer assertion, require `AuthnInstant`, exactly one direct SAML `AuthnContext`, and at most one direct SAML `SubjectLocality` in each `AuthnStatement` | Mandatory | Core §2.7.2, `AuthnStatementType` | Always |
| Require each such `AuthnInstant` to be a UTC `xs:dateTime`. A leap second is accepted, as for `IssueInstant` | Mandatory | Core §1.3.3, §2.7.2, `AuthnStatementType` | Always |
| Expose the context and locality of each accepted statement. Keep references and authorities in document order and collapse URI whitespace | Optional | Core §2.7.2, §2.7.2.1, §2.7.2.2 | `AuthnStatement::authn_context`, `AuthnStatement::subject_locality` |
| Reject the whole response, without falling back to another assertion, when the selected bearer assertion fails its confirmation, audience, or `Conditions` check, or breaks the statement-shape or `AuthnInstant` rule above | Library policy: accepting another assertion would discard the authentication evidence selected for the session. | Profiles §4.1.4.3, E26 | Always |
| For a solicited login, require at least one validated `AuthnStatement` of the consumed assertion to match a requested class or declaration reference stored in pending state | Library policy: Core §3.3.2.2.1 obligates the IdP, and step-up logins need to reject weaker or missing contexts. | Core §3.3.2.2.1, E45 | `StartSso::require_exact_authn_context` |
| Require a signature directly on each `Assertion` | Library policy: reason not recorded. | Profiles §4.1.4.5, E26 | `AssertionSignaturePolicy::RequireSigned` |
| Require a signature covering every successful `Response` | Library policy: reason not recorded. | Profiles §4.1.4.5, E26 | `ResponseSignaturePolicy::RequireSigned` |
| Require a signature on the `Response` when an `EncryptedAssertion` uses CBC | Recommended | Core §6.2, Profiles §4.1.3.5, E93 | `ResponseSignaturePolicy::AllowUnsignedEncryptedCbc` relaxes it |
| For HTTP-POST, require an XML signature on the successful `Response` or on each assertion | Mandatory | Profiles §4.1.4.5, E26, E93 | Always |
| Verify every signature on the `Response` and on its assertions, including decrypted ones. A signature that fails rejects the response even when another verifies | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Report each verified embedded signature that covers the `Response` or directly covers the selected assertion, including after SimpleSign verification or assertion decryption | Optional | Core §5.4, SimpleSign CD-04 §2.4–2.6 | `SsoSession::verified_xml_signatures` |
| Reject MD5, RIPEMD-160, and RSA keys shorter than 2048 bits | Library policy: see [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys). | XMLDSig 1.1 §6.2, Conformance §4.1 | `XmlSignatureProfile::AllowWeakAlgorithms` relaxes it |
| Do not require the RSA-SHA2 XML signature profile | Library policy: Conformance §4.1 requires RSAwithSHA1, and Core §5.4.4 does not require a verifier to reject other transforms. | Conformance §4.1, Core §5.4.4 | `XmlSignatureProfile::StrictRsaSha2` requires it |
| Decrypt each `EncryptedAssertion`, each `EncryptedID` in an assertion `Subject`, and each `EncryptedAttribute`, whatever `XmlEncryptionPolicy` selects. Evaluate each decrypted assertion as a plaintext one. Without a decryption key, an encrypted assertion or `NameID` leaves nothing to accept, and an `EncryptedAttribute` is not decoded | Mandatory | Conformance §3.4, Core §2.3.4, §2.2.4, §2.7.3.2 | Always |
| Reject a response when an `EncryptedAssertion` or `EncryptedAttribute` does not decrypt, such as one encrypted for another recipient | Library policy: reason not recorded. | Conformance §3.4 | Always |
| Reject an unsigned `Response` that mixes `Assertion` and `EncryptedAssertion` children when only the plaintext assertions are signed | Library policy: those signatures do not cover an encrypted sibling. | Core §3.3.3 | Always |
| Reject a plaintext `Assertion`, `NameID`, or `Attribute` once its encrypted form is required | Library policy: encrypting a sibling leaves the plaintext element exposed. | Core §3.3.3, §2.4.1, §2.7.3 | `XmlEncryptionPolicy` fields `assertions`, `identifiers`, and `attributes` set to `EncryptAssertions`, `EncryptIdentifiers`, and `EncryptAttributes` |
| Verify a signature that covers a CBC-encrypted `EncryptedID` or `EncryptedAttribute` before decrypting it | Recommended | Core §6.2, E93 | Always |
| Apply that order to every other data-encryption algorithm. With several assertions, the signature must cover the `Response` | Library policy: reason not recorded. | Core §6.2, E93 | Always |
| Reject an `EncryptedAssertion` that holds anything but one `EncryptedData` followed only by `EncryptedKey` elements | Mandatory | Core §2.3.4, `EncryptedElementType` | Always |
| Reject an `EncryptedAssertion` whose plaintext is not one `Assertion`, and an `EncryptedID` or `EncryptedAttribute` whose plaintext is not one `NameID` or `Attribute` in the assertion namespace | Library policy: reason not recorded. | Core §2.3.4, §2.2.4, §2.7.3.2 | Always |
| Resolve an `EncryptedKey` embedded in `EncryptedData` or named by a `ds:RetrievalMethod` of type `EncryptedKey` | Recommended | Core §6.2, E43 | Always |
| Reject the selected assertion when a `Conditions` child is not understood | Mandatory | Core §2.5.1.1 | Always |
| Treat a generic `Condition` as not understood, even when its `xsi:type` names `AudienceRestrictionType`, `OneTimeUseType`, or `ProxyRestrictionType` | Library policy: the audience check reads only `AudienceRestriction` elements, Profiles §4.1.4.2 requires that element, and OpenSAML Java 5.2.3 also rejects this form. | Core §2.5.1, §2.5.1.1, `ConditionsType` | Always |
| Accept `OneTimeUse` and `ProxyRestriction`. The SP keeps no assertion for later use and issues no later assertion | Mandatory | Core §2.5.1.5, §2.5.1.6 | Always |
| Reject the selected bearer assertion when any `AudienceRestriction` lacks the SP's entity ID among its whitespace-collapsed `Audience` values | Mandatory | Core §2.5.1.1, §2.5.1.4, E46, XML Schema Part 2 §4.3.6 | Always |
| Require an `AudienceRestriction` in the selected bearer assertion | Library policy: the deployment requires explicit audience targeting. | Profiles §4.1.4.2, E26 | `AudienceValidationPolicy::RequireRestriction` |
| Evaluate the selected bearer assertion on its own: bearer confirmation, audience, `Conditions` children and window, and `SessionNotOnOrAfter` | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Discard another assertion that fails its own bearer confirmation, audience, `Conditions`, or `SessionNotOnOrAfter` check, without rejecting the response | Recommended | Profiles §4.1.4.3, E26 | Always |
| Reject a response whose assertions repeat an `ID`, compared after XML whitespace collapse, including after decryption and without an embedded signature | Mandatory | XML 1.0 VC: ID, `AssertionType`, XML Schema Part 2 §3.3.8 | Always |
| Permit other assertions beside the selected one, with or without a bearer confirmation. Apply the issuer, principal, and signature rules to each | Library policy: E26 leaves their processing outside the profile, and these rules keep every assertion of one response tied to one IdP and one principal. | Profiles §4.1.4.2, E26 | Always |
| Reject the whole response if any assertion's `Issuer` differs from the responding identity provider's entity ID | Library policy: all assertion IDs recorded for one session must belong to the same identity provider. | Profiles §4.1.4.2, §4.1.4.3, E26 | Always |
| Reject assertions that differ in principal: `NameID` value, `Format`, `NameQualifier`, or `SPNameQualifier`. Collapse XML whitespace in `Format`, and read an omitted `Format` as `unspecified`. An assertion without a `NameID` matches no other assertion | Library policy: it ties the assertion IDs recorded for one session to one subject, and the SP has no mapping between different identifiers for one principal. | Profiles §4.1.4.2, E26, Core §2.2.2 | Always |
| Treat the `Subject` identifier of the selected assertion as optional. Without one, report no `NameID` | Mandatory | Core §2.4.1, `SubjectType` | `SsoSession::name_id` |
| Without a direct `NameID`, reject a `Subject` child other than `SubjectConfirmation`, `BaseID`, or `EncryptedID` | Mandatory | `SubjectType` | Always |
| Reject a selected assertion whose `Subject` names the principal with a `BaseID` | Library policy: Core §3.7.3.1 requires the SP to apply a logout that names this `BaseID`, and the library cannot interpret or compare an extension identifier. | Core §2.2.1, §2.4.1, §3.7.3.1 | Always |
| With a replay cache, store every direct assertion ID. Use each sibling's latest bearer expiration plus skew, or the selected assertion's replay deadline when the sibling has no bearer expiration that is still ahead | Library policy: reason not recorded. | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| Reject a present `Response` issuer other than the IdP's entity ID. An omitted issuer is accepted with a supplied descriptor, or by the resolver only through the plaintext fallback above | Library policy: compare any present issuer before accepting the session. | Profiles §4.1.4.2, E17, Core §3.2.2 | Always |
| Reject a second direct `Issuer` on the `Response` | Mandatory | Core §3.2.2, `StatusResponseType` | Always |
| Reject a `Response` or `Assertion` `IssueInstant` that is not UTC. A leap second is accepted | Mandatory | Core §1.3.3 | Always |
| Read each bearer time bound only as a UTC `xs:dateTime`: `Conditions@NotBefore` and `NotOnOrAfter`, bearer `SubjectConfirmationData@NotBefore` and `NotOnOrAfter`, and `AuthnStatement@SessionNotOnOrAfter`. A value with an offset or no time zone fails its check | Mandatory | Core §1.3.3, §2.4.1.2, §2.5.1, §2.7.2, E79 | Always |
| Fail the check of a UTC bound that the runtime cannot compare with the clock: a year outside 0001 through 9999, `24:00:00`, or a leap second outside the last minute of a UTC month | Library policy: such a value cannot be compared with the clock. | Core §1.3.3 | Always |
| Identify bearer confirmations by the bearer URI after collapsing XML whitespace in `Method`. Use the same comparison for assertion selection, confirmation, and replay expiry | Mandatory | Core §1.3.2, §2.4.1.1, `SubjectConfirmationType`, Profiles §4.1.4.3, E26 | Always |
| Verify that a bearer confirmation's `NotOnOrAfter` has not passed and its whitespace-collapsed `Recipient` matches the assertion consumer URL. For a solicited response, also match the whitespace-collapsed `InResponseTo` to the request ID | Mandatory | Profiles §4.1.4.3, E26, `SubjectConfirmationDataType`, XML Schema Part 2 §4.3.6 | Always |
| Accept one satisfied confirmation as sufficient to confirm the assertion | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Reject a bearer confirmation without `NotOnOrAfter` | Library policy: reason not recorded. | Profiles §4.1.4.2, §4.1.4.3, E26 | Always |
| Require a successful solicited `Response` to carry the pending request ID in `InResponseTo`, compared after XML whitespace collapse | Library policy: otherwise an assertion with a matching bearer confirmation could complete a pending login inside a response whose own request correlation is missing or inconsistent. | Core §3.2.2, Profiles §4.1.4.3, E26 | Always |
| Leave a bearer confirmation of an unsolicited response unsatisfied when it carries `InResponseTo`, empty or not. Another bearer confirmation can still confirm the assertion | Mandatory | Profiles §4.1.4.3, E26 | Always |
| Reject a response-level `InResponseTo` on an unsolicited `Success` response, empty or not | Library policy: Profiles §4.1.4.3 names only the bearer confirmation, and a reply tied to a request must pass the pending request's correlation checks. | Core §3.2.2, Profiles §4.1.5 | Always |
| Reject a bearer confirmation whose `NotBefore` has not been reached, after skew. A `NotBefore` that has been reached is accepted | Mandatory | Core §2.4.1.2, Profiles §4.1.4.2, E26 | Always |
| For the session, correlation, repeated-ID, and replay checks, read the `Response` `ID`, `IssueInstant`, `Destination`, and `InResponseTo`, and the assertion `ID` and `IssueInstant`, only from unqualified attributes | Mandatory | `StatusResponseType`, `AssertionType` | Always |
| Permit schema-allowed foreign attributes on `SubjectConfirmationData` and `Attribute`. Read bearer checks and SAML attribute names, formats, and labels from unqualified attributes | Mandatory | Core §2.4.1.2, §2.7.3.1, `SubjectConfirmationDataType`, `AttributeType`, Profiles §4.1.4.3, E26 | Always |
| Require `NotBefore` to precede `NotOnOrAfter` when both appear in `Conditions` or bearer `SubjectConfirmationData`. Compare the bounds before applying clock skew | Mandatory | Core §2.4.1.2, §2.5.1.1, §2.5.1.2, E92 | Always |
| Allow five minutes of clock skew on `NotBefore` and `NotOnOrAfter` | Recommended | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew`, `ClockSkew::strict` |
| For `Conditions` and bearer confirmation, treat an upper bound shifted past year 9999 as open and reject an unrepresentable shifted `NotBefore`. Reject an unrepresentable shifted session or replay deadline | Library policy: the runtime cannot represent the shifted instant. | Core §1.3.3, E92 | `SamlValidationContext::with_clock_skew` |
| Reject an assertion whose earliest `SessionNotOnOrAfter`, widened by the `NotOnOrAfter` skew, has passed | Library policy: reason not recorded. | Profiles §4.1.4.3, E26, E79 | `SamlValidationContext::with_clock_skew` |
| Expose the earliest explicit `SessionNotOnOrAfter` of the consumed assertion before clock skew so the application can cap its session | Optional | Profiles §4.1.4.3, E26, E79 | `SsoSession::session_not_on_or_after` |
| Reject an otherwise valid later assertion that matches a caller-supplied unexpired logout from the assertion issuer | Mandatory | Core §3.7.3.1 | `finish_sso_with_outstanding_logout`, `accept_unsolicited_sso_with_outstanding_logout` |
| Match the `NameID` value, `NameQualifier`, `SPNameQualifier`, `SPProvidedID`, and effective `Format`. Collapse XML whitespace in the format URI and read an omitted format as `unspecified`. An assertion without a `NameID` does not match | Mandatory | Core §2.2.2, §3.3.4, §3.7.3.1, E60, `NameIDType` | Same methods |
| Require at least one matching `SessionIndex` when the request lists indexes. Apply a request without indexes to all sessions for that issuer and principal | Mandatory | Core §3.7.3.1, Profiles §4.4.4.1, E38, `LogoutRequestType` | Same methods |
| Apply the `NotOnOrAfter` skew to the logout deadline, and exclude the deadline itself | Mandatory | Core §3.7.3.1 | Same methods |
| Compare a present `Destination` with the receiving URL after collapsing XML whitespace. Require it on a signed browser POST response | Mandatory | Core §3.2.2, Bindings §3.5.5.2, CD-04 §2.4, XML Schema Part 2 §4.3.6 | `SamlValidationContext::with_recipient_endpoint` |
| The selected bearer assertion of a solicited or unsolicited response needs one satisfied confirmation whose `Recipient` matches the receiving assertion consumer URL | Mandatory | Core §3.2.2, Profiles §4.1.3, §4.1.4.3, E26 | `SamlValidationContext::with_recipient_endpoint` |
| In `finish_sso`, require the response to name the assertion consumer the pending request asked for, and reject a supplied receiving URL other than that one | Library policy: the `AuthnRequest` selected that consumer, so a response that names or reaches another one does not answer the request as sent. | Profiles §4.1.4.1, §4.1.4.3 | Always |
| Reject a supplied recipient endpoint that this SP does not publish as an `AssertionConsumerService` for the incoming binding | Library policy: the URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this SP does not operate for that binding. | Core §3.2.2 | `SamlValidationContext::with_recipient_endpoint` |
| Without a supplied URL, expect the assertion consumer the pending request asked for in `finish_sso`, and the default `AssertionConsumerService` for the incoming binding in `accept_unsolicited_sso` | Library policy: the library is not told which endpoint received the response. | Profiles §4.1.4.1, §4.1.5 | `SamlValidationContext::with_recipient_endpoint` |
| Report a status other than `Success` as an error after the signature, `Issuer`, correlation, and `Destination` checks. Reject a top-level code outside the four in Core | Library policy: a failed check takes precedence over the reported status, and no OASIS rule orders them. | Core §3.2.2.2, Profiles §4.1.4.3 | Always |
| Permit an unsigned error `Response` | Library policy: identity providers often send unsigned error responses. | Profiles §4.1.4.3 | Always |
| Permit omission of `InResponseTo` on an error `Response`. Compare a present value with the pending request ID after XML whitespace collapse for solicited errors, empty or not. Skip correlation for unsolicited errors | Library policy: a value for another request indicates a different exchange. | Core §3.2.2 | Always |
| Reject a received `RelayState` longer than 4096 bytes | Library policy: a resource limit on unauthenticated input. The bindings limit the sender to 80 bytes and set no receiver rule. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Reject a second `RelayState` value | Library policy: saml-rs compares, reports, or echoes only one value, and a caller's framework may read another. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Require the session `RelayState` to equal the pending request's when the request supplied one, empty or not | Library policy: Bindings §3.5.5.2 warns that an attacker can swap the `RelayState` values of two valid POST responses. | Bindings §3.4.3, §3.5.3, §3.5.5.2, CD-04 §2.3 | `finish_sso` |
| Accept a `RelayState` the identity provider adds when the request carried none, and on an unsolicited response | Optional | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| When verifying a SimpleSign signature, use the raw XML, then `RelayState` when present, then `SigAlg` | Mandatory | CD-04 §2.5, §2.6 | Always |
| Require `SigAlg` on every SimpleSign `Response` | Library policy: the SP keeps the selected binding and uses `SigAlg` to reconstruct the signature input. | CD-04 §2.4, §2.5, §2.10 | Always |
| Require a verified detached signature on a successful SimpleSign `Response`, even if it carries an XML signature | Library policy: the detached signature authenticates the full response and covers any `RelayState`. | CD-04 §2.4, §2.7.2 | Always |
| For a SimpleSign error `Response`, allow `Signature` to be absent only if neither the response nor its assertions carry an XML signature | Library policy: unsigned errors cannot establish sessions. Verify signatures before reporting a signed error's status. | CD-04 §2.4, §2.6, Profiles §4.1.4.3 | Always |
| Ignore ASCII whitespace in the message and the detached `Signature` value, and reject any other character outside the base64 alphabet | Library policy: Bindings §3.4.4.1 requires the sender to remove whitespace and §3.5.4 allows only line wrapping, so any other character means the value was altered. | Bindings §3.4.4.1, §3.5.4, RFC 2045 §6.8 | Always |

### Scoped attributes

The SP application can check scoped values in an accepted `SsoSession` before
using them for account lookup or access decisions. It decides whether to discard
reported values or decline the login. The [Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/saml-subject-id-attr-v1.0.html)
recommends discarding unauthorized subject identifiers. The [saml2int deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html)
requires an issuer-specific policy and restricts when the SP can rely on
metadata scopes.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Check the named attributes after acceptance against the assertion issuer's explicit policy or its unexpired registration-authority-signed metadata. Compare literal scopes case-sensitively | Mandatory capability | Subject Identifier §3.5.2, §4.2, saml2int SDP-SP17, E94 | `SsoSession::scoped_attribute_violations` |
| Ignore regular expression declarations for authorization | Optional | saml2int SDP-SP17 | Always |
| Report unscoped and unauthorized values. The application applies its policy to the reported values | Library policy: applications choose which attributes they use and how to handle violations. | Subject Identifier §3.5.2 | `SsoSession::scoped_attribute_violations` |

### Status codes

These rules apply to response recipients in SSO, Single Logout, name
identifier management, and artifact resolution.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require one `Status` with one top-level `StatusCode`, at most one subordinate `StatusCode`, and a `Value` on each of them | Mandatory | `StatusResponseType`, `StatusType`, `StatusCodeType` | Always |
| Collapse XML whitespace in both `StatusCode` values before comparing or reporting them | Mandatory | Core §3.2.2.2, `StatusCodeType`, [XML Schema Part 2 §4.3.6](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) | Always |

### Operator diagnostics

These rules apply to SP receipt of non-success HTTP-POST and
HTTP-POST-SimpleSign `Response` messages. For HTTP-Artifact, see
[artifact acceptance](web-browser-sso-artifact.md#service-provider-receipt).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read one nonempty, text-only protocol `StatusMessage` directly under `Status`. Omit diagnostics with attributes, child elements, or ambiguous cardinality | Optional | Core §3.2.2.1, §3.2.2.3, `StatusType` | Always |
| Expose the diagnostic after issuer and recipient checks only if a response signature or detached SimpleSign signature covers it | Library policy: the text must be attributable to the peer. | Core §3.2.2, Bindings §3.5.5.2, CD-04 §2.4 | Always |
| For solicited errors, expose the diagnostic only when `InResponseTo` and any requested `RelayState` match. For unsolicited errors, require an absent `InResponseTo` to expose it | Library policy: attach the text only to an error attributable to the current exchange. | Core §3.2.2, Bindings §3.5.3, CD-04 §2.3 | Always |

### Not implemented in the service provider

- Check of the bearer `Address` against the client address. Optional, Profiles §4.1.4.3.
- Association of an `EncryptedKey` positioned beside `EncryptedData` without a `RetrievalMethod`. Optional, Core §6.2, E43.
- Multicast reference from `ds:KeyName` to `xenc:CarriedKeyName`. Recommended, Core §6.2, E43.
- An `EncryptedID` that carries a `BaseID` or an `Assertion`. Optional, Core §2.2.4.

## Identity provider

`receive_sso` reads `IdpValidationPolicy::authn_request_signatures` and
`IdpValidationPolicy.xml_signatures`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a signed `AuthnRequest` | Optional | Metadata §2.4.3, E7 | `AuthnRequestValidationPolicy::RequireSigned` |
| Refuse an unsigned `AuthnRequest` when any SAML 2.0 `SPSSODescriptor` for the service provider sets `AuthnRequestsSigned` to true. Return only refusal data for an otherwise valid request | Mandatory | Metadata §2.4.4, E7 | Always |
| Reject MD5, RIPEMD-160, and RSA keys shorter than 2048 bits | Library policy: see [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys). | XMLDSig 1.1 §6.2, Conformance §4.1 | `XmlSignatureProfile::AllowWeakAlgorithms` relaxes it |
| Verify a signature on an `AuthnRequest` against the SP's signing credentials. The request has at most one direct `ds:Signature`. Redirect also verifies the query signature, and SimpleSign the detached signature when present, even when the request also carries an XML signature | Mandatory | Core §3.2.1, Bindings §3.4.4.1, CD-04 §2.4–2.6, §2.10 | Always |
| Parse a SimpleSign `AuthnRequest` with neither `Signature` nor `SigAlg` as HTTP-POST and apply the same request signature policy. Use the original binding to select the endpoint for the `Destination` check | Optional | CD-04 §2.10 | Always |
| Reject a SimpleSign `AuthnRequest` that carries only one of `Signature` and `SigAlg` | Library policy: either field signals a detached signature, which requires both fields to verify. | CD-04 §2.4, §2.5, §2.10 | Always |
| Reject an `IssueInstant` that is not UTC. A leap second is accepted | Mandatory | Core §1.3.3 | Always |
| Compare XML namespace names in an `AuthnRequest` after normalizing the declaration value | Mandatory | Namespaces in XML 1.0 §2.3, `AuthnRequestType` | Always |
| Accept an `AuthnRequest` `IssueInstant` from now − `max_age` − past tolerance through now + future tolerance, inclusive. A positive `NotOnOrAfter` skew supplies the past tolerance, and a negative `NotBefore` skew supplies the future tolerance | Library policy: Core §1.3.3 defines no maximum age, and the limit can reject a conformant request. | Core §1.3.3 | `SamlValidationContext::with_authn_request_age`, `RequestAgePolicy::Bounded` |
| Compare a present `Destination` with the receiving `SingleSignOnService` `Location` after collapsing XML whitespace. Require it on a signed request. `ResponseLocation` is unused | Mandatory | Core §3.2.1, Bindings §3.4.5.2, §3.5.5.2, CD-04 §2.4, Metadata §2.2.2, E41 | `SamlValidationContext::with_recipient_endpoint` |
| When checking `Destination` in `receive_sso`, reject a supplied receiving URL that is not published for the incoming binding, and several published URLs without an explicit one | Library policy: the URL is caller input, and the restriction keeps a value derived from the request from naming an endpoint this identity provider does not operate for that binding. | Core §3.2.1 | `SamlValidationContext::with_recipient_endpoint` |
| Verify that a requested ACS URL or index used for delivery names the SP's assertion consumer. Collapse XML whitespace in a requested URL before comparing | Mandatory | Profiles §4.1.4.1, `AuthnRequestType`, XML Schema Part 2 §4.3.6 | Always |
| Expose `ForceAuthn`, `IsPassive`, `RequestedAuthnContext`, the requested `Subject`, and `NameIDPolicy`. Presence never rejects the request, and the caller decides how to authenticate. A `Subject` with no identifier means the presenter | Optional | Core §3.4.1, §3.4.1.1, §3.4.1.4, E45, E75 | Always |
| Permit schema-allowed foreign attributes on `SubjectConfirmationData` in the requested `Subject` | Mandatory | Core §2.4.1.2, §3.4.1, `SubjectConfirmationDataType` | Always |
| Allow at most one `RequestedAuthnContext`. Require one or more assertion-namespace references, all class or all declaration. Keep them in request order, most preferred first. An optional unqualified `Comparison` is `exact`, `minimum`, `maximum`, or `better`, and defaults to `exact` | Mandatory | Core §3.3.2.2.1, E45, `RequestedAuthnContextType` | Always |
| Read the `ID` with XML whitespace collapsed, and write that value as `InResponseTo` | Mandatory | `RequestAbstractType`, Core §3.2.2, XML Schema Part 2 §3.3.8, §4.3.6 | `AuthnRequest::id` |
| Read context references with XML whitespace collapsed, including relative references | Library policy: Core §1.3.2 requires absolute URI references from the producer. | Core §1.3.2, XML Schema Part 2 §4.3.6 | `AuthnRequest::requested_authn_context` |
| Read `ForceAuthn`, `IsPassive`, and `AllowCreate` as `xs:boolean` and `AssertionConsumerServiceIndex` as `xs:unsignedShort`, with XML whitespace collapsed. Reject another value or a qualified attribute | Mandatory | `AuthnRequestType`, `NameIDPolicyType`, XML Schema Part 2 §3.2.2, §3.3.23, §4.3.6 | Always |
| Reject a qualified `Format`, `SPNameQualifier`, or `AllowCreate` on `NameIDPolicy`, and a qualified `Format`, `NameQualifier`, `SPNameQualifier`, or `SPProvidedID` on the requested `NameID` | Mandatory | Core §2.2.2, §3.4.1.1, `NameIDType`, `NameIDPolicyType` | Always |
| Reject a second `Subject`, a second identifier, or an identifier in a foreign namespace in a requested `Subject` | Mandatory | Core §3.4.1, `SubjectType` | Always |
| Process a requested encrypted `NameID` when decryption succeeds. If the key is absent, the unsigned ciphertext is ineligible, or decryption does not yield one `NameID`, retain the unread `EncryptedID`. Only an error response can answer that request | Mandatory | Conformance §3.4, Core §3.4.1, §3.4.1.4 | Always |
| Decrypt an unsigned request's `EncryptedID` only when its `EncryptedData` is AES-GCM | Library policy: Errata 05 E93 asks for integrity protection before CBC-encrypted data is processed, and AES-GCM authenticates the ciphertext. | Profiles §4.1.4.1, E93 | Always |
| Reject a received `RelayState` longer than 4096 bytes | Library policy: a resource limit on unauthenticated input. The bindings limit the sender to 80 bytes and set no receiver rule. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Reject a second `RelayState` value | Library policy: saml-rs compares, reports, or echoes only one value, and a caller's framework may read another. | Bindings §3.4.3, §3.5.3, CD-04 §2.3 | Always |
| Verify an HTTP-Redirect signature over `SAMLRequest`, then `RelayState` when present, then `SigAlg`, using the original URL-encoded values of the parameters found by decoded name. Raw-inflate the message after base64 decoding | Mandatory | Bindings §3.4.4.1 | Always |
| Raw-inflate the message when `SAMLEncoding` is absent or names DEFLATE | Mandatory | Bindings §3.4.4 | Always |
| Reject a repeated `SAMLEncoding`, or one that names another encoding, an empty value included | Library policy: saml-rs implements only DEFLATE, and inflating another encoding misreads the message. | Bindings §3.4.4 | Always |
| Reject a received HTTP-Redirect `RelayState`, or another SAML parameter the message reads, that is not UTF-8 after percent-decoding | Library policy: `RelayState` is text, and replacing the bytes would change the value the responder returns. | Bindings §3.4.3 | Always |
| When verifying a SimpleSign signature, use the raw XML, then `RelayState` when present, then `SigAlg` | Mandatory | CD-04 §2.5, §2.6 | Always |
| Ignore ASCII whitespace in the message and the detached `Signature` value, and reject any other character outside the base64 alphabet | Library policy: Bindings §3.4.4.1 requires the sender to remove whitespace and §3.5.4 allows only line wrapping, so any other character means the value was altered. | Bindings §3.4.4.1, §3.5.4, RFC 2045 §6.8 | Always |

### Not implemented in the identity provider

- Decoding of a `BaseID` in a requested `Subject`. Optional, Core §3.4.1.
- Treating the content of an unauthenticated `AuthnRequest` as advisory.
  Mandatory, Profiles §4.1.4.1. The caller decides from
  `Received::authentication`, which reports `MessageAuthentication::Unauthenticated`
  when no verified signature covers the request.
