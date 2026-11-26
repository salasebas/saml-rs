# SAML-defined identifiers

Attribute names, attribute name formats, name identifier formats, entity
identifiers, and generated `ID` values. In typed Web Browser SSO the identity provider writes
them with `respond_sso`, `initiate_sso`, `respond_sso_artifact`, and
`initiate_sso_artifact`, and reads a requested `<NameID>` with `receive_sso`.
The service provider reads them with `finish_sso` and `accept_unsolicited_sso`.
The generated-ID rules apply to every flow. This record claims neither
operational mode. Normative text is Conformance Requirements §3.3, Core §1.3.2, §1.3.4,
§2.7.3.1, §8.2, and §8.3, and Metadata §2.2.1, as corrected by Approved
Errata 05 E49, E55, E78, and E86. A `Format` URI is read as `xs:anyURI` (XML
Schema 1.0 Part 2 §3.2.17 and §4.3.6) with the escaping of
[XLink 1.0 §5.4](https://www.w3.org/TR/2001/REC-xlink-20010627/#link-locators),
RFC 2396, and RFC 2732. [Name identifier management](name-id-management.md)
and [Single Logout](single-logout.md) use the name identifier rules here.

## Attribute names and name formats

The identity provider writes `<Attribute>` elements with `SsoAssertion::attributes`, and the service provider reads them. A `FriendlyName` is a human-readable label for the `Name`. `<AttributeQuery>` and metadata `<RequestedAttribute>` are not claimed, so a service provider writes no `<Attribute>`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Support every Core §8.2 `NameFormat` on output | Mandatory | Conformance §3.3, Core §8.2 | `Attribute::with_name_format` |
| Allow another `NameFormat` URI or an omitted `NameFormat`, which means `unspecified` | Optional | Core §2.7.3.1 | `Attribute::with_name_format` |
| Reject a written `NameFormat` that is not an absolute URI reference | Mandatory | Core §1.3.2 | Always |
| Reject a `basic` attribute name that is not an `xs:Name` | Mandatory | Core §8.2.3 | Always |
| Reject a `uri` attribute name that is not an absolute URI reference, checked as written without whitespace collapse because `Name` is an `xs:string` | Mandatory | Core §1.3.2, §8.2.2 | Always |
| Reject a written `Name`, `FriendlyName`, or nonempty value with no non-whitespace character | Mandatory | Core §1.3.1, §2.7.3.1.1, `AttributeType` | Always |
| Omit `AttributeStatement` when the assertion has no attributes | Mandatory | Core §2.7.3, `AttributeStatementType` | Always |
| Omit `AttributeValue` for an attribute without values | Mandatory | Core §2.7.3.1 | Always |
| Write each value as its own `AttributeValue` | Recommended | Core §2.7.3.1 | Always |
| Write an empty value as an empty `AttributeValue` | Mandatory | Core §2.7.3.1.1 | Always |
| When an attribute has several values and any declares `xsi:type`, give every value the same datatype. The writer uses `xs:string` when it declares a type | Mandatory | Core §2.7.3.1 | Always |
| Write a `FriendlyName` only when the caller sets one, XML-escaped | Optional | Core §2.7.3.1 | `Attribute::with_friendly_name` |
| Write no `AttributeStatement` in an error `Response` | Mandatory | Profiles §4.1.4.2 | `SsoOutcome::Failure` |
| Support every Core §8.2 `NameFormat` on input | Mandatory | Conformance §3.3, Core §8.2 | `Attribute::name_format` |
| Read a received `NameFormat` with XML Schema whitespace collapse, and the `Name` as sent | Mandatory | `AttributeType`, XML Schema Part 2 §3.2.17, §4.3.6 | Always |
| Read the `FriendlyName` of an accepted `<Attribute>`, also one decrypted from an `<EncryptedAttribute>`, as sent | Optional | Core §2.7.3.1 | `Attribute::friendly_name` |
| Do not identify an attribute by its `FriendlyName`. `Attributes::get` matches the `Name`, and `Attributes::get_by_friendly_name` is for display and mapping only | Mandatory | Core §2.7.3.1 | Always |
| Reject an accepted `<Attribute>` without an unqualified `Name` | Mandatory | `AttributeType` | Always |
| Accept `Name=""`, and a `basic` name that is not an `xs:Name` | Library policy: Core §8.2.3 binds the producer, and the schema types `Name` as `xs:string`. | Core §8.2.3 | Always |
| Report a received `NameFormat` whether or not it is an absolute URI reference | Library policy: Core §1.3.2 binds the writer. | Core §1.3.2 | Always |
| Merge `<Attribute>` elements with the same `Name` and `NameFormat` into one `Attribute`, in document order, whatever their `FriendlyName` values. Treat an omitted `NameFormat` as `unspecified`, and report the `NameFormat` and `FriendlyName` of the first element | Library policy: E49 identifies an attribute by `NameFormat` and `Name` together, and the standard does not define how repeated elements combine. | Core §2.7.3.1, E49 | Always |

Core §2.7.3.1.1 lets a producer declare another simple datatype with
`xsi:type`, define structured content in an extension schema, or send a null
value, which must be an empty `AttributeValue` with `xsi:nil` set to `true` or
`1`. The identity provider writes none of these forms: `AttributeValue::new`
takes a string, which it writes as escaped text.

## Subject identifier attributes

The [Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html)
defines a general-purpose identifier in §3.3 and a pairwise identifier in
§3.4. Both use the same syntax.

### Identity provider

The identity provider writes these attributes with `SsoAssertion::attributes`.
`Attribute::from(SubjectId)` and `Attribute::from(PairwiseId)` supply the profile
name and format.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write the profile's `subject-id` or `pairwise-id` name with the `uri` `NameFormat` | Mandatory | Subject Identifier §3.3, §3.4 | `SsoAssertion::attributes` |
| Write each of these attributes at most once per assertion, with exactly one value | Mandatory | Subject Identifier §3.2, §3.3.1, §3.4.1 | Always |
| Write a `uniqueID@scope` value. Each part starts with an ASCII letter or digit and has 1 to 127 characters. The unique ID also allows `=` and `-`. The scope also allows `-` and `.` | Mandatory | Subject Identifier §3.3.1, §3.4.1 | `SubjectId::try_new`, `PairwiseId::try_new` |
| Omit `xsi:type` from these values | Recommended | Subject Identifier §3.3.1, §3.4.1 | Always |
| Write the scope in lowercase | Recommended | Subject Identifier §3.3.1, §3.5.2 | Always |
| Write the unique ID entirely in uppercase or entirely in lowercase | Recommended | Subject Identifier §3.3.1, §3.4.1 | Always |
| Bind a value to one subject and never reassign it. For a pairwise value, keep it stable within each relying party, vary it across relying parties, and prevent mapping to a non-pairwise identifier | Mandatory | Subject Identifier §3.3.2, §3.4.2 | Caller |

`PairwiseId` documents a derivation that uses lowercase hexadecimal. The
profile warns against Base64 because identifier equality ignores case.

### Service provider

`SsoSession::subject_id` and `SsoSession::pairwise_id` interpret the attributes
in an accepted assertion. The raw values remain in `SsoSession::attributes`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Match each attribute by its profile name and the `uri` format. Also accept an omitted or `unspecified` format for that name | Library policy: this follows the URI attribute mapping in Shibboleth SP. | Subject Identifier §3.3, §3.4, Core §2.7.3.1 | Always |
| Remove leading and trailing XML whitespace before parsing an identifier value | Mandatory | Subject Identifier §3.3.1, §3.4.1 | Always |
| Compare identifier values without regard to ASCII case. The value returned by `as_str` preserves its case | Mandatory | Subject Identifier §3.3.1, §3.4.1 | Always |
| Require exactly one value across matching attributes, in the profile grammar, when the caller reads the identifier | Library policy: the typed accessor needs one identifier. | Subject Identifier §3.2, §3.3.1 | `SsoSession::subject_id`, `SsoSession::pairwise_id` |
| Read a received identifier by its text regardless of `xsi:type` | Library policy: the type requirement applies to the producer. | Subject Identifier §3.3.1 | Always |

An identity provider can [publish scope declarations](metadata-and-replay.md#idp-scope-declarations)
under §4.1. A service provider can publish
[`subject-id:req`](metadata-and-replay.md#entity-attributes) and
[check an accepted session](web-browser-sso-acceptance.md#scoped-attributes)
under §4.2. The application configures the policy and acts on its result
before using the identifiers.

## Name identifier formats

The identity provider and service provider write and read `<NameID>` elements. Conformance §3.3 puts Core §8.3.7 and §8.3.8 on the producer.
`NameIdFormat` has a variant for each Core §8.3 identifier and `Custom` for any
other `Format` URI.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Support every Core §8.3 `Format` on input and output | Mandatory | Conformance §3.3, Core §8.3 | `NameId::with_format` |
| Allow another `Format` URI or an omitted `Format` | Optional | Core §2.2.2 | `NameId::with_format` |
| Reject a written `Format` that is not an absolute URI reference, in a `Response`, an `AuthnRequest` `NameIDPolicy`, a `LogoutRequest`, a `ManageNameIDRequest`, and metadata `NameIDFormat` | Mandatory | Core §1.3.2 | Always |
| Accept a received `Format` that is not an absolute URI reference, and report it | Library policy: Core §1.3.2 binds the writer. | Core §1.3.2 | Always |
| Read the `Format` of a received `NameID` or `NameIDPolicy` with XML Schema whitespace collapse: in an assertion `Subject`, a `LogoutRequest`, an `AuthnRequest` `Subject` or `NameIDPolicy`, and a `ManageNameIDRequest` | Mandatory | `NameIDType`, `NameIDPolicyType`, XML Schema Part 2 §3.2.17, §4.3.6 | `SsoSession::name_id`, `LogoutRequest::name_id`, `RequestedSubject::name_id`, `NameIdPolicy::format`, `ManageNameIdRequest::name_id` |
| Generate a transient value under the generated-ID rules below | Mandatory | Core §8.3.8, §1.3.4 | `NameId::generate_transient` |
| Reject a transient value of more than 256 characters that the identity provider writes in a `Response` or a `LogoutRequest` | Mandatory | Core §8.3.8 | Always |
| Generate a persistent value with no discernible correspondence to the subject | Mandatory | Core §8.3.7, E86 | `NameId::generate_persistent` |
| Generate a persistent value that is unique among those the identity provider issues for a service provider or affiliation | Mandatory | Core §8.3.7, E86 | `NameId::generate_persistent` |
| Reject a persistent value of more than 256 characters in `NameId::persistent`, and one that the identity provider writes in a `Response`, a `LogoutRequest`, or a `ManageNameIDRequest` `NameID` or `NewID` | Mandatory | Core §8.3.7 | Always |
| For a persistent or pairwise transient ID, omit `NameQualifier` only when context identifies its creator, and `SPNameQualifier` only in a message solely for the service provider it would name | Optional | Core §8.3.7, §8.3.8 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| Reject an `entity` `<NameID>` that the identity provider writes in a `Response`, a `LogoutRequest`, or a `ManageNameIDRequest` whose value or `NewID` is not an absolute URI reference of at most 1024 characters, or that has `NameQualifier`, `SPNameQualifier`, or `SPProvidedID` | Mandatory | Core §8.3.6, §1.3.2 | Always |
| Reject an `entity` value in those identity provider messages that the `anyURI` whitespace collapse would change | Library policy: a peer compares the value with an entity ID without collapsing it. | Core §8.3.6 | Always |
| Send a persistent `<NameID>` value over 256 characters in a service provider `LogoutRequest` or `ManageNameIDRequest`, and a transient one in a service provider `LogoutRequest`, unchanged | Library policy: Conformance §3.3 places Core §8.3.7 and §8.3.8 on the identity provider that produced the identifier, and the request must name the principal as it was issued. | Conformance §3.3, Core §3.6.1, Profiles §4.4.4.1 | Always |
| Forward an `entity` `<NameID>` that breaks Core §8.3.6 in those service provider requests as received | Library policy: a compatibility exception to Core §8.3.6, so that a session accepted from an identity provider that sent such an identifier can still be logged out or managed. | Core §8.3.6, Profiles §4.4.4.1, Core §3.6.1 | Always |
| For a persistent ID, write the alternative identifier most recently set by the service provider or affiliation, and omit `SPProvidedID` if none exists | Mandatory | Core §8.3.7, §3.6.3, E55 | `NameId::with_sp_provided_id` |
| Accept a caller-supplied persistent or transient value without checking randomness, opacity, or reassignment | Library policy: the crate cannot check those properties on a value it did not generate. | Core §8.3.7, §8.3.8 | `NameId::new` |
| Accept a received persistent or transient `<NameID>` that misses the producer rules, including one over 256 characters | Library policy: Conformance §3.3 places Core §8.3.7 and §8.3.8 on the producer. | Conformance §3.3 | Always |

The 256-character and 1024-character limits count Unicode scalar values and
apply to the effective format after XML whitespace collapse, including the
identity provider's first configured format when the issued `NameId` omits one.
An `entity` identifier such as
`<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://partner.example.org/metadata</NameID>`
has no qualifier attributes.

The caller owns these rules, and the crate has no identifier store or log.

- Assign a persistent value to one principal only, and store it so later
  responses reuse it through `NameId::persistent`. Mandatory, Core §8.3.7, E78.
- Keep a persistent value out of clear text shared with other providers and out
  of unprotected logs, and do not use the format for non-opaque values.
  Mandatory, Core §8.3.7.
- Treat a transient value as opaque and temporary. Recommended, Core §8.3.8.
- Set `NameQualifier` and `SPNameQualifier` to the entities Core §8.3.7
  names. Mandatory, Core §8.3.7.
- Omit `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` on an
  `entity`-format `NameId` that the service provider builds for a
  `LogoutRequest` or a `ManageNameIDRequest`, which write every qualifier
  they are given. Mandatory, Core §8.3.6.

A requested `NameIDPolicy` `SPNameQualifier` is checked as in
[Web Browser SSO generation](web-browser-sso-generation.md#identity-provider-response).

## Entity identifiers

The identity provider and service provider write their own `entityID` and `Issuer` and read a peer's.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an own entity identifier that is not an absolute URI reference of at most 1024 characters | Mandatory | Core §8.3.6, §1.3.2, Metadata §2.2.1 | `SpConfigBuilder::build`, `IdpConfigBuilder::build`, `generate_sp_metadata`, `generate_idp_metadata` |
| Reject an own entity identifier that the `anyURI` whitespace collapse would change | Library policy: an `Issuer` is an `xs:string` that a peer reads without collapsing it. | Core §8.3.6 | Always |
| Compare a received `Issuer` with the expected entity ID exactly, including in SOAP | Mandatory | Core §1.3.1, `NameIDType` | Always |
| Read an `Issuer`'s `Format` with [XML Schema whitespace collapse](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) where the flow checks that format | Mandatory | `NameIDType`, XML Schema Part 2 §4.3.6 | Always |
| Accept a peer entity identifier that is not an absolute URI reference or is longer than 1024 characters | Library policy: Core §8.3.6 and §1.3.2 bind the writer, so `EntityId::try_new` rejects only a value with nothing but XML whitespace. | Core §8.3.6, Metadata §2.2.1 | `EntityId::try_new` |

## Generated message and assertion identifiers

Every request, response, and assertion the crate generates takes its `ID` this way, in every flow. The `ID` is `_` and 160 random bits in hexadecimal, an `xs:ID` of 41 characters.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Generate an `xs:ID` with a pairwise collision probability of at most 2^-128 | Mandatory | Core §1.3.4 | Always |
| Keep the pairwise collision probability at most 2^-160 | Recommended | Core §1.3.4 | Always |
| Use the enclosing assertion's `ID` as each `SessionIndex`, so that the value cannot correlate the principal's activity across session participants | Recommended | Core §2.7.2 | Always |

Whether the identity provider writes a `SessionIndex` is a [Web Browser SSO generation](web-browser-sso-generation.md#identity-provider-response) rule: Profiles §4.1.4.2 requires one when the identity provider supports Single Logout.
