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
| Omit `AttributeStatement` when the assertion has no attributes | Mandatory | Core §2.7.3, `AttributeStatementType` | Always |
| Omit `AttributeValue` for an attribute without values | Mandatory | Core §2.7.3.1 | Always |
| Write each value as its own `AttributeValue` | Recommended | Core §2.7.3.1 | Always |
| When an attribute has several values and any declares `xsi:type`, give every value the same datatype. The writer uses `xs:string` when it declares a type | Mandatory | Core §2.7.3.1 | Always |
| Write a `FriendlyName` only when the caller sets one, XML-escaped. Any string of XML characters is written, the empty string included | Optional | Core §2.7.3.1 | `Attribute::with_friendly_name` |
| Write no `AttributeStatement` in an error `Response` | Mandatory | Profiles §4.1.4.2 | `SsoOutcome::Failure` |
| Support every Core §8.2 `NameFormat` on input | Mandatory | Conformance §3.3, Core §8.2 | `Attribute::name_format` |
| Read the `FriendlyName` of an accepted `<Attribute>`, also one decrypted from an `<EncryptedAttribute>`, as sent | Optional | Core §2.7.3.1 | `Attribute::friendly_name` |
| Do not identify an attribute by its `FriendlyName`. `Attributes::get` matches the `Name`, and `Attributes::get_by_friendly_name` is for display and mapping only | Mandatory | Core §2.7.3.1 | Always |
| Reject an accepted `<Attribute>` without an unqualified `Name` | Mandatory | `AttributeType` | Always |
| Accept `Name=""`, and a `basic` name that is not an `xs:Name` | Library policy: Core §8.2.3 binds the producer, and the schema types `Name` as `xs:string`. | Core §8.2.3 | Always |
| Report a received `NameFormat` as sent, whether or not it is an absolute URI reference | Library policy: Core §1.3.2 binds the writer. | Core §1.3.2 | Always |
| Merge `<Attribute>` elements with the same `Name` and `NameFormat` into one `Attribute`, in document order, whatever their `FriendlyName` values. Treat an omitted `NameFormat` as `unspecified`, and report the `NameFormat` and `FriendlyName` of the first element | Library policy: E49 identifies an attribute by `NameFormat` and `Name` together, and the standard does not define how repeated elements combine. | Core §2.7.3.1, E49 | Always |

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
| Accept a received `Format` that is not an absolute URI reference, and report it as sent | Library policy: Core §1.3.2 binds the writer. | Core §1.3.2 | Always |
| Generate a transient value under the generated-ID rules below | Mandatory | Core §8.3.8, §1.3.4 | `NameId::generate_transient` |
| Reject a transient value of more than 256 characters in a `Response` | Mandatory | Core §8.3.8 | Always |
| Generate a persistent value with no discernible correspondence to the subject | Mandatory | Core §8.3.7, E86 | `NameId::generate_persistent` |
| Generate a persistent value that is unique among those the identity provider issues for a service provider or affiliation | Mandatory | Core §8.3.7, E86 | `NameId::generate_persistent` |
| Reject a persistent value of more than 256 characters, in a `Response` and in `NameId::persistent` | Mandatory | Core §8.3.7 | Always |
| For a persistent or pairwise transient ID, omit `NameQualifier` only when context identifies its creator, and `SPNameQualifier` only in a message solely for the service provider it would name | Optional | Core §8.3.7, §8.3.8 | `NameId::with_name_qualifier`, `NameId::with_sp_name_qualifier` |
| For a persistent ID, write the alternative identifier most recently set by the service provider or affiliation, and omit `SPProvidedID` if none exists | Mandatory | Core §8.3.7, §3.6.3, E55 | `NameId::with_sp_provided_id` |
| Accept a caller-supplied persistent or transient value without checking randomness, opacity, or reassignment | Library policy: the crate cannot check those properties on a value it did not generate. | Core §8.3.7, §8.3.8 | `NameId::new` |
| Accept a received persistent or transient `<NameID>` that misses the producer rules, including one over 256 characters | Library policy: Conformance §3.3 places Core §8.3.7 and §8.3.8 on the producer. | Conformance §3.3 | Always |

The 256-character limit counts Unicode scalar values and applies to the effective
format after XML whitespace collapse, including the identity provider's first
configured format when the issued `NameId` omits one.

The caller owns these rules, and the crate has no identifier store or log.

- Assign a persistent value to one principal only, and store it so later
  responses reuse it through `NameId::persistent`. Mandatory, Core §8.3.7, E78.
- Keep a persistent value out of clear text shared with other providers and out
  of unprotected logs, and do not use the format for non-opaque values.
  Mandatory, Core §8.3.7.
- Treat a transient value as opaque and temporary. Recommended, Core §8.3.8.
- Set `NameQualifier` and `SPNameQualifier` to the entities Core §8.3.7
  names, and omit `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` on an
  `entity`-format `<NameID>`. Mandatory, Core §8.3.6, §8.3.7.

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
| Accept a peer entity identifier that is not an absolute URI reference or is longer than 1024 characters | Library policy: Core §8.3.6 and §1.3.2 bind the writer, so `EntityId::try_new` rejects only a value without a non-whitespace character. | Core §8.3.6, Metadata §2.2.1 | `EntityId::try_new` |

## Generated message and assertion identifiers

Every request, response, and assertion the crate generates takes its `ID` this way, in every flow. The `ID` is `_` and 160 random bits in hexadecimal, an `xs:ID` of 41 characters.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Generate an `xs:ID` with a pairwise collision probability of at most 2^-128 | Mandatory | Core §1.3.4 | Always |
| Keep the pairwise collision probability at most 2^-160 | Recommended | Core §1.3.4 | Always |
| Use the enclosing assertion's `ID` as the `SessionIndex` when the identity provider publishes Single Logout metadata | Recommended | Core §2.7.2 | Always |
