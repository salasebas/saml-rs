# SAML-defined identifiers

The identity provider and the service provider write their own entity
identifiers and generated `ID` values in every typed flow, and read a peer's
entity identifiers. The identity provider writes a `NameId` and the
attributes of `SsoAssertion::attributes`, and the service provider reads them
from `SsoSession`. [Name identifier management](name-id-management.md) and
[Single Logout](single-logout.md) use the name identifier rules here, and the
record claims neither operational mode.

Normative text is Conformance Requirements §3.3, Core §1.3, §2.2, §2.7.2,
§2.7.3, §8.2, and §8.3, and Metadata §2.2.1, as corrected by Approved Errata
05 E49, E55, E60, E78, and E86, and the
[Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html)
(Committee Specification 01). A URI reference, such as a `Format`, is read as
an `xs:anyURI` (XML Schema 1.0 Part 2 §3.2.17 and §4.3.6) with the escaping
of [XLink 1.0 §5.4](https://www.w3.org/TR/2001/REC-xlink-20010627/#link-locators),
RFC 2396, and RFC 2732.

<a id="encrypted-identifiers-and-attributes"></a>

The statuses hold on builds with a crypto provider. A build without one
neither encrypts nor decrypts identifiers and attributes. Its configuration
builders refuse `IdentifierEncryptionPolicy::EncryptIdentifiers` and
`AttributeEncryptionPolicy::EncryptAttributes`.

## Support

### Attributes

The identity provider writes attributes in the assertion of a `Response`, and
the service provider reads them. No API writes an `AttributeQuery` or a
metadata `RequestedAttribute`, so the service provider writes no `Attribute`
in a protocol message.

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| `Attribute` with a `Name` in an `AttributeStatement` | Core §2.7.3.1 | Supported | Supported |
| The `unspecified`, `uri`, and `basic` name formats | Conformance §3.3, Core §8.2 | Supported | Supported |
| Another `NameFormat` URI, or an omitted `NameFormat`, which means `unspecified` | Core §2.7.3.1 | Supported | Supported |
| `FriendlyName` | Core §2.7.3.1 | Supported | Supported |
| `EncryptedAttribute` | Core §2.7.3.2 | Supported | Supported |
| The `subject-id` attribute | Subject Identifier §3.3 | Supported | Supported |
| The `pairwise-id` attribute | Subject Identifier §3.4 | Supported | Supported |

Metadata carries the `subject-id:req` requirement and the scope declarations
of Subject Identifier §3.5, as the
[metadata extensions](metadata-and-replay.md#metadata-extensions) show.

### Attribute values that the identity provider writes

`AttributeValue::new` takes a string, which the identity provider writes as
escaped text.

| Feature | Section | Identity provider |
| --- | --- | --- |
| A value of another simple datatype, declared with `xsi:type` | Core §2.7.3.1.1 | Not supported |
| Structured content defined in an extension schema | Core §2.7.3.1.1 | Not supported |
| A null value: an empty `AttributeValue` with `xsi:nil` set to `true` or `1` | Core §2.7.3.1.1 | Not supported |

### Name identifiers

The identity provider writes name identifiers in a `Response`, a
`LogoutRequest`, and a `ManageNameIDRequest`, and reads them in the requested
`Subject` of an `AuthnRequest`, a `LogoutRequest`, and a `ManageNameIDRequest`.
The service provider writes them in a `LogoutRequest` and a
`ManageNameIDRequest`, and reads them in an assertion `Subject` and in those
two requests. Neither role writes a transient identifier in a
`ManageNameIDRequest`, as
[name identifier management](name-id-management.md#turning-the-protocol-on)
states.

| Feature | Section | Identity provider writes | Identity provider reads | Service provider writes | Service provider reads |
| --- | --- | --- | --- | --- | --- |
| `NameID` | Core §2.2.3 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` | Core §2.2.2 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| An omitted `Format`, which means `unspecified` | Core §2.2.2, E60 | Supported | Supported | Supported | Supported |
| The `unspecified`, `emailAddress`, `X509SubjectName`, `WindowsDomainQualifiedName`, and `kerberos` formats | Conformance §3.3, Core §8.3.1 to §8.3.5 | Supported | Supported | Supported | Supported |
| The `entity` format | Conformance §3.3, Core §8.3.6 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| The `persistent` format | Conformance §3.3, Core §8.3.7 | Supported | Supported | Supported | Supported |
| The `transient` format | Conformance §3.3, Core §8.3.8 | Supported | Supported | Supported | Supported |
| Another `Format` URI | Core §2.2.2 | Supported | Supported | Supported | Supported |
| `EncryptedID` that carries a `NameID` | Core §2.2.4 | Supported | Supported | [Partial](#service-provider-requests) | Supported |
| The identifier in a `BaseID` | Core §2.2.1 | Not supported | Not supported | Not supported | Not supported |
| The identifier in an `EncryptedID` that carries a `BaseID` or an `Assertion` | Core §2.2.4 | Not supported | Not supported | Not supported | Not supported |

### Entity and generated identifiers

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| The provider's own entity identifier, written as `entityID` and `Issuer` | Core §2.2.5, §8.3.6, Metadata §2.2.1 | Supported | Supported |
| A peer's entity identifier, read from metadata and `Issuer` | Core §2.2.5, §8.3.6, Metadata §2.2.1 | Supported | Supported |
| The `ID` of each request, response, and assertion the provider writes | Core §1.3.4 | Supported | Supported |
| The value of each `SessionIndex` on an `AuthnStatement` | Core §2.7.2 | Supported | — |

## Partial support

### Service provider requests

- **Supported:** a service provider `LogoutRequest` or `ManageNameIDRequest`
  writes the `NameID` of the `NameId` it is given, in the clear or in an
  `EncryptedID`, and refuses a `Format` that is not an absolute URI
  reference.
- **Not supported:** it writes a value or qualifier that holds only XML
  whitespace, which Core §1.3.1 forbids, and an `entity` `NameID` that breaks
  Core §8.3.6, unchanged. The
  [service provider policy](#service-provider-request-policy) gives the
  reason for the `entity` case.

## Rules

<a id="attribute-names-and-name-formats"></a>

### Identity provider: `SsoAssertion::attributes`

Code: `src/idp/login_response.rs`, `src/model/attributes.rs`, `src/xml/name.rs`, `src/xml/any_uri.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a written `NameFormat` that is not an absolute URI reference | Mandatory | Core §1.3.2 | Always |
| Reject a `basic` attribute name that is not an `xs:Name` | Mandatory | Core §8.2.3 | Always |
| Reject a `uri` attribute name that is not an absolute URI reference, checked as written, without whitespace collapse | Mandatory | Core §1.3.2, §8.2.2, `AttributeType` | Always |
| Reject a written `Name`, `FriendlyName`, or nonempty value with no non-whitespace character | Mandatory | Core §1.3.1, §2.7.3.1.1, `AttributeType` | Always |
| Omit `AttributeStatement` when the assertion has no attributes | Mandatory | Core §2.7.3, `AttributeStatementType` | Always |
| Omit `AttributeValue` for an attribute without values | Mandatory | Core §2.7.3.1 | Always |
| Write each value as its own `AttributeValue` | Recommended | Core §2.7.3.1 | Always |
| Write an empty value as an empty `AttributeValue` | Mandatory | Core §2.7.3.1.1 | Always |
| When an attribute has several values and any declares `xsi:type`, give every value the same datatype. The writer uses `xs:string` when it declares a type | Mandatory | Core §2.7.3.1, E49 | Always |
| Write a `FriendlyName`, XML-escaped, only when the caller sets one | Optional | Core §2.7.3.1 | `Attribute::with_friendly_name` |
| Write no `AttributeStatement` in an error `Response` | Mandatory | Profiles §4.1.4.2 | Always |

### Service provider: `SsoSession::attributes`

Code: `src/model/extract.rs`, `src/model/attributes.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an accepted `<Attribute>` without an unqualified `Name` | Mandatory | `AttributeType` | Always |
| Read a received `NameFormat` with XML Schema whitespace collapse, and the `Name` as sent | Mandatory | `AttributeType`, XML Schema Part 2 §3.2.17, §4.3.6 | Always |
| Read the `FriendlyName` of an accepted `<Attribute>`, also one decrypted from an `<EncryptedAttribute>`, as sent | Optional | Core §2.7.3.1 | Always |
| Match the `Name` in `Attributes::get`, never the `FriendlyName`. `Attributes::get_by_friendly_name` is a separate lookup | Mandatory | Core §2.7.3.1 | Always |

<a id="subject-identifier-attributes"></a>
<a id="identity-provider"></a>

### Identity provider: `SubjectId`, `PairwiseId`

Code: `src/model/subject_identifier.rs`, `src/idp/login_response.rs`

`Attribute::from(SubjectId)` and `Attribute::from(PairwiseId)` supply the
profile name and format, and `SsoAssertion::attributes` writes them. The
writer applies these rows to every attribute with either profile name and the
`uri` or `unspecified` `NameFormat`, or none.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write the profile's `subject-id` or `pairwise-id` name with the `uri` `NameFormat` | Mandatory | Subject Identifier §3.3, §3.4 | Always |
| Write each of these attributes at most once per assertion, with exactly one value | Mandatory | Subject Identifier §3.2, §3.3.1, §3.4.1 | Always |
| Write a `uniqueID@scope` value. Each part starts with an ASCII letter or digit and has 1 to 127 characters. The unique ID also allows `=` and `-`. The scope also allows `-` and `.` | Mandatory | Subject Identifier §3.3.1, §3.4.1 | Always |
| Omit `xsi:type` from these values | Recommended | Subject Identifier §3.3.1, §3.4.1 | Always |
| Write the scope in lowercase | Recommended | Subject Identifier §3.3.1, §3.5.2 | Always |
| Write the unique ID entirely in uppercase or entirely in lowercase | Recommended | Subject Identifier §3.3.1, §3.4.1 | Always |

<a id="service-provider"></a>

### Service provider: `SsoSession::subject_id`, `SsoSession::pairwise_id`

Code: `src/model/subject_identifier.rs`

These accessors interpret the attributes in an accepted assertion. The raw
values remain in `SsoSession::attributes`.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Remove leading and trailing XML whitespace before parsing an identifier value | Mandatory | Subject Identifier §3.3.1, §3.4.1 | Always |
| Compare identifier values without regard to ASCII case. The value returned by `as_str` preserves its case | Mandatory | Subject Identifier §3.3.1, §3.4.1 | Always |

An identity provider can [publish scope declarations](metadata-and-replay.md#idp-scope-declarations)
under §4.1. A service provider can publish
[`subject-id:req`](metadata-and-replay.md#entity-attributes) and
[check an accepted session](web-browser-sso-acceptance.md#scoped-attributes)
under §4.2.

<a id="name-identifier-formats"></a>

### Identity provider and service provider: written `Format`

Code: `src/model/subject.rs`, `src/xml/any_uri.rs`, `src/idp.rs`, `src/sp.rs`, `src/logout/creation.rs`, `src/name_id_management/xml.rs`, `src/metadata/generate.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a written `Format` that is not an absolute URI reference, in a `Response`, an `AuthnRequest` `NameIDPolicy`, a `LogoutRequest`, a `ManageNameIDRequest`, and metadata `NameIDFormat` | Mandatory | Core §1.3.2 | Always |

### Identity provider: `NameId` in a `Response`, a `LogoutRequest`, or a `ManageNameIDRequest`

Code: `src/model/subject.rs`, `src/config/descriptors.rs`, `src/entity.rs`, `src/idp.rs`, `src/logout/creation.rs`, `src/name_id_management/xml.rs`

The rows cover the `NameID` of each of these messages and the `NewID` of a
`ManageNameIDRequest`. The 256-character and 1024-character limits count
Unicode scalar values and apply to the effective format after XML whitespace
collapse, including the identity provider's first configured format when the
issued `NameId` omits one.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a value, `NameQualifier`, `SPNameQualifier`, `SPProvidedID`, or `NewID` with no character other than XML whitespace | Mandatory | Core §1.3.1, XML 1.0 §2.3 | Always |
| Generate a transient value under the [generated-ID rules](#generated-message-and-assertion-identifiers) | Mandatory | Core §8.3.8, §1.3.4 | `NameId::generate_transient` |
| Generate a persistent value with no discernible correspondence to the subject, unique among those the identity provider issues for a service provider or affiliation | Mandatory | Core §8.3.7, E86 | `NameId::generate_persistent` |
| Reject a transient value of more than 256 characters in a `Response` or a `LogoutRequest` | Mandatory | Core §8.3.8 | Always |
| Reject a persistent value of more than 256 characters, in `NameId::persistent` and in each of these messages | Mandatory | Core §8.3.7 | Always |
| Reject an `entity` `NameID` whose value or `NewID` is not an absolute URI reference of at most 1024 characters, or that has `NameQualifier`, `SPNameQualifier`, or `SPProvidedID` | Mandatory | Core §8.3.6, §1.3.2 | Always |

A requested `NameIDPolicy` `SPNameQualifier` is checked as in
[Web Browser SSO generation](web-browser-sso-generation.md#identity-provider-response).

### Identity provider and service provider: `SsoSession::name_id`, `LogoutRequest::name_id`, `RequestedSubject::name_id`, `NameIdPolicy::format`, `ManageNameIdRequest::name_id`

Code: `src/model/extract.rs`, `src/model/authn.rs`, `src/name_id_management.rs`, `src/config/algorithms.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the `Format` of a received `NameID` or `NameIDPolicy` with XML Schema whitespace collapse: in an assertion `Subject`, a `LogoutRequest`, an `AuthnRequest` `Subject` or `NameIDPolicy`, and a `ManageNameIDRequest` | Mandatory | `NameIDType`, `NameIDPolicyType`, XML Schema Part 2 §3.2.17, §4.3.6 | Always |

<a id="entity-identifiers"></a>

### Identity provider and service provider: `SpConfigBuilder::build`, `IdpConfigBuilder::build`, `generate_sp_metadata`, `generate_idp_metadata`

Code: `src/config/descriptors.rs`, `src/metadata/generate.rs`, `src/xml/any_uri.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an own entity identifier that is not an absolute URI reference of at most 1024 characters, read as an `xs:anyURI`, which allows an inner space | Mandatory | Core §8.3.6, §1.3.2, Metadata §2.2.1, `entityIDType` | Always |

### Identity provider and service provider: received `Issuer`

Code: `src/xml/protocol_element.rs`, `src/flow/response_issuer.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Compare a received `Issuer` with the expected entity ID exactly, including in SOAP | Mandatory | Core §1.3.1, `NameIDType` | Always |
| Read an `Issuer`'s `Format` with [XML Schema whitespace collapse](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) where the flow checks that format | Mandatory | `NameIDType`, XML Schema Part 2 §4.3.6 | Always |

<a id="generated-message-and-assertion-identifiers"></a>

### Identity provider and service provider: generated `ID` values

Code: `src/entity.rs`

Every request, response, and assertion the crate writes, in every flow, takes
an `ID` of `_` and 160 random bits in hexadecimal, an `xs:ID` of 41
characters.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Generate an `xs:ID` with a pairwise collision probability of at most 2^-128 | Mandatory | Core §1.3.4 | Always |
| Keep the pairwise collision probability at most 2^-160 | Recommended | Core §1.3.4 | Always |

### Identity provider: `SessionIndex` of a login `Response`

Code: `src/idp.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Use the enclosing assertion's `ID` as each `SessionIndex`, so that the value cannot correlate the principal's activity across session participants | Recommended | Core §2.7.2 | Always |

Whether the identity provider writes a `SessionIndex` is a
[Web Browser SSO generation](web-browser-sso-generation.md#identity-provider-response)
rule: Profiles §4.1.4.2 requires one when the identity provider supports
Single Logout.

## Library policies

### Service provider: `SsoSession::attributes`

Code: `src/model/extract.rs`, `src/model/attributes.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept `Name=""`, and a `basic` name that is not an `xs:Name` | Reason not recorded. | Core §8.2.3, `AttributeType` | Always |
| Report a received `NameFormat` whether or not it is an absolute URI reference | Reason not recorded. | Core §1.3.2 | Always |
| Merge `<Attribute>` elements with the same `Name` and `NameFormat` into one `Attribute`, in document order, whatever their `FriendlyName` values. Treat an omitted `NameFormat` as `unspecified`, and report the `NameFormat` and `FriendlyName` of the first element | E49 identifies an attribute by `NameFormat` and `Name` together, and the standard does not define how repeated elements combine. | Core §2.7.3.1, E49 | Always |

### Service provider: `SsoSession::subject_id`, `SsoSession::pairwise_id`

Code: `src/model/subject_identifier.rs`, `src/model/attributes.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Match each attribute by its profile name and the `uri` format. Also accept an omitted or `unspecified` format for that name | Reason not recorded. | Subject Identifier §3.3, §3.4, Core §2.7.3.1 | Always |
| Require exactly one value across matching attributes, in the profile grammar, when the caller reads the identifier | the typed accessor needs one identifier. | Subject Identifier §3.2, §3.3.1 | Always |
| Read a received identifier by its text regardless of `xsi:type` | the type requirement applies to the producer. | Subject Identifier §3.3.1 | Always |

[Shibboleth SP 3.5.0](https://codeberg.org/Shibboleth/cpp-sp/src/tag/3.5.0/shibsp/attribute/resolver/impl/XMLAttributeExtractor.cpp#L516-L543)
maps an attribute with an omitted or `unspecified` `NameFormat` that has no
rule of its own to the rule configured for the `uri` format.

### Identity provider: `NameId` in a `Response`, a `LogoutRequest`, or a `ManageNameIDRequest`

Code: `src/model/subject.rs`, `src/config/descriptors.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an `entity` value that the `anyURI` whitespace collapse would change | A peer compares the value with an entity ID without collapsing it, so a value that collapse would change matches no entity ID. | Core §8.3.6 | Always |
| Accept a caller-supplied persistent or transient value without checking randomness, opacity, or reassignment | The crate cannot check those properties on a value it did not generate. | Core §8.3.7, §8.3.8 | `NameId::new` |

<a id="service-provider-request-policy"></a>

### Service provider: `NameId` in a `LogoutRequest` or a `ManageNameIDRequest`

Code: `src/logout/creation.rs`, `src/name_id_management/xml.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Write a persistent `NameID` value over 256 characters, a transient one in a `LogoutRequest`, and an `entity` `NameID` that breaks Core §8.3.6, unchanged | The request names the principal as the identity provider issued it, so a session accepted with such an identifier can still be logged out or managed. | Conformance §3.3, Core §3.6.1, §8.3.6, Profiles §4.4.4.1 | Always |

### Identity provider and service provider: `SsoSession::name_id`, `LogoutRequest::name_id`, `RequestedSubject::name_id`, `NameIdPolicy::format`, `ManageNameIdRequest::name_id`

Code: `src/model/extract.rs`, `src/model/authn.rs`, `src/name_id_management.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept a received `Format` that is not an absolute URI reference, and report it | Reason not recorded. | Core §1.3.2 | Always |
| Accept a received persistent or transient `<NameID>` that misses the producer rules, including one over 256 characters | Reason not recorded. | Conformance §3.3, Core §8.3.7, §8.3.8 | Always |

### Identity provider and service provider: `SpConfigBuilder::build`, `IdpConfigBuilder::build`, `generate_sp_metadata`, `generate_idp_metadata`

Code: `src/config/descriptors.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an own entity identifier that the `anyURI` whitespace collapse would change | A peer reads the metadata `entityID` with whitespace collapse but compares the `Issuer`, an `xs:string`, exactly, so the two would differ. | Core §8.3.6, §1.3.1 | Always |

### Identity provider and service provider: `EntityId::try_new`, `accept_unsolicited_sso_with_resolver`

Code: `src/config/descriptors.rs`, `src/flow/response_issuer.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept a peer entity identifier that is not an absolute URI reference or is longer than 1024 characters, in `EntityId::try_new` and as the `Issuer` passed to the IdP resolver. Reject only a value with nothing but XML whitespace | A peer whose entity ID is not a URI, such as `idp.example.com`, can still be configured and resolved. | Core §8.3.6, Metadata §2.2.1 | Always |

## Application duties

The crate has no identifier store or log.

| Duty | Level | Section |
| --- | --- | --- |
| Give the provider an entity identifier that is a URL containing its own domain name. `SpConfig::builder` and `IdpConfig::builder` accept any absolute URI, such as a URN, and check no domain | Recommended | Core §8.3.6 |
| Identity provider: assign a persistent value to one principal only, and store it so later responses reuse it through `NameId::persistent` | Mandatory | Core §8.3.7, E78 |
| Identity provider and service provider: keep a persistent value out of clear text shared with providers other than those that established it, and out of log files without appropriate controls | Mandatory | Core §8.3.7 |
| Identity provider: do not use the persistent format for values that are not opaque | Mandatory | Core §8.3.7 |
| Identity provider: generate a transient value passed to `NameId::new` under the Core §1.3.4 rules, as `NameId::generate_transient` does | Mandatory | Core §8.3.8, §1.3.4 |
| Identity provider: when a persistent or pairwise transient `NameId` carries `NameQualifier` or `SPNameQualifier`, set them with `NameId::with_name_qualifier` and `NameId::with_sp_name_qualifier` to the entities Core §8.3.7 names | Mandatory | Core §8.3.7, §8.3.8 |
| Identity provider: for a persistent or pairwise transient `NameId`, omit `NameQualifier` only when context identifies its creator, and `SPNameQualifier` only in a message solely for the service provider it would name | Optional | Core §8.3.7, §8.3.8 |
| Identity provider: set the `SPProvidedID` of a persistent `NameId` to the alternative identifier that the service provider or affiliation most recently set, with `NameId::with_sp_provided_id`, and set none if no such identifier exists | Mandatory | Core §8.3.7, §3.6.3, E55 |
| Identity provider: bind a `subject-id` or `pairwise-id` value to one subject and never reassign it. For a pairwise value, keep it stable within each relying party, vary it across relying parties, and prevent mapping to a non-pairwise identifier | Mandatory | Subject Identifier §3.3.2, §3.4.2 |
| Service provider: omit `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` on an `entity`-format `NameId` that it builds for a `LogoutRequest` or a `ManageNameIDRequest`, which write every qualifier they are given | Mandatory | Core §8.3.6 |
| Service provider: treat a transient value as opaque and temporary | Recommended | Core §8.3.8 |
| Service provider: identify an attribute by its `Name` and `NameFormat`, not its `FriendlyName`. Use `Attributes::get_by_friendly_name` for display and mapping only | Mandatory | Core §2.7.3.1 |
| Service provider: before using `SsoSession::subject_id` or `SsoSession::pairwise_id`, check its scope with `SsoSession::scoped_attribute_violations` or another policy, and discard a value whose scope the issuer may not assert | Recommended | Subject Identifier §3.5.2 |

The [name identifier management duties](name-id-management.md#after-the-exchange)
cover the `SPProvidedID` after a `NewID`.

## Not supported

- The identifier in a `BaseID`, and in an `EncryptedID` that carries a
  `BaseID` or an `Assertion`, for both roles. Core §2.2.1 defines `BaseID` as
  an extension point with no SAML-defined type, and neither role writes one.
  A `LogoutRequest` that carries a `BaseID` has no `LogoutRequest::name_id`,
  and the receiver can still answer it with `respond_slo`. The identity
  provider reports a requested `BaseID` as
  `RequestedSubjectIdentifier::BaseId`, and the service provider refuses an
  assertion whose `Subject` carries one.
