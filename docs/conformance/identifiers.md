# SAML-defined identifiers

Attribute names, attribute name formats, and name identifier formats in typed
Web Browser SSO.
The identity provider writes them with `respond_sso`, `initiate_sso`,
`respond_sso_artifact`, and `initiate_sso_artifact`. The
service provider reads them with `finish_sso` and `accept_unsolicited_sso`.
The identity provider reads a requested `<NameID>` with `receive_sso`. This
page does not claim the IdP operational mode or the SP operational mode.

[Entity identifiers](#entity-identifiers) covers the `entityID` and `Issuer`
of the provider the crate configures, and of its peers.
[Generated message and assertion identifiers](#generated-message-and-assertion-identifiers)
covers the `ID` of every message and assertion the crate generates, in every
flow.
[Subject identifier attributes](#subject-identifier-attributes) covers the
`subject-id` and `pairwise-id` attributes in the same Web Browser SSO
operations.

Normative text is Conformance Requirements §3.3, SAML Core §1.3.2, §1.3.4,
§2.2.2, §2.7.3.1, §8.2, and §8.3, and Metadata §2.2.1, as corrected by Approved
Errata 05 E49, E55, E78, and E86. A `Format` URI is read as XML Schema 1.0 Part 2 §3.2.17 and
§4.3.6 define `anyURI`, with the escaping of
[XLink 1.0 §5.4](https://www.w3.org/TR/2001/REC-xlink-20010627/#link-locators),
RFC 2396, and RFC 2732.

Conformance §3.3 says a producer is able to create, and a consumer is able to
process, every identifier constant in Core §8.2 and §8.3. To process an
identifier is to parse and handle it without failing. What an application does
with it afterwards is outside that section. The same section says Core §8.3.7
and §8.3.8 are rules for the producer of the identifier. No receiver row below
rejects a message.

An `<Attribute>` travels one way in these flows: from the identity provider's
assertion to the service provider. `<AttributeQuery>` and metadata
`<RequestedAttribute>` are not claimed features, so a service provider writes
no `<Attribute>` and an identity provider reads none.

## Attribute names and name formats

`AttributeNameFormat` is `Unspecified`, `Uri`, `Basic`, or `Custom` for any
other `NameFormat` URI. An `Attribute` can also carry a `FriendlyName`, a
human-readable label for its `Name`.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An `<Attribute>` carries any Core §8.2 identifier, another URI, or no `NameFormat` | Identity provider | Generate Response | Optional. Core §2.7.3.1 and §8.2 say the identifiers `MAY` be used. Conformance §3.3 requires the producer to be able to create each one. `SsoAssertion::with_attributes` writes the `AttributeStatement`. `Attribute::with_name_format` writes that format's URI. An `Attribute::new` without it omits `NameFormat`, and `unspecified` is then in effect (Core §2.7.3.1). No attributes writes no statement |
| A written `NameFormat` is an absolute URI reference | Identity provider | Generate Response | Mandatory. Core §1.3.2: a URI reference value in a SAML-defined attribute has at least one non-whitespace character and is absolute, read as for a [name identifier format](#name-identifier-formats). A response whose `SsoAssertion::with_attributes` has one that is not returns `SamlError::Invalid` before it is signed. A received `NameFormat` is reported as sent |
| A `basic` attribute name is an `xs:Name` | Identity provider | Generate Response | Mandatory. Core §8.2.3. A response with a `basic` name that is not an `xs:Name` is not generated. `Custom` with the `basic` URI is the `basic` format. The name is checked against the XML 1.0 Fifth Edition `Name` production, which this crate also uses for `xs:NCName`. `unspecified` and `uri` have no rule to check: Conformance §3.3 says they specify no normative processing rules |
| An `<Attribute>` carries a `FriendlyName` only when the caller sets one | Identity provider | Generate Response | Optional. Core §2.7.3.1 lists `FriendlyName` as `[Optional]`, and the schema types it as `xs:string`. `Attribute::with_friendly_name` sets it, and the response writes it XML-escaped. Any string of XML characters is written, the empty string included. An attribute without one has no `FriendlyName` |
| An attribute without values has no `<AttributeValue>` | Identity provider | Generate Response | Mandatory. Core §2.7.3.1 |
| Each value is its own `<AttributeValue>`, and every value has the same datatype | Identity provider | Generate Response | Recommendation for one element per value, and a requirement for one datatype once any value declares `xsi:type`. Core §2.7.3.1. Each value has the XML Schema `string` type, including when `xs` or `xsi` is the configured assertion prefix. A `subject-id` or `pairwise-id` value has no `xsi:type`, as [Subject identifier attributes](#subject-identifier-attributes) records |
| An error `Response` has no `AttributeStatement` | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2: an error response includes no assertions. `SsoOutcome::Failure` carries no `SsoAssertion`, so it has no attributes to write |
| The `NameFormat` of an accepted `<Attribute>` is read, whatever its URI | Service provider | Accept Response | Mandatory. Conformance §3.3. `Attribute::name_format` is the `AttributeNameFormat`, and `AttributeNameFormat::as_uri` gives its URI. It is `None` when the element has no `NameFormat` |
| The `FriendlyName` of an accepted `<Attribute>` is read | Service provider | Accept Response | Library behaviour. Core §2.7.3.1 makes `FriendlyName` optional and states no receiver rule. `Attribute::friendly_name` reports it as sent, for an `<Attribute>` in the assertion and for one decrypted from an `<EncryptedAttribute>`. It is `None` when the element has no `FriendlyName` |
| A `FriendlyName` does not identify an attribute | Service provider | Accept Response | Mandatory for the crate's own processing. Core §2.7.3.1: the value `MUST NOT` be used as a basis for formally identifying SAML attributes. Elements with the same `Name` and `NameFormat` are one `Attribute` whatever their `FriendlyName` values, and `Attributes::get` matches the `Name`. `Attributes::get_by_friendly_name` finds an attribute by its label for display and mapping. Its rustdoc says the label does not identify the attribute, so an application does not base access decisions on it |
| A `basic` attribute whose name is not an `xs:Name` is accepted | Service provider | Accept Response | No receiver rule. Core §8.2.3 states which names belong to the format. The schema types `Name` as `xs:string`, and no section requires a relying party to reject the attribute |
| An accepted `<Attribute>` has a `Name` | Service provider | Accept Response | Mandatory. The assertion schema declares `Name` on `AttributeType` with `use="required"`, and Core §2.7.3.1 lists it as `[Required]`. A response whose assertion has an `<Attribute>` without an unqualified `Name` returns `SamlError::ProtocolProfile`. `Name=""` is a valid `xs:string` and is accepted as an attribute named `""` |
| `<Attribute>` elements with the same `Name` and `NameFormat` are one `Attribute` | Service provider | Accept Response | Library behaviour. Errata 05 E49 adds to Core §2.7.3.1 that attributes are identified by `NameFormat` and `Name` together. `SsoSession::attributes` has one `Attribute` for each pair, in document order, with the values of every element that has that pair. Elements with the same `Name` and different `NameFormat` values are separate attributes. An omitted `NameFormat` is `unspecified` (Core §2.7.3.1), so it is the same attribute as an explicit `unspecified`. The attribute reports the `NameFormat` and the `FriendlyName` of its first element |

## Name identifier formats

`NameIdFormat` has a variant for each Core §8.3 identifier and `Custom` for
any other `Format` URI.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| A `<NameID>` carries any Core §8.3 identifier, another URI, or no `Format` | Identity provider and service provider | Generate and accept | Mandatory to be able to create and to process each one. Conformance §3.3. `NameId::with_format` takes any format, and an accepted `<NameID>` reports the format it carries |
| A written name identifier format is an absolute URI reference | Identity provider and service provider | Generate Response, AuthnRequest `NameIDPolicy`, LogoutRequest, ManageNameIDRequest, and metadata `NameIDFormat` | Mandatory. Core §1.3.2: a URI reference value in a SAML-defined element or attribute has at least one non-whitespace character and is absolute. XML whitespace is collapsed. The characters XLink escapes, such as a space, `<`, or a non-ASCII letter, count as `%HH` octets. The result is an RFC 2396 absolute URI, with RFC 2732 IPv6 hosts, and an optional fragment. A blank, relative, or malformed value is `SamlError::Invalid` before the message is signed or returned. The check covers a `NameId` format, the first configured NameID format, and every metadata `NameIDFormat` that is written. A valid value is written as given and XML-escaped. An absent format is omitted. A configured format that is empty is an explicit value and is rejected. Logout templates receive the checked value in `{NameIDFormat}`. Text a template writes itself is the caller's XML and is not checked. Single Logout producer rules compare the written `Format` with the checked one |
| A received `Format` that is not an absolute URI reference is reported as sent | Service provider and identity provider | Accept | No receiver rule. Core §1.3.2 binds the writer. `NameIdFormat::Custom` carries the value. This crate rejects the same `NameId` when it is sent back in a `LogoutRequest` or `ManageNameIDRequest` |
| A transient value follows the rules for SAML identifiers | Identity provider | Generate Response | Mandatory. Core §8.3.8 and §1.3.4. `NameId::generate_transient` returns 160 random bits as `_` and 40 hexadecimal digits, which is an `xs:ID`. Core §1.3.4 requires a collision probability of at most 2^-128 and recommends 2^-160. The bits come from the operating system's random source |
| A transient value is at most 256 characters | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.8. The generated value is 41 characters. A response whose transient `<NameID>` is longer is not generated, whichever constructor made the `NameId`, and also when the format is the identity provider's first configured NameID format. The format is compared after the `xs:anyURI` whitespace collapse. A character is a Unicode scalar value |
| A persistent value has no discernible correspondence to the subject's identity | Identity provider | Generate Response | Mandatory. Core §8.3.7 as replaced by E86. `NameId::generate_persistent` returns 160 random bits that are not derived from the principal. E86 allows any other derivation with no guessable relationship to the identity. That derivation is the caller's, and its value goes through `NameId::persistent` |
| A persistent value is unique among those the identity provider generates for a service provider or affiliation | Identity provider | Generate Response | Mandatory. Core §8.3.7 as replaced by E86. Two generated values are equal with a probability of 2^-160. The crate keeps no record of issued values |
| A persistent value is at most 256 characters | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.7. The generated value is 41 characters. `NameId::persistent` rejects a longer value. A response whose persistent `<NameID>` is longer is not generated, whichever constructor made the `NameId`, and also when the format is the identity provider's first configured NameID format. The format is compared after the `xs:anyURI` whitespace collapse. A character is a Unicode scalar value |
| A persistent value is not assigned to another principal | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.7 as amended by E78. A generated value is new. The deployment stores it for one principal and one service provider and passes it to `NameId::persistent` on later responses. The crate has no identifier store, so it cannot detect a reassignment |
| `NameQualifier` and `SPNameQualifier` are omitted unless the issued `NameId` sets them | Identity provider | Generate Response | Optional omission. Core §8.3.7: `NameQualifier` `MAY` be omitted when it is the issuer of the assertion, and `SPNameQualifier` when the message is only for the service provider it would name. Core §8.3.8 applies the same rule to a transient value. Typed responses write the attributes the issued `NameId` sets and omit the ones it leaves unset. The library does not check that a written `NameQualifier` or `SPNameQualifier` names the entities §8.3.7 requires, or that an `entity`-format `NameID` omits them as §8.3.6 requires; the caller chooses them. A requested `NameIDPolicy` `SPNameQualifier` is checked as in [Web Browser SSO generation](web-browser-sso-generation.md#identity-provider-response) |
| `SPProvidedID` is the service provider's alternative identifier, and is omitted when there is none | Identity provider | Generate Response | Mandatory. Core §8.3.7 and §3.6.3, in the text E55 restates. The service provider sets the value with `NewID` through [name identifier management](name-id-management.md). The caller stores it and passes it on the subject `NameId`. Typed responses write it from `NameId::sp_provided_id` and omit it when that is `None`. |
| A persistent value is not shared in clear text with other providers, is not logged without controls, and is not a non-opaque value | Deployment | Use of the identifier | Mandatory for the deployment. Core §8.3.7. This crate writes no log. Who receives the value and where it is stored are outside the crate |
| `NameId::new` takes any value for the persistent and transient formats | Identity provider | Generate Response | Library behaviour. The response still enforces the 256-character limit. Randomness, opacity, and non-reassignment cannot be checked on a value the caller supplies: `NameId::generate_transient` and `NameId::generate_persistent` produce values that meet them |
| A persistent or transient `<NameID>` is accepted when it parses | Service provider on a `Response`, identity provider on a requested `<Subject>` | Accept | No receiver rule. Conformance §3.3 places Core §8.3.7 and §8.3.8 on the producer. A value longer than 256 characters, or one that resembles a username, is accepted and reported as it was sent. Core §8.3.8 says a relying party `SHOULD` treat a transient value as opaque and temporary. That is the application's use of the value |

## Subject identifier attributes

The [SAML V2.0 Subject Identifier Attributes Profile Version 1.0](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html)
§3.3 defines `subject-id`, a value the same for every relying party, and §3.4
defines `pairwise-id`, a value for one relying party. §3.4.1 gives
`pairwise-id` the syntax and handling rules of §3.3.1, so each row applies to
both. `SubjectId` and `PairwiseId` hold the values. The identity provider adds
them as `Attribute::from(SubjectId)` and `Attribute::from(PairwiseId)`. The
service provider reads them with `SsoSession::subject_id` and
`SsoSession::pairwise_id`.

This page does not claim either conformance clause of the profile (§4).
Clause 1 also needs the identity provider's generated metadata to publish
`<shibmd:Scope>` (§3.5.2). Clause 2 also needs the service provider to accept
values only in the scopes that the identity provider's metadata lists. The
crate does neither. The `subject-id:req` entity attribute that clause 2 asks a
service provider's metadata generator to support (§3.5.1) is in
[Metadata and replay](metadata-and-replay.md#entity-attributes).

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| The attribute has the profile's `Name` and the `uri` `NameFormat` | Identity provider and service provider | Generate and accept Response | Mandatory. §3.3 and §3.4 name `urn:oasis:names:tc:SAML:attribute:subject-id` and `urn:oasis:names:tc:SAML:attribute:pairwise-id` with the `uri` name format, published as `constants::attribute_name`. `Attribute::from(SubjectId)` and `Attribute::from(PairwiseId)` write that `NameFormat`. Library reading: an attribute with that `Name` and no `NameFormat`, or the unspecified one, is the same identifier, because Core §2.7.3.1 gives an absent `NameFormat` the unspecified meaning, and Shibboleth SP maps such an attribute to a `uri` rule. The service provider reads it. The identity provider returns `SamlError::Invalid` for it, so a response carries these identifiers only with the `uri` `NameFormat`. Another `NameFormat` names a different attribute, as for [entity attributes](metadata-and-replay.md#entity-attributes), and the identity provider writes it as given |
| The attribute has exactly one `<AttributeValue>`, and an assertion carries it once | Identity provider | Generate Response | Mandatory. §3.3.1, and §3.2 limits each attribute to a single value in an assertion. A response whose attribute has no value or several values, or whose assertion has a second matching attribute, returns `SamlError::Invalid` before it is signed |
| The value is `uniqueID@scope` | Identity provider | Generate Response | Mandatory. §3.3.1: a unique ID of 1 to 127 ASCII letters, digits, `=`, and `-`, and a scope of 1 to 127 ASCII letters, digits, `-`, and `.`, each starting with a letter or a digit. `SubjectId::try_new` and `PairwiseId::try_new` return `SamlError::Invalid` for any other text, including surrounding whitespace. A response whose attribute value breaks the grammar returns `SamlError::Invalid`, whichever constructor made the attribute |
| The `<AttributeValue>` has no `xsi:type` | Identity provider | Generate Response | Recommended. §3.3.1: `xsi:type` `SHOULD` be absent and `MUST` be `xs:string` when present. Typed responses write these values without `xsi:type`. Other attributes keep the `xs:string` type |
| The scope is lower case | Identity provider | Generate Response | Recommended. §3.3.1 and §3.5.2. A response whose scope has an upper case letter returns `SamlError::Invalid`. No option relaxes it. §3.5.2 matches a scope against `<shibmd:Scope>` case-sensitively, so a relying party that filters scopes drops a value whose case differs from the published scope |
| The unique ID is all upper case or all lower case | Identity provider | Generate Response | Recommended. §3.3.1. A response whose unique ID has both upper and lower case letters returns `SamlError::Invalid`. No option relaxes it. Digits, `=`, and `-` have no case, so a Base32 or hexadecimal unique ID passes |
| The value is bound to one subject and is never reassigned. A `pairwise-id` value is stable for one relying party, differs between relying parties, and does not map to the subject's other identifiers | Identity provider | Generate Response | Mandatory for the deployment. §3.3.2 and §3.4.2. The caller derives the value and stores what it needs. The `PairwiseId` documentation shows a keyed-hash derivation in lowercase hexadecimal. §3.4.3 warns that Base64 is not safe, because two of its values can differ only in case |
| Leading and trailing XML whitespace of the value is removed before it is parsed or compared | Service provider | Accept Response | Mandatory. §3.3.1. The space, tab, line feed, and carriage return are removed. `SubjectId::as_str` and `PairwiseId::as_str` return the rest as it was sent |
| Values that differ only in case are the same | Service provider and identity provider | Compare | Mandatory. §3.3.1. `SubjectId` and `PairwiseId` equality and `Hash` ignore ASCII case. `as_str` keeps the case of the value |
| An identifier attribute that is not exactly one value in the §3.3.1 grammar is an error | Service provider | Accept Response | Library behaviour. §3.3.1 binds the attribute's form and states no receiver rejection, so the response is accepted and the attribute stays in `SsoSession::attributes`. `SsoSession::subject_id` and `SsoSession::pairwise_id` return `SamlError::ProtocolProfile` for it, because it is not an identifier. The values of every matching `<Attribute>` count together, so two elements with one value each are an error |
| A received value whose `xsi:type` is not `xs:string` is read by its text | Service provider | Accept Response | No receiver rule. The `xsi:type` rule of §3.3.1 binds the producer |
| A value whose scope the issuer may not assert is discarded | Service provider | Accept Response | Recommended. §3.5.2. Not implemented: the crate does not read `<shibmd:Scope>`. The application checks `scope()` against `SsoSession::issuer` before it trusts the value |

## Entity identifiers

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| A provider's own entity identifier is an absolute URI reference of at most 1024 characters | Identity provider and service provider | Generate metadata `entityID` and the `Issuer` of each message and assertion | Mandatory. Core §8.3.6 makes an entity identifier a URI of not more than 1024 characters. Core §1.3.2 requires a URI reference value in a SAML-defined element or attribute to have a non-whitespace character and to be absolute. Metadata §2.2.1 types `entityID` as `entityIDType`, an `anyURI` of at most 1024 characters. `SpConfig` and `IdpConfig` validation, `generate_sp_metadata`, and `generate_idp_metadata` return `SamlError::Invalid` otherwise. The URI is read as for a [name identifier format](#name-identifier-formats). A character is a Unicode scalar value. Library policy also rejects a value that the `anyURI` whitespace collapse would change, such as one with leading or trailing whitespace, because an `Issuer` is an `xs:string` that a peer reads without collapsing it. `EntityId` constructors check only for a non-whitespace character, so config validation checks the configured one |
| A peer's entity identifier that is not an absolute URI reference, or is longer than 1024 characters, is read as sent | Identity provider and service provider | Import metadata and accept a message | No receiver rule. Core §8.3.6 and §1.3.2 bind the writer. `IdpDescriptor`, `SpDescriptor`, and a received `Issuer` reject only a value without a non-whitespace character. The metadata schema's 1024-character limit is not applied on import. `EntityId::try_new` names such a peer as the expected entity ID |
| A received `Issuer` names the expected entity only when its content is the same string | Identity provider and service provider | Accept a message or an assertion | Mandatory. Core §1.3.1 requires an exact binary comparison of `xs:string` content unless the specification or a profile notes otherwise, and none does for `Issuer`. `NameIDType` gives `Issuer` `xs:string` content. Every flow, SOAP included, compares the content as sent, so whitespace around the entity ID is a different issuer and returns `SamlError::IssuerMismatch`. `ArtifactResolve` withholds the message instead |

## Generated message and assertion identifiers

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Two generated `ID` values are equal with a probability of at most 2^-128 | Every producer | Generate any request, response, or assertion | Mandatory, with a recommendation of at most 2^-160. Core §1.3.4. The library writes `_` and 160 random bits as 40 hexadecimal digits, an `xs:ID` of 41 characters, so it meets both. The bits come from the operating system's random source. Every SSO, logout, artifact resolution, and name identifier management message and assertion the crate generates gets its `ID` this way. A `SessionIndex` the identity provider writes is the assertion `ID`. Logout templates must preserve the generated message `ID` |
