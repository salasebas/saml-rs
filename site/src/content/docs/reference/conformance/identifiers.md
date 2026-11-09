---
title: "SAML-defined identifiers"
description: "Attribute name formats and name identifier formats in typed Web Browser SSO: `RespondSso::attributes`, `AttributeNameFormat`, and the persistent and transient `NameId` constructors."
---

Attribute name formats and name identifier formats in typed Web Browser SSO.
The identity provider writes them with `respond_sso` and `initiate_sso`. The
service provider reads them with `finish_sso` and `accept_unsolicited_sso`.
The identity provider reads a requested `<NameID>` with `receive_sso`. This
page does not claim the IdP operational mode or the SP operational mode.

Normative text is Conformance Requirements §3.3 and SAML Core §1.3.4, §2.2.2,
§2.7.3.1, §8.2, and §8.3, as corrected by Approved Errata 05 E49, E55, E78,
and E86.

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

## Attribute name formats

`AttributeNameFormat` is `Unspecified`, `Uri`, `Basic`, or `Custom` for any
other `NameFormat` URI.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An `<Attribute>` carries any Core §8.2 identifier, another URI, or no `NameFormat` | Identity provider | Generate Response | Optional. Core §2.7.3.1 and §8.2 say the identifiers `MAY` be used. Conformance §3.3 requires the producer to be able to create each one. `RespondSso::attributes` writes the `AttributeStatement`. `Attribute::with_name_format` writes that format's URI. `Attribute::new` with no format omits `NameFormat`, and `unspecified` is then in effect (Core §2.7.3.1). No attributes writes no statement |
| A `basic` attribute name is an `xs:Name` | Identity provider | Generate Response | Mandatory. Core §8.2.3. A response with a `basic` name that is not an `xs:Name` is not generated. `Custom` with the `basic` URI is the `basic` format. The name is checked against the XML 1.0 Fifth Edition `Name` production, which this crate also uses for `xs:NCName`. `unspecified` and `uri` have no rule to check: Conformance §3.3 says they specify no normative processing rules |
| An attribute without values has no `<AttributeValue>` | Identity provider | Generate Response | Mandatory. Core §2.7.3.1 |
| Each value is its own `<AttributeValue>`, and every value has the same datatype | Identity provider | Generate Response | Recommendation for one element per value, and a requirement for one datatype once any value declares `xsi:type`. Core §2.7.3.1. Each value is written as `xs:string` |
| `RespondSso::attributes` is not combined with a login response template | Identity provider | Generate Response | Library policy. A template has its own attribute list, so the response is rejected rather than merged |
| An error `Response` has no `AttributeStatement` | Identity provider | Generate Response | Mandatory. Profiles §4.1.4.2: an error response includes no assertions. The attributes passed to `RespondSso::attributes` are not written |
| The `NameFormat` of an accepted `<Attribute>` is read, whatever its URI | Service provider | Accept Response | Mandatory. Conformance §3.3. `Attribute::format` is the `AttributeNameFormat`, and `Attribute::name_format` is the URI. Both are `None` when the element has no `NameFormat` |
| A `basic` attribute whose name is not an `xs:Name` is accepted | Service provider | Accept Response | No receiver rule. Core §8.2.3 states which names belong to the format. The schema types `Name` as `xs:string`, and no section requires a relying party to reject the attribute |
| `<Attribute>` elements with the same `Name` are one `Attribute` | Service provider | Accept Response | Library behaviour, unchanged. E49 identifies an attribute by `NameFormat` and `Name` together. The typed session still groups values by `Name` alone, and reports the `NameFormat` of the first element with that name |

## Name identifier formats

`NameIdFormat` has a variant for each Core §8.3 identifier and `Custom` for
any other `Format` URI.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| A `<NameID>` carries any Core §8.3 identifier, another URI, or no `Format` | Identity provider and service provider | Generate and accept | Mandatory to be able to create and to process each one. Conformance §3.3. `NameId::new` takes any format, and an accepted `<NameID>` reports the format it carries |
| A transient value follows the rules for SAML identifiers | Identity provider | Generate Response | Mandatory. Core §8.3.8 and §1.3.4. `NameId::generate_transient` returns 160 random bits as `_` and 40 hexadecimal digits, which is an `xs:ID`. Core §1.3.4 requires a collision probability of at most 2^-128 and recommends 2^-160. The bits come from the operating system's random source |
| A transient value is at most 256 characters | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.8. The generated value is 41 characters |
| A persistent value has no discernible correspondence to the subject's identity | Identity provider | Generate Response | Mandatory. Core §8.3.7 as replaced by E86. `NameId::generate_persistent` returns 160 random bits that are not derived from the principal. E86 allows any other derivation with no guessable relationship to the identity. That derivation is the caller's, and its value goes through `NameId::persistent` |
| A persistent value is unique among those the identity provider generates for a service provider or affiliation | Identity provider | Generate Response | Mandatory. Core §8.3.7 as replaced by E86. Two generated values are equal with a probability of 2^-160. The crate keeps no record of issued values |
| A persistent value is at most 256 characters | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.7. The generated value is 41 characters. `NameId::persistent` rejects a longer value. A character is a Unicode scalar value |
| A persistent value is not assigned to another principal | Identity provider | Generate Response | Mandatory prohibition. Core §8.3.7 as amended by E78. A generated value is new. The deployment stores it for one principal and one service provider and passes it to `NameId::persistent` on later responses. The crate has no identifier store, so it cannot detect a reassignment |
| `NameQualifier` and `SPNameQualifier` are omitted | Identity provider | Generate Response | Optional omission. Core §8.3.7: `NameQualifier` `MAY` be omitted when it is the issuer of the assertion, and `SPNameQualifier` when the message is only for the service provider it would name. Core §8.3.8 applies the same rule to a transient value. Typed responses write neither attribute. An identifier created by another identity provider, or for an affiliation, cannot omit them and is not a claimed feature |
| `SPProvidedID` is omitted | Identity provider | Generate Response | Mandatory when the service provider has set no alternative identifier. Core §8.3.7, in the text E55 restates. Name identifier management is not a claimed feature, so no alternative identifier exists |
| A persistent value is not shared in clear text with other providers, is not logged without controls, and is not a non-opaque value | Deployment | Use of the identifier | Mandatory for the deployment. Core §8.3.7. This crate writes no log. Who receives the value and where it is stored are outside the crate |
| `NameId::new` takes any value for the persistent and transient formats | Identity provider | Generate Response | Library behaviour, unchanged. The producer rules above are applied by `NameId::generate_transient`, `NameId::generate_persistent`, and `NameId::persistent` |
| A persistent or transient `<NameID>` is accepted when it parses | Service provider on a `Response`, identity provider on a requested `<Subject>` | Accept | No receiver rule. Conformance §3.3 places Core §8.3.7 and §8.3.8 on the producer. A value longer than 256 characters, or one that resembles a username, is accepted and reported as it was sent. Core §8.3.8 says a relying party `SHOULD` treat a transient value as opaque and temporary. That is the application's use of the value |
