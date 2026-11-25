# Metadata trust and replay

Callers pass `MetadataTrustPolicy` to `IdpDescriptor::from_metadata_xml`, `SpDescriptor::from_metadata_xml`, and `MetadataAggregate::from_xml`. Callers pass `ReplayPolicy` to `SamlValidationContext::new`. Neither is a field of `SpValidationPolicy` or `IdpValidationPolicy`. Their defaults are in [validation presets](https://samlrs.vercel.app/explanation/validation-presets/).
Normative text is [SAML Metadata 2.0](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf) and its [schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd), Profiles 2.0, and Core 2.0, as corrected by Approved Errata 05.
Neighbouring records are [Web Browser SSO generation](web-browser-sso-generation.md), [Web Browser SSO acceptance](web-browser-sso-acceptance.md), and [XML security algorithms](xml-security-algorithms.md).

## Metadata trust

The caller passes `MetadataTrustPolicy` to the descriptor import. The import reads a document the caller already holds. `Metadata::parse`, `IdpMetadata::from_xml`, and `SpMetadata::from_xml` apply no trust policy and no `validUntil` check.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Count the members of a metadata group as its direct `md:EntityDescriptor` children and those of its direct `md:EntitiesDescriptor` groups. `Extensions` content adds none | Mandatory | Metadata §2.3.1, `EntitiesDescriptorType` | Always |
| Import a document with exactly one entity through the single-entity constructors | Library policy: those constructors require unambiguous input without searching an aggregate. | Metadata §2.3.1 | Use `MetadataAggregate` for several members |
| Import metadata without a signature | Optional | Metadata §3 | `MetadataTrustPolicy::Unverified` |
| Leave a signature that is present unverified, and report no signed metadata | Library policy: the caller selected `Unverified` after authenticating the document through another channel. | Metadata §4.3.3.2 | `MetadataTrustPolicy::Unverified` |
| Have some means to establish trust in metadata before relying on it. The caller supplies it as `MetadataTrustPolicy` | Recommended | Metadata §4 | `MetadataTrustPolicy` |
| Verify the root signature against caller-pinned certificates, and reject unsigned metadata or a signature that no pinned certificate verifies | Optional | Metadata §4.3.3.2 | `MetadataTrustPolicy::RequireSignature` |
| Accept an otherwise valid signature without `ds:KeyInfo` | Optional | Core §5.4.6, Metadata §3.1.6, E91 | Always |
| Verify metadata signatures with caller-pinned certificates. For certificate-based message signatures, verify with the peer role's signing keys. An embedded certificate neither selects nor restricts the key, and a certificate in a `KeyDescriptor` is no trust anchor | Library policy: reason not recorded. | Metadata §3.1.6 (E91), E69 | `MetadataTrustPolicy::RequireSignature` for metadata |
| A signed metadata element has an enveloped signature and an `ID`. Its single `ds:Reference` names that `ID` and covers the element and its children | Mandatory | Metadata §3.1.1, §3.1.2 | `MetadataTrustPolicy::RequireSignature` |
| Import signed metadata only when a single signature is a direct child of the document root and covers that root | Library policy: reason not recorded. | Metadata §3.1.2 | `MetadataTrustPolicy::RequireSignature` |
| Reject a transform other than enveloped signature or exclusive canonicalization, with or without comments | Optional | Metadata §3.1.4 | `MetadataTrustPolicy::RequireSignatureAllowingInclusiveCanonicalization` also accepts inclusive canonicalization |
| Reject a `ds:Object` in a metadata signature | Recommended | Metadata §3.1.5 (E91) | All `RequireSignature` variants. `Unverified` skips the check |
| Reject an MD5 or RIPEMD-160 signature or digest algorithm and an RSA signing key under 2048 bits. See [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys) | Library policy: the certificates a verified document publishes are then trusted for its messages, so the trust root must not use weak algorithms. | Metadata §3.1.1 (E81) | `MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` |
| Reject a `ds:Object` in a message signature that authenticates the accepted message | Recommended | Core §5.4.5 (E91) | `XmlSignatureProfile::AllowWeakAlgorithms` |

### Federation aggregate import

`MetadataAggregate::from_xml` loads a caller-supplied document for IdP and SP
lookups. It applies the same metadata signature policy and role selection as
single-entity import. The single root signature authenticates the members and
their enclosing groups, which can publish validity bounds and entity attributes.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Select a member of an `md:EntitiesDescriptor` by its whitespace-collapsed `entityID` before reading its SAML 2.0 roles | Optional | Metadata §2.3.1, §2.3.2 | `MetadataAggregate::idp_descriptor`, `MetadataAggregate::sp_descriptor` |
| Refuse a lookup with no match or several members with the requested ID | Library policy: selecting a different member or one of several matches can bind the caller to the wrong keys and endpoints. | Metadata §2.2.1, §2.3.1 | Always |
| Under a signature-requiring policy, require the signature to cover the aggregate root and reuse that verification for lookups | Library policy: a member signature cannot authenticate its enclosing groups or sibling members. | Metadata §3.1.2 | `MetadataTrustPolicy::Unverified` when the caller already trusts the entire document |
| Require explicit XML resource limits when loading an aggregate | Library policy: feeds vary in size and callers choose their parsing budget. | — | `XmlLimits` |

## Reading peer metadata

The peer descriptors read the role the peer acts in. `Metadata::parse` has no role and reads every SSO role descriptor.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the published `entityID` with XML Schema whitespace collapse during typed peer import. | Mandatory | Metadata §2.3.2, `entityIDType`, [XML Schema 1.0 Part 2 §4.3.6](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) | Always |
| Read keys, signing flags, `NameIDFormat`, endpoints, and role-level `validUntil` only from role descriptors in the metadata namespace that list `urn:oasis:names:tc:SAML:2.0:protocol`. Refuse an entity with none | Library policy: a role published for another protocol must not supply keys, flags, or endpoints for SAML 2.0 messages. | Metadata §2.4.1 | Always |
| Read several such roles of one kind together | Library policy: Metadata §2.3.2 leaves the choice among role descriptors that share a protocol undefined. | Metadata §2.3.2 | Always |
| Read `AuthnRequestsSigned` as true when any SAML 2.0 `SPSSODescriptor` sets it | Library policy: reason not recorded. | Metadata §2.4.4 | Always |
| Read `WantAssertionsSigned` as true when any selected `SPSSODescriptor` sets it | Library policy: an IdP serving these roles together honors each role's request for signed assertions. | Metadata §2.3.2, §2.4.4 | Always |
| Read `WantAuthnRequestsSigned` from the first SAML 2.0 `IDPSSODescriptor` that specifies it | Library policy: reason not recorded. | Metadata §2.4.3 | Always |
| Read the keys of a peer from the `KeyDescriptor` elements of the role it acts in. Verify its signatures and encrypt to it with that role's certificates | Mandatory | Metadata §2.4.1 | Always |
| Reject a message signed with a key that only the peer's other role publishes | Library policy: no OASIS receiver rule names that case. | Metadata §2.4.1 | Always |
| Verify with the certificates of a `KeyDescriptor` whose `use` is `signing` or absent, and encrypt with those whose `use` is `encryption` or absent | Mandatory | Metadata §2.4.1.1, E62 | Always |
| Ignore a `KeyDescriptor` whose `use` is neither value | Library policy: reason not recorded. | Metadata §2.4.1.1 | Always |
| Try every certificate published for the same use when verifying | Recommended | E68 | Always |
| Read `NameIDFormat` with XML Schema whitespace collapse | Mandatory | Metadata §2.4.2, XML Schema 1.0 Part 2 §4.3.6 | Always |
| Read unqualified `Binding` and `Location` with XML Schema whitespace collapse. Apply the same rule to `ResponseLocation` on logout and name identifier management services, `index` on artifact and assertion consumer services, and `isDefault` on assertion consumer services. A qualified attribute of the same local name is foreign and is not read | Mandatory | Metadata §2.2.2, §2.2.3, XML Schema 1.0 Part 2 §4.3.6 | Always |
| Choose the default of an indexed set as the first endpoint with `isDefault` true, else the first without `isDefault` false, else the first | Mandatory | Metadata §2.2.3, E37 | Always |
| Select a default `AssertionConsumerService` within one SAML 2.0 `SPSSODescriptor`: the first one for a lookup without a binding, else the first one that publishes the binding | Library policy: E37 defines the default within one role, and Metadata §2.3.2 leaves the choice among roles undefined. | Metadata §2.2.3, §2.3.2, E37 | Always |
| Look up an `AssertionConsumerServiceIndex` in each selected `SPSSODescriptor`, counting endpoints of every binding. Refuse an index that one of them publishes twice or that more than one of them publishes | Library policy: the request names the index but not the role, so a guessed endpoint could receive an assertion the requester did not route there. | Core §3.4.1, Metadata §2.2.3, §2.3.2 | Always |
| Require unqualified `Binding`, `Location`, and an `unsignedShort` `index` on each `ArtifactResolutionService` | Mandatory | Metadata §2.2.2, §2.2.3 | `IdpMetadata::artifact_resolution_services` |
| Reject duplicate `ArtifactResolutionService` indexes within one `IDPSSODescriptor` | Mandatory | Metadata §2.2.3 | `IdpMetadata::artifact_resolution_services` |
| Look up an artifact's `EndpointIndex` in each selected `IDPSSODescriptor`, and refuse an index that more than one of them publishes | Library policy: the artifact names its issuer and index but not the role, so a guessed role could receive an `ArtifactResolve` for an artifact it did not issue. | Metadata §2.2.3, §2.3.2, Bindings §3.6.4 | `IdpMetadata::artifact_resolution_service` |
| Reject an empty `Binding` or `Location` after whitespace collapse | Library policy: reason not recorded. | Core §1.3.2, Metadata §2.2.2 | `IdpMetadata::artifact_resolution_services` |

[Shibboleth SP 3.6.0](https://codeberg.org/Shibboleth/cpp-sp/src/tag/3.6.0/shibsp/binding/impl/ArtifactResolver.cpp)
looks up the artifact's index only in the first `IDPSSODescriptor` that is
currently valid and supports SAML 2.0. It takes that role from
[OpenSAML-C 3.3.1](https://codeberg.org/Shibboleth/cpp-opensaml/src/tag/3.3.1/saml/saml2/metadata/Metadata.h#L594).
saml-rs reads these roles together, so an index that only a later role
publishes still resolves.

[SimpleSAMLphp 2.3.5](https://github.com/simplesamlphp/simplesamlphp/blob/v2.3.5/src/SimpleSAML/Metadata/SAMLParser.php#L545-L546)
reads only the first `SPSSODescriptor` that supports SAML 2.0, and its
[identity provider](https://github.com/simplesamlphp/simplesamlphp/blob/v2.3.5/modules/saml/src/IdP/SAML2.php#L198-L253)
looks up the `AssertionConsumerServiceIndex` and the default for a
`ProtocolBinding` in that role.
[OpenSAML 5.1.3](https://codeberg.org/Shibboleth/java-opensaml/src/tag/5.1.3/opensaml-saml-impl/src/main/java/org/opensaml/saml/common/binding/impl/SAMLMetadataLookupHandler.java#L181)
also resolves a single role descriptor for the peer. saml-rs reads the SP
roles together, so an index or a binding that only a later role publishes is
still served.

## Metadata validity

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For each role, take the earliest `validUntil` on the role, its entity, or an enclosing group | Mandatory | `EntitiesDescriptorType`, `EntityDescriptorType`, `RoleDescriptorType`, E76, E94 | Always |
| Bound all roles of one kind by the earliest of them | Library policy: the descriptor reads those roles together. | E76 | Always |
| Refuse a typed flow at or after the effective `validUntil`, without clock skew. A flow that takes `SamlValidationContext` uses its clock | Mandatory | E94 | Always |
| Read only the unqualified `validUntil` | Mandatory | `EntityDescriptorType` | Always |
| Require an `xs:dateTime` value, including the prohibition on year 0000 | Mandatory | XML Schema 1.0 Part 2 §3.2.7.1 | Always |
| Require an explicit timezone | Library policy: XML Schema 1.0 §3.2.7.4 leaves the order of a value without one against an instant indeterminate, so the expiry cannot be decided. | XML Schema 1.0 Part 2 §3.2.7.4 | Always |
| Read `24:00:00` as midnight of the next day in the supplied timezone | Mandatory | XML Schema 1.0 §3.2.7.1 | Always |
| Of schema-valid years, accept only local years 0001 to 9999, including after midnight rollover. Reject a leap second outside the last minute of a UTC month | Library policy: the RFC 3339 parser the library uses reads four-digit years and accepts a leap second only in that minute. | XML Schema 1.0 Part 2 §3.2.7.1 | Always |
| Keep using a descriptor whose `cacheDuration` has elapsed | Optional | E94 | Always |

## Generating metadata

The SP and IdP build metadata with `generate_sp_metadata` and
`generate_idp_metadata`, including when their typed configuration builders run.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write role descriptor children in schema order: `Extensions` (IdP scopes), `KeyDescriptor`, `ArtifactResolutionService` (IdP only), `SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`, then `SingleSignOnService` or `AssertionConsumerService` | Mandatory | Metadata §2.4.1 to §2.4.4 | Always |
| Keep the configured order of the endpoints in each group | Library policy: reason not recorded. | — | Always |
| Write entity-level `Organization`, then `ContactPerson`, after the role descriptors | Mandatory | Metadata §2.3.2 | `organization`, `contact`, `contacts` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Write at least one name, display name, and URL, each with an `xml:lang` that matches the XML Schema 1.0 [language pattern](https://www.w3.org/TR/xmlschema-2/#language), in an `Organization`. Require an absolute `OrganizationURL` and `errorURL` | Mandatory | Metadata §2.2.4, §2.2.5, §2.3.2.1, Core §1.3.2 | Always |
| Write a `ContactPerson` with one of the five `contactType` values and only `mailto:` email addresses | Mandatory | Metadata §2.3.2.2 | Always |
| Publish the [REFEDS security contact](https://wiki.refeds.org/spaces/STAN/pages/44957728/Security%2BContact%2BMetadata%2BExtension%2BSchema) with `ContactType::Security` | Optional | — | `ContactType::Security` |
| Write `errorURL` on the SSO role descriptor | Optional | Metadata §2.4.1 | `error_url` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Write each `NameIDFormat` as an absolute URI reference | Mandatory | Metadata §2.4.2, Core §1.3.2 | Always |
| Write an `emailAddress` `NameIDFormat` when a service provider configures none | Library policy: reason not recorded. | Metadata §2.4.2 | `name_id_format`, `name_id_formats` |
| Write at least one `SingleSignOnService` in an `IDPSSODescriptor` and one `AssertionConsumerService` in an `SPSSODescriptor` | Mandatory | `IDPSSODescriptorType`, `SPSSODescriptorType`, Metadata §2.4.3, §2.4.4 | Always |
| Write an absolute URI reference as each endpoint's `Location` | Mandatory | Metadata §2.2.2, Core §1.3.2 | Always |
| Write a unique `index` on each `AssertionConsumerService` | Mandatory | Metadata §2.2.3 | Always |
| Write a unique `index` on each `ArtifactResolutionService` in an `IDPSSODescriptor` | Mandatory | Metadata §2.2.3 | Always |
| Write `isDefault` only on indexed endpoints. The generator supports the flag on `AssertionConsumerService` | Mandatory | Metadata §2.2.2, §2.2.3 | `Endpoint::is_default` |
| Write `validUntil`, `cacheDuration`, or both on the root `EntityDescriptor`. `validUntil` is UTC, truncated to whole seconds | Mandatory | Metadata §2.3.2 | `MetadataLifetime` |
| Write `cacheDuration="PT86400S"` when no lifetime is configured | Library policy: a daily refresh target without a fixed expiration for metadata generated once at config build. | Metadata §2.3.2, E94 | `metadata_lifetime` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Publish several signing `KeyDescriptor` elements | Optional | Metadata §2.4.1, E68 | `Credentials::with_additional_signing_certificate` |
| Publish several encryption `KeyDescriptor` elements | Optional | Metadata §2.4.1, E68 | `Credentials::with_decryption_credential` |
| Check that every published `ds:X509Certificate` contains nonempty standard base64. The caller supplies the X.509 certificate bytes | Mandatory | Metadata §2.4.1.1, XML Signature §4.4.4, XML Schema Datatypes §3.2.16 | Always |
| With a crypto provider, load the signing and decryption keys and all their certificates, including additional signing certificates. Check that each private key matches its certificate | Library policy: peers use the published certificates to verify signatures and encrypt messages. | Metadata §2.4.1.1 | `SpConfigBuilder::build`, `IdpConfigBuilder::build` |
| Allow decryption with any locally configured key published for encryption. Keys are tried in the order added | Recommended | E68 | `Credentials::with_decryption_credential` |

The metadata generators accept absolute URI references for endpoint locations.
Typed endpoints use `EndpointUrl`, which requires HTTP or HTTPS. Import
preserves relative locations.

## Entity attributes

Normative text is the
[SAML V2.0 Metadata Extension for Entity Attributes](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-attr.html)
(MDAttr), Committee Specification 01. The named attributes also cite
[RFC 8409](https://www.rfc-editor.org/rfc/rfc8409), the
[SAML V2.0 Identity Assurance Profiles](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-assurance-profile.html),
and the [SAML V2.0 Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html).
These rows do not claim saml2int. Attribute release by category is the
application's.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the `saml:Attribute` children of every `mdattr:EntityAttributes` in the `Extensions` of the `EntityDescriptor` and of each enclosing `EntitiesDescriptor`, outermost group first, as attributes of the entity, from the document `RequireSignature` verified. Import adds no rejection | Optional | MDAttr §2.2, §2.3 | `Metadata::entity_attributes`, `SpDescriptor::entity_attributes`, `IdpDescriptor::entity_attributes` |
| Ignore `EntityAttributes` in a role descriptor's `Extensions` or in a foreign element | Library policy: MDAttr §2.3 gives it no meaning there. | MDAttr §2.3 | Always |
| Write at most one `EntityAttributes` in one `Extensions`, with `saml:Attribute` children only | Mandatory | MDAttr §2.3 | Always |
| Publish entity attributes as one `Extensions` with one `mdattr:EntityAttributes`, the first child of `EntityDescriptor`. Values have no `xsi:type`, and a set `FriendlyName` is written | Optional | MDAttr §2.3, `EntityDescriptorType` | `SpMetadataInput::entity_attributes`, `IdpMetadataInput::entity_attributes`, the builders' `entity_attribute` and `entity_attributes` |
| Write them in the entity's `Extensions`, not in the SP role's `Extensions` that saml2int SDP-SP39 uses | Optional | MDAttr §2.3, Subject Identifier §3.5.1 | Always |
| Reject a generated `NameFormat` that is not an absolute URI reference, a `basic` name that is not an XML name, a `uri` name that is not an absolute URI reference, a `Name`, `FriendlyName`, or nonempty value with no non-whitespace character, or text XML cannot carry | Mandatory | Core §1.3.1, §1.3.2, §8.2.2, §8.2.3 | Always |
| Match a well-known entity attribute by its `Name` with the URI `NameFormat`, no `NameFormat`, or `unspecified`, and ignore `FriendlyName` | Library policy: Core §2.7.3.1 gives an absent `NameFormat` the unspecified meaning, and the Shibboleth `EntityAttributes` predicate matches such an attribute. | RFC 8409 §§3.1, 4.1, Identity Assurance §3.3, Subject Identifier §3.5.1 | Always |
| Return entity category and category support values of every matching attribute in order, compared as opaque strings, including those an enclosing group binds | Optional | RFC 8409 §§3.1–3.2, 4.1–4.2, MDAttr §2.3 | `EntityAttributes::entity_categories`, `EntityAttributes::entity_category_support` |
| Return assurance certification framework URIs in order, such as REFEDS Sirtfi's `https://refeds.org/sirtfi` | Optional | Identity Assurance §§3.2–3.5 | `EntityAttributes::assurance_certifications` |
| Publish `subject-id:req` with exactly one value: `subject-id`, `pairwise-id`, `none`, or `any`, with the URI `NameFormat` and no `xsi:type` | Mandatory | Subject Identifier §3.5.1, §4.2 | `Attribute::from(SubjectIdRequirement)` |
| Reject a read `subject-id:req` without exactly one value, with a value outside the four, or repeated with a different requirement. Import does not reject it | Library policy: the profile rules these out, and one requirement cannot be chosen from them. | Subject Identifier §3.5.1 | `EntityAttributes::subject_id_requirement` |

- Signed `saml:Assertion` children of `EntityAttributes` are neither read nor written. Mandatory for a publisher that includes one, MDAttr §2.4.

## IdP scope declarations

The [Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/saml-subject-id-attr-v1.0.html)
defines `shibmd:Scope` and its schema. The [saml2int deployment profile](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html)
requires an IdP deployment to publish one or more literal scopes for the
subject identifiers it supports. The deployment supplies that list.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read direct `shibmd:Scope` declarations in the entity's `Extensions` and in the selected SAML 2.0 IdP roles' `Extensions` | Mandatory capability for relying parties that consume metadata under the Subject Identifier Profile. Recommended by saml2int. | Subject Identifier §3.5.2, §4.2, saml2int SDP-SP17 | `IdpMetadata::scopes`, `IdpDescriptor::scopes` |
| Preserve the scope text and the `regexp` flag. Treat an omitted flag as false and report malformed declarations when scopes are read | Mandatory | Subject Identifier §3.5.2.1 | Always |
| Support publishing scopes in the IdP role's `Extensions`. Write `regexp` explicitly on every declaration | Mandatory capability, recommended explicit flag | Subject Identifier §3.5.2, §3.5.2.2, §4.1, `RoleDescriptorType` | `IdpConfigBuilder::scopes`, `IdpMetadataInput::scopes` |
| Reject uppercase ASCII letters in literal scopes at publication | Library policy: a case-sensitive literal has to match the lowercase scope the typed IdP issues. | Subject Identifier §3.3.1 and §3.5.2 | Always |
| Verify a pinned root signature for scope authorization under a certificate the SP pins as a trusted third-party registration authority | Library policy: distinguish the authority's signature from a generic metadata publisher's signature. | Subject Identifier §3.5.2, saml2int SDP-SP17, Metadata §3.1.1–§3.1.6 (E91) | `MetadataTrustPolicy::RequireRegistrationAuthoritySignature` |

For the use of declarations after login, see [scoped attributes](web-browser-sso-acceptance.md#scoped-attributes).

## Replay

The service provider requires a caller-owned `ReplayCache` for HTTP-POST SSO responses. Artifact and name identifier management replay rows are in [Artifact resolution](artifact-resolution.md) and [Name identifier management](name-id-management.md).
The `ReplayCache` contract defines the result when an assertion deadline
passes before storage.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a caller-owned cache for every HTTP-POST SSO acceptance. The cache must atomically reject duplicate bearer assertion `ID`s across all accepting nodes. A duplicate or storage failure prevents acceptance | Mandatory | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| For HTTP-POST, retain each bearer assertion `ID` through its `SubjectConfirmationData@NotOnOrAfter` validity window, including allowed skew | Mandatory | Profiles §4.1.4.3, §4.1.4.5, E26, E92 | `SamlValidationContext::with_clock_skew` |
| For each direct bearer assertion, use its latest UTC bearer deadline. Ignore an unparseable deadline if another parses. Storage fails when none parses for the selected assertion. Give another assertion the selected assertion's deadline when its own has passed or does not parse | Library policy: it keeps the identifier at least as long as the confirmation that satisfied the checks. | Profiles §4.1.4.3 | Always |
| Also store the `Response` `ID` until the earliest of `Conditions@NotOnOrAfter`, the bearer confirmation, and each `SessionNotOnOrAfter`, plus skew | Library policy: reason not recorded. | — | `ReplayPolicy::RequireCache` |
| Store bearer assertion `ID`s for HTTP-POST-SimpleSign or HTTP-Artifact when a cache is supplied | Library policy: Profiles §4.1.4.5 states the duty for HTTP POST only, and Security considerations §7.1.1.4 defers replay countermeasures to the binding. | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| Store the `ID` of an `AuthnRequest` that `receive_sso` accepts, and of a `LogoutResponse` with status `Success` in `finish_slo`, for `with_replay_retention`. A refused request or a response with another status is not stored | Library policy: Web Browser SSO and Single Logout require no identifier cache for these messages. | — | `ReplayPolicy::RequireCache` |
| Store the `ID` of an authenticated `LogoutRequest` in `receive_slo`, before decrypting its identifier, until its `NotOnOrAfter` plus skew, or for `with_replay_retention` when it has none. A refused newer version or an expired request is not stored | Library policy: Single Logout requires no identifier cache. | — | `ReplayPolicy::RequireCache` |
| Treat `OneTimeUse` as always valid and never retain the assertion for later use | Mandatory | Core §2.5.1.5 | Always |
| Use an assertion that carries `OneTimeUse` immediately | Recommended | Core §2.5.1.5 | Always |

## Typed metadata accessors

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Return a selected endpoint as an `EndpointUrl`. A non-HTTP(S) URL is an error from the accessor, and import accepts it | Library policy: the typed endpoint contract is absolute HTTP(S), and Metadata §2.2.2 and §2.2.3 use `anyURI` without that restriction. | Metadata §2.2.2, §2.2.3 | Always |
| For `single_logout_response_location`, use a nonempty `ResponseLocation` on the selected endpoint, falling back to `Location` | Optional | Metadata §2.2.2, E41 | Always |
| Publish an `ArtifactResolutionService` with an `EndpointUrl` and the SOAP binding | Library policy: reason not recorded. | Metadata §2.2.2 | `IdpConfigBuilder::artifact_resolution_service` |

## Not implemented

- Sign at least the metadata root in the absence of authenticated delivery. Recommended, Metadata §3.
- For Metadata §4 resolution, publishers must provide document integrity and consumers must validate any XML signature present. Mandatory, Metadata §4.3.3, §4.3.3.2. Server-authenticated transport is recommended, Metadata §4, §4.3.3.3.
- Base caching of resolved metadata on `cacheDuration`. Mandatory for a consumer that caches, E94.
- Check that an `entityID` is unique across a deployment. Mandatory for the publisher, Metadata §2.2.1.
