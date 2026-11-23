# Metadata trust and replay

Callers pass `MetadataTrustPolicy` to `IdpDescriptor::from_metadata_xml` and `SpDescriptor::from_metadata_xml`, and `ReplayPolicy` to `SamlValidationContext::new`. Neither is a field of `SpValidationPolicy` or `IdpValidationPolicy`. Their defaults are in [validation presets](https://samlrs.vercel.app/explanation/validation-presets/).
Normative text is [SAML Metadata 2.0](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf) and its [schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd), Profiles 2.0, and Core 2.0, as corrected by Approved Errata 05.
Neighbouring records are [Web Browser SSO generation](web-browser-sso-generation.md), [Web Browser SSO acceptance](web-browser-sso-acceptance.md), and [XML security algorithms](xml-security-algorithms.md).

## Metadata trust

The caller passes `MetadataTrustPolicy` to the descriptor import. The import reads a document the caller already holds. `Metadata::parse`, `IdpMetadata::from_xml`, and `SpMetadata::from_xml` apply no trust policy and no `validUntil` check.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Count the members of a metadata group as its direct `md:EntityDescriptor` children and those of its direct `md:EntitiesDescriptor` groups. `Extensions` content adds none | Mandatory | Metadata §2.3.1, `EntitiesDescriptorType` | Always |
| Import a document with exactly one entity | Library policy: the import returns a single entity. | Metadata §2.3.1 | Always |
| Import metadata without a signature | Optional | Metadata §3 | `MetadataTrustPolicy::AllowUnsigned` |
| Leave a signature that is present unverified, and report no signed metadata | Library policy: the caller selected `AllowUnsigned` after authenticating the document through another channel. | Metadata §4.3.3.2 | `MetadataTrustPolicy::AllowUnsigned` |
| Have some means to establish trust in metadata before relying on it. The caller supplies it as `MetadataTrustPolicy` | Recommended | Metadata §4 | `MetadataTrustPolicy` |
| Verify the root signature against caller-pinned certificates, and reject unsigned metadata or a signature that no pinned certificate verifies | Optional | Metadata §4.3.3.2 | `MetadataTrustPolicy::RequireSignature` |
| Accept an otherwise valid signature without `ds:KeyInfo` | Optional | Core §5.4.6, Metadata §3.1.6, E91 | Always |
| Verify metadata signatures with caller-pinned certificates. For certificate-based message signatures, verify with the peer role's signing keys. An embedded certificate neither selects nor restricts the key, and a certificate in a `KeyDescriptor` is no trust anchor | Library policy: reason not recorded. | Metadata §3.1.6 (E91), E69 | `MetadataTrustPolicy::RequireSignature` for metadata |
| A signed metadata element has an enveloped signature and an `ID`. Its single `ds:Reference` names that `ID` and covers the element and its children | Mandatory | Metadata §3.1.1, §3.1.2 | `MetadataTrustPolicy::RequireSignature` |
| Import signed metadata only when a single signature is a direct child of the document root and covers that root | Library policy: reason not recorded. | Metadata §3.1.2 | `MetadataTrustPolicy::RequireSignature` |
| Reject a transform other than enveloped signature or exclusive canonicalization, with or without comments | Optional | Metadata §3.1.4 | `MetadataTrustPolicy::RequireSignatureAllowingOtherCanonicalization` also accepts inclusive canonicalization |
| Reject a `ds:Object` in a metadata signature | Recommended | Metadata §3.1.5 (E91) | All `RequireSignature` variants. `AllowUnsigned` skips the check |
| Reject an MD5 or RIPEMD-160 signature or digest algorithm and an RSA signing key under 2048 bits. See [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys) | Library policy: the certificates a verified document publishes are then trusted for its messages, so the trust root must not use weak algorithms. | Metadata §3.1.1 (E81) | `MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` |
| Reject a `ds:Object` in a message signature that authenticates the accepted message | Recommended | Core §5.4.5 (E91) | `XmlSignatureProfile::AllowWeakAlgorithms` |

## Reading peer metadata

The peer descriptors read the role the peer acts in. `Metadata::parse` has no role and reads every SSO role descriptor.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read keys, signing flags, `NameIDFormat`, endpoints, and role-level `validUntil` only from role descriptors in the metadata namespace that list `urn:oasis:names:tc:SAML:2.0:protocol`. Refuse an entity with none | Library policy: a role published for another protocol must not supply keys, flags, or endpoints for SAML 2.0 messages. | Metadata §2.4.1 | Always |
| Read several such roles of one kind together | Library policy: Metadata §2.3.2 leaves the choice among role descriptors that share a protocol undefined. | Metadata §2.3.2 | Always |
| Read `AuthnRequestsSigned` as true when any SAML 2.0 `SPSSODescriptor` sets it | Library policy: reason not recorded. | Metadata §2.4.4 | Always |
| Read `WantAssertionsSigned` as true only when the entity has exactly one SAML 2.0 `SPSSODescriptor` and it sets the flag | Library policy: reason not recorded. | Metadata §2.4.4 | Always |
| Read `WantAuthnRequestsSigned` from the first SAML 2.0 `IDPSSODescriptor` that specifies it | Library policy: reason not recorded. | Metadata §2.4.3 | Always |
| Read the keys of a peer from the `KeyDescriptor` elements of the role it acts in. Verify its signatures and encrypt to it with that role's certificates | Mandatory | Metadata §2.4.1 | Always |
| Reject a message signed with a key that only the peer's other role publishes | Library policy: no OASIS receiver rule names that case. | Metadata §2.4.1 | Always |
| Verify with the certificates of a `KeyDescriptor` whose `use` is `signing` or absent, and encrypt with those whose `use` is `encryption` or absent | Mandatory | Metadata §2.4.1.1, E62 | Always |
| Ignore a `KeyDescriptor` whose `use` is neither value | Library policy: reason not recorded. | Metadata §2.4.1.1 | Always |
| Try every certificate published for the same use when verifying | Recommended | E68 | Always |
| Read `NameIDFormat` with XML Schema whitespace collapse | Mandatory | Metadata §2.4.2, XML Schema 1.0 Part 2 §4.3.6 | Always |
| Read unqualified `Binding` and `Location` with XML Schema whitespace collapse. Apply the same rule to `ResponseLocation` on logout and name identifier management services, `index` on artifact and assertion consumer services, and `isDefault` on assertion consumer services. A qualified attribute of the same local name is foreign and is not read | Mandatory | Metadata §2.2.2, §2.2.3, XML Schema 1.0 Part 2 §4.3.6 | Always |
| Choose the default of an indexed set as the first endpoint with `isDefault` true, else the first without `isDefault` false, else the first | Mandatory | Metadata §2.2.3, E37 | Always |
| For an `AssertionConsumerService` lookup without a binding, select the default within the first matching SAML 2.0 SP role | Library policy: reason not recorded. | Metadata §2.3.2 | Always |
| Require unqualified `Binding`, `Location`, and an `unsignedShort` `index` on each `ArtifactResolutionService` | Mandatory | Metadata §2.2.2, §2.2.3 | `IdpMetadata::artifact_resolution_services` |
| Reject an empty `Binding` or `Location` after whitespace collapse | Library policy: reason not recorded. | Core §1.3.2, Metadata §2.2.2 | `IdpMetadata::artifact_resolution_services` |

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

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write role descriptor children in schema order: `KeyDescriptor`, `ArtifactResolutionService` (IdP only), `SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`, then `SingleSignOnService` or `AssertionConsumerService` | Mandatory | Metadata §2.4.1 to §2.4.4 | Always |
| Keep the configured order of the endpoints in each group | Library policy: reason not recorded. | — | Always |
| Write entity-level `Organization`, then `ContactPerson`, after the role descriptors | Mandatory | Metadata §2.3.2 | `organization`, `contact`, `contacts` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Write at least one name, display name, and URL, each with an `xml:lang` that matches the XML Schema 1.0 [language pattern](https://www.w3.org/TR/xmlschema-2/#language), in an `Organization`. Require an absolute `OrganizationURL` and `errorURL` | Mandatory | Metadata §2.2.4, §2.2.5, §2.3.2.1, Core §1.3.2 | Always |
| Write a `ContactPerson` with one of the five `contactType` values and only `mailto:` email addresses | Mandatory | Metadata §2.3.2.2 | Always |
| Publish the [REFEDS security contact](https://wiki.refeds.org/spaces/STAN/pages/44957728/Security%2BContact%2BMetadata%2BExtension%2BSchema) with `ContactType::Security` | Optional | — | `ContactType::Security` |
| Write `errorURL` on the SSO role descriptor | Optional | Metadata §2.4.1 | `error_url` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Write each `NameIDFormat` as an absolute URI reference | Mandatory | Metadata §2.4.2, Core §1.3.2 | Always |
| Write an `emailAddress` `NameIDFormat` when a service provider configures none | Library policy: reason not recorded. | Metadata §2.4.2 | `name_id_format`, `name_id_formats` |
| Write at least one `SingleSignOnService` in an `IDPSSODescriptor` and one `AssertionConsumerService` in an `SPSSODescriptor` | Mandatory | `IDPSSODescriptorType`, `SPSSODescriptorType`, Metadata §2.4.3, §2.4.4 | Always |
| Write a unique `index` on each `AssertionConsumerService` | Mandatory | Metadata §2.2.3 | Always |
| Write `isDefault` only on indexed endpoints. The generator supports the flag on `AssertionConsumerService` | Mandatory | Metadata §2.2.2, §2.2.3 | `Endpoint::is_default` |
| Write `validUntil`, `cacheDuration`, or both on the root `EntityDescriptor`. `validUntil` is UTC, truncated to whole seconds | Mandatory | Metadata §2.3.2 | `MetadataLifetime` |
| Write `cacheDuration="PT86400S"` when no lifetime is configured | Library policy: a daily refresh target without a fixed expiration for metadata generated once at config build. | Metadata §2.3.2, E94 | `metadata_lifetime` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Publish several signing `KeyDescriptor` elements | Optional | Metadata §2.4.1, E68 | `Credentials::with_additional_signing_certificate` |
| Publish several encryption `KeyDescriptor` elements | Optional | Metadata §2.4.1, E68 | `Credentials::with_decryption_credential` |
| Allow decryption with any locally configured key published for encryption. Keys are tried in the order added | Recommended | E68 | `Credentials::with_decryption_credential` |

## Entity attributes

Normative text is the
[SAML V2.0 Metadata Extension for Entity Attributes](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-attr.html)
(MDAttr), Committee Specification 01. The rows for the four named attributes
also cite [RFC 8409](https://www.rfc-editor.org/rfc/rfc8409), the
[SAML V2.0 Identity Assurance Profiles](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-assurance-profile.html),
and the [SAML V2.0 Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html).
These rows do not claim saml2int, and the library leaves attribute release by
category to the application.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `mdattr:EntityAttributes` in an `EntityDescriptor`'s `Extensions` binds its attributes to that entity. In an `EntitiesDescriptor`'s `Extensions`, it binds them to each `EntityDescriptor` in the group | Metadata consumer | Read imported metadata | Optional extension. MDAttr §2.2 lets consumers process or ignore it, and §2.3 states the binding. `Metadata::entity_attributes`, `SpDescriptor::entity_attributes`, and `IdpDescriptor::entity_attributes` return the `saml:Attribute` children of every `mdattr:EntityAttributes` in the `Extensions` of every enclosing `EntitiesDescriptor` and of the `EntityDescriptor`, outermost group first. They read the same document whose root `RequireSignature` verified. Import adds no rejection. An attribute without `Name` returns `SamlError::Invalid` from the accessor |
| `EntityAttributes` elsewhere has no defined meaning | Metadata consumer | Read imported metadata | MDAttr §2.3 leaves the meaning undefined anywhere other than those two `Extensions`. The accessors do not read `EntityAttributes` in a role descriptor's `Extensions` or in an element outside the metadata, `mdattr`, or assertion namespaces |
| A `saml:Assertion` in `EntityAttributes` is independently signed and holds one attribute statement about the entity | Metadata publisher | Generate metadata | Mandatory when present. MDAttr §2.4. The accessors do not read `saml:Assertion` children, and the generators do not write them |
| `EntityAttributes` appears at most once in one `Extensions`, and an `EntitiesDescriptor` carries no `saml:Assertion` in it | Metadata publisher | Generate metadata | Mandatory. MDAttr §2.3. The generators write one `EntityAttributes` with `saml:Attribute` children only. No receiver rule asks for rejection, so the accessors read every `EntityAttributes` they find |
| Publish entity attributes | SP and IdP metadata publisher | Generate metadata | Optional extension. MDAttr §2.3. `SpMetadataInput::entity_attributes`, `IdpMetadataInput::entity_attributes`, and the builders' `entity_attribute` and `entity_attributes` write one `Extensions` with one `mdattr:EntityAttributes` as the first child of `EntityDescriptor`, where `EntityDescriptorType` in the metadata schema places `Extensions`. Each value is written without `xsi:type`, and a `FriendlyName` is written when set and read back. Generation returns `SamlError::Invalid` for a `NameFormat` that is not an absolute URI reference, an `AttributeNameFormat::Basic` name that is not an XML name, or text XML cannot carry. saml2int SDP-SP39 places the element in the SP role's `Extensions`. Generation follows MDAttr §2.3 instead, which the Subject Identifier profile §3.5.1 cites, and which Shibboleth follows by reading only entity and group `Extensions` |
| A well-known entity attribute is the attribute with its `Name` and the URI `NameFormat` | Metadata consumer | Read imported metadata | Library reading. RFC 8409 §§3.1 and 4.1, Identity Assurance §3.3, and Subject Identifier §3.5.1 each name the URI `NameFormat`. `EntityAttributes` also matches an attribute with no `NameFormat` or the unspecified one, because Core §2.7.3.1 gives an absent `NameFormat` the unspecified meaning, and the Shibboleth `EntityAttributes` predicate matches such an attribute. Another `NameFormat` names a different attribute. `FriendlyName` plays no part, as Core §2.7.3.1 requires |
| Entity category and entity category support values are URIs, compared as opaque strings, and repeated attributes combine | Metadata consumer | Read imported metadata | RFC 8409 §§3.1–3.2 and 4.1–4.2. `EntityAttributes::entity_categories` and `entity_category_support` return the values of every matching attribute, in order, without normalization. A category on an enclosing `EntitiesDescriptor` is included because MDAttr §2.3 binds it to the entity. RFC 8409 defines the attribute only on `EntityDescriptor` |
| Assurance certification values are framework URIs, on the identity provider's `EntityDescriptor` or an enclosing `EntitiesDescriptor` | Metadata consumer | Read imported metadata | Identity Assurance §§3.2–3.5. Several values are allowed. `EntityAttributes::assurance_certifications` returns them in order, including REFEDS Sirtfi's `https://refeds.org/sirtfi` |
| A relying party that uses metadata publishes `subject-id:req` with exactly one value: `subject-id`, `pairwise-id`, `none`, or `any` | Relying party metadata publisher | Generate metadata | Mandatory when the deployment uses the profile. Subject Identifier §3.5.1, and §4.2 requires a relying party's metadata generator to support it. `Attribute::from(SubjectIdRequirement)` writes the name, the URI `NameFormat`, and one value without `xsi:type`. Generation does not add the attribute when the caller does not configure it |
| Read the subject identifier a relying party requires | Asserting party | Read imported metadata | Library policy. Subject Identifier §3.5.1 defines no asserting-party behaviour. `EntityAttributes::subject_id_requirement` returns `None` without the attribute. It returns `SamlError::Invalid` for an attribute without exactly one value, a value outside the four, or two attributes that require different identifiers, because the profile rules those out and one requirement cannot be chosen from them. Import itself does not reject them |

## Replay

The service provider requires a caller-owned `ReplayCache` for HTTP-POST SSO responses. Artifact and name identifier management replay rows are in [Artifact resolution](artifact-resolution.md) and [Name identifier management](name-id-management.md).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a caller-owned cache for every HTTP-POST SSO acceptance. The cache must atomically reject duplicate bearer assertion `ID`s across all accepting nodes. A duplicate or storage failure prevents acceptance | Mandatory | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| For HTTP-POST, retain each bearer assertion `ID` through its `SubjectConfirmationData@NotOnOrAfter` validity window, including allowed skew | Mandatory | Profiles §4.1.4.3, §4.1.4.5, E26, E92 | `SamlValidationContext::with_clock_skew` |
| For each direct bearer assertion, use its latest UTC bearer deadline. Ignore an unparseable deadline if another parses. Storage fails when none parses | Library policy: it keeps the identifier at least as long as the confirmation that satisfied the checks. | Profiles §4.1.4.3 | Always |
| Also store the `Response` `ID` until the earliest of `Conditions@NotOnOrAfter`, the bearer confirmation, and each `SessionNotOnOrAfter`, plus skew | Library policy: reason not recorded. | — | `ReplayPolicy::RequireCache` |
| Store bearer assertion `ID`s for HTTP-POST-SimpleSign or HTTP-Artifact when a cache is supplied | Library policy: Profiles §4.1.4.5 states the duty for HTTP POST only, and Security considerations §7.1.1.4 defers replay countermeasures to the binding. | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| Store the `ID` of an `AuthnRequest` in `receive_sso` and `receive_paos_sso`, and of a `LogoutResponse` in `finish_slo`, for `with_replay_retention` | Library policy: Web Browser SSO and Single Logout require no identifier cache. | — | `ReplayPolicy::RequireCache` |
| Store the `ID` of a `LogoutRequest` in `receive_slo` until its `NotOnOrAfter` plus skew, or for `with_replay_retention` when it has none | Library policy: Single Logout requires no identifier cache. | — | `ReplayPolicy::RequireCache` |
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
- Require bearer assertion replay protection when consuming a PAOS response. Mandatory, Profiles §4.2.3.8, §4.1.4.5.
