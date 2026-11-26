# Metadata and replay

`generate_sp_metadata` and `generate_idp_metadata` write the metadata of the
crate's own role, and `SpConfigBuilder::build` and `IdpConfigBuilder::build`
call them. `IdpDescriptor::from_metadata_xml`, `SpDescriptor::from_metadata_xml`,
and `MetadataAggregate::from_xml` import a peer's metadata under a
caller-chosen `MetadataTrustPolicy`. With `ReplayPolicy::RequireCache` in the
`SamlValidationContext`, a typed receive operation refuses a repeat of each
message, assertion, or artifact key that the replay rows below store, and
neither policy is part of the
[role validation defaults](https://samlrs.vercel.app/explanation/validation-presets/).

Normative text is [SAML Metadata 2.0](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
and its [schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd),
Core 2.0 §2.5.1.5 for `OneTimeUse`, and Profiles 2.0 §4.1.4.5 for bearer
assertion replay, as corrected by [Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/).
The extension rows cite the
[SAML V2.0 Metadata Extension for Entity Attributes](https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-attr.html)
(MDAttr, Committee Specification 01), [RFC 8409](https://www.rfc-editor.org/rfc/rfc8409),
the [SAML V2.0 Identity Assurance Profiles](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-assurance-profile.html),
the [SAML V2.0 Subject Identifier Attributes Profile](https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html),
the [REFEDS Security Contact Metadata Extension](https://wiki.refeds.org/spaces/STAN/pages/44957728/Security%2BContact%2BMetadata%2BExtension%2BSchema),
the [Login and Discovery User Interface](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/cs01/sstc-saml-metadata-ui-v1.0-cs01.pdf)
(MDUI), [Algorithm Support](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.pdf),
and [Registration and Publication Information](https://docs.oasis-open.org/security/saml/Post2.0/saml-metadata-rpi/v1.0/cs01/saml-metadata-rpi-v1.0-cs01.pdf)
(RPI) specifications. The [saml2int](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html)
rows name their requirement.

<a id="signature-on-the-document-root"></a>

The statuses hold on builds with a crypto provider. A build without one
completes no import under a signature-requiring `MetadataTrustPolicy`, so
only `MetadataTrustPolicy::Unverified` imports metadata. Its service
provider verifies no XML signature, so it accepts no successful SSO response
and stores no bearer assertion `ID`.

## Support

The publisher writes the metadata of the crate's own identity provider or
service provider. The consumer imports a peer's metadata through the
descriptor imports and `MetadataAggregate`.

### Metadata documents

| Feature | Section | Publisher | Consumer |
| --- | --- | --- | --- |
| `EntityDescriptor` as the document root, with its `entityID` | Metadata §2.3, §2.3.2 | Supported | Supported |
| `EntitiesDescriptor` groups, nested groups included | Metadata §2.3.1 | Not supported | Supported |
| `Organization` and `ContactPerson` of an entity | Metadata §2.3.2.1, §2.3.2.2 | Supported | Supported |
| `Organization` and `ContactPerson` of a role | Metadata §2.4.1 | Not supported | Not supported |
| `AdditionalMetadataLocation` | Metadata §2.3.2.3 | Not supported | Not supported |
| `IDPSSODescriptor` with `SingleSignOnService` and `WantAuthnRequestsSigned` | Metadata §2.4.3 | Supported | Supported |
| `NameIDMappingService`, `AssertionIDRequestService`, `AttributeProfile`, and `saml:Attribute` in an `IDPSSODescriptor` | Metadata §2.4.3 | Not supported | Not supported |
| `SPSSODescriptor` with `AssertionConsumerService`, `AuthnRequestsSigned`, and `WantAssertionsSigned` | Metadata §2.4.4 | Supported | Supported |
| `AttributeConsumingService` and `RequestedAttribute` | Metadata §2.4.4.1, §2.4.4.2 | Not supported | Not supported |
| `SingleLogoutService`, `ManageNameIDService`, and `NameIDFormat` in an SSO role | Metadata §2.4.2 | Supported | Supported |
| `ArtifactResolutionService` in an `IDPSSODescriptor` | Metadata §2.4.2 | Supported | Supported |
| `ArtifactResolutionService` in an `SPSSODescriptor` | Metadata §2.4.2 | Not supported | Not supported |
| `AuthnAuthorityDescriptor`, `AttributeAuthorityDescriptor`, and `PDPDescriptor` | Metadata §2.4.5 to §2.4.7 | Not supported | Not supported |
| `AffiliationDescriptor` | Metadata §2.5 | Not supported | Not supported |
| A role that extends `RoleDescriptorType` | Metadata §2.4.1 | Not supported | Not supported |
| `errorURL` on a role | Metadata §2.4.1 | Supported | Not supported |
| `ResponseLocation` on an endpoint | Metadata §2.2.2, E41 | Not supported | Supported |
| `index` on an `AssertionConsumerService` and an `ArtifactResolutionService`, and `isDefault="true"` on an `AssertionConsumerService` | Metadata §2.2.3, E37 | Supported | Supported |
| `isDefault="false"` on an `AssertionConsumerService` | Metadata §2.2.3, E37 | Not supported | Supported |
| `KeyDescriptor` with an X.509 certificate and a `use` of `signing` or `encryption` | Metadata §2.4.1.1, E62, E68 | Supported | Supported |
| `KeyDescriptor` without `use`, for signing and encryption | Metadata §2.4.1.1, E62 | Not supported | Supported |
| Other `ds:KeyInfo` content, such as `ds:KeyValue` or `ds:KeyName` | Metadata §2.4.1.1, E69 | Not supported | Not supported |
| `EncryptionMethod` in a `KeyDescriptor` | Metadata §2.4.1.1 | Not supported | Not supported |
| `validUntil` | Metadata §2.3.1, §2.3.2, §2.4.1, E76, E94 | Supported | Supported |
| `cacheDuration` and caching by it | Metadata §2.3.2, §4.3.1, E94 | Supported | Not supported |
| Signature on the document root | Metadata §3, §4.3.3.2 | Not supported | Supported |
| Signature on an element below the document root | Metadata §3 | Not supported | Not supported |
| Publication and resolution at the well-known location | Metadata §4.1 | Not supported | Not supported |
| Publication and resolution through DNS | Metadata §4.2 | Not supported | Not supported |

### Metadata extensions

| Feature | Section | Publisher | Consumer |
| --- | --- | --- | --- |
| `saml:Attribute` with text values in `mdattr:EntityAttributes` | MDAttr §2.2, §2.3 | Supported | Supported |
| `saml:Attribute` with element content in an `AttributeValue`, in `mdattr:EntityAttributes` | MDAttr §2.2, Core §2.7.3.1.1 | Not supported | Not supported |
| `saml:Assertion` in `mdattr:EntityAttributes` | MDAttr §2.3, §2.4 | Not supported | Not supported |
| Entity category, entity category support, and assurance certification attributes | RFC 8409 §3, §4, Identity Assurance §3 | Supported | Supported |
| `subject-id:req` | Subject Identifier §3.5.1 | Supported | Supported |
| `shibmd:Scope` | Subject Identifier §3.5.2 | Supported | Supported |
| REFEDS security contact | REFEDS Security Contact | Supported | Supported |
| `mdui:UIInfo` and `mdui:DiscoHints` | MDUI §2.1, §2.2 | Not supported | Not supported |
| `alg:DigestMethod` and `alg:SigningMethod` | Algorithm Support §2.4 | Not supported | Not supported |
| `mdrpi:RegistrationInfo`, `mdrpi:PublicationInfo`, and `mdrpi:PublicationPath` | RPI §2.1 to §2.3 | Not supported | Not supported |

### Replay detection

| Feature | Section | Identity provider | Service provider |
| --- | --- | --- | --- |
| Refuse a replayed bearer assertion delivered by HTTP-POST | Profiles §4.1.4.5 | — | Supported |
| `OneTimeUse` condition | Core §2.5.1.5 | Not supported | Supported |

Replay of a protocol message `ID` is library policy. Artifact single use is
in [Artifact resolution](artifact-resolution.md).

## Rules

### Metadata publisher: `generate_sp_metadata`, `generate_idp_metadata`

Code: `src/metadata/generate.rs`, `src/metadata/description.rs`, `src/metadata/lifetime.rs`, `src/metadata/entity_attributes.rs`, `src/metadata/scope.rs`, `src/config/provider.rs`

#### Roles, endpoints, and keys

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write role descriptor children in schema order: `Extensions` (IdP scopes), `KeyDescriptor`, `ArtifactResolutionService` (IdP only), `SingleLogoutService`, `ManageNameIDService`, `NameIDFormat`, then `SingleSignOnService` or `AssertionConsumerService` | Mandatory | Metadata §2.4.1 to §2.4.4 | Always |
| Write at least one `SingleSignOnService` in an `IDPSSODescriptor` and one `AssertionConsumerService` in an `SPSSODescriptor` | Mandatory | `IDPSSODescriptorType`, `SPSSODescriptorType`, Metadata §2.4.3, §2.4.4 | Always |
| Write an absolute URI reference as each endpoint's `Location` | Mandatory | Metadata §2.2.2, Core §1.3.2 | Always |
| Write a unique `index` on each `AssertionConsumerService`, and on each `ArtifactResolutionService` of an `IDPSSODescriptor` | Mandatory | Metadata §2.2.3 | Always |
| Write `isDefault` only on indexed endpoints. The generator supports the flag on `AssertionConsumerService` | Mandatory | Metadata §2.2.2, §2.2.3 | `Endpoint::is_default` |
| Write each `NameIDFormat` as an absolute URI reference | Mandatory | Metadata §2.4.2, Core §1.3.2 | Always |
| Write `errorURL` on the SSO role descriptor | Optional | Metadata §2.4.1 | `error_url` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Publish several signing and several encryption `KeyDescriptor` elements | Optional | Metadata §2.4.1, E68 | `Credentials::with_additional_signing_certificate`, `Credentials::with_decryption_credential` |
| Check that every published `ds:X509Certificate` contains nonempty standard base64. The caller supplies the X.509 certificate bytes | Mandatory | Metadata §2.4.1.1, XML Signature §4.4.4, XML Schema Datatypes §3.2.16 | Always |

#### Organization and contacts

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write entity-level `Organization`, then `ContactPerson`, after the role descriptors | Mandatory | Metadata §2.3.2 | `organization`, `contact`, `contacts` on `SpConfigBuilder` and `IdpConfigBuilder` |
| Write at least one name, display name, and URL, each with an `xml:lang` that matches the XML Schema 1.0 [language pattern](https://www.w3.org/TR/xmlschema-2/#language), in an `Organization`. Require an absolute `OrganizationURL` and `errorURL` | Mandatory | Metadata §2.2.4, §2.2.5, §2.3.2.1, Core §1.3.2 | Always |
| Write a `ContactPerson` with one of the five `contactType` values and only `mailto:` email addresses | Mandatory | Metadata §2.3.2.2 | Always |
| Write at least one child element in each `ContactPerson`: a company, given name, surname, email address, or telephone number. Import accepts a contact with none | Recommended | Metadata §2.3.2.2, E82 | Always |
| Publish the REFEDS security contact | Optional | REFEDS Security Contact | `ContactType::Security` |

#### Lifetime

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `validUntil`, `cacheDuration`, or both on the root `EntityDescriptor` | Mandatory | Metadata §2.3.2 | `MetadataLifetime` |
| Write lifetime attributes only on the root element | Recommended | Metadata §2.3.2 | Always |

#### Entity attributes

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Publish entity attributes as `saml:Attribute` children of one `mdattr:EntityAttributes` in the entity's `Extensions`. Values have no `xsi:type`, and a set `FriendlyName` is written | Optional | MDAttr §2.3 | `SpMetadataInput::entity_attributes`, `IdpMetadataInput::entity_attributes`, the builders' `entity_attribute` and `entity_attributes` |
| Write at most one `EntityAttributes` in one `Extensions` | Mandatory | MDAttr §2.3 | Always |
| Write that `Extensions` after any `ds:Signature` and before the role descriptors | Mandatory | Metadata §2.3.2, `EntityDescriptorType` | Always |
| Write them in the entity's `Extensions`, not in the SP role's `Extensions` that saml2int SDP-SP39 uses | Optional | MDAttr §2.3, Subject Identifier §3.5.1 | Always |
| Reject a generated `NameFormat` that is not an absolute URI reference, a `basic` name that is not an XML name, a `uri` name that is not an absolute URI reference, a `Name`, `FriendlyName`, or nonempty value with no non-whitespace character, or text XML cannot carry | Mandatory | Core §1.3.1, §1.3.2, §8.2.2, §8.2.3 | Always |
| Publish `subject-id:req` with exactly one value: `subject-id`, `pairwise-id`, `none`, or `any`, with the URI `NameFormat` and no `xsi:type` | Mandatory | Subject Identifier §3.5.1, §4.2 | `Attribute::from(SubjectIdRequirement)` |

#### IdP scope declarations

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Support publishing scopes in the IdP role's `Extensions` | Mandatory | Subject Identifier §3.5.2, §4.1, `RoleDescriptorType` | `IdpConfigBuilder::scopes`, `IdpMetadataInput::scopes` |
| Write `regexp` explicitly on every declaration, as metadata that is signed needs | Recommended | Subject Identifier §3.5.2.2 | Always |

### Identity provider and service provider: decryption with published keys

Code: `src/crypto/keys.rs`, `src/crypto/enc/decrypt.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Allow decryption with any locally configured key published for encryption. Keys are tried in the order added | Recommended | E68 | `Credentials::with_decryption_credential` |

### Metadata consumer: signed metadata

Code: `src/config/metadata_trust.rs`, `src/config/metadata_signature_shape.rs`, `src/crypto/verify.rs`, `src/config/descriptors.rs`, `src/config/descriptors/aggregate.rs`

The descriptor imports read a document that the caller already holds.
`Metadata::parse`, `IdpMetadata::from_xml`, and `SpMetadata::from_xml` apply
no trust policy and no `validUntil` check.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Have some means to establish trust in metadata before relying on it. Every descriptor import takes it as a `MetadataTrustPolicy` | Recommended | Metadata §4 | `MetadataTrustPolicy` |
| Import metadata without a signature | Optional | Metadata §3 | `MetadataTrustPolicy::Unverified` |
| Verify the root signature against caller-pinned certificates, and reject unsigned metadata or a signature that no pinned certificate verifies | Optional | Metadata §4.3.3.2 | `MetadataTrustPolicy::RequireSignature` |
| Accept an otherwise valid signature without `ds:KeyInfo` | Mandatory | Core §5.4.6, Metadata §3.1.6, E91, XMLDSig §4.4 | Always |
| A signed metadata element has an enveloped signature and an `ID`. Its single `ds:Reference` names that `ID` and covers the element and its children | Mandatory | Metadata §3.1.1, §3.1.2, §4.3.3.2 | `MetadataTrustPolicy::RequireSignature` |
| Reject a transform other than enveloped signature or exclusive canonicalization, with or without comments | Optional | Metadata §3.1.4 | `MetadataTrustPolicy::RequireSignatureAllowingInclusiveCanonicalization` also accepts inclusive canonicalization |
| Reject a `ds:Object` in a metadata signature | Recommended | Metadata §3.1.5 (E91) | All `RequireSignature` variants. `Unverified` skips the check |

The `ds:Object` rule for message signatures is in
[inbound XML signature verification](xml-security-algorithms.md#inbound-xml-signature-verification).

<a id="reading-peer-metadata"></a>
<a id="federation-aggregate-import"></a>

### Metadata consumer: entities and roles

Code: `src/metadata/read.rs`, `src/metadata/role.rs`, `src/config/descriptors/aggregate.rs`

`SpMetadata`, `IdpMetadata`, and the descriptor imports built on them read
only the role that the peer acts in. `Metadata::parse` has no role and reads
every SSO role descriptor, whatever its namespace or
`protocolSupportEnumeration`. `MetadataAggregate` applies the same trust
policy and role selection as the single-entity import.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Count the members of a metadata group as its direct `md:EntityDescriptor` children and those of its direct `md:EntitiesDescriptor` groups. `Extensions` content adds none | Mandatory | Metadata §2.3.1, `EntitiesDescriptorType` | Always |
| Read the published `entityID` with XML Schema whitespace collapse during typed peer import | Mandatory | Metadata §2.3.2, `entityIDType`, [XML Schema 1.0 Part 2 §4.3.6](https://www.w3.org/TR/xmlschema-2/#rf-whiteSpace) | Always |
| Select a member of an `md:EntitiesDescriptor` by its whitespace-collapsed `entityID` before reading its SAML 2.0 roles | Optional | Metadata §2.3.1, §2.3.2 | `MetadataAggregate::idp_descriptor`, `MetadataAggregate::sp_descriptor` |
| Read `NameIDFormat` only from a child of a selected role descriptor in the metadata namespace, with XML Schema whitespace collapse. A child with the same local name in another namespace is not a format | Mandatory | Metadata §2.4.2, `SSODescriptorType`, XML Schema 1.0 Part 2 §4.3.6 | Always |

### Metadata consumer: keys

Code: `src/metadata/key_certificates.rs`, `src/flow.rs`, `src/crypto/verify.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the keys of a peer from the `KeyDescriptor` elements of the role it acts in. Verify its signatures and encrypt to it with that role's certificates | Mandatory | Metadata §2.4.1 | Always |
| Verify with the certificates of a `KeyDescriptor` whose `use` is `signing` or absent, and encrypt with those whose `use` is `encryption` or absent | Mandatory | Metadata §2.4.1.1, E62 | Always |
| Read a certificate only from a `ds:X509Certificate` in a `ds:X509Data` of the `ds:KeyInfo` of a `KeyDescriptor`, each in its own namespace. An element of the same local name in another namespace holds no key | Mandatory | Metadata §2.4.1.1, `KeyDescriptorType`, XML Signature §4.4, §4.4.4 | Always |
| Try every certificate published for the same use when verifying | Recommended | E68 | Always |

<a id="typed-metadata-accessors"></a>

### Metadata consumer: endpoints

Code: `src/metadata/endpoints.rs`, `src/metadata/mod.rs`, `src/metadata/idp.rs`, `src/metadata/sp.rs`, `src/config/descriptors.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read an endpoint only from a child of a selected role descriptor in the metadata namespace. A child with the same local name in another namespace is not an endpoint | Mandatory | Metadata §2.4.2, §2.4.3, §2.4.4, `SSODescriptorType`, `IDPSSODescriptorType`, `SPSSODescriptorType`, E37 | Always |
| Read unqualified `Binding` and `Location` with XML Schema whitespace collapse. Apply the same rule to `ResponseLocation` on logout and name identifier management services, and `index` and `isDefault` on artifact and assertion consumer services. A qualified attribute of the same local name is foreign and is not read | Mandatory | Metadata §2.2.2, §2.2.3, XML Schema 1.0 Part 2 §4.3.6 | Always |
| Choose the default of an indexed set as the first endpoint with `isDefault` true, else the first without `isDefault` false, else the first | Mandatory | Metadata §2.2.3, E37 | Always |
| Require unqualified `Binding`, `Location`, and an `unsignedShort` `index` on each `ArtifactResolutionService` when the role's artifact resolution endpoints are read | Mandatory | Metadata §2.2.2, §2.2.3 | `IdpMetadata::artifact_resolution_services` |
| Reject duplicate `ArtifactResolutionService` indexes within one `IDPSSODescriptor` | Mandatory | Metadata §2.2.3 | `IdpMetadata::artifact_resolution_services` |
| For `single_logout_response_location`, use a nonempty `ResponseLocation` on the selected endpoint, falling back to `Location` | Optional | Metadata §2.2.2, E41 | Always |

<a id="metadata-validity"></a>

### Metadata consumer: validity

Code: `src/metadata/validity.rs`, `src/metadata/role.rs`, `src/config/descriptors.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| For each role, take the earliest `validUntil` on the role, its entity, or an enclosing group | Mandatory | `EntitiesDescriptorType`, `EntityDescriptorType`, `RoleDescriptorType`, E76, E94 | Always |
| Refuse a typed flow at or after the effective `validUntil`, without clock skew. A flow that takes `SamlValidationContext` uses its clock | Mandatory | E94 | Always |
| Read only the unqualified `validUntil` | Mandatory | `EntityDescriptorType` | Always |
| Require an `xs:dateTime` value, including the prohibition on year 0000 | Mandatory | XML Schema 1.0 Part 2 §3.2.7.1 | Always |
| Read `24:00:00` as midnight of the next day in the supplied timezone | Mandatory | XML Schema 1.0 §3.2.7.1 | Always |
| Keep using a descriptor whose `cacheDuration` has elapsed | Optional | E94 | Always |

### Metadata consumer: entity attributes and scopes

Code: `src/metadata/entity_attributes.rs`, `src/metadata/scope.rs`, `src/metadata/role.rs`

These rows do not claim saml2int. Releasing attributes by entity category is
the application's.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Read the `saml:Attribute` children of every `mdattr:EntityAttributes` in the `Extensions` of the `EntityDescriptor` and of each enclosing `EntitiesDescriptor`, outermost group first, as attributes of the entity, from the document `RequireSignature` verified. Import adds no rejection | Optional | MDAttr §2.2, §2.3 | `Metadata::entity_attributes`, `SpDescriptor::entity_attributes`, `IdpDescriptor::entity_attributes` |
| Return entity category and category support values in order | Optional | RFC 8409 §3.1, §4.1 | `EntityAttributes::entity_categories`, `EntityAttributes::entity_category_support` |
| Combine the values of every matching attribute into one list | Recommended | RFC 8409 §3.1, §4.1 | Always |
| Compare the values as opaque strings, with no order between versions | Mandatory | RFC 8409 §3.2, §4.2 | Always |
| Return assurance certification framework URIs in order, such as REFEDS Sirtfi's `https://refeds.org/sirtfi` | Optional | Identity Assurance §§3.2–3.5 | `EntityAttributes::assurance_certifications` |
| Read direct `shibmd:Scope` declarations in the entity's `Extensions` and in the selected SAML 2.0 IdP roles' `Extensions`, so a relying party can accept scoped values by their authorized scopes | Mandatory | Subject Identifier §3.5.2, §4.2 | `IdpMetadata::scopes`, `IdpDescriptor::scopes` |
| Preserve the scope text and the `regexp` flag. Treat an omitted flag as false and report malformed declarations when scopes are read | Mandatory | Subject Identifier §3.5.2.1 | Always |

For the use of scope declarations after login, see
[scoped attributes](web-browser-sso-acceptance.md#scoped-attributes).

<a id="replay"></a>

### Service provider: SSO replay

Code: `src/model/validation.rs`, `src/model/sso.rs`, `src/assertion_acceptance.rs`

With `ReplayPolicy::RequireCache`, receive operations store message,
assertion, and artifact keys in the caller's `ReplayCache` and refuse a
repeated key. `ReplayPolicy::NoCache` skips only that storage, and the
signature, issuer, correlation, destination, and time checks still run.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Require a caller-owned cache for every HTTP-POST SSO acceptance. A duplicate bearer assertion `ID` or a storage failure prevents acceptance | Mandatory | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |
| For HTTP-POST, retain each bearer assertion `ID` through its `SubjectConfirmationData@NotOnOrAfter` validity window, including allowed skew | Mandatory | Profiles §4.1.4.3, §4.1.4.5, E26, E92 | `SamlValidationContext::with_clock_skew` |
| Treat `OneTimeUse` as always valid | Mandatory | Core §2.5.1.5 | Always |
| Report whether the consumed assertion carries `OneTimeUse` | Optional | Core §2.5.1.5 | `SsoSession::is_one_time_use` |

The [SSO replay policies](#sso-replay-deadlines) set the deadline of each
stored key. Artifact and name identifier management replay rows are in
[Artifact resolution](artifact-resolution.md) and
[Name identifier management](name-id-management.md). The `ReplayCache`
contract defines the result when an assertion deadline passes before storage.

## Library policies

<a id="generating-metadata"></a>

### Metadata publisher: `generate_sp_metadata`, `generate_idp_metadata`

Code: `src/metadata/generate.rs`, `src/metadata/lifetime.rs`, `src/metadata/scope.rs`, `src/model/endpoint.rs`, `src/config/descriptors.rs`, `src/config/builders.rs`, `src/crypto/keys.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Keep the configured order of the endpoints in each group | A peer takes the first suitable endpoint and the first indexed default (Metadata §2.2.3, E37), so the caller's order is its preference. | Metadata §2.2.3, E37 | Always |
| Write an `emailAddress` `NameIDFormat` when a service provider configures none | The typed service provider requests the first format its metadata lists, so the published format matches the one it requests. | Metadata §2.4.2 | `name_id_format`, `name_id_formats` |
| Give an `AssertionConsumerService` without an explicit index its position as `index`, or the smallest unused value when an explicit index holds that position | Metadata §2.2.3 leaves the values open, and positions keep the numbers that peers stored until the caller sets an index. | Metadata §2.2.3 | `Endpoint::index` |
| Take each endpoint that `SpConfigBuilder` and `IdpConfigBuilder` publish as an `EndpointUrl`, an absolute HTTP or HTTPS URL. The generators take any absolute URI reference | Reason not recorded. | Metadata §2.2.2 | Always |
| Publish an `ArtifactResolutionService` with an `EndpointUrl` and the SOAP binding | Artifact resolution uses a synchronous binding, and SOAP over HTTP is the one the crate implements for it. | Metadata §2.2.2, Bindings §3.6 | `IdpConfigBuilder::artifact_resolution_service` |
| Write `validUntil` in UTC truncated to whole seconds, and refuse one outside the years 0001 to 9999 | Truncation never extends the validity the caller chose, and the import reads only four-digit years. | Metadata §2.3.2, XML Schema 1.0 Part 2 §3.2.7 | `MetadataLifetime` |
| Write `cacheDuration="PT86400S"` when no lifetime is configured | A daily refresh target without a fixed expiration suits metadata generated once at config build. | Metadata §2.3.2, E94 | `metadata_lifetime` on `SpConfigBuilder` and `IdpConfigBuilder` |
| With a crypto provider, load the signing and decryption keys and all their certificates, including additional signing certificates. Check that each private key matches its certificate | Peers use the published certificates to verify signatures and encrypt messages. | Metadata §2.4.1.1 | `SpConfigBuilder::build`, `IdpConfigBuilder::build` |
| Reject uppercase ASCII letters in literal scopes at publication | A case-sensitive literal has to match the lowercase scope the typed IdP issues. | Subject Identifier §3.3.1 and §3.5.2 | Always |

<a id="metadata-trust"></a>

### Metadata consumer: signed metadata

Code: `src/config/metadata_trust.rs`, `src/config/metadata_signature_shape.rs`, `src/crypto/verify.rs`, `src/config/descriptors.rs`, `src/config/descriptors/aggregate.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Leave a signature that is present unverified, and report no signed metadata | The caller selected `Unverified` after authenticating the document through another channel. | Metadata §4.3.3.2 | `MetadataTrustPolicy::Unverified` |
| Verify a metadata signature only with caller-pinned certificates. A certificate in the document's `ds:KeyInfo` or `KeyDescriptor` is no trust anchor for it | A key that the document publishes proves nothing about who published it, so the trust anchor comes from outside the document. | Metadata §3.1.6 (E91), E69 | `MetadataTrustPolicy::RequireSignature` |
| Import signed metadata only when its single `ds:Signature` is a direct child of the document root and covers that root. An element named `Signature` or `Object` in another namespace is not an XML signature element | The import verifies only the root signature against the pinned certificates, so a member signature would otherwise be accepted without being verified. | Metadata §3.1.2 | `MetadataTrustPolicy::RequireSignature` |
| Reject an MD5 or RIPEMD-160 signature or digest algorithm and an RSA signing key under 2048 bits. See [weak algorithms and keys](xml-security-algorithms.md#weak-algorithms-and-keys) | The certificates a verified document publishes are then trusted for its messages, so the trust root must not use weak algorithms. | Metadata §3.1.1 (E81) | `MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` |
| Under a signature-requiring policy, require the signature to cover the aggregate root and reuse that verification for lookups | A member signature cannot authenticate its enclosing groups or sibling members. | Metadata §3.1.2 | `MetadataTrustPolicy::Unverified` when the caller already trusts the entire document |
| Verify a pinned root signature for scope authorization under a certificate the SP pins as a trusted third-party registration authority | It distinguishes the authority's signature from a generic metadata publisher's signature. | Subject Identifier §3.5.2, saml2int SDP-SP17, Metadata §3.1.1–§3.1.6 (E91) | `MetadataTrustPolicy::RequireRegistrationAuthoritySignature` |

### Metadata consumer: entities and roles

Code: `src/metadata/read.rs`, `src/metadata/role.rs`, `src/config/metadata_trust.rs`, `src/config/descriptors/aggregate.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Import a document with exactly one entity through the single-entity constructors | Those constructors require unambiguous input without searching an aggregate. | Metadata §2.3.1 | Use `MetadataAggregate` for several members |
| Require the expected `EntityId` to equal the whitespace-collapsed `entityID` character for character, with no URI normalization or case folding | Federations register entity identifiers as opaque strings, so a normalized match could bind the caller to another registered entity. | Metadata §2.3.2, `entityIDType` | Always |
| Require an `md:EntitiesDescriptor` root when loading an aggregate | The aggregate looks up members of a group, and a document whose root is one `EntityDescriptor` has the single-entity import. | Metadata §2.3.1 | `IdpDescriptor::from_metadata_xml`, `SpDescriptor::from_metadata_xml` |
| Refuse an aggregate lookup with no match or several members with the requested ID | Selecting a different member or one of several matches can bind the caller to the wrong keys and endpoints. | Metadata §2.2.1, §2.3.1 | Always |
| Require explicit XML resource limits when loading an aggregate | Feeds vary in size and callers choose their parsing budget. | — | `XmlLimits` |
| Read keys, signing flags, `NameIDFormat`, endpoints, and role-level `validUntil` only from role descriptors in the metadata namespace that list `urn:oasis:names:tc:SAML:2.0:protocol`. Refuse an entity with none | A role published for another protocol must not supply keys, flags, or endpoints for SAML 2.0 messages. | Metadata §2.4.1 | Always |
| Read several such roles of one kind together | A key, an endpoint, or an index that only a later role publishes still works. | Metadata §2.3.2 | Always |
| Read `AuthnRequestsSigned` as true when any SAML 2.0 `SPSSODescriptor` sets it. The identity provider then [refuses an unsigned request](web-browser-sso-acceptance.md#identity-provider) | E7 makes the identity provider refuse an unsigned request from a service provider whose metadata sets the flag, and the request does not name a role. | Metadata §2.3.2, §2.4.4, E7 | Always |
| Read `WantAssertionsSigned` as true when any selected `SPSSODescriptor` sets it | An IdP serving these roles together honors each role's request for signed assertions. | Metadata §2.3.2, §2.4.4 | Always |
| Read `WantAuthnRequestsSigned` from the first SAML 2.0 `IDPSSODescriptor` that specifies it | When only a later role publishes the flag, it still applies, like a key or an endpoint that only a later role publishes. | Metadata §2.4.3 | Always |

### Metadata consumer: keys

Code: `src/metadata/key_certificates.rs`, `src/flow.rs`, `src/crypto/verify.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Verify a certificate-based message signature with the signing keys of the peer's role. A certificate embedded in the message neither selects nor restricts the key | The sender chooses what the message embeds, so only keys from the peer's metadata authenticate it. | Metadata §2.4.1.1, E69 | Always |
| Reject a message signed with a key that only the peer's other role publishes | Reason not recorded. | Metadata §2.4.1 | Always |
| Ignore a `KeyDescriptor` whose `use` is neither value | `KeyTypes` defines no other purpose, so such a key authorizes neither use, and the rest of the role stays usable. | Metadata §2.4.1.1, `KeyTypes` | Always |

### Metadata consumer: endpoints

Code: `src/metadata/sp.rs`, `src/metadata/idp.rs`, `src/metadata/endpoints.rs`, `src/xml/schema_value.rs`, `src/config/descriptors.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Select a default `AssertionConsumerService` within one SAML 2.0 `SPSSODescriptor`: the first one for a lookup without a binding, else the first one that publishes the binding | E37 defines the default within one role, and Metadata §2.3.2 leaves the choice among roles undefined. | Metadata §2.2.3, §2.3.2, E37 | Always |
| Look up an `AssertionConsumerServiceIndex` in each selected `SPSSODescriptor`, counting endpoints of every binding. Refuse an index that one of them publishes twice or that more than one of them publishes | The request names the index but not the role, so a guessed endpoint could receive an assertion the requester did not route there. | Core §3.4.1, Metadata §2.2.3, §2.3.2 | Always |
| Refuse the import when an `AssertionConsumerService` of a selected SP role or an `ArtifactResolutionService` of a selected IdP role has no `Binding`, no `Location` or an empty one, no `index` or one that is not an integer, or an `isDefault` that is not an `xs:boolean` | Reading such an endpoint leniently or skipping it could change which endpoint the default and index lookups select. | Metadata §2.2.2, §2.2.3, E37 | Always |
| Import such an endpoint when its `Binding` is empty, its `Binding` or `Location` holds only whitespace, or its `index` is an integer outside 0 to 65535. An assertion consumer service reads such an `index` as none, and the artifact resolution accessors refuse the endpoint | The rest of the peer's metadata stays usable, and a lookup reads such an endpoint without the value, skips it, or refuses it. | Core §1.3.2, Metadata §2.2.2, §2.2.3 | Always |
| Skip an `AssertionConsumerService` whose `Binding` the crate does not support in a lookup by binding or URL. Refuse the default for a lookup without a binding when the endpoint it selects has such a `Binding` | Reason not recorded. | Metadata §2.2.2, §2.2.3, E37 | Always |
| Look up an artifact's `EndpointIndex` in each selected `IDPSSODescriptor`, and refuse an index that more than one of them publishes | The artifact names its issuer and index but not the role, so a guessed role could receive an `ArtifactResolve` for an artifact it did not issue. | Metadata §2.2.3, §2.3.2, Bindings §3.6.4 | `IdpMetadata::artifact_resolution_service` |
| Reject an `ArtifactResolutionService` whose `Binding` or `Location` is empty after whitespace collapse | Reason not recorded. | Core §1.3.2, Metadata §2.2.2 | `IdpMetadata::artifact_resolution_services` |
| Return a selected endpoint as an `EndpointUrl`. A non-HTTP(S) URL is an error from the accessor, and import accepts it | The typed endpoint contract is absolute HTTP(S), and Metadata §2.2.2 and §2.2.3 use `anyURI` without that restriction. | Metadata §2.2.2, §2.2.3 | Always |

[Shibboleth SP 3.6.0](https://codeberg.org/Shibboleth/cpp-sp/src/tag/3.6.0/shibsp/binding/impl/ArtifactResolver.cpp)
looks up the artifact's index only in the first `IDPSSODescriptor` that is
currently valid and supports SAML 2.0, a role it takes from
[OpenSAML-C 3.3.1](https://codeberg.org/Shibboleth/cpp-opensaml/src/tag/3.3.1/saml/saml2/metadata/Metadata.h#L594).

[SimpleSAMLphp 2.3.5](https://github.com/simplesamlphp/simplesamlphp/blob/v2.3.5/src/SimpleSAML/Metadata/SAMLParser.php#L545-L546)
reads only the first `SPSSODescriptor` that supports SAML 2.0, and its
[identity provider](https://github.com/simplesamlphp/simplesamlphp/blob/v2.3.5/modules/saml/src/IdP/SAML2.php#L198-L253)
looks up the `AssertionConsumerServiceIndex` and the default for a
`ProtocolBinding` in that role.
[OpenSAML 5.1.3](https://codeberg.org/Shibboleth/java-opensaml/src/tag/5.1.3/opensaml-saml-impl/src/main/java/org/opensaml/saml/common/binding/impl/SAMLMetadataLookupHandler.java#L181)
also resolves a single role descriptor for the peer.

### Metadata consumer: validity

Code: `src/metadata/validity.rs`, `src/metadata/role.rs`, `src/config/descriptors.rs`, `src/config/descriptors/aggregate.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Bound all roles of one kind by the earliest `validUntil` of them | The descriptor reads those roles together. | E76 | Always |
| Require an explicit timezone | XML Schema 1.0 §3.2.7.4 leaves the order of a value without one against an instant indeterminate, so the expiry cannot be decided. | XML Schema 1.0 Part 2 §3.2.7.4 | Always |
| Of schema-valid years, accept only local years 0001 to 9999, including after midnight rollover. Reject a leap second outside the last minute of a UTC month | The RFC 3339 parser the library uses reads four-digit years and accepts a leap second only in that minute. | XML Schema 1.0 Part 2 §3.2.7.1 | Always |
| Refuse metadata whose root element has no `validUntil`, or one more than a caller-chosen interval after the caller's time. A `validUntil` below the root does not count | It implements saml2int SDP-MD03, which bounds how long a captured document stays usable after a key revocation. | Metadata §2.3.1, §2.3.2, saml2int SDP-MD03 | `require_root_valid_until` on `MetadataAggregate`, `IdpDescriptor`, `SpDescriptor` |

### Metadata consumer: entity attributes and scopes

Code: `src/metadata/entity_attributes.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Ignore `EntityAttributes` in a role descriptor's `Extensions` or nested in another extension element | MDAttr §2.3 leaves its meaning undefined outside the `Extensions` of an entity or group. | MDAttr §2.3 | Always |
| Match a well-known entity attribute by its `Name` with the URI `NameFormat`, no `NameFormat`, or `unspecified`, and ignore `FriendlyName` | Core §2.7.3.1 gives an absent `NameFormat` the unspecified meaning, and the Shibboleth `EntityAttributes` predicate matches such an attribute. | RFC 8409 §§3.1, 4.1, Identity Assurance §3.3, Subject Identifier §3.5.1 | Always |
| Include the values that an enclosing `EntitiesDescriptor` binds | RFC 8409 §3.1 defines the attribute only in the entity's own `Extensions`, and MDAttr §2.3 binds a group's attributes to each member. | RFC 8409 §3.1, MDAttr §2.3 | Always |
| Reject a read `subject-id:req` without exactly one value, with a value outside the four, or repeated with a different requirement. Import does not reject it | The profile rules these out, and one requirement cannot be chosen from them. | Subject Identifier §3.5.1 | `EntityAttributes::subject_id_requirement` |

<a id="sso-replay-deadlines"></a>

### Service provider: SSO replay

Code: `src/model/sso.rs`, `src/assertion_acceptance.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| For each direct bearer assertion, use its latest UTC bearer deadline. Ignore an unparseable deadline if another parses. Storage fails when none parses for the selected assertion. Give another assertion the selected assertion's deadline when its own has passed or does not parse | It keeps the identifier at least as long as the confirmation that satisfied the checks. | Profiles §4.1.4.3 | Always |
| Also store the `Response` `ID` until the earliest of `Conditions@NotOnOrAfter`, the bearer confirmation, and each `SessionNotOnOrAfter`, plus skew | The response follows the [protocol message ID rule](#protocol-message-ids), and the response is not accepted after that deadline. | — | `ReplayPolicy::RequireCache` |
| Store bearer assertion `ID`s for HTTP-POST-SimpleSign or HTTP-Artifact when a cache is supplied | Profiles §4.1.4.5 states the duty for HTTP POST only, and Security considerations §7.1.1.4 defers replay countermeasures to the binding. | Profiles §4.1.4.5 | `ReplayPolicy::RequireCache` |

<a id="protocol-message-ids"></a>

### Receive operations: protocol message IDs

Code: `src/model/validation.rs`, `src/api/idp.rs`, `src/api/sp.rs`, `src/api/slo.rs`, `src/name_id_management.rs`, `src/name_id_management/redirect.rs`, `src/api/name_id_management/redirect.rs`

These rows cover the `ID` of an `AuthnRequest`, a `LogoutRequest`, a
`LogoutResponse`, and an SSO `Response`. The name identifier management
records link here for their messages.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Store a request `ID` only after authentication and every check that refuses it before storage. Store a response `ID` only for `Success`. A message refused or failed before storage is not stored, so its repeat is validated again from the start | An unsigned `ID` stops no replay because anyone can mint a new one, and a refusal changes no state. | — | `ReplayPolicy::RequireCache` |
| Store a `LogoutRequest` or `ManageNameIDRequest` `ID` before decrypting its identifier, so an undecryptable request counts as stored. Store the IDs of an SSO response whose assertion matches an `OutstandingLogout` before refusing it | The receiver has read the content and acted on it once, so a repeat must not reach decryption or acceptance again. | Core §3.7.3.1 | `ReplayPolicy::RequireCache` |
| Store the `ID` of an authenticated `AuthnRequest` that `receive_sso` returns, and of a `Success` `LogoutResponse` in `finish_slo`, for `with_replay_retention` | Web Browser SSO and Single Logout require no identifier cache for these messages, so the cache is the caller's choice. | — | `ReplayPolicy::RequireCache` |
| Store the `ID` of an authenticated `LogoutRequest` in `receive_slo` until its `NotOnOrAfter` plus skew, or for `with_replay_retention` when it has none | Single Logout requires no identifier cache, so the cache is the caller's choice. | Core §3.7.1 | `ReplayPolicy::RequireCache` |
| Refuse to store a message without `NotOnOrAfter` when `with_replay_retention` is unset or zero | The library has no acceptance deadline for such a message, so a default retention could expire while the message is still accepted. | — | `SamlValidationContext::with_replay_retention` |

`finish_slo` and `finish_name_id_management_redirect` borrow the pending
request, so using each pending request once is the caller's storage duty. A
store that removes it before the call needs no cache for the response, and a
store that can return it again, such as a client-side session, needs one.

<a id="onetimeuse-application-duties"></a>

## Application duties

saml-rs keeps no assertion of its own, and the `ReplayCache` stores only
identifiers. The returned `SsoSession` holds the response XML, so an
application that keeps the session keeps its assertions and owns the
`OneTimeUse` duties.

| Duty | Level | Section |
| --- | --- | --- |
| Give the entity an `entityID` that no other entity in the deployment uses | Mandatory | Metadata §2.2.1 |
| Under `MetadataTrustPolicy::Unverified`, establish trust in the document through another channel, such as a file the operator provisions, before the import | Recommended | Metadata §4 |
| In a saml2int deployment, pass each scope of the subject identifiers the identity provider issues to `IdpConfigBuilder::scopes` as a `MetadataScope` with `regexp: false` | Mandatory | saml2int SDP-IDP14 |
| For HTTP-POST SSO, pass a `ReplayCache` whose storage every node that accepts HTTP-POST responses shares, such as `InMemoryReplayCache` in a single process. It atomically refuses a duplicate bearer assertion `ID` and keeps each key until the `expires_at` it receives | Mandatory | Profiles §4.1.4.5 |
| Do not keep an assertion that carries `OneTimeUse`, or the information it carries in another form, for future use. `SsoSession::is_one_time_use` reports the condition on the consumed assertion only | Mandatory | Core §2.5.1.5 |
| Use an assertion that carries `OneTimeUse` immediately | Recommended | Core §2.5.1.5 |

<a id="not-implemented"></a>

## Not supported

- Signing at least the root element of published metadata. Recommended,
  Metadata §3, when no other context authenticates the document. The
  application signs the XML that `metadata_xml` returns, or delivers it over
  an authenticated channel.
- Publication at, and resolution from, the well-known location or DNS,
  Metadata §4.1 and §4.2. The application serves the XML that `metadata_xml`
  returns, fetches a peer's document, and passes it to a descriptor import.
- Trust processing for Metadata §4 publication and resolution: document
  integrity at the publisher (Mandatory, Metadata §4.3.3), a signature on
  each published document (Recommended, Metadata §4.3.3.2), validation of a
  signature present on a resolved document at the consumer (Mandatory,
  Metadata §4.3.3.2), and server-authenticated TLS for retrieval
  (Recommended, Metadata §4, §4.3.3.3). The caller chooses a
  `MetadataTrustPolicy` for the document it fetched.
- Caching peer metadata by its `cacheDuration`. Mandatory for a consumer that
  caches, Metadata §4.3.1 as amended by E94. The application decides when to
  fetch a fresh copy and import it again.
- `saml:Assertion` in `mdattr:EntityAttributes`, at the publisher and the
  consumer. Import ignores it. A relying party that reads one processes it by
  the Core rules (MDAttr §2.3). A publisher signs each one (MDAttr §2.4) and
  puts none in a group's `EntityAttributes` (MDAttr §2.3), both Mandatory.
- The algorithm support elements `alg:DigestMethod` and `alg:SigningMethod`,
  and `EncryptionMethod` in a `KeyDescriptor` whose `use` is absent or
  `encryption`, at the publisher and the consumer. Publishing them is Recommended, Algorithm Support §2.3 and §2.4. A
  consumer that signs or encrypts with knowledge of the peer consults them,
  Mandatory, Algorithm Support §2.5. The generators write none of them, import
  ignores them, and the caller selects algorithms with `AlgorithmPolicy`.
- The login and discovery user interface elements `mdui:UIInfo` and
  `mdui:DiscoHints` (MDUI §2.1, §2.2), and the registration and publication
  elements `mdrpi:RegistrationInfo`, `mdrpi:PublicationInfo`, and
  `mdrpi:PublicationPath` (RPI §2.1 to §2.3), at the publisher and the
  consumer. The generators write none of them, and import ignores them.
