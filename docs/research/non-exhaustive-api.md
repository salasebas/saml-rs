# Public API extensibility audit

Research date: 2026-11-13. These choices are design judgments based on the current code, not normative Rust requirements. The 20 enums in the additions table receive enum-level annotations. The remaining types keep their current construction and matching contracts.

## Meaning and compatibility cost

`#[non_exhaustive]` reserves room for future enum variants or struct fields. Outside the defining crate, an annotated enum requires a catch-all match arm but still permits construction of its existing variants. An annotated struct prevents literals, including `..Default::default()` and other struct update expressions. Callers need a constructor, builder, or `Default`, followed by field mutation. Inside the defining crate, the attribute has no effect. [Rust Reference](https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute).

Enum-level annotation reserves new variants, not new fields on existing variants. Variant-level annotation also prevents downstream construction of that variant and restricts its patterns. Those are separate API decisions. No variant-level annotations are recommended by this audit. [Rust Reference](https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute).

Adding the attribute to an existing exhaustive enum, variant, or struct without private fields is source-breaking. A struct with a private field already prevents literal construction and ordinarily permits additional fields without this attribute. Other compatibility constraints still apply. [Cargo SemVer guide](https://doc.rust-lang.org/cargo/reference/semver.html#major-adding-non_exhaustive-to-an-existing-enum-variant-or-struct-with-no-private-fields).

Public fields remain mutable after annotation. The attribute does not establish validation invariants. The API Guidelines recommend private fields for encapsulation and recognize public fields as suitable for passive data records. They do not prescribe blanket use of `non_exhaustive`. [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/future-proofing.html#structs-have-private-fields-c-struct-private).

## Audit boundary

The audit follows [root exports and module visibility](../../src/lib.rs), the [public API map](../architecture/002-public-api-map.md), and public definitions under `src/`. Hidden public modules remain externally accessible and are included. Private implementation types are excluded. The private pending module's public associated-detail types are recorded below because they support public generic types. Type aliases need no separate annotation. The attribute does not apply to traits, functions, or modules.

The existing annotations listed below were present when research began. These changes preserve protocol behavior, defaults, and variant payloads. The source break and catch-all handling are documented in the [0.7-to-0.8 migration](../migrations/0.7-to-0.8.md#18-extend-exhaustive-matches).

## Selected additions

The attribute applies at enum level for these types. A catch-all means callers must handle future cases intentionally. It does not make an unsupported binding or algorithm supported.

| Types | Extensibility reason and evidence |
| --- | --- |
| `SignatureAlgorithm`, `DigestAlgorithm`, `DataEncryptionAlgorithm`, `KeyEncryptionAlgorithm`, `TransformAlgorithm` | Named algorithm capabilities can grow with provider support. Their `Custom(String)` variants already represent URI extensibility, but do not make additional named variants source-compatible. Keep existing variants constructible, especially `KeyEncryptionAlgorithm::RsaOaep { digest, mgf }`. [Definitions](../../src/config/algorithms.rs). |
| `MaskGenerationFunction` | Supported XML Encryption MGF algorithm URIs, currently a selected subset. Additional supported digests belong in this list. [Definition and URI mapping](../../src/config/algorithms.rs). |
| `NameIdFormat`, `AttributeNameFormat` | Named URI formats plus custom URI values. Future named formats or extension support are plausible without changing the shape of existing variants. [NameID formats](../../src/config/algorithms.rs), [attribute formats](../../src/model/attributes.rs). |
| `Binding` | Library-supported binding inventory, not a complete, permanently fixed SAML vocabulary. The existing list mixes core bindings with SimpleSign and omits PAOS as a raw binding variant. [Definition](../../src/constants.rs). |
| `SsoRequestBinding`, `SsoResponseBinding`, `LogoutBinding`, `NameIdManagementBinding` | These explicitly describe supported capabilities for each operation. Adding another permitted, implemented binding should not require downstream matches to enumerate it immediately. Profile restrictions still apply. [Definitions and conversions](../../src/browser/bindings.rs). |
| `BrowserInput<Message>` | Supported inbound delivery representations can grow alongside bindings. Existing marker-specific constructors already express intended usage. Enum-level annotation preserves direct variant construction and payload patterns. [Definition and constructors](../../src/browser/input.rs). |
| `ParserType` | Inventory of implemented protocol parsers. More SAML operations can join the current authentication, logout, and identifier-management operations. [Definition and mappings](../../src/constants.rs). |
| `XmlSignatureProfile` | Named algorithm and signature-shape profiles can evolve as provider capabilities and security guidance change. These are library profiles, not a fixed protocol enumeration. [Definition](../../src/config/policies.rs). |
| `MetadataTrustPolicy<'a>` | Named trust and compatibility profiles already distinguish signature algorithms and canonicalization. Additional explicit trust profiles are credible. Retain construction of certificate-bearing variants. [Definition and import behavior](../../src/config/metadata_trust.rs). |
| `NameIdManagementRefusal`, `ArtifactWithheld` | Diagnostic reasons describe current refusal checks, rather than a complete protocol vocabulary. Additional checks can introduce additional reasons. [Identifier refusal reasons](../../src/name_id_management.rs), [artifact withholding reasons](../../src/artifact.rs). |
| `ContactType` | Already extends the base contact vocabulary with `Security`, encoded using REFEDS attributes. More explicitly supported contact extensions are credible. This recommendation follows the current extension-aware model. [Definition and writer](../../src/metadata/description.rs). |

## Existing annotations to retain

| Types | Assessment |
| --- | --- |
| `SamlError`, `SignatureVerificationReason`, `ReferenceResolutionReason`, `SubjectConfirmationReason`, `TimeWindowField` | Appropriate evolving failure classifications and validation locations. Enum-level annotations do not reserve changes to existing error payloads. [Definitions](../../src/error.rs). |
| `ReplayKey`, `ReplayPolicy<'a>` | Replay namespaces can grow with implemented operations. Preserve the existing policy annotation. [Definitions](../../src/model/validation.rs). |
| `CryptoProvider`, `CryptoFipsStatus` | Provider and initialization-status inventories can grow. [Definitions](../../src/crypto/provider.rs). |
| `AssertionDecryptionOptions` | Existing annotation reserves future options, with `Default` as the construction entry. [Definition](../../src/crypto/enc/decrypt.rs). |
| `BergshamraBackend` | Existing annotation deliberately reserves state in a currently unit-shaped backend. A `Default` constructor exists. [Definition](../../src/crypto/bergshamra.rs). |
| `EntitySetting`, `FlowOptions<'a>`, `CryptoProviderInfo` | Existing annotations may stay, but private fields already provide most of the construction restriction. Their presence is not a reason to annotate every private-field struct. [Settings](../../src/entity.rs), [flow options](../../src/flow.rs), [provider info](../../src/crypto/provider.rs). |

## Retain exhaustive enums

These types describe closed choices in the current abstraction. Exhaustiveness helps callers implement complete behavior. A future requirement can justify revisiting an individual decision.

| Types | Reason to retain exhaustiveness |
| --- | --- |
| `ForceAuthn`, `IsPassive` | Named boolean choices. [Definitions](../../src/model/authn.rs). |
| `NameIdCreationRequest`, `NameIdCreationPolicy` | Omitted, true, and false request states, or the explicit true and false configuration choice. [Request model](../../src/model/subject.rs), [policy](../../src/config/policies.rs). |
| `RelayStateParam` | Complete absent, empty, and nonempty classification. [Definition](../../src/model/relay.rs). |
| `TopLevelStatusCode` | The four SAML 2.0 top-level status values are a closed set in Core §3.2.2.2. Extension URIs belong to subordinate status codes, represented separately. [Definition](../../src/model/status.rs), [OASIS Core, pp. 39–40](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf). |
| `AuthnContextComparison`, `AuthnContextReferenceKind` | The schema enumerates four comparisons and chooses class references or declaration references. New reference URI values do not require new kinds. [Definitions](../../src/model/authn_context.rs), [OASIS Core §3.3.2.2.1, pp. 44–45](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf). |
| `RequestedSubjectIdentifier` | The current subject model distinguishes no identifier, `NameID`, `BaseID`, and `EncryptedID`. A new `BaseID` implementation can fit the existing category. [Definition](../../src/model/subject.rs). |
| `NameIdChange` | Change to a new identifier or terminate its use. Encrypted new identifiers decode into the same change category. [Definition](../../src/name_id_management.rs), [OASIS Core §3.6.1, pp. 57–58](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf). |
| `CertUse`, `MessageSignatureOrder` | Signing versus encryption key selection, and the two orders of signing and encryption. These are closed choices at their current scope. [Definitions](../../src/constants.rs). |
| `PartyAuthentication`, `MessageIntegrity`, `MessageConfidentiality` | Explicit channel protection claims, each currently a binary choice. Additional authentication mechanisms need not change whether mutual authentication is attested. [Definitions](../../src/soap.rs). |
| `AssertionSignaturePolicy`, `AuthnRequestSigningPolicy`, `LogoutSignaturePolicy` | Require or allow a signature, or sign or do not sign. [Definitions](../../src/config/policies.rs). |
| `AssertionEncryptionPolicy`, `IdentifierEncryptionPolicy`, `AttributeEncryptionPolicy` | Plaintext versus encrypted element selection. Additional algorithms belong to the algorithm enums. [Definitions](../../src/config/policies.rs). |
| `AuthnRequestValidationPolicy`, `AudienceValidationPolicy` | Deliberate ignore, evaluate-if-present, and require-and-evaluate modes. Preserve complete handling of these security choices. [Definitions](../../src/config/policies.rs). |
| `ResponseSignaturePolicy` | Current explicit acceptance modes for the response signature and encrypted-CBC case. Prefer complete handling unless a concrete additional mode is planned. This is a judgment call. [Definition](../../src/config/policies.rs). |
| `LogoutSigning` | Follow local policy, sign, or explicitly decline signing. These are dispatch decisions, not a profile registry. [Definition](../../src/api/options.rs). |
| `AuthnRequestAgePolicy`, `ManageNameIdRequestAgePolicy` | Disabled or bounded time window. Both modes retain direct variant construction. [Definitions](../../src/model/validation.rs). |
| `MetadataLifetime`, `CommonDomainCookieLifetime` | Combinations of the two existing metadata lifetime attributes, or session versus persistent cookie lifetime. [Metadata](../../src/metadata/lifetime.rs), [cookie](../../src/discovery.rs). |
| `VerifiedXmlSignatureCoverage` | Nonempty combinations of response-root and consumed-assertion coverage. This type reports SSO coverage, not arbitrary future signed objects. [Definition](../../src/model/sso.rs). |
| `ReceivedNameIdManagement<Response>` | Request handed to the application versus refusal already answered. New reasons belong to `NameIdManagementRefusal`. [Definition](../../src/name_id_management.rs). |
| `ArtifactRelease` | Returned message, withheld message, or version-mismatch reply. New withholding reasons fit `ArtifactWithheld`. Additional reply categories would justify reopening this decision. [Definition](../../src/artifact.rs). |
| `SignatureAction`, `LocalPath`, `Value` | Current placement operations, single versus multiple extraction paths, and the extractor's null, string, array, and object value grammar. No concrete extension need found. Additional numeric or typed values would be a deliberate extractor API change. [Placement](../../src/entity.rs), [paths](../../src/xml/extract.rs), [values](../../src/util.rs). |
| `Unknown`, `ManageNameIdResponse` | Empty marker enums. Downstream uninhabited reasoning is useful; `non_exhaustive` would make them considered inhabited outside the crate. [Role marker](../../src/api/mod.rs), [response marker](../../src/name_id_management.rs), [Rust Reference](https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute). |

## Retain public-field struct construction

An extensible configuration record can justify the attribute in a new API. Here, constructors or `Default` alone do not outweigh an established literal-construction contract. No new struct annotations are recommended in this audit.

| Types | Construction evidence and cost |
| --- | --- |
| `SpConfig`, `IdpConfig` | `new`, `try_new`, and full builders exist, but advanced literal construction is explicitly supported by the [construction design](../architecture/005-config-and-metadata.md#construction-style). Integration tests compare builders with literals. Reserving fields would require deliberately withdrawing that supported path. [Tests](../../tests/builder_policy.rs). |
| `config::SpMetadataConfig`, `config::IdpMetadataConfig` | Constructors accept required endpoints, while public fields and literals expose complete metadata choices. The same builder-versus-literal tests exercise them. [Definitions](../../src/config/descriptors.rs), [tests](../../tests/builder_policy.rs). |
| `SpValidationPolicy`, `IdpValidationPolicy`, `LogoutPolicy`, `XmlPolicy`, `AlgorithmPolicy`, `TemplatePolicy` | Presets and defaults are customized with public-field literals and update syntax. `SpValidationPolicy::recommended` and `XmlPolicy` document that style. The policy enums can reserve extensibility independently. [Definitions and examples](../../src/config/policies.rs), [integration construction](../../tests/builder_policy.rs). |
| `Credentials`, `DecryptionCredential` | Credential records are supplied through literals, including `Credentials { ..Default::default() }`. `DecryptionCredential` has neither `Default` nor an alternative public constructor. Annotating it alone removes ordinary downstream construction. [Definitions](../../src/config/credentials.rs), [example](../../examples/sso.rs), [rollover tests](../../tests/builder_policy.rs). |
| `metadata::generate::SpMetadataConfig`, `metadata::generate::IdpMetadataConfig`, `metadata::generate::Endpoint`, `ArtifactResolutionEndpoint` | Raw generation records use literals and default updates. `Endpoint::new` does not imply the raw configuration construction contract is withdrawn. `ArtifactResolutionEndpoint` has no alternative constructor. [Definitions](../../src/metadata/generate.rs), [raw example](../../examples/raw_compat.rs). |
| `LocalizedValue`, `Organization`, `ContactPerson` | Passive metadata records. Constructors exist for localized values and contacts, while organization and contact overrides use literals. [Definitions](../../src/metadata/description.rs), [tests](../../tests/metadata_description.rs). |
| `XmlLimits` | Real extension potential for parser budgets, but callers configure limits with default update syntax. Preserve this ergonomic contract for the current audit. [Definition](../../src/xml/dom.rs), [usage test](../../tests/default_xml_limits.rs). |
| `LoginRequestOptions<'a>`, `LoginResponseOptions<'a>` | Raw compatibility options use literals with defaults; the API map itself demonstrates response options this way. [Request options](../../src/sp.rs), [response options](../../src/idp.rs), [API map](../architecture/002-public-api-map.md#raw-api-in-this-design). |
| `IdentityProvider`, `ServiceProvider`, `User`, `SignatureConfig`, `BindingContext`, `HttpRequest`, `FlowResult` | Raw passive records retain assembly and mutation through public fields. Annotation would remove that construction API without a specific new field requirement. [Providers](../../src/idp.rs), [SP](../../src/sp.rs), [entity records](../../src/entity.rs), [flow records](../../src/flow.rs). |
| `LoginResponseAttribute`, `LoginResponseTemplate` | Caller-authored template data with public fields. Keep literals, including complete attribute descriptions. [Definitions](../../src/template.rs). |
| `PendingPaosSsoSnapshot` | Persistence record that callers rebuild from stored fields. It has no public constructor replacing literals. [Definition and restoration](../../src/api/paos/mod.rs). |
| `Started<Message>`, `StartedPaosSso` | Simple output pairs. Complete destructuring and assembly are useful; no specific extra field is identified. [Browser result](../../src/browser/pending.rs), [PAOS result](../../src/api/paos/mod.rs). |
| `Node`, `Document`, `ExtractorField` | Public raw XML and extraction records. `ExtractorField` also has fluent constructors, but current public data construction remains useful. No specific growth requirement justifies withdrawing it. [DOM](../../src/xml/dom.rs), [extraction](../../src/xml/extract.rs). |

## Redundant private-field struct annotations and markers

These structs already have a non-public field, including mixed-visibility structs. They can acquire fields without newly banning downstream literals, which are already unavailable. Public accessors, constructors, and trait implementations still carry their own compatibility contracts. [Cargo SemVer guide](https://doc.rust-lang.org/cargo/reference/semver.html#minor-adding-or-removing-private-fields-when-at-least-one-already-exists).

| Types | Existing boundary |
| --- | --- |
| `Saml<Role>`, `Sp`, `Idp`, `SpConfigBuilder`, `IdpConfigBuilder` | Private runtime state or builder storage. [Facade](../../src/api/mod.rs), [builders](../../src/config/builders.rs). |
| `PrivateKeyPem`, `CertificatePem`, `Passphrase`, `HmacSecret`, `EntityId`, `ArtifactResolutionService`, `ManageNameIdService`, `IdpDescriptor`, `SpDescriptor` | Private wrappers or descriptor state. [Credentials](../../src/config/credentials.rs), [descriptors](../../src/config/descriptors.rs). |
| `XmlEncryptionPolicy` | Public element choices coexist with a private RSA-v1.5 compatibility flag; literals are already unavailable. [Definition](../../src/config/policies.rs). |
| `StartSso`, `RespondSso<Delivery>`, `StartSlo`, `RespondSlo`, `StartNameIdManagement`, `ReceiveNameIdManagement`, `RespondNameIdManagement` | Private or restricted option storage with named constructors and fluent methods. [Definitions](../../src/api/options.rs). |
| `PaosClientRequest`, `StartPaosSso`, `RespondPaosSso`, `PendingPaosSso`, `HttpHeader`, `PaosHttpResponse<Message>`, `PaosAuthnRequest`, `PaosSsoResponse` | Private marker, option, message, or response storage. [Definitions](../../src/api/paos/mod.rs). |
| `RelayState`, `EndpointUrl`, `MessageId`, `AssertionId`, `SamlInstant`, `SessionIndex`, `AttributeValue`, `Attributes` | Private newtype fields. [RelayState](../../src/model/relay.rs), [endpoint](../../src/model/endpoint.rs), [identifiers](../../src/model/identifiers.rs), [attributes](../../src/model/attributes.rs). |
| `Attribute`, `AuthnContext`, `AuthnContextReference`, `RequestedAuthnContext`, `SubjectLocality`, `SubordinateStatusCode`, `Status`, `ClockSkew`, `SamlValidationContext<'a>`, `InMemoryReplayCache` | Private models or validation state. [Attributes](../../src/model/attributes.rs), [authentication context](../../src/model/authn_context.rs), [accepted authentication details](../../src/model/authn_details.rs), [status](../../src/model/status.rs), [validation](../../src/model/validation.rs), [cache](../../src/model/replay_cache.rs). |
| `AuthnRequest`, `AuthnSession`, `NameId`, `NameIdPolicy`, `SubjectConfirmation`, `Subject`, `RequestedSubject`, `Received<Message>` | Private message and subject state. [Request](../../src/model/authn.rs), [session](../../src/model/session.rs), [subjects](../../src/model/subject.rs), [received message](../../src/model/received.rs). |
| `SsoResponse`, `Assertion`, `VerifiedXmlSignature`, `SsoSession`, `LogoutSubject`, `LogoutRequest`, `LogoutResponse`, `LogoutCompleted`, `OutstandingLogout` | Private accepted-message or logout state. [SSO](../../src/model/sso.rs), [logout](../../src/model/logout.rs), [outstanding logout](../../src/model/outstanding_logout.rs). |
| `FormField`, `PostForm`, `SsoEndpoint`, `AcsEndpoint`, `SloEndpoint`, `Outbound<Message>`, `ArtifactDelivery`, `DeliveredArtifact`, `Pending<Message>`, `PendingSnapshot<Message>` | Private browser state. Even the public snapshot has a private marker field. [Forms](../../src/browser/forms.rs), [endpoints](../../src/browser/endpoints.rs), [outbound](../../src/browser/outbound.rs), [artifacts](../../src/browser/artifact.rs), [pending state](../../src/browser/pending.rs). |
| `AuthnPendingDetails`, `LogoutPendingDetails`, `ManageNameIdPendingDetails` | Private-field associated-detail storage inside a private module; no separately exported construction API. [Definitions](../../src/browser/pending.rs). |
| `Metadata`, `IdpMetadata`, `SpMetadata`, `ArtifactResolutionServiceEndpoint`, `MetadataSignatureVerification` | Private parsed or verified metadata storage. [Metadata](../../src/metadata/mod.rs), [IdP](../../src/metadata/idp.rs), [SP](../../src/metadata/sp.rs), [verification result](../../src/crypto/verify.rs). |
| `Artifact`, `ArtifactDereference`, `IssuedMessage`, `IssuedArtifacts`, `ArtifactUses`, `AnsweredArtifact`, `ArtifactResolution`, `ResolvedProtocolMessage` | Private artifact data or lifecycle state. [Definitions](../../src/artifact.rs). |
| `ManageNameIdRequest`, `RefusedNameIdManagement<Response>`, `StartedNameIdManagement` | Private identifier-management state. [Definitions](../../src/name_id_management.rs). |
| `SoapChannel`, `SoapRequest`, `SoapResponse`, `SoapProtocolMessage`, `RememberIdentityProvider<'a>`, `CommonDomainCookie` | Private channel, message, or discovery state. [SOAP](../../src/soap.rs), [discovery](../../src/discovery.rs). |
| `MessageDelivery`, `SoapFault` | Public unit markers, rather than private-field structs. Annotation would prevent direct unit construction with no identified extensibility benefit. Keep their current marker contract. [Delivery marker](../../src/api/options.rs), [fault marker](../../src/api/paos/mod.rs). |

## Remaining judgment calls

The strongest additions are the algorithm and URI enums, supported binding and parser inventories, named signature and metadata trust profiles, and refusal reasons. `ContactType` is justified by its existing extension-aware design.

`ResponseSignaturePolicy` and `ArtifactRelease` could become extensible if new acceptance modes or reply categories are planned. Current code supplies no concrete need beyond their existing categories. `XmlLimits` and top-level configs have credible future field growth, but annotation would withdraw documented literal construction. The recommendation is to retain that contract. Choosing differently requires an explicit construction-policy change and migration examples, not an annotation applied for consistency.

The audit inspected public definitions, visibility, constructors, documentation, and client-style integration usage. Compilation and runtime verification belong to the accompanying code change.
