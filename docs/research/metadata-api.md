# Metadata API cleanup research

This note evaluates the planned metadata API cleanup. It uses the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/), the [SAML Metadata specification](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf), and [OASIS Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html). The repository's [standards conformance policy](../standards-conformance.md) and [coding standards](../../CODING_STANDARDS.md) govern how to apply those sources here.

## API guidance supports the proposed shape

The Rust API Guidelines recommend inherent static constructors and commonly suffix secondary constructors with `_with_foo` ([C-CTOR](https://rust-lang.github.io/api-guidelines/predictability.html#c-ctor)). Keep `from_metadata_xml` and `from_metadata_xml_with_policy`. Requiring `MetadataTrustPolicy` on both keeps the trust decision explicit. C-CTOR supports the naming pattern, not a security requirement.

Rust getters normally omit `get_` ([C-GETTER](https://rust-lang.github.io/api-guidelines/naming.html#c-getter)). Typed accessors such as `single_sign_on_location` fit that convention. Arguments should use deliberate types instead of ambiguous `bool` or `Option` values ([C-CUSTOM-TYPE](https://rust-lang.github.io/api-guidelines/type-safety.html#c-custom-type)). `MetadataTrustPolicy` therefore communicates the caller's trust choice better than a boolean or implicit default. Neither guideline establishes SAML wire rules.

## Metadata preserves more than typed flows need

Metadata §2.2.2 defines `Binding` and `Location` as required `anyURI` attributes and says that the allowed `Location` syntax depends on the binding. Metadata commonly permits repeated endpoint elements so consumers can choose among bindings and locations. Section 2.2.3 defines indexed endpoints, including a unique `index` within a collection of like endpoints and default selection rules. Errata 05 E37 clarifies default selection within a sequence whose endpoints share an element name and namespace. Keep endpoint order and grouping when selecting defaults; do not merge unlike endpoint elements.

Section 2.4.2 defines zero or more `ArtifactResolutionService` elements as indexed endpoints for the Artifact Resolution profile, and requires omission of `ResponseLocation`. It also defines zero or more `NameIDFormat` values as `anyURI`. A typed `NameIdFormat` should therefore map known values and retain other URIs as `Custom(String)`. Return the values in document order and preserve repeats. This avoids loss in the API; the standard does not assign ordering or uniqueness semantics to `NameIDFormat` values.

The Artifact Resolution profile uses the SAML SOAP binding, and the binding requires SAML over SOAP over HTTP ([Profiles §5.2](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf), [Bindings §3.2.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)). Publishing an artifact-resolution endpoint with SOAP binding and an HTTP(S) `EndpointUrl` fits that use. Treat `HTTP(S)` as the publisher API's typed constraint where it goes beyond the binding's transport rule, not as a general rule for metadata `Location` values. On import, retain raw `ArtifactResolutionService` binding and location values. A flow can select SOAP endpoints without rejecting unfamiliar metadata during import.

## Keep certificate and trust choices explicit

Errata 05 E62 clarifies that `KeyDescriptor use="signing"` covers signing and TLS keys in the enclosing role, while `use="encryption"` denotes key wrapping. E68 says multiple descriptors with the same `use` mean any included key may be used and recommends that relying parties allow any of them. E69 says `KeyInfo` is generic and extensible. The specification makes no assumptions about certificates included by value or reference, or about their validity and revocation checks. These errata support removing a getter that returns only the first certificate. Keep access to all declared certificates; do not imply that a metadata certificate is trusted just because it is present.

Metadata §4.3.3 describes several trust mechanisms. It does not require every metadata document to carry a signature. A required `MetadataTrustPolicy` is therefore an explicit library and application policy, not a universal OASIS requirement. Keep `AllowUnsigned` as a visible choice if compatibility requires it; do not silently default callers to it or to pinned trust. The selected policy determines whether a signature is required and which keys are trusted.

## Keep import permissive and validate selected values on access

The SAML type permits `anyURI`; it does not require every endpoint to be an HTTP(S) URL. Typed SP and IdP descriptor accessors can return an `EndpointUrl` and report an error when the selected endpoint is not absolute HTTP(S), while metadata import keeps unknown bindings and URI values. That HTTP(S) filter is a library API policy for the supported flow. It must not become an import-time protocol rejection. Read organization, contact, and `NameIDFormat` values without narrowing the imported XML. Report accessor-specific interpretation errors only when callers request those values. The only planned behavior change is requiring the raw artifact publisher to receive a typed HTTP(S) URL. It does not change protocol acceptance on import.

Hiding the extractor argument and keeping `metadata::{sp,idp,generate}` private behind deliberate reexports are API encapsulation choices, not SAML requirements. Removing filesystem export is also an API cleanup, not a conformance change. The change removes the extractor arguments, raw descriptor accessors, singular certificate getter, filesystem writer, and duplicate submodule paths. These are library API changes, not newly discovered SAML protocol defects.
## Explicit raw composition and final names

The raw role readers borrow their shared fields through `as_metadata()`.
They no longer use `Deref` as inheritance. This follows
[C-DEREF](https://rust-lang.github.io/api-guidelines/predictability.html#c-deref)
and leaves the role-specific reader responsible for selecting its shared view.
No additional view type is needed. The typed descriptor still offers direct,
role-specific endpoint accessors. Methods returning one endpoint location use
`_location`, while the configuration's endpoint collections retain `_service`.

Raw generator records are `SpMetadataInput` and `IdpMetadataInput`. The names
separate those passive inputs from the typed config readers. List getters use
`name_id_formats()` and the builder's repeatable setter stays singular.

`metadata_signature_verified()` names the import-time check, and
`signed_metadata_xml()` names evidence that may cover an `EntitiesDescriptor`.
Neither method claims that metadata is unexpired or that the default algorithm
policy was selected.
