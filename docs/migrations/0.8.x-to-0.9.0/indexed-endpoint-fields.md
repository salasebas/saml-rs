# Handle peer metadata with a malformed indexed endpoint

This change affects code that imports peer metadata with `IdpDescriptor`,
`SpDescriptor`, `metadata::IdpMetadata`, or `metadata::SpMetadata`. No code
fails to compile.

The import now returns `SamlError::Invalid` when an endpoint of the role it
reads has one of the faults below. An SP import checks each
`AssertionConsumerService` of the entity's SAML 2.0 `SPSSODescriptor`
elements, and an IdP import checks each `ArtifactResolutionService` of its
SAML 2.0 `IDPSSODescriptor` elements.

- no `Binding`
- no `Location`, or `Location=""`
- no `index`, or an `index` that is not an integer, such as `index=""` or
  `index="one"`
- an `isDefault` that is not `true`, `false`, `1`, or `0`, such as
  `isDefault="yes"`

In 0.8, the import accepted such metadata:

- An assertion consumer service with no readable `index` had no index.
- One whose `isDefault` was unreadable counted as unmarked, so it could
  become the default.
- One with no `Binding` or no `Location` was skipped in a lookup for a
  binding. When it was the default across bindings, the identity provider's
  response failed.
- One with `Location=""` was kept.
- `IdpMetadata::artifact_resolution_services` failed for an artifact
  resolution service whose `Binding`, `Location`, or `index` was missing or
  empty after whitespace collapse, or whose `index` was not a 16-bit integer.
  `ServiceProvider::resolve_artifact` then failed for every artifact of that
  identity provider. The accessor did not read `isDefault`.

The import accepts an endpoint with an empty `Binding`, a `Binding` or
`Location` that holds only whitespace, or an integer `index` outside 0 to
65535. The artifact resolution accessors return `SamlError::Invalid` for an
artifact resolution service with such an `index`. They return one with such a
`Binding` or `Location`, collapsed to an empty value, and
`ServiceProvider::resolve_artifact` refuses only an artifact whose index
names it. Code that read `binding()` or `location()` from
`artifact_resolution_services` can now see an empty string.

If a peer's metadata no longer imports, ask the peer to correct the endpoint.
