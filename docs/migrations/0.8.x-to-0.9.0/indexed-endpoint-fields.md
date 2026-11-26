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

In 0.8, the import accepted such metadata. An assertion consumer service with
no readable `index` had no index, one whose `isDefault` was unreadable counted
as unmarked and could become the default, and one with no `Location` was
skipped. A malformed artifact resolution service failed only
`IdpMetadata::artifact_resolution_services` and
`IdpMetadata::artifact_resolution_service`.

These cases import as in 0.8: an empty `Binding`, a `Binding` or `Location`
that holds only whitespace, and an integer `index` outside 0 to 65535. The
artifact resolution accessors still refuse such an endpoint.

If a peer's metadata no longer imports, ask the peer to correct the endpoint.
