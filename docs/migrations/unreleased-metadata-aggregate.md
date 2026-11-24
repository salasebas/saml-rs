# Import peers from a federation aggregate

If you currently extract individual entities from a federation document, pass
the complete document to `MetadataAggregate::from_xml`. Supply limits sized for
the feed and pin the federation publisher's certificate with
`MetadataTrustPolicy::RequireSignature`. Reuse the aggregate to import IdP and
SP descriptors by entity ID. This keeps the enclosing groups' metadata
attributes and validity bounds and verifies the root signature once.

Handle `SamlError::MetadataEntityNotFound { .. }` when the requested ID is absent
and `SamlError::DuplicateMetadataEntity { .. }` when several members publish it.
If a lookup is ambiguous, obtain corrected metadata from the publisher before
retrying.

Applications that import a single entity can continue using
`IdpDescriptor::from_metadata_xml` or `SpDescriptor::from_metadata_xml`.
