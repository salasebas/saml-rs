# Look up artifact resolution endpoints by role

`IdpMetadata::artifact_resolution_services` no longer fails when two SAML 2.0
`IDPSSODescriptor` elements of one entity publish the same `index`. Metadata
§2.2.3 requires an `index` to be unique only among the
`ArtifactResolutionService` elements of one role descriptor. The method still returns `SamlError::Invalid` when two endpoints of one
`IDPSSODescriptor` share an `index`.

The returned list holds the endpoints of every selected `IDPSSODescriptor`, so
it can repeat an `index`. If you search that list for an artifact's
`EndpointIndex`, call `IdpMetadata::artifact_resolution_service(index)`
instead:

```rust
let endpoint = metadata.artifact_resolution_service(artifact.endpoint_index())?;
```

The method returns `Ok(None)` when no selected role publishes the index. It
returns `SamlError::Invalid` when more than one selected role publishes it.
`ServiceProvider::resolve_artifact`, `resolve_artifact_with_signed_request`,
and `IdentityProvider::issue_artifact` use the same lookup. An entity whose
roles repeat only an unrelated index now resolves its artifacts.
