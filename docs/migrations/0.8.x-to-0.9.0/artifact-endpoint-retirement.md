# Remove artifacts of a retired resolution endpoint

`IdentityProvider::answer_artifact_resolve` no longer checks that the
artifact's `EndpointIndex` still names a SOAP `ArtifactResolutionService` in
the identity provider metadata. An outstanding artifact now resolves after
you remove or renumber its endpoint, if the request reaches a published SOAP
`ArtifactResolutionService` and every other check passes. Before, the answer
withheld the message with `ArtifactWithheld::NotOutstanding`.

Issuance still requires a SOAP `ArtifactResolutionService` at the index.

If you retire an endpoint and want its outstanding artifacts to stop
resolving, remove them from the store, for example with
`IssuedArtifacts::remove`, or let them expire.
