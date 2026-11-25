# Expect an answer for an empty artifact

`IdentityProvider::answer_artifact_resolve` now answers an `ArtifactResolve`
whose `Artifact` element is empty or holds only whitespace. The answer has
status `Success` without the message, and `AnsweredArtifact::release` returns
`ArtifactRelease::Withheld(ArtifactWithheld::NotOutstanding)`, as for any
artifact that is not outstanding. Before, the call returned
`SamlError::ProtocolProfile`.

A request without an `Artifact` element, or with two, still returns
`SamlError::ProtocolProfile`. If your handler sent a SOAP fault for an empty
artifact, it now sends the `ArtifactResponse` instead. No code change is
needed.
