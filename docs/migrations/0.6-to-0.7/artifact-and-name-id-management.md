# Update artifact resolution and name identifier management

[How to upgrade from 0.6 to 0.7](README.md)

## Handle artifact responses and services

If your IdP receives `SsoResponseBinding::Artifact`, answer with
`respond_sso_artifact` and `RespondSso::artifact(...)`. `receive_sso` now
accepts that request, while `respond_sso` returns `SamlError::Invalid`.
Publish a SOAP `ArtifactResolutionService` at the delivery index and answer
`ArtifactResolve` with `answer_artifact_resolve`. Use distinct endpoint indexes.
See [artifact response handling](../../conformance/web-browser-sso-artifact.md).

If you detected an artifact ACS through `SamlError::UndefinedBinding`,
compare `AcsEndpoint::binding` with `SsoResponseBinding::Artifact` instead.
`SsoResponseBinding::try_from(Binding::Artifact)` and
`AcsEndpoint::try_from_raw` now succeed. An explicit artifact ACS index now
starts artifact login through `StartSso`, while `respond_sso` returns
`SamlError::Invalid` for it. ECP and request and logout bindings still reject
HTTP-Artifact.

## Publish name identifier management endpoints

To enable name identifier management, publish the required SOAP or Redirect
endpoint through `manage_name_id_service`. IdPs support both bindings. SPs
support only Redirect. A missing endpoint returns `SamlError::MissingMetadata`.
See [name identifier management](../../conformance/name-id-management.md).
