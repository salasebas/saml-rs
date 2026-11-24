# Handle SOAP artifact response size errors

If you issue large messages as artifacts, handle `SamlError::LimitExceeded`
from `IdentityProvider::issue_artifact`, `respond_sso_artifact`,
`respond_sso_refusal_artifact`, and `initiate_sso_artifact`. Issuance checks
whether the complete SOAP response fits within the default `XmlLimits`. It
counts any signatures already in the
message and reserves space for the `ArtifactResponse`, the SOAP envelope,
and the longest request ID the response can echo. A failed issuance stores
no artifact. Reduce the message size before you retry issuance.

If you keep outstanding artifacts in a shared store during the upgrade, a
previously stored message may make the SOAP response exceed the same limit.
`IdentityProvider::answer_artifact_resolve` returns `SamlError::LimitExceeded`
and keeps the entry outstanding until a successful resolution or expiry.
