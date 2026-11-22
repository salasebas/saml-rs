# Handle SSO error responses that omit `InResponseTo`

When an identity provider cannot determine the request ID, SAML Core §3.2.2
requires it to omit `InResponseTo`. An otherwise valid error response that
omits it now returns `SamlError::StatusNotSuccess` with the reported status
codes. Previously, it returned `SamlError::InResponseToMismatch` with
`actual: None`.

This applies to `ServiceProvider::finish_sso`,
`ServiceProvider::finish_paos_sso`, and their `_with_outstanding_logout`
variants. If an error handler relied on `InResponseToMismatch` for this
case, handle `StatusNotSuccess` as a failed login and read its `status` field
for diagnostics. A present request ID still has to match the pending request.
When the ID is absent, `StatusNotSuccess` reports the failure without
establishing which request the response answered.
