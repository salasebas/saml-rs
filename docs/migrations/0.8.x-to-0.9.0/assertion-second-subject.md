# Handle assertions with a second `Subject`

The service provider now refuses a response when the selected assertion has
two `Subject` elements, also when only one of them holds a `NameID`.
`finish_sso`, `accept_unsolicited_sso`,
`accept_unsolicited_sso_with_resolver`, and the two
`_with_outstanding_logout` variants return `SamlError::Invalid`. For
HTTP-Artifact, artifact resolution still returns the resolved response, and
`finish_sso` with `Inbound::artifact` returns the error.

Before, the session was created with the `NameID` of the `Subject` that held
one.

A second `Issuer` in the selected assertion is refused as before, with
`SamlError::IssuerMismatch`. When `accept_unsolicited_sso_with_resolver`
identifies the identity provider by the assertion issuers, because an
unsigned response omits its own `Issuer`, a second `Issuer` in any assertion
returns `SamlError::IdpResolution`. Otherwise another assertion of the
response may still repeat its `Issuer` or its `Subject`: the service provider
compares only its first `Issuer`, and the session reads no value from it.

No code change is needed unless an identity provider sends such an
assertion. Ask that identity provider to send one `Subject`.
