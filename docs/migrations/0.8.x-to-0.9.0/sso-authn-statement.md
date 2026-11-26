# Send an `AuthnStatement` in every successful SSO response

This change affects service providers whose identity provider sends a
successful SSO `Response` without an `AuthnStatement` in any bearer assertion,
for example a response that carries only an `AttributeStatement`.

`ServiceProvider::finish_sso`, the unsolicited SSO methods, and their
outstanding-logout variants now reject such a response with
`SamlError::ProtocolProfile`. This includes a response delivered as an
HTTP-Artifact. In 0.8, the session used the first bearer assertion,
`SsoSession::authn_sessions` returned an empty slice, and
`SsoSession::authn_session` returned an empty `AuthnSession`. Error responses
carry no assertion and are unchanged.

Profiles §4.1.4.2 requires the identity provider to send at least one
`AuthnStatement` in the bearer assertions of a successful response. If a peer
omits it, configure that identity provider to report the authentication. An
accepted `SsoSession` now always has at least one `AuthnStatement`.
