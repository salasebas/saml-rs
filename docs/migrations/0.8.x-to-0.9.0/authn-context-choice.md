# Handle responses with an invalid `AuthnContext`

The service provider now refuses a response when an `AuthnStatement` of the
selected assertion has an `AuthnContext` that its schema type does not allow.
`finish_sso`, `accept_unsolicited_sso`, and
`accept_unsolicited_sso_with_resolver` return `SamlError::ProtocolProfile`
for the forms below. For HTTP-Artifact, artifact resolution still returns the
resolved response, and `finish_sso` with `Inbound::artifact` returns the
error:

- an empty `AuthnContext`,
- two `AuthnContextClassRef` elements,
- an `AuthnContextDecl` together with an `AuthnContextDeclRef`, or two of
  either.

Before, the session reported an empty context, only the first class
reference, or both declaration forms.

A class reference, a declaration, a declaration reference, or a class
reference followed by one declaration form is accepted as before. No code
change is needed unless an identity provider sends one of the refused forms.
Ask that identity provider to send a valid `AuthnContext`.
