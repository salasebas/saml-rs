# Handle assertions with child elements inside text values

The service provider now refuses a response when one of these elements of the
selected assertion holds a child element:

- the assertion `Issuer`,
- the `NameID` of its `Subject`,
- an `Audience` of its `AudienceRestriction`,
- an `AuthnContextClassRef`, `AuthnContextDeclRef`, or
  `AuthenticatingAuthority` of its `AuthnStatement`.

`finish_sso`, `accept_unsolicited_sso`,
`accept_unsolicited_sso_with_resolver`, and the two
`_with_outstanding_logout` variants return `SamlError::ProtocolProfile`. For
HTTP-Artifact, artifact resolution still returns the resolved response, and
`finish_sso` with `Inbound::artifact` returns the error. Two checks that run
earlier can refuse the same response with their own error:

- when the text around the child element in the assertion `Issuer` is not
  the identity provider's entity ID, the issuer comparison returns
  `SamlError::IssuerMismatch`;
- when `accept_unsolicited_sso_with_resolver` uses an assertion `Issuer` to
  identify the identity provider, a child element in that `Issuer` produces
  `SamlError::IdpResolution`.

Before, the service provider read the text around the child element and
ignored the child, so `<saml:NameID>alice@example.com<ext:Note/></saml:NameID>`
gave the `NameID` `alice@example.com`.

A comment inside such an element is still ignored. `finish_sso` and
`accept_unsolicited_sso` still compare the `Issuer` of the `Response` and of
another assertion as the text around a child element, and the session reads
no value from another assertion.

No code change is needed unless an identity provider sends such markup. Ask
that identity provider to send these values as text.
