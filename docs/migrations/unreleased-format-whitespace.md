# Read received formats without surrounding whitespace

saml-rs now reads a received `NameID` `Format` and an `Attribute`
`NameFormat` after XML whitespace collapse. Collapse removes leading and
trailing whitespace and turns each inner run of whitespace into one space.
The change applies to `SsoSession::name_id` and `SsoSession::attributes` on
the service provider, and to `LogoutRequest::name_id` on both providers.

These values change only when the URI from the peer has leading or trailing
XML whitespace, or inner whitespace other than one space:

- A standard URI is its named variant. For example,
  `" urn:oasis:names:tc:SAML:2.0:nameid-format:persistent "` is
  `NameIdFormat::Persistent`, and an attribute `NameFormat` of
  `" urn:oasis:names:tc:SAML:2.0:attrname-format:uri "` is
  `AttributeNameFormat::Uri`. Before, each was `Custom` with the padded text.
- Another URI is `Custom` with the collapsed text.
- Attributes with the same `Name` merge when their `NameFormat` values differ
  only in whitespace.
- `SsoSession::subject_id` and `SsoSession::pairwise_id` read an attribute
  with a padded `uri` or `unspecified` `NameFormat`. An identifier that the
  session missed before can now be returned, or reported as an error when it
  breaks the profile.
- A response whose assertions differ only in whitespace around the `NameID`
  `Format` is accepted. Before, `finish_sso` and `accept_unsolicited_sso`
  returned `SamlError::PrincipalMismatch`.

If you match `NameIdFormat::Custom` or `AttributeNameFormat::Custom` against
padded text, or store the padded spelling, match the named variant or the
collapsed URI instead. Attribute `Name` values are compared exactly, as
before.
