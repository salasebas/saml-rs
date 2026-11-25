# Read requested formats without surrounding whitespace

saml-rs now reads every received `NameID` `Format` and `NameIDPolicy`
`Format` after XML whitespace collapse. Collapse removes leading and trailing
whitespace and turns each inner run of whitespace into one space. The change
reaches these accessors:

- `RequestedSubject::name_id` and `NameIdPolicy::format`, which
  `IdentityProvider::receive_sso` returns.
- `ManageNameIdRequest::name_id`, which `receive_name_id_management` on the
  identity provider and `receive_name_id_management_redirect` on both
  providers return.

These values change only when the URI from the peer has leading or trailing
XML whitespace, or inner whitespace other than one space:

- A standard URI is its named variant. For example, a `NameIDPolicy` `Format`
  of `" urn:oasis:names:tc:SAML:2.0:nameid-format:persistent "` is
  `NameIdFormat::Persistent`. Before, it was `NameIdFormat::Custom` with the
  padded text.
- Another URI, including the `encrypted` `NameIDPolicy` format, is
  `NameIdFormat::Custom` with the collapsed text.

`respond_sso` already compared these formats after collapse, so the
identifiers it accepts and refuses do not change.

If you match `NameIdFormat::Custom` against padded text from these accessors,
or store the padded spelling, match the named variant or the collapsed URI
instead.
