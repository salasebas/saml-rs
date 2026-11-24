# Handle identity provider response value errors

If you run an identity provider, `IdentityProvider::respond_sso`,
`initiate_sso`, `respond_sso_refusal`, and their artifact variants now
return `SamlError::Invalid` for values that a SAML response cannot carry.
Before, the identity provider wrote them and the service provider received a
response that breaks SAML Core.

The response is rejected in these cases:

- The `AuthnContextReference` in `SsoAssertion::authn_context` is not an
  absolute URI reference. A reference you copied from
  `RequestedAuthnContext::references` can be relative, because the identity
  provider reads a received request as sent.
- `SsoOutcome::Failure` carries a `Status` whose subordinate code is not an
  absolute URI reference. A status you read from a received response, such as
  `SamlError::StatusNotSuccess` in a proxy, can have one.
- `RespondSso::status_message` has only whitespace.
- The effective NameID format is `entity`, and the value is not an absolute
  URI reference of at most 1024 characters with collapsed whitespace, or the
  `NameId` has `NameQualifier`, `SPNameQualifier`, or `SPProvidedID`. The
  effective format is the first configured NameID format when the `NameId`
  has none.
- The received `AuthnRequest` `ID` is not an `xs:NCName`, so it cannot be
  written as `InResponseTo`. `receive_sso` still accepts such a request.

To upgrade, pass an absolute URI, such as a constant from
`saml_rs::constants::authn_context_class_ref`, or build the value with
`AuthnContextReference::class` or `SubordinateStatusCode::try_new` and handle
their errors. Leave the status message unset when you have no text. Issue an
`entity` identifier without qualifiers:

```rust
use saml_rs::{NameId, NameIdFormat};

let partner = NameId::new("https://partner.example.org/metadata")
    .with_format(NameIdFormat::Entity);
```

A request whose `ID` is not an `xs:NCName` cannot get a response.
