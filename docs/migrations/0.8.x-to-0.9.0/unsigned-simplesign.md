# Handle unsigned HTTP-POST-SimpleSign messages

These changes affect service providers that receive SSO responses or logout
messages over HTTP-POST-SimpleSign, and applications that match the error for
a SimpleSign message without a `SigAlg` field.

A SimpleSign message without `Signature` is unsigned, whether or not it has a
`SigAlg` field. `SigAlg` is now needed only to verify a present `Signature`.
In 0.8, a SimpleSign SSO `Response` or logout message without `SigAlg`
returned `SamlError::MissingSigAlg` before any other check.
`IdentityProvider::receive_sso` is unchanged.

- `ServiceProvider::finish_sso` and the unsolicited SSO methods now report the
  status of an unsigned error `Response` with neither `Signature` nor `SigAlg`
  as `SamlError::StatusNotSuccess`, as they already did for an unsigned error
  that kept its `SigAlg`.
- A successful SimpleSign `Response` and a SimpleSign `LogoutRequest` or
  `LogoutResponse` with neither field now return `SamlError::SignatureMissing`.
  They are still rejected.
- A message with `Signature` and no `SigAlg` now returns
  `SamlError::MissingBindingParameter { name: "SigAlg" }`, as
  [Fix compile errors](compile-errors.md#16-match-the-samlerror-variant-the-crate-returns)
  describes.

If your application matched `SamlError::MissingSigAlg` to detect an unsigned
SimpleSign message, match `SamlError::SignatureMissing` instead, and handle
`StatusNotSuccess` for an unsigned SSO error response.
