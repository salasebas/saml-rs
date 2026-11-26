# Handle blank NameID strings in service provider requests

A service provider now refuses to send a blank NameID string in a
`LogoutRequest` or a `ManageNameIDRequest`. No code fails to compile.

A string is blank when it is empty or made only of XML whitespace: space, tab,
carriage return, and line feed. Core §1.3.1 requires every SAML string in a
message to contain another character. A value such as a no-break space is
still sent.

## The service provider refuses a blank string in its requests

`ServiceProvider::start_slo` now returns `SamlError::Invalid` when the
`LogoutSubject` `NameId` value, `NameQualifier`, `SPNameQualifier`, or
`SPProvidedID` is blank. `ServiceProvider::start_name_id_management_redirect`
returns the same error for a blank string in its `NameId`, and for a blank
`NameIdChange::NewId` value. The new `ServiceProvider::start_async_slo` applies
the same check.

In 0.8, `start_slo` and `start_name_id_management_redirect` wrote the blank
string. The identity provider methods refuse the same strings in this
upgrade, as
[Handle NameID value errors from the identity provider](identity-provider-name-id-checks.md#the-identity-provider-refuses-a-blank-nameid-string)
describes.

## Upgrade your logout and name identifier management code

`SsoSession::logout_subject` still returns `None` for a blank `NameID` value.
It keeps every qualifier as the identity provider issued it, a blank
one included, so the subject still matches the identity provider's own
`LogoutRequest` through `Received::<LogoutRequest>::matches_sp_session`.

To upgrade:

- Keep storing the subject from `SsoSession::logout_subject` at sign-in. The
  session still needs it to match a logout from the identity provider.
- When a qualifier in that subject is blank, `start_slo` refuses it. End the
  local session without Single Logout then: no request that repeats the
  identifier can carry that string.
- If you store the identifier and build the `NameId` yourself, keep each
  qualifier as the identity provider issued it. Do not set an empty string
  for a qualifier the identity provider omitted.
- Before you send `NameIdChange::NewId`, check that the new alias holds a
  character other than XML whitespace.
