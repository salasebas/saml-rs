# Handle NameID value errors in identity provider logout and management

An identity provider now checks the `NameId` it writes in a `LogoutRequest`
or a `ManageNameIDRequest` with the rules it already applied to SSO
responses. A service provider no longer checks the length of a persistent
`NameId` it sends in a `ManageNameIDRequest`. No code fails to compile.

## The identity provider refuses a NameID that Core §8.3 forbids

`IdentityProvider::start_slo`, `IdentityProvider::start_name_id_management`,
and `IdentityProvider::start_name_id_management_redirect` now return
`SamlError::Invalid` before they sign or encrypt the request when, with the
format the request writes:

- a persistent or transient value is longer than 256 characters
- an `entity` value is not an absolute URI reference of at most 1024
  characters with collapsed whitespace
- an `entity` `NameId` has `NameQualifier`, `SPNameQualifier`, or
  `SPProvidedID`

The format the request writes is the `NameId` format, or the first configured
NameID format when the `NameId` has none. In name identifier management, a
`NameIdChange::NewId` value follows the same length and `entity` value rules.

Before, `start_slo` checked only that the format was an absolute URI
reference, and name identifier management checked only the persistent length.
An SSO response with the same `NameId` was already refused, so a `NameId`
that `respond_sso` issued passes these checks.

If you build the `NameId` yourself, take it from the identifier the identity
provider issued. Remove any qualifier from an `entity` `NameId`.

## The service provider sends the NameID it received

`ServiceProvider::start_name_id_management_redirect` no longer refuses a
persistent `NameId` longer than 256 characters. `ServiceProvider::start_slo`
never checked the value. Both now send the identifier as the identity
provider issued it, because the request must name the principal as both
providers know it. You do not need to change code. If you matched that
`SamlError::Invalid` error, the request now succeeds instead.
