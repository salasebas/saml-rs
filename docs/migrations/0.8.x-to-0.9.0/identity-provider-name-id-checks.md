# Handle NameID value errors from the identity provider

An identity provider now checks the `NameId` it writes in a `LogoutRequest`
or a `ManageNameIDRequest` with the rules it already applied to SSO
responses, and refuses a blank NameID string in all three messages. A service
provider no longer checks the length of a persistent `NameId` it sends in a
`ManageNameIDRequest`. No code fails to compile.

## The identity provider refuses a NameID that Core §8.3 forbids

`IdentityProvider::start_slo`, `IdentityProvider::start_name_id_management`,
and `IdentityProvider::start_name_id_management_redirect` now return
`SamlError::Invalid` before they sign or encrypt the request when, with the
format the request writes:

- a persistent value is longer than 256 characters, and for `start_slo` also
  a transient value (name identifier management refuses every transient
  identifier, as before)
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

## The identity provider refuses a blank NameID string

`IdentityProvider::respond_sso`, `initiate_sso`, `respond_sso_artifact`,
`initiate_sso_artifact`, `start_slo`, `start_name_id_management`, and
`start_name_id_management_redirect` now return `SamlError::Invalid` when the
`NameId` value, its `NameQualifier`, `SPNameQualifier`, or `SPProvidedID`, or
a `NameIdChange::NewId` value is empty or made only of XML whitespace: space,
tab, carriage return, and line feed. Core §1.3.1 requires every such string to
contain another character. A value such as a no-break space is still written.

Before, these methods wrote the empty or whitespace-only string. A peer that
follows Core §1.3.1 could not use it to identify the principal.

If a user record can hold an empty identifier, check it before you call these
methods. For a new SSO relationship, generate an identifier, such as
`NameId::generate_persistent`, and store it for later responses. For logout
or name identifier management, pass the identifier already established with
the service provider: a new value would not name the principal's session or
alias. Omit a qualifier instead of setting it to an empty string.

## The service provider sends the NameID it received

`ServiceProvider::start_name_id_management_redirect` no longer refuses a
persistent `NameId` longer than 256 characters. `ServiceProvider::start_slo`
never checked the value. Both now send the identifier as the identity
provider issued it, because the request must name the principal as both
providers know it. You do not need to change code. If you matched that
`SamlError::Invalid` error, the request now succeeds instead.

An `entity` `NameId` must still omit `NameQualifier`, `SPNameQualifier`, and
`SPProvidedID`. The service provider forwards a received one unchanged so
that the session stays manageable, but do not add qualifiers to an `entity`
`NameId` you build yourself.
