# Handle strings that hold only non-XML whitespace

saml-rs now decides that a SAML string is empty only when it contains
nothing but XML whitespace: space, tab, carriage return, and line feed. Core
§1.3.1 defines whitespace this way. Before, saml-rs used the Unicode
whitespace set, which also includes characters such as U+00A0 NO-BREAK SPACE.

- `EntityId::try_new`, `MessageId::try_new`, `AssertionId::try_new`,
  `SessionIndex::try_new`, and `SamlInstant::try_new` now accept a value such
  as `"\u{a0}"`. A received `SessionIndex`, message `ID`, or assertion `ID`
  with that value no longer fails as empty.
- `receive_name_id_management` and `receive_name_id_management_redirect`
  return `SamlError::ProtocolProfile` for a `Terminate` element that contains
  such a character. Before, the request was returned as a termination.
- `SsoSession::logout_subject` now returns a subject for a `NameID` such as
  `"\u{a0}"`. It still returns `None` for an empty value or one made only of
  XML whitespace.
- `OutstandingLogout::try_new` now records every `NameID` value, an empty one
  included. A later assertion with the same `NameID` fails
  `finish_sso_with_outstanding_logout` and
  `accept_unsolicited_sso_with_outstanding_logout`.

If you relied on these calls to reject such a value, check the value
yourself before you call them.
