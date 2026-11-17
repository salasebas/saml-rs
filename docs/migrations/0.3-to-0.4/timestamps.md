# Check timestamp requirements

[How to upgrade from 0.3 to 0.4](README.md)

## Shared timestamp rule

Apply this rule wherever the upgrade requires `IssueInstant` or
`NotOnOrAfter`:

- The attribute is unqualified. `saml:IssueInstant` and `samlp:IssueInstant`
  do not count.
- The value is a UTC `xs:dateTime` ending in `Z`. Fractional seconds are
  accepted. `+00:00` is not a substitute for `Z`.
- A missing, qualified, malformed, or non-UTC value returns
  `SamlError::ProtocolProfile`.
- An older, well-formed UTC value stays accepted. These checks add no maximum
  age, freshness window, or new replay default.

Whitespace around the value is normalised before a typed accessor returns it.

## If your tests reject inbound leap seconds

Inbound parsers accept XML Schema second `60` on `AuthnRequest`, SSO
`Response` and `Assertion`, `LogoutRequest@IssueInstant`, and
`LogoutResponse`. The value is kept as sent. Standard generators still emit
seconds `00` through `59`.

A leap second in `LogoutRequest@NotOnOrAfter` can still fail deadline
comparison as `TimeWindowField::LogoutRequestNotOnOrAfter`, because that
attribute is compared with the runtime clock. That is deadline handling, not
a general lexical rejection. Enforce any stricter local rule in application
code after parsing.
