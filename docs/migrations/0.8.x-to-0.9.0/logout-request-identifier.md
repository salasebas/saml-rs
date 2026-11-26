# Send one principal identifier per logout request

[How to upgrade from 0.8 to 0.9](README.md)

The built-in check in `receive_slo` for both roles returns
`SamlError::ProtocolProfile` for a `LogoutRequest` with zero or several direct
SAML principal identifiers.
If the peer sends such a request, update it to send exactly one `saml:BaseID`,
`saml:NameID`, or `saml:EncryptedID` as a direct child of `LogoutRequest`.

Keep the existing call to `receive_slo`. A request with a single `BaseID` or
an `EncryptedID` the recipient cannot decrypt still produces a received
request whose `name_id()` returns `None`. You can answer it with `respond_slo`.
