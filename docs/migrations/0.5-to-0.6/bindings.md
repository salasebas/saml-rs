# Update HTTP-Redirect signatures and unsolicited RelayState

[How to upgrade from 0.5 to 0.6](README.md)

## Remove a protocol signature before HTTP-Redirect

This breaks a typed HTTP-Redirect whose protocol element still has a direct
child `ds:Signature`.

Who must change: `start_sso`, `start_slo`, and `respond_slo` on that binding,
including a custom template that embeds the signature.

An unsigned redirect returns `SamlError::ProtocolProfile`. Remove the
protocol signature and attach the detached query signature.

A signed redirect removes that signature before raw DEFLATE. The detached
signature covers `SAMLRequest` or `SAMLResponse`, then `RelayState` when it
is present, then `SigAlg`. A signature nested on an assertion stays in the
XML. Verify the query signature. The classification is in
[Web Browser SSO generation](../../conformance/web-browser-sso-generation.md)
and [Single Logout](../../conformance/single-logout.md).

## Shorten RelayState on an unsolicited response

This breaks an unsolicited login response whose `RelayState` is longer than
80 bytes.

Who must change: the caller of `accept_unsolicited_sso` or
`accept_unsolicited_sso_with_outstanding_logout`. The call returns
`SamlError::Invalid`. Shorten `RelayState` to 80 bytes, or omit it.

`finish_sso`, `receive_sso`, and typed Single Logout already enforced this
limit. The classification is in
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md).
