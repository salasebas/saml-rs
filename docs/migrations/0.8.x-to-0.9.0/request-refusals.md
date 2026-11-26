# Send SAML responses for refused requests

[How to upgrade from 0.8 to 0.9](README.md)

## Single Logout

When `receive_slo` authenticates a request with a newer version, it can now
return `SamlError::LogoutRequestRefused` in place of a protocol profile
error. If your SP or IdP maps every receive error to a local page or SOAP
fault, add an arm for that variant.
Pass its `refusal` to `respond_slo_refusal` with the same peer descriptor
and `RespondSlo` options you use for `respond_slo`. Send the resulting
`Outbound<LogoutResponse>` on the selected binding.

The response echoes the request's RelayState on browser bindings and includes
the subordinate status when required by the request version.

## Name identifier management

If your handler catches `TimeWindowInvalid` for
`ManageNameIdRequestIssueInstant`, handle a refused receipt. Match
`NameIdManagementReceipt::Refused` over SOAP or
`NameIdManagementRedirectReceipt::Refused` over HTTP-Redirect. Read
`NameIdManagementRefusal::RequestAgeOutsideWindow` from `refused.reason()`
and send `refused.response()` as you would for an undecryptable identifier.

## Response versions

Single Logout, NameID Management, and Artifact Resolution use a 2.0
`VersionMismatch` for an unsupported version such as 2.1. For a newer
major version such as 3.0, the response includes `RequestVersionTooHigh`.
A declared version below 2.0 returns `SamlError::ProtocolProfile`
because a 2.0 responder cannot emit a response for that version.
