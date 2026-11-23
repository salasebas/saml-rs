# Send SAML responses for refused requests

## Single Logout

If your SP or IdP handler maps every `receive_slo` error to a local error
page or SOAP fault, add an arm for `SamlError::LogoutRequestRefused`.
Pass its `refusal` to `respond_slo_refusal` with the same peer descriptor
and `RespondSlo` options you use for `respond_slo`. Send the resulting
`Outbound<LogoutResponse>` on the selected binding.

The response echoes the request's RelayState on browser bindings. It uses
the built-in XML writer so it can include the required subordinate status
even when you configured a custom logout-response template.

## Name identifier management

If your SOAP or HTTP-Redirect handler catches
`TimeWindowInvalid` for `ManageNameIdRequestIssueInstant`, handle
`NameIdManagementReceipt::Refused` instead. The reason is
`NameIdManagementRefusal::RequestAgeOutsideWindow`. Send
`refused.response()` as you would for an undecryptable identifier.

## PAOS

When `receive_paos_sso` returns `SamlError::PaosRequestRefused`, return
the error's `response` as HTTP 200. The `source` holds the age or replay
error for logging. Use `PaosHttpResponse::soap_fault()` for SOAP errors.
An issuer or signature failure lacks a verified requester. Discard an
`AuthnRequest` addressed to a different endpoint.

## Response versions

Single Logout, NameID Management, and Artifact Resolution use a 2.0
`VersionMismatch` for an unsupported version such as 2.1. For a newer
major version such as 3.0, the response includes `RequestVersionTooHigh`.
A declared version below 2.0 returns `SamlError::ProtocolProfile`
because a 2.0 responder cannot emit a response for that version.
