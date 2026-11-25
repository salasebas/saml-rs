# Handle logout endpoint choice and status messages

This upgrade changes two Single Logout behaviors. No signature changes.

## Logout goes to a later `https` endpoint

If you run a service provider, `ServiceProvider::start_slo`, `respond_slo`, and
`respond_slo_refusal` on HTTP-Redirect, HTTP-POST, and HTTP-POST-SimpleSign,
and `start_async_slo` on HTTP-Redirect and HTTP-POST, now send to the identity
provider's first `SingleLogoutService` for the binding whose URL is `https`. A
request uses `Location`. A response uses `ResponseLocation`, or `Location` when
the endpoint has none. Before, these calls took the first endpoint for the binding
and returned `SamlError::ProtocolProfile` when it was `http`, even when a later
one was `https`.

`StartSlo::allow_http` and `RespondSlo::allow_http` still send to the first
endpoint. The identity provider's browser messages and SOAP requests from
either role still use the first endpoint. A SOAP response still returns on the
request's exchange.

You do not need to change code. If your identity provider's metadata lists an
`http` endpoint before an `https` one, the message now goes to the `https`
one. If you selected `allow_http` only to reach such a peer, you can remove it.
Before you remove it from `start_async_slo`, confirm that the `https` endpoint
also supports asynchronous logout.

## A logout status message needs visible text

`RespondSlo::status_message` with only spaces, tabs, carriage returns, and
line feeds now makes `respond_slo` and `respond_slo_refusal` on either role
return `SamlError::Invalid`. Before, the response carried that text. An empty
string now leaves `StatusMessage` out. Before, the response carried an empty
`StatusMessage`.

To upgrade, leave the status message unset when you have no text.
