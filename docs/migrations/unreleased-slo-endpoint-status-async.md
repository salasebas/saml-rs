# Handle logout endpoint choice, status messages, and asynchronous markers

This upgrade changes three Single Logout behaviors. No signature changes.

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

## Asynchronous markers with schema hints

If you run an identity provider, `IdentityProvider::receive_slo_with_async`
on HTTP-Redirect and HTTP-POST now returns `IdpLogoutAction::CompleteLocally`
when the `aslo:Asynchronous` marker carries `xsi:schemaLocation`,
`xsi:noNamespaceSchemaLocation`, or an `xsi:type` of `AsynchronousType` with
the marker's own prefix, such as `xsi:type="aslo:AsynchronousType"` on
`aslo:Asynchronous`. Before, it returned `IdpLogoutAction::Respond` for such a
request. A marker with any other attribute still returns
`IdpLogoutAction::Respond`. That includes `xsi:nil`, and an `xsi:type` that
uses another prefix or names another type.

You do not need to change code. Such a request now finishes at the identity
provider, which presents the result to the user and sends no
`LogoutResponse`. If such a request has a newer SAML version, the call now
returns `SamlError::ProtocolProfile`, as for any asynchronous request, instead
of `SamlError::LogoutRequestRefused`.
