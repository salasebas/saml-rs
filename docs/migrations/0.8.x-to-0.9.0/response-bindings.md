# Answer logout and NameID Management requests on the correct channel

If your handler uses both SOAP and browser bindings, choose the response from
the channel that delivered the request. Mixing channels now returns
`SamlError::UnsupportedBinding`. The error's `binding` field identifies the
selected response binding. A SOAP logout reply to a browser request with
RelayState previously returned `SamlError::ProtocolProfile`.

## Single Logout

Pass `RespondSlo::soap()` to `respond_slo` when the request arrives over SOAP.
Return `response.soap_response()?` on that HTTP exchange. For requests that
arrive through a browser, use `RespondSlo::redirect()`, `RespondSlo::post()`, or
`RespondSlo::simple_sign()` as supported by the peer.

## NameID Management

For a SOAP request, call `IdentityProvider::respond_name_id_management` and
return its `SoapResponse` on the same HTTP exchange. For an HTTP-Redirect
request, call `respond_name_id_management_redirect` and redirect the browser to
the returned `Outbound::redirect_url()`.
