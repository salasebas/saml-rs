# Handle requests whose `ID` cannot be written as `InResponseTo`

If you answer artifact resolution or name identifier management requests, a
request whose `ID` is not an `xs:NCName`, such as `1bad:id` or a UUID that
starts with a digit, no longer gets that `ID` back as `InResponseTo`.
`StatusResponseType` declares `InResponseTo` as an `xs:NCName`, but 0.8
copied the `ID` into the response anyway. `ID` values surrounded by XML
whitespace are still written as `InResponseTo`.

- `IdentityProvider::answer_artifact_resolve` answers such a request with
  status `Requester`, without `InResponseTo` and without the message, as
  [Handle a malformed request](artifact-resolve-answers.md#handle-a-malformed-request)
  describes. The artifact stays outstanding.
- `IdentityProvider::receive_name_id_management` and
  `respond_name_id_management` write their SOAP response without
  `InResponseTo`. The response returns on the request's HTTP exchange.
- `respond_name_id_management_redirect` on both providers returns
  `SamlError::Invalid`, and `receive_name_id_management_redirect` returns it
  when it would have returned `NameIdManagementReceipt::Refused`. An
  HTTP-Redirect response reaches the requester through the user agent, and
  without `InResponseTo` nothing ties it to the request.

The receive methods still accept such a request when they would not refuse
it, and service providers still accept responses and assertions with such an
`ID`.

To upgrade, send the SOAP answers as you send the others. Over
HTTP-Redirect, handle the error as you handle the other errors of each
method: send no response, or show the user an error page.
