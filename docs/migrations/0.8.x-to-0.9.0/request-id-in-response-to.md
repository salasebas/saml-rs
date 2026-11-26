# Handle requests whose `ID` cannot be written as `InResponseTo`

If you answer artifact resolution or name identifier management requests,
these methods now return `SamlError::Invalid` for a request whose `ID` is not
an `xs:NCName`, such as `1bad:id` or a UUID that starts with a digit:

- `IdentityProvider::answer_artifact_resolve`, when it would otherwise write
  an answer. The artifact stays outstanding. A request whose signature does
  not verify still returns the verification error.
- `IdentityProvider::respond_name_id_management`, and
  `respond_name_id_management_redirect` on both providers.
- `IdentityProvider::receive_name_id_management`, and
  `receive_name_id_management_redirect` on both providers, when they would
  have returned `NameIdManagementReceipt::Refused`.

`StatusResponseType` declares `InResponseTo` as an `xs:NCName`, so the
response cannot carry such an `ID`. In 0.8 these methods copied it into the
response anyway. `ID` values surrounded by XML whitespace are still answered.

The receive methods still accept such a request when they would not refuse
it, and service providers still accept responses and assertions with such an
`ID`.

To upgrade, handle the error as you handle the other errors of each method.
Over SOAP, answer with a `SoapFault` as its rustdoc describes. Over
HTTP-Redirect, send no response, or show the user an error page.
