# Answer AuthnRequests with an unusable binding or unreadable content

`IdentityProvider::receive_sso` now returns `SamlError::AuthnRequestRefused`
for a request that passed its signature, `Issuer`, and `Destination` checks
but that it cannot read or answer as asked:

- A `ProtocolBinding` of HTTP-Redirect or SOAP, or a URI other than
  HTTP-POST, HTTP-POST-SimpleSign, and HTTP-Artifact.
  `RefusedAuthnRequest::reason` returns
  `AuthnRequestRefusalReason::UnsupportedProtocolBinding`. In 0.8,
  `receive_sso` returned `SamlError::UndefinedBinding` for HTTP-Redirect and
  SOAP, and `SamlError::Invalid` for another URI.
- A second `Subject` or `RequestedAuthnContext`, a `Subject` with more than
  one identifier, a `RequestedAuthnContext` without references or with both
  kinds, a `Comparison`, `ForceAuthn`, `IsPassive`, `AllowCreate`, or
  `AssertionConsumerServiceIndex` outside its schema type, or an
  `AssertionConsumerServiceURL` that is not an absolute HTTP(S) URL. The
  reason is `AuthnRequestRefusalReason::MalformedRequest`. In 0.8,
  `receive_sso` returned `SamlError::Invalid`.
- A requested `EncryptedID` whose decrypted `NameID` breaks the protocol
  profile, such as a qualified `NameQualifier`. The reason is
  `MalformedRequest`. In 0.8, `receive_sso` returned the profile or XML error.

SAML Profiles §4.1.4.1 requires an identity provider that cannot satisfy a
request to answer with an error `Response`. Core §3.2.1 gives the status
`Requester` to the answer to a request that breaks SAML syntax or processing
rules, and the identity provider also uses it for a binding URI it does not
support. `RefusedAuthnRequest::content_error`
returns the parsing error behind the refusal, for your logs. The response
carries only the status.

This change affects an identity provider login handler that matches
`Invalid`, `UndefinedBinding`, or `ProtocolProfile` from `receive_sso` for
these requests, or that sends a local error page for every receipt error. No
code fails to compile. Match `AuthnRequestRefused` before the other errors,
and pass the refusal to `respond_sso_refusal` or
`respond_sso_refusal_artifact`, as
[Answer AuthnRequests refused for their signature or age](authn-request-signature-and-age-refusals.md)
shows. To keep showing a local error page for these requests, match the
reason and do not send the refusal.

For `UnsupportedProtocolBinding`, the response carries `Requester` with the
subordinate code `UnsupportedBinding`. For a request refused because its
`AssertionConsumerServiceURL`, `ProtocolBinding`, or
`AssertionConsumerServiceIndex` cannot be read, the response goes to the
default assertion consumer service of the service provider metadata.
Pass `RespondSso` options with the binding of that default. Another binding
returns an error.

These requests still return an error and no refusal:

- A request whose signature does not verify, whose `Issuer` is not the
  service provider, or whose `Destination` names another location.
- A request that breaks the protocol profile before its signature is
  checked, such as a qualified attribute, an element in a foreign namespace,
  or a `Version` other than `2.0`.
- A request whose `ID`, `IssueInstant`, `Issuer`, or `Destination` cannot be
  read.
