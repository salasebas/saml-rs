# Answer AuthnRequests with an unusable binding, unreadable content, or a later version

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
- Both an `AssertionConsumerServiceURL` and an
  `AssertionConsumerServiceIndex`. The reason is `MalformedRequest`. In 0.8,
  `receive_sso` returned the request, and `respond_sso` refused it with
  `SamlError::Invalid`, so the request got no answer.
- A requested `EncryptedID` whose decrypted `NameID` breaks the protocol
  profile, such as a qualified `NameQualifier`. The reason is
  `MalformedRequest`. In 0.8, `receive_sso` returned the profile or XML error.
- A `Version` later than `2.0`, such as `2.1` or `3.0`. The reason is
  `AuthnRequestRefusalReason::VersionMismatch`, and the identity provider
  reads none of the request's other content. In 0.8, `receive_sso` returned
  `SamlError::ProtocolProfile` before it checked the signature.

SAML Profiles §4.1.4.1 requires an identity provider that cannot satisfy a
request to answer with an error `Response`. Core §3.2.1 gives the status
`Requester` to the answer to a request that breaks SAML syntax or processing
rules. The identity provider also uses it for a binding URI it does not
support and for an `AssertionConsumerServiceURL` that is not HTTP(S). Core
§4.1.3.2 gives the status `VersionMismatch` to the answer to a request of
another version. `RefusedAuthnRequest::content_error` returns the parsing
error behind a content refusal, for your logs. The response carries only the
status.

This change affects an identity provider login handler that matches
`Invalid`, `UndefinedBinding`, or `ProtocolProfile` from `receive_sso` for
these requests, or `Invalid` from `respond_sso` for a request with both an
`AssertionConsumerServiceURL` and an `AssertionConsumerServiceIndex`. It also
affects a handler that sends a local error page for every receipt error. No
code fails to compile. Match `AuthnRequestRefused` before the other errors,
and pass the refusal to `respond_sso_refusal` or
`respond_sso_refusal_artifact`, as
[Answer AuthnRequests refused for their signature or age](authn-request-signature-and-age-refusals.md)
shows. To keep showing a local error page for these requests, match the
reason and do not send the refusal.

For `UnsupportedProtocolBinding`, the response carries `Requester` with the
subordinate code `UnsupportedBinding`. For `VersionMismatch`, it carries
`VersionMismatch`, with the subordinate code `RequestVersionTooHigh` for a
later major version such as `3.0`. Some refused requests get their response
at the default assertion consumer service of the service provider metadata:

- A request whose `AssertionConsumerServiceURL`, `ProtocolBinding`, or
  `AssertionConsumerServiceIndex` cannot be read.
- A request with both an `AssertionConsumerServiceURL` and an
  `AssertionConsumerServiceIndex`.
- A request whose `Version` is later than `2.0`, whether it is refused as
  `VersionMismatch` or, unsigned when a signature is required, as
  `Unsigned`.

Pass `RespondSso` options with the binding of that default. Another binding
returns an error.

These requests still return an error and no refusal:

- A request whose signature does not verify, whose `Issuer` is not the
  service provider, or whose `Destination` names another location.
- A request that breaks the protocol profile before its signature is
  checked, such as a qualified attribute or an element in a foreign
  namespace.
- A request whose `Version` declares a major version below 2, such as `1.1`,
  or is not a `major.minor` number. Core §4.1.3.2 forbids a SAML 2.0
  response to a request of a lower version.
- An unsigned request of a later major version, such as `3.0`, when the
  service provider's metadata or this identity provider requires signed
  requests.
- A request whose `ID`, `IssueInstant`, `Issuer`, or `Destination` cannot be
  read.
