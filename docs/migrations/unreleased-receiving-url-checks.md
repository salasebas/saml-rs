# Check messages against the URL that received them

Three receivers now compare a present `Destination`, and for SSO the bearer
`Recipient`, with the endpoint that received the message.

## Pass the receiving URL to `answer_artifact_resolve`

`IdentityProvider::answer_artifact_resolve` takes the URL of the HTTP handler
that received the `ArtifactResolve`, after `request_envelope`. Take the URL
from your handler, not from the request. It must be a SOAP
`ArtifactResolutionService` location that the identity provider publishes.

Before:

```rust
let answer = idp.answer_artifact_resolve(&sp, envelope, &mut issued, channel)?;
```

After:

```rust
let received_at = EndpointUrl::try_new("https://idp.example.com/artifact")?;
let answer = idp.answer_artifact_resolve(&sp, envelope, &received_at, &mut issued, channel)?;
```

An unpublished URL returns `SamlError::RecipientEndpointNotPublished`. A
request whose `Destination` names another URL gets `Success` without the
message, and `AnsweredArtifact::release` returns
`ArtifactRelease::Withheld(ArtifactWithheld::DestinationMismatch)`. Before,
the identity provider compared `Destination` with the endpoint index in the
artifact. A request addressed to another published endpoint and received
there is now answered.

## Supply the assertion consumer to `finish_sso`

`ServiceProvider::finish_sso` and `finish_sso_with_outstanding_logout` now
read `SamlValidationContext::with_recipient_endpoint`, as
`accept_unsolicited_sso` does. Before, they ignored it and always expected the
assertion consumer of the pending request.

If your service provider publishes several assertion consumers for one
binding, pass the URL of the handler that received the response. Without a
supplied URL, nothing changes.

A supplied URL now returns:

- `SamlError::DestinationMismatch` when it is another published assertion
  consumer than the one the pending request asked for. `expected` is the requested location and `actual` is
  the supplied URL.
- `SamlError::RecipientEndpointNotPublished` when it is not an assertion
  consumer for the pending request's binding.

## Expect `Destination` checks on SOAP logout responses

`finish_slo` on both roles now checks a present `Destination` on a SOAP
`LogoutResponse`. It must name the local SOAP `SingleLogoutService`
`Location`. A response without `Destination` is accepted as before, with or
without a local SOAP endpoint.

After the signature checks, a response with `Destination` can now return:

- `SamlError::DestinationMismatch` when it names another URL.
- `SamlError::MissingMetadata` when the local party publishes no SOAP
  `SingleLogoutService`.
- `SamlError::RecipientEndpointAmbiguous` when the local party publishes
  several and you supply none with `with_recipient_endpoint`.
- `SamlError::RecipientEndpointNotPublished` when the local party publishes
  a SOAP `SingleLogoutService` and the URL you supply with
  `with_recipient_endpoint` is not its location, such as a browser logout
  URL.
