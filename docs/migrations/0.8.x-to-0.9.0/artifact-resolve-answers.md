# Send the ArtifactResponse for store, signature, and request failures

`IdentityProvider::answer_artifact_resolve` returns an `AnsweredArtifact` when
the artifact store fails, when a present request signature does not verify or
cannot be verified, and when the request is malformed. Send its `response()`
with HTTP 200, as for every other answer. Log `AnsweredArtifact::error()` to
keep the cause. The message is not released in any of these cases, and the
artifact stays outstanding.

## Handle a failing artifact store

In 0.8, `answer_artifact_resolve` read `IssuedArtifacts`, which could not
fail. It now reads any [`ArtifactStore`](soap-artifact-discovery.md#pass-an-artifactstore-to-artifact-issuing-and-resolution).
When the store's `lookup`, `now`, or `consume` fails, the answer has status
`Success` without the message. `release()` returns
`ArtifactRelease::Withheld(ArtifactWithheld::StoreUnavailable)`, and `error()`
returns the store error. Issuing an artifact still returns
`SamlError::ArtifactStoreUnavailable`.

To alert on store failures, check the answer:

```rust
let answer = idp.answer_artifact_resolve(&sp, envelope, &received_at, &mut issued, channel)?;
if let Some(cause) = answer.error() {
	report_artifact_failure(cause);
}
let body = answer.response().envelope();
```

## Handle a request signature that does not verify

In 0.8, `answer_artifact_resolve` did not verify an `ArtifactResolve`
signature. It now verifies a present one, as
[Update signing keys for SOAP artifact resolution](soap-artifact-signatures.md)
describes. When the signature does not verify, the answer has status
`Requester` with `RequestDenied` and no message. `release()` returns
`ArtifactRelease::RequestDenied`, and `error()` returns the verification
error, such as `SamlError::SignatureVerification` or
`SamlError::AlgorithmUnsupported`.

When the identity provider cannot verify a present signature, because the
build has no crypto provider or the provider fails to start, the answer has
status `Responder` and no message. `release()` returns
`ArtifactRelease::VerificationUnavailable`, and `error()` returns
`SamlError::Unsupported` or `SamlError::Crypto`.

A request whose `Version` has a major version below 2 returns
`SamlError::ProtocolProfile` instead, even when its signature does not
verify, because a SAML 2.0 answer would have a higher version than the
request.

A request whose `Version` has a later major version, such as `3.0`, and whose
present signature does not verify or cannot be verified gets no answer:
`answer_artifact_resolve` returns the error that `error()` would hold. A SAML
2.0 answer to such a request may report only `RequestVersionTooHigh`, and the
`Version` of a request that fails verification cannot be relied on. 0.8
answered it with `VersionMismatch`. Answer the error with a SOAP fault, as
[Answer SOAP processing failures with a SOAP fault](status-and-soap-replies.md#answer-soap-processing-failures-with-a-soap-fault)
describes.

A service provider that reads one of these answers with
`ArtifactResolution::finish` gets `SamlError::StatusNotSuccess` with its
status. An answer without `InResponseTo` gives
`SamlError::InResponseToMismatch` instead.

## Handle a malformed request

In 0.8, `answer_artifact_resolve` returned `SamlError::ProtocolProfile` for a
request without exactly one `Artifact` element, with a second `Issuer`, or
without `ID`, `Version`, or a UTC `IssueInstant`, and you answered with a SOAP
fault. It now answers these requests with status `Requester` and no message.
`release()` returns `ArtifactRelease::MalformedRequest`, and `error()` returns
the error that 0.8 returned.

Two requests that 0.8 answered as usual now get the same `Requester` answer:

- A request whose `ID` is not an `xs:NCName`, which 0.8 copied into
  `InResponseTo`. See
  [Handle requests whose `ID` cannot be written as `InResponseTo`](request-id-in-response-to.md).
- A request whose `Version` is not a `major.minor` number, such as `2`, which
  0.8 answered with `VersionMismatch`.

An answer to a request whose `ID` is missing or not an `xs:NCName` has no
`InResponseTo`.

A request of a later version, such as `2.1` or `3.0`, gets `VersionMismatch`,
with `RequestVersionTooHigh` for a later major version, even when it lacks
one of the parts above. A configured `SchemaValidator` that rejects the
request still returns its error first. 0.8 returned
`SamlError::ProtocolProfile` for such a request when it lacked one of those
parts.

## Update matches and derives

In 0.8, `ArtifactRelease` had three variants. It is now `#[non_exhaustive]`
and has the variants `RequestDenied`, `VerificationUnavailable`, and
`MalformedRequest`. Add a wildcard arm to an exhaustive `match`.

`AnsweredArtifact` no longer implements `Clone`, `PartialEq`, or `Eq`, because
it can carry a `SamlError`. Compare `release()` and `response()` instead.
