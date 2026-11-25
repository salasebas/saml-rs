# Send the ArtifactResponse for store and signature failures

`IdentityProvider::answer_artifact_resolve` returns an `AnsweredArtifact` when
the artifact store fails and when a present request signature does not verify.
Send its `response()` with HTTP 200, as for every other answer. Log
`AnsweredArtifact::error()` to keep the cause. The message is not released in
either case.

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
`ArtifactRelease::RequestDenied`, `error()` returns the verification error,
such as `SamlError::SignatureVerification` or `SamlError::AlgorithmUnsupported`,
and the artifact stays outstanding.

These cases return the verification error instead, because the identity
provider cannot send a correlated SAML 2.0 answer or the failure is its own:

- A request whose `ID` is not an `xs:NCName` or whose `Version` is not `2.0`.
- A build without a crypto provider, which returns `SamlError::Unsupported`.
- A crypto provider that fails to initialize, which returns
  `SamlError::Crypto`.

A service provider that reads the denial with `ArtifactResolution::finish`
gets `SamlError::StatusNotSuccess` with that status.

## Update matches and derives

In 0.8, `ArtifactRelease` had three variants. It is now `#[non_exhaustive]`
and has the variant `RequestDenied`. Add a wildcard arm to an exhaustive
`match`.

`AnsweredArtifact` no longer implements `Clone`, `PartialEq`, or `Eq`, because
it can carry a `SamlError`. Compare `release()` and `response()` instead.
