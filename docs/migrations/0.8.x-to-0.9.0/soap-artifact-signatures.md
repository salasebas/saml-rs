# Update signing keys for SOAP artifact resolution

`IdentityProvider::answer_artifact_resolve` and `ArtifactResolution::finish`
now verify a present XML signature over the SOAP body message. A signature
that fails verification makes `finish` return an error, and makes
`answer_artifact_resolve` answer with `RequestDenied`, as
[Send the ArtifactResponse for store, signature, and request failures](artifact-resolve-answers.md#handle-a-request-signature-that-does-not-verify)
describes. Both calls still accept unsigned messages over a SOAP channel that
supplies the required protection.

If your peer signs the SOAP message, enable a crypto provider feature and
import the peer's current signing certificates into its `SpDescriptor` or
`IdpDescriptor`. For HMAC signatures, configure the shared secret with the
descriptor's `with_hmac_secret` method. Without a crypto provider, `finish`
returns `SamlError::Unsupported` for a signed response, and
`answer_artifact_resolve` answers a signed request with `Responder`.

After the IdP rotates its signing key, use the updated `IdpDescriptor` when
you start a new resolution. `finish` uses the keys captured by
`ServiceProvider::resolve_artifact`. The issuer keeps an artifact outstanding
when it rejects the request signature, so the intended SP can still resolve it
within its lifetime.
