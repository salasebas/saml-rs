# Update signing keys for SOAP name identifier management

`IdentityProvider::receive_name_id_management` and
`StartedNameIdManagement::finish` now verify a present XML signature over the
received SOAP message. Both calls accept unsigned messages on a mutually
authenticated, integrity-protected channel.

If your service provider signs these messages, enable a crypto provider feature
and import its current signing certificates into the `SpDescriptor` you pass to
the identity provider. For HMAC signatures, set the shared secret with
`SpDescriptor::with_hmac_secret`. Use the updated descriptor when you start a new
exchange. `finish` uses the keys captured by `start_name_id_management`.

An invalid signature now makes `finish` return a verification error. For
example, `SamlError::SignatureVerification` can mean that the peer rotated its
signing key and the descriptor still has the old certificate. Refresh the
descriptor before starting or retrying the exchange.

`receive_name_id_management` refuses a request from the service provider
whose signature does not verify: it returns `NameIdManagementReceipt::Refused`
with `NameIdManagementRefusal::RequestDenied`, and the response has status
`Requester` with `RequestDenied`. Without a crypto provider, or when the
provider fails to start, it refuses a signed request with
`NameIdManagementRefusal::VerificationUnavailable` and status `Responder`.
Send `refused.response()` as for the other refusals, and log
`RefusedNameIdManagement::signature_error()` to keep the cause. A request
refused for its signature is not stored for replay detection, so the service
provider can retry it. `NameIdManagementRefusal` is `#[non_exhaustive]`, so a `match` on it
already has a wildcard arm.

A request whose `Version` has a later major version, such as `3.0`, and whose
present signature does not verify or cannot be verified is not refused:
`receive_name_id_management` returns the error that `signature_error()` would
hold. A SAML 2.0 response to such a request may report only
`RequestVersionTooHigh`, and the `Version` of a request that fails
verification cannot be relied on. 0.8 refused it with `VersionMismatch`.
Answer the error with a SOAP fault, as
[Answer SOAP processing failures with a SOAP fault](status-and-soap-replies.md#answer-soap-processing-failures-with-a-soap-fault)
describes.
