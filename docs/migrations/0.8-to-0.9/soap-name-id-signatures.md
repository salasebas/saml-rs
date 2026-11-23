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

An invalid signature now returns a verification error. For example,
`SamlError::SignatureVerification` can mean that the peer rotated its signing
key and the descriptor still has the old certificate. Refresh the descriptor
before starting or retrying the exchange.
