# KeyDescriptor `use` selects signing and encryption certificates

This break is unreleased. It applies to metadata parsed by `IdpDescriptor`,
`SpDescriptor`, `IdpMetadata`, `SpMetadata`, and `Metadata`.

A certificate in a `KeyDescriptor` with `use="encryption"` is no longer used
to verify signatures. A certificate in a `KeyDescriptor` with `use="signing"`
is no longer used to encrypt. Before, when the peer's metadata held exactly
one certificate, that certificate served both uses whatever its `use` said.

A `KeyDescriptor` without `use` now serves both uses alongside the keys
published for one use. Before, it was ignored unless it held the only
certificate.

Who must change: integrations whose peer publishes its only key with the
other `use`. Verifying that peer's XML signatures now fails with
`SamlError::NoTrustedCertificate`, and its HTTP-Redirect and
HTTP-POST-SimpleSign signatures with `SamlError::SignatureVerification`.
Encrypting to it now fails with `SamlError::MissingMetadata`.

Ask the peer to publish the key with the `use` it serves, or without `use`
when it serves both. When you keep a local copy of the peer's metadata, make
the same change there.
