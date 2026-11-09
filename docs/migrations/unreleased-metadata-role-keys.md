# Metadata keys from the peer's role

This change is unreleased. It affects you only if one entity's metadata has
both an `IDPSSODescriptor` and an `SPSSODescriptor`, and those roles publish
different `KeyDescriptor` certificates.

`IdpMetadata` now reads `KeyDescriptor` certificates from the
`IDPSSODescriptor` only, and `SpMetadata` reads them from the
`SPSSODescriptor` only. Before, both read the certificates of every role in
document order. This applies to `IdpDescriptor`, `SpDescriptor`, the raw
`IdentityProvider` and `ServiceProvider`, and `x509_certificates` and
`get_x509_certificate` on `IdpMetadata` and `SpMetadata`.

What changes at runtime:

- A message from a dual-role peer verifies only against the signing
  certificates of the role that sent it. A message signed with a key that
  only the other role publishes now fails, usually with
  `SamlError::CertificateMismatch`.
- Assertions, identifiers, and attributes encrypted for a dual-role peer use
  the encryption certificate of the role you address. If that role publishes
  none, the call returns `SamlError::MissingMetadata`, even when the other
  role publishes one.
- A single `KeyDescriptor` certificate in a role is used for both signing and
  encryption when that role has no other certificate, even when the other
  role has its own keys.

To upgrade, publish each role's keys in that role's descriptor.

`Metadata::parse` and `Metadata::parse_with_limits` have no role. They still
read the certificates of every role.

The rule is in [Metadata trust and replay](../conformance/metadata-and-replay.md).
