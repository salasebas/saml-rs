# Encrypt logout and name identifier management for the receiving role

This change affects a service provider or identity provider that encrypts the
identifiers of a `LogoutRequest` or a `ManageNameIDRequest`, for a peer entity
with more than one role descriptor of the peer's kind. No code fails to
compile.

`StartSlo::identifier_encryption` and
`StartNameIdManagement::identifier_encryption` with
`IdentifierEncryptionPolicy::EncryptIdentifiers` now take the peer encryption
keys from the role descriptor that publishes the endpoint the request goes to:

- `start_slo` and `start_async_slo` read the role that publishes the selected
  `SingleLogoutService`.
- `start_name_id_management` and `start_name_id_management_redirect` read
  the role that publishes the selected `ManageNameIDService`.

Before, they read the first peer role that published an encryption
certificate, even when another role published the endpoint. A peer whose
receiving role could not decrypt with that key answered as if the request had
no identifier, or refused it.

Metadata §2.4.1 and Errata 05 E62 declare a `KeyDescriptor` for the entity
acting in the role that contains it. SSO responses already take their keys
from the role that publishes the receiving `AssertionConsumerService`.

If the receiving role publishes no encryption certificate, these operations
now return `SamlError::MissingMetadata`, even when another role of the peer
publishes one. Before, they encrypted for the other role's key. To keep
encrypting for that peer, ask it to publish its encryption key in the role
that publishes the endpoint, or send the identifiers in plaintext with
`IdentifierEncryptionPolicy::PlaintextIdentifiers`.
