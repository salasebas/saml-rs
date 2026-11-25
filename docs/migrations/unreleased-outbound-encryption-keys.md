# Encrypt for a usable key and write its certificate

## Logout and name identifier management skip an unusable key

`StartSlo::identifier_encryption` and
`StartNameIdManagement::identifier_encryption` with
`IdentifierEncryptionPolicy::EncryptIdentifiers` now encrypt for the first
peer encryption key that the configured algorithms can use. They read the
keys from the peer metadata the same way an identity provider does for an
SSO response. Before, they used the first encryption certificate in the peer
metadata and failed with `SamlError::Crypto` when it did not load or the
crypto provider could not encrypt for it, such as an EC key or an RSA key
too small for the key transport. Now they try the next key.

A peer without an encryption certificate still returns
`SamlError::MissingMetadata`. A peer without a usable key still returns the
`SamlError::Crypto` error of its first key. You do not need to change code.
