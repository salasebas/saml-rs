# Extend encryption algorithm matches

**Affects:** callers with an exhaustive `match` on `DataEncryptionAlgorithm`
or `KeyEncryptionAlgorithm`, including through the compatibility crates.

Add arms for `DataEncryptionAlgorithm::Aes256Gcm` and
`KeyEncryptionAlgorithm::RsaOaep { digest, mgf }`. The latter carries a
`DigestAlgorithm` and a `MaskGenerationFunction`; do not discard these when
storing or forwarding the selected algorithm. `as_uri()` returns the key
transport URI without its parameters.

The defaults remain AES-256-CBC and RSA-OAEP-MGF1P. Existing configurations
and raw encryption function signatures are unchanged. Selecting the new
variants requires a crypto provider. Both config builders return
`SamlError::Unsupported` for unsupported OAEP parameters; AWS-LC and FIPS
require matching SHA-256, SHA-384, or SHA-512 digest and MGF1 hashes.
