# Configure ECDSA and Ed25519 signing

If you already sign with an ECDSA or Ed25519 URI in
`SignatureAlgorithm::Custom`, you can use
`SignatureAlgorithm::EcdsaSha256`, `EcdsaSha384`, `EcdsaSha512`, or
`Ed25519` in `AlgorithmPolicy::signature`.

```rust
use saml_rs::{AlgorithmPolicy, SignatureAlgorithm};

let mut algorithms = AlgorithmPolicy::default();
algorithms.signature = SignatureAlgorithm::EcdsaSha256;
```

Pass the policy to `SpConfigBuilder::algorithms` or
`IdpConfigBuilder::algorithms`. Set the signing credential to an EC or
Ed25519 private key and its matching certificate. Use a P-256 key with
ECDSA-SHA256 for compatibility across providers.

A configuration that used one of these URIs with the wrong signing key
family now returns `SamlError::Invalid` from `build()`. Set a signing
credential of the required family, or select an algorithm that matches
your current key. An Ed25519 configuration on `crypto-fips` now returns
`SamlError::Unsupported` from `build()`. Select ECDSA with an EC credential
if you need the FIPS provider.

You can keep using `Custom` with a compatible credential. The same builder
checks apply to the named variants and their `Custom` URIs. Existing matches
on the non-exhaustive enum can keep their wildcard arm.
