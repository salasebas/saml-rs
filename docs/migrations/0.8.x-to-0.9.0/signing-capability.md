# Select a signature method the crypto provider can sign

`SpConfigBuilder::build` and `IdpConfigBuilder::build` now sign a short test
input with the selected `AlgorithmPolicy::signature` and the key that the
entity signs with: the signing credential, or the HMAC secret for an HMAC
method. When the crypto provider cannot sign with that method and key,
`build` returns `SamlError::Crypto` with the message
`the crypto provider cannot sign <URI> with the configured key`. Without a
signing credential or HMAC secret, `build` does not run the check.

Before, these configurations built, and the first signed message failed with
`SamlError::Crypto`:

- `SignatureAlgorithm::RsaSha1` on `crypto-aws-lc` or `crypto-fips`.
- `SignatureAlgorithm::HmacSha1` on `crypto-fips`.
- `SignatureAlgorithm::DsaSha1` without a DSA key, or on a build without
  `crypto-legacy-algorithms`.
- An RSA method with an EC signing key, and a `SignatureAlgorithm::Custom`
  URI that the provider does not sign.

To upgrade, select a method that the build signs. The
[signature algorithms by build](../../conformance/xml-security-algorithms.md#signature-algorithms-by-build)
table lists them. If a peer accepts only SHA-1 signatures, build with the
default RustCrypto provider.
