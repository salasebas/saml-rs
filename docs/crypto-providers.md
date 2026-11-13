# Crypto providers and features

`saml-rs` delegates XML-DSig, XML-Enc, C14N, and detached message signatures to
[`bergshamra`](https://crates.io/crates/bergshamra). Cargo features choose the
provider behind it.

## Features

| Feature | Selects |
| --- | --- |
| `crypto-bergshamra` (default) | RustCrypto plus `crypto-legacy-algorithms`, `crypto-post-quantum`, and `crypto-pkcs11` |
| `crypto-rustcrypto` | The RustCrypto provider |
| `crypto-aws-lc` | The AWS-LC provider. Select it with the default features off |
| `crypto-fips` | AWS-LC in FIPS mode. Select it with the default features off |
| `crypto-legacy-algorithms` | Bergshamra's legacy algorithms. Selects no provider |
| `crypto-post-quantum` | Bergshamra's post-quantum algorithms. Selects no provider |
| `crypto-pkcs11` | Bergshamra's PKCS#11 support. Selects no provider |

At most one of `crypto-rustcrypto`, `crypto-aws-lc`, and `crypto-fips` can be
selected. Other combinations are rejected at compile time.

With `default-features = false` and no provider, the crate still builds
messages, parses metadata, and extracts fields. Signing, verification, and
encryption return `SamlError::Unsupported`.

## What a provider enables

- XML signatures verified against metadata-declared keys.
- Signed-reference placement checks that help mitigate XML Signature Wrapping.
- XML-Enc. RSA-OAEP key transport decrypts with the default options. RSA-v1.5
  key-transport decryption stays off until the caller selects it through
  [`XmlEncryptionPolicy`](https://docs.rs/saml-rs/latest/saml_rs/config/struct.XmlEncryptionPolicy.html).

The algorithms each provider verifies are in
[XML security algorithms](conformance/xml-security-algorithms.md). Custom
algorithm URIs are listed in Bergshamra's
[provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.12.0/docs/provider-capabilities.md).

## AWS-LC and FIPS

Bergshamra supports AWS-LC and FIPS on Linux x86_64 and aarch64. This
repository's provider tests run on Linux x86_64.

AWS-LC has a narrower algorithm set than RustCrypto. Non-FIPS AWS-LC still
verifies inbound RSA-SHA1 Redirect and XML-DSig signatures.

`crypto-fips` means the selected AWS-LC provider attested FIPS mode. It does not
certify the consuming binary or deployment. FIPS policy rejects algorithms
outside its approved set, including SHA-1 `RSA_OAEP_MGF1P` key transport and
both signing and verifying `RSA_SHA1`.

## How to surface provider initialisation at startup

`saml-rs` initialises Bergshamra before the first crypto operation.
Initialisation, attestation, unsupported-algorithm, and key-import failures map
to `SamlError::Crypto`. To see an initialisation failure at startup instead of
on the first SAML operation, call `initialize_crypto_provider`:

```rust
fn startup() -> Result<(), saml_rs::SamlError> {
    let provider = saml_rs::initialize_crypto_provider()?;
    assert_ne!(
        provider.fips_status(),
        saml_rs::CryptoFipsStatus::Uninitialized,
    );
    Ok(())
}
```
