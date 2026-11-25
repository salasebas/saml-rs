---
title: "Crypto provider"
description: "Pick the provider before the first release build. Keep the default unless you need AWS-LC or FIPS."
---

Pick the provider before the first release build. Keep the default unless you need AWS-LC or FIPS.

## Default

```sh
cargo add saml-rs --git https://github.com/salasebas/saml-rs.git --branch main
```

`crypto-bergshamra` selects RustCrypto together with bergshamra's legacy-algorithm, post-quantum, and PKCS#11 capabilities. `saml-rs` initialises that provider before the first crypto operation.

## Check at startup

Call `initialize_crypto_provider` when a bad provider should fail before the first SAML operation.

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

Initialisation, attestation, unsupported-algorithm, and key-import failures return `SamlError::Crypto`.

## AWS-LC and FIPS

Turn the default features off and enable exactly one of `crypto-rustcrypto`, `crypto-aws-lc`, or `crypto-fips`. Combinations fail at compile time. `--all-features` does not apply.

RustCrypto with `crypto-legacy-algorithms`, which the default build enables, implements every algorithm that Conformance §4.1 and §4.2 require, and both SHA-1 `SigAlg` methods that HTTP-Redirect and HTTP-POST-SimpleSign require. `crypto-rustcrypto` without `crypto-legacy-algorithms` lacks DSA-SHA1, Triple DES, and RSA-v1.5. [Signature algorithms by build](../reference/conformance/xml-security-algorithms.md#signature-algorithms-by-build) and [encryption algorithms by provider](../reference/conformance/xml-security-algorithms.md#encryption-algorithms-by-provider) list what each build implements.

Bergshamra supports AWS-LC and FIPS on Linux x86_64 and aarch64. The provider tests in this repository run on Linux x86_64.

`crypto-fips` means the selected AWS-LC provider attested FIPS mode. It does not certify the binary or the deployment. In a `crypto-fips` build, a successful `initialize_crypto_provider` reports `CryptoFipsStatus::Active`.

FIPS rejects algorithms outside its approved set, including SHA-1 `RSA_OAEP_MGF1P` key transport and both signing and verifying `RSA_SHA1`. Non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and XML-DSig signatures. AWS-LC covers a narrower set than RustCrypto. The table is bergshamra's [provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.12.0/docs/provider-capabilities.md).

## Next

The flag list is [Cargo features](../reference/features.md). What the signature adapter already turns on is [XML signatures](../explanation/xml-signature-recommendations.md).
