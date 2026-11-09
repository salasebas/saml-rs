---
title: "Cargo features"
description: "The default feature turns signing and encryption on. Turn it off when you want messages without cryptography."
---

The default feature turns signing and encryption on. Turn it off when you want messages without cryptography.

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = [
    "crypto-rustcrypto",
    "crypto-legacy-algorithms",
    "crypto-post-quantum",
    "crypto-pkcs11",
]
crypto-rustcrypto = ["dep:bergshamra", "bergshamra/rustcrypto"]
crypto-aws-lc = ["dep:bergshamra", "bergshamra/aws-lc"]
crypto-fips = ["dep:bergshamra", "bergshamra/fips"]
```

With `default-features = false`, the crate still builds messages, parses metadata, and extracts fields. Signing, verification, and encryption return `SamlError::Unsupported`.

At most one of `crypto-rustcrypto`, `crypto-aws-lc`, and `crypto-fips` can be selected. Combinations are rejected at compile time. AWS-LC and FIPS are selected with the default features off.

`crypto-legacy-algorithms`, `crypto-post-quantum`, and `crypto-pkcs11` forward bergshamra capabilities. They do not select a provider. The default `crypto-bergshamra` feature enables those capabilities together with RustCrypto.

Bergshamra supports AWS-LC and FIPS on Linux x86_64 and aarch64. This repository's provider tests run on Linux x86_64.

`crypto-fips` means the selected AWS-LC provider attested FIPS mode. It does not certify the consuming binary or deployment. FIPS policy rejects algorithms outside its approved set, including SHA-1 `RSA_OAEP_MGF1P` key transport and both signing and verifying `RSA_SHA1`. Non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and XML-DSig signatures.

Custom algorithm URIs are listed in bergshamra's [provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.9.0/docs/provider-capabilities.md). How to select a provider is [Crypto provider](../guides/crypto-provider.md).
