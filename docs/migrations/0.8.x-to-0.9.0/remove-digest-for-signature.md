# Replace calls to `constants::digest_for_signature`

`saml_rs::constants::digest_for_signature` is removed from the public API. It
implemented part of `saml-rs`'s internal XML signature reference digest
selection and returned `None` for algorithms such as ECDSA-SHA256 while the
signer fell back to SHA-256.

This change affects you only if your code imports or calls
`saml_rs::constants::digest_for_signature`. Outgoing XML signing still selects
the same reference digests, so callers that configure `SignatureAlgorithm` need
no change.

To upgrade, use the digest URI constants in `saml_rs::constants::digest_algorithm`
or `DigestAlgorithm::as_uri` directly.

Before:

```rust
use saml_rs::constants::{digest_for_signature, signature_algorithm};

let digest = digest_for_signature(signature_algorithm::RSA_SHA256);
```

After:

```rust
use saml_rs::constants::digest_algorithm;

let digest = digest_algorithm::SHA256;
```

If your code maps an arbitrary signature algorithm URI to a digest URI, write
that `match` in your own crate using `saml_rs::constants::signature_algorithm`
and `saml_rs::constants::digest_algorithm`.
