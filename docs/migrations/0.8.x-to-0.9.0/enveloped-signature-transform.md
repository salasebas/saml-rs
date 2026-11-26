# Start reference transform lists with the enveloped-signature transform

`SpConfigBuilder::build` and `IdpConfigBuilder::build` now return
`SamlError::Invalid` when `AlgorithmPolicy::signed_reference_transforms` is
not empty and its first entry is not the enveloped-signature transform. Either
`TransformAlgorithm::EnvelopedSignature` or a `TransformAlgorithm::Custom`
with the URI `http://www.w3.org/2000/09/xmldsig#enveloped-signature` counts.
An empty list still selects the default transforms.

Every embedded signature sits inside the element it signs, and the signer
writes no transform parameters, so only the enveloped-signature transform can
take the signature out of the digest. Without it, the digest covered the
signature's own `DigestValue` and `SignatureValue`, and no peer could verify
the messages such a config signed. With the transform after another one, signing failed with
`SamlError::Crypto` at the first message. Both now fail when the config is
built.

The change affects only a caller that sets `signed_reference_transforms`.
Put the enveloped-signature transform first:

```rust
use saml_rs::{AlgorithmPolicy, TransformAlgorithm};

let mut algorithms = AlgorithmPolicy::default();
algorithms.signed_reference_transforms = vec![
    TransformAlgorithm::EnvelopedSignature,
    TransformAlgorithm::CanonicalXml,
];
```
