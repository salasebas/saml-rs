# Conformance §4 algorithms

This change is unreleased. It applies to the release that first publishes
`SignatureAlgorithm::RsaSha1`.

Defaults do not change. A typed identity provider and service provider still
sign with RSA-SHA256 and a SHA-256 digest, and encrypt with AES-256-CBC and
RSA-OAEP, unless the caller selects another algorithm.

## Add arms for the new algorithm variants

Who must change: code with an exhaustive `match` on `SignatureAlgorithm` or
`TransformAlgorithm`.

`SignatureAlgorithm` gains `RsaSha1`, `DsaSha1`, and `HmacSha1`. `TransformAlgorithm`
gains `CanonicalXml`, which is Canonical XML 1.0 without comments. Add an arm
for each:

```rust
use saml_rs::SignatureAlgorithm;

fn label(algorithm: &SignatureAlgorithm) -> &str {
    match algorithm {
        SignatureAlgorithm::RsaSha256 => "rsa-sha256",
        SignatureAlgorithm::RsaSha384 => "rsa-sha384",
        SignatureAlgorithm::RsaSha512 => "rsa-sha512",
        SignatureAlgorithm::RsaSha1 => "rsa-sha1",
        SignatureAlgorithm::DsaSha1 => "dsa-sha1",
        SignatureAlgorithm::HmacSha1 => "hmac-sha1",
        SignatureAlgorithm::Custom(uri) => uri,
    }
}
```

A caller that used `SignatureAlgorithm::Custom` with the RSA-SHA1 URI can
select `SignatureAlgorithm::RsaSha1` instead. Both write the same XML.
`SignatureAlgorithm::Custom` with the DSA-SHA1 URI used to fail with
`SamlError::Crypto` because no digest was known for it. It now signs with a
SHA-1 digest.

## Add the HMAC secret field to struct literals

Who must change: code that builds `Credentials`, the raw `EntitySetting`, or
the raw `FlowOptions` with a struct literal that lists every field.

Each gains `hmac_secret`. On `Credentials` it is an `Option<HmacSecret>`, the
secret `SignatureAlgorithm::HmacSha1` signs with. On `EntitySetting` it is the
same secret as bytes. On `FlowOptions` it is the peer's secret that verifies
an HMAC signature. Set it to `None`, or end the literal with `..Default::default()`:

```rust
use saml_rs::{CertificatePem, Credentials, PrivateKeyPem};

let credentials = Credentials {
    signing_key: Some(PrivateKeyPem::new("-----BEGIN PRIVATE KEY-----...")),
    signing_certificate: Some(CertificatePem::new("-----BEGIN CERTIFICATE-----...")),
    ..Credentials::default()
};
```

## Expect the identity provider's own reference transforms on a response

Who must change: an identity provider that sets
`IdpConfig::algorithms.signed_reference_transforms` to something other than
the default, and expects its responses to keep the default transforms.

`respond_sso`, `initiate_sso`, `respond_sso_artifact`, `initiate_sso_artifact`,
and `respond_paos_sso` used to sign the response with the default
enveloped-signature and exclusive canonicalization transforms, whatever the
identity provider configured. They now use `signed_reference_transforms`, as
the service provider and logout messages already did. The raw
`IdentityProvider` still signs with the transforms on the raw service
provider's `EntitySetting`.

Set the default transforms again to keep them:

```rust
use saml_rs::{AlgorithmPolicy, TransformAlgorithm};

let algorithms = AlgorithmPolicy {
    signed_reference_transforms: vec![
        TransformAlgorithm::EnvelopedSignature,
        TransformAlgorithm::ExclusiveCanonicalization,
    ],
    ..AlgorithmPolicy::default()
};
```
