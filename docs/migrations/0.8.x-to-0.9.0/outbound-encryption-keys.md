# Encrypt for a usable key and write its certificate

## Logout and name identifier management skip an unusable key

`StartSlo::identifier_encryption` and
`StartNameIdManagement::identifier_encryption` with
`IdentifierEncryptionPolicy::EncryptIdentifiers` now encrypt for the first
peer encryption key that the configured algorithms can use. They read the
keys of the peer role that receives the request, as
[Encrypt logout and name identifier management for the receiving role](logout-and-nim-encryption-role.md)
describes, the same way an identity provider reads the keys of a role for an
SSO response. Before, they used the first encryption certificate in the peer
metadata and failed with `SamlError::Crypto` when it did not load or the
crypto provider could not encrypt for it, such as an EC key or an RSA key
too small for the key transport. Now they try the next key.

A peer without an encryption certificate still returns
`SamlError::MissingMetadata`. A peer without a usable key still returns the
`SamlError::Crypto` error of its first key. You do not need to change code.

In a build without a crypto provider, `StartSlo::identifier_encryption`
with `EncryptIdentifiers` now returns `SamlError::Unsupported` before it
looks up the peer encryption certificate, as name identifier management
already did.
Before, a peer without an encryption certificate gave
`SamlError::MissingMetadata` there. If you match that error in such a
build, also match `SamlError::Unsupported`.

## Each EncryptedKey names the certificate it was encrypted for

Every `xenc:EncryptedKey` that the crate writes now carries a `ds:KeyInfo`
with the peer certificate it encrypted for:

```xml
<xenc:EncryptedKey>
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data>
  </ds:KeyInfo>
  <xenc:CipherData>...</xenc:CipherData>
</xenc:EncryptedKey>
```

This covers SSO responses, `LogoutRequest` identifiers, and name identifier
management identifiers. Metadata §2.4.1.1, as amended by Approved Errata 05
E68, recommends that the encrypting party say which key it used. A peer with
several published keys can then pick its matching private key. OpenSAML
5.2.0, and so the Shibboleth identity provider, writes the same element.

Each encrypted element grows by the base64 certificate, about 1.3 KB for a
typical 2048-bit RSA certificate. An HTTP-Redirect URL grows by about as
much, depending on compression and URL encoding. A second copy of the same
certificate in one message compresses well. You do not need to change code.

## KeyInfo outside the XML Signature namespace holds no key

`Metadata`, `SpMetadata`, `IdpMetadata`, `SpDescriptor`, and `IdpDescriptor`
now read a certificate only from a `ds:X509Certificate` in a `ds:X509Data` of
the `ds:KeyInfo` of a `md:KeyDescriptor`, with
`ds` bound to `http://www.w3.org/2000/09/xmldsig#`. Before, they matched
these elements by local name, so an element such as `<KeyInfo>` in the
metadata namespace, or in any other namespace, gave a signing or encryption
certificate.

Metadata that leaves `KeyInfo` unprefixed under a default metadata namespace
is schema-invalid, and other SAML implementations read no key from it.
With such metadata, `x509_certificates` now returns no certificate for that
`KeyDescriptor`. Signature verification then fails, and encryption returns
`SamlError::MissingMetadata`. To fix it, ask the peer to publish valid
metadata. Signed metadata must come back re-signed by its publisher, because
an edit breaks its signature. If you import the metadata with
`MetadataTrustPolicy::Unverified`, you can instead bind the XML Signature
namespace in your copy:

```xml
<!-- Before -->
<KeyInfo><X509Data><X509Certificate>MIIC...</X509Certificate></X509Data></KeyInfo>
<!-- After -->
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
```

## crypto-fips encrypts with RSA-OAEP and SHA-256 by default

With `crypto-fips`, `KeyEncryptionAlgorithm::default()`, and so
`AlgorithmPolicy::default().key_encryption`, is now:

```rust
use saml_rs::{DigestAlgorithm, KeyEncryptionAlgorithm, MaskGenerationFunction};

let fips_default = KeyEncryptionAlgorithm::RsaOaep {
    digest: DigestAlgorithm::Sha256,
    mgf: MaskGenerationFunction::Mgf1Sha256,
};
```

It writes the key transport URI `http://www.w3.org/2009/xmlenc11#rsa-oaep`
with a SHA-256 `ds:DigestMethod` and an `xenc11:MGF` for MGF1 with SHA-256.
Before, the default was `KeyEncryptionAlgorithm::RsaOaepMgf1p`, which uses
SHA-1 in OAEP. The FIPS provider refuses SHA-1 there, so every encrypted
assertion, identifier, or attribute failed with `SamlError::Crypto` when the
message was built. Other providers keep `RsaOaepMgf1p` as the default.

`SpConfigBuilder::build` and `IdpConfigBuilder::build` with `crypto-fips` now
return `SamlError::Unsupported` when `AlgorithmPolicy::key_encryption` is
`KeyEncryptionAlgorithm::RsaOaepMgf1p`, or a `KeyEncryptionAlgorithm::Custom`
with its URI. Before, the builders accepted it and
encryption failed later.

The change affects `crypto-fips` deployments:

- If your code sets `key_encryption` to `RsaOaepMgf1p`, the config no longer
  builds, even when it never encrypts. Remove that line or select
  `KeyEncryptionAlgorithm::RsaOaep` with SHA-256, SHA-384, or SHA-512.
- If you encrypt for a peer, check that the peer supports XML Encryption 1.1
  RSA-OAEP with SHA-256. OpenSAML and the Shibboleth service provider do.

## RSA-v1.5 key transport on AWS-LC

The `KeyEncryptionAlgorithm::Rsa15` rustdoc and the conformance record said
that RSA-v1.5 key transport works only on RustCrypto. It also works with
`crypto-aws-lc` and `crypto-legacy-algorithms`. The behaviour did not change.
