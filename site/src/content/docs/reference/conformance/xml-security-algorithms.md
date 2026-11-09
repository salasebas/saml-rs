---
title: "XML Signature and XML Encryption algorithms"
description: "The Conformance §4 algorithms a typed identity provider and service provider sign, verify, encrypt, and decrypt with, and the `AlgorithmPolicy` defaults."
---

The algorithms a typed identity provider and service provider sign, verify,
encrypt, and decrypt with. `AlgorithmPolicy` selects what is generated. It is
not a field of `SpValidationPolicy` or `IdpValidationPolicy`, so Recommended
and Compatibility do not change it. `AlgorithmPolicy::default()` is what
`Default`, `new`, `try_new`, and the config builders use: RSA-SHA256 with a
SHA-256 digest, the enveloped-signature and exclusive canonicalization
transforms, AES-256-CBC, and RSA-OAEP. This page does not claim the IdP
operational mode or the SP operational mode.

Normative text is Conformance Requirements §4, as clarified by Approved
Errata 05 E50. §4.1 lists the XML Signature algorithms and §4.2 the XML
Encryption algorithms that a compliant SAML V2.0 implementation `MUST`
implement. E50 says that list is the minimal set, and that other XML Signature
and XML Encryption algorithms `MAY` be used. E81 replaces the Core §5.4.1
RSA-SHA1 sentence with the same permission and does not change §4.1.
Conformance §5 is the TLS stack of the deployment and is not on this page.

To implement an algorithm here is to sign or encrypt with it when the caller
selects it, and to verify or decrypt it when a peer sends it. Which algorithm a
producer selects is not stated by §4. Generating SHA-1, Triple DES, or RSA-v1.5
only when the caller selects it is library policy. The algorithms are
available on the RustCrypto provider with `crypto-legacy-algorithms`, which the
default `crypto-bergshamra` feature enables. AWS-LC and FIPS have a narrower
set, listed in each row.

The signer's algorithm applies to every message it signs: the `AuthnRequest`,
the `Response`, and logout messages. It is the XML-DSig `SignatureMethod` on
HTTP-POST and the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. The
encryption algorithms apply to `EncryptedAssertion`.

## XML Signature

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| SHA-1 digest | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. Generated only with `SignatureAlgorithm::RsaSha1` or `SignatureAlgorithm::DsaSha1`, which take their digest from the signature algorithm. Verified under `XmlSignatureProfile::AllowProviderSupportedForCompatibility`, the value Recommended uses. `StrictRsaSha2` is library hardening and rejects it |
| RSAwithSHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `SignatureAlgorithm::RsaSha1` selects it. It is never the default. AWS-LC and FIPS do not sign with it. FIPS does not verify it |
| DSAwithSHA1 | Identity provider and service provider | Sign and verify | Recommendation to implement. Conformance §4.1. `SignatureAlgorithm::DsaSha1` selects it with a DSA signing key, and a DSA certificate in the peer's metadata verifies it. It is never the default, on the same library policy as the SHA-1 digest. RustCrypto with `crypto-legacy-algorithms` only |
| HMAC-SHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `SignatureAlgorithm::HmacSha1` signs with `Credentials::hmac_secret`, and the signature carries no `KeyInfo`. The verifier sets the same secret with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`, next to the peer's metadata certificates. SAML metadata has no shared-secret key, so the secret is exchanged out of band. Metadata signatures are not verified with it. The 160-bit minimum `HMACOutputLength` is existing library hardening |
| An HMAC secret is at least 20 bytes | Identity provider and service provider | Configure signing and verification | Library policy. RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. `HmacSecret::try_new` rejects a shorter secret with `SamlError::Invalid`. It is local configuration and does not reject a message |
| Canonical XML 1.0 without comments | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::CanonicalXml` puts it in `signed_reference_transforms`, for the messages in the row below. `SignedInfo` is canonicalized with exclusive canonicalization. Verification accepts it on `SignedInfo` and on a reference under `AllowProviderSupportedForCompatibility`. `StrictRsaSha2` rejects it |
| Enveloped-signature transform | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::EnvelopedSignature` is the first default transform |
| The identity provider signs a browser response with its own transforms | Identity provider | Generate Response | Library behaviour. `IdpConfig::algorithms.signed_reference_transforms` applies to `respond_sso` and `initiate_sso`. `respond_sso_artifact`, `initiate_sso_artifact`, and `respond_paos_sso` keep the enveloped-signature and exclusive canonicalization transforms. Their `Response` is signed before it is placed in a SOAP envelope, and Canonical XML would take the envelope's namespace declarations into the digest of a verifier that checks the signature in place |
| RSA-SHA256, RSA-SHA384, RSA-SHA512, and a backend URI | Identity provider and service provider | Sign and verify | Optional. Errata 05 E50. `SignatureAlgorithm::RsaSha256` is the default. `SignatureAlgorithm::Custom` passes a URI to the provider |

## XML Encryption

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Triple DES block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::TripleDesForCompatibility` selects it. The variant keeps its samlify-port name. It is a CBC mode, so the Errata 05 E93 Response signature applies. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS |
| AES-128 and AES-256 block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::Aes256` is the default. `Aes128` selects AES-128 |
| RSA-v1.5 key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::Rsa15ForCompatibility` selects it. The variant keeps its samlify-port name. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS. XML Encryption 1.1 §5.5.1 makes it optional and says its implementation is `NOT RECOMMENDED`, which supports generating it only when selected. Decryption still accepts it whenever RSA key-transport decryption runs. Refusing it unless selected is [issue 251](https://github.com/salasebas/saml-rs/issues/251) |
| RSA-OAEP key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::RsaOaepMgf1p` is the default. FIPS does not use its SHA-1 MGF1 |
| RSA key-transport decryption on RustCrypto | Service provider | Decrypt `EncryptedAssertion` | Library policy, unchanged. RSA-v1.5 and RSA-OAEP decryption on RustCrypto need `XmlEncryptionPolicy::with_insecure_software_rsa_key_transport_decryption_allowed` because that backend is affected by `RUSTSEC-2023-0071` |
| AES-128-GCM and a backend URI | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Optional. Errata 05 E50. `DataEncryptionAlgorithm::Aes128Gcm` and `Custom` |
