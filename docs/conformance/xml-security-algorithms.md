# XML Signature and XML Encryption algorithms

The algorithms a typed identity provider and service provider sign, verify,
encrypt, and decrypt with. `AlgorithmPolicy` selects what is generated. It is
not a field of `SpValidationPolicy` or `IdpValidationPolicy`, so Recommended
and Compatibility do not change it. `AlgorithmPolicy::default()` is what
`Default`, `new`, `try_new`, and the config builders use: RSA-SHA256 with a
SHA-256 digest, the enveloped-signature and exclusive canonicalization
transforms, AES-256-CBC, and RSA-OAEP. `AlgorithmPolicy` does not limit what
is verified. That set is in
[Inbound XML signature verification](#inbound-xml-signature-verification).
This page does not claim the IdP operational mode or the SP operational mode.

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
HTTP-POST and SOAP, and the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. The
encryption algorithms apply to `EncryptedAssertion`, `EncryptedID`,
`EncryptedAttribute`, and `NewEncryptedID`. The rows below name
`EncryptedAssertion` for all four.

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
| A message carried in SOAP keeps exclusive canonicalization | Identity provider and service provider | Generate Response and logout messages | Library behaviour. `signed_reference_transforms` applies to the `AuthnRequest`, to `respond_sso` and `initiate_sso`, and to logout messages on HTTP-POST. `respond_sso_artifact`, `initiate_sso_artifact`, `respond_paos_sso`, and logout messages over SOAP keep the enveloped-signature and exclusive canonicalization transforms. Each message is signed before it is placed in a SOAP envelope, and Canonical XML would take the envelope's namespace declarations into the digest of a verifier that checks the signature in place |
| RSA-SHA256, RSA-SHA384, RSA-SHA512, and a backend URI | Identity provider and service provider | Sign and verify | Optional. Errata 05 E50. `SignatureAlgorithm::RsaSha256` is the default. `SignatureAlgorithm::Custom` passes a URI to the provider |

## Inbound XML signature verification

A verifier accepts every `SignatureMethod` and `DigestMethod` that the
selected provider implements and that the peer's key can verify, unless
`XmlSignatureProfile::StrictRsaSha2` narrows it. `XmlSignatureProfile` is the
`xml_signatures` field of `SpValidationPolicy`. Recommended and Compatibility
both use `AllowProviderSupportedForCompatibility`. Accepting an algorithm
outside the Conformance §4.1 set is the Errata 05 E50 `MAY`. Neither profile
is an OASIS receiver rule.

The key is a signing certificate in the peer's metadata, or the secret set
with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`.
An algorithm verifies only with a key of its family: RSA for RSA and RSA-PSS,
EC for ECDSA, Ed25519, DSA, the HMAC secret for HMAC, and an ML-DSA or SLH-DSA
key of the same parameter set.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An embedded signature on a received `Response`, `Assertion`, or logout message is verified under `xml_signatures` | Accepting service provider | Inbound | Optional. Errata 05 E50. `AllowProviderSupportedForCompatibility` accepts the provider-supported set below. `StrictRsaSha2` is library hardening. A signature over the accepted content must use RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, exclusive canonicalization, and only the enveloped-signature and exclusive canonicalization transforms. Otherwise it is rejected with `SamlError::AlgorithmUnsupported` |
| An embedded signature on a received `AuthnRequest` or logout message | Identity provider | Inbound | Optional. Errata 05 E50. `IdpValidationPolicy` has no `xml_signatures` field. The provider-supported set applies |
| A detached `SigAlg` signature | Identity provider and service provider | Inbound HTTP-Redirect and HTTP-POST-SimpleSign | Optional. Errata 05 E50. `XmlSignatureProfile` does not apply, and `StrictRsaSha2` does not narrow it. Any `SigAlg` in the provider-supported set verifies |
| A signed metadata document | Metadata consumer | Inbound | Optional. Errata 05 E50. `MetadataTrustPolicy` limits the transforms, not the signature or digest algorithm. The provider-supported set applies |

On the default build, the provider-supported set includes SHA-1, MD5, and
RIPEMD-160 signatures and digests. `StrictRsaSha2` excludes them from the
embedded signatures it covers. Only the build features exclude them from a
detached `SigAlg`, a signature an identity provider verifies, or a metadata
signature.
`SsoSession::verified_xml_signatures` reports each accepted `SignatureMethod`
URI, and `SsoSession::sig_alg` the accepted detached `SigAlg`. Neither applies
an allowlist.

### Provider-supported set

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms` and `crypto-post-quantum`. A row marked Legacy
needs `crypto-legacy-algorithms`, and a row marked Post-quantum needs
`crypto-post-quantum`. A signature with an algorithm the build does not
verify does not verify. An RSA key shorter than 2048 bits verifies only on
RustCrypto with `crypto-legacy-algorithms`, including under `StrictRsaSha2`.
RustCrypto without it, AWS-LC, and FIPS reject it.

| `SignatureMethod` | Default build | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- |
| RSA-SHA256, RSA-SHA384, RSA-SHA512 | Yes | Yes | Yes |
| RSA-SHA1 | Yes | Yes | No |
| RSA-SHA224 | Yes | No | No |
| RSA-PSS with SHA-256, SHA-384, or SHA-512 | Yes | Yes | Yes |
| RSA-PSS with SHA-1, SHA-224, or SHA-3 | Yes | No | No |
| ECDSA with SHA-256, SHA-384, or SHA-512 | Yes | Yes | Yes |
| ECDSA-SHA224 | Yes | P-521 key only | P-521 key only |
| ECDSA with SHA-1 or SHA-3 | Yes | No | No |
| EdDSA Ed25519 | Yes | Yes | No |
| HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 | Yes | Yes | Yes |
| HMAC-SHA1 | Yes | Yes | No |
| DSA-SHA1, DSA-SHA256 | Legacy | No | No |
| RSA-MD5, RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-MD5, HMAC-RIPEMD160 | Legacy | No | No |
| ML-DSA-44, ML-DSA-65, ML-DSA-87, and the SLH-DSA-SHA2 parameter sets | Post-quantum | No | No |

| `DigestMethod` | Default build | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- |
| SHA-224, SHA-256, SHA-384, SHA-512 | Yes | Yes | Yes |
| SHA-1 | Yes | Yes | No |
| SHA3-256, SHA3-384, SHA3-512 | Yes | Yes | No |
| SHA3-224 | Yes | No | No |
| MD5, RIPEMD-160 | Legacy | No | No |

## XML Encryption

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Triple DES block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::TripleDesForCompatibility` selects it. The variant keeps its samlify-port name. It is a CBC mode, so the Errata 05 E93 Response signature applies. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS |
| AES-128 and AES-256 block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::Aes256` is the default. `Aes128` selects AES-128 |
| RSA-v1.5 key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::Rsa15ForCompatibility` selects it. The variant keeps its samlify-port name. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS. XML Encryption 1.1 §5.5.1 makes it optional and says its implementation is `NOT RECOMMENDED`, which supports generating it only when selected. An entity decrypts it, in any encrypted element it receives, only with `XmlEncryptionPolicy::with_rsa15_key_transport_decryption_allowed`. Without it, an `EncryptionMethod` that names RSA-v1.5 is rejected with `SamlError::Unsupported` before any key is decrypted. That refusal is library policy, an implementation-security control against Bleichenbacher's chosen-ciphertext attack, and not an OASIS rejection: SAML V2.0 cites XML Encryption 1.0, whose §5.1 requires RSA-v1.5. XML Encryption 1.1 §6.1.3 says implementations `SHOULD` restrict algorithm usage to those secure against chosen-ciphertext attacks, and OpenSAML's default decryption configuration excludes RSA-v1.5 |
| RSA-OAEP key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::RsaOaepMgf1p` is the default. FIPS does not use its SHA-1 MGF1 |
| RSA key-transport decryption on RustCrypto | Service provider | Decrypt `EncryptedAssertion` | Library policy, unchanged. RSA-v1.5 and RSA-OAEP decryption on RustCrypto need `XmlEncryptionPolicy::with_insecure_software_rsa_key_transport_decryption_allowed` because that backend is affected by `RUSTSEC-2023-0071` |
| AES-128-GCM and a backend URI | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Optional. Errata 05 E50. `DataEncryptionAlgorithm::Aes128Gcm` and `Custom` |
