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
| SHA-1 digest | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. Generated only with `SignatureAlgorithm::RsaSha1` or `SignatureAlgorithm::DsaSha1`, which take their digest from the signature algorithm. Verified under `XmlSignatureProfile::ExcludeWeakAlgorithms`, the value Recommended uses, and under `AllowProviderSupportedForCompatibility`. `StrictRsaSha2` is library hardening and rejects it |
| RSAwithSHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `SignatureAlgorithm::RsaSha1` selects it. It is never the default. AWS-LC and FIPS do not sign with it. FIPS does not verify it |
| DSAwithSHA1 | Identity provider and service provider | Sign and verify | Recommendation to implement. Conformance §4.1. `SignatureAlgorithm::DsaSha1` selects it with a DSA signing key, and a DSA certificate in the peer's metadata verifies it. It is never the default, on the same library policy as the SHA-1 digest. RustCrypto with `crypto-legacy-algorithms` only |
| HMAC-SHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `SignatureAlgorithm::HmacSha1` signs with `Credentials::hmac_secret`, and the signature carries no `KeyInfo`. The verifier sets the same secret with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`, next to the peer's metadata certificates. SAML metadata has no shared-secret key, so the secret is exchanged out of band. Metadata signatures are not verified with it. The 160-bit minimum `HMACOutputLength` is existing library hardening |
| An HMAC secret is at least 20 bytes | Identity provider and service provider | Configure signing and verification | Library policy. RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. `HmacSecret::try_new` rejects a shorter secret with `SamlError::Invalid`. It is local configuration and does not reject a message |
| Canonical XML 1.0 without comments | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::CanonicalXml` puts it in `signed_reference_transforms`, for the messages in the row below. `SignedInfo` is canonicalized with exclusive canonicalization. Verification accepts it on `SignedInfo` and on a reference under `ExcludeWeakAlgorithms` and `AllowProviderSupportedForCompatibility`. `StrictRsaSha2` rejects it |
| Enveloped-signature transform | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::EnvelopedSignature` is the first default transform |
| A message carried in SOAP keeps exclusive canonicalization | Identity provider and service provider | Generate Response and logout messages | Library behaviour. `signed_reference_transforms` applies to the `AuthnRequest`, to `respond_sso` and `initiate_sso`, and to logout messages on HTTP-POST. `respond_sso_artifact`, `initiate_sso_artifact`, `respond_paos_sso`, and logout messages over SOAP keep the enveloped-signature and exclusive canonicalization transforms. Each message is signed before it is placed in a SOAP envelope, and Canonical XML would take the envelope's namespace declarations into the digest of a verifier that checks the signature in place |
| RSA-SHA256, RSA-SHA384, RSA-SHA512, and a backend URI | Identity provider and service provider | Sign and verify | Optional. Errata 05 E50. `SignatureAlgorithm::RsaSha256` is the default. `SignatureAlgorithm::Custom` passes a URI to the provider |

## Inbound XML signature verification

A verifier accepts the `SignatureMethod` and `DigestMethod` values that the
selected provider implements, that the peer's key can verify, and that the
`XmlSignatureProfile` allows. `XmlSignatureProfile` is the `xml_signatures`
field of `SpValidationPolicy` and `IdpValidationPolicy`. Recommended uses
`ExcludeWeakAlgorithms`. Compatibility uses
`AllowProviderSupportedForCompatibility`. Accepting an algorithm outside the
Conformance §4.1 set is the Errata 05 E50 `MAY`. No profile is an OASIS
receiver rule.

The key is a signing certificate in the peer's metadata, or the secret set
with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`.
An algorithm verifies only with a key of its family: RSA for RSA and RSA-PSS,
EC for ECDSA, Ed25519, DSA, the HMAC secret for HMAC, and an ML-DSA or SLH-DSA
key of the same parameter set.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An embedded signature on a received `Response`, `Assertion`, or logout message is verified under `xml_signatures` | Accepting service provider | Inbound | Optional. Errata 05 E50. `AllowProviderSupportedForCompatibility` accepts the provider-supported set below. `ExcludeWeakAlgorithms` accepts that set without the weak algorithms and keys in the next table. `StrictRsaSha2` is library hardening. A signature over the accepted content must use RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, exclusive canonicalization, and only the enveloped-signature and exclusive canonicalization transforms. Otherwise it is rejected with `SamlError::AlgorithmUnsupported` |
| An embedded signature on a received `AuthnRequest` or logout message is verified under `xml_signatures` | Identity provider | Inbound | Optional. Errata 05 E50. The same profiles as the row above |
| A detached `SigAlg` signature is verified under `xml_signatures` | Identity provider and service provider | Inbound HTTP-Redirect and HTTP-POST-SimpleSign | Optional. Errata 05 E50. `AllowProviderSupportedForCompatibility` accepts any `SigAlg` in the provider-supported set. `ExcludeWeakAlgorithms` excludes the weak algorithms and keys in the next table. `StrictRsaSha2` is library hardening and accepts RSA-SHA256, RSA-SHA384, or RSA-SHA512. Another `SigAlg` is rejected with `SamlError::AlgorithmUnsupported` before the signature is verified |
| A signed metadata document is verified under `MetadataTrustPolicy` | Metadata consumer | Inbound typed descriptor import | Optional. Errata 05 E50, and E81 for Metadata §3.1.1. `RequireSignature` and `RequireSignatureAllowingOtherCanonicalization` accept the provider-supported set without the weak algorithms and keys in the next table. `RequireSignatureAllowingWeakAlgorithmsForCompatibility` accepts the provider-supported set. The raw `verify_metadata_signature` functions and `Metadata::verify_signature` accept the provider-supported set |

### Weak algorithms and keys

`ExcludeWeakAlgorithms` and `StrictRsaSha2` exclude these from the signatures
they cover. `AllowProviderSupportedForCompatibility` re-allows them where the
build verifies them. Signed metadata import excludes them under
`MetadataTrustPolicy::RequireSignature` and
`RequireSignatureAllowingOtherCanonicalization`, and
`RequireSignatureAllowingWeakAlgorithmsForCompatibility` re-allows them.

| Excluded | Rule | Level |
| --- | --- | --- |
| RSA-MD5, HMAC-MD5, and the MD5 digest | A verified signature that authenticates the accepted message, a detached `SigAlg`, or a verified metadata signature that uses one is rejected with `SamlError::AlgorithmUnsupported` | Library policy, on in Recommended for both roles and in signed metadata import. No OASIS rule requires a receiver to reject them. XML Signature 1.1 §6.2 says MD5 `SHOULD NOT` be used in `DigestMethod`, a rule on use. OpenSAML excludes these three URIs in `DefaultSecurityConfigurationBootstrap.buildDefaultSignatureValidationConfiguration`, and xmlsec1 has built without MD5 by default since 1.3.0 |
| RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-RIPEMD160, and the RIPEMD-160 digest | As above | Library policy, on in Recommended for both roles and in signed metadata import. No OASIS rule requires a receiver to reject them. They are outside Conformance §4.1. xmlsec1 has built without RIPEMD-160 by default since 1.3.7, and the AWS-LC and FIPS providers do not verify them. OpenSAML does not exclude them |
| An RSA signing certificate shorter than 2048 bits | The certificate is not used to verify. When the peer has no other usable key, verification returns `SamlError::Crypto`, as it does on AWS-LC. Otherwise a message signed with the short key fails signature verification. A pinned metadata signing certificate is treated the same way | Library policy, on in Recommended for both roles and in signed metadata import. XML Signature 1.1 §6.4.2 lets a verifier use an RSA key of 1024 bits or less, and names 2048-bit public keys the minimum recommended key length. RustCrypto without `crypto-legacy-algorithms`, AWS-LC, and FIPS refuse it in every profile. OpenSAML sets no minimum |

SHA-1 stays accepted under `ExcludeWeakAlgorithms`: Conformance §4.1 makes the
SHA-1 digest and RSAwithSHA1 mandatory to implement, and OpenSAML and xmlsec1
verify them by default. `StrictRsaSha2` excludes
SHA-1 as well. A metadata signature is checked under `MetadataTrustPolicy`, not
`xml_signatures`.

The exclusion on signed metadata is stricter than OpenSAML's default there.
OpenSAML's `SignatureValidationFilter` passes the trust engine no
`SignatureValidationParametersCriterion`, so the default exclusions apply to a
metadata signature only when a deployment adds that criterion. The 2048-bit
floor matches the Shibboleth Metadata Aggregator's `X509RSAKeyLengthValidator`,
whose default is an error for an RSA key shorter than 2048 bits in a metadata
certificate.

`SsoSession::verified_xml_signatures` reports the `SignatureMethod` URI of each
verified signature over the Response root or the consumed Assertion, and
`SsoSession::sig_alg` the accepted detached `SigAlg`. Neither applies
an allowlist.

### Provider-supported set

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms` and `crypto-post-quantum`. A row marked Legacy
needs `crypto-legacy-algorithms`, and a row marked Post-quantum needs
`crypto-post-quantum`. A signature with an algorithm the build does not
verify does not verify. For a message signature, an RSA key of 1024 to 2047
bits verifies only on RustCrypto with `crypto-legacy-algorithms`, and only
under `AllowProviderSupportedForCompatibility`. For a metadata signature it
verifies on that build only under
`RequireSignatureAllowingWeakAlgorithmsForCompatibility`. RustCrypto without it, AWS-LC, and
FIPS reject it. An RSA key shorter than 1024 bits verifies on no build in any
profile.

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
| RSA-OAEP key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::RsaOaepMgf1p` is the default. An entity decrypts it with the default options on RustCrypto and AWS-LC. FIPS does not use its SHA-1 MGF1 |
| AES-128-GCM and a backend URI | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Optional. Errata 05 E50. `DataEncryptionAlgorithm::Aes128Gcm` and `Custom` |
