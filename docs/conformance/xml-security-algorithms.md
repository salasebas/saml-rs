# XML Signature and XML Encryption algorithms

The algorithms a typed identity provider and service provider sign, verify,
encrypt, and decrypt with. `AlgorithmPolicy` selects what is generated. It is
not a field of `SpValidationPolicy` or `IdpValidationPolicy`, so Recommended
does not change it. `AlgorithmPolicy::default()` is what
`Default` and the config builders use: RSA-SHA256 with a
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
set. Neither build implements the full HTTP-Redirect `SigAlg` requirement of
Bindings §3.4.4.1 because neither signs RSAwithSHA1 or DSAwithSHA1.
RSA-v1.5 decryption is disabled by default even on a build that supports it.
See the [provider matrix](#provider-supported-set).

The signer's algorithm applies to every message it signs: the `AuthnRequest`,
the `Response`, and logout messages. It is the XML-DSig `SignatureMethod` on
HTTP-POST and SOAP, and the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. The
encryption algorithms apply to `EncryptedAssertion`, `EncryptedID`,
`EncryptedAttribute`, and `NewEncryptedID`. The rows below name
`EncryptedAssertion` for all four.

## XML Signature

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| SHA-1 digest | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. The SHA-1 signature algorithms, including `SignatureAlgorithm::HmacSha1`, select this digest. Verified under `XmlSignatureProfile::ExcludeWeakAlgorithms`, the value Recommended uses, and under `AllowWeakAlgorithms`. `StrictRsaSha2` is library hardening and rejects it |
| RSAwithSHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1, and Bindings §3.4.4.1 signature rule 5 for the HTTP-Redirect `SigAlg`. `SignatureAlgorithm::RsaSha1` selects it. It is never the default. AWS-LC and FIPS do not sign with it. FIPS does not verify it. Neither meets the HTTP-Redirect rule |
| DSAwithSHA1 | Identity provider and service provider | Sign and verify | Recommendation to implement in Conformance §4.1. Mandatory to implement for the HTTP-Redirect `SigAlg`: Bindings §3.4.4.1 signature rule 5. `SignatureAlgorithm::DsaSha1` selects it with a DSA signing key, and a DSA certificate in the peer's metadata verifies it. It is never the default, on the same library policy as the SHA-1 digest. RustCrypto with `crypto-legacy-algorithms` only, so the default build meets the HTTP-Redirect rule, and `crypto-aws-lc`, `crypto-fips`, and RustCrypto without `crypto-legacy-algorithms` do not |
| HMAC-SHA1 | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `SignatureAlgorithm::HmacSha1` signs with the secret of `Credentials::with_hmac_secret`, and the signature carries no `KeyInfo`. The verifier sets the same secret with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`, next to the peer's metadata certificates. SAML metadata has no shared-secret key, so the secret is exchanged out of band. Metadata signatures are not verified with it |
| An HMAC secret is at least 20 bytes | Identity provider and service provider | Configure signing and verification | Library policy. RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. `HmacSecret::try_new` rejects a shorter secret with `SamlError::Invalid`. It is local configuration and does not reject a message |
| Canonical XML 1.0 without comments | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::CanonicalXml` puts it in `signed_reference_transforms`, for the messages in the row below. `SignedInfo` is canonicalized with exclusive canonicalization. Verification accepts it on `SignedInfo` and on a reference under `ExcludeWeakAlgorithms` and `AllowWeakAlgorithms`. `StrictRsaSha2` rejects it |
| Enveloped-signature transform | Identity provider and service provider | Sign and verify | Mandatory to implement. Conformance §4.1. `TransformAlgorithm::EnvelopedSignature` is the first default transform |
| A message carried in SOAP keeps exclusive canonicalization | Identity provider and service provider | Generate Response and logout messages | Library behaviour. `signed_reference_transforms` applies to the `AuthnRequest`, to `respond_sso` and `initiate_sso`, and to logout messages on HTTP-POST. `respond_sso_artifact`, `initiate_sso_artifact`, `respond_paos_sso`, and logout messages over SOAP keep the enveloped-signature and exclusive canonicalization transforms. Each message is signed before it is placed in a SOAP envelope, and Canonical XML would take the envelope's namespace declarations into the digest of a verifier that checks the signature in place |
| RSA-SHA256, RSA-SHA384, RSA-SHA512, and a backend URI | Identity provider and service provider | Sign and verify | Optional. Errata 05 E50. `SignatureAlgorithm::RsaSha256` is the default. `SignatureAlgorithm::Custom` passes a URI to the provider |

## Inbound XML signature verification

A verifier accepts the `SignatureMethod` and `DigestMethod` values that the
selected provider implements, that the peer's key can verify, and that the
`XmlSignatureProfile` allows. `XmlSignatureProfile` is the `xml_signatures`
field of `SpValidationPolicy` and `IdpValidationPolicy`. Recommended uses
`ExcludeWeakAlgorithms`, and `AllowWeakAlgorithms` relaxes it. Accepting an algorithm outside the
Conformance §4.1 set is the Errata 05 E50 `MAY`. No profile is an OASIS
receiver rule.

The key is a signing certificate in the peer's metadata, or the secret set
with `IdpDescriptor::with_hmac_secret` or `SpDescriptor::with_hmac_secret`.
An algorithm verifies only with a key of its family: RSA for RSA and RSA-PSS,
EC for ECDSA, Ed25519, DSA, the HMAC secret for HMAC, and an ML-DSA or SLH-DSA
key of the same parameter set.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| An embedded signature on a received `Response`, `Assertion`, or logout message is verified under `xml_signatures` | Accepting service provider | Inbound | Optional. Errata 05 E50. `AllowWeakAlgorithms` accepts the provider-supported set below. `ExcludeWeakAlgorithms` accepts that set without the [weak algorithms and keys](#weak-algorithms-and-keys). `StrictRsaSha2` is library hardening. A signature over the accepted content must use RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, exclusive canonicalization, and only the enveloped-signature and exclusive canonicalization transforms. Otherwise it is rejected with `SamlError::AlgorithmUnsupported` |
| An embedded signature on a received `AuthnRequest` or logout message is verified under `xml_signatures` | Identity provider | Inbound | Optional. Errata 05 E50. The same profiles as the row above |
| A detached `SigAlg` signature is verified under `xml_signatures` | Identity provider and service provider | Inbound HTTP-Redirect and HTTP-POST-SimpleSign | Optional. Errata 05 E50. `AllowWeakAlgorithms` accepts any `SigAlg` in the provider-supported set. `ExcludeWeakAlgorithms` excludes the [weak algorithms and keys](#weak-algorithms-and-keys). `StrictRsaSha2` is library hardening and accepts RSA-SHA256, RSA-SHA384, or RSA-SHA512. Another `SigAlg` is rejected with `SamlError::AlgorithmUnsupported` before the signature is verified. A verifier that selects `StrictRsaSha2` does not meet Bindings §3.4.4.1 signature rule 5, which makes DSAwithSHA1 and RSAwithSHA1 mandatory for HTTP-Redirect |
| A signed metadata document is verified under `MetadataTrustPolicy` | Metadata consumer | Inbound typed descriptor import | Optional. Errata 05 E50, and E81 for Metadata §3.1.1. `RequireSignature` and `RequireSignatureAllowingOtherCanonicalization` accept the provider-supported set without the [weak algorithms and keys](#weak-algorithms-and-keys). `RequireSignatureAllowingWeakAlgorithms` accepts the provider-supported set. The raw `verify_metadata_signature` functions and `Metadata::verify_signature` accept the provider-supported set |

### HMAC truncation

These rules apply when an identity provider or service provider verifies an
enveloped HMAC XML signature with a configured peer secret and a provider
that supports the selected algorithm. They apply under every profile that
allows the algorithm.

| Rule | Level |
| --- | --- |
| An explicit `ds:HMACOutputLength` must be at least half the hash output length and at least 80 bits | Mandatory for the verifier. [XML Signature 1.1 §§4.4.2 and 6.3.1](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureMethod). This requires 192 bits for HMAC-SHA384 and 256 bits for HMAC-SHA512 |
| An explicit `ds:HMACOutputLength` must be at least 160 bits | Library policy. A lower floor would let a peer choose a shorter tag and reduce the number of bits an attacker must guess for an accepted signature |

Omitting `ds:HMACOutputLength` requests the full MAC. Detached signatures
use a separate verifier and have no `ds:HMACOutputLength` parameter.

### Reference and coverage processing

This section covers inbound embedded-signature processing in the public XML
verification functions and the internal verifier used by the typed flows.
It does not claim conformance with an entire SAML profile or binding.

| Rule | Actor and condition | Scope and basis |
| --- | --- | --- |
| References in every processed signature stay within the input document | Library verifier, before resolving references or executing transforms, including optional signatures outside SAML candidate positions | Library policy. Core §5.4.2 requires a SAML signer to reference the ID of the signed assertion or protocol message. It does not require a receiver to reject every extension signature with other references. Rejecting such references before processing prevents local-file resolution by the dependency |
| Strict-profile reference transforms are checked before processing | Library verifier using `StrictRsaSha2`, for every processed signature, including invalid and unrelated signatures | Library policy beyond Core §5.4.4's permission to reject other transforms. Other profiles keep their existing transform handling. The strict profile allows only XML-DSig enveloped-signature and exclusive canonicalization transforms |
| Public verification success includes covered content | Library verifier, after cryptographic verification | Library API contract. Assertion-bearing protocol responses retain their existing direct-Assertion coverage and extraction rules. Other documents require root coverage. A signature over a different sibling object is insufficient |

The [protocol schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd)
places optional `ds:Signature` and `samlp:Extensions` children on
`RequestAbstractType` and `StatusResponseType`. `ExtensionsType` permits
foreign-namespace elements with lax processing. Signature placement alone
therefore does not describe every XML-DSig signature the dependency processes.

[Core §§5.4.2–5.4.4](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
distinguish the signed assertion or protocol message from its XML container.
For SAML signature verifiers, §5.4.4 requires preservation of message content
when other transforms are accepted. The preflight restrictions above are
implementation controls, not a new receiver `MUST` inferred from signer rules.
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html)
E91's Object recommendation remains enforced by the existing profiles after
verification. E93's correction to Profiles §4.1.3.5 permits a signed Assertion
or Response for HTTP-POST browser SSO. This change preserves that choice.

The pinned `bergshamra-dsig` 0.12.0
[`DsigContext`](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-dsig/src/context.rs)
has no option to disable relative-file references. Its
[`verify` source](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-dsig/src/verify.rs)
resolves references and executes transforms before verifying `SignatureValue`.
The first-signature function processes the first XML-DSig descendant in
document order. The all-signatures function processes every XML-DSig
descendant and turns individual processing failures into invalid results.
Preflight uses the same namespace-aware dependency DOM and document order.

### Weak algorithms and keys

`ExcludeWeakAlgorithms` and `StrictRsaSha2` exclude these from the signatures
they cover. `AllowWeakAlgorithms` re-allows them where the
build verifies them. Signed metadata import excludes them under
`MetadataTrustPolicy::RequireSignature` and
`RequireSignatureAllowingOtherCanonicalization`, and
`RequireSignatureAllowingWeakAlgorithms` re-allows them.

| Excluded | Rule | Level |
| --- | --- | --- |
| RSA-MD5, HMAC-MD5, and the MD5 digest | A verified signature that authenticates the accepted message, a detached `SigAlg`, or a verified metadata signature that uses one is rejected with `SamlError::AlgorithmUnsupported` | Library policy, on in Recommended for both roles and in signed metadata import. No OASIS rule requires a receiver to reject them. XML Signature 1.1 §6.2 says MD5 `SHOULD NOT` be used in `DigestMethod`, a rule on use. OpenSAML excludes these three URIs in `DefaultSecurityConfigurationBootstrap.buildDefaultSignatureValidationConfiguration`, and xmlsec1 has built without MD5 by default since 1.3.0 |
| RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-RIPEMD160, and the RIPEMD-160 digest | As above | Library policy, on in Recommended for both roles and in signed metadata import. No OASIS rule requires a receiver to reject them. The default excludes RIPEMD-160 for limited provider support. Conformance §4.1 does not require it. xmlsec1 has built without RIPEMD-160 by default since 1.3.7, and the AWS-LC and FIPS providers do not verify them. OpenSAML does not exclude them |
| An RSA signing certificate with a modulus shorter than 2048 bits | The verifier skips the certificate and tries the peer's other keys. Without a usable key, verification returns `SamlError::Crypto`. The same key filter applies to a pinned metadata signing certificate | Library policy. Both roles use the same RSA minimum for inbound embedded and detached message signatures so that enabling legacy algorithms on RustCrypto cannot weaken the default below the AWS-LC and FIPS minimum. Signed metadata import has a separate [trust-root rationale](metadata-and-replay.md#metadata-trust) |

The IdP and SP rely on message signatures to authenticate current requests,
responses, and assertions. [NIST SP 800-131A Rev. 2 §3, Table 2](https://doi.org/10.6028/NIST.SP.800-131Ar2)
classifies RSA verification with a 1024–2047-bit modulus as legacy use
and verification with at least 2048 bits as acceptable.
[XML Signature 1.1 §6.4.2](https://www.w3.org/TR/xmldsig-core1/#sec-RSA)
permits verification of signatures from older systems with keys of 1024 bits
or less. SAML Conformance §4.1 and Errata 05 E50 and E81 address algorithm
support. Neither they nor the [XML Signature schema](https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd)
set a minimum RSA modulus length for a SAML receiver. OpenSAML sets no minimum.

On RustCrypto with `crypto-legacy-algorithms`, `AllowWeakAlgorithms` also
permits the other excluded algorithms. An SP processing a browser SSO response
still rejects a signature on the Response or Assertion that fails verification
under that profile (Profiles §4.1.4.3).

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
`SsoSession::binding_signature_algorithm_uri` the accepted detached
`SigAlg`. Neither applies an allowlist.

### Provider-supported set

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms` and `crypto-post-quantum`. A row marked Legacy
needs `crypto-legacy-algorithms`, and a row marked Post-quantum needs
`crypto-post-quantum`. A signature with an algorithm the build does not
verify does not verify. For a message signature, an RSA key of 1024 to 2047
bits verifies only on RustCrypto with `crypto-legacy-algorithms`, and only
under `AllowWeakAlgorithms`. For typed metadata import it
verifies on that build only under
`RequireSignatureAllowingWeakAlgorithms`. The raw metadata
verification functions accept it there. RustCrypto without it, AWS-LC, and
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

The SP's `RequireForEncryptedCbc` check and the IdP's unsigned requested-subject
GCM check read the namespace-complete canonicalized wrapper sent to bergshamra.
They use its first XML Encryption `EncryptedData` and first child XML Encryption
`EncryptionMethod`, and Uppsala's local-name attribute lookup. Namespace
declarations are separate from attributes. AES-192-CBC joins AES-128-CBC,
AES-256-CBC, and Triple DES under the relying-party recommendation in
[Approved Errata 05 E93](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html).
The actor is the relying party processing CBC-encrypted assertions or their
encrypted children; the recommendation requires integrity protection before
decryption. Recommended implements it for inbound browser SSO with
`RequireForEncryptedCbc`; `AllowUnsignedEncryptedCbc` explicitly relaxes it.
Missing methods return `Crypto` and unknown assertion data algorithms return
`Unsupported` under `RequireForEncryptedCbc`.

Inbound decryption also applies the configurable library resource allowance
`XmlEncryptionPolicy::max_decryption_work`, defaulting to
`constants::DEFAULT_MAX_DECRYPTION_WORK` (16). Across the document, each
`xenc:EncryptedData`, `xenc:EncryptedKey`, and `xenc11:DerivedKey` costs one
unit per configured decryption key. Revealed encrypted content shares the
allowance before subsequent decryption. Excess work returns
`SamlError::LimitExceeded` with `ResourceLimit::DecryptionWork`, including for
signed messages and explicit CBC or RSA-v1.5 relaxations. This is library
resource policy beyond Core's encrypted-element rules and Conformance §4.2,
not an OASIS receiver obligation. It bounds unauthenticated key resolution
and key-rollover retries that XML byte limits alone do not bound.
The default is not a standard-prescribed number or a CPU-time guarantee.
XML Encryption 1.0 [§6.4](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#sec-Denial)
recommends restricting total processing resources without a numeric threshold.
Applications may raise or lower the finite allowance; zero refuses encrypted
input. Rate and concurrency controls remain deployment responsibilities.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Triple DES block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::TripleDesCbc` selects it. It is a CBC mode, so the Errata 05 E93 Response signature applies. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS |
| AES-128 and AES-256 block encryption | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `DataEncryptionAlgorithm::Aes256Cbc` is the default. `Aes128Cbc` selects AES-128 |
| RSA-v1.5 key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::Rsa15` selects it. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS. XML Encryption 1.1 §5.5.1 makes it optional and says its implementation is `NOT RECOMMENDED`, which supports generating it only when selected. An entity decrypts it, in any encrypted element it receives, only when `XmlEncryptionPolicy::rsa15_key_transport` is `Rsa15KeyTransportPolicy::AllowDecryption`. Without it, an `EncryptionMethod` that names RSA-v1.5 is rejected with `SamlError::Unsupported` before any key is decrypted. That refusal is library policy, an implementation-security control against Bleichenbacher's chosen-ciphertext attack, and not an OASIS rejection: SAML V2.0 cites XML Encryption 1.0, whose §5.1 requires RSA-v1.5. XML Encryption 1.1 §6.1.3 says implementations `SHOULD` restrict algorithm usage to those secure against chosen-ciphertext attacks, and OpenSAML's default decryption configuration excludes RSA-v1.5 |
| RSA-OAEP key transport | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Mandatory to implement. Conformance §4.2. `KeyEncryptionAlgorithm::RsaOaepMgf1p` is the default. An entity decrypts it with the default options on RustCrypto and AWS-LC. FIPS does not use its SHA-1 MGF1 |
| AES-128-GCM, AES-256-GCM, and a backend URI | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Optional. Errata 05 E50 and [XML Encryption 1.1 §5.2.4](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-AES-GCM). `DataEncryptionAlgorithm::Aes128Gcm`, `Aes256Gcm`, and `Custom`. Both named GCM algorithms work on RustCrypto, AWS-LC, and FIPS |
| XML Encryption 1.1 RSA-OAEP with explicit digest and MGF | Identity provider, and the service provider that decrypts | Encrypt and decrypt `EncryptedAssertion` | Optional. Errata 05 E50 and [XML Encryption 1.1 §5.5.2](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-RSA-OAEP). `KeyEncryptionAlgorithm::RsaOaep { digest, mgf }` writes `ds:DigestMethod` and `xenc11:MGF` under the key's `EncryptionMethod`. SHA-256, SHA-384, and SHA-512 with the matching `MaskGenerationFunction` work on RustCrypto, AWS-LC, and FIPS. RustCrypto also supports independent digest and MGF hashes. Both config builders reject unsupported parameters with `SamlError::Unsupported`; a build without a crypto provider rejects either new named algorithm. Existing defaults and `Custom` URI handling are unchanged |
