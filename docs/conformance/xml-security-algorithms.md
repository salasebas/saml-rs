# XML Signature and XML Encryption algorithms

`AlgorithmPolicy` selects the algorithms a typed `IdentityProvider` and
`ServiceProvider` sign and encrypt with. `XmlSignatureProfile` selects the
signature algorithms they verify, and `XmlEncryptionPolicy` bounds decryption.
Normative text is Conformance Requirements §4, as clarified by Approved Errata
05 E50: §4.1 and §4.2 list the algorithms a compliant implementation `MUST`
implement, E50 calls that list the minimal set, and other algorithms `MAY` be
used. E81 replaces the Core §5.4.1 RSA-SHA1 sentence with the same permission.
This page claims neither operational mode, and Conformance §5 (TLS) is not on it.

The signature algorithm is the XML-DSig `SignatureMethod` on HTTP-POST and
SOAP, and the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. Encryption
algorithms apply to `EncryptedAssertion`, `EncryptedID`, `EncryptedAttribute`,
and `NewEncryptedID`. The rows name `EncryptedAssertion` for all four.

## XML Signature

The identity provider and service provider sign and verify. Algorithms that
the AWS-LC and FIPS builds lack are in the
[provider matrix](#provider-supported-set).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Sign with RSA-SHA256, a SHA-256 digest, and the enveloped-signature and exclusive canonicalization transforms | Library policy: reason not recorded. | Conformance §4.1 | `AlgorithmPolicy::default()` |
| Generate a SHA-1 signature (RSAwithSHA1, DSAwithSHA1, HMAC-SHA1) only when the caller selects it | Library policy: reason not recorded. | Conformance §4.1 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Sign and verify with the SHA-1 digest. The SHA-1 signature algorithms select it | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Sign and verify RSAwithSHA1. AWS-LC and FIPS do not sign with it, and FIPS does not verify it | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1` |
| Sign and verify DSAwithSHA1 with a DSA key, and a DSA certificate in the peer's metadata. Needs RustCrypto with `crypto-legacy-algorithms` | Recommended | Conformance §4.1 | `SignatureAlgorithm::DsaSha1` |
| Support RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. The default build does. AWS-LC and FIPS sign neither, and RustCrypto without `crypto-legacy-algorithms` lacks DSAwithSHA1 | Mandatory | Bindings §3.4.4.1, CD-04 §2.5 | `SignatureAlgorithm::RsaSha1`, `DsaSha1` |
| Implement HMAC-SHA1 signing and verification for messages | Mandatory | Conformance §4.1 | `SignatureAlgorithm::HmacSha1`, `Credentials::with_hmac_secret`, `IdpDescriptor::with_hmac_secret`, `SpDescriptor::with_hmac_secret` |
| Reject an HMAC secret shorter than 20 bytes. It is configuration and does not reject a message | Library policy: RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. | RFC 2104 §3 | `HmacSecret::try_new` |
| Sign and verify Canonical XML 1.0 without comments as a reference transform. `SignedInfo` is canonicalized with exclusive canonicalization. Verification accepts it on `SignedInfo` and on a reference under `ExcludeWeakAlgorithms` and `AllowWeakAlgorithms` | Mandatory | Conformance §4.1 | `TransformAlgorithm::CanonicalXml` in `signed_reference_transforms` |
| Sign and verify with the enveloped-signature transform | Mandatory | Conformance §4.1 | `TransformAlgorithm::EnvelopedSignature`, the first default transform |
| Sign `respond_sso_artifact`, `initiate_sso_artifact`, `respond_paos_sso`, and SOAP logout messages with the enveloped-signature and exclusive canonicalization transforms only | Library policy: Canonical XML would put the SOAP envelope's namespace declarations into the digest of a verifier that checks in place. | — | Always |
| Sign with RSA-SHA256, RSA-SHA384, or RSA-SHA512 | Optional | E50 | `SignatureAlgorithm::RsaSha256` (default), `RsaSha384`, `RsaSha512` |
| Sign with a custom URI. A detached signature accepts any URI the provider supports. An embedded signature needs a digest for the URI, which only the `SignatureAlgorithm` URIs and `signature_algorithm::RSA_SHA256_MGF1` have. Any other URI fails to sign | Optional | E50 | `SignatureAlgorithm::Custom` |

Peers configure an HMAC shared secret out of band. Generated HMAC signatures
omit `KeyInfo`. Typed metadata import verifies with pinned certificates, not
the secret. `AlgorithmPolicy::signed_reference_transforms` applies to embedded
`AuthnRequest` signatures, responses from `respond_sso` and `initiate_sso`, and
HTTP-POST logout messages.

## Inbound XML signature verification

A verifier accepts the `SignatureMethod` and `DigestMethod` values that the
selected provider implements, that the peer's key can verify, and that
`XmlSignatureProfile` allows. `XmlSignatureProfile` is the `xml_signatures`
field of `SpValidationPolicy` and `IdpValidationPolicy`, and Recommended uses
`ExcludeWeakAlgorithms`. Accepting an algorithm outside the Conformance §4.1
set is the E50 `MAY`. No profile is an OASIS receiver rule.
`ExcludeWeakAlgorithms` permits the SHA-1 digest and RSAwithSHA1 when the
provider implements them.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Allow additional provider-supported algorithms when verifying an embedded signature on a received `Response`, `Assertion`, or logout message (service provider), or `AuthnRequest` or logout message (identity provider). `ExcludeWeakAlgorithms` leaves out the [weak algorithms](#weak-algorithms-and-keys). `AllowWeakAlgorithms` accepts the provider-supported set | Optional | E50 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `AllowWeakAlgorithms` |
| Allow additional provider-supported algorithms when verifying a detached `SigAlg` signature on HTTP-Redirect and HTTP-POST-SimpleSign. `ExcludeWeakAlgorithms` leaves out the weak algorithms and keys. `AllowWeakAlgorithms` accepts any `SigAlg` in the provider-supported set | Optional | E50 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `AllowWeakAlgorithms` |
| Allow additional provider-supported algorithms when verifying a pinned metadata signature. `RequireSignature` and `RequireSignatureAllowingOtherCanonicalization` leave out the weak algorithms and keys. `RequireSignatureAllowingWeakAlgorithms` accepts the provider-supported set | Optional | E50, E81 | `MetadataTrustPolicy::RequireSignature`, `RequireSignatureAllowingOtherCanonicalization`, `RequireSignatureAllowingWeakAlgorithms` |
| Accept an embedded signature only with RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, exclusive canonicalization, and the enveloped-signature and exclusive canonicalization transforms. This rejects the SHA-1 digest and Canonical XML 1.0 | Library policy: reason not recorded. | E50 | `XmlSignatureProfile::StrictRsaSha2` |
| Accept a detached `SigAlg` only when it is RSA-SHA256, RSA-SHA384, or RSA-SHA512, and reject another before verifying the signature. This profile omits both SHA-1 algorithms required by those bindings | Library policy: reason not recorded. | Bindings §3.4.4.1, CD-04 §2.5 | `XmlSignatureProfile::StrictRsaSha2` |

### HMAC truncation

These rules apply when an identity provider or service provider verifies an
enveloped HMAC XML signature with a configured peer secret, under every profile
that allows the algorithm. Omitting `ds:HMACOutputLength` requests the full MAC.
Detached signatures use a separate verifier and have no such parameter.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an explicit `ds:HMACOutputLength` below half the hash output length or below 80 bits. This requires 192 bits for HMAC-SHA384 and 256 bits for HMAC-SHA512 | Mandatory | XMLDSig 1.1 §4.4.2, §6.3.1 | Always |
| Reject an explicit `ds:HMACOutputLength` below 160 bits | Library policy: a lower floor would let a peer choose a shorter tag and reduce the number of bits an attacker must guess for an accepted signature. | XMLDSig 1.1 §6.3.1 | Always |

### Reference and coverage processing

This section covers inbound embedded-signature processing in the typed flows.
It does not claim conformance with an entire SAML profile or binding. The
protocol schema places optional `ds:Signature` and `samlp:Extensions` children
on `RequestAbstractType` and `StatusResponseType`, and `ExtensionsType` permits
foreign-namespace elements with lax processing. Signature placement alone
therefore does not describe every XML-DSig signature the verifier processes.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject a reference outside the input document in every processed signature, including an optional signature outside the SAML candidate positions, before resolving references or executing transforms | Library policy: Core §5.4.2 binds a signer, not a receiver, and the dependency would resolve local files. | Core §5.4.2 | Always |
| Check the reference transforms of each processed signature before processing, even an invalid or unrelated one, and allow only the enveloped-signature and exclusive canonicalization transforms. Other profiles keep their existing handling | Library policy: beyond Core §5.4.4's permission to reject other transforms, and the dependency executes transforms before it verifies `SignatureValue`. | Core §5.4.4 | `XmlSignatureProfile::StrictRsaSha2` |
| Count a signature as verified only when it covers the accepted content. Assertion-bearing protocol responses keep their direct-Assertion coverage and extraction rules. Other documents require root coverage, and a signature over a different sibling object is insufficient | Library policy: a verification success is an API contract that the accepted content is covered. | — | Always |
| Protect every HTTP-POST browser SSO assertion with a signature on the `Response` or on each individual `Assertion` | Mandatory | Profiles §4.1.4.5, E26, E93 | Always |
| Reject a signature that authenticates the message and contains a `ds:Object` | Recommended | E91 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `StrictRsaSha2`. `AllowWeakAlgorithms` relaxes it |

Core §5.4.4 requires a verifier that accepts other transforms to keep every
part of the SAML message in the signature. The preflight restrictions are
implementation controls, not a new receiver `MUST` inferred from signer rules.

### Weak algorithms and keys

`ExcludeWeakAlgorithms` and `StrictRsaSha2` exclude these from the signatures
they cover, and signed metadata import excludes them under `RequireSignature`
and `RequireSignatureAllowingOtherCanonicalization`.
`XmlSignatureProfile::AllowWeakAlgorithms` and
`MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` re-allow them
where the build verifies them. Recommended excludes them for both roles.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an embedded signature that authenticates accepted content, a detached `SigAlg`, or a verified metadata signature that uses RSA-MD5, HMAC-MD5, or the MD5 digest | Library policy: XMLDSig 1.1 §6.2 says MD5 `SHOULD NOT` be used in `DigestMethod`, a rule on use, and no OASIS rule has a receiver reject it. | XMLDSig 1.1 §6.2 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
| Reject the same for RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-RIPEMD160, and the RIPEMD-160 digest | Library policy: provider support is limited, and Conformance §4.1 does not require it. | Conformance §4.1 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
| Do not verify with an RSA key shorter than 2048 bits. Skip the certificate, so a message only that key could verify is rejected | Library policy: the identity provider and service provider authenticate current messages, and NIST SP 800-131A Rev. 2 §3 Table 2 classifies 1024-bit to 2047-bit RSA keys as legacy. | XMLDSig 1.1 §6.4.2 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |

Pinned metadata keys have the same floor for a separate
[trust-root reason](metadata-and-replay.md#metadata-trust). Only
`AllowWeakAlgorithms` on RustCrypto with `crypto-legacy-algorithms` accepts
a short key. It also permits MD5, RIPEMD-160, and `ds:Object`, which can carry
unsigned data. An invalid Response or Assertion signature still causes the
service provider to reject the browser SSO response (Profiles §4.1.4.3).

### Provider-supported set

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms` and `crypto-post-quantum`. A row marked Legacy needs
`crypto-legacy-algorithms`, and a row marked Post-quantum needs
`crypto-post-quantum`. A signature with an algorithm the build does not verify
does not verify. An RSA key of 1024 to 2047 bits verifies only on RustCrypto
with `crypto-legacy-algorithms`, for a message signature under
`AllowWeakAlgorithms` and for typed metadata import under
`RequireSignatureAllowingWeakAlgorithms`. An RSA key shorter than 1024 bits
verifies on no build.

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

For assertion delivery, the identity provider encrypts and the service
provider decrypts. In name identifier management, either role can encrypt
identifiers for its peer. The decryption rules apply to every encrypted element
an entity receives.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Encrypt and decrypt with AES-128 and AES-256 block encryption | Mandatory | Conformance §4.2 | `DataEncryptionAlgorithm::Aes128Cbc`, `Aes256Cbc` (default) |
| Encrypt and decrypt with Triple DES block encryption. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS | Mandatory | Conformance §4.2 | `DataEncryptionAlgorithm::TripleDesCbc` |
| Encrypt and decrypt with RSA-OAEP key transport. Decryption with the default options works on RustCrypto and AWS-LC. FIPS does not use its SHA-1 MGF1 | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::RsaOaepMgf1p` (default) |
| Encrypt and decrypt with RSA-v1.5 key transport. Needs `crypto-legacy-algorithms`. Not on AWS-LC or FIPS | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::Rsa15` |
| Generate Triple DES and RSA-v1.5 only when the caller selects them | Library policy: Conformance §4 does not say which algorithm a producer selects, and XML Encryption 1.1 §5.5.1 makes RSA-v1.5 optional and `NOT RECOMMENDED`. | Conformance §4.2 | `DataEncryptionAlgorithm::TripleDesCbc`, `KeyEncryptionAlgorithm::Rsa15` |
| Decrypt RSA-v1.5 only when allowed. Otherwise reject an `EncryptionMethod` that names it before any key is decrypted | Library policy: Bleichenbacher's chosen-ciphertext attack, and no OASIS rule rejects it, because SAML V2.0 cites XML Encryption 1.0, whose §5.1 requires RSA-v1.5. | XML Encryption 1.1 §6.1.3 | `XmlEncryptionPolicy::rsa15_key_transport`, `Rsa15KeyTransportPolicy::AllowDecryption` |
| Encrypt and decrypt with AES-128-GCM and AES-256-GCM on RustCrypto, AWS-LC, and FIPS. Forward a custom URI to the provider | Optional | E50, XML Encryption 1.1 §5.2.4 | `DataEncryptionAlgorithm::Aes128Gcm`, `Aes256Gcm`, `Custom` |
| Write `ds:DigestMethod` and `xenc11:MGF` under the key's `EncryptionMethod`. SHA-256, SHA-384, and SHA-512 with the matching `MaskGenerationFunction` work on all providers, and RustCrypto also supports independent hashes. With a crypto provider, the config builders reject unsupported parameters | Optional | E50, XML Encryption 1.1 §5.5.2 | `KeyEncryptionAlgorithm::RsaOaep { digest, mgf }` |
| Require a signed `Response` before the service provider processes an `EncryptedAssertion` encrypted with AES-128-CBC, AES-192-CBC, AES-256-CBC, or Triple DES, in inbound browser SSO | Recommended | Core §6.2, Profiles §4.1.3.5, §4.1.4.3, E93 | `ResponseSignaturePolicy::RequireForEncryptedCbc`. `AllowUnsignedEncryptedCbc` relaxes it |
| Reject an `EncryptedAssertion` with a missing or unrecognized data-encryption algorithm | Library policy: the service provider cannot tell whether the ciphertext is CBC. | Core §6.2, E93 | `ResponseSignaturePolicy::RequireForEncryptedCbc` |
| Verify a signature that covers a CBC-encrypted `EncryptedID` or `EncryptedAttribute` in an assertion before decrypting it | Recommended | Core §6.2, E93 | Always |
| Require that covering signature for every other data-encryption algorithm too | Library policy: reason not recorded. | Core §6.2, E93 | Always |
| Decrypt the `EncryptedID` in the requested `Subject` of an unauthenticated `AuthnRequest` only when its `EncryptedData` is AES-GCM | Library policy: an unsigned request is allowed by Profiles §4.1.4.1, and AES-GCM authenticates the ciphertext where E93 asks for integrity protection before CBC. | Profiles §4.1.4.1, E93 | Always |
| Charge each `xenc:EncryptedData`, `xenc:EncryptedKey`, and `xenc11:DerivedKey` one unit per configured decryption key against a per-message allowance of 16 by default, shared with revealed encrypted content. Zero refuses encrypted input | Library policy: it bounds unauthenticated key resolution and key-rollover retries that XML byte limits alone do not bound. | XML Encryption 1.0 §6.4 | `XmlEncryptionPolicy::max_decryption_work` |
