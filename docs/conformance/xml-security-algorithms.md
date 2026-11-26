# XML Signature and XML Encryption algorithms

`AlgorithmPolicy` selects the algorithms that a typed `IdentityProvider` and
`ServiceProvider` sign and encrypt with, `XmlSignatureProfile` selects the
signature algorithms they verify, and `XmlEncryptionPolicy` bounds
decryption. The signature algorithm is the XML-DSig `SignatureMethod` on
HTTP-POST and SOAP, and the `SigAlg` on HTTP-Redirect and
HTTP-POST-SimpleSign. Encryption covers `EncryptedAssertion`, `EncryptedID`,
`EncryptedAttribute`, and `NewEncryptedID`.

Normative text is [Conformance](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
§4.1 and §4.2, which list the algorithms that a compliant implementation
`MUST` implement, and Core §5.4 and §6. In
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/),
E50 calls that list the minimal set and lets other algorithms be used, and
E81 replaces the Core §5.4.1 RSA-SHA1 sentence with the same permission.
Bindings §3.4.4.1 and the HTTP-POST-SimpleSign
[Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html)
(CS-01) §2.5 name the `SigAlg` methods.
[XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) and XML Encryption
[1.0](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/) and
[1.1](https://www.w3.org/TR/xmlenc-core1/) define the algorithms. This record
claims neither operational mode, and Conformance §5 (TLS) is not in it.

<a id="builds-without-a-crypto-provider"></a>

The statuses hold on builds with a crypto provider. A build without one
neither signs nor verifies, and neither encrypts nor decrypts. Its config
builders refuse a policy that needs a crypto provider.

## Support

The identity provider and the service provider each sign, verify, encrypt,
and decrypt. For assertion delivery the identity provider encrypts and the
service provider decrypts, and in single logout and name identifier
management either role encrypts identifiers for its peer.

### XML Signature

| Feature | Section | Signer | Verifier |
| --- | --- | --- | --- |
| SHA-1 digest | Conformance §4.1 | [Partial](#signature-algorithms-by-build) | [Partial](#signature-algorithms-by-build) |
| HMAC-SHA1 | Conformance §4.1 | [Partial](#signature-algorithms-by-build) | [Partial](#signature-algorithms-by-build) |
| Canonical XML 1.0 without comments | Conformance §4.1 | Supported | Supported |
| Enveloped-signature transform | Conformance §4.1 | Supported | Supported |
| RSAwithSHA1 | Conformance §4.1 | [Partial](#signature-algorithms-by-build) | [Partial](#signature-algorithms-by-build) |
| DSAwithSHA1 | Conformance §4.1 | [Partial](#signature-algorithms-by-build) | [Partial](#signature-algorithms-by-build) |
| RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` of HTTP-Redirect and HTTP-POST-SimpleSign | Bindings §3.4.4.1, CS-01 §2.5 | [Partial](#signature-algorithms-by-build) | [Partial](#signature-algorithms-by-build) |
| Exclusive canonicalization without comments, in `SignedInfo` and as a reference transform | Core §5.4.3, E83 | Supported | Supported |
| RSA-SHA256, RSA-SHA384, and RSA-SHA512 | E50 | Supported | Supported |
| ECDSA-SHA256, ECDSA-SHA384, and ECDSA-SHA512 | E50, RFC 9231 §2.3.6 | [Partial](#generation-by-provider) | Supported |
| Ed25519 | E50, RFC 9231 §2.3.12 | [Partial](#generation-by-provider) | [Partial](#provider-supported-set) |
| Other signature and digest algorithms | E50, E81 | [Partial](#generation-by-provider) | [Partial](#provider-supported-set) |
| Explicit `HMACOutputLength` on an HMAC `SignatureMethod` | XMLDSig 1.1 §4.4.2, §6.3.1 | Not supported | Supported |

### XML Encryption

| Feature | Section | Encrypter | Decrypter |
| --- | --- | --- | --- |
| AES-128-CBC and AES-256-CBC | Conformance §4.2 | Supported | Supported |
| Triple DES CBC | Conformance §4.2 | [Partial](#encryption-algorithms-by-provider) | [Partial](#encryption-algorithms-by-provider) |
| RSA-v1.5 key transport | Conformance §4.2 | [Partial](#encryption-algorithms-by-provider) | [Partial](#encryption-algorithms-by-provider) |
| RSA-OAEP-MGF1P key transport | Conformance §4.2 | [Partial](#encryption-algorithms-by-provider) | [Partial](#encryption-algorithms-by-provider) |
| AES-128-GCM and AES-256-GCM | E50, XML Encryption 1.1 §5.2.4 | Supported | Supported |
| XML Encryption 1.1 RSA-OAEP with a SHA-256, SHA-384, or SHA-512 digest and MGF1 | E50, XML Encryption 1.1 §5.5.2 | [Partial](#encryption-algorithms-by-provider) | [Partial](#encryption-algorithms-by-provider) |
| Other encryption algorithms | E50 | [Partial](#encryption-algorithms-by-provider) | [Partial](#encryption-algorithms-by-provider) |
| `EncryptedKey` embedded in the `ds:KeyInfo` of `EncryptedData` | XML Encryption 1.0 §3.5.1, E43 | Supported | Supported |
| `ds:RetrievalMethod` that names an `EncryptedKey` inside the encrypted element | XML Encryption 1.0 §3.5.2, E43 | Not supported | Supported |
| `ds:RetrievalMethod` that names an `EncryptedKey` elsewhere in the message | XML Encryption 1.0 §3.5, E43 | Not supported | Not supported |
| A `ds:RetrievalMethod` after the first one whose reference resolves | XML Encryption 1.0 §3.5.2, E43 | — | Not supported |
| `ds:KeyName` that names an `EncryptedKey` by its `CarriedKeyName` | XML Encryption 1.0 §3.5, E43 | Not supported | Not supported |
| `EncryptedKey` beside `EncryptedData` without a `ds:RetrievalMethod` | E43 | Not supported | Not supported |
| `CipherReference` to ciphertext outside the encrypted element | XML Encryption 1.0 §3.3.1 | Not supported | Not supported |
| An error for `EncryptionMethod` content that its algorithm does not permit | XML Encryption 1.0 §3.2 | — | Not supported |

## Partial support

### Signature algorithms by build

- **Supported:** RustCrypto with `crypto-legacy-algorithms`, which the
  default build enables, signs and verifies every Conformance §4.1
  algorithm, the DSAwithSHA1 that it recommends, and both `SigAlg` methods of
  Bindings §3.4.4.1 and CS-01 §2.5.
- **Not supported:** the other builds lack what the table marks.
  `XmlSignatureProfile::StrictRsaSha2` refuses every SHA-1 algorithm on
  every build. That is verifier policy, not build capability.

| Algorithm | RustCrypto with `crypto-legacy-algorithms`, as in the default build | RustCrypto without `crypto-legacy-algorithms` | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- | --- |
| SHA-1 digest (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | No |
| HMAC-SHA1 (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | No |
| Canonical XML 1.0 without comments (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | Sign and verify |
| Enveloped-signature transform (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | Sign and verify |
| RSAwithSHA1 (Conformance §4.1) | Sign and verify | Sign and verify | Verify only | No |
| DSAwithSHA1 (Conformance §4.1, recommended) | Sign and verify | No | No | No |
| RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` (Bindings §3.4.4.1) | Sign and verify | RSAwithSHA1 only | Verify RSAwithSHA1 only | No |

The CI `provider-matrix` job runs the tests on RustCrypto with
`crypto-legacy-algorithms`, `crypto-aws-lc`, and `crypto-fips`. RustCrypto
without `crypto-legacy-algorithms` is not in that job.

### Generation by provider

These methods apply to the embedded signatures and detached `SigAlg` values
that each flow already generates: AuthnRequests on HTTP-POST, HTTP-Redirect,
and HTTP-POST-SimpleSign, responses and assertions on HTTP-POST,
HTTP-POST-SimpleSign, and artifact delivery, and logout messages on
HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign, and SOAP. A SimpleSign
response carries a detached signature and an embedded assertion signature.
The method does not change which bindings a flow supports.

- **Supported:** every crypto provider signs ECDSA-SHA256 with a P-256 key,
  ECDSA-SHA384 with a P-384 key, and ECDSA-SHA512 with a P-521 key.
  RustCrypto and `crypto-aws-lc` sign with Ed25519. A
  `SignatureAlgorithm::Custom` URI signs when the provider supports it.
- **Not supported:** `crypto-fips` does not sign with Ed25519. Other curve
  and digest combinations depend on the crypto provider. The signature method
  selects the reference digest, so the signer writes SHA-1, SHA-256,
  SHA-384, or SHA-512 and no other digest, such as SHA3-256.

| `SignatureMethod` or `SigAlg` | RustCrypto | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- |
| ECDSA-SHA256 | Yes | Yes | Yes |
| ECDSA-SHA384 | Yes | Yes | Yes |
| ECDSA-SHA512 | Yes | Yes | Yes |
| Ed25519 | Yes | Yes | No |

[Kantara saml2int 2.0](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html)
SDP-ALG01 requires deployments that claim the profile to support
ECDSA-SHA256 and RSA-SHA256, and SDP-MD07 sets a 256-bit floor for their EC
public keys. The OASIS rules leave ECDSA and Ed25519 optional, and
[RFC 9231](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3) names
their URIs.

### Provider-supported set

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms` and `crypto-post-quantum`. A row marked Legacy
needs `crypto-legacy-algorithms`, and a row marked Post-quantum needs
`crypto-post-quantum`.

- **Supported:** each build verifies the algorithms that the tables mark for
  it.
- **Not supported:** a signature with an algorithm the build does not verify
  does not verify. An RSA key of 1024 to 2047 bits verifies only on
  RustCrypto with `crypto-legacy-algorithms`, for a message signature under
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

### Encryption algorithms by provider

The default build is `crypto-bergshamra`: RustCrypto with
`crypto-legacy-algorithms`. A cell marked Legacy needs
`crypto-legacy-algorithms`. Each listed algorithm encrypts and decrypts
unless its row or cell says otherwise.

- **Supported:** RustCrypto with `crypto-legacy-algorithms` encrypts and
  decrypts all five Conformance §4.2 algorithms: Triple DES, AES-128,
  AES-256, RSA-v1.5, and RSA-OAEP-MGF1P.
- **Not supported:** `crypto-aws-lc` lacks Triple DES, and implements
  RSA-v1.5 only with `crypto-legacy-algorithms`. `crypto-fips` lacks Triple
  DES and RSA-v1.5, and refuses the SHA-1 digest and MGF1 of RSA-OAEP-MGF1P.
  RSA-v1.5 decryption also needs `Rsa15KeyTransportPolicy::AllowDecryption`.

| Algorithm | RustCrypto | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- |
| AES-128-CBC, AES-256-CBC | Yes | Yes | Yes |
| AES-192-CBC, encrypted only with `DataEncryptionAlgorithm::Custom` | Yes | Yes | Yes |
| Triple DES CBC | Legacy | No | No |
| AES-128-GCM, AES-256-GCM | Yes | Yes | Yes |
| AES-192-GCM, encrypted only with `DataEncryptionAlgorithm::Custom` | Yes | Yes | Decrypt only |
| RSA-OAEP-MGF1P with its default SHA-1 digest | Yes | Yes | No |
| RSA-OAEP-MGF1P with a SHA-256, SHA-384, or SHA-512 `ds:DigestMethod`, decrypted only | Yes | No | No |
| XML Encryption 1.1 RSA-OAEP with SHA-256, SHA-384, or SHA-512 as both the digest and the MGF1 hash | Yes | Yes | Yes |
| XML Encryption 1.1 RSA-OAEP with different digest and MGF1 hashes. Encryption takes MGF1 with SHA-256, SHA-384, or SHA-512 | Yes | No | No |
| XML Encryption 1.1 RSA-OAEP with SHA-1 as both the digest and the MGF1 hash, encrypted only with `KeyEncryptionAlgorithm::Custom` | Yes | Yes | No |
| RSA-v1.5 | Legacy | Legacy | No |

## Rules

### Signer and verifier: `AlgorithmPolicy`, `XmlSignatureProfile`

Code: `src/crypto/sign.rs`, `src/crypto/verify.rs`, `src/binding/signing.rs`, `src/flow/detached.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Sign and verify with the SHA-1 digest, which the SHA-1 signature algorithms select | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Sign and verify RSAwithSHA1 | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1` |
| Sign and verify DSAwithSHA1 with a DSA key, and a DSA certificate in the peer's metadata | Recommended | Conformance §4.1 | `SignatureAlgorithm::DsaSha1` |
| Support RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign | Mandatory | Bindings §3.4.4.1, CS-01 §2.5 | `SignatureAlgorithm::RsaSha1`, `DsaSha1` |
| Sign and verify messages with HMAC-SHA1 and a shared secret that the peers configure out of band | Mandatory | Conformance §4.1 | `SignatureAlgorithm::HmacSha1`, `Credentials::with_hmac_secret`, `IdpDescriptor::with_hmac_secret`, `SpDescriptor::with_hmac_secret` |
| Sign and verify Canonical XML 1.0 without comments as a reference transform. Verification accepts it on `SignedInfo` and on a reference under `ExcludeWeakAlgorithms` and `AllowWeakAlgorithms` | Mandatory | Conformance §4.1 | `TransformAlgorithm::CanonicalXml` in `signed_reference_transforms` |
| Sign and verify with the enveloped-signature transform | Mandatory | Conformance §4.1 | `TransformAlgorithm::EnvelopedSignature`, the first default transform |

### Signer: `AlgorithmPolicy`

Code: `src/crypto/sign.rs`, `src/binding/signed_message.rs`, `src/binding/signing.rs`, `src/config/policies.rs`, `src/config/algorithms.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Canonicalize `SignedInfo` with exclusive canonicalization, which Core §5.4.3 recommends with or without comments. The signer writes the form without comments | Recommended | Core §5.4.3, E83 | Always |
| Sign with the enveloped-signature and exclusive canonicalization reference transforms by default. The setting covers embedded `AuthnRequest` signatures, responses from `respond_sso` and `initiate_sso`, and HTTP-POST logout messages | Recommended | Core §5.4.3, §5.4.4 | `AlgorithmPolicy::signed_reference_transforms` |
| Sign with RSA-SHA256, RSA-SHA384, or RSA-SHA512 | Optional | E50 | `SignatureAlgorithm::RsaSha256` (default), `RsaSha384`, `RsaSha512` |
| Sign with ECDSA-SHA256, ECDSA-SHA384, or ECDSA-SHA512 and an EC key | Optional | E50, E81, RFC 9231 §2.3.6 | `SignatureAlgorithm::EcdsaSha256`, `EcdsaSha384`, `EcdsaSha512` |
| Sign with Ed25519 and an Ed25519 key | Optional | E50, E81, RFC 9231 §2.3.12 | `SignatureAlgorithm::Ed25519` |
| Sign embedded and detached messages with a custom signature URI the provider supports | Optional | E50, E81 | `SignatureAlgorithm::Custom` |

#### Signature shape

These rules apply to every embedded signature that the identity provider and
the service provider generate.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `ID` on the signed element, and reference it with one `ds:Reference` whose `URI` is `#` followed by that `ID` | Mandatory | Core §5.4.2 | Always |
| Write one `SignedInfo` with one `CanonicalizationMethod`, one `SignatureMethod`, and one `Reference` with one `DigestMethod` | Mandatory | XMLDSig §4, Core §5.4.2 | Always |
| Put the signature inside the element it signs, as an enveloped signature | Mandatory | Core §5.4.1 | Always |
| Put `ds:Signature` right after the signed element's `Issuer`, or first when the element has no `Issuer` | Mandatory | `RequestAbstractType`, `StatusResponseType`, `AssertionType` | Always |
| Write no `ds:Object` | Recommended | Core §5.4.5, E91 | Always |
| Write `KeyInfo` with the signing certificate as `X509Certificate`, and leave `KeyInfo` out of an HMAC signature | Optional | Core §5.4.6, E91 | Always |
| Write the enveloped-signature transform in every embedded signature. The signer writes no transform parameters, so no other transform can take the signature out of its own digest | Mandatory | Core §5.4.1, XMLDSig §6.6.4 | Always |

<a id="inbound-xml-signature-verification"></a>

### Verifier: `XmlSignatureProfile`, `MetadataTrustPolicy`

Code: `src/crypto/verify.rs`, `src/crypto/verify/processing.rs`, `src/crypto/signature_profile.rs`, `src/flow/embedded.rs`, `src/flow/detached.rs`, `src/crypto/sign.rs`, `src/config/metadata_trust.rs`

A verifier accepts the `SignatureMethod` and `DigestMethod` values that the
selected provider implements, that the peer's key can verify, and that
`XmlSignatureProfile` allows. `XmlSignatureProfile` is the `xml_signatures`
field of `SpValidationPolicy` and `IdpValidationPolicy`, whose `default()`
selects `ExcludeWeakAlgorithms`, and `ExcludeWeakAlgorithms` permits the
SHA-1 digest and RSAwithSHA1 when the provider implements them. An embedded
signature here is one on a received message: the service provider's
`Response`, `Assertion`, and logout messages, the identity provider's
`AuthnRequest` and logout messages, SOAP artifact resolution messages for both
roles, and SOAP name identifier management messages at the identity provider.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Allow additional provider-supported algorithms in an embedded signature and in a detached `SigAlg` signature on HTTP-Redirect and HTTP-POST-SimpleSign. `ExcludeWeakAlgorithms` leaves out the [weak algorithms and keys](#weak-algorithms-and-keys), and `AllowWeakAlgorithms` accepts the provider-supported set | Optional | E50 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `AllowWeakAlgorithms` |
| Allow additional provider-supported algorithms in a pinned metadata signature. `RequireSignatureAllowingWeakAlgorithms` accepts the provider-supported set, and the other policies leave out the weak algorithms and keys | Optional | E50, E81 | `MetadataTrustPolicy` variants. See [weak algorithms and keys](#weak-algorithms-and-keys) |
| Reject a signature that authenticates the message and contains a `ds:Object` | Recommended | Core §5.4.5, E91 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `StrictRsaSha2`. `AllowWeakAlgorithms` relaxes it |

#### HMAC truncation

This rule applies when the identity provider or the service provider verifies
an enveloped HMAC XML signature with a configured peer secret, under every
profile that allows the algorithm. Omitting `ds:HMACOutputLength` requests
the full MAC. Detached signatures use a separate verifier and have no such
parameter.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an explicit `ds:HMACOutputLength` below half the hash output length or below 80 bits. This requires 192 bits for HMAC-SHA384 and 256 bits for HMAC-SHA512 | Mandatory | XMLDSig 1.1 §4.4.2, §6.3.1 | Always |

### Encrypter and decrypter: `AlgorithmPolicy`, `XmlEncryptionPolicy`

Code: `src/crypto/enc/encrypt.rs`, `src/crypto/enc/decrypt.rs`

Core §6.1 provides SAML encryption through XML Encryption 1.0, and
Conformance §4.2 takes its mandatory algorithms from that specification. An
XML Encryption 1.0 rule for an encryptor or a decryptor applies to each
`EncryptedData` and `EncryptedKey` that `EncryptedElementType` admits, unless
a SAML rule narrows it.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Encrypt and decrypt with AES-128 and AES-256 block encryption | Mandatory | Conformance §4.2 | `DataEncryptionAlgorithm::Aes128Cbc`, `Aes256Cbc` |
| Encrypt and decrypt with Triple DES block encryption | Mandatory | Conformance §4.2 | `DataEncryptionAlgorithm::TripleDesCbc` |
| Encrypt and decrypt with RSA-OAEP-MGF1P key transport | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::RsaOaepMgf1p` (default except on FIPS) |
| Encrypt and decrypt with RSA-v1.5 key transport | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::Rsa15`, and `Rsa15KeyTransportPolicy::AllowDecryption` to decrypt |
| Encrypt and decrypt with AES-128-GCM and AES-256-GCM. Forward a custom URI to the provider | Optional | E50, XML Encryption 1.1 §5.2.4 | `DataEncryptionAlgorithm::Aes128Gcm`, `Aes256Gcm`, `Custom` |

Each flow record holds the integrity rules that decide whether an entity
decrypts what it receives:
[service provider SSO acceptance](web-browser-sso-acceptance.md#service-provider),
the requested `Subject` in
[identity provider SSO acceptance](web-browser-sso-acceptance.md#identity-provider),
[single logout](single-logout.md#encrypted-principal-identifier), and
[name identifier management](name-id-management.md#encryptedid-and-newencryptedid).

### Encrypter: `AlgorithmPolicy`

Code: `src/crypto/enc/encrypt.rs`

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Embed the `EncryptedKey` in the `ds:KeyInfo` of `EncryptedData` | Recommended | XML Encryption 1.0 §3.5.1, E43 | Always |
| Write `ds:DigestMethod` and `xenc11:MGF` under the key's `EncryptionMethod` | Optional | E50, XML Encryption 1.1 §5.5.2 | `KeyEncryptionAlgorithm::RsaOaep { digest, mgf }` |

### Decrypter: `XmlEncryptionPolicy`

Code: `src/crypto/enc/decrypt.rs`

#### Key resolution

An entity finds the key of each encrypted element it receives as follows. It
tries its configured decryption keys in order, and with each one the embedded
`EncryptedKey` elements in document order.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Decrypt with an `EncryptedKey` embedded in the `ds:KeyInfo` of `EncryptedData` | Mandatory | XML Encryption 1.0 §3.5, §3.5.1 | Always |
| With several embedded `EncryptedKey` elements, use the first one the entity can decrypt | Recommended | E43 | Always |
| Resolve a `ds:RetrievalMethod` of type `EncryptedKey` whose same-document reference names an `EncryptedKey` inside the encrypted element, such as a sibling of `EncryptedData` | Mandatory | XML Encryption 1.0 §3.5, §3.5.2, E43 | Always |

## Library policies

### Signer and verifier: `HmacSecret::try_new`

Code: `src/config/credentials.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an HMAC secret shorter than 20 bytes. It is configuration and does not reject a message | RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. | RFC 2104 §3 | Always |

### Signer: `AlgorithmPolicy`, `SpConfigBuilder::build`, `IdpConfigBuilder::build`

Code: `src/config/algorithms.rs`, `src/crypto/sign.rs`, `src/binding/signed_message.rs`, `src/api/idp.rs`, `src/entity.rs`, `src/crypto/keys.rs`, `src/config/builders.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Sign with RSA-SHA256 and a SHA-256 reference digest by default | saml2int SDP-ALG01 lists RSA-SHA256, every crypto provider signs it, and it needs neither SHA-1 nor an EC key. | E50, saml2int SDP-ALG01 | `AlgorithmPolicy::default()` |
| Generate a SHA-1 signature (RSAwithSHA1, DSAwithSHA1, HMAC-SHA1) only when the caller selects it | Conformance §4.1 requires SHA-1 to be implemented, not used, and saml2int SDP-ALG01 calls SHA-1 weakening. | Conformance §4.1, E50 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Use SHA-256 for the reference digest of an embedded signature outside the built-in digest mapping | SHA-256 is the existing reference digest default and works independently of the signature method. | XMLDSig §4.4.2, §4.4.3.5 | ECDSA, Ed25519, and unmapped `Custom` methods |
| Sign `respond_sso_artifact`, `initiate_sso_artifact`, the SOAP `ArtifactResolve`, and SOAP logout messages with the enveloped-signature and exclusive canonicalization transforms only | Canonical XML would put the SOAP envelope's namespace declarations into the digest of a verifier that checks in place. | — | Always |
| Reject a non-empty `signed_reference_transforms` that does not start with the enveloped-signature transform, in the SP and IdP config builders | The signer fails on that transform after a canonicalization transform, so the builders refuse the order before the first message. | XMLDSig §6.6.4 | Always |
| Reject ECDSA-SHA256, ECDSA-SHA384, ECDSA-SHA512, or Ed25519 with a signing key of another family, and Ed25519 on `crypto-fips`, in the SP and IdP config builders | The selected method cannot sign and would otherwise fail when the application sends a message. | — | Always |
| Accept every other method that the crypto provider cannot sign with the configured signing key or HMAC secret, such as an RSA method with an EC key or RSA-SHA1 on `crypto-aws-lc`. The first signed message fails when it is created | An entity configured this way still completes the flows that sign nothing, such as IdP-initiated SSO at the service provider and artifact resolution at the identity provider. | — | Always |

### Verifier: `XmlSignatureProfile`, `MetadataTrustPolicy`

Code: `src/crypto/signature_profile.rs`, `src/crypto/verify.rs`, `src/crypto/verify/processing.rs`, `src/crypto/response_root.rs`, `src/flow/embedded.rs`, `src/flow/detached.rs`, `src/crypto/sign.rs`, `src/soap.rs`, `src/config/metadata_trust.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Accept an embedded signature only with RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, one `Reference`, and no canonicalization or transform but exclusive canonicalization and enveloped-signature | The opt-in allowlist refuses SHA-1, which saml2int SDP-ALG01 calls weakening, and forms that Core §5.4.2 to §5.4.4 do not ask of a signer. | Core §5.4.2–§5.4.4, E50 | `XmlSignatureProfile::StrictRsaSha2` |
| Under `StrictRsaSha2`, also reject `xml-exc-c14n#WithComments` as the `CanonicalizationMethod` and as a reference transform | Reason not recorded. | Core §5.4.3, §5.4.4 | `XmlSignatureProfile::StrictRsaSha2` |
| Accept a detached `SigAlg` only when it is RSA-SHA256, RSA-SHA384, or RSA-SHA512, and reject another before verifying the signature. This profile omits both SHA-1 algorithms required by those bindings | Reason not recorded. | Bindings §3.4.4.1, CS-01 §2.5 | `XmlSignatureProfile::StrictRsaSha2` |
| Reject an explicit `ds:HMACOutputLength` below 160 bits, where the [HMAC truncation](#hmac-truncation) rule applies | A lower floor would let a peer choose a shorter tag and reduce the number of bits an attacker must guess for an accepted signature. | XMLDSig 1.1 §6.3.1 | Always |

#### Verification keys

These policies apply to every profile and to both roles.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Verify a certificate-backed message signature with the peer descriptor's signing certificates, ignoring their chain, validity period, and revocation. HMAC uses the shared secret | Accepted metadata is the trust decision, as in the explicit-key model of Metadata IOP §2.6.1, which forbids path validation of those keys. | Metadata IOP §2.6.1 | Always |
| Verify a metadata signature with the key of a caller-pinned certificate, not with the HMAC secret, and without checking the certificate's chain, validity period, or revocation | The caller's pin is the trust decision, and the crate makes no PKI claim about the pinned certificate. | Metadata IOP §2.3 | Always |

#### Reference and coverage processing

These policies cover inbound embedded-signature processing in the typed flows,
and claim no whole SAML profile or binding. The protocol schema places
optional `ds:Signature` and `samlp:Extensions` children on
`RequestAbstractType` and `StatusResponseType`, and `ExtensionsType` permits
foreign-namespace elements with lax processing, so signature placement alone
does not describe every XML-DSig signature the verifier processes.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject a reference outside the input document in every processed signature, including an optional signature outside the SAML candidate positions, before resolving references or executing transforms | Core §5.4.2 binds a signer, not a receiver, and the dependency would resolve local files. | Core §5.4.2 | Always |
| Check the reference transforms of each processed signature before processing, even an invalid or unrelated one, and allow only the enveloped-signature and exclusive canonicalization transforms. Other profiles keep their existing handling | Library policy: beyond Core §5.4.4's permission to reject other transforms, and the dependency executes transforms before it verifies `SignatureValue`. | Core §5.4.4 | `XmlSignatureProfile::StrictRsaSha2` |
| Count a signature as verified only when it covers the accepted content. Assertion-bearing protocol responses keep their direct-Assertion coverage and extraction rules. Other documents require root coverage, and a signature over a different sibling object is insufficient | A verification success is an API contract that the accepted content is covered. | — | Always |

Core §5.4.4 requires a verifier that accepts other transforms to keep every
part of the SAML message in the signature. The preflight restrictions are
implementation controls, not a new receiver `MUST` inferred from signer rules.

Profiles §4.1.4.5 requires a signature on each HTTP-POST browser SSO
assertion or on its `Response`. The identity provider's rule is in
[Identity provider Response](web-browser-sso-generation.md#identity-provider-response),
and the service provider's rule is in
[Service provider](web-browser-sso-acceptance.md#service-provider).

#### SOAP body signatures

This policy applies under every `XmlSignatureProfile` to SOAP artifact
resolution, for both roles, and to SOAP name identifier management at the
identity provider.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Verify a present body-message signature only when, with the SOAP `Header` set aside, it is the message's one direct `ds:Signature` and the first in the document, with one `SignedInfo` and one `Reference` to the message `ID` | The receiver binds the one signature it verifies to the SAML message it reads, and Core §5.4.2 binds only the signer. | Core §5.4, §5.4.2 | Always |

#### Weak algorithms and keys

`ExcludeWeakAlgorithms` and `StrictRsaSha2` exclude these from the signatures
they cover, and signed metadata import excludes them under
`RequireSignature`, `RequireRegistrationAuthoritySignature`, and
`RequireSignatureAllowingInclusiveCanonicalization`.
`XmlSignatureProfile::AllowWeakAlgorithms` and
`MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` re-allow them
where the build verifies them, as the
[provider-supported set](#provider-supported-set) shows.

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Reject an embedded signature that authenticates accepted content, a detached `SigAlg`, or a verified metadata signature that uses RSA-MD5, HMAC-MD5, or the MD5 digest | XMLDSig 1.1 §6.2 says MD5 `SHOULD NOT` be used in `DigestMethod` because collisions have been demonstrated for it, and no OASIS rule has a receiver reject it. | XMLDSig 1.1 §6.2 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
| Reject the same for RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-RIPEMD160, and the RIPEMD-160 digest | Its 160-bit output has the same 80-bit generic collision bound as SHA-1, and only the Conformance §4.1 requirement keeps SHA-1 accepted. | Conformance §4.1, E50 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
| Do not verify with an RSA key shorter than 2048 bits. Skip the certificate, so a message only that key could verify is rejected | The identity provider and service provider authenticate current messages, and NIST SP 800-131A Rev. 2 §3 Table 2 classifies 1024-bit to 2047-bit RSA keys as legacy. | XMLDSig 1.1 §6.4.2 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |

Pinned metadata keys have the same floor for a separate
[trust-root reason](metadata-and-replay.md#metadata-trust). Under
`AllowWeakAlgorithms`, an invalid Response or Assertion signature still makes
the service provider reject the browser SSO response (Profiles §4.1.4.3).

### Encrypter: `AlgorithmPolicy`

Code: `src/config/algorithms.rs`, `src/config/encryption.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Encrypt with AES-256-CBC unless the caller selects another data-encryption algorithm | Every peer must decrypt AES-CBC under Conformance §4.2 but not AES-GCM, and the identity provider reads no `md:EncryptionMethod` that would show a peer supports AES-GCM. | Conformance §4.2, E50, XML Encryption 1.1 §5.1.1 | `AlgorithmPolicy::data_encryption` |
| Encrypt with XML Encryption 1.1 RSA-OAEP, SHA-256, and MGF1 with SHA-256 by default on FIPS | The FIPS provider refuses SHA-1 in RSA-OAEP, and SHA-256 with MGF1-SHA-256 is the smallest digest pair it encrypts with. | Conformance §4.2, E50 | `KeyEncryptionAlgorithm::RsaOaep` (FIPS default) |
| Generate Triple DES and RSA-v1.5 only when the caller selects them | Every peer must also decrypt AES and RSA-OAEP, and XML Encryption 1.1 §5.5.1 recommends RSA-OAEP for AES keys and calls implementing RSA-v1.5 `NOT RECOMMENDED`. | Conformance §4.2, XML Encryption 1.1 §5.1.1, §5.5.1 | `DataEncryptionAlgorithm::TripleDesCbc`, `KeyEncryptionAlgorithm::Rsa15` |
| Reject in the config builders a key transport that the crypto provider does not encrypt with: RSA-OAEP-MGF1P on `crypto-fips`, and XML Encryption 1.1 RSA-OAEP parameters that the provider does not support | Reason not recorded. | XML Encryption 1.1 §5.5.2 | Always |

### Decrypter: `XmlEncryptionPolicy`

Code: `src/crypto/enc/decrypt.rs`, `src/crypto/enc/work.rs`

| Policy | Reason | Section | Option |
| --- | --- | --- | --- |
| Decrypt RSA-v1.5 only when allowed. Otherwise reject an `EncryptionMethod` that names it before any key is decrypted | RSA-v1.5 is open to Bleichenbacher's chosen-ciphertext attack, and no OASIS rule rejects it, because SAML V2.0 cites XML Encryption 1.0, whose §5.1 requires RSA-v1.5. | XML Encryption 1.1 §6.1.3 | `XmlEncryptionPolicy::rsa15_key_transport`, `Rsa15KeyTransportPolicy::AllowDecryption` |
| Charge each `xenc:EncryptedData`, `xenc:EncryptedKey`, and `xenc11:DerivedKey` one unit per configured decryption key against a per-message allowance of 16 by default, shared with revealed encrypted content. Zero refuses encrypted input | It bounds unauthenticated key resolution and key-rollover retries that XML byte limits alone do not bound. | XML Encryption 1.0 §6.4 | `XmlEncryptionPolicy::max_decryption_work` |

## Not supported

### Not implemented in the decrypter

- A `ds:RetrievalMethod` that names an `EncryptedKey` elsewhere in the
  message. The decrypter receives only the encrypted element. Mandatory,
  XML Encryption 1.0 §3.5, E43.
- A `ds:RetrievalMethod` after the first one whose reference resolves. An
  element whose content key is wrapped for several recipients this way
  decrypts only when this entity's key is named first. Recommended, E43,
  XML Encryption 1.0 §3.5.2.
- A `ds:KeyName` that names an `EncryptedKey` by its `CarriedKeyName`, the
  E43 form for several recipients. Recommended, XML Encryption 1.0 §3.5,
  E43.
- Association of an `EncryptedKey` beside `EncryptedData` without a
  `ds:RetrievalMethod`. Optional, E43.
- An error for an `EncryptionMethod` child that its algorithm does not
  permit, or for a `KeySize` inconsistent with the algorithm. Mandatory,
  XML Encryption 1.0 §3.2. The decrypter checks neither. For example, it
  applies an `xenc11:MGF` under `rsa-oaep-mgf1p`.
- A `CipherReference` to ciphertext outside the encrypted element, elsewhere
  in the message. Mandatory, XML Encryption 1.0 §3.3.1.
