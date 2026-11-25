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

The identity provider and service provider sign and verify. Which
algorithms each build signs and verifies is in
[signature algorithms by build](#signature-algorithms-by-build).

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Canonicalize `SignedInfo` with exclusive canonicalization, which Core §5.4.3 recommends with or without comments. The signer writes the form without comments | Recommended | Core §5.4.3, E83 | Always |
| Sign with the enveloped-signature and exclusive canonicalization reference transforms by default | Recommended | Core §5.4.3, §5.4.4 | `AlgorithmPolicy::signed_reference_transforms` |
| Sign with RSA-SHA256 and a SHA-256 reference digest by default | Library policy: saml2int SDP-ALG01 lists RSA-SHA256, every build signs it, and it needs neither SHA-1 nor an EC key. | E50, saml2int SDP-ALG01 | `AlgorithmPolicy::default()` |
| Generate a SHA-1 signature (RSAwithSHA1, DSAwithSHA1, HMAC-SHA1) only when the caller selects it | Library policy: Conformance §4.1 requires SHA-1 to be implemented, not used, and saml2int SDP-ALG01 calls SHA-1 weakening. | Conformance §4.1, E50 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Sign and verify with the SHA-1 digest. The SHA-1 signature algorithms select it. `crypto-fips` does not implement it | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1`, `DsaSha1`, `HmacSha1` |
| Sign and verify RSAwithSHA1. `crypto-aws-lc` only verifies it, and `crypto-fips` does not implement it | Mandatory | Conformance §4.1 | `SignatureAlgorithm::RsaSha1` |
| Sign and verify DSAwithSHA1 with a DSA key, and a DSA certificate in the peer's metadata. Needs RustCrypto with `crypto-legacy-algorithms` | Recommended | Conformance §4.1 | `SignatureAlgorithm::DsaSha1` |
| Support RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` on HTTP-Redirect and HTTP-POST-SimpleSign. The default build does. AWS-LC and FIPS sign neither, and RustCrypto without `crypto-legacy-algorithms` lacks DSAwithSHA1 | Mandatory | Bindings §3.4.4.1, CD-04 §2.5 | `SignatureAlgorithm::RsaSha1`, `DsaSha1` |
| Implement HMAC-SHA1 signing and verification for messages. `crypto-fips` does not implement it | Mandatory | Conformance §4.1 | `SignatureAlgorithm::HmacSha1`, `Credentials::with_hmac_secret`, `IdpDescriptor::with_hmac_secret`, `SpDescriptor::with_hmac_secret` |
| Reject an HMAC secret shorter than 20 bytes. It is configuration and does not reject a message | Library policy: RFC 2104 §3 discourages a key shorter than the hash output, which is 20 bytes for SHA-1. | RFC 2104 §3 | `HmacSecret::try_new` |
| Sign and verify Canonical XML 1.0 without comments as a reference transform. `SignedInfo` is canonicalized with exclusive canonicalization. Verification accepts it on `SignedInfo` and on a reference under `ExcludeWeakAlgorithms` and `AllowWeakAlgorithms` | Mandatory | Conformance §4.1 | `TransformAlgorithm::CanonicalXml` in `signed_reference_transforms` |
| Sign and verify with the enveloped-signature transform | Mandatory | Conformance §4.1 | `TransformAlgorithm::EnvelopedSignature`, the first default transform |
| Sign `respond_sso_artifact`, `initiate_sso_artifact`, the SOAP `ArtifactResolve`, and SOAP logout messages with the enveloped-signature and exclusive canonicalization transforms only | Library policy: Canonical XML would put the SOAP envelope's namespace declarations into the digest of a verifier that checks in place. | — | Always |
| Sign with RSA-SHA256, RSA-SHA384, or RSA-SHA512 | Optional | E50 | `SignatureAlgorithm::RsaSha256` (default), `RsaSha384`, `RsaSha512` |
| Sign with ECDSA-SHA256, ECDSA-SHA384, or ECDSA-SHA512 and an EC key | Optional | E50, E81, RFC 9231 §2.3.6 | `SignatureAlgorithm::EcdsaSha256`, `EcdsaSha384`, `EcdsaSha512` |
| Sign with Ed25519 and an Ed25519 key on RustCrypto and AWS-LC | Optional | E50, E81, RFC 9231 §2.3.12 | `SignatureAlgorithm::Ed25519` |
| Reject a signature method that the provider cannot sign with the configured signing credential or HMAC secret, in the SP and IdP config builders. It is configuration and does not reject a message | Library policy: the selected method cannot sign and would otherwise fail when the application sends a message. | — | Always |
| Sign embedded and detached messages with a custom signature URI the provider supports | Optional | E50, E81 | `SignatureAlgorithm::Custom` |
| Use SHA-256 for the reference digest of an embedded signature outside the built-in digest mapping | Library policy: SHA-256 is the existing reference digest default and works independently of the signature method. | XMLDSig §4.4.2, §4.4.3.5 | ECDSA, Ed25519, and unmapped `Custom` methods |

Peers configure an HMAC shared secret out of band. Typed metadata import
verifies with pinned certificates, not the secret.
`AlgorithmPolicy::signed_reference_transforms` applies to embedded
`AuthnRequest` signatures, responses from `respond_sso` and `initiate_sso`, and
HTTP-POST logout messages.

### Signature shape

These rules apply to every embedded signature the identity provider and
service provider generate.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Write `ID` on the signed element, and reference it with one `ds:Reference` whose `URI` is `#` followed by that `ID` | Mandatory | Core §5.4.2 | Always |
| Write one `SignedInfo` with one `CanonicalizationMethod`, one `SignatureMethod`, and one `Reference` with one `DigestMethod` | Mandatory | XMLDSig §4, Core §5.4.2 | Always |
| Put the signature inside the element it signs, as an enveloped signature | Mandatory | Core §5.4.1 | Always |
| Put `ds:Signature` right after the signed element's `Issuer`, or first when the element has no `Issuer` | Mandatory | `RequestAbstractType`, `StatusResponseType`, `AssertionType` | Always |
| Write no `ds:Object` | Recommended | E91 | Always |
| Write `KeyInfo` with the signing certificate as `X509Certificate`, and leave `KeyInfo` out of an HMAC signature | Optional | Core §5.4.5, E91 | Always |
| Write the enveloped-signature transform in every embedded signature. The signer writes no transform parameters, so no other transform can take the signature out of its own digest | Mandatory | Core §5.4.1, XMLDSig §6.6.4 | Always |
| Reject a non-empty `signed_reference_transforms` that does not start with the enveloped-signature transform, in the SP and IdP config builders | Library policy: the signer fails on that transform after a canonicalization transform, so the builders refuse the order before the first message. | XMLDSig §6.6.4 | Always |

### Signature algorithms by build

Conformance §4.1 lists the algorithms a compliant implementation `MUST`
implement for embedded XML signatures, and recommends DSAwithSHA1. Bindings
§3.4.4.1 adds the `SigAlg` rule for HTTP-Redirect, and HTTP-POST-SimpleSign
follows it. Each cell says
what that build does with the algorithm. The CI `provider-matrix` job runs the
tests on RustCrypto with `crypto-legacy-algorithms`, `crypto-aws-lc`, and
`crypto-fips`. RustCrypto without `crypto-legacy-algorithms` is not in that
job.

| Algorithm | RustCrypto with `crypto-legacy-algorithms`, as in the default build | RustCrypto without `crypto-legacy-algorithms` | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- | --- |
| SHA-1 digest (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | No |
| HMAC-SHA1 (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | No |
| Canonical XML 1.0 without comments (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | Sign and verify |
| Enveloped-signature transform (Conformance §4.1) | Sign and verify | Sign and verify | Sign and verify | Sign and verify |
| RSAwithSHA1 (Conformance §4.1) | Sign and verify | Sign and verify | Verify only | No |
| DSAwithSHA1 (Conformance §4.1, recommended) | Sign and verify | No | No | No |
| RSAwithSHA1 and DSAwithSHA1 as the `SigAlg` (Bindings §3.4.4.1) | Sign and verify | RSAwithSHA1 only | Verify RSAwithSHA1 only | No |

Only RustCrypto with `crypto-legacy-algorithms` implements the whole
Conformance §4.1 list, its DSAwithSHA1 recommendation, and the Bindings
§3.4.4.1 `SigAlg` rule. The default build includes it. A build generates a
SHA-1 algorithm only when the caller selects it, and generates the
enveloped-signature transform by default. `XmlSignatureProfile::StrictRsaSha2` refuses every SHA-1 algorithm on
every build. That is verifier policy, not build capability.

### Generation by provider

These methods apply to the embedded signatures and detached `SigAlg` values
that each flow already generates. This includes AuthnRequests on HTTP-POST,
Redirect and SimpleSign, Responses and assertions on HTTP-POST, SimpleSign
and artifact delivery,
and logout messages on HTTP-POST, Redirect, SimpleSign, and SOAP. A
SimpleSign Response carries a detached signature and an embedded assertion
signature. The method does not change which bindings a flow supports.

| `SignatureMethod` or `SigAlg` | RustCrypto | `crypto-aws-lc` | `crypto-fips` |
| --- | --- | --- | --- |
| ECDSA-SHA256 | Yes | Yes | Yes |
| ECDSA-SHA384 | Yes | Yes | Yes |
| ECDSA-SHA512 | Yes | Yes | Yes |
| Ed25519 | Yes | Yes | No |

Use P-256 with SHA-256, P-384 with SHA-384, or P-521 with SHA-512 for
portable ECDSA signing. Other curve and digest combinations depend on
the crypto provider. The builders check the key family. The provider
checks whether it can sign with the particular curve and digest.

Kantara saml2int 2.0 SDP-ALG01 requires deployments in that profile to
support ECDSA-SHA256 and RSA-SHA256. SDP-MD07 sets a 256-bit floor for
EC public keys in that profile. Those requirements apply to deployments
that claim the profile. The OASIS base SAML rules leave ECDSA and Ed25519
optional. See [Kantara saml2int 2.0](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html)
and [RFC 9231](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3).

## Inbound XML signature verification

A verifier accepts the `SignatureMethod` and `DigestMethod` values that the
selected provider implements, that the peer's key can verify, and that
`XmlSignatureProfile` allows. `XmlSignatureProfile` is the `xml_signatures`
field of `SpValidationPolicy` and `IdpValidationPolicy`, and Recommended uses
`ExcludeWeakAlgorithms`. Accepting an algorithm outside the Conformance §4.1
set is the E50 `MAY`. No profile is an OASIS receiver rule.
`ExcludeWeakAlgorithms` permits the SHA-1 digest and RSAwithSHA1 when the
provider implements them.

An embedded signature here is one on a received message: the service
provider's `Response`, `Assertion`, and logout messages, the identity
provider's `AuthnRequest` and logout messages, SOAP artifact resolution
messages for both roles, and SOAP name identifier management messages at the
identity provider.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Allow additional provider-supported algorithms in an embedded signature. `ExcludeWeakAlgorithms` leaves out the [weak algorithms](#weak-algorithms-and-keys), and `AllowWeakAlgorithms` accepts the provider-supported set | Optional | E50 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `AllowWeakAlgorithms` |
| Allow additional provider-supported algorithms when verifying a detached `SigAlg` signature on HTTP-Redirect and HTTP-POST-SimpleSign. `ExcludeWeakAlgorithms` leaves out the weak algorithms and keys. `AllowWeakAlgorithms` accepts any `SigAlg` in the provider-supported set | Optional | E50 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `AllowWeakAlgorithms` |
| Allow additional provider-supported algorithms in a pinned metadata signature. `RequireSignatureAllowingWeakAlgorithms` accepts the provider-supported set, and the other policies leave out the weak algorithms and keys | Optional | E50, E81 | `MetadataTrustPolicy` variants. See [weak algorithms and keys](#weak-algorithms-and-keys) |
| Accept an embedded signature only with RSA-SHA256, RSA-SHA384, or RSA-SHA512, a SHA-256, SHA-384, or SHA-512 digest, one `Reference`, and no canonicalization or transform but exclusive canonicalization and enveloped-signature | Library policy: an opt-in allowlist that refuses SHA-1, which saml2int SDP-ALG01 calls weakening, and forms Core §5.4.2 to §5.4.4 do not ask of a signer. | Core §5.4.2–§5.4.4, E50 | `XmlSignatureProfile::StrictRsaSha2` |
| Under `StrictRsaSha2`, also reject `xml-exc-c14n#WithComments` as the `CanonicalizationMethod` and as a reference transform | Library policy: reason not recorded. | Core §5.4.3, §5.4.4 | `XmlSignatureProfile::StrictRsaSha2` |
| Accept a detached `SigAlg` only when it is RSA-SHA256, RSA-SHA384, or RSA-SHA512, and reject another before verifying the signature. This profile omits both SHA-1 algorithms required by those bindings | Library policy: reason not recorded. | Bindings §3.4.4.1, CD-04 §2.5 | `XmlSignatureProfile::StrictRsaSha2` |

### Verification keys

These rules apply to every profile and to both roles.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a certificate-backed message signature with the peer descriptor's signing certificates, ignoring their chain, validity period, and revocation. HMAC uses the [shared secret](#xml-signature) | Library policy: accepted metadata is the trust decision, as in the explicit-key model of Metadata IOP §2.6.1, which forbids path validation of those keys. | Metadata IOP §2.6.1 | Always |
| Verify a metadata signature with the key of a caller-pinned certificate, without checking its chain, validity period, or revocation | Library policy: the caller's pin is the trust decision, and the crate makes no PKI claim about the pinned certificate. | Metadata IOP §2.3 | Always |

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
| Reject a signature that authenticates the message and contains a `ds:Object` | Recommended | E91 | `XmlSignatureProfile::ExcludeWeakAlgorithms`, `StrictRsaSha2`. `AllowWeakAlgorithms` relaxes it |

Core §5.4.4 requires a verifier that accepts other transforms to keep every
part of the SAML message in the signature. The preflight restrictions are
implementation controls, not a new receiver `MUST` inferred from signer rules.

Profiles §4.1.4.5 requires a signature on each HTTP-POST browser SSO
assertion or on its `Response`. The identity provider's rule is in
[Identity provider Response](web-browser-sso-generation.md#identity-provider-response),
and the service provider's rule is in
[Service provider](web-browser-sso-acceptance.md#service-provider).

### SOAP body signatures

This rule applies under every `XmlSignatureProfile` to SOAP artifact
resolution, for both roles, and to SOAP name identifier management at the
identity provider.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Verify a present body-message signature only when, with the SOAP `Header` set aside, it is the message's one direct `ds:Signature` and the first in the document, with one `SignedInfo` and one `Reference` to the message `ID` | Library policy: Core §5.4.2 binds the signer, and the receiver binds the one signature it verifies to the SAML message it reads. | Core §5.4, §5.4.2 | Always |

### Weak algorithms and keys

`ExcludeWeakAlgorithms` and `StrictRsaSha2` exclude these from the signatures
they cover, and signed metadata import excludes them under `RequireSignature`,
`RequireRegistrationAuthoritySignature`, and
`RequireSignatureAllowingInclusiveCanonicalization`.
`XmlSignatureProfile::AllowWeakAlgorithms` and
`MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithms` re-allow them
where the build verifies them. Recommended excludes them for both roles.

| Rule | Level | Section | Option |
| --- | --- | --- | --- |
| Reject an embedded signature that authenticates accepted content, a detached `SigAlg`, or a verified metadata signature that uses RSA-MD5, HMAC-MD5, or the MD5 digest | Library policy: XMLDSig 1.1 §6.2 says MD5 `SHOULD NOT` be used in `DigestMethod`, a rule on use, and no OASIS rule has a receiver reject it. | XMLDSig 1.1 §6.2 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
| Reject the same for RSA-RIPEMD160, ECDSA-RIPEMD160, HMAC-RIPEMD160, and the RIPEMD-160 digest | Library policy: its 160-bit output has the same 80-bit generic collision bound as SHA-1, and only the Conformance §4.1 requirement keeps SHA-1 accepted. | Conformance §4.1, E50 | `AllowWeakAlgorithms` for messages, `RequireSignatureAllowingWeakAlgorithms` for metadata |
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
| Encrypt and decrypt with RSA-OAEP key transport on RustCrypto and AWS-LC. FIPS refuses its SHA-1 digest and MGF1, and its config builders reject it | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::RsaOaepMgf1p` (default except on FIPS) |
| Encrypt with XML Encryption 1.1 RSA-OAEP, SHA-256, and MGF1 with SHA-256 by default on FIPS | Library policy: the FIPS provider refuses SHA-1 in RSA-OAEP, and SHA-256 with MGF1-SHA-256 is the smallest digest pair it encrypts with. | Conformance §4.2, E50 | `KeyEncryptionAlgorithm::RsaOaep` (FIPS default) |
| Encrypt and decrypt with RSA-v1.5 key transport. Needs `crypto-legacy-algorithms` on RustCrypto or AWS-LC. Not on FIPS | Mandatory | Conformance §4.2 | `KeyEncryptionAlgorithm::Rsa15` |
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
