# 2. Check the signature and trust defaults

[How to upgrade from 0.7 to 0.8](README.md)

| Change | Affects you if | Section |
| --- | --- | --- |
| Recommended excludes MD5, RIPEMD-160, and RSA keys under 2048 bits | A peer signs with one of them and you use `recommended()` or `Default` | [2.1](#21-stop-relying-on-md5-ripemd-160-and-short-rsa-keys-under-recommended) |
| `StrictRsaSha2` covers detached `SigAlg` and the identity provider | You select `StrictRsaSha2` | [2.2](#22-expect-strictrsasha2-on-detached-and-identity-provider-signatures) |
| `ds:Object` in a message signature is rejected | A peer signs with `ds:Object` | [2.3](#23-expect-dsobject-in-a-message-signature-to-be-rejected) |
| A signature that does not verify rejects an SSO response | An identity provider sends a broken assertion signature | [2.4](#24-expect-a-signature-that-does-not-verify-to-reject-an-sso-response) |
| Signed metadata excludes weak algorithms and short keys | You import signed metadata | [2.5](#25-stop-relying-on-md5-ripemd-160-and-short-rsa-keys-in-signed-metadata) |
| `CertificateMismatch` is no longer returned | You match it | [2.6](#26-handle-signature-verification-errors-instead-of-certificatemismatch) |
| Unsigned `AuthnRequest` from a signing SP is rejected | You run an identity provider on Recommended | [2.7](#27-expect-unsigned-requests-from-a-signing-service-provider-to-be-rejected) |

Compatibility presets and the raw API are unchanged by sections 2.1 to 2.4.

## Relax one peer at a time

Sections 2.1, 2.3, and 2.4 share one relaxation. Ask the peer to fix its
signatures. Until it does, keep Recommended and relax only `xml_signatures`:

```rust
use saml_rs::{SpValidationPolicy, XmlSignatureProfile};

let validation = SpValidationPolicy {
    xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
    ..SpValidationPolicy::recommended()
};
```

The same field exists on `IdpValidationPolicy`. It accepts all three cases at
once: weak algorithms and keys, `ds:Object`, and an unverified assertion
signature beside a verified Response signature.

## 2.1 Stop relying on MD5, RIPEMD-160, and short RSA keys under Recommended

**Affects:** `SpValidationPolicy::recommended`,
`IdpValidationPolicy::recommended`, or their `Default`, with a peer that signs
with MD5, RIPEMD-160, or an RSA key shorter than 2048 bits. Also
`XmlSignatureProfile::StrictRsaSha2` with a peer RSA key shorter than 2048
bits. See
[weak algorithms and keys](../../conformance/xml-security-algorithms.md#weak-algorithms-and-keys).

**Before:** Recommended used `AllowProviderSupportedForCompatibility`.
**Now:** Recommended sets `xml_signatures` to the new
`XmlSignatureProfile::ExcludeWeakAlgorithms` on both roles. SHA-1 still
verifies.

- A signature that authenticates the received message, or a detached
  `SigAlg`, that uses RSA-MD5, HMAC-MD5, RSA-RIPEMD160, ECDSA-RIPEMD160,
  HMAC-RIPEMD160, or an MD5 or RIPEMD-160 digest returns
  `SamlError::AlgorithmUnsupported`.
- A signing certificate with an RSA key shorter than 2048 bits is not used to
  verify. When the peer has no other usable key, the message returns
  `SamlError::Crypto`. Otherwise a message signed with the short key fails
  signature verification. `StrictRsaSha2` applies the same key rule.

Only the default build and RustCrypto with `crypto-legacy-algorithms` verified
these before, and for RSA only keys of 1024 bits or more. AWS-LC, FIPS, and
RustCrypto without that feature already rejected them. On those builds a
detached MD5 or RIPEMD-160 `SigAlg` now returns
`SamlError::AlgorithmUnsupported` instead of the provider's
`SamlError::Crypto`.

**Upgrade:** ask the peer to sign with RSA-SHA256 and a 2048-bit key or
larger. Until it does, [relax one peer](#relax-one-peer-at-a-time).

## 2.2 Expect `StrictRsaSha2` on detached and identity provider signatures

**Affects:** callers that select `XmlSignatureProfile::StrictRsaSha2`. See
[inbound XML signature verification](../../conformance/xml-security-algorithms.md#inbound-xml-signature-verification).

**Before:** any detached `SigAlg` the crypto provider supported verified, and
`IdpValidationPolicy` had no profile.
**Now:** `StrictRsaSha2` also applies to the detached `SigAlg` of an
HTTP-Redirect or HTTP-POST-SimpleSign message. A `SigAlg` other than
RSA-SHA256, RSA-SHA384, or RSA-SHA512 returns
`SamlError::AlgorithmUnsupported`. An identity provider applies the profile
through `IdpValidationPolicy::xml_signatures`
([section 1.7](compile-errors.md#17-complete-struct-literals)).

**Upgrade:** if a peer signs Redirect or SimpleSign messages with RSA-SHA1,
ask it to move to RSA-SHA256, or select
`AllowProviderSupportedForCompatibility`.

`SamlError::AlgorithmUnsupported` now displays `signature algorithm is not
allowed`. Before, it displayed `embedded XML signature algorithm is not
allowed`.

## 2.3 Expect `ds:Object` in a message signature to be rejected

**Affects:** `SpValidationPolicy::recommended`,
`IdpValidationPolicy::recommended`, their `Default`, or
`XmlSignatureProfile::StrictRsaSha2`, with a peer that puts `ds:Object` inside
the signature of a `Response`, `Assertion`, `AuthnRequest`, `LogoutRequest`,
or `LogoutResponse`. See
[metadata trust](../../conformance/metadata-and-replay.md#metadata-trust).

**Before:** the message was accepted, and the `ds:Object` content was not
signed.
**Now:** a received message whose authenticating signature contains
`ds:Object` returns `SamlError::SignedReferenceMismatch` on every binding that
carries an XML signature.

**Upgrade:** ask the peer to sign without `ds:Object`. Until it does,
[relax one peer](#relax-one-peer-at-a-time).

## 2.4 Expect a signature that does not verify to reject an SSO response

**Affects:** `SpValidationPolicy::recommended`, its `Default`, or
`XmlSignatureProfile::StrictRsaSha2`, with `finish_sso`,
`accept_unsolicited_sso`, or `finish_paos_sso`. See
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md#service-provider).

**Before:** an assertion signature that did not verify was ignored when the
Response signature verified, and HTTP-Redirect and HTTP-POST-SimpleSign
verified only the detached signature.
**Now:** a response returns `SamlError::SignatureVerification` with
`SignatureVerificationReason::XmlSignature` when a signature on the
`Response`, on one of its assertions, or on a decrypted assertion does not
verify. That includes a `Response` signature that verifies only after the
assertions are decrypted. Profiles §4.1.4.3 requires the service provider to
verify any signature present on the response or its assertions.

Under `AssertionSignaturePolicy::RequireSigned`, the same response used to
return `AssertionSignatureRequired`. It now returns this error.

**Upgrade:** ask the identity provider to send signatures that verify with the
keys in its metadata. Until it does,
[relax one peer](#relax-one-peer-at-a-time).

## 2.5 Stop relying on MD5, RIPEMD-160, and short RSA keys in signed metadata

**Affects:** imports with `MetadataTrustPolicy::RequireSignature` or
`RequireSignatureAllowingOtherCanonicalization` of metadata signed with MD5,
RIPEMD-160, or an RSA key shorter than 2048 bits. See
[metadata trust](../../conformance/metadata-and-replay.md#metadata-trust).

**Before:** both options verified every algorithm and key the crypto provider
verified.
**Now:** both exclude what Recommended excludes for messages. SHA-1 still
verifies. `UnsignedForCompatibility`, `verify_metadata_signature`, and
`Metadata::verify_signature` are unchanged.

- A metadata signature that uses RSA-MD5, RSA-RIPEMD160, ECDSA-RIPEMD160, or
  an MD5 or RIPEMD-160 digest returns `SamlError::AlgorithmUnsupported`.
- A pinned RSA certificate shorter than 2048 bits is not used to verify. When
  no other pinned certificate loads, the import returns `SamlError::Crypto`.
  Otherwise metadata signed with the short key returns
  `SamlError::SignatureVerification`.

Only the default build and RustCrypto with `crypto-legacy-algorithms` verified
these algorithms or keys before. Other builds reject such metadata as they did
before.

**Upgrade:** ask the publisher to sign with RSA-SHA256 and a 2048-bit key or
larger. Until it does, select the new option, which keeps the signature shape
and transform rules of `RequireSignature`:

```rust
use saml_rs::{CertificatePem, IdpDescriptor, MetadataTrustPolicy};

let certificates = [CertificatePem::new(metadata_signing_certificate_pem)];
let idp = IdpDescriptor::from_metadata_xml_for(
    expected_entity_id,
    &metadata_xml,
    MetadataTrustPolicy::RequireSignatureAllowingWeakAlgorithmsForCompatibility {
        trusted_certificates: &certificates,
    },
)?;
```

No option accepts both an inclusive canonicalization reference transform and
these algorithms.

## 2.6 Handle signature verification errors instead of `CertificateMismatch`

**Affects:** code that matches `SamlError::CertificateMismatch`, or relies on
rejecting a signature whose `KeyInfo` carries a certificate the peer's
metadata does not list. See
[metadata trust](../../conformance/metadata-and-replay.md#metadata-trust).

**Now:** verification no longer compares the certificate in `KeyInfo` with the
trusted certificates. A signature verifies when a trusted key verifies it. No
signature verification returns `SamlError::CertificateMismatch`.

| Signature | Before | Now |
| --- | --- | --- |
| By a trusted key, `KeyInfo` carries another certificate (such as a re-issued certificate for the same key pair) | `CertificateMismatch` | Verifies |
| By another key, typed flows and `MetadataTrustPolicy::RequireSignature` | `CertificateMismatch` when `KeyInfo` carried a certificate | `SignatureVerification` with `SignatureVerificationReason::XmlSignature` |
| By another key, `verify_signature` and `verify_metadata_signature_detailed` | `CertificateMismatch` when `KeyInfo` carried a certificate | Reported as not verified |

**Upgrade:** handle `SignatureVerification`, or an unverified result, where
you handled `CertificateMismatch`.

## 2.7 Expect unsigned requests from a signing service provider to be rejected

**Affects:** identity providers on `IdpValidationPolicy::recommended`, its
`Default`, or `AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent`
that call `receive_sso` or `receive_paos_sso` with an `SpDescriptor` whose
metadata sets `AuthnRequestsSigned="true"`. See
[Web Browser SSO acceptance](../../conformance/web-browser-sso-acceptance.md#identity-provider).

**Before:** an unsigned `AuthnRequest` from that service provider was
accepted.
**Now:** it returns `SamlError::SignatureMissing`. Metadata §2.4.4, as amended
by Errata 05 E7, forbids fulfilling it. Signed requests, and requests from a
service provider whose metadata omits the flag or sets it to false, are
received as before. `RequireSigned`, Compatibility, and raw identity providers
built without an `IdpConfig` are unchanged.

`SpMetadata::is_authn_request_signed` now returns true when any SAML 2.0
`SPSSODescriptor` of the entity sets the flag. Before, an entity with two such
roles read false. A raw service provider built from that metadata now signs
its AuthnRequests.

**Upgrade:** ask the service provider to sign its requests, or to publish
metadata without `AuthnRequestsSigned="true"`, then import that metadata
again.
