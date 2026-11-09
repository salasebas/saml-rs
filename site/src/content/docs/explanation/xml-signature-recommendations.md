---
title: "XML signatures"
description: "An XML signature protects the bytes a reference points at. It does not, by itself, say that the signer is the identity provider you trust, or that the assertion you are about..."
---

An XML signature protects the bytes a reference points at. It does not, by itself, say that the signer is the identity provider you trust, or that the assertion you are about to read is the element that was signed.

[bergshamra](https://crates.io/crates/bergshamra) is the library saml-rs uses for XML-DSig, XML-Enc, and canonicalisation. Its notes, and the demos in [secexample](https://github.com/kushaldas/secexample), name three attacks that show up in SAML.

## Wrapping

**Signature wrapping** moves a legitimately signed element and puts forged content where the application reads. The signature stays valid because the signed bytes did not change. secexample shows one SAML-shaped variant: a forged `Assertion` where the service provider reads, and the original assertion buried beside it.

Bergshamra rejects duplicate identifiers. Strict verification requires every same-document reference to land on the document element, an ancestor of the `Signature`, or a sibling of the `Signature`. After verification, the references say which nodes were covered. A service provider still has to consume one of those nodes.

## Key injection

**Key injection** puts the signer's public key inside `KeyInfo`. A verifier that trusts that inline key accepts a document the attacker signed with a key they just created. Bergshamra's trusted-keys mode ignores inline keys and uses only keys already loaded. For SAML, those keys are the ones you already decided to trust.

## HMAC truncation

**HMAC truncation** (CVE-2009-0217) uses `HMACOutputLength` to shrink an HMAC until it can be guessed. secexample sets a floor of 128 bits. Bergshamra's SAML note also suggests `trusted_keys_only`, `strict_verification`, and validating the identity-provider certificate chain when you drive `DsigContext` yourself.

## Already on

The typed verification path does not take a `DsigContext` from the application. It builds one with:

- `trusted_keys_only`, so the signature is checked against the certificate you pass in. For SSO that is the certificate declared in metadata, not an inline `KeyInfo` key.
- `strict_verification`, so a reference has to land on the document element, an ancestor of the signature, or a sibling of the signature.
- `require_reference_digests`, so a signature without local digest coverage does not count.
- a minimum HMAC length of 160 bits.
- rejection of an `Assertion` or `Signature` nested under `SubjectConfirmationData`.
- extraction limited to content a verified reference covered.

The same path calls `with_insecure(true)`. That flag skips X.509 chain building and certificate time checks only. Metadata certificates are pinned key material, so saml-rs does not ask bergshamra to validate them as a public CA chain. Signature, digest, reference, duplicate-ID, and wrapping checks stay on. Do not replace this adapter with `DsigContext::new_permissive()`.

`MetadataTrustPolicy::UnsignedForCompatibility` can still parse a signed document and does not record that signature as verified. A certificate inside a metadata `KeyDescriptor` is not a trust anchor. Errata 05 E69 says no trust follows from including one.

## Your choices

The adapter does not pick your peer. `recommended()` does not invent a trust anchor or a replay cache.

- Import metadata with `MetadataTrustPolicy::RequireSignature` and the certificate you pinned out of band. `UnsignedForCompatibility` is the hatch the examples use so they compile alone.
- Pass `ReplayPolicy::RequireCache` with a cache you own on browser SSO.
- Start from `recommended()`, then add `AssertionSignaturePolicy::RequireSigned` or `XmlSignatureProfile::StrictRsaSha2` only when you want that hardening.
- Leave software RSA key-transport decryption off on RustCrypto unless you have a separate reason to opt in. That backend is affected by RUSTSEC-2023-0071. See [Security](../reference/security.md).

If you call bergshamra yourself, outside this crate, use the configuration secexample prints: trusted keys only, strict verification, and a minimum HMAC length. Inspect `VerifyResult` references before you read an assertion. Leave the raw-inline-key hatch off for untrusted XML. That direct use is a different API from `Saml::sp`.

The runnable demos are `cargo run` in [secexample](https://github.com/kushaldas/secexample). Bergshamra's SAML note is in the [bergshamra README](https://github.com/kushaldas/bergshamra#recommended-configuration-for-saml).
