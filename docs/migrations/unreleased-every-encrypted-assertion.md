# Every EncryptedAssertion is decrypted

This change is unreleased. It applies to the release in which a service
provider first decrypts each `<EncryptedAssertion>` of a `<Response>`, not only
the first.

## Expect a later `<EncryptedAssertion>` to be evaluated

Who must change: a service provider whose identity provider sends more than one
`<EncryptedAssertion>` in one `<Response>`.

`finish_sso`, `accept_unsolicited_sso`, and `finish_paos_sso` decrypt every
`<EncryptedAssertion>` and evaluate each decrypted `<Assertion>` as they
evaluate several plaintext ones: issuer, principal, audience, bearer
confirmation, time window, and replay. Before, only the first was decrypted,
and the rest were ignored. A later assertion that fails one of those checks now
rejects the response with that check's error, for example
`SamlError::AudienceMismatch`. Under `AssertionSignaturePolicy::RequireSigned`,
each decrypted assertion must carry its own signature, or the response fails
with `SamlError::SignatureMissing`.

An `<EncryptedAssertion>` that does not decrypt, for example one encrypted for
another recipient, now fails with `SamlError::Crypto`. There is no setting to
skip it. Ask the identity provider to send only assertions for this service
provider.

## Expect `decrypt_assertion` to decrypt every `<EncryptedAssertion>`

Who must change: code that calls `saml_rs::crypto::decrypt_assertion` or
`decrypt_assertion_with_limits` directly, or the raw `ServiceProvider` with a
decryption key.

The returned response has each `<EncryptedAssertion>` child of the document
element replaced by its `<Assertion>`, and the returned assertion is the first
one decrypted. Any one that does not decrypt fails the call. The raw flow reads
the first bearer `<Assertion>` of the decrypted response, as it does for
plaintext assertions.
