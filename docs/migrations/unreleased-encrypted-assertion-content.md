# EncryptedAssertion content

This change is unreleased. It applies to the release in which an
`<EncryptedAssertion>` key placed beside `<xenc:EncryptedData>` and named by a
`ds:RetrievalMethod` is first decrypted.

## Expect `ProtocolProfile` for an `<EncryptedAssertion>` outside its schema

Who must change: a service provider whose identity provider sends an
`<EncryptedAssertion>` that does not match `EncryptedElementType`, and code
that calls `saml_rs::crypto::decrypt_assertion` or
`decrypt_assertion_with_limits` directly.

The `<EncryptedAssertion>` decrypted is the first child of the document element
in the SAML assertion namespace. It must hold one `<xenc:EncryptedData>`
followed only by `<xenc:EncryptedKey>` elements. Comments, processing
instructions, and whitespace may appear between them. Its plaintext must be one
`<Assertion>`. Anything else now fails with `SamlError::ProtocolProfile`.
Before, other children were ignored, `decrypt_assertion` returned whatever
plaintext it decrypted, and an element named `EncryptedAssertion` in another
namespace was decrypted.

There is no setting to restore the old behaviour. Ask the identity provider to
send the schema form.

## Expect an RSA-v1.5 `<EncryptedKey>` beside `EncryptedData` to be refused

Who must change: a service provider whose identity provider places an
RSA-v1.5 `<EncryptedKey>` after `<xenc:EncryptedData>`, for example one key for
each of several recipients.

The RSA-v1.5 refusal in
[RSA-v1.5 key-transport decryption](unreleased-rsa15-key-transport-decryption.md)
now covers every `<EncryptedKey>` in the `<EncryptedAssertion>`, as it already
did for `<EncryptedID>` and `<EncryptedAttribute>`. A response whose embedded
key uses RSA-OAEP fails with `SamlError::Unsupported` when another key beside
`EncryptedData` uses RSA-v1.5, unless RSA-v1.5 decryption is selected.
