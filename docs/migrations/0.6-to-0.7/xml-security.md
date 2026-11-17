# Check encryption and signature settings

[How to upgrade from 0.6 to 0.7](README.md)

If your IdP sets non-default `signed_reference_transforms`, verify the output
of `respond_sso` and `initiate_sso`. They now honour that setting. To retain
the old transforms, select `EnvelopedSignature` and `ExclusiveCanonicalization`.
Artifact responses, PAOS, and SOAP logout still use the default transforms.

If you configure `Credentials::decryption_key`, expect received encrypted
assertions, IDs, and attributes to be decrypted even when you did not select
their generation. Handle decryption failures instead of relying on ignored
attributes or undecrypted identifiers. An `<EncryptedAttribute>` that does not
decrypt, for example one encrypted for another recipient, returns
`SamlError::Crypto`. On RustCrypto, select
`with_insecure_software_rsa_key_transport_decryption_allowed` when needed.
Generation remains opt-in. Selecting encryption still requires the encrypted form.

For requested subjects, handle `RequestedSubjectIdentifier::NameId` after
decryption. A requested `<EncryptedID>` is decrypted only when the request is
signed or its `EncryptedData` uses AES-GCM. An undecrypted `EncryptedId` still needs an error response for
an unrecognised subject. For signed logout requests or requests over an
authenticated SOAP channel, use the decrypted NameID to find sessions.

If your peer sends multiple encrypted assertions, ensure all are intended
for this SP and pass validation. Every one is now decrypted and checked.
Under `AssertionSignaturePolicy::RequireSigned`, each must be signed,
including plaintext assertions beside encrypted ones in a response without
a verified signature. A later invalid or undecryptable assertion rejects
the whole response. There is no option to skip it.
Direct `decrypt_assertion` calls also decrypt every encrypted assertion,
while separately returning the first. Raw flows still read the first bearer assertion.

Require schema-shaped encrypted content from peers: one `EncryptedData`
followed only by `EncryptedKey` elements, decrypting to one Assertion.
Other content now returns `SamlError::ProtocolProfile`. No setting restores
the old behaviour.

If a peer uses RSA-v1.5 key transport, ask it to use RSA-OAEP. Otherwise,
select `with_rsa15_key_transport_decryption_allowed`, enable
`crypto-legacy-algorithms`, and retain the software RSA opt-in on RustCrypto.
Without that selection, any RSA-v1.5 key causes `SamlError::Unsupported`,
including sibling keys beside `EncryptedData`. For raw APIs, set
`allow_rsa15_key_transport_decryption` on `AssertionDecryptionOptions`,
`EntitySetting`, or `FlowOptions`.
See [XML security settings](../../conformance/xml-security-algorithms.md).
