# EncryptedID and EncryptedAttribute

This change is unreleased. It applies to the release that first publishes
`XmlEncryptionPolicy::encrypt_ids` and `XmlEncryptionPolicy::encrypt_attributes`.

Generation stays off until a configuration selects one of them. A service
provider or identity provider with `Credentials::decryption_key` now decrypts
the encrypted elements it receives without that selection, as Conformance
§3.4 requires. Callers that handle errors or compare policies also have two
new things to handle.

## Expect decrypted elements in a response you did not select them for

Who must change: a service provider that configures
`Credentials::decryption_key` and whose identity provider sends
`<EncryptedAssertion>`, `<EncryptedID>`, or `<EncryptedAttribute>` that its
`XmlEncryptionPolicy` does not select, for example Shibboleth IdP, which
encrypts assertions by default.

`finish_sso`, `accept_unsolicited_sso`, and `finish_paos_sso` used to reject a
response with an unselected `<EncryptedAssertion>` or `<EncryptedID>`, and
ignore an unselected `<EncryptedAttribute>`. They now decrypt each one with the
`decryption_key` and return the session. An `<EncryptedAttribute>` that does
not decrypt, for example one encrypted for another recipient, now fails with
`SamlError::Crypto` instead of being ignored. On RustCrypto, decryption still
needs `XmlEncryptionPolicy::with_insecure_software_rsa_key_transport_decryption_allowed`;
without it such a response now fails with that error. Selecting
`encrypt_assertions`, `encrypt_ids`, or `encrypt_attributes` still rejects the
plaintext form. Without a `decryption_key`, nothing changes.

## Expect a `NameID` from an encrypted `AuthnRequest` subject

Who must change: an identity provider that configures
`Credentials::decryption_key` and matches
`RequestedSubjectIdentifier::EncryptedId` from `receive_sso` or
`receive_paos_sso`.

A requested `<Subject>` whose `<EncryptedID>` decrypts is now
`RequestedSubjectIdentifier::NameId`. The request must be signed, or its
`EncryptedData` must use AES-GCM. `EncryptedId` now means that the identifier
was not decrypted: there is no `decryption_key`, the request is unsigned and
uses CBC, or the ciphertext does not decrypt to one `<NameID>`. Answer it with
an error `<Response>`, as for a requested subject you do not recognize.

## Handle the new error

Who must change: code that maps every `SamlError` variant to its own outcome,
for example a log or HTTP status table, without a fallback.

`SamlError::EncryptionRequired { element }` is new. A service provider returns
it from `finish_sso` and `accept_unsolicited_sso` when it selects
`encrypt_ids` and the assertion `<Subject>` carries a plaintext `<NameID>`
(`element` is `"NameID"`), or when it selects `encrypt_attributes` and an
`<AttributeStatement>` carries a plaintext `<Attribute>` (`element` is
`"Attribute"`). Treat it as a rejected response:

```rust
use saml_rs::SamlError;

fn rejected_because_plaintext(error: &SamlError) -> bool {
    matches!(error, SamlError::EncryptionRequired { .. })
}
```

## Expect two more fields on `XmlEncryptionPolicy`

Who must change: code that prints or compares the `Debug` output of
`XmlEncryptionPolicy`, `XmlPolicy`, `SpConfig`, `IdpConfig`, or
`EntitySetting`.

`XmlEncryptionPolicy` gains `identifiers` and `attributes`. Both default to the
plaintext form, so `XmlEncryptionPolicy::default()` and
`XmlEncryptionPolicy::encrypt_assertions()` generate and accept what they did
before. The `Debug` output of these types now includes the new fields.

## Expect a `NameID` from an encrypted `LogoutRequest`

Who must change: an identity provider or service provider that configures
`Credentials::decryption_key` and whose peer sends `LogoutRequest` with
`<EncryptedID>`, for example Shibboleth IdP by default.

`receive_slo` used to return such a request with no `name_id()`. When the
request is signed, or arrives on an authenticated SOAP channel, it now
decrypts the `<EncryptedID>` and returns the `NameID` it carries. Use that
`NameID` to find the principal's sessions. A request encrypted for another key
now fails with `SamlError::Crypto` instead of being accepted. Without a
`decryption_key`, or for an unsigned request, nothing changes.

Sending `<EncryptedID>` is off until `StartSlo::identifier_encryption`
selects it. The `Debug` output of `StartSlo` now includes that field.
