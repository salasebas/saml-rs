# EncryptedID and EncryptedAttribute

This change is unreleased. It applies to the release that first publishes
`XmlEncryptionPolicy::encrypt_ids` and `XmlEncryptionPolicy::encrypt_attributes`.

Nothing changes until a configuration selects one of them. Two things are new
for callers that handle errors or compare policies.

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
