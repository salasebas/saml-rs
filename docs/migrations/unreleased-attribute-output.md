# Handle attribute name errors and encryption key choice

If you run an identity provider, `IdentityProvider::respond_sso`,
`initiate_sso`, and their artifact variants now return `SamlError::Invalid`
for an attribute that SAML Core does not allow in an assertion. Metadata
generation returns the same error for such an entity attribute, from
`SpConfigBuilder::build`, `IdpConfigBuilder::build`, `generate_sp_metadata`,
and `generate_idp_metadata`. Before, these attributes were written, except
a `basic` name that was empty or had only whitespace.

An attribute is rejected in these cases:

- Its `Name` is empty or has only spaces, tabs, carriage returns, and line
  feeds.
- It has a `FriendlyName` that is empty or has only those characters.
- It has a value with only those characters. An empty value is still
  written, as an empty `AttributeValue`.
- Its `NameFormat` is `AttributeNameFormat::Uri` and its `Name` is not an
  absolute URI reference, such as `mail`, `given name`, or a URN with a
  leading space. The name is checked as written, without trimming.

`Attribute::with_name_format` now stores `AttributeNameFormat::Custom` with
the `uri`, `basic`, or `unspecified` URI and surrounding whitespace as that
variant, and `Attribute::name_format` returns it. The `uri` and `basic` name
rules then apply to it, and so do the `subject-id` and `pairwise-id` rules of
`SsoAssertion::attributes`.

To upgrade, leave the friendly name unset when you have no label, pass an
empty value instead of one with only whitespace, and give a `uri` attribute
its URI name. A `subject-id` or `pairwise-id` value must still be
`uniqueID@scope`, so it cannot be empty:

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue};

let mail = Attribute::new(
    "urn:oid:0.9.2342.19200300.100.1.3",
    [AttributeValue::new("alice@example.com")],
)
.with_name_format(AttributeNameFormat::Uri)
.with_friendly_name("mail");
```

If the attribute name is a short name such as `mail`, use
`AttributeNameFormat::Basic` or `AttributeNameFormat::Unspecified` instead
of `AttributeNameFormat::Uri`.

## Encryption certificate choice

An identity provider that encrypts assertions, identifiers, or attributes
now uses the first encryption key in the service provider metadata that the
configured algorithms can encrypt for. Before, the identity provider used the
first encryption certificate and failed with `SamlError::Crypto` when it did
not load or the crypto provider could not encrypt for it, such as an EC key
or an RSA key too small for the key transport. Now it tries the next key.
When no key works, it still returns the `SamlError::Crypto` error of the
first key.

The keys come from the service provider role that publishes the
`AssertionConsumerService` receiving the response. When several roles
publish that endpoint, they come from the first of them. Before, the
identity provider took the first encryption certificate of any service
provider role. A role that publishes the endpoint but no
encryption certificate now returns `SamlError::MissingMetadata`, even when
another role of the entity publishes one. To fix it, ask the service provider
to publish its encryption certificate in the role that receives the response.

Each `ds:X509Data` of a `KeyDescriptor` whose `use` is `encryption` or absent
gives one key, in document order. A sole certificate is that key, whatever
else the `KeyInfo` declares, such as `KeyName`, `KeyValue`, or
`X509SubjectName`. In a certificate chain, the key is the first certificate
that issued none of the others, in any order. Before, the identity provider used the first
certificate of the first `KeyDescriptor`, which in a chain that lists its
issuer first is the issuer certificate.

With attribute encryption alone, an assertion without attributes no longer
needs an encryption certificate in the service provider metadata. Before,
the response failed with `SamlError::MissingMetadata`.

You do not need to change code for these changes. Logout and name
identifier management requests read keys from a role the same way, as
[Encrypt for a usable key and write its certificate](unreleased-outbound-encryption-keys.md)
describes.
