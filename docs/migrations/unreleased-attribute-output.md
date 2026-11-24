# Handle attribute name errors and encryption key choice

If you run an identity provider, `IdentityProvider::respond_sso`,
`initiate_sso`, and their artifact variants now return `SamlError::Invalid`
for an attribute that SAML Core does not allow in an assertion. Metadata
generation returns the same error for such an entity attribute, from
`SpConfigBuilder::build`, `IdpConfigBuilder::build`, `generate_sp_metadata`,
and `generate_idp_metadata`. Before, these attributes were written.

An attribute is rejected in these cases:

- Its `Name` is empty or has only spaces, tabs, carriage returns, and line
  feeds.
- It has a `FriendlyName` that is empty or has only those characters.
- Its `NameFormat` is `AttributeNameFormat::Uri` and its `Name` is not an
  absolute URI reference, such as `mail`, `given name`, or a URN with a
  leading space. The name is checked as written, without trimming.

An empty value is still written as an empty `AttributeValue`.

To upgrade, leave the friendly name unset when you have no label, and give a
`uri` attribute its URI name:

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
now uses the first certificate in the service provider metadata that has an
RSA key. Before, it used the first encryption certificate and failed with
`SamlError::Crypto` when that certificate had another key type, such as an
EC key, or did not load. A service provider that lists an EC key before its
RSA key now receives responses encrypted for the RSA key.

With attribute encryption alone, an assertion without attributes no longer
needs an encryption certificate in the service provider metadata. Before,
the response failed with `SamlError::MissingMetadata`.

You do not need to change code for these two changes. Logout and name
identifier management requests still use the first encryption certificate.
