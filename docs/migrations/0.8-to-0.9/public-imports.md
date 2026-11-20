# 2. Move off the hidden modules

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** code that imports from a root module hidden from docs.rs:
`binding`, `context`, `crypto`, `entity`, `flow`, `idp`, `logout`, `sp`,
`template`, `util`, `validator`, or `xml`.

**Now:** the items below have a documented path. The old paths still compile,
and the deprecated functions warn. The modules become crate-private in the next
minor release, so move every import in this table now. A moved type does not
warn, because Rust ignores `#[deprecated]` on a re-export.

| Old path | Documented path |
| --- | --- |
| `xml::XmlLimits`, `xml::dom::XmlLimits` | `saml_rs::XmlLimits` |
| `template::LoginResponseTemplate`, `template::LoginResponseAttribute` | `saml_rs::raw::LoginResponseTemplate`, `saml_rs::raw::LoginResponseAttribute` |
| `entity::SignatureConfig`, `entity::SignatureAction` | `saml_rs::SignatureConfig`, `saml_rs::SignatureAction` |
| `template::LOGIN_REQUEST_TEMPLATE`, `template::LOGIN_RESPONSE_TEMPLATE` | `saml_rs::config::AUTHN_REQUEST_TEMPLATE`, `saml_rs::config::SSO_RESPONSE_TEMPLATE` |
| `template::LOGOUT_REQUEST_TEMPLATE`, `template::LOGOUT_RESPONSE_TEMPLATE` | The same names under `saml_rs::config` |
| `xml::ExtractorField`, `xml::LocalPath` | `saml_rs::raw::ExtractorField`, `saml_rs::raw::LocalPath` |
| `util::Value` | `saml_rs::raw::Value` |
| `binding::base64_encode`, `binding::base64_decode` (deprecated) | The `base64` crate. See [2.1](#21-use-the-base64-crate) |
| `template::attribute_statement_builder` (deprecated) | `SsoAssertion::with_attributes`. See [2.2](#22-pass-attributes-to-the-response) |
| `crypto::keys::load_private_key`, `crypto::construct_saml_signature`, `crypto::construct_message_signature`, `crypto::verify_signature`, `crypto::verify_signature_with_limits`, `crypto::verify_message_signature`, `crypto::decrypt_assertion` (deprecated) | The typed API, or `bergshamra`. See [2.3](#23-sign-verify-and-decrypt-through-the-typed-api) |
| `crypto::XmlSecurityBackend`, `crypto::BergshamraBackend` (deprecated) | The typed API, or `bergshamra`. See [2.3](#23-sign-verify-and-decrypt-through-the-typed-api) |
| `crypto::verify_metadata_signature`, `verify_metadata_signature_with_limits`, `verify_metadata_signature_detailed`, `verify_metadata_signature_detailed_with_limits` (deprecated) | `IdpDescriptor::from_metadata_xml` or `SpDescriptor::from_metadata_xml`. See [7](metadata.md#7-verify-signed-metadata-on-import) |
| `xml::dom::parse`, `parse_with_limits`, `parse_roots`, `parse_roots_with_limits`, `context::is_valid_xml` (deprecated) | An XML library. See [2.4](#24-parse-xml-with-an-xml-library) |

Update the imports, and rename `LOGIN_REQUEST_TEMPLATE` and
`LOGIN_RESPONSE_TEMPLATE` where you use them. The other items are the same, so
the code that uses them does not change:

```rust
use saml_rs::config::SSO_RESPONSE_TEMPLATE;
use saml_rs::raw::{LoginResponseTemplate, Value};
use saml_rs::{TemplatePolicy, XmlLimits, XmlPolicy};
```

A typed config sets an SSO template on the role's builder, not through
`TemplatePolicy`, as
[Set SSO templates on the role's builder](config.md#set-sso-templates-on-the-roles-builder)
shows.

## 2.1 Use the `base64` crate

**Affects:** callers of `saml_rs::binding::base64_encode` or
`saml_rs::binding::base64_decode`.

**Now:** both are deprecated. They are the standard alphabet with padding and
no line wrapping, which is `STANDARD` in the
[`base64`](https://docs.rs/base64) crate. `base64_decode` also skips ASCII
whitespace: space, tab, line feed, form feed, and carriage return. `STANDARD`
rejects whitespace, so remove it before you decode input that may be
line-wrapped:

```rust
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

let encoded = STANDARD.encode(xml.as_bytes());

let compact: Vec<u8> = received
    .bytes()
    .filter(|byte| !byte.is_ascii_whitespace())
    .collect();
let decoded = STANDARD.decode(compact)?;
```

`STANDARD.decode` returns `base64::DecodeError`, not `SamlError::Base64`.

## 2.2 Pass attributes to the response

**Affects:** callers of `saml_rs::template::attribute_statement_builder`.

**Now:** it is deprecated. A typed identity provider passes attributes in the
`SsoAssertion` it answers with, and `respond_sso` and `initiate_sso` write the
`<AttributeStatement>`:

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue, Attributes, NameId, SsoAssertion};

let assertion = SsoAssertion::new(NameId::new("alice@example.com")).with_attributes(Attributes::new([
    Attribute::new(
        "urn:oid:0.9.2342.19200300.100.1.3",
        [AttributeValue::new("alice@example.com")],
    )
    .with_name_format(AttributeNameFormat::Uri),
]));
```

`SsoAssertion::with_attributes` cannot be combined with
`IdpConfigBuilder::sso_response_template`, and a typed identity provider has
no template attributes. See
[4](sso-attributes.md#4-give-each-login-response-template-attribute-a-value).

## 2.3 Sign, verify, and decrypt through the typed API

**Affects:** callers of `saml_rs::crypto::keys::load_private_key`,
`construct_saml_signature`, `construct_message_signature`, `verify_signature`,
`verify_signature_with_limits`, `verify_message_signature`,
`decrypt_assertion`, or `BergshamraBackend::verify_signature` through the
`XmlSecurityBackend` trait. No saml-rs operation takes an
`XmlSecurityBackend`.

**Now:** they are deprecated, and saml-rs has no public replacement for them.
The typed API signs, verifies, and decrypts the messages it creates and
receives. Pass the key in `Credentials` as a `PrivateKeyPem`.

The three verifiers return `Ok` when the input is unsigned or its signature
does not verify: `verify_signature` and `verify_signature_with_limits` return
`Ok((false, None))`, and `verify_message_signature` returns `Ok(false)`. A
call that only applies `?` to the result accepts such input. Until you
migrate, check the returned `bool`.

To sign, verify, or decrypt other XML, call
[`bergshamra`](https://docs.rs/bergshamra) directly. Call
`saml_rs::initialize_crypto_provider` first, and load the key with
`bergshamra::keys::loader::load_pem_auto`.

## 2.4 Parse XML with an XML library

**Affects:** callers of `saml_rs::xml::dom::parse`, `parse_with_limits`,
`parse_roots`, `parse_roots_with_limits`, or `saml_rs::context::is_valid_xml`.

**Now:** they are deprecated. The typed API parses and checks every message it
receives. To read other XML, use an XML library such as
[`roxmltree`](https://docs.rs/roxmltree):

```rust
let document = roxmltree::Document::parse(xml)?;
let id = document.root_element().attribute("ID");
```
