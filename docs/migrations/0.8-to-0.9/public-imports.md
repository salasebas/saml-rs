# 2. Move off the hidden modules

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** code that imports from a root module hidden from docs.rs:
`binding`, `context`, `crypto`, `entity`, `flow`, `idp`, `logout`, `sp`,
`template`, `util`, `validator`, or `xml`.

**Now:** the items in the table below have a documented path. Their old paths
still compile, and the deprecated functions warn. The helpers in
[2.5](#25-replace-the-helpers-that-are-no-longer-public) do not compile at
their old paths. The modules become crate-private in the next minor release, so
move every import in this table now. A moved type does not warn, because Rust
ignores `#[deprecated]` on a re-export.

| Old path | Documented path |
| --- | --- |
| `xml::XmlLimits`, `xml::dom::XmlLimits` | `saml_rs::XmlLimits` |
| `template::LoginResponseTemplate`, `template::LoginResponseAttribute` | `saml_rs::LoginResponseTemplate`, `saml_rs::LoginResponseAttribute` |
| `entity::SignatureConfig`, `entity::SignatureAction` | `saml_rs::SignatureConfig`, `saml_rs::SignatureAction` |
| `template::LOGIN_REQUEST_TEMPLATE`, `LOGIN_RESPONSE_TEMPLATE`, `LOGOUT_REQUEST_TEMPLATE`, `LOGOUT_RESPONSE_TEMPLATE` | The same names under `saml_rs::config` |
| `xml::ExtractorField`, `xml::LocalPath` | `saml_rs::raw::ExtractorField`, `saml_rs::raw::LocalPath` |
| `util::Value` | `saml_rs::raw::Value` |
| `binding::base64_encode`, `binding::base64_decode` (deprecated) | The `base64` crate. See [2.1](#21-use-the-base64-crate) |
| `template::attribute_statement_builder` (deprecated) | `RespondSso::attributes`. See [2.2](#22-pass-attributes-to-the-response) |
| `crypto::keys::load_private_key`, `crypto::construct_saml_signature`, `crypto::construct_message_signature`, `crypto::verify_signature`, `crypto::verify_signature_with_limits`, `crypto::verify_message_signature`, `crypto::decrypt_assertion` (deprecated) | The typed API, or `bergshamra`. See [2.3](#23-sign-verify-and-decrypt-through-the-typed-api) |
| `crypto::XmlSecurityBackend`, `crypto::BergshamraBackend` (deprecated) | The typed API, or `bergshamra`. See [2.3](#23-sign-verify-and-decrypt-through-the-typed-api) |
| `crypto::verify_metadata_signature`, `verify_metadata_signature_with_limits`, `verify_metadata_signature_detailed`, `verify_metadata_signature_detailed_with_limits` (deprecated) | `IdpDescriptor::from_metadata_xml` or `SpDescriptor::from_metadata_xml`. See [7](metadata.md#7-verify-signed-metadata-on-import) |
| `xml::dom::parse`, `parse_with_limits`, `parse_roots`, `parse_roots_with_limits`, `context::is_valid_xml` (deprecated) | An XML library. See [2.4](#24-parse-xml-with-an-xml-library) |

Update the imports. The types are the same, so the code that uses them does
not change:

```rust
use saml_rs::config::LOGIN_RESPONSE_TEMPLATE;
use saml_rs::raw::Value;
use saml_rs::{LoginResponseTemplate, TemplatePolicy, XmlLimits, XmlPolicy};
```

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

**Now:** it is deprecated. A typed identity provider passes attributes to the
response, and `respond_sso` and `initiate_sso` write the
`<AttributeStatement>`:

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue, Attributes, RespondSso};

let options = RespondSso::post().attributes(Attributes::new([Attribute::new(
    "urn:oid:0.9.2342.19200300.100.1.3",
    [AttributeValue::new("alice@example.com")],
)
.with_name_format(AttributeNameFormat::Uri)]));
```

`RespondSso::attributes` cannot be combined with a login response template,
and the typed methods give no values to `LoginResponseTemplate::attributes`.
See [4](sso-attributes.md#4-give-each-login-response-template-attribute-a-value).

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

## 2.5 Replace the helpers that are no longer public

**Affects:** code that calls one of these helpers from a hidden module.

**Now:** each helper is crate-private, removed, or merged into a function that
takes its limit as an argument. A call to it no longer compiles.

| Item | Use instead |
| --- | --- |
| `binding::redirect_binding_query` | `Outbound::redirect_url` from the typed operation. To build a query yourself, use `url::form_urlencoded::Serializer` |
| `binding::xml_escape` | An XML writer, or your own escaping of `&`, `<`, `>`, `"`, and `'` |
| `binding::html_escape` | An HTML template engine that escapes attribute values. `Outbound` builds the POST form |
| `binding::base64_decode_with_limit` | The `base64` crate. Check the input length against your limit first. See [2.1](#21-use-the-base64-crate) |
| `binding::deflate_raw_decode_with_limit` | `binding::deflate_raw_decode(input, max_output_len)`. The one-argument `deflate_raw_decode` is removed. Pass `MAX_DEFLATE_RAW_DECODE_BYTES` to keep its limit |
| `util::normalize_cert_string` | Your own code that removes the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines and all whitespace |
| `util::normalize_pem_string` | Your own code that removes the `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----` lines and all whitespace |
| `util::uniq`, `util::camel_case`, `util::zip_object` | Your own code. They served the internal field extractor |
| `entity::generate_id` | The typed operations, which write the `ID` of every message and assertion they generate |
| `entity::now_iso8601` | `time::OffsetDateTime::now_utc()`, written as `YYYY-MM-DDTHH:MM:SSZ` |
| `template::attr_tag` | The placeholder `{attr<Tag>}`: `attr` and the `value_tag` in camel case with a capital first letter, such as `{attrEmail}` for `email` |
| `xml::fields` | The typed results, such as `SsoSession` and `LogoutRequest` |
| `xml::dom::DEFAULT_XML_MAX_*` | The fields of `XmlLimits::default()`, such as `XmlLimits::default().max_bytes`. Each field's documentation states its default |
| `validator::verify_time` | The typed receive operations, which check time windows with the `ClockSkew` of `SamlValidationContext` |
| `validator::check_status_with_limits` | `validator::check_status(content, parser_type, limits)`. The two-argument `check_status` is removed. Pass `XmlLimits::default()` to keep its limits |
