# 2. Move off the hidden modules

[How to upgrade from 0.8 to 0.9](README.md)

Imports from `binding`, `context`, `crypto`, `template`, `util`, `validator`,
and `xml` no longer compile. The same applies to the compatibility crates
`opensaml`, `samlify`, and `samlet`. For the old `entity`, `flow`, `idp`,
`logout`, and `sp` imports, see [Move off the raw API](raw-api.md).

| Old import | Use instead |
| --- | --- |
| `xml::XmlLimits` or `xml::dom::XmlLimits` | `saml_rs::XmlLimits` |
| `context::SchemaValidator` | `saml_rs::SchemaValidator` |
| `entity::{SignatureConfig, SignatureAction}` | Removed; set `TemplatePolicy::signature_prefix`. See [Set the signature prefix on `TemplatePolicy`](signature-placement.md) |
| `template::{LOGOUT_REQUEST_TEMPLATE, LOGOUT_RESPONSE_TEMPLATE}` | [Typed logout operations](config.md#replace-logout-templates-with-typed-operations) |
| `crypto::{crypto_provider_info, initialize_crypto_provider, CryptoFipsStatus, CryptoProvider, CryptoProviderInfo}` | The same names in `saml_rs`, with a crypto provider enabled |

## 2.1 Use the `base64` crate

Replace `binding::base64_encode`, `binding::base64_decode`, and
`binding::base64_decode_with_limit` with the standard padded engine in the
[`base64`](https://docs.rs/base64) crate. Remove ASCII whitespace before decoding
to keep the old decoder's whitespace handling.

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

Map `base64::DecodeError` into your application's error type. If you used the
bounded decoder, check the length before allocating and the decoded length
afterward. The limit counts decoded bytes.

```rust
fn decode_with_limit(input: &str, max_output_len: usize) -> Option<Vec<u8>> {
    let encoded = || input.bytes().filter(|byte| !byte.is_ascii_whitespace());
    if encoded().count() > max_output_len.div_ceil(3).saturating_mul(4) {
        return None;
    }
    let compact: Vec<u8> = encoded().collect();
    let decoded = STANDARD.decode(compact).ok()?;
    (decoded.len() <= max_output_len).then_some(decoded)
}
```

## 2.2 Pass attributes to the response

Replace `template::attribute_statement_builder`, `LoginResponseAttribute`,
`ATTRIBUTE_TEMPLATE`, and `ATTRIBUTE_STATEMENT_TEMPLATE` with
`SsoAssertion::attributes`. The IdP writes the attribute statement when
you call `respond_sso` or `initiate_sso`.

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue, Attributes, NameId, SsoAssertion};
use std::time::SystemTime;

let authenticated_at = SystemTime::now();
let assertion = SsoAssertion::new(NameId::new("alice@example.com"), authenticated_at).attributes(Attributes::new([
    Attribute::new(
        "urn:oid:0.9.2342.19200300.100.1.3",
        [AttributeValue::new("alice@example.com")],
    )
    .with_name_format(AttributeNameFormat::Uri),
]));
```

For `LoginResponseTemplate`, `LOGIN_REQUEST_TEMPLATE`, and
`LOGIN_RESPONSE_TEMPLATE`, see how to
[replace SSO templates with typed options](config.md#replace-sso-templates-with-typed-options).
If you used `replace_tags_by_value`, `replace_tags_by_optional_value`, or
`attr_tag` with your own templates, use your own XML writer or template engine.

## 2.3 Sign, verify, and decrypt through the typed API

Configure key material with `Credentials`, `PrivateKeyPem`, and
`CertificatePem`. The typed operations sign and verify SAML messages and
apply the configured `XmlEncryptionPolicy`. To verify metadata, see
[Verify signed metadata on import](metadata.md#7-verify-signed-metadata-on-import).
That also replaces the four `verify_metadata_signature` variants and
`MetadataSignatureVerification`.

For standalone cryptographic operations, use
[`bergshamra`](https://docs.rs/bergshamra) directly. Initialize the configured
provider with `saml_rs::initialize_crypto_provider()` first.

| Removed helper in `crypto` | Operation in `bergshamra` |
| --- | --- |
| `keys::load_private_key`, `keys::load_certificate`, `keys::build_key_info` | `keys::loader::load_pem_auto`, `keys::loader::load_x509_cert_pem`, `keys::keyinfo::build_x509_key_info` |
| `construct_saml_signature`, `verify_signature`, `verify_signature_with_limits`, `XmlSecurityBackend`, `BergshamraBackend` | `sign`, `verify` |
| `construct_message_signature`, `verify_message_signature` | `crypto::sign::from_uri` and the resulting algorithm's `sign` or `verify` method |
| `encrypt_assertion`, `decrypt_assertion`, `decrypt_assertion_with_limits`, `AssertionDecryptionOptions` | `encrypt`, `decrypt` |

When calling `bergshamra` directly, configure trust and resource limits for your
input. Use the typed API when you need SAML message coverage and validation.

## 2.4 Parse XML with an XML library

Use an XML library such as [`roxmltree`](https://docs.rs/roxmltree) for
standalone XML parsing. This replaces `context::is_valid_xml`,
`context::is_valid_xml_with_limits`, and the `xml::dom` parsers and node types.
If you used the multi-root parsers, use a streaming XML reader and choose the
root rules and limits you need. Replace `xml::dom::DEFAULT_XML_MAX_*` with the
corresponding fields of `XmlLimits::default()`. In a constant, use the literal
default from the field's documentation because `XmlLimits::default()` is not
a `const fn`.

Replace `xml::extract`, `extract_with_limits`, `ExtractorField`, `LocalPath`,
the field definitions in `xml::fields`, and `util::Value` with typed results
such as `SsoSession` and `LogoutRequest`. For XML outside those flows, read the
elements and attributes with your XML library.

## 2.5 Replace the helpers that are no longer public

| Old helper | Use instead |
| --- | --- |
| `binding::build_redirect_url`, `build_redirect_octet`, `redirect_binding_query`, `append_signature` | Get the complete URL from `Outbound::redirect_url()`. It includes the signature parameters when required. |
| `binding::saml_post_binding_form`, `try_saml_post_binding_form` | Render the form in your application using the action and fields from `Outbound::post_form()`. |
| `binding::deflate_raw_encode`, `deflate_raw_decode`, `deflate_raw_decode_with_limit`, `MAX_DEFLATE_RAW_DECODE_BYTES` | Use `flate2`'s raw `DeflateEncoder` or `DeflateDecoder`. For bounded reads, take up to one byte beyond your limit and reject outputs longer than the limit. The old constant and one-argument decoder used a 1 MiB limit. |
| `binding::xml_escape`, `binding::html_escape` | Use an XML writer or an HTML template engine that escapes attribute values. |
| `validator::verify_time` | Use the typed receive operations with the `ClockSkew` of `SamlValidationContext`. |
| `validator::check_status`, `check_status_with_limits` | Read the typed outcome or handle the `SamlError::StatusNotSuccess` from the typed operation. |
| `util::normalize_cert_string`, `normalize_pem_string` | Use a PEM reader, or pass PEM to `CertificatePem` or `PrivateKeyPem` for a typed configuration. |
| `util::uniq`, `camel_case`, `zip_object` | Use your own collection or string operations. |
| `entity::generate_id`, `entity::now_iso8601` | Typed operations set message IDs and issue instants. For standalone timestamps, use `time::OffsetDateTime::now_utc()`. |
