# 9. Move schema validation into XML policy

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** integrations that register a global schema validator or construct
`XmlPolicy` by listing every field.

## 9.1 Configure each local role

`context::set_schema_validator` is removed. Set the optional callback on each
role's `XmlPolicy` before building its configuration:

```rust
let mut xml = XmlPolicy::default();
xml.schema_validator = Some(validate_schema);
let config = sp_builder.xml(xml).build()?;
```

Import `saml_rs::SchemaValidator` in place of `context::SchemaValidator`.
The callback signature remains `fn(&str) -> Result<(), String>`. An error
rejects the input with `SamlError::Invalid`. Use `None` to build a configuration
without the additional schema check. A configuration does not change another
configuration's validator.

The callback receives decoded protocol documents, SOAP envelopes, and
protocol documents after decryption. It can run multiple times during
one operation. Support every document type used by that role, including SOAP
and extension schemas. Load schemas from trusted local resources and disable
network resolution in your validator.

`XmlPolicy` is non-exhaustive now. Replace a full
`XmlPolicy` literal as
[Assign fields instead of writing a struct literal](config.md#assign-fields-instead-of-writing-a-struct-literal)
describes.

## 9.2 Validate imported metadata explicitly

Metadata is imported before a local role receives a peer descriptor. Pass the
policy when importing it:

```rust
let idp = IdpDescriptor::from_metadata_xml_with_policy(
    expected_idp_entity_id,
    metadata_xml,
    trust,
    &xml,
)?;
```

`SpDescriptor` has the same constructor. Raw metadata offers
`IdpMetadata::from_xml_with_policy`, `SpMetadata::from_xml_with_policy`, and
`Metadata::parse_with_policy`. Existing constructors keep their default XML
limits and have no callback.
