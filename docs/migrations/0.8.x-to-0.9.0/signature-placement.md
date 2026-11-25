# Set the signature prefix on `TemplatePolicy`

`TemplatePolicy::signature_config` is gone, and so are `SignatureConfig` and
`SignatureAction`. `TemplatePolicy` has a `signature_prefix: String` field in
their place, `ds` by default. The identity provider and service provider now
put every embedded `ds:Signature` in the slot the SAML schemas give it: right
after the signed element's `Issuer`, or first when the element has no
`Issuer`.

`SignatureConfig::reference` and `SignatureConfig::action` could put the
signature before `Issuer`, after `Status`, or inside `Extensions`. The
protocol schema allows `ds:Signature` only between `Issuer` and `Extensions`,
and the assertion schema only between `Issuer` and `Subject`, so a
schema-validating peer rejects the first two. `Extensions` can hold a
schema-valid foreign element, but a signature there is not the message
signature that SAML Core §5.4 profiles, so a peer that requires a signed
message, this crate included, treats the message as unsigned.

The prefix now also applies to assertion signatures. Before, an assertion
signature always used `ds`, whatever `SignatureConfig::prefix` said.

Code that names `SignatureConfig`, `SignatureAction`, or
`TemplatePolicy::signature_config` fails to compile. To keep a custom prefix,
set the new field:

```rust
use saml_rs::TemplatePolicy;

let mut templates = TemplatePolicy::default();
templates.signature_prefix = "sig".to_string();
```

Remove any `reference` and `action` you set. A peer that read the signature
in another position now receives it in the schema slot, which is where SAML
Core §5.4 profiles it.

The builders reject a `signature_prefix` that is not an XML NCName or that
begins with `xml` in any case, with `SamlError::Invalid`, as they did for
`SignatureConfig::prefix`.
