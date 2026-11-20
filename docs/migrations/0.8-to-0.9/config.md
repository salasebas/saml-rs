# Upgrade typed config code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers callers that build an `SpConfig` or `IdpConfig`, fill
`Credentials`, build a policy, limit, or input struct with a struct literal,
destructure a started flow, set an `XmlEncryptionPolicy`,
`AudienceValidationPolicy`, or `TemplatePolicy`, or configure an SSO template.
Apply the sections that match your integration.

## Pass the first endpoint to `builder`

**Affects:** every call to `SpConfig::builder` and `IdpConfig::builder`.

**Before:** `builder` took the entity ID alone. `build()` returned
`SamlError::MissingMetadata("AssertionConsumerService")` for an SP without
`acs_endpoint`, and `MissingMetadata("SingleSignOnService")` for an IdP
without `sso_endpoint`.

**Now:** `SpConfig::builder(entity_id, acs)` takes the first
`AssertionConsumerService` endpoint, and `IdpConfig::builder(entity_id, sso)`
takes the first `SingleSignOnService` endpoint. The metadata schema requires
one of each, so a config without one no longer compiles. `acs_endpoint` and
`sso_endpoint` append the next endpoints, as before, and `acs_endpoints` and
`sso_endpoints` append several. `mark_default` is now `with_default`, as
[Rename the remaining calls](browser-transport.md#rename-the-remaining-calls)
describes.

**Upgrade:** move the first `acs_endpoint` or `sso_endpoint` argument into
`builder`:

```rust
// Before
let sp = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?.mark_default())
    .acs_endpoint(AcsEndpoint::artifact("https://sp.example.com/acs/artifact")?)
    .build()?;

// Now
let sp = SpConfig::builder(
    EntityId::try_new("https://sp.example.com/metadata")?,
    AcsEndpoint::post("https://sp.example.com/acs")?.with_default(),
)
.acs_endpoint(AcsEndpoint::artifact("https://sp.example.com/acs/artifact")?)
.build()?;
```

Remove the `MissingMetadata` arms that handled a missing endpoint from
`build()`.

## Remove the `?` after `Saml::sp` and `Saml::idp`

**Affects:** every call to `Saml::sp` and `Saml::idp`.

**Before:** both returned `Result`. They generated the metadata, so a config
that `build()` accepted could still fail there, for example with two ACS
endpoints that share an index.

**Now:** `build()` generates the metadata, returns its errors as
[section 6](metadata.md#6-handle-metadata-errors-from-build) lists, and keeps
the provider it made. `Saml::sp(config)` returns `Saml<Sp>` and
`Saml::idp(config)` returns `Saml<Idp>`.

**Upgrade:** handle metadata errors where you call `build()`. Then delete the
`?`, or the error handling, after `Saml::sp` and `Saml::idp`:

```rust
// Before
let sp = Saml::sp(config)?;

// Now
let sp = Saml::sp(config);
```

A function that returned `Saml::sp(..)` as its `Result` wraps it in `Ok`.

The `Debug` output of `SpConfig` and `IdpConfig` shows the 0.9 field names
and ends with `..`, for the provider it leaves out. Update a snapshot that
compares it.

## Publish an SP name identifier management endpoint by URL

**Affects:** service providers that call `SpConfigBuilder::manage_name_id_service`.

**Before:** it took a `ManageNameIdService`. `build()` returned
`SamlError::Unsupported` for `ManageNameIdService::soap`, because saml-rs does
not implement SOAP name identifier management for a service provider.

**Now:** the method is `manage_name_id_redirect_service`, and it takes the
`EndpointUrl` of the HTTP-Redirect endpoint. The identity provider's
`manage_name_id_service` still takes a `ManageNameIdService`.

**Upgrade:** rename the call and pass the URL:

```rust
// Before
let builder = builder.manage_name_id_service(ManageNameIdService::redirect(
    EndpointUrl::try_new("https://sp.example.com/nameid")?,
));

// Now
let builder = builder.manage_name_id_redirect_service(EndpointUrl::try_new(
    "https://sp.example.com/nameid",
)?);
```

## Remove `elements_order` from typed builders

**Affects:** callers of `SpConfigBuilder::elements_order` or
`IdpConfigBuilder::elements_order`, or readers of
`config.metadata.elements_order`.

**Before:** `elements_order` took a `Vec<String>` of element group names and
wrote the children of the role descriptor in that order. Generation ignored an
unknown name and wrote a repeated group again, as
[section 8](metadata.md#8-update-metadata-element-orders) describes.

**Now:** the typed builders have no `elements_order`, and the typed metadata
config has no getter for it. Typed metadata always lists `KeyDescriptor`,
`ArtifactResolutionService`, `SingleLogoutService`, `ManageNameIDService`,
`NameIDFormat`, then `SingleSignOnService` or `AssertionConsumerService`. The
metadata schema declares these children as an `xs:sequence` (Metadata
§§2.4.1 to 2.4.4). Any other order of the groups a config fills produces
metadata the schema rejects, and an order that keeps the sequence changes
nothing. The raw `SpMetadataInput` and `IdpMetadataInput` keep their
`elements_order`.

**Upgrade:** delete the call. A peer that validates metadata against the
schema accepts the new order. With the OneLogin order, which put
`NameIDFormat` before `SingleLogoutService`, the metadata now lists
`SingleLogoutService` first:

```rust
// Before
let builder = builder.elements_order(
    elements_order::ONELOGIN.iter().map(|name| name.to_string()).collect(),
);

// Now: no call. Generation writes the schema sequence.
```

## Read config fields and fill credentials

Section 1.8 of [Fix compile errors](compile-errors.md#18-read-config-fields-through-getters)
lists the getters that replace the 0.8 config fields, including the plural
endpoint lists such as `acs_endpoints()`. Section
[1.9](compile-errors.md#19-fill-credentials-with-the-with-methods) shows how
to fill `Credentials` with `X509Credential`, which replaces
`DecryptionCredential`.

## Assign fields instead of writing a struct literal

**Affects:** code that builds one of these structs with a struct literal,
including a literal that ends in `..SpValidationPolicy::recommended()` or
another base:

| Struct | Start from |
| --- | --- |
| `SpValidationPolicy`, `IdpValidationPolicy`, `LogoutPolicy` | `recommended()`, `compatibility()`, or `default()` |
| `XmlPolicy`, `AlgorithmPolicy`, `TemplatePolicy` | `default()` |
| `XmlLimits` | `default()` or `unbounded()` |
| `SignatureConfig`, `Organization` | `default()` |
| `ContactPerson` | `ContactPerson::new(contact_type)` |
| `Endpoint` | `Endpoint::new(binding, location)` |

**Before:** every field of these structs was public, so a struct literal
compiled.

**Now:** the structs are `#[non_exhaustive]`, and their fields stay public.
Outside saml-rs, a struct literal fails with `E0639`, also with a `..` base.
Reading a field does not change. `XmlEncryptionPolicy` follows the same rule,
as [Set `XmlEncryptionPolicy` fields directly](#set-xmlencryptionpolicy-fields-directly)
shows. So do `SpMetadataInput` and `IdpMetadataInput`, the renamed 0.8
`SpMetadataConfig` and `IdpMetadataConfig`. Start them from `default()`, as
[Distinguish raw generation inputs from typed configs](metadata-api.md#distinguish-raw-generation-inputs-from-typed-configs)
shows.

**Upgrade:** take a value from the preset, `Default`, or constructor that the
table names, and assign each field you set. Assign a nested field through its
parent:

```rust
// Before
let validation = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::recommended()
};
let xml = XmlPolicy {
    limits: XmlLimits {
        max_depth: 64,
        ..XmlLimits::default()
    },
    ..XmlPolicy::default()
};
let contact = ContactPerson {
    email_addresses: vec!["mailto:ops@example.com".into()],
    ..ContactPerson::new(ContactType::Technical)
};

// Now
let mut validation = SpValidationPolicy::recommended();
validation.assertions = AssertionSignaturePolicy::RequireSigned;
let mut xml = XmlPolicy::default();
xml.limits.max_depth = 64;
let mut contact = ContactPerson::new(ContactType::Technical);
contact.email_addresses = vec!["mailto:ops@example.com".into()];
```

A literal that listed every field has no base. Start it from `default()`, or
from the constructor the table names, and assign each field it listed.

## Destructure `Started` and `StartedPaosSso` with a rest pattern

**Affects:** code that destructures a `Started` or a `StartedPaosSso` with a
struct pattern.

**Before:** a pattern could list every field, such as
`Started { pending, outbound }`.

**Now:** both structs are `#[non_exhaustive]`. Outside saml-rs, a struct
pattern without `..` fails with `E0638`. Reading a field, such as
`started.pending`, does not change.

**Upgrade:** end the pattern with `..`:

```rust
// Before
let Started { pending, outbound } = sp.start_sso(&idp, StartSso::redirect())?;

// Now
let Started { pending, outbound, .. } = sp.start_sso(&idp, StartSso::redirect())?;
```

## Set `XmlEncryptionPolicy` fields directly

**Affects:** callers of `XmlEncryptionPolicy::encrypt_assertions`,
`encrypt_ids`, `encrypt_attributes`, `with_max_decryption_work`,
`max_decryption_work()`, or `with_rsa15_key_transport_decryption_allowed`.

**Before:** three presets each set one field, two settings were private
fields behind `with_` methods, and the other three were public fields.

**Now:** every setting is a public field. Start from
`XmlEncryptionPolicy::default()` and assign the fields you select. The struct
is `#[non_exhaustive]`, so a struct literal does not compile outside saml-rs.
The RSA-v1.5 opt-in is the `rsa15_key_transport` field, a
`Rsa15KeyTransportPolicy`. Defaults do not change.

| 0.8 | 0.9 |
| --- | --- |
| `XmlEncryptionPolicy::encrypt_assertions()` | `.assertions = AssertionEncryptionPolicy::EncryptAssertions` |
| `XmlEncryptionPolicy::encrypt_ids()` | `.identifiers = IdentifierEncryptionPolicy::EncryptIdentifiers` |
| `XmlEncryptionPolicy::encrypt_attributes()` | `.attributes = AttributeEncryptionPolicy::EncryptAttributes` |
| `.with_max_decryption_work(n)`, `.max_decryption_work()` | `.max_decryption_work = n`, `.max_decryption_work` |
| `.with_rsa15_key_transport_decryption_allowed()` | `.rsa15_key_transport = Rsa15KeyTransportPolicy::AllowDecryption` |

**Upgrade:** assign the fields you select:

```rust
// Before
let encryption = XmlEncryptionPolicy::encrypt_assertions()
    .with_max_decryption_work(64)
    .with_rsa15_key_transport_decryption_allowed();

// Now
let mut encryption = XmlEncryptionPolicy::default();
encryption.assertions = AssertionEncryptionPolicy::EncryptAssertions;
encryption.rsa15_key_transport = Rsa15KeyTransportPolicy::AllowDecryption;
encryption.max_decryption_work = 64;
```

## Rename `AudienceValidationPolicy::Validate` to `RequireRestriction`

**Affects:** code that names `AudienceValidationPolicy::Validate`.

**Before:** `Validate` was the strictest value. It also rejected a bearer
assertion without `<AudienceRestriction>`, which the recommended
`EvaluatePresentRestrictions` accepts.

**Now:** the variant is `RequireRestriction`. The behavior is the same.

**Upgrade:** rename each use:

```rust
let mut validation = SpValidationPolicy::recommended();
// Before: AudienceValidationPolicy::Validate
validation.audience = AudienceValidationPolicy::RequireRestriction;
```

## Send RelayState per request

**Affects:** service providers that set `TemplatePolicy::relay_state`.

**Before:** `start_sso` without `StartSso::relay_state` sent
`TemplatePolicy::relay_state` as the RelayState. The pending request did not
record it, so `finish_sso` did not compare the RelayState the identity
provider returned.

**Now:** the field is removed. A request carries no RelayState unless you set
one, and the pending request records what was sent.

**Upgrade:** pass the value on each request that needs it:

```rust
// Before
let sp = Saml::sp(
    SpConfig::builder(entity_id)
        .acs_endpoint(acs)
        .templates(TemplatePolicy {
            relay_state: "/home".into(),
            ..TemplatePolicy::default()
        })
        .build()?,
)?;
let started = sp.start_sso(&idp, StartSso::redirect())?;

// Now
let sp = Saml::sp(SpConfig::builder(entity_id, acs).build()?);
let started = sp.start_sso(
    &idp,
    StartSso::redirect().relay_state(RelayState::try_new("/home")?),
)?;
```

## Set the EncryptedAssertion prefix with the assertion prefix

**Affects:** identity providers that set
`TemplatePolicy::tag_prefix_encrypted_assertion`.

**Before:** the field set the prefix of a generated `<EncryptedAssertion>`,
apart from `tag_prefix_assertion`, although both elements are in the
assertion namespace.

**Now:** the field is removed. A typed identity provider writes
`<EncryptedAssertion>` with `tag_prefix_assertion`, which defaults to `saml`,
as the old field did. The raw `EntitySetting` keeps its field.

**Upgrade:** delete the field. If you set it to a value other than
`tag_prefix_assertion`, an encrypted response now uses the assertion prefix.
The namespace is the same, so a peer that reads namespaces reads the same
element.

## Set SSO templates on the role's builder

**Affects:** callers that set `TemplatePolicy::login_request_template` or
`TemplatePolicy::login_response_template`.

**Before:** `SpConfigBuilder::templates` and `IdpConfigBuilder::templates`
took the same `TemplatePolicy`, and each role read one of its two SSO
templates. A service provider rendered its `<AuthnRequest>` from
`login_request_template`, an `Option<String>`. An identity provider rendered
its `<Response>` from `login_response_template`, an
`Option<LoginResponseTemplate>` with a `context` template and an `attributes`
list. A config that set the other role's template built and ignored it.
`LoginResponseTemplate` and the default templates were importable only from
the hidden `saml_rs::template` module.

**Now:** `TemplatePolicy` has no SSO template. Set the `<AuthnRequest>`
template with `SpConfigBuilder::authn_request_template` and the SSO
`<Response>` template with `IdpConfigBuilder::sso_response_template`. Each
takes the template text, and `SpConfig::authn_request_template()` and
`IdpConfig::sso_response_template()` return it. A config that sets the other
role's template no longer compiles. The default templates to start from are
`saml_rs::config::AUTHN_REQUEST_TEMPLATE` and
`saml_rs::config::SSO_RESPONSE_TEMPLATE`. `LoginResponseTemplate` and
`LoginResponseAttribute` remain for the raw
`EntitySetting::login_response_template`, under `saml_rs::raw`.

**Upgrade:**

1. On a service provider, pass the template to `authn_request_template`:

   ```rust
   // Before
   let sp = Saml::sp(
       SpConfig::builder(entity_id)
           .acs_endpoint(acs)
           .templates(TemplatePolicy {
               login_request_template: Some(template),
               ..TemplatePolicy::default()
           })
           .build()?,
   )?;

   // Now
   let sp = Saml::sp(
       SpConfig::builder(entity_id, acs)
           .authn_request_template(template)
           .build()?,
   );
   ```

2. On an identity provider, pass the `context` text to
   `sso_response_template`:

   ```rust
   // Before
   use saml_rs::template::LoginResponseTemplate;

   let idp = Saml::idp(
       IdpConfig::builder(entity_id)
           .sso_endpoint(sso)
           .templates(TemplatePolicy {
               login_response_template: Some(LoginResponseTemplate {
                   context: Some(template),
                   attributes: vec![],
               }),
               ..TemplatePolicy::default()
           })
           .build()?,
   )?;

   // Now
   let idp = Saml::idp(
       IdpConfig::builder(entity_id, sso)
           .sso_response_template(template)
           .build()?,
   );
   ```

3. Delete a template that you set on the other role's config. That role never
   rendered it.
4. Delete `LoginResponseTemplate::attributes` from a typed identity provider.
   The typed response methods never gave those attributes values, as
   [4](sso-attributes.md#4-give-each-login-response-template-attribute-a-value)
   describes. Pass the attributes with `SsoAssertion::with_attributes`. A
   response with attributes needs the built-in renderer, so leave
   `sso_response_template` unset.
5. Import the default templates from `saml_rs::config`:
   `template::LOGIN_REQUEST_TEMPLATE` is `AUTHN_REQUEST_TEMPLATE`, and
   `template::LOGIN_RESPONSE_TEMPLATE` is `SSO_RESPONSE_TEMPLATE`.

## Use one rule for generated XML prefixes

**Affects:** callers that set `TemplatePolicy::tag_prefix_protocol`,
`tag_prefix_assertion`, or `signature_config`, or the same fields of a raw
`EntitySetting`.

**Before:** three checks disagreed. Templates rejected a tag prefix that was
not an XML NCName or was exactly `xml` or `xmlns`. Signing and encryption
accepted only ASCII letters, digits, `_`, `-`, and `.`, and rejected `xml` and
`xmlns` in any case. `build()` did not check `SignatureConfig::prefix`, so a
prefix such as `ds:sig` failed when the first embedded XML signature was
written. A detached HTTP-Redirect signature does not use the prefix.

**Now:** every generated prefix must be an XML NCName that does not begin with
`xml` in any case. Namespaces in XML 1.0 §3 reserves those prefixes and says
documents should not use them. `build()` applies the rule to both tag prefixes
and to `SignatureConfig::prefix`, and returns `SamlError::Invalid`, for
example `SignatureConfig.prefix XML prefix must be an XML NCName`. Signing and
encryption now accept a non-ASCII NCName, and their messages say `must be an
XML NCName` in place of `contains an invalid character`. A prefix such as
`xmlsig`, `xml2`, or `XML` is now rejected everywhere.

**Upgrade:** choose an NCName that does not begin with `xml`, such as `ds` or
`saml2`, and update a check that compares the old message.
