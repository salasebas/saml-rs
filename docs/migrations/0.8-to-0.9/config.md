# Upgrade typed config code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers callers that build an `SpConfig` or `IdpConfig`, fill
`Credentials`, build a policy, limit, or input struct with a struct literal,
destructure one or a started flow, match on a policy enum, set an
`XmlEncryptionPolicy`, `AudienceValidationPolicy`, or `TemplatePolicy`,
build a config without a crypto provider, or configure an SSO template. Apply the sections that match your integration.

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

## Call `ServiceProvider::new` and `IdentityProvider::new` without `?`

**Affects:** every call to `Saml::sp` and `Saml::idp`.

**Before:** both returned `Result`. They generated the metadata, so a config
that `build()` accepted could still fail there, for example with two ACS
endpoints that share an index.

**Now:** `build()` generates the metadata, returns its errors as
[section 6](metadata.md#6-handle-metadata-errors-from-build) lists, and keeps
the provider it made. `ServiceProvider::new(config)` returns a
`ServiceProvider` and `IdentityProvider::new(config)` returns an
`IdentityProvider`. Both replace `Saml::sp` and `Saml::idp`, as
[1.25](compile-errors.md#125-replace-samlsp-and-samlidp-with-serviceprovider-and-identityprovider)
shows.

**Upgrade:** handle metadata errors where you call `build()`. Then call
`ServiceProvider::new` and `IdentityProvider::new` without the `?`, or the
error handling, that followed `Saml::sp` and `Saml::idp`:

```rust
// Before
let sp = Saml::sp(config)?;

// Now
let sp = ServiceProvider::new(config);
```

A function that returned `Saml::sp(..)` as its `Result` wraps
`ServiceProvider::new(..)` in `Ok`.

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
unknown name and wrote a repeated group again.

**Now:** the typed builders have no `elements_order`, and the typed metadata
config has no getter for it. Typed metadata always lists `KeyDescriptor`,
`ArtifactResolutionService`, `SingleLogoutService`, `ManageNameIDService`,
`NameIDFormat`, then `SingleSignOnService` or `AssertionConsumerService`. The
metadata schema declares these children as an `xs:sequence` (Metadata
§§2.4.1 to 2.4.4). Any other order of the groups a config fills produces
metadata the schema rejects, and an order that keeps the sequence changes
nothing. The same sequence applies to the
[standalone generators](metadata.md#8-remove-metadata-element-orders).

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

## Pass each key with the certificate of its key pair

**Affects:** builds with a crypto provider feature that pass `Credentials`
to `SpConfigBuilder::credentials` or `IdpConfigBuilder::credentials`.

**Before:** `build()` checked only that a credential the selected policy
needs was set. It did not read the PEM. A key or certificate that did not load
built, and the metadata published the certificate text as written. The first
signature or decryption then returned `SamlError::Crypto`. A signing key with
the certificate of another key pair signed every message, and every peer
rejected the signatures.

**Now:** `build()` loads the key of the signing credential and of each
decryption credential with its passphrase. It loads every certificate,
including each additional signing certificate, and checks that each key is the
private key of its certificate. A failure returns `SamlError::Crypto`. Its
message names the credential, then the problem:

| Problem | Cause |
| --- | --- |
| `the private key does not load` | The key is not PEM that the crypto provider reads, or its passphrase is wrong |
| `the private key PEM holds only a public key` | The key field holds a certificate or a public key |
| `the certificate does not load` | The certificate is not an X.509 certificate in PEM or base64 |
| `the private key does not match the certificate` | The certificate holds the public key of another key pair |

The credential is `signing credential`, `additional signing certificate at
index N`, or `decryption credential at index N`, where `N` counts from zero
in the order the credentials were added. When the provider reports why a key
or certificate does not load, `std::error::Error::source` returns that
report. A build without a crypto provider still checks only that each needed
credential is set.

**Upgrade:** pair each key with the certificate of its own public key. For a
matching pair, these two commands print the same digest:

```sh
openssl pkey -in key.pem -pubout | openssl sha256
openssl x509 -in cert.pem -noout -pubkey | openssl sha256
```

A test that built a config with placeholder text, such as
`PrivateKeyPem::new("test key")`, needs a real key pair. A test that used a key
that does not load to make every decryption fail can set
`XmlEncryptionPolicy::max_decryption_work` to zero instead.

## Assign fields instead of writing a struct literal

**Affects:** code that builds one of these structs with a struct literal,
including a literal that ends in `..SpValidationPolicy::default()` or
another base:

| Struct | Start from |
| --- | --- |
| `SpValidationPolicy`, `IdpValidationPolicy` | `default()` |
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

**Upgrade:** take a value from the `Default`, preset, or constructor that the
table names, and assign each field you set. Assign a nested field through its
parent:

```rust
// Before
let validation = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::default()
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
let mut validation = SpValidationPolicy::default();
validation.assertions = AssertionSignaturePolicy::RequireSigned;
let mut xml = XmlPolicy::default();
xml.limits.max_depth = 64;
let mut contact = ContactPerson::new(ContactType::Technical);
contact.email_addresses = vec!["mailto:ops@example.com".into()];
```

A literal that listed every field has no base. Start it from `default()`, or
from the constructor the table names, and assign each field it listed.

The presets and `default()` are not `const fn`, so a `const` or `static` that
held one of these literals fails with `E0015` when it starts from one. Build
the value in a function or a `std::sync::LazyLock`. `XmlLimits::unbounded()`
is a `const fn`.

## Destructure with a rest pattern

**Affects:** code that destructures one of the structs above, a `Started`, or
a `StartedPaosSso` with a struct pattern that lists every field, and code that
builds a `Started` or a `StartedPaosSso` with a struct literal.

**Before:** a pattern could list every field, such as
`Started { pending, outbound }`, and a struct literal could build a started
flow from its parts.

**Now:** `Started` and `StartedPaosSso` are `#[non_exhaustive]` too. Outside
saml-rs, a struct pattern without `..` fails with `E0638`, and a struct
literal of a started flow fails with `E0639`: only saml-rs builds one. Reading
a field, such as `started.pending`, does not change.

**Upgrade:** end the pattern with `..`. Keep the started flow an operation
returned, and move its fields out where you need them:

```rust
// Before
let Started { pending, outbound } = sp.start_sso(&idp, StartSso::redirect())?;

// Now
let Started { pending, outbound, .. } = sp.start_sso(&idp, StartSso::redirect())?;
```

## Add a wildcard arm to a `match` on a policy enum

**Affects:** code that matches on `AssertionSignaturePolicy`,
`ResponseSignaturePolicy`, `AuthnRequestSigningPolicy`,
`AuthnRequestValidationPolicy`,
`AudienceValidationPolicy`, `AssertionEncryptionPolicy`,
`IdentifierEncryptionPolicy`, or `AttributeEncryptionPolicy`
without a wildcard arm.

**Before:** these enums were exhaustive, so a `match` that listed every
variant compiled. `XmlSignatureProfile` was already non-exhaustive.

**Now:** they are `#[non_exhaustive]`, so a later release can add a variant
without a breaking change. Outside saml-rs, a `match` without a wildcard arm
fails with `E0004`. `Rsa15KeyTransportPolicy`, new in 0.9, is non-exhaustive
too. `NameIdCreationPolicy` stays exhaustive. A `matches!` or `==` comparison
does not change.

**Upgrade:** add a `_` arm after the variants you handle, and decide what your
code does with a variant it does not know:

```rust
// Before
let label = match validation.assertions {
    AssertionSignaturePolicy::RequireSigned => "signed",
    AssertionSignaturePolicy::AllowUnsignedForCompatibility => "unsigned allowed",
};

// Now
let label = match validation.assertions {
    AssertionSignaturePolicy::RequireSigned => "signed",
    AssertionSignaturePolicy::AllowUnsigned => "unsigned allowed",
    _ => "other",
};
```

[Rename the relaxed policy and algorithm variants](compile-errors.md#116-rename-the-relaxed-policy-and-algorithm-variants)
lists the renamed variants.

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

A service provider configured with `EncryptAssertions` now returns
`SamlError::EncryptionRequired` if a response contains both plaintext and
encrypted assertions. If your identity provider sends mixed responses,
configure it to encrypt every assertion. If your service provider accepts
plaintext assertions, select `PlaintextAssertions` (the default) and keep its
decryption credential to process the encrypted assertions.

## Stop relying on encryption algorithm errors without a crypto provider

**Affects:** builds without a crypto provider feature that expect
`SpConfigBuilder::build` or `IdpConfigBuilder::build` to return
`SamlError::Unsupported` for `DataEncryptionAlgorithm::Aes256Gcm` or
`KeyEncryptionAlgorithm::RsaOaep`.

**Before:** without a crypto provider, both builders rejected these two
algorithms. They accepted every other algorithm, including `Aes128Gcm`.

**Now:** without a crypto provider, both builders accept any
`AlgorithmPolicy`. That build cannot encrypt or decrypt, so the algorithm has
no effect. The builders still return `SamlError::Unsupported` for an
`XmlEncryptionPolicy` that encrypts. Builds with a crypto provider do not
change.

**Upgrade:** if you used this error to detect a build without a crypto
provider, check which `saml-rs` features the build enables instead, for
example with `cargo tree -e features -i saml-rs`.

## Rename `AudienceValidationPolicy::Validate` to `RequireRestriction`

**Affects:** code that names `AudienceValidationPolicy::Validate`.

**Before:** `Validate` was the strictest value. It also rejected a bearer
assertion without `<AudienceRestriction>`, which the recommended
`EvaluatePresentRestrictions` accepts.

**Now:** the variant is `RequireRestriction`. The behavior is the same.

**Upgrade:** rename each use:

```rust
let mut validation = SpValidationPolicy::default();
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
let sp = ServiceProvider::new(SpConfig::builder(entity_id, acs).build()?);
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
as the old field did.

**Upgrade:** delete the field. If you set it to a value other than
`tag_prefix_assertion`, an encrypted response now uses the assertion prefix.
The namespace is the same, so a peer that reads namespaces reads the same
element.

## Replace SSO templates with typed options

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

**Now:** browser SSO and PAOS generate XML from typed inputs. The role-specific
builders and configs accept typed SSO settings only.

**Upgrade:** delete the template from your configuration. Set the ACS, binding,
and NameID formats on the role that advertises them. Use `StartSso` for request
preferences, `SsoAssertion` for the subject, attributes, authentication context
and instant, and `SsoOutcome::Failure` for an error status. Arbitrary XML
extensions have no typed replacement. Logout templates remain available on
`TemplatePolicy`.

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

## Update consumers that match literal SAML prefixes

If you set `TemplatePolicy::tag_prefix_protocol` or `tag_prefix_assertion`,
the sending entity now uses those prefixes in `AuthnRequest`, `ArtifactResolve`,
`ArtifactResponse`, and both SOAP name identifier management messages.
The SAML elements inside the ECP request header also use them.
Previously those paths always emitted `samlp` and `saml`.

Update peers and XML snapshots that expect the old spellings. In a
namespace-aware consumer, match the namespace URI and local name. To emit
`samlp` and `saml` throughout, use the default prefix settings. The artifact
response embeds the stored protocol message with its original prefixes.

## Write logout templates as well-formed XML

**Affects:** callers that set `TemplatePolicy::logout_request_template` or
`TemplatePolicy::logout_response_template`.

**Before:** the library searched the template text for a placeholder to decide
which optional attribute or element to omit. Text that looked like markup
counted as markup. For example, without an `InResponseTo` value,
`<custom:Note text='InResponseTo="{InResponseTo}"'/>` rendered as
`<custom:Note text=''/>`. A start tag inside a comment before a placeholder
could cut the output short. A start tag with a bare placeholder,
such as `<samlp:LogoutResponse ... {InResponseTo}>`, rendered when the value
was absent.

**Now:** the library parses the template's tags and attributes before it fills
the placeholders. It omits an attribute only when the attribute's whole value
is the placeholder, and an element only when the placeholder is its only
content. Other text stays as written. A template whose tags or attributes
cannot be read returns `SamlError::Xml`, even when the filled template would
have been well-formed. A bare placeholder in a start tag and a repeated
attribute are two such cases. When the library omits an attribute, it
rewrites that start tag with one space before each remaining attribute. Each
value keeps double quotes unless it contains one, and then takes single quotes.

**Upgrade:** write the template as well-formed XML. Replace a bare placeholder
in a start tag with an attribute whose value is the placeholder, such as
`InResponseTo="{InResponseTo}"`. The library omits that attribute when there
is no value. Declare each attribute once.
