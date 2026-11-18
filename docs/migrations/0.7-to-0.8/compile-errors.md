# 1. Fix compile errors

[How to upgrade from 0.7 to 0.8](README.md)

| You use | What changed | Section |
| --- | --- | --- |
| `util::OneOrMany`, `cast_array_opt`, `is_non_empty_array`, `verify_fields`, `last` | Removed | [1.1](#11-replace-the-collection-helpers) |
| `Saml<Idp>::respond_paos_sso` | Takes a fourth argument | [1.2](#12-pass-respondpaossso-to-respond_paos_sso) |
| `RespondSlo::relay_state` | Removed | [1.3](#13-drop-respondslorelay_state) |
| `IssuedArtifacts::new`, `IssuedArtifacts::default` | Removed | [1.4](#14-give-issuedartifacts-a-lifetime) |
| `*insecure_software_rsa_key_transport_decryption*` | Removed | [1.5](#15-remove-the-software-rsa-key-transport-opt-in) |
| `FlowOptions::strict_xml_signature_profile` | Replaced by `xml_signatures` | [1.6](#16-replace-flowoptionsstrict_xml_signature_profile) |
| A struct literal of `Credentials`, `SpMetadataConfig`, `IdpMetadataConfig`, or `IdpValidationPolicy` | New field | [1.7](#17-complete-struct-literals) |
| An exhaustive `match` on `XmlSignatureProfile`, `MetadataTrustPolicy`, `DataEncryptionAlgorithm`, or `KeyEncryptionAlgorithm` | New variant | [1.8](#18-extend-exhaustive-matches) |
| `finish_name_id_management_redirect` matched as `Ok(())` | Returns the RelayState | [1.9](#19-bind-the-relaystate-from-finish_name_id_management_redirect) |
| `bergshamra` as a direct dependency | 0.12 | [1.10](#110-update-bergshamra-to-012-if-you-depend-on-it-directly) |

## 1.1 Replace the collection helpers

**Affects:** callers of these `saml_rs::util` items, including through the
compatibility crates. Typed `Saml<Sp>` and `Saml<Idp>` operations are not
affected.

| Removed | Replacement |
| --- | --- |
| `OneOrMany::One(value)` | `vec![value]` |
| `OneOrMany::Many(values)` | `values` (a `Vec<T>`) |
| `OneOrMany::into_vec()` | Store a `Vec<T>` directly |
| `cast_array_opt(value)` | `value.unwrap_or_default()` on an `Option<Vec<T>>` |
| `is_non_empty_array(items)` | `!items.is_empty()` |
| `verify_fields(field, meta_field)` | `!field.is_empty() && field.iter().all(\|value\| value == meta_field)` |
| `last(items)` | `items.last()` |

Keep the empty-input mismatch when you replace `verify_fields`. If your
application needs a single-or-many input type, define it in the application.

## 1.2 Pass `RespondPaosSso` to `respond_paos_sso`

**Affects:** identity providers that answer Enhanced Client/Proxy login with
`Saml<Idp>::respond_paos_sso`. Service providers and `reject_paos_sso` callers
need no change.

**Now:** `respond_paos_sso` takes a fourth argument. `RespondPaosSso::default()`
keeps the previous response, which has no `AttributeStatement`:

```rust
let answered = idp.respond_paos_sso(&sp, &received, subject, RespondPaosSso::default())?;
```

To send attributes, set them on the options. They are written the same way as
`RespondSso::attributes`:

```rust
let answered = idp.respond_paos_sso(
	&sp,
	&received,
	subject,
	RespondPaosSso::default().attributes(attributes),
)?;
```

`respond_paos_sso` returns `SamlError::Invalid` when these attributes are
combined with a login response template, or when a basic attribute name is not
an XML name.

## 1.3 Drop `RespondSlo::relay_state`

**Affects:** callers of `RespondSlo::relay_state`.

**Before:** the setter could replace or drop the RelayState of a logout
response.
**Now:** `respond_slo` always writes the exact RelayState that arrived with the
`LogoutRequest`, as Bindings §3.1.1 requires of a responder.

**Upgrade:** remove the call. If you passed the received or stored RelayState
back, the response is unchanged:

```rust
let response = idp.respond_slo(&sp, &received, RespondSlo::post())?;
```

If you replaced or suppressed the RelayState, keep that state on your side,
for example in a session keyed by the RelayState you sent. You can no longer
add a RelayState to a response whose request had none.

`RespondSlo::soap` still returns `SamlError::ProtocolProfile` for a request
that carried RelayState, because SOAP cannot return it. Suppressing the
RelayState no longer avoids that error. Answer that request over a
front-channel binding.

## 1.4 Give `IssuedArtifacts` a lifetime

**Affects:** identity providers that issue artifacts with `issue_artifact`,
`respond_sso_artifact`, or `initiate_sso_artifact`.

**Before:** `IssuedArtifacts::new()` and `Default` built a store in which an
unresolved artifact stayed resolvable until you called
`IssuedArtifacts::remove`.
**Now:** both are removed. Build the store with a lifetime:

```rust
use std::time::Duration;

use saml_rs::IssuedArtifacts;

let mut issued = IssuedArtifacts::expire_after(Duration::from_secs(60));
```

An `ArtifactResolve` that arrives after the lifetime gets Success without the
message, and `AnsweredArtifact::release` reports
`ArtifactWithheld::NotOutstanding`. Each issue drops the artifacts issued more
than one lifetime ago, so you no longer need `remove` to bound memory.

**Choose the lifetime:** SAML Core §3.5.3 asks the issuer for the shortest
practical time limit. Use the time a service provider needs to receive the
artifact and send `ArtifactResolve`. On the service provider, keep the
`ArtifactUses::enforce_single_use` period longer than that lifetime.

## 1.5 Remove the software RSA key-transport opt-in

**Affects:** callers of
`XmlEncryptionPolicy::allow_insecure_software_rsa_key_transport_decryption`
or `XmlEncryptionPolicy::with_insecure_software_rsa_key_transport_decryption_allowed`,
code that sets `allow_insecure_software_rsa_key_transport_decryption` on
`EntitySetting`, `FlowOptions`, or `AssertionDecryptionOptions`, and every
`crypto-rustcrypto` build with a decryption key.

**Upgrade:** delete the call or the assignment. Replace the
`allow_insecure_software_rsa_key_transport_decryption()` constructor with
`XmlEncryptionPolicy::default()` or the constructor you want:

```rust
use saml_rs::{XmlEncryptionPolicy, XmlPolicy};

let xml = XmlPolicy {
    encryption: XmlEncryptionPolicy::encrypt_assertions(),
    ..XmlPolicy::default()
};
```

**Behaviour:** on `crypto-rustcrypto`, RSA key transport now runs in
`kryptering` on `rsa` 0.10, which RustSec lists as patched for
RUSTSEC-2023-0071. With a decryption key configured, these now decrypt with
the default options, as they already did on `crypto-aws-lc`: an encrypted
assertion, `<EncryptedID>`, `<EncryptedAttribute>`, `<NewEncryptedID>`, and
the `<EncryptedID>` of a `LogoutRequest` or `AuthnRequest`.

| Without the opt-in on `crypto-rustcrypto` | Before | Now |
| --- | --- | --- |
| Encrypted element received | `SamlError::Unsupported` | Decrypted |
| `ManageNameIDRequest` with an encrypted identifier | Refused with `NameIdManagementRefusal::UndecryptableIdentifier` or `UndecryptableNewIdentifier` | Decrypted |

If you relied on that refusal, configure no decryption key for the entity.

RSA-v1.5 key transport still needs
`XmlEncryptionPolicy::with_rsa15_key_transport_decryption_allowed` and
`crypto-legacy-algorithms`. It no longer needs the removed opt-in.

## 1.6 Replace `FlowOptions::strict_xml_signature_profile`

**Affects:** raw flows that set `FlowOptions::strict_xml_signature_profile`.

**Now:** the `bool` is replaced by `FlowOptions::xml_signatures`, an
`XmlSignatureProfile`.

| Before | Now |
| --- | --- |
| `strict_xml_signature_profile: true` | `xml_signatures: XmlSignatureProfile::StrictRsaSha2` |
| `strict_xml_signature_profile: false` (default) | `xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility` (default) |

What `StrictRsaSha2` now also checks is in
[section 2.2](signature-and-trust.md#22-expect-strictrsasha2-on-detached-and-identity-provider-signatures).

## 1.7 Complete struct literals

**Affects:** a struct literal that names every field and does not end with
`..Default::default()` or the listed preset.

| Struct | New field | Value that keeps 0.7 behaviour |
| --- | --- | --- |
| `Credentials` | `additional_decryption_keys: Vec<DecryptionCredential>` | `Vec::new()` |
| `Credentials` | `additional_signing_certificates: Vec<CertificatePem>` | `Vec::new()` |
| Typed and raw `SpMetadataConfig`, `IdpMetadataConfig` | `lifetime: Option<MetadataLifetime>` | `None` |
| Typed and raw `SpMetadataConfig`, `IdpMetadataConfig` | `organization: Option<Organization>` | `None` |
| Typed and raw `SpMetadataConfig`, `IdpMetadataConfig` | `contacts: Vec<ContactPerson>` | `Vec::new()` |
| Typed and raw `SpMetadataConfig`, `IdpMetadataConfig` | `error_url: Option<String>` | `None` |
| `IdpValidationPolicy` | `xml_signatures: XmlSignatureProfile` | `AllowProviderSupportedForCompatibility` |

Prefer ending the literal with `..Credentials::default()`,
`..Default::default()`, or `..IdpValidationPolicy::recommended()`.

For raw metadata configs, `..Default::default()` initializes all three
description fields to the values above. Typed metadata configs do not implement
`Default`. Use `SpMetadataConfig::new(acs_endpoints)` or
`IdpMetadataConfig::new(sso_endpoints)`, or add the fields to your literal.
Existing config builder calls need no change. Empty description fields preserve
the previous metadata output. When populated, invalid organization, contact,
or error URI inputs return `SamlError::Invalid` during generation.

**`lifetime`:** `None` keeps metadata without `validUntil` and
`cacheDuration`. Metadata §2.3.1 and §2.3.2 require one of them on the root
element, so prefer setting it. The config builders take the same value through
`metadata_lifetime`:

```rust
use std::time::Duration;
use saml_rs::MetadataLifetime;

let lifetime = Some(MetadataLifetime::CacheDuration(Duration::from_secs(86_400)));
```

A `MetadataLifetime::ValidUntil` instant is fixed when `Saml` is built. Build a
new `Saml` before it passes, or use `MetadataLifetime::CacheDuration`.

**`xml_signatures` on `IdpValidationPolicy`:** `compatibility()` sets
`AllowProviderSupportedForCompatibility`, so an identity provider on that
preset verifies what it verified before. `recommended()` sets
`ExcludeWeakAlgorithms` ([section 2.1](signature-and-trust.md#21-stop-relying-on-md5-ripemd-160-and-short-rsa-keys-under-recommended)).
With `StrictRsaSha2`, the identity provider applies the profile to the
`AuthnRequest` and logout messages it receives:

```rust
use saml_rs::{IdpValidationPolicy, XmlSignatureProfile};

let validation = IdpValidationPolicy {
    xml_signatures: XmlSignatureProfile::StrictRsaSha2,
    ..IdpValidationPolicy::recommended()
};
```

**`additional_decryption_keys`:** the field rolls over an encryption key
without downtime:

1. Put the next key and its certificate in a `DecryptionCredential` in the
   list. Metadata publishes both certificates, and decryption tries
   `decryption_key` first, then each additional key.
2. Make the next key the `decryption_key` and `encryption_certificate`, and
   move the old key and certificate into the list. A peer that encrypts for
   the first published certificate, as saml-rs does, now uses the new one.
3. Once every peer has refreshed your metadata, remove the old key.

A non-empty list without a `decryption_key` returns
`SamlError::MissingKey("decryption_key")` from the config builders.

## 1.8 Extend exhaustive matches

| Enum | Add an arm for | Meaning |
| --- | --- | --- |
| `XmlSignatureProfile` | `ExcludeWeakAlgorithms` | [Section 2.1](signature-and-trust.md#21-stop-relying-on-md5-ripemd-160-and-short-rsa-keys-under-recommended) |
| `MetadataTrustPolicy` | `RequireSignatureAllowingWeakAlgorithmsForCompatibility { trusted_certificates }` | [Section 2.5](signature-and-trust.md#25-stop-relying-on-md5-ripemd-160-and-short-rsa-keys-in-signed-metadata) |
| `DataEncryptionAlgorithm` | `Aes256Gcm` | AES-256-GCM content encryption |
| `KeyEncryptionAlgorithm` | `RsaOaep { digest, mgf }` | XML Encryption 1.1 RSA-OAEP with explicit digest and mask generation |

These public enum families now use `#[non_exhaustive]`, including through
the compatibility crates:

| Family | Enums |
| --- | --- |
| Algorithms | `SignatureAlgorithm`, `DigestAlgorithm`, `DataEncryptionAlgorithm`, `KeyEncryptionAlgorithm`, `MaskGenerationFunction`, `TransformAlgorithm` |
| URI formats | `NameIdFormat`, `AttributeNameFormat` |
| Supported transports and parsers | `Binding`, `SsoRequestBinding`, `SsoResponseBinding`, `LogoutBinding`, `NameIdManagementBinding`, `BrowserInput`, `ParserType` |
| Validation and trust profiles | `XmlSignatureProfile`, `MetadataTrustPolicy` |
| Refusal reasons | `NameIdManagementRefusal`, `ArtifactWithheld` |
| Contact extensions | `ContactType` |

Add a catch-all arm even when a `match` covers every current variant.
Existing variants remain constructible. A security decision must reject an
unhandled future variant rather than silently accept it:

```rust
use saml_rs::MaskGenerationFunction as Mgf;

fn digest_name(mgf: Mgf) -> Result<&'static str, &'static str> {
	match mgf {
		Mgf::Mgf1Sha256 => Ok("SHA-256"),
		Mgf::Mgf1Sha384 => Ok("SHA-384"),
		Mgf::Mgf1Sha512 => Ok("SHA-512"),
		_ => Err("unsupported mask generation function"),
	}
}
```

The catch-all covers future variants. It does not make an unsupported
algorithm or binding work. Inside saml-rs, the attribute does not require
catch-all arms. Exhaustive matches can still identify implementations that
need an update.
The rule for which enums are non-exhaustive is in
[coding standards](../../../CODING_STANDARDS.md#public-enums-that-can-grow).

If a match only maps variants to URIs, replace it with `as_uri()`:

```rust
let data_uri = algorithms.data_encryption.as_uri();
let key_uri = algorithms.key_encryption.as_uri();
```

`RsaOaep` carries a `DigestAlgorithm` and a `MaskGenerationFunction`. Keep
both when storing or forwarding the selected algorithm. `as_uri()` returns
the key transport URI without its parameters.

The defaults remain AES-256-CBC and RSA-OAEP-MGF1P. Existing configurations
and raw encryption function signatures are unchanged. Selecting the new
variants requires a crypto provider. Both config builders return
`SamlError::Unsupported` for unsupported OAEP parameters. AWS-LC and FIPS
require matching SHA-256, SHA-384, or SHA-512 digest and MGF1 hashes.

`TimeWindowField` gains `MetadataValidUntil` and
`ManageNameIdRequestIssueInstant`. It is `#[non_exhaustive]`, so a wildcard
arm already covers them.

## 1.9 Bind the RelayState from `finish_name_id_management_redirect`

**Affects:** service providers that call `finish_name_id_management_redirect`
and match its result as `Ok(())`.

**Now:** it returns the received `RelayStateParam` instead of `()`. Code that
ends the call with `?;` compiles unchanged. Otherwise bind the value:

```rust
let relay_state = sp.finish_name_id_management_redirect(&idp, &pending, input, validation)?;
```

Why the value can be present is in
[section 3.8](sp-sso.md#38-read-the-relaystate-a-peer-adds-to-a-response).

## 1.10 Update `bergshamra` to 0.12 if you depend on it directly

**Affects:** a crate that also depends on `bergshamra`, for example to name
the `bergshamra::keys::Key` that `saml_rs::crypto::keys::load_private_key`
returns and that `construct_saml_signature`, `construct_message_signature`,
and `decrypt_assertion` take. Integrations that only call `saml-rs` are not
affected.

**Now:** `crypto-rustcrypto`, `crypto-aws-lc`, and `crypto-fips` use
Bergshamra 0.12.0. A `Key` from a `bergshamra` 0.11 dependency is a different
type, so that code no longer compiles. Set `bergshamra = "0.12"` and apply the
[Bergshamra 0.12.0 changelog](https://github.com/kushaldas/bergshamra/blob/v0.12.0/CHANGELOG.md)
to your direct calls.

Through `saml-rs`, RSA keys shorter than 1024 bits behave as in 0.7:

- A peer certificate with such a key verifies no signature on any provider and
  returns `SamlError::Crypto`. Only the error message changes.
- A local private key with such a key still loads, signs, and decrypts on the
  default `crypto-bergshamra` feature. AWS-LC and FIPS still reject it.
