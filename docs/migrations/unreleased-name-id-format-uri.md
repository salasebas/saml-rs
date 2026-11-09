# NameID formats must be absolute URIs

This change is unreleased. It applies to the release in which
`generate_sp_metadata` first returns a `Result`.

SAML Core §1.3.2 requires every written NameID format to be an absolute URI
reference with at least one non-whitespace character. The format is checked
wherever this crate writes it:

- the `NameID` of a Response, LogoutRequest, or ManageNameIDRequest;
- the AuthnRequest `NameIDPolicy`;
- each metadata `NameIDFormat`.

Received formats are still accepted as sent.

## Send absolute NameID format URIs

Who must change: code that writes a NameID format that is empty, blank,
relative, or malformed. Examples are `NameIdFormat::Custom(String::new())`,
`NameIdFormat::Custom("local-format".into())`, and `urn:` with nothing after
the colon. The format can come from any of these places:

- a `NameId`;
- `SpConfig` or `IdpConfig` `name_id_format`;
- `SpMetadataConfig` or `IdpMetadataConfig` `name_id_format`;
- raw `EntitySetting::name_id_format`.

These calls now return `SamlError::Invalid` instead of writing the value:

- `Saml::sp` and `Saml::idp`;
- `respond_sso`, `initiate_sso`, their artifact forms, and `respond_paos_sso`;
- `start_slo`;
- `start_name_id_management` and its HTTP-Redirect forms;
- `ServiceProvider::from_config` and `IdentityProvider::from_config`;
- `create_login_request`, `create_login_response`, and
  `create_logout_request`.

A `custom` callback writes its own XML and is not checked.

Use an absolute URI, such as a URN or an HTTPS URL, or a `NameIdFormat`
constant:

```rust
use saml_rs::{NameId, NameIdFormat};

let name_id = NameId::new(
    "alice",
    Some(NameIdFormat::Custom("urn:example:name-id-format".into())),
);
```

To leave the format unspecified, pass no format. `NameId::new(value, None)`
and an empty `name_id_format` list omit `Format`. An empty or whitespace-only
configured entry is now an error, not an omitted format.

A `NameId` from a received message keeps the format the peer sent. Sending it
back in `start_slo` or `start_name_id_management` now fails when that format
is not an absolute URI reference.

## Handle the `Result` from metadata generation

Who must change: callers of `saml_rs::metadata::generate_sp_metadata` and
`generate_idp_metadata`.

Both now return `Result<String, SamlError>`. They return `SamlError::Invalid`
when a `NameIDFormat` they write is not an absolute URI reference.
`try_generate_idp_metadata` returns the same error.

```rust
use saml_rs::metadata::{generate_sp_metadata, SpMetadataConfig};

fn metadata(config: &SpMetadataConfig) -> Result<String, saml_rs::SamlError> {
    generate_sp_metadata(config)
}
```

## Expect no `Format` on `NameIDPolicy` without a configured format

Who must change: raw service provider code that compares AuthnRequest XML and
has an empty `EntitySetting::name_id_format`.

`create_login_request` wrote `<samlp:NameIDPolicy Format="" …/>`. It now
omits `Format`, which leaves the identity provider free to choose the
identifier format. A login request template drops an attribute whose
complete value is `{NameIDFormat}`. Typed service providers are unaffected,
because they always configure a format.
