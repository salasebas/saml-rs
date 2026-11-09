# Name identifier management

This break is unreleased. It applies to the release that first publishes name
identifier management over SOAP and HTTP-Redirect.

Four metadata config structs gain a field, so an existing struct literal that
names every field no longer compiles. `ParserType` gains two variants.
Identity-provider responses now write the subject `NameID` `SPProvidedID`, and
refuse it with a login response template.

## Name the new metadata field

This breaks a struct literal of `saml_rs::SpMetadataConfig`,
`saml_rs::IdpMetadataConfig`, `saml_rs::metadata::SpMetadataConfig`, or
`saml_rs::metadata::IdpMetadataConfig` (the last two also imported from
`saml_rs::raw::metadata`) that names every field.

Who must change: code that builds one of those structs without
`..Default::default()` or a constructor. `SpMetadataConfig::new` and
`IdpMetadataConfig::new` already supply an empty list.

Add `manage_name_id_service`. An empty list publishes no
`ManageNameIDService`, which is what the metadata had before. On the typed
structs it holds `ManageNameIdService`. On the raw structs it holds
`saml_rs::metadata::Endpoint`, with `Binding::Soap` or `Binding::Redirect`.

```rust
use saml_rs::{AcsEndpoint, SpMetadataConfig};

fn config(acs: AcsEndpoint) -> SpMetadataConfig {
    SpMetadataConfig {
        name_id_format: Vec::new(),
        single_logout_service: Vec::new(),
        assertion_consumer_service: vec![acs],
        manage_name_id_service: Vec::new(),
        elements_order: None,
    }
}
```

Publish an endpoint from the typed builder to turn the protocol on. The
builder starts on Recommended, and this snippet leaves that preset in place.
A service provider takes only `ManageNameIdService::redirect`.

```rust
use saml_rs::{EndpointUrl, EntityId, IdpConfig, ManageNameIdService, SsoEndpoint};

fn publish() -> Result<IdpConfig, saml_rs::SamlError> {
    IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            "https://idp.example.com/nameid/soap",
        )?))
        .manage_name_id_service(ManageNameIdService::redirect(EndpointUrl::try_new(
            "https://idp.example.com/nameid/redirect",
        )?))
        .build()
}
```

Without the SOAP endpoint, `start_name_id_management` and
`receive_name_id_management` return `SamlError::MissingMetadata`. Without the
HTTP-Redirect endpoint, the `_redirect` operations do.

## Match the new parser types

This breaks an exhaustive `match` on `saml_rs::constants::ParserType`.

Who must change: code that matches every variant without a wildcard arm.

Add arms for `ParserType::ManageNameIdRequest` and
`ParserType::ManageNameIdResponse`. `as_str` returns `ManageNameIDRequest` and
`ManageNameIDResponse`, and `query_param` returns `SAMLRequest` and
`SAMLResponse`.

```rust
use saml_rs::constants::ParserType;

fn is_request(parser_type: ParserType) -> bool {
    match parser_type {
        ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::ManageNameIdRequest => {
            true
        }
        ParserType::SamlResponse
        | ParserType::LogoutResponse
        | ParserType::ManageNameIdResponse => false,
    }
}
```

## Check the SPProvidedID your responses send

Who must change: identity providers that pass a `Subject` whose `NameId` was
built with `NameId::with_qualifiers` and a `sp_provided_id`.

`respond_sso`, `initiate_sso`, `respond_sso_artifact`, `initiate_sso_artifact`,
and `respond_paos_sso` used to drop `SPProvidedID`. They now write it on the
assertion `NameID`. Pass it only when the service provider set that
alternative identifier, for example through `receive_name_id_management` or
`receive_name_id_management_redirect`.
Otherwise build the `NameId` with `None` for it. `NameQualifier` and
`SPNameQualifier` are still not written.

A login response template has no `SPProvidedID` placeholder. A subject
`NameId` with `SPProvidedID` combined with a template now returns
`SamlError::Invalid` instead of a response without it. Drop the template, or
pass `None` for `SPProvidedID`.
