# Name identifier management over SOAP

This break is unreleased. It applies to the release that first publishes name
identifier management over SOAP.

Two identity-provider metadata structs gain a field, so an existing struct
literal that names every field no longer compiles. Identity-provider responses
now write the subject `NameID` `SPProvidedID`, and refuse it with a login
response template.

## Add the name identifier management list

This breaks a struct literal of `saml_rs::IdpMetadataConfig` or
`saml_rs::metadata::IdpMetadataConfig` (also imported as
`saml_rs::raw::metadata::IdpMetadataConfig`).

Who must change: code that constructs either struct by listing its fields.
`IdpMetadataConfig::new` and `..Default::default()` on the raw struct already
supply an empty list.

Leave the list empty when this identity provider does not manage name
identifiers. On the typed struct, set `manage_name_id_service: Vec::new()`
beside the existing fields. On the raw struct, the same field holds SOAP
locations as `String`.

Publish the SOAP endpoint from the typed builder. The builder starts on
Recommended, and this snippet leaves that preset in place.

```rust
use saml_rs::{EndpointUrl, EntityId, IdpConfig, ManageNameIdService, SsoEndpoint};

fn publish() -> Result<IdpConfig, saml_rs::SamlError> {
    IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .manage_name_id_service(ManageNameIdService::soap(EndpointUrl::try_new(
            "https://idp.example.com/nameid",
        )?))
        .build()
}
```

Without the endpoint, `start_name_id_management` and
`receive_name_id_management` return `SamlError::MissingMetadata`.

## Check the SPProvidedID your responses send

Who must change: identity providers that pass a `Subject` whose `NameId` was
built with `NameId::with_qualifiers` and a `sp_provided_id`.

`respond_sso`, `initiate_sso`, `respond_sso_artifact`, `initiate_sso_artifact`,
and `respond_paos_sso` used to drop `SPProvidedID`. They now write it on the
assertion `NameID`. Pass it only when the service provider set that
alternative identifier, for example through `receive_name_id_management`.
Otherwise build the `NameId` with `None` for it. `NameQualifier` and
`SPNameQualifier` are still not written.

A login response template has no `SPProvidedID` placeholder. A subject
`NameId` with `SPProvidedID` combined with a template now returns
`SamlError::Invalid` instead of a response without it. Drop the template, or
pass `None` for `SPProvidedID`.
