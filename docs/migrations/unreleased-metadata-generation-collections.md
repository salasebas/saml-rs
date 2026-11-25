# Use plural names for metadata generation collections

The `Vec` fields on `metadata::SpMetadataInput` and
`metadata::IdpMetadataInput` now use plural names that match the metadata
elements they write.

This change affects callers that build or read `metadata::SpMetadataInput` or
`metadata::IdpMetadataInput` directly, such as callers of
`metadata::generate_sp_metadata` or `metadata::generate_idp_metadata`. Callers
that use `SpConfigBuilder` or `IdpConfigBuilder` need no changes. The typed
builders keep their singular append methods and their bulk methods.

Rename each field assignment and read as listed below:

| Input | Before | After |
| --- | --- | --- |
| `SpMetadataInput`, `IdpMetadataInput` | `name_id_format` | `name_id_formats` |
| `SpMetadataInput`, `IdpMetadataInput` | `single_logout_service` | `single_logout_services` |
| `SpMetadataInput`, `IdpMetadataInput` | `manage_name_id_service` | `manage_name_id_services` |
| `SpMetadataInput` | `assertion_consumer_service` | `assertion_consumer_services` |
| `IdpMetadataInput` | `single_sign_on_service` | `single_sign_on_services` |
| `IdpMetadataInput` | `artifact_resolution_service` | `artifact_resolution_services` |

Before:

```rust
use saml_rs::constants::Binding;
use saml_rs::metadata::{Endpoint, SpMetadataInput};

let mut input = SpMetadataInput::default();
input.entity_id = "https://sp.example.com/metadata".into();
input.name_id_format = vec!["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()];
input.assertion_consumer_service = vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
input.single_logout_service = vec![Endpoint::new(Binding::Redirect, "https://sp.example.com/slo")];
input.manage_name_id_service = vec![Endpoint::new(Binding::Redirect, "https://sp.example.com/mni")];
```

After:

```rust
use saml_rs::constants::Binding;
use saml_rs::metadata::{Endpoint, SpMetadataInput};

let mut input = SpMetadataInput::default();
input.entity_id = "https://sp.example.com/metadata".into();
input.name_id_formats = vec!["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()];
input.assertion_consumer_services = vec![Endpoint::new(Binding::Post, "https://sp.example.com/acs")];
input.single_logout_services = vec![Endpoint::new(Binding::Redirect, "https://sp.example.com/slo")];
input.manage_name_id_services = vec![Endpoint::new(Binding::Redirect, "https://sp.example.com/mni")];
```

Generated XML does not change. Each field writes one element per value in input
order and keeps its previous empty-list behavior. An empty
`SpMetadataInput::name_id_formats` still writes the `emailAddress` format, and
other empty optional lists are omitted. An empty
`SpMetadataInput::assertion_consumer_services` or
`IdpMetadataInput::single_sign_on_services` still returns
`SamlError::MissingMetadata`.
