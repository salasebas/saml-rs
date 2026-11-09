# Metadata in the schema element order

This change is unreleased. It applies to the release that first generates
metadata in the schema element order.

Generated metadata now writes the children of `SPSSODescriptor` and
`IDPSSODescriptor` in the order the metadata schema requires. No code stops
compiling. The generated XML changes.

## Check code that compares generated metadata

Who must change: code that compares `metadata_xml()`,
`generate_sp_metadata`, or `generate_idp_metadata` output byte for byte, or
that reads children by position. This covers code that leaves
`elements_order` unset and code that names `elements_order::DEFAULT` or
`elements_order::idp::DEFAULT`.

The service provider default moves `SingleLogoutService` before
`NameIDFormat`:

```text
before: KeyDescriptor, NameIDFormat, SingleLogoutService, AssertionConsumerService
after:  KeyDescriptor, SingleLogoutService, NameIDFormat, AssertionConsumerService
```

The identity provider default moves `NameIDFormat` and `SingleSignOnService`
to the end:

```text
before: KeyDescriptor, NameIDFormat, ArtifactResolutionService, SingleSignOnService, SingleLogoutService
after:  KeyDescriptor, ArtifactResolutionService, SingleLogoutService, ManageNameIDService, NameIDFormat, SingleSignOnService
```

Update the expected output. A peer that validates metadata against the schema
now accepts it.

To keep the old service-provider order, select `elements_order::ONELOGIN`.
That list is the old default. For the old identity-provider order, pass that
list to `elements_order`. Both old orders are rejected by a peer that
validates the schema.

```rust
use saml_rs::constants::elements_order;

let old_sp_order: Vec<String> =
    elements_order::ONELOGIN.iter().map(|name| (*name).to_string()).collect();
let old_idp_order: Vec<String> = [
    "KeyDescriptor",
    "NameIDFormat",
    "ArtifactResolutionService",
    "SingleSignOnService",
    "SingleLogoutService",
]
.iter()
.map(|name| (*name).to_string())
.collect();
```

Pass either list to the `elements_order` builder method or config field.
