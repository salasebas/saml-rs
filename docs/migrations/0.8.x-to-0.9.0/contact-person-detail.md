# Give each published contact a detail

This change affects code that publishes a `ContactPerson` with
`SpConfigBuilder::contact`, `SpConfigBuilder::contacts`, the matching
`IdpConfigBuilder` methods, or the `contacts` field of `SpMetadataInput` or
`IdpMetadataInput`. No code fails to compile.

Metadata generation now returns `SamlError::Invalid` for a contact with no
company, given name, surname, email address, or telephone number. Before, such
a contact was written as an empty `ContactPerson` element. The builders'
`build()` returns the error, and so do `generate_sp_metadata` and
`generate_idp_metadata`. Approved Errata 05 E82 recommends at least one child
element in a `ContactPerson`.

To upgrade, assign at least one detail to each contact you publish:

```rust
use saml_rs::{ContactPerson, ContactType};

let mut support = ContactPerson::new(ContactType::Support);
support.email_addresses = vec!["mailto:help@example.com".into()];
```

Remove a contact that has no detail to publish. Importing peer metadata does
not change: a peer contact with no child element is still read.
