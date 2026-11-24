# Keep AllowCreate false in AuthnRequests

`SpValidationPolicy::default()` now sets `name_id_creation` to
`NameIdCreationPolicy::AllowCreate`, and `NameIdCreationPolicy::default()`
returns `AllowCreate`. `ServiceProvider::start_sso` therefore writes
`AllowCreate="true"` in the `NameIDPolicy` of every AuthnRequest whose format
is not transient. Before, the default wrote `AllowCreate="false"`. A request
for the transient format still omits the attribute.

SAML Core §3.4.1.1, as changed by Approved Errata E14, says that a requester
that makes no specific use of `AllowCreate` should set it to `true`. With
`false`, an identity provider that keeps an identifier for each service
provider can refuse the first login of a principal with an
`InvalidNameIDPolicy` status.

The change affects a service provider that keeps the default policy and
requests a format other than transient. No code fails to compile. The
identity provider receives `true` and can create or link an identifier for
the principal. Code that compares
`SpValidationPolicy::default().name_id_creation` or
`NameIdCreationPolicy::default()` with `DoNotAllowCreate` now sees
`AllowCreate`.

To keep the previous request, set the field after `default()`:

```rust
use saml_rs::{NameIdCreationPolicy, SpValidationPolicy};

let mut validation = SpValidationPolicy::default();
validation.name_id_creation = NameIdCreationPolicy::DoNotAllowCreate;
```

Pass `validation` to `SpConfig::builder(..).validation(..)` as before.
