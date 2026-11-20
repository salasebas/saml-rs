# 3. Move off the deprecated raw API

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** code that calls the raw message functions under `saml_rs::raw`,
`saml_rs::flow`, or `saml_rs::logout`.

**Now:** these functions are deprecated, and a build that calls one warns with
its replacement. The next minor release removes the raw API, including
`raw`, `FlowResult`, `BindingContext`, `HttpRequest`, `EntitySetting`, and the
`raw_*` accessors on typed values. Move each call to the typed `Saml` API
before that upgrade:

| Deprecated | Replacement |
| --- | --- |
| `ServiceProvider::create_login_request` | `Saml::<Sp>::start_sso` |
| `ServiceProvider::parse_login_response_with_request_id` | `Saml::<Sp>::finish_sso` |
| `ServiceProvider::parse_unsolicited_login_response` | `Saml::<Sp>::accept_unsolicited_sso` |
| `IdentityProvider::parse_login_request` | `Saml::<Idp>::receive_sso` |
| `IdentityProvider::create_login_response` | `Saml::<Idp>::respond_sso`, or `Saml::<Idp>::initiate_sso` for an unsolicited response |
| `logout::create_logout_request`, `create_logout_request_with_id` | `start_slo` on `Saml<Sp>` or `Saml<Idp>` |
| `logout::parse_logout_request` | `receive_slo` |
| `logout::create_logout_response`, `create_logout_response_with_id` | `respond_slo`, with `&Status::success()` for the `Success` they write |
| `logout::parse_logout_response`, `parse_logout_response_without_request_id` | `finish_slo` |
| `flow::flow` | The typed receive operation for the message |
| `HttpRequest::redirect` | `Inbound::redirect` with the raw query string |

A service-provider login moves from a raw request and response to a pending
request that `finish_sso` checks the response against:

```rust
// Before
let request = sp.create_login_request(&idp, Binding::Redirect, &LoginRequestOptions::default())?;
// Store request.id, then redirect the browser to request.context.
let result = sp.parse_login_response_with_request_id(&idp, Binding::Post, &http, &request.id)?;
let name_id = result.extract.get_str("nameID");

// After
let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
// Store started.pending.snapshot(), then redirect the browser to started.outbound.
let session = sp.finish_sso(
    &idp_descriptor,
    &pending,
    Inbound::post(fields),
    validation,
)?;
let name_id = session.name_id().value();
```

`examples/sso.rs` and `examples/slo.rs` show the full typed flows. Typed
operations check what the raw functions left to the caller, such as
`InResponseTo` correlation, RelayState, and the receiving endpoint. The typed
`SpValidationPolicy::compatibility` preset keeps the raw service-provider
acceptance behaviour while you migrate.
