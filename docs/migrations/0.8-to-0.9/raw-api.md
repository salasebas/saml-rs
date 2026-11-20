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
| `logout::create_logout_response`, `create_logout_response_with_id` | `respond_slo` |
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

## 3.1 Set the signature check and clock skew on `FlowOptions`

**Affects:** code that sets `check_signature`, `verify_signature_if_present`,
or `clock_drifts` on `saml_rs::raw::FlowOptions`.

**Now:** one `signature_check: SignatureCheck` field replaces the two `bool`
fields, and `clock_skew: ClockSkew` replaces `clock_drifts: (i64, i64)`. The
defaults are unchanged: `SignatureCheck::Skip` and `ClockSkew::strict()`.

Map the two `bool` fields to one variant:

| `check_signature` | `verify_signature_if_present` | `signature_check` |
| --- | --- | --- |
| `true` | `true` or `false` | `SignatureCheck::Require` |
| `false` | `true` | `SignatureCheck::VerifyIfPresent` |
| `false` | `false` | `SignatureCheck::Skip` |

Pass the drift tuple to `ClockSkew::from_millis` in the same order,
`(not_before_ms, not_on_or_after_ms)`:

```rust
// Before
let mut options = FlowOptions::default();
options.check_signature = true;
options.clock_drifts = (-120_000, 180_000);

// Now
use saml_rs::raw::{FlowOptions, SignatureCheck};
use saml_rs::ClockSkew;

let mut options = FlowOptions::default();
options.signature_check = SignatureCheck::Require;
options.clock_skew = ClockSkew::from_millis(-120_000, 180_000);
```

`EntitySetting::clock_drifts` stays a tuple. These fields keep a raw call
compiling until you move it to the typed API, which takes its clock skew from
`SamlValidationContext`.
