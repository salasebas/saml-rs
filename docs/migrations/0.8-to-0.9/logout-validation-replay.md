# Upgrade logout, validation, and replay code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet`. Apply the sections that match your integration.

## Use one request age policy type

Replace imports and type annotations for `AuthnRequestAgePolicy` and
`ManageNameIdRequestAgePolicy` with `RequestAgePolicy`. The two setters keep
their names. Both getters, `authn_request_age()` and
`manage_name_id_request_age()`, return `RequestAgePolicy`.

Before the upgrade, the setters take different policy types.

```rust,ignore
let validation = SamlValidationContext::new(now, replay)
	.with_authn_request_age(AuthnRequestAgePolicy::Bounded { max_age })
	.with_manage_name_id_request_age(ManageNameIdRequestAgePolicy::Disabled);
```

After the upgrade, pass `RequestAgePolicy` to both.

```rust
# use std::time::{Duration, SystemTime};
# use saml_rs::{ReplayPolicy, RequestAgePolicy, SamlValidationContext};
# fn configure(now: SystemTime, replay: ReplayPolicy<'_>, max_age: Duration) {
let validation = SamlValidationContext::new(now, replay)
	.with_authn_request_age(RequestAgePolicy::Bounded { max_age })
	.with_manage_name_id_request_age(RequestAgePolicy::Disabled);
let authn_age: RequestAgePolicy = validation.authn_request_age();
let manage_name_id_age: RequestAgePolicy = validation.manage_name_id_request_age();
# }
```

Configure the settings independently. Both start disabled, and `Bounded`
keeps the same inclusive time window. The new enum is non-exhaustive. Add a
wildcard arm to matches outside the crate so they handle future variants.

## Select and read clock skew explicitly

`ClockSkew` no longer implements `Default`. Replace `ClockSkew::default()`
and other calls that relied on its `Default` implementation with
`ClockSkew::strict()` to preserve zero tolerance. If your configuration derived
`Default` with a `ClockSkew` field, implement `Default` on your configuration
and initialize that field with `ClockSkew::strict()`. A new `SamlValidationContext`
still uses `ClockSkew::five_minutes()`.

Replace `with_not_before_millis` and `with_not_on_or_after_millis` with one
call to `from_millis`. When changing only one value, pass the other value
from a named getter.

Before the upgrade, set and read both components as follows.

```rust,ignore
let skew = ClockSkew::strict()
	.with_not_before_millis(-30_000)
	.with_not_on_or_after_millis(120_000);
let (not_before, not_on_or_after) = skew.as_millis();
```

After the upgrade, use the two named getters.

```rust
use saml_rs::ClockSkew;

let skew = ClockSkew::from_millis(-30_000, 120_000);
let not_before = skew.not_before_millis();
let not_on_or_after = skew.not_on_or_after_millis();
```

`as_millis()` is removed. For an API that still takes a tuple, such as
`EntitySetting::clock_drifts`, pass `(not_before, not_on_or_after)` in that
order. A negative `NotBefore` value permits early acceptance. A positive
`NotOnOrAfter` value permits late acceptance.

## Build a logout subject with session indexes

Start with `LogoutSubject::new(name_id)`. Append one index with
`with_session_index` or pass a collection to `with_session_indexes`.

| Before | After |
| --- | --- |
| `LogoutSubject::from_name_id(name_id)` | `LogoutSubject::new(name_id)` |
| `LogoutSubject::with_session_index(name_id, index)` | `LogoutSubject::new(name_id).with_session_index(index)` |
| `LogoutSubject::new(name_id, indexes)` | `LogoutSubject::new(name_id).with_session_indexes(indexes)` |
| `subject.session_index()` | `subject.session_indexes().first()` |

```rust
# use saml_rs::{LogoutSubject, NameId, SessionIndex};
# fn subject(name_id: NameId, index: SessionIndex, indexes: Vec<SessionIndex>) -> LogoutSubject {
LogoutSubject::new(name_id)
	.with_session_index(index)
	.with_session_indexes(indexes)
# }
```

The plural method accepts any `IntoIterator<Item = SessionIndex>`. Both
methods append in order and keep duplicates. An empty iterator leaves the
selection alone. With no indexes, the subject selects every session for its
NameID. A session participant still needs an index when applying the Single
Logout generation rules.

On `OutstandingLogout`, change `principal()` to `name_id()` and `sessions()`
to `session_indexes()`. The types returned by those methods stay the same.

## Obtain the completed response through `finish_slo`

`LogoutCompleted::new(peer)` and `LogoutCompleted::from_response(peer, response)`
are removed from the public API. Call `finish_slo` on either role to obtain a
completion with the response and received RelayState. Use a logout exchange
in tests that previously constructed a completion by hand.

`response()` and `raw_flow()` now return references directly. Replace the
removed `LogoutCompleted::status()` with `completed.response().status()` to
read the typed status, including any subordinate code such as `PartialLogout`.

Before the upgrade, callers unwrap the optional fields.

```rust,ignore
let response = completed.response().ok_or("missing response")?;
let raw = completed.raw_flow().ok_or("missing raw flow")?;
let top_level_uri = completed.status().ok_or("missing status")?;
```

After the upgrade, read the fields from the completion returned by `finish_slo`.

```rust
# use saml_rs::{IdpDescriptor, Inbound, LogoutResponse, PendingLogoutRequest, Saml, SamlError, SamlValidationContext, Sp};
# fn finish(sp: &Saml<Sp>, idp: &IdpDescriptor, pending: &PendingLogoutRequest,
#     input: Inbound<LogoutResponse>, validation: SamlValidationContext<'_>) -> Result<(), SamlError> {
let completed = sp.finish_slo(idp, pending, input, validation)?;
let response = completed.response();
let raw = completed.raw_flow();
let status = response.status();
let top_level_uri = status.top_level().as_uri();
let subordinate = status.subordinate();
# Ok(()) }
```

`peer_entity_id()` reads the response issuer. `LogoutCompleted` no longer
implements `PartialEq` or `Eq`. The old equality compared only the peer.
Use `first.peer_entity_id() == second.peer_entity_id()` for that same
comparison. Use the response ID and request correlation to distinguish exchanges.

## Update replay keys and cache access

Rename the variants you construct or match on.

| Before | After |
| --- | --- |
| `ReplayKey::AuthnRequestId` | `ReplayKey::AuthnRequest` |
| `ReplayKey::LogoutRequestId` | `ReplayKey::LogoutRequest` |
| `ReplayKey::LogoutResponseId` | `ReplayKey::LogoutResponse` |
| `ReplayKey::ManageNameIdRequestId` | `ReplayKey::ManageNameIdRequest` |
| `ReplayKey::ManageNameIdResponseId` | `ReplayKey::ManageNameIdResponse` |
| `ReplayKey::ResponseId` | `ReplayKey::SsoResponse` |
| `ReplayKey::AssertionId` | `ReplayKey::Assertion` |

Variant payloads, `kind()` and `cache_key()` strings, and replay deadlines
stay the same. Keep any existing cache entries during the upgrade.

`SamlValidationContext::replay_retention()` is removed. Keep the duration
in your application's configuration if you need to read it elsewhere.
Continue to set it with `with_replay_retention(retention)`.

If you share an `Arc<Mutex<InMemoryReplayCache>>`, you can pass a mutable
reference to the handle directly. The borrowed mutex form still works.

Before the upgrade, borrow the mutex from the `Arc`.

```rust,ignore
let mut shared = cache.as_ref();
let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut shared));
```

After the upgrade, pass the handle directly.

```rust
# use std::{sync::{Arc, Mutex}, time::SystemTime};
# use saml_rs::{InMemoryReplayCache, ReplayPolicy, SamlValidationContext};
# fn configure(now: SystemTime, cache: &Arc<Mutex<InMemoryReplayCache>>) {
let mut handle = Arc::clone(cache);
let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut handle));
# }
```

`InMemoryReplayCache`, `ReplayPolicy`, and `SamlValidationContext` now
implement `Debug`. The cache reports entry count and capacity. Formatting
omits replay identifiers and leaves the cache clock untouched.
