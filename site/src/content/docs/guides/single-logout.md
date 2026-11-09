---
title: "Single Logout"
description: "End a session that a typed SSO flow already created. You have an `SsoSession` and a peer that advertises a `SingleLogoutService`."
---

End a session that a typed SSO flow already created. You have an `SsoSession` and a peer that advertises a `SingleLogoutService`.

`start_slo`, `receive_slo`, `respond_slo`, and `finish_slo` run on both roles. One call talks to one peer. Sending logout on to every other participant is outside that call.

## Service provider

1. Read `session.logout_subject()`.
2. Call `start_slo` and store `logout.pending` with the browser session.
3. When the identity provider answers, call `finish_slo`.

```rust
let subject = session
    .logout_subject()
    .ok_or("session has no logout subject")?;
let logout = sp.start_slo(
    &idp,
    subject,
    StartSlo::post().apply_single_logout_generation_rules(),
)?;
store_with_session(logout.pending.snapshot());

let pending = Pending::<LogoutRequest>::from_snapshot(load_snapshot())?;
let completed = sp.finish_slo(
    &idp,
    &pending,
    BrowserInput::<LogoutResponse>::post(response_fields),
    validation,
)?;
let status = completed.status();
```

`redirect()`, `post()`, and `simple_sign()` leave the logout generation rules off until you call `apply_single_logout_generation_rules()`. With those rules selected, a session participant signs the request and sends the browser to an `https` logout URL. `StartSlo::allow_http_single_logout()` relaxes the `https` recommendation only.

## Identity provider

1. Call `receive_slo` with the browser fields from the `LogoutRequest`.
2. Call `respond_slo`. Typed `respond_slo` always signs the response.

`stored_relay_state` is the `RelayState` you kept with the pending logout. The example copies `logout.pending.relay_state()`.

```rust
let logout_request = idp.receive_slo(
    &sp,
    BrowserInput::<LogoutRequest>::post(request_fields),
    validation,
)?;
let logout_response = idp.respond_slo(
    &sp,
    &logout_request,
    RespondSlo::post().relay_state(stored_relay_state),
)?;
```

When the identity provider starts logout itself, `Saml<Idp>::start_slo` is the session authority. It always emits `LogoutRequest@NotOnOrAfter`. The deadline comes from the same issuance lifetime used for assertion time bounds. The five-minute default is library policy. Why that does not claim an ordering against every historical assertion is in [Logout expiration](../explanation/logout-expiration.md).

`LogoutPolicy::recommended()` requires a signature on logout requests and responses. `LogoutPolicy::compatibility()` is the legacy unsigned hatch.

## Next

```sh
cargo run -p saml-rs --example slo
```

The last line prints the `LogoutResponse` status. The rules for each role are in [Logout](../reference/conformance/single-logout.md).
