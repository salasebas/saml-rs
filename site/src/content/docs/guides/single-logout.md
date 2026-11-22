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
    StartSlo::post(),
)?;
store_with_session(logout.pending.snapshot());

let pending = PendingLogoutRequest::from_snapshot(load_snapshot())?;
let completed = sp.finish_slo(
    &idp,
    &pending,
    Inbound::post(response_fields),
    validation,
)?;
let status = completed.response().status();
```

With the `serde` feature, the snapshot serializes to JSON for your session store. `finish_slo` trusts the snapshot to name the request the response answers, so keep it on the server, or authenticate it when the browser carries it. The stored format is in [Cargo features](../reference/features.md#serialize-pending-snapshots-with-serde).

The service provider includes at least one session index, signs the request and sends the browser to an `https` logout URL. `StartSlo::allow_http()` relaxes the `https` recommendation only.

## Identity provider

1. Call `receive_slo` with the browser fields from the `LogoutRequest`.
2. End the principal's session at the identity provider.
3. Call `respond_slo` with the outcome as its `status` argument. Typed `respond_slo` always signs the response.

Pass `Status::success()` after the identity provider ends its own session with the principal. If another session participant did not confirm its logout, add `SubordinateStatusCode::partial_logout()` with `Status::with_subordinate`. If the session could not be ended, pass an error status such as `Status::responder()`. saml-rs tracks no sessions, so `respond_slo` has no default status.

The response carries the exact `RelayState` that arrived with the request. It may use another front-channel binding than the request; the service provider's `finish_slo` accepts any front-channel binding its metadata publishes.

```rust
let logout_request = idp.receive_slo(
    &sp,
    Inbound::post(request_fields),
    validation,
)?;
let status = match end_session(&logout_request) {
    Ok(()) => Status::success(),
    Err(_) => Status::responder(),
};
let logout_response = idp.respond_slo(&sp, &logout_request, &status, RespondSlo::post())?;
```

When the identity provider starts logout itself, `IdentityProvider::start_slo` is the session authority. It always emits `LogoutRequest@NotOnOrAfter`. The deadline comes from the same issuance lifetime used for assertion time bounds. The five-minute default is library policy. Why that does not claim an ordering against every historical assertion is in [Logout expiration](../explanation/logout-expiration.md).

Both roles verify the sender's signature before accepting a browser logout request or response. Publish the signing certificate in the peer metadata for XML signatures on POST and detached signatures on Redirect or SimpleSign.

## Over SOAP

`StartSlo::soap()` and `RespondSlo::soap()` run the same calls as one back-channel SOAP exchange. Your HTTP client sends the request, and saml-rs reads the reply. Both peers publish `SloEndpoint::soap(...)`. saml-rs signs every SOAP logout message it writes, and none carries `RelayState`. `Inbound::soap(body, channel)` reads a received envelope. With `SoapChannel::unattested()`, the message must be signed. When your server or client authenticated the peer with mutual TLS, pass a `SoapChannel` that says so; an unsigned message is then accepted, and a present signature is still checked.

```rust
let logout = sp.start_slo(&idp, subject, StartSlo::soap())?;
let request = logout.outbound.soap_request()?;
let reply_body = post_soap(request.endpoint().as_str(), request.envelope())?;
let completed = sp.finish_slo(
    &idp,
    &logout.pending,
    Inbound::soap(reply_body, SoapChannel::unattested()),
    validation,
)?;
```

The receiving side reads the posted body and returns the response envelope as the HTTP 200 body:

```rust
let logout_request = idp.receive_slo(&sp, Inbound::soap(body, SoapChannel::unattested()), validation)?;
let logout_response = idp.respond_slo(&sp, &logout_request, &Status::success(), RespondSlo::soap())?;
let reply_body = logout_response.soap_response()?.envelope();
```

## Next

```sh
cargo run -p saml-rs --example slo
```

The last line prints the `LogoutResponse` status. The rules for each role are in [Logout](../reference/conformance/single-logout.md).
