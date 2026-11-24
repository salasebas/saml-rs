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

### Let the IdP present the result

Use `ServiceProvider::start_async_slo` when the selected IdP endpoint supports
the [OASIS Asynchronous Single Logout extension](https://docs.oasis-open.org/security/saml/Post2.0/saml-async-slo/v1.0/saml-async-slo-v1.0.html).
Confirm support in your deployment before choosing this flow. The IdP handles
logout and presents its result to the user.

```rust
let subject = session
    .logout_subject()
    .ok_or("session has no logout subject")?;
let outbound = sp.start_async_slo(&idp, subject, StartSlo::redirect())?;
let url = outbound.redirect_url()?;
```

For HTTP-POST, use `StartSlo::post()` and get the form with
`outbound.post_form()?`. After building the request, end the local
application session. Then redirect the browser to `url` or return the POST form.
This flow ends at dispatch for the SP. It returns no pending state for
`finish_slo`.

### Receive a logout from the IdP

When the SP accepts a sign-in, store `session.issuer()` and the value from
`session.logout_subject()` with the application session. Keep the full `NameID`
and every `SessionIndex` in the subject.

Verify the logout request with `ServiceProvider::receive_slo`. For each
candidate in your session store, pass the issuer and subject from that
candidate's accepted sign-in to `matches_sp_session`.

```rust
use saml_rs::Inbound;

let received = sp.receive_slo(&idp, Inbound::post(request_fields), validation)?;
if received.matches_sp_session(&stored_assertion_issuer, &stored_logout_subject) {
    invalidate_session(session_key)?;
}
```

With no `SessionIndex`, the request can match every session with the same
assertion issuer and `NameID`. Use the same check for each candidate. A `BaseID`
or an identifier that could not be decrypted gives no match. Use
`ServiceProvider::respond_slo` to report the outcome after processing every
candidate.

Use `OutstandingLogout` during SSO to check an assertion that arrives after a
logout request.

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

### Receive asynchronous logout

Use `IdentityProvider::receive_slo_with_async` on an IdP endpoint that supports
asynchronous logout over HTTP-Redirect or HTTP-POST. The method verifies the
request before it looks for the extension.

```rust
use saml_rs::{IdpLogoutAction, Inbound, RespondSlo, SamlError, Status};

match idp.receive_slo_with_async(&sp, Inbound::post(request_fields), validation) {
    Ok(IdpLogoutAction::CompleteLocally(request)) => {
        let outcome = end_sessions(request.issuer(), request.name_id(), request.session_indexes());
        render_logout_result(outcome)
    }
    Ok(IdpLogoutAction::Respond(request)) => {
        let status = match end_session(&request) {
            Ok(()) => Status::success(),
            Err(_) => Status::responder(),
        };
        send_post(idp.respond_slo(&sp, &request, &status, RespondSlo::post())?)
    }
    Err(SamlError::LogoutRequestRefused { refusal, .. }) => {
        send_post(idp.respond_slo_refusal(&sp, &refusal, RespondSlo::post())?)
    }
    Err(error) => render_logout_failure(error),
}
```

In the local branch, look up sessions associated with the requesting SP and
use the full `NameID` and the supplied session indexes to select which sessions
to end. Your application owns the session store and any logout propagation to
other SPs. Render the result at the IdP for both success and failure. The local
branch sends no `LogoutResponse` to the initiating SP.

### Start logout at the IdP

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
