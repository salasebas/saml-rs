# Upgrade SOAP, artifact resolution, and discovery cookie code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers callers of `saml-rs`, `opensaml`, `samlify`, and `samlet`
that send SAML messages over SOAP or through the browser, resolve or answer
artifacts, or write the `_saml_idp` cookie. Apply the sections that match your
integration.

## Send the SOAP headers from `headers()`

**Affects:** code that calls `soap_action()`, `cache_control()`, `pragma()`,
or `content_type()` on `SoapRequest`, `SoapResponse`, or `AnsweredArtifact`.

**Before:** each header had its own method, and each method returned the same
constant on every value.

**Now:** the methods are removed. `SoapRequest::headers()` returns
`Content-Type`, `SOAPAction`, `Cache-Control`, and `Pragma`.
`SoapResponse::headers()` returns `Content-Type`, `Cache-Control`, and
`Pragma`. Both return `&[HttpHeader]`, like `PaosHttpResponse::headers()`.
The values are unchanged. For a SOAP logout message, `Outbound::headers()`
returns the same list.

**Upgrade:** copy every header the slice holds onto the HTTP message.

Before the upgrade:

```rust,ignore
let request = resolution.request();
let response = client
	.post(request.endpoint().as_str())
	.header("SOAPAction", request.soap_action())
	.header("Cache-Control", request.cache_control())
	.header("Pragma", request.pragma())
	.header("Content-Type", request.content_type())
	.body(request.envelope().to_string())
	.send()?;
```

After the upgrade:

```rust,ignore
let request = resolution.request();
let mut post = client.post(request.endpoint().as_str());
for header in request.headers() {
	post = post.header(header.name(), header.value());
}
let response = post.body(request.envelope().to_string()).send()?;
```

## Send the browser headers from `Outbound::headers`

**Affects:** identity providers that send `ArtifactDelivery::CACHE_CONTROL` or
`ArtifactDelivery::PRAGMA` with an artifact. Every caller that sends an
`Outbound` should read the upgrade.

**Before:** the two constants held the `Cache-Control` and `Pragma` values for
the HTTP response that carries an artifact. Nothing gave those values for a
plain redirect or POST form, although Bindings §3.4.5.1 and §3.5.5.1 recommend
them there as well.

**Now:** the two constants are removed. `Outbound::headers()` returns the
headers to send with any outbound message. A redirect or a POST form, including
one that carries an artifact, gets `Cache-Control: no-cache, no-store` and
`Pragma: no-cache`. A SOAP logout message gets the `SoapRequest::headers()` or
`SoapResponse::headers()` list. The slice does not hold `Location`, which is
`redirect_url()`, or the `Content-Type` of the page that renders the form.

**Upgrade:** copy every header the slice holds onto the HTTP response, for
every redirect and form you send, not only for an artifact.

```rust,ignore
// Before
let response = Response::builder()
	.status(StatusCode::SEE_OTHER)
	.header("Location", outbound.redirect_url()?)
	.header("Cache-Control", ArtifactDelivery::CACHE_CONTROL)
	.header("Pragma", ArtifactDelivery::PRAGMA)
	.body(Body::empty())?;

// After
let mut response = Response::builder()
	.status(StatusCode::SEE_OTHER)
	.header("Location", outbound.redirect_url()?);
for header in outbound.headers() {
	response = response.header(header.name(), header.value());
}
let response = response.body(Body::empty())?;
```

## Build SOAP envelopes with `SoapRequest::try_new` and `SoapResponse::try_new`

**Affects:** callers of `SoapProtocolMessage::request` or
`SoapProtocolMessage::response_envelope`.

**Before:** `SoapProtocolMessage::request(endpoint, xml)` returned a
`SoapRequest`, and `SoapProtocolMessage::response_envelope(xml)` returned the
envelope as a `String`.

**Now:** both are removed. `SoapRequest::try_new(endpoint, xml)` and
`SoapResponse::try_new(xml)` build the values, and `envelope()` returns the
envelope. `SoapProtocolMessage` only reads a received envelope, with
`SoapProtocolMessage::from_envelope`.

| Before | After |
| --- | --- |
| `SoapProtocolMessage::request(endpoint, xml)?` | `SoapRequest::try_new(endpoint, xml)?` |
| `SoapProtocolMessage::response_envelope(xml)?` | `SoapResponse::try_new(xml)?.envelope().to_string()` |

## Read the artifact response from `AnsweredArtifact::response`

**Affects:** identity providers that call `answer_artifact_resolve`.

**Before:** `AnsweredArtifact::envelope()` returned the SOAP envelope, and
`AnsweredArtifact` had its own header methods.

**Now:** `AnsweredArtifact::response()` returns the `SoapResponse`, which is
the type every other SOAP answer uses. `envelope()` and the header methods are
removed from `AnsweredArtifact`. `release()` is unchanged.

**Upgrade:** replace `answer.envelope()` with `answer.response().envelope()`,
and send the headers from `answer.response().headers()`.

## Pass the protocol XML to `issue_artifact`

**Affects:** identity providers that call `Saml<Idp>::issue_artifact`.

**Before:** the message was an `IssuedMessage`. You built it with
`IssuedMessage::web_browser_sso_response(xml)` for a `<Response>` and with
`IssuedMessage::protocol(xml)` for any other element. Each constructor
rejected the other kind.

**Now:** `IssuedMessage` is removed. `issue_artifact` takes the XML as `&str`
and reads the element. It releases a `<Response>` only over a channel that is
mutually authenticated, integrity protected, and confidential, and any other
protocol element over a mutually authenticated, integrity-protected channel.
Those are the rules the two constructors selected. Malformed XML returns
`SamlError::Xml`, and an element outside the SAML protocol namespace returns
`SamlError::ProtocolProfile`, as before.

**Upgrade:**

```rust,ignore
// Before
let message = IssuedMessage::protocol(logout_request_xml)?;
let artifact = idp.issue_artifact(&sp, message, 0, &mut issued)?;

// After
let artifact = idp.issue_artifact(&sp, &logout_request_xml, 0, &mut issued)?;
```

To answer an `AuthnRequest` with an artifact, keep using
`respond_sso_artifact`, which builds and stores the `<Response>`.

## Resolve an artifact with a channel and a validation context

**Affects:** service providers that call `Saml<Sp>::resolve_artifact`.

**Before:** `resolve_artifact` took an `ArtifactDereference` and an
`&mut ArtifactUses`:

- `ArtifactDereference::web_browser_sso(channel)` required a mutually
  authenticated, integrity-protected, and confidential channel, and accepted
  only a `<Response>`.
- `ArtifactDereference::protocol(channel)` did not require confidentiality,
  and rejected a `<Response>`.
- `ArtifactUses::enforce_single_use(period)` kept the artifacts this process
  resolved in memory. `ArtifactUses::allow_reuse()` kept none.

**Now:** `ArtifactDereference` and `ArtifactUses` are removed.
`resolve_artifact` takes the `SoapChannel` and a `SamlValidationContext`:

- Every dereference requires a mutually authenticated, integrity-protected,
  and confidential channel. Otherwise the call returns
  `SamlError::SoapChannelProtection` before it builds the request.
  `ArtifactResolution::finish` returns a `<Response>` or any other protocol
  element.
- With `ReplayPolicy::RequireCache`, the call stores
  `ReplayKey::Artifact` in your `ReplayCache` until the context time plus
  `SamlValidationContext::with_replay_retention`. That is the cache
  `finish_sso` already uses, so a cache shared by several processes now also
  blocks an artifact resolved in another process. A repeated artifact returns
  `SamlError::ReplayDetected`, as before. A context with a cache and no
  retention returns `SamlError::TimeWindowInvalid` with
  `TimeWindowField::ReplayExpiration`, and stores nothing.
- The call stores the artifact before it sends `ArtifactResolve`, so a
  forged `SAMLart` value also takes a cache entry. A cache with an entry
  limit, such as `InMemoryReplayCache::with_max_entries`, needs room for one
  entry per artifact received during the retention. Otherwise pass a separate
  cache for `resolve_artifact`, so a flood of artifacts cannot fill the cache
  that `finish_sso` uses. A full cache returns
  `SamlError::ReplayCacheUnavailable`.
- `ReplayPolicy::Disabled` skips the check, as `allow_reuse()` did. The
  identity provider still returns the message only once.
- The context time is the instant at which the identity provider metadata
  must be valid. Before, that was the system clock.

**Upgrade:** pass the channel directly. Replace the single-use period with
the retention on a context that holds your replay cache:

```rust,ignore
// Before
let mut uses = ArtifactUses::enforce_single_use(Duration::from_secs(10 * 60));
let resolution = sp.resolve_artifact(
	&idp,
	delivered.artifact(),
	ArtifactDereference::web_browser_sso(channel)?,
	&mut uses,
)?;
```

```rust
# use std::time::{Duration, SystemTime};
# use saml_rs::{
# 	DeliveredArtifact, IdpDescriptor, InMemoryReplayCache, ReplayPolicy, SamlError,
# 	SamlValidationContext, ServiceProvider, SoapChannel,
# };
# fn resolve(
# 	sp: &ServiceProvider,
# 	idp: &IdpDescriptor,
# 	delivered: &DeliveredArtifact,
# 	replay_cache: &mut InMemoryReplayCache,
# ) -> Result<(), SamlError> {
let channel = SoapChannel::mutually_authenticated_confidential();
let resolution = sp.resolve_artifact(
	idp,
	delivered.artifact(),
	channel,
	SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(replay_cache))
		.with_replay_retention(Duration::from_secs(10 * 60)),
)?;
# let _ = resolution;
# Ok(())
# }
```

Choose a retention longer than the lifetime the identity provider gives its
artifacts, as you did for the period.

If you resolved a protocol element other than a `<Response>` over a channel
without confidentiality, protect that channel, for example with TLS. A
deployment that cannot do that has no supported way to resolve the artifact.

## Call `Artifact::try_new`

**Affects:** callers of `Artifact::try_from_encoded`.

**Now:** it is renamed `Artifact::try_new`, like the other validated string
types such as `EntityId::try_new` and `RelayState::try_new`. It accepts the
same values.

## Write the discovery cookie name and path from the constants

**Affects:** identity providers that call `name()`, `path()`, or `secure()` on
`CommonDomainCookie`.

**Before:** `name()` returned `"_saml_idp"`, `path()` returned `"/"`, and
`secure()` returned `true`, on every cookie.

**Now:** the three methods are removed. Use the constants
`CommonDomainCookie::NAME` and `CommonDomainCookie::PATH`, which hold the same
values, and always mark the cookie `Secure`. `set_cookie_header()` already
writes all three.

```rust,ignore
// Before
let cookie = Cookie::build((common_domain_cookie.name(), common_domain_cookie.value()))
	.path(common_domain_cookie.path())
	.domain(common_domain_cookie.domain())
	.secure(common_domain_cookie.secure());

// After
let cookie = Cookie::build((CommonDomainCookie::NAME, common_domain_cookie.value()))
	.path(CommonDomainCookie::PATH)
	.domain(common_domain_cookie.domain())
	.secure(true);
```
