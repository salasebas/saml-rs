# Update SSO results and identities

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet` that issue or read SSO responses, or that build `NameId`,
`Attribute`, or `RequestedAuthnContext` values. Apply the sections that match
your integration.

## Answer with an `SsoAssertion` or an `SsoOutcome`

**Affects:** identity providers that call `respond_sso`, `initiate_sso`,
`respond_sso_artifact`, `initiate_sso_artifact`, or `respond_paos_sso`, or
that set `RespondSso::attributes`, `RespondSso::authn_context`,
`RespondSso::authn_instant`, or `RespondSso::status`.

**Before:** these methods took a `Subject`. The `RespondSso` options carried
both how the response was delivered and what it said: the assertion's
attributes, authentication context, and authentication instant, and the
response status. A browser or HTTP-Artifact error response still needed a
`Subject`, which it did not write.

**Now:** the `Subject` type is removed. The third argument (the second for
`initiate_sso` and `initiate_sso_artifact`) is `impl Into<SsoOutcome>`, and
it says what the response reports:

- `SsoAssertion::new(name_id)` answers with a `Success` response. The method
  writes the assertion `Subject` with that `NameId` and one bearer
  `SubjectConfirmation`. `SsoAssertion::new` takes the `NameId` by value, so
  clone one you only borrow. To re-issue the principal of an accepted session,
  pass `SsoAssertion::new(session.name_id().clone())`. A `Subject`
  with confirmations returned `SamlError::Unsupported`. A caller can no longer
  pass one.
- `RespondSso::attributes`, `authn_context`, and `authn_instant` become
  `SsoAssertion::with_attributes`, `with_authn_context`, and
  `with_authn_instant`. They take the same values and are checked as before.
- `RespondSso::status` is removed. Pass `SsoOutcome::Failure(status)` for an
  error response. It needs no `NameId`, and it cannot carry the assertion
  options. Put the authentication context, instant, attributes and NameID
  qualifiers on the successful assertion.
- `RespondSso` keeps `post`, `simple_sign`, `artifact`, `relay_state`,
  `sign_response`, and `allow_unsigned_encrypted_cbc`.

`respond_paos_sso` takes the same outcome, as
[Answer PAOS login with an `SsoOutcome`](typed-operations.md#answer-paos-login-with-an-ssooutcome)
shows.

Before the upgrade:

```rust,ignore
let response = idp.respond_sso(
	&sp,
	&request,
	Subject::new(NameId::new("alice@example.com", None), Vec::new()),
	RespondSso::post().attributes(attributes),
)?;
let denied = idp.respond_sso(
	&sp,
	&request,
	Subject::new(NameId::new("unknown", None), Vec::new()),
	RespondSso::post().status(Status::responder()),
)?;
```

After the upgrade:

```rust
# use saml_rs::{AuthnRequest, Attributes, NameId, Received, RespondSso, SamlError, SpDescriptor, SsoAssertion, SsoOutcome, Status, IdentityProvider};
# fn respond(idp: &IdentityProvider, sp: &SpDescriptor, request: &Received<AuthnRequest>, attributes: Attributes) -> Result<(), SamlError> {
let response = idp.respond_sso(
	sp,
	request,
	SsoAssertion::new(NameId::new("alice@example.com")).with_attributes(attributes),
	RespondSso::post(),
)?;
let denied = idp.respond_sso(
	sp,
	request,
	SsoOutcome::Failure(Status::responder()),
	RespondSso::post(),
)?;
# let _ = (response, denied);
# Ok(()) }
```

Two status choices behave differently:

- `SsoOutcome::Failure` with a top-level `Success` status returns
  `SamlError::Invalid` from every one of these methods. Before the upgrade,
  `RespondSso::status(Status::success())` wrote a `Success` response with its
  assertion. Pass an `SsoAssertion` instead.
- A `Success` response always has the bare top-level `Success` status.
  Before the upgrade, `RespondSso::status` could put a subordinate code under
  `Success` next to the assertion. That response cannot be expressed now.

## Build a `NameId` with its `with_` methods

**Affects:** callers of `NameId::new` and `NameId::with_qualifiers`.

`NameId::new` takes only the value. Each optional attribute has its own
method.

| Before | After |
| --- | --- |
| `NameId::new(value, None)` | `NameId::new(value)` |
| `NameId::new(value, Some(format))` | `NameId::new(value).with_format(format)` |
| `NameId::with_qualifiers(value, Some(format), Some(nq), Some(spnq), Some(id))` | `NameId::new(value).with_format(format).with_name_qualifier(nq).with_sp_name_qualifier(spnq).with_sp_provided_id(id)` |

Leave out the method for an attribute that you passed as `None`. When the
value is an `Option` only known at run time, call the method inside
`if let Some(..)`. The qualifier methods take `impl Into<String>`, so pass a
`&str` or a `String`.

```rust
use saml_rs::{NameId, NameIdFormat};

let mail = NameId::new("alice@example.com").with_format(NameIdFormat::EmailAddress);
let pseudonym = NameId::generate_persistent()
	.with_sp_name_qualifier("https://affiliation.example.com");
let stored = pseudonym.value().to_string();

let reissued = NameId::persistent(stored)?
	.with_sp_name_qualifier("https://affiliation.example.com");
assert_eq!(reissued, pseudonym);
# let _ = mail;
# Ok::<(), saml_rs::SamlError>(())
```

`generate_persistent` returns a new opaque value. Store it for the principal
and the affiliation. On later responses, rebuild it with
`NameId::persistent(stored)` and the same `with_sp_name_qualifier`.
`NameId::persistent` restores only the value and the format.

## Build attributes with `with_name_format`

**Affects:** identity providers that build `Attribute` values, and service
providers that read an attribute's `NameFormat`.

| Before | After |
| --- | --- |
| `Attribute::new(name, None, values)` | `Attribute::new(name, values)` |
| `Attribute::new(name, Some(uri), values)` | `Attribute::new(name, values).with_name_format(AttributeNameFormat::Custom(uri))` |
| `Attribute::with_name_format(name, format, values)` | `Attribute::new(name, values).with_name_format(format)` |
| `attribute.format()` | `attribute.name_format()` |
| `attribute.name_format()`, the URI | `attribute.name_format().map(AttributeNameFormat::as_uri)` |

`Attribute::new`, `Attributes::new`, and `RequestedAuthnContext::try_new`
accept any `IntoIterator`, so an array works where a `Vec` did. A call that
passes `iter.collect()` no longer compiles, because the collection type cannot
be inferred. Pass the iterator itself: write `Attributes::new(iter)` instead of
`Attributes::new(iter.collect())`. A `Custom` URI that names a SAML format is
still stored as that format.

```rust
use saml_rs::{Attribute, AttributeNameFormat, AttributeValue, Attributes};

let attributes = Attributes::new([
	Attribute::new("urn:oid:0.9.2342.19200300.100.1.3", [AttributeValue::new("alice@example.com")])
		.with_name_format(AttributeNameFormat::Uri),
	Attribute::new("groups", [AttributeValue::new("staff"), AttributeValue::new("admins")]),
]);
# let _ = attributes;
```

`Attributes::first_value(name)` returns the first value of the attribute that
`get(name)` finds. A `for` loop over `&Attributes` visits each attribute.
`Attributes` also implements `FromIterator<Attribute>`.

## Read the SSO session without the removed views

**Affects:** service providers that read an `SsoSession` or an
`AuthnSession`.

`AuthnSession` is renamed `AuthnStatement`, because each value is one
`<AuthnStatement>` of the assertion.

| Before | After |
| --- | --- |
| `session.subject().name_id()` | `session.name_id()` |
| `session.subject().confirmations()` | `session.subject_confirmations()` |
| `AuthnSession` | `AuthnStatement` |
| `session.authn_sessions()` | `session.authn_statements()` |
| `session.authn_session()` | `session.authn_statements().first()` |
| `session.assertion()` | `session.assertion_id()`, `session.issuer()`, and `session.name_id()` |
| `authn_session.not_on_or_after()` | `statement.session_not_on_or_after()` |
| `session.replay_keys()` | Removed |

`authn_session()` returned an empty `AuthnSession` when the assertion had no
`AuthnStatement`. `authn_statements().first()` returns `None` instead. The
renamed `session_not_on_or_after()` is the statement's `SessionNotOnOrAfter`.
`SsoSession::not_on_or_after()` is still the assertion's
`Conditions@NotOnOrAfter`.

Before the upgrade:

```rust,ignore
let expires = session.authn_session().not_on_or_after();
```

After the upgrade:

```rust
# fn read(session: &saml_rs::SsoSession) {
let expires = session
	.authn_statements()
	.first()
	.and_then(|statement| statement.session_not_on_or_after());
# let _ = expires;
# }
```

`replay_keys()` listed keys without their expirations and skipped values it
could not read. `finish_sso` and the other receiving methods already store
the keys in the `ReplayCache` of the validation context.

## Read audiences per restriction and call the renamed accessors

**Affects:** service providers that call `SsoSession::audience()` or
`SsoSession::sig_alg()`, and identity providers that call
`AuthnRequest::is_passive()`.

| Before | After |
| --- | --- |
| `session.audience()` | `session.audience_restrictions()`, then `restriction.audiences()` on each |
| `session.sig_alg()` | `session.binding_signature_algorithm_uri()` |
| `request.is_passive()` | `request.passive()` |

`audience()` returned the `<Audience>` values of every `<AudienceRestriction>`
in one list. That list loses which restriction each audience belongs to.
SAML Core §2.5.1.4 needs that grouping: the relying party must be in every
restriction, and one audience is enough within a restriction.
`audience_restrictions()` returns one `AudienceRestriction` for each element,
in document order.

To list the audiences, flatten the restrictions.

Before the upgrade:

```rust,ignore
let audiences: Vec<&str> = session.audience().iter().map(EntityId::as_str).collect();
```

After the upgrade:

```rust
# fn read(session: &saml_rs::SsoSession) {
use saml_rs::{AudienceRestriction, EntityId};

let audiences: Vec<&str> = session
	.audience_restrictions()
	.iter()
	.flat_map(AudienceRestriction::audiences)
	.map(EntityId::as_str)
	.collect();
# let _ = audiences;
# }
```

`binding_signature_algorithm_uri()` returns the value that `sig_alg()`
returned: the `SigAlg` of a verified HTTP-POST-SimpleSign signature, which
travels next to the message. A response signed only inside the XML still
returns `None`. Read its algorithms from `verified_xml_signatures()`.

`passive()` returns the same `Option<IsPassive>` as `is_passive()`. A Rust
method that starts with `is_` returns `bool`, and this one does not. `None`
still means that the request omitted `IsPassive`.

## Check audience restrictions before accepting a session

**Affects:** service providers that selected `AudienceValidationPolicy::SkipForCompatibility`
or `SpValidationPolicy::compatibility()`.

Remove the audience override. If you used the compatibility preset, start from
`SpValidationPolicy::default()`. The SP checks each audience restriction on every
bearer assertion before `finish_sso` or `accept_unsolicited_sso` returns a session.
If any restriction omits the SP's entity ID, the method returns
`SamlError::AudienceMismatch`. Configure the IdP to include your SP's entity ID
in each restriction intended for it.

Remove any application check that only repeats the SP's membership check.
The default, `EvaluatePresentRestrictions`, allows an assertion without an
audience restriction. To reject omission too, set `validation.audience` to
`AudienceValidationPolicy::RequireRestriction`.

## Let the receiving method check replay

**Affects:** callers of `SsoSession::check_and_store_replay` or
`AuthnRequest::check_and_store_replay`.

Both methods are removed from the public API. What to do depends on where
the value came from:

- **A typed receiving method.** `finish_sso`, `accept_unsolicited_sso`,
  `finish_paos_sso`, `receive_sso`, and `receive_paos_sso` store the replay
  keys under `ReplayPolicy::RequireCache`. A removed method called on their
  result returned `SamlError::ReplayDetected`, because the keys were already
  stored. Delete the call.
- **`TryFrom<FlowResult>`.** For an `SsoSession` or `AuthnRequest` converted
  from a raw flow, that call was the only replay check. The conversion is
  removed with the raw API: receive the message with `finish_sso`,
  `accept_unsolicited_sso`, or `receive_sso` instead, as
  [Move off the raw API](raw-api.md) shows.

## Stop building values that only a received message carries

**Affects:** callers that construct these values, usually in tests.

| Before | After |
| --- | --- |
| `NameIdPolicy::new`, `unspecified`, `allow_creation`, `disallow_creation`, `with_sp_name_qualifier` | Removed. Read `AuthnRequest::name_id_policy()` |
| `policy.allow_create()` | `policy.creation_request()` |
| `AuthnSession::new` | Removed. Read `SsoSession::authn_statements()` |
| `SubjectConfirmation::from_raw_xml` | Removed. Read `SsoSession::subject_confirmations()` |
| `Assertion` | Removed. Read the `SsoSession` accessors |
| `SsoResponse` accessors and `SsoResponse::try_from(flow)` | Removed. Use `SsoSession` |

A service provider configures the `NameIDPolicy` it sends on `SpConfig`. To
compare a received policy in a test, compare its accessors:

```rust
# fn check(request: &saml_rs::AuthnRequest) -> Option<()> {
use saml_rs::{NameIdCreationRequest, NameIdFormat};

let policy = request.name_id_policy()?;
assert_eq!(policy.format(), Some(&NameIdFormat::Persistent));
assert_eq!(policy.creation_request(), NameIdCreationRequest::AllowCreate);
# Some(()) }
```

`SsoResponse` now only names the SSO response message in
`Inbound<SsoResponse>`, `Outbound<SsoResponse>`, and
`PaosHttpResponse<SsoResponse>`. It has no values.

## Call `RequestedAuthnContext::try_new`

**Affects:** service providers that call `StartSso::requested_authn_context`.

`RequestedAuthnContext::new` is renamed to `try_new`. It takes any
`IntoIterator` of references, as [Build attributes](#build-attributes-with-with_name_format)
describes, and returns the same errors.

```rust
use saml_rs::{AuthnContextComparison, AuthnContextReference, RequestedAuthnContext, StartSso};

let options = StartSso::post().requested_authn_context(RequestedAuthnContext::try_new(
	AuthnContextComparison::Minimum,
	[AuthnContextReference::class(
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	)?],
)?);
# let _ = options;
# Ok::<(), saml_rs::SamlError>(())
```

## Send exactly one authentication context per statement

**Affects:** service providers whose identity provider omits the SAML
`AuthnContext` of an `AuthnStatement` or sends more than one, and code that
calls `authn_context()` on an `AuthnStatement`.

Ask the identity provider to send exactly one context in each statement, as
the assertion schema requires. Before the upgrade, the service provider
accepted both shapes: `authn_context()` returned `None` for an omitted
context and the last context for repeated ones.

If a configured schema validator rejects the document, the service provider
returns `SamlError::Invalid` from that callback. If the document reaches the
built-in statement reader, `finish_sso`, `accept_unsolicited_sso`, and
`finish_paos_sso` return `SamlError::ProtocolProfile` when a statement of the
selected assertion has no context or more than one.

`AuthnStatement::authn_context()` returns `&AuthnContext` instead of
`Option<&AuthnContext>`. Remove the `None` case.

Before the upgrade:

```rust,ignore
let class = session
	.authn_session()
	.authn_context()
	.and_then(|context| context.class_reference());
```

After the upgrade:

```rust
# fn read(session: &saml_rs::SsoSession) {
use saml_rs::AuthnStatement;

let class = session
	.authn_statements()
	.first()
	.map(AuthnStatement::authn_context)
	.and_then(|context| context.class_reference());
# let _ = class;
# }
```
