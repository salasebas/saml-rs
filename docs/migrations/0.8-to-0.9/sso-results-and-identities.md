# Update SSO results and identities

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet` that issue or read SSO responses, or that build `NameId`,
`Attribute`, or `RequestedAuthnContext` values. Apply the sections that match
your integration.

## Pass a `NameId` to the response methods

**Affects:** identity providers that call `respond_sso`, `initiate_sso`,
`respond_sso_artifact`, `initiate_sso_artifact`, or `respond_paos_sso`.

The `Subject` type is removed. These methods borrow the principal's `NameId`
and write the assertion `Subject` themselves, with one bearer
`SubjectConfirmation`. Before the upgrade, a `Subject` with confirmations
returned `SamlError::Unsupported`. A caller can no longer pass one.

Before the upgrade:

```rust,ignore
let response = idp.respond_sso(
	&sp,
	&request,
	Subject::new(NameId::new("alice@example.com", None), Vec::new()),
	RespondSso::post(),
)?;
```

After the upgrade:

```rust
# use saml_rs::{AuthnRequest, NameId, Received, RespondSso, Saml, SamlError, SpDescriptor};
# fn respond(idp: &Saml<saml_rs::Idp>, sp: &SpDescriptor, request: &Received<AuthnRequest>) -> Result<(), SamlError> {
let response = idp.respond_sso(
	sp,
	request,
	&NameId::new("alice@example.com"),
	RespondSso::post(),
)?;
# let _ = response;
# Ok(()) }
```

To re-issue the principal of an accepted session, pass `session.name_id()`.

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

| Before | After |
| --- | --- |
| `session.subject().name_id()` | `session.name_id()` |
| `session.subject().confirmations()` | `session.subject_confirmations()` |
| `session.authn_session()` | `session.authn_sessions().first()` |
| `session.assertion()` | `session.assertion_id()`, `session.issuer()`, and `session.name_id()` |
| `authn_session.not_on_or_after()` | `authn_session.session_not_on_or_after()` |
| `session.replay_keys()` | Removed |

`authn_session()` returned an empty `AuthnSession` when the assertion had no
`AuthnStatement`. `authn_sessions().first()` returns `None` instead. The
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
	.authn_sessions()
	.first()
	.and_then(|statement| statement.session_not_on_or_after());
# let _ = expires;
# }
```

`replay_keys()` listed keys without their expirations and skipped values it
could not read. `finish_sso` and the other receiving methods already store
the keys in the `ReplayCache` of the validation context.

## Let the receiving method check replay

**Affects:** callers of `SsoSession::check_and_store_replay` or
`AuthnRequest::check_and_store_replay`.

Both methods are removed from the public API. `finish_sso`,
`accept_unsolicited_sso`, `finish_paos_sso`, `receive_sso`, and
`receive_paos_sso` store the replay keys under
`ReplayPolicy::RequireCache`. Calling a removed method on their result
returned `SamlError::ReplayDetected`, because the keys were already stored.

Delete the call. If you convert a raw `FlowResult` with `TryFrom` and then
check replay, receive the message through the typed method instead. See
[Move off the deprecated raw API](raw-api.md).

## Stop building values that only a received message carries

**Affects:** callers that construct these values, usually in tests.

| Before | After |
| --- | --- |
| `NameIdPolicy::new`, `unspecified`, `allow_creation`, `disallow_creation`, `with_sp_name_qualifier` | Removed. Read `AuthnRequest::name_id_policy()` |
| `policy.allow_create()` | `policy.creation_request()` |
| `AuthnSession::new` | Removed. Read `SsoSession::authn_sessions()` |
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
