# Upgrade RelayState, pending state, and inbound message code

[How to upgrade from 0.8 to 0.9](README.md)

This guide covers typed API callers of `saml-rs`, `opensaml`, `samlify`, and
`samlet`. Apply the sections that match your integration.

## Replace `RelayStateParam` with `RelayState`

`RelayStateParam` is removed. The `relay_state` setters take a `RelayState`,
and the `relay_state` getters return `Option<&RelayState>`. `None` is a
message without a `RelayState` parameter, and an empty `RelayState` is a
parameter sent with no value. The two stay distinct, as `Absent` and
`PresentEmpty` did.

| Before | After |
| --- | --- |
| `RelayStateParam::Absent`, `RelayStateParam::absent()` | `None` |
| `RelayStateParam::PresentEmpty`, `RelayStateParam::present_empty()` | `Some(RelayState::try_new("")?)` |
| `RelayStateParam::PresentValue(value)` | `Some(value)` |
| `RelayStateParam::try_from_option(Some(value))`, `RelayStateParam::try_from(Some(value))` | `RelayState::try_new(value)` |
| `relay_state.as_deref()` | `relay_state.map(RelayState::as_str)` |
| `&RelayStateParam` returned by `relay_state()` | `Option<&RelayState>` |
| `RelayStateMismatch { expected, actual }` with `RelayStateParam` | The same fields as `Option<RelayState>` |

The `relay_state` setters of `StartSso`, `RespondSso`, `StartSlo`, and
`StartNameIdManagement` take a `RelayState`. A request
carries no RelayState when you leave its setter out. A response always carries
the RelayState its request carried, as the next section describes. `finish_name_id_management_redirect` returns
`Option<RelayState>`.

Before the upgrade, wrap the value and read it back through `as_deref`.

```rust,ignore
let relay_state = RelayStateParam::try_from_option(Some("return-to-cart".to_string()))?;
let started = sp.start_sso(&idp, StartSso::redirect().relay_state(relay_state))?;

let session = sp.finish_sso(&idp, &pending, input, validation)?;
let target = session.relay_state().as_deref();
```

After the upgrade, pass the `RelayState` and read an `Option`.

```rust
# use saml_rs::{IdpDescriptor, RelayState, SamlError, ServiceProvider, SsoSession, StartSso};
# fn start(sp: &ServiceProvider, idp: &IdpDescriptor) -> Result<(), SamlError> {
let relay_state = RelayState::try_new("return-to-cart")?;
let started = sp.start_sso(idp, StartSso::redirect().relay_state(relay_state))?;
# let _ = started;
# Ok(())
# }
# fn target(session: &SsoSession) -> Option<&str> {
let target = session.relay_state().map(RelayState::as_str);
# target
# }
```

## Let `respond_sso` return the RelayState it received

**Affects:** identity providers that call `RespondSso::relay_state` when they
answer an `AuthnRequest`.

**Before:** `RespondSso::relay_state` replaced the RelayState the request
carried, and `RespondSso::relay_state(RelayStateParam::absent())` dropped it.

**Now:** `respond_sso` and `respond_sso_artifact` always return the
RelayState of the `Received<AuthnRequest>`. SAML Bindings §3.4.3 and §3.5.3
require the responder to return the exact value. `RespondSso::relay_state`
sets the RelayState of an unsolicited response, or of a response to a request
that carried none. On a request that carried RelayState, the operation returns
`SamlError::ProtocolProfile`.

**Upgrade:** call `RespondSso::relay_state` only for `initiate_sso`,
`initiate_sso_artifact`, or a request whose `relay_state()` is `None`.

```rust
# use saml_rs::{AuthnRequest, Received, RelayState, RespondSso, SamlError};
# fn options(request: &Received<AuthnRequest>) -> Result<RespondSso, SamlError> {
let options = match request.relay_state() {
    Some(_) => RespondSso::post(),
    None => RespondSso::post().relay_state(RelayState::try_new("welcome")?),
};
# Ok(options)
# }
```

## Store pending state with the snapshot for its message

**Affects:** callers that store pending state between the start and the finish
of a request.

`PendingSnapshot<Message>` and its constructors `authn_request`,
`logout_request`, and `manage_name_id_request` are removed. Each pending type
has its own snapshot:

- `PendingAuthnRequest::snapshot` returns `PendingAuthnRequestSnapshot`.
- `PendingLogoutRequest::snapshot` returns `PendingLogoutRequestSnapshot`.
- `PendingManageNameIdRequest::snapshot` returns
  `PendingManageNameIdRequestSnapshot`.

The snapshot structs are non-exhaustive, so a struct literal of one does not
compile. Build a snapshot from stored
values with `new`, which takes the required fields. Assign the optional
fields, then call `from_snapshot`. A pattern that destructures a snapshot
ends with `..`.

| Snapshot | `new` takes | You assign |
| --- | --- | --- |
| `PendingAuthnRequestSnapshot` | `request_id`, `idp_entity_id`, `acs_binding`, `acs_url` | `relay_state`, `acs_index`, `acs_is_default` |
| `PendingLogoutRequestSnapshot` | `request_id`, `peer_entity_id`, `request_binding` | `relay_state`, `not_on_or_after` |
| `PendingManageNameIdRequestSnapshot` | `request_id`, `peer_entity_id` | `relay_state` |

Before the upgrade, a constructor filled part of the snapshot and you assigned
the rest.

```rust,ignore
let mut snapshot = PendingSnapshot::<AuthnRequest>::authn_request(
    row.id,
    RelayStateParam::try_from_option(row.relay_state)?,
    row.idp_entity_id,
    row.expected_binding,
    row.acs_url,
    row.acs_binding,
);
snapshot.acs_index = row.acs_index;
snapshot.acs_is_default = row.acs_is_default;
let pending = Pending::<AuthnRequest>::from_snapshot(snapshot)?;
```

After the upgrade, build the snapshot with `new` and assign the optional
fields.

```rust
# use saml_rs::{PendingAuthnRequest, PendingAuthnRequestSnapshot, SamlError};
# struct Row { request_id: String, relay_state: Option<String>, idp_entity_id: String,
#     acs_binding: String, acs_url: String, acs_index: Option<u16>, acs_is_default: bool }
# fn restore(row: Row) -> Result<PendingAuthnRequest, SamlError> {
let mut snapshot = PendingAuthnRequestSnapshot::new(
    row.request_id,
    row.idp_entity_id,
    row.acs_binding,
    row.acs_url,
);
snapshot.relay_state = row.relay_state;
snapshot.acs_index = row.acs_index;
snapshot.acs_is_default = row.acs_is_default;
let pending = PendingAuthnRequest::from_snapshot(snapshot)?;
# Ok(pending)
# }
```

A snapshot you stored with 0.8 maps to the new fields as follows:

| 0.8 field | AuthnRequest | LogoutRequest | ManageNameIDRequest |
| --- | --- | --- | --- |
| `id` | `request_id` | `request_id` | `request_id` |
| `relay_state` | `relay_state` | `relay_state` | `relay_state` |
| `peer_entity_id` | `idp_entity_id` | `peer_entity_id` | `peer_entity_id` |
| `expected_binding` | `acs_binding` | `request_binding` | Removed |
| `request_binding` | Removed | Removed. It was optional and held the same binding as `expected_binding` | Removed |
| `acs_url`, `acs_index`, `acs_is_default` | Unchanged | Removed | Removed |
| `acs_binding` | `acs_binding` | Removed | Removed |
| `issued_at` | Removed | Removed | Removed |
| `expires_at` | Removed | `not_on_or_after` for a session authority's request, otherwise `None` | Removed |

`relay_state` is an `Option<String>`: `None` for `Absent`, `Some("")` for
`PresentEmpty`, and `Some(value)` for `PresentValue`. An AuthnRequest's
`expected_binding` and `acs_binding` always held the same binding.
`PendingManageNameIdRequest` tracks only HTTP-Redirect requests. saml-rs set
`issued_at` and `expires_at` only on a session authority's LogoutRequest. If
you set them yourself with `with_issue_instant` or `with_expiration`, on any
pending type, store those values next to the snapshot. Do not copy them into
`not_on_or_after`.

`from_snapshot` still reads a binding as a short name, such as `post`, or as a
binding URN. A SOAP logout snapshot with RelayState returns
`SamlError::ProtocolProfile`, because a SOAP request carries none.

## Read pending state through one accessor each

Each value has one accessor, named for what it is:

| Before | After |
| --- | --- |
| `id()`, and `PendingAuthnRequest::request_id()` | `request_id()` on every pending type |
| `PendingAuthnRequest::peer_entity_id()`, and `idp_entity_id()` | `idp_entity_id()` |
| `peer_entity_id()` on `PendingLogoutRequest` and `PendingManageNameIdRequest` | Unchanged |
| `PendingAuthnRequest::response_binding()` | `acs().binding()` |
| `PendingAuthnRequest::request_binding()` | Removed. The binding is the one you passed to `StartSso` |
| `PendingLogoutRequest::request_binding()`, `response_binding()` | `request_binding()`. Both returned the same value |
| `PendingLogoutRequest::issued_at()` | Removed. saml-rs does not use the request's `IssueInstant` after sending it |
| `PendingLogoutRequest::expires_at()` | `not_on_or_after()`. `None` for a session participant |
| `PendingManageNameIdRequest::request_binding()`, `response_binding()` | Removed. Both returned `NameIdManagementBinding::Redirect` |
| `issued_at()`, `expires_at()` on `PendingAuthnRequest` or `PendingManageNameIdRequest` | Removed. saml-rs never set them; keep a time you set yourself next to the pending state |

`Pending::try_new`, `with_request_binding`, `with_issue_instant`, and
`with_expiration` are removed. Take pending state from the start operation,
or rebuild it from stored fields with `from_snapshot`.

## Build received messages with `Inbound`

**Affects:** every call that passes a received message to `receive_sso`,
`finish_sso`, `accept_unsolicited_sso`, `receive_slo`, `finish_slo`,
`receive_name_id_management_redirect`, or
`finish_name_id_management_redirect`.

`BrowserInput<Message>` is renamed `Inbound<Message>`, the received
counterpart of `Outbound<Message>`. A browser does not deliver SOAP input, so
the old name did not fit.

The constructors now take `Message` from the operation you pass the value to.
In 0.8, `BrowserInput::post(fields)` failed with error E0034, because each
message type had its own `post`, so every call named the message type.
`Inbound::post(fields)` compiles wherever the operation fixes the type. A call
that names the type, such as `Inbound::<SsoResponse>::post(fields)`, still
compiles.

`Inbound` is a struct with private fields. The variants `Redirect`, `Post`,
`SimpleSignPost`, `Artifact`, and `Soap` are gone. Build the value with a
constructor. If you matched on the variant to learn the binding, call
`Inbound::binding`. A variant built directly could pair a message with a
binding saml-rs does not receive it over, such as an `SsoResponse` over
HTTP-Redirect. That pair failed when the operation ran, and it no longer
compiles.

`BrowserInput::soap(envelope)` and `soap_with_channel(envelope, channel)` are
now one constructor, `Inbound::soap(envelope, channel)`. Where you called
`soap`, pass `SoapChannel::unattested()`. The message must then carry an XML
signature, as before.

| Before | After |
| --- | --- |
| `BrowserInput<Message>` | `Inbound<Message>` |
| `BrowserInput::<AuthnRequest>::redirect(query)` | `Inbound::redirect(query)` |
| `BrowserInput::<SsoResponse>::post(fields)` | `Inbound::post(fields)` |
| `BrowserInput::<LogoutRequest>::simple_sign(fields)` | `Inbound::simple_sign(fields)` |
| `BrowserInput::<SsoResponse>::artifact(delivered, resolved)` | `Inbound::artifact(delivered, resolved)` |
| `BrowserInput::<LogoutRequest>::soap(envelope)` | `Inbound::soap(envelope, SoapChannel::unattested())` |
| `BrowserInput::<LogoutResponse>::soap_with_channel(envelope, channel)` | `Inbound::soap(envelope, channel)` |
| `BrowserInput::Post { fields, _message: PhantomData }` | `Inbound::post(fields)` |
| `match input { BrowserInput::Soap { .. } => .., .. }` | `match input.binding() { Binding::Soap => .., .. }` |

Before the upgrade, each call named the message type.

```rust,ignore
let session = sp.finish_sso(
    &idp_descriptor,
    &pending,
    BrowserInput::<SsoResponse>::post(fields),
    finish_validation,
)?;
let request = idp.receive_slo(
    &sp_descriptor,
    BrowserInput::<LogoutRequest>::soap(body),
    receive_validation,
)?;
```

After the upgrade, the operation fixes the message type.

```rust
# use saml_rs::{
#     FormField, IdpDescriptor, Inbound, PendingAuthnRequest, ReplayPolicy, SamlError,
#     SamlValidationContext, ServiceProvider, SoapChannel, SpDescriptor,
# };
# fn finish(
#     sp: &ServiceProvider, idp: &IdpDescriptor, pending: &PendingAuthnRequest, fields: Vec<FormField>,
#     validation: SamlValidationContext<'_>,
# ) -> Result<(), SamlError> {
let session = sp.finish_sso(idp, pending, Inbound::post(fields), validation)?;
# let _ = session;
# Ok(())
# }
# fn receive(
#     idp: &saml_rs::IdentityProvider, sp: &SpDescriptor, body: String,
#     validation: SamlValidationContext<'_>,
# ) -> Result<(), SamlError> {
let request = idp.receive_slo(sp, Inbound::soap(body, SoapChannel::unattested()), validation)?;
# let _ = (request, ReplayPolicy::Disabled);
# Ok(())
# }
```

A helper that is generic over the message type bounds it with the trait of
the constructor it calls: `RedirectMessage`, `PostMessage`, or `SoapMessage`.
`PostMessage` covers HTTP-POST and HTTP-POST-SimpleSign. saml-rs implements
these sealed traits for the messages it receives over each binding.

```rust
# use saml_rs::{FormField, Inbound, PostMessage};
fn posted<Message: PostMessage>(form: Vec<(String, String)>) -> Inbound<Message> {
    let fields = form
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect();
    Inbound::post(fields)
}
```

## Pass parsed fields to `Inbound::simple_sign`

`BrowserInput::simple_sign_body` is removed, and the `raw_body` field of
`BrowserInput::SimpleSignPost` is gone with the variant. The
HTTP-POST-SimpleSign signature covers the decoded field values, so the raw
body was not needed. Parse the form as you do for `Inbound::post`.

Before the upgrade, you passed the raw body.

```rust,ignore
let input = BrowserInput::<SsoResponse>::simple_sign_body(body);
```

After the upgrade, pass the parsed fields.

```rust
# use saml_rs::{FormField, Inbound, SsoResponse};
# fn input(form: Vec<(String, String)>) -> Inbound<SsoResponse> {
let fields = form
    .into_iter()
    .map(|(name, value)| FormField::new(name, value))
    .collect();
let input = Inbound::simple_sign(fields);
# input
# }
```

## Rename the remaining calls

| Before | After |
| --- | --- |
| `AcsEndpoint::mark_default()` | `AcsEndpoint::with_default()` |
| `SsoRequestBinding::as_binding()`, `SsoResponseBinding::as_binding()`, `LogoutBinding::as_binding()`, `NameIdManagementBinding::as_binding()` | `Binding::from(binding)` |
| `Received::new`, `Received::with_relay_state` | Removed. Take a `Received` from the receive operation |
| `PostForm::new` | Removed. Take a `PostForm` from `Outbound::post_form` |

`NameIdManagementBinding` now implements `TryFrom<Binding>`. A binding other
than HTTP-Redirect or SOAP returns `SamlError::UnsupportedBinding`.
