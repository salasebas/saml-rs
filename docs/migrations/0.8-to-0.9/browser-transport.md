# Upgrade RelayState, pending state, and browser input code

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

The `relay_state` setters of `StartSso`, `RespondSso`, `StartSlo`,
`StartNameIdManagement`, and `StartPaosSso` take a `RelayState`. A request
carries no RelayState when you leave its setter out. A response always carries
the RelayState its request carried, as the next section describes. `finish_name_id_management_redirect` returns
`Option<RelayState>`.

Before the upgrade, wrap the value and read it back through `as_deref`.

```rust,ignore
let relay_state = RelayStateParam::try_from_option(Some("return-to-cart".to_string()))?;
let started = sp.start_sso(&idp, StartSso::redirect().relay_state(relay_state))?;

let session = sp.finish_sso(&idp, &pending, input, validation)?;
if session.relay_state() == &RelayStateParam::Absent {
    return Ok(None);
}
let target = session.relay_state().as_deref();
```

After the upgrade, pass the `RelayState` and read an `Option`.

```rust
# use saml_rs::{IdpDescriptor, RelayState, Saml, SamlError, Sp, SsoSession, StartSso};
# fn start(sp: &Saml<Sp>, idp: &IdpDescriptor) -> Result<(), SamlError> {
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

`PendingSnapshot<Message>` and its constructors `authn_request`,
`logout_request`, and `manage_name_id_request` are removed. Each pending type
has its own snapshot, a plain struct with public fields:

- `PendingAuthnRequest::snapshot` returns `PendingAuthnRequestSnapshot`.
- `PendingLogoutRequest::snapshot` returns `PendingLogoutRequestSnapshot`.
- `PendingManageNameIdRequest::snapshot` returns
  `PendingManageNameIdRequestSnapshot`.

Build a snapshot from stored values with a struct literal, then call
`from_snapshot`.

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

After the upgrade, write the snapshot as one literal.

```rust
# use saml_rs::{PendingAuthnRequest, PendingAuthnRequestSnapshot, SamlError};
# struct Row { request_id: String, relay_state: Option<String>, idp_entity_id: String,
#     acs_binding: String, acs_url: String, acs_index: Option<u16>, acs_is_default: bool }
# fn restore(row: Row) -> Result<PendingAuthnRequest, SamlError> {
let pending = PendingAuthnRequest::from_snapshot(PendingAuthnRequestSnapshot {
    request_id: row.request_id,
    relay_state: row.relay_state,
    idp_entity_id: row.idp_entity_id,
    acs_binding: row.acs_binding,
    acs_url: row.acs_url,
    acs_index: row.acs_index,
    acs_is_default: row.acs_is_default,
})?;
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

`PendingPaosSsoSnapshot` keeps its field names. Its `relay_state` is an
`Option<String>`.

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

`PendingPaosSso` keeps `request_id()` and `idp_entity_id()`.

`Pending::try_new`, `with_request_binding`, `with_issue_instant`, and
`with_expiration` are removed. Take pending state from the start operation,
or rebuild it from stored fields with `from_snapshot`.

## Pass parsed fields to `BrowserInput::simple_sign`

`BrowserInput::simple_sign_body` is removed, and
`BrowserInput::SimpleSignPost` no longer has a `raw_body` field. The
HTTP-POST-SimpleSign signature covers the decoded field values, so the raw
body was not needed. Parse the form as you do for `BrowserInput::post`.

Before the upgrade, you passed the raw body.

```rust,ignore
let input = BrowserInput::<SsoResponse>::simple_sign_body(body);
```

After the upgrade, pass the parsed fields.

```rust
# use saml_rs::{BrowserInput, FormField, SsoResponse};
# fn input(form: Vec<(String, String)>) -> BrowserInput<SsoResponse> {
let fields = form
    .into_iter()
    .map(|(name, value)| FormField::new(name, value))
    .collect();
let input = BrowserInput::<SsoResponse>::simple_sign(fields);
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
