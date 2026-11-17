# Naming

> Design record for the typed API. The live file index is
> [the module map](../module-map.md). A heading that says Proposed, Target,
> or Today describes this design.

This note explains which public names are canonical for the typed facade, and
which names were rejected.

## Crate names

- Cargo package: `saml-rs`
- Rust import path: `saml_rs`
- Canonical error type: `SamlError`

Public names prefixed with `OpenSaml` were rejected. This crate is not
Shibboleth OpenSAML, and `opensaml` remains only the compatibility package
name.

## Active Local Roles

Recommended:

```rust
pub struct Saml<Role = Unknown> {
    // private fields
}

pub enum Unknown {}
pub enum Sp {}
pub enum Idp {}
```

Constructors:

```rust
impl Saml<Unknown> {
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError>;
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError>;
}
```

Rationale:

- `Saml<Sp>` and `Saml<Idp>` clearly mean "this crate's active local role".
- The marker type prevents calling IdP-only methods on an SP.
- Internals can remain private, unlike today's raw `ServiceProvider` and
  `IdentityProvider` structs.

## Peer Metadata Names

Recommended:

```rust
pub struct SpDescriptor { /* private */ }
pub struct IdpDescriptor { /* private */ }
```

Rejected:

- `SpPeer` / `IdpPeer`: superseded by `SpDescriptor` / `IdpDescriptor`.
- `ServiceProvider` / `IdentityProvider`: keep for raw compatibility, not the
  primary typed facade.

Rationale:

- A peer in SAML is normally represented by metadata, not by an active local
  role with private settings.
- `Descriptor` is shorthand for trusted peer entity metadata: entity ID, role
  descriptor, keys, endpoints, policies, and trust state.
- `IdpDescriptor` can carry trust state without implying it can issue messages.
- Plans and docs that still say `Peer` should be updated; `Descriptor` is the
  branch source of truth for peer metadata names.

## Raw Compatibility Names

The current public structs stay available under `raw`:

```rust
pub mod raw {
    pub use crate::flow::{FlowResult, HttpRequest};
    pub use crate::entity::{BindingContext, EntitySetting, User};
    pub use crate::sp::ServiceProvider;
    pub use crate::idp::IdentityProvider;
}
```

The crate root does not re-export `ServiceProvider`, `IdentityProvider`, or
`EntitySetting`. New docs should prefer `Saml<Sp>` and `Saml<Idp>`.

## Binding Names

Recommended:

```rust
#[non_exhaustive]
pub enum SsoRequestBinding {
    Redirect,
    Post,
    SimpleSign,
}

#[non_exhaustive]
pub enum SsoResponseBinding {
    Post,
    SimpleSign,
    Artifact,
}

#[non_exhaustive]
pub enum LogoutBinding {
    Redirect,
    Post,
    SimpleSign,
}
```

Rationale:

- Web SSO AuthnRequests can use Redirect, POST, and SimpleSign.
- Web SSO Responses should not use Redirect in the typed API.
- A Web SSO Response can be delivered as an HTTP-Artifact. Its options are
  `RespondSso<ArtifactDelivery>`, which `respond_sso` does not take.
- Logout has a separate legal binding set.
- Raw `Binding::Artifact` remains the browser HTTP-Artifact binding. SOAP
  artifact resolution does not add a `Binding` variant.

## Endpoint Names

Recommended:

```rust
pub struct SsoEndpoint { /* binding: SsoRequestBinding */ }
pub struct AcsEndpoint { /* binding: SsoResponseBinding, index, default */ }
pub struct SloEndpoint { /* binding: LogoutBinding */ }
```

Rationale:

- ACS endpoints have `index` and `is_default`.
- SSO and SLO endpoints do not.
- One generic typed `Endpoint` would keep today's ambiguity.

## Flow State Names

Recommended:

```rust
pub struct Started<Message> {
    pub pending: Pending<Message>,
    pub outbound: Outbound<Message>,
}

pub struct Pending<Message> { /* private */ }
pub struct Received<Message> { /* private */ }
pub struct PendingSnapshot<Message> { /* public data, no keys */ }
```

Message markers:

```rust
pub struct AuthnRequest;
pub struct SsoResponse;
pub struct LogoutRequest;
pub struct LogoutResponse;
```

`Pending<Message>` remains private-field typed state. Web applications persist
`PendingSnapshot<Message>`, rebuilt through validation constructors such as
`Pending::from_snapshot(snapshot)`. Snapshots expose request ID, RelayState
presence/value, peer entity ID, expected binding, and timing metadata, but never
store keys or raw metadata.

## Domain Result Names

Recommended:

```rust
pub struct SsoSession;
pub struct Subject;
pub struct NameId;
pub struct Attributes;
pub struct Attribute;
pub struct AuthnSession;
pub struct LogoutCompleted;
pub struct StartSso;
pub struct RespondSso;
pub struct StartSlo;
pub struct RespondSlo;
pub struct LogoutSubject;
pub struct LogoutSigning;
pub struct SamlStatus;
pub struct PostForm;
pub struct FormField;
```

`Identity` is intentionally not the preferred result name because "identity" is
too broad for a SAML login session. `SsoSession` communicates that this is the
validated result of browser SSO.

## Configuration method names

These rules distinguish the roles of similarly named methods. They apply when
an API is introduced or redesigned. Existing names are reviewed within the
change that owns that API, rather than renamed across unrelated operations.

- Read accessors use `foo()` or `foo_mut()`, without `get_`. In-place setters
  use `set_foo(&mut self, value)`.
- A dedicated builder uses `foo(value)` for chained configuration.
- An owned value uses `with_foo(self, value) -> Self` for chained
  configuration, leaving `foo()` available for reading. This is the crate's
  convention, not a universal Rust naming requirement.
- Primary constructors use `new`, or `try_new` when fallible. New secondary
  associated constructors use `new_with_foo`, a `from_foo` conversion, or a
  domain name. Reserve a new bare `with_foo` name for the method taking `self`.
- A single-valued configuration method replaces its value. For repeated
  elements, the singular method appends one and the plural appends an
  iterable. Start their doc comments with `Replace`, `Set`, or `Append`.
  Preserve `with_additional_foo` where a primary slot and extra values differ.
- When callers naturally hold a collection, accept it directly. A useful
  singular and plural pair is not redundant. Use `impl IntoIterator<Item = T>`
  when storing each owned item. Do not require callers to reconstruct bulk
  input with a fold or loop.

The [Rust API Guidelines' getter rules](https://rust-lang.github.io/api-guidelines/naming.html#getter-names-follow-rust-convention-c-getter)
cover accessors. Their [constructor rules](https://rust-lang.github.io/api-guidelines/predictability.html#constructors-are-static-inherent-methods-c-ctor)
apply to associated functions without `self`. Their
[builder example](https://rust-lang.github.io/api-guidelines/type-safety.html#builders-enable-construction-of-complex-values-c-builder)
uses bare methods and pairs singular `arg` with plural `args`.

[Google's Rust Style Guide](https://google.github.io/styleguide/rustguide.html#getters-and-setters)
uses `with_foo` for closure accessors, a separate pattern. Google's
[copy-and-set naming example](https://google.github.io/comprehensive-rust/idiomatic/foundations-api-design/predictable-api/naming-conventions/with-copy-setter.html)
is related prior art for value configuration; it does not mandate this crate's
consuming method convention. Google's
[iterator parameter rule](https://google.github.io/styleguide/rustguide.html#iterators-vs-slices-in-function-parameters)
supports the plural input shape.
