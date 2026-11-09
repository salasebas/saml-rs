# Public API map

> Design record for the typed API. The live file index is
> [the module map](../module-map.md). A heading that says Proposed, Target,
> or Today describes this design.

This note records the names proposed for the typed facade and the map from
raw names to those names. The reasons for the role names are in
[Naming](001-naming.md).

## Root Exports

Root exports in this design:

```rust
pub use api::{Idp, Saml, Sp, Unknown};
pub use config::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AttributeEncryptionPolicy, AuthnRequestSigningPolicy,
    AuthnRequestValidationPolicy, Credentials, IdentifierEncryptionPolicy,
    IdpConfig, IdpConfigBuilder, IdpValidationPolicy, LogoutSignaturePolicy,
    SpConfig, SpConfigBuilder, SpValidationPolicy, XmlEncryptionPolicy,
    XmlPolicy,
};
pub use descriptor::{IdpDescriptor, SpDescriptor};
pub use error::SamlError;
pub use metadata::{MetadataTrustPolicy, VerifiedIdpMetadata, VerifiedSpMetadata};
pub use model::{
    AcsEndpoint, AuthnRequest, AuthnSession, BrowserInput, LogoutBinding,
    LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSigning,
    LogoutSubject, NameId, NameIdCreationRequest, Outbound, Pending,
    PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, Received,
    RelayState, SamlStatus,
    SloEndpoint, SsoEndpoint, SsoRequestBinding,
    SsoResponse, SsoResponseBinding, SsoSession, StartSlo, StartSso,
    Started, Subject, RespondSlo, RespondSso,
};
pub use browser::{FormField, PostForm};
pub use validation::{ReplayCache, ReplayKey, ReplayPolicy, SamlValidationContext};
```

The exact module names can change during implementation, but root docs should
make these types discoverable.

## docs.rs public surface

New integrations should use the crate-root re-exports and visible docs.rs
modules as the supported public documentation surface. The visible modules are
`browser`, `config`, `constants`, `error`, `metadata`, `model`, and `raw`.
Advanced callers that need the lower-level compatibility API should import it
through `saml_rs::raw`.

Some root modules remain publicly importable but hidden from docs.rs. These
hidden public modules are not the recommended starting point for new
integrations. When such paths remain available for compatibility, they are
lower-level implementation or protocol surfaces and may receive less item-level
documentation than the visible API.

Current hidden root modules are classified as:

| Category | Modules |
| --- | --- |
| Root-reexported implementation module | `api` |
| Raw implementation modules | `sp`, `idp`, `flow`, `entity`, `logout` |
| Protocol/helper modules | `binding`, `crypto`, `xml`, `context`, `template`, `util`, `validator` |

## Raw API in this design

The raw call shape this design kept:

```rust
let request = sp.create_login_request(&idp, Binding::Post, None)?;

let parsed = idp.parse_login_request(
    &sp,
    Binding::Post,
    &HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]),
)?;

let response = idp.create_login_response(
    &sp,
    Binding::Post,
    &user,
    &LoginResponseOptions {
        in_response_to: parsed.extract.get_str("request.id"),
        ..Default::default()
    },
)?;

let result = sp.parse_login_response_with_request_id(
    &idp,
    Binding::Post,
    &HttpRequest::post(vec![("SAMLResponse".into(), response.context)]),
    &request.id,
)?;

let name_id = result.extract.get_str("nameID");
```

This remains available as raw compatibility.

## Typed API in this design

The typed call shape this design called for:

```rust
let sp_saml = Saml::sp(sp_config)?;
let idp_descriptor =
    IdpDescriptor::from_metadata_xml_for(expected_idp_entity_id, idp_xml, trust_policy)?;

let started = sp_saml.start_sso(&idp_descriptor, StartSso::post())?;

let request = idp_saml.receive_sso(
    &sp_descriptor,
    BrowserInput::<AuthnRequest>::post(form_fields),
    validation,
)?;

let response = idp_saml.respond_sso(
    &sp_descriptor,
    &request,
    subject,
    RespondSso::post(),
)?;

let session = sp_saml.finish_sso(
    &idp_descriptor,
    &started.pending,
    BrowserInput::<SsoResponse>::post(response_fields),
    validation,
)?;
```

## Mapping Table

| Current | New typed API | Notes |
| --- | --- | --- |
| `ServiceProvider` | `Saml<Sp>` | Active local SP. Current type remains raw. |
| `IdentityProvider` | `Saml<Idp>` | Active local IdP. Current type remains raw. |
| peer `ServiceProvider` | `SpDescriptor` | Peer SP metadata and trust state. |
| peer `IdentityProvider` | `IdpDescriptor` | Peer IdP metadata and trust state. |
| `EntitySetting` | `SpConfig`, `IdpConfig` | Typed config with redacted credentials. |
| raw `Binding` | `SsoRequestBinding`, `SsoResponseBinding`, `LogoutBinding`, `NameIdManagementBinding` | Operation-specific binding sets. |
| `Endpoint` | `SsoEndpoint`, `AcsEndpoint`, `SloEndpoint`, `ManageNameIdService` | Endpoint role matters. |
| `BindingContext` | `Outbound<Message>` | Binding-specific browser output. |
| `HttpRequest` | `BrowserInput<Message>` | Typed inbound browser input. |
| bare request ID string | `PendingAuthnRequest`, `PendingLogoutRequest`, `PendingManageNameIdRequest`, `PendingSnapshot<_>` | Correlation state. |
| `FlowResult` | `SsoSession`, `Received<_>`, `LogoutCompleted` | Typed results with raw escape hatches. |
| `FlowResult.extract.get_str(...)` | typed accessors | String keys become internal. |

`Pending<Message>` has private fields and marker-specific binding storage.
Applications persist `PendingSnapshot<Message>` through accessors and rebuild a
pending value with a validating `Pending::from_snapshot` constructor. Authn
snapshots carry the selected ACS endpoint; logout snapshots carry the selected
logout binding. Snapshots carry correlation data only: request ID, exact
RelayState state, peer entity ID, binding data, and timing metadata. They do
not carry keys, raw metadata, or raw entity settings.

## Compatibility Rule

The typed API is additive first. The raw API remains available:

```rust
use saml_rs::raw::{
    BindingContext, EntitySetting, FlowResult, HttpRequest, IdentityProvider,
    ServiceProvider,
};
```

`raw::ServiceProvider` and `raw::IdentityProvider` are the recommended raw
imports. Root-level `ServiceProvider` and `IdentityProvider` can remain during
the migration window only as rustdoc-deprecated compatibility exports before
typed API stabilization.
