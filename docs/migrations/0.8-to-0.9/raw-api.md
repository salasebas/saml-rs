# 3. Move off the raw API

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** code that imports `saml_rs::raw`, or calls the message functions
of the hidden `saml_rs::sp`, `saml_rs::idp`, `saml_rs::flow`, or
`saml_rs::logout` modules.

**Now:** the raw API is removed. `raw`, `sp`, `idp`, `entity`, `flow`, and
`logout` are no longer public, and so are `EntitySetting`, `User`,
`LoginRequestOptions`, `LoginResponseOptions`, `FlowOptions`, `FlowResult`,
`BindingContext`, and `HttpRequest`. The raw `ServiceProvider` and
`IdentityProvider` are removed too, and their names now belong to the typed
providers that replace `Saml<Sp>` and `Saml<Idp>`. Move each call to the
typed API:

| Removed | Replacement |
| --- | --- |
| `ServiceProvider::create_login_request`, `create_login_request_with_options` | `ServiceProvider::start_sso` |
| `ServiceProvider::parse_login_response_with_request_id` | `ServiceProvider::finish_sso` |
| `ServiceProvider::parse_unsolicited_login_response`, `parse_login_response` | `ServiceProvider::accept_unsolicited_sso` |
| `IdentityProvider::parse_login_request` | `IdentityProvider::receive_sso` |
| `IdentityProvider::create_login_response` | `IdentityProvider::respond_sso`, or `IdentityProvider::initiate_sso` for an unsolicited response |
| `logout::create_logout_request`, `create_logout_request_with_id` | `start_slo` on `ServiceProvider` or `IdentityProvider` |
| `logout::parse_logout_request` | `receive_slo` |
| `logout::create_logout_response`, `create_logout_response_with_id` | `respond_slo`, with `&Status::success()` for the `Success` they write |
| `logout::parse_logout_response`, `parse_logout_response_without_request_id` | `finish_slo` |
| `flow::flow` | The typed receive operation for the message |
| `HttpRequest::redirect`, `HttpRequest::post` | `Inbound::redirect` with the raw query string, `Inbound::post` with the form fields |
| `ServiceProvider::from_metadata`, `IdentityProvider::from_metadata` | For your own role, `ServiceProvider::new` with an `SpConfig` or `IdentityProvider::new` with an `IdpConfig`. For the peer, `SpDescriptor::from_metadata_xml` or `IdpDescriptor::from_metadata_xml` |
| `EntitySetting` | `SpConfig` and `IdpConfig`, with their builders |
| `LoginRequestOptions::custom`, `LoginResponseOptions::custom` | Use typed SSO inputs. See [Typed config](config.md#replace-sso-templates-with-typed-options) |
| `LoginResponseOptions::encrypt_then_sign` | Nothing. It was never read: an encrypted, message-signed response is always signed after the assertion is encrypted |
| `Outbound::raw_context().binding` | `Outbound::delivery()` |
| `Outbound::raw_context().context`, `into_raw_context` | `Outbound::redirect_url`, `post_form`, `soap_request`, or `soap_response` |
| `raw_flow()` on `SsoSession`, `AuthnRequest`, `LogoutRequest`, `LogoutResponse`, and `LogoutCompleted` | The typed accessors of the message |
| `Saml::<Sp>::raw_service_provider`, `Saml::<Idp>::raw_identity_provider` | Nothing. Configure the provider with `SpConfig` or `IdpConfig` |
| `TryFrom<FlowResult>` for `SsoSession`, `AuthnRequest`, `LogoutRequest`, and `LogoutResponse` | The typed receive operation, which also runs the receiver checks those conversions skipped |
| `TryFrom<BindingContext>` for `Outbound<_>`, `TryFrom<Inbound<_>>` for `HttpRequest` | Nothing. Typed operations return an `Outbound` and take an `Inbound` |
| `raw::Binding` | `saml_rs::constants::Binding` |

A service-provider login moves from a raw request and response to a pending
request that `finish_sso` checks the response against:

```rust
// Before
let request = sp.create_login_request(&idp, Binding::Redirect, None)?;
// Store request.id, then redirect the browser to request.context.
let result = sp.parse_login_response_with_request_id(&idp, Binding::Post, &http, &request.id)?;
let name_id = result.extract.get_str("nameID");

// After
let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;
// Store started.pending.snapshot(), then redirect the browser to started.outbound.
let session = sp.finish_sso(
    &idp_descriptor,
    &pending,
    Inbound::post(fields),
    validation,
)?;
let name_id = session.name_id().value();
```

Code that sends any outbound message the same way matches on its delivery:

```rust
use saml_rs::{Outbound, OutboundDelivery};

fn send<Message>(outbound: &Outbound<Message>) {
    match outbound.delivery() {
        OutboundDelivery::Redirect(url) => { /* 303 to url */ }
        OutboundDelivery::PostForm(form) => { /* render the auto-submitted form */ }
        OutboundDelivery::SoapRequest(request) => { /* POST request.envelope() */ }
        OutboundDelivery::SoapResponse(response) => { /* reply with response.envelope() */ }
        _ => {}
    }
}
```

The [SSO example](../../../examples/sso.rs) and
[logout example](../../../examples/slo.rs) show the full typed flows.
Use [replay storage](logout-validation-replay.md#supply-replay-storage-for-http-post-sso)
when receiving HTTP-POST SSO. The typed operations also check
`InResponseTo` correlation, RelayState, and the receiving endpoint.

The raw service provider's defaults differ from `SpValidationPolicy::default`
in three fields. To select the old settings, set those fields as shown below.
The SP now [verifies every present SSO signature](logout-validation-replay.md#verify-every-signature-on-sso-responses)
under these settings.

```rust
use saml_rs::{
    AudienceValidationPolicy, ResponseSignaturePolicy, SpValidationPolicy, XmlSignatureProfile,
};

let mut validation = SpValidationPolicy::default();
validation.responses = ResponseSignaturePolicy::AllowUnsignedEncryptedCbc;
validation.xml_signatures = XmlSignatureProfile::AllowWeakAlgorithms;
validation.audience = AudienceValidationPolicy::RequireRestriction;
```

The raw identity provider's defaults differ from
`IdpValidationPolicy::default` in two fields. The raw IdP skipped AuthnRequest signature
verification and used the equivalent of `XmlSignatureProfile::AllowWeakAlgorithms`.
The typed IdP [verifies present request signatures](authn-request-signatures.md).

`accept_unsolicited_sso` rejects an unsolicited response that carries an empty
`InResponseTo=""`. `parse_unsolicited_login_response` read an empty value as
absent.
