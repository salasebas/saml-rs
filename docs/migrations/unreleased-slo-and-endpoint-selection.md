# Endpoint selection and respond_slo issuer

This change is unreleased. Existing calls compile. Runtime logout and
Web Browser SSO routing changes.

## Match the LogoutRequest issuer in respond_slo

`Saml<Sp>::respond_slo` and `Saml<Idp>::respond_slo` compare the
`LogoutRequest` issuer with the peer descriptor entity ID before building a
`LogoutResponse`. A mismatch returns `SamlError::IssuerMismatch`. `expected`
is the request issuer. `actual` is the descriptor entity ID.

Who must change: a caller that responds through a descriptor for a different
party than the request issuer.

Pass the descriptor whose entity ID is that issuer. The same check already
applies to `respond_sso`. It keeps `InResponseTo` from being sent to another
party's `SingleLogoutService`. This rejection is library policy.

## Use the metadata default AssertionConsumerService

When an `AuthnRequest` names no ACS URL, ACS index, or `ProtocolBinding`,
`respond_sso` uses the default `AssertionConsumerService` across the entire
metadata role. `initiate_sso` uses the same global default for an unsolicited
response.

Only ACS endpoints in the selected `SPSSODescriptor` advertising
`urn:oasis:names:tc:SAML:2.0:protocol` participate. A default in a role for
another protocol does not affect SAML 2.0 routing.

The default, among all ACS endpoints in the role, is the first with `isDefault`
true (`true` or `1`), otherwise the first whose `isDefault` is not false
(`false` or `0`), otherwise the first. These XML Schema boolean values also
allow surrounding spaces, tabs, carriage returns, and line feeds.
Only the unqualified `isDefault` attribute controls selection. A qualified
extension attribute such as `ext:isDefault` does not change the default.

An unsupported default or a default whose binding differs from the chosen
`RespondSso` binding returns `SamlError::Invalid`. The response does not fall
back to another endpoint. Choose `RespondSso::post` or
`RespondSso::simple_sign` to match the default endpoint's binding.

Who must change: a deployment that relied on an unspecified request or an
unsolicited response going to a nondefault ACS for the chosen binding.

Mark the endpoint that should receive traffic with `AcsEndpoint::mark_default`,
or remove `isDefault="false"` from the endpoint that should remain the
default.

`start_sso` without an ACS index still chooses an endpoint within its response
binding, then explicitly emits that URL and `ProtocolBinding`. Requests that
select an ACS URL or ACS index keep that explicit selection. Binding-only
requests and `start_sso` now use the indexed-default algorithm within their
binding's candidates, instead of the first endpoint.

The raw `SpMetadata::get_assertion_consumer_service(binding)` lookup keeps its
binding-specific scope and applies the new default algorithm. Raw request and
response creation, and response parsing without an explicit recipient, use
that lookup. Update metadata defaults if you relied on the first endpoint.

`Saml<Sp>::start_paos_sso` without an explicit ACS URL applies the same default
algorithm to its HTTP-POST and HTTP-POST-SimpleSign candidates. This can skip
a first endpoint marked `isDefault="false"`. Select the desired URL with
`StartPaosSso::acs_url`, or update the published default.

## Send LogoutResponse to ResponseLocation

A `LogoutResponse` is sent to `ResponseLocation` on the first
`SingleLogoutService` for the binding when that attribute is present and
non-empty. XML Schema whitespace in endpoint attributes is collapsed first.
Otherwise it is sent to `Location`. A `LogoutRequest` still uses
`Location`. `Metadata::get_single_logout_response_service` reads the response
URL.

Who must change: a peer that publishes `ResponseLocation` and still expects
the response at `Location`.

Accept the response at `ResponseLocation`, or omit that attribute when both
messages belong at `Location`. The service-provider `https` recommendation
checks the URL that is actually used.

## Supply the actual receiving endpoint

`Saml<Idp>::receive_sso`, both roles' `receive_slo`, and both roles'
`finish_slo` compare `Destination` with the actual receiving URL.
Publishing another URL does not make messages for that URL valid at the
current handler.

Who must change: a caller with multiple distinct local endpoints for the
incoming binding. Without an explicit receiving URL, these methods now
return `SamlError::Invalid` when endpoint selection is ambiguous. A caller
with one endpoint keeps the existing calls.

Pass the handler's externally visible URL through
`SamlValidationContext::with_recipient_endpoint`:

```rust
use saml_rs::{EndpointUrl, ReplayPolicy, SamlValidationContext};
use std::time::SystemTime;

let validation = SamlValidationContext::new(
	SystemTime::now(),
	ReplayPolicy::DisabledForCompatibility,
)
.with_recipient_endpoint(EndpointUrl::try_new("https://idp.example.com/sso/second")?);
# Ok::<(), saml_rs::SamlError>(())
```

Read that URL from trusted handler configuration or the trusted HTTP
request context. Do not copy the message's `Destination` into the context.
`SamlValidationContext::recipient_endpoint` exposes the supplied value.

The URL must be published for the incoming binding and message direction.
`receive_sso` uses `SingleSignOnService` `Location` and ignores
`ResponseLocation`. `receive_slo` uses `SingleLogoutService` `Location`.
`finish_slo` uses each `ResponseLocation`, with `Location` as its fallback.
An unpublished receiving URL returns `SamlError::Invalid`. A mismatched
message destination returns `SamlError::DestinationMismatch`, whose
`expected` field names the actual receiving URL.

Explicit selection for ambiguous metadata and the published-URL restriction
are library configuration policy. Core and the HTTP bindings require the
comparison with the actual receiving URL.
