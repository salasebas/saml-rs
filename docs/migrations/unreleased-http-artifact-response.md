# Web SSO response over HTTP-Artifact

This break is unreleased. It applies to the release that first publishes the
HTTP-Artifact response.

Two public enums gain a variant, so an exhaustive `match` on either no longer
compiles. Two conversions that returned `SamlError::UndefinedBinding` for
HTTP-Artifact now succeed.

## Match the new response binding

This breaks an exhaustive `match` on `saml_rs::SsoResponseBinding`.

Who must change: code that matches every variant without a wildcard arm.

Add an arm for `SsoResponseBinding::Artifact`. A service provider that does
not publish an HTTP-Artifact assertion consumer never starts a login with that
binding. An identity provider can still receive it from
`AuthnRequest::protocol_binding`.

```rust
use saml_rs::SsoResponseBinding;

fn label(binding: SsoResponseBinding) -> &'static str {
    match binding {
        SsoResponseBinding::Post => "post",
        SsoResponseBinding::SimpleSign => "simple-sign",
        SsoResponseBinding::Artifact => "artifact",
    }
}
```

## Match the new browser input

This breaks an exhaustive `match` on `saml_rs::BrowserInput`.

Who must change: code that matches every variant without a wildcard arm.

Add an arm for `BrowserInput::Artifact`. It is built only by
`BrowserInput::<SsoResponse>::artifact`. Typed AuthnRequest and logout calls
return an error for it.

## Handle an AuthnRequest that asks for an artifact

Who must change: an identity provider that relied on `receive_sso` rejecting
`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"`.

`Saml<Idp>::receive_sso` now returns that request, and
`AuthnRequest::protocol_binding` reports `SsoResponseBinding::Artifact`.
`respond_sso` returns `SamlError::Invalid` for it, because the request does
not allow HTTP-POST or HTTP-POST-SimpleSign. Answer it with
`respond_sso_artifact`:

```rust
use saml_rs::{
    ArtifactDelivery, AuthnRequest, IssuedArtifacts, Outbound, Received, RespondSso, Saml,
    SamlError, SpDescriptor, SsoResponse, SsoResponseBinding, Subject,
};

fn respond(
    idp: &Saml<saml_rs::Idp>,
    sp: &SpDescriptor,
    request: &Received<AuthnRequest>,
    subject: Subject,
    issued: &mut IssuedArtifacts,
) -> Result<Outbound<SsoResponse>, SamlError> {
    match request.message().protocol_binding() {
        Some(SsoResponseBinding::Artifact) => idp.respond_sso_artifact(
            sp,
            request,
            subject,
            RespondSso::artifact(ArtifactDelivery::redirect(0)),
            issued,
        ),
        Some(SsoResponseBinding::SimpleSign) => {
            idp.respond_sso(sp, request, subject, RespondSso::simple_sign())
        }
        Some(SsoResponseBinding::Post) | None => {
            idp.respond_sso(sp, request, subject, RespondSso::post())
        }
    }
}
```

The identity provider publishes a SOAP `ArtifactResolutionService` at the
index it passes to `ArtifactDelivery`, and answers the service provider's
`ArtifactResolve` with `answer_artifact_resolve`.

## Stop relying on the HTTP-Artifact conversion error

Who must change: code that used `SamlError::UndefinedBinding` to detect an
HTTP-Artifact assertion consumer.

`SsoResponseBinding::try_from(Binding::Artifact)` and
`AcsEndpoint::try_from_raw` for an HTTP-Artifact endpoint now succeed. Compare
`AcsEndpoint::binding` with `SsoResponseBinding::Artifact` instead.
`SsoRequestBinding` and `LogoutBinding` still reject HTTP-Artifact.

Two calls change with that conversion when an assertion consumer index names
an HTTP-Artifact endpoint:

- `StartSso::assertion_consumer_service_index` with that index now starts a
  login whose response binding is HTTP-Artifact. It returned
  `SamlError::UndefinedBinding`.
- `respond_sso` for an `AuthnRequest` that carries that index now returns
  `SamlError::Invalid`, because the index does not allow HTTP-POST or
  HTTP-POST-SimpleSign. It returned `SamlError::UndefinedBinding`.

Enhanced Client/Proxy SSO still rejects a `ProtocolBinding` that names
HTTP-Artifact.
