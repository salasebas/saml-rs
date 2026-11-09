# Single Logout over SOAP

This break is unreleased. It applies to the release that first publishes
Single Logout over SOAP.

Three public enums gain a SOAP variant. A `match` with no wildcard arm no
longer compiles.

## Handle `LogoutBinding::Soap`

Who must change: code that matches `saml_rs::LogoutBinding`, for example on
`SloEndpoint::binding` or `PendingLogoutRequest::response_binding`.

Add an arm for `LogoutBinding::Soap`. A pending logout restored from a
snapshot reports it when the logout was started with `StartSlo::soap`.

## Handle `Binding::Soap`

Who must change: code that matches `saml_rs::raw::Binding` (also
`saml_rs::constants::Binding`), for example on `BindingContext::binding`.

Add an arm for `Binding::Soap`. Raw SSO creation returns
`SamlError::UnsupportedBinding` for it, and the raw parsers do not read it.
`Binding::from_urn` now returns `Binding::Soap` for
`urn:oasis:names:tc:SAML:2.0:bindings:SOAP` instead of `None`. An
`AuthnRequest` whose `ProtocolBinding` is that URN now fails with
`SamlError::UndefinedBinding` instead of `SamlError::Invalid`.

## Handle `BrowserInput::Soap`

Who must change: code that matches `saml_rs::BrowserInput` by variant.

Add an arm for `BrowserInput::Soap { envelope, .. }`. Build it with
`BrowserInput::<LogoutRequest>::soap` or
`BrowserInput::<LogoutResponse>::soap`.

## Other changes

`BindingContext::context` for a SOAP logout message is the protocol XML, not
base64. `BindingContext::entity_endpoint` is empty for a SOAP
`LogoutResponse`, which has no `Destination`.
