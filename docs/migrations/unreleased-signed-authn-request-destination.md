# A signed AuthnRequest must carry Destination under RequireSigned

This break is unreleased. It applies to `Saml<Idp>::receive_sso` with
`AuthnRequestValidationPolicy::RequireSigned`.

A signed HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign `AuthnRequest`
without `Destination` now returns `SamlError::DestinationMismatch` with no
actual value. Before, `RequireSigned` accepted it, while
`AllowUnsignedVerifyIfPresent` already rejected it. Bindings §§3.4.5.2 and
3.5.5.2 require `Destination` on a signed message and require the recipient to
verify it.

Who must change: identity providers that use `RequireSigned` and accept
requests from a service provider that signs without `Destination`. That
service provider must send `Destination` set to the identity provider's
`SingleSignOnService` URL. `saml-rs` service providers already do.
`receive_paos_sso` is unchanged.
