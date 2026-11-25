# Read `WantAuthnRequestsSigned` from every identity provider role

This change affects service providers that start SSO with an identity provider
whose metadata has more than one SAML 2.0 `IDPSSODescriptor`, and code that
reads `metadata::IdpMetadata::want_authn_requests_signed`. No code fails to
compile.

`want_authn_requests_signed` is now true when any SAML 2.0 `IDPSSODescriptor`
of the entity sets `WantAuthnRequestsSigned` to `true` or `1`. Before, the
first role that set the attribute decided, so an earlier `false` hid a later
`true`. This matches how `AuthnRequestsSigned` and `WantAssertionsSigned` are
read from several service provider roles.

A service provider that does not sign its `AuthnRequest` now gets
`SamlError::AuthnRequestSigningRequired` for such an identity provider. To
upgrade, give the service provider a signing credential and set
`SpValidationPolicy::authn_request_signing` to
`AuthnRequestSigningPolicy::Sign`. Unsigned requests keep working when no
SAML 2.0 role of the identity provider sets `WantAuthnRequestsSigned` to
`true` or `1`.
