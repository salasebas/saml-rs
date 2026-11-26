# Send timeout logout reasons only from the identity provider

SAML Core §3.7.3.2 reserves two `LogoutRequest` reasons for the session
authority:

- `urn:oasis:names:tc:SAML:2.0:logout:global-timeout`
- `urn:oasis:names:tc:SAML:2.0:logout:sp-timeout`

`ServiceProvider::start_slo` and `ServiceProvider::start_async_slo` now
return `SamlError::Invalid` when `StartSlo::reason` holds either URI, after
XML whitespace collapse. Before, the service provider sent the reason.

This change affects you only if your service provider passes one of these
URIs to `StartSlo::reason`. To upgrade a local timeout, send no reason or a
custom URI that you agreed with the identity provider. Send
`urn:oasis:names:tc:SAML:2.0:logout:user` only when the principal asked to
log out.

`IdentityProvider::start_slo` still sends both URIs. `receive_slo` on both
providers still returns any received reason through `LogoutRequest::reason`.
