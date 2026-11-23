# Remove Enhanced Client/Proxy SSO

[How to upgrade from 0.8 to 0.9](README.md)

**Affects:** service providers that call `start_paos_sso`, `finish_paos_sso`,
or `finish_paos_sso_with_outstanding_logout`, identity providers that call
`receive_paos_sso` or `respond_paos_sso`, and deployments that store a
`PendingPaosSsoSnapshot`.

**Before:** both roles ran Enhanced Client/Proxy (ECP) login. The service
provider used PAOS and the identity provider used SOAP.

**Now:** ECP and its PAOS binding are removed, with these items:

- `StartPaosSso`, `StartedPaosSso`, `PendingPaosSso`, and
  `PendingPaosSsoSnapshot`
- `PaosHttpResponse` and `SoapFault`
- `check_paos_client_headers`
- `ServiceProvider::start_paos_sso`, `finish_paos_sso`, and
  `finish_paos_sso_with_outstanding_logout`
- `IdentityProvider::receive_paos_sso` and `respond_paos_sso`

Browser SSO, SOAP Single Logout, SOAP artifact resolution, and SOAP name
identifier management are unchanged.

**Upgrade:** saml-rs 0.9 has no replacement.

- To log in a client without a browser, use the flow your identity provider
  offers for it, such as the OAuth 2.0 device authorization grant.
- To keep an ECP endpoint, run that endpoint on saml-rs 0.8.
- Delete stored `PendingPaosSsoSnapshot` JSON. A pending ECP login cannot
  finish after the upgrade.

If your deployment needs ECP in saml-rs, open an issue that names the identity
provider product and the client that uses it.
