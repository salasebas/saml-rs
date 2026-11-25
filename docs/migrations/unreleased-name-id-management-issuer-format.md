# Handle non-entity issuers in HTTP-Redirect name identifier management

If you exchange `ManageNameIDRequest` messages over HTTP-Redirect, two
methods on both `ServiceProvider` and `IdentityProvider` now return
`SamlError::ProtocolProfile` when the peer's `Issuer` has a `Format` other
than `urn:oasis:names:tc:SAML:2.0:nameid-format:entity`:

- `receive_name_id_management_redirect`, for any request.
- `finish_name_id_management_redirect`, for a response with a `Success`
  status. A response with another status still returns
  `SamlError::StatusNotSuccess`.

Before, these methods compared only the `Issuer` value. The SOAP methods
`receive_name_id_management` and `StartedNameIdManagement::finish` already
refused such an `Issuer`.

Profiles §4.5.4.1 and §4.5.4.2 oblige the sender to omit `Format` or write
`entity`, so a conforming peer is not affected. If a peer writes another
`Format`, ask its operator to omit it. No option relaxes the check.
