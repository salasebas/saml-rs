# Single Logout endpoints from the peer's role

This change is unreleased. It affects you only if one entity's metadata has
both an `IDPSSODescriptor` and an `SPSSODescriptor`, and those roles publish
different `SingleLogoutService` endpoints.

`SpMetadata` now reads `SingleLogoutService` from the `SPSSODescriptor` only,
and `IdpMetadata` reads it from the `IDPSSODescriptor` only. Before, both read
the endpoints of every role in document order. This applies to
`SpDescriptor`, `IdpDescriptor`, the raw `ServiceProvider` and
`IdentityProvider`, and these methods on `SpMetadata` and `IdpMetadata`:

- `get_single_logout_service`
- `get_single_logout_response_service`
- `get_support_bindings`

What changes at runtime:

- Logout requests and responses to a dual-role peer go to the endpoint of
  the role you address: `SPSSODescriptor` for a service provider,
  `IDPSSODescriptor` for an identity provider.
- Typed `receive_slo` and `finish_slo` take as receiving URLs only the
  endpoints of your own role.
- If the addressed role publishes no `SingleLogoutService` for the binding,
  the call returns `SamlError::MissingMetadata("SingleLogoutService")`, even
  when the other role publishes one.
- A raw `IdentityProvider` writes `SessionIndex` only when its
  `IDPSSODescriptor` publishes a `SingleLogoutService`.

To upgrade, publish each role's logout endpoints in that role's descriptor.
Receive logout messages for a role at the URLs published in that role's
descriptor.

`Metadata::parse` and `Metadata::parse_with_limits` have no role. They still
read the endpoints of every role.

The rule is in [Single Logout](../conformance/single-logout.md).
