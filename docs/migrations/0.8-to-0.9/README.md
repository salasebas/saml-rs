# How to upgrade from 0.8 to 0.9

This guide moves an integration of `saml-rs`, `opensaml`, `samlify`, or
`samlet` from the latest `0.8.x` release to `0.9.x`. The compatibility crates
re-export the same API, so every step applies to them too. Compatible
additions are in the [changelog](../../../CHANGELOG.md).

`samlify` is deprecated and will no longer be maintained. To move off it,
rename the `samlify` key in `Cargo.toml` to `saml-rs`, keeping its version,
`default-features`, and `features`. Then change the import path from
`samlify` to `saml_rs`. The API and the feature flags are the same.

Starting with 0.9, we're focusing on stabilizing the public API ahead of 1.0.
We expect breaking changes to be less frequent and will document any changes
that require updates to existing integrations.

## Topics

Check the topics that affect your integration.

- [Fix compile errors](compile-errors.md)
- [Move off the hidden modules](public-imports.md)
- [Move off the raw API](raw-api.md)
- [Update SSO attributes](sso-attributes.md)
- [Update SSO results and identities](sso-results-and-identities.md)
- [Update metadata configuration and trust](metadata.md)
- [Update metadata imports and accessors](metadata-api.md)
- [Move schema validation into XML policy](xml-policy.md)
- [Upgrade logout, validation, and replay code](logout-validation-replay.md)
- [Match typed `SamlError` variants](errors.md)
- [Upgrade RelayState, pending state, and inbound message code](browser-transport.md)
- [Upgrade typed config code](config.md)
- [Upgrade SOAP, artifact resolution, and discovery cookie code](soap-artifact-discovery.md)
- [Upgrade typed operation options, PAOS, and name identifier management code](typed-operations.md)

[All migration guides](../README.md)
