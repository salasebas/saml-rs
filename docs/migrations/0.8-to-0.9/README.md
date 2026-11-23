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
- [Honor the requested NameID format](name-id-policy.md)
- [Update metadata configuration and trust](metadata.md)
- [Update metadata imports and accessors](metadata-api.md)
- [Correct metadata signing flags](metadata-signing-flags.md)
- [Keep response signatures for SPs with several SAML 2.0 roles](sso-response-signatures.md)
- [Move schema validation into XML policy](xml-policy.md)
- [Update AuthnRequest signature verification](authn-request-signatures.md)
- [Update truncated XML HMAC signatures](hmac-truncation.md)
- [Authenticate browser logout messages](logout-authentication.md)
- [Send one principal identifier per logout request](logout-request-identifier.md)
- [Upgrade logout, validation, and replay code](logout-validation-replay.md)
- [Match typed `SamlError` variants](errors.md)
- [Handle SSO error responses with missing correlation data or mismatched RelayState](sso-error-correlation.md)
- [Upgrade RelayState, pending state, and inbound message code](browser-transport.md)
- [Upgrade typed config code](config.md)
- [Upgrade SOAP, artifact resolution, and discovery cookie code](soap-artifact-discovery.md)
- [Prepare SOAP payloads without processing instructions](soap-processing-instructions.md)
- [Upgrade typed operation options and name identifier management code](typed-operations.md)
- [Remove Enhanced Client/Proxy SSO](ecp-removal.md)
- [Send SAML responses for refused requests](request-refusals.md)
- [Update signing keys for SOAP name identifier management](soap-name-id-signatures.md)
- [Update signing keys for SOAP artifact resolution](soap-artifact-signatures.md)

[All migration guides](../README.md)
