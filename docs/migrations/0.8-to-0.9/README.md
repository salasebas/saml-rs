# How to upgrade from 0.8 to 0.9

This guide moves an integration of `saml-rs`, `opensaml`, `samlify`, or
`samlet` from the latest `0.8.x` release to `0.9.x`. The compatibility crates
re-export the same API, so every step applies to them too. Compatible
additions are in the [changelog](../../../CHANGELOG.md).

## Topics

Check the topics that affect your integration.

- [Fix compile errors](compile-errors.md)
- [Move off the hidden modules](public-imports.md)
- [Move off the deprecated raw API](raw-api.md)
- [Update SSO attributes](sso-attributes.md)
- [Update metadata configuration and trust](metadata.md)
- [Update metadata imports and accessors](metadata-api.md)
- [Move schema validation into XML policy](xml-policy.md)
- [Upgrade logout, validation, and replay code](logout-validation-replay.md)

[All migration guides](../README.md)
