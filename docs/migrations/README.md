# How to upgrade saml-rs

Apply the guides in order, starting with your installed minor version. Each
guide covers one upgrade. The [changelog](../../CHANGELOG.md) lists compatible
additions.

## Guides

- [How to upgrade from 0.2 to 0.3](0.2-to-0.3/README.md)
- [How to upgrade from 0.3 to 0.4](0.3-to-0.4/README.md)
- [How to upgrade from 0.4 to 0.5](0.4-to-0.5/README.md)
- [How to upgrade from 0.5 to 0.6](0.5-to-0.6/README.md)
- [How to upgrade from 0.6 to 0.7](0.6-to-0.7/README.md)
- [How to upgrade from 0.7 to 0.8](0.7-to-0.8/README.md)
- [How to upgrade from 0.8 to 0.9](0.8-to-0.9/README.md)

## Unreleased changes

- [Handle SOAP artifact response size errors](unreleased-artifact-response-budget.md)
- [Configure ECDSA and Ed25519 signing](unreleased-elliptic-curve-signing.md)
- [Read received formats without surrounding whitespace](unreleased-format-whitespace.md)
- [Handle browser binding parameter errors](unreleased-browser-binding-parameters.md)
- [Import peers from a federation aggregate](unreleased-metadata-aggregate.md)
- [Check messages against the URL that received them](unreleased-receiving-url-checks.md)
- [Look up artifact resolution endpoints by role](unreleased-artifact-index-per-role.md)
- [Handle identity provider response value errors](unreleased-idp-response-values.md)
- [Send timeout logout reasons only from the identity provider](unreleased-session-authority-logout-reasons.md)
- [Keep AllowCreate false in AuthnRequests](unreleased-allow-create-default.md)
- [Handle status shape errors and SOAP replies](unreleased-status-and-soap-replies.md)
- [Handle attribute name errors and encryption key choice](unreleased-attribute-output.md)
- [Handle SSO responses with alternative assertions and confirmations](unreleased-bearer-alternatives.md)
- [Read requested formats without surrounding whitespace](unreleased-requested-format-whitespace.md)
- [Select assertion consumer services within one SP role](unreleased-acs-index-per-role.md)

[How to add a migration guide](../../CONTRIBUTING.md#how-to-add-a-migration-guide)
