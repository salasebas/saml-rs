# How to upgrade from 0.7 to 0.8

This guide moves an integration of `saml-rs`, `opensaml`, `samlify`, or
`samlet` from the latest `0.7.x` release to `0.8.x`. The compatibility crates
re-export the same API, so every step applies to them too. Compatible
additions are in the [changelog](../../../CHANGELOG.md).

## Topics

1. [Fix compile errors](compile-errors.md).
2. [Check the signature and trust defaults](signature-and-trust.md).
   They change what `recommended()` accepts, so most deployments read this
   part.
3. Check the roles and features you use.
   - [Service provider SSO](sp-sso.md)
   - [Identity provider SSO](idp-sso.md)
   - [Metadata](metadata.md)
   - [Single Logout and name identifier management](logout-and-name-id-management.md)
   - [XML, SOAP, and bindings](xml-and-bindings.md)
4. Check [smaller changes](other-changes.md) if you compare outputs or match
   specific errors.

Use the **Affects** notes to identify the changes you need.

[All migration guides](../README.md)
