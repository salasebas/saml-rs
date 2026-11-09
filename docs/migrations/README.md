# How to upgrade saml-rs

Apply every guide from the minor version you run today up to the version you
are installing. Each guide is the work an existing integration must do. The
[changelog](../../CHANGELOG.md) lists the rest of the release, including
compatible additions.

## Guides

- [How to upgrade from 0.2 to 0.3](0.2-to-0.3.md)
- [How to upgrade from 0.3 to 0.4](0.3-to-0.4.md)
- [How to upgrade from 0.4 to 0.5](0.4-to-0.5.md)
- [How to upgrade from 0.5 to 0.6](0.5-to-0.6.md)
- [How to upgrade from 0.6 to 0.7](0.6-to-0.7.md)

## Unreleased

- [Artifact resolution service on IdP metadata](unreleased-artifact-resolution.md)
- [How to update endpoint routing and logout responses](unreleased-slo-and-endpoint-selection.md)
- [Attribute name formats and persistent and transient NameID length](unreleased-attribute-name-format.md)
- [Limited base64 decoding ignores only space, tab, CR, LF, and form feed](unreleased-base64-whitespace.md)
- [Web SSO response over HTTP-Artifact](unreleased-http-artifact-response.md)
- [Single Logout over SOAP](unreleased-soap-logout.md)
- [Conformance §4 algorithms](unreleased-conformance-algorithms.md)
- [Name identifier management](unreleased-name-id-management.md)
- [Metadata in the schema element order](unreleased-metadata-element-order.md)
- [EncryptedID and EncryptedAttribute](unreleased-encrypted-id-and-attribute.md)
- [LogoutResponse status after authentication](unreleased-logout-response-status.md)
- [Single Logout endpoints from the peer's role](unreleased-slo-role-endpoints.md)
- [RSA-v1.5 key-transport decryption](unreleased-rsa15-key-transport-decryption.md)
- [EncryptedAssertion content](unreleased-encrypted-assertion-content.md)
- [Generated IDs are 160 random bits in 41 characters](unreleased-generated-id-length.md)
- [NameID formats must be absolute URIs](unreleased-name-id-format-uri.md)
- [Every EncryptedAssertion is decrypted](unreleased-every-encrypted-assertion.md)
- [A signed AuthnRequest must carry Destination under RequireSigned](unreleased-signed-authn-request-destination.md)

Someone shipping a breaking change adds the next guide from
[Contributing](../../CONTRIBUTING.md#how-to-add-a-migration-guide).
