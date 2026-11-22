---
title: "Coverage"
description: "`ServiceProvider` and `IdentityProvider` implement this surface."
---

`ServiceProvider` and `IdentityProvider` implement this surface.

| Area | Support |
| --- | --- |
| Web SSO | The service provider can send a signed `AuthnRequest` over HTTP-POST, HTTP-Redirect, or HTTP-POST-SimpleSign. The identity provider can send a signed `Response` over HTTP-POST, HTTP-POST-SimpleSign, or HTTP-Artifact |
| Enhanced Client/Proxy SSO | The service provider uses PAOS with the enhanced client. The identity provider uses SOAP with the enhanced client |
| Metadata | Parse peer metadata, generate SP and IdP descriptors, verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` over HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, or SOAP for the identity provider and service provider. The deployment sends the SOAP HTTP request |
| Identity Provider Discovery | `common_domain_cookie` returns the `_saml_idp` cookie for the caller to write. Service providers do not set or read it |
| Identifiers | Every attribute name format on `SsoAssertion::with_attributes` and on an accepted `Attribute`. `NameId::generate_transient`, `NameId::generate_persistent`, and `NameId::persistent` for the identifiers an identity provider issues. The library writes the `ID` of every generated message and assertion |
| HTTP-Artifact response | A Web SSO `Response` delivered as an artifact through `respond_sso_artifact`, and accepted by `finish_sso` after `resolve_artifact`. `AuthnRequest` and logout messages are not delivered this way |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` through `resolve_artifact` and `answer_artifact_resolve`. The deployment sends the HTTP request |
| Name identifier management | The identity provider and the service provider change or end a `NameID` over HTTP-Redirect through the `_redirect` operations, and the identity provider also over SOAP through `start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`. Each binding turns on with a `ManageNameIDService`. The service provider has no SOAP name identifier management |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through bergshamra. The Conformance §4 algorithms, with SHA-1, Triple DES, and RSA-v1.5 used only when selected |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

## Supported SOAP exchanges

- Artifact resolution
- Single Logout at both the identity provider and the service provider
- Name identifier management at the identity provider
- Enhanced Client/Proxy SSO at the identity provider (the service provider uses PAOS)

## Unsupported profiles

- HTTP-Artifact delivery of an `<AuthnRequest>` or a logout message
- SOAP name identifier management at the service provider
- SAML query protocols
- Name identifier mapping
- Other SOAP profiles
- Metadata federation
- The enhanced-client role in Enhanced Client/Proxy SSO

The crate does not claim the [IdP or SP operational mode](conformance/idp-sp-operational-modes.md).

A request for one of the remaining profiles needs the profile, the binding, the peer product, and a minimal expected flow on [an issue](https://github.com/salasebas/saml-rs/issues).

Claimed rules for the flows that do exist are the [conformance records](conformance.md). Method signatures are on [docs.rs](https://docs.rs/saml-rs).
