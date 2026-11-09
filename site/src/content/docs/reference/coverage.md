---
title: "Coverage"
description: "`Saml<Sp>` and `Saml<Idp>` implement this surface."
---

`Saml<Sp>` and `Saml<Idp>` implement this surface.

| Area | Support |
| --- | --- |
| Web SSO | Signed `AuthnRequest` and `Response` over HTTP-POST, HTTP-Redirect, and HTTP-POST-SimpleSign |
| Enhanced Client/Proxy SSO | Service-provider and identity-provider ends over PAOS. The enhanced client is not a facade |
| Metadata | Parse peer metadata, generate SP and IdP descriptors, verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` on the same three bindings, and over SOAP for the identity provider and service provider. The deployment sends the SOAP HTTP request |
| Identity Provider Discovery | `remember_identity_provider` returns the `_saml_idp` cookie for the caller to write. Service providers do not set or read it |
| Identifiers | Every attribute name format on `RespondSso::attributes` and on an accepted `Attribute`. `NameId::generate_transient`, `NameId::generate_persistent`, and `NameId::persistent` for the identifiers an identity provider issues |
| HTTP-Artifact response | A Web SSO `Response` delivered as an artifact through `respond_sso_artifact`, and accepted by `finish_sso` after `resolve_artifact`. `AuthnRequest` and logout messages are not delivered this way |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` through `resolve_artifact` and `answer_artifact_resolve`. The deployment sends the HTTP request |
| Name identifier management | The identity provider changes or ends a `NameID` over SOAP through `start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`. It turns on with a `ManageNameIDService`. The service provider has no name identifier management |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through bergshamra. The Conformance §4 algorithms, with SHA-1, Triple DES, and RSA-v1.5 used only when selected |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

HTTP-Artifact delivery of an `AuthnRequest` or a logout message, SOAP profiles other than artifact resolution, Single Logout, name identifier management at the identity provider, and the identity-provider leg of Enhanced Client/Proxy SSO, the enhanced-client role, SAML query protocols, name identifier management over HTTP-Redirect or at the service provider, name identifier mapping, and metadata federation are outside the typed `Saml` API. The HTTP-Artifact response, artifact resolution, Single Logout, and name identifier management over SOAP do not claim the IdP or SP operational mode.

A request for one of the remaining profiles needs the profile, the binding, the peer product, and a minimal expected flow on [an issue](https://github.com/salasebas/saml-rs/issues).

Claimed rules for the flows that do exist are the [conformance records](conformance.md). Method signatures are on [docs.rs](https://docs.rs/saml-rs).
