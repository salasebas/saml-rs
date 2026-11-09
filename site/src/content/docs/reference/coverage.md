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
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` on the same three bindings |
| Identity Provider Discovery | `remember_identity_provider` returns the `_saml_idp` cookie for the caller to write. Service providers do not set or read it |
| Identifiers | Every attribute name format on `RespondSso::attributes` and on an accepted `Attribute`. `NameId::generate_transient`, `NameId::generate_persistent`, and `NameId::persistent` for the identifiers an identity provider issues |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` through `resolve_artifact` and `answer_artifact_resolve`. The deployment sends the HTTP request |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through bergshamra |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

HTTP-Artifact browser delivery, SOAP profiles other than artifact resolution and the identity-provider leg of Enhanced Client/Proxy SSO, the enhanced-client role, SAML query protocols, NameID management, and metadata federation are outside the typed `Saml` API. Artifact resolution over SOAP does not claim the IdP or SP operational mode.

A request for one of the remaining profiles needs the profile, the binding, the peer product, and a minimal expected flow on [an issue](https://github.com/salasebas/saml-rs/issues).

Claimed rules for the flows that do exist are the [conformance records](conformance.md). Method signatures are on [docs.rs](https://docs.rs/saml-rs).
