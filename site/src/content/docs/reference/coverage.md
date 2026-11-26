---
title: "Coverage"
description: "`ServiceProvider` and `IdentityProvider` implement this surface."
---

`ServiceProvider` and `IdentityProvider` implement this surface.

| Area | Support |
| --- | --- |
| Web SSO | The service provider can send a signed `AuthnRequest` over HTTP-POST, HTTP-Redirect, or HTTP-POST-SimpleSign. The identity provider can send a signed `Response` over HTTP-POST, HTTP-POST-SimpleSign, or HTTP-Artifact |
| Metadata | Parse peer metadata, generate SP and IdP descriptors, verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` over HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, or SOAP for the identity provider and service provider. The deployment sends the SOAP HTTP request |
| Identity Provider Discovery | `common_domain_cookie` returns the `_saml_idp` cookie for the caller to write. Service providers do not set or read it |
| Identifiers | Every attribute name format on `SsoAssertion::attributes` and on an accepted `Attribute`. `NameId::generate_transient`, `NameId::generate_persistent`, and `NameId::persistent` for the identifiers an identity provider issues. `SubjectId` and `PairwiseId` for the `subject-id` and `pairwise-id` attributes. The library writes the `ID` of every generated message and assertion |
| HTTP-Artifact response | The identity provider delivers a Web SSO `Response` through `respond_sso_artifact`. After `resolve_artifact`, `finish_sso` requires an XML signature on the response or each assertion to establish a session. See the [HTTP-Artifact acceptance rules](conformance/web-browser-sso-artifact.md#service-provider-receipt) |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` through `resolve_artifact` and `answer_artifact_resolve`. The deployment sends the HTTP request |
| Name identifier management | The identity provider and the service provider change or end a `NameID` over HTTP-Redirect through the `_redirect` operations, and the identity provider also over SOAP through `start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`. Each binding turns on with a `ManageNameIDService`. The service provider has no SOAP name identifier management |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through bergshamra. On RustCrypto with `crypto-legacy-algorithms`, which the default build enables, the Conformance §4 algorithms and the SHA-1 `SigAlg` methods of HTTP-Redirect and HTTP-POST-SimpleSign, with SHA-1, Triple DES, and RSA-v1.5 used only when selected. The other builds lack some of them, as [signature algorithms by build](conformance/xml-security-algorithms.md#signature-algorithms-by-build) and [encryption algorithms by provider](conformance/xml-security-algorithms.md#encryption-algorithms-by-provider) show |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

## Supported SOAP exchanges

- Artifact resolution
- Single Logout at both the identity provider and the service provider
- Name identifier management at the identity provider

## Unsupported profiles

- HTTP-Artifact delivery of an `<AuthnRequest>` or a logout message
- SOAP name identifier management at the service provider
- SAML query protocols
- Name identifier mapping
- Other SOAP profiles
- Metadata federation
- Enhanced Client/Proxy SSO and its PAOS binding

The crate does not claim the [IdP or SP operational mode](conformance/idp-sp-operational-modes.md). That record lists each [exchange that is not implemented](conformance/idp-sp-operational-modes.md#exchanges-not-implemented).

A request for one of the remaining profiles needs the profile, the binding, the peer product, and a minimal expected flow on [an issue](https://github.com/salasebas/saml-rs/issues).

The [conformance records](conformance.md) list the rules for each supported flow. Run `cargo doc -p saml-rs --open` from the repository root to read the API reference for `main`.
