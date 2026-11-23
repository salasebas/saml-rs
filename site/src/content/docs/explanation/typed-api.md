---
title: "Typed API"
description: "Browser flows start from `ServiceProvider` and `IdentityProvider`. The local role is the configuration you build. The peer is a descriptor you import from metadata. A binding that SAML Web..."
---

Browser flows start from `ServiceProvider` and `IdentityProvider`. The local role is the configuration you build. The peer is a descriptor you import from metadata. A binding that SAML Web SSO does not allow cannot be represented on the typed builders.

Request correlation, `RelayState`, the clock, replay, and metadata trust show up in the function arguments. There is no hidden cache and no implied metadata signer. XML-DSig, canonicalisation, and XML-Enc stay in bergshamra. This crate does not implement them.

SOAP artifact resolution is in the typed API through `issue_artifact`, `resolve_artifact`, and `answer_artifact_resolve`. The deployment sends the HTTP request. A Web SSO response delivered as an HTTP-Artifact is in the typed API through `respond_sso_artifact`, and `finish_sso` accepts it after `resolve_artifact`. The identity provider and the service provider change or end a name identifier over HTTP-Redirect through the `_redirect` operations, and the identity provider also over SOAP through `start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`.

The [coverage table](../reference/coverage.md) lists the supported exchanges by role and binding. Claimed rules are in [HTTP-Artifact response](../reference/conformance/web-browser-sso-artifact.md), [Artifact resolution](../reference/conformance/artifact-resolution.md), and [Name identifier management](../reference/conformance/name-id-management.md).

The service-provider round trip is [Service provider](../guides/service-provider-sso.md). The guides on this site are the current calls.
