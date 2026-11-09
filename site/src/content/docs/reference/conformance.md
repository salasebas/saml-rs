---
title: "Conformance"
description: "Each record is a table for one flow. A row names the rule, the obligated actor, the direction, and the level: mandatory, recommendation, optional, or library policy."
---

Each record is a table for one flow. A row names the rule, the obligated actor, the direction, and the level: mandatory, recommendation, optional, or library policy.

`recommended()` publishes the combination recorded for that flow. It is not an implementation of SAML V2.0 as a whole. A producer requirement does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them by name.

Normative text is SAML Core 2.0, Profiles 2.0, Bindings 2.0, and Metadata 2.0, as corrected by Approved Errata 05. HTTP-POST-SimpleSign is the supported CD04 binding.

- [SSO acceptance](conformance/web-browser-sso-acceptance.md) for `finish_sso`, `accept_unsolicited_sso`, and `receive_sso`.
- [SSO generation](conformance/web-browser-sso-generation.md) for `start_sso`, `respond_sso`, and `initiate_sso`.
- [Enhanced Client/Proxy](conformance/enhanced-client-proxy.md) for `start_paos_sso`, `finish_paos_sso`, `receive_paos_sso`, and `respond_paos_sso`.
- [Logout](conformance/single-logout.md) for `start_slo`, `respond_slo`, `receive_slo`, and `finish_slo`.
- [Identity Provider Discovery](conformance/identity-provider-discovery.md) for `remember_identity_provider`.
- [SAML-defined identifiers](conformance/identifiers.md) for `RespondSso::attributes`, `AttributeNameFormat`, and the persistent and transient `NameId` constructors.
- [Metadata and replay](conformance/metadata-and-replay.md) for `MetadataTrustPolicy` and `ReplayPolicy`.
- [Artifact resolution](conformance/artifact-resolution.md) for `issue_artifact`, `resolve_artifact`, and `answer_artifact_resolve`.

Why Compatibility and Recommended are separate is in [Validation presets](../explanation/validation-presets.md).
