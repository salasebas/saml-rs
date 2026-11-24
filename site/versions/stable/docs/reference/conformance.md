---
title: "Conformance"
description: "Each record is a table for one flow. A row names the rule, the obligated actor, the direction, and the level: mandatory, recommendation, optional, or library policy."
---

Each record is a table for one flow. A row names the rule, the obligated actor, the direction, and the level: mandatory, recommendation, optional, or library policy.

`recommended()` publishes the combination recorded for that flow. It is not an implementation of SAML V2.0 as a whole. A producer requirement does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them by name.

Normative text is SAML Core 2.0, Profiles 2.0, Bindings 2.0, and Metadata 2.0, as corrected by Approved Errata 05.

OASIS approved HTTP-POST-SimpleSign as [Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html). The records cite the later [Committee Draft 04](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html), whose §2.5 clarifies that absent `RelayState` is omitted from the signature input.

- [IdP and SP operational modes](conformance/idp-sp-operational-modes.md) maps the four IdP and SP columns of Table 2 to the exchanges supported in this release.
- [Extended, authority, and requester modes](conformance/extended-and-authority-modes.md) for every Table 3 and Table 4 cell and the attribute profiles, none of them claimed.
- [SSO acceptance](conformance/web-browser-sso-acceptance.md) for `finish_sso`, `accept_unsolicited_sso`, and `receive_sso`.
- [SSO generation](conformance/web-browser-sso-generation.md) for `start_sso`, `respond_sso`, and `initiate_sso`.
- [Enhanced Client/Proxy](conformance/enhanced-client-proxy.md) for `start_paos_sso`, `finish_paos_sso`, `receive_paos_sso`, and `respond_paos_sso`.
- [Logout](conformance/single-logout.md) for `start_slo`, `respond_slo`, `receive_slo`, and `finish_slo`.
- [Identity Provider Discovery](conformance/identity-provider-discovery.md) for `remember_identity_provider`.
- [SAML-defined identifiers](conformance/identifiers.md) for `RespondSso::attributes`, `AttributeNameFormat`, the persistent and transient `NameId` constructors, and `entity::generate_id`.
- [Metadata and replay](conformance/metadata-and-replay.md) for `MetadataTrustPolicy` and `ReplayPolicy`.
- [HTTP-Artifact response](conformance/web-browser-sso-artifact.md) for `respond_sso_artifact`, `initiate_sso_artifact`, and `finish_sso` with `BrowserInput::artifact`.
- [Artifact resolution](conformance/artifact-resolution.md) for `issue_artifact`, `resolve_artifact`, and `answer_artifact_resolve`.
- [XML signature processing](conformance/xml-signature-processing.md) for reference preflight and signed-content coverage in public verification and embedded-signature flows.
- [XML Signature and XML Encryption algorithms](conformance/xml-security-algorithms.md) for `AlgorithmPolicy`, `SignatureAlgorithm`, `TransformAlgorithm`, `DataEncryptionAlgorithm`, and `KeyEncryptionAlgorithm`.
- [Name identifier management](conformance/name-id-management.md) for `start_name_id_management`, `receive_name_id_management`, `respond_name_id_management`, and their `_redirect` counterparts with `finish_name_id_management_redirect`.

Why Compatibility and Recommended are separate is in [Validation presets](../explanation/validation-presets.md).
