---
title: "Conformance"
description: "Each record covers one flow. A row names the rule, its level (mandatory, recommended, optional, or library policy), the section that states it, and the option that controls it."
---

Each record covers one flow. Its headings name the actor and the APIs. A row names the rule, its level (mandatory, recommended, optional, or library policy), the section that states it, and the option that controls it. A library-policy row also gives its reason.

The default validation policies select the settings recorded for each flow. Each conformance claim covers the role, flow, and binding in its record. A producer requirement does not, by itself, become a receiver rejection. Optional capabilities stay off until you select them by name.

Normative text is SAML Core 2.0, Profiles 2.0, Bindings 2.0, and Metadata 2.0, as corrected by Approved Errata 05.

OASIS approved HTTP-POST-SimpleSign as [Committee Specification 01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.html). The crate's records cite the later [Committee Draft 04](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html) for the signature input. Both texts sign the raw XML when a signature is used. CD-04 §2.5 explicitly omits the entire `RelayState` field when it is absent. The binding makes the detached signature optional. For the crate's stricter Web SSO policy, see [SSO generation](conformance/web-browser-sso-generation.md) and [SSO acceptance](conformance/web-browser-sso-acceptance.md).

- [IdP and SP operational modes](conformance/idp-sp-operational-modes.md) maps the Table 2 requirements to individual exchanges and lists the additional modes in Tables 3 and 4.
- [SSO acceptance](conformance/web-browser-sso-acceptance.md) for `finish_sso`, `accept_unsolicited_sso`, and `receive_sso`.
- [SSO generation](conformance/web-browser-sso-generation.md) for `start_sso`, `respond_sso`, and `initiate_sso`.
- [Logout](conformance/single-logout.md) for `start_slo`, `start_async_slo`, `respond_slo`, `receive_slo`, `receive_slo_with_async`, and `finish_slo`.
- [Identity Provider Discovery](conformance/identity-provider-discovery.md) for `common_domain_cookie`.
- [SAML-defined identifiers](conformance/identifiers.md) for `SsoAssertion::attributes`, `AttributeNameFormat`, the persistent and transient `NameId` constructors, the `subject-id` and `pairwise-id` attributes, and the `ID` of every generated message and assertion.
- [Metadata and replay](conformance/metadata-and-replay.md) for `MetadataTrustPolicy` and `ReplayPolicy`.
- [HTTP-Artifact response](conformance/web-browser-sso-artifact.md) for `respond_sso_artifact`, `initiate_sso_artifact`, and `finish_sso` with `Inbound::artifact`.
- [Artifact resolution](conformance/artifact-resolution.md) for `issue_artifact`, `resolve_artifact`, `resolve_artifact_with_signed_request`, and `answer_artifact_resolve`.
- [XML Signature and XML Encryption algorithms](conformance/xml-security-algorithms.md) for `AlgorithmPolicy`, `SignatureAlgorithm`, `TransformAlgorithm`, `DataEncryptionAlgorithm`, and `KeyEncryptionAlgorithm`, and for reference preflight and signed-content coverage in public verification and embedded-signature flows.
- [XML schema validation](conformance/xml-schema-validation.md) for the optional callback on each role and explicit metadata imports.
- [Name identifier management](conformance/name-id-management.md) for `start_name_id_management`, `receive_name_id_management`, `respond_name_id_management`, and their `_redirect` counterparts with `finish_name_id_management_redirect`.

Why Recommended is the only preset is in [Validation presets](../explanation/validation-presets.md).
