# Conformance

The records cover specific exchanges and APIs. Each row gives the rule, level, source section, and controlling option. A library policy also gives its reason.

Use [validation defaults](https://samlrs.vercel.app/explanation/validation-presets/) to find the role settings selected by `SpValidationPolicy::default()` and `IdpValidationPolicy::default()`. Each claim applies to the role, flow, and binding in its record.

See [Standards conformance](https://github.com/salasebas/saml-rs/blob/main/docs/standards-conformance.md#find-the-rule) for the normative sources and how to apply them. The [SOAP envelope rules](artifact-resolution.md#soap-envelope-rules) cover all supported SOAP exchanges.

| Record | Public entry points and scope |
| --- | --- |
| [SSO generation](web-browser-sso-generation.md) | `start_sso`, `respond_sso`, `initiate_sso` |
| [SSO acceptance](web-browser-sso-acceptance.md) | `receive_sso`, `finish_sso`, `accept_unsolicited_sso`, `accept_unsolicited_sso_with_resolver` |
| [HTTP-Artifact response](web-browser-sso-artifact.md) | `respond_sso_artifact`, `initiate_sso_artifact`, `finish_sso` with `Inbound::artifact` |
| [Artifact resolution over SOAP](artifact-resolution.md) | `issue_artifact`, `resolve_artifact`, `resolve_artifact_with_signed_request`, `answer_artifact_resolve` |
| [Single Logout](single-logout.md) | `start_slo`, `receive_slo`, `respond_slo`, `finish_slo`. See [asynchronous logout](single-logout.md#asynchronous-single-logout) for `start_async_slo` and `receive_slo_with_async`, and [SOAP](single-logout.md#soap-binding) for back-channel logout. |
| [Name identifier management](name-id-management.md) | `start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`, including their Redirect variants and `finish_name_id_management_redirect` |
| [Browser bindings](browser-bindings.md) | `Outbound`, `Inbound::redirect`, `Inbound::post`, `Inbound::simple_sign`, `DeliveredArtifact`, `RelayState`, and `Artifact` encoding, shared by every browser flow |
| [Identity Provider Discovery](identity-provider-discovery.md) | `common_domain_cookie` and unsupported discovery exchanges |
| [Identifiers](identifiers.md) | `NameId`, `AttributeNameFormat`, subject identifier attributes, and generated IDs |
| [Metadata and replay](metadata-and-replay.md) | Peer descriptor and aggregate imports, `MetadataTrustPolicy`, and `ReplayPolicy` |
| [XML security algorithms](xml-security-algorithms.md) | `AlgorithmPolicy`, `XmlSignatureProfile`, and signature coverage |
| [XML schema validation](xml-schema-validation.md) | `SchemaValidator` on typed flows and explicit metadata imports |
| [XML input limits and encoding](xml-input.md) | `XmlLimits`, the XML declaration, and the character encoding of received XML |
| [Common message fields](common-message-fields.md) | `Consent`, `StatusDetail`, status code depth, and `Extensions` on every typed message |
| [IdP and SP operational modes](idp-sp-operational-modes.md) | Supported exchanges, excluded modes, and application duties |
