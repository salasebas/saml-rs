# Conformance

The records cover specific exchanges and APIs. Each row gives the rule, level, source section, and controlling option. A library policy also gives its reason.

Use [validation defaults](https://samlrs.vercel.app/explanation/validation-presets/) to find the role settings selected by `SpValidationPolicy::default()` and `IdpValidationPolicy::default()`. Each claim applies to the role, flow, and binding in its record.

See [Standards conformance](https://github.com/salasebas/saml-rs/blob/main/docs/standards-conformance.md#find-the-rule) for the normative sources and how to apply them. The [SOAP envelope rules](artifact-resolution.md#soap-envelope-rules) cover all supported SOAP exchanges.

| Record | Public entry points and scope |
| --- | --- |
| [SSO generation](web-browser-sso-generation.md) | `ServiceProvider::start_sso`. `IdentityProvider::respond_sso`, `respond_sso_refusal`, and `initiate_sso` |
| [SSO acceptance](web-browser-sso-acceptance.md) | `IdentityProvider::receive_sso`. `ServiceProvider::finish_sso`, `finish_sso_with_outstanding_logout`, `accept_unsolicited_sso`, and `accept_unsolicited_sso_with_outstanding_logout` with `Inbound::post` or `Inbound::simple_sign`, and `accept_unsolicited_sso_with_resolver` with `Inbound::post` |
| [HTTP-Artifact response](web-browser-sso-artifact.md) | `IdentityProvider::respond_sso_artifact`, `respond_sso_refusal_artifact`, and `initiate_sso_artifact`. `ServiceProvider::finish_sso`, `finish_sso_with_outstanding_logout`, `accept_unsolicited_sso`, and `accept_unsolicited_sso_with_outstanding_logout` with `Inbound::artifact` |
| [Artifact resolution over SOAP](artifact-resolution.md) | `IdentityProvider::issue_artifact` and `answer_artifact_resolve`. `ServiceProvider::resolve_artifact`, `resolve_artifact_with_signed_request`, and `ArtifactResolution::finish` |
| [Single Logout](single-logout.md) | `start_slo`, `receive_slo`, `respond_slo`, `respond_slo_refusal`, and `finish_slo` on both roles, over HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and [SOAP](single-logout.md#soap-binding). `ServiceProvider::start_async_slo` and `IdentityProvider::receive_slo_with_async` for [asynchronous logout](single-logout.md#asynchronous-single-logout) over HTTP-Redirect and HTTP-POST |
| [Name identifier management](name-id-management.md) | `IdentityProvider::start_name_id_management`, `receive_name_id_management`, and `respond_name_id_management`, and `StartedNameIdManagement::finish`, over SOAP. `start_name_id_management_redirect`, `receive_name_id_management_redirect`, `respond_name_id_management_redirect`, and `finish_name_id_management_redirect` on both roles |
| [Browser bindings](browser-bindings.md) | `Outbound`, `Inbound::redirect`, `Inbound::post`, `Inbound::simple_sign`, `DeliveredArtifact`, `RelayState`, and `Artifact` encoding, shared by every browser flow |
| [Identity Provider Discovery](identity-provider-discovery.md) | `IdentityProvider::common_domain_cookie` and unsupported discovery exchanges |
| [Identifiers](identifiers.md) | `NameId`, `AttributeNameFormat`, subject identifier attributes, and generated IDs |
| [Metadata and replay](metadata-and-replay.md) | Peer descriptor and aggregate imports, `MetadataTrustPolicy`, and `ReplayPolicy` |
| [XML security algorithms](xml-security-algorithms.md) | `AlgorithmPolicy`, `XmlSignatureProfile`, and signature coverage |
| [XML schema validation](xml-schema-validation.md) | `SchemaValidator` on typed flows and explicit metadata imports |
| [XML input limits and encoding](xml-input.md) | `XmlLimits`, the XML declaration, and the character encoding of received XML |
| [Common message fields](common-message-fields.md) | `Consent`, `StatusDetail`, status code depth, and `Extensions` on every typed message |
| [IdP and SP operational modes](idp-sp-operational-modes.md) | Each Conformance operational mode, the Table 2 feature matrix with a status for each role, what blocks each mode, and the exchanges not implemented |
