# Module map

Where a SAML behaviour is implemented. Conformance rows for the same public
methods are in [`docs/conformance/`](conformance/). The typed-API design record
is in [`docs/architecture/`](architecture/README.md).

## Typed browser SSO

| Behaviour | File |
| --- | --- |
| SP `start_sso`, `finish_sso`, `accept_unsolicited_sso` | `src/api/sp.rs` |
| IdP `receive_sso`, `respond_sso`, `initiate_sso` | `src/api/idp.rs` |
| Assertion conditions on an accepted response | `src/assertion_acceptance.rs` |
| Typed `start_slo`, `receive_slo`, `respond_slo`, `finish_slo` | `src/api/slo.rs` |
| IdP `issue_artifact`, `answer_artifact_resolve`; SP `resolve_artifact` | `src/api/artifact.rs`, `src/artifact.rs` |
| IdP `respond_sso_artifact`, `initiate_sso_artifact` | `src/api/artifact.rs`, `src/api/idp.rs` |
| `ArtifactDelivery`, `DeliveredArtifact` | `src/browser/artifact.rs` |
| Raw response rendering for an artifact | `src/idp/artifact.rs` |
| SOAP 1.1 envelope, `SoapRequest`, `SoapResponse` | `src/soap.rs` |
| Single Logout over SOAP: `StartSlo::soap`, `BrowserInput::soap`, `Outbound::soap_request` and `soap_response` | `src/api/slo.rs`, `src/browser/input.rs`, `src/browser/outbound.rs` |

`finish_sso_with_outstanding_logout` and
`accept_unsolicited_sso_with_outstanding_logout` are in `src/api/sp.rs`.
`finish_sso` and `accept_unsolicited_sso` take a resolved artifact through
`BrowserInput::artifact`.

## Enhanced Client/Proxy SSO

| Behaviour | File |
| --- | --- |
| SP `start_paos_sso`, `finish_paos_sso`, `finish_paos_sso_with_outstanding_logout` | `src/api/paos/mod.rs` |
| IdP `receive_paos_sso`, `respond_paos_sso`, `reject_paos_sso`, `paos_soap_fault` | `src/api/paos/mod.rs` |
| PAOS header and SOAP envelopes | `src/api/paos/protocol.rs` |
| Raw PAOS AuthnRequest rendering | `src/sp/paos.rs` |
| Raw PAOS response rendering | `src/idp/paos.rs` |

The enhanced-client role is not a facade. The IdP and SP operational modes
stay unclaimed.

## Name identifier management

| Behaviour | File |
| --- | --- |
| IdP `start_name_id_management`, `receive_name_id_management`, `respond_name_id_management` | `src/api/name_id_management.rs` |
| `start_name_id_management_redirect`, `receive_name_id_management_redirect`, `respond_name_id_management_redirect`, `finish_name_id_management_redirect` on both roles | `src/api/name_id_management/redirect.rs` |
| `ManageNameIdRequest`, `NameIdChange`, and SOAP messages | `src/name_id_management.rs` |
| Request and response XML for both bindings, including the E14 transient rule | `src/name_id_management/xml.rs` |
| HTTP-Redirect signing and parsing | `src/name_id_management/redirect.rs` |
| `PendingManageNameIdRequest` | `src/browser/pending.rs` |
| `ManageNameIDService` in metadata | `src/metadata/mod.rs`, `src/metadata/generate.rs` |
| Protocol elements read with their namespaces | `src/xml/protocol_element.rs` |

The service provider has no SOAP name identifier management. Name identifier
mapping is not implemented.

## Identity Provider Discovery

| Behaviour | File |
| --- | --- |
| IdP `remember_identity_provider` | `src/api/idp.rs`, `src/discovery.rs` |

## SAML-defined identifiers

| Behaviour | File |
| --- | --- |
| `AttributeNameFormat`, `Attribute` | `src/model/attributes.rs` |
| Persistent and transient `NameId` constructors | `src/model/subject.rs` |
| `RespondSso::attributes` and the `AttributeStatement` it writes | `src/api/options.rs`, `src/idp/login_response.rs` |
| `NameFormat` of an accepted attribute | `src/xml/fields.rs`, `src/model/extract.rs` |
| `xs:Name` and `xs:NCName` | `src/xml/name.rs` |

## Raw login

| Behaviour | File |
| --- | --- |
| Raw service provider | `src/sp.rs` |
| Raw identity provider | `src/idp.rs` |
| Login response construction | `src/idp/login_response.rs` |
| Shared raw flow | `src/flow.rs` |

## Validation and cryptography

| Behaviour | File |
| --- | --- |
| XML signature verification | `src/crypto/verify.rs` |
| Protocol response roots that take the wrapping and coverage checks | `src/crypto/response_root.rs` |
| XML signature generation | `src/crypto/sign.rs` |
| Algorithm variants and `AlgorithmPolicy` | `src/config/algorithms.rs`, `src/config/policies.rs` |
| `EncryptedAssertion`, `EncryptedID`, and `EncryptedAttribute` | `src/crypto/enc.rs` |
| Decryption of a verified response's encrypted children | `src/flow.rs` |
| Clock, replay context, and message age | `src/model/validation.rs` |
| Validation presets and named policies | `src/config/policies.rs` |
| Peer descriptors | `src/config/descriptors.rs` |

## Logout

| Behaviour | File |
| --- | --- |
| Logout request and response construction | `src/logout/creation.rs` |
| Parsing | `src/logout/parsing.rs` |
| Rendering | `src/logout/rendering.rs` |
| Signing | `src/logout/signing.rs` |
| `EncryptedID` in place of the `LogoutRequest` `NameID` | `src/logout/encrypted_id.rs`, `src/crypto/enc.rs` |

Logout is the directory `src/logout/`.

## Conformance rows

| Flow | Page |
| --- | --- |
| Inbound Web Browser SSO | [`web-browser-sso-acceptance.md`](conformance/web-browser-sso-acceptance.md) |
| Outbound Web Browser SSO | [`web-browser-sso-generation.md`](conformance/web-browser-sso-generation.md) |
| Single Logout | [`single-logout.md`](conformance/single-logout.md) |
| Enhanced Client/Proxy SSO over PAOS | [`enhanced-client-proxy.md`](conformance/enhanced-client-proxy.md) |
| Identity Provider Discovery | [`identity-provider-discovery.md`](conformance/identity-provider-discovery.md) |
| SAML-defined identifiers | [`identifiers.md`](conformance/identifiers.md) |
| Web Browser SSO response over HTTP-Artifact | [`web-browser-sso-artifact.md`](conformance/web-browser-sso-artifact.md) |
| Artifact resolution over SOAP | [`artifact-resolution.md`](conformance/artifact-resolution.md) |
| Name identifier management | [`name-id-management.md`](conformance/name-id-management.md) |
| Metadata trust and replay | [`metadata-and-replay.md`](conformance/metadata-and-replay.md) |
| XML Signature and XML Encryption algorithms | [`xml-security-algorithms.md`](conformance/xml-security-algorithms.md) |

## Compatibility crates

| Crate | Path |
| --- | --- |
| `opensaml`, `samlify`, `samlet` | `crates/<name>` |

Workspace members are in the root `Cargo.toml`. Publish configuration is in
`release-plz.toml` and `.github/workflows/ci.yml`.

## Large modules

- `src/flow.rs`
- `src/idp.rs`
- `src/sp.rs`
- `src/crypto/verify.rs`
- `src/logout/creation.rs`
