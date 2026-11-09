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
| SOAP 1.1 envelope | `src/soap.rs` |

`finish_sso_with_outstanding_logout` and
`accept_unsolicited_sso_with_outstanding_logout` are in `src/api/sp.rs`.

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
| XML signature generation | `src/crypto/sign.rs` |
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
| Artifact resolution over SOAP | [`artifact-resolution.md`](conformance/artifact-resolution.md) |
| Metadata trust and replay | [`metadata-and-replay.md`](conformance/metadata-and-replay.md) |

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
