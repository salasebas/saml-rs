# Module map

This map lists the behaviour whose file name does not give it away.

| Behaviour | File |
| --- | --- |
| Shared processing of a received browser message: decode, verify, extract, and validate | `src/flow.rs` |
| Detached HTTP-Redirect and SimpleSign signature checks | `src/flow/detached.rs` |
| Embedded XML signature checks, and the order in which encrypted assertions are decrypted and verified | `src/flow/embedded.rs` |
| Checks on a login `Response` with an error status, before its status is reported | `src/flow/error_response.rs` |
| `Issuer` of a login `Response` | `src/flow/response_issuer.rs` |
| Assertion conditions, audience, and bearer confirmation of an accepted response | `src/assertion_acceptance.rs` |
| SP processing of each encrypted assertion, subject identifier, and attribute in a login response | `src/flow.rs`, `src/flow/embedded.rs`, `src/encrypted_elements.rs` |
| SP or IdP decryption of the principal identifier in an authenticated logout request | `src/logout/encrypted_id.rs` |
| Protocol responses that take the wrapping and coverage checks | `src/crypto/response_root.rs` |
| Algorithms and RSA key sizes each `XmlSignatureProfile` accepts | `src/crypto/signature_profile.rs` |
| Response rendering for HTTP-Artifact | `src/idp/posted_response.rs` |
| IdP choice of assertion consumer by URL, index, binding, or default | `src/api/response_acs.rs`, `src/metadata/sp.rs` |
| A binding parameter that may occur once | `src/binding/parameters.rs` |
| Protocol elements read with their namespaces, and their `Status` | `src/xml/protocol_element.rs` |
| Status extraction from a SOAP response body | `src/soap.rs`, `src/xml/status.rs` |
| Selection of SAML 2.0 roles in peer metadata | `src/metadata/role.rs` |
| Signature trust for imported metadata and selection of an entity in a signed aggregate | `src/config/metadata_trust.rs`, `src/config/descriptors/aggregate.rs` |
| Effective metadata expiry from group, entity, and role bounds | `src/metadata/role.rs`, `src/metadata/validity.rs` |
| Receiving endpoint, replay retention, and request age in the validation context | `src/model/validation.rs` |
| Typed config to the internal `EntitySetting` | `src/config/entity_setting.rs` |
| Typed config to the metadata generator input and the internal provider | `src/config/provider.rs` |
| `EncryptedID` in the requested `Subject` of a received `AuthnRequest` | `src/api/requested_subject.rs` |

For new behaviour in a large module, prefer a focused file. Examples include
`src/api/slo.rs`, `src/soap.rs`, `src/xml/dom.rs`, `src/idp.rs`,
`src/metadata/mod.rs`, and `src/xml/profile.rs`.

The compatibility crates `opensaml`, `samlify`, and `samlet` are in
`crates/<name>` and re-export `saml-rs`.
