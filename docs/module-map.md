# Module map

This map lists the behaviour whose file name does not give it away.

| Behaviour | File |
| --- | --- |
| Shared processing of a received browser message: decode, verify, extract, and validate | `src/flow.rs` |
| Detached HTTP-Redirect and SimpleSign signature checks | `src/flow/detached.rs` |
| Checks on a login `Response` with an error status, before its status is reported | `src/flow/error_response.rs` |
| `Issuer` of a login `Response` | `src/flow/response_issuer.rs` |
| Assertion conditions, audience, and bearer confirmation of an accepted response | `src/assertion_acceptance.rs` |
| Decryption of a verified response's encrypted children | `src/flow.rs`, `src/encrypted_elements.rs` |
| Protocol responses that take the wrapping and coverage checks | `src/crypto/response_root.rs` |
| Algorithms and RSA key sizes each `XmlSignatureProfile` accepts | `src/crypto/signature_profile.rs` |
| Response rendering for HTTP-Artifact and PAOS | `src/idp/posted_response.rs` |
| A binding parameter that may occur once | `src/binding/parameters.rs` |
| Protocol elements read with their namespaces, and their `Status` | `src/xml/protocol_element.rs` |
| Typed config to raw `EntitySetting` | `src/config/entity_setting.rs` |
| Typed config to the metadata generator input and the internal provider | `src/config/provider.rs` |
| `EncryptedID` in the requested `Subject` of a received `AuthnRequest` | `src/api/requested_subject.rs` |

`src/idp.rs`, `src/flow.rs`, `src/crypto/verify.rs`, and `src/sp.rs` are the
largest files. Put a new behaviour in a focused module instead of growing them.

The compatibility crates `opensaml`, `samlify`, and `samlet` are in
`crates/<name>` and re-export `saml-rs`.
