# XML signature processing

This page covers inbound embedded-signature processing in the public XML
verification functions and the internal verifier used by typed and raw flows.
It does not claim conformance with an entire SAML profile or binding.

| Rule | Actor and condition | Scope and basis |
| --- | --- | --- |
| References in every processed signature stay within the input document | Library verifier, before resolving references or executing transforms, including optional signatures outside SAML candidate positions | Library policy. Core §5.4.2 requires a SAML signer to reference the ID of the signed assertion or protocol message. It does not require a receiver to reject every extension signature with other references. Rejecting such references before processing prevents local-file resolution by the dependency |
| Strict-profile reference transforms are checked before processing | Library verifier using `StrictRsaSha2`, for every processed signature, including invalid and unrelated signatures | Library policy beyond Core §5.4.4's permission to reject other transforms. Other profiles keep their existing transform handling. The strict profile allows only XML-DSig enveloped-signature and exclusive canonicalization transforms |
| Public verification success includes covered content | Library verifier, after cryptographic verification | Library API contract. Assertion-bearing protocol responses retain their existing direct-Assertion coverage and extraction rules. Other documents require root coverage. A signature over a different sibling object is insufficient |

The [protocol schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd)
places optional `ds:Signature` and `samlp:Extensions` children on
`RequestAbstractType` and `StatusResponseType`. `ExtensionsType` permits
foreign-namespace elements with lax processing. Signature placement alone
therefore does not describe every XML-DSig signature the dependency processes.

[Core §§5.4.2–5.4.4](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
distinguish the signed assertion or protocol message from its XML container.
For SAML signature verifiers, §5.4.4 requires preservation of message content
when other transforms are accepted. The preflight restrictions above are
implementation controls, not a new receiver `MUST` inferred from signer rules.
[Approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/saml-v2.0-errata05-os.html)
E91's Object recommendation remains enforced by the existing profiles after
verification. E93's correction to Profiles §4.1.3.5 permits a signed Assertion
or Response for HTTP-POST browser SSO. This change preserves that choice.

The pinned `bergshamra-dsig` 0.12.0
[`DsigContext`](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-dsig/src/context.rs)
has no option to disable relative-file references. Its
[`verify` source](https://github.com/kushaldas/bergshamra/blob/9fcc0c1e1cc0145fb0b8cf417aaa694a635f212c/crates/bergshamra-dsig/src/verify.rs)
resolves references and executes transforms before verifying `SignatureValue`.
The first-signature function processes the first XML-DSig descendant in
document order. The all-signatures function processes every XML-DSig
descendant and turns individual processing failures into invalid results.
Preflight uses the same namespace-aware dependency DOM and document order.
