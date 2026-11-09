---
title: "Security"
description: "Properties of the crate. Metadata trust and replay are caller choices, covered in the guides. The signature trust model is XML signatures."
---

Properties of the crate. Metadata trust and replay are caller choices, covered in the guides. The signature trust model is [XML signatures](../explanation/xml-signature-recommendations.md).

- `#![forbid(unsafe_code)]` on the crate root.
- DOCTYPE and XXE rejection, with bounded XML parsing before authentication.
- XML escaping for generated templates, metadata endpoint locations, and SAML attribute values.
- Response checks for issuer, status, assertion time window, audience, destination, recipient, bearer subject confirmation, and `InResponseTo`.
- Logout checks for issuer and request/response correlation.
- Signed metadata must cover the signed root when `MetadataTrustPolicy::RequireSignature` is selected.
- Signed `AuthnRequest` messages must cover the request root when signed requests are required.
- Detached Redirect and SimpleSign signatures are bound to the fields the flow parser consumes.
- HTTP-Redirect raw DEFLATE output is limited.
- Inbound SAML XML signatures trust metadata-pinned keys only. Inline `<KeyInfo>` is not a trust anchor.
- Signed-reference placement is strict: each reference targets the document element, an ancestor of the signature, or a sibling of the signature.
- An `Assertion` or `Signature` nested under `SubjectConfirmationData` is rejected.
- Only content covered by a verified reference is returned for extraction.
- Local digest and reference coverage is required.
- HMAC output shorter than 160 bits is rejected.
- The adapter skips X.509 chain and time checks because metadata certificates are pinned key material. Signature, digest, reference, duplicate-ID, and wrapping checks stay on.
- Software RSA key-transport decryption is disabled by default on RustCrypto because that backend, reached through bergshamra and kryptering, is affected by RUSTSEC-2023-0071. AWS-LC and FIPS do not use that gate. AWS-LC decrypts RSA-OAEP with the default options.

Schema validation is optional defence in depth through `context::set_schema_validator`.

Report a suspected vulnerability in private. Until GitHub Security Advisories are enabled for the repository, open a minimal public issue that does not include exploit details, and ask for a private disclosure channel. The policy text is [SECURITY.md](https://github.com/salasebas/saml-rs/blob/main/SECURITY.md).
