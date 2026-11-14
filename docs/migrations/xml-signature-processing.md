# Upgrade XML signature processing and coverage

This unreleased change affects callers of `crypto::verify_signature`,
`crypto::verify_signature_with_limits`, `BergshamraBackend`, and flows that
verify embedded XML signatures.

## Keep processed references within the document

Every signature passed to the cryptographic verifier now takes the existing
same-document reference checks, including signatures inside extensions.
Previously, these checks covered only signatures directly under the root or
its direct Assertion children. All-signatures flows reject a processed external
reference with `SamlError::ReferenceResolution`, with reason
`ReferenceResolutionReason::ExternalReference`, before resolving references or
running transforms. Unsupported fragment forms keep
`ReferenceResolutionReason::UnsupportedReferenceUri`.

If your peer includes optional signatures with external references, remove
those signatures or change them to reference content within the message.
`AllowProviderSupportedForCompatibility` does not allow external references.
With `StrictRsaSha2`, every processed signature must also use only the existing
allowed reference transforms, even when that signature would fail verification
or cover unrelated content. Replace other transforms with enveloped-signature
and exclusive canonicalization transforms, or remove the optional signature.
The failure is `SamlError::AlgorithmUnsupported`.

The public `verify_signature` functions still process the first XML-DSig
signature in document order when a SAML candidate signature is present. They
preflight that actual first signature. They do not process later signatures.
Flows that inspect all signatures preflight all of them. Harmless optional
signatures that fail verification outside SAML candidate positions remain
ignorable when their processing passes these restrictions.

## Consume the returned signed content

A successful public verification now always returns `(true, Some(xml))`.
For an assertion-bearing protocol response, `xml` remains the consumed signed
Assertion, and the existing checks still require coverage of every direct
Assertion. Other documents require coverage of the document root and return
that root. This includes status-only Responses, ArtifactResolve,
ManageNameIDRequest, and ArtifactResponse documents.

If you relied on `(true, None)`, handle `SamlError::SignedReferenceMismatch`
when a valid signature covers only a different object. Have the peer sign the
root of the document you need to authenticate. Root-covered documents that
previously returned no content now return their signed root.
`BergshamraBackend` applies the same guarantee before returning `Ok(())`.
Assertion-only signatures on SSO Response containers remain supported.

These are library processing and coverage guarantees. They do not add general
schema or protocol validation to the public verification functions. The exact
standards scope and library policies are recorded in
[XML signature processing](../conformance/xml-signature-processing.md).
