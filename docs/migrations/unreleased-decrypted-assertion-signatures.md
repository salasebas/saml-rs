# Sign encrypted assertions for the response they arrive in

When the service provider decrypts an `EncryptedAssertion`, it now verifies
the assertion's signature with the namespaces in scope where the assertion
sits in the decrypted `Response`. Before, it verified the decrypted text
alone in two cases:

- The `Response` carries its own XML signature.
- An HTTP-POST-SimpleSign response is accepted under the default
  `AssertionSignaturePolicy::AllowUnsigned`.

Other responses already had their decrypted assertions verified in the
decrypted `Response`. Those include an unsigned `Response` and a SimpleSign
response under `AssertionSignaturePolicy::RequireSigned` without a `Response`
signature.

In the two cases above, two kinds of signed assertion now verify:

- An assertion that uses a prefix declared on the `Response`. Before, it
  failed with `SamlError::Xml`.
- An assertion signed inside its `Response` with inclusive canonicalization.
  `XmlSignatureProfile::StrictRsaSha2` still refuses an inclusive
  canonicalization method or reference transform. Before, the assertion
  failed with `SamlError::SignatureVerification`.

In the two cases above, under `AssertionSignaturePolicy::RequireSigned`, a
decrypted assertion with no signature returns `SamlError::SignatureMissing`.
Before, some unsigned assertions returned another refusal first. One was
`SamlError::Xml` for a prefix declared on the `Response`. Another was
`SamlError::PotentialWrappingAttack` for a repeated `ID` inside the
assertion.

## Ask peers that sign with inclusive canonicalization to switch to exclusive

Inclusive canonicalization covers every namespace in scope. Suppose a peer
signed a self-contained assertion with inclusive canonicalization, encrypted
it, and sent it in a `Response` that declares other namespaces. That
signature now fails with `SamlError::SignatureVerification`. Ask the peer to
sign the assertion with exclusive canonicalization, which SAML Core §5.4.3
recommends.

Signing the assertion inside its `Response` also works when the `Response`
and its ancestors set no attribute in the `xml` namespace, such as
`xml:lang`, `xml:space`, or `xml:base`. The service provider verifies the
decrypted assertion with the namespaces in scope, but without the `xml`
attributes it would inherit from the `Response`.

## Raise the attribute limit for many inherited namespaces

A decrypted assertion that carries a signature is verified with its own
attributes and a declaration for every namespace in scope at the `Response`.
`XmlLimits::max_attributes_per_element` counts both, so a response that
declares many namespaces can exceed it. The default is 64. If that happens,
raise the limit in `XmlLimits`.
